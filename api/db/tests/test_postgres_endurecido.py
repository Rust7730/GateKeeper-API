"""Endurecimiento del PostgreSQL desechable de las pruebas (F1.07, hallazgos de gk-security).

- CWE-668: el puerto 5432 del contenedor se publica solo en 127.0.0.1, nunca en todas
  las interfaces; se comprueba consultando a Docker, no leyendo el código.
- CWE-668: lo mismo para el 8080 del reaper de testcontainers (ryuk), que testcontainers
  publica en todas las interfaces y no deja configurar. Y como el ajuste toca cómo se
  crea el reaper, se comprueba que sigue limpiando: si el proceso de pytest muere con
  SIGKILL (sin ``atexit``), el reaper quita los contenedores de esa sesión.
- El reaper de la sesión confirmó el registro (respondió ``ACK``). testcontainers 4.15
  conecta sin esperar a que ryuk escuche; ``docker-proxy`` acepta igual y luego corta, y
  ryuk, sin cliente, se apaga a los 60 s sin proteger nada. Ver
  ``confirmar_registro_en_reaper``.
- CWE-532: la contraseña sale de una sola función, ``generar_contrasena``, con alfabeto
  urlsafe. El saneado de los errores de arranque busca la contraseña literal; si tuviera
  ``'`` testcontainers la escaparía (``'"'"'``) y el saneado ya no la encontraría.
- CWE-532: con ``pytest -l`` (showlocals) un fallo en los fixtures no muestra la
  contraseña entre las variables locales, ni en el teardown ni en el setup posterior al
  arranque (la primera conexión a la BD falla de verdad).
"""

import json
import os
import signal
import socket
import string
import struct

# subprocess solo corre pytest en un proceso hijo, con argumentos fijos y sin shell.
import subprocess  # nosec B404
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import testcontainers.core.container as modulo_container
from docker import DockerClient as ClienteDocker
from docker.models.containers import Container
from testcontainers.community.postgres import PostgresContainer
from testcontainers.core.config import testcontainers_config
from testcontainers.core.container import Reaper
from testcontainers.core.docker_client import DockerClient
from testcontainers.core.labels import LABEL_SESSION_ID, SESSION_ID

from api.db.tests.soporte_postgres import (
    IP_PUBLICACION,
    PUERTO_POSTGRES,
    arrancar_reaper_en_loopback,
    confirmar_registro_en_reaper,
    exigir_docker,
    generar_contrasena,
)

RAIZ_REPO = Path(__file__).resolve().parents[3]
ALFABETO_URLSAFE = frozenset(string.ascii_letters + string.digits + "-_")
# 2000 muestras de 32 caracteres: si el generador admitiera aunque sea una comilla entre
# ~90 caracteres imprimibles, la probabilidad de no verla sería ~(89/90)^64000 ≈ 0.
MUESTRAS = 2000


def test_el_puerto_publicado_escucha_solo_en_127_0_0_1(
    contenedor_postgres: PostgresContainer,
) -> None:
    assert IP_PUBLICACION == "127.0.0.1"
    docker = contenedor_postgres.get_wrapped_container()
    docker.reload()  # lo mismo que `docker inspect` en este momento
    puerto = f"{PUERTO_POSTGRES}/tcp"

    pedidos = docker.attrs["HostConfig"]["PortBindings"][puerto]
    assert pedidos, f"{puerto} no se pidió publicar"
    assert {p["HostIp"] for p in pedidos} == {"127.0.0.1"}, pedidos

    # Lo que Docker publicó de verdad: con 0.0.0.0 aparecerían también 0.0.0.0 y ::.
    publicados = docker.attrs["NetworkSettings"]["Ports"][puerto]
    assert publicados, f"{puerto} no quedó publicado"
    assert {p["HostIp"] for p in publicados} == {"127.0.0.1"}, publicados


def _exigir_solo_loopback(attrs: dict, puerto: str) -> None:
    """``attrs`` de ``docker inspect``: pedido y publicado solo en 127.0.0.1."""
    pedidos = attrs["HostConfig"]["PortBindings"][puerto]
    assert pedidos, f"{puerto} no se pidió publicar"
    assert {p["HostIp"] for p in pedidos} == {"127.0.0.1"}, pedidos
    publicados = attrs["NetworkSettings"]["Ports"][puerto]
    assert publicados, f"{puerto} no quedó publicado"
    assert {p["HostIp"] for p in publicados} == {"127.0.0.1"}, publicados


def _nombre_reaper(sesion: str) -> str:
    return f"testcontainers-ryuk-{sesion}"


def test_el_reaper_publica_8080_solo_en_127_0_0_1(
    contenedor_postgres: PostgresContainer,
) -> None:
    # El reaper de esta sesión de pytest, buscado en Docker por el nombre que le pone
    # testcontainers (no por el objeto en memoria): lo que importa es lo que publicó.
    cliente = contenedor_postgres.get_docker_client().client
    reaper = cliente.containers.get(_nombre_reaper(SESSION_ID))
    reaper.reload()
    assert reaper.status == "running", reaper.status
    _exigir_solo_loopback(reaper.attrs, "8080/tcp")


def test_el_reaper_registro_esta_sesion(
    contenedor_postgres: PostgresContainer,
) -> None:
    """ryuk recibió el filtro de esta sesión: es lo que le permite limpiar tras un SIGKILL.

    Sin registro, ryuk escribe ``Timeout waiting for connection`` a los 60 s, sale sin
    quitar nada y ``auto_remove`` lo borra: la sesión queda sin reaper y la prueba de
    arriba falla con ``No such container``.
    """
    cliente = contenedor_postgres.get_docker_client().client
    reaper = cliente.containers.get(_nombre_reaper(SESSION_ID))
    bitacora = reaper.logs().decode("utf-8", errors="replace")
    assert f'"{LABEL_SESSION_ID}={SESSION_ID}":true' in bitacora, bitacora
    assert "Timeout waiting for connection" not in bitacora, bitacora


class _RyukFalso:
    """Servidor TCP en 127.0.0.1 que imita a ryuk detrás de ``docker-proxy``.

    Las primeras ``cortes`` conexiones las cierra sin leer nada, como ``docker-proxy``
    cuando acepta en el puerto del host y el contenedor todavía no escucha (``reset``:
    con RST, como cuando el proxy aborta). Las demás reciben ``ACK`` por cada línea.
    """

    def __init__(self, cortes: int, *, reset: bool = False) -> None:
        self._cortes = cortes
        self._reset = reset
        self.conexiones = 0
        self.lineas: list[bytes] = []
        self._abiertas: list[socket.socket] = []
        self._servidor = socket.create_server(("127.0.0.1", 0))
        self._servidor.settimeout(0.2)
        self.destino: tuple[str, int] = self._servidor.getsockname()[:2]
        self._parar = threading.Event()
        self._hilo = threading.Thread(target=self._atender, daemon=True)
        self._hilo.start()

    def _atender(self) -> None:
        while not self._parar.is_set():
            try:
                conexion, _ = self._servidor.accept()
            except TimeoutError:
                continue
            self.conexiones += 1
            if self._cortes > 0:
                self._cortes -= 1
                if self._reset:
                    conexion.setsockopt(
                        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                    )
                conexion.close()
                continue
            conexion.settimeout(2)
            linea = b""
            while not linea.endswith(b"\n"):
                trozo = conexion.recv(64)
                if not trozo:
                    break
                linea += trozo
            self.lineas.append(linea)
            conexion.sendall(b"ACK\n")
            self._abiertas.append(conexion)

    def cerrar(self) -> None:
        self._parar.set()
        self._hilo.join(timeout=5)
        for conexion in self._abiertas:
            conexion.close()
        self._servidor.close()


@pytest.fixture
def ryuk_falso(request: pytest.FixtureRequest) -> Iterator[_RyukFalso]:
    cortes, reset = request.param
    servidor = _RyukFalso(cortes, reset=reset)
    try:
        yield servidor
    finally:
        servidor.cerrar()


_LINEA_REGISTRO = b"label=org.testcontainers.session-id=prueba\r\n"


def _conectar_como_testcontainers(destino: tuple[str, int]) -> socket.socket:
    """Lo que hace ``Reaper._create_instance``: conecta, manda el filtro y no lee nada."""
    conexion = socket.socket()
    conexion.settimeout(1)
    conexion.connect(destino)
    conexion.send(_LINEA_REGISTRO)
    return conexion


@pytest.mark.parametrize("ryuk_falso", [(0, False)], indirect=True)
def test_con_ack_a_la_primera_conserva_la_conexion(ryuk_falso: _RyukFalso) -> None:
    actual = _conectar_como_testcontainers(ryuk_falso.destino)
    try:
        confirmada = confirmar_registro_en_reaper(
            actual, ryuk_falso.destino, _LINEA_REGISTRO, intentos=3, pausa_s=0.01
        )
        assert confirmada is actual
        assert ryuk_falso.conexiones == 1
        assert ryuk_falso.lineas == [_LINEA_REGISTRO]
    finally:
        actual.close()


@pytest.mark.parametrize(
    "ryuk_falso",
    [pytest.param((1, False), id="cierre"), pytest.param((1, True), id="reset")],
    indirect=True,
)
def test_si_el_proxy_corta_la_primera_conexion_se_reconecta_hasta_el_ack(
    ryuk_falso: _RyukFalso,
) -> None:
    actual = _conectar_como_testcontainers(ryuk_falso.destino)
    confirmada = confirmar_registro_en_reaper(
        actual, ryuk_falso.destino, _LINEA_REGISTRO, intentos=3, pausa_s=0.01
    )
    try:
        assert confirmada is not actual
        assert actual.fileno() == -1, "la conexión cortada se debe cerrar"
        assert confirmada.fileno() != -1
        assert ryuk_falso.conexiones == 2
        assert ryuk_falso.lineas == [_LINEA_REGISTRO]
    finally:
        confirmada.close()


@pytest.mark.parametrize("ryuk_falso", [(100, False)], indirect=True)
def test_si_ryuk_nunca_confirma_falla_con_mensaje_claro(
    ryuk_falso: _RyukFalso,
) -> None:
    actual = _conectar_como_testcontainers(ryuk_falso.destino)
    with pytest.raises(RuntimeError) as falla:
        confirmar_registro_en_reaper(
            actual, ryuk_falso.destino, _LINEA_REGISTRO, intentos=3, pausa_s=0.01
        )
    assert "ACK" in str(falla.value)
    assert f"{ryuk_falso.destino[0]}:{ryuk_falso.destino[1]}" in str(falla.value)
    assert actual.fileno() == -1
    assert ryuk_falso.conexiones == 1 + 3


def test_el_reaper_desactivado_falla_con_mensaje_claro(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(testcontainers_config, "ryuk_disabled", True)
    with pytest.raises(pytest.fail.Exception) as falla:
        arrancar_reaper_en_loopback()
    assert "TESTCONTAINERS_RYUK_DISABLED" in str(falla.value)


def test_un_reaper_previo_sin_el_ajuste_falla_con_mensaje_claro(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(testcontainers_config, "ryuk_disabled", False)
    # Un reaper que alguien creó antes por el camino normal de testcontainers. Se usa
    # __new__ para no construirlo: el constructor de DockerContainer contacta a Docker.
    monkeypatch.setattr(Reaper, "_instance", Reaper())
    monkeypatch.setattr(
        Reaper,
        "_container",
        modulo_container.DockerContainer.__new__(modulo_container.DockerContainer),
    )
    with pytest.raises(pytest.fail.Exception) as falla:
        arrancar_reaper_en_loopback()
    assert "reaper" in str(falla.value) and "127.0.0.1" in str(falla.value)


def test_la_sustitucion_solo_dura_lo_que_tarda_crear_el_reaper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sin Docker: el reaper se crea con la subclase y la global se restaura aunque falle."""
    original = modulo_container.DockerContainer
    vista: list[type] = []

    def _crear_y_fallar() -> Reaper:
        vista.append(modulo_container.DockerContainer)
        raise RuntimeError("falla simulada al crear el reaper")

    monkeypatch.setattr(testcontainers_config, "ryuk_disabled", False)
    # Aislada del reaper real de la sesión (si ya existe): al fallar se llama a
    # Reaper.delete_instance(), que cerraría su socket y ryuk quitaría el PostgreSQL.
    monkeypatch.setattr(Reaper, "_instance", None)
    monkeypatch.setattr(Reaper, "_container", None)
    monkeypatch.setattr(Reaper, "_socket", None)
    monkeypatch.setattr(Reaper, "get_instance", staticmethod(_crear_y_fallar))

    with pytest.raises(pytest.fail.Exception) as falla:
        arrancar_reaper_en_loopback()
    assert "falla simulada al crear el reaper" in str(falla.value)

    assert len(vista) == 1
    assert vista[0] is not original and issubclass(vista[0], original)
    # Sin construirla (el constructor contacta a Docker): basta con sus puertos.
    instancia = vista[0].__new__(vista[0])
    instancia.ports = {}
    instancia.with_exposed_ports(8080)
    assert instancia.ports == {"8080": (IP_PUBLICACION, None)}
    assert instancia.get_container_host_ip() == IP_PUBLICACION
    assert modulo_container.DockerContainer is original, "la global no se restauró"


# Proceso hijo de la prueba de limpieza: arranca el reaper (con el ajuste) y PostgreSQL
# como lo hace conftest.py, avisa que está listo y se queda esperando a que lo maten.
_HIJO_REAPER = """
import json
import sys
import time
from pathlib import Path

from testcontainers.core.labels import SESSION_ID

from api.db.tests.soporte_postgres import (
    arrancar_contenedor,
    arrancar_reaper_en_loopback,
    crear_contenedor,
    exigir_docker,
)

exigir_docker()
arrancar_reaper_en_loopback()
contenedor = crear_contenedor()
arrancar_contenedor(contenedor)
listo = Path(sys.argv[1])
temporal = listo.with_suffix(".tmp")
temporal.write_text(
    json.dumps({"sesion": SESSION_ID, "postgres": contenedor.get_wrapped_container().id}),
    encoding="utf-8",
)
temporal.replace(listo)
time.sleep(600)
"""
# Lo que tarda ryuk en limpiar después de perder la conexión. Corto para que la prueba
# no espere los 10 s por omisión.
_RECONEXION_REAPER = "2s"
_PLAZO_ARRANQUE_S = 120.0
_PLAZO_LIMPIEZA_S = 60.0


def _contenedores_de_la_sesion(cliente: ClienteDocker, sesion: str) -> list[Container]:
    """Contenedores (corriendo o detenidos) de una sesión de testcontainers y su reaper."""
    por_etiqueta = cliente.containers.list(
        all=True, filters={"label": f"{LABEL_SESSION_ID}={sesion}"}
    )
    # El filtro por nombre de Docker es por subcadena; se exige el nombre exacto.
    por_nombre = [
        c
        for c in cliente.containers.list(
            all=True, filters={"name": _nombre_reaper(sesion)}
        )
        if c.name == _nombre_reaper(sesion)
    ]
    return por_etiqueta + por_nombre


def _esperar_listo(hijo: subprocess.Popen, listo: Path, bitacora: Path) -> dict:
    limite = time.monotonic() + _PLAZO_ARRANQUE_S
    while not listo.is_file():
        if hijo.poll() is not None:
            pytest.fail(
                f"el proceso hijo terminó ({hijo.returncode}) antes de arrancar:\n"
                + bitacora.read_text(encoding="utf-8", errors="replace"),
                pytrace=False,
            )
        if time.monotonic() > limite:
            pytest.fail("el proceso hijo no arrancó a tiempo", pytrace=False)
        time.sleep(0.2)
    return json.loads(listo.read_text(encoding="utf-8"))


def test_si_pytest_muere_con_sigkill_el_reaper_quita_sus_contenedores(
    tmp_path: Path,
) -> None:
    exigir_docker()
    cliente = DockerClient().client
    guion = tmp_path / "gk_hijo_reaper.py"
    guion.write_text(_HIJO_REAPER, encoding="utf-8")
    listo = tmp_path / "listo.json"
    bitacora = tmp_path / "hijo.log"
    entorno = {
        **os.environ,
        "RYUK_RECONNECTION_TIMEOUT": _RECONEXION_REAPER,
        "PYTHONPATH": os.pathsep.join(
            filter(None, [str(RAIZ_REPO), os.environ.get("PYTHONPATH")])
        ),
    }
    sesion = None
    with bitacora.open("w", encoding="utf-8") as salida_hijo:
        hijo = subprocess.Popen(  # nosec B603
            [sys.executable, str(guion), str(listo)],
            cwd=RAIZ_REPO,
            env=entorno,
            stdout=salida_hijo,
            stderr=subprocess.STDOUT,
        )
    try:
        datos = _esperar_listo(hijo, listo, bitacora)
        sesion = datos["sesion"]
        assert sesion != SESSION_ID

        # Antes de matarlo: PostgreSQL y el reaper del hijo existen, y el reaper del
        # hijo también quedó solo en loopback.
        postgres = cliente.containers.get(datos["postgres"])
        assert postgres.status == "running", postgres.status
        reaper = cliente.containers.get(_nombre_reaper(sesion))
        _exigir_solo_loopback(reaper.attrs, "8080/tcp")

        hijo.send_signal(signal.SIGKILL)
        hijo.wait(timeout=10)

        limite = time.monotonic() + _PLAZO_LIMPIEZA_S
        restantes = _contenedores_de_la_sesion(cliente, sesion)
        while restantes and time.monotonic() < limite:
            time.sleep(0.5)
            restantes = _contenedores_de_la_sesion(cliente, sesion)
        assert not restantes, (
            f"tras SIGKILL quedaron contenedores de la sesión {sesion}: "
            f"{[(c.name, c.status) for c in restantes]}"
        )
    finally:
        if hijo.poll() is None:
            hijo.kill()
            hijo.wait(timeout=10)
        # Si la prueba falló, no se dejan contenedores huérfanos en la máquina.
        if sesion is not None:
            for sobrante in _contenedores_de_la_sesion(cliente, sesion):
                sobrante.remove(force=True, v=True)


def test_la_contrasena_generada_es_urlsafe_y_sin_comillas_ni_barras() -> None:
    generadas = {generar_contrasena() for _ in range(MUESTRAS)}
    assert len(generadas) == MUESTRAS, "el generador repite contraseñas"
    for contrasena in generadas:
        assert contrasena, "contraseña vacía"
        assert not {"'", '"', "\\"} & set(contrasena)
        assert set(contrasena) <= ALFABETO_URLSAFE


# Plugins del pytest hijo. Ninguno deja la contraseña en una variable local; la guardan
# en el archivo que indica GK_ARCHIVO_CONTRASENA para que el padre la busque en la salida.
#
# Teardown: después de detener de verdad el contenedor (no queda nada corriendo), simula
# un fallo al detenerlo.
_PLUGIN_FALLA_AL_DETENER = """
import os
from pathlib import Path

from testcontainers.community.postgres import PostgresContainer

_detener_original = PostgresContainer.stop


def _detener_y_fallar(self, *args, **kwargs):
    _detener_original(self, *args, **kwargs)
    Path(os.environ["GK_ARCHIVO_CONTRASENA"]).write_text(self.password, encoding="utf-8")
    raise RuntimeError("falla simulada al detener el contenedor")


PostgresContainer.stop = _detener_y_fallar
"""
# Setup después del arranque: PostgreSQL arranca bien y luego se le quita el permiso de
# entrar al superusuario (por el socket local, que no pide contraseña). La primera
# conexión del fixture ``conexion`` falla de verdad, con SQLAlchemy y psycopg en la pila.
_PLUGIN_FALLA_AL_CONECTAR = """
import os
from pathlib import Path

from testcontainers.community.postgres import PostgresContainer

_arrancar_original = PostgresContainer.start
_QUITAR_LOGIN = "ALTER ROLE gk_pruebas NOLOGIN"


def _arrancar_y_quitar_el_login(self, *args, **kwargs):
    resultado = _arrancar_original(self, *args, **kwargs)
    Path(os.environ["GK_ARCHIVO_CONTRASENA"]).write_text(self.password, encoding="utf-8")
    codigo, salida = self.exec(
        ["psql", "-v", "ON_ERROR_STOP=1", "-U", self.username, "-d", self.dbname,
         "-c", _QUITAR_LOGIN]
    )
    if codigo != 0:
        raise RuntimeError(f"no se pudo quitar el login: {salida!r}")
    return resultado


PostgresContainer.start = _arrancar_y_quitar_el_login
"""


def _correr_pytest_hijo_con_plugin(
    tmp_path: Path, plugin: str
) -> tuple[int, bool, str]:
    """Corre una prueba de la BD con ``pytest -l`` y un plugin que la hace fallar.

    Devuelve (código de salida, si la salida contenía la contraseña, salida saneada).
    La contraseña no queda en ninguna variable local y la salida se sanea antes de
    devolverla, para que un fallo de esta prueba con ``-l`` tampoco la muestre.
    """
    (tmp_path / "gk_plugin_falla.py").write_text(plugin, encoding="utf-8")
    archivo_contrasena = tmp_path / "contrasena"
    entorno = {
        **os.environ,
        "GK_ARCHIVO_CONTRASENA": str(archivo_contrasena),
        "PYTHONPATH": os.pathsep.join(
            filter(None, [str(tmp_path), os.environ.get("PYTHONPATH")])
        ),
    }
    prueba = (
        "api/db/tests/test_postgres_desechable.py::test_el_servidor_es_postgresql_16"
    )
    resultado = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-l",
            "--tb=long",
            "-p",
            "no:cacheprovider",
            "-p",
            "gk_plugin_falla",
            prueba,
        ],
        cwd=RAIZ_REPO,
        env=entorno,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    codigo, salida = resultado.returncode, resultado.stdout + resultado.stderr
    del resultado  # su stdout podría traer la contraseña sin sanear
    if not archivo_contrasena.is_file() or archivo_contrasena.stat().st_size == 0:
        # El plugin no llegó a guardar la contraseña: no hay con qué comparar.
        return -1, False, salida
    filtrada = archivo_contrasena.read_text(encoding="utf-8") in salida
    salida = salida.replace(archivo_contrasena.read_text(encoding="utf-8"), "***")
    archivo_contrasena.unlink()
    return codigo, filtrada, salida


@pytest.mark.parametrize(
    ("plugin", "falla_esperada", "local_esperada"),
    [
        pytest.param(
            _PLUGIN_FALLA_AL_DETENER,
            "falla simulada al detener el contenedor",
            "pytestconfig = <",
            id="teardown",
        ),
        pytest.param(
            _PLUGIN_FALLA_AL_CONECTAR,
            "is not permitted to log in",
            "motor_postgres = Engine(",
            id="setup-tras-arrancar",
        ),
    ],
)
def test_con_showlocals_un_fallo_del_fixture_no_muestra_la_contrasena(
    tmp_path: Path, plugin: str, falla_esperada: str, local_esperada: str
) -> None:
    codigo, filtrada, salida = _correr_pytest_hijo_con_plugin(tmp_path, plugin)
    assert codigo != -1, f"el plugin no guardó la contraseña del contenedor:\n{salida}"

    # El fallo ocurrió en el fixture y -l mostró sus variables locales...
    assert codigo != 0, f"el pytest hijo debía fallar en el fixture:\n{salida}"
    assert falla_esperada in salida, salida
    assert local_esperada in salida, f"-l no mostró las locales del fixture:\n{salida}"
    # ...y aun así la contraseña no aparece (la salida de arriba ya va saneada).
    assert not filtrada, f"pytest -l mostró la contraseña del contenedor:\n{salida}"
