"""Lado del padre del CDR, sin BD: la línea del hijo, el lanzamiento y la salida (K09, INV-09).

La matriz de ataque ya prueba por HTTP que cada fallo termina en ``error``. Aquí se fija lo
que hay por debajo: qué se admite exactamente y que el padre nunca se queda esperando.
"""

import asyncio
import json
import os
import socket
import sys
import time
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
import uvloop

from api.app import analisis
from api.app.analisis import (
    ENTORNO_HIJO,
    TOPE_SALIDA_HIJO,
    FalloDelHijo,
    Veredicto,
    correr_hijo,
    interpretar_salida,
    publicar_salida,
)
from api.app.cdr_salida import TOPE_SALIDA, SalidaDemasiadoGrande
from api.db.repositorios import ArchivoNoEncontrado, ConflictoDeEstado, DatoRechazado

LIMPIO = {"veredicto": "limpio", "tipo": "image/png", "motivo": "ok"}
RECHAZADO = {"veredicto": "rechazado", "tipo": "text/x-php", "motivo": "tipo"}


def _linea(datos: object) -> bytes:
    return json.dumps(datos).encode() + b"\n"


def _hijo(tmp_path: Path, cuerpo: str) -> tuple[str, ...]:
    ruta = tmp_path / "hijo.py"
    ruta.write_text(cuerpo)
    return (sys.executable, "-I", str(ruta))


@pytest.fixture(params=["asyncio", "uvloop"])
def fabrica_de_bucle(request: pytest.FixtureRequest) -> Callable[[], Any]:
    """Los dos bucles: pytest usa asyncio y uvicorn arranca con uvloop, que crea los
    procesos por otro camino (``uv_spawn``, no ``subprocess.Popen``)."""
    return (
        asyncio.new_event_loop if request.param == "asyncio" else uvloop.new_event_loop
    )


@pytest.fixture
def correr(fabrica_de_bucle: Callable[[], Any]) -> Callable[[Awaitable[Any]], Any]:
    def _correr(promesa: Awaitable[Any]) -> Any:
        async def _esperar() -> Any:
            return await promesa

        return asyncio.run(_esperar(), loop_factory=fabrica_de_bucle)

    return _correr


# ------------------------------------------------------------------- interpretar_salida


@pytest.mark.parametrize("datos", [LIMPIO, RECHAZADO], ids=["limpio", "rechazado"])
def test_una_linea_valida(datos: dict[str, str]) -> None:
    assert interpretar_salida(_linea(datos)) == Veredicto(**datos)


@pytest.mark.parametrize(
    "salida",
    [
        b"",
        b"\n",
        json.dumps(LIMPIO).encode(),
        b"limpio\n",
        b"\xff\xfe\n",
        b"null\n",
        b'["limpio"]\n',
        b"[" * 100_000 + b"\n",
        _linea(LIMPIO) + _linea(RECHAZADO),
        _linea(RECHAZADO) + _linea(LIMPIO),
        json.dumps(LIMPIO).encode("utf-16") + b"\n",
        b"\n" + _linea(LIMPIO),
        _linea(LIMPIO) + b"\n",
        _linea({**LIMPIO, "extra": 1}),
        _linea({"veredicto": "limpio", "motivo": "ok"}),
        _linea({"veredicto": "limpio", "tipo": "image/png"}),
        _linea({"tipo": "image/png", "motivo": "ok"}),
        _linea({**LIMPIO, "veredicto": "LIMPIO"}),
        _linea({**LIMPIO, "veredicto": "limpio "}),
        _linea({**LIMPIO, "veredicto": True}),
        _linea({**LIMPIO, "veredicto": ["limpio"]}),
        _linea({**LIMPIO, "tipo": None}),
        _linea({**LIMPIO, "tipo": "text/html"}),
        _linea({**LIMPIO, "tipo": ["image/png"]}),
        _linea({**LIMPIO, "motivo": 1}),
        _linea({**RECHAZADO, "tipo": None}),
        (
            b'{"veredicto": "rechazado", "veredicto": "limpio", '
            b'"tipo": "image/png", "motivo": "ok"}\n'
        ),
    ],
    ids=[
        "vacia",
        "solo_salto",
        "sin_salto_final",
        "no_json",
        "bytes_invalidos",
        "nulo",
        "lista",
        "anidamiento",
        "dos_lineas_rechazado_primero",
        "dos_lineas_limpio_primero",
        "utf16",
        "linea_vacia_antes",
        "linea_vacia_despues",
        "clave_extra",
        "sin_tipo",
        "sin_motivo",
        "sin_veredicto",
        "veredicto_mayusculas",
        "veredicto_espacio",
        "veredicto_booleano",
        "veredicto_lista",
        "tipo_nulo",
        "tipo_fuera_de_lista",
        "tipo_lista",
        "motivo_no_texto",
        "rechazado_sin_tipo",
        "clave_duplicada",
    ],
)
def test_lo_que_no_es_exactamente_el_formato_no_vale(salida: bytes) -> None:
    with pytest.raises(FalloDelHijo):
        interpretar_salida(salida)


def test_el_error_no_conserva_la_salida_del_hijo() -> None:
    """CWE-532: `JSONDecodeError.doc` trae el texto completo; no debe quedar encadenado."""
    with pytest.raises(FalloDelHijo) as error:
        interpretar_salida(b"contenido del hijo\n")
    assert error.value.__context__ is None
    assert error.value.__cause__ is None


# -------------------------------------------------------------------------- correr_hijo


def test_el_entorno_es_una_lista_blanca_de_valores_fijos(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, correr: Any
) -> None:
    monkeypatch.setenv("SECRETO_CUALQUIERA", "x")
    registro = tmp_path / "entorno.json"
    comando = _hijo(
        tmp_path,
        f"import json, os\njson.dump(dict(os.environ), open({str(registro)!r}, 'w'))\n"
        f"print({json.dumps(json.dumps(LIMPIO))})\n",
    )
    assert correr(correr_hijo(comando, 5)).veredicto == "limpio"
    assert set(json.loads(registro.read_text())) <= set(ENTORNO_HIJO) | {"LC_CTYPE"}


def test_stdin_es_dev_null(tmp_path: Path, correr: Any) -> None:
    registro = tmp_path / "stdin"
    comando = _hijo(
        tmp_path,
        f"import os\nopen({str(registro)!r}, 'w').write(os.readlink('/proc/self/fd/0'))\n"
        f"print({json.dumps(json.dumps(LIMPIO))})\n",
    )
    correr(correr_hijo(comando, 5))
    assert registro.read_text() == "/dev/null"


def test_el_hijo_arranca_en_su_propio_grupo(tmp_path: Path, correr: Any) -> None:
    registro = tmp_path / "grupo"
    comando = _hijo(
        tmp_path,
        "import os\n"
        f"open({str(registro)!r}, 'w').write(f'{{os.getpid()}} {{os.getpgid(0)}}')\n"
        f"print({json.dumps(json.dumps(LIMPIO))})\n",
    )
    correr(correr_hijo(comando, 5))
    pid, grupo = registro.read_text().split()
    assert pid == grupo


def test_el_hijo_real_cierra_lo_que_el_padre_no_puede_cerrar_bajo_uvloop(
    tmp_path: Path, correr: Any
) -> None:
    """K28. uvloop no aplica `close_fds`: un socket heredable del padre llega al hijo.

    Por eso lo cierra el propio hijo. El sustituto empieza igual que `main` y luego vuelca
    sus descriptores. El socket es heredable a propósito: el caso que no hay que suponer.
    """
    registro = tmp_path / "descriptores.json"
    codigo = (
        "import json, os\n"
        "from api.app.cdr_hijo import cerrar_descriptores_heredados\n"
        "cerrar_descriptores_heredados()\n"
        f"salida = open({str(registro)!r}, 'w')\n"
        "fds = {}\n"
        "for n in os.listdir('/proc/self/fd'):\n"
        "    try:\n"
        "        fds[n] = os.readlink(f'/proc/self/fd/{n}')\n"
        "    except OSError:\n"
        "        pass\n"
        "json.dump(fds, salida)\n"
        f"print({json.dumps(json.dumps(LIMPIO))})\n"
    )
    comando = (sys.executable, "-c", codigo)
    uno, otro = socket.socketpair()
    os.set_inheritable(uno.fileno(), True)
    try:
        correr(correr_hijo(comando, 5))
    finally:
        uno.close()
        otro.close()

    descriptores = json.loads(registro.read_text())
    assert descriptores["0"] == "/dev/null"
    assert descriptores["1"].startswith("pipe:")
    assert descriptores["2"] == "/dev/null"
    ajenos = {
        destino
        for numero, destino in descriptores.items()
        if int(numero) > 2
        and destino != str(registro)
        and not destino.startswith("/proc/")
    }
    assert ajenos == set()


@pytest.mark.parametrize(
    ("cuerpo", "motivo"),
    [
        ("import sys\nsys.exit(3)\n", "codigo_salida"),
        ("print('no es json')\n", "salida_invalida"),
        ("print('a' * (20 * 1024 * 1024))\n", "salida_invalida"),
        ("", "salida_invalida"),
    ],
    ids=["codigo", "no_json", "enorme", "muda"],
)
def test_motivo_de_cada_fallo(
    tmp_path: Path, cuerpo: str, motivo: str, correr: Any
) -> None:
    with pytest.raises(FalloDelHijo) as error:
        correr(correr_hijo(_hijo(tmp_path, cuerpo), 5))
    assert error.value.motivo == motivo


def test_comando_que_no_arranca_no_deja_descriptores(
    tmp_path: Path, correr: Any
) -> None:
    antes = set(os.listdir("/proc/self/fd"))
    with pytest.raises(FalloDelHijo) as error:
        correr(correr_hijo((str(tmp_path / "no_existe"),), 5))
    assert error.value.motivo == "no_arranco"
    assert set(os.listdir("/proc/self/fd")) <= antes


def test_salida_enorme_corta_sin_esperar_el_timeout(
    tmp_path: Path, correr: Any
) -> None:
    comando = _hijo(tmp_path, "while True:\n    print('a' * 65536, flush=True)\n")
    inicio = time.monotonic()
    with pytest.raises(FalloDelHijo):
        correr(correr_hijo(comando, 20))
    assert time.monotonic() - inicio < 5


def test_el_tope_de_la_salida_cabe_de_sobra_en_un_veredicto() -> None:
    assert len(_linea(RECHAZADO)) * 10 < TOPE_SALIDA_HIJO


def test_timeout_mata_tambien_a_los_descendientes(tmp_path: Path, correr: Any) -> None:
    pid_nieto = tmp_path / "nieto"
    comando = _hijo(
        tmp_path,
        "import os, time\n"
        "if os.fork() == 0:\n"
        f"    open({str(pid_nieto)!r}, 'w').write(str(os.getpid()))\n"
        "    time.sleep(30)\n"
        "    os._exit(0)\n"
        "time.sleep(30)\n",
    )
    with pytest.raises(FalloDelHijo) as error:
        correr(correr_hijo(comando, 0.5))
    assert error.value.motivo == "timeout"
    pid = int(pid_nieto.read_text())
    limite = time.monotonic() + 3
    while time.monotonic() < limite and _vivo(pid):
        time.sleep(0.01)
    assert not _vivo(pid), "el nieto sigue vivo"


def _vivo(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except (FileNotFoundError, ProcessLookupError):
        # El proceso ya no existe: /proc/<pid> desaparece o su lectura da ESRCH.
        return False


def test_un_nieto_escapado_con_stdout_abierto_no_retiene_al_padre(
    tmp_path: Path, correr: Any
) -> None:
    """`setsid` lo saca del grupo: `killpg` no lo alcanza y la tubería sigue abierta."""
    pid_nieto = tmp_path / "nieto"
    comando = _hijo(
        tmp_path,
        "import os, time\n"
        "if os.fork() == 0:\n"
        "    os.setsid()\n"
        f"    open({str(pid_nieto)!r}, 'w').write(str(os.getpid()))\n"
        "    time.sleep(30)\n"
        "    os._exit(0)\n"
        "time.sleep(30)\n",
    )
    inicio = time.monotonic()
    try:
        with pytest.raises(FalloDelHijo) as error:
            correr(correr_hijo(comando, 0.5))
        assert error.value.motivo == "timeout"
        assert time.monotonic() - inicio < 5
    finally:
        if pid_nieto.exists():
            os.kill(int(pid_nieto.read_text()), 9)


def test_hijo_que_cierra_stdout_y_no_termina_vence_por_timeout(
    tmp_path: Path, correr: Any
) -> None:
    comando = _hijo(
        tmp_path,
        f"import os, time\nprint({json.dumps(json.dumps(LIMPIO))}, flush=True)\n"
        "os.close(1)\ntime.sleep(30)\n",
    )
    with pytest.raises(FalloDelHijo) as error:
        correr(correr_hijo(comando, 0.5))
    assert error.value.motivo == "timeout"


def test_cancelar_mata_al_hijo(
    tmp_path: Path, fabrica_de_bucle: Callable[[], Any]
) -> None:
    pid_hijo = tmp_path / "pid"
    comando = _hijo(
        tmp_path,
        "import os, time\n"
        f"open({str(pid_hijo)!r}, 'w').write(str(os.getpid()))\n"
        "time.sleep(30)\n",
    )

    async def _cancelar() -> None:
        tarea = asyncio.create_task(correr_hijo(comando, 20))
        while not pid_hijo.exists() or not pid_hijo.read_text():
            await asyncio.sleep(0.01)
        tarea.cancel()
        with pytest.raises(asyncio.CancelledError):
            await tarea

    asyncio.run(_cancelar(), loop_factory=fabrica_de_bucle)
    assert not _vivo(int(pid_hijo.read_text()))


# ---------------------------------------------------------------------- publicar_salida


def test_publicar_renombra(tmp_path: Path) -> None:
    parcial, final = tmp_path / "parcial", tmp_path / "final"
    parcial.write_bytes(b"datos")
    publicar_salida(parcial, final)
    assert final.read_bytes() == b"datos"
    assert not parcial.exists()


def test_publicar_sin_archivo(tmp_path: Path) -> None:
    with pytest.raises(FalloDelHijo) as error:
        publicar_salida(tmp_path / "parcial", tmp_path / "final")
    assert error.value.motivo == "sin_salida"


def test_publicar_rechaza_un_enlace(tmp_path: Path) -> None:
    """Un hijo comprometido no consigue que la API sirva otro archivo del disco."""
    secreto = tmp_path / "secreto"
    secreto.write_bytes(b"secreto")
    parcial, final = tmp_path / "parcial", tmp_path / "final"
    parcial.symlink_to(secreto)
    with pytest.raises(FalloDelHijo) as error:
        publicar_salida(parcial, final)
    assert error.value.motivo == "sin_salida"
    assert not final.exists()


def test_publicar_rechaza_un_directorio(tmp_path: Path) -> None:
    parcial, final = tmp_path / "parcial", tmp_path / "final"
    parcial.mkdir()
    with pytest.raises(FalloDelHijo):
        publicar_salida(parcial, final)
    assert not final.exists()


def test_publicar_rechaza_un_archivo_vacio(tmp_path: Path) -> None:
    parcial, final = tmp_path / "parcial", tmp_path / "final"
    parcial.write_bytes(b"")
    with pytest.raises(FalloDelHijo):
        publicar_salida(parcial, final)
    assert not final.exists()


def test_k46_publicar_rechaza_una_salida_sobre_el_tope(tmp_path: Path) -> None:
    """El hijo no es de fiar (K28): el tope se aplica también al publicar."""
    parcial, final = tmp_path / "parcial", tmp_path / "final"
    with parcial.open("wb") as salida:
        salida.truncate(TOPE_SALIDA + 1)
    with pytest.raises(SalidaDemasiadoGrande):
        publicar_salida(parcial, final)
    assert not final.exists()


def test_k46_publicar_admite_el_tope_justo(tmp_path: Path) -> None:
    parcial, final = tmp_path / "parcial", tmp_path / "final"
    with parcial.open("wb") as salida:
        salida.truncate(TOPE_SALIDA)
    publicar_salida(parcial, final)
    assert final.stat().st_size == TOPE_SALIDA


# ------------------------------------------------- reintento del registro del error


class _SesionesQueFallan:
    """``begin()`` falla las primeras ``fallos`` veces con ``error``; luego abre."""

    def __init__(self, fallos: int, error: Exception) -> None:
        self.fallos = fallos
        self.error = error
        self.intentos = 0

    def begin(self) -> "_SesionesQueFallan":
        self.intentos += 1
        return self

    async def __aenter__(self) -> object:
        if self.intentos <= self.fallos:
            raise self.error
        return object()

    async def __aexit__(self, *_: object) -> None:
        return None


@pytest.fixture
def registros(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    hechos: list[str] = []

    async def _resultado(*_: object, **__: object) -> None:
        hechos.append("resultado")

    async def _estado(*_: object, **__: object) -> None:
        hechos.append("estado")

    monkeypatch.setattr(analisis, "registrar_resultado", _resultado)
    monkeypatch.setattr(analisis, "cambiar_estado", _estado)
    monkeypatch.setattr(analisis, "ESPERAS_REGISTRO_ERROR_S", (0, 0))
    return hechos


def _registrar(sesiones: object) -> None:
    asyncio.run(
        analisis._registrar_error(sesiones, uuid.uuid4(), uuid.uuid4(), "timeout", 1)
    )


def test_el_error_se_reintenta_si_la_bd_no_responde(registros: list[str]) -> None:
    """Sin reintento el archivo quedaría en `pendiente`, ocupando cupo de K48 hasta reiniciar."""
    sesiones = _SesionesQueFallan(2, OSError("sin conexión"))
    _registrar(sesiones)
    assert sesiones.intentos == 3
    assert registros == ["resultado", "estado"]


def test_el_reintento_es_acotado(
    registros: list[str], caplog: pytest.LogCaptureFixture
) -> None:
    sesiones = _SesionesQueFallan(99, OSError("sin conexión"))
    _registrar(sesiones)
    assert sesiones.intentos == analisis.INTENTOS_REGISTRO_ERROR == 3
    assert registros == []
    assert "sin conexión" not in caplog.text


def test_las_esperas_son_las_propuestas() -> None:
    assert analisis.ESPERAS_REGISTRO_ERROR_S == (0.5, 1.0)


@pytest.mark.parametrize(
    "error",
    [ConflictoDeEstado(), ArchivoNoEncontrado(), DatoRechazado()],
    ids=["conflicto", "no_encontrado", "dato"],
)
def test_lo_que_no_es_de_la_conexion_no_se_reintenta(
    registros: list[str], error: Exception
) -> None:
    sesiones = _SesionesQueFallan(99, error)
    _registrar(sesiones)
    assert sesiones.intentos == 1
