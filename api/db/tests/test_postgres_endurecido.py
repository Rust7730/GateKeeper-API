"""Endurecimiento del PostgreSQL desechable de las pruebas (F1.07, hallazgos de gk-security).

- CWE-668: el puerto 5432 del contenedor se publica solo en 127.0.0.1, nunca en todas
  las interfaces; se comprueba consultando a Docker, no leyendo el código.
- CWE-532: la contraseña sale de una sola función, ``generar_contrasena``, con alfabeto
  urlsafe. El saneado de los errores de arranque busca la contraseña literal; si tuviera
  ``'`` testcontainers la escaparía (``'"'"'``) y el saneado ya no la encontraría.
- CWE-532: con ``pytest -l`` (showlocals) un fallo en el fixture no muestra la contraseña
  entre las variables locales.
"""

import os
import string

# subprocess solo corre pytest en un proceso hijo, con argumentos fijos y sin shell.
import subprocess  # nosec B404
import sys
from pathlib import Path

from testcontainers.community.postgres import PostgresContainer

from api.db.tests.soporte_postgres import (
    IP_PUBLICACION,
    PUERTO_POSTGRES,
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


def test_la_contrasena_generada_es_urlsafe_y_sin_comillas_ni_barras() -> None:
    generadas = {generar_contrasena() for _ in range(MUESTRAS)}
    assert len(generadas) == MUESTRAS, "el generador repite contraseñas"
    for contrasena in generadas:
        assert contrasena, "contraseña vacía"
        assert not {"'", '"', "\\"} & set(contrasena)
        assert set(contrasena) <= ALFABETO_URLSAFE


# Plugin del pytest hijo: después de detener de verdad el contenedor (no queda nada
# corriendo), guarda la contraseña en el archivo que indica la variable y simula un fallo
# en el teardown del fixture. Sin variables locales con la contraseña.
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


def _correr_pytest_hijo_que_falla_al_detener(tmp_path: Path) -> tuple[int, bool, str]:
    """Corre una prueba de la BD con ``pytest -l`` y un teardown que falla.

    Devuelve (código de salida, si la salida contenía la contraseña, salida saneada).
    La contraseña no queda en ninguna variable local y la salida se sanea antes de
    devolverla, para que un fallo de esta prueba con ``-l`` tampoco la muestre.
    """
    (tmp_path / "gk_plugin_falla_al_detener.py").write_text(
        _PLUGIN_FALLA_AL_DETENER, encoding="utf-8"
    )
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
            "gk_plugin_falla_al_detener",
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


def test_con_showlocals_un_fallo_del_fixture_no_muestra_la_contrasena(
    tmp_path: Path,
) -> None:
    codigo, filtrada, salida = _correr_pytest_hijo_que_falla_al_detener(tmp_path)
    assert codigo != -1, f"el plugin no guardó la contraseña del contenedor:\n{salida}"

    # El fallo ocurrió en el fixture y -l mostró sus variables locales...
    assert codigo != 0, f"el pytest hijo debía fallar en el teardown:\n{salida}"
    assert "falla simulada al detener el contenedor" in salida, salida
    assert "pytestconfig = <" in salida, (
        f"-l no mostró las locales del fixture:\n{salida}"
    )
    # ...y aun así la contraseña no aparece (la salida de arriba ya va saneada).
    assert not filtrada, f"pytest -l mostró la contraseña del contenedor:\n{salida}"
