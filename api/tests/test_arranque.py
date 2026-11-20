"""Arranque (F3.09, K28, K51): barrido de los restos de un apagado anómalo y proceso protegido.

La matriz de ataque cubre el barrido por HTTP. Aquí van los bordes del disco (enlaces,
directorios, nombres que no son del barrido) y lo que pasa si la BD no responde.
"""

import ctypes
import os
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

from api.app import arranque, principal
from api.app.ajustes import (
    VARIABLE_DATOS,
    VARIABLE_HMAC,
    VARIABLE_REDIS,
    Ajustes,
    ConfiguracionError,
)
from api.app.estados import Estado
from api.app.principal import crear_app
from api.db.config import VARIABLE_URL_BD, VARIABLE_URL_MIGRACION
from api.db.repositorios import cambiar_estado, crear_archivo, registrar_resultado
from api.db.sesion import crear_motor, fabrica_sesiones
from api.tests.soporte_api import KeySembrada, sembrar_key, url_sin_servidor
from api.tests.soporte_redis import url_redis_sin_servidor

RAIZ = Path(__file__).resolve().parents[2]
_PR_GET_DUMPABLE = 3


def _sembrar(url: URL, app: KeySembrada, destino: Estado) -> str:
    async def _crear() -> str:
        motor = crear_motor(url)
        archivo_id = uuid.uuid4()
        try:
            async with fabrica_sesiones(motor).begin() as sesion:
                await crear_archivo(
                    sesion, app.aplicacion_id, archivo_id, "x", 1, "0" * 64
                )
                if destino is Estado.LIMPIO:
                    await registrar_resultado(
                        sesion, app.aplicacion_id, archivo_id, "cdr", "limpio", {}, 1
                    )
                if destino is not Estado.PENDIENTE:
                    await cambiar_estado(
                        sesion,
                        app.aplicacion_id,
                        archivo_id,
                        Estado.PENDIENTE,
                        destino,
                        tipo_detectado="image/png",
                        tipo_error="transitorio" if destino is Estado.ERROR else None,
                    )
        finally:
            await motor.dispose()
        return str(archivo_id)

    return anyio.run(_crear)


def _fila(url: URL, archivo_id: str) -> dict[str, Any]:
    motor = create_engine(url)
    try:
        with motor.connect() as con:
            return dict(
                con.execute(
                    text(
                        "SELECT estado, tipo_error, analizado_en FROM archivo"
                        " WHERE id = :id"
                    ),
                    {"id": uuid.UUID(archivo_id)},
                )
                .mappings()
                .one()
            )
    finally:
        motor.dispose()


@pytest.fixture
def datos(tmp_path: Path) -> Path:
    raiz = tmp_path / "datos"
    for nombre in ("uploads_tmp", "clean_store"):
        (raiz / nombre).mkdir(mode=0o700, parents=True)
    return raiz


def _ajustes(url: URL, datos: Path) -> Ajustes:
    return Ajustes(
        url_bd=url,
        pepper=secrets.token_hex(32).encode(),
        datos=datos,
        url_redis=url_redis_sin_servidor(),
    )


def test_k51_el_tipo_de_error_del_barrido_es_el_de_la_decision() -> None:
    assert arranque.TIPO_ERROR_BARRIDO == "final"


def test_el_barrido_cierra_los_pendientes_y_no_toca_lo_terminado(
    bd_limpia: URL, datos: Path
) -> None:
    app = sembrar_key(bd_limpia, secrets.token_hex(32).encode())
    pendiente = _sembrar(bd_limpia, app, Estado.PENDIENTE)
    limpio = _sembrar(bd_limpia, app, Estado.LIMPIO)
    con_error = _sembrar(bd_limpia, app, Estado.ERROR)

    with TestClient(crear_app(_ajustes(bd_limpia, datos))):
        pass

    cerrado = _fila(bd_limpia, pendiente)
    assert cerrado["estado"] == "error"
    assert cerrado["tipo_error"] == "final"
    assert cerrado["analizado_en"] is not None
    assert _fila(bd_limpia, limpio)["estado"] == "limpio"
    assert _fila(bd_limpia, con_error)["tipo_error"] == "transitorio"


def test_el_barrido_limpia_el_disco_sin_seguir_enlaces(
    bd_limpia: URL, datos: Path, tmp_path: Path
) -> None:
    app = sembrar_key(bd_limpia, secrets.token_hex(32).encode())
    pendiente = _sembrar(bd_limpia, app, Estado.PENDIENTE)
    limpio = _sembrar(bd_limpia, app, Estado.LIMPIO)
    uploads, clean = datos / "uploads_tmp", datos / "clean_store"
    victima = tmp_path / "victima"
    victima.write_bytes(b"intacto")

    (uploads / pendiente).write_bytes(b"original")
    (uploads / secrets.token_hex(4)).symlink_to(victima)
    (uploads / "subdirectorio").mkdir()
    (clean / f"{pendiente}.parcial").write_bytes(b"a medias")
    (clean / f"{uuid.uuid4()}.parcial").symlink_to(victima)
    # El directorio de trabajo de un hijo (K53), con lo que dejó dentro.
    trabajo = clean / f"{uuid.uuid4()}.parcial"
    trabajo.mkdir()
    (trabajo / "salida").write_bytes(b"a medias")
    (trabajo / "enlace").symlink_to(victima)
    (clean / f"{uuid.uuid4()}.parcial").symlink_to(tmp_path)
    (clean / pendiente).write_bytes(b"publicado sin confirmar")
    (clean / limpio).write_bytes(b"entregable")

    with TestClient(crear_app(_ajustes(bd_limpia, datos))):
        pass

    assert sorted(p.name for p in uploads.iterdir()) == ["subdirectorio"]
    assert sorted(p.name for p in clean.iterdir()) == [limpio]
    assert (clean / limpio).read_bytes() == b"entregable"
    assert victima.read_bytes() == b"intacto"


def test_sin_bd_al_arrancar_no_arranca_ni_muestra_la_contrasena(
    datos: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Sin barrido, los huérfanos ocuparían para siempre el cupo de K48."""
    contrasena = secrets.token_urlsafe(24)
    ajustes = Ajustes(
        url_bd=url_sin_servidor(contrasena),
        pepper=secrets.token_hex(32).encode(),
        datos=datos,
        url_redis=url_redis_sin_servidor(),
    )
    with pytest.raises(ConfiguracionError) as error, TestClient(crear_app(ajustes)):
        pass  # pragma: no cover
    assert contrasena not in str(error.value)
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert contrasena not in caplog.text


# ------------------------------------------------------------------- PR_SET_DUMPABLE


def test_k28_el_arranque_deja_el_proceso_sin_volcar(
    bd_limpia: URL, datos: Path
) -> None:
    with TestClient(crear_app(_ajustes(bd_limpia, datos))):
        assert ctypes.CDLL(None).prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0) == 0


@pytest.mark.parametrize("bucle", ["asyncio", "uvloop"])
def test_k28_con_uvicorn_nadie_lee_el_entorno_de_la_api(
    bd_limpia: URL, datos: Path, bucle: str
) -> None:
    """Como se arranca de verdad: uvicorn por línea de órdenes, con el bucle de cada caso."""
    with __import__("socket").socket() as sock:
        sock.bind(("127.0.0.1", 0))
        puerto = sock.getsockname()[1]
    entorno = {
        "PATH": os.environ["PATH"],
        VARIABLE_URL_BD: bd_limpia.render_as_string(hide_password=False),
        VARIABLE_HMAC: secrets.token_hex(32),
        VARIABLE_DATOS: str(datos),
        VARIABLE_REDIS: url_redis_sin_servidor(),
    }
    proceso = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "--factory",
            "api.app.principal:crear_app",
            "--no-server-header",
            "--loop",
            bucle,
            "--host",
            "127.0.0.1",
            "--port",
            str(puerto),
        ],
        cwd=RAIZ,
        env=entorno,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        limite = time.monotonic() + 30
        while True:
            assert proceso.poll() is None, "uvicorn terminó al arrancar"
            try:
                if httpx.get(f"http://127.0.0.1:{puerto}/health").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            assert time.monotonic() < limite, "uvicorn no respondió /health"
            time.sleep(0.05)
        with pytest.raises(PermissionError), open(f"/proc/{proceso.pid}/environ", "rb"):
            pass  # pragma: no cover
    finally:
        proceso.terminate()
        try:
            proceso.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proceso.kill()
            proceso.wait()


# ------------------------------------------- K52: ningún ancestro expone los secretos

_COMPROBAR = (
    "import sys\n"
    f"sys.path.insert(0, {str(RAIZ)!r})\n"
    "from api.app.ajustes import ConfiguracionError\n"
    "from api.app.arranque import comprobar_ancestros\n"
    "try:\n"
    "    comprobar_ancestros()\n"
    "except ConfiguracionError as error:\n"
    "    print('ERROR', error)\n"
    "else:\n"
    "    print('OK')\n"
)


def _desde_un_padre(entorno_del_padre: dict[str, str], antes: str = "") -> str:
    """Un padre con ese entorno lanza al hijo que comprueba; el hijo no lo hereda."""
    padre = (
        "import os, subprocess, sys\n"
        + antes
        + f"r = subprocess.run([sys.executable, '-c', {_COMPROBAR!r}],"
        " env={'PATH': os.environ['PATH']}, capture_output=True, text=True)\n"
        "sys.stdout.write(r.stdout + r.stderr)\n"
    )
    salida = subprocess.run(
        [sys.executable, "-c", padre],
        env={"PATH": os.environ["PATH"], **entorno_del_padre},
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return salida.stdout


@pytest.mark.parametrize("variable", [VARIABLE_HMAC, VARIABLE_URL_BD, VARIABLE_REDIS])
def test_k52_un_padre_con_los_secretos_impide_arrancar(variable: str) -> None:
    secreto = secrets.token_hex(24)
    salida = _desde_un_padre({variable: secreto})
    assert salida.startswith("ERROR")
    assert variable in salida
    assert "uvicorn" in salida
    assert secreto not in salida


def test_k52_un_abuelo_tambien_cuenta() -> None:
    secreto = secrets.token_hex(24)
    abuelo = (
        "import os, subprocess, sys\n"
        f"r = subprocess.run([sys.executable, '-c', {_COMPROBAR!r}],"
        " capture_output=True, text=True,"
        " env={'PATH': os.environ['PATH']})\n"
        "sys.stdout.write(r.stdout)\n"
    )
    # El abuelo tiene el secreto; el padre se lanza sin él.
    salida = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import os, subprocess, sys\n"
                f"r = subprocess.run([sys.executable, '-c', {abuelo!r}],"
                " env={'PATH': os.environ['PATH']}, capture_output=True, text=True)\n"
                "sys.stdout.write(r.stdout)\n"
            ),
        ],
        env={"PATH": os.environ["PATH"], VARIABLE_HMAC: secreto},
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    ).stdout
    assert salida.startswith("ERROR")
    assert secreto not in salida


def test_k52_un_padre_sin_los_secretos_deja_arrancar() -> None:
    otras = {"GATEKEEPER_DATOS": "/srv/gatekeeper", "OTRA": secrets.token_hex(8)}
    assert _desde_un_padre(otras).startswith("OK")


def test_k52_un_nombre_que_solo_empieza_igual_no_cuenta() -> None:
    salida = _desde_un_padre({f"{VARIABLE_URL_BD}_OTRA": secrets.token_hex(8)})
    assert salida.startswith("OK")


def test_k52_la_url_de_migracion_tambien_cuenta() -> None:
    """Lleva la misma contraseña de la BD."""
    secreto = secrets.token_hex(24)
    salida = _desde_un_padre({VARIABLE_URL_MIGRACION: secreto})
    assert salida.startswith("ERROR")
    assert secreto not in salida


def test_k52_un_padre_ilegible_no_cuenta_como_expuesto() -> None:
    """Un ancestro no volcable (u otro usuario) no deja leer su entorno a nadie."""
    salida = _desde_un_padre(
        {VARIABLE_HMAC: secrets.token_hex(24)},
        antes="import ctypes\nctypes.CDLL(None).prctl(4, 0, 0, 0, 0)\n",
    )
    assert salida.startswith("OK")


def test_k52_pytest_no_expone_los_secretos() -> None:
    """Las pruebas que arrancan la app dentro de pytest no deben toparse con K52."""
    arranque.comprobar_ancestros()


def test_k52_el_arranque_comprueba_los_ancestros(
    bd_limpia: URL, datos: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _expuesto() -> None:
        raise ConfiguracionError("ancestro expuesto")

    monkeypatch.setattr(principal, "comprobar_ancestros", _expuesto)
    with (
        pytest.raises(ConfiguracionError),
        TestClient(crear_app(_ajustes(bd_limpia, datos))),
    ):
        pass  # pragma: no cover
