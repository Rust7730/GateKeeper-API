"""Arranque y apagado (diseño §2): motor, fábrica, directorios y fallos sin valores."""

import os
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from api.app import principal
from api.app.ajustes import (
    CLEAN_STORE,
    UPLOADS_TMP,
    VARIABLE_DATOS,
    VARIABLE_HMAC,
    VARIABLE_REDIS,
    Ajustes,
    ConfiguracionError,
)
from api.app.principal import crear_app
from api.db.config import VARIABLE_URL_BD, ConfiguracionBDError
from api.tests.soporte_api import url_cruda, url_sin_servidor
from api.tests.soporte_redis import url_redis_sin_servidor

RAIZ = Path(__file__).resolve().parents[2]
# token_urlsafe y no token_hex: una URL de abajo la usa de puerto y no debe ser un número.
CONTRASENA_BD = secrets.token_urlsafe(24)
# Nada escucha en el puerto 1: si algo intentara conectar, fallaría.
URL_SIN_SERVIDOR = url_sin_servidor(CONTRASENA_BD)
PEPPER = secrets.token_hex(16).encode()
PEPPER_CORTO = secrets.token_hex(15)
# K59: tampoco hay Redis; la app arranca igual (K60) y aquí no se cuenta nada.
URL_REDIS = url_redis_sin_servidor()


async def _sin_barrido(*_: object) -> None:
    return None


@pytest.fixture(autouse=True)
def sin_barrido(monkeypatch: pytest.MonkeyPatch) -> None:
    """Aquí no hay BD: el barrido del arranque tiene sus pruebas en ``test_arranque.py``.

    El subproceso de uvicorn no lo ve, pero ahí el arranque falla antes por el pepper.
    """
    monkeypatch.setattr(principal, "barrer_restos", _sin_barrido)


@pytest.fixture
def ajustes(tmp_path: Path) -> Ajustes:
    return Ajustes(
        url_bd=URL_SIN_SERVIDOR,
        pepper=PEPPER,
        datos=tmp_path / "datos",
        url_redis=URL_REDIS,
    )


@pytest.fixture
def sin_entorno(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for variable in (VARIABLE_URL_BD, VARIABLE_HMAC, VARIABLE_DATOS, VARIABLE_REDIS):
        monkeypatch.delenv(variable, raising=False)
    return monkeypatch


def test_crear_app_con_ajustes_no_lee_el_entorno(
    ajustes: Ajustes, sin_entorno: pytest.MonkeyPatch
) -> None:
    with TestClient(crear_app(ajustes)) as cliente:
        assert cliente.app.state.ajustes is ajustes


def test_el_arranque_crea_los_directorios_0750(ajustes: Ajustes) -> None:
    with TestClient(crear_app(ajustes)):
        for ruta in (ajustes.datos / UPLOADS_TMP, ajustes.datos / CLEAN_STORE):
            assert stat.S_IMODE(ruta.stat().st_mode) == 0o750


def test_crear_app_no_toca_el_disco_hasta_arrancar(ajustes: Ajustes) -> None:
    crear_app(ajustes)
    assert not ajustes.datos.exists()


def test_el_arranque_deja_motor_y_fabrica_en_el_estado(ajustes: Ajustes) -> None:
    with TestClient(crear_app(ajustes)) as cliente:
        assert isinstance(cliente.app.state.motor, AsyncEngine)
        assert isinstance(cliente.app.state.sesiones, async_sessionmaker)


def test_el_apagado_cierra_el_motor(
    ajustes: Ajustes, monkeypatch: pytest.MonkeyPatch
) -> None:
    cerrados = []
    original = AsyncEngine.dispose

    async def _dispose(motor: AsyncEngine, close: bool = True) -> None:
        cerrados.append(motor)
        await original(motor, close)

    monkeypatch.setattr(AsyncEngine, "dispose", _dispose)
    with TestClient(crear_app(ajustes)) as cliente:
        motor = cliente.app.state.motor
        assert cerrados == []
    assert cerrados == [motor]


def test_health_no_toca_la_bd(ajustes: Ajustes) -> None:
    with TestClient(crear_app(ajustes)) as cliente:
        inicio = time.perf_counter()
        respuesta = cliente.get("/health")
        duracion = time.perf_counter() - inicio
    assert respuesta.status_code == 200
    assert respuesta.json() == {"estado": "ok"}
    assert duracion < 1


def test_sin_ajustes_se_leen_del_entorno_al_arrancar(
    sin_entorno: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    app = crear_app()  # sin entorno todavía: leerlo aquí fallaría
    sin_entorno.setenv(VARIABLE_URL_BD, URL_SIN_SERVIDOR)
    sin_entorno.setenv(VARIABLE_HMAC, PEPPER.decode())
    sin_entorno.setenv(VARIABLE_DATOS, str(tmp_path / "datos"))
    sin_entorno.setenv(VARIABLE_REDIS, URL_REDIS)
    with TestClient(app) as cliente:
        assert cliente.app.state.ajustes.pepper == PEPPER
    assert (tmp_path / "datos" / UPLOADS_TMP).is_dir()


@pytest.mark.parametrize(
    ("faltante", "error"),
    [
        (VARIABLE_URL_BD, ConfiguracionBDError),
        (VARIABLE_HMAC, ConfiguracionError),
        (VARIABLE_DATOS, ConfiguracionError),
        (VARIABLE_REDIS, ConfiguracionError),
    ],
)
def test_sin_un_dato_el_arranque_falla(
    sin_entorno: pytest.MonkeyPatch,
    tmp_path: Path,
    faltante: str,
    error: type[Exception],
) -> None:
    sin_entorno.setenv(VARIABLE_URL_BD, URL_SIN_SERVIDOR)
    sin_entorno.setenv(VARIABLE_HMAC, PEPPER.decode())
    sin_entorno.setenv(VARIABLE_DATOS, str(tmp_path / "datos"))
    sin_entorno.setenv(VARIABLE_REDIS, URL_REDIS)
    sin_entorno.delenv(faltante)
    with pytest.raises(error, match=faltante) as capturado, TestClient(crear_app()):
        pass  # pragma: no cover
    assert CONTRASENA_BD not in str(capturado.value)
    assert PEPPER.decode() not in str(capturado.value)


def test_un_pepper_corto_falla_al_arrancar_sin_mostrarlo(
    sin_entorno: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sin_entorno.setenv(VARIABLE_URL_BD, URL_SIN_SERVIDOR)
    sin_entorno.setenv(VARIABLE_HMAC, PEPPER_CORTO)
    sin_entorno.setenv(VARIABLE_DATOS, str(tmp_path / "datos"))
    sin_entorno.setenv(VARIABLE_REDIS, URL_REDIS)
    with pytest.raises(ConfiguracionError) as capturado, TestClient(crear_app()):
        pass  # pragma: no cover
    assert PEPPER_CORTO not in str(capturado.value)


@pytest.mark.parametrize(
    "url",
    [
        # make_url lanza ValueError con el puerto: aquí, un trozo de la contraseña.
        url_cruda(
            "postgresql+psycopg", f"gk_app:{CONTRASENA_BD}", f"def:{CONTRASENA_BD}/gk"
        ),
        f"esto no es una url {CONTRASENA_BD}",
        url_cruda("mysql", f"gk_app:{CONTRASENA_BD}", "127.0.0.1/gk"),
    ],
    ids=["contrasena_en_el_puerto", "no_es_url", "esquema_ajeno"],
)
def test_una_url_invalida_falla_al_arrancar_sin_mostrarla(
    tmp_path: Path, url: str
) -> None:
    app = crear_app(
        Ajustes(
            url_bd=url, pepper=PEPPER, datos=tmp_path / "datos", url_redis=URL_REDIS
        )
    )
    with pytest.raises(ConfiguracionError) as capturado, TestClient(app):
        pass  # pragma: no cover
    assert CONTRASENA_BD not in str(capturado.value)
    assert capturado.value.__context__ is None
    assert capturado.value.__cause__ is None


def test_si_fallan_los_directorios_no_arranca(tmp_path: Path) -> None:
    (tmp_path / "datos").write_bytes(b"x")
    app = crear_app(
        Ajustes(
            url_bd=URL_SIN_SERVIDOR,
            pepper=PEPPER,
            datos=tmp_path / "datos",
            url_redis=URL_REDIS,
        )
    )
    with pytest.raises(ConfiguracionError), TestClient(app):
        pass  # pragma: no cover


def test_una_ruta_de_datos_relativa_no_arranca_ni_crea_nada(
    sin_entorno: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sin_entorno.chdir(tmp_path)
    sin_entorno.setenv(VARIABLE_URL_BD, URL_SIN_SERVIDOR)
    sin_entorno.setenv(VARIABLE_HMAC, PEPPER.decode())
    sin_entorno.setenv(VARIABLE_DATOS, "relativa")
    sin_entorno.setenv(VARIABLE_REDIS, URL_REDIS)
    with (
        pytest.raises(ConfiguracionError, match=VARIABLE_DATOS),
        TestClient(crear_app()),
    ):
        pass  # pragma: no cover
    assert list(tmp_path.iterdir()) == []


def _arrancar_uvicorn(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "--factory",
            "api.app.principal:crear_app",
            "--no-server-header",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
        ],
        check=False,
        cwd=RAIZ,
        env={"PATH": os.environ["PATH"], **env},
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_uvicorn_termina_con_error_y_sin_mostrar_valores(tmp_path: Path) -> None:
    # Con `lifespan=auto`, uvicorn sigue arrancando si cree que la app no soporta lifespan:
    # esta prueba comprueba que el proceso real sí muere.
    salida = _arrancar_uvicorn(
        {
            VARIABLE_URL_BD: URL_SIN_SERVIDOR,
            VARIABLE_HMAC: PEPPER_CORTO,
            VARIABLE_DATOS: str(tmp_path / "datos"),
        }
    )
    assert salida.returncode != 0
    texto = salida.stdout + salida.stderr
    assert VARIABLE_HMAC in texto
    assert PEPPER_CORTO not in texto
    assert CONTRASENA_BD not in texto
