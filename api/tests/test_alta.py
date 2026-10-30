"""Alta de aplicación y key desde la terminal (diseño §6), contra PostgreSQL real."""

import logging
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from api.app import alta
from api.app.ajustes import VARIABLE_DATOS, VARIABLE_HMAC, Ajustes
from api.app.autenticacion import AplicacionAutenticada, calcular_hash, generar_key
from api.app.principal import crear_app
from api.app.v1 import crear_router_v1
from api.db.config import VARIABLE_URL_BD
from api.db.modelos import ApiKey, Aplicacion
from api.tests.soporte_api import url_cruda, url_sin_servidor

RAIZ = Path(__file__).resolve().parents[2]
FORMATO_CREDENCIAL = re.compile(r"gk_[0-9a-f]{12}\.[A-Za-z0-9_-]{43}")
# token_urlsafe y no token_hex: una prueba la usa de puerto y no debe ser un número.
CONTRASENA_FALSA = secrets.token_urlsafe(24)
URL_SIN_SERVIDOR = url_sin_servidor(CONTRASENA_FALSA)
PEPPER_VALIDO = secrets.token_hex(16)
PEPPER_CORTO = secrets.token_hex(15)


@pytest.fixture
def pepper() -> bytes:
    return secrets.token_hex(32).encode()


@pytest.fixture
def entorno(
    bd_limpia: URL, pepper: bytes, monkeypatch: pytest.MonkeyPatch
) -> pytest.MonkeyPatch:
    monkeypatch.setenv(VARIABLE_URL_BD, bd_limpia.render_as_string(hide_password=False))
    monkeypatch.setenv(VARIABLE_HMAC, pepper.decode())
    monkeypatch.delenv(VARIABLE_DATOS, raising=False)
    return monkeypatch


def _filas(url: URL) -> tuple[list[tuple[str, bool]], list[tuple[str, str]]]:
    motor = create_engine(url)
    try:
        with motor.connect() as con:
            aplicaciones = con.execute(
                select(Aplicacion.nombre, Aplicacion.activa)
            ).all()
            keys = con.execute(select(ApiKey.prefijo, ApiKey.hash)).all()
    finally:
        motor.dispose()
    return [tuple(a) for a in aplicaciones], [tuple(k) for k in keys]


@pytest.mark.usefixtures("entorno")
def test_crea_aplicacion_activa_y_key_con_su_hmac(
    bd_limpia: URL, pepper: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    assert alta.main(["Portal de Pagos"]) == 0

    key = capsys.readouterr().out.strip()
    assert FORMATO_CREDENCIAL.fullmatch(key)
    aplicaciones, keys = _filas(bd_limpia)
    assert aplicaciones == [("Portal de Pagos", True)]
    assert keys == [(key.split(".")[0], calcular_hash(pepper, key))]


@pytest.mark.usefixtures("entorno")
def test_la_key_se_imprime_una_sola_vez_y_solo_en_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert alta.main(["portal"]) == 0
    salida = capsys.readouterr()
    key = salida.out.strip()
    secreto = key.split(".")[1]
    assert salida.out == f"{key}\n"
    assert (salida.out + salida.err).count(secreto) == 1


@pytest.mark.usefixtures("entorno")
def test_la_key_impresa_autentica_en_la_api(
    bd_limpia: URL,
    pepper: bytes,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert alta.main(["portal"]) == 0
    key = capsys.readouterr().out.strip()

    app = crear_app(Ajustes(url_bd=bd_limpia, pepper=pepper, datos=tmp_path / "d"))
    router = crear_router_v1()

    @router.get("/_prueba")
    async def _prueba(aplicacion_id: AplicacionAutenticada) -> str:
        return str(aplicacion_id)

    app.include_router(router)
    with TestClient(app) as cliente:
        respuesta = cliente.get(
            "/v1/_prueba", headers={"Authorization": f"Bearer {key}"}
        )
    assert respuesta.status_code == 200


@pytest.mark.usefixtures("entorno")
def test_la_key_ni_su_hash_se_registran_en_logs(
    pepper: bytes,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        assert alta.main(["portal"]) == 0
    assert caplog.records, "el nivel DEBUG debe capturar algo para que esto compruebe"
    key = capsys.readouterr().out.strip()
    assert key.split(".")[1] not in caplog.text
    assert calcular_hash(pepper, key) not in caplog.text


@pytest.mark.parametrize("repetido", ["portal", "PORTAL", "Portal"])
@pytest.mark.usefixtures("entorno")
def test_nombre_repetido_da_mensaje_claro_y_salida_distinta_de_0(
    bd_limpia: URL, capsys: pytest.CaptureFixture[str], repetido: str
) -> None:
    assert alta.main(["portal"]) == 0
    capsys.readouterr()

    codigo = alta.main([repetido])

    salida = capsys.readouterr()
    assert codigo not in (0, None)
    assert salida.out == ""
    assert "Ya existe" in salida.err
    assert "Traceback" not in salida.err
    aplicaciones, keys = _filas(bd_limpia)
    assert aplicaciones == [("portal", True)]
    assert len(keys) == 1


@pytest.mark.parametrize(
    "nombre",
    ["", " portal", "portal ", "a" * 101, "con\x07control", "con\x85c1", "   "],
)
@pytest.mark.usefixtures("entorno")
def test_nombre_invalido_no_imprime_key_ni_deja_filas(
    bd_limpia: URL, capsys: pytest.CaptureFixture[str], nombre: str
) -> None:
    codigo = alta.main([nombre])

    salida = capsys.readouterr()
    assert codigo not in (0, None)
    assert salida.out == ""
    assert "nombre" in salida.err
    assert _filas(bd_limpia) == ([], [])


@pytest.mark.parametrize("nombre", ["con\x00nul", "con\udcffsurrogate"])
@pytest.mark.usefixtures("entorno")
def test_nombre_que_la_bd_no_puede_recibir_falla_sin_traceback(
    bd_limpia: URL, capsys: pytest.CaptureFixture[str], nombre: str
) -> None:
    # Un nombre con bytes que no son UTF-8 llega por argv como surrogate.
    codigo = alta.main([nombre])

    salida = capsys.readouterr()
    assert codigo not in (0, None)
    assert salida.out == ""
    assert "nombre" in salida.err
    assert nombre not in salida.err.encode("utf-8", "replace").decode()
    assert _filas(bd_limpia) == ([], [])


@pytest.mark.usefixtures("entorno")
def test_el_error_no_repite_el_nombre_recibido(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Un nombre con secuencias de escape no debe llegar a la terminal de quien lo corre.
    alta.main(["\x1b[31mportal"])
    assert "\x1b" not in capsys.readouterr().err


@pytest.mark.usefixtures("entorno")
def test_choque_de_prefijo_revierte_tambien_la_aplicacion(
    bd_limpia: URL,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert alta.main(["primera"]) == 0
    key = capsys.readouterr().out.strip()
    prefijo = key.split(".")[0]
    _, otra_key = generar_key()
    monkeypatch.setattr(
        alta, "generar_key", lambda: (prefijo, f"{prefijo}.{otra_key.split('.')[1]}")
    )

    codigo = alta.main(["segunda"])

    salida = capsys.readouterr()
    assert codigo not in (0, None)
    assert salida.out == ""
    aplicaciones, keys = _filas(bd_limpia)
    assert aplicaciones == [("primera", True)]
    assert len(keys) == 1


@pytest.mark.usefixtures("entorno")
def test_si_falla_la_escritura_de_la_key_no_queda_nada(
    bd_limpia: URL,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def _falla(*_: object) -> None:
        raise RuntimeError("fallo después de insertar")

    monkeypatch.setattr(alta, "crear_api_key", _falla)
    codigo = alta.main(["portal"])
    salida = capsys.readouterr()
    assert codigo not in (0, None)
    assert salida.out == ""
    assert "RuntimeError" in salida.err
    assert "fallo después de insertar" not in salida.err
    assert _filas(bd_limpia) == ([], [])


class _FabricaQueNoConfirma:
    """Fábrica cuya transacción se revierte y falla justo donde iría el COMMIT."""

    def __init__(self, fabrica: async_sessionmaker[AsyncSession]) -> None:
        self._contexto = fabrica.begin()

    def begin(self) -> "_FabricaQueNoConfirma":
        return self

    async def __aenter__(self) -> AsyncSession:
        return await self._contexto.__aenter__()

    async def __aexit__(self, *_: object) -> None:
        error = RuntimeError("fallo al confirmar")
        await self._contexto.__aexit__(RuntimeError, error, None)
        raise error


@pytest.mark.usefixtures("entorno")
def test_si_falla_el_commit_no_se_imprime_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    original = alta.fabrica_sesiones
    monkeypatch.setattr(
        alta, "fabrica_sesiones", lambda m: _FabricaQueNoConfirma(original(m))
    )
    assert alta.main(["portal"]) not in (0, None)
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("argumentos", [[], ["uno", "dos"]])
def test_uso_incorrecto_sale_con_2(
    argumentos: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert alta.main(argumentos) == 2
    salida = capsys.readouterr()
    assert salida.out == ""
    assert "api.app.alta" in salida.err


def test_sin_pepper_falla_sin_mostrar_la_url(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(VARIABLE_URL_BD, URL_SIN_SERVIDOR)
    monkeypatch.delenv(VARIABLE_HMAC, raising=False)

    codigo = alta.main(["portal"])

    salida = capsys.readouterr()
    assert codigo not in (0, None)
    assert VARIABLE_HMAC in salida.err
    assert CONTRASENA_FALSA not in salida.err


def test_pepper_corto_falla_sin_mostrarlo(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(VARIABLE_URL_BD, URL_SIN_SERVIDOR)
    monkeypatch.setenv(VARIABLE_HMAC, PEPPER_CORTO)

    codigo = alta.main(["portal"])

    salida = capsys.readouterr()
    assert codigo not in (0, None)
    assert PEPPER_CORTO[:12] not in salida.err


def test_sin_url_falla(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(VARIABLE_URL_BD, raising=False)
    monkeypatch.setenv(VARIABLE_HMAC, PEPPER_VALIDO)

    codigo = alta.main(["portal"])

    assert codigo not in (0, None)
    assert VARIABLE_URL_BD in capsys.readouterr().err


def test_url_que_no_se_puede_leer_no_muestra_ningun_trozo(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(
        VARIABLE_URL_BD,
        url_cruda(
            "postgresql+psycopg", f"gk:{CONTRASENA_FALSA}", f"def:{CONTRASENA_FALSA}/gk"
        ),
    )
    monkeypatch.setenv(VARIABLE_HMAC, PEPPER_VALIDO)

    codigo = alta.main(["portal"])

    assert codigo not in (0, None)
    assert CONTRASENA_FALSA not in capsys.readouterr().err


def test_bd_inalcanzable_falla_sin_traceback_ni_credenciales(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(VARIABLE_URL_BD, URL_SIN_SERVIDOR)
    monkeypatch.setenv(VARIABLE_HMAC, PEPPER_VALIDO)

    codigo = alta.main(["portal"])

    salida = capsys.readouterr()
    assert codigo not in (0, None)
    assert salida.out == ""
    assert "Traceback" not in salida.err
    assert CONTRASENA_FALSA not in salida.err


@pytest.mark.usefixtures("entorno")
def test_no_crea_directorios_de_datos(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # El alta solo necesita BD y pepper: GATEKEEPER_DATOS no aplica aquí (diseño §6).
    monkeypatch.chdir(tmp_path)
    assert alta.main(["portal"]) == 0
    assert list(tmp_path.iterdir()) == []


def _proceso(env: dict[str, str], *argumentos: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "api.app.alta", *argumentos],
        check=False,
        cwd=RAIZ,
        env={"PATH": os.environ["PATH"], **env},
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_como_modulo_imprime_la_key_y_repite_con_error(
    bd_limpia: URL, pepper: bytes
) -> None:
    env = {
        VARIABLE_URL_BD: bd_limpia.render_as_string(hide_password=False),
        VARIABLE_HMAC: pepper.decode(),
    }

    primera = _proceso(env, "portal")
    assert primera.returncode == 0
    assert FORMATO_CREDENCIAL.fullmatch(primera.stdout.strip())
    assert primera.stdout.strip().split(".")[1] not in primera.stderr

    segunda = _proceso(env, "PORTAL")
    assert segunda.returncode != 0
    assert segunda.stdout == ""
    assert "Ya existe" in segunda.stderr
    assert "Traceback" not in segunda.stderr
