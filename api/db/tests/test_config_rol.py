"""Nombre del rol de la API para la migración 0002 (``rol_app``).

El nombre sale del entorno (``GATEKEEPER_ROL_APP``) con ``gk_app`` por defecto y se valida
antes de tocar la BD: solo un identificador simple de PostgreSQL en minúsculas. Lo que no
cumple se rechaza sin mostrar el valor (CWE-117), en lugar de citarlo o recortarlo: el
nombre termina dentro de un ``GRANT`` y no se arma SQL con texto (CWE-89).
"""

import pytest

from api.db import config
from api.db.config import ConfiguracionBDError, rol_app

VAR_ROL = "GATEKEEPER_ROL_APP"


@pytest.fixture(autouse=True)
def entorno_limpio(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(VAR_ROL, raising=False)


def test_la_variable_tiene_el_nombre_del_diseno() -> None:
    assert config.VARIABLE_ROL_APP == VAR_ROL
    assert config.ROL_APP_POR_DEFECTO == "gk_app"


def test_sin_la_variable_el_rol_es_gk_app() -> None:
    assert rol_app() == "gk_app"


@pytest.mark.parametrize("nombre", ["gk_app", "gk_app_staging", "_rol", "a", "x" * 63])
def test_acepta_un_identificador_simple(
    nombre: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(VAR_ROL, nombre)
    assert rol_app() == nombre


@pytest.mark.parametrize(
    "nombre",
    [
        pytest.param("", id="vacio"),
        pytest.param(" gk_app", id="espacio-inicial"),
        pytest.param("gk_app\n", id="salto-final"),
        pytest.param("GK_APP", id="mayusculas"),
        pytest.param("gk-app", id="guion"),
        pytest.param("gk app", id="espacio"),
        pytest.param('gk_app"; DROP TABLE archivo; --', id="inyeccion"),
        pytest.param("gk_app; GRANT ALL", id="punto-y-coma"),
        pytest.param('"gk_app"', id="ya-citado"),
        pytest.param("1gk", id="empieza-con-digito"),
        pytest.param("x" * 64, id="64-caracteres"),
        pytest.param("pg_monitor", id="reservado-pg"),
        pytest.param("public", id="public"),
        pytest.param("gk_áp", id="no-ascii"),
        pytest.param("gk\x00app", id="nul"),
    ],
)
def test_rechaza_lo_que_no_es_un_identificador_simple(
    nombre: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # monkeypatch.setenv no acepta NUL: se prueba la validación directamente.
    if "\x00" in nombre:
        with pytest.raises(ConfiguracionBDError) as error:
            config._validar_rol(nombre)
    else:
        monkeypatch.setenv(VAR_ROL, nombre)
        with pytest.raises(ConfiguracionBDError) as error:
            rol_app()
    mensaje = str(error.value)
    assert VAR_ROL in mensaje
    if nombre:
        assert nombre not in mensaje, "el mensaje no debe repetir el valor (CWE-117)"
