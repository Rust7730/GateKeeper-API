"""Pruebas de la configuración de la BD por entorno (F1.07, commit 2).

Las URLs salen solo del entorno: sin valor por defecto, con un error que nombra la
variable sin mostrar su valor, y solo con el esquema ``postgresql+psycopg://`` (K23).
"""

import pytest

from api.db import config
from api.db.config import ConfiguracionBDError, url_bd, url_migraciones

VAR_APP = "GATEKEEPER_DATABASE_URL"
VAR_MIGRACION = "GATEKEEPER_DATABASE_URL_MIGRACION"

# Credenciales obviamente falsas. La contraseña es un centinela para comprobar que
# ningún mensaje de error muestra el valor de la variable.
CENTINELA = "NO-MOSTRAR-ESTO"
URL_APP = f"postgresql+psycopg://gk_app:{CENTINELA}@bd.invalid:5432/gatekeeper"
URL_MIGRACION = f"postgresql+psycopg://gk_dueno:{CENTINELA}@bd.invalid:5432/gatekeeper"

FUNCIONES = [
    pytest.param(url_bd, VAR_APP, URL_APP, id="url_bd"),
    pytest.param(url_migraciones, VAR_MIGRACION, URL_MIGRACION, id="url_migraciones"),
]


@pytest.fixture(autouse=True)
def entorno_limpio(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cada prueba parte sin ninguna de las dos variables."""
    monkeypatch.delenv(VAR_APP, raising=False)
    monkeypatch.delenv(VAR_MIGRACION, raising=False)


def test_las_variables_tienen_el_nombre_del_diseno() -> None:
    assert config.VARIABLE_URL_BD == VAR_APP
    assert config.VARIABLE_URL_MIGRACION == VAR_MIGRACION


def test_el_error_es_un_runtimeerror() -> None:
    assert issubclass(ConfiguracionBDError, RuntimeError)


@pytest.mark.parametrize(("funcion", "variable", "url"), FUNCIONES)
def test_devuelve_la_url_del_entorno(monkeypatch, funcion, variable, url) -> None:
    monkeypatch.setenv(variable, url)
    assert funcion() == url


@pytest.mark.parametrize(("funcion", "variable", "url"), FUNCIONES)
def test_sin_variable_falla_y_la_nombra(funcion, variable, url) -> None:
    with pytest.raises(ConfiguracionBDError, match=variable):
        funcion()


@pytest.mark.parametrize("vacio", ["", "   ", "\t\n"])
@pytest.mark.parametrize(("funcion", "variable", "url"), FUNCIONES)
def test_variable_vacia_falla_y_la_nombra(
    monkeypatch, funcion, variable, url, vacio
) -> None:
    monkeypatch.setenv(variable, vacio)
    with pytest.raises(ConfiguracionBDError, match=variable):
        funcion()


@pytest.mark.parametrize(
    "esquema",
    [
        "postgresql://",
        "postgres://",
        "postgresql+psycopg2://",
        "postgresql+asyncpg://",
        "postgresql+psycopg:/",
        "POSTGRESQL+PSYCOPG://",
        "sqlite+aiosqlite:///",
        "mysql+aiomysql://",
        " postgresql+psycopg://",
    ],
)
@pytest.mark.parametrize(("funcion", "variable", "url"), FUNCIONES)
def test_rechaza_otro_esquema_sin_mostrar_el_valor(
    monkeypatch, funcion, variable, url, esquema
) -> None:
    resto = url.split("://", 1)[1]
    monkeypatch.setenv(variable, esquema + resto)
    with pytest.raises(ConfiguracionBDError, match=variable) as error:
        funcion()
    mensaje = str(error.value)
    assert "postgresql+psycopg://" in mensaje
    assert CENTINELA not in mensaje
    assert resto not in mensaje


def test_cada_funcion_lee_solo_su_variable(monkeypatch) -> None:
    """La API nunca debe caer en la URL del dueño, ni Alembic en la de gk_app."""
    monkeypatch.setenv(VAR_MIGRACION, URL_MIGRACION)
    with pytest.raises(ConfiguracionBDError, match=VAR_APP):
        url_bd()

    monkeypatch.delenv(VAR_MIGRACION)
    monkeypatch.setenv(VAR_APP, URL_APP)
    with pytest.raises(ConfiguracionBDError, match=VAR_MIGRACION):
        url_migraciones()


def test_el_error_no_encadena_otra_excepcion_con_el_valor(monkeypatch) -> None:
    """Ni __cause__ ni __context__ deben arrastrar el valor a un traceback."""
    monkeypatch.setenv(VAR_APP, "postgresql://gk_app:" + CENTINELA + "@bd.invalid/x")
    with pytest.raises(ConfiguracionBDError) as error:
        url_bd()
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert CENTINELA not in repr(error.value.args)
