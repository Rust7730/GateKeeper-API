"""PostgreSQL 16 desechable para las pruebas de la BD (F1.07, diseño §6).

- Un solo contenedor ``postgres:16`` por sesión de pytest (testcontainers). Se crea la
  primera vez que una prueba lo pide y se destruye al terminar la sesión.
- ``url_postgres`` (sesión): ``sqlalchemy.engine.URL`` del superusuario del contenedor,
  con el driver ``postgresql+psycopg``. Es un objeto ``URL`` y no un ``str`` a propósito:
  su ``str()`` y su ``repr()`` ocultan la contraseña, así que no se filtra en un
  traceback ni en un log. Si hace falta el texto completo (p. ej. para una variable de
  entorno de Alembic), usa ``url.render_as_string(hide_password=False)`` y no lo
  imprimas. La contraseña es aleatoria en cada sesión; no hay credenciales en el código.
- ``motor_postgres`` (sesión): ``Engine`` síncrono de SQLAlchemy sobre esa URL.
- ``conexion`` (por prueba): una conexión dentro de una transacción que se revierte al
  terminar la prueba, así que nada de lo que escribe (ni el DDL) llega a la siguiente.
  La prueba no debe hacer ``commit()``; para esperar un error de la BD sin perder la
  transacción, usa ``conexion.begin_nested()`` (savepoint).

Sin Docker, o si el contenedor no arranca, las pruebas que piden estos fixtures
**fallan** con un mensaje claro (sin la contraseña, aunque testcontainers la incluya en
su error). Nunca se omiten ni se cambian por SQLite: tipos, bloqueos y ``RETURNING`` se
comportan distinto y la prueba no demostraría nada.
"""

import secrets
import time
from collections.abc import Iterator

import pytest
from sqlalchemy import Connection, Engine, create_engine
from sqlalchemy.engine import URL
from testcontainers.community.postgres import PostgresContainer

from api.db.tests.soporte_postgres import (
    IMAGEN_POSTGRES,
    NOMBRE_BD,
    PUERTO_POSTGRES,
    USUARIO_SUPERUSUARIO,
    arrancar_contenedor,
    exigir_docker,
)

_CLAVE_ARRANQUE = pytest.StashKey[float]()


@pytest.fixture(scope="session")
def url_postgres(pytestconfig: pytest.Config) -> Iterator[URL]:
    """URL ``postgresql+psycopg`` del superusuario de un PostgreSQL 16 desechable."""
    exigir_docker()
    contrasena = secrets.token_urlsafe(24)
    contenedor = PostgresContainer(
        IMAGEN_POSTGRES,
        port=PUERTO_POSTGRES,
        username=USUARIO_SUPERUSUARIO,
        password=contrasena,
        dbname=NOMBRE_BD,
        driver="psycopg",
    )
    inicio = time.perf_counter()
    arrancar_contenedor(contenedor, contrasena)
    try:
        pytestconfig.stash[_CLAVE_ARRANQUE] = time.perf_counter() - inicio
        yield URL.create(
            "postgresql+psycopg",
            username=USUARIO_SUPERUSUARIO,
            password=contrasena,
            host=contenedor.get_container_host_ip(),
            port=int(contenedor.get_exposed_port(PUERTO_POSTGRES)),
            database=NOMBRE_BD,
        )
    finally:
        contenedor.stop()


@pytest.fixture(scope="session")
def motor_postgres(url_postgres: URL) -> Iterator[Engine]:
    """``Engine`` síncrono (SQLAlchemy 2.0 + psycopg 3) sobre el contenedor de la sesión."""
    motor = create_engine(url_postgres)
    try:
        yield motor
    finally:
        motor.dispose()


@pytest.fixture
def conexion(motor_postgres: Engine) -> Iterator[Connection]:
    """Conexión dentro de una transacción que se revierte al terminar la prueba."""
    with motor_postgres.connect() as con:
        transaccion = con.begin()
        try:
            yield con
        finally:
            if transaccion.is_active:
                transaccion.rollback()


def pytest_terminal_summary(
    terminalreporter: pytest.TerminalReporter, config: pytest.Config
) -> None:
    """Reporta cuánto tardó en arrancar el contenedor (incluye el reaper de testcontainers)."""
    segundos = config.stash.get(_CLAVE_ARRANQUE, None)
    if segundos is not None:
        terminalreporter.write_line(
            f"PostgreSQL desechable ({IMAGEN_POSTGRES}): arranque en {segundos:.2f} s"
        )
