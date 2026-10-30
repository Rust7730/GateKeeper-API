"""PostgreSQL 16 desechable para las pruebas de la BD (F1.07, diseño §6).

- ``contenedor_postgres`` (sesión): un solo contenedor ``postgres:16`` por sesión de
  pytest (testcontainers). Se crea la primera vez que una prueba lo pide y se destruye al
  terminar la sesión. Su puerto 5432 se publica solo en 127.0.0.1 (CWE-668).
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

Con ``pytest -l`` (showlocals) un fallo en estos fixtures muestra sus variables locales.
Por eso ninguna guarda la contraseña: vive solo en ``contenedor.password`` (el ``repr``
del contenedor no la muestra) y en la ``URL`` (que la oculta), y se lee de ahí cuando
hace falta (CWE-532). Eso no basta cuando falla una conexión: con ``-l`` pytest muestra
también las locales de SQLAlchemy (``cparams``) y psycopg (``conninfo``, ``params``),
que sí la llevan. Por eso ``pytest_runtest_makereport`` reemplaza la contraseña por
``***`` en todos los reportes de ``api/db/`` (setup, prueba y teardown) antes de mostrarlos.

El reaper de testcontainers (ryuk) se crea antes que PostgreSQL con
``arrancar_reaper_en_loopback``, para que su 8080 también quede solo en 127.0.0.1.
"""

import time
from collections.abc import Generator, Iterator

import pytest
from sqlalchemy import Connection, Engine, create_engine
from sqlalchemy.engine import URL
from testcontainers.community.postgres import PostgresContainer

from api.db.tests.soporte_postgres import (
    IMAGEN_POSTGRES,
    IP_PUBLICACION,
    NOMBRE_BD,
    PUERTO_POSTGRES,
    USUARIO_SUPERUSUARIO,
    arrancar_contenedor,
    arrancar_reaper_en_loopback,
    crear_contenedor,
    exigir_docker,
)

_CLAVE_ARRANQUE = pytest.StashKey[float]()
# El contenedor (no la contraseña) para que el saneado de reportes la lea de ahí.
_CLAVE_CONTENEDOR = pytest.StashKey[PostgresContainer]()


@pytest.fixture(scope="session")
def contenedor_postgres(pytestconfig: pytest.Config) -> Iterator[PostgresContainer]:
    """PostgreSQL 16 desechable de la sesión, publicado solo en 127.0.0.1."""
    exigir_docker()
    inicio = time.perf_counter()
    arrancar_reaper_en_loopback()
    contenedor = crear_contenedor()
    pytestconfig.stash[_CLAVE_CONTENEDOR] = contenedor
    arrancar_contenedor(contenedor)
    try:
        pytestconfig.stash[_CLAVE_ARRANQUE] = time.perf_counter() - inicio
        yield contenedor
    finally:
        contenedor.stop()


@pytest.fixture(scope="session")
def url_postgres(contenedor_postgres: PostgresContainer) -> URL:
    """URL ``postgresql+psycopg`` del superusuario de un PostgreSQL 16 desechable.

    El host es la IP donde se publicó el puerto (127.0.0.1), no ``localhost``, que
    podría resolver primero a ``::1`` y ahí no hay nada escuchando.
    """
    return URL.create(
        "postgresql+psycopg",
        username=USUARIO_SUPERUSUARIO,
        password=contenedor_postgres.password,
        host=IP_PUBLICACION,
        port=int(contenedor_postgres.get_exposed_port(PUERTO_POSTGRES)),
        database=NOMBRE_BD,
    )


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


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    """Quita la contraseña del PostgreSQL de las pruebas de cualquier reporte (CWE-532).

    Aplica a las pruebas de ``api/db/`` (las de este conftest). El reporte con
    traceback se convierte en texto solo si la contraseña aparece en él.
    """
    reporte = yield
    contenedor = item.config.stash.get(_CLAVE_CONTENEDOR, None)
    if contenedor is None or not contenedor.password:
        return reporte
    if reporte.longrepr is not None and contenedor.password in str(reporte.longrepr):
        reporte.longrepr = str(reporte.longrepr).replace(contenedor.password, "***")
    reporte.sections = [
        (titulo, texto.replace(contenedor.password, "***"))
        for titulo, texto in reporte.sections
    ]
    return reporte


def pytest_terminal_summary(
    terminalreporter: pytest.TerminalReporter, config: pytest.Config
) -> None:
    """Reporta cuánto tardó en arrancar el contenedor (incluye crear el reaper de testcontainers)."""
    segundos = config.stash.get(_CLAVE_ARRANQUE, None)
    if segundos is not None:
        terminalreporter.write_line(
            f"PostgreSQL desechable ({IMAGEN_POSTGRES}): arranque en {segundos:.2f} s"
        )
