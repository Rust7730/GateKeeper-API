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
- ``url_repositorios`` (sesión): URL de una base aparte en el mismo contenedor, creada
  **con la migración** y no con ``create_all``, para que los repositorios se prueben
  contra el esquema real. Va aparte porque aquí sí se hace ``COMMIT``: la concurrencia
  solo se ve entre transacciones confirmadas.
- ``rol_app`` (sesión): crea en el contenedor el rol de la API ``gk_app`` con contraseña
  aleatoria y los atributos del contrato (``ATRIBUTOS_ROL_APP``), como lo hará la
  infraestructura. Los roles son del clúster: sirve para todas las bases de la sesión.
  La migración 0002 lo exige, así que todo fixture que migra a ``head`` depende de él.
- ``sesiones`` (por prueba, asíncrono): fábrica de sesiones sobre esa base **conectada como
  ``gk_app``**, igual que la API en producción: todas las pruebas de los repositorios
  demuestran también que los permisos de la 0002 bastan. Antes de cada prueba se vacían las
  tablas (``TRUNCATE``, como dueño). Las pruebas asíncronas corren con el plugin de
  ``anyio`` (``pytest.mark.anyio``), que ya viene instalado.
- ``sesiones_dueno`` (por prueba, asíncrono): lo mismo, pero con el dueño del esquema. Solo
  para lo que ``gk_app`` no puede hacer a propósito, como ``ANALYZE`` (que con otro rol
  se salta con una advertencia, sin fallar) o medir la latencia contra el dueño.

Sin Docker, o si el contenedor no arranca, las pruebas que piden estos fixtures
**fallan** con un mensaje claro (sin la contraseña, aunque testcontainers la incluya en
su error). Nunca se omiten ni se cambian por SQLite: tipos, bloqueos y ``RETURNING`` se
comportan distinto y la prueba no demostraría nada.

Con ``pytest -l`` (showlocals) un fallo en estos fixtures muestra sus variables locales.
Por eso ninguna guarda la contraseña: vive solo en ``contenedor.password`` (el ``repr``
del contenedor no la muestra) y en la ``URL`` (que la oculta), y se lee de ahí cuando
hace falta (CWE-532). La de ``gk_app`` vive en ``CredencialRol.password``, que tampoco
sale en el ``repr``. Eso no basta cuando falla una conexión: con ``-l`` pytest muestra
también las locales de SQLAlchemy (``cparams``) y psycopg (``conninfo``, ``params``),
que sí la llevan. Por eso ``pytest_runtest_makereport`` reemplaza las dos contraseñas por
``***`` en todos los reportes de ``api/db/`` (setup, prueba y teardown) antes de mostrarlos.

El reaper de testcontainers (ryuk) se crea antes que PostgreSQL con
``arrancar_reaper_en_loopback``, para que su 8080 también quede solo en 127.0.0.1.
"""

import time
from collections.abc import AsyncIterator, Generator, Iterator

import pytest
from alembic import command
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from testcontainers.community.postgres import PostgresContainer

from api.db.config import VARIABLE_URL_MIGRACION
from api.db.sesion import crear_motor, fabrica_sesiones
from api.db.tests.soporte_postgres import (
    IMAGEN_POSTGRES,
    IP_PUBLICACION,
    NOMBRE_BD,
    PUERTO_POSTGRES,
    ROL_APP,
    USUARIO_SUPERUSUARIO,
    CredencialRol,
    arrancar_contenedor,
    arrancar_reaper_en_loopback,
    borrar_bd,
    config_alembic,
    crear_bd,
    crear_contenedor,
    crear_rol_con_contrasena,
    exigir_docker,
)

BD_REPOSITORIOS = "gk_repositorios"

_CLAVE_ARRANQUE = pytest.StashKey[float]()
# El contenedor (no la contraseña) para que el saneado de reportes la lea de ahí.
_CLAVE_CONTENEDOR = pytest.StashKey[PostgresContainer]()
# La credencial de gk_app, por lo mismo.
_CLAVE_ROL_APP = pytest.StashKey[CredencialRol]()


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


@pytest.fixture(scope="session")
def rol_app(pytestconfig: pytest.Config, motor_postgres: Engine) -> CredencialRol:
    """Rol ``gk_app`` del clúster de la sesión, con contraseña aleatoria."""
    credencial = crear_rol_con_contrasena(motor_postgres, ROL_APP)
    pytestconfig.stash[_CLAVE_ROL_APP] = credencial
    return credencial


@pytest.fixture(scope="session")
def url_repositorios(
    motor_postgres: Engine, url_postgres: URL, rol_app: CredencialRol
) -> Iterator[URL]:
    """Base con el esquema de la migración, para las pruebas que confirman transacciones."""
    crear_bd(motor_postgres, BD_REPOSITORIOS)
    url = url_postgres.set(database=BD_REPOSITORIOS)
    try:
        with pytest.MonkeyPatch.context() as parche:
            parche.setenv(
                VARIABLE_URL_MIGRACION, url.render_as_string(hide_password=False)
            )
            command.upgrade(config_alembic(), "head")
        yield url
    finally:
        borrar_bd(motor_postgres, BD_REPOSITORIOS)


@pytest.fixture
def bd_limpia(url_repositorios: URL) -> URL:
    """Vacía las tablas antes de la prueba; devuelve la URL de la base."""
    motor = create_engine(url_repositorios)
    try:
        with motor.begin() as con:
            con.execute(
                text("TRUNCATE resultado_analisis, archivo, api_key, aplicacion")
            )
    finally:
        motor.dispose()
    return url_repositorios


@pytest.fixture
def anyio_backend() -> str:
    """Las pruebas asíncronas corren sobre asyncio, igual que la API."""
    return "asyncio"


@pytest.fixture
def url_gk_app(bd_limpia: URL, rol_app: CredencialRol) -> URL:
    """La base de los repositorios, ya vacía, conectando como ``gk_app``."""
    return bd_limpia.set(username=rol_app.nombre, password=rol_app.password)


@pytest.fixture
async def motor(url_gk_app: URL) -> AsyncIterator[AsyncEngine]:
    """Motor de la API: ``crear_motor`` conectado como ``gk_app``."""
    motor_asincrono = crear_motor(url_gk_app)
    try:
        yield motor_asincrono
    finally:
        await motor_asincrono.dispose()


@pytest.fixture
def sesiones(motor: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return fabrica_sesiones(motor)


@pytest.fixture
async def motor_dueno(bd_limpia: URL) -> AsyncIterator[AsyncEngine]:
    """Motor con el dueño del esquema, para lo que ``gk_app`` no debe poder hacer."""
    motor_asincrono = crear_motor(bd_limpia)
    try:
        yield motor_asincrono
    finally:
        await motor_asincrono.dispose()


@pytest.fixture
def sesiones_dueno(motor_dueno: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return fabrica_sesiones(motor_dueno)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    """Quita las contraseñas de las pruebas de cualquier reporte (CWE-532).

    Las del superusuario del contenedor y de ``gk_app``. Aplica a las pruebas de
    ``api/db/`` (las de este conftest). El reporte con traceback se convierte en texto
    solo si alguna contraseña aparece en él.
    """
    reporte = yield
    contenedor = item.config.stash.get(_CLAVE_CONTENEDOR, None)
    credencial = item.config.stash.get(_CLAVE_ROL_APP, None)
    for secreto in (
        contenedor.password if contenedor is not None else None,
        credencial.password if credencial is not None else None,
    ):
        if not secreto:
            continue
        if reporte.longrepr is not None and secreto in str(reporte.longrepr):
            reporte.longrepr = str(reporte.longrepr).replace(secreto, "***")
        reporte.sections = [
            (titulo, texto.replace(secreto, "***"))
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
