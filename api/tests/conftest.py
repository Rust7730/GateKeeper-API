"""Fixtures de BD de las pruebas de la API: las de gk-db, sin copiarlas.

``pytest_plugins`` no se admite fuera del conftest raíz, así que se importan: pytest las
registra también para ``api/tests/``. Se paga un precio: cada conftest tiene su propia copia
de los fixtures de sesión, y una corrida que junta ``api/db/tests`` y ``api/tests`` arranca
dos contenedores desechables.

``pytest_runtest_makereport`` viene con ellos porque un hook de conftest solo aplica a las
pruebas de su directorio: sin él, un fallo aquí con ``pytest -l`` mostraría la contraseña
del PostgreSQL de las pruebas (CWE-532). ``pytest_terminal_summary`` no se importa: ya
aplica a toda la sesión y se imprimiría dos veces.

Redis (K59): un contenedor por sesión (``soporte_redis.py``), vaciado antes de cada prueba que
pide ``url_redis``: sin vaciarlo, el límite por IP se arrastraría de una prueba a otra. Sus
contraseñas las sanea ``_SaneoRedis``, registrado como plugin.
"""

from collections.abc import Generator, Iterator

import pytest

from api.db.tests.conftest import (  # noqa: F401
    anyio_backend,
    bd_limpia,
    contenedor_postgres,
    motor,
    motor_postgres,
    pytest_runtest_makereport,
    rol_app,
    sesiones,
    url_gk_app,
    url_postgres,
    url_repositorios,
)
from api.tests.soporte_redis import SECRETOS, RedisDePrueba, redis_desechable


class _SaneoRedis:
    """Cambia por ``***`` las contraseñas del Redis de pruebas en todo reporte (CWE-532)."""

    @pytest.hookimpl(wrapper=True)
    def pytest_runtest_makereport(
        self, item: pytest.Item, call: pytest.CallInfo[None]
    ) -> Generator[None, pytest.TestReport, pytest.TestReport]:
        reporte = yield
        for secreto in sorted(SECRETOS, key=len, reverse=True):
            if reporte.longrepr is not None and secreto in str(reporte.longrepr):
                reporte.longrepr = str(reporte.longrepr).replace(secreto, "***")
            reporte.sections = [
                (titulo, texto.replace(secreto, "***"))
                for titulo, texto in reporte.sections
            ]
        return reporte


def pytest_configure(config: pytest.Config) -> None:
    if not config.pluginmanager.has_plugin("saneo-redis-api"):
        config.pluginmanager.register(_SaneoRedis(), "saneo-redis-api")


@pytest.fixture(scope="session")
def redis_prueba(contenedor_postgres) -> Iterator[RedisDePrueba]:  # noqa: F811
    """Redis de la sesión. Pide antes el PostgreSQL para que el reaper lo cree gk-db."""
    with redis_desechable() as desechable:
        yield desechable


@pytest.fixture
def url_redis(redis_prueba: RedisDePrueba) -> str:
    """URL del usuario de la API en el Redis de la sesión, ya vacío."""
    admin = redis_prueba.admin()
    try:
        admin.flushall()
    finally:
        admin.close()
    return redis_prueba.url_api()
