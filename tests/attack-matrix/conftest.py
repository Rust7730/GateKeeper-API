"""Fixtures de la matriz de ataque.

Los de PostgreSQL son los de gk-db. ``pytest_runtest_makereport`` viene con ellos porque un hook de
conftest solo aplica a las pruebas de su directorio: sin él, un fallo de aquí con ``pytest -l``
mostraría la contraseña del PostgreSQL de las pruebas (CWE-532). Las contraseñas propias de la
matriz (Redis, el rol de prueba de ``gk_app``) las sanea ``_SaneoMatriz``, registrado como plugin.

Redis (K59): un contenedor por sesión, vaciado antes de cada prueba que usa ``banco``. Sin vaciarlo,
el límite por IP (60/min) se arrastraría de una prueba a otra.
"""

from collections.abc import Generator, Iterator
from pathlib import Path

import pytest
from soporte_matriz import Banco, ClienteMatriz, abrir_banco
from soporte_redis import SECRETOS, cliente_de, redis_desechable, url_de
from sqlalchemy.engine import URL
from testcontainers.community.redis import RedisContainer

from api.db.tests.conftest import (  # noqa: F401
    bd_limpia,
    contenedor_postgres,
    motor_postgres,
    pytest_runtest_makereport,
    rol_app,
    url_postgres,
    url_repositorios,
)


class _SaneoMatriz:
    """Cambia por ``***`` los secretos de la matriz en todo reporte (CWE-532)."""

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
    if not config.pluginmanager.has_plugin("saneo-matriz"):
        config.pluginmanager.register(_SaneoMatriz(), "saneo-matriz")


@pytest.fixture(scope="session")
def contenedor_redis(contenedor_postgres) -> Iterator[RedisContainer]:  # noqa: F811
    """Redis de la sesión. Pide antes el PostgreSQL para que el reaper lo cree gk-db."""
    with redis_desechable() as contenedor:
        yield contenedor


@pytest.fixture
def url_redis(contenedor_redis: RedisContainer) -> str:
    """URL del Redis de la sesión, ya vacío."""
    cliente = cliente_de(contenedor_redis)
    try:
        cliente.flushall()
    finally:
        cliente.close()
    return url_de(contenedor_redis)


@pytest.fixture
def banco(bd_limpia: URL, tmp_path: Path, url_redis: str) -> Iterator[Banco]:  # noqa: F811
    with abrir_banco(bd_limpia, tmp_path, url_redis) as abierto:
        yield abierto


@pytest.fixture
def cliente(banco: Banco) -> Iterator[ClienteMatriz]:
    """La API tal como arranca en producción: sin ninguna costura de prueba.

    Salvo el reloj del rate limit, que corre 1 s por lectura (``RelojQueCorre``, soporte_matriz.py).
    """
    with banco.api() as abierto:
        yield abierto
