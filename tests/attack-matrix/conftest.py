"""Fixtures de la matriz de ataque.

Los de PostgreSQL son los de gk-db. ``pytest_runtest_makereport`` viene con ellos porque un hook de
conftest solo aplica a las pruebas de su directorio: sin él, un fallo de aquí con ``pytest -l``
mostraría la contraseña del PostgreSQL de las pruebas (CWE-532).
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from soporte_matriz import Banco, ClienteMatriz, abrir_banco
from sqlalchemy.engine import URL

from api.db.tests.conftest import (  # noqa: F401
    bd_limpia,
    contenedor_postgres,
    motor_postgres,
    pytest_runtest_makereport,
    url_postgres,
    url_repositorios,
)


@pytest.fixture
def banco(bd_limpia: URL, tmp_path: Path) -> Iterator[Banco]:  # noqa: F811
    with abrir_banco(bd_limpia, tmp_path) as abierto:
        yield abierto


@pytest.fixture
def cliente(banco: Banco) -> Iterator[ClienteMatriz]:
    """La API tal como arranca en producción: sin ninguna costura de prueba."""
    with banco.api() as abierto:
        yield abierto
