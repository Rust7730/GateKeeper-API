"""Fixtures de BD de las pruebas de la API: las de gk-db, sin copiarlas.

``pytest_plugins`` no se admite fuera del conftest raíz, así que se importan: pytest las
registra también para ``api/tests/``. Se paga un precio: cada conftest tiene su propia copia
de los fixtures de sesión, y una corrida que junta ``api/db/tests`` y ``api/tests`` arranca
dos contenedores desechables.

``pytest_runtest_makereport`` viene con ellos porque un hook de conftest solo aplica a las
pruebas de su directorio: sin él, un fallo aquí con ``pytest -l`` mostraría la contraseña
del PostgreSQL de las pruebas (CWE-532). ``pytest_terminal_summary`` no se importa: ya
aplica a toda la sesión y se imprimiría dos veces.
"""

from api.db.tests.conftest import (  # noqa: F401
    anyio_backend,
    bd_limpia,
    contenedor_postgres,
    motor,
    motor_postgres,
    pytest_runtest_makereport,
    sesiones,
    url_postgres,
    url_repositorios,
)
