"""Sesión asíncrona de la API: SQLAlchemy 2.0 sobre psycopg 3 (K23).

El motor y la fábrica se crean una sola vez al arrancar la API. ``expire_on_commit`` va
apagado porque, con asyncio, leer un atributo caducado dispararía E/S implícita y fallaría.

Lo que fija ``crear_motor``:

- ``hide_parameters``: los valores de una consulta no salen en el texto de un error ni en
  un log (CWE-532). Solo se quita lo que agrega SQLAlchemy: el mensaje de PostgreSQL sigue
  trayendo datos, y por eso ``repositorios.py`` traduce los errores de cada escritura.
- Timeouts de 5 s en conectar, en ejecutar una sentencia y en esperar una conexión del
  pool. ``statement_timeout`` va en ``options``: lo aplica el servidor al abrir cada
  conexión, así que no depende de ninguna consulta extra y vale para todas las del pool.
  Al vencer, una sentencia lanza ``OperationalError`` (SQLSTATE 57014) y la espera del
  pool, ``sqlalchemy.exc.TimeoutError``.
"""

from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from api.db.config import ConfiguracionBDError

DRIVER_PERMITIDO = "postgresql+psycopg"
TIMEOUT_BD_S = 5


def crear_motor(url: str | URL) -> AsyncEngine:
    """Crea el motor. Solo acepta ``postgresql+psycopg``; el error no muestra la URL.

    ``make_url`` lanza ``ValueError`` con el texto del puerto, y ahí termina un trozo de
    la contraseña si lleva ``@`` y ``:`` sin escapar; ``ArgumentError`` puede repetir el
    valor. El ``raise`` va fuera del ``except`` para no dejarlos en ``__context__``.
    """
    interpretada: URL | None
    try:
        interpretada = make_url(url)
    except (ArgumentError, ValueError):
        interpretada = None
    if interpretada is None:
        raise ConfiguracionBDError(
            "La URL de la base de datos no se pudo interpretar; si la contraseña lleva "
            "caracteres como @ o :, escápalos con %40 y %3A "
            "(el valor no se muestra porque puede contener credenciales)."
        )
    if interpretada.drivername != DRIVER_PERMITIDO:
        raise ConfiguracionBDError(
            f"La URL de la base de datos debe usar {DRIVER_PERMITIDO} "
            "(el valor no se muestra porque puede contener credenciales)."
        )
    return create_async_engine(
        interpretada,
        hide_parameters=True,
        pool_timeout=TIMEOUT_BD_S,
        connect_args={
            "connect_timeout": TIMEOUT_BD_S,
            "options": f"-c statement_timeout={TIMEOUT_BD_S}s",
        },
    )


def fabrica_sesiones(motor: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Fábrica de sesiones del motor."""
    return async_sessionmaker(motor, expire_on_commit=False)
