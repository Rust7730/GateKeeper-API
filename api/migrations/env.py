"""Entorno de Alembic de Gatekeeper.

La URL sale solo de ``url_migraciones()`` (rol dueño del esquema). Se pasa directo a
``create_engine`` y no por ``config.set_main_option``: la configuración interpola ``%``
y una contraseña con ese carácter rompería, además de dejar la URL guardada en memoria
dentro de la configuración.

Las migraciones corren en modo síncrono: psycopg 3 sirve para los dos modos y Alembic no
gana nada con el asíncrono.
"""

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from api.db.config import url_migraciones
from api.db.modelos import Base


def correr_migraciones() -> None:
    motor = create_engine(url_migraciones(), poolclass=NullPool)
    try:
        with motor.connect() as conexion:
            context.configure(
                connection=conexion,
                target_metadata=Base.metadata,
                compare_type=True,
                compare_server_default=True,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        motor.dispose()


if context.is_offline_mode():
    raise RuntimeError("Las migraciones de Gatekeeper no se generan en modo offline.")

correr_migraciones()
