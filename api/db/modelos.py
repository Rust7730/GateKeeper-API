"""Modelos ORM (SQLAlchemy 2.0) de la base de datos de Gatekeeper (F1.07, diseño §3).

- ``METADATA`` lleva una convención de nombres para que **toda** restricción e índice
  tenga un nombre estable: Alembic solo compara restricciones con nombre, y las pruebas
  identifican qué restricción rechazó una fila por ese nombre.
- Las claves primarias son UUID generados por el servidor (``gen_random_uuid()``).
- Todas las fechas son ``timestamptz``.
- Los modelos solo describen el esquema. Las consultas viven en los repositorios, que
  llegan con el paso que los usa (diseño §1).
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    CHAR,
    CheckConstraint,
    DateTime,
    ForeignKey,
    MetaData,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

CONVENCION_NOMBRES = {
    "pk": "pk_%(table_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "ix": "ix_%(column_0_label)s",
}

METADATA = MetaData(naming_convention=CONVENCION_NOMBRES)

# HMAC-SHA-256 en hex minúsculas: exactamente 64 caracteres de [0-9a-f].
PATRON_HMAC_HEX = "^[0-9a-f]{64}$"


class Base(DeclarativeBase):
    metadata = METADATA


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )


def _ahora() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now())


class Aplicacion(Base):
    """Aplicación cliente de Gatekeeper; dueña de sus API keys y sus archivos (K05, INV-10)."""

    __tablename__ = "aplicacion"

    id: Mapped[uuid.UUID] = _uuid_pk()
    nombre: Mapped[str] = mapped_column(Text, unique=True)
    activa: Mapped[bool] = mapped_column(server_default=text("true"))
    creada_en: Mapped[datetime] = _ahora()


class ApiKey(Base):
    """API key de una aplicación (K05).

    Nunca se guarda la key: solo su prefijo visible y su HMAC-SHA-256 en hex (V13).
    ``revocada_en`` es nulo mientras la key está activa.
    """

    __tablename__ = "api_key"
    __table_args__ = (
        # Con char(64) el valor se compara sin los espacios de relleno, así que un
        # hash de 63 caracteres no pasa por tener 64 con el relleno.
        CheckConstraint(f"hash ~ '{PATRON_HMAC_HEX}'", name="hash_hex"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    aplicacion_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("aplicacion.id"), index=True
    )
    prefijo: Mapped[str] = mapped_column(Text, unique=True)
    hash: Mapped[str] = mapped_column(CHAR(64), unique=True)
    creada_en: Mapped[datetime] = _ahora()
    revocada_en: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
