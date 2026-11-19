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
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    MetaData,
    SmallInteger,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

CONVENCION_NOMBRES = {
    "pk": "pk_%(table_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "ix": "ix_%(column_0_label)s",
}

METADATA = MetaData(naming_convention=CONVENCION_NOMBRES)


class Base(DeclarativeBase):
    metadata = METADATA


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )


def _ahora() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now())


class Aplicacion(Base):
    """Aplicación cliente de Gatekeeper; dueña de sus API keys y sus archivos (K05, INV-10).

    Reglas de ``nombre`` ("sin bordes ni controles"):

    - ``ck_aplicacion_nombre_valido``: de 1 a 100 caracteres (no bytes) y sin espacio en
      blanco en los extremos. "Espacio en blanco" es la propiedad Unicode White_Space
      completa (U+0009–U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000–U+200A, U+2028,
      U+2029, U+202F, U+205F, U+3000), escrita con escapes ``\\uXXXX`` en vez de
      ``[[:space:]]``, cuyo alcance depende de la collation de la BD. Un nombre de solo
      espacios en blanco empieza con uno, así que también queda rechazado.
    - ``ck_aplicacion_nombre_sin_control``: ningún carácter de control en ninguna posición:
      C0 (U+0000–U+001F), U+007F y C1 (U+0080–U+009F). PostgreSQL ya no admite U+0000 en
      ``text``; el rango lo incluye para que la regla sea la escrita.

    Los dos CHECK se solapan a propósito en tabulador, salto de línea, U+0085, etc. en
    los extremos. El nombre es único sin distinguir mayúsculas: "Portal" y "portal" chocan.
    El índice único sobre ``lower(nombre)`` ya impide también los nombres idénticos, así
    que no hay un UNIQUE exacto aparte (sería un segundo índice que no rechaza nada más).
    """

    __tablename__ = "aplicacion"
    __table_args__ = (
        # Literales crudos: el "\u" tiene que llegar tal cual a PostgreSQL, que lo
        # interpreta dentro de la expresión regular (standard_conforming_strings = on,
        # el valor por omisión desde PostgreSQL 9.1). En sus expresiones regulares "$"
        # es el fin del texto, no el de una línea.
        CheckConstraint(
            r"char_length(nombre) BETWEEN 1 AND 100"
            r" AND nombre !~ '^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a"
            r"\u2028\u2029\u202f\u205f\u3000]"
            r"|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a"
            r"\u2028\u2029\u202f\u205f\u3000]$'",
            name="nombre_valido",
        ),
        CheckConstraint(
            r"nombre !~ '[\u0000-\u001f\u007f-\u009f]'", name="nombre_sin_control"
        ),
        # Índice funcional: la convención "ix" no aplica (no hay columna), así que el
        # nombre va explícito.
        Index("uq_aplicacion_nombre_lower", func.lower(text("nombre")), unique=True),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    nombre: Mapped[str] = mapped_column(Text)
    activa: Mapped[bool] = mapped_column(server_default=text("true"))
    creada_en: Mapped[datetime] = _ahora()


class ApiKey(Base):
    """API key de una aplicación (K05).

    Nunca se guarda la key: solo su prefijo visible y su HMAC-SHA-256 en hex (V13).
    El prefijo es ``gk_`` + 12 hex minúsculas (48 bits) que genera el servidor,
    independiente de la parte secreta. ``revocada_en`` es nulo mientras la key está
    activa. Una aplicación con keys no se puede borrar (``ON DELETE RESTRICT``): hay que
    borrar o conservar sus keys de forma explícita.
    """

    __tablename__ = "api_key"
    __table_args__ = (
        # El DDL de los CHECK va como literal, nunca armado con f-string ni con
        # concatenación (CWE-89): un patrón con comillas rompería la sentencia.
        # Con char(64) el valor se compara sin los espacios de relleno, así que un
        # hash de 63 caracteres no pasa por tener 64 con el relleno.
        CheckConstraint("hash ~ '^[0-9a-f]{64}$'", name="hash_hex"),
        # En las expresiones regulares de PostgreSQL "$" es el fin del texto: un salto
        # de línea final no pasa.
        CheckConstraint("prefijo ~ '^gk_[0-9a-f]{12}$'", name="prefijo_formato"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    aplicacion_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("aplicacion.id", ondelete="RESTRICT"), index=True
    )
    prefijo: Mapped[str] = mapped_column(Text, unique=True)
    hash: Mapped[str] = mapped_column(CHAR(64), unique=True)
    creada_en: Mapped[datetime] = _ahora()
    revocada_en: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Archivo(Base):
    """Archivo recibido por Gatekeeper; pertenece a una sola aplicación (INV-10).

    - La API puede asignar ``id`` antes de guardar (INV-03); si no, lo genera la BD.
    - ``estado`` lo cambia solo el repositorio, tras validar con el dominio (F2.04).
    - ``nombre_original`` es solo para mostrar: nunca entra en rutas ni en decisiones
      (INV-02, INV-03).
    - Una aplicación con archivos no se puede borrar (``ON DELETE RESTRICT``): el
      archivo es la evidencia de lo que pasó por el sistema.
    """

    __tablename__ = "archivo"
    __table_args__ = (
        CheckConstraint(
            "tamano_bytes BETWEEN 1 AND 10485760", name="tamano_bytes_rango"
        ),
        CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="sha256_hex"),
        CheckConstraint(
            "estado IN ('pendiente', 'limpio', 'en_cuarentena', 'rechazado', 'error')",
            name="estado_valido",
        ),
        CheckConstraint(
            "tipo_error IN ('transitorio', 'final')", name="tipo_error_valido"
        ),
        CheckConstraint("reintentos BETWEEN 0 AND 2", name="reintentos_rango"),
        CheckConstraint(
            "(estado = 'error') = (tipo_error IS NOT NULL)",
            name="tipo_error_solo_en_error",
        ),
        # El IS NOT NULL es indispensable: "NULL IN (...)" da NULL y un CHECK solo
        # rechaza FALSE, así que sin él un "limpio" sin tipo pasaría la barrera.
        CheckConstraint(
            "estado <> 'limpio' OR (tipo_detectado IS NOT NULL AND tipo_detectado IN"
            " ('image/jpeg', 'image/png', 'application/pdf'))",
            name="limpio_en_lista_blanca",
        ),
        # Nombre explícito: con la convención "ix" los dos índices se llamarían igual
        # (solo usa la primera columna).
        Index("ix_archivo_aplicacion_id_estado", "aplicacion_id", "estado"),
        Index("ix_archivo_aplicacion_id_creado_en", "aplicacion_id", "creado_en"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    aplicacion_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("aplicacion.id", ondelete="RESTRICT")
    )
    nombre_original: Mapped[str] = mapped_column(String(255))
    tipo_detectado: Mapped[str | None] = mapped_column(String(100))
    tamano_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(CHAR(64))
    estado: Mapped[str] = mapped_column(Text, server_default=text("'pendiente'"))
    tipo_error: Mapped[str | None] = mapped_column(Text)
    reintentos: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    creado_en: Mapped[datetime] = _ahora()
    analizado_en: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ResultadoAnalisis(Base):
    """Resultado de una capa de análisis sobre un archivo.

    Lo que varía por capa va en ``detalle``: siempre un objeto JSON (CWE-20) y con un tope
    de 64 KB (65 536 bytes; CWE-770). El tope se mide sobre el texto del JSON y no con
    ``pg_column_size``, que mide la representación interna: su cifra no es la que ve quien
    escribe el JSON.
    ``none_as_null`` hace que un ``None`` de Python llegue como NULL de SQL, y lo rechace
    el NOT NULL, en vez de guardarse como el JSON ``null``.

    Un archivo con resultados no se puede borrar (``ON DELETE RESTRICT``).
    """

    __tablename__ = "resultado_analisis"
    __table_args__ = (
        CheckConstraint(
            "capa IN ('firma', 'cdr', 'clamav', 'virustotal')", name="capa_valida"
        ),
        CheckConstraint(
            "veredicto IN ('limpio', 'malicioso', 'rechazado', 'error', 'no_evaluada')",
            name="veredicto_valido",
        ),
        CheckConstraint("jsonb_typeof(detalle) = 'object'", name="detalle_objeto"),
        CheckConstraint(
            "octet_length(CAST(detalle AS text)) <= 65536", name="detalle_tope"
        ),
        CheckConstraint("duracion_ms >= 0", name="duracion_ms_no_negativa"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    archivo_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("archivo.id", ondelete="RESTRICT"), index=True
    )
    capa: Mapped[str] = mapped_column(Text)
    veredicto: Mapped[str] = mapped_column(Text)
    detalle: Mapped[dict[str, object]] = mapped_column(
        JSONB(none_as_null=True), server_default=text("'{}'::jsonb")
    )
    duracion_ms: Mapped[int | None] = mapped_column(Integer)
    creado_en: Mapped[datetime] = _ahora()
