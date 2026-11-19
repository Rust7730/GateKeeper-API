"""Esquema inicial: aplicacion, api_key, archivo y resultado_analisis.

Escrita a mano y sin importar los modelos: una migración es una foto fija del esquema y
no debe cambiar si mañana cambian los modelos. ``test_migraciones.py`` exige que el
resultado coincida con ellos. ``usuario``, ``refresh_token`` y ``evento_auditoria`` llegan
con el dashboard, y los permisos de ``gk_app``, en la 0002.

Los nombres de los CHECK van con ``op.f()``: ``env.py`` pasa los modelos como metadatos y
Alembic les aplicaría la convención de nombres otra vez (``ck_archivo_ck_archivo_...``).

Revision ID: 0001_esquema_inicial
Revises:
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_esquema_inicial"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "aplicacion",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("nombre", sa.Text(), nullable=False),
        sa.Column(
            "activa", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column(
            "creada_en",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            r"char_length(nombre) BETWEEN 1 AND 100"
            r" AND nombre !~ '^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a"
            r"\u2028\u2029\u202f\u205f\u3000]"
            r"|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a"
            r"\u2028\u2029\u202f\u205f\u3000]$'",
            name=op.f("ck_aplicacion_nombre_valido"),
        ),
        sa.CheckConstraint(
            r"nombre !~ '[\u0000-\u001f\u007f-\u009f]'",
            name=op.f("ck_aplicacion_nombre_sin_control"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_aplicacion"),
    )
    op.create_index(
        "uq_aplicacion_nombre_lower",
        "aplicacion",
        [sa.literal_column("lower(nombre)")],
        unique=True,
    )

    op.create_table(
        "api_key",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("aplicacion_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("prefijo", sa.Text(), nullable=False),
        sa.Column("hash", sa.CHAR(64), nullable=False),
        sa.Column(
            "creada_en",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("revocada_en", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_api_key_hash_hex")),
        sa.CheckConstraint(
            "prefijo ~ '^gk_[0-9a-f]{12}$'", name=op.f("ck_api_key_prefijo_formato")
        ),
        sa.ForeignKeyConstraint(
            ["aplicacion_id"],
            ["aplicacion.id"],
            name="fk_api_key_aplicacion_id_aplicacion",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_api_key"),
        sa.UniqueConstraint("hash", name="uq_api_key_hash"),
        sa.UniqueConstraint("prefijo", name="uq_api_key_prefijo"),
    )
    op.create_index("ix_api_key_aplicacion_id", "api_key", ["aplicacion_id"])

    op.create_table(
        "archivo",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("aplicacion_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("nombre_original", sa.String(255), nullable=False),
        sa.Column("tipo_detectado", sa.String(100), nullable=True),
        sa.Column("tamano_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.CHAR(64), nullable=False),
        sa.Column(
            "estado", sa.Text(), server_default=sa.text("'pendiente'"), nullable=False
        ),
        sa.Column("tipo_error", sa.Text(), nullable=True),
        sa.Column(
            "reintentos", sa.SmallInteger(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "creado_en",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("analizado_en", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "tamano_bytes BETWEEN 1 AND 10485760",
            name=op.f("ck_archivo_tamano_bytes_rango"),
        ),
        sa.CheckConstraint(
            "sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_archivo_sha256_hex")
        ),
        sa.CheckConstraint(
            "estado IN ('pendiente', 'limpio', 'en_cuarentena', 'rechazado', 'error')",
            name=op.f("ck_archivo_estado_valido"),
        ),
        sa.CheckConstraint(
            "tipo_error IN ('transitorio', 'final')",
            name=op.f("ck_archivo_tipo_error_valido"),
        ),
        sa.CheckConstraint(
            "reintentos BETWEEN 0 AND 2", name=op.f("ck_archivo_reintentos_rango")
        ),
        sa.CheckConstraint(
            "(estado = 'error') = (tipo_error IS NOT NULL)",
            name=op.f("ck_archivo_tipo_error_solo_en_error"),
        ),
        sa.CheckConstraint(
            "estado <> 'limpio' OR (tipo_detectado IS NOT NULL AND tipo_detectado IN"
            " ('image/jpeg', 'image/png', 'application/pdf'))",
            name=op.f("ck_archivo_limpio_en_lista_blanca"),
        ),
        sa.ForeignKeyConstraint(
            ["aplicacion_id"],
            ["aplicacion.id"],
            name="fk_archivo_aplicacion_id_aplicacion",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_archivo"),
    )
    op.create_index(
        "ix_archivo_aplicacion_id_estado", "archivo", ["aplicacion_id", "estado"]
    )
    op.create_index(
        "ix_archivo_aplicacion_id_creado_en", "archivo", ["aplicacion_id", "creado_en"]
    )

    op.create_table(
        "resultado_analisis",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("archivo_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("capa", sa.Text(), nullable=False),
        sa.Column("veredicto", sa.Text(), nullable=False),
        sa.Column(
            "detalle",
            postgresql.JSONB(none_as_null=True),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("duracion_ms", sa.Integer(), nullable=True),
        sa.Column(
            "creado_en",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "capa IN ('firma', 'cdr', 'clamav', 'virustotal')",
            name=op.f("ck_resultado_analisis_capa_valida"),
        ),
        sa.CheckConstraint(
            "veredicto IN ('limpio', 'malicioso', 'rechazado', 'error', 'no_evaluada')",
            name=op.f("ck_resultado_analisis_veredicto_valido"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(detalle) = 'object'",
            name=op.f("ck_resultado_analisis_detalle_objeto"),
        ),
        sa.CheckConstraint(
            "octet_length(CAST(detalle AS text)) <= 65536",
            name=op.f("ck_resultado_analisis_detalle_tope"),
        ),
        sa.CheckConstraint(
            "duracion_ms >= 0",
            name=op.f("ck_resultado_analisis_duracion_ms_no_negativa"),
        ),
        sa.ForeignKeyConstraint(
            ["archivo_id"],
            ["archivo.id"],
            name="fk_resultado_analisis_archivo_id_archivo",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_resultado_analisis"),
    )
    op.create_index(
        "ix_resultado_analisis_archivo_id", "resultado_analisis", ["archivo_id"]
    )


def downgrade() -> None:
    # Al borrar cada tabla, PostgreSQL borra también sus índices y restricciones.
    op.drop_table("resultado_analisis")
    op.drop_table("archivo")
    op.drop_table("api_key")
    op.drop_table("aplicacion")
