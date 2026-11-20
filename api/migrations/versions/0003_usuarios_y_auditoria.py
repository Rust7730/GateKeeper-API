"""Tablas de administración: ``usuario``, ``refresh_token`` y ``evento_auditoria`` (F5, K21).

- ``evento_auditoria`` es de solo inserción: dos triggers impiden ``UPDATE``, ``DELETE`` y
  ``TRUNCATE`` incluso para el dueño del esquema.
- Concede al rol de la API (``gk_app``) ``SELECT, INSERT, UPDATE`` en ``usuario`` y
  ``refresh_token``, y únicamente ``SELECT, INSERT`` en ``evento_auditoria``.

Revision ID: 0003_usuarios_y_auditoria
Revises: 0002_permisos_gk_app
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from psycopg import sql
from sqlalchemy.dialects import postgresql

from api.db.config import rol_app

revision: str = "0003_usuarios_y_auditoria"
down_revision: str | Sequence[str] | None = "0002_permisos_gk_app"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ESQUEMA = "public"


def _ejecutar(sentencias: Sequence[sql.Composable]) -> None:
    cursor = op.get_bind().connection.cursor()
    try:
        for sentencia in sentencias:
            cursor.execute(sentencia)
    finally:
        cursor.close()


def _rol_existe(conexion: sa.Connection, rol: str) -> bool:
    return bool(
        conexion.execute(
            sa.text("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :rol)"),
            {"rol": rol},
        ).scalar_one()
    )


def upgrade() -> None:
    op.create_table(
        "usuario",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("hash_password", sa.Text(), nullable=False),
        sa.Column("rol", sa.Text(), nullable=False),
        sa.Column("totp_secreto_cifrado", sa.LargeBinary(), nullable=True),
        sa.Column(
            "activo", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column(
            "creado_en",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_usuario"),
        sa.CheckConstraint("rol IN ('admin', 'analista')", name="rol_valido"),
        sa.CheckConstraint(
            r"char_length(email) BETWEEN 3 AND 254"
            r" AND email !~ '[\u0000-\u001f\u007f-\u009f]'",
            name="email_valido",
        ),
    )
    op.create_index(
        "uq_usuario_email_lower",
        "usuario",
        [sa.func.lower(sa.text("email"))],
        unique=True,
    )

    op.create_table(
        "refresh_token",
        sa.Column(
            "jti",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("usuario_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("familia", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("expira_en", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "revocado", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column(
            "creado_en",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["usuario_id"],
            ["usuario.id"],
            name="fk_refresh_token_usuario_id_usuario",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("jti", name="pk_refresh_token"),
    )
    op.create_index(
        "ix_refresh_token_usuario_id", "refresh_token", ["usuario_id"], unique=False
    )
    op.create_index(
        "ix_refresh_token_familia", "refresh_token", ["familia"], unique=False
    )

    op.create_table(
        "evento_auditoria",
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(always=True),
            nullable=False,
        ),
        sa.Column("usuario_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("accion", sa.Text(), nullable=False),
        sa.Column("objetivo_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("motivo", sa.Text(), nullable=True),
        sa.Column("ip", postgresql.INET(), nullable=True),
        sa.Column(
            "fecha",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["usuario_id"],
            ["usuario.id"],
            name="fk_evento_auditoria_usuario_id_usuario",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evento_auditoria"),
    )
    op.create_index(
        "ix_evento_auditoria_usuario_id",
        "evento_auditoria",
        ["usuario_id"],
        unique=False,
    )
    op.create_index(
        "ix_evento_auditoria_fecha", "evento_auditoria", ["fecha"], unique=False
    )

    # Bitácora de solo inserción: ningún UPDATE, DELETE ni TRUNCATE pasa.
    op.execute(
        """
        CREATE FUNCTION fn_auditoria_solo_insercion() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'evento_auditoria es de solo insercion';
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_evento_auditoria_no_modificar
        BEFORE UPDATE OR DELETE ON evento_auditoria
        FOR EACH ROW EXECUTE FUNCTION fn_auditoria_solo_insercion();
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_evento_auditoria_no_vaciar
        BEFORE TRUNCATE ON evento_auditoria
        FOR EACH STATEMENT EXECUTE FUNCTION fn_auditoria_solo_insercion();
        """
    )

    rol = rol_app()
    conexion = op.get_bind()
    if _rol_existe(conexion, rol):
        destino = sql.Identifier(rol)
        _ejecutar(
            [
                sql.SQL("REVOKE ALL ON TABLE public.usuario FROM PUBLIC, {}").format(
                    destino
                ),
                sql.SQL(
                    "REVOKE ALL ON TABLE public.refresh_token FROM PUBLIC, {}"
                ).format(destino),
                sql.SQL(
                    "REVOKE ALL ON TABLE public.evento_auditoria FROM PUBLIC, {}"
                ).format(destino),
                sql.SQL(
                    "GRANT SELECT, INSERT, UPDATE ON TABLE public.usuario, public.refresh_token TO {}"
                ).format(destino),
                sql.SQL(
                    "GRANT SELECT, INSERT ON TABLE public.evento_auditoria TO {}"
                ).format(destino),
            ]
        )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS trg_evento_auditoria_no_vaciar ON evento_auditoria"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_evento_auditoria_no_modificar ON evento_auditoria"
    )
    op.execute("DROP FUNCTION IF EXISTS fn_auditoria_solo_insercion()")
    op.drop_index("ix_evento_auditoria_fecha", table_name="evento_auditoria")
    op.drop_index("ix_evento_auditoria_usuario_id", table_name="evento_auditoria")
    op.drop_table("evento_auditoria")
    op.drop_index("ix_refresh_token_familia", table_name="refresh_token")
    op.drop_index("ix_refresh_token_usuario_id", table_name="refresh_token")
    op.drop_table("refresh_token")
    op.drop_index("uq_usuario_email_lower", table_name="usuario")
    op.drop_table("usuario")
