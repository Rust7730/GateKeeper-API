"""Permisos mínimos del rol de la API (``gk_app``): solo ``GRANT`` y ``REVOKE``.

Diseño de F1.07 §4, limitado a las 4 tablas que existen:

- ``aplicacion``, ``api_key``, ``archivo``: ``SELECT, INSERT, UPDATE``.
- ``resultado_analisis``: ``SELECT, INSERT`` (un resultado no se corrige: se agrega otro).
- Nada más: ni ``DELETE``, ``TRUNCATE``, ``REFERENCES`` o ``TRIGGER``, ni permisos sobre
  ``alembic_version`` (la escribe el dueño) o sobre la secuencia de identidad de
  ``resultado_analisis``: ``GENERATED ALWAYS AS IDENTITY`` saca el valor sin comprobar
  permisos de la secuencia, y con ``USAGE`` o ``UPDATE`` el rol podría quemar ids
  (``nextval``) o moverlos (``setval``).
- Sin DDL: el rol no es dueño de nada. En el esquema ``public`` solo tiene ``USAGE`` (y a
  ``PUBLIC`` se le quita ``CREATE``, que PostgreSQL 16 ya no da por omisión). En la base,
  solo ``CONNECT``: a ``PUBLIC`` se le quita ``TEMPORARY`` para que nadie sin permisos
  explícitos cree tablas o funciones temporales.
- **Privilegios por omisión:** no se usa ``ALTER DEFAULT PRIVILEGES`` a propósito. Así una
  tabla nueva nace sin permisos para el rol y la migración que la crea debe darlos de forma
  explícita (falla cerrado). Como el rol no puede crear objetos, sus propios privilegios por
  omisión no importan.

**El rol no se crea aquí:** lo crea la infraestructura (``deploy/instalar.sh``) antes de
migrar. Si no existe, la migración falla con un mensaje claro y no deja nada: Alembic corre
todo el ``upgrade`` en una sola transacción, así que en una base vacía tampoco queda la 0001.
También falla, por la misma razón, si el rol anularía estos permisos: si es superusuario,
si es el mismo rol con que se migra, si es miembro de otro rol (heredaría sus permisos; p.
ej. ``pg_write_all_data``) o si es dueño de algo en la base.

El nombre sale de ``GATEKEEPER_ROL_APP`` (``rol_app()``; por omisión ``gk_app``), validado
como identificador simple. Nunca se arma SQL con texto (CWE-89): los identificadores van con
``psycopg.sql.Identifier`` y los valores, como parámetros.

``downgrade`` quita lo que dio el ``upgrade`` y devuelve ``TEMPORARY`` a ``PUBLIC`` (el
valor de omisión). No devuelve ``CREATE`` en ``public`` a ``PUBLIC``: PostgreSQL 16 no lo da
por omisión y hacerlo abriría el esquema. Si el rol ya no existe no hay nada que quitarle
(un rol con permisos no se puede borrar) y solo se deshace lo demás.

Revision ID: 0002_permisos_gk_app
Revises: 0001_esquema_inicial
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from psycopg import sql

from api.db.config import rol_app

revision: str = "0002_permisos_gk_app"
down_revision: str | Sequence[str] | None = "0001_esquema_inicial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ESQUEMA = "public"
# Foto fija de las tablas de la 0001, como en esa migración: no se leen de los modelos.
TABLAS_LECTURA_ESCRITURA = ("aplicacion", "api_key", "archivo")
TABLAS_SOLO_INSERCION = ("resultado_analisis",)
COLUMNA_IDENTIDAD = ("resultado_analisis", "id")
PRIVILEGIOS_LECTURA_ESCRITURA = sql.SQL("SELECT, INSERT, UPDATE")
PRIVILEGIOS_SOLO_INSERCION = sql.SQL("SELECT, INSERT")


class RolDeLaApiInvalido(RuntimeError):
    """El rol de la API no existe o anularía los permisos mínimos. No se cambió nada."""


def _ejecutar(sentencias: Sequence[sql.Composable]) -> None:
    """Ejecuta sentencias compuestas con psycopg dentro de la transacción de Alembic."""
    cursor = op.get_bind().connection.cursor()
    try:
        for sentencia in sentencias:
            cursor.execute(sentencia)
    finally:
        cursor.close()


def _fila_del_rol(conexion: sa.Connection, rol: str) -> sa.Row | None:
    return conexion.execute(
        sa.text(
            """
            SELECT r.rolname = current_user AS es_quien_migra,
                   r.rolsuper AS es_superusuario,
                   EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid)
                       AS es_miembro,
                   EXISTS (SELECT 1 FROM pg_class WHERE relowner = r.oid)
                   OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspowner = r.oid)
                   OR EXISTS (SELECT 1 FROM pg_proc WHERE proowner = r.oid)
                   OR EXISTS (SELECT 1 FROM pg_type WHERE typowner = r.oid)
                   OR EXISTS (SELECT 1 FROM pg_database
                              WHERE datname = current_database() AND datdba = r.oid)
                       AS es_dueno_de_algo
            FROM pg_roles r
            WHERE r.rolname = :rol
            """
        ),
        {"rol": rol},
    ).one_or_none()


def _exigir_rol_valido(conexion: sa.Connection, rol: str) -> None:
    fila = _fila_del_rol(conexion, rol)
    if fila is None:
        raise RolDeLaApiInvalido(
            f"El rol de la API '{rol}' no existe. Créalo antes de migrar: lo crea la "
            "infraestructura (deploy/instalar.sh). Esta migración solo le da permisos y "
            "no crea roles."
        )
    if fila.es_quien_migra:
        raise RolDeLaApiInvalido(
            f"El rol de la API '{rol}' es el mismo con el que se migra (el dueño del "
            "esquema). La API debe conectar con otro rol, que no sea dueño de nada."
        )
    if fila.es_superusuario:
        raise RolDeLaApiInvalido(
            f"El rol de la API '{rol}' es superusuario: ningún permiso lo limitaría. "
            "Créalo con NOSUPERUSER."
        )
    if fila.es_miembro:
        raise RolDeLaApiInvalido(
            f"El rol de la API '{rol}' es miembro de otro rol y heredaría sus permisos "
            "(p. ej. los del dueño o de pg_write_all_data). Quítale esa membresía."
        )
    if fila.es_dueno_de_algo:
        raise RolDeLaApiInvalido(
            f"El rol de la API '{rol}' es dueño de objetos en esta base; no debe ser "
            "dueño de nada."
        )


def _secuencia_de_identidad(conexion: sa.Connection) -> sql.Identifier:
    tabla, columna = COLUMNA_IDENTIDAD
    fila = conexion.execute(
        sa.text(
            "SELECT n.nspname, c.relname FROM pg_class c"
            " JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE c.oid = pg_get_serial_sequence(:tabla, :columna)::regclass"
        ),
        {"tabla": f"{ESQUEMA}.{tabla}", "columna": columna},
    ).one()
    return sql.Identifier(fila.nspname, fila.relname)


def _tabla(nombre: str) -> sql.Identifier:
    return sql.Identifier(ESQUEMA, nombre)


def _tabla_de_versiones() -> sql.Identifier:
    contexto = op.get_context()
    return sql.Identifier(
        contexto.version_table_schema or ESQUEMA, contexto.version_table
    )


def _base(conexion: sa.Connection) -> sql.Identifier:
    return sql.Identifier(
        conexion.execute(sa.text("SELECT current_database()")).scalar_one()
    )


def _exigir_resultado(conexion: sa.Connection, rol: str) -> None:
    """Comprueba lo que se pidió: un ``REVOKE`` sin permiso solo da una advertencia."""
    sobrantes = conexion.execute(
        sa.text(
            """
            SELECT has_database_privilege(:rol, current_database(), 'TEMPORARY')
                OR has_database_privilege(:rol, current_database(), 'CREATE')
                OR has_schema_privilege(:rol, :esquema, 'CREATE')
                OR EXISTS (
                    SELECT 1
                    FROM pg_class c,
                         unnest(ARRAY['DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'])
                             AS p(privilegio)
                    WHERE c.relnamespace = to_regnamespace(:esquema)
                      AND c.relkind IN ('r', 'p')
                      AND has_table_privilege(to_regrole(:rol), c.oid, p.privilegio))
            """
        ),
        {"rol": rol, "esquema": ESQUEMA},
    ).scalar_one()
    if sobrantes:
        raise RolDeLaApiInvalido(
            f"Después de los REVOKE el rol de la API '{rol}' todavía puede crear objetos "
            "o borrar datos: el rol con que se migra debe ser dueño de la base y del "
            "esquema."
        )


def upgrade() -> None:
    rol = rol_app()
    conexion = op.get_bind()
    _exigir_rol_valido(conexion, rol)

    destino = sql.Identifier(rol)
    base = _base(conexion)
    esquema = sql.Identifier(ESQUEMA)
    todas = [
        *(_tabla(t) for t in TABLAS_LECTURA_ESCRITURA + TABLAS_SOLO_INSERCION),
        _tabla_de_versiones(),
    ]
    _ejecutar(
        [
            # Base: solo conectar. TEMPORARY lo trae PUBLIC por omisión y se le quita.
            sql.SQL("REVOKE ALL ON DATABASE {} FROM {}").format(base, destino),
            sql.SQL("REVOKE TEMPORARY ON DATABASE {} FROM PUBLIC").format(base),
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(base, destino),
            # Esquema: usarlo, nunca crear en él.
            sql.SQL("REVOKE CREATE ON SCHEMA {} FROM PUBLIC").format(esquema),
            sql.SQL("REVOKE ALL ON SCHEMA {} FROM {}").format(esquema, destino),
            sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(esquema, destino),
            # Se parte de cero: nada que el rol tuviera antes, ni lo que heredaría de PUBLIC.
            *(
                sql.SQL("REVOKE ALL ON TABLE {} FROM PUBLIC, {}").format(t, destino)
                for t in todas
            ),
            sql.SQL("REVOKE ALL ON SEQUENCE {} FROM PUBLIC, {}").format(
                _secuencia_de_identidad(conexion), destino
            ),
            sql.SQL("GRANT {} ON TABLE {} TO {}").format(
                PRIVILEGIOS_LECTURA_ESCRITURA,
                sql.SQL(", ").join(_tabla(t) for t in TABLAS_LECTURA_ESCRITURA),
                destino,
            ),
            sql.SQL("GRANT {} ON TABLE {} TO {}").format(
                PRIVILEGIOS_SOLO_INSERCION,
                sql.SQL(", ").join(_tabla(t) for t in TABLAS_SOLO_INSERCION),
                destino,
            ),
        ]
    )
    _exigir_resultado(conexion, rol)


def downgrade() -> None:
    rol = rol_app()
    conexion = op.get_bind()
    base = _base(conexion)
    fila = _fila_del_rol(conexion, rol)
    if fila is not None and fila.es_quien_migra:
        # Revocarle todo al dueño lo dejaría sin permisos sobre sus propias tablas.
        raise RolDeLaApiInvalido(
            f"El rol de la API '{rol}' es el mismo con el que se migra; no se le quitan "
            "permisos al dueño del esquema."
        )

    sentencias: list[sql.Composable] = []
    if fila is not None:
        destino = sql.Identifier(rol)
        sentencias += [
            *(
                sql.SQL("REVOKE ALL ON TABLE {} FROM {}").format(_tabla(t), destino)
                for t in TABLAS_LECTURA_ESCRITURA + TABLAS_SOLO_INSERCION
            ),
            sql.SQL("REVOKE ALL ON SCHEMA {} FROM {}").format(
                sql.Identifier(ESQUEMA), destino
            ),
            sql.SQL("REVOKE ALL ON DATABASE {} FROM {}").format(base, destino),
        ]
    sentencias.append(sql.SQL("GRANT TEMPORARY ON DATABASE {} TO PUBLIC").format(base))
    _ejecutar(sentencias)
