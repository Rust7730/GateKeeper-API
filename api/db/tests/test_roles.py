"""Permisos del rol de la API ``gk_app`` (migración 0002; diseño de F1.07 §4).

- **Matriz exacta:** ``aplicacion``, ``api_key`` y ``archivo``: ``SELECT, INSERT, UPDATE``;
  ``resultado_analisis``: ``SELECT, INSERT``. Nada más en ninguna tabla, tampoco en
  ``alembic_version`` ni en la secuencia de identidad de ``resultado_analisis``
  (``GENERATED ALWAYS AS IDENTITY`` no exige permisos sobre la secuencia; la prueba de los
  repositorios lo demuestra insertando como ``gk_app``).
- **Sin DDL:** ``gk_app`` no es dueño de nada, no crea objetos (ni en ``public``, ni
  esquemas, ni tablas temporales) y no puede borrar, truncar, alterar ni tirar tablas.
  Se comprueba intentándolo de verdad, no leyendo el catálogo.
- **La migración:** no crea el rol; sin él, o con un rol que anularía los permisos
  (superusuario, miembro de otro rol, dueño de algo, el propio dueño), falla sin dejar nada
  a medias. El nombre sale de ``GATEKEEPER_ROL_APP`` y se valida antes de tocar la BD.
- **Reversible:** upgrade → downgrade → upgrade deja los permisos (tablas, secuencia,
  esquema, base y privilegios por defecto) exactamente como estaban en cada punto.
- ``alembic_version`` la escribe el dueño; migrar conectado como ``gk_app`` falla.

Que **todas** las funciones de ``repositorios.py`` funcionan como ``gk_app`` lo demuestran
las pruebas de los repositorios, porque su fixture ``sesiones`` conecta como ``gk_app``;
aquí se comprueba esa premisa y se recorre cada función pública una vez.
"""

import inspect
import uuid
from collections.abc import Iterator

import psycopg
import pytest
from alembic import command
from psycopg import sql
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from api.app.estados import Estado
from api.db import repositorios
from api.db.config import VARIABLE_ROL_APP, VARIABLE_URL_MIGRACION, ConfiguracionBDError
from api.db.tests.soporte_postgres import (
    ROL_APP,
    USUARIO_SUPERUSUARIO,
    CredencialRol,
    borrar_bd,
    config_alembic,
    crear_bd,
    rol_temporal,
)

Sesiones = async_sessionmaker[AsyncSession]

REVISION_0001 = "0001_esquema_inicial"
REVISION_0002 = "0002_permisos_gk_app"
REVISION_0003 = "0003_usuarios_y_auditoria"
BD_ROLES = "gk_roles"
SHA256 = "a" * 64
PERMISO_DENEGADO = "42501"  # insufficient_privilege

PRIVILEGIOS_TABLA = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)
ESPERADOS_POR_TABLA = {
    "aplicacion": {"SELECT", "INSERT", "UPDATE"},
    "api_key": {"SELECT", "INSERT", "UPDATE"},
    "archivo": {"SELECT", "INSERT", "UPDATE"},
    "resultado_analisis": {"SELECT", "INSERT"},
    "usuario": {"SELECT", "INSERT", "UPDATE"},
    "refresh_token": {"SELECT", "INSERT", "UPDATE"},
    "evento_auditoria": {"SELECT", "INSERT"},
    "alembic_version": set(),
}
SECUENCIA = "resultado_analisis_id_seq"
TABLAS_0001 = (
    "aplicacion",
    "api_key",
    "archivo",
    "resultado_analisis",
    "alembic_version",
)
TABLAS = tuple(ESPERADOS_POR_TABLA)


# --------------------------------------------------------------------------- soporte


@pytest.fixture
def motor_dueno_repos(url_repositorios: URL) -> Iterator[Engine]:
    """La base de los repositorios (ya migrada a ``head``), como dueño."""
    motor = create_engine(url_repositorios)
    try:
        yield motor
    finally:
        motor.dispose()


@pytest.fixture
def motor_gk_app_repos(
    url_repositorios: URL, rol_app: CredencialRol
) -> Iterator[Engine]:
    """La base de los repositorios, conectando como ``gk_app``."""
    motor = create_engine(
        url_repositorios.set(username=rol_app.nombre, password=rol_app.password)
    )
    try:
        yield motor
    finally:
        motor.dispose()


@pytest.fixture
def url_bd_vacia(
    motor_postgres: Engine,
    url_postgres: URL,
    rol_app: CredencialRol,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[URL]:
    """Base vacía para migrar, con la URL del dueño en el entorno y el rol por omisión."""
    borrar_bd(motor_postgres, BD_ROLES)
    crear_bd(motor_postgres, BD_ROLES)
    url = url_postgres.set(database=BD_ROLES)
    monkeypatch.setenv(
        VARIABLE_URL_MIGRACION, url.render_as_string(hide_password=False)
    )
    monkeypatch.delenv(VARIABLE_ROL_APP, raising=False)
    try:
        yield url
    finally:
        borrar_bd(motor_postgres, BD_ROLES)


@pytest.fixture
def motor_bd_vacia(url_bd_vacia: URL) -> Iterator[Engine]:
    motor = create_engine(url_bd_vacia)
    try:
        yield motor
    finally:
        motor.dispose()


def _version(motor: Engine) -> str | None:
    with motor.connect() as con:
        existe = con.execute(text("SELECT to_regclass('alembic_version')")).scalar()
        if existe is None:
            return None
        return con.execute(text("SELECT version_num FROM alembic_version")).scalar()


def _privilegios_de_tabla(con: Connection, rol: str, tabla: str) -> set[str]:
    return {
        privilegio
        for privilegio in PRIVILEGIOS_TABLA
        if con.execute(
            text("SELECT has_table_privilege(:rol, :tabla, :privilegio)"),
            {"rol": rol, "tabla": f"public.{tabla}", "privilegio": privilegio},
        ).scalar_one()
    }


def _privilegios_de_secuencia(con: Connection, rol: str) -> set[str]:
    return {
        privilegio
        for privilegio in ("USAGE", "SELECT", "UPDATE")
        if con.execute(
            text("SELECT has_sequence_privilege(:rol, :secuencia, :privilegio)"),
            {"rol": rol, "secuencia": f"public.{SECUENCIA}", "privilegio": privilegio},
        ).scalar_one()
    }


def _acl(motor: Engine) -> set[tuple[str, ...]]:
    """Permisos efectivos de la base, explotados: lo que PostgreSQL usará al decidir.

    Un ACL nulo es el de omisión (``acldefault``), así que "nunca tocado" y "revocado y
    vuelto a dar" se comparan por lo que permiten, no por cómo están escritos.
    """
    consulta = text(
        """
        WITH objetos AS (
            SELECT 'relacion:' || c.relname AS objeto,
                   coalesce(c.relacl, acldefault(
                       CASE c.relkind WHEN 'S' THEN 's'::"char" ELSE 'r'::"char" END,
                       c.relowner)) AS acl
            FROM pg_class c
            WHERE c.relnamespace = 'public'::regnamespace
              AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
            UNION ALL
            SELECT 'esquema:' || n.nspname,
                   coalesce(n.nspacl, acldefault('n', n.nspowner))
            FROM pg_namespace n WHERE n.nspname = 'public'
            UNION ALL
            SELECT 'base', coalesce(d.datacl, acldefault('d', d.datdba))
            FROM pg_database d WHERE d.datname = current_database()
            UNION ALL
            SELECT 'por_omision:' || d.defaclobjtype::text || ':'
                   || CASE d.defaclnamespace WHEN 0 THEN '*'
                      ELSE d.defaclnamespace::regnamespace::text END
                   || ':' || d.defaclrole::regrole::text,
                   d.defaclacl
            FROM pg_default_acl d
        )
        SELECT o.objeto,
               CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,
               a.grantor::regrole::text,
               a.privilege_type,
               a.is_grantable::text
        FROM objetos o CROSS JOIN LATERAL aclexplode(o.acl) a
        """
    )
    with motor.connect() as con:
        return {tuple(fila) for fila in con.execute(consulta)}


def _denegado(error: DBAPIError) -> bool:
    return getattr(error.orig, "sqlstate", None) == PERMISO_DENEGADO


def _sentencia_rechazada(con: Connection, sentencia: sql.Composable) -> psycopg.Error:
    """Ejecuta ``sentencia`` con el cursor de psycopg y devuelve el error que lanzó.

    Corre dentro de la transacción de ``con``, que quien llama revierte. Si la sentencia
    pasa, falla la prueba.
    """
    cursor = con.connection.cursor()
    try:
        with pytest.raises(psycopg.Error) as error:
            cursor.execute(sentencia)
    finally:
        cursor.close()
    return error.value


# --------------------------------------------------- la matriz de permisos en head


def test_las_tablas_de_public_son_las_que_cubre_la_matriz(
    motor_dueno_repos: Engine,
) -> None:
    # Una tabla nueva obliga a decidir sus permisos (y a tocar esta prueba).
    with motor_dueno_repos.connect() as con:
        tablas = set(
            con.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            ).scalars()
        )
    assert tablas == set(ESPERADOS_POR_TABLA)


@pytest.mark.parametrize("tabla", sorted(ESPERADOS_POR_TABLA))
def test_gk_app_tiene_exactamente_los_permisos_del_diseno(
    motor_dueno_repos: Engine, tabla: str
) -> None:
    with motor_dueno_repos.connect() as con:
        assert _privilegios_de_tabla(con, ROL_APP, tabla) == ESPERADOS_POR_TABLA[tabla]


def test_gk_app_no_tiene_permisos_sobre_la_secuencia_de_identidad(
    motor_dueno_repos: Engine,
) -> None:
    # GENERATED ALWAYS AS IDENTITY no los pide: nextval de una identidad no comprueba
    # permisos. Con USAGE o UPDATE podría quemar ids (nextval) o moverlos (setval).
    with motor_dueno_repos.connect() as con:
        assert _privilegios_de_secuencia(con, ROL_APP) == set()


def test_gk_app_no_es_dueno_de_nada_ni_miembro_de_ningun_rol(
    motor_dueno_repos: Engine,
) -> None:
    consultas = {
        "relaciones": "SELECT count(*) FROM pg_class WHERE relowner = to_regrole(:rol)",
        "esquemas": "SELECT count(*) FROM pg_namespace WHERE nspowner = to_regrole(:rol)",
        "funciones": "SELECT count(*) FROM pg_proc WHERE proowner = to_regrole(:rol)",
        "tipos": "SELECT count(*) FROM pg_type WHERE typowner = to_regrole(:rol)",
        "bases": "SELECT count(*) FROM pg_database WHERE datdba = to_regrole(:rol)",
        "membresias": "SELECT count(*) FROM pg_auth_members WHERE member = to_regrole(:rol)",
        "por_omision": "SELECT count(*) FROM pg_default_acl d, aclexplode(d.defaclacl) a"
        " WHERE a.grantee = to_regrole(:rol) OR d.defaclrole = to_regrole(:rol)",
    }
    with motor_dueno_repos.connect() as con:
        assert con.execute(
            text("SELECT to_regrole(:rol) IS NOT NULL"), {"rol": ROL_APP}
        ).scalar_one()
        cuentas = {
            nombre: con.execute(text(sql), {"rol": ROL_APP}).scalar_one()
            for nombre, sql in consultas.items()
        }
    assert cuentas == dict.fromkeys(consultas, 0)


def test_gk_app_no_crea_en_el_esquema_ni_en_la_base(motor_dueno_repos: Engine) -> None:
    with motor_dueno_repos.connect() as con:
        fila = con.execute(
            text(
                "SELECT has_schema_privilege(:rol, 'public', 'USAGE'),"
                " has_schema_privilege(:rol, 'public', 'CREATE'),"
                " has_database_privilege(:rol, current_database(), 'CONNECT'),"
                " has_database_privilege(:rol, current_database(), 'CREATE'),"
                " has_database_privilege(:rol, current_database(), 'TEMPORARY')"
            ),
            {"rol": ROL_APP},
        ).one()
    assert tuple(fila) == (True, False, True, False, False)


# ------------------------------------------- lo que gk_app no puede hacer, intentándolo


def _por_tabla(plantilla: str, etiqueta: str) -> list[object]:
    return [
        pytest.param(
            sql.SQL(plantilla).format(sql.Identifier(tabla)),  # type: ignore[arg-type]
            id=f"{etiqueta}-{tabla}",
        )
        for tabla in TABLAS
    ]


def _fija(sentencia: str, etiqueta: str) -> object:
    return pytest.param(sql.SQL(sentencia), id=etiqueta)  # type: ignore[arg-type]


PROHIBIDAS = [
    *_por_tabla("DELETE FROM {}", "delete"),
    *_por_tabla("TRUNCATE {}", "truncate"),
    *_por_tabla("ALTER TABLE {} ADD COLUMN intruso int", "alter"),
    *_por_tabla("DROP TABLE {}", "drop"),
    _fija("ALTER TABLE archivo DISABLE TRIGGER ALL", "disable-trigger"),
    _fija("ALTER TABLE archivo DROP CONSTRAINT ck_archivo_estado_valido", "drop-check"),
    _fija("CREATE INDEX ix_intruso ON archivo (nombre_original)", "create-index"),
    _fija("CREATE TABLE public.intrusa (id int)", "create-table-public"),
    _fija("CREATE TABLE intrusa (id int)", "create-table-search-path"),
    _fija("CREATE TEMPORARY TABLE intrusa (id int)", "create-temp"),
    _fija(
        "CREATE FUNCTION pg_temp.intrusa() RETURNS int LANGUAGE sql AS 'SELECT 1'",
        "create-function-pg-temp",
    ),
    _fija("CREATE SCHEMA intruso", "create-schema"),
    _fija("CREATE VIEW intrusa AS SELECT 1", "create-view"),
    _fija(
        "CREATE FUNCTION public.intrusa() RETURNS int LANGUAGE sql AS 'SELECT 1'",
        "create-function",
    ),
    _fija(
        "CREATE TRIGGER intruso BEFORE UPDATE ON archivo FOR EACH ROW"
        " EXECUTE FUNCTION suppress_redundant_updates_trigger()",
        "create-trigger",
    ),
    _fija("COMMENT ON TABLE archivo IS 'intruso'", "comment"),
    _fija("UPDATE resultado_analisis SET veredicto = 'limpio'", "update-resultado"),
    _fija("SELECT version_num FROM alembic_version", "select-alembic-version"),
    _fija("UPDATE alembic_version SET version_num = 'x'", "update-alembic-version"),
    _fija("INSERT INTO alembic_version VALUES ('x')", "insert-alembic-version"),
    _fija("SELECT nextval('resultado_analisis_id_seq')", "nextval"),
    _fija("SELECT setval('resultado_analisis_id_seq', 1)", "setval"),
]


@pytest.mark.parametrize("sentencia", PROHIBIDAS)
def test_gk_app_no_puede(motor_gk_app_repos: Engine, sentencia: sql.Composable) -> None:
    with motor_gk_app_repos.connect() as con:
        transaccion = con.begin()
        try:
            assert con.execute(text("SELECT current_user")).scalar_one() == ROL_APP
            error = _sentencia_rechazada(con, sentencia)
        finally:
            # Si la sentencia pasara (la prueba falla), no deja nada en la base compartida.
            transaccion.rollback()
    assert error.sqlstate == PERMISO_DENEGADO, repr(error)


@pytest.mark.parametrize(
    ("sentencia", "grantee", "privilegio"),
    [
        pytest.param(
            "GRANT SELECT ON archivo TO PUBLIC", "public", "SELECT", id="a-public"
        ),
        pytest.param(
            "GRANT DELETE ON archivo TO CURRENT_USER",
            ROL_APP,
            "DELETE",
            id="a-si-mismo",
        ),
    ],
)
def test_gk_app_no_puede_regalar_permisos(
    motor_gk_app_repos: Engine, sentencia: str, grantee: str, privilegio: str
) -> None:
    # Sin GRANT OPTION, PostgreSQL responde con una advertencia y no concede nada.
    with motor_gk_app_repos.connect() as con, con.begin():
        con.execute(text(sentencia))
        concedido = con.execute(
            text("SELECT has_table_privilege(:rol, 'public.archivo', :privilegio)"),
            {"rol": grantee, "privilegio": privilegio},
        ).scalar_one()
        con.rollback()
    assert concedido is False


# ------------------------------------------------------ los repositorios con gk_app


@pytest.mark.anyio
async def test_las_sesiones_de_las_pruebas_conectan_como_gk_app(
    sesiones: Sesiones, sesiones_dueno: Sesiones
) -> None:
    async with sesiones() as sesion:
        usuario = (await sesion.execute(text("SELECT current_user"))).scalar_one()
    async with sesiones_dueno() as sesion:
        dueno = (await sesion.execute(text("SELECT current_user"))).scalar_one()
    assert usuario == ROL_APP
    assert dueno == USUARIO_SUPERUSUARIO


@pytest.mark.anyio
async def test_cada_funcion_de_repositorios_funciona_como_gk_app(
    sesiones: Sesiones,
) -> None:
    llamadas: set[str] = set()

    def anotar(nombre: str) -> None:
        llamadas.add(nombre)

    async with sesiones.begin() as sesion:
        app_id = await repositorios.crear_aplicacion(sesion, f"app-{uuid.uuid4()}")
        anotar("crear_aplicacion")
        prefijo = f"gk_{uuid.uuid4().hex[:12]}"
        await repositorios.crear_api_key(sesion, app_id, prefijo, "b" * 64)
        anotar("crear_api_key")
    async with sesiones() as sesion:
        assert await repositorios.obtener_api_key_activa(sesion, prefijo) is not None
        anotar("obtener_api_key_activa")

    async with sesiones.begin() as sesion:
        primero = await repositorios.crear_archivo(
            sesion, app_id, uuid.uuid4(), "a.pdf", 10, SHA256
        )
        anotar("crear_archivo")
    # Con el FOR NO KEY UPDATE sobre aplicacion: exige UPDATE en esa tabla.
    async with sesiones.begin() as sesion:
        segundo = await repositorios.crear_archivo_con_cupo(
            sesion, app_id, uuid.uuid4(), "b.pdf", 10, SHA256, tope_pendientes=20
        )
        anotar("crear_archivo_con_cupo")
    async with sesiones() as sesion:
        assert await repositorios.contar_pendientes(sesion, app_id) == 2
        anotar("contar_pendientes")
        assert (
            await repositorios.obtener_archivo(sesion, app_id, primero.id) is not None
        )
        anotar("obtener_archivo")

    # La identidad de resultado_analisis sin permisos sobre la secuencia.
    async with sesiones.begin() as sesion:
        resultado_id = await repositorios.registrar_resultado(
            sesion, app_id, primero.id, "cdr", "limpio", {"capa": "cdr"}, 3
        )
        anotar("registrar_resultado")
        assert resultado_id > 0
        limpio = await repositorios.cambiar_estado(
            sesion,
            app_id,
            primero.id,
            Estado.PENDIENTE,
            Estado.LIMPIO,
            tipo_detectado="application/pdf",
        )
        anotar("cambiar_estado")
    assert limpio.estado is Estado.LIMPIO

    async with sesiones.begin() as sesion:
        cerrados = await repositorios.cerrar_pendientes_huerfanos(
            sesion, tipo_error="transitorio"
        )
        anotar("cerrar_pendientes_huerfanos")
    assert cerrados == [segundo.id]

    publicas = {
        nombre
        for nombre, funcion in inspect.getmembers(
            repositorios, inspect.iscoroutinefunction
        )
        if not nombre.startswith("_") and funcion.__module__ == repositorios.__name__
    }
    assert llamadas == publicas, (
        "una función nueva de repositorios no se probó con gk_app"
    )


# ---------------------------------------------------------------- la migración 0002


def test_el_rol_no_existe_la_migracion_falla_y_no_lo_crea(
    url_bd_vacia: URL, motor_bd_vacia: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    command.upgrade(config_alembic(), REVISION_0001)
    monkeypatch.setenv(VARIABLE_ROL_APP, "gk_no_existe")

    with pytest.raises(RuntimeError) as error:
        command.upgrade(config_alembic(), "head")

    mensaje = str(error.value)
    assert "gk_no_existe" in mensaje and "no existe" in mensaje, mensaje
    assert "infraestructura" in mensaje, mensaje
    with motor_bd_vacia.connect() as con:
        assert con.execute(text("SELECT to_regrole('gk_no_existe')")).scalar() is None
    assert _version(motor_bd_vacia) == REVISION_0001


def test_desde_cero_sin_el_rol_no_queda_ni_el_esquema(
    url_bd_vacia: URL, motor_bd_vacia: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Todo el upgrade va en una transacción: por eso el rol se crea antes de migrar.
    monkeypatch.setenv(VARIABLE_ROL_APP, "gk_no_existe")
    with pytest.raises(RuntimeError):
        command.upgrade(config_alembic(), "head")
    with motor_bd_vacia.connect() as con:
        tablas = con.execute(
            text("SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")
        ).scalar_one()
    assert tablas == 0


@pytest.mark.parametrize(
    "nombre", ["GK_APP", 'gk_app"; DROP TABLE archivo; --', "gk app", ""]
)
def test_un_nombre_invalido_falla_antes_de_tocar_la_bd(
    url_bd_vacia: URL,
    motor_bd_vacia: Engine,
    monkeypatch: pytest.MonkeyPatch,
    nombre: str,
) -> None:
    command.upgrade(config_alembic(), REVISION_0001)
    acl_antes = _acl(motor_bd_vacia)
    monkeypatch.setenv(VARIABLE_ROL_APP, nombre)

    with pytest.raises(ConfiguracionBDError, match=VARIABLE_ROL_APP):
        command.upgrade(config_alembic(), "head")

    assert _version(motor_bd_vacia) == REVISION_0001
    assert _acl(motor_bd_vacia) == acl_antes
    with motor_bd_vacia.connect() as con:
        assert con.execute(text("SELECT to_regclass('archivo')")).scalar() == "archivo"


@pytest.mark.parametrize(
    ("atributos", "motivo"),
    [
        pytest.param("NOLOGIN SUPERUSER", "superusuario", id="superusuario"),
        pytest.param(
            f"NOLOGIN IN ROLE {USUARIO_SUPERUSUARIO}", "miembro", id="miembro-del-dueno"
        ),
        pytest.param(
            "NOLOGIN IN ROLE pg_write_all_data", "miembro", id="pg_write_all_data"
        ),
    ],
)
def test_un_rol_que_anularia_los_permisos_se_rechaza(
    url_bd_vacia: URL,
    motor_bd_vacia: Engine,
    monkeypatch: pytest.MonkeyPatch,
    atributos: str,
    motivo: str,
) -> None:
    command.upgrade(config_alembic(), REVISION_0001)
    with rol_temporal(motor_bd_vacia, "gk_rol_peligroso", atributos) as nombre:
        monkeypatch.setenv(VARIABLE_ROL_APP, nombre)
        with pytest.raises(RuntimeError) as error:
            command.upgrade(config_alembic(), "head")
        assert motivo in str(error.value), str(error.value)
        assert _version(motor_bd_vacia) == REVISION_0001


def test_un_rol_dueno_de_un_objeto_se_rechaza(
    url_bd_vacia: URL, motor_bd_vacia: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    command.upgrade(config_alembic(), REVISION_0001)
    with rol_temporal(motor_bd_vacia, "gk_rol_dueno") as nombre:
        with motor_bd_vacia.begin() as con:
            con.execute(text("CREATE TABLE ajena (id int)"))
            cursor = con.connection.cursor()
            cursor.execute(
                sql.SQL("ALTER TABLE ajena OWNER TO {}").format(sql.Identifier(nombre))
            )
            cursor.close()
        monkeypatch.setenv(VARIABLE_ROL_APP, nombre)
        with pytest.raises(RuntimeError) as error:
            command.upgrade(config_alembic(), "head")
        assert "dueño" in str(error.value), str(error.value)
        assert _version(motor_bd_vacia) == REVISION_0001


def test_el_dueno_no_puede_ser_el_rol_de_la_api(
    url_bd_vacia: URL, motor_bd_vacia: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # REVOKE ALL sobre sus propias tablas le quitaría los permisos al dueño.
    command.upgrade(config_alembic(), REVISION_0001)
    monkeypatch.setenv(VARIABLE_ROL_APP, USUARIO_SUPERUSUARIO)
    with pytest.raises(RuntimeError) as error:
        command.upgrade(config_alembic(), "head")
    assert "dueño" in str(error.value), str(error.value)
    assert _version(motor_bd_vacia) == REVISION_0001


def test_el_rol_sale_de_la_configuracion(
    url_bd_vacia: URL, motor_bd_vacia: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    with rol_temporal(motor_bd_vacia, "gk_app_alterno") as nombre:
        monkeypatch.setenv(VARIABLE_ROL_APP, nombre)
        command.upgrade(config_alembic(), "head")
        with motor_bd_vacia.connect() as con:
            assert _privilegios_de_tabla(con, nombre, "archivo") == {
                "SELECT",
                "INSERT",
                "UPDATE",
            }
            assert _privilegios_de_tabla(con, ROL_APP, "archivo") == set()


def test_upgrade_downgrade_upgrade_restaura_los_permisos(
    url_bd_vacia: URL, motor_bd_vacia: Engine
) -> None:
    config = config_alembic()
    command.upgrade(config, REVISION_0001)
    en_0001 = _acl(motor_bd_vacia)

    command.upgrade(config, "head")
    assert _version(motor_bd_vacia) == REVISION_0003
    en_head = _acl(motor_bd_vacia)
    assert en_head != en_0001
    with motor_bd_vacia.connect() as con:
        assert (
            _privilegios_de_tabla(con, ROL_APP, "archivo")
            == ESPERADOS_POR_TABLA["archivo"]
        )

    command.downgrade(config, REVISION_0001)
    assert _version(motor_bd_vacia) == REVISION_0001
    assert _acl(motor_bd_vacia) == en_0001
    with motor_bd_vacia.connect() as con:
        for tabla in TABLAS_0001:
            assert _privilegios_de_tabla(con, ROL_APP, tabla) == set(), tabla

    command.upgrade(config, "head")
    assert _acl(motor_bd_vacia) == en_head

    command.downgrade(config, "base")
    command.upgrade(config, "head")
    assert _acl(motor_bd_vacia) == en_head


def test_el_downgrade_sin_el_rol_no_falla(
    url_bd_vacia: URL, motor_bd_vacia: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Un rol no se puede borrar mientras tenga permisos: si no existe, no hay nada que
    # quitarle, y el downgrade solo deshace lo demás.
    config = config_alembic()
    command.upgrade(config, REVISION_0001)
    en_0001 = _acl(motor_bd_vacia)
    with rol_temporal(motor_bd_vacia, "gk_app_efimero") as nombre:
        monkeypatch.setenv(VARIABLE_ROL_APP, nombre)
        command.upgrade(config, "head")
    command.downgrade(config, REVISION_0001)
    assert _acl(motor_bd_vacia) == en_0001


# ------------------------------------------------------------ alembic_version y dueño


def test_alembic_version_es_del_dueno_y_gk_app_no_la_toca(
    url_bd_vacia: URL, motor_bd_vacia: Engine
) -> None:
    command.upgrade(config_alembic(), "head")
    with motor_bd_vacia.connect() as con:
        dueno = con.execute(
            text("SELECT tableowner FROM pg_tables WHERE tablename = 'alembic_version'")
        ).scalar_one()
        assert dueno == USUARIO_SUPERUSUARIO
        assert _privilegios_de_tabla(con, ROL_APP, "alembic_version") == set()
        duenos = set(
            con.execute(
                text("SELECT tableowner FROM pg_tables WHERE schemaname = 'public'")
            ).scalars()
        )
    assert duenos == {USUARIO_SUPERUSUARIO}
    assert _version(motor_bd_vacia) == REVISION_0003


@pytest.mark.parametrize("desde", [None, REVISION_0001], ids=["bd-vacia", "en-0001"])
def test_migrar_como_gk_app_falla_sin_dejar_nada(
    url_bd_vacia: URL,
    motor_bd_vacia: Engine,
    rol_app: CredencialRol,
    monkeypatch: pytest.MonkeyPatch,
    desde: str | None,
) -> None:
    if desde is not None:
        command.upgrade(config_alembic(), desde)
    acl_antes = _acl(motor_bd_vacia)
    monkeypatch.setenv(
        VARIABLE_URL_MIGRACION,
        url_bd_vacia.set(
            username=rol_app.nombre, password=rol_app.password
        ).render_as_string(hide_password=False),
    )

    with pytest.raises(DBAPIError) as error:
        command.upgrade(config_alembic(), "head")

    assert _denegado(error.value), repr(error.value.orig)
    assert _version(motor_bd_vacia) == desde
    assert _acl(motor_bd_vacia) == acl_antes
