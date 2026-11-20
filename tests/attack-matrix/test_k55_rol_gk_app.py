"""Rol `gk_app` con permisos mínimos (migración 0002; prerrequisito de K55 para abrir al público).

La API se conecta como `gk_app`, no como dueño del esquema. Si alguien encuentra una inyección SQL o
toma el proceso de la API, con `gk_app` no puede borrar ni truncar nada, ni cambiar el esquema, ni
crear objetos (CWE-89, CWE-269, INV-08: la bitácora no se borra). Y aun así la API hace todo su
trabajo: autenticar, recibir con el cupo de K48, analizar hasta `limpio`, entregar y el barrido al
arrancar (K51).

Permisos esperados (diseño de la apertura, §3):
- `aplicacion`, `api_key`, `archivo`: SELECT, INSERT, UPDATE.
- `resultado_analisis`: SELECT, INSERT.
- Ningún DELETE, TRUNCATE, REFERENCES ni TRIGGER; ninguno sobre `alembic_version`; dueño de nada.

El rol `gk_app` lo crea la infraestructura; aquí, el fixture ``rol_app`` de gk-db, con contraseña
aleatoria. Las pruebas entran con él tal como la API en producción.
"""

from collections.abc import Iterator

import pytest
from alembic import command
from generadores import png
from soporte_matriz import Banco, abrir_banco, exigir_limpio
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError

from api.db.config import VARIABLE_URL_MIGRACION
from api.db.tests.soporte_postgres import (
    CredencialRol,
    borrar_bd,
    config_alembic,
    crear_bd,
)

ROL_APP = "gk_app"
BD_PERMISOS = "gk_matriz_permisos"
TABLAS = ("aplicacion", "api_key", "archivo", "resultado_analisis")
PRIVILEGIOS = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)
ESPERADOS = {
    "aplicacion": {"SELECT", "INSERT", "UPDATE"},
    "api_key": {"SELECT", "INSERT", "UPDATE"},
    "archivo": {"SELECT", "INSERT", "UPDATE"},
    "resultado_analisis": {"SELECT", "INSERT"},
    "alembic_version": set(),
}
SIN_PRIVILEGIO = "42501"  # insufficient_privilege


@pytest.fixture(scope="module")
def bases_gk_app(
    motor_postgres: Engine, url_postgres: URL, rol_app: CredencialRol
) -> Iterator[tuple[URL, URL]]:
    """``(url del dueño, url como gk_app)`` de una base propia migrada a ``head``.

    El rol lo crea ``rol_app`` (gk-db) como lo hará la infraestructura. La base es propia para que
    una sentencia destructiva que pasara por error no dañe la de las demás pruebas.
    """
    url_dueno = url_postgres.set(database=BD_PERMISOS)
    crear_bd(motor_postgres, BD_PERMISOS)
    try:
        with pytest.MonkeyPatch.context() as parche:
            parche.setenv(
                VARIABLE_URL_MIGRACION, url_dueno.render_as_string(hide_password=False)
            )
            command.upgrade(config_alembic(), "head")
        yield (
            url_dueno,
            url_dueno.set(username=rol_app.nombre, password=rol_app.password),
        )
    finally:
        borrar_bd(motor_postgres, BD_PERMISOS)


@pytest.fixture(scope="module")
def motor_app(bases_gk_app) -> Iterator[Engine]:
    motor = create_engine(bases_gk_app[1], isolation_level="AUTOCOMMIT")
    try:
        with motor.connect() as con:
            assert con.execute(text("SELECT current_user")).scalar_one() == ROL_APP, (
                "la conexión de prueba no quedó como gk_app"
            )
        yield motor
    finally:
        motor.dispose()


def _privilegios(motor: Engine, tabla: str) -> set[str]:
    with motor.connect() as con:
        return {
            privilegio
            for privilegio in PRIVILEGIOS
            if con.execute(
                text("SELECT has_table_privilege(:rol, :tabla, :p)"),
                {"rol": ROL_APP, "tabla": f"public.{tabla}", "p": privilegio},
            ).scalar_one()
        }


def _exigir_que_la_api_puede_trabajar(motor: Engine) -> None:
    """Sin esto, un rol sin ningún permiso pasaría todas las pruebas de "no puede"."""
    for tabla in TABLAS:
        assert "SELECT" in _privilegios(motor, tabla), (
            f"gk_app no puede leer {tabla}: falta la migración 0002"
        )


def _exigir_denegado(motor: Engine, sentencia: str) -> None:
    _exigir_que_la_api_puede_trabajar(motor)
    with pytest.raises(DBAPIError) as error, motor.connect() as con:
        con.execute(text(sentencia))
    estado = getattr(error.value.orig, "sqlstate", None)
    assert estado == SIN_PRIVILEGIO, (
        f"`{sentencia}` falló con {estado}, no por permisos"
    )


@pytest.mark.parametrize("tabla", [*TABLAS, "alembic_version"])
def test_k55_gk_app_tiene_exactamente_los_permisos_de_la_api(motor_app, tabla):
    _exigir_que_la_api_puede_trabajar(motor_app)
    assert _privilegios(motor_app, tabla) == ESPERADOS[tabla]


@pytest.mark.parametrize("tabla", TABLAS)
@pytest.mark.parametrize(
    "sentencia",
    [
        "DELETE FROM {t}",
        "TRUNCATE {t} CASCADE",
        "ALTER TABLE {t} ADD COLUMN gk_matriz integer",
        "ALTER TABLE {t} DISABLE TRIGGER ALL",
        "DROP TABLE {t} CASCADE",
    ],
    ids=["delete", "truncate", "alter", "alter_trigger", "drop"],
)
def test_k55_gk_app_no_puede_borrar_ni_cambiar_el_esquema(motor_app, tabla, sentencia):
    _exigir_denegado(motor_app, sentencia.format(t=tabla))


@pytest.mark.parametrize(
    "sentencia",
    [
        "CREATE TABLE public.gk_matriz (id integer)",
        "CREATE SCHEMA gk_matriz",
        "CREATE FUNCTION public.gk_matriz() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
        "CREATE VIEW public.gk_matriz AS SELECT 1",
        "DROP TABLE alembic_version",
        "UPDATE alembic_version SET version_num = 'x'",
    ],
    ids=["tabla", "esquema", "funcion", "vista", "drop_alembic", "update_alembic"],
)
def test_k55_gk_app_no_puede_crear_objetos_ni_tocar_las_migraciones(
    motor_app, sentencia
):
    _exigir_denegado(motor_app, sentencia)


def test_k55_gk_app_no_es_dueno_de_nada(motor_app):
    _exigir_que_la_api_puede_trabajar(motor_app)
    with motor_app.connect() as con:
        propios = con.execute(
            text(
                "SELECT (SELECT count(*) FROM pg_class WHERE relowner = r.oid)"
                " + (SELECT count(*) FROM pg_namespace WHERE nspowner = r.oid)"
                " + (SELECT count(*) FROM pg_proc WHERE proowner = r.oid)"
                " + (SELECT count(*) FROM pg_type WHERE typowner = r.oid)"
                " FROM pg_roles r WHERE r.rolname = :rol"
            ),
            {"rol": ROL_APP},
        ).scalar_one()
    assert propios == 0, f"gk_app es dueño de {propios} objetos"


# --------------------------------------------------------------------- la API entera con gk_app


@pytest.fixture
def banco_gk_app(bases_gk_app, tmp_path, url_redis) -> Iterator[Banco]:
    url_dueno, _ = bases_gk_app
    motor = create_engine(url_dueno)
    try:
        with motor.begin() as con:
            con.execute(
                text("TRUNCATE resultado_analisis, archivo, api_key, aplicacion")
            )
    finally:
        motor.dispose()
    with abrir_banco(url_dueno, tmp_path, url_redis) as abierto:
        yield abierto


def test_k55_la_api_conectada_como_gk_app_hace_todo_su_trabajo(
    banco_gk_app, bases_gk_app
):
    """Barrido al arrancar, 401, subida con cupo, análisis hasta `limpio`, estado y descarga."""
    banco = banco_gk_app
    huerfano = banco.sembrar_archivo("pendiente", banco.app_a)
    with banco.api(url_bd=bases_gk_app[1]) as cliente:
        assert banco.fila(huerfano)["estado"] == "error", (
            "K51: el barrido no corrió con gk_app"
        )
        assert cliente.post_archivo(png(), key="no-es-una-key").status_code == 401
        archivo_id, _ = exigir_limpio(cliente, banco, png(), tipo_esperado="image/png")
        assert cliente.ver(archivo_id).status_code == 200
        assert cliente.ver(archivo_id, key=banco.app_b.key).status_code == 404
