"""Migraciones de Alembic (F1.07, diseño §5 y §6).

Cada prueba trabaja en una base vacía propia dentro del contenedor de la sesión.

"Sin diferencias con los modelos" se demuestra de dos formas porque ninguna basta sola:

- ``compare_metadata`` es lo que usa ``alembic check``, pero no compara los CHECK.
- La comparación de catálogos crea una base con la migración y otra con
  ``Base.metadata.create_all`` y exige que PostgreSQL describa igual columnas,
  restricciones (con su definición completa) e índices.
"""

import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine, create_engine, inspect, text
from sqlalchemy.engine import URL

from api.db.config import VARIABLE_URL_MIGRACION, ConfiguracionBDError
from api.db.modelos import Base
from api.db.tests.soporte_postgres import (
    RUTA_ALEMBIC_INI,
    CredencialRol,
    borrar_bd,
    config_alembic,
    crear_bd,
)

BD_MIGRACION = "gk_migracion"
BD_MODELOS = "gk_modelos"
TABLAS_ESPERADAS = {"aplicacion", "api_key", "archivo", "resultado_analisis"}
REVISION_INICIAL = "0001_esquema_inicial"
REVISION_PERMISOS = "0002_permisos_gk_app"


@pytest.fixture
def url_migracion(
    motor_postgres: Engine,
    url_postgres: URL,
    rol_app: CredencialRol,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[URL]:
    """Base vacía, con su URL en la variable de entorno que lee ``env.py``.

    Depende de ``rol_app`` porque la 0002 exige que el rol de la API ya exista.
    """
    borrar_bd(motor_postgres, BD_MIGRACION)
    crear_bd(motor_postgres, BD_MIGRACION)
    url = url_postgres.set(database=BD_MIGRACION)
    monkeypatch.setenv(
        VARIABLE_URL_MIGRACION, url.render_as_string(hide_password=False)
    )
    try:
        yield url
    finally:
        borrar_bd(motor_postgres, BD_MIGRACION)


@pytest.fixture
def con_migrada(url_migracion: URL) -> Iterator[Connection]:
    """Conexión a la base ya migrada a ``head``."""
    command.upgrade(config_alembic(), "head")
    motor = create_engine(url_migracion)
    try:
        with motor.connect() as con:
            yield con
    finally:
        motor.dispose()


def _tablas(url: URL) -> set[str]:
    motor = create_engine(url)
    try:
        with motor.connect() as con:
            return set(inspect(con).get_table_names())
    finally:
        motor.dispose()


def _catalogo(con: Connection) -> dict[str, set[tuple[object, ...]]]:
    """Cómo describe PostgreSQL el esquema, sin la tabla de control de Alembic."""
    columnas = con.execute(
        text(
            "SELECT table_name, ordinal_position, column_name, data_type,"
            " character_maximum_length, is_nullable, column_default,"
            " is_identity, identity_generation"
            " FROM information_schema.columns"
            " WHERE table_schema = 'public' AND table_name <> 'alembic_version'"
        )
    ).all()
    restricciones = con.execute(
        text(
            "SELECT conrelid::regclass::text, conname, contype,"
            " pg_get_constraintdef(oid)"
            " FROM pg_constraint"
            " WHERE connamespace = 'public'::regnamespace"
            " AND conrelid::regclass::text <> 'alembic_version'"
        )
    ).all()
    indices = con.execute(
        text(
            "SELECT tablename, indexname, indexdef FROM pg_indexes"
            " WHERE schemaname = 'public' AND tablename <> 'alembic_version'"
        )
    ).all()
    return {
        "columnas": {tuple(f) for f in columnas},
        "restricciones": {tuple(f) for f in restricciones},
        "indices": {tuple(f) for f in indices},
    }


def test_upgrade_downgrade_upgrade_sobre_bd_vacia(url_migracion: URL) -> None:
    config = config_alembic()
    assert _tablas(url_migracion) == set()

    command.upgrade(config, "head")
    assert _tablas(url_migracion) == TABLAS_ESPERADAS | {"alembic_version"}

    command.downgrade(config, "base")
    assert _tablas(url_migracion) == {"alembic_version"}, "el downgrade dejó tablas"

    command.upgrade(config, "head")
    assert _tablas(url_migracion) == TABLAS_ESPERADAS | {"alembic_version"}


def test_hay_una_sola_cabeza_y_es_la_de_permisos() -> None:
    guion = ScriptDirectory.from_config(config_alembic())
    assert guion.get_heads() == [REVISION_PERMISOS]
    permisos = guion.get_revision(REVISION_PERMISOS)
    assert permisos is not None
    assert permisos.down_revision == REVISION_INICIAL


def test_alembic_no_detecta_diferencias_con_los_modelos(
    con_migrada: Connection,
) -> None:
    contexto = MigrationContext.configure(
        con_migrada,
        opts={"compare_type": True, "compare_server_default": True},
    )
    assert compare_metadata(contexto, Base.metadata) == []


def test_catalogo_de_la_migracion_igual_al_de_los_modelos(
    con_migrada: Connection, motor_postgres: Engine, url_postgres: URL
) -> None:
    borrar_bd(motor_postgres, BD_MODELOS)
    crear_bd(motor_postgres, BD_MODELOS)
    motor = create_engine(url_postgres.set(database=BD_MODELOS))
    try:
        Base.metadata.create_all(motor)
        with motor.connect() as con:
            desde_modelos = _catalogo(con)
    finally:
        motor.dispose()
        borrar_bd(motor_postgres, BD_MODELOS)

    desde_migracion = _catalogo(con_migrada)
    assert desde_migracion["columnas"] == desde_modelos["columnas"]
    assert desde_migracion["restricciones"] == desde_modelos["restricciones"]
    assert desde_migracion["indices"] == desde_modelos["indices"]
    assert desde_migracion["restricciones"], "la comparación no vio ninguna restricción"


def test_la_migracion_usa_url_migraciones(monkeypatch: pytest.MonkeyPatch) -> None:
    # Sin la variable, env.py falla con el error de config.py: no hay URL de respaldo.
    monkeypatch.delenv(VARIABLE_URL_MIGRACION, raising=False)
    with pytest.raises(ConfiguracionBDError, match=VARIABLE_URL_MIGRACION):
        command.upgrade(config_alembic(), "head")


def test_la_cli_de_alembic_funciona_desde_otro_directorio(
    url_migracion: URL, tmp_path: Path
) -> None:
    # Dentro de pytest "api" ya se importa; aquí se comprueba el ini tal como lo usa quien
    # migra de verdad, en un proceso nuevo y fuera de la raíz del repositorio.
    resultado = subprocess.run(
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            str(RUTA_ALEMBIC_INI),
            "upgrade",
            "head",
        ],
        cwd=tmp_path,
        env=os.environ,
        capture_output=True,
        text=True,
        check=False,
    )
    assert resultado.returncode == 0, resultado.stderr
    assert _tablas(url_migracion) == TABLAS_ESPERADAS | {"alembic_version"}
