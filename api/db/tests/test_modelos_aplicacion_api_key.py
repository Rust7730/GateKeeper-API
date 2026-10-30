"""Modelos ``aplicacion`` y ``api_key`` (F1.07, commit 4; diseño §3).

Cada prueba crea el esquema con ``Base.metadata.create_all`` dentro de la transacción
del fixture ``conexion``, que se revierte al terminar: el DDL tampoco sobrevive. Los
errores esperados se provocan dentro de ``conexion.begin_nested()`` (savepoint) para no
perder la transacción, y se comprueba **qué** restricción los rechazó con
``diag.constraint_name``: así la prueba demuestra a la vez el rechazo y el nombre.

- ``api_key.hash`` es el HMAC-SHA-256 de la key en hex minúsculas (V13); nunca la key.
  Los valores de prueba son aleatorios (``secrets.token_hex``), no secretos reales.
- La latencia del ``INSERT`` de ``api_key`` se mide con 1000 inserciones (p95) dentro
  de la transacción de la prueba (sin el ``COMMIT``); el tope es holgado para detectar
  regresiones sin volverse inestable.
"""

import secrets
import statistics
import time
import uuid
from datetime import datetime
from typing import Any

import pytest
from sqlalchemy import Connection, Executable, insert, select, text
from sqlalchemy.exc import IntegrityError

from api.db.modelos import ApiKey, Aplicacion, Base

INSERCIONES_LATENCIA = 1000
TOPE_P95_MS = 20.0


@pytest.fixture
def esquema(conexion: Connection) -> Connection:
    """La conexión de la prueba con las tablas de los modelos ya creadas."""
    Base.metadata.create_all(conexion)
    return conexion


def _hash_hmac() -> str:
    """64 caracteres hex en minúsculas, con la forma de un HMAC-SHA-256 (no es uno real)."""
    return secrets.token_hex(32)


def _prefijo() -> str:
    return f"gk_{secrets.token_hex(4)}"


def _crear_aplicacion(con: Connection, nombre: str | None = None) -> uuid.UUID:
    sentencia = (
        insert(Aplicacion)
        .values(nombre=nombre or f"app-{uuid.uuid4()}")
        .returning(Aplicacion.id)
    )
    return con.execute(sentencia).scalar_one()


def _insert_api_key(aplicacion_id: Any, **cambios: Any) -> Executable:
    valores = {
        "aplicacion_id": aplicacion_id,
        "prefijo": _prefijo(),
        "hash": _hash_hmac(),
    }
    valores.update(cambios)
    return insert(ApiKey).values(**valores)


def _rechazada_por(con: Connection, sentencia: Executable, restriccion: str) -> None:
    """Exige que la BD rechace la sentencia por la restricción nombrada."""
    with pytest.raises(IntegrityError) as error, con.begin_nested():
        con.execute(sentencia)
    assert error.value.orig is not None
    assert error.value.orig.diag.constraint_name == restriccion  # type: ignore[attr-defined]


# --- Inserción válida y valores por defecto ---------------------------------------


def test_aplicacion_valida_toma_los_valores_por_defecto(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema, "portal-clientes")
    fila = esquema.execute(select(Aplicacion).where(Aplicacion.id == app_id)).one()

    assert isinstance(fila.id, uuid.UUID)
    assert fila.nombre == "portal-clientes"
    assert fila.activa is True
    assert isinstance(fila.creada_en, datetime)
    assert fila.creada_en.tzinfo is not None, "creada_en debe ser timestamptz"


def test_api_key_valida_toma_los_valores_por_defecto(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema)
    hash_hmac = _hash_hmac()
    key_id = esquema.execute(
        _insert_api_key(app_id, prefijo="gk_a1b2c3d4", hash=hash_hmac).returning(
            ApiKey.id
        )
    ).scalar_one()
    fila = esquema.execute(select(ApiKey).where(ApiKey.id == key_id)).one()

    assert isinstance(fila.id, uuid.UUID)
    assert fila.aplicacion_id == app_id
    assert fila.prefijo == "gk_a1b2c3d4"
    assert fila.hash == hash_hmac
    assert fila.creada_en.tzinfo is not None, "creada_en debe ser timestamptz"
    assert fila.revocada_en is None, "una key nueva está activa"


def test_tipos_de_columna_en_la_bd(esquema: Connection) -> None:
    filas = esquema.execute(
        text(
            "SELECT table_name, column_name, data_type, character_maximum_length,"
            " is_nullable FROM information_schema.columns"
            " WHERE table_schema = current_schema()"
            " AND table_name IN ('aplicacion', 'api_key')"
        )
    ).all()
    columnas = {(f.table_name, f.column_name): f[2:] for f in filas}

    assert columnas == {
        ("aplicacion", "id"): ("uuid", None, "NO"),
        ("aplicacion", "nombre"): ("text", None, "NO"),
        ("aplicacion", "activa"): ("boolean", None, "NO"),
        ("aplicacion", "creada_en"): ("timestamp with time zone", None, "NO"),
        ("api_key", "id"): ("uuid", None, "NO"),
        ("api_key", "aplicacion_id"): ("uuid", None, "NO"),
        ("api_key", "prefijo"): ("text", None, "NO"),
        ("api_key", "hash"): ("character", 64, "NO"),
        ("api_key", "creada_en"): ("timestamp with time zone", None, "NO"),
        ("api_key", "revocada_en"): ("timestamp with time zone", None, "YES"),
    }


# --- Unicidad y claves foráneas -----------------------------------------------------


def test_nombre_de_aplicacion_repetido_se_rechaza(esquema: Connection) -> None:
    _crear_aplicacion(esquema, "repetida")
    _rechazada_por(
        esquema, insert(Aplicacion).values(nombre="repetida"), "uq_aplicacion_nombre"
    )


def test_api_key_de_aplicacion_inexistente_se_rechaza(esquema: Connection) -> None:
    _rechazada_por(
        esquema,
        _insert_api_key(uuid.uuid4()),
        "fk_api_key_aplicacion_id_aplicacion",
    )


def test_prefijo_repetido_se_rechaza(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema)
    esquema.execute(_insert_api_key(app_id, prefijo="gk_repetido"))
    _rechazada_por(
        esquema, _insert_api_key(app_id, prefijo="gk_repetido"), "uq_api_key_prefijo"
    )


def test_hash_repetido_se_rechaza(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema)
    hash_hmac = _hash_hmac()
    esquema.execute(_insert_api_key(app_id, hash=hash_hmac))
    # Otra aplicación tampoco puede registrar el mismo hash.
    otra_app = _crear_aplicacion(esquema)
    _rechazada_por(
        esquema, _insert_api_key(otra_app, hash=hash_hmac), "uq_api_key_hash"
    )


# --- Formato del hash (V13) ---------------------------------------------------------


@pytest.mark.parametrize(
    ("caso", "valor"),
    [
        ("mayusculas", lambda: "A" + _hash_hmac()[1:]),
        ("longitud_63", lambda: _hash_hmac()[:63]),
        ("no_hex", lambda: "g" + _hash_hmac()[1:]),
        ("vacio", lambda: ""),
    ],
)
def test_hash_que_no_es_hex_minusculas_de_64_se_rechaza(
    esquema: Connection, caso: str, valor: Any
) -> None:
    app_id = _crear_aplicacion(esquema)
    _rechazada_por(
        esquema, _insert_api_key(app_id, hash=valor()), "ck_api_key_hash_hex"
    )


@pytest.mark.parametrize(
    ("modelo", "columna"),
    [
        (Aplicacion, "nombre"),
        (ApiKey, "aplicacion_id"),
        (ApiKey, "prefijo"),
        (ApiKey, "hash"),
    ],
)
def test_columnas_obligatorias_rechazan_null(
    esquema: Connection, modelo: type[Base], columna: str
) -> None:
    if modelo is Aplicacion:
        sentencia = insert(Aplicacion).values(nombre=None)
    else:
        sentencia = _insert_api_key(_crear_aplicacion(esquema)).values(
            **{columna: None}
        )
    with pytest.raises(IntegrityError) as error, esquema.begin_nested():
        esquema.execute(sentencia)
    assert error.value.orig is not None
    assert error.value.orig.sqlstate == "23502"  # not_null_violation
    assert error.value.orig.diag.column_name == columna  # type: ignore[attr-defined]


# --- Convención de nombres ------------------------------------------------------------


def test_restricciones_con_nombre_segun_la_convencion(esquema: Connection) -> None:
    filas = esquema.execute(
        text(
            "SELECT conrelid::regclass::text AS tabla, conname, contype"
            " FROM pg_constraint"
            " WHERE conrelid = ANY(CAST(:tablas AS regclass[]))"
        ),
        {"tablas": ["aplicacion", "api_key"]},
    ).all()

    assert {(f.tabla, f.conname, f.contype) for f in filas} == {
        ("aplicacion", "pk_aplicacion", "p"),
        ("aplicacion", "uq_aplicacion_nombre", "u"),
        ("api_key", "pk_api_key", "p"),
        ("api_key", "fk_api_key_aplicacion_id_aplicacion", "f"),
        ("api_key", "uq_api_key_prefijo", "u"),
        ("api_key", "uq_api_key_hash", "u"),
        ("api_key", "ck_api_key_hash_hex", "c"),
    }


def test_indices_con_nombre_segun_la_convencion(esquema: Connection) -> None:
    filas = esquema.execute(
        text(
            "SELECT tablename, indexname FROM pg_indexes"
            " WHERE schemaname = current_schema()"
            " AND tablename IN ('aplicacion', 'api_key')"
        )
    ).all()

    # Los de PK y UNIQUE los crea PostgreSQL con el nombre de la restricción; el de
    # aplicacion_id sirve para listar y revocar las keys de una aplicación.
    assert {(f.tablename, f.indexname) for f in filas} == {
        ("aplicacion", "pk_aplicacion"),
        ("aplicacion", "uq_aplicacion_nombre"),
        ("api_key", "pk_api_key"),
        ("api_key", "uq_api_key_prefijo"),
        ("api_key", "uq_api_key_hash"),
        ("api_key", "ix_api_key_aplicacion_id"),
    }


# --- Latencia -----------------------------------------------------------------------


def test_latencia_insert_api_key_p95(esquema: Connection, record_property: Any) -> None:
    app_id = _crear_aplicacion(esquema)
    tiempos_ms = []
    for _ in range(INSERCIONES_LATENCIA):
        sentencia = _insert_api_key(app_id).returning(ApiKey.id)
        inicio = time.perf_counter()
        esquema.execute(sentencia).scalar_one()
        tiempos_ms.append((time.perf_counter() - inicio) * 1000)

    p95 = statistics.quantiles(tiempos_ms, n=100)[94]
    mediana = statistics.median(tiempos_ms)
    record_property("insert_api_key_p95_ms", round(p95, 3))
    print(
        f"\nINSERT api_key ({INSERCIONES_LATENCIA}, sin COMMIT): "
        f"p50 = {mediana:.3f} ms, p95 = {p95:.3f} ms"
    )
    assert p95 < TOPE_P95_MS, f"p95 del INSERT de api_key = {p95:.2f} ms"
