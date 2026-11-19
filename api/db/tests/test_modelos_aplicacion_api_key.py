"""Modelos ``aplicacion`` y ``api_key`` (F1.07, commit 4; diseño §3).

Cada prueba crea el esquema con ``Base.metadata.create_all`` dentro de la transacción
del fixture ``conexion``, que se revierte al terminar: el DDL tampoco sobrevive. Los
errores esperados se provocan dentro de ``conexion.begin_nested()`` (savepoint) para no
perder la transacción, y se comprueba **qué** restricción los rechazó con
``diag.constraint_name``: así la prueba demuestra a la vez el rechazo y el nombre.

- ``api_key.hash`` es el HMAC-SHA-256 de la key en hex minúsculas (V13); nunca la key.
  Los valores de prueba son aleatorios (``secrets.token_hex``), no secretos reales.
- ``api_key.prefijo`` es ``gk_`` + 12 hex minúsculas (48 bits) que genera el servidor,
  independiente de la parte secreta. Los prefijos fijos de estas pruebas son de ejemplo.
- ``aplicacion.nombre`` tiene de 1 a 100 caracteres, no empieza ni termina con espacio
  en blanco Unicode, no contiene caracteres de control (U+0000–U+001F, U+007F) y es
  único sin distinguir mayúsculas (índice único sobre ``lower(nombre)``).
- Borrar una aplicación que todavía tiene keys se rechaza (``ON DELETE RESTRICT``).
- La latencia del ``INSERT`` de ``aplicacion`` y del de ``api_key`` se mide con 1000
  inserciones (p95) dentro de la transacción de la prueba (sin el ``COMMIT``); el tope
  es holgado para detectar regresiones sin volverse inestable. En GitHub Actions se
  multiplica por ``GATEKEEPER_FACTOR_LATENCIA`` (K56; ver ``latencia.py``).
"""

import secrets
import statistics
import time
import uuid
from datetime import datetime
from typing import Any

import pytest
from sqlalchemy import Connection, Executable, delete, insert, select, text
from sqlalchemy.exc import IntegrityError

from api.db.modelos import ApiKey, Aplicacion, Base
from api.db.tests.latencia import exigir_tope_ms

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
    """``gk_`` + 12 hex minúsculas, como los que genera el servidor."""
    return f"gk_{secrets.token_hex(6)}"


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
        _insert_api_key(app_id, prefijo="gk_a1b2c3d4e5f6", hash=hash_hmac).returning(
            ApiKey.id
        )
    ).scalar_one()
    fila = esquema.execute(select(ApiKey).where(ApiKey.id == key_id)).one()

    assert isinstance(fila.id, uuid.UUID)
    assert fila.aplicacion_id == app_id
    assert fila.prefijo == "gk_a1b2c3d4e5f6"
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


@pytest.mark.parametrize(
    ("primero", "segundo"),
    [
        ("repetida", "repetida"),
        ("Portal", "portal"),
        ("portal", "PORTAL"),
    ],
)
def test_nombre_de_aplicacion_repetido_sin_distinguir_mayusculas_se_rechaza(
    esquema: Connection, primero: str, segundo: str
) -> None:
    _crear_aplicacion(esquema, primero)
    _rechazada_por(
        esquema,
        insert(Aplicacion).values(nombre=segundo),
        "uq_aplicacion_nombre_lower",
    )


def test_api_key_de_aplicacion_inexistente_se_rechaza(esquema: Connection) -> None:
    _rechazada_por(
        esquema,
        _insert_api_key(uuid.uuid4()),
        "fk_api_key_aplicacion_id_aplicacion",
    )


def test_prefijo_repetido_se_rechaza(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema)
    esquema.execute(_insert_api_key(app_id, prefijo="gk_0123456789ab"))
    _rechazada_por(
        esquema,
        _insert_api_key(app_id, prefijo="gk_0123456789ab"),
        "uq_api_key_prefijo",
    )


def test_borrar_aplicacion_con_keys_se_rechaza(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema)
    esquema.execute(_insert_api_key(app_id))
    _rechazada_por(
        esquema,
        delete(Aplicacion).where(Aplicacion.id == app_id),
        "fk_api_key_aplicacion_id_aplicacion",
    )


def test_borrar_aplicacion_sin_keys_se_permite(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema)
    borradas = esquema.execute(delete(Aplicacion).where(Aplicacion.id == app_id))
    assert borradas.rowcount == 1


def test_fk_de_api_key_declara_on_delete_restrict(esquema: Connection) -> None:
    # NO ACTION (el valor por omisión) también rechazaría el DELETE de la prueba
    # anterior; el catálogo demuestra que RESTRICT es explícito y no se difiere.
    accion = esquema.execute(
        text(
            "SELECT confdeltype FROM pg_constraint"
            " WHERE conname = 'fk_api_key_aplicacion_id_aplicacion'"
        )
    ).scalar_one()
    assert accion == "r", f"ON DELETE esperado RESTRICT ('r'), es {accion!r}"


def test_hash_repetido_se_rechaza(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema)
    hash_hmac = _hash_hmac()
    esquema.execute(_insert_api_key(app_id, hash=hash_hmac))
    # Otra aplicación tampoco puede registrar el mismo hash.
    otra_app = _crear_aplicacion(esquema)
    _rechazada_por(
        esquema, _insert_api_key(otra_app, hash=hash_hmac), "uq_api_key_hash"
    )


# --- Nombre de la aplicación ---------------------------------------------------------
#
# Regla: 1 a 100 caracteres (no bytes), sin espacio en blanco Unicode en los extremos
# (``ck_aplicacion_nombre_valido``) y sin caracteres de control C0, U+007F ni C1
# (U+0080–U+009F) en ninguna posición (``ck_aplicacion_nombre_sin_control``). PostgreSQL
# prueba los CHECK en orden alfabético por nombre (documentado en CREATE TABLE), así que
# un nombre que rompe las dos reglas (p. ej. "\t") lo rechaza ``..._sin_control``. Que la
# regla de bordes cubre también esos casos por sí sola lo demuestra una prueba aparte.

_RECHAZADOS_POR_BORDES_O_LONGITUD = [
    ("vacio", ""),
    ("solo_espacios", "   "),
    ("101_caracteres", "a" * 101),
    ("101_caracteres_multibyte", "ñ" * 101),
    ("espacio_al_inicio", " Portal"),
    ("espacio_al_final", "Portal "),
    ("nbsp_al_inicio", " Portal"),
    ("solo_nbsp", " "),
    ("ogham_al_inicio", " Portal"),
    ("em_space_al_final", "Portal "),
    ("narrow_nbsp_al_final", "Portal "),
    ("separador_de_linea_al_inicio", " Portal"),
    ("separador_de_parrafo_al_final", "Portal "),
    ("espacio_matematico_al_inicio", " Portal"),
    ("espacio_ideografico_al_final", "Portal　"),
]

_RECHAZADOS_POR_CONTROL = [
    ("tabulador_solo", "\t"),
    ("salto_de_linea_solo", "\n"),
    ("tabulador_al_inicio", "\tPortal"),
    ("salto_de_linea_al_final", "Portal\n"),
    ("retorno_de_carro_al_final", "Portal\r"),
    ("campana_en_medio", "Por\x07tal"),
    ("tabulador_en_medio", "Por\ttal"),
    ("salto_de_linea_en_medio", "Por\ntal"),
    ("u0001_en_medio", "Por\x01tal"),
    ("escape_en_medio", "Por\x1btal"),
    ("u001f_en_medio", "Por\x1ftal"),
    ("del_en_medio", "Por\x7ftal"),
    ("c1_primero_u0080_en_medio", "Por\x80tal"),
    ("c1_nel_u0085_en_medio", "Por\x85tal"),
    ("c1_csi_u009b_en_medio", "Por\x9btal"),
    ("c1_ultimo_u009f_en_medio", "Por\x9ftal"),
    ("c1_u0080_al_inicio", "\x80Portal"),
    ("c1_u009f_al_final", "Portal\x9f"),
    ("c1_solo", "\x85"),
    ("nel_al_final", "Portal\u0085"),
]


@pytest.mark.parametrize(("caso", "nombre"), _RECHAZADOS_POR_BORDES_O_LONGITUD)
def test_nombre_con_bordes_o_longitud_invalidos_se_rechaza(
    esquema: Connection, caso: str, nombre: str
) -> None:
    _rechazada_por(
        esquema,
        insert(Aplicacion).values(nombre=nombre),
        "ck_aplicacion_nombre_valido",
    )


@pytest.mark.parametrize(("caso", "nombre"), _RECHAZADOS_POR_CONTROL)
def test_nombre_con_caracteres_de_control_se_rechaza(
    esquema: Connection, caso: str, nombre: str
) -> None:
    _rechazada_por(
        esquema,
        insert(Aplicacion).values(nombre=nombre),
        "ck_aplicacion_nombre_sin_control",
    )


@pytest.mark.parametrize(
    ("caso", "nombre"),
    [
        ("tabulador_solo", "\t"),
        ("salto_de_linea_solo", "\n"),
        ("retorno_de_carro_solo", "\r"),
        ("tabulador_vertical_al_inicio", "\x0bPortal"),
        ("avance_de_pagina_al_final", "Portal\x0c"),
        ("tabulador_al_inicio", "\tPortal"),
        ("salto_de_linea_al_final", "Portal\n"),
        ("nel_al_final", "Portal\u0085"),
    ],
)
def test_bordes_de_control_se_rechazan_aun_sin_la_regla_de_control(
    esquema: Connection, caso: str, nombre: str
) -> None:
    # Defensa en profundidad: la regla de bordes no depende de la de control. Se quita
    # ..._sin_control dentro de un savepoint que se revierte (el DDL es transaccional).
    with esquema.begin_nested() as savepoint:
        esquema.execute(
            text(
                "ALTER TABLE aplicacion DROP CONSTRAINT ck_aplicacion_nombre_sin_control"
            )
        )
        _rechazada_por(
            esquema,
            insert(Aplicacion).values(nombre=nombre),
            "ck_aplicacion_nombre_valido",
        )
        savepoint.rollback()


@pytest.mark.parametrize(
    ("caso", "nombre"),
    [
        ("simple", "Portal"),
        ("espacios_en_medio", "Mi App 2"),
        ("1_caracter", "a"),
        ("100_caracteres", "a" * 100),
        ("100_caracteres_multibyte", "ñ" * 100),
        ("acentos", "Árbol de Datos"),
        # Los vecinos de los rangos de control: el CHECK no debe pasarse de largo.
        ("u007e_vecino_de_del", "Por~tal"),
        ("u00a0_vecino_de_c1", "Por\u00a0tal"),
        ("u00a1_vecino_de_c1", "¡Portal!"),
    ],
)
def test_nombre_de_aplicacion_valido_se_acepta(
    esquema: Connection, caso: str, nombre: str
) -> None:
    app_id = _crear_aplicacion(esquema, nombre)
    guardado = esquema.execute(
        select(Aplicacion.nombre).where(Aplicacion.id == app_id)
    ).scalar_one()
    assert guardado == nombre


# --- Formato del prefijo ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("caso", "prefijo"),
    [
        ("sin_gk", "abcabcabcabc"),
        ("gk_en_mayusculas", "GK_a1b2c3d4e5f6"),
        ("11_hex", "gk_a1b2c3d4e5f"),
        ("13_hex", "gk_a1b2c3d4e5f6a"),
        ("hex_en_mayusculas", "gk_A1B2C3D4E5F6"),
        ("no_hex", "gk_g1b2c3d4e5f6"),
        ("salto_de_linea_final", "gk_a1b2c3d4e5f6\n"),
        ("vacio", ""),
    ],
)
def test_prefijo_con_otro_formato_se_rechaza(
    esquema: Connection, caso: str, prefijo: str
) -> None:
    app_id = _crear_aplicacion(esquema)
    _rechazada_por(
        esquema,
        _insert_api_key(app_id, prefijo=prefijo),
        "ck_api_key_prefijo_formato",
    )


def test_prefijo_valido_se_acepta(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema)
    key_id = esquema.execute(
        _insert_api_key(app_id, prefijo="gk_0123456789ab").returning(ApiKey.id)
    ).scalar_one()
    assert key_id is not None


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
        ("aplicacion", "ck_aplicacion_nombre_valido", "c"),
        ("aplicacion", "ck_aplicacion_nombre_sin_control", "c"),
        ("api_key", "pk_api_key", "p"),
        ("api_key", "fk_api_key_aplicacion_id_aplicacion", "f"),
        ("api_key", "uq_api_key_prefijo", "u"),
        ("api_key", "uq_api_key_hash", "u"),
        ("api_key", "ck_api_key_hash_hex", "c"),
        ("api_key", "ck_api_key_prefijo_formato", "c"),
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
    # aplicacion_id sirve para listar y revocar las keys de una aplicación. El nombre
    # solo es único por lower(nombre): no hay un UNIQUE exacto aparte, que sobraría.
    assert {(f.tablename, f.indexname) for f in filas} == {
        ("aplicacion", "pk_aplicacion"),
        ("aplicacion", "uq_aplicacion_nombre_lower"),
        ("api_key", "pk_api_key"),
        ("api_key", "uq_api_key_prefijo"),
        ("api_key", "uq_api_key_hash"),
        ("api_key", "ix_api_key_aplicacion_id"),
    }


def test_indice_unico_del_nombre_es_sobre_lower(esquema: Connection) -> None:
    definicion = esquema.execute(
        text(
            "SELECT indexdef FROM pg_indexes"
            " WHERE schemaname = current_schema()"
            " AND indexname = 'uq_aplicacion_nombre_lower'"
        )
    ).scalar_one()
    assert definicion.startswith("CREATE UNIQUE INDEX uq_aplicacion_nombre_lower ")
    assert definicion.endswith("USING btree (lower(nombre))")


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
    exigir_tope_ms("p95 del INSERT de api_key", p95, TOPE_P95_MS)


def test_latencia_insert_aplicacion_p95(
    esquema: Connection, record_property: Any
) -> None:
    # Incluye la evaluación de los dos CHECK del nombre (expresiones regulares) y del
    # índice único sobre lower(nombre).
    tiempos_ms = []
    for i in range(INSERCIONES_LATENCIA):
        sentencia = (
            insert(Aplicacion)
            .values(nombre=f"Aplicación de prueba {i:04d}")
            .returning(Aplicacion.id)
        )
        inicio = time.perf_counter()
        esquema.execute(sentencia).scalar_one()
        tiempos_ms.append((time.perf_counter() - inicio) * 1000)

    p95 = statistics.quantiles(tiempos_ms, n=100)[94]
    mediana = statistics.median(tiempos_ms)
    record_property("insert_aplicacion_p95_ms", round(p95, 3))
    print(
        f"\nINSERT aplicacion ({INSERCIONES_LATENCIA}, sin COMMIT): "
        f"p50 = {mediana:.3f} ms, p95 = {p95:.3f} ms"
    )
    exigir_tope_ms("p95 del INSERT de aplicacion", p95, TOPE_P95_MS)
