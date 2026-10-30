"""Modelos ``archivo`` y ``resultado_analisis`` (F1.07, diseño §3).

Igual que en ``test_modelos_aplicacion_api_key.py``: cada prueba crea el esquema dentro
de la transacción del fixture ``conexion`` (se revierte al terminar) y los errores
esperados se provocan en un savepoint, comprobando **qué** restricción rechazó la fila.

Dos trampas de SQL que estas pruebas fijan a propósito:

- Un ``CHECK (x IN (...))`` deja pasar ``NULL``: la expresión da NULL y un CHECK solo
  rechaza FALSE. Por eso ``limpio`` con ``tipo_detectado`` nulo y ``capa``/``veredicto``
  nulos tienen sus propios casos.
- ``detalle`` se mide sobre su texto, no con ``pg_column_size``, que mide la
  representación interna y rechazaría un JSON de exactamente 64 KB.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Connection, Executable, delete, insert, select, text
from sqlalchemy.exc import DataError, IntegrityError

from api.app.estados import TIPOS_ERROR, Estado
from api.db.modelos import (
    Aplicacion,
    Archivo,
    Base,
    ResultadoAnalisis,
)

TAMANO_MAXIMO = 10_485_760  # 10 MiB, igual que Nginx
TOPE_DETALLE = 65_536  # 64 KB


@pytest.fixture
def esquema(conexion: Connection) -> Connection:
    """La conexión de la prueba con las tablas de los modelos ya creadas."""
    Base.metadata.create_all(conexion)
    return conexion


def _crear_aplicacion(con: Connection) -> uuid.UUID:
    sentencia = (
        insert(Aplicacion).values(nombre=f"app-{uuid.uuid4()}").returning(Aplicacion.id)
    )
    return con.execute(sentencia).scalar_one()


def _sha256() -> str:
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()


def _insert_archivo(aplicacion_id: Any, **cambios: Any) -> Executable:
    valores = {
        "aplicacion_id": aplicacion_id,
        "nombre_original": "factura.pdf",
        "tamano_bytes": 1024,
        "sha256": _sha256(),
    }
    valores.update(cambios)
    return insert(Archivo).values(**valores)


def _crear_archivo(con: Connection, **cambios: Any) -> uuid.UUID:
    sentencia = _insert_archivo(_crear_aplicacion(con), **cambios)
    return con.execute(sentencia.returning(Archivo.id)).scalar_one()


def _insert_resultado(archivo_id: Any, **cambios: Any) -> Executable:
    valores = {"archivo_id": archivo_id, "capa": "firma", "veredicto": "limpio"}
    valores.update(cambios)
    return insert(ResultadoAnalisis).values(**valores)


def _rechazada_por(con: Connection, sentencia: Executable, restriccion: str) -> None:
    """Exige que la BD rechace la sentencia por la restricción nombrada."""
    with pytest.raises(IntegrityError) as error, con.begin_nested():
        con.execute(sentencia)
    assert error.value.orig is not None
    assert error.value.orig.diag.constraint_name == restriccion  # type: ignore[attr-defined]


def _rechazada_por_no_nulo(
    con: Connection, sentencia: Executable, columna: str
) -> None:
    with pytest.raises(IntegrityError) as error, con.begin_nested():
        con.execute(sentencia)
    assert error.value.orig is not None
    assert error.value.orig.diag.column_name == columna  # type: ignore[attr-defined]


# --- archivo: valores por defecto e id asignado por la API ------------------------------


def test_archivo_valido_toma_los_valores_por_defecto(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema)
    sha = _sha256()
    archivo_id = esquema.execute(
        _insert_archivo(app_id, sha256=sha).returning(Archivo.id)
    ).scalar_one()
    fila = esquema.execute(select(Archivo).where(Archivo.id == archivo_id)).one()

    assert isinstance(fila.id, uuid.UUID), "sin id, lo genera gen_random_uuid()"
    assert fila.aplicacion_id == app_id
    assert fila.sha256 == sha
    assert fila.estado == "pendiente"
    assert fila.tipo_detectado is None
    assert fila.tipo_error is None
    assert fila.reintentos == 0
    assert fila.creado_en.tzinfo is not None, "creado_en debe ser timestamptz"
    assert fila.analizado_en is None


def test_archivo_acepta_el_id_que_asigna_la_api(esquema: Connection) -> None:
    # INV-03: la API genera el UUID antes de guardar el archivo en disco.
    asignado = uuid.uuid4()
    guardado = esquema.execute(
        _insert_archivo(_crear_aplicacion(esquema), id=asignado).returning(Archivo.id)
    ).scalar_one()
    assert guardado == asignado


def test_tipos_de_columna_de_archivo_en_la_bd(esquema: Connection) -> None:
    filas = esquema.execute(
        text(
            "SELECT column_name, data_type, character_maximum_length, is_nullable"
            " FROM information_schema.columns WHERE table_name = 'archivo'"
        )
    ).all()
    assert {
        f.column_name: (f.data_type, f.character_maximum_length, f.is_nullable)
        for f in filas
    } == {
        "id": ("uuid", None, "NO"),
        "aplicacion_id": ("uuid", None, "NO"),
        "nombre_original": ("character varying", 255, "NO"),
        "tipo_detectado": ("character varying", 100, "YES"),
        "tamano_bytes": ("bigint", None, "NO"),
        "sha256": ("character", 64, "NO"),
        "estado": ("text", None, "NO"),
        "tipo_error": ("text", None, "YES"),
        "reintentos": ("smallint", None, "NO"),
        "creado_en": ("timestamp with time zone", None, "NO"),
        "analizado_en": ("timestamp with time zone", None, "YES"),
    }


@pytest.mark.parametrize("columna", ["nombre_original", "tamano_bytes", "sha256"])
def test_columnas_obligatorias_de_archivo(esquema: Connection, columna: str) -> None:
    _rechazada_por_no_nulo(
        esquema,
        _insert_archivo(_crear_aplicacion(esquema), **{columna: None}),
        columna,
    )


def test_nombre_original_de_256_caracteres_no_cabe(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema)
    with pytest.raises(DataError), esquema.begin_nested():
        esquema.execute(_insert_archivo(app_id, nombre_original="a" * 256))


def test_nombre_original_de_255_caracteres_cabe(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema)
    esquema.execute(_insert_archivo(app_id, nombre_original="ñ" * 255))


# --- archivo: tamaño, sha256, estado, tipo_error, reintentos -----------------------------


@pytest.mark.parametrize("tamano", [0, -1, TAMANO_MAXIMO + 1])
def test_tamano_fuera_de_rango_se_rechaza(esquema: Connection, tamano: int) -> None:
    _rechazada_por(
        esquema,
        _insert_archivo(_crear_aplicacion(esquema), tamano_bytes=tamano),
        "ck_archivo_tamano_bytes_rango",
    )


@pytest.mark.parametrize("tamano", [1, TAMANO_MAXIMO])
def test_tamano_en_los_limites_se_acepta(esquema: Connection, tamano: int) -> None:
    esquema.execute(_insert_archivo(_crear_aplicacion(esquema), tamano_bytes=tamano))


@pytest.mark.parametrize(
    ("caso", "sha"),
    [
        ("mayusculas", "A" * 64),
        ("no_hex", "g" * 64),
        ("63_caracteres", "a" * 63),
        ("con_espacio_final", "a" * 63 + " "),
        ("salto_de_linea_final", "a" * 63 + "\n"),
        ("vacio", ""),
    ],
)
def test_sha256_invalido_se_rechaza(esquema: Connection, caso: str, sha: str) -> None:
    _rechazada_por(
        esquema,
        _insert_archivo(_crear_aplicacion(esquema), sha256=sha),
        "ck_archivo_sha256_hex",
    )


def test_sha256_de_65_caracteres_no_cabe(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema)
    with pytest.raises(DataError), esquema.begin_nested():
        esquema.execute(_insert_archivo(app_id, sha256="a" * 65))


@pytest.mark.parametrize("estado", ["PENDIENTE", "aprobado", "", "limpio "])
def test_estado_desconocido_se_rechaza(esquema: Connection, estado: str) -> None:
    _rechazada_por(
        esquema,
        _insert_archivo(_crear_aplicacion(esquema), estado=estado),
        "ck_archivo_estado_valido",
    )


def test_estado_nulo_se_rechaza(esquema: Connection) -> None:
    _rechazada_por_no_nulo(
        esquema, _insert_archivo(_crear_aplicacion(esquema), estado=None), "estado"
    )


@pytest.mark.parametrize("estado", list(Estado))
def test_los_estados_del_dominio_son_los_del_check(
    esquema: Connection, estado: Estado
) -> None:
    # Si el dominio ganara un estado sin que el CHECK lo admita, esta prueba falla.
    extra: dict[str, str] = {}
    if estado is Estado.ERROR:
        extra["tipo_error"] = "final"
    if estado is Estado.LIMPIO:
        extra["tipo_detectado"] = "image/png"
    esquema.execute(
        _insert_archivo(_crear_aplicacion(esquema), estado=estado.value, **extra)
    )


@pytest.mark.parametrize("tipo_error", sorted(TIPOS_ERROR))
def test_tipos_de_error_del_dominio_son_los_del_check(
    esquema: Connection, tipo_error: str
) -> None:
    esquema.execute(
        _insert_archivo(
            _crear_aplicacion(esquema), estado="error", tipo_error=tipo_error
        )
    )


def test_tipo_error_desconocido_se_rechaza(esquema: Connection) -> None:
    _rechazada_por(
        esquema,
        _insert_archivo(
            _crear_aplicacion(esquema), estado="error", tipo_error="temporal"
        ),
        "ck_archivo_tipo_error_valido",
    )


@pytest.mark.parametrize("reintentos", [-1, 3])
def test_reintentos_fuera_de_rango_se_rechaza(
    esquema: Connection, reintentos: int
) -> None:
    _rechazada_por(
        esquema,
        _insert_archivo(_crear_aplicacion(esquema), reintentos=reintentos),
        "ck_archivo_reintentos_rango",
    )


@pytest.mark.parametrize("reintentos", [0, 1, 2])
def test_reintentos_en_rango_se_acepta(esquema: Connection, reintentos: int) -> None:
    esquema.execute(_insert_archivo(_crear_aplicacion(esquema), reintentos=reintentos))


# --- archivo: reglas entre columnas -----------------------------------------------------


def test_estado_error_sin_tipo_error_se_rechaza(esquema: Connection) -> None:
    _rechazada_por(
        esquema,
        _insert_archivo(_crear_aplicacion(esquema), estado="error"),
        "ck_archivo_tipo_error_solo_en_error",
    )


@pytest.mark.parametrize(
    "estado", ["pendiente", "en_cuarentena", "rechazado", "limpio"]
)
def test_tipo_error_fuera_de_error_se_rechaza(esquema: Connection, estado: str) -> None:
    _rechazada_por(
        esquema,
        _insert_archivo(
            _crear_aplicacion(esquema),
            estado=estado,
            tipo_error="final",
            tipo_detectado="image/png",
        ),
        "ck_archivo_tipo_error_solo_en_error",
    )


@pytest.mark.parametrize("tipo", ["image/jpeg", "image/png", "application/pdf"])
def test_limpio_con_tipo_permitido_se_acepta(esquema: Connection, tipo: str) -> None:
    esquema.execute(
        _insert_archivo(
            _crear_aplicacion(esquema), estado="limpio", tipo_detectado=tipo
        )
    )


@pytest.mark.parametrize(
    "tipo", ["image/gif", "image/svg+xml", "IMAGE/PNG", "image/png ", "application/zip"]
)
def test_limpio_con_tipo_fuera_de_la_lista_se_rechaza(
    esquema: Connection, tipo: str
) -> None:
    _rechazada_por(
        esquema,
        _insert_archivo(
            _crear_aplicacion(esquema), estado="limpio", tipo_detectado=tipo
        ),
        "ck_archivo_limpio_en_lista_blanca",
    )


def test_limpio_sin_tipo_detectado_se_rechaza(esquema: Connection) -> None:
    # La trampa: "NULL IN (...)" da NULL y un CHECK solo rechaza FALSE.
    _rechazada_por(
        esquema,
        _insert_archivo(_crear_aplicacion(esquema), estado="limpio"),
        "ck_archivo_limpio_en_lista_blanca",
    )


@pytest.mark.parametrize("estado", ["rechazado", "en_cuarentena"])
def test_tipo_real_fuera_de_la_lista_se_registra_si_no_es_limpio(
    esquema: Connection, estado: str
) -> None:
    # Defecto que corrigió el CoVe: la lista blanca no puede impedir registrar qué era
    # en realidad un archivo rechazado.
    esquema.execute(
        _insert_archivo(
            _crear_aplicacion(esquema),
            estado=estado,
            tipo_detectado="application/x-dosexec",
        )
    )


# --- archivo: claves foráneas, restricciones e índices -----------------------------------


def test_archivo_de_aplicacion_inexistente_se_rechaza(esquema: Connection) -> None:
    _rechazada_por(
        esquema,
        _insert_archivo(uuid.uuid4()),
        "fk_archivo_aplicacion_id_aplicacion",
    )


def test_borrar_aplicacion_con_archivos_se_rechaza(esquema: Connection) -> None:
    app_id = _crear_aplicacion(esquema)
    esquema.execute(_insert_archivo(app_id))
    _rechazada_por(
        esquema,
        delete(Aplicacion).where(Aplicacion.id == app_id),
        "fk_archivo_aplicacion_id_aplicacion",
    )


def test_borrar_archivo_con_resultados_se_rechaza(esquema: Connection) -> None:
    archivo_id = _crear_archivo(esquema)
    esquema.execute(_insert_resultado(archivo_id))
    _rechazada_por(
        esquema,
        delete(Archivo).where(Archivo.id == archivo_id),
        "fk_resultado_analisis_archivo_id_archivo",
    )


@pytest.mark.parametrize(
    "restriccion",
    [
        "fk_archivo_aplicacion_id_aplicacion",
        "fk_resultado_analisis_archivo_id_archivo",
    ],
)
def test_fk_nuevas_declaran_on_delete_restrict(
    esquema: Connection, restriccion: str
) -> None:
    accion = esquema.execute(
        text("SELECT confdeltype FROM pg_constraint WHERE conname = :nombre"),
        {"nombre": restriccion},
    ).scalar_one()
    assert accion == "r", f"ON DELETE esperado RESTRICT ('r'), es {accion!r}"


def test_restricciones_con_nombre_segun_la_convencion(esquema: Connection) -> None:
    filas = esquema.execute(
        text(
            "SELECT conrelid::regclass::text AS tabla, conname, contype"
            " FROM pg_constraint"
            " WHERE conrelid = ANY(CAST(:tablas AS regclass[]))"
        ),
        {"tablas": ["archivo", "resultado_analisis"]},
    ).all()

    assert {(f.tabla, f.conname, f.contype) for f in filas} == {
        ("archivo", "pk_archivo", "p"),
        ("archivo", "fk_archivo_aplicacion_id_aplicacion", "f"),
        ("archivo", "ck_archivo_tamano_bytes_rango", "c"),
        ("archivo", "ck_archivo_sha256_hex", "c"),
        ("archivo", "ck_archivo_estado_valido", "c"),
        ("archivo", "ck_archivo_tipo_error_valido", "c"),
        ("archivo", "ck_archivo_reintentos_rango", "c"),
        ("archivo", "ck_archivo_tipo_error_solo_en_error", "c"),
        ("archivo", "ck_archivo_limpio_en_lista_blanca", "c"),
        ("resultado_analisis", "pk_resultado_analisis", "p"),
        ("resultado_analisis", "fk_resultado_analisis_archivo_id_archivo", "f"),
        ("resultado_analisis", "ck_resultado_analisis_capa_valida", "c"),
        ("resultado_analisis", "ck_resultado_analisis_veredicto_valido", "c"),
        ("resultado_analisis", "ck_resultado_analisis_detalle_objeto", "c"),
        ("resultado_analisis", "ck_resultado_analisis_detalle_tope", "c"),
        ("resultado_analisis", "ck_resultado_analisis_duracion_ms_no_negativa", "c"),
    }


def test_indices_con_nombre_y_columnas_esperadas(esquema: Connection) -> None:
    filas = esquema.execute(
        text(
            "SELECT tablename, indexname, indexdef FROM pg_indexes"
            " WHERE schemaname = current_schema()"
            " AND tablename IN ('archivo', 'resultado_analisis')"
        )
    ).all()
    definiciones = {(f.tablename, f.indexname): f.indexdef for f in filas}

    assert set(definiciones) == {
        ("archivo", "pk_archivo"),
        ("archivo", "ix_archivo_aplicacion_id_estado"),
        ("archivo", "ix_archivo_aplicacion_id_creado_en"),
        ("resultado_analisis", "pk_resultado_analisis"),
        ("resultado_analisis", "ix_resultado_analisis_archivo_id"),
    }
    assert definiciones[("archivo", "ix_archivo_aplicacion_id_estado")].endswith(
        "USING btree (aplicacion_id, estado)"
    )
    assert definiciones[("archivo", "ix_archivo_aplicacion_id_creado_en")].endswith(
        "USING btree (aplicacion_id, creado_en)"
    )


# --- resultado_analisis -----------------------------------------------------------------


def test_resultado_valido_toma_los_valores_por_defecto(esquema: Connection) -> None:
    archivo_id = _crear_archivo(esquema)
    resultado_id = esquema.execute(
        _insert_resultado(archivo_id).returning(ResultadoAnalisis.id)
    ).scalar_one()
    fila = esquema.execute(
        select(ResultadoAnalisis).where(ResultadoAnalisis.id == resultado_id)
    ).one()

    assert isinstance(fila.id, int)
    assert fila.archivo_id == archivo_id
    assert fila.detalle == {}
    assert fila.duracion_ms is None
    assert fila.creado_en.tzinfo is not None, "creado_en debe ser timestamptz"


def test_tipos_de_columna_de_resultado_en_la_bd(esquema: Connection) -> None:
    filas = esquema.execute(
        text(
            "SELECT column_name, data_type, is_nullable, is_identity"
            " FROM information_schema.columns"
            " WHERE table_name = 'resultado_analisis'"
        )
    ).all()
    assert {
        f.column_name: (f.data_type, f.is_nullable, f.is_identity) for f in filas
    } == {
        "id": ("bigint", "NO", "YES"),
        "archivo_id": ("uuid", "NO", "NO"),
        "capa": ("text", "NO", "NO"),
        "veredicto": ("text", "NO", "NO"),
        "detalle": ("jsonb", "NO", "NO"),
        "duracion_ms": ("integer", "YES", "NO"),
        "creado_en": ("timestamp with time zone", "NO", "NO"),
    }


def test_resultado_de_archivo_inexistente_se_rechaza(esquema: Connection) -> None:
    _rechazada_por(
        esquema,
        _insert_resultado(uuid.uuid4()),
        "fk_resultado_analisis_archivo_id_archivo",
    )


@pytest.mark.parametrize("capa", ["firma", "cdr", "clamav", "virustotal"])
def test_capas_validas_se_aceptan(esquema: Connection, capa: str) -> None:
    esquema.execute(_insert_resultado(_crear_archivo(esquema), capa=capa))


def test_capa_desconocida_se_rechaza(esquema: Connection) -> None:
    _rechazada_por(
        esquema,
        _insert_resultado(_crear_archivo(esquema), capa="yara"),
        "ck_resultado_analisis_capa_valida",
    )


@pytest.mark.parametrize(
    "veredicto", ["limpio", "malicioso", "rechazado", "error", "no_evaluada"]
)
def test_veredictos_validos_se_aceptan(esquema: Connection, veredicto: str) -> None:
    esquema.execute(_insert_resultado(_crear_archivo(esquema), veredicto=veredicto))


def test_veredicto_desconocido_se_rechaza(esquema: Connection) -> None:
    _rechazada_por(
        esquema,
        _insert_resultado(_crear_archivo(esquema), veredicto="dudoso"),
        "ck_resultado_analisis_veredicto_valido",
    )


@pytest.mark.parametrize("columna", ["capa", "veredicto"])
def test_capa_y_veredicto_nulos_se_rechazan(esquema: Connection, columna: str) -> None:
    # Sin NOT NULL el CHECK de pertenencia dejaría pasar NULL ("NULL IN (...)" es NULL).
    _rechazada_por_no_nulo(
        esquema, _insert_resultado(_crear_archivo(esquema), **{columna: None}), columna
    )


def test_duracion_negativa_se_rechaza(esquema: Connection) -> None:
    _rechazada_por(
        esquema,
        _insert_resultado(_crear_archivo(esquema), duracion_ms=-1),
        "ck_resultado_analisis_duracion_ms_no_negativa",
    )


def test_duracion_cero_se_acepta(esquema: Connection) -> None:
    esquema.execute(_insert_resultado(_crear_archivo(esquema), duracion_ms=0))


def _detalle_de_tamano(bytes_texto: int) -> dict[str, str]:
    """JSON cuyo texto en PostgreSQL mide exactamente ``bytes_texto`` bytes."""
    # jsonb::text escribe {"x": "aaa"}: 9 bytes de sintaxis más el valor.
    return {"x": "a" * (bytes_texto - len(json.dumps({"x": ""})))}


def test_detalle_en_el_tope_se_acepta(esquema: Connection) -> None:
    esquema.execute(
        _insert_resultado(
            _crear_archivo(esquema), detalle=_detalle_de_tamano(TOPE_DETALLE)
        )
    )


def test_detalle_sobre_el_tope_se_rechaza(esquema: Connection) -> None:
    _rechazada_por(
        esquema,
        _insert_resultado(
            _crear_archivo(esquema), detalle=_detalle_de_tamano(TOPE_DETALLE + 1)
        ),
        "ck_resultado_analisis_detalle_tope",
    )


def test_detalle_none_no_se_guarda_como_null_json(esquema: Connection) -> None:
    # Con JSONB normal, None se guarda como el JSON null y esquiva el NOT NULL.
    _rechazada_por_no_nulo(
        esquema, _insert_resultado(_crear_archivo(esquema), detalle=None), "detalle"
    )


@pytest.mark.parametrize(
    "valor",
    [
        "'[1, 2]'::jsonb",
        "'\"texto\"'::jsonb",
        "'1'::jsonb",
        "'true'::jsonb",
        "'null'::jsonb",
    ],
    ids=["lista", "texto", "numero", "booleano", "null_json"],
)
def test_detalle_que_no_es_un_objeto_se_rechaza(
    esquema: Connection, valor: str
) -> None:
    # CWE-20. Literal de JSON en SQL: el JSON null no debe confundirse con el NULL de SQL,
    # que ya rechaza el NOT NULL.
    _rechazada_por(
        esquema,
        _insert_resultado(_crear_archivo(esquema), detalle=text(valor)),
        "ck_resultado_analisis_detalle_objeto",
    )


def test_detalle_objeto_se_acepta(esquema: Connection) -> None:
    esquema.execute(
        _insert_resultado(_crear_archivo(esquema), detalle={"anidado": [1, {"a": 2}]})
    )


def test_fechas_de_archivo_aceptan_zona_horaria(esquema: Connection) -> None:
    analizado = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
    archivo_id = _crear_archivo(esquema, analizado_en=analizado)
    guardado = esquema.execute(
        select(Archivo.analizado_en).where(Archivo.id == archivo_id)
    ).scalar_one()
    assert guardado == analizado
