"""Cupo de pendientes por aplicación (K48) y barrido de pendientes huérfanos (K51).

Corren contra la base creada con la migración y confirman de verdad, como en la API. La
concurrencia usa transacciones reales en paralelo: cada tarea abre su propia conexión.
"""

import asyncio
import hashlib
import inspect
import secrets
import traceback
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from api.app.estados import Estado, TransicionInvalida
from api.db import repositorios
from api.db.modelos import Archivo
from api.db.repositorios import (
    CupoDePendientesAgotado,
    DatoRechazado,
    DatosArchivo,
    ViolacionDeRestriccion,
    cerrar_pendientes_huerfanos,
    contar_pendientes,
    crear_aplicacion,
    crear_archivo,
    crear_archivo_con_cupo,
)

pytestmark = pytest.mark.anyio

Sesiones = async_sessionmaker[AsyncSession]

TOPE = 20  # K48; en la API lo pasa la configuración.
SHA256 = hashlib.sha256(b"contenido").hexdigest()


async def _aplicacion(sesiones: Sesiones) -> uuid.UUID:
    async with sesiones.begin() as sesion:
        return await crear_aplicacion(sesion, f"app-{uuid.uuid4()}")


async def _cargar(
    sesiones: Sesiones, aplicacion_id: uuid.UUID, cantidad: int, estado: str
) -> list[uuid.UUID]:
    """Inserta filas directo, sin el repositorio que se está probando."""
    ids = [uuid.uuid4() for _ in range(cantidad)]
    if not ids:
        return ids
    extra: dict[str, object] = {"estado": estado}
    if estado == "error":
        extra["tipo_error"] = "transitorio"
    if estado == "limpio":
        extra["tipo_detectado"] = "image/png"
    if estado != "pendiente":
        extra["analizado_en"] = datetime.now(UTC)
    async with sesiones.begin() as sesion:
        await sesion.execute(
            insert(Archivo),
            [
                {
                    "id": archivo_id,
                    "aplicacion_id": aplicacion_id,
                    "nombre_original": "previo.pdf",
                    "tamano_bytes": 1024,
                    "sha256": SHA256,
                    **extra,
                }
                for archivo_id in ids
            ],
        )
    return ids


async def _pendientes_reales(sesiones: Sesiones, aplicacion_id: uuid.UUID) -> int:
    """Cuenta directo, sin pasar por ``contar_pendientes``."""
    async with sesiones() as sesion:
        consulta = select(func.count()).where(
            Archivo.aplicacion_id == aplicacion_id, Archivo.estado == "pendiente"
        )
        return (await sesion.execute(consulta)).scalar_one()


async def _existe(sesiones: Sesiones, archivo_id: uuid.UUID) -> bool:
    async with sesiones() as sesion:
        consulta = select(func.count()).where(Archivo.id == archivo_id)
        return (await sesion.execute(consulta)).scalar_one() == 1


async def _con_cupo(
    sesiones: Sesiones,
    aplicacion_id: uuid.UUID,
    archivo_id: uuid.UUID | None = None,
    *,
    tope: int = TOPE,
) -> DatosArchivo:
    async with sesiones.begin() as sesion:
        return await crear_archivo_con_cupo(
            sesion,
            aplicacion_id,
            archivo_id or uuid.uuid4(),
            "factura.pdf",
            2048,
            SHA256,
            tope_pendientes=tope,
        )


async def _esperar_bloqueada(sesiones: Sesiones) -> None:
    """Espera a que alguna sentencia esté detenida esperando un bloqueo."""
    consulta = text(
        "SELECT count(*) FROM pg_stat_activity"
        " WHERE datname = current_database() AND wait_event_type = 'Lock'"
    )
    for _ in range(500):
        async with sesiones() as sesion:
            if (await sesion.execute(consulta)).scalar_one() > 0:
                return
        await asyncio.sleep(0.01)
    pytest.fail("la segunda inserción nunca llegó a esperar el bloqueo")


def _texto_visible(error: BaseException) -> str:
    return "\n".join(
        [
            str(error),
            repr(error),
            repr(error.args),
            "".join(traceback.format_exception(error)),
        ]
    )


def _sin_rastro(error: BaseException, *datos: str) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    texto = _texto_visible(error)
    for dato in datos:
        assert dato not in texto
    assert "Failing row" not in texto
    assert "DETAIL" not in texto


# --- Firmas: INV-10 y lo que no se recibe -------------------------------------------------


@pytest.mark.parametrize("funcion", [contar_pendientes, crear_archivo_con_cupo])
def test_aplicacion_id_es_obligatorio_y_sin_valor_por_defecto(
    funcion: Callable[..., Any],
) -> None:
    parametro = inspect.signature(funcion).parameters["aplicacion_id"]
    assert parametro.default is inspect.Parameter.empty
    assert parametro.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD


def test_el_tope_es_solo_por_nombre_y_sin_valor_por_defecto() -> None:
    # K48 lo fija la configuración de la API: aquí no vive un 20 escondido.
    parametro = inspect.signature(crear_archivo_con_cupo).parameters["tope_pendientes"]
    assert parametro.kind is inspect.Parameter.KEYWORD_ONLY
    assert parametro.default is inspect.Parameter.empty


def test_crear_archivo_con_cupo_no_permite_elegir_estado_ni_reintentos() -> None:
    parametros = inspect.signature(crear_archivo_con_cupo).parameters
    assert not {"estado", "reintentos", "analizado_en"} & set(parametros)


# --- contar_pendientes --------------------------------------------------------------------


async def test_contar_pendientes_cuenta_solo_los_pendientes_de_la_aplicacion(
    sesiones: Sesiones,
) -> None:
    app_id, vecina = await _aplicacion(sesiones), await _aplicacion(sesiones)
    await _cargar(sesiones, app_id, 3, "pendiente")
    for estado in ("limpio", "rechazado", "en_cuarentena", "error"):
        await _cargar(sesiones, app_id, 2, estado)
    await _cargar(sesiones, vecina, 7, "pendiente")

    async with sesiones() as sesion:
        assert await contar_pendientes(sesion, app_id) == 3
        assert await contar_pendientes(sesion, vecina) == 7


async def test_contar_pendientes_de_otra_aplicacion_no_ve_nada(
    sesiones: Sesiones,
) -> None:
    # INV-10: los pendientes ajenos no existen para esta aplicación.
    duena, ajena = await _aplicacion(sesiones), await _aplicacion(sesiones)
    await _cargar(sesiones, duena, 5, "pendiente")

    async with sesiones() as sesion:
        assert await contar_pendientes(sesion, ajena) == 0
        assert await contar_pendientes(sesion, uuid.uuid4()) == 0


async def test_contar_pendientes_devuelve_un_int(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    async with sesiones() as sesion:
        resultado = await contar_pendientes(sesion, app_id)
    assert type(resultado) is int
    assert resultado == 0


async def test_contar_pendientes_lo_sirve_el_indice(sesiones: Sesiones) -> None:
    # Con datos y estadísticas, como en producción: una tabla vacía siempre da Seq Scan.
    app_id, vecina = await _aplicacion(sesiones), await _aplicacion(sesiones)
    await _cargar(sesiones, vecina, 5000, "limpio")
    await _cargar(sesiones, app_id, 15, "pendiente")
    await _cargar(sesiones, app_id, 500, "rechazado")
    async with sesiones() as sesion, sesion.begin():
        await sesion.execute(text("ANALYZE archivo"))

    # Misma forma que la consulta de contar_pendientes (y que la cuenta dentro de
    # crear_archivo_con_cupo), con el parámetro tipado como lo envía psycopg.
    async with sesiones() as sesion:
        plan = await sesion.execute(
            text(
                "EXPLAIN SELECT count(*) AS count_1 FROM archivo"
                " WHERE archivo.aplicacion_id = CAST(:app AS UUID)"
                " AND archivo.estado = 'pendiente'"
            ),
            {"app": app_id},
        )
        lineas = "\n".join(plan.scalars())

    print(f"\nplan de contar_pendientes:\n{lineas}")
    assert "ix_archivo_aplicacion_id_estado" in lineas, lineas
    assert "Seq Scan" not in lineas, lineas


# --- crear_archivo_con_cupo: lo básico ----------------------------------------------------


async def test_con_cupo_crea_igual_que_crear_archivo(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    asignado = uuid.uuid4()

    async with sesiones.begin() as sesion:
        creado = await crear_archivo_con_cupo(
            sesion, app_id, asignado, "foto.png", 10, SHA256, tope_pendientes=TOPE
        )

    assert creado.id == asignado
    assert creado.aplicacion_id == app_id
    assert creado.nombre_original == "foto.png"
    assert creado.tamano_bytes == 10
    assert creado.sha256 == SHA256
    assert creado.estado is Estado.PENDIENTE
    assert creado.tipo_detectado is None
    assert creado.tipo_error is None
    assert creado.reintentos == 0
    assert creado.creado_en.tzinfo is not None
    assert creado.analizado_en is None
    async with sesiones() as sesion:
        assert await repositorios.obtener_archivo(sesion, app_id, asignado) == creado


async def test_con_un_lugar_libre_entra(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    await _cargar(sesiones, app_id, TOPE - 1, "pendiente")

    creado = await _con_cupo(sesiones, app_id)

    assert creado.estado is Estado.PENDIENTE
    assert await _pendientes_reales(sesiones, app_id) == TOPE


async def test_sin_cupo_no_inserta_nada(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    await _cargar(sesiones, app_id, TOPE, "pendiente")
    rechazado = uuid.uuid4()

    with pytest.raises(CupoDePendientesAgotado):
        await _con_cupo(sesiones, app_id, rechazado)

    assert not await _existe(sesiones, rechazado)
    assert await _pendientes_reales(sesiones, app_id) == TOPE


async def test_la_llamada_21_de_k48_se_rechaza(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)

    for _ in range(TOPE):
        await _con_cupo(sesiones, app_id)
    with pytest.raises(CupoDePendientesAgotado):
        await _con_cupo(sesiones, app_id)

    assert await _pendientes_reales(sesiones, app_id) == TOPE


@pytest.mark.parametrize("tope", [1, 3])
async def test_el_tope_es_el_que_pasa_quien_llama(
    sesiones: Sesiones, tope: int
) -> None:
    app_id = await _aplicacion(sesiones)

    for _ in range(tope):
        await _con_cupo(sesiones, app_id, tope=tope)
    with pytest.raises(CupoDePendientesAgotado):
        await _con_cupo(sesiones, app_id, tope=tope)


async def test_los_terminados_no_ocupan_cupo(sesiones: Sesiones) -> None:
    # K48 limita lo que está en cola; lo que ya tiene veredicto no la llena.
    app_id = await _aplicacion(sesiones)
    for estado in ("limpio", "rechazado", "en_cuarentena", "error"):
        await _cargar(sesiones, app_id, TOPE, estado)
    await _cargar(sesiones, app_id, TOPE - 1, "pendiente")

    await _con_cupo(sesiones, app_id)

    assert await _pendientes_reales(sesiones, app_id) == TOPE


async def test_al_terminar_un_pendiente_se_libera_un_lugar(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    ids = await _cargar(sesiones, app_id, TOPE, "pendiente")
    with pytest.raises(CupoDePendientesAgotado):
        await _con_cupo(sesiones, app_id)

    async with sesiones.begin() as sesion:
        await repositorios.cambiar_estado(
            sesion, app_id, ids[0], Estado.PENDIENTE, Estado.RECHAZADO
        )

    await _con_cupo(sesiones, app_id)
    assert await _pendientes_reales(sesiones, app_id) == TOPE


async def test_una_aplicacion_llena_no_afecta_a_otra(sesiones: Sesiones) -> None:
    llena, otra = await _aplicacion(sesiones), await _aplicacion(sesiones)
    await _cargar(sesiones, llena, TOPE, "pendiente")

    with pytest.raises(CupoDePendientesAgotado):
        await _con_cupo(sesiones, llena)
    for _ in range(TOPE):
        await _con_cupo(sesiones, otra)

    assert await _pendientes_reales(sesiones, otra) == TOPE


async def test_los_pendientes_ajenos_no_ocupan_el_cupo(sesiones: Sesiones) -> None:
    # INV-10: solo cuentan los archivos de la aplicación que sube.
    duena, ajena = await _aplicacion(sesiones), await _aplicacion(sesiones)
    await _cargar(sesiones, ajena, TOPE, "pendiente")

    creado = await _con_cupo(sesiones, duena)

    assert creado.aplicacion_id == duena
    assert await _pendientes_reales(sesiones, duena) == 1
    assert await _pendientes_reales(sesiones, ajena) == TOPE


async def test_nombre_hostil_se_guarda_como_texto(sesiones: Sesiones) -> None:
    # CWE-89: el nombre lo elige quien sube el archivo.
    app_id = await _aplicacion(sesiones)
    nombre = "'; DROP TABLE archivo; --"
    async with sesiones.begin() as sesion:
        creado = await crear_archivo_con_cupo(
            sesion, app_id, uuid.uuid4(), nombre, 1, SHA256, tope_pendientes=TOPE
        )
    assert creado.nombre_original == nombre


async def test_un_nombre_de_255_caracteres_entra_completo(sesiones: Sesiones) -> None:
    # Un CAST explícito a varchar(255) truncaría en silencio; la columna debe decidir.
    app_id = await _aplicacion(sesiones)
    nombre = "n" * 251 + ".pdf"
    async with sesiones.begin() as sesion:
        creado = await crear_archivo_con_cupo(
            sesion, app_id, uuid.uuid4(), nombre, 1, SHA256, tope_pendientes=TOPE
        )
    assert creado.nombre_original == nombre


async def test_no_confirma_por_su_cuenta(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    async with sesiones() as sesion:
        creado = await crear_archivo_con_cupo(
            sesion, app_id, uuid.uuid4(), "a.png", 1, SHA256, tope_pendientes=TOPE
        )
        await sesion.rollback()

    assert not await _existe(sesiones, creado.id)


# --- crear_archivo_con_cupo: validación del tope ------------------------------------------


@pytest.mark.parametrize(
    "tope",
    [0, -1, True, False, 20.0, "20", None, 2**63],
    ids=["cero", "negativo", "true", "false", "float", "texto", "none", "enorme"],
)
async def test_un_tope_invalido_se_rechaza_sin_tocar_la_bd(tope: Any) -> None:
    # Sin sesión: si intentara consultar reventaría con AttributeError, no con esto.
    with pytest.raises((TypeError, ValueError)) as error:
        await crear_archivo_con_cupo(
            None,  # type: ignore[arg-type]
            uuid.uuid4(),
            uuid.uuid4(),
            "a.pdf",
            1,
            SHA256,
            tope_pendientes=tope,
        )
    assert not isinstance(error.value, DatoRechazado)


# --- crear_archivo_con_cupo: K48 bajo concurrencia ----------------------------------------


async def test_con_19_pendientes_y_8_inserciones_simultaneas_entra_exactamente_una(
    sesiones: Sesiones,
) -> None:
    app_id = await _aplicacion(sesiones)
    await _cargar(sesiones, app_id, TOPE - 1, "pendiente")
    barrera = asyncio.Event()
    listas = 0

    async def _intento() -> str:
        nonlocal listas
        # Cada tarea abre su transacción y su conexión antes de la barrera: así las 8
        # están vivas a la vez y compiten de verdad.
        async with sesiones() as sesion, sesion.begin():
            await sesion.execute(select(1))
            listas += 1
            await barrera.wait()
            try:
                await crear_archivo_con_cupo(
                    sesion,
                    app_id,
                    uuid.uuid4(),
                    "a.pdf",
                    1,
                    SHA256,
                    tope_pendientes=TOPE,
                )
            except CupoDePendientesAgotado:
                return "sin_cupo"
        return "creado"

    for _ronda in range(5):
        tareas = [asyncio.create_task(_intento()) for _ in range(8)]
        while listas < 8:
            await asyncio.sleep(0.005)
        barrera.set()
        resultados = await asyncio.gather(*tareas)

        assert sorted(resultados) == ["creado"] + ["sin_cupo"] * 7
        assert await _pendientes_reales(sesiones, app_id) == TOPE
        # Siguiente ronda: se libera un lugar y vuelven a competir 8.
        async with sesiones.begin() as sesion:
            await sesion.execute(
                update(Archivo)
                .where(
                    Archivo.id
                    == select(Archivo.id)
                    .where(
                        Archivo.aplicacion_id == app_id, Archivo.estado == "pendiente"
                    )
                    .limit(1)
                    .scalar_subquery()
                )
                .values(estado="rechazado", analizado_en=func.now())
            )
        barrera.clear()
        listas = 0


async def test_la_segunda_espera_a_la_primera_y_ve_su_insercion(
    sesiones: Sesiones,
) -> None:
    # Intercalado determinista: A inserta el lugar 20 sin confirmar, B queda esperando y,
    # cuando A confirma, B cuenta 20 y no inserta.
    app_id = await _aplicacion(sesiones)
    await _cargar(sesiones, app_id, TOPE - 1, "pendiente")
    segundo = uuid.uuid4()

    async with sesiones() as sesion_a, sesion_a.begin():
        await crear_archivo_con_cupo(
            sesion_a, app_id, uuid.uuid4(), "a.pdf", 1, SHA256, tope_pendientes=TOPE
        )
        segunda = asyncio.create_task(_con_cupo(sesiones, app_id, segundo))
        await _esperar_bloqueada(sesiones)
        assert not segunda.done()

    with pytest.raises(CupoDePendientesAgotado):
        await segunda
    assert not await _existe(sesiones, segundo)
    assert await _pendientes_reales(sesiones, app_id) == TOPE


async def test_si_la_primera_revierte_la_segunda_entra(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    await _cargar(sesiones, app_id, TOPE - 1, "pendiente")

    async with sesiones() as sesion_a:
        await sesion_a.begin()
        await crear_archivo_con_cupo(
            sesion_a, app_id, uuid.uuid4(), "a.pdf", 1, SHA256, tope_pendientes=TOPE
        )
        segunda = asyncio.create_task(_con_cupo(sesiones, app_id))
        await _esperar_bloqueada(sesiones)
        await sesion_a.rollback()

    creado = await segunda
    assert creado.estado is Estado.PENDIENTE
    assert await _pendientes_reales(sesiones, app_id) == TOPE


async def test_el_bloqueo_de_una_aplicacion_no_detiene_a_otra(
    sesiones: Sesiones,
) -> None:
    # A retiene el cupo de su aplicación sin confirmar; B, de otra, no debe esperarla.
    app_a, app_b = await _aplicacion(sesiones), await _aplicacion(sesiones)

    async with sesiones() as sesion_a, sesion_a.begin():
        await crear_archivo_con_cupo(
            sesion_a, app_a, uuid.uuid4(), "a.pdf", 1, SHA256, tope_pendientes=TOPE
        )
        creado = await asyncio.wait_for(_con_cupo(sesiones, app_b), timeout=2)
        assert creado.aplicacion_id == app_b


async def test_el_bloqueo_no_detiene_otras_escrituras_de_la_misma_aplicacion(
    sesiones: Sesiones,
) -> None:
    # Los veredictos (UPDATE de archivo) y las keys nuevas (FK a aplicacion) no esperan el
    # cupo: solo se serializan las altas con cupo.
    app_id = await _aplicacion(sesiones)
    previo = (await _cargar(sesiones, app_id, 1, "pendiente"))[0]

    async def _otras() -> None:
        async with sesiones.begin() as sesion:
            await repositorios.cambiar_estado(
                sesion, app_id, previo, Estado.PENDIENTE, Estado.RECHAZADO
            )
        async with sesiones.begin() as sesion:
            await repositorios.crear_api_key(
                sesion, app_id, f"gk_{secrets.token_hex(6)}", secrets.token_hex(32)
            )

    async with sesiones() as sesion_a, sesion_a.begin():
        await crear_archivo_con_cupo(
            sesion_a, app_id, uuid.uuid4(), "a.pdf", 1, SHA256, tope_pendientes=TOPE
        )
        await asyncio.wait_for(_otras(), timeout=2)


async def test_fuera_de_read_committed_se_rechaza(sesiones: Sesiones) -> None:
    # En REPEATABLE READ la cuenta saldría de la foto tomada antes de esperar el bloqueo
    # y dos transacciones podrían pasar el tope. Falla cerrado.
    app_id = await _aplicacion(sesiones)
    archivo_id = uuid.uuid4()

    async with sesiones() as sesion:
        conexion = await sesion.connection(
            execution_options={"isolation_level": "REPEATABLE READ"}
        )
        assert conexion is not None
        with pytest.raises(RuntimeError, match="READ COMMITTED"):
            await crear_archivo_con_cupo(
                sesion, app_id, archivo_id, "a.pdf", 1, SHA256, tope_pendientes=TOPE
            )
        await sesion.rollback()

    assert not await _existe(sesiones, archivo_id)


# --- crear_archivo_con_cupo: errores sin datos --------------------------------------------


def test_cupo_agotado_no_lleva_datos() -> None:
    error = CupoDePendientesAgotado()
    assert vars(error) == {}
    assert error.args == (str(error),)
    assert not issubclass(
        CupoDePendientesAgotado, (ViolacionDeRestriccion, DatoRechazado)
    )


async def test_cupo_agotado_no_muestra_la_aplicacion_ni_el_archivo(
    sesiones: Sesiones,
) -> None:
    app_id = await _aplicacion(sesiones)
    await _cargar(sesiones, app_id, 1, "pendiente")
    archivo_id = uuid.uuid4()

    with pytest.raises(CupoDePendientesAgotado) as error:
        await _con_cupo(sesiones, app_id, archivo_id, tope=1)

    _sin_rastro(error.value, str(app_id), str(archivo_id), SHA256, "factura")
    assert str(error.value) == str(CupoDePendientesAgotado())


NOMBRE_HOSTIL = "linea1\nINFO falsa entrada de log\r\n.pdf"
SHA_MARCADO = "c0ffee" * 10 + "c0ff"


@pytest.mark.parametrize(
    ("tamano", "restriccion"),
    [(0, "ck_archivo_tamano_bytes_rango"), (10485761, "ck_archivo_tamano_bytes_rango")],
)
async def test_un_check_se_traduce_sin_la_fila(
    sesiones: Sesiones, tamano: int, restriccion: str
) -> None:
    app_id = await _aplicacion(sesiones)

    with pytest.raises(ViolacionDeRestriccion) as error:
        async with sesiones.begin() as sesion:
            await crear_archivo_con_cupo(
                sesion,
                app_id,
                uuid.uuid4(),
                NOMBRE_HOSTIL,
                tamano,
                SHA_MARCADO,
                tope_pendientes=TOPE,
            )

    assert error.value.restriccion == restriccion
    _sin_rastro(error.value, "linea1", "INFO falsa", SHA_MARCADO)


async def test_sha256_invalido_lo_rechaza_su_check(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)

    with pytest.raises(ViolacionDeRestriccion) as error:
        async with sesiones.begin() as sesion:
            await crear_archivo_con_cupo(
                sesion, app_id, uuid.uuid4(), "a.pdf", 1, "Z" * 64, tope_pendientes=TOPE
            )

    assert error.value.restriccion == "ck_archivo_sha256_hex"


async def test_id_repetido_se_traduce(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _con_cupo(sesiones, app_id)

    with pytest.raises(ViolacionDeRestriccion) as error:
        await _con_cupo(sesiones, app_id, creado.id)

    assert error.value.restriccion == "pk_archivo"
    _sin_rastro(error.value, str(creado.id))


async def test_aplicacion_inexistente_se_traduce(sesiones: Sesiones) -> None:
    with pytest.raises(ViolacionDeRestriccion) as error:
        await _con_cupo(sesiones, uuid.uuid4())

    assert error.value.restriccion == "fk_archivo_aplicacion_id_aplicacion"


Alta = Callable[[AsyncSession, uuid.UUID, str], Awaitable[object]]


def _alta(
    archivo_id: Callable[[str], Any] = lambda _m: uuid.uuid4(),
    nombre: Callable[[str], Any] = lambda m: m,
    tamano: Callable[[str], Any] = lambda _m: 1,
    sha256: Callable[[str], Any] = lambda _m: SHA_MARCADO,
) -> Alta:
    return lambda sesion, app, marca: crear_archivo_con_cupo(
        sesion,
        app,
        archivo_id(marca),
        nombre(marca),
        tamano(marca),
        sha256(marca),
        tope_pendientes=TOPE,
    )


ALTAS_RECHAZADAS = {
    "nombre_nul": _alta(nombre=lambda m: m + "\x00"),
    "nombre_surrogate": _alta(nombre=lambda m: m + "\ud800"),
    "nombre_largo": _alta(nombre=lambda m: m + "x" * 256),
    "sha256_nul": _alta(sha256=lambda m: m + "\x00"),
    "sha256_largo": _alta(sha256=lambda m: m * 9),
    "tamano_fuera_de_bigint": _alta(tamano=lambda _m: 2**63),
    "id_que_no_es_uuid": _alta(archivo_id=lambda m: m),
}


@pytest.mark.parametrize("alta", ALTAS_RECHAZADAS.values(), ids=ALTAS_RECHAZADAS.keys())
async def test_un_valor_rechazado_no_deja_rastro(
    sesiones: Sesiones, alta: Alta
) -> None:
    app_id = await _aplicacion(sesiones)
    marca = secrets.token_hex(8)

    with pytest.raises(DatoRechazado) as error:
        async with sesiones.begin() as sesion:
            await alta(sesion, app_id, marca)

    _sin_rastro(error.value, marca)
    assert vars(error.value) == {}
    assert await _pendientes_reales(sesiones, app_id) == 0


# --- cerrar_pendientes_huerfanos (K51) ----------------------------------------------------


def test_el_barrido_no_recibe_aplicacion_ni_valores_por_defecto() -> None:
    parametros = inspect.signature(cerrar_pendientes_huerfanos).parameters
    assert list(parametros) == ["sesion", "tipo_error"]
    assert parametros["tipo_error"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parametros["tipo_error"].default is inspect.Parameter.empty


def test_el_barrido_explica_por_que_no_filtra_por_aplicacion() -> None:
    documentacion = inspect.getdoc(cerrar_pendientes_huerfanos) or ""
    assert "INV-10" in documentacion
    assert "mantenimiento" in documentacion


async def test_el_barrido_cierra_los_pendientes_de_todas_las_aplicaciones(
    sesiones: Sesiones,
) -> None:
    app_a, app_b = await _aplicacion(sesiones), await _aplicacion(sesiones)
    pendientes = await _cargar(sesiones, app_a, 3, "pendiente")
    pendientes += await _cargar(sesiones, app_b, 2, "pendiente")

    async with sesiones.begin() as sesion:
        inicio = (await sesion.execute(select(func.now()))).scalar_one()
        await asyncio.sleep(0.05)
        cerrados = await cerrar_pendientes_huerfanos(sesion, tipo_error="final")

    assert sorted(cerrados) == sorted(pendientes)
    assert all(type(archivo_id) is uuid.UUID for archivo_id in cerrados)
    async with sesiones() as sesion:
        filas = (
            await sesion.execute(select(Archivo).where(Archivo.id.in_(pendientes)))
        ).scalars()
        for fila in filas:
            assert (fila.estado, fila.tipo_error) == ("error", "final")
            # La hora la pone la BD con clock_timestamp(), no la del inicio de la
            # transacción.
            assert fila.analizado_en is not None
            assert fila.analizado_en - inicio >= timedelta(milliseconds=40)
    assert await _pendientes_reales(sesiones, app_a) == 0
    assert await _pendientes_reales(sesiones, app_b) == 0


async def test_el_barrido_devuelve_solo_ids(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    await _cargar(sesiones, app_id, 2, "pendiente")

    async with sesiones.begin() as sesion:
        cerrados = await cerrar_pendientes_huerfanos(sesion, tipo_error="final")

    assert type(cerrados) is list
    assert len(cerrados) == 2
    assert all(type(archivo_id) is uuid.UUID for archivo_id in cerrados)


async def test_el_barrido_no_toca_los_demas_estados(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    otros = {
        estado: await _cargar(sesiones, app_id, 2, estado)
        for estado in ("limpio", "rechazado", "error", "en_cuarentena")
    }
    pendiente = await _cargar(sesiones, app_id, 1, "pendiente")

    async def _foto() -> dict[uuid.UUID, tuple[Any, ...]]:
        async with sesiones() as sesion:
            filas = (
                await sesion.execute(
                    select(
                        Archivo.id,
                        Archivo.estado,
                        Archivo.tipo_error,
                        Archivo.tipo_detectado,
                        Archivo.analizado_en,
                        Archivo.reintentos,
                    ).where(Archivo.id.not_in(pendiente))
                )
            ).all()
        return {fila.id: tuple(fila) for fila in filas}

    antes = await _foto()
    async with sesiones.begin() as sesion:
        cerrados = await cerrar_pendientes_huerfanos(sesion, tipo_error="final")

    assert cerrados == pendiente
    assert await _foto() == antes
    assert set(antes) == {i for ids in otros.values() for i in ids}


async def test_el_barrido_sin_pendientes_devuelve_lista_vacia(
    sesiones: Sesiones,
) -> None:
    app_id = await _aplicacion(sesiones)
    await _cargar(sesiones, app_id, 2, "limpio")
    async with sesiones.begin() as sesion:
        assert await cerrar_pendientes_huerfanos(sesion, tipo_error="final") == []


async def test_el_barrido_acepta_transitorio(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    ids = await _cargar(sesiones, app_id, 1, "pendiente")
    async with sesiones.begin() as sesion:
        assert (
            await cerrar_pendientes_huerfanos(sesion, tipo_error="transitorio") == ids
        )
    async with sesiones() as sesion:
        fila = (
            await sesion.execute(select(Archivo).where(Archivo.id == ids[0]))
        ).scalar_one()
    assert fila.tipo_error == "transitorio"


@pytest.mark.parametrize(
    "tipo_error",
    [None, "", "temporal", "FINAL", " final", 1, b"final"],
    ids=["none", "vacio", "desconocido", "mayusculas", "espacio", "int", "bytes"],
)
async def test_el_barrido_rechaza_un_tipo_error_invalido_sin_tocar_la_bd(
    tipo_error: Any,
) -> None:
    with pytest.raises(TransicionInvalida) as error:
        await cerrar_pendientes_huerfanos(
            None,  # type: ignore[arg-type]
            tipo_error=tipo_error,
        )
    if isinstance(tipo_error, str) and tipo_error:
        assert tipo_error not in str(error.value)


async def test_el_barrido_no_confirma_por_su_cuenta(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    await _cargar(sesiones, app_id, 2, "pendiente")

    async with sesiones() as sesion:
        await cerrar_pendientes_huerfanos(sesion, tipo_error="final")
        await sesion.rollback()

    assert await _pendientes_reales(sesiones, app_id) == 2


async def test_un_archivo_creado_con_crear_archivo_tambien_ocupa_cupo(
    sesiones: Sesiones,
) -> None:
    # El cupo cuenta filas, no el camino por el que entraron.
    app_id = await _aplicacion(sesiones)
    async with sesiones.begin() as sesion:
        await crear_archivo(sesion, app_id, uuid.uuid4(), "a.pdf", 1, SHA256)
    with pytest.raises(CupoDePendientesAgotado):
        await _con_cupo(sesiones, app_id, tope=1)
