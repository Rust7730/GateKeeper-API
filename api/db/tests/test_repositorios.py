"""Repositorios de la rebanada vertical (F1.07, F2.02, F2.04, F2.06).

Corren contra la base creada con la migración y confirman de verdad: cada operación va en
su propia transacción, como en la API. Los repositorios nunca confirman por su cuenta; la
transacción la abre quien llama, para poder juntar varias operaciones.
"""

import asyncio
import dataclasses
import hashlib
import inspect
import secrets
import traceback
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import DataError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from api.app.estados import Estado, TransicionInvalida, es_descargable
from api.db import repositorios
from api.db.modelos import ApiKey, Aplicacion, Archivo, ResultadoAnalisis
from api.db.repositorios import (
    ArchivoNoEncontrado,
    ConflictoDeEstado,
    DatosApiKey,
    DatosArchivo,
    SinEvidenciaCDR,
    ViolacionDeRestriccion,
    cambiar_estado,
    crear_api_key,
    crear_aplicacion,
    crear_archivo,
    obtener_api_key_activa,
    obtener_archivo,
    registrar_resultado,
)

pytestmark = pytest.mark.anyio

Sesiones = async_sessionmaker[AsyncSession]


def _hash_hmac() -> str:
    return secrets.token_hex(32)


def _prefijo() -> str:
    return f"gk_{secrets.token_hex(6)}"


async def _aplicacion(sesiones: Sesiones, nombre: str | None = None) -> uuid.UUID:
    async with sesiones.begin() as sesion:
        return await crear_aplicacion(sesion, nombre or f"app-{uuid.uuid4()}")


async def _archivo(sesiones: Sesiones, aplicacion_id: uuid.UUID) -> DatosArchivo:
    async with sesiones.begin() as sesion:
        return await crear_archivo(
            sesion,
            aplicacion_id,
            uuid.uuid4(),
            "factura.pdf",
            2048,
            hashlib.sha256(b"contenido").hexdigest(),
        )


async def _leer(sesiones: Sesiones, archivo_id: uuid.UUID) -> Any:
    """Lee la fila directo, sin pasar por el repositorio que se está probando."""
    async with sesiones() as sesion:
        resultado = await sesion.execute(
            select(Archivo).where(Archivo.id == archivo_id)
        )
        return resultado.scalar_one()


async def _llevar_a(
    sesiones: Sesiones, archivo_id: uuid.UUID, estado: str, **valores: Any
) -> None:
    """Coloca la fila en un estado sin pasar por ``cambiar_estado``."""
    async with sesiones.begin() as sesion:
        await sesion.execute(
            update(Archivo)
            .where(Archivo.id == archivo_id)
            .values(estado=estado, **valores)
        )


async def _resultado_cdr(
    sesiones: Sesiones,
    aplicacion_id: uuid.UUID,
    archivo_id: uuid.UUID,
    veredicto: str = "limpio",
    capa: str = "cdr",
) -> None:
    async with sesiones.begin() as sesion:
        await registrar_resultado(
            sesion, aplicacion_id, archivo_id, capa, veredicto, {}, 5
        )


async def _resultados(sesiones: Sesiones, archivo_id: uuid.UUID) -> int:
    async with sesiones() as sesion:
        filas = await sesion.execute(
            select(ResultadoAnalisis).where(ResultadoAnalisis.archivo_id == archivo_id)
        )
        return len(filas.all())


# --- Aplicaciones y API keys ------------------------------------------------------------


async def test_crear_aplicacion_guarda_una_aplicacion_activa(
    sesiones: Sesiones,
) -> None:
    app_id = await _aplicacion(sesiones, "portal-clientes")

    async with sesiones() as sesion:
        fila = (
            await sesion.execute(select(Aplicacion).where(Aplicacion.id == app_id))
        ).scalar_one()
    assert fila.nombre == "portal-clientes"
    assert fila.activa is True


async def test_crear_api_key_guarda_solo_prefijo_y_hash(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    prefijo, hash_hmac = _prefijo(), _hash_hmac()

    async with sesiones.begin() as sesion:
        key_id = await crear_api_key(sesion, app_id, prefijo, hash_hmac)

    async with sesiones() as sesion:
        fila = (
            await sesion.execute(select(ApiKey).where(ApiKey.id == key_id))
        ).scalar_one()
    assert (fila.aplicacion_id, fila.prefijo, fila.hash) == (app_id, prefijo, hash_hmac)
    assert fila.revocada_en is None


async def test_obtener_api_key_activa_devuelve_lo_necesario_para_autenticar(
    sesiones: Sesiones,
) -> None:
    app_id = await _aplicacion(sesiones)
    prefijo, hash_hmac = _prefijo(), _hash_hmac()
    async with sesiones.begin() as sesion:
        key_id = await crear_api_key(sesion, app_id, prefijo, hash_hmac)

    async with sesiones() as sesion:
        key = await obtener_api_key_activa(sesion, prefijo)

    assert key is not None
    assert (key.id, key.aplicacion_id, key.prefijo, key.hash) == (
        key_id,
        app_id,
        prefijo,
        hash_hmac,
    )


async def test_el_hash_no_aparece_en_el_repr_de_la_key(sesiones: Sesiones) -> None:
    # Un log de la API con la key leída no debe llevarse el HMAC (CWE-532).
    app_id = await _aplicacion(sesiones)
    prefijo, hash_hmac = _prefijo(), _hash_hmac()
    async with sesiones.begin() as sesion:
        await crear_api_key(sesion, app_id, prefijo, hash_hmac)
    async with sesiones() as sesion:
        key = await obtener_api_key_activa(sesion, prefijo)
    assert hash_hmac not in repr(key)


async def test_prefijo_desconocido_no_devuelve_nada(sesiones: Sesiones) -> None:
    async with sesiones() as sesion:
        assert await obtener_api_key_activa(sesion, _prefijo()) is None


@pytest.mark.parametrize(
    "revocada_en",
    [
        datetime(2026, 1, 1, tzinfo=UTC),
        # Cualquier fecha de revocación cuenta, también una futura: falla cerrado.
        datetime.now(UTC) + timedelta(days=30),
    ],
)
async def test_key_revocada_no_se_devuelve(
    sesiones: Sesiones, revocada_en: datetime
) -> None:
    app_id = await _aplicacion(sesiones)
    prefijo = _prefijo()
    async with sesiones.begin() as sesion:
        key_id = await crear_api_key(sesion, app_id, prefijo, _hash_hmac())
        await sesion.execute(
            update(ApiKey).where(ApiKey.id == key_id).values(revocada_en=revocada_en)
        )

    async with sesiones() as sesion:
        assert await obtener_api_key_activa(sesion, prefijo) is None


async def test_key_de_aplicacion_inactiva_no_se_devuelve(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    prefijo = _prefijo()
    async with sesiones.begin() as sesion:
        await crear_api_key(sesion, app_id, prefijo, _hash_hmac())
        await sesion.execute(
            update(Aplicacion).where(Aplicacion.id == app_id).values(activa=False)
        )

    async with sesiones() as sesion:
        assert await obtener_api_key_activa(sesion, prefijo) is None


# --- INV-10: la firma lo hace obligatorio -----------------------------------------------


@pytest.mark.parametrize(
    "funcion",
    [crear_archivo, obtener_archivo, cambiar_estado, registrar_resultado],
)
def test_aplicacion_id_es_obligatorio_y_sin_valor_por_defecto(
    funcion: Callable[..., Any],
) -> None:
    parametro = inspect.signature(funcion).parameters["aplicacion_id"]
    assert parametro.default is inspect.Parameter.empty


def test_toda_funcion_publica_que_toca_archivos_recibe_aplicacion_id() -> None:
    # Si alguien agrega otra función sobre archivos, esta prueba le recuerda INV-10.
    exentas = {"crear_aplicacion", "crear_api_key", "obtener_api_key_activa"}
    funciones = {
        nombre: funcion
        for nombre, funcion in inspect.getmembers(
            repositorios, inspect.iscoroutinefunction
        )
        if funcion.__module__ == repositorios.__name__ and not nombre.startswith("_")
    }
    assert set(funciones) >= exentas
    for nombre, funcion in funciones.items():
        if nombre not in exentas:
            assert "aplicacion_id" in inspect.signature(funcion).parameters, nombre


# --- crear_archivo y obtener_archivo -----------------------------------------------------


async def test_crear_archivo_usa_el_id_que_asigna_la_api(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    asignado = uuid.uuid4()
    sha = hashlib.sha256(b"x").hexdigest()

    async with sesiones.begin() as sesion:
        creado = await crear_archivo(sesion, app_id, asignado, "foto.png", 10, sha)

    assert creado.id == asignado
    assert creado.aplicacion_id == app_id
    assert creado.nombre_original == "foto.png"
    assert creado.tamano_bytes == 10
    assert creado.sha256 == sha
    assert creado.estado is Estado.PENDIENTE
    assert creado.tipo_detectado is None
    assert creado.tipo_error is None
    assert creado.reintentos == 0
    assert creado.creado_en.tzinfo is not None
    assert creado.analizado_en is None


def test_crear_archivo_no_permite_elegir_estado_ni_reintentos() -> None:
    # Un archivo siempre nace pendiente, sin reintentos gastados (K17).
    parametros = inspect.signature(crear_archivo).parameters
    assert "estado" not in parametros
    assert "reintentos" not in parametros


async def test_nombre_hostil_se_guarda_como_texto(sesiones: Sesiones) -> None:
    # CWE-89: el nombre lo elige quien sube el archivo.
    app_id = await _aplicacion(sesiones)
    nombre = "'; DROP TABLE archivo; --"
    async with sesiones.begin() as sesion:
        creado = await crear_archivo(sesion, app_id, uuid.uuid4(), nombre, 1, "a" * 64)
    async with sesiones() as sesion:
        leido = await obtener_archivo(sesion, app_id, creado.id)
    assert leido is not None
    assert leido.nombre_original == nombre


async def test_obtener_archivo_propio(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)

    async with sesiones() as sesion:
        leido = await obtener_archivo(sesion, app_id, creado.id)

    assert leido == creado


async def test_un_archivo_ajeno_se_comporta_como_inexistente(
    sesiones: Sesiones,
) -> None:
    duena, ajena = await _aplicacion(sesiones), await _aplicacion(sesiones)
    creado = await _archivo(sesiones, duena)

    async with sesiones() as sesion:
        assert await obtener_archivo(sesion, ajena, creado.id) is None
        assert await obtener_archivo(sesion, ajena, uuid.uuid4()) is None


async def test_el_estado_leido_sirve_para_decidir_la_descarga(
    sesiones: Sesiones,
) -> None:
    # es_descargable exige el miembro Estado.LIMPIO: con el texto de la BD daría False
    # siempre y ningún archivo se podría descargar (K15).
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    assert not es_descargable(creado.estado)
    await _resultado_cdr(sesiones, app_id, creado.id)

    async with sesiones.begin() as sesion:
        await cambiar_estado(
            sesion,
            app_id,
            creado.id,
            Estado.PENDIENTE,
            Estado.LIMPIO,
            tipo_detectado="application/pdf",
        )
    async with sesiones() as sesion:
        leido = await obtener_archivo(sesion, app_id, creado.id)

    assert leido is not None
    assert leido.estado is Estado.LIMPIO
    assert es_descargable(leido.estado)


# --- cambiar_estado: caminos válidos ----------------------------------------------------


async def test_veredicto_limpio_guarda_tipo_y_fecha(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    await _resultado_cdr(sesiones, app_id, creado.id)

    async with sesiones.begin() as sesion:
        cambiado = await cambiar_estado(
            sesion,
            app_id,
            creado.id,
            Estado.PENDIENTE,
            Estado.LIMPIO,
            tipo_detectado="image/png",
        )

    assert cambiado.estado is Estado.LIMPIO
    assert cambiado.tipo_detectado == "image/png"
    assert cambiado.analizado_en is not None
    fila = await _leer(sesiones, creado.id)
    assert (fila.estado, fila.tipo_detectado, fila.analizado_en) == (
        "limpio",
        "image/png",
        cambiado.analizado_en,
    )


async def test_la_bd_pone_la_hora_del_veredicto(sesiones: Sesiones) -> None:
    # Un veredicto sin fecha dejaría al archivo fuera de M2 (creado_en -> analizado_en).
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)

    async with sesiones.begin() as sesion:
        cambiado = await cambiar_estado(
            sesion, app_id, creado.id, Estado.PENDIENTE, Estado.RECHAZADO
        )

    assert cambiado.analizado_en is not None
    assert cambiado.analizado_en >= creado.creado_en


def test_analizado_en_no_puede_venir_de_quien_llama() -> None:
    # M2 se mide con esta columna: un valor del llamador falsearía la métrica.
    assert "analizado_en" not in inspect.signature(cambiar_estado).parameters


async def test_analizado_en_es_la_hora_del_veredicto_no_la_de_la_transaccion(
    sesiones: Sesiones,
) -> None:
    # clock_timestamp() y no now(): now() es la hora a la que empezó la transacción.
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)

    async with sesiones.begin() as sesion:
        inicio_transaccion = (await sesion.execute(select(func.now()))).scalar_one()
        await asyncio.sleep(0.05)
        cambiado = await cambiar_estado(
            sesion, app_id, creado.id, Estado.PENDIENTE, Estado.RECHAZADO
        )

    assert cambiado.analizado_en is not None
    assert cambiado.analizado_en - inicio_transaccion >= timedelta(milliseconds=40)


async def test_rechazado_registra_el_tipo_real_aunque_no_este_permitido(
    sesiones: Sesiones,
) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)

    async with sesiones.begin() as sesion:
        cambiado = await cambiar_estado(
            sesion,
            app_id,
            creado.id,
            Estado.PENDIENTE,
            Estado.RECHAZADO,
            tipo_detectado="application/x-dosexec",
        )

    assert cambiado.tipo_detectado == "application/x-dosexec"


async def test_entrar_a_cuarentena_desde_pendiente(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)

    async with sesiones.begin() as sesion:
        cambiado = await cambiar_estado(
            sesion, app_id, creado.id, Estado.PENDIENTE, Estado.EN_CUARENTENA
        )

    assert cambiado.estado is Estado.EN_CUARENTENA


@pytest.mark.parametrize("tipo_error", ["transitorio", "final"])
async def test_entrar_a_error_guarda_el_tipo(
    sesiones: Sesiones, tipo_error: str
) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)

    async with sesiones.begin() as sesion:
        cambiado = await cambiar_estado(
            sesion,
            app_id,
            creado.id,
            Estado.PENDIENTE,
            Estado.ERROR,
            tipo_error=tipo_error,
        )

    assert cambiado.estado is Estado.ERROR
    assert cambiado.tipo_error == tipo_error
    assert cambiado.analizado_en is not None


# --- cambiar_estado: lo que se rechaza --------------------------------------------------


async def test_transicionar_valida_antes_de_tocar_la_bd() -> None:
    # Sin sesión: si intentara el UPDATE reventaría con AttributeError, no con esto.
    with pytest.raises(TransicionInvalida):
        await cambiar_estado(
            None,  # type: ignore[arg-type]
            uuid.uuid4(),
            uuid.uuid4(),
            Estado.LIMPIO,
            Estado.RECHAZADO,
        )


@pytest.mark.parametrize(
    ("actual", "nuevo"),
    [
        ("pendiente", Estado.LIMPIO),
        (Estado.PENDIENTE, "limpio"),
        ("pendiente", "limpio"),
    ],
)
async def test_estados_como_texto_se_rechazan(actual: Any, nuevo: Any) -> None:
    with pytest.raises(TransicionInvalida):
        await cambiar_estado(None, uuid.uuid4(), uuid.uuid4(), actual, nuevo)  # type: ignore[arg-type]


async def test_entrar_a_error_sin_tipo_error_se_rechaza() -> None:
    with pytest.raises(TransicionInvalida):
        await cambiar_estado(
            None,  # type: ignore[arg-type]
            uuid.uuid4(),
            uuid.uuid4(),
            Estado.PENDIENTE,
            Estado.ERROR,
        )


async def test_tipo_error_desconocido_se_rechaza() -> None:
    with pytest.raises(TransicionInvalida):
        await cambiar_estado(
            None,  # type: ignore[arg-type]
            uuid.uuid4(),
            uuid.uuid4(),
            Estado.PENDIENTE,
            Estado.ERROR,
            tipo_error="temporal",
        )


async def test_tipo_error_fuera_de_error_se_rechaza() -> None:
    with pytest.raises(TransicionInvalida):
        await cambiar_estado(
            None,  # type: ignore[arg-type]
            uuid.uuid4(),
            uuid.uuid4(),
            Estado.PENDIENTE,
            Estado.RECHAZADO,
            tipo_error="final",
        )


@pytest.mark.parametrize("tipo_error", [None, "transitorio"])
async def test_el_reintento_no_existe_en_esta_rebanada(
    sesiones: Sesiones, tipo_error: str | None
) -> None:
    # K17: reintentos lo manda la fila, nunca quien llama. Hasta que ese UPDATE exista no
    # debe haber ningún camino de error a pendiente.
    assert "reintentos" not in inspect.signature(cambiar_estado).parameters
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    await _llevar_a(sesiones, creado.id, "error", tipo_error="transitorio")

    async with sesiones.begin() as sesion:
        with pytest.raises(TransicionInvalida):
            await cambiar_estado(
                sesion,
                app_id,
                creado.id,
                Estado.ERROR,
                Estado.PENDIENTE,
                tipo_error=tipo_error,
            )

    assert (await _leer(sesiones, creado.id)).estado == "error"


@pytest.mark.parametrize(
    ("nuevo", "extra"),
    [
        (Estado.LIMPIO, {"tipo_detectado": "image/png"}),
        (Estado.RECHAZADO, {}),
        (Estado.ERROR, {"tipo_error": "final"}),
    ],
)
async def test_salir_de_cuarentena_sin_bitacora_no_existe(
    sesiones: Sesiones, nuevo: Estado, extra: dict[str, str]
) -> None:
    # INV-08: la liberación y su evento_auditoria van en la misma transacción. Esa tabla
    # todavía no existe, así que este camino tampoco.
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    await _llevar_a(sesiones, creado.id, "en_cuarentena")

    async with sesiones.begin() as sesion:
        with pytest.raises(TransicionInvalida):
            await cambiar_estado(
                sesion, app_id, creado.id, Estado.EN_CUARENTENA, nuevo, **extra
            )

    assert (await _leer(sesiones, creado.id)).estado == "en_cuarentena"


def test_cambiar_estado_no_recibe_datos_de_liberacion() -> None:
    parametros = inspect.signature(cambiar_estado).parameters
    assert not {"usuario", "motivo", "liberado_en"} & set(parametros)


@pytest.mark.parametrize(
    ("tipo", "caso"), [(None, "sin_tipo"), ("image/gif", "tipo_no_permitido")]
)
async def test_limpio_sin_tipo_permitido_se_rechaza(
    sesiones: Sesiones, tipo: str | None, caso: str
) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    await _resultado_cdr(sesiones, app_id, creado.id)

    with pytest.raises(ViolacionDeRestriccion) as error:
        async with sesiones.begin() as sesion:
            await cambiar_estado(
                sesion,
                app_id,
                creado.id,
                Estado.PENDIENTE,
                Estado.LIMPIO,
                tipo_detectado=tipo,
            )

    assert error.value.restriccion == "ck_archivo_limpio_en_lista_blanca"
    assert (await _leer(sesiones, creado.id)).estado == "pendiente"


# --- cambiar_estado: K16, evidencia del CDR en el mismo UPDATE ------------------------------


async def _a_limpio(
    sesiones: Sesiones, aplicacion_id: uuid.UUID, archivo_id: uuid.UUID
) -> DatosArchivo:
    async with sesiones.begin() as sesion:
        return await cambiar_estado(
            sesion,
            aplicacion_id,
            archivo_id,
            Estado.PENDIENTE,
            Estado.LIMPIO,
            tipo_detectado="image/png",
        )


async def _sigue_intacto(sesiones: Sesiones, archivo_id: uuid.UUID) -> None:
    fila = await _leer(sesiones, archivo_id)
    assert (fila.estado, fila.tipo_detectado, fila.analizado_en) == (
        "pendiente",
        None,
        None,
    )


async def test_limpio_sin_resultado_de_cdr_no_cambia_la_fila(
    sesiones: Sesiones,
) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)

    with pytest.raises(SinEvidenciaCDR):
        await _a_limpio(sesiones, app_id, creado.id)

    await _sigue_intacto(sesiones, creado.id)


@pytest.mark.parametrize(
    "veredicto", ["rechazado", "error", "malicioso", "no_evaluada"]
)
async def test_limpio_con_cdr_que_no_dio_limpio_no_cambia_la_fila(
    sesiones: Sesiones, veredicto: str
) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    await _resultado_cdr(sesiones, app_id, creado.id, veredicto)

    with pytest.raises(SinEvidenciaCDR):
        await _a_limpio(sesiones, app_id, creado.id)

    await _sigue_intacto(sesiones, creado.id)


async def test_limpio_con_cdr_limpio_se_aplica(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    await _resultado_cdr(sesiones, app_id, creado.id)

    cambiado = await _a_limpio(sesiones, app_id, creado.id)

    assert cambiado.estado is Estado.LIMPIO
    assert (await _leer(sesiones, creado.id)).estado == "limpio"


@pytest.mark.parametrize("capa", ["firma", "clamav", "virustotal"])
async def test_el_limpio_de_otra_capa_no_es_evidencia(
    sesiones: Sesiones, capa: str
) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    await _resultado_cdr(sesiones, app_id, creado.id, capa=capa)

    with pytest.raises(SinEvidenciaCDR):
        await _a_limpio(sesiones, app_id, creado.id)

    await _sigue_intacto(sesiones, creado.id)


async def test_el_cdr_limpio_de_otro_archivo_no_es_evidencia(
    sesiones: Sesiones,
) -> None:
    app_id = await _aplicacion(sesiones)
    creado, otro = await _archivo(sesiones, app_id), await _archivo(sesiones, app_id)
    await _resultado_cdr(sesiones, app_id, otro.id)

    with pytest.raises(SinEvidenciaCDR):
        await _a_limpio(sesiones, app_id, creado.id)

    await _sigue_intacto(sesiones, creado.id)


async def test_la_evidencia_vale_en_la_misma_transaccion(sesiones: Sesiones) -> None:
    # Así lo hará quien decide: guarda el resultado y aplica el veredicto juntos.
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)

    async with sesiones.begin() as sesion:
        await registrar_resultado(sesion, app_id, creado.id, "cdr", "limpio", {}, 5)
        cambiado = await cambiar_estado(
            sesion,
            app_id,
            creado.id,
            Estado.PENDIENTE,
            Estado.LIMPIO,
            tipo_detectado="image/png",
        )

    assert cambiado.estado is Estado.LIMPIO


def test_sin_evidencia_no_se_confunde_con_un_conflicto() -> None:
    # Un conflicto se resuelve releyendo; la falta de evidencia, no.
    assert not issubclass(SinEvidenciaCDR, ConflictoDeEstado)
    assert not issubclass(ConflictoDeEstado, SinEvidenciaCDR)
    assert not issubclass(SinEvidenciaCDR, ArchivoNoEncontrado)


async def test_sin_evidencia_no_abre_el_archivo_ajeno(sesiones: Sesiones) -> None:
    # INV-10: un archivo ajeno da 404 tenga o no evidencia, igual que uno inexistente.
    duena, ajena = await _aplicacion(sesiones), await _aplicacion(sesiones)
    con_evidencia, sin_evidencia = (
        await _archivo(sesiones, duena),
        await _archivo(sesiones, duena),
    )
    await _resultado_cdr(sesiones, duena, con_evidencia.id)

    errores = [
        await _error_de(partial(_a_limpio, sesiones, ajena, archivo_id))
        for archivo_id in (con_evidencia.id, sin_evidencia.id, uuid.uuid4())
    ]

    assert [type(error) for error in errores] == [ArchivoNoEncontrado] * 3
    assert len({str(error) for error in errores}) == 1
    await _sigue_intacto(sesiones, con_evidencia.id)
    await _sigue_intacto(sesiones, sin_evidencia.id)


@pytest.mark.parametrize(
    ("nuevo", "extra"),
    [
        (Estado.RECHAZADO, {}),
        (Estado.EN_CUARENTENA, {}),
        (Estado.ERROR, {"tipo_error": "final"}),
    ],
)
async def test_los_otros_veredictos_no_exigen_evidencia_de_cdr(
    sesiones: Sesiones, nuevo: Estado, extra: dict[str, str]
) -> None:
    # Un rechazo por firma nunca llega al CDR: exigirlo dejaría el archivo en pendiente.
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)

    async with sesiones.begin() as sesion:
        cambiado = await cambiar_estado(
            sesion, app_id, creado.id, Estado.PENDIENTE, nuevo, **extra
        )

    assert cambiado.estado is nuevo


# --- cambiar_estado: INV-10 y conflictos ------------------------------------------------


async def test_otra_aplicacion_no_puede_cambiar_el_estado(sesiones: Sesiones) -> None:
    duena, ajena = await _aplicacion(sesiones), await _aplicacion(sesiones)
    creado = await _archivo(sesiones, duena)

    async with sesiones.begin() as sesion:
        with pytest.raises(ArchivoNoEncontrado):
            await cambiar_estado(
                sesion,
                ajena,
                creado.id,
                Estado.PENDIENTE,
                Estado.RECHAZADO,
            )

    fila = await _leer(sesiones, creado.id)
    assert (fila.estado, fila.analizado_en) == ("pendiente", None)


async def _error_de(accion: Callable[[], Awaitable[object]]) -> Exception:
    with pytest.raises(Exception) as error:
        await accion()
    assert isinstance(error.value, Exception)
    return error.value


async def test_ajeno_e_inexistente_son_indistinguibles_al_cambiar_estado(
    sesiones: Sesiones,
) -> None:
    # Si el ajeno diera conflicto (409) y el inexistente 404, la API confirmaría qué ids
    # existen en otras aplicaciones.
    duena, ajena = await _aplicacion(sesiones), await _aplicacion(sesiones)
    creado = await _archivo(sesiones, duena)

    async def _intentar(archivo_id: uuid.UUID) -> None:
        async with sesiones.begin() as sesion:
            await cambiar_estado(
                sesion, ajena, archivo_id, Estado.PENDIENTE, Estado.RECHAZADO
            )

    con_ajeno = await _error_de(lambda: _intentar(creado.id))
    con_inexistente = await _error_de(lambda: _intentar(uuid.uuid4()))

    assert type(con_ajeno) is ArchivoNoEncontrado
    assert type(con_inexistente) is ArchivoNoEncontrado
    assert str(con_ajeno) == str(con_inexistente)


async def test_estado_actual_desfasado_es_conflicto(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    await _llevar_a(sesiones, creado.id, "rechazado")

    async with sesiones.begin() as sesion:
        with pytest.raises(ConflictoDeEstado):
            await cambiar_estado(
                sesion,
                app_id,
                creado.id,
                Estado.PENDIENTE,
                Estado.LIMPIO,
                tipo_detectado="image/png",
            )

    fila = await _leer(sesiones, creado.id)
    assert (fila.estado, fila.tipo_detectado) == ("rechazado", None)


async def _esperar_bloqueada(sesiones: Sesiones) -> None:
    """Espera a que alguna sentencia esté detenida esperando un bloqueo de fila."""
    consulta = text(
        "SELECT count(*) FROM pg_stat_activity"
        " WHERE datname = current_database() AND wait_event_type = 'Lock'"
    )
    for _ in range(500):
        async with sesiones() as sesion:
            if (await sesion.execute(consulta)).scalar_one() > 0:
                return
        await asyncio.sleep(0.01)
    pytest.fail("la segunda transición nunca llegó a esperar el bloqueo de la fila")


async def test_segunda_transicion_espera_a_la_primera_y_pierde(
    sesiones: Sesiones,
) -> None:
    # Intercalado determinista: A actualiza sin confirmar, B queda esperando la fila y,
    # cuando A confirma, PostgreSQL reevalúa el WHERE de B, que ya no coincide.
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    await _resultado_cdr(sesiones, app_id, creado.id)

    async def _segunda() -> None:
        async with sesiones.begin() as sesion:
            await cambiar_estado(
                sesion, app_id, creado.id, Estado.PENDIENTE, Estado.RECHAZADO
            )

    async with sesiones() as sesion_a, sesion_a.begin():
        await cambiar_estado(
            sesion_a,
            app_id,
            creado.id,
            Estado.PENDIENTE,
            Estado.LIMPIO,
            tipo_detectado="image/png",
        )
        segunda = asyncio.create_task(_segunda())
        await _esperar_bloqueada(sesiones)
        assert not segunda.done()

    with pytest.raises(ConflictoDeEstado):
        await segunda
    assert (await _leer(sesiones, creado.id)).estado == "limpio"


async def test_limpio_que_pierde_la_carrera_es_conflicto_y_no_falta_de_evidencia(
    sesiones: Sesiones,
) -> None:
    # B ya tenía evidencia y queda esperando la fila que A rechazó. Si A confirma, B debe
    # releer y ver que perdió: decirle "sin evidencia" sería una causa falsa.
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    await _resultado_cdr(sesiones, app_id, creado.id)

    async with sesiones() as sesion_a, sesion_a.begin():
        await cambiar_estado(
            sesion_a, app_id, creado.id, Estado.PENDIENTE, Estado.RECHAZADO
        )
        segunda = asyncio.create_task(_a_limpio(sesiones, app_id, creado.id))
        await _esperar_bloqueada(sesiones)
        assert not segunda.done()

    with pytest.raises(ConflictoDeEstado):
        await segunda
    assert (await _leer(sesiones, creado.id)).estado == "rechazado"


async def test_entre_muchas_transiciones_concurrentes_solo_pasa_una(
    sesiones: Sesiones,
) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    barrera = asyncio.Event()

    async def _intento(i: int) -> str:
        await barrera.wait()
        try:
            async with sesiones.begin() as sesion:
                await cambiar_estado(
                    sesion,
                    app_id,
                    creado.id,
                    Estado.PENDIENTE,
                    Estado.ERROR,
                    tipo_error="final" if i % 2 else "transitorio",
                )
        except ConflictoDeEstado:
            return "conflicto"
        return "aplicado"

    tareas = [asyncio.create_task(_intento(i)) for i in range(8)]
    barrera.set()
    resultados = await asyncio.gather(*tareas)

    assert sorted(resultados) == ["aplicado"] + ["conflicto"] * 7


# --- registrar_resultado ----------------------------------------------------------------


async def test_registrar_resultado_guarda_la_capa(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    detalle = {"mime": "application/pdf", "motores": 0, "nota": "o'brien"}

    async with sesiones.begin() as sesion:
        resultado_id = await registrar_resultado(
            sesion, app_id, creado.id, "firma", "limpio", detalle, 12
        )

    async with sesiones() as sesion:
        fila = (
            await sesion.execute(
                select(ResultadoAnalisis).where(ResultadoAnalisis.id == resultado_id)
            )
        ).scalar_one()
    assert fila.archivo_id == creado.id
    assert (fila.capa, fila.veredicto, fila.duracion_ms) == ("firma", "limpio", 12)
    assert fila.detalle == detalle


async def test_registrar_resultado_sin_duracion(sesiones: Sesiones) -> None:
    # VirusTotal sin cuota responde no_evaluada sin haber medido nada.
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)

    async with sesiones.begin() as sesion:
        await registrar_resultado(
            sesion, app_id, creado.id, "virustotal", "no_evaluada", {}, None
        )

    assert await _resultados(sesiones, creado.id) == 1


async def test_otra_aplicacion_no_puede_registrar_resultados(
    sesiones: Sesiones,
) -> None:
    duena, ajena = await _aplicacion(sesiones), await _aplicacion(sesiones)
    creado = await _archivo(sesiones, duena)

    async with sesiones.begin() as sesion:
        with pytest.raises(ArchivoNoEncontrado):
            await registrar_resultado(
                sesion, ajena, creado.id, "firma", "limpio", {}, 1
            )

    assert await _resultados(sesiones, creado.id) == 0


async def test_registrar_resultado_de_archivo_inexistente(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)

    async with sesiones.begin() as sesion:
        with pytest.raises(ArchivoNoEncontrado):
            await registrar_resultado(
                sesion, app_id, uuid.uuid4(), "firma", "limpio", {}, 1
            )


@pytest.mark.parametrize(
    ("capa", "veredicto", "detalle", "duracion", "restriccion"),
    [
        ("yara", "limpio", {}, 1, "ck_resultado_analisis_capa_valida"),
        ("firma", "dudoso", {}, 1, "ck_resultado_analisis_veredicto_valido"),
        (
            "firma",
            "limpio",
            {"x": "a" * 65_536},
            1,
            "ck_resultado_analisis_detalle_tope",
        ),
        ("firma", "limpio", {}, -1, "ck_resultado_analisis_duracion_ms_no_negativa"),
        ("firma", "limpio", ["lista"], 1, "ck_resultado_analisis_detalle_objeto"),
    ],
)
async def test_registrar_resultado_respeta_las_restricciones(
    sesiones: Sesiones,
    capa: str,
    veredicto: str,
    detalle: dict[str, object],
    duracion: int,
    restriccion: str,
) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)

    with pytest.raises(ViolacionDeRestriccion) as error:
        async with sesiones.begin() as sesion:
            await registrar_resultado(
                sesion, app_id, creado.id, capa, veredicto, detalle, duracion
            )

    assert error.value.restriccion == restriccion


async def test_detalle_none_no_se_guarda_como_null_json(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)

    with pytest.raises(ViolacionDeRestriccion) as error:
        async with sesiones.begin() as sesion:
            await registrar_resultado(
                sesion,
                app_id,
                creado.id,
                "firma",
                "limpio",
                None,  # type: ignore[arg-type]
                1,
            )

    # En PostgreSQL 16 un NOT NULL no tiene nombre de restricción.
    assert error.value.restriccion is None
    assert await _resultados(sesiones, creado.id) == 0


async def test_los_repositorios_no_confirman_por_su_cuenta(sesiones: Sesiones) -> None:
    # La transacción es de quien llama: así la liberación (F5.06) podrá escribir el estado
    # y la bitácora juntos (INV-08).
    app_id = await _aplicacion(sesiones)

    async with sesiones() as sesion:
        creado = await crear_archivo(sesion, app_id, uuid.uuid4(), "a.png", 1, "a" * 64)
        await sesion.rollback()

    async with sesiones() as sesion:
        assert await obtener_archivo(sesion, app_id, creado.id) is None


# --- CWE-117/CWE-532: un choque de restricción no arrastra datos ---------------------------

NOMBRE_HOSTIL = "linea1\nINFO falsa entrada de log\r\n.pdf"
SHA_MARCADO = "c0ffee" * 10 + "c0ff"


def _texto_visible(error: BaseException) -> str:
    """Todo lo que un log o un traceback podría sacar de la excepción."""
    return "\n".join(
        [
            str(error),
            repr(error),
            repr(error.args),
            "".join(traceback.format_exception(error)),
        ]
    )


def _sin_rastro(error: BaseException, *datos: str) -> None:
    # No basta con suprimir el contexto al imprimir: ``raise ... from None`` dentro del
    # except deja el IntegrityError en __context__, y con él el DETAIL completo.
    assert error.__cause__ is None
    assert error.__context__ is None
    texto = _texto_visible(error)
    for dato in datos:
        assert dato not in texto
    assert "Failing row" not in texto
    assert "DETAIL" not in texto


def test_el_error_de_restriccion_lleva_solo_el_nombre() -> None:
    error = ViolacionDeRestriccion("ck_archivo_sha256_hex")
    assert error.restriccion == "ck_archivo_sha256_hex"
    assert "ck_archivo_sha256_hex" in str(error)


async def test_crear_archivo_no_filtra_nombre_ni_sha256(sesiones: Sesiones) -> None:
    # tamano_bytes = 0 rompe un CHECK: el DETAIL ("Failing row contains") trae toda la fila.
    app_id = await _aplicacion(sesiones)

    with pytest.raises(ViolacionDeRestriccion) as error:
        async with sesiones.begin() as sesion:
            await crear_archivo(
                sesion, app_id, uuid.uuid4(), NOMBRE_HOSTIL, 0, SHA_MARCADO
            )

    assert error.value.restriccion == "ck_archivo_tamano_bytes_rango"
    _sin_rastro(error.value, "linea1", "INFO falsa", SHA_MARCADO)


@pytest.mark.parametrize("cola", ["x" * 256, "\x00"], ids=["demasiado_largo", "nul"])
async def test_nombre_que_no_cabe_en_el_tipo_no_se_muestra(
    sesiones: Sesiones, cola: str
) -> None:
    # No choca con una restricción sino con el tipo: es un DataError y no se traduce. Lo
    # que importa es que el nombre, que lo elige quien sube el archivo, no vaya en él.
    app_id = await _aplicacion(sesiones)
    marca = secrets.token_hex(8)

    with pytest.raises(DataError) as error:
        async with sesiones.begin() as sesion:
            await crear_archivo(
                sesion, app_id, uuid.uuid4(), marca + cola, 1, SHA_MARCADO
            )

    assert marca not in _texto_visible(error.value)
    assert SHA_MARCADO not in _texto_visible(error.value)


async def test_crear_archivo_con_id_repetido(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)

    with pytest.raises(ViolacionDeRestriccion) as error:
        async with sesiones.begin() as sesion:
            await crear_archivo(sesion, app_id, creado.id, "b.png", 1, "a" * 64)

    assert error.value.restriccion == "pk_archivo"
    _sin_rastro(error.value, str(creado.id))


async def test_crear_api_key_no_filtra_el_hash(sesiones: Sesiones) -> None:
    # El prefijo inválido rompe un CHECK; el DETAIL traería el hash de la key.
    app_id = await _aplicacion(sesiones)
    hash_hmac = _hash_hmac()

    with pytest.raises(ViolacionDeRestriccion) as error:
        async with sesiones.begin() as sesion:
            await crear_api_key(sesion, app_id, "invalido", hash_hmac)

    assert error.value.restriccion == "ck_api_key_prefijo_formato"
    _sin_rastro(error.value, hash_hmac)


async def test_crear_api_key_con_hash_repetido_no_lo_muestra(
    sesiones: Sesiones,
) -> None:
    # El choque de UNIQUE repite la clave en el DETAIL: "Key (hash)=(...) already exists".
    app_id = await _aplicacion(sesiones)
    hash_hmac = _hash_hmac()
    async with sesiones.begin() as sesion:
        await crear_api_key(sesion, app_id, _prefijo(), hash_hmac)

    with pytest.raises(ViolacionDeRestriccion) as error:
        async with sesiones.begin() as sesion:
            await crear_api_key(sesion, app_id, _prefijo(), hash_hmac)

    assert error.value.restriccion == "uq_api_key_hash"
    _sin_rastro(error.value, hash_hmac)


async def test_crear_api_key_de_aplicacion_inexistente(sesiones: Sesiones) -> None:
    with pytest.raises(ViolacionDeRestriccion) as error:
        async with sesiones.begin() as sesion:
            await crear_api_key(sesion, uuid.uuid4(), _prefijo(), _hash_hmac())

    assert error.value.restriccion == "fk_api_key_aplicacion_id_aplicacion"


async def test_crear_aplicacion_repetida_no_filtra_el_nombre(
    sesiones: Sesiones,
) -> None:
    # Aleatorio: un literal aparecería en el traceback, en la línea fuente de esta prueba.
    nombre = f"Portal-{secrets.token_hex(8)}"
    await _aplicacion(sesiones, nombre)

    with pytest.raises(ViolacionDeRestriccion) as error:
        await _aplicacion(sesiones, nombre.lower())

    assert error.value.restriccion == "uq_aplicacion_nombre_lower"
    _sin_rastro(error.value, nombre, nombre.lower())


async def test_cambiar_estado_no_filtra_la_fila(sesiones: Sesiones) -> None:
    # El CHECK de limpio se dispara con la fila completa, nombre_original incluido.
    app_id = await _aplicacion(sesiones)
    archivo_id = uuid.uuid4()
    async with sesiones.begin() as sesion:
        await crear_archivo(sesion, app_id, archivo_id, NOMBRE_HOSTIL, 1, SHA_MARCADO)
    await _resultado_cdr(sesiones, app_id, archivo_id)

    with pytest.raises(ViolacionDeRestriccion) as error:
        async with sesiones.begin() as sesion:
            await cambiar_estado(
                sesion,
                app_id,
                archivo_id,
                Estado.PENDIENTE,
                Estado.LIMPIO,
                tipo_detectado="image/gif",
            )

    assert error.value.restriccion == "ck_archivo_limpio_en_lista_blanca"
    _sin_rastro(error.value, "linea1", "INFO falsa", SHA_MARCADO)


async def test_registrar_resultado_no_filtra_el_detalle(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    marca = secrets.token_hex(8)

    with pytest.raises(ViolacionDeRestriccion) as error:
        async with sesiones.begin() as sesion:
            await registrar_resultado(
                sesion, app_id, creado.id, "yara", "limpio", {"pista": marca}, 1
            )

    assert error.value.restriccion == "ck_resultado_analisis_capa_valida"
    _sin_rastro(error.value, marca)


async def test_registrar_resultado_con_not_null_tampoco_filtra(
    sesiones: Sesiones,
) -> None:
    # El NOT NULL también responde "Failing row contains" y no trae constraint_name.
    app_id = await _aplicacion(sesiones)
    creado = await _archivo(sesiones, app_id)
    marca = secrets.token_hex(8)

    with pytest.raises(ViolacionDeRestriccion) as error:
        async with sesiones.begin() as sesion:
            await registrar_resultado(
                sesion,
                app_id,
                creado.id,
                "firma",
                None,  # type: ignore[arg-type]
                {"pista": marca},
                1,
            )

    assert error.value.restriccion is None
    _sin_rastro(error.value, marca)


# --- CWE-532: los resultados no llevan datos sensibles al repr ------------------------------


def test_datos_api_key_no_muestra_ni_compara_el_hash() -> None:
    comunes = {
        "id": uuid.uuid4(),
        "aplicacion_id": uuid.uuid4(),
        "prefijo": _prefijo(),
    }
    una, otra = _hash_hmac(), _hash_hmac()
    key = DatosApiKey(**comunes, hash=una)

    assert una not in repr(key)
    # Comparar el HMAC con == no es de tiempo constante: el dataclass no debe hacerlo.
    assert key == DatosApiKey(**comunes, hash=otra)
    campo = {c.name: c for c in dataclasses.fields(DatosApiKey)}["hash"]
    assert (campo.repr, campo.compare) == (False, False)


async def test_datos_archivo_no_muestra_nombre_ni_sha256(sesiones: Sesiones) -> None:
    app_id = await _aplicacion(sesiones)

    async with sesiones.begin() as sesion:
        creado = await crear_archivo(
            sesion, app_id, uuid.uuid4(), NOMBRE_HOSTIL, 1, SHA_MARCADO
        )

    assert "linea1" not in repr(creado)
    assert SHA_MARCADO not in repr(creado)
    assert str(creado.id) in repr(creado)
