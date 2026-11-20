"""Latencia de los repositorios del camino de un archivo (M1, M2; diseño §6).

Cada muestra es una operación completa como la hace la API: sesión nueva del pool,
consulta y, en las escrituras, ``COMMIT``. Antes se cargan filas para no medir tablas
vacías. El tope es holgado a propósito: detecta regresiones sin volverse inestable. El
número útil es el p95 que se imprime; se ve con ``pytest -s``. En GitHub Actions el tope
se multiplica por ``GATEKEEPER_FACTOR_LATENCIA`` (K56; ver ``latencia.py``).

Se mide conectado como ``gk_app``, igual que la API. Las consultas del camino del 202
(autenticar la key y registrar el archivo) se miden además con el dueño del esquema, para
ver si los permisos de la 0002 cambian la latencia (``medidas``). Los datos previos y el
``ANALYZE`` los hace siempre el dueño: con ``gk_app`` PostgreSQL 16 salta el ``ANALYZE``.
"""

import asyncio
import hashlib
import secrets
import statistics
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import func, insert, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from api.app.estados import Estado
from api.db.modelos import Archivo, ResultadoAnalisis
from api.db.repositorios import (
    DatosArchivo,
    cambiar_estado,
    contar_pendientes,
    crear_api_key,
    crear_aplicacion,
    crear_archivo,
    crear_archivo_con_cupo,
    obtener_api_key_activa,
    obtener_archivo,
)
from api.db.tests.latencia import exigir_tope_ms

pytestmark = pytest.mark.anyio

Sesiones = async_sessionmaker[AsyncSession]

MUESTRAS = 1000
FILAS_PREVIAS = 5000
TOPE_P95_MS = 20.0
SHA256 = hashlib.sha256(b"contenido").hexdigest()


@dataclass(frozen=True, slots=True)
class Medidas:
    """Sesiones con las que se mide y el rol con que conectan."""

    rol: str
    sesiones: Sesiones


@pytest.fixture(params=["gk_app", "dueno"])
def medidas(
    request: pytest.FixtureRequest, sesiones: Sesiones, sesiones_dueno: Sesiones
) -> Medidas:
    return Medidas(
        request.param, sesiones if request.param == "gk_app" else sesiones_dueno
    )


async def _medir(
    nombre: str,
    operacion: Callable[[int], Awaitable[object]],
    record_property: Any,
) -> None:
    tiempos_ms = []
    for i in range(MUESTRAS):
        inicio = time.perf_counter()
        await operacion(i)
        tiempos_ms.append((time.perf_counter() - inicio) * 1000)

    _reportar(nombre, tiempos_ms, record_property)


async def _preparar(sesiones: Sesiones) -> uuid.UUID:
    """Crea una aplicación con ``FILAS_PREVIAS`` archivos ajenos a la de la medición."""
    async with sesiones.begin() as sesion:
        vecina = await crear_aplicacion(sesion, "vecina")
        await sesion.execute(
            insert(Archivo),
            [
                {
                    "aplicacion_id": vecina,
                    "nombre_original": "previo.pdf",
                    "tamano_bytes": 1024,
                    "sha256": SHA256,
                }
                for _ in range(FILAS_PREVIAS)
            ],
        )
        app_id = await crear_aplicacion(sesion, "medida")
    async with sesiones() as sesion, sesion.begin():
        await sesion.execute(text("ANALYZE archivo"))
    return app_id


async def _analizar(sesiones: Sesiones) -> None:
    """Actualiza las estadísticas para que el plan sea el de una tabla con datos."""
    async with sesiones() as sesion, sesion.begin():
        await sesion.execute(text("ANALYZE archivo"))
        await sesion.execute(text("ANALYZE resultado_analisis"))


async def _crear_resultados(sesiones: Sesiones, ids: list[uuid.UUID]) -> None:
    """Deja en cada archivo las filas de la rebanada: firma y CDR limpios (K16)."""
    async with sesiones.begin() as sesion:
        await sesion.execute(
            insert(ResultadoAnalisis),
            [
                {"archivo_id": archivo_id, "capa": capa, "veredicto": "limpio"}
                for archivo_id in ids
                for capa in ("firma", "cdr")
            ],
        )


async def _crear_pendientes(
    sesiones: Sesiones, app_id: uuid.UUID, cantidad: int
) -> list[uuid.UUID]:
    ids = [uuid.uuid4() for _ in range(cantidad)]
    async with sesiones.begin() as sesion:
        await sesion.execute(
            insert(Archivo),
            [
                {
                    "id": archivo_id,
                    "aplicacion_id": app_id,
                    "nombre_original": "medida.pdf",
                    "tamano_bytes": 1024,
                    "sha256": SHA256,
                }
                for archivo_id in ids
            ],
        )
    return ids


async def test_latencia_crear_archivo(
    medidas: Medidas, sesiones_dueno: Sesiones, record_property: Any
) -> None:
    app_id = await _preparar(sesiones_dueno)

    async def _operacion(_i: int) -> None:
        async with medidas.sesiones.begin() as sesion:
            await crear_archivo(
                sesion, app_id, uuid.uuid4(), "medida.pdf", 1024, SHA256
            )

    await _medir(f"crear_archivo [{medidas.rol}]", _operacion, record_property)


async def test_latencia_cambiar_estado(
    sesiones: Sesiones, sesiones_dueno: Sesiones, record_property: Any
) -> None:
    app_id = await _preparar(sesiones_dueno)
    ids = await _crear_pendientes(sesiones_dueno, app_id, MUESTRAS)
    await _crear_resultados(sesiones_dueno, ids)
    await _analizar(sesiones_dueno)

    async def _operacion(i: int) -> None:
        async with sesiones.begin() as sesion:
            await cambiar_estado(
                sesion,
                app_id,
                ids[i],
                Estado.PENDIENTE,
                Estado.LIMPIO,
                tipo_detectado="application/pdf",
            )

    await _medir("cambiar_estado", _operacion, record_property)


async def test_el_exists_de_la_evidencia_lo_sirve_el_indice(
    sesiones: Sesiones, sesiones_dueno: Sesiones
) -> None:
    # Misma forma que el UPDATE de cambiar_estado hacia limpio (K16).
    app_id = await _preparar(sesiones_dueno)
    ids = await _crear_pendientes(sesiones_dueno, app_id, MUESTRAS)
    await _crear_resultados(sesiones_dueno, ids)
    await _analizar(sesiones_dueno)

    async with sesiones() as sesion:
        plan = await sesion.execute(
            text(
                "EXPLAIN UPDATE archivo SET estado = 'limpio'"
                " WHERE id = :id AND aplicacion_id = :app AND estado = 'pendiente'"
                " AND EXISTS (SELECT 1 FROM resultado_analisis"
                " WHERE resultado_analisis.archivo_id = archivo.id"
                " AND capa = 'cdr' AND veredicto = 'limpio')"
            ),
            {"id": ids[0], "app": app_id},
        )
        lineas = "\n".join(plan.scalars())

    assert "ix_resultado_analisis_archivo_id" in lineas, lineas
    assert "Seq Scan" not in lineas, lineas


async def test_latencia_obtener_archivo(
    sesiones: Sesiones, sesiones_dueno: Sesiones, record_property: Any
) -> None:
    app_id = await _preparar(sesiones_dueno)
    ids = await _crear_pendientes(sesiones_dueno, app_id, MUESTRAS)

    async def _operacion(i: int) -> None:
        async with sesiones() as sesion:
            assert await obtener_archivo(sesion, app_id, ids[i]) is not None

    await _medir("obtener_archivo", _operacion, record_property)


TOPE_K48 = 20
PENDIENTES_DE_FONDO = 10  # Cola a medio llenar: 10 + 8 escritores < 20, nunca se agota.
ESCRITORES = 8
# Con contención las altas con cupo de una aplicación se forman en fila: el bloqueo dura hasta
# el COMMIT, y el COMMIT espera el fsync del WAL (~3.5 ms aquí). Lo esperable es cerca de
# ESCRITORES x COMMIT; el tope es el doble, para detectar regresiones sin volverse inestable.
TOPE_P95_CONTENCION_MS = 2 * ESCRITORES * 3.5


async def _rechazar(sesiones: Sesiones, archivo_id: uuid.UUID) -> None:
    """Saca el archivo de pendiente fuera de la medición, para que la cola no crezca."""
    async with sesiones.begin() as sesion:
        await sesion.execute(
            update(Archivo)
            .where(Archivo.id == archivo_id)
            .values(estado="rechazado", analizado_en=func.now())
        )


async def test_latencia_contar_pendientes(
    sesiones: Sesiones, sesiones_dueno: Sesiones, record_property: Any
) -> None:
    app_id = await _preparar(sesiones_dueno)
    await _crear_pendientes(sesiones_dueno, app_id, PENDIENTES_DE_FONDO)
    await _analizar(sesiones_dueno)

    async def _operacion(_i: int) -> None:
        async with sesiones() as sesion:
            assert await contar_pendientes(sesion, app_id) == PENDIENTES_DE_FONDO

    await _medir("contar_pendientes", _operacion, record_property)


async def test_latencia_crear_archivo_con_cupo(
    medidas: Medidas, sesiones_dueno: Sesiones, record_property: Any
) -> None:
    # Cada muestra: bloqueo de la aplicación, cuenta, INSERT y COMMIT, como en el 202.
    app_id = await _preparar(sesiones_dueno)
    await _crear_pendientes(sesiones_dueno, app_id, PENDIENTES_DE_FONDO)
    await _analizar(sesiones_dueno)
    tiempos_ms: list[float] = []
    sesiones = medidas.sesiones

    async def _operacion(_i: int) -> None:
        inicio = time.perf_counter()
        async with sesiones.begin() as sesion:
            creado = await crear_archivo_con_cupo(
                sesion,
                app_id,
                uuid.uuid4(),
                "medida.pdf",
                1024,
                SHA256,
                tope_pendientes=TOPE_K48,
            )
        tiempos_ms.append((time.perf_counter() - inicio) * 1000)
        await _rechazar(sesiones_dueno, creado.id)

    for i in range(MUESTRAS):
        await _operacion(i)
    _reportar(f"crear_archivo_con_cupo [{medidas.rol}]", tiempos_ms, record_property)


async def _medir_concurrente(
    sesiones: Sesiones,
    sesiones_dueno: Sesiones,
    app_id: uuid.UUID,
    crear: Callable[[AsyncSession], Awaitable[DatosArchivo]],
) -> list[float]:
    """``ESCRITORES`` tareas simultáneas de la misma aplicación; ``MUESTRAS`` en total."""
    tiempos_ms: list[float] = []
    barrera = asyncio.Event()

    async def _escritor() -> None:
        await barrera.wait()
        for _ in range(MUESTRAS // ESCRITORES):
            inicio = time.perf_counter()
            async with sesiones.begin() as sesion:
                creado = await crear(sesion)
            tiempos_ms.append((time.perf_counter() - inicio) * 1000)
            await _rechazar(sesiones_dueno, creado.id)

    tareas = [asyncio.create_task(_escritor()) for _ in range(ESCRITORES)]
    barrera.set()
    await asyncio.gather(*tareas)
    return tiempos_ms


async def test_latencia_con_escritores_simultaneos_de_la_misma_aplicacion(
    medidas: Medidas, sesiones_dueno: Sesiones, record_property: Any
) -> None:
    # El bloqueo de la aplicación serializa sus altas: se compara con crear_archivo, que
    # no espera a nadie, bajo la misma carga.
    app_id = await _preparar(sesiones_dueno)
    await _crear_pendientes(sesiones_dueno, app_id, PENDIENTES_DE_FONDO)
    await _analizar(sesiones_dueno)

    def _con_cupo(sesion: AsyncSession) -> Awaitable[DatosArchivo]:
        return crear_archivo_con_cupo(
            sesion,
            app_id,
            uuid.uuid4(),
            "medida.pdf",
            1024,
            SHA256,
            tope_pendientes=TOPE_K48,
        )

    def _sin_cupo(sesion: AsyncSession) -> Awaitable[DatosArchivo]:
        return crear_archivo(sesion, app_id, uuid.uuid4(), "medida.pdf", 1024, SHA256)

    _reportar(
        f"crear_archivo x{ESCRITORES} [{medidas.rol}]",
        await _medir_concurrente(medidas.sesiones, sesiones_dueno, app_id, _sin_cupo),
        record_property,
    )
    _reportar(
        f"crear_archivo_con_cupo x{ESCRITORES} [{medidas.rol}]",
        await _medir_concurrente(medidas.sesiones, sesiones_dueno, app_id, _con_cupo),
        record_property,
        tope_ms=TOPE_P95_CONTENCION_MS,
    )


def _reportar(
    nombre: str,
    tiempos_ms: list[float],
    record_property: Any,
    *,
    tope_ms: float = TOPE_P95_MS,
) -> None:
    p95 = statistics.quantiles(tiempos_ms, n=100)[94]
    mediana = statistics.median(tiempos_ms)
    record_property(f"{nombre}_p95_ms", round(p95, 3))
    print(f"\n{nombre} ({len(tiempos_ms)}): p50 = {mediana:.3f} ms, p95 = {p95:.3f} ms")
    assert len(tiempos_ms) == MUESTRAS
    exigir_tope_ms(f"p95 de {nombre}", p95, tope_ms)


async def test_latencia_obtener_api_key_activa(
    medidas: Medidas, sesiones_dueno: Sesiones, record_property: Any
) -> None:
    app_id = await _preparar(sesiones_dueno)
    prefijos = [f"gk_{secrets.token_hex(6)}" for _ in range(MUESTRAS)]
    async with sesiones_dueno.begin() as sesion:
        for prefijo in prefijos:
            await crear_api_key(sesion, app_id, prefijo, secrets.token_hex(32))

    async def _operacion(i: int) -> None:
        async with medidas.sesiones() as sesion:
            assert await obtener_api_key_activa(sesion, prefijos[i]) is not None

    await _medir(f"obtener_api_key_activa [{medidas.rol}]", _operacion, record_property)
