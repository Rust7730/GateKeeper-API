"""Latencia de los repositorios del camino de un archivo (M1, M2; diseño §6).

Cada muestra es una operación completa como la hace la API: sesión nueva del pool,
consulta y, en las escrituras, ``COMMIT``. Antes se cargan filas para no medir tablas
vacías. El tope es holgado a propósito: detecta regresiones sin volverse inestable. El
número útil es el p95 que se imprime; se ve con ``pytest -s``.
"""

import hashlib
import secrets
import statistics
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import insert, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from api.app.estados import Estado
from api.db.modelos import Archivo, ResultadoAnalisis
from api.db.repositorios import (
    cambiar_estado,
    crear_api_key,
    crear_aplicacion,
    crear_archivo,
    obtener_api_key_activa,
    obtener_archivo,
)

pytestmark = pytest.mark.anyio

Sesiones = async_sessionmaker[AsyncSession]

MUESTRAS = 1000
FILAS_PREVIAS = 5000
TOPE_P95_MS = 20.0
SHA256 = hashlib.sha256(b"contenido").hexdigest()


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

    p95 = statistics.quantiles(tiempos_ms, n=100)[94]
    mediana = statistics.median(tiempos_ms)
    record_property(f"{nombre}_p95_ms", round(p95, 3))
    print(f"\n{nombre} ({MUESTRAS}): p50 = {mediana:.3f} ms, p95 = {p95:.3f} ms")
    assert p95 < TOPE_P95_MS, f"p95 de {nombre} = {p95:.2f} ms"


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


async def test_latencia_crear_archivo(sesiones: Sesiones, record_property: Any) -> None:
    app_id = await _preparar(sesiones)

    async def _operacion(_i: int) -> None:
        async with sesiones.begin() as sesion:
            await crear_archivo(
                sesion, app_id, uuid.uuid4(), "medida.pdf", 1024, SHA256
            )

    await _medir("crear_archivo", _operacion, record_property)


async def test_latencia_cambiar_estado(
    sesiones: Sesiones, record_property: Any
) -> None:
    app_id = await _preparar(sesiones)
    ids = await _crear_pendientes(sesiones, app_id, MUESTRAS)
    await _crear_resultados(sesiones, ids)
    await _analizar(sesiones)

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
    sesiones: Sesiones,
) -> None:
    # Misma forma que el UPDATE de cambiar_estado hacia limpio (K16).
    app_id = await _preparar(sesiones)
    ids = await _crear_pendientes(sesiones, app_id, MUESTRAS)
    await _crear_resultados(sesiones, ids)
    await _analizar(sesiones)

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
    sesiones: Sesiones, record_property: Any
) -> None:
    app_id = await _preparar(sesiones)
    ids = await _crear_pendientes(sesiones, app_id, MUESTRAS)

    async def _operacion(i: int) -> None:
        async with sesiones() as sesion:
            assert await obtener_archivo(sesion, app_id, ids[i]) is not None

    await _medir("obtener_archivo", _operacion, record_property)


async def test_latencia_obtener_api_key_activa(
    sesiones: Sesiones, record_property: Any
) -> None:
    app_id = await _preparar(sesiones)
    prefijos = [f"gk_{secrets.token_hex(6)}" for _ in range(MUESTRAS)]
    async with sesiones.begin() as sesion:
        for prefijo in prefijos:
            await crear_api_key(sesion, app_id, prefijo, secrets.token_hex(32))

    async def _operacion(i: int) -> None:
        async with sesiones() as sesion:
            assert await obtener_api_key_activa(sesion, prefijos[i]) is not None

    await _medir("obtener_api_key_activa", _operacion, record_property)
