"""Latencia de ``autenticar`` con BD real y HMAC incluido.

Corre en cada petición de ``/v1``, antes de M1 y de cualquier lectura de estado. Cada muestra
es una llamada completa: sesión del pool, consulta, HMAC y comparación. Se mide cada camino
por separado, para ver también que un prefijo inexistente no se distingue del resto. El tope
es holgado a propósito (como en ``test_latencia_repositorios.py``); el número útil es el
p95 que se imprime con ``pytest -s``.
"""

import secrets
import statistics
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.requests import Request

from api.app.ajustes import Ajustes
from api.app.autenticacion import autenticar, calcular_hash, generar_key
from api.app.principal import crear_app
from api.db.repositorios import crear_api_key, crear_aplicacion

pytestmark = pytest.mark.anyio

Sesiones = async_sessionmaker[AsyncSession]

MUESTRAS = 1000
TOPE_P95_MS = 20.0
SECRETO_INCORRECTO = secrets.token_urlsafe(32)


@pytest.fixture
def pepper() -> bytes:
    return secrets.token_hex(32).encode()


@pytest.fixture
def app(bd_limpia: URL, pepper: bytes, tmp_path: Path, sesiones: Sesiones) -> Any:
    # Sin lifespan: usa la fábrica del fixture, sobre el mismo bucle de eventos que la prueba.
    ajustes = Ajustes(url_bd=bd_limpia, pepper=pepper, datos=tmp_path)
    aplicacion = crear_app(ajustes)
    aplicacion.state.ajustes = ajustes
    aplicacion.state.sesiones = sesiones
    return aplicacion


def _request(app: Any, key: str) -> Request:
    return Request(
        {
            "type": "http",
            "app": app,
            "headers": [(b"authorization", f"Bearer {key}".encode())],
        }
    )


async def _sembrar(sesiones: Sesiones, pepper: bytes) -> list[str]:
    keys = []
    async with sesiones.begin() as sesion:
        aplicacion_id = await crear_aplicacion(sesion, "medida")
        for _ in range(MUESTRAS):
            prefijo, key = generar_key()
            await crear_api_key(
                sesion, aplicacion_id, prefijo, calcular_hash(pepper, key)
            )
            keys.append(key)
    return keys


async def _medir(
    nombre: str, operacion: Callable[[int], Awaitable[object]], record_property: Any
) -> float:
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
    return p95


async def test_latencia_autenticar_key_valida(
    app: Any, sesiones: Sesiones, pepper: bytes, record_property: Any
) -> None:
    keys = await _sembrar(sesiones, pepper)

    async def _operacion(i: int) -> None:
        await autenticar(_request(app, keys[i]))

    await _medir("autenticar_valida", _operacion, record_property)


async def test_latencia_autenticar_secreto_incorrecto(
    app: Any, sesiones: Sesiones, pepper: bytes, record_property: Any
) -> None:
    keys = await _sembrar(sesiones, pepper)

    async def _operacion(i: int) -> None:
        with pytest.raises(HTTPException):
            prefijo = keys[i].split(".")[0]
            await autenticar(_request(app, f"{prefijo}.{SECRETO_INCORRECTO}"))

    await _medir("autenticar_secreto_incorrecto", _operacion, record_property)


async def test_latencia_autenticar_prefijo_inexistente(
    app: Any, sesiones: Sesiones, pepper: bytes, record_property: Any
) -> None:
    await _sembrar(sesiones, pepper)

    async def _operacion(_i: int) -> None:
        with pytest.raises(HTTPException):
            await autenticar(_request(app, generar_key()[1]))

    await _medir("autenticar_prefijo_inexistente", _operacion, record_property)


def test_latencia_hmac_solo() -> None:
    pepper = secrets.token_hex(32).encode()
    key = generar_key()[1]
    tiempos_us = []
    for _ in range(10_000):
        inicio = time.perf_counter()
        calcular_hash(pepper, key)
        tiempos_us.append((time.perf_counter() - inicio) * 1_000_000)
    p95 = statistics.quantiles(tiempos_us, n=100)[94]
    print(f"\ncalcular_hash (10000): p95 = {p95:.2f} us")
    assert p95 < 1000
