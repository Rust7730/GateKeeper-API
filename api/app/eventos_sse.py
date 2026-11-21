"""Hub centralizado de eventos SSE sobre Redis pub/sub dedicado (H-07, F5.11, K20).

Mantiene **una sola** suscripción a ``CANAL_EVENTOS`` en una conexión Redis independiente del
pool compartido ``cola_orquestar``, evitando que clientes SSE bloqueen ``POST /v1/files`` o
``/v1/auth/*``. Hace fan-out en memoria a colas acotadas por cliente y aplica lista blanca K20.
"""

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator
from typing import Any

import redis.asyncio as redis_async

from api.app.cola import CANAL_EVENTOS

logger = logging.getLogger("gatekeeper.sse")

MAX_CLIENTES_SSE = 64
TAMANO_COLA_CLIENTE = 64
_TIPOS_CON_NOMBRE_K20 = frozenset({"malware_detectado", "archivo_liberado"})
_CLAVES_EVENTO_BASE = (
    "id",
    "severidad",
    "tipo",
    "archivo_id",
    "aplicacion_nombre",
    "en",
)


class LimiteClientesSSE(Exception):
    """Se alcanzó el límite máximo de clientes SSE simultáneos."""


def _sanear_evento_k20(bruto: str) -> str | None:
    """Aplica lista blanca de campos ``EventoDto`` y privacidad K20 antes de enviar al cliente."""
    try:
        datos = json.loads(bruto)
    except json.JSONDecodeError:
        return None
    if not isinstance(datos, dict) or not isinstance(datos.get("tipo"), str):
        return None
    limpio: dict[str, Any] = {k: datos.get(k) for k in _CLAVES_EVENTO_BASE}
    if datos["tipo"] in _TIPOS_CON_NOMBRE_K20 and isinstance(
        datos.get("nombre_archivo"), str
    ):
        limpio["nombre_archivo"] = datos["nombre_archivo"]
    return json.dumps(limpio)


class HubEventosSSE:
    """Distribuidor 1-a-N de eventos SSE con una única conexión Redis dedicada."""

    def __init__(
        self,
        url_redis: str,
        *,
        max_clientes: int = MAX_CLIENTES_SSE,
        tamano_cola: int = TAMANO_COLA_CLIENTE,
    ) -> None:
        self._url_redis = url_redis
        self._max_clientes = max_clientes
        self._tamano_cola = tamano_cola
        self._clientes: set[asyncio.Queue[str]] = set()
        self._tarea: asyncio.Task[None] | None = None
        self._redis: Any = None
        self._lock = asyncio.Lock()

    async def _escuchar(self) -> None:
        cliente = redis_async.from_url(self._url_redis, max_connections=2)
        self._redis = cliente
        pubsub = cliente.pubsub()
        try:
            await pubsub.subscribe(CANAL_EVENTOS)
            while self._clientes:
                mensaje = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0
                )
                if mensaje is None:
                    continue
                datos = mensaje.get("data")
                if isinstance(datos, bytes):
                    datos = datos.decode("utf-8", errors="replace")
                if not isinstance(datos, str):
                    continue
                serializado = _sanear_evento_k20(datos)
                if serializado is None:
                    continue
                for cola in list(self._clientes):
                    if cola.full():
                        with contextlib.suppress(asyncio.QueueEmpty):
                            cola.get_nowait()
                    with contextlib.suppress(asyncio.QueueFull):
                        cola.put_nowait(serializado)
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001
            logger.warning("Suscriptor SSE interrumpido (%s)", type(error).__name__)
        finally:
            with contextlib.suppress(Exception):
                await pubsub.unsubscribe(CANAL_EVENTOS)
                await pubsub.aclose()
            with contextlib.suppress(Exception):
                await cliente.aclose()
            self._redis = None

    @contextlib.asynccontextmanager
    async def suscribir(self) -> AsyncIterator[asyncio.Queue[str]]:
        cola: asyncio.Queue[str] = asyncio.Queue(maxsize=self._tamano_cola)
        async with self._lock:
            if len(self._clientes) >= self._max_clientes:
                raise LimiteClientesSSE
            self._clientes.add(cola)
            if self._tarea is None or self._tarea.done():
                self._tarea = asyncio.create_task(self._escuchar())
        try:
            yield cola
        finally:
            async with self._lock:
                self._clientes.discard(cola)
                if not self._clientes and self._tarea is not None:
                    self._tarea.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await self._tarea
                    self._tarea = None

    async def cerrar(self) -> None:
        async with self._lock:
            self._clientes.clear()
            if self._tarea is not None:
                self._tarea.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._tarea
                self._tarea = None
