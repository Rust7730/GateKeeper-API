"""Colas ARQ sobre Redis con serialización JSON estricta (K02, K08, K36, K64).

Módulo sin dependencias de ``api.db`` ni de FastAPI para que ``worker/`` pueda importarlo sin
arrastrar nada de la base de datos (INV-04, F1.05).

- **Sin ``pickle`` (K36):** toda carga entre ``api``, ``coordinator`` y ``worker`` es JSON UTF-8.
  Un worker comprometido no puede inyectar objetos ejecutables al ``coordinator``.
- **Claves duplicadas y tamaño acotado:** se rechazan claves repetidas (evita interpretaciones
  divergentes) y mensajes de más de 64 KiB (CWE-770).
- **Sin fugas de credenciales (CWE-532):** un fallo al construir el pool nunca expone la URL, y
  una excepción devuelta en un resultado ARQ se serializa solo por su nombre de clase.
"""

import asyncio
import contextlib
import json
from typing import Any

from arq.connections import ArqRedis
from arq.utils import poll
from arq.worker import Worker
from redis.asyncio import BlockingConnectionPool
from redis.backoff import NoBackoff
from redis.retry import Retry

COLA_ORQUESTAR = "gk:cola:orquestar"
COLA_ANALIZAR = "gk:cola:analizar"
CANAL_EVENTOS = "gk:eventos:archivo"

POLL_DELAY_S = 0.05  # K08: polling de 50 ms en workers y en Job.result()
TIMEOUT_JOB_WORKER_S = 35  # K64: cubre los 30 s del CDR + margen de proceso hijo
TIMEOUT_JOB_COORDINATOR_S = 45  # K64: cubre worker + futura gracia de VT
MAX_REINTENTOS = 2  # K11: solo errores transitorios
TOPE_MENSAJE_COLA = 65_536  # 64 KiB por mensaje JSON en Redis
TIMEOUT_COLA_S = 1.0  # K61: una operación de cola no retiene más de 1 s
CONEXIONES_COLA = 16


class ErrorDeCola(RuntimeError):
    """Error de configuración o conexión de la cola ARQ, sin credenciales en el texto."""


def _rechazar_duplicadas(pares: list[tuple[str, Any]]) -> dict[str, Any]:
    datos = dict(pares)
    if len(datos) != len(pares):
        raise ValueError("clave repetida en el mensaje de la cola")
    return datos


def serializar_json(datos: dict[str, Any]) -> bytes:
    """Serializa un diccionario ARQ a JSON UTF-8 compacto, nunca ``pickle`` (K36)."""
    if type(datos) is not dict:
        raise ValueError("el mensaje de la cola debe ser un diccionario")
    preparado = datos
    # Si un job falló con una excepción, ARQ la pone en `r`: guardamos solo el nombre de clase
    # para que sea JSON válido y nunca filtre trazas ni secretos (CWE-532).
    if datos.get("s") is False and isinstance(datos.get("r"), BaseException):
        preparado = {**datos, "r": type(datos["r"]).__name__}
    return json.dumps(
        preparado, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def deserializar_json(brutos: bytes) -> dict[str, Any]:
    """Deserializa un mensaje JSON UTF-8 de la cola ARQ, con tope de tamaño y sin duplicados."""
    if not isinstance(brutos, (bytes, bytearray)) or len(brutos) > TOPE_MENSAJE_COLA:
        raise ValueError("mensaje de cola inválido o demasiado grande")
    try:
        texto = brutos.decode("utf-8")
        datos = json.loads(texto, object_pairs_hook=_rechazar_duplicadas)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ValueError("mensaje de cola no es JSON UTF-8 válido") from error
    if type(datos) is not dict:
        raise ValueError("el mensaje de la cola debe ser un objeto JSON")
    return datos


def abrir_cola(
    url: str,
    *,
    cola: str,
    nombre_variable: str,
    max_conexiones: int = CONEXIONES_COLA,
    timeout_s: float = TIMEOUT_COLA_S,
) -> ArqRedis:
    """Crea un cliente ``ArqRedis`` sin conectar todavía, usando JSON y sin ``CLIENT SETINFO``."""
    pool = None
    # Amplio a propósito: cualquier error al analizar la URL podría incluir la contraseña.
    with contextlib.suppress(Exception):
        pool = BlockingConnectionPool.from_url(
            url,
            max_connections=max_conexiones,
            timeout=timeout_s,
            socket_timeout=timeout_s,
            socket_connect_timeout=timeout_s,
            retry=Retry(NoBackoff(), 0),
            protocol=2,
            driver_info=None,
            health_check_interval=0,
        )
    if pool is None:
        raise ErrorDeCola(
            f"La URL de Redis ({nombre_variable}) no es válida "
            "(el valor no se muestra porque puede contener credenciales)."
        )
    return ArqRedis(
        pool_or_conn=pool,
        job_serializer=serializar_json,
        job_deserializer=deserializar_json,
        default_queue_name=cola,
    )


async def cerrar_cola(cola: ArqRedis) -> None:
    """Cierra el cliente ARQ y su pool de conexiones."""
    await cola.aclose()
    await cola.connection_pool.aclose()


class WorkerSinInfo(Worker):
    """Subclase de ``arq.Worker`` que no ejecuta ``INFO`` ni ``DBSIZE`` al arrancar.

    La ACL de Redis niega ``@dangerous`` (incluye ``INFO``) en ``redis-main`` y ``redis-queue``
    (K59, K62). Además usa ``aclose()`` al cerrar para evitar la deprecación de ``redis-py`` 8.
    """

    async def main(self) -> None:
        self.ctx["redis"] = self.pool
        if self.on_startup:
            await self.on_startup(self.ctx)
        async for _ in poll(self.poll_delay_s):
            await self._poll_iteration()

    async def close(self) -> None:
        if not self._pool:
            return
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)
        await self.pool.delete(self.health_check_key)
        if self.on_shutdown:
            await self.on_shutdown(self.ctx)
        await cerrar_cola(self.pool)
        self._pool = None
