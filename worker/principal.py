"""Worker ARQ aislado: consume ``analizar`` desde ``redis-queue`` (INV-04, F1.05, K09, K64).

- Lee el original desde ``uploads_tmp/<uuid>`` (montado en solo lectura en el contenedor).
- Ejecuta el CDR en un proceso hijo endurecido (``RLIMIT_AS``, ``RLIMIT_CPU``, Landlock, seccomp).
- Si resulta ``limpio``, publica la versión reconstruida en ``clean_store/<uuid>`` (modo ``0640``)
  y devuelve el veredicto por la cola ARQ en JSON (K36).
- Nunca toca PostgreSQL ni ``redis-main``, ni borra ``uploads_tmp`` (eso lo hace ``coordinator``).
"""

import asyncio
import ctypes
import logging
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from arq.worker import func

from api.app.cdr_salida import SalidaDemasiadoGrande
from api.app.cola import (
    COLA_ANALIZAR,
    POLL_DELAY_S,
    TIMEOUT_JOB_WORKER_S,
    WorkerSinInfo,
    abrir_cola,
    deserializar_json,
    serializar_json,
)
from worker.ajustes import VARIABLE_REDIS_QUEUE, AjustesWorker, leer_ajustes_worker
from worker.ejecutor import (
    LIMPIO,
    RECHAZADO,
    FalloDelHijo,
    correr_hijo,
    publicar_salida,
)

logger = logging.getLogger("gatekeeper.worker")

_SUFIJO_PARCIAL = ".parcial"
_MODO_TRABAJO = 0o700
_ERROR = "error"
_MOTIVO_INTERNO = "interno"
_MOTIVO_SALIDA_GRANDE = "salida_grande"
_MOTIVO_ID_INVALIDO = "id_invalido"
_PR_SET_DUMPABLE = 4


def _id_canonico(valor: object) -> uuid.UUID | None:
    if type(valor) is not str:
        return None
    try:
        identificador = uuid.UUID(valor)
    except ValueError:
        return None
    return identificador if str(identificador) == valor else None


def _borrar(ruta: Path) -> None:
    try:
        ruta.unlink(missing_ok=True)
    except OSError as error:
        logger.error("No se pudo borrar salida temporal (%s)", type(error).__name__)


def _borrar_trabajo(trabajo: Path) -> None:
    try:
        shutil.rmtree(trabajo)
    except FileNotFoundError:
        pass
    except OSError as error:
        logger.error("No se pudo borrar directorio parcial (%s)", type(error).__name__)


def _proteger_proceso() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        numero = ctypes.get_errno()
        raise OSError(numero, os.strerror(numero))


async def analizar(ctx: dict[str, Any], archivo_id: str) -> dict[str, Any]:
    """Ejecuta el CDR sobre ``uploads_tmp/<archivo_id>`` y devuelve el veredicto en JSON."""
    inicio = time.perf_counter()

    def _duracion_ms() -> int:
        return round((time.perf_counter() - inicio) * 1000)

    identificador = _id_canonico(archivo_id)
    if identificador is None:
        return {
            "veredicto": _ERROR,
            "tipo": "",
            "motivo": _MOTIVO_ID_INVALIDO,
            "duracion_ms": _duracion_ms(),
        }

    ajustes: AjustesWorker = ctx["ajustes"]
    entrada = ajustes.uploads_tmp / str(identificador)
    trabajo = ajustes.clean_store / f"{identificador}{_SUFIJO_PARCIAL}"
    parcial = trabajo / str(identificador)
    final = ajustes.clean_store / str(identificador)

    publicado = False
    try:
        trabajo.mkdir(mode=_MODO_TRABAJO)
        resultado = await correr_hijo(
            (*ajustes.comando_cdr, str(entrada), str(parcial)),
            ajustes.timeout_cdr_s,
        )
        duracion_ms = _duracion_ms()
        if resultado.veredicto == LIMPIO:
            try:
                publicar_salida(parcial, final)
                publicado = True
            except SalidaDemasiadoGrande:
                return {
                    "veredicto": RECHAZADO,
                    "tipo": resultado.tipo,
                    "motivo": _MOTIVO_SALIDA_GRANDE,
                    "duracion_ms": duracion_ms,
                }
        return {
            "veredicto": resultado.veredicto,
            "tipo": resultado.tipo,
            "motivo": resultado.motivo,
            "duracion_ms": duracion_ms,
        }
    except Exception as error:  # noqa: BLE001
        motivo = error.motivo if isinstance(error, FalloDelHijo) else _MOTIVO_INTERNO
        logger.warning(
            "El análisis en worker de %s terminó en error: %s (%s)",
            identificador,
            motivo,
            type(error).__name__,
        )
        _borrar(final)
        return {
            "veredicto": _ERROR,
            "tipo": "",
            "motivo": motivo,
            "duracion_ms": _duracion_ms(),
        }
    finally:
        if not publicado:
            _borrar(final)
        _borrar_trabajo(trabajo)


def crear_worker(
    ajustes: AjustesWorker,
    *,
    handle_signals: bool = True,
    poll_delay_s: float = POLL_DELAY_S,
) -> WorkerSinInfo:
    """Construye el ``Worker`` de ARQ sobre ``redis-queue`` (K02, K08, K09, K36, K64)."""
    cola = abrir_cola(
        ajustes.url_redis_queue,
        cola=COLA_ANALIZAR,
        nombre_variable=VARIABLE_REDIS_QUEUE,
        max_conexiones=max(16, ajustes.max_jobs * 2),
    )

    return WorkerSinInfo(
        functions=[func(analizar, name="analizar")],
        queue_name=COLA_ANALIZAR,
        redis_pool=cola,
        handle_signals=handle_signals,
        max_jobs=ajustes.max_jobs,
        job_timeout=TIMEOUT_JOB_WORKER_S,
        keep_result=300,
        poll_delay=poll_delay_s,
        health_check_key="gk:salud:worker",
        # K11: el worker no reintenta a ciegas (un timeout por bomba es error final); los
        # reintentos transitorios los controla el coordinator.
        max_tries=1,
        retry_jobs=False,
        job_serializer=serializar_json,
        job_deserializer=deserializar_json,
        ctx={"ajustes": ajustes},
        log_results=False,
    )


def main() -> int:
    _proteger_proceso()
    ajustes = leer_ajustes_worker()
    worker = crear_worker(ajustes, handle_signals=True)
    asyncio.run(worker.async_run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
