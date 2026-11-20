"""Worker ARQ del servicio ``reputation`` sobre ``redis-main`` (INV-05, F4.03–F4.08, K08)."""

import asyncio
import ctypes
import os
import sys
from typing import Any

import httpx
from arq.worker import func

from api.app.cola import (
    COLA_REPUTACION,
    POLL_DELAY_S,
    TIMEOUT_JOB_REPUTATION_S,
    WorkerSinInfo,
    abrir_cola,
    deserializar_json,
    serializar_json,
)
from reputation.ajustes import (
    VARIABLE_REDIS,
    AjustesReputacion,
    leer_ajustes_reputacion,
)
from reputation.cliente import consultar_virustotal

_PR_SET_DUMPABLE = 4


def _proteger_proceso() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        numero = ctypes.get_errno()
        raise OSError(numero, os.strerror(numero))


async def consultar_hash(ctx: dict[str, Any], sha256: str) -> dict[str, Any]:
    """Job ARQ: consulta un hash SHA-256 en VirusTotal con caché y cuota en Redis."""
    return await consultar_virustotal(sha256, ctx["ajustes"], ctx["redis"], ctx["http"])


def crear_reputation(
    ajustes: AjustesReputacion,
    *,
    handle_signals: bool = True,
    poll_delay_s: float = POLL_DELAY_S,
) -> WorkerSinInfo:
    cola = abrir_cola(
        ajustes.url_redis,
        cola=COLA_REPUTACION,
        nombre_variable=VARIABLE_REDIS,
        max_conexiones=16,
    )
    cliente_http = httpx.AsyncClient()

    async def al_apagar(_ctx: dict[str, Any]) -> None:
        await cliente_http.aclose()

    return WorkerSinInfo(
        functions=[func(consultar_hash, name="consultar_hash")],
        queue_name=COLA_REPUTACION,
        redis_pool=cola,
        on_shutdown=al_apagar,
        handle_signals=handle_signals,
        max_jobs=4,
        job_timeout=TIMEOUT_JOB_REPUTATION_S,
        keep_result=60,
        poll_delay=poll_delay_s,
        health_check_key="gk:salud:reputation",
        max_tries=1,
        retry_jobs=False,
        job_serializer=serializar_json,
        job_deserializer=deserializar_json,
        ctx={"ajustes": ajustes, "http": cliente_http},
        log_results=False,
    )


def main() -> int:
    _proteger_proceso()
    ajustes = leer_ajustes_reputacion()

    async def _correr() -> None:
        servicio = crear_reputation(ajustes, handle_signals=True)
        await servicio.async_run()

    asyncio.run(_correr())
    return 0


if __name__ == "__main__":
    sys.exit(main())
