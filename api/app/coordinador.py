"""Servicio ``coordinator``: orquesta el análisis y consolida el veredicto (K01, K08, F1.05).

Corre en la red interna ``backend`` (sin contacto con archivos hostiles, sin salida a internet):
1. Consume ``orquestar(aplicacion_id, archivo_id)`` desde ``redis-main``.
2. Encola ``analizar(archivo_id)`` en ``redis-queue`` hacia ``worker`` y espera el resultado
   con ``poll_delay=0.05`` (K08).
3. Valida estrictamente la respuesta del ``worker`` (desconfiando de un worker comprometido, K02)
   y verifica en disco ``clean_store/<uuid>`` (``lstat``, archivo regular, ``<= 32 MiB`` K46).
4. Escribe los resultados y la transición en PostgreSQL como ``gk_app`` (K16, INV-09).
5. Borra ``uploads_tmp/<uuid>`` (F3.09) y publica el cambio de estado en ``redis-main``.
"""

import asyncio
import contextlib
import json
import logging
import math
import os
import stat
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from arq.jobs import Job
from arq.worker import func
from sqlalchemy.engine import URL

from api.app import analisis
from api.app.ajustes import (
    CLEAN_STORE,
    UPLOADS_TMP,
    VARIABLE_DATOS,
    VARIABLE_REDIS,
    ConfiguracionError,
    abrir_motor,
)
from api.app.analisis import _ERROR, _MOTIVO_INTERNO
from api.app.arranque import barrer_restos, comprobar_ancestros, proteger_proceso
from api.app.cdr_salida import TOPE_SALIDA
from api.app.cola import (
    CANAL_EVENTOS,
    COLA_ANALIZAR,
    COLA_ORQUESTAR,
    POLL_DELAY_S,
    TIMEOUT_JOB_COORDINATOR_S,
    TIMEOUT_JOB_WORKER_S,
    WorkerSinInfo,
    abrir_cola,
    cerrar_cola,
    deserializar_json,
    serializar_json,
)
from api.app.estados import Estado
from api.app.tipos import TIPOS_PERMITIDOS
from api.db.config import url_bd
from api.db.sesion import fabrica_sesiones
from worker.ajustes import VARIABLE_REDIS_QUEUE
from worker.ejecutor import LIMPIO, RECHAZADO, Veredicto

logger = logging.getLogger("gatekeeper.coordinator")

_CLAVES_RESULTADO_WORKER = {"veredicto", "tipo", "motivo", "duracion_ms"}
_VEREDICTOS_WORKER = {LIMPIO, RECHAZADO, _ERROR}
_MOTIVO_TIMEOUT_WORKER = "timeout_worker"
_MOTIVO_RESPUESTA_INVALIDA = "respuesta_worker_invalida"
_MOTIVO_SIN_SALIDA = "sin_salida"
_MOTIVO_SALIDA_GRANDE = "salida_grande"


@dataclass(frozen=True, slots=True)
class AjustesCoordinador:
    """Ajustes del servicio ``coordinator``. Secretos fuera del ``repr`` (CWE-532)."""

    url_bd: str | URL = field(repr=False)
    url_redis: str = field(repr=False)
    url_redis_queue: str = field(repr=False)
    datos: Path
    timeout_worker_s: float = float(TIMEOUT_JOB_WORKER_S)
    poll_delay_s: float = POLL_DELAY_S
    max_jobs: int = field(default_factory=lambda: max(4, (os.cpu_count() or 1) * 2))

    def __post_init__(self) -> None:
        if not self.url_bd:
            raise ConfiguracionError("Falta la URL de la base de datos.")
        for nombre, valor in (
            (VARIABLE_REDIS, self.url_redis),
            (VARIABLE_REDIS_QUEUE, self.url_redis_queue),
        ):
            if type(valor) is not str or not valor.strip() or valor != valor.strip():
                raise ConfiguracionError(
                    f"La URL de Redis ({nombre}) falta o es inválida "
                    "(el valor no se muestra)."
                )
        if not isinstance(self.datos, Path) or not self.datos.is_absolute():
            raise ConfiguracionError(
                f"El directorio ({VARIABLE_DATOS}) debe ser una ruta absoluta "
                "(la ruta no se muestra)."
            )
        if (
            type(self.timeout_worker_s) not in (int, float)
            or not math.isfinite(self.timeout_worker_s)
            or self.timeout_worker_s <= 0
        ):
            raise ConfiguracionError("timeout_worker_s debe ser un número positivo.")

    @property
    def uploads_tmp(self) -> Path:
        return self.datos / UPLOADS_TMP

    @property
    def clean_store(self) -> Path:
        return self.datos / CLEAN_STORE


def leer_ajustes_coordinador() -> AjustesCoordinador:
    """Lee la configuración del ``coordinator`` desde el entorno."""
    url_redis = os.environ.get(VARIABLE_REDIS)
    url_queue = os.environ.get(VARIABLE_REDIS_QUEUE)
    datos = os.environ.get(VARIABLE_DATOS)
    for nombre, valor in (
        (VARIABLE_REDIS, url_redis),
        (VARIABLE_REDIS_QUEUE, url_queue),
        (VARIABLE_DATOS, datos),
    ):
        if valor is None or not valor.strip():
            raise ConfiguracionError(
                f"Falta la variable de entorno {nombre} o está vacía; "
                "no hay valor por defecto."
            )
    assert url_redis is not None and url_queue is not None and datos is not None
    if datos != datos.strip():
        raise ConfiguracionError(
            f"La variable de entorno {VARIABLE_DATOS} tiene espacios en los bordes."
        )
    return AjustesCoordinador(
        url_bd=url_bd(),
        url_redis=url_redis,
        url_redis_queue=url_queue,
        datos=Path(datos),
    )


def validar_resultado_worker(
    bruto: Any,
) -> tuple[str, Veredicto | None, int, str]:
    """Valida el dict devuelto por el worker, sin confiar en él (K02, INV-09).

    Devuelve ``(estado_str, Veredicto | None, duracion_ms, motivo_error)``.
    """
    if type(bruto) is not dict or set(bruto) != _CLAVES_RESULTADO_WORKER:
        return _ERROR, None, 0, _MOTIVO_RESPUESTA_INVALIDA
    veredicto = bruto["veredicto"]
    tipo = bruto["tipo"]
    motivo = bruto["motivo"]
    duracion_ms = bruto["duracion_ms"]
    if (
        type(veredicto) is not str
        or type(tipo) is not str
        or type(motivo) is not str
        or type(duracion_ms) is not int
        or duracion_ms < 0
    ):
        return _ERROR, None, 0, _MOTIVO_RESPUESTA_INVALIDA
    if veredicto not in _VEREDICTOS_WORKER:
        return _ERROR, None, duracion_ms, _MOTIVO_RESPUESTA_INVALIDA
    if veredicto == _ERROR:
        return _ERROR, None, duracion_ms, motivo or _MOTIVO_INTERNO
    if veredicto == LIMPIO and tipo not in TIPOS_PERMITIDOS:
        return _ERROR, None, duracion_ms, _MOTIVO_RESPUESTA_INVALIDA
    return (
        veredicto,
        Veredicto(veredicto=veredicto, tipo=tipo, motivo=motivo),
        duracion_ms,
        "",
    )


def _verificar_salida_limpia(final: Path) -> str | None:
    """Comprueba en disco que ``clean_store/<uuid>`` es un archivo regular y cabe en K46.

    Devuelve ``None`` si es válida, o el motivo de fallo/rechazo.
    """
    info = None
    with contextlib.suppress(FileNotFoundError):
        info = os.lstat(final)
    if info is None or not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        return _MOTIVO_SIN_SALIDA
    if info.st_size > TOPE_SALIDA:
        return _MOTIVO_SALIDA_GRANDE
    return None


def _borrar(ruta: Path) -> None:
    try:
        ruta.unlink(missing_ok=True)
    except OSError as error:
        logger.error("No se pudo borrar temporal (%s)", type(error).__name__)


async def _publicar_evento(cola_main: Any, archivo_id: uuid.UUID, estado: str) -> None:
    """Notifica el cambio de estado por pub/sub de ``redis-main`` (best-effort)."""
    try:
        async with asyncio.timeout(1.0):
            await cola_main.publish(
                CANAL_EVENTOS,
                json.dumps({"archivo_id": str(archivo_id), "estado": estado}),
            )
    except Exception as error:  # noqa: BLE001
        logger.warning(
            "No se pudo publicar evento de %s (%s)", archivo_id, type(error).__name__
        )


async def _esperar_resultado(
    trabajo: Job, timeout_s: float, poll_delay_s: float
) -> Any:
    """Espera el resultado del worker sin la carrera de ``Job.result()`` en ARQ 0.25.

    En ARQ 0.25 ``Job.result()`` lee ``result`` y ``zscore`` en dos llamadas separadas: si el
    worker termina justo entre ambas, lanza ``ResultNotFound`` aunque el resultado ya exista.
    """
    limite = time.monotonic() + timeout_s
    while True:
        info = await trabajo.result_info()
        if info is not None:
            if info.success:
                return info.result
            raise RuntimeError(str(info.result))
        if time.monotonic() >= limite:
            raise TimeoutError
        await asyncio.sleep(poll_delay_s)


async def orquestar(
    ctx: dict[str, Any], aplicacion_id_str: str, archivo_id_str: str
) -> str:
    """Orquesta el análisis de un archivo y registra el veredicto en PostgreSQL (K01, K08)."""
    ajustes: AjustesCoordinador = ctx["ajustes"]
    sesiones = ctx["sesiones"]
    cola_queue = ctx["cola_queue"]
    cola_main = ctx["cola_main"]

    aplicacion_id = uuid.UUID(aplicacion_id_str)
    archivo_id = uuid.UUID(archivo_id_str)
    entrada = ajustes.uploads_tmp / str(archivo_id)
    final = ajustes.clean_store / str(archivo_id)
    inicio = time.perf_counter()

    def _duracion_ms() -> int:
        return round((time.perf_counter() - inicio) * 1000)

    confirmado = False
    estado_final = Estado.ERROR.value
    try:
        trabajo = await cola_queue.enqueue_job(
            "analizar",
            str(archivo_id),
            _job_id=f"analizar:{archivo_id}",
            _queue_name=COLA_ANALIZAR,
        )
        if trabajo is None:
            raise RuntimeError("job duplicado en redis-queue")
        try:
            bruto = await _esperar_resultado(
                trabajo,
                ajustes.timeout_worker_s,
                ajustes.poll_delay_s,
            )
        except TimeoutError:
            _borrar(final)
            await analisis._registrar_error(
                sesiones,
                aplicacion_id,
                archivo_id,
                _MOTIVO_TIMEOUT_WORKER,
                _duracion_ms(),
            )
            return Estado.ERROR.value

        categoria, veredicto, duracion_ms, motivo_error = validar_resultado_worker(
            bruto
        )
        if categoria == _ERROR or veredicto is None:
            _borrar(final)
            await analisis._registrar_error(
                sesiones,
                aplicacion_id,
                archivo_id,
                motivo_error or _MOTIVO_INTERNO,
                duracion_ms or _duracion_ms(),
            )
            return Estado.ERROR.value

        if veredicto.veredicto == LIMPIO:
            problema = _verificar_salida_limpia(final)
            if problema == _MOTIVO_SALIDA_GRANDE:
                _borrar(final)
                veredicto = Veredicto(RECHAZADO, veredicto.tipo, _MOTIVO_SALIDA_GRANDE)
            elif problema is not None:
                _borrar(final)
                await analisis._registrar_error(
                    sesiones, aplicacion_id, archivo_id, problema, duracion_ms
                )
                return Estado.ERROR.value

        await analisis._registrar_veredicto(
            sesiones, aplicacion_id, archivo_id, veredicto, duracion_ms
        )
        confirmado = True
        estado_final = (
            Estado.LIMPIO.value
            if veredicto.veredicto == LIMPIO
            else Estado.RECHAZADO.value
        )
        return estado_final
    except Exception as error:  # noqa: BLE001
        logger.warning(
            "Orquestación de %s terminó en error (%s)",
            archivo_id,
            type(error).__name__,
        )
        _borrar(final)
        await analisis._registrar_error(
            sesiones, aplicacion_id, archivo_id, _MOTIVO_INTERNO, _duracion_ms()
        )
        return Estado.ERROR.value
    finally:
        if not confirmado:
            _borrar(final)
        _borrar(entrada)
        await _publicar_evento(cola_main, archivo_id, estado_final)


def crear_coordinador(
    ajustes: AjustesCoordinador,
    *,
    handle_signals: bool = True,
    barrer_al_arrancar: bool = True,
) -> WorkerSinInfo:
    """Construye el ``Worker`` de ARQ del ``coordinator`` sobre ``redis-main``."""
    cola_main = abrir_cola(
        ajustes.url_redis,
        cola=COLA_ORQUESTAR,
        nombre_variable=VARIABLE_REDIS,
        max_conexiones=max(16, ajustes.max_jobs * 2),
    )
    cola_queue = abrir_cola(
        ajustes.url_redis_queue,
        cola=COLA_ANALIZAR,
        nombre_variable=VARIABLE_REDIS_QUEUE,
        max_conexiones=max(16, ajustes.max_jobs * 2),
    )
    motor = abrir_motor(ajustes.url_bd)
    sesiones = fabrica_sesiones(motor)

    async def al_arrancar(_ctx: dict[str, Any]) -> None:
        if barrer_al_arrancar:
            await barrer_restos(ajustes, sesiones)

    async def al_apagar(_ctx: dict[str, Any]) -> None:
        await motor.dispose()
        await cerrar_cola(cola_queue)

    return WorkerSinInfo(
        functions=[func(orquestar, name="orquestar")],
        queue_name=COLA_ORQUESTAR,
        redis_pool=cola_main,
        on_startup=al_arrancar,
        on_shutdown=al_apagar,
        handle_signals=handle_signals,
        max_jobs=ajustes.max_jobs,
        job_timeout=TIMEOUT_JOB_COORDINATOR_S,
        keep_result=60,
        poll_delay=ajustes.poll_delay_s,
        health_check_key="gk:salud:coordinator",
        max_tries=1,
        retry_jobs=False,
        job_serializer=serializar_json,
        job_deserializer=deserializar_json,
        ctx={
            "ajustes": ajustes,
            "sesiones": sesiones,
            "cola_main": cola_main,
            "cola_queue": cola_queue,
        },
        log_results=False,
    )


def main() -> int:
    proteger_proceso()
    comprobar_ancestros()
    ajustes = leer_ajustes_coordinador()
    coordinador = crear_coordinador(ajustes, handle_signals=True)
    asyncio.run(coordinador.async_run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
