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
import stat
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
from worker.clamav import ResultadoClamav, escanear_clamav
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


_NO_EVALUADA = "no_evaluada"
_MALICIOSO = "malicioso"
_MODO_CUARENTENA = 0o640
_TOPE_COPIA_BYTES = 10 * 1024 * 1024  # 10 MiB (K41 / CWE-400)
_BLOQUE_COPIA = 65_536


def _copiar_a_cuarentena(origen: Path, destino: Path) -> None:
    """Copia el original regular a ``quarantine/<uuid>`` (0640, O_NOFOLLOW) sin borrar ``uploads_tmp``."""
    fd_in = os.open(origen, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd_in)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _TOPE_COPIA_BYTES:
            raise OSError("origen de cuarentena invalido")
        destino.parent.mkdir(mode=0o770, parents=True, exist_ok=True)
        fd_out = os.open(
            destino,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            _MODO_CUARENTENA,
        )
        try:
            os.fchmod(fd_out, _MODO_CUARENTENA)
            copiados = 0
            with os.fdopen(fd_out, "wb") as salida:
                while True:
                    trozo = os.read(fd_in, _BLOQUE_COPIA)
                    if not trozo:
                        break
                    copiados += len(trozo)
                    if copiados > _TOPE_COPIA_BYTES:
                        raise ValueError("archivo supera el tope de copia")
                    salida.write(trozo)
        except BaseException:
            _borrar(destino)
            raise
    finally:
        os.close(fd_in)


async def _escanear_clamav_si_activo(
    ajustes: AjustesWorker, entrada: Path
) -> ResultadoClamav:
    if ajustes.clamav_host is None:
        return ResultadoClamav(_NO_EVALUADA, None, "clamav_no_configurado", 0)
    return await escanear_clamav(entrada, ajustes.clamav_host, ajustes.clamav_puerto)


async def analizar(
    ctx: dict[str, Any], archivo_id: str, solo_cdr: bool = False
) -> dict[str, Any]:
    """Ejecuta ClamAV (D1, sobre el ORIGINAL) en paralelo con firma+CDR y devuelve JSON.

    Con ``solo_cdr=True`` (liberación de cuarentena, D4) omite ClamAV y corre solo firma+CDR.
    """
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
            "clamav": ResultadoClamav(
                _NO_EVALUADA, None, _MOTIVO_ID_INVALIDO, 0
            ).como_dict(),
        }

    ajustes: AjustesWorker = ctx["ajustes"]
    entrada = ajustes.uploads_tmp / str(identificador)
    trabajo = ajustes.clean_store / f"{identificador}{_SUFIJO_PARCIAL}"
    parcial = trabajo / str(identificador)
    final = ajustes.clean_store / str(identificador)
    cuarentena = ajustes.quarantine / str(identificador)

    publicado = False
    res_clamav = ResultadoClamav(_NO_EVALUADA, None, "no_ejecutada", 0)
    try:
        trabajo.mkdir(mode=_MODO_TRABAJO)
        if solo_cdr:
            res_clamav = ResultadoClamav(_NO_EVALUADA, None, "liberacion_cdr", 0)
            try:
                resultado_cdr: Any = await correr_hijo(
                    (*ajustes.comando_cdr, str(entrada), str(parcial)),
                    ajustes.timeout_cdr_s,
                )
            except Exception as exc:  # noqa: BLE001
                resultado_cdr = exc
        else:
            # D1: ClamAV sobre el ORIGINAL en paralelo con firma+CDR.
            res_clamav, resultado_cdr = await asyncio.gather(
                _escanear_clamav_si_activo(ajustes, entrada),
                correr_hijo(
                    (*ajustes.comando_cdr, str(entrada), str(parcial)),
                    ajustes.timeout_cdr_s,
                ),
                return_exceptions=True,
            )
        if isinstance(res_clamav, BaseException):
            if isinstance(res_clamav, asyncio.CancelledError):
                raise res_clamav
            res_clamav = ResultadoClamav(_ERROR, None, _MOTIVO_INTERNO, _duracion_ms())

        if res_clamav.veredicto == _MALICIOSO:
            # INV-07 / F4.09: original a cuarentena, nunca se publica salida en clean_store.
            _copiar_a_cuarentena(entrada, cuarentena)
            _borrar(final)

        if isinstance(resultado_cdr, BaseException):
            if isinstance(resultado_cdr, asyncio.CancelledError):
                raise resultado_cdr
            motivo_cdr = (
                resultado_cdr.motivo
                if isinstance(resultado_cdr, FalloDelHijo)
                else _MOTIVO_INTERNO
            )
            return {
                "veredicto": _ERROR,
                "tipo": "",
                "motivo": motivo_cdr,
                "duracion_ms": _duracion_ms(),
                "clamav": res_clamav.como_dict(),
            }

        duracion_ms = _duracion_ms()
        if resultado_cdr.veredicto == LIMPIO and res_clamav.veredicto not in (
            _MALICIOSO,
            _ERROR,
        ):
            try:
                publicar_salida(parcial, final)
                publicado = True
            except SalidaDemasiadoGrande:
                return {
                    "veredicto": RECHAZADO,
                    "tipo": resultado_cdr.tipo,
                    "motivo": _MOTIVO_SALIDA_GRANDE,
                    "duracion_ms": duracion_ms,
                    "clamav": res_clamav.como_dict(),
                }
        return {
            "veredicto": resultado_cdr.veredicto,
            "tipo": resultado_cdr.tipo,
            "motivo": resultado_cdr.motivo,
            "duracion_ms": duracion_ms,
            "clamav": res_clamav.como_dict(),
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
            "clamav": res_clamav.como_dict(),
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

    async def _correr() -> None:
        worker = crear_worker(ajustes, handle_signals=True)
        await worker.async_run()

    asyncio.run(_correr())
    return 0


if __name__ == "__main__":
    sys.exit(main())
