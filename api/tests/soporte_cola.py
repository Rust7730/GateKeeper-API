"""Pipeline ARQ real (coordinator + worker) en un hilo de fondo para las pruebas (K64).

Arranca ``coordinator`` (``gk:cola:orquestar``) y ``worker`` (``gk:cola:analizar``) sobre el
Redis desechable de la sesión con ``poll_delay=0.01`` s para que las pruebas usen exactamente
el mismo camino de colas que producción sin añadir espera artificial.
"""

import asyncio
import contextlib
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from api.app.ajustes import Ajustes
from api.app.coordinador import AjustesCoordinador, crear_coordinador
from reputation.ajustes import AjustesReputacion
from reputation.principal import crear_reputation
from worker.ajustes import AjustesWorker
from worker.principal import crear_worker


@contextmanager
def correr_pipeline(
    ajustes: Ajustes,
    *,
    url_redis_queue: str | None = None,
    poll_delay_s: float = 0.01,
) -> Iterator[None]:
    """Corre ``coordinator``, ``worker`` y (si hay VT configurado) ``reputation``."""
    url_queue = url_redis_queue or ajustes.url_redis
    listo = threading.Event()
    detener = threading.Event()
    errores: list[BaseException] = []

    def _hilo() -> None:
        async def _ejecutar() -> None:
            con_vt = ajustes.vt_base_url is not None
            coordinador = crear_coordinador(
                AjustesCoordinador(
                    url_bd=ajustes.url_bd,
                    url_redis=ajustes.url_redis,
                    url_redis_queue=url_queue,
                    datos=ajustes.datos,
                    timeout_worker_s=max(ajustes.timeout_cdr_s + 5.0, 5.0),
                    poll_delay_s=poll_delay_s,
                    consultar_reputacion=con_vt,
                ),
                handle_signals=False,
                barrer_al_arrancar=False,
            )
            worker = crear_worker(
                AjustesWorker(
                    url_redis_queue=url_queue,
                    datos=ajustes.datos,
                    comando_cdr=ajustes.comando_cdr,
                    timeout_cdr_s=ajustes.timeout_cdr_s,
                    clamav_host=ajustes.clamav_host,
                    clamav_puerto=ajustes.clamav_puerto,
                ),
                handle_signals=False,
                poll_delay_s=poll_delay_s,
            )
            servicios = [coordinador, worker]
            if con_vt:
                servicios.append(
                    crear_reputation(
                        AjustesReputacion(
                            url_redis=ajustes.url_redis,
                            vt_api_key=ajustes.vt_api_key,
                            vt_base_url=ajustes.vt_base_url or "",
                        ),
                        handle_signals=False,
                        poll_delay_s=poll_delay_s,
                    )
                )
            tareas = [asyncio.create_task(s.main()) for s in servicios]
            # Un pequeño giro del bucle asegura que todos los workers empezaron a sondear Redis.
            await asyncio.sleep(0.05)
            for tarea in tareas:
                if tarea.done() and not tarea.cancelled():
                    exc = tarea.exception()
                    if exc is not None:
                        raise exc
            listo.set()
            try:
                while not detener.is_set():
                    await asyncio.sleep(0.02)
            finally:
                for servicio in servicios:
                    for job_task in list(servicio.tasks.values()):
                        job_task.cancel()
                for tarea in tareas:
                    tarea.cancel()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(
                        asyncio.gather(*tareas, return_exceptions=True),
                        timeout=3.0,
                    )
                for servicio in reversed(servicios):
                    with contextlib.suppress(Exception):
                        await asyncio.wait_for(servicio.close(), timeout=2.0)

        try:
            asyncio.run(_ejecutar())
        except BaseException as error:  # noqa: BLE001
            errores.append(error)
            listo.set()

    hilo = threading.Thread(target=_hilo, name="gk-pipeline-test", daemon=True)
    hilo.start()
    listo.wait(timeout=10.0)
    try:
        yield
    finally:
        detener.set()
        hilo.join(timeout=10.0)
    if errores:
        raise errores[0]
