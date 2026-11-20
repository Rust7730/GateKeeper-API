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
from worker.ajustes import AjustesWorker
from worker.principal import crear_worker


@contextmanager
def correr_pipeline(
    ajustes: Ajustes,
    *,
    url_redis_queue: str | None = None,
    poll_delay_s: float = 0.01,
) -> Iterator[None]:
    """Corre ``coordinator`` y ``worker`` mientras dure el bloque ``with``."""
    url_queue = url_redis_queue or ajustes.url_redis
    listo = threading.Event()
    detener = threading.Event()
    errores: list[BaseException] = []

    def _hilo() -> None:
        async def _ejecutar() -> None:
            coordinador = crear_coordinador(
                AjustesCoordinador(
                    url_bd=ajustes.url_bd,
                    url_redis=ajustes.url_redis,
                    url_redis_queue=url_queue,
                    datos=ajustes.datos,
                    timeout_worker_s=max(ajustes.timeout_cdr_s + 5.0, 5.0),
                    poll_delay_s=poll_delay_s,
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
                ),
                handle_signals=False,
                poll_delay_s=poll_delay_s,
            )
            tarea_coord = asyncio.create_task(coordinador.main())
            tarea_worker = asyncio.create_task(worker.main())
            # Un pequeño giro del bucle asegura que ambos workers empezaron a sondear Redis.
            await asyncio.sleep(0.05)
            for tarea in (tarea_coord, tarea_worker):
                if tarea.done() and not tarea.cancelled():
                    exc = tarea.exception()
                    if exc is not None:
                        raise exc
            listo.set()
            try:
                while not detener.is_set():
                    await asyncio.sleep(0.02)
            finally:
                for servicio in (coordinador, worker):
                    for job_task in list(servicio.tasks.values()):
                        job_task.cancel()
                for tarea in (tarea_coord, tarea_worker):
                    tarea.cancel()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(
                        asyncio.gather(
                            tarea_coord, tarea_worker, return_exceptions=True
                        ),
                        timeout=3.0,
                    )
                for servicio in (worker, coordinador):
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
