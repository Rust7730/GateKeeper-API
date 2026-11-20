"""Pruebas unitarias de ``api/app/cola.py``, ``worker/`` y ``api/app/coordinador.py``."""

import asyncio
import secrets
import uuid
from pathlib import Path
from typing import Any

import pytest

from api.app.cola import (
    ErrorDeCola,
    abrir_cola,
    deserializar_json,
    serializar_json,
)
from api.app.coordinador import validar_resultado_worker
from worker.ajustes import (
    VARIABLE_DATOS,
    VARIABLE_REDIS_QUEUE,
    AjustesWorker,
    ConfiguracionWorkerError,
    leer_ajustes_worker,
)


def test_serializar_excepcion_no_filtra_mensaje_ni_secretos() -> None:
    secreto = secrets.token_hex(16)
    brutos = serializar_json({"s": False, "r": RuntimeError(f"boom {secreto}")})
    assert secreto.encode() not in brutos
    assert deserializar_json(brutos) == {"s": False, "r": "RuntimeError"}


def test_abrir_cola_con_url_invalida_no_muestra_contrasena() -> None:
    clave = secrets.token_hex(12)
    with pytest.raises(ErrorDeCola) as error:
        abrir_cola(
            f"http://user:{clave}@127.0.0.1:1/0",
            cola="gk:cola:test",
            nombre_variable="GATEKEEPER_REDIS_QUEUE_URL",
        )
    assert clave not in str(error.value)
    assert error.value.__cause__ is None


def test_ajustes_worker_oculta_url_y_exige_ruta_absoluta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clave = secrets.token_hex(12)
    url = f"redis://worker:{clave}@127.0.0.1:6379/0"
    ajustes = AjustesWorker(url_redis_queue=url, datos=tmp_path)
    assert clave not in repr(ajustes)
    assert clave not in str(ajustes)

    monkeypatch.setenv(VARIABLE_REDIS_QUEUE, url)
    monkeypatch.setenv(VARIABLE_DATOS, "relativa")
    with pytest.raises(ConfiguracionWorkerError):
        leer_ajustes_worker()


@pytest.mark.parametrize(
    "bruto",
    [
        None,
        "limpio",
        {
            "veredicto": "limpio",
            "tipo": "image/png",
            "motivo": "ok",
        },  # falta duracion_ms
        {
            "veredicto": "limpio",
            "tipo": "image/svg+xml",  # tipo fuera de lista blanca
            "motivo": "ok",
            "duracion_ms": 5,
        },
        {
            "veredicto": "limpio",
            "tipo": "image/png",
            "motivo": "ok",
            "duracion_ms": -1,
        },
        {
            "veredicto": "otro",
            "tipo": "image/png",
            "motivo": "ok",
            "duracion_ms": 5,
        },
    ],
)
def test_validar_resultado_worker_falla_cerrado_ante_carga_invalida(bruto: Any) -> None:
    categoria, veredicto, _, motivo = validar_resultado_worker(bruto)
    assert categoria == "error"
    assert veredicto is None
    assert motivo


def test_validar_resultado_worker_acepta_limpio_y_rechazado_validos() -> None:
    cat, ver, ms, err = validar_resultado_worker(
        {"veredicto": "limpio", "tipo": "image/png", "motivo": "ok", "duracion_ms": 12}
    )
    assert (cat, ver.veredicto, ver.tipo, ms, err) == (
        "limpio",
        "limpio",
        "image/png",
        12,
        "",
    )

    cat2, ver2, ms2, err2 = validar_resultado_worker(
        {
            "veredicto": "rechazado",
            "tipo": "text/plain",
            "motivo": "tipo_no_permitido",
            "duracion_ms": 3,
        }
    )
    assert (cat2, ver2.veredicto, ms2, err2) == ("rechazado", "rechazado", 3, "")
    assert uuid.uuid4()  # sanity


def test_worker_sin_info_async_run_usa_el_bucle_de_asyncio_run(
    url_redis: str, tmp_path: Path
) -> None:
    """Regresión: crear_worker + asyncio.run(async_run()) no debe fallar por distinto bucle."""
    from worker.principal import crear_worker

    async def _arrancar_y_parar() -> None:
        worker = crear_worker(
            AjustesWorker(url_redis_queue=url_redis, datos=tmp_path),
            handle_signals=False,
            poll_delay_s=0.05,
        )
        tarea = asyncio.create_task(worker.async_run())
        await asyncio.sleep(0.1)
        assert not tarea.done(), f"worker terminó con error: {tarea.exception()}"
        tarea.cancel()
        with pytest.raises(asyncio.CancelledError):
            await tarea

    asyncio.run(_arrancar_y_parar())
