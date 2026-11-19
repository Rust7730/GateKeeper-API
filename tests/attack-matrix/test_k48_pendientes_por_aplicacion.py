"""K48 — Como máximo 20 archivos en `pendiente` por aplicación (CWE-770).

La subida número 21 recibe `429 {"detail": "Too Many Requests"}`, sin temporal ni fila. Otra
aplicación no se ve afectada, y en cuanto una termina se vuelve a aceptar.

Origen: hallazgo de la revisión de cierre. La cola de análisis no tenía tope: una sola key podía
acumular originales en `uploads_tmp` y dejar a las demás aplicaciones esperando.

Los `pendiente` se fijan de dos formas: sembrados en la BD después de arrancar la API (sin carreras,
y sin que un barrido de arranque los toque), o con un hijo que espera una puerta.
"""

import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor

from generadores import png
from hijos import hijo_con_puerta
from soporte_matriz import nombres
from sqlalchemy import text

from api.app.estados import Estado
from api.db.repositorios import cambiar_estado
from api.db.sesion import crear_motor, fabrica_sesiones

TOPE_PENDIENTES = 20  # K48
TOO_MANY_REQUESTS = {"detail": "Too Many Requests"}


def _sembrar(banco, app, estado: str, cantidad: int) -> list[str]:
    return [banco.sembrar_archivo(estado, app) for _ in range(cantidad)]


def _pendientes(banco, app) -> int:
    with banco.motor.connect() as con:
        return con.execute(
            text(
                "SELECT count(*) FROM archivo"
                " WHERE aplicacion_id = :app AND estado = 'pendiente'"
            ),
            {"app": app.aplicacion_id},
        ).scalar_one()


def _terminar(banco, app, archivo_id: str) -> None:
    """Un análisis que acaba en `error`, escrito con el repositorio real."""

    async def _cambiar() -> None:
        motor = crear_motor(banco.url)
        try:
            async with fabrica_sesiones(motor).begin() as sesion:
                await cambiar_estado(
                    sesion,
                    app.aplicacion_id,
                    uuid.UUID(archivo_id),
                    Estado.PENDIENTE,
                    Estado.ERROR,
                    tipo_error="final",
                )
        finally:
            await motor.dispose()

    asyncio.run(_cambiar())


def _exigir_429_sin_rastro(cliente, banco, app) -> None:
    antes_disco = nombres(banco.uploads_tmp)
    antes_filas = banco.contar_archivos()
    respuesta = cliente.post_archivo(png(), key=app.key)
    assert respuesta.status_code == 429, f"respondió {respuesta.status_code}"
    assert respuesta.json() == TOO_MANY_REQUESTS
    assert nombres(banco.uploads_tmp) <= antes_disco, (
        "quedó un temporal de la subida 21"
    )
    assert banco.contar_archivos() == antes_filas, "la subida 21 dejó una fila"


def test_k48_la_subida_21_recibe_429_sin_temporal_ni_fila(banco, tmp_path):
    """Con subidas reales: las 20 se quedan en análisis y la 21 se rechaza."""
    comando, puerta, _ = hijo_con_puerta(tmp_path)
    with banco.api(comando_cdr=comando, timeout_cdr_s=25) as cliente:
        try:
            for _ in range(TOPE_PENDIENTES):
                cliente.subir(png())
            assert _pendientes(banco, banco.app_a) == TOPE_PENDIENTES
            _exigir_429_sin_rastro(cliente, banco, banco.app_a)
        finally:
            puerta.touch()


def test_k48_con_20_pendientes_sembrados_la_siguiente_es_429(cliente, banco):
    _sembrar(banco, banco.app_a, "pendiente", TOPE_PENDIENTES)
    _exigir_429_sin_rastro(cliente, banco, banco.app_a)


def test_k48_otra_aplicacion_no_se_ve_afectada(cliente, banco):
    _sembrar(banco, banco.app_a, "pendiente", TOPE_PENDIENTES)
    _exigir_429_sin_rastro(cliente, banco, banco.app_a)
    assert cliente.post_archivo(png(), key=banco.app_b.key).status_code == 202


def test_k48_al_terminar_alguna_se_vuelve_a_aceptar(cliente, banco):
    sembrados = _sembrar(banco, banco.app_a, "pendiente", TOPE_PENDIENTES)
    _exigir_429_sin_rastro(cliente, banco, banco.app_a)

    _terminar(banco, banco.app_a, sembrados[0])

    assert cliente.post_archivo(png()).status_code == 202


def test_k48_control_solo_cuentan_los_pendientes(cliente, banco):
    """Los terminados no ocupan cupo: con 19 pendientes y 30 terminados se acepta."""
    for estado in ("limpio", "rechazado", "error"):
        _sembrar(banco, banco.app_a, estado, 10)
    _sembrar(banco, banco.app_a, "pendiente", TOPE_PENDIENTES - 1)
    assert cliente.post_archivo(png()).status_code == 202


def test_k48_subidas_simultaneas_no_pasan_del_tope(banco, tmp_path):
    """Con 19 pendientes y 8 subidas a la vez entra una sola: el tope no se comprueba y luego se
    inserta por separado, porque entre las dos cosas cabe la recepción entera de otra subida."""
    comando, puerta, _ = hijo_con_puerta(tmp_path)
    with banco.api(comando_cdr=comando, timeout_cdr_s=25) as cliente:
        try:
            _sembrar(banco, banco.app_a, "pendiente", TOPE_PENDIENTES - 1)
            contenido = png() + bytes(512 * 1024)
            with ThreadPoolExecutor(8) as hilos:
                respuestas = list(
                    hilos.map(lambda _: cliente.post_archivo(contenido), range(8))
                )
            codigos = sorted(r.status_code for r in respuestas)
            assert codigos == [202] + [429] * 7, f"códigos: {codigos}"
            assert _pendientes(banco, banco.app_a) == TOPE_PENDIENTES
        finally:
            puerta.touch()
