"""vec:14 — 200 subidas en un minuto: HTTP 429 al superar el umbral (K10, K58; CWE-770).

K58: por API key, token bucket por aplicación de capacidad 20 que se recarga a 2 por segundo (120 por
minuto sostenidos, ráfaga de 20). El exceso responde `429 {"detail": "Too Many Requests"}` con
`Retry-After` en segundos enteros y `Connection: close`, antes de leer el cuerpo: sin temporal ni
fila. K10: el bucket es de la aplicación (``aplicacion_id``), no de la key ni de la IP.

El ritmo se prueba con la costura ``Ajustes.reloj_limite`` congelada (soporte_limite.RelojFalso).
Una prueba más usa el reloj real, sin costura, para que la de producción también limite.
"""

import math
import time

import pytest
from soporte_limite import (
    CAPACIDAD_KEY,
    RECARGA_POR_S,
    RelojFalso,
    agotar,
    drenar,
    es_429_del_limite,
    exigir_429_del_limite,
    exigir_sin_rastro,
    hijo_rapido,
    subir,
)
from soporte_matriz import TOPE_ARCHIVO, multipart, nombres

from api.tests.soporte_api import KeySembrada


@pytest.fixture
def reloj() -> RelojFalso:
    return RelojFalso(time.time())


@pytest.fixture
def abrir(banco, tmp_path, reloj):
    """Abre la API con el reloj congelado. Se abre dentro de la prueba, no en un fixture: si falta
    la costura, la prueba falla (no da error de preparación)."""

    def _abrir():
        return banco.api(comando_cdr=hijo_rapido(tmp_path), reloj_limite=reloj)

    return _abrir


def _exigir_429_sin_rastro(cliente, banco, app) -> None:
    antes_disco, antes_filas = nombres(banco.uploads_tmp), banco.contar_archivos()
    exigir_429_del_limite(subir(cliente, banco, app))
    exigir_sin_rastro(banco, antes_disco, antes_filas)


def test_vec14_las_primeras_20_pasan_y_la_21_recibe_429_sin_temporal_ni_fila(
    abrir, banco
):
    with abrir() as limitada:
        agotar(limitada, banco, banco.app_a)
        assert banco.pendientes(banco.app_a) == 0, (
            "el 429 debe ser del rate limit, no de K48"
        )
        _exigir_429_sin_rastro(limitada, banco, banco.app_a)


def test_vec14_se_recarga_a_2_por_segundo(abrir, banco, reloj):
    with abrir() as limitada:
        agotar(limitada, banco, banco.app_a)
        _exigir_429_sin_rastro(limitada, banco, banco.app_a)

        # 0.49 s son 0.98 fichas: todavía no alcanza para una subida.
        reloj.avanzar(0.49)
        _exigir_429_sin_rastro(limitada, banco, banco.app_a)

        # Con 0.02 s más pasa justo una.
        reloj.avanzar(0.02)
        assert subir(limitada, banco, banco.app_a).status_code == 202
        _exigir_429_sin_rastro(limitada, banco, banco.app_a)

        # Un segundo más: dos subidas, ni una más.
        reloj.avanzar(1.0)
        assert [subir(limitada, banco, banco.app_a).status_code for _ in range(2)] == [
            202,
            202,
        ]
        _exigir_429_sin_rastro(limitada, banco, banco.app_a)


def test_vec14_la_rafaga_no_pasa_de_20_aunque_espere_mucho(abrir, banco, reloj):
    """El bucket se llena hasta 20: una hora quieta no da 7200 subidas seguidas."""
    with abrir() as limitada:
        agotar(limitada, banco, banco.app_a)
        reloj.avanzar(3600)
        agotar(limitada, banco, banco.app_a)
        _exigir_429_sin_rastro(limitada, banco, banco.app_a)


def test_vec14_200_subidas_en_un_minuto_reciben_429_al_superar_el_umbral(
    abrir, banco, reloj
):
    """El vector literal: 200 intentos repartidos en 60 s.

    Con 20 de ráfaga y 2 por segundo pasan 139 (cálculo continuo); se admite ±2 por redondeo de la
    implementación. Menos de 137 sería más estricto que K58; más de 141, que no limita.
    """
    with abrir() as limitada:
        aceptadas = 0
        for _ in range(200):
            respuesta = subir(limitada, banco, banco.app_a)
            if respuesta.status_code == 202:
                aceptadas += 1
            else:
                exigir_429_del_limite(respuesta)
            reloj.avanzar(0.3)
        drenar(banco, banco.app_a)
        assert 137 <= aceptadas <= 141, f"pasaron {aceptadas} de 200 en un minuto"
        assert banco.contar_archivos() == aceptadas, "un 429 dejó fila"


def test_vec14_otra_aplicacion_no_se_ve_afectada(abrir, banco):
    with abrir() as limitada:
        agotar(limitada, banco, banco.app_a)
        _exigir_429_sin_rastro(limitada, banco, banco.app_a)
        agotar(limitada, banco, banco.app_b)
        _exigir_429_sin_rastro(limitada, banco, banco.app_a)


def test_vec14_otra_key_de_la_misma_aplicacion_comparte_el_limite(abrir, banco):
    """K10: el límite es por aplicación. Rotar la key no da otra ráfaga."""
    with abrir() as limitada:
        agotar(limitada, banco, banco.app_a)
        otra = KeySembrada(
            banco.app_a.aplicacion_id,
            banco.app_a.prefijo,
            banco.key_nueva_para(banco.app_a.aplicacion_id),
        )
        _exigir_429_sin_rastro(limitada, banco, otra)


def test_vec14_el_429_llega_sin_leer_un_cuerpo_de_10_mib(abrir, banco):
    """Una key agotada no hace recibir 10 MiB al servidor (mismo método que el 401 de F2.01)."""
    with abrir() as limitada:
        agotar(limitada, banco, banco.app_a)
        antes_disco, antes_filas = nombres(banco.uploads_tmp), banco.contar_archivos()
        cuerpo, content_type = multipart(bytes(TOPE_ARCHIVO))
        trozos = [cuerpo[i : i + 65_536] for i in range(0, len(cuerpo), 65_536)]
        respuesta = limitada.asgi(
            "POST",
            "/v1/files",
            {
                **limitada.cabeceras(banco.app_a.key),
                "content-type": content_type,
                "content-length": str(len(cuerpo)),
            },
            trozos,
        )
        exigir_429_del_limite(respuesta)
        assert respuesta.leidos == 0, (
            f"se leyeron {respuesta.leidos} bytes antes del 429"
        )
        exigir_sin_rastro(banco, antes_disco, antes_filas)


def test_vec14_sin_costura_el_reloj_real_tambien_limita(banco, tmp_path):
    """La API de producción, sin reloj falso: pasan la ráfaga y lo recargado, y nada más."""
    with banco.api(reloj_real=True, comando_cdr=hijo_rapido(tmp_path)) as cliente:
        inicio = time.monotonic()
        aceptadas = 0
        limitada = None
        for _ in range(80):
            respuesta = subir(cliente, banco, banco.app_a)
            if respuesta.status_code == 202:
                aceptadas += 1
                continue
            assert es_429_del_limite(respuesta.status_code, respuesta.headers), (
                f"respondió {respuesta.status_code} sin ser el 429 del rate limit"
            )
            limitada = respuesta
            break
        transcurrido = time.monotonic() - inicio
        drenar(banco, banco.app_a)
    tope = CAPACIDAD_KEY + math.ceil(RECARGA_POR_S * transcurrido) + 1
    assert limitada is not None, f"80 subidas en {transcurrido:.1f} s sin ningún 429"
    exigir_429_del_limite(limitada)
    assert CAPACIDAD_KEY <= aceptadas <= tope, (
        f"pasaron {aceptadas} en {transcurrido:.1f} s (permitidas entre {CAPACIDAD_KEY} y {tope})"
    )
