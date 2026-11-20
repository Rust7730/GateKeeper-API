"""Ayudas de las pruebas del rate limit (K10, K58).

- ``RelojFalso``: el reloj que se pasa por la costura ``Ajustes.reloj_limite`` (ver
  soporte_matriz.py). Arranca en la hora real y solo avanza cuando la prueba lo pide: así se prueba
  la recarga de 2 por segundo sin dormir.
- El tope de K48 (20 en ``pendiente``) también responde 429, pero sin ``Retry-After``. Para que el
  429 que se mide sea el del rate limit, las subidas usan un hijo del CDR que responde enseguida y
  la prueba espera en la BD (no por HTTP: cada GET también pasa por la autenticación) a que los
  pendientes bajen.
"""

import re
from pathlib import Path

import httpx
from generadores import png
from hijos import RESPUESTA_RECHAZADO, hijo_falso
from soporte_matriz import (
    TOPE_HIJO_FALSO_S,
    Banco,
    RespuestaAsgi,
    esperar_que,
    multipart,
    nombres,
)

from api.tests.soporte_api import KeySembrada

CAPACIDAD_KEY = 20  # K58: ráfaga
RECARGA_POR_S = 2  # K58: 120 por minuto sostenidos
LIMITE_IP_POR_MIN = 60  # K58: sin autenticar o con key inválida
TOO_MANY_REQUESTS = {"detail": "Too Many Requests"}
UNAUTHORIZED = b'{"detail":"Unauthorized"}'
# Por debajo del tope de K48, con margen, se vacían los pendientes antes de seguir.
_UMBRAL_DRENAJE = 15
_RETRY_AFTER = re.compile(r"[1-9][0-9]*")


class RelojFalso:
    """Segundos de época, como ``time.time``; solo avanza con ``avanzar``."""

    def __init__(self, inicio: float) -> None:
        self.ahora = inicio

    def __call__(self) -> float:
        return self.ahora

    def avanzar(self, segundos: float) -> None:
        self.ahora += segundos


def hijo_rapido(directorio: Path) -> tuple[str, ...]:
    """CDR sustituto que termina en milisegundos: el archivo deja de estar ``pendiente``."""
    return hijo_falso(directorio, f"print({RESPUESTA_RECHAZADO!r})\n")


def drenar(banco: Banco, app: KeySembrada) -> None:
    esperar_que(
        lambda: banco.pendientes(app) == 0,
        "los análisis no terminaron: el tope de K48 se mezclaría con el rate limit",
        tope=TOPE_HIJO_FALSO_S,
    )


def subir(cliente, banco: Banco, app: KeySembrada) -> httpx.Response:
    """Una subida con la key de ``app``. Si deja muchos pendientes, espera a que terminen."""
    cuerpo, content_type = multipart(png())
    respuesta = cliente._http.post(
        "/v1/files",
        content=cuerpo,
        headers={"Authorization": f"Bearer {app.key}", "Content-Type": content_type},
    )
    if respuesta.status_code == 202 and banco.pendientes(app) >= _UMBRAL_DRENAJE:
        drenar(banco, app)
    return respuesta


def es_429_del_limite(estado: int, cabeceras) -> bool:
    return estado == 429 and "retry-after" in {n.lower() for n in cabeceras}


def exigir_429_del_limite(respuesta: httpx.Response | RespuestaAsgi) -> None:
    """429 de K58: cuerpo exacto, ``Retry-After`` en segundos enteros ≥ 1 y ``Connection: close``."""
    if isinstance(respuesta, RespuestaAsgi):
        estado, cabeceras = respuesta.estado, dict(respuesta.cabeceras)
        cuerpo = (
            httpx.Response(200, content=respuesta.cuerpo).json()
            if respuesta.cuerpo
            else None
        )
    else:
        estado = respuesta.status_code
        cabeceras = {n.lower(): v for n, v in respuesta.headers.items()}
        cuerpo = respuesta.json() if respuesta.content else None
    assert estado == 429, f"debía responder 429 y respondió {estado}"
    assert cuerpo == TOO_MANY_REQUESTS, f"cuerpo del 429: {cuerpo!r}"
    assert "retry-after" in cabeceras, (
        "429 sin Retry-After: no es el del rate limit (el de K48 no lo lleva)"
    )
    assert _RETRY_AFTER.fullmatch(cabeceras["retry-after"]), (
        f"Retry-After debe ser un entero de segundos ≥ 1: {cabeceras['retry-after']!r}"
    )
    assert cabeceras.get("connection", "").lower() == "close", (
        "el 429 se responde sin leer el cuerpo: debe cerrar la conexión"
    )


def exigir_sin_rastro(banco: Banco, antes_disco: set[str], antes_filas: int) -> None:
    assert nombres(banco.uploads_tmp) <= antes_disco, "el rechazo dejó un temporal"
    assert banco.contar_archivos() == antes_filas, "el rechazo dejó una fila"


def agotar(cliente, banco: Banco, app: KeySembrada) -> None:
    """Las ``CAPACIDAD_KEY`` subidas de la ráfaga, todas 202, con el reloj congelado."""
    for numero in range(1, CAPACIDAD_KEY + 1):
        respuesta = subir(cliente, banco, app)
        assert respuesta.status_code == 202, (
            f"la subida {numero} de la ráfaga respondió {respuesta.status_code}"
        )
    drenar(banco, app)
