"""Autenticación por API key (F2.01, diseño §3).

La key es ``gk_<12 hex>.<secreto>``. En la BD solo queda el prefijo y el
HMAC-SHA-256(pepper, key completa) en hexadecimal (V13). Cualquier fallo responde el mismo
401, sin decir cuál fue, y nada aquí registra la key ni su hash (CWE-532).
"""

import hashlib
import hmac
import re
import secrets
import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from api.db.repositorios import obtener_api_key_activa

ESQUEMA = "Bearer "
_BYTES_ALEATORIOS = 32
# Se usa con fullmatch: `$` aceptaría un salto de línea final. Clases ASCII explícitas, para
# que un NUL o un surrogate no lleguen a la BD.
_FORMATO_CREDENCIAL = re.compile(r"(?P<prefijo>gk_[0-9a-f]{12})\.[A-Za-z0-9_-]{43}")
# Contra esto se compara cuando no hay fila, para hacer el mismo trabajo. El resultado de esa
# comparación no decide nada: sin fila siempre es 401.
_HASH_SIN_FILA = "0" * 64


def calcular_hash(pepper: bytes, key: str) -> str:
    """HMAC-SHA-256(pepper, key completa) en hexadecimal, tal como lo guarda ``api_key.hash``."""
    return hmac.new(pepper, key.encode("ascii"), hashlib.sha256).hexdigest()


def generar_key() -> tuple[str, str]:
    """Key nueva: devuelve ``(prefijo, key completa)``. La key completa no se guarda nunca."""
    prefijo = f"gk_{secrets.token_hex(6)}"
    return prefijo, f"{prefijo}.{secrets.token_urlsafe(_BYTES_ALEATORIOS)}"


def _no_autorizado() -> HTTPException:
    """El mismo 401 en todos los casos. ``Connection: close`` porque se responde sin leer el
    cuerpo: sin ella, el servidor seguiría recibiéndolo para reutilizar la conexión, y sin
    autenticar no hay tope de tiempo (K40 empieza después)."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
        headers={"WWW-Authenticate": "Bearer", "Connection": "close"},
    )


async def autenticar(request: Request) -> uuid.UUID:
    """Devuelve el ``aplicacion_id`` de la key, o responde 401.

    El HMAC se calcula también si no hay fila: una key revocada, de una aplicación inactiva
    o con un prefijo inexistente tardan lo mismo que una con el secreto incorrecto.
    """
    cabeceras = request.headers.getlist("authorization")
    # Dos cabeceras Authorization no son válidas (RFC 9110) y un proxy podría ver otra.
    if len(cabeceras) != 1 or not cabeceras[0].startswith(ESQUEMA):
        raise _no_autorizado()
    key = cabeceras[0].removeprefix(ESQUEMA)
    formato = _FORMATO_CREDENCIAL.fullmatch(key)
    if formato is None:
        raise _no_autorizado()

    estado = request.app.state
    # La sesión se cierra aquí: una subida lenta no debe retener una conexión del pool.
    async with estado.sesiones() as sesion:
        fila = await obtener_api_key_activa(sesion, formato["prefijo"])

    calculado = calcular_hash(estado.ajustes.pepper, key)
    guardado = _HASH_SIN_FILA if fila is None else fila.hash
    coincide = hmac.compare_digest(calculado, guardado)
    if fila is None or not coincide:
        raise _no_autorizado()
    return fila.aplicacion_id


AplicacionAutenticada = Annotated[uuid.UUID, Depends(autenticar)]
