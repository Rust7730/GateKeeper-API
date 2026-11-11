"""Autenticación — Todo 401 lleva `Connection: close` (CWE-770).

Hallazgo media de la revisión de cierre. La API no lee el cuerpo antes de autenticar, pero sin esta
cabecera el servidor sigue recibiéndolo para reutilizar la conexión: un cliente sin key mandó 1908 MiB
en 3 s después del 401, y sin autenticar no hay tope de tiempo (K40 empieza después). El 401 sigue
siendo idéntico en todos los casos (diseño §3).
"""

import base64
import secrets

import pytest
from generadores import png
from soporte_matriz import multipart

UNAUTHORIZED = {"detail": "Unauthorized"}
_CON_FORMATO = f"gk_{secrets.token_hex(6)}.{secrets.token_urlsafe(32)}"
_BASIC = base64.b64encode(secrets.token_bytes(12)).decode()
CASOS = pytest.mark.parametrize(
    "autorizacion",
    [None, "Bearer no-es-una-key", f"Bearer {_CON_FORMATO}", f"Basic {_BASIC}"],
    ids=["sin_cabecera", "mal_formada", "inexistente", "otro_esquema"],
)


def _exigir_401_que_cierra(respuesta) -> None:
    assert respuesta.status_code == 401
    assert respuesta.json() == UNAUTHORIZED
    assert respuesta.headers.get("www-authenticate") == "Bearer"
    assert respuesta.headers.get("connection", "").lower() == "close", (
        "el 401 no cierra la conexión: el servidor seguiría recibiendo el cuerpo"
    )


def _cabeceras(autorizacion: str | None) -> dict[str, str]:
    return {} if autorizacion is None else {"Authorization": autorizacion}


@CASOS
def test_post_401_cierra_la_conexion(cliente, autorizacion):
    cuerpo, content_type = multipart(png())
    respuesta = cliente._http.post(
        "/v1/files",
        content=cuerpo,
        headers={**_cabeceras(autorizacion), "Content-Type": content_type},
    )
    _exigir_401_que_cierra(respuesta)


@CASOS
def test_get_401_cierra_la_conexion(cliente, banco, autorizacion):
    existente = banco.sembrar_archivo("limpio", banco.app_a)
    respuesta = cliente._http.get(
        f"/v1/files/{existente}", headers=_cabeceras(autorizacion)
    )
    _exigir_401_que_cierra(respuesta)


def test_key_revocada_401_cierra_la_conexion(cliente, banco):
    banco.revocar(banco.app_a.prefijo)
    cuerpo, content_type = multipart(png())
    respuesta = cliente._http.post(
        "/v1/files",
        content=cuerpo,
        headers={**cliente.cabeceras(), "Content-Type": content_type},
    )
    _exigir_401_que_cierra(respuesta)
