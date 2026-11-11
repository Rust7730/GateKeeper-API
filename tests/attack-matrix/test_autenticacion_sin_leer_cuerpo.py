"""Autenticación — `POST` sin key válida responde 401 sin leer el cuerpo (diseño §3).

`api/tests/test_autenticacion.py` lo comprueba con una ruta de prueba. Aquí va contra la ruta real: FastAPI
lee el cuerpo antes de las dependencias si la ruta declara `File` o `Form`, y entonces un anónimo
podría llenar el disco sin autenticarse.
"""

import base64
import secrets
import uuid

import pytest
from generadores import png
from soporte_matriz import multipart, nombres

UNAUTHORIZED = b'{"detail":"Unauthorized"}'
_CON_FORMATO = f"gk_{secrets.token_hex(6)}.{secrets.token_urlsafe(32)}"
_BASIC = base64.b64encode(secrets.token_bytes(12)).decode()


def _exigir_401_sin_leer(cliente, banco, cabeceras: dict[str, str]) -> None:
    cuerpo, content_type = multipart(png())
    respuesta = cliente.asgi(
        "POST", "/v1/files", {**cabeceras, "content-type": content_type}, [cuerpo]
    )
    assert respuesta.estado == 401, f"respondió {respuesta.estado}"
    assert respuesta.cuerpo == UNAUTHORIZED
    assert respuesta.leidos == 0, "se leyó el cuerpo antes de autenticar"
    assert nombres(banco.uploads_tmp) == set()
    assert banco.contar_archivos() == 0


@pytest.mark.parametrize(
    "autorizacion",
    [
        None,
        "Bearer no-es-una-key",
        f"Bearer {_CON_FORMATO}",
        f"Basic {_BASIC}",
    ],
    ids=["sin_cabecera", "mal_formada", "inexistente", "otro_esquema"],
)
def test_post_sin_key_valida_responde_401_sin_leer_el_cuerpo(
    cliente, banco, autorizacion
):
    cabeceras = {} if autorizacion is None else {"authorization": autorizacion}
    _exigir_401_sin_leer(cliente, banco, cabeceras)


def test_post_con_key_revocada_responde_401_sin_leer_el_cuerpo(cliente, banco):
    banco.revocar(banco.app_a.prefijo)
    _exigir_401_sin_leer(cliente, banco, cliente.cabeceras())


def test_post_anonimo_con_content_length_excesivo_responde_401_no_413(cliente, banco):
    """Un anónimo no aprende los límites del servicio: la autenticación va primero."""
    respuesta = cliente.asgi(
        "POST",
        "/v1/files",
        {
            "content-type": "multipart/form-data; boundary=x",
            "content-length": str(500 * 2**20),
        },
        [b"x" * 1024],
    )
    assert respuesta.estado == 401
    assert respuesta.leidos == 0


def test_control_con_key_valida_el_post_si_lee_el_cuerpo(cliente, banco):
    """Sin esto, una API que no tuviera la ruta o rechazara todo pasaría las de arriba."""
    assert cliente.post_archivo(png()).status_code == 202
    assert banco.contar_archivos() == 1


@pytest.mark.parametrize("sufijo", ["", "/content"], ids=["estado", "contenido"])
def test_get_sin_key_responde_401_exista_o_no_el_archivo(cliente, banco, sufijo):
    """El 401 va antes de buscar: no sirve para sondear ids."""
    existente = banco.sembrar_archivo("limpio", banco.app_a)
    respuestas = [
        cliente._http.get(f"/v1/files/{archivo_id}{sufijo}")
        for archivo_id in (existente, uuid.uuid4())
    ]
    assert [r.status_code for r in respuestas] == [401, 401]
    assert respuestas[0].content == respuestas[1].content == UNAUTHORIZED
