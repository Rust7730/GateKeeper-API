"""vec:10 — Archivo de 500 MB (CWE-770). En la rebanada se comprueba en la API: 413 y sin temporal
residual. El límite de Nginx queda fuera (K26), así que la parte "la petición no llega a la API" del KG
sigue pendiente.

Tope: 10 485 760 bytes de archivo. Se corta en cuanto se supera, y un `Content-Length` por encima del
tope más 64 KiB se rechaza sin leer el cuerpo (diseño §4). Estas pruebas usan ASGI directo para contar
lo que la API lee: TestClient le entrega el cuerpo entero de una vez.
"""

import contextlib
from collections.abc import Iterator

import pytest
from generadores import MIB, png
from soporte_matriz import (
    DESCONEXION,
    DETALLES_413,
    MARGEN_CONTENT_LENGTH,
    TOPE_ARCHIVO,
    esperar_que,
    nombres,
)

TROZO = 64 * 1024
# Lo que se puede leer de más: las cabeceras multipart y el trozo que hizo pasar el tope.
HOLGURA_LECTURA = MARGEN_CONTENT_LENGTH + TROZO


def _exigir_413_sin_rastro(respuesta_estado: int, detalle: object, banco) -> None:
    assert respuesta_estado == 413
    assert detalle in DETALLES_413
    assert nombres(banco.uploads_tmp) == set(), "quedó un temporal"
    assert banco.contar_archivos() == 0, "quedó una fila de un archivo rechazado"


def _cuerpo_infinito(limite: bytes, megas: int) -> Iterator[bytes]:
    yield (
        b'--%s\r\nContent-Disposition: form-data; name="file"; filename="g.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n" % limite
    )
    relleno = b"\xab" * TROZO
    for _ in range(megas * MIB // TROZO):
        yield relleno


def _cabeceras_multipart(cliente, limite: bytes, **extra: str) -> dict[str, str]:
    return {
        **cliente.cabeceras(),
        "content-type": f"multipart/form-data; boundary={limite.decode()}",
        **extra,
    }


def test_vec10_un_byte_sobre_el_tope_responde_413(cliente, banco):
    respuesta = cliente.post_archivo(bytes(TOPE_ARCHIVO + 1))
    assert respuesta.status_code == 413
    _exigir_413_sin_rastro(respuesta.status_code, respuesta.json()["detail"], banco)


def test_vec10_exactamente_en_el_tope_se_acepta(cliente):
    """Control positivo: el tope es de 10 485 760 bytes, no menos, y el multipart no cuenta."""
    relleno = png()
    contenido = relleno + bytes(TOPE_ARCHIVO - len(relleno))
    archivo_id = cliente.subir(contenido, b"foto.png", b"image/png")
    assert cliente.esperar(archivo_id)["tamano_bytes"] == TOPE_ARCHIVO


@pytest.mark.parametrize(
    "declarado",
    [TOPE_ARCHIVO + MARGEN_CONTENT_LENGTH + 1, 500 * MIB],
    ids=["justo_sobre_el_margen", "500_mb"],
)
def test_vec10_content_length_excesivo_se_rechaza_sin_leer(cliente, banco, declarado):
    limite = b"limitegk"
    respuesta = cliente.asgi(
        "POST",
        "/v1/files",
        _cabeceras_multipart(cliente, limite, **{"content-length": str(declarado)}),
        _cuerpo_infinito(limite, 500),
    )
    assert respuesta.leidos == 0, (
        "la API leyó el cuerpo de una petición que ya sabía excesiva"
    )
    assert respuesta.estado == 413
    assert nombres(banco.uploads_tmp) == set()


def test_vec10_500_mb_sin_content_length_se_cortan_al_pasar_el_tope(cliente, banco):
    """El caso del KG: 500 MB en chunked, donde no hay cabecera que delate el tamaño."""
    limite = b"limitegk"
    respuesta = cliente.asgi(
        "POST",
        "/v1/files",
        _cabeceras_multipart(cliente, limite),
        _cuerpo_infinito(limite, 500),
    )
    assert not respuesta.excedio_alarma, "la API siguió leyendo muy por encima del tope"
    assert respuesta.leidos <= TOPE_ARCHIVO + HOLGURA_LECTURA
    assert respuesta.estado == 413
    assert nombres(banco.uploads_tmp) == set(), "quedó un temporal"
    assert banco.contar_archivos() == 0


def test_vec10_cuerpo_sin_parte_file_tampoco_se_lee_entero(cliente, banco):
    """Un campo de texto enorme no es un archivo, pero ocupa la conexión igual (CWE-770)."""
    limite = b"limitegk"

    def _campo_infinito() -> Iterator[bytes]:
        yield b'--%s\r\nContent-Disposition: form-data; name="otro"\r\n\r\n' % limite
        for _ in range(500 * MIB // TROZO):
            yield b"a" * TROZO

    respuesta = cliente.asgi(
        "POST", "/v1/files", _cabeceras_multipart(cliente, limite), _campo_infinito()
    )
    assert not respuesta.excedio_alarma, "la API siguió leyendo muy por encima del tope"
    assert respuesta.leidos <= TOPE_ARCHIVO + HOLGURA_LECTURA
    assert respuesta.estado in (400, 413)
    assert nombres(banco.uploads_tmp) == set()


def test_vec10_cliente_que_corta_a_mitad_no_deja_temporal(cliente, banco):
    """Sin esto, subidas abandonadas llenarían el disco sin llegar nunca al tope."""
    limite = b"limitegk"
    assert cliente.post_archivo(png()).status_code == 202, (
        "control: la ruta debe existir"
    )

    def _trozos() -> Iterator[object]:
        yield (
            b'--%s\r\nContent-Disposition: form-data; name="file"; filename="g.bin"\r\n\r\n'
            % limite
        )
        yield b"\xab" * TROZO
        yield DESCONEXION

    subidos = banco.contar_archivos()
    # Cómo termine la petición para un cliente que ya no está no importa: importa el disco.
    with contextlib.suppress(Exception):
        cliente.asgi(
            "POST", "/v1/files", _cabeceras_multipart(cliente, limite), _trozos()
        )
    esperar_que(
        lambda: not nombres(banco.uploads_tmp),
        "quedó un temporal de una subida interrumpida",
    )
    assert banco.contar_archivos() == subidos, (
        "quedó una fila de una subida interrumpida"
    )
