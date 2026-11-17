"""K47: escaneos de un JPEG contados sobre su estructura de marcadores, sin decodificarlo."""

import os
import struct
import time

import pytest

from api.app.cdr_jpeg import MAX_ESCANEOS, contar_escaneos, fin_jpeg

SOI = b"\xff\xd8"
EOI = b"\xff\xd9"


def _segmento(marcador: int, datos: bytes) -> bytes:
    return b"\xff" + bytes([marcador]) + struct.pack(">H", len(datos) + 2) + datos


def _escaneo(datos: bytes = b"\x12\x34") -> bytes:
    """Cabecera SOS de una componente y sus datos con entropía."""
    return _segmento(0xDA, b"\x01\x01\x00\x00\x3f\x00") + datos


def _jpeg(*partes: bytes) -> bytes:
    return SOI + _segmento(0xE0, b"JFIF\x00") + b"".join(partes) + EOI


def test_el_tope_es_el_de_la_decision() -> None:
    assert MAX_ESCANEOS == 64


def test_cuenta_cada_escaneo() -> None:
    assert contar_escaneos(_jpeg(*[_escaneo()] * 7)) == 7


def test_ff_da_dentro_de_un_segmento_no_cuenta() -> None:
    comentario = _segmento(0xFE, b"\xff\xda" * 200)
    aplicacion = _segmento(0xE1, b"\xff\xda\x00\x08" * 50)
    assert contar_escaneos(_jpeg(comentario, aplicacion, _escaneo())) == 1


def test_relleno_y_reinicios_dentro_de_los_datos_no_cortan_el_escaneo() -> None:
    """`FF 00` es un FF de los datos y `FF D0`..`FF D7` son marcadores de reinicio."""
    datos = b"\x01\xff\x00\x02\xff\xd0\x03\xff\xd7\x04"
    assert contar_escaneos(_jpeg(_escaneo(datos), _escaneo(datos))) == 2


def test_escaneos_vacios_seguidos_cuentan_todos() -> None:
    """La bomba de la revisión: cabeceras SOS sin datos, una detrás de otra."""
    cabecera = _escaneo(b"")
    assert contar_escaneos(_jpeg(cabecera * 300), hasta=None) == 300


def test_basura_entre_segmentos_no_esconde_un_escaneo() -> None:
    """libjpeg salta los bytes sueltos hasta el siguiente FF; aquí también."""
    basura = b"\x00\x11\x22"
    assert contar_escaneos(_jpeg(basura, _escaneo(), basura, _escaneo())) == 2


def test_bytes_de_relleno_antes_de_un_marcador() -> None:
    assert contar_escaneos(_jpeg(b"\xff\xff\xff" + _escaneo())) == 1


def test_lo_que_va_tras_el_fin_de_imagen_no_cuenta() -> None:
    assert contar_escaneos(_jpeg(_escaneo()) + _escaneo() * 100) == 1


def test_sin_inicio_de_imagen_no_hay_escaneos() -> None:
    assert contar_escaneos(_escaneo() * 100) == 0


@pytest.mark.parametrize("corte", [1, 3, 5, 9])
def test_truncado_cuenta_hasta_donde_llega(corte: int) -> None:
    contenido = _jpeg(_escaneo(), _escaneo())
    assert contar_escaneos(contenido[: -2 - corte]) in (1, 2)


def test_hasta_corta_en_cuanto_lo_pasa() -> None:
    contenido = _jpeg(_escaneo(b"") * 5000)
    assert contar_escaneos(contenido, hasta=MAX_ESCANEOS) == MAX_ESCANEOS + 1


def test_diez_mib_de_datos_se_recorren_en_milisegundos() -> None:
    """Va en el camino de todo JPEG (M2): datos al azar, con un FF cada 256 bytes."""
    datos = os.urandom(10 * 1024 * 1024).replace(b"\xff", b"\xff\x00")
    contenido = _jpeg(_escaneo(datos))
    inicio = time.perf_counter()
    assert contar_escaneos(contenido, hasta=MAX_ESCANEOS) == 1
    assert time.perf_counter() - inicio < 0.2


def test_diez_mib_de_ff_se_recorren_en_milisegundos() -> None:
    """Relleno puro: con un bucle byte a byte en Python costaba 1.5 s."""
    contenido = SOI + b"\xff" * (10 * 1024 * 1024) + EOI
    inicio = time.perf_counter()
    assert contar_escaneos(contenido, hasta=MAX_ESCANEOS) == 0
    assert time.perf_counter() - inicio < 0.2


def test_diez_mib_de_ff00_se_recorren_en_milisegundos() -> None:
    contenido = _jpeg(_escaneo(b"\xff\x00" * (5 * 1024 * 1024)))
    inicio = time.perf_counter()
    assert contar_escaneos(contenido, hasta=MAX_ESCANEOS) == 1
    assert time.perf_counter() - inicio < 0.2


# --------------------------------------------- K49: fin de un JPEG en línea en un PDF


def test_fin_jpeg_es_el_byte_que_sigue_al_eoi() -> None:
    contenido = _jpeg(_escaneo(b"\x01\xff\x00\x02"))
    assert fin_jpeg(contenido + b"\nEI basura") == len(contenido)


def test_fin_jpeg_no_se_engana_con_un_eoi_en_un_comentario() -> None:
    contenido = _jpeg(_segmento(0xFE, b"\xff\xd9" * 10), _escaneo())
    assert fin_jpeg(contenido) == len(contenido)


@pytest.mark.parametrize(
    "contenido",
    [b"no es jpeg", SOI + _segmento(0xE0, b"JFIF\x00") + _escaneo()],
    ids=["sin_soi", "sin_eoi"],
)
def test_fin_jpeg_sin_fin_es_none(contenido: bytes) -> None:
    assert fin_jpeg(contenido) is None
