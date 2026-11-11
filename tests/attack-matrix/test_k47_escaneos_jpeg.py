"""K47 — JPEG con más de 64 escaneos (marcadores SOS): `rechazado`, contado sobre los bytes antes de Pillow.

Origen: hallazgo de la revisión de cierre (CWE-770). Cada escaneo de un JPEG progresivo recorre la
imagen entera, aunque no traiga datos: ~500 KB de cabeceras SOS tenían ocupado un cupo del CDR 27 s,
y doce bombas así dejaban a todas las aplicaciones esperando el timeout de 30 s.

Un JPEG progresivo legítimo trae unos 10 escaneos y sigue `limpio`. El conteo es sobre la estructura
del archivo: un `FF DA` dentro de un comentario no es un escaneo.
"""

from datetime import datetime

import pytest
from generadores_cdr import (
    escaneos_jpeg,
    jpeg_con_escaneos,
    jpeg_con_sos_en_comentario,
    jpeg_escaneos_vacios,
    jpeg_progresivo,
)
from soporte_matriz import TOPE_ARCHIVO, exigir_limpio, exigir_rechazado

MAX_ESCANEOS = 64  # K47
# Rechazar contando marcadores cuesta milisegundos. Sin el control, esta bomba tarda segundos en
# decodificarse y sale `limpio`.
TOPE_RECHAZO_S = 5.0


@pytest.mark.parametrize("total", [MAX_ESCANEOS + 1, 200], ids=["65", "200"])
def test_k47_mas_de_64_escaneos_rechazado(cliente, banco, total):
    contenido = jpeg_con_escaneos(total)
    exigir_rechazado(cliente, banco, contenido, b"foto.jpg", b"image/jpeg")


def test_k47_control_64_escaneos_justos_limpio(cliente, banco):
    """El borde: "más de 64". Mismo archivo que el de 65, con un escaneo menos."""
    exigir_limpio(
        cliente,
        banco,
        jpeg_con_escaneos(MAX_ESCANEOS),
        b"foto.jpg",
        b"image/jpeg",
        "image/jpeg",
    )


def test_k47_control_progresivo_legitimo_limpio(cliente, banco):
    contenido = jpeg_progresivo()
    assert 5 <= len(escaneos_jpeg(contenido)) <= 15, "un progresivo normal trae ~10"
    exigir_limpio(cliente, banco, contenido, b"foto.jpg", b"image/jpeg", "image/jpeg")


def test_k47_bomba_de_escaneos_vacios_se_rechaza_sin_decodificarla(cliente, banco):
    """5000 cabeceras SOS sin datos sobre 16 MP: el rechazo llega antes de que Pillow la abra."""
    contenido = jpeg_escaneos_vacios(5000, 4000, 4000)
    assert len(contenido) < TOPE_ARCHIVO

    archivo_id = exigir_rechazado(cliente, banco, contenido, b"foto.jpg", b"image/jpeg")

    fila = banco.fila(archivo_id)
    datos = cliente.ver(archivo_id).json()
    duracion = (
        datetime.fromisoformat(datos["analizado_en"])
        - datetime.fromisoformat(datos["creado_en"])
    ).total_seconds()
    assert fila["estado"] == "rechazado"
    assert duracion < TOPE_RECHAZO_S, f"el rechazo tardó {duracion:.1f} s"


def test_k47_control_ff_da_en_un_comentario_no_cuenta(cliente, banco):
    """Contar `FF DA` en bytes crudos rechazaría este JPEG de un solo escaneo."""
    contenido = jpeg_con_sos_en_comentario(200)
    assert contenido.count(b"\xff\xda") > MAX_ESCANEOS
    assert len(escaneos_jpeg(contenido)) == 1
    exigir_limpio(cliente, banco, contenido, b"foto.jpg", b"image/jpeg", "image/jpeg")
