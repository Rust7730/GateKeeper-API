"""K49 — Imágenes en línea de PDF (`BI ... ID ... EI`) y filtros tras un códec de imagen.

Las imágenes en línea se miden con el mismo tope de K13, 100 MB descomprimidos por PDF, y si lo
superan el archivo queda `rechazado`. Un filtro después de un códec de imagen, como
`[/DCTDecode /FlateDecode]`, también da `rechazado`: no se puede medir sin decodificar el códec.

Origen: hallazgo de la revisión de cierre. K13 solo recorría los objetos del archivo: una imagen en
línea va dentro de un flujo de contenido, y un PDF de 1.9 MB que el lector descomprime en 2 GB salía
`limpio`. El presupuesto es uno por PDF: imágenes en línea y flujos suman juntos.
"""

import io
import zlib

import pikepdf
import pytest
from generadores import ceros_comprimidos
from generadores_cdr import (
    contenido_en_linea,
    jpeg_64,
    pdf_en_linea,
    pdf_en_linea_bomba,
    pdf_en_linea_bomba_hex,
    pdf_en_linea_en_formulario,
    pdf_en_linea_y_flujo,
    pdf_imagen_con_filtros,
)
from pikepdf import Name
from soporte_matriz import TOPE_ARCHIVO, exigir_limpio, exigir_rechazado

SOBRE_EL_TOPE_MIB = 120
CASO_DE_LA_REVISION_MIB = 2048


def _rechazado(cliente, banco, contenido: bytes) -> None:
    assert len(contenido) < TOPE_ARCHIVO
    exigir_rechazado(cliente, banco, contenido, b"doc.pdf", b"application/pdf")


def test_k49_caso_de_la_revision_2_gb_en_linea_rechazado(cliente, banco):
    """~2 MB que se descomprimen en 2 GiB dentro de `BI ... ID ... EI`."""
    _rechazado(cliente, banco, pdf_en_linea_bomba(CASO_DE_LA_REVISION_MIB))


@pytest.mark.parametrize(
    "filtro",
    [b"/F /Fl", b"/Filter /FlateDecode", b"/F [/Fl]", b"/Filter [/FlateDecode]"],
    ids=["abreviado", "completo", "lista_abreviada", "lista_completa"],
)
def test_k49_en_linea_sobre_el_tope_rechazado(cliente, banco, filtro):
    """Las imágenes en línea usan abreviaturas propias (`/F`, `/Fl`): hay que entender las dos."""
    _rechazado(cliente, banco, pdf_en_linea_bomba(SOBRE_EL_TOPE_MIB, filtro))


def test_k49_en_linea_tras_ascii_hex_rechazado(cliente, banco):
    _rechazado(cliente, banco, pdf_en_linea_bomba_hex(SOBRE_EL_TOPE_MIB))


def test_k49_en_linea_dentro_de_un_formulario_rechazado(cliente, banco):
    """También en el contenido de un Form XObject, no solo en el de la página."""
    _rechazado(cliente, banco, pdf_en_linea_en_formulario(SOBRE_EL_TOPE_MIB))


def test_k49_en_linea_y_flujo_suman_un_solo_presupuesto(cliente, banco):
    """60 MiB en línea y 60 MiB en un flujo: cada parte cabe, la suma no."""
    _rechazado(cliente, banco, pdf_en_linea_y_flujo(60, 60))


def test_k49_filtro_tras_un_codec_de_imagen_rechazado(cliente, banco):
    datos = zlib.compress(jpeg_64(), 9)
    contenido = pdf_imagen_con_filtros(datos, [Name.DCTDecode, Name.FlateDecode])
    _rechazado(cliente, banco, contenido)


def test_k49_filtro_tras_un_codec_de_imagen_en_linea_rechazado(cliente, banco):
    datos = zlib.compress(jpeg_64(), 9)
    _rechazado(cliente, banco, pdf_en_linea(datos, 64, 64, b"/F [/DCT /Fl]"))


def test_k49_bomba_tras_un_codec_de_imagen_rechazada(cliente, banco):
    """El caso de la revisión: 2 GiB de Flate detrás de `/DCTDecode`, que K13 no medía."""
    contenido = pdf_imagen_con_filtros(
        ceros_comprimidos(CASO_DE_LA_REVISION_MIB),
        [Name.DCTDecode, Name.FlateDecode],
    )
    _rechazado(cliente, banco, contenido)


# ------------------------------------------------------------------------------ controles positivos


def test_k49_control_imagen_en_linea_pequena_limpia_y_conservada(cliente, banco):
    """Rechazar todo PDF con `BI` también pasaría lo de arriba."""
    datos = zlib.compress(bytes(range(256)) * 16, 9)
    _, entregado = exigir_limpio(
        cliente,
        banco,
        pdf_en_linea(datos, 64, 64),
        b"doc.pdf",
        b"application/pdf",
        "application/pdf",
    )
    with pikepdf.open(io.BytesIO(entregado)) as pdf:
        assert pdf.pages[0].Contents.read_bytes() == contenido_en_linea(
            datos, 64, 64, b"/F /Fl"
        )


def test_k49_control_en_linea_bajo_el_tope_limpio(cliente, banco):
    """90 MiB en línea caben en los 100 MB de K13."""
    exigir_limpio(
        cliente,
        banco,
        pdf_en_linea_bomba(90),
        b"doc.pdf",
        b"application/pdf",
        "application/pdf",
    )


@pytest.mark.parametrize(
    "filtros",
    [[Name.DCTDecode], [Name.FlateDecode, Name.DCTDecode]],
    ids=["solo_dct", "flate_y_luego_dct"],
)
def test_k49_control_codec_al_final_de_la_cadena_limpio(cliente, banco, filtros):
    """Un códec de imagen como última etapa es lo normal y no se rechaza."""
    datos = jpeg_64()
    if filtros[0] == Name.FlateDecode:
        datos = zlib.compress(datos, 9)
    exigir_limpio(
        cliente,
        banco,
        pdf_imagen_con_filtros(datos, filtros),
        b"doc.pdf",
        b"application/pdf",
        "application/pdf",
    )
