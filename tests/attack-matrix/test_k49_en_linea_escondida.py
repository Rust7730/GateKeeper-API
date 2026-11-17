"""K49 — Imagen en línea escondida dentro de los datos de otra imagen en línea.

qpdf y el lector no cortan los datos de una imagen en línea en el mismo sitio:

- **qpdf** busca el `EI` que cierra la imagen con una heurística: un `EI` entre blancos al que
  sigan tokens que parezcan contenido. Si detrás del primer `EI` hay un token inválido, lo descarta
  y sigue buscando.
- **poppler** lee lo que pide la imagen (los bytes de `/W` x `/H` sin filtro, o hasta el fin de
  zlib con `/Fl`) y corta en el primer `EI` que venga después. El token inválido lo salta y sigue.

Así, para qpdf la segunda imagen (`BI ... ID <bomba> EI`) es parte de los datos de la primera, y
el CDR solo mide esos datos: sin filtro, tal cual; con `/Fl`, hasta el fin de zlib, porque
`_flate` no mira lo que queda detrás. Para poppler es una imagen más, y la descomprime entera.

Origen: revisión de la vuelta 1 (2026-11-10). Un PDF de 1.4 KB con una imagen escondida de
20000 x 20000 salía `limpio` en 3 ms; `pdfimages -list` sobre la salida mostraba la imagen y
`pdftoppm` inflaba sus 400 MB. Resultado esperado por K49: `rechazado`.
"""

import zlib

import pytest
from generadores import ceros_comprimidos, guardar, pdf_base
from soporte_matriz import TOPE_ARCHIVO, exigir_limpio, exigir_rechazado

SOBRE_EL_TOPE_MIB = 120
_INICIO = b"q 200 0 0 200 0 0 cm\n"
_FIN = b"\nEI\nQ\n"


def _escondida(mib: int) -> bytes:
    """La imagen que qpdf no ve: ``mib`` MiB de ceros en grises de 8 bits."""
    return (
        b"BI /W 1024 /H %d /BPC 8 /CS /G /F /Fl ID\n" % (mib * 1024)
        + ceros_comprimidos(mib)
        + _FIN
    )


# Primera imagen de 1 x 1, el `EI` que la cierra para poppler y un token que qpdf toma por basura.
_PRIMERAS = {
    "sin_filtro_y_control": b"BI /W 1 /H 1 /BPC 8 /CS /G ID\nX\nEI\n\x01\x02\n",
    "sin_filtro_y_palabra": b"BI /W 1 /H 1 /BPC 8 /CS /G ID\nX\nEI\nx1\n",
    "flate_y_control": (
        b"BI /W 1 /H 1 /BPC 8 /CS /G /F /Fl ID\n"
        + zlib.compress(b"X")
        + b"\nEI\n\x01\n"
    ),
}


def _pdf(contenido: bytes) -> bytes:
    pdf = pdf_base()
    pdf.pages[0].Contents = pdf.make_stream(contenido)
    return guardar(pdf)


@pytest.mark.parametrize("primera", list(_PRIMERAS), ids=list(_PRIMERAS))
def test_k49_en_linea_escondida_en_otra_rechazada(cliente, banco, primera):
    contenido = _pdf(_INICIO + _PRIMERAS[primera] + _escondida(SOBRE_EL_TOPE_MIB))
    assert len(contenido) < TOPE_ARCHIVO
    exigir_rechazado(cliente, banco, contenido, b"doc.pdf", b"application/pdf")


def test_k49_control_dos_imagenes_en_linea_legitimas_limpio(cliente, banco):
    """Dos imágenes en línea seguidas, bien cerradas, son lo normal: no se rechazan."""
    imagen = (
        b"BI /W 2 /H 2 /BPC 8 /CS /G /F /Fl ID\n"
        + zlib.compress(b"\x10\x20\x30\x40")
        + _FIN
    )
    exigir_limpio(
        cliente,
        banco,
        _pdf(_INICIO + imagen + _INICIO + imagen),
        b"doc.pdf",
        b"application/pdf",
        "application/pdf",
    )
