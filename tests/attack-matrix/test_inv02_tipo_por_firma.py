"""INV-02 — El `Content-Type` de la parte, la extensión y el nombre no deciden nada.

Los mismos bytes, con cualquier disfraz, dan el mismo estado y el mismo tipo detectado. Lo que se
entrega tampoco hereda nada de lo declarado: `Content-Type` y extensión salen del tipo detectado.
"""

import re

import pytest
from generadores import guardar, jpeg, pdf_base, png
from soporte_matriz import exigir_limpio, exigir_rechazado

DISFRACES = [
    (b"virus.exe", b"application/x-msdownload"),
    (b"pagina.html", b"text/html"),
    (b"dibujo.svg", b"image/svg+xml"),
    (b"datos.zip", b"application/zip"),
    (b"sin_extension", None),
]
IDS_DISFRACES = ["exe", "html", "svg", "zip", "sin_tipo"]
SCRIPT = b"<?php system($_GET['c']); ?>\n"


@pytest.mark.parametrize(("nombre", "tipo"), DISFRACES, ids=IDS_DISFRACES)
@pytest.mark.parametrize(
    ("generar", "mime", "extension"),
    [
        (png, "image/png", "png"),
        (jpeg, "image/jpeg", "jpe?g"),
        (lambda: guardar(pdf_base()), "application/pdf", "pdf"),
    ],
    ids=["png", "jpeg", "pdf"],
)
def test_inv02_lo_declarado_no_cambia_un_archivo_legitimo(
    cliente, banco, nombre, tipo, generar, mime, extension
):
    archivo_id, _ = exigir_limpio(cliente, banco, generar(), nombre, tipo, mime)

    descarga = cliente.descargar(archivo_id)
    assert descarga.headers["content-type"] == mime
    assert re.fullmatch(
        rf'attachment; filename="{archivo_id}\.{extension}"',
        descarga.headers["content-disposition"],
    )


@pytest.mark.parametrize(
    ("nombre", "tipo"),
    [
        (b"foto.png", b"image/png"),
        (b"foto.jpg", b"image/jpeg"),
        (b"doc.pdf", b"application/pdf"),
        (b"sin_extension", None),
    ],
    ids=["png", "jpeg", "pdf", "sin_tipo"],
)
def test_inv02_lo_declarado_no_salva_un_archivo_peligroso(cliente, banco, nombre, tipo):
    exigir_rechazado(cliente, banco, SCRIPT, nombre, tipo)


def test_inv02_tipo_cruzado_entrega_el_tipo_real(cliente, banco):
    """Un PNG declarado como PDF se detecta y se entrega como PNG, no como lo declarado."""
    exigir_limpio(cliente, banco, png(), b"doc.pdf", b"application/pdf", "image/png")
