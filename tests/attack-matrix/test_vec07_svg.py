"""vec:07 — SVG (CWE-434). Resultado esperado en el KG: `rechazado`. No está en la lista blanca."""

import pytest
from soporte_matriz import exigir_rechazado

SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">'
    b"<script>alert(document.domain)</script></svg>"
)
SVG_CON_XML = b'<?xml version="1.0" encoding="UTF-8"?>\n' + SVG


@pytest.mark.parametrize("contenido", [SVG, SVG_CON_XML], ids=["svg", "con_xml"])
@pytest.mark.parametrize(
    ("nombre", "tipo"),
    [
        (b"dibujo.svg", b"image/svg+xml"),
        (b"dibujo.png", b"image/png"),
        (b"dibujo.pdf", b"application/pdf"),
    ],
    ids=["declarado", "como_png", "como_pdf"],
)
def test_vec07_svg_rechazado(cliente, banco, contenido, nombre, tipo):
    exigir_rechazado(cliente, banco, contenido, nombre, tipo)
