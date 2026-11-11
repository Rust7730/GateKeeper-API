"""vec:08 — ZIP (CWE-434). Resultado esperado en el KG: `rechazado`. No está en la lista blanca."""

import pytest
from generadores import carga_php, png, zip_con
from soporte_matriz import exigir_rechazado

ZIP = zip_con(carga_php("zip"))


@pytest.mark.parametrize(
    ("contenido", "nombre", "tipo"),
    [
        (ZIP, b"datos.zip", b"application/zip"),
        (ZIP, b"datos.png", b"image/png"),
        (ZIP, b"datos.pdf", b"application/pdf"),
        (ZIP + png(), b"datos.png", b"image/png"),
    ],
    ids=["declarado", "como_png", "como_pdf", "zip_con_png_detras"],
)
def test_vec08_zip_rechazado(cliente, banco, contenido, nombre, tipo):
    exigir_rechazado(cliente, banco, contenido, nombre, tipo)
