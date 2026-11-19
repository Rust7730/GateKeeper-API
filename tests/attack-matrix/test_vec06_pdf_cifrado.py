"""vec:06 — PDF cifrado. Resultado esperado en el KG: `rechazado`, incluido el PDF con solo contraseña
de propietario: ese se abre sin contraseña y se podría sanear, pero `docs/decisiones.md` §5 lo rechaza.
"""

import io
import secrets

import pikepdf
import pytest
from generadores import pdf_cifrado
from soporte_matriz import exigir_rechazado


@pytest.mark.parametrize("revision", [6, 4], ids=["aes256", "r4"])
def test_vec06_solo_contrasena_de_propietario_rechazado(cliente, banco, revision):
    contenido = pdf_cifrado(secrets.token_urlsafe(16), revision=revision)
    with pikepdf.open(io.BytesIO(contenido)) as pdf:
        assert pdf.is_encrypted, "la prueba debe mandar un PDF que abre sin contraseña"
    exigir_rechazado(cliente, banco, contenido, b"doc.pdf", b"application/pdf")


def test_vec06_con_contrasena_de_usuario_rechazado(cliente, banco):
    """No es un fallo del análisis: pikepdf no lo abre, y eso es `rechazado`, no `error`."""
    contenido = pdf_cifrado(secrets.token_urlsafe(16), secrets.token_urlsafe(16))
    exigir_rechazado(cliente, banco, contenido, b"doc.pdf", b"application/pdf")
