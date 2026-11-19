"""F3.06 — Límite de páginas de PDF (param:max_paginas_pdf = 200). Sin vector en el KG."""

from generadores import guardar, pdf_base
from soporte_matriz import exigir_limpio, exigir_rechazado


def test_f306_201_paginas_rechazado(cliente, banco):
    contenido = guardar(pdf_base(paginas=201))
    exigir_rechazado(cliente, banco, contenido, b"doc.pdf", b"application/pdf")


def test_f306_200_paginas_se_aceptan(cliente, banco):
    contenido = guardar(pdf_base(paginas=200))
    exigir_limpio(
        cliente, banco, contenido, b"doc.pdf", b"application/pdf", "application/pdf"
    )
