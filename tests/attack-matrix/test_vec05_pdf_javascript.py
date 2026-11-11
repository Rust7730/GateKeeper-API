"""vec:05 — PDF con JavaScript o acciones automáticas. Resultado esperado en el KG: `limpio`, sin
/JavaScript, /OpenAction ni /AA en el PDF entregado.

También cubre F3.04 y F3.05. `docs/decisiones.md` §5 manda sobre el diseño: además de las claves
que lista F3.04, se eliminan /AcroForm y /Annots.

El PDF entregado se analiza con pikepdf, objeto por objeto: una búsqueda en los bytes no ve lo que
queda dentro de un /ObjStm o de un flujo comprimido. Se busca en todo el documento y no solo en
las claves del catálogo, porque una acción también puede colgar de /Outlines.
"""

import io

import pikepdf
import pytest
from generadores import (
    TEXTO_PAGINA,
    guardar,
    marca,
    nombres_pdf,
    objetos_pdf,
    pdf_aa_catalogo,
    pdf_aa_nodo_de_paginas,
    pdf_aa_pagina,
    pdf_accion_en_clave_propia,
    pdf_anotacion_launch,
    pdf_anotacion_uri,
    pdf_base,
    pdf_con_metadatos,
    pdf_datos_anexados,
    pdf_embebido,
    pdf_en_flujos_de_objetos,
    pdf_marcador_js,
    pdf_marcador_launch,
    pdf_names_javascript,
    pdf_nombres_ofuscados,
    pdf_open_action,
    pdf_open_action_en_flujo,
    pdf_submit_form,
    texto_del_pdf,
)
from soporte_matriz import exigir_limpio

NOMBRES_PROHIBIDOS = {
    "/JavaScript",
    "/JS",
    "/OpenAction",
    "/AA",
    "/Launch",
    "/EmbeddedFiles",
    "/EF",
    "/URI",
    "/SubmitForm",
    "/AcroForm",
    "/Annots",
}


def _comprobar_pdf(entregado: bytes, token: str) -> None:
    assert b"/JavaScript" not in entregado
    assert b"/OpenAction" not in entregado
    with pikepdf.open(io.BytesIO(entregado)) as pdf:
        hallados = set()
        for objeto in objetos_pdf(pdf):
            hallados |= nombres_pdf(objeto)
        assert not NOMBRES_PROHIBIDOS & hallados
        assert token.encode() not in texto_del_pdf(pdf)
        assert token.encode() not in entregado


@pytest.mark.parametrize(
    "generar",
    [
        pdf_open_action,
        pdf_open_action_en_flujo,
        pdf_en_flujos_de_objetos,
        pdf_aa_catalogo,
        pdf_aa_pagina,
        pdf_aa_nodo_de_paginas,
        pdf_accion_en_clave_propia,
        pdf_names_javascript,
        pdf_embebido,
        pdf_anotacion_launch,
        pdf_anotacion_uri,
        pdf_submit_form,
        pdf_marcador_js,
        pdf_marcador_launch,
        pdf_nombres_ofuscados,
        pdf_datos_anexados,
    ],
    ids=lambda f: f.__name__.removeprefix("pdf_"),
)
def test_vec05_pdf_activo_limpio_y_sin_acciones(cliente, banco, generar):
    token = marca()
    _, entregado = exigir_limpio(
        cliente,
        banco,
        generar(token),
        b"doc.pdf",
        b"application/pdf",
        "application/pdf",
    )
    _comprobar_pdf(entregado, token)


def test_vec05_el_contenido_de_las_paginas_se_conserva(cliente, banco):
    """Control positivo: vaciar el documento también quitaría el JavaScript."""
    pdf = pdf_base(paginas=3)
    pdf.Root.OpenAction = pikepdf.Dictionary(
        S=pikepdf.Name.JavaScript, JS=pikepdf.String("app.alert(1)")
    )
    _, entregado = exigir_limpio(
        cliente, banco, guardar(pdf), b"doc.pdf", b"application/pdf", "application/pdf"
    )
    with pikepdf.open(io.BytesIO(entregado)) as salida:
        assert len(salida.pages) == 3
        for pagina in salida.pages:
            assert pagina.Contents.read_bytes() == TEXTO_PAGINA


def test_f305_sin_info_ni_xmp(cliente, banco):
    token = marca()
    original = pdf_con_metadatos(token)
    assert token.encode() in original, (
        "los metadatos deben estar en el archivo de entrada"
    )

    _, entregado = exigir_limpio(
        cliente, banco, original, b"doc.pdf", b"application/pdf", "application/pdf"
    )

    assert token.encode() not in entregado
    with pikepdf.open(io.BytesIO(entregado)) as pdf:
        assert "/Info" not in pdf.trailer
        assert "/Metadata" not in pdf.Root
        assert token.encode() not in texto_del_pdf(pdf)
