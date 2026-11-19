"""K13 (vecx:flate_bomb) — Bomba de flujos FlateDecode en un PDF (CWE-770). Resultado esperado: `rechazado`.

Tope: 100 MB descomprimidos por PDF. El tope es por documento y no por flujo. `error` no vale: una
descompresión sin tope en un hijo con 1 GiB termina en `MemoryError`, que es justo lo que K13 evita
("nunca `read_bytes()` sin tope sobre un flujo no confiable").
"""

import pytest
from generadores import (
    pdf_bomba_doble_flate,
    pdf_bomba_en_catalogo,
    pdf_bomba_en_pagina,
    pdf_bomba_filtro_en_lista,
    pdf_bomba_repartida,
    pdf_bomba_tras_hex,
)
from hijos import leer_sonda, sonda_hijo_real
from soporte_matriz import TOPE_ARCHIVO, exigir_limpio, exigir_rechazado

SOBRE_EL_TOPE_MIB = 120
BAJO_EL_TOPE_MIB = 90
# Más que RLIMIT_AS: quien descomprime entero no llega a un veredicto `rechazado`.
MAYOR_QUE_RLIMIT_MIB = 1100
# Importar Pillow y pikepdf más, como mucho, los 100 MB del tope.
RSS_MAX_KIB = 512 * 1024


@pytest.mark.parametrize(
    "generar",
    [
        pdf_bomba_en_catalogo,
        pdf_bomba_en_pagina,
        pdf_bomba_filtro_en_lista,
        pdf_bomba_doble_flate,
        pdf_bomba_tras_hex,
    ],
    ids=[
        "catalogo",
        "contenido_de_pagina",
        "filtro_en_lista",
        "doble_flate",
        "tras_hex",
    ],
)
def test_k13_flujo_sobre_el_tope_rechazado(cliente, banco, generar):
    contenido = generar(SOBRE_EL_TOPE_MIB)
    assert len(contenido) < TOPE_ARCHIVO
    exigir_rechazado(cliente, banco, contenido, b"doc.pdf", b"application/pdf")


def test_k13_el_tope_es_por_pdf_no_por_flujo(cliente, banco):
    """30 flujos de 4 MiB: cada uno cabe de sobra, la suma no."""
    contenido = pdf_bomba_repartida(30, 4)
    exigir_rechazado(cliente, banco, contenido, b"doc.pdf", b"application/pdf")


def test_k13_bomba_mayor_que_rlimit_rechazada_sin_agotar_la_memoria(banco, tmp_path):
    comando, registro = sonda_hijo_real(tmp_path)
    contenido = pdf_bomba_en_catalogo(MAYOR_QUE_RLIMIT_MIB)
    assert len(contenido) < TOPE_ARCHIVO
    with banco.api(comando_cdr=comando) as cliente:
        exigir_rechazado(cliente, banco, contenido, b"doc.pdf", b"application/pdf")
    assert leer_sonda(registro)["rss_max_kib"] < RSS_MAX_KIB


def test_k13_bajo_el_tope_se_acepta(cliente, banco):
    """Control positivo: un PDF legítimo puede descomprimirse por encima de su tamaño."""
    exigir_limpio(
        cliente,
        banco,
        pdf_bomba_en_catalogo(BAJO_EL_TOPE_MIB),
        b"doc.pdf",
        b"application/pdf",
        "application/pdf",
    )
