"""F3.04 y K43 — Referencias externas y archivos incrustados que no son acciones.

Hallazgo media de la revisión de cierre: en un PDF `limpio` sobrevivían el `/F` de un flujo con
`/FS /URL` (los datos de una imagen vienen de una URL) y el `/Ref` de un Form XObject de referencia.
Ninguno es una acción, así que `_CLAVES_ACTIVAS` no los veía, pero un lector puede resolverlos al
abrir el archivo. Lo mismo con `/OPI` y con un flujo `/Type /EmbeddedFile` colgado de una clave
inventada en lugar de `/EF`.

Resultado aceptado: `limpio` sin nada de eso, o `rechazado`. Nunca `limpio` con la referencia.
"""

import io

import pikepdf
import pytest
from generadores import marca, objetos_pdf, texto_del_pdf
from generadores_cdr import (
    pdf_flujo_externo,
    pdf_incrustado_en_clave_propia,
    pdf_opi,
    pdf_xobjeto_ref,
)
from soporte_matriz import exigir_conflicto, exigir_sin_original, nombres

CLAVES_DE_FLUJO_EXTERNO = {"/F", "/FFilter", "/FDecodeParms"}


def _claves(objeto: object) -> set[str]:
    if isinstance(objeto, pikepdf.Dictionary | pikepdf.Stream):
        return set(objeto.keys())
    return set()


def _todas_las_claves(pdf: pikepdf.Pdf) -> set[str]:
    """Claves de todos los objetos, bajando por los valores directos."""
    halladas: set[str] = set()
    pendientes = list(objetos_pdf(pdf))
    while pendientes:
        objeto = pendientes.pop()
        if isinstance(objeto, pikepdf.Array):
            pendientes.extend(
                v for v in objeto if isinstance(v, pikepdf.Object) and not v.is_indirect
            )
        elif isinstance(objeto, pikepdf.Dictionary | pikepdf.Stream):
            for clave in objeto.keys():  # noqa: SIM118
                halladas.add(clave)
                valor = objeto[clave]
                if isinstance(valor, pikepdf.Object) and not valor.is_indirect:
                    pendientes.append(valor)
    return halladas


def _exigir_sin_referencias(entregado: bytes, token: str) -> None:
    assert token.encode() not in entregado, "la referencia sigue en el PDF entregado"
    with pikepdf.open(io.BytesIO(entregado)) as pdf:
        for objeto in pdf.objects:
            if isinstance(objeto, pikepdf.Stream):
                sobrantes = CLAVES_DE_FLUJO_EXTERNO & _claves(objeto)
                assert not sobrantes, f"un flujo conserva {sorted(sobrantes)}"
                assert objeto.get("/Type") != pikepdf.Name.EmbeddedFile, (
                    "sobrevive un flujo /Type /EmbeddedFile"
                )
        claves = _todas_las_claves(pdf)
        assert "/Ref" not in claves
        assert "/OPI" not in claves
        assert token.encode() not in texto_del_pdf(pdf), (
            "la referencia sigue en un flujo o una cadena"
        )


@pytest.mark.parametrize(
    "generar",
    [pdf_flujo_externo, pdf_xobjeto_ref, pdf_opi, pdf_incrustado_en_clave_propia],
    ids=["flujo_con_F_url", "xobjeto_ref", "opi", "embeddedfile_en_clave_propia"],
)
def test_f304_referencia_externa_no_sobrevive_en_un_pdf_limpio(cliente, banco, generar):
    token = marca()
    contenido = generar(token)
    assert token.encode() in contenido, "la referencia debe estar en la entrada"

    archivo_id, final = cliente.analizar(contenido, b"doc.pdf", b"application/pdf")

    assert final["estado"] in ("limpio", "rechazado"), (
        f"estado final: {final['estado']}"
    )
    if final["estado"] == "limpio":
        descarga = cliente.descargar(archivo_id)
        assert descarga.status_code == 200
        _exigir_sin_referencias(descarga.content, token)
    else:
        exigir_conflicto(cliente.descargar(archivo_id))
        assert archivo_id not in nombres(banco.clean_store)
    exigir_sin_original(banco)
