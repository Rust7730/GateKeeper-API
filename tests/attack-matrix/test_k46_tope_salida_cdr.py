"""K46 — Tope de salida del CDR: 32 MiB. Si la salida lo supera, el archivo queda `rechazado` (CWE-770).

Origen: hallazgo alta de la revisión de cierre de la API. Un PDF de ~90 KB salía como 95 MB en
`clean_store`, porque qpdf reescribía el /ObjStm sin comprimir. Sin cuota ni retención, unas cuantas
subidas pequeñas llenaban el disco.

Se prueba con el hijo real (una entrada legítima de 9.5 MiB que reconstruida pasa de 32 MiB) y con un
hijo sustituto. El sustituto fija el borde exacto y exige que el tope se aplique al publicar: el
padre es quien deja la salida en `clean_store`, y el hijo no es de fiar (K28).
"""

import pytest
from generadores_cdr import (
    jpeg_que_crece_al_reconstruir,
    jpeg_ruido,
    pdf_objstm_inflado,
)
from hijos import RESPUESTA_LIMPIO, hijo_falso
from soporte_matriz import (
    TOPE_ARCHIVO,
    TOPE_HIJO_FALSO_S,
    exigir_conflicto,
    exigir_limpio,
    exigir_rechazado,
    exigir_sin_original,
    nombres,
)

TOPE_SALIDA = 32 * 1024 * 1024  # K46
MIB = 1024 * 1024


def _sin_salidas_grandes(banco) -> None:
    grandes = [
        ruta.name
        for ruta in banco.clean_store.iterdir()
        if ruta.stat().st_size > TOPE_SALIDA
    ]
    assert not grandes, f"clean_store guarda salidas de más de 32 MiB: {grandes}"


def test_k46_regresion_objstm_no_deja_95_mb_en_clean_store(cliente, banco):
    """92 KB que salían como 95 MB: salida del tamaño del original, o `rechazado`."""
    contenido = pdf_objstm_inflado(95_000_000)
    assert len(contenido) < 200 * 1024

    archivo_id, final = cliente.analizar(contenido, b"doc.pdf", b"application/pdf")

    assert final["estado"] in ("limpio", "rechazado"), (
        f"estado final: {final['estado']}"
    )
    _sin_salidas_grandes(banco)
    if final["estado"] == "limpio":
        entregado = cliente.descargar(archivo_id).content
        assert len(entregado) <= 2 * len(contenido), (
            f"entraron {len(contenido)} bytes y se entregan {len(entregado)}"
        )
    else:
        exigir_conflicto(cliente.descargar(archivo_id))
        assert archivo_id not in nombres(banco.clean_store)
    exigir_sin_original(banco)


def test_k46_reconstruccion_legitima_sobre_el_tope_rechazada(cliente, banco):
    """Hijo real: 9.5 MiB de JPEG válido que reconstruidos a calidad 90 (K38) pasan de 32 MiB."""
    contenido = jpeg_que_crece_al_reconstruir()
    assert len(contenido) <= TOPE_ARCHIVO

    archivo_id = exigir_rechazado(cliente, banco, contenido, b"foto.jpg", b"image/jpeg")

    assert not [n for n in nombres(banco.clean_store) if n.startswith(archivo_id)], (
        "quedó la salida o un .parcial del archivo rechazado"
    )
    _sin_salidas_grandes(banco)


def test_k46_control_reconstruccion_de_varios_mib_sigue_limpia(cliente, banco):
    """Control positivo: el tope es 32 MiB, no los 10 MiB de la entrada."""
    contenido = jpeg_ruido(8000, 5000, 15)
    assert len(contenido) <= TOPE_ARCHIVO

    _, entregado = exigir_limpio(
        cliente, banco, contenido, b"foto.jpg", b"image/jpeg", "image/jpeg"
    )

    assert 10 * MIB < len(entregado) <= TOPE_SALIDA, (
        f"la prueba necesita una salida entre 10 y 32 MiB, salió {len(entregado)}"
    )


def _hijo_que_escribe(directorio, tamano: int) -> tuple[str, ...]:
    cuerpo = (
        "import sys\n"
        "with open(sys.argv[2], 'xb') as salida:\n"
        f"    salida.truncate({tamano})\n"
        f"print({RESPUESTA_LIMPIO!r}, flush=True)\n"
    )
    return hijo_falso(directorio, cuerpo)


def test_k46_salida_de_32_mib_mas_un_byte_rechazada_al_publicar(banco, tmp_path):
    comando = _hijo_que_escribe(tmp_path, TOPE_SALIDA + 1)
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id, final = cliente.analizar(
            b"\x89PNG cualquier cosa", b"a.png", b"image/png", tope=TOPE_HIJO_FALSO_S
        )
        assert final["estado"] == "rechazado", f"estado final: {final['estado']}"
        exigir_conflicto(cliente.descargar(archivo_id))
    assert not [n for n in nombres(banco.clean_store) if n.startswith(archivo_id)]
    assert ("cdr", "limpio") not in banco.resultados(archivo_id)


def test_k46_control_salida_de_32_mib_justos_se_publica(banco, tmp_path):
    """El borde: "si la supera". 32 MiB exactos no la superan."""
    comando = _hijo_que_escribe(tmp_path, TOPE_SALIDA)
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id, final = cliente.analizar(
            b"\x89PNG cualquier cosa", b"a.png", b"image/png", tope=TOPE_HIJO_FALSO_S
        )
        assert final["estado"] == "limpio", f"estado final: {final['estado']}"
        assert (banco.clean_store / archivo_id).stat().st_size == TOPE_SALIDA


@pytest.mark.parametrize(
    "tamano", [TOPE_SALIDA + 1, 100 * MIB], ids=["borde", "100_mib"]
)
def test_k46_ningun_rastro_de_la_salida_rechazada(banco, tmp_path, tamano):
    """Rechazar no basta: tampoco puede quedar el archivo grande en disco."""
    comando = _hijo_que_escribe(tmp_path, tamano)
    with banco.api(comando_cdr=comando) as cliente:
        cliente.analizar(b"\x89PNG", b"a.png", b"image/png", tope=TOPE_HIJO_FALSO_S)
    _sin_salidas_grandes(banco)
