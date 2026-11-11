"""vec:04 — Imagen polyglot (CWE-434). Resultado esperado en el KG: `limpio`, y el archivo entregado
ya no contiene la carga útil.

La imagen se reconstruye desde los píxeles, sin EXIF, ICC ni chunks de texto (F3.03), y lo anexado
detrás del final de la imagen desaparece (vecx:datos_anexados).

La carga en los píxeles no se cubre: sobrevive a cualquier recodificación sin pérdida y la imagen
sigue siendo una imagen. Las cargas comprimidas (zTXt) no se ven buscando en los bytes, y por eso
además se comprueba qué fragmentos tiene la salida.
"""

import io

import pytest
from generadores import (
    carga_php,
    fragmentos_png,
    imagen,
    jpeg,
    jpeg_con_exif,
    marca,
    png,
    png_con_exif,
    png_con_fragmento_privado,
    png_con_texto,
    png_con_texto_comprimido,
    segmentos_jpeg,
    zip_con,
)
from PIL import Image, ImageChops, ImageStat
from PIL.PngImagePlugin import PngInfo
from soporte_matriz import exigir_limpio

# IHDR, datos e IEND, más los auxiliares que solo describen los píxeles.
FRAGMENTOS_PNG_PERMITIDOS = {
    "IHDR",
    "PLTE",
    "tRNS",
    "IDAT",
    "IEND",
    "gAMA",
    "pHYs",
    "sRGB",
}
# APP0 (JFIF), DQT, SOF0/SOF2, DHT, DRI. Nada de APP1 (EXIF, XMP), APP2 (ICC) ni COM.
SEGMENTOS_JPEG_PERMITIDOS = {0xE0, 0xDB, 0xC0, 0xC2, 0xC4, 0xDD}
CLAVES_DE_METADATOS = {
    "exif",
    "icc_profile",
    "comment",
    "xmp",
    "photoshop",
    "XML:com.adobe.xmp",
}


def _jpeg_anexado(t: str) -> bytes:
    return jpeg() + carga_php(t)


def _jpeg_comentario(t: str) -> bytes:
    return jpeg(comment=carga_php(t))


def _jpeg_icc(t: str) -> bytes:
    return jpeg(icc_profile=carga_php(t) * 4)


def _jpeg_xmp(t: str) -> bytes:
    return jpeg(xmp=carga_php(t))


def _png_anexado(t: str) -> bytes:
    return png() + carga_php(t)


def _png_con_zip(t: str) -> bytes:
    return png() + zip_con(carga_php(t))


def _png_icc(t: str) -> bytes:
    return png(icc_profile=carga_php(t) * 4)


def _comprobar_jpeg(entregado: bytes, original: Image.Image) -> None:
    assert entregado.startswith(b"\xff\xd8") and entregado.endswith(b"\xff\xd9")
    assert set(segmentos_jpeg(entregado)) <= SEGMENTOS_JPEG_PERMITIDOS
    with Image.open(io.BytesIO(entregado)) as salida:
        assert salida.format == "JPEG"
        assert salida.size == original.size
        assert not CLAVES_DE_METADATOS & set(salida.info)
        assert not salida.getexif()
        # Con pérdida, pero la misma imagen: una reconstrucción en blanco no pasa.
        diferencia = ImageChops.difference(
            salida.convert("RGB"), original.convert("RGB")
        )
        assert max(ImageStat.Stat(diferencia).mean) < 24


def _comprobar_png(entregado: bytes, original: Image.Image) -> None:
    assert set(fragmentos_png(entregado)) <= FRAGMENTOS_PNG_PERMITIDOS
    with Image.open(io.BytesIO(entregado)) as salida:
        assert salida.format == "PNG"
        assert not salida.text
        assert not CLAVES_DE_METADATOS & set(salida.info)
        assert not salida.getexif()
        # Sin pérdida: los mismos píxeles.
        assert salida.convert("RGBA").tobytes() == original.convert("RGBA").tobytes()


@pytest.mark.parametrize(
    "generar",
    [_jpeg_anexado, _jpeg_comentario, jpeg_con_exif, _jpeg_icc, _jpeg_xmp],
    ids=["anexado", "comentario", "exif", "icc", "xmp"],
)
def test_vec04_jpeg_polyglot_limpio_sin_la_carga(cliente, banco, generar):
    token = marca()
    original = generar(token)
    assert token.encode() in original, "la carga debe estar en el archivo de entrada"

    _, entregado = exigir_limpio(
        cliente, banco, original, b"foto.jpg", b"image/jpeg", "image/jpeg"
    )

    assert token.encode() not in entregado
    _comprobar_jpeg(entregado, imagen())


@pytest.mark.parametrize(
    "generar",
    [
        _png_anexado,
        _png_con_zip,
        png_con_texto,
        png_con_texto_comprimido,
        png_con_fragmento_privado,
        png_con_exif,
        _png_icc,
    ],
    ids=["anexado", "zip_anexado", "texto", "ztxt", "privado", "exif", "icc"],
)
def test_vec04_png_polyglot_limpio_sin_la_carga(cliente, banco, generar):
    token = marca()
    original = generar(token)

    _, entregado = exigir_limpio(
        cliente, banco, original, b"foto.png", b"image/png", "image/png"
    )

    assert token.encode() not in entregado
    _comprobar_png(entregado, imagen())


@pytest.mark.parametrize("modo", ["RGB", "RGBA", "L"])
def test_f303_png_conserva_los_pixeles_por_modo(cliente, banco, modo):
    """La reconstrucción no degrada lo legítimo: la transparencia sigue ahí."""
    lienzo = imagen(modo=modo)
    # El texto obliga a que la salida difiera de la entrada aunque el codificador coincida.
    info = PngInfo()
    info.add_text("Comment", marca())
    _, entregado = exigir_limpio(
        cliente,
        banco,
        png(lienzo, pnginfo=info),
        b"foto.png",
        b"image/png",
        "image/png",
    )
    _comprobar_png(entregado, lienzo)
