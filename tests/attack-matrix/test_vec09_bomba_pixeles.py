"""vec:09 — Bomba de píxeles (CWE-770). Resultado esperado en el KG: `rechazado` sin agotar la memoria.

El límite es 40 000 000 píxeles (F3.01). Pillow solo lanza un error al pasar del doble; entre uno y dos
veces el límite solo avisa con `DecompressionBombWarning`, y por eso el caso de 40 008 000 px detecta
una advertencia que no se trató como error. `error` no vale: significa que el hijo se quedó sin
memoria o se cayó, justo lo que el control debe evitar.
"""

from generadores import jpeg, jpeg_con_dimensiones, png, png_bomba
from hijos import leer_sonda, sonda_hijo_real
from PIL import Image
from soporte_matriz import exigir_limpio, exigir_rechazado

# Con dimensiones validadas antes de load(), el hijo no reserva la imagen: se queda en lo que
# ocupa importar Pillow y pikepdf. Decodificar esta bomba costaría unos 400 MiB.
RSS_MAX_KIB = 256 * 1024
# 38 710 000 píxeles RGB ocupan unos 155 MiB al decodificarse, más lo que cuesta importar.
RSS_DECODIFICADA_KIB = 150 * 1024


def _lienzo_1_bit(ancho: int, alto: int) -> Image.Image:
    return Image.new("1", (ancho, alto))


def test_vec09_png_grande_rechazado(cliente, banco):
    exigir_rechazado(
        cliente, banco, png_bomba(10_000, 10_000), b"foto.png", b"image/png"
    )


def test_vec09_png_sobre_el_limite_y_bajo_el_doble_rechazado(cliente, banco):
    contenido = png(_lienzo_1_bit(8000, 5001))
    exigir_rechazado(cliente, banco, contenido, b"foto.png", b"image/png")


def test_vec09_jpeg_sobre_el_limite_y_bajo_el_doble_rechazado(cliente, banco):
    contenido = jpeg(Image.new("L", (8000, 5001)))
    exigir_rechazado(cliente, banco, contenido, b"foto.jpg", b"image/jpeg")


def test_vec09_jpeg_con_dimensiones_falsas_rechazado(cliente, banco):
    """Pocos KB que declaran 4 225 000 000 píxeles."""
    contenido = jpeg_con_dimensiones(65_000, 65_000)
    exigir_rechazado(cliente, banco, contenido, b"foto.jpg", b"image/jpeg")


def test_f301_exactamente_en_el_limite_se_acepta(cliente, banco):
    """Control positivo: el límite es 40 000 000, no menos."""
    exigir_limpio(
        cliente,
        banco,
        png(_lienzo_1_bit(8000, 5000)),
        b"foto.png",
        b"image/png",
        "image/png",
    )


def test_vec09_la_bomba_no_llega_a_decodificarse(banco, tmp_path):
    """F3.02: las dimensiones se validan antes de `load()`, con el hijo real bajo la sonda."""
    comando, registro = sonda_hijo_real(tmp_path)
    with banco.api(comando_cdr=comando) as cliente:
        exigir_rechazado(
            cliente, banco, png_bomba(10_000, 10_000), b"foto.png", b"image/png"
        )
    assert leer_sonda(registro)["rss_max_kib"] < RSS_MAX_KIB


def test_vec09_control_la_sonda_nota_una_imagen_decodificada(banco, tmp_path):
    """Control de la prueba anterior: bajo el límite, decodificar sí se ve en la memoria del hijo."""
    comando, registro = sonda_hijo_real(tmp_path)
    with banco.api(comando_cdr=comando) as cliente:
        exigir_limpio(
            cliente,
            banco,
            png_bomba(7900, 4900),
            b"foto.png",
            b"image/png",
            "image/png",
        )
    assert leer_sonda(registro)["rss_max_kib"] > RSS_DECODIFICADA_KIB
