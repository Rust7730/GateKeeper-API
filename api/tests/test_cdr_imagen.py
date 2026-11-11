"""Reconstrucción de imágenes (F3.01–F3.03): casos que la matriz de ataque no fija.

La matriz cubre EXIF, ICC, texto, datos anexados y bombas por HTTP. Aquí van los modos de
imagen y lo que un hijo real tiene que devolver como motivo.
"""

import io
import struct
import warnings
from pathlib import Path

import pytest
from PIL import Image, ImageFile
from PIL.PngImagePlugin import PngInfo

from api.app.cdr_imagen import MAX_PIXELES, reconstruir_imagen


def _guardar(tmp_path: Path, imagen: Image.Image, formato: str, **opciones) -> Path:
    ruta = tmp_path / "entrada"
    imagen.save(ruta, formato, **opciones)
    return ruta


def _reconstruir(tmp_path: Path, entrada: Path, tipo: str) -> tuple[str | None, Path]:
    salida = tmp_path / "salida"
    return reconstruir_imagen(entrada, salida, tipo), salida


def test_el_limite_es_el_del_parametro() -> None:
    assert MAX_PIXELES == 40_000_000


def test_reconstruir_no_altera_el_estado_global_de_warnings(tmp_path: Path) -> None:
    entrada = _guardar(tmp_path, Image.new("L", (4, 4)), "PNG")
    antes = list(warnings.filters)
    reconstruir_imagen(entrada, tmp_path / "salida", "image/png")
    assert warnings.filters == antes


@pytest.mark.parametrize("modo", ["1", "L", "LA", "RGB", "RGBA", "I;16"])
def test_png_conserva_el_modo_y_los_pixeles(tmp_path: Path, modo: str) -> None:
    original = Image.new("RGBA", (8, 8), (10, 200, 30, 128)).convert(modo)
    entrada = _guardar(tmp_path, original, "PNG")

    motivo, salida = _reconstruir(tmp_path, entrada, "image/png")

    assert motivo is None
    with Image.open(salida) as resultado:
        assert resultado.mode == modo
        assert resultado.tobytes() == original.tobytes()


def test_png_con_paleta_y_transparencia_la_conserva(tmp_path: Path) -> None:
    original = Image.new("P", (4, 4), 1)
    original.putpalette([0, 0, 0, 255, 0, 0])
    entrada = _guardar(tmp_path, original, "PNG", transparency=1)

    motivo, salida = _reconstruir(tmp_path, entrada, "image/png")

    assert motivo is None
    with Image.open(salida) as resultado:
        assert resultado.convert("RGBA").getpixel((0, 0)) == (255, 0, 0, 0)


def test_png_rgb_con_transparencia_por_color_la_conserva(tmp_path: Path) -> None:
    entrada = _guardar(
        tmp_path, Image.new("RGB", (4, 4), (9, 9, 9)), "PNG", transparency=(9, 9, 9)
    )

    motivo, salida = _reconstruir(tmp_path, entrada, "image/png")

    assert motivo is None
    with Image.open(salida) as resultado:
        assert resultado.convert("RGBA").getpixel((0, 0)) == (9, 9, 9, 0)


def test_png_solo_conserva_transparencia_de_la_info(tmp_path: Path) -> None:
    info = PngInfo()
    info.add_text("Comment", "carga")
    entrada = _guardar(
        tmp_path, Image.new("L", (4, 4)), "PNG", pnginfo=info, dpi=(9, 9)
    )

    _, salida = _reconstruir(tmp_path, entrada, "image/png")

    with Image.open(salida) as resultado:
        assert set(resultado.info) == set()


@pytest.mark.parametrize("modo", ["L", "RGB", "CMYK"])
def test_jpeg_conserva_el_modo_y_el_tamano(tmp_path: Path, modo: str) -> None:
    entrada = _guardar(tmp_path, Image.new(modo, (16, 8)), "JPEG")

    motivo, salida = _reconstruir(tmp_path, entrada, "image/jpeg")

    assert motivo is None
    with Image.open(salida) as resultado:
        assert (resultado.format, resultado.mode) == ("JPEG", modo)
        assert resultado.size == (16, 8)


# ------------------------------------------------------------------------------- K37 y K38


def _ruido_rgb(lado: int = 96) -> Image.Image:
    return Image.merge("RGB", [Image.effect_noise((lado, lado), 60) for _ in range(3)])


def test_k37_png_se_codifica_con_nivel_3(tmp_path: Path) -> None:
    original = _ruido_rgb()
    entrada = _guardar(tmp_path, original, "PNG")

    _, salida = _reconstruir(tmp_path, entrada, "image/png")

    nivel_3, nivel_6 = io.BytesIO(), io.BytesIO()
    original.save(nivel_3, "PNG", compress_level=3)
    original.save(nivel_6, "PNG")
    assert nivel_3.getvalue() != nivel_6.getvalue(), "control: los niveles difieren"
    assert salida.read_bytes() == nivel_3.getvalue()


def test_k38_jpeg_se_codifica_con_calidad_90(tmp_path: Path) -> None:
    entrada = _guardar(tmp_path, _ruido_rgb(), "JPEG", quality=95)

    _, salida = _reconstruir(tmp_path, entrada, "image/jpeg")

    with Image.open(entrada) as decodificada:
        calidad_90, por_defecto = io.BytesIO(), io.BytesIO()
        decodificada.save(calidad_90, "JPEG", quality=90)
        decodificada.save(por_defecto, "JPEG")
    assert calidad_90.getvalue() != por_defecto.getvalue(), "control"
    assert salida.read_bytes() == calidad_90.getvalue()


# ------------------------------------------------------------------------------------ K39

ORIENTACION = 0x0112
# Filas de una imagen de 2 x 3 con estos valores, tal como se ve con cada orientación. Están
# escritas a mano para no usar como oráculo la misma tabla que usa el código.
a, b, c, d, e, f = 10, 40, 80, 120, 160, 200
PIXELES_ORIGINALES = [[a, b], [c, d], [e, f]]
FILAS_POR_ORIENTACION = {
    2: [[b, a], [d, c], [f, e]],
    3: [[f, e], [d, c], [b, a]],
    4: [[e, f], [c, d], [a, b]],
    5: [[a, c, e], [b, d, f]],
    6: [[e, c, a], [f, d, b]],
    7: [[f, d, b], [e, c, a]],
    8: [[b, d, f], [a, c, e]],
}


def _exif(orientacion: object) -> Image.Exif:
    exif = Image.Exif()
    exif[ORIENTACION] = orientacion
    return exif


def _dos_por_tres() -> Image.Image:
    imagen = Image.new("L", (2, 3))
    imagen.putdata([valor for fila in PIXELES_ORIGINALES for valor in fila])
    return imagen


def _filas(imagen: Image.Image) -> list[list[int]]:
    ancho, alto = imagen.size
    return [[imagen.getpixel((x, y)) for x in range(ancho)] for y in range(alto)]


@pytest.mark.parametrize("orientacion", FILAS_POR_ORIENTACION)
def test_k39_png_cada_orientacion_gira_los_pixeles(
    tmp_path: Path, orientacion: int
) -> None:
    entrada = _guardar(tmp_path, _dos_por_tres(), "PNG", exif=_exif(orientacion))

    motivo, salida = _reconstruir(tmp_path, entrada, "image/png")

    assert motivo is None
    with Image.open(salida) as resultado:
        assert _filas(resultado) == FILAS_POR_ORIENTACION[orientacion]
        assert not resultado.getexif()
        assert "exif" not in resultado.info


def test_k39_jpeg_con_orientacion_6_sale_girado_y_sin_exif(tmp_path: Path) -> None:
    """Rotar 90 grados a la derecha: la mitad izquierda, clara, queda arriba."""
    original = Image.new("L", (64, 32), 0)
    original.paste(255, (0, 0, 32, 32))
    entrada = _guardar(tmp_path, original, "JPEG", exif=_exif(6))
    assert b"Exif" in entrada.read_bytes()

    motivo, salida = _reconstruir(tmp_path, entrada, "image/jpeg")

    assert motivo is None
    assert b"Exif" not in salida.read_bytes()
    with Image.open(salida) as resultado:
        assert resultado.size == (32, 64)
        assert resultado.getpixel((16, 8)) > 200
        assert resultado.getpixel((16, 56)) < 50
        assert not resultado.getexif()


@pytest.mark.parametrize("modo", ["1", "L", "LA", "P", "RGB", "RGBA", "I;16"])
def test_k39_png_gira_en_todos_los_modos(tmp_path: Path, modo: str) -> None:
    entrada = _guardar(tmp_path, Image.new(modo, (6, 2)), "PNG", exif=_exif(8))

    motivo, salida = _reconstruir(tmp_path, entrada, "image/png")

    assert motivo is None
    with Image.open(salida) as resultado:
        assert (resultado.mode, resultado.size) == (modo, (2, 6))


def test_k39_jpeg_cmyk_gira(tmp_path: Path) -> None:
    entrada = _guardar(tmp_path, Image.new("CMYK", (6, 2)), "JPEG", exif=_exif(6))
    motivo, salida = _reconstruir(tmp_path, entrada, "image/jpeg")
    assert motivo is None
    with Image.open(salida) as resultado:
        assert (resultado.mode, resultado.size) == ("CMYK", (2, 6))


def test_k39_girar_conserva_la_transparencia(tmp_path: Path) -> None:
    original = Image.new("P", (2, 1), 0)
    original.putpalette([0, 0, 0, 255, 0, 0])
    original.putpixel((1, 0), 1)
    entrada = _guardar(tmp_path, original, "PNG", transparency=1, exif=_exif(6))

    motivo, salida = _reconstruir(tmp_path, entrada, "image/png")

    assert motivo is None
    with Image.open(salida) as resultado:
        convertida = resultado.convert("RGBA")
        assert convertida.size == (1, 2)
        assert convertida.getpixel((0, 0)) == (0, 0, 0, 255)
        assert convertida.getpixel((0, 1))[3] == 0


@pytest.mark.parametrize("orientacion", [1, 0, 9, 255, 65535])
def test_k39_una_orientacion_sin_sentido_no_gira(
    tmp_path: Path, orientacion: int
) -> None:
    entrada = _guardar(tmp_path, _dos_por_tres(), "PNG", exif=_exif(orientacion))
    motivo, salida = _reconstruir(tmp_path, entrada, "image/png")
    assert motivo is None
    with Image.open(salida) as resultado:
        assert _filas(resultado) == PIXELES_ORIGINALES


def _exif_crudo(tipo: int, cuenta: int, valor: bytes) -> bytes:
    """TIFF escrito a mano con una sola etiqueta: el escritor de Pillow no deja poner esto."""
    entrada = struct.pack("<HHI4s", ORIENTACION, tipo, cuenta, valor)
    return b"Exif\x00\x00II*\x00\x08\x00\x00\x00\x01\x00" + entrada + bytes(4)


@pytest.mark.parametrize(
    "exif",
    [_exif_crudo(2, 2, b"6\0\0\0"), _exif_crudo(11, 1, struct.pack("<f", 6.5))],
    ids=["texto", "decimal"],
)
def test_k39_una_orientacion_de_otro_tipo_no_gira(tmp_path: Path, exif: bytes) -> None:
    entrada = _guardar(tmp_path, _dos_por_tres(), "PNG", exif=exif)
    motivo, salida = _reconstruir(tmp_path, entrada, "image/png")
    assert motivo is None
    with Image.open(salida) as resultado:
        assert _filas(resultado) == PIXELES_ORIGINALES


@pytest.mark.parametrize(
    "exif",
    [
        b"Exif\x00\x00esto no es un tiff",
        b"Exif\x00\x00II*\x00\xff\xff\xff\xff",
        b"Exif\x00\x00MM\x00*\x00\x00\x00\x08\xff\xff",
        b"Exif\x00\x00II*\x00\x08\x00\x00\x00\xff\xff" + b"\x12\x01" * 400,
    ],
    ids=["no_es_tiff", "offset_fuera", "ifd_cortado", "entradas_de_mas"],
)
@pytest.mark.parametrize(
    ("formato", "tipo"), [("JPEG", "image/jpeg"), ("PNG", "image/png")]
)
def test_k39_un_exif_ilegible_no_rechaza_ni_gira(
    tmp_path: Path, exif: bytes, formato: str, tipo: str
) -> None:
    """Era `limpio` antes de K39 y lo sigue siendo: el EXIF se elimina de todos modos."""
    original = Image.new("L", (4, 2), 128)
    entrada = _guardar(tmp_path, original, formato, exif=exif)

    motivo, salida = _reconstruir(tmp_path, entrada, tipo)

    assert motivo is None
    assert b"esto no es" not in salida.read_bytes()
    with Image.open(salida) as resultado:
        assert resultado.size == (4, 2)


def test_k39_sobre_el_tope_se_rechaza_antes_de_mirar_la_orientacion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Las dimensiones se validan antes de `load()`: girar no abre otro camino a la bomba."""
    original = Image.new("1", (8000, 5001))
    entrada = _guardar(tmp_path, original, "PNG", exif=_exif(6))

    def _no_debe_llamarse(*_: object, **__: object) -> None:
        raise AssertionError("se llegó a decodificar o a girar")

    monkeypatch.setattr(Image.Image, "transpose", _no_debe_llamarse)
    monkeypatch.setattr(ImageFile.ImageFile, "load", _no_debe_llamarse)

    motivo, salida = _reconstruir(tmp_path, entrada, "image/png")

    assert motivo == "pixeles"
    assert not salida.exists()


def test_k39_girar_no_duplica_la_copia_de_los_pixeles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`transpose` ya es la copia: añadir otra triplicaría la imagen en memoria."""
    entrada = _guardar(tmp_path, Image.new("L", (6, 2)), "PNG", exif=_exif(6))

    def _no_debe_llamarse(*_: object, **__: object) -> None:
        raise AssertionError("copia de más")

    monkeypatch.setattr(Image.Image, "copy", _no_debe_llamarse)

    motivo, _ = _reconstruir(tmp_path, entrada, "image/png")

    assert motivo is None


def test_png_animado_queda_en_un_solo_fotograma(tmp_path: Path) -> None:
    fotogramas = [Image.new("RGB", (4, 4), (i, 0, 0)) for i in (10, 200)]
    entrada = _guardar(
        tmp_path, fotogramas[0], "PNG", save_all=True, append_images=fotogramas[1:]
    )

    motivo, salida = _reconstruir(tmp_path, entrada, "image/png")

    assert motivo is None
    with Image.open(salida) as resultado:
        assert getattr(resultado, "n_frames", 1) == 1


def test_el_formato_se_exige_el_del_tipo_detectado(tmp_path: Path) -> None:
    """Un JPEG que python-magic llamó PNG no se abre con otro plugin."""
    entrada = _guardar(tmp_path, Image.new("RGB", (4, 4)), "JPEG")
    motivo, salida = _reconstruir(tmp_path, entrada, "image/png")
    assert motivo == "imagen_invalida"
    assert not salida.exists()


@pytest.mark.parametrize(
    ("contenido", "tipo"),
    [
        (b"\xff\xd8\xff\xe0basura", "image/jpeg"),
        (b"\x89PNG\r\n\x1a\nbasura", "image/png"),
    ],
    ids=["jpeg", "png"],
)
def test_firma_falsa_es_motivo_de_rechazo(
    tmp_path: Path, contenido: bytes, tipo: str
) -> None:
    entrada = tmp_path / "entrada"
    entrada.write_bytes(contenido)
    motivo, salida = _reconstruir(tmp_path, entrada, tipo)
    assert motivo == "imagen_invalida"
    assert not salida.exists()


def test_imagen_truncada_es_motivo_de_rechazo(tmp_path: Path) -> None:
    salida = io.BytesIO()
    Image.effect_noise((64, 64), 40).save(salida, "PNG")
    entrada = tmp_path / "entrada"
    entrada.write_bytes(salida.getvalue()[:-60])
    motivo, destino = _reconstruir(tmp_path, entrada, "image/png")
    assert motivo == "imagen_invalida"
    assert not destino.exists()


def test_la_salida_no_sigue_un_enlace_ni_pisa_un_archivo(tmp_path: Path) -> None:
    entrada = _guardar(tmp_path, Image.new("L", (4, 4)), "PNG")
    victima = tmp_path / "victima"
    victima.write_bytes(b"intacto")
    salida = tmp_path / "salida"
    salida.symlink_to(victima)
    with pytest.raises(OSError):
        reconstruir_imagen(entrada, salida, "image/png")
    assert victima.read_bytes() == b"intacto"
