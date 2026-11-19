"""Reconstrucción de imágenes (F3.01–F3.03, vec:04, vec:09, CDR §5).

Solo se importa dentro del proceso hijo, ya con ``RLIMIT_AS`` puesto (K31). La salida sale de
una copia de los píxeles: lo único que se conserva de la original es la transparencia, que
describe los píxeles. EXIF, ICC, texto, fragmentos privados y lo anexado se quedan atrás.

La orientación EXIF se aplica a los píxeles antes de perder el EXIF (K39): sin ella, una foto
de móvil saldría girada. La lee ``getexif()``, que, si el EXIF no la trae, también la busca en
el XMP con una expresión regular sencilla (``tiff:Orientation``, sin retroceso): el XMP
hostil sí se lee aquí, aunque solo para esa etiqueta. No se usa ``ImageOps.exif_transpose``,
que además reescribe el EXIF y el XMP recibidos después de girar: de sobra, porque aquí todo
eso se tira. Girar cambia el ancho por el alto, no el número de píxeles, así que el tope ya
validado sigue valiendo y ``transpose`` ocupa lo mismo que la copia a la que sustituye.

Antes de abrir un JPEG se cuentan sus escaneos sobre los bytes (K47): uno progresivo con miles
de escaneos vacíos ocuparía el CDR hasta el timeout. La salida no pasa de 32 MiB (K46): se
corta al escribirla.
"""

import warnings
from pathlib import Path

from PIL import Image

from api.app.cdr_jpeg import MAX_ESCANEOS, contar_escaneos
from api.app.cdr_salida import TOPE_SALIDA, SalidaDemasiadoGrande, escribir_acotado

MAX_PIXELES = 40_000_000  # param:max_pixeles_imagen
_FORMATOS = {"image/jpeg": "JPEG", "image/png": "PNG"}
_OPCIONES_DE_SALIDA: dict[str, dict[str, int]] = {
    "JPEG": {"quality": 90},  # K38
    "PNG": {
        "compress_level": 3
    },  # K37: M2 en el peor caso, a cambio de un 9 % de tamaño.
}
_TRANSPARENCIA = "transparency"
_ETIQUETA_ORIENTACION = 0x0112
_TRANSPOSICIONES = {
    2: Image.Transpose.FLIP_LEFT_RIGHT,
    3: Image.Transpose.ROTATE_180,
    4: Image.Transpose.FLIP_TOP_BOTTOM,
    5: Image.Transpose.TRANSPOSE,
    6: Image.Transpose.ROTATE_270,
    7: Image.Transpose.TRANSVERSE,
    8: Image.Transpose.ROTATE_90,
}


class _DemasiadosPixeles(Exception):
    pass


def _transposicion(imagen: Image.Image) -> Image.Transpose | None:
    """Lo que pide la orientación EXIF, o ``None`` si no pide nada o no se puede leer.

    Un EXIF ilegible no rechaza la imagen: los píxeles son válidos y el EXIF se elimina de
    todos modos. Pillow lanza de todo con un EXIF hostil, por eso el ``except`` es amplio.
    """
    try:
        return _TRANSPOSICIONES.get(imagen.getexif().get(_ETIQUETA_ORIENTACION))
    except MemoryError:
        raise
    except Exception:  # noqa: BLE001
        return None


def _leer_pixeles(entrada: Path, formato: str) -> Image.Image:
    """Abre solo con el plugin del tipo detectado y valida el tamaño antes de ``load()``."""
    with Image.open(entrada, formats=(formato,)) as imagen:
        ancho, alto = imagen.size
        if ancho * alto > MAX_PIXELES:
            raise _DemasiadosPixeles
        imagen.load()
        transposicion = _transposicion(imagen)
        limpia = (
            imagen.copy() if transposicion is None else imagen.transpose(transposicion)
        )
    transparencia = limpia.info.get(_TRANSPARENCIA)
    limpia.info = {} if transparencia is None else {_TRANSPARENCIA: transparencia}
    return limpia


def reconstruir_imagen(entrada: Path, salida: Path, tipo: str) -> str | None:
    """Escribe la imagen reconstruida. Devuelve el motivo de rechazo o ``None`` si salió bien.

    Lo que falle al **leer** es un archivo inválido: ``rechazado``. Pillow lanza de todo con
    entrada hostil (``OSError``, ``SyntaxError``, ``ValueError``, ``struct.error``...), por
    eso el ``except`` es amplio y el ``try`` tan corto. ``MemoryError`` no es culpa del
    archivo y sigue su camino hasta ``error`` (INV-09), igual que un fallo al escribir.
    """
    formato = _FORMATOS[tipo]
    # La entrada ya pasó por el tope de 10 MB de la recepción.
    if formato == "JPEG" and (
        contar_escaneos(entrada.read_bytes(), hasta=MAX_ESCANEOS) > MAX_ESCANEOS
    ):
        return "escaneos"
    Image.MAX_IMAGE_PIXELS = MAX_PIXELES
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            limpia = _leer_pixeles(entrada, formato)
    except MemoryError:
        raise
    except (
        _DemasiadosPixeles,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ):
        return "pixeles"
    except Exception:  # noqa: BLE001
        return "imagen_invalida"

    try:
        with escribir_acotado(salida, TOPE_SALIDA) as destino:
            limpia.save(destino, format=formato, **_OPCIONES_DE_SALIDA[formato])
    except SalidaDemasiadoGrande:
        return "salida_grande"
    return None
