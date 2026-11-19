"""K47: cuenta los escaneos (marcadores SOS) de un JPEG sin decodificarlo.

Cada escaneo de un JPEG progresivo recorre la imagen entera aunque no traiga datos: unas miles
de cabeceras SOS vacías ocupaban un cupo del CDR 30 s. Por eso se cuentan antes de abrir el
archivo con Pillow, sobre los bytes y con solo la biblioteca estándar.

Se recorre la estructura como lo hace libjpeg, para no contar menos que el decodificador:

- Un segmento con longitud se salta entero: un ``FF DA`` dentro de un comentario o de un APPn
  no es un escaneo.
- Tras un segmento se busca el siguiente ``FF``: así se atraviesan los datos con entropía de un
  escaneo y también los bytes sueltos que libjpeg descarta. ``FF 00`` (un FF de los datos),
  ``FF FF`` (relleno) y los marcadores sin longitud (``RSTn``, ``TEM``) no cortan la búsqueda.
- ``EOI`` termina: lo que venga después no lo lee nadie.

La búsqueda del siguiente marcador va con una expresión regular compilada, no byte a byte.
"""

import re
from collections.abc import Iterator

MAX_ESCANEOS = 64  # K47
_SOI = b"\xff\xd8"
_SOS = 0xDA
_EOI = 0xD9
# El siguiente marcador de verdad: un FF seguido de algo que no sea FF 00 (datos), TEM, SOI,
# un RSTn ni otro FF (relleno). Lo que salta la regex es lo mismo que saltaba el bucle byte a
# byte, pero en C: 10 MiB de FF costaban 1.5 s.
_MARCADOR = re.compile(rb"\xff[^\x00\x01\xd0-\xd8\xff]")


def _marcadores(datos: bytes) -> Iterator[tuple[int, int]]:
    """``(marcador, posición)`` de cada marcador con estructura, hasta ``EOI`` incluido.

    Un archivo que no empieza por SOI no da ninguno. Uno truncado da los que haya hasta el
    corte; un segmento cuya longitud no llega a leerse no se entrega.
    """
    if not datos.startswith(_SOI):
        return
    total = len(datos)
    posicion = len(_SOI)
    while (hallado := _MARCADOR.search(datos, posicion)) is not None:
        posicion = hallado.start()
        marcador = datos[posicion + 1]
        if marcador == _EOI:
            yield marcador, posicion
            return
        if posicion + 4 > total:
            return
        yield marcador, posicion
        posicion += 2 + int.from_bytes(datos[posicion + 2 : posicion + 4], "big")


def contar_escaneos(datos: bytes, hasta: int | None = None) -> int:
    """Escaneos de ``datos``. Con ``hasta``, deja de contar en cuanto lo pasa.

    Un archivo que no empieza por SOI tiene 0: no es un JPEG y Pillow lo rechazará. Uno
    truncado cuenta lo que haya hasta el corte.
    """
    escaneos = 0
    for marcador, _ in _marcadores(datos):
        if marcador == _SOS:
            escaneos += 1
            if hasta is not None and escaneos > hasta:
                break
    return escaneos


def fin_jpeg(datos: bytes) -> int | None:
    """Posición que sigue al ``EOI``, o ``None`` si no es un JPEG o no termina (K49).

    Sirve para saber dónde acaba un JPEG en línea dentro de un PDF: lo que venga después lo
    lee el lector como contenido.
    """
    for marcador, posicion in _marcadores(datos):
        if marcador == _EOI:
            return posicion + 2
    return None
