"""K13: mide cuánto se descomprimen los flujos de un PDF sin pasar nunca de un tope.

Solo biblioteca estándar, para poder probarlo sin pikepdf. ``read_bytes()`` de pikepdf
descomprime entero y sin tope, así que aquí se recorre la cadena de ``/Filter`` a mano, con
generadores: cada etapa entrega bloques y el primero que agota el presupuesto corta todo.
Lo descomprimido no se conserva: solo se cuenta.

El presupuesto es por PDF y cuenta la salida de **todas** las etapas. Si solo contara la
última, una cadena de dos Flate podría gastar horas de CPU en su etapa intermedia.

Un filtro que no se conoce no se da por bueno: no se puede saber cuánto ocuparía. Los
códecs de imagen quedan fuera porque aquí no se decodifican imágenes (F3.07).
"""

import base64
import binascii
import zlib
from collections.abc import Iterable, Iterator, Sequence

MIB = 1024 * 1024
TOPE_DESCOMPRESION = 100 * MIB  # param:pdf_tope_descompresion
BLOQUE = 64 * 1024
# Múltiplo de 5: cada grupo de ASCII85 son 5 caracteres.
_BLOQUE_ASCII85 = 5 * 13_107
_BLANCOS = b"\x00\t\n\x0c\r "
_LZW_LIMPIAR = 256
_LZW_FIN = 257
_LZW_ANCHO_MAX = 12
_LZW_ENTRADAS_MAX = 1 << _LZW_ANCHO_MAX
_RL_FIN = 128

type _Trozos = Iterable[bytes]


class TopeDescompresion(Exception):
    """El PDF supera el tope de K13."""


class FiltroNoAdmitido(Exception):
    """El flujo usa un filtro que no se sabe medir."""


class FlujoInvalido(Exception):
    """Los datos no son válidos para su filtro."""


class Presupuesto:
    """Bytes que aún se pueden descomprimir en este PDF."""

    def __init__(self, tope: int = TOPE_DESCOMPRESION) -> None:
        self.restante = tope

    def gastar(self, bytes_producidos: int) -> None:
        self.restante -= bytes_producidos
        if self.restante < 0:
            raise TopeDescompresion


def _flate(trozos: _Trozos) -> Iterator[bytes]:
    descompresor = zlib.decompressobj()
    for trozo in trozos:
        pendiente = trozo
        while not descompresor.eof:
            salida = descompresor.decompress(pendiente, BLOQUE)
            if salida:
                yield salida
            pendiente = descompresor.unconsumed_tail
            # Un bloque lleno sin entrada pendiente puede dejar salida dentro de zlib.
            if not pendiente and len(salida) < BLOQUE:
                break
        if descompresor.eof:
            return


def _ascii_hex(trozos: _Trozos) -> Iterator[bytes]:
    impar = b""
    for trozo in trozos:
        digitos = impar + trozo.translate(None, _BLANCOS)
        cierre = digitos.find(b">")
        if cierre >= 0:
            digitos = digitos[:cierre]
            yield binascii.unhexlify(digitos + b"0" * (len(digitos) % 2))
            return
        corte = len(digitos) & ~1
        impar = digitos[corte:]
        yield binascii.unhexlify(digitos[:corte])
    if impar:
        yield binascii.unhexlify(impar + b"0")


def _ascii85(trozos: _Trozos) -> Iterator[bytes]:
    datos = b"".join(trozos).translate(None, _BLANCOS)
    datos = datos.partition(b"~>")[0].replace(b"z", b"!!!!!")
    for inicio in range(0, len(datos), _BLOQUE_ASCII85):
        yield base64.a85decode(datos[inicio : inicio + _BLOQUE_ASCII85])


def _run_length(trozos: _Trozos) -> Iterator[bytes]:
    datos = b"".join(trozos)
    salida = bytearray()
    posicion = 0
    while posicion < len(datos) and datos[posicion] != _RL_FIN:
        longitud = datos[posicion]
        if longitud < _RL_FIN:
            salida += datos[posicion + 1 : posicion + 2 + longitud]
            posicion += longitud + 2
        else:
            salida += datos[posicion + 1 : posicion + 2] * (257 - longitud)
            posicion += 2
        if len(salida) >= BLOQUE:
            yield bytes(salida)
            salida.clear()
    yield bytes(salida)


def _lzw(trozos: _Trozos, cambio_temprano: int) -> Iterator[bytes]:
    """LZW de PDF: MSB primero, códigos de 9 a 12 bits."""
    tabla = [bytes((valor,)) for valor in range(256)] + [b"", b""]
    base = len(tabla)
    ancho = 9
    acumulado = bits = 0
    previo: bytes | None = None
    salida = bytearray()

    for trozo in trozos:
        for byte in trozo:
            acumulado = (acumulado << 8) | byte
            bits += 8
            if bits < ancho:
                continue
            bits -= ancho
            codigo = acumulado >> bits
            acumulado &= (1 << bits) - 1

            if codigo == _LZW_FIN:
                yield bytes(salida)
                return
            if codigo == _LZW_LIMPIAR:
                del tabla[base:]
                ancho, previo = 9, None
                continue
            if codigo < len(tabla):
                entrada = tabla[codigo]
                nueva = None if previo is None else previo + entrada[:1]
            elif previo is not None and codigo == len(tabla):
                entrada = nueva = previo + previo[:1]
            else:
                raise FlujoInvalido
            if nueva is not None and len(tabla) < _LZW_ENTRADAS_MAX:
                tabla.append(nueva)
            previo = entrada
            salida += entrada
            if len(tabla) + cambio_temprano >= (1 << ancho) and ancho < _LZW_ANCHO_MAX:
                ancho += 1
            if len(salida) >= BLOQUE:
                yield bytes(salida)
                salida.clear()
    yield bytes(salida)


_DECODIFICADORES = {
    "/FlateDecode": _flate,
    "/Fl": _flate,
    "/ASCIIHexDecode": _ascii_hex,
    "/AHx": _ascii_hex,
    "/ASCII85Decode": _ascii85,
    "/A85": _ascii85,
    "/RunLengthDecode": _run_length,
    "/RL": _run_length,
}
_LZW = frozenset({"/LZWDecode", "/LZW"})
_CODECS_DE_IMAGEN = frozenset(
    {
        "/DCTDecode",
        "/DCT",
        "/JPXDecode",
        "/CCITTFaxDecode",
        "/CCF",
        "/JBIG2Decode",
    }
)


def _contar(trozos: _Trozos, presupuesto: Presupuesto) -> Iterator[bytes]:
    for trozo in trozos:
        presupuesto.gastar(len(trozo))
        yield trozo


def medir_flujo(
    crudo: bytes,
    filtros: Sequence[str],
    presupuesto: Presupuesto,
    *,
    cambio_temprano: Sequence[int] = (),
) -> None:
    """Recorre la cadena de filtros de un flujo y gasta del presupuesto.

    ``cambio_temprano`` es el ``/EarlyChange`` de cada filtro, en el mismo orden; lo que
    falte vale 1, como en la especificación de PDF. Lanza ``TopeDescompresion``,
    ``FiltroNoAdmitido`` o ``FlujoInvalido``.
    """
    etapa: _Trozos = (crudo,)
    for indice, filtro in enumerate(filtros):
        if filtro in _CODECS_DE_IMAGEN:
            break
        if filtro in _LZW:
            temprano = cambio_temprano[indice] if indice < len(cambio_temprano) else 1
            etapa = _contar(_lzw(etapa, temprano), presupuesto)
        elif filtro in _DECODIFICADORES:
            etapa = _contar(_DECODIFICADORES[filtro](etapa), presupuesto)
        else:
            raise FiltroNoAdmitido

    invalido = False
    try:
        for _ in etapa:
            pass
    # binascii.Error es ValueError; a85decode lanza ValueError.
    except (zlib.error, ValueError):
        invalido = True
    if invalido:
        raise FlujoInvalido
