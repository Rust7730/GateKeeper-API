"""K13: mide cuánto se descomprimen los flujos de un PDF sin pasar nunca de un tope.

Solo biblioteca estándar (y ``cdr_jpeg``, que tampoco usa más), para poder probarlo sin
pikepdf. ``read_bytes()`` de pikepdf
descomprime entero y sin tope, así que aquí se recorre la cadena de ``/Filter`` a mano, con
generadores: cada etapa entrega bloques y el primero que agota el presupuesto corta todo.
Lo descomprimido no se conserva: solo se cuenta.

El presupuesto es por PDF y cuenta la salida de **todas** las etapas. Si solo contara la
última, una cadena de dos Flate podría gastar horas de CPU en su etapa intermedia.

Un filtro que no se conoce no se da por bueno: no se puede saber cuánto ocuparía. Los
códecs de imagen quedan fuera porque aquí no se decodifican imágenes (F3.07), y por eso solo
se admiten como última etapa: un filtro detrás de un códec no se puede medir sin decodificarlo
(K49).

``buscar`` dice si un texto aparece en la salida, mirando los mismos bloques que se cuentan:
así el CDR sabe, sin descomprimir dos veces, si un flujo de contenido puede llevar imágenes en
línea (K49).
"""

import base64
import binascii
import zlib
from collections.abc import Iterable, Iterator, Sequence

from api.app.cdr_jpeg import fin_jpeg

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


class _Resto:
    """Lo que queda del crudo tras el fin de datos del filtro; ``None`` si no llegó a él.

    Solo se anota en la primera etapa, la que lee el crudo (K49). Se anota antes de entregar
    el último bloque: la etapa siguiente puede no volver a pedir.
    """

    __slots__ = ("datos",)

    def __init__(self) -> None:
        self.datos: bytes | None = None


def _flate(trozos: _Trozos, resto: _Resto | None = None) -> Iterator[bytes]:
    descompresor = zlib.decompressobj()
    iterador = iter(trozos)
    for trozo in iterador:
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
            if resto is not None:
                resto.datos = descompresor.unused_data + b"".join(iterador)
            return


def _ascii_hex(trozos: _Trozos, resto: _Resto | None = None) -> Iterator[bytes]:
    impar = b""
    iterador = iter(trozos)
    for trozo in iterador:
        digitos = impar + trozo.translate(None, _BLANCOS)
        cierre = digitos.find(b">")
        if cierre >= 0:
            if resto is not None:
                resto.datos = trozo[trozo.find(b">") + 1 :] + b"".join(iterador)
            digitos = digitos[:cierre]
            yield binascii.unhexlify(digitos + b"0" * (len(digitos) % 2))
            return
        corte = len(digitos) & ~1
        impar = digitos[corte:]
        yield binascii.unhexlify(digitos[:corte])
    if impar:
        yield binascii.unhexlify(impar + b"0")


def _ascii85(trozos: _Trozos, resto: _Resto | None = None) -> Iterator[bytes]:
    crudo = b"".join(trozos)
    datos, cierre, despues = crudo.partition(b"~>")
    if resto is not None and cierre:
        resto.datos = despues
    datos = datos.translate(None, _BLANCOS).replace(b"z", b"!!!!!")
    for inicio in range(0, len(datos), _BLOQUE_ASCII85):
        yield base64.a85decode(datos[inicio : inicio + _BLOQUE_ASCII85])


def _run_length(trozos: _Trozos, resto: _Resto | None = None) -> Iterator[bytes]:
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
    if resto is not None and posicion < len(datos):
        resto.datos = datos[posicion + 1 :]
    yield bytes(salida)


def _lzw(
    trozos: _Trozos, cambio_temprano: int, resto: _Resto | None = None
) -> Iterator[bytes]:
    """LZW de PDF: MSB primero, códigos de 9 a 12 bits."""
    tabla = [bytes((valor,)) for valor in range(256)] + [b"", b""]
    base = len(tabla)
    ancho = 9
    acumulado = bits = 0
    previo: bytes | None = None
    salida = bytearray()

    iterador = iter(trozos)
    for trozo in iterador:
        for indice, byte in enumerate(trozo):
            acumulado = (acumulado << 8) | byte
            bits += 8
            if bits < ancho:
                continue
            bits -= ancho
            codigo = acumulado >> bits
            acumulado &= (1 << bits) - 1

            if codigo == _LZW_FIN:
                if resto is not None:
                    resto.datos = trozo[indice + 1 :] + b"".join(iterador)
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
_DCT = frozenset({"/DCTDecode", "/DCT"})
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


def _cadena(
    crudo: bytes,
    filtros: Sequence[str],
    presupuesto: Presupuesto,
    cambio_temprano: Sequence[int],
    resto: _Resto | None = None,
) -> tuple[_Trozos, bool]:
    """Los generadores de la cadena, y si acaba en un códec de imagen (que no se decodifica).

    ``resto`` se le pasa solo a la primera etapa.
    """
    etapa: _Trozos = (crudo,)
    for indice, filtro in enumerate(filtros):
        anotar = resto if indice == 0 else None
        if filtro in _CODECS_DE_IMAGEN:
            if indice != len(filtros) - 1:
                raise FiltroNoAdmitido
            return etapa, True
        if filtro in _LZW:
            temprano = cambio_temprano[indice] if indice < len(cambio_temprano) else 1
            etapa = _contar(_lzw(etapa, temprano, anotar), presupuesto)
        elif filtro in _DECODIFICADORES:
            etapa = _contar(_DECODIFICADORES[filtro](etapa, anotar), presupuesto)
        else:
            raise FiltroNoAdmitido
    return etapa, False


def _buscar(trozos: _Trozos, texto: bytes) -> bool:
    """Si ``texto`` aparece en la concatenación de ``trozos``, sin juntarlos.

    Se guarda la cola del trozo anterior: el texto puede quedar partido entre dos bloques.
    """
    cola = b""
    hallado = False
    for trozo in trozos:
        if not hallado:
            hallado = texto in cola + trozo[: len(texto) - 1] or texto in trozo
            cola = trozo[-(len(texto) - 1) :] if len(texto) > 1 else b""
    return hallado


def _recorrer_cadena(etapa: _Trozos, buscar: bytes | None) -> tuple[int, bool]:
    """Consume la cadena: bytes de la última etapa y si ``buscar`` apareció en ellos."""
    invalido = False
    producidos = 0
    hallado = False
    try:
        if buscar is None:
            for trozo in etapa:
                producidos += len(trozo)
        else:
            hallado = _buscar(etapa, buscar)
    # binascii.Error es ValueError; a85decode lanza ValueError.
    except (zlib.error, ValueError):
        invalido = True
    if invalido:
        raise FlujoInvalido
    return producidos, hallado


def medir_flujo(
    crudo: bytes,
    filtros: Sequence[str],
    presupuesto: Presupuesto,
    *,
    cambio_temprano: Sequence[int] = (),
    buscar: bytes | None = None,
) -> bool:
    """Recorre la cadena de filtros de un flujo y gasta del presupuesto.

    ``cambio_temprano`` es el ``/EarlyChange`` de cada filtro, en el mismo orden; lo que
    falte vale 1, como en la especificación de PDF. Lanza ``TopeDescompresion``,
    ``FiltroNoAdmitido`` o ``FlujoInvalido``.

    Devuelve si ``buscar`` aparece en la salida. Con un códec de imagen al final la salida
    real no se conoce y devuelve ``True``: quien pregunta debe mirar el flujo de otro modo.
    Sin ``buscar``, ``False``.
    """
    etapa, con_codec = _cadena(crudo, filtros, presupuesto, cambio_temprano)
    _, hallado = _recorrer_cadena(etapa, buscar)
    return buscar is not None and (con_codec or hallado)


def _exigir_solo_blancos(datos: bytes) -> None:
    if datos.translate(None, _BLANCOS):
        raise FlujoInvalido


def medir_en_linea(
    crudo: bytes,
    filtros: Sequence[str],
    presupuesto: Presupuesto,
    *,
    cambio_temprano: Sequence[int] = (),
) -> int | None:
    """Mide una imagen en línea con filtros y comprueba que sus datos acaban donde dice qpdf.

    qpdf corta los datos en un ``EI`` elegido con una heurística; un lector como poppler los
    corta donde acaba el primer filtro (fin de zlib, ``>``, ``~>``, el 128 de RunLength, el
    257 de LZW, el ``EOI`` de un JPEG) y toma lo que sigue por contenido. Si tras ese fin
    queda algo que no sea blanco, los dos leen cosas distintas: ``FlujoInvalido``. También si
    el primer filtro no llega a su fin. ``/CCITTFaxDecode``, JPX y JBIG2 no marcan su fin:
    ``FiltroNoAdmitido``.

    Devuelve los bytes que produce la cadena, o ``None`` si acaba en un códec de imagen.
    ``filtros`` no puede estar vacío: sin filtro, el fin lo da el tamaño de la imagen.
    """
    primero = filtros[0]
    if primero in _CODECS_DE_IMAGEN:
        if primero not in _DCT or len(filtros) > 1:
            raise FiltroNoAdmitido
        fin = fin_jpeg(crudo)
        if fin is None:
            raise FlujoInvalido
        _exigir_solo_blancos(crudo[fin:])
        return None
    resto = _Resto()
    etapa, con_codec = _cadena(crudo, filtros, presupuesto, cambio_temprano, resto)
    producidos, _ = _recorrer_cadena(etapa, None)
    if resto.datos is None:
        raise FlujoInvalido
    _exigir_solo_blancos(resto.datos)
    return None if con_codec else producidos
