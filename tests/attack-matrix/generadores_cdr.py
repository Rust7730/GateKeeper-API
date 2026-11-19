"""Generadores para K46, K47, K49 y las referencias externas de PDF (fase A complementaria).

Todo se arma en tiempo de ejecución. Van aparte de ``generadores.py`` para no tocar lo que ya
usan las pruebas selladas.
"""

import binascii
import io
import os
import struct
import zlib

import pikepdf
from generadores import ceros_comprimidos, guardar, imagen, pdf_base
from pikepdf import Array, Dictionary, Name, String
from PIL import Image

SOS = 0xDA
EOI = 0xD9
_SIN_LARGO = {0x01, *range(0xD0, 0xD8)}  # TEM y RSTn no llevan longitud


# ------------------------------------------------------------------------------------------ JPEG


def _segmento(marcador: int, datos: bytes) -> bytes:
    return b"\xff" + bytes([marcador]) + struct.pack(">H", len(datos) + 2) + datos


def escaneos_jpeg(datos: bytes) -> list[tuple[int, int]]:
    """``(inicio, fin)`` de cada escaneo: del marcador SOS hasta el siguiente marcador real.

    Recorre la estructura: un ``FF DA`` dentro de un comentario o de datos con relleno no cuenta.
    """
    assert datos[:2] == b"\xff\xd8"
    posicion = 2
    escaneos = []
    while posicion < len(datos):
        assert datos[posicion] == 0xFF, f"se esperaba un marcador en {posicion}"
        marcador = datos[posicion + 1]
        if marcador == EOI:
            break
        if marcador in _SIN_LARGO:
            posicion += 2
            continue
        largo = struct.unpack(">H", datos[posicion + 2 : posicion + 4])[0]
        fin = posicion + 2 + largo
        if marcador == SOS:
            # Datos con entropía: termina en un FF que no va seguido de 00 ni de un RSTn.
            while not (
                datos[fin] == 0xFF
                and datos[fin + 1] != 0
                and not 0xD0 <= datos[fin + 1] <= 0xD7
            ):
                fin += 1
            escaneos.append((posicion, fin))
        posicion = fin
    return escaneos


def jpeg_progresivo(lienzo: Image.Image | None = None) -> bytes:
    salida = io.BytesIO()
    (lienzo or imagen(64, 64)).save(salida, "JPEG", quality=90, progressive=True)
    return salida.getvalue()


def jpeg_con_escaneos(total: int, lienzo: Image.Image | None = None) -> bytes:
    """JPEG progresivo con exactamente ``total`` escaneos: se repite el primero (DC).

    libjpeg lo decodifica con una advertencia de progresión, así que el archivo es legible:
    el único motivo para rechazarlo es contar los escaneos (K47).
    """
    base = jpeg_progresivo(lienzo)
    escaneos = escaneos_jpeg(base)
    faltan = total - len(escaneos)
    assert faltan >= 0, f"el progresivo base ya tiene {len(escaneos)} escaneos"
    inicio, fin = escaneos[0]
    resultado = base[:inicio] + base[inicio:fin] * faltan + base[inicio:]
    assert len(escaneos_jpeg(resultado)) == total
    return resultado


def jpeg_escaneos_vacios(extra: int, ancho: int, alto: int) -> bytes:
    """Bomba de CPU: ``extra`` cabeceras SOS sin datos. Cada una recorre la imagen entera."""
    base = jpeg_progresivo(Image.new("RGB", (ancho, alto), (9, 9, 9)))
    inicio, _ = escaneos_jpeg(base)[0]
    largo = struct.unpack(">H", base[inicio + 2 : inicio + 4])[0]
    cabecera = base[inicio : inicio + 2 + largo]
    return base[:inicio] + cabecera * extra + base[inicio:]


def jpeg_con_sos_en_comentario(repeticiones: int) -> bytes:
    """JPEG base de un solo escaneo con un comentario lleno de ``FF DA``."""
    base = io.BytesIO()
    imagen().save(base, "JPEG", quality=90)
    datos = base.getvalue()
    comentario = _segmento(0xFE, b"\xff\xda" * repeticiones)
    return datos[:2] + comentario + datos[2:]


def _esparcir(nibble: int) -> int:
    """``abcd`` -> ``0a0b0c0d``: cada bit de signo queda tras un código Huffman de un bit."""
    return sum(((nibble >> i) & 1) << (2 * i) for i in range(4))


_ALTO = bytes(_esparcir(b >> 4) for b in range(256))
_BAJO = bytes(_esparcir(b & 0x0F) for b in range(256))


def jpeg_que_crece_al_reconstruir(ancho: int = 8000, alto: int = 5000) -> bytes:
    """JPEG en grises, legítimo para libjpeg, cuya reconstrucción a calidad 90 crece casi 4 veces.

    Cuantización 255 en todo coeficiente AC y tablas Huffman de un solo símbolo: cada coeficiente
    vale ±1 y cuesta 2 bits, así que un bloque ocupa 16 bytes justos. Reconstruido (K38) cada
    bloque pasa de 64 bytes. Con 40 MP (justo el tope de píxeles) entran ~9.5 MiB y salen
    ~37.5 MiB: más que K46 aunque el CDR no tenga ningún fallo.

    Los bytes de datos nunca valen FF (máximo 0x55): no hace falta relleno.
    """
    bloques = (ancho // 8) * (alto // 8)
    azar = os.urandom(bloques * 8)
    datos = bytearray(bloques * 16)
    datos[0::2] = azar.translate(_ALTO)
    datos[1::2] = azar.translate(_BAJO)
    # Primer byte de cada bloque: dos bits del código DC (00) y tres coeficientes.
    datos[0::16] = bytes(b & 0x15 for b in datos[0::16])
    cabeceras = (
        b"\xff\xd8"
        + _segmento(0xDB, b"\x00" + b"\x01" + b"\xff" * 63)
        + _segmento(
            0xC0, b"\x08" + struct.pack(">HH", alto, ancho) + b"\x01\x01\x11\x00"
        )
        + _segmento(0xC4, b"\x00" + bytes([0, 1] + [0] * 14) + b"\x00")
        + _segmento(0xC4, b"\x10" + bytes([1] + [0] * 15) + b"\x01")
        + _segmento(SOS, b"\x01\x01\x00\x00\x3f\x00")
    )
    return cabeceras + bytes(datos) + b"\xff\xd9"


def jpeg_ruido(ancho: int, alto: int, calidad: int) -> bytes:
    """Ruido a baja calidad: legítimo y con una reconstrucción de varios MiB."""
    lienzo = Image.frombytes("RGB", (ancho, alto), os.urandom(ancho * alto * 3))
    salida = io.BytesIO()
    lienzo.save(salida, "JPEG", quality=calidad)
    return salida.getvalue()


# ------------------------------------------------------------------------------------------- PDF


def pdf_objstm_inflado(tam: int) -> bytes:
    """Hallazgo alta de la revisión: un /ObjStm de ~90 KB con una cadena de ``tam`` bytes.

    Se arma a mano con tabla de referencias en flujo, para que la cadena viva solo dentro del
    /ObjStm comprimido. Queda por debajo de K13 (100 MB) y la referencia el catálogo.
    """
    cuerpo = b"10 0 (" + b"a" * tam + b")"
    comprimido = zlib.compress(cuerpo, 9)
    objetos = {
        1: b"1 0 obj<</Type/Catalog/Pages 2 0 R/GkDatos 10 0 R>>endobj\n",
        2: b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n",
        3: b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 100 100]>>endobj\n",
        4: b"4 0 obj<</Type/ObjStm/N 1/First 5/Filter/FlateDecode/Length %d>>stream\n"
        % len(comprimido)
        + comprimido
        + b"\nendstream endobj\n",
    }
    salida = bytearray(b"%PDF-1.7\n")
    desplazamientos = {}
    for numero, objeto in objetos.items():
        desplazamientos[numero] = len(salida)
        salida += objeto
    xref = len(salida)
    filas = [b"\x00" + struct.pack(">IH", 0, 65535)]
    filas += [b"\x01" + struct.pack(">IH", desplazamientos[n], 0) for n in (1, 2, 3, 4)]
    filas += [b"\x00" + struct.pack(">IH", 0, 0)] * 5
    filas += [b"\x02" + struct.pack(">IH", 4, 0), b"\x01" + struct.pack(">IH", xref, 0)]
    tabla = b"".join(filas)
    salida += (
        b"11 0 obj<</Type/XRef/Size 12/W[1 4 2]/Root 1 0 R/Length %d>>stream\n"
        % len(tabla)
        + tabla
        + b"\nendstream endobj\nstartxref\n%d\n%%%%EOF\n" % xref
    )
    return bytes(salida)


def _con_contenido(
    pdf: pikepdf.Pdf, contenido: bytes, recursos: Dictionary | None = None
) -> None:
    pagina = pdf.pages[0]
    pagina.Contents = pdf.make_stream(contenido)
    if recursos is not None:
        pagina.Resources = recursos


def contenido_en_linea(datos: bytes, ancho: int, alto: int, filtro: bytes) -> bytes:
    """Flujo de contenido con una imagen en línea (``BI ... ID ... EI``)."""
    return (
        b"q 100 0 0 100 0 0 cm\nBI /W %d /H %d /CS /G /BPC 8 %s /L %d ID "
        % (ancho, alto, filtro, len(datos))
        + datos
        + b"\nEI Q\n"
    )


def pdf_en_linea(
    datos: bytes, ancho: int, alto: int, filtro: bytes = b"/F /Fl"
) -> bytes:
    pdf = pdf_base()
    _con_contenido(pdf, contenido_en_linea(datos, ancho, alto, filtro))
    return guardar(pdf)


def pdf_en_linea_bomba(mib: int, filtro: bytes = b"/F /Fl") -> bytes:
    """Imagen en línea de ``mib`` MiB de ceros, en grises de 8 bits: 1024 x (mib * 1024)."""
    return pdf_en_linea(ceros_comprimidos(mib), 1024, mib * 1024, filtro)


def pdf_en_linea_bomba_hex(mib: int) -> bytes:
    datos = binascii.hexlify(ceros_comprimidos(mib)) + b">"
    return pdf_en_linea(datos, 1024, mib * 1024, b"/F [/AHx /Fl]")


def pdf_en_linea_en_formulario(mib: int) -> bytes:
    """La imagen en línea va en un Form XObject, no en el contenido de la página."""
    pdf = pdf_base()
    formulario = pdf.make_stream(
        contenido_en_linea(ceros_comprimidos(mib), 1024, mib * 1024, b"/F /Fl")
    )
    formulario.Type = Name.XObject
    formulario.Subtype = Name.Form
    formulario.BBox = Array([0, 0, 100, 100])
    _con_contenido(
        pdf, b"q /GkForm Do Q\n", Dictionary(XObject=Dictionary(GkForm=formulario))
    )
    return guardar(pdf)


def pdf_en_linea_y_flujo(mib_en_linea: int, mib_en_flujo: int) -> bytes:
    """Cada parte cabe bajo el tope; la suma no. El tope de K13 es uno por PDF (K49)."""
    pdf = pdf_base()
    _con_contenido(
        pdf,
        contenido_en_linea(
            ceros_comprimidos(mib_en_linea), 1024, mib_en_linea * 1024, b"/F /Fl"
        ),
    )
    flujo = pdf.make_stream(b"")
    flujo.write(ceros_comprimidos(mib_en_flujo), filter=Name.FlateDecode)
    pdf.Root.GkDatos = pdf.make_indirect(flujo)
    return guardar(pdf)


def _imagen_xobjeto(
    pdf: pikepdf.Pdf, datos: bytes, filtros: Array | Name | None
) -> pikepdf.Stream:
    flujo = pdf.make_stream(b"")
    if filtros is None:
        flujo.write(datos)
    else:
        flujo.write(datos, filter=filtros)
    flujo.Type = Name.XObject
    flujo.Subtype = Name.Image
    flujo.Width = 64
    flujo.Height = 64
    flujo.ColorSpace = Name.DeviceRGB
    flujo.BitsPerComponent = 8
    return flujo


def _pagina_con_imagen(pdf: pikepdf.Pdf, flujo: pikepdf.Stream) -> None:
    _con_contenido(
        pdf,
        b"q 100 0 0 100 0 0 cm /GkImg Do Q\n",
        Dictionary(XObject=Dictionary(GkImg=flujo)),
    )


def jpeg_64() -> bytes:
    salida = io.BytesIO()
    imagen(64, 64).save(salida, "JPEG", quality=90)
    return salida.getvalue()


def pdf_imagen_con_filtros(datos: bytes, filtros: list[Name]) -> bytes:
    """Imagen con la cadena ``filtros`` tal cual; ``datos`` ya van codificados para ella."""
    pdf = pdf_base()
    flujo = _imagen_xobjeto(pdf, datos, None)
    flujo.Filter = Array(filtros)
    _pagina_con_imagen(pdf, flujo)
    return guardar(pdf)


# ------------------------------------------------------------------------ referencias externas


def _url(token: str) -> String:
    return String(f"http://{token}.invalid/recurso")


def pdf_flujo_externo(token: str) -> bytes:
    """Imagen cuyos datos vienen de una URL (``/F`` en el diccionario del flujo)."""
    pdf = pdf_base()
    flujo = _imagen_xobjeto(pdf, bytes(64 * 64 * 3), None)
    flujo.F = Dictionary(FS=Name.URL, F=_url(token))
    flujo.FFilter = Name.FlateDecode
    flujo.FDecodeParms = Dictionary()
    _pagina_con_imagen(pdf, flujo)
    return guardar(pdf)


def pdf_xobjeto_ref(token: str) -> bytes:
    """Form XObject de referencia: importa una página de otro PDF, aquí remoto."""
    pdf = pdf_base()
    formulario = pdf.make_stream(b"q Q\n")
    formulario.Type = Name.XObject
    formulario.Subtype = Name.Form
    formulario.BBox = Array([0, 0, 100, 100])
    formulario.Ref = Dictionary(F=Dictionary(FS=Name.URL, F=_url(token)), Page=0)
    _con_contenido(
        pdf, b"q /GkForm Do Q\n", Dictionary(XObject=Dictionary(GkForm=formulario))
    )
    return guardar(pdf)


def pdf_opi(token: str) -> bytes:
    """Imagen con ``/OPI``: la versión de alta resolución se busca en un archivo externo."""
    pdf = pdf_base()
    flujo = _imagen_xobjeto(pdf, bytes(64 * 64 * 3), None)
    flujo.OPI = Dictionary(
        {"/2.0": Dictionary(Type=Name.OPI, Version=2.0, F=_url(token))}
    )
    _pagina_con_imagen(pdf, flujo)
    return guardar(pdf)


def pdf_incrustado_en_clave_propia(token: str) -> bytes:
    """Un flujo ``/Type /EmbeddedFile`` colgado de una clave inventada, sin ``/EF``."""
    pdf = pdf_base()
    pdf.Root.GkOculto = pdf.make_stream(b"MZ" + token.encode(), Type=Name.EmbeddedFile)
    return guardar(pdf)
