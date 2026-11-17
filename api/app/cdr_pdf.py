"""Saneamiento estructural de PDF (F3.04–F3.07, K13, vec:05, vec:06, CDR §5).

Solo se importa dentro del proceso hijo, ya con ``RLIMIT_AS`` puesto (K31).

- **Orden:** primero las políticas que rechazan (cifrado, páginas, K13) y después los
  cambios. K13 recorre todos los flujos del archivo, también los que nada referencia.
- **Contenido activo:** se recorre todo el documento y no solo el catálogo. Una acción
  puede colgar de ``/Outlines``, de un nodo intermedio de ``/Pages``, de ``/Next`` o de una
  clave inventada. Lo que queda sin referencia lo descarta qpdf al escribir.
- **Referencias externas (F3.04):** un flujo con ``/F`` toma sus datos de otro archivo o de
  una URL; ``/Ref`` y ``/OPI`` apuntan también fuera. Se quitan, igual que todo flujo
  ``/Type /EmbeddedFile``, cuelgue de la clave que cuelgue.
- **Imágenes en línea (K49):** ``BI ... ID ... EI`` va dentro de un flujo de contenido, así que
  K13 solo vería el contenido. Se miden con el mismo presupuesto. Parsear el contenido es caro
  (~70 ms en 200 páginas de texto), así que solo se parsea si su salida contiene ``BI`` o si no
  se puede saber (predictor o códec de imagen). Son contenido: las páginas, los Form XObject,
  los patrones de mosaico y los glifos de Type3. Además, los datos de cada imagen en línea
  tienen que acabar donde los corta qpdf (``_comprobar_en_linea``): si no, el lector ve como
  contenido, y quizá como otra imagen, lo que qpdf tomó por datos.
- **Flujos:** se copian sin decodificar (``StreamDecodeLevel.none``). Decodificarlos al
  guardar sería la descompresión sin tope que prohíbe K13, y además costaría tiempo. Los que no
  traen filtro, y los ``/ObjStm`` que qpdf reescribe, se comprimen: sin eso, 92 KB salían
  como 95 MB (K46). La salida no pasa de 32 MiB (K46): se corta al escribir.

Limitaciones declaradas: las imágenes embebidas no se recodifican (F3.07, propuesto). Lo que
qpdf lee por su cuenta (``/ObjStm``, ``/XRef``) no se mide aquí antes de abrir: si agotara la
memoria, ``RLIMIT_AS`` termina en ``error``.
"""

import math
import re
from collections.abc import Iterator
from pathlib import Path

import pikepdf

from api.app.cdr_flujos import (
    FiltroNoAdmitido,
    FlujoInvalido,
    Presupuesto,
    TopeDescompresion,
    medir_en_linea,
    medir_flujo,
)
from api.app.cdr_salida import TOPE_SALIDA, SalidaDemasiadoGrande, escribir_acotado

MAX_PAGINAS = 200  # param:max_paginas_pdf

# docs/decisiones.md §5 y F3.04. Se quitan estén donde estén, con todo lo que cuelga de ellas.
_CLAVES_ACTIVAS = frozenset(
    {
        "/AA",
        "/AcroForm",
        "/Annots",
        "/EF",
        "/EmbeddedFiles",
        "/JS",
        "/JavaScript",
        "/Launch",
        "/Metadata",
        "/Names",
        "/OPI",
        "/OpenAction",
        "/Ref",
        "/SubmitForm",
        "/URI",
    }
)
# Solo en un flujo: ahí ``/F`` es un archivo externo con los datos. En otro diccionario es otra
# cosa (los indicadores de una anotación, por ejemplo).
_CLAVES_DE_FLUJO_EXTERNO = frozenset({"/F", "/FFilter", "/FDecodeParms"})
# Operadores que pide el parseo del contenido: solo las imágenes en línea, para que qpdf no
# guarde en memoria el resto de las instrucciones.
_OPERADORES_EN_LINEA = "BI ID EI"
_INICIO_EN_LINEA = b"BI"
_BLANCOS = b"\x00\t\n\x0c\r "
# Un `EI` como token: entre blancos, o seguido de un delimitador o del final. Dentro de los datos
# de una imagen, un lector que corte en el primer `EI` (pdf.js, por ejemplo) vería otra cosa.
_EI_EN_LOS_DATOS = re.compile(
    rb"[\x00\t\n\x0c\r ]EI(?=[\x00\t\n\x0c\r ()<>\[\]{}/%]|\Z)"
)
# Componentes de cada espacio de color que se resuelve sin los recursos de la página.
_COMPONENTES = {
    "/DeviceGray": 1,
    "/CalGray": 1,
    "/Indexed": 1,
    "/DeviceRGB": 3,
    "/CalRGB": 3,
    "/Lab": 3,
    "/DeviceCMYK": 4,
}
_PREDICTOR_PNG = 10
# Valores de `/S` en una acción (ISO 32000-2, 12.6.4). Un diccionario con `/S` no siempre lo
# es: `/S /Transparency` en `/Group` no se toca. `/GoTo` también se quita, porque puede
# llevar colgada la acción peligrosa de `/Next`.
_TIPOS_DE_ACCION = frozenset(
    {
        "/GoTo",
        "/GoTo3DView",
        "/GoToDp",
        "/GoToE",
        "/GoToR",
        "/Hide",
        "/ImportData",
        "/JavaScript",
        "/Launch",
        "/Movie",
        "/Named",
        "/Rendition",
        "/ResetForm",
        "/RichMediaExecute",
        "/SetOCGState",
        "/Sound",
        "/SubmitForm",
        "/Thread",
        "/Trans",
        "/URI",
    }
)


def _filtros(flujo: pikepdf.Stream) -> list[str]:
    filtro = flujo.get("/Filter")
    if filtro is None:
        return []
    nombres = []
    for elemento in filtro if isinstance(filtro, pikepdf.Array) else [filtro]:
        if not isinstance(elemento, pikepdf.Name):
            raise FlujoInvalido
        nombres.append(str(elemento))
    return nombres


def _parametros(flujo: pikepdf.Object) -> list[object]:
    parametros = flujo.get("/DecodeParms")
    return list(parametros) if isinstance(parametros, pikepdf.Array) else [parametros]


def _cambios_tempranos(flujo: pikepdf.Object) -> list[int]:
    """``/EarlyChange`` de cada filtro: sin él, los códigos de LZW se leerían mal."""
    cambios = []
    for elemento in _parametros(flujo):
        valor = 1
        if isinstance(elemento, pikepdf.Dictionary):
            valor = elemento.get("/EarlyChange", 1)
        cambios.append(0 if valor == 0 else 1)
    return cambios


def _con_predictor(flujo: pikepdf.Stream) -> bool:
    """Con predictor, la salida de los filtros no es aún lo que lee el lector."""
    return any(
        isinstance(elemento, pikepdf.Dictionary) and "/Predictor" in elemento
        for elemento in _parametros(flujo)
    )


def _medir(
    flujo: pikepdf.Object,
    crudo: bytes,
    presupuesto: Presupuesto,
    buscar: bytes | None = None,
) -> bool:
    return medir_flujo(
        crudo,
        _filtros(flujo),
        presupuesto,
        cambio_temprano=_cambios_tempranos(flujo),
        buscar=buscar,
    )


def _recorrer(pdf: pikepdf.Pdf) -> Iterator[pikepdf.Object]:
    """Cada diccionario, flujo y array del documento, también los directos anidados.

    Los hijos se miran después de entregar el objeto: lo que quien recorre borre de él ya no
    se visita. Con una pila y no con recursión: la profundidad la decide quien escribió el
    archivo. Los indirectos no se siguen aquí: ya salen de ``pdf.objects``, y seguirlos
    repetiría trabajo y entraría en los ciclos de ``/Parent``.
    """
    pendientes: list[pikepdf.Object] = [*pdf.objects, pdf.trailer]
    while pendientes:
        objeto = pendientes.pop()
        if isinstance(objeto, pikepdf.Array):
            yield objeto
            pendientes.extend(v for v in objeto if _es_contenedor_directo(v))
        elif isinstance(objeto, pikepdf.Dictionary | pikepdf.Stream):
            yield objeto
            pendientes.extend(
                objeto[clave]
                for clave in list(objeto.keys())
                if _es_contenedor_directo(objeto[clave])
            )


type _Contenido = tuple[pikepdf.Page | pikepdf.Stream, list[pikepdf.Stream]]


def _contenidos(pdf: pikepdf.Pdf) -> list[_Contenido]:
    """Lo que un lector interpreta como instrucciones: qué se parsea y con qué flujos.

    Una página se parsea entera porque una imagen en línea puede empezar en un flujo de su
    ``/Contents`` y seguir en el siguiente.
    """
    contenidos: list[_Contenido] = []
    for pagina in pdf.pages:
        contenido = pagina.obj.get("/Contents")
        lista = contenido if isinstance(contenido, pikepdf.Array) else [contenido]
        flujos = [flujo for flujo in lista if isinstance(flujo, pikepdf.Stream)]
        if flujos:
            contenidos.append((pagina, flujos))
    for objeto in _recorrer(pdf):
        if isinstance(objeto, pikepdf.Array):
            continue
        if isinstance(objeto, pikepdf.Stream) and (
            objeto.get("/Subtype") == pikepdf.Name.Form
            or objeto.get("/PatternType") == 1
        ):
            contenidos.append((objeto, [objeto]))
        glifos = objeto.get("/CharProcs")
        if isinstance(glifos, pikepdf.Dictionary):
            contenidos.extend(
                (glifo, [glifo])
                for glifo in glifos.values()
                if isinstance(glifo, pikepdf.Stream)
            )
    return contenidos


def _componentes(diccionario: pikepdf.Dictionary) -> int | None:
    """Componentes por píxel, o ``None`` si hacen falta los recursos de la página."""
    if diccionario.get("/ImageMask") is True:
        return 1
    espacio = diccionario.get("/ColorSpace")
    if isinstance(espacio, pikepdf.Array) and len(espacio) > 0:
        espacio = espacio[0]
    if not isinstance(espacio, pikepdf.Name):
        return None
    return _COMPONENTES.get(str(espacio))


def _bytes_de_imagen(diccionario: pikepdf.Dictionary) -> int | None:
    """Lo que lee un lector de una imagen sin filtro: ceil(W·BPC·n/8)·H. ``None`` si no se sabe."""
    ancho, alto = diccionario.get("/Width"), diccionario.get("/Height")
    mascara = diccionario.get("/ImageMask") is True
    bits = 1 if mascara else diccionario.get("/BitsPerComponent")
    componentes = _componentes(diccionario)
    valores = (ancho, alto, bits)
    if componentes is None or not all(type(v) is int and v > 0 for v in valores):
        return None
    return math.ceil(ancho * bits * componentes / 8) * alto


def _holgura_de_predictor(diccionario: pikepdf.Dictionary) -> int:
    """Con predictor PNG cada fila lleva un byte más que la imagen."""
    alto = diccionario.get("/Height")
    for parametros in _parametros(diccionario):
        if isinstance(parametros, pikepdf.Dictionary):
            predictor = parametros.get("/Predictor", 1)
            if type(predictor) is int and predictor >= _PREDICTOR_PNG:
                return alto if type(alto) is int else 0
    return 0


def _comprobar_en_linea(
    diccionario: pikepdf.Dictionary, crudo: bytes, presupuesto: Presupuesto
) -> None:
    """Una imagen en línea: la mide y exige que acabe donde la cortó qpdf (K49).

    qpdf y los lectores cortan los datos en sitios distintos: qpdf salta un ``EI`` seguido de
    un token inválido; poppler lee lo que pide la imagen y corta ahí. Lo que haya entre los
    dos puntos es contenido para el lector e invisible para qpdf, otra imagen incluida. Por
    eso, tras el fin real de los datos solo puede haber blancos:

    - Sin filtro, el fin es exactamente ceil(W·BPC·n/8)·H bytes. Si el espacio de color no
      se resuelve aquí, no se sabe: se rechaza.
    - Con filtro, el fin lo marca el primer filtro (``medir_en_linea``). Si además se sabe el
      tamaño, la cadena no puede producir más: el lector dejaría de leer a mitad del filtro y
      buscaría ``EI`` en los bytes que quedan.
    """
    if _EI_EN_LOS_DATOS.search(crudo):
        raise FlujoInvalido
    filtros = _filtros(diccionario)
    necesarios = _bytes_de_imagen(diccionario)
    if not filtros:
        if necesarios is None or len(crudo) < necesarios:
            raise FlujoInvalido
        if crudo[necesarios:].translate(None, _BLANCOS):
            raise FlujoInvalido
        return
    producidos = medir_en_linea(
        crudo,
        filtros,
        presupuesto,
        cambio_temprano=_cambios_tempranos(diccionario),
    )
    if (
        producidos is not None
        and necesarios is not None
        and producidos > necesarios + _holgura_de_predictor(diccionario)
    ):
        raise FlujoInvalido


def _medir_en_linea(
    objetivo: pikepdf.Page | pikepdf.Stream, presupuesto: Presupuesto
) -> None:
    """Gasta del presupuesto lo que descomprimen las imágenes en línea de ``objetivo``.

    pikepdf ya expande las abreviaturas (``/F /Fl`` es ``/Filter /FlateDecode``). Lo que no
    sepa interpretar de una imagen en línea es un archivo inválido.
    """
    for instruccion in pikepdf.parse_content_stream(objetivo, _OPERADORES_EN_LINEA):
        if not isinstance(instruccion, pikepdf.ContentStreamInlineImage):
            continue
        try:
            imagen = instruccion.iimage
            diccionario, crudo = imagen.obj, imagen.read_raw_bytes()
        except MemoryError:
            raise
        except Exception:  # noqa: BLE001
            raise FlujoInvalido from None
        _comprobar_en_linea(diccionario, crudo, presupuesto)


def _comprobar_flujos(pdf: pikepdf.Pdf) -> None:
    """K13 sobre todos los flujos y K49 sobre las imágenes en línea, con un solo presupuesto."""
    presupuesto = Presupuesto()
    contenidos = _contenidos(pdf)
    de_contenido = {flujo.objgen for _, flujos in contenidos for flujo in flujos}
    por_parsear: set[tuple[int, int]] = set()
    for objeto in pdf.objects:
        if not isinstance(objeto, pikepdf.Stream):
            continue
        if objeto.objgen not in de_contenido:
            _medir(objeto, objeto.read_raw_bytes(), presupuesto)
        elif _medir(
            objeto, objeto.read_raw_bytes(), presupuesto, _INICIO_EN_LINEA
        ) or _con_predictor(objeto):
            por_parsear.add(objeto.objgen)
    for objetivo, flujos in contenidos:
        if any(flujo.objgen in por_parsear for flujo in flujos):
            _medir_en_linea(objetivo, presupuesto)


def _es_accion(valor: object) -> bool:
    if not isinstance(valor, pikepdf.Dictionary | pikepdf.Stream):
        return False
    subtipo = valor.get("/S")
    return valor.get("/Type") == pikepdf.Name.Action or (
        isinstance(subtipo, pikepdf.Name) and str(subtipo) in _TIPOS_DE_ACCION
    )


def _es_contenedor_directo(valor: object) -> bool:
    # Los indirectos se visitan desde `pdf.objects`: seguirlos aquí repetiría trabajo y
    # entraría en los ciclos de `/Parent`.
    return (
        isinstance(valor, pikepdf.Array | pikepdf.Dictionary) and not valor.is_indirect
    )


def _es_incrustado(valor: object) -> bool:
    return (
        isinstance(valor, pikepdf.Stream)
        and valor.get("/Type") == pikepdf.Name.EmbeddedFile
    )


def _quitar(valor: object) -> bool:
    return _es_accion(valor) or _es_incrustado(valor)


def _limpiar_claves(objeto: pikepdf.Object) -> None:
    externas = (
        _CLAVES_DE_FLUJO_EXTERNO if isinstance(objeto, pikepdf.Stream) else frozenset()
    )
    for clave in list(objeto.keys()):
        if clave in _CLAVES_ACTIVAS or clave in externas or _quitar(objeto[clave]):
            del objeto[clave]


def _limpiar_lista(lista: pikepdf.Array) -> None:
    for indice in reversed(range(len(lista))):
        if _quitar(lista[indice]):
            del lista[indice]


def _eliminar_contenido_activo(pdf: pikepdf.Pdf) -> None:
    """Quita las claves activas, las referencias externas y las acciones (F3.04, F3.05)."""
    if "/Info" in pdf.trailer:
        del pdf.trailer["/Info"]
    for objeto in _recorrer(pdf):
        if isinstance(objeto, pikepdf.Array):
            _limpiar_lista(objeto)
        else:
            _limpiar_claves(objeto)


def _guardar(pdf: pikepdf.Pdf, salida: Path) -> None:
    with escribir_acotado(salida, TOPE_SALIDA) as destino:
        pdf.save(
            destino,
            stream_decode_level=pikepdf.StreamDecodeLevel.none,
            compress_streams=True,
            fix_metadata_version=False,
        )


def sanear_pdf(entrada: Path, salida: Path) -> str | None:
    """Escribe el PDF saneado. Devuelve el motivo de rechazo o ``None`` si salió bien.

    Un PDF que pide contraseña o que qpdf no entiende es ``rechazado``, no un fallo del
    análisis. ``MemoryError`` y un fallo del disco siguen su camino hasta ``error`` (INV-09).
    """
    try:
        documento = pikepdf.open(entrada)
    except pikepdf.PasswordError:
        return "pdf_cifrado"
    except pikepdf.PdfError:
        return "pdf_invalido"

    with documento as pdf:
        # Se comprueba después de abrir: el que solo tiene contraseña de propietario abre
        # sin ella, y aun así se rechaza (vec:06).
        if pdf.is_encrypted:
            return "pdf_cifrado"
        try:
            if len(pdf.pages) > MAX_PAGINAS:
                return "paginas"
            _comprobar_flujos(pdf)
            _eliminar_contenido_activo(pdf)
            _guardar(pdf, salida)
        except TopeDescompresion:
            return "descompresion"
        except SalidaDemasiadoGrande:
            return "salida_grande"
        except (FiltroNoAdmitido, FlujoInvalido):
            return "flujo_invalido"
        # Un nombre es de bytes y `str()` falla si no son UTF-8. Solo se convierte `/S` y
        # `/Filter`: si no se pueden leer, no se puede decidir sobre ellos.
        except (pikepdf.PdfError, UnicodeDecodeError):
            return "pdf_invalido"
    return None
