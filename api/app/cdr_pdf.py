"""Saneamiento estructural de PDF (F3.04–F3.07, K13, vec:05, vec:06, CDR §5).

Solo se importa dentro del proceso hijo, ya con ``RLIMIT_AS`` puesto (K31).

- **Orden:** primero las políticas que rechazan (cifrado, páginas, K13) y después los
  cambios. K13 recorre todos los flujos del archivo, también los que nada referencia.
- **Contenido activo:** se recorre todo el documento y no solo el catálogo. Una acción
  puede colgar de ``/Outlines``, de un nodo intermedio de ``/Pages``, de ``/Next`` o de una
  clave inventada. Lo que queda sin referencia lo descarta qpdf al escribir.
- **Flujos:** se copian sin decodificar (``StreamDecodeLevel.none``). Decodificarlos al
  guardar sería la descompresión sin tope que prohíbe K13, y además costaría tiempo.

Limitaciones declaradas: las imágenes embebidas no se recodifican (F3.07, propuesto) y K13 no
ve las imágenes en línea de un flujo de contenido (``BI ... ID``): su filtro va dentro de datos
que aquí no se interpretan. Lo que qpdf lee por su cuenta (``/ObjStm``, ``/XRef``) no se mide
aquí antes de abrir: si agotara la memoria, ``RLIMIT_AS`` termina en ``error``.
"""

from pathlib import Path

import pikepdf

from api.app.cdr_flujos import (
    FiltroNoAdmitido,
    FlujoInvalido,
    Presupuesto,
    TopeDescompresion,
    medir_flujo,
)

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
        "/OpenAction",
        "/SubmitForm",
        "/URI",
    }
)
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


def _cambios_tempranos(flujo: pikepdf.Stream) -> list[int]:
    """``/EarlyChange`` de cada filtro: sin él, los códigos de LZW se leerían mal."""
    parametros = flujo.get("/DecodeParms")
    lista = parametros if isinstance(parametros, pikepdf.Array) else [parametros]
    cambios = []
    for elemento in lista:
        valor = 1
        if isinstance(elemento, pikepdf.Dictionary):
            valor = elemento.get("/EarlyChange", 1)
        cambios.append(0 if valor == 0 else 1)
    return cambios


def _comprobar_flujos(pdf: pikepdf.Pdf) -> None:
    presupuesto = Presupuesto()
    for objeto in pdf.objects:
        if isinstance(objeto, pikepdf.Stream):
            medir_flujo(
                objeto.read_raw_bytes(),
                _filtros(objeto),
                presupuesto,
                cambio_temprano=_cambios_tempranos(objeto),
            )


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


def _limpiar_claves(objeto: pikepdf.Object, pendientes: list[pikepdf.Object]) -> None:
    for clave in list(objeto.keys()):
        valor = objeto[clave]
        if clave in _CLAVES_ACTIVAS or _es_accion(valor):
            del objeto[clave]
        elif _es_contenedor_directo(valor):
            pendientes.append(valor)


def _limpiar_lista(lista: pikepdf.Array, pendientes: list[pikepdf.Object]) -> None:
    for indice in reversed(range(len(lista))):
        valor = lista[indice]
        if _es_accion(valor):
            del lista[indice]
        elif _es_contenedor_directo(valor):
            pendientes.append(valor)


def _eliminar_contenido_activo(pdf: pikepdf.Pdf) -> None:
    """Quita las claves activas y las acciones de todo el documento (F3.04, F3.05).

    Con una pila y no con recursión: la profundidad la decide quien escribió el archivo.
    """
    if "/Info" in pdf.trailer:
        del pdf.trailer["/Info"]
    pendientes: list[pikepdf.Object] = [*pdf.objects, pdf.trailer]
    while pendientes:
        objeto = pendientes.pop()
        if isinstance(objeto, pikepdf.Array):
            _limpiar_lista(objeto, pendientes)
        elif isinstance(objeto, pikepdf.Dictionary | pikepdf.Stream):
            _limpiar_claves(objeto, pendientes)


def _guardar(pdf: pikepdf.Pdf, salida: Path) -> None:
    # "xb": crea el archivo y falla si ya existe, también si es un enlace simbólico.
    with open(salida, "xb") as destino:
        pdf.save(
            destino,
            stream_decode_level=pikepdf.StreamDecodeLevel.none,
            compress_streams=False,
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
        except (FiltroNoAdmitido, FlujoInvalido):
            return "flujo_invalido"
        # Un nombre es de bytes y `str()` falla si no son UTF-8. Solo se convierte `/S` y
        # `/Filter`: si no se pueden leer, no se puede decidir sobre ellos.
        except (pikepdf.PdfError, UnicodeDecodeError):
            return "pdf_invalido"
    return None
