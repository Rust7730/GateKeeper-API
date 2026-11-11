"""Repositorios de la API: las únicas consultas de la capa pública (F2.02, F2.04, F2.06).

Reglas de este módulo:

- **Transacción:** ninguna función confirma. La abre quien llama (``async with
  fabrica.begin() as sesion``), para poder juntar operaciones en una sola.
- **INV-10:** toda función sobre un ``archivo`` o sus resultados recibe ``aplicacion_id``
  sin valor por defecto y lo usa en el ``WHERE``. Un archivo ajeno se comporta igual que
  uno inexistente.
- **Resultados:** devuelven dataclasses inmutables, nunca entidades ORM, y ``estado`` ya
  convertido a ``Estado`` (K15): ``es_descargable`` exige el miembro, no el texto.
- **CWE-89:** solo constructor de consultas de SQLAlchemy, siempre con parámetros.

- **CWE-117/CWE-532:** ningún error de una escritura sale de aquí con datos. Toda escritura
  pasa por ``_escribir``, que hace dos cambios:

  - ``IntegrityError`` por ``ViolacionDeRestriccion``, con solo el nombre de la restricción.
    Su DETAIL trae la fila completa ("Failing row contains ..."), con ``nombre_original``
    sin escapar y el hash de la key.
  - ``DataError`` y ``ValueError`` por ``DatoRechazado``, sin nada del valor. El ``CONTEXT``
    de PostgreSQL trae un trozo del dato y ``.params`` todos los valores. Un surrogate llega
    como ``UnicodeEncodeError`` sin envolver, y su ``.object`` guarda el texto completo.

Tras cualquiera de las dos, quien llama debe salir del bloque ``fabrica.begin()``, que
revierte, y no seguir usando esa sesión. Si el rechazo vino del servidor la transacción ya
está abortada y un ``COMMIT`` sería en realidad un ``ROLLBACK``. Si vino de psycopg, la
sentencia no llegó a enviarse y la transacción sigue viva: confirmar guardaría a medias.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import (
    ColumnElement,
    Executable,
    Integer,
    Result,
    Row,
    Text,
    exists,
    func,
    insert,
    literal,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.app.estados import Estado, TransicionInvalida, transicionar
from api.db.modelos import ApiKey, Aplicacion, Archivo, ResultadoAnalisis


class ArchivoNoEncontrado(Exception):
    """El archivo no existe o es de otra aplicación: la API responde 404 en los dos casos."""

    def __init__(self) -> None:
        super().__init__("archivo no encontrado")


class ConflictoDeEstado(Exception):
    """Otro proceso cambió el estado antes. No se reintenta a ciegas: hay que releer."""

    def __init__(self) -> None:
        super().__init__("el archivo ya no está en el estado esperado")


class SinEvidenciaCDR(Exception):
    """``limpio`` sin un resultado ``limpio`` del CDR de ese archivo (K16).

    La fila no cambió. No es un conflicto: releer no lo arregla, hace falta que el CDR
    termine bien. Que llegue aquí es un fallo de quien decide, nunca un error del cliente.
    """

    def __init__(self) -> None:
        super().__init__("el archivo no tiene un resultado limpio del CDR")


class ViolacionDeRestriccion(Exception):
    """La BD rechazó una escritura; lleva solo el nombre de la restricción.

    ``restriccion`` es ``None`` en un NOT NULL: en PostgreSQL 16 no tiene nombre.
    """

    def __init__(self, restriccion: str | None) -> None:
        super().__init__(f"la BD rechazó la escritura: {restriccion or 'sin nombre'}")
        self.restriccion = restriccion


class DatoRechazado(Exception):
    """Un valor no se puede guardar: NUL, surrogate o no cabe en la columna.

    No lleva nada del valor, ni en el mensaje ni en atributos.
    """

    def __init__(self) -> None:
        super().__init__("la BD no puede guardar uno de los valores")


@dataclass(frozen=True, slots=True)
class DatosApiKey:
    id: uuid.UUID
    aplicacion_id: uuid.UUID
    prefijo: str
    # Fuera del repr para que un log de la key no se lleve el HMAC (CWE-532), y fuera de
    # la comparación porque == no es de tiempo constante.
    hash: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class DatosArchivo:
    id: uuid.UUID
    aplicacion_id: uuid.UUID
    # Fuera del repr: el nombre lo elige quien sube el archivo (CWE-117) y K20 limita
    # quién puede ver estos dos campos.
    nombre_original: str = field(repr=False)
    tipo_detectado: str | None
    tamano_bytes: int
    sha256: str = field(repr=False)
    estado: Estado
    tipo_error: str | None
    reintentos: int
    creado_en: datetime
    analizado_en: datetime | None


# Lista explícita: una columna nueva no sale de aquí sin que alguien lo decida.
_COLUMNAS_ARCHIVO = (
    Archivo.id,
    Archivo.aplicacion_id,
    Archivo.nombre_original,
    Archivo.tipo_detectado,
    Archivo.tamano_bytes,
    Archivo.sha256,
    Archivo.estado,
    Archivo.tipo_error,
    Archivo.reintentos,
    Archivo.creado_en,
    Archivo.analizado_en,
)


# K16: la evidencia va dentro del WHERE del UPDATE, así que no hay un momento entre leerla y
# aplicar el cambio. La sirve ix_resultado_analisis_archivo_id.
_CDR_LIMPIO: ColumnElement[bool] = exists().where(
    ResultadoAnalisis.archivo_id == Archivo.id,
    ResultadoAnalisis.capa == "cdr",
    ResultadoAnalisis.veredicto == "limpio",
)


def _a_datos_archivo(fila: Row[Any]) -> DatosArchivo:
    return DatosArchivo(**{**fila._asdict(), "estado": Estado(fila.estado)})


def _nombre_de_restriccion(error: IntegrityError) -> str | None:
    return getattr(getattr(error.orig, "diag", None), "constraint_name", None)


async def _escribir(sesion: AsyncSession, sentencia: Executable) -> Result[Any]:
    """Ejecuta una escritura y traduce lo que la BD rechaza por los datos.

    ``ValueError`` cubre lo que psycopg lanza al codificar un parámetro antes de enviarlo
    (``UnicodeEncodeError`` es una subclase) y SQLAlchemy deja pasar sin envolver. El ``try``
    abarca solo la ejecución, y todo lo demás (BD caída, timeout) sale tal cual: no es
    culpa del dato.

    El ``raise`` va fuera del ``except`` a propósito: dentro, ``from None`` solo evita que
    se imprima el contexto, pero el error original seguiría en ``__context__`` con el
    DETAIL completo, al alcance de cualquier manejador de errores.
    """
    rechazo: ViolacionDeRestriccion | DatoRechazado
    try:
        return await sesion.execute(sentencia)
    except IntegrityError as error:
        rechazo = ViolacionDeRestriccion(_nombre_de_restriccion(error))
    except (DataError, ValueError):
        rechazo = DatoRechazado()
    raise rechazo from None


# ------------------------------------------------------------------- aplicaciones y keys


async def crear_aplicacion(sesion: AsyncSession, nombre: str) -> uuid.UUID:
    """Da de alta una aplicación activa y devuelve su id."""
    sentencia = insert(Aplicacion).values(nombre=nombre).returning(Aplicacion.id)
    return (await _escribir(sesion, sentencia)).scalar_one()


async def crear_api_key(
    sesion: AsyncSession, aplicacion_id: uuid.UUID, prefijo: str, hash: str
) -> uuid.UUID:
    """Guarda una key: solo el prefijo visible y su HMAC-SHA-256, nunca la key (V13)."""
    sentencia = (
        insert(ApiKey)
        .values(aplicacion_id=aplicacion_id, prefijo=prefijo, hash=hash)
        .returning(ApiKey.id)
    )
    return (await _escribir(sesion, sentencia)).scalar_one()


async def obtener_api_key_activa(
    sesion: AsyncSession, prefijo: str
) -> DatosApiKey | None:
    """Key con ese prefijo, solo si no está revocada y su aplicación sigue activa.

    Corre en cada petición autenticada; la sirven el índice único de ``prefijo`` y la PK
    de ``aplicacion``. Cualquier ``revocada_en`` cuenta como revocada, también una futura.
    """
    sentencia = (
        select(ApiKey.id, ApiKey.aplicacion_id, ApiKey.prefijo, ApiKey.hash)
        .join(Aplicacion, Aplicacion.id == ApiKey.aplicacion_id)
        .where(
            ApiKey.prefijo == prefijo,
            ApiKey.revocada_en.is_(None),
            Aplicacion.activa.is_(True),
        )
    )
    fila = (await sesion.execute(sentencia)).one_or_none()
    return None if fila is None else DatosApiKey(**fila._asdict())


# ------------------------------------------------------------------------------ archivos


async def crear_archivo(
    sesion: AsyncSession,
    aplicacion_id: uuid.UUID,
    archivo_id: uuid.UUID,
    nombre_original: str,
    tamano_bytes: int,
    sha256: str,
) -> DatosArchivo:
    """Registra un archivo con el id que asignó la API (INV-03).

    Siempre nace ``pendiente`` y sin reintentos gastados: no se reciben como argumento.
    """
    sentencia = (
        insert(Archivo)
        .values(
            id=archivo_id,
            aplicacion_id=aplicacion_id,
            nombre_original=nombre_original,
            tamano_bytes=tamano_bytes,
            sha256=sha256,
        )
        .returning(*_COLUMNAS_ARCHIVO)
    )
    return _a_datos_archivo((await _escribir(sesion, sentencia)).one())


async def obtener_archivo(
    sesion: AsyncSession, aplicacion_id: uuid.UUID, archivo_id: uuid.UUID
) -> DatosArchivo | None:
    """El archivo de esa aplicación, o ``None`` si no existe o es de otra (INV-10)."""
    sentencia = select(*_COLUMNAS_ARCHIVO).where(
        Archivo.id == archivo_id, Archivo.aplicacion_id == aplicacion_id
    )
    fila = (await sesion.execute(sentencia)).one_or_none()
    return None if fila is None else _a_datos_archivo(fila)


def _validar_cambio(actual: Estado, nuevo: Estado, tipo_error: str | None) -> None:
    """Todo lo que se comprueba antes de tocar la BD. Lanza ``TransicionInvalida``."""
    # Estos dos caminos existen en el dominio, pero aquí todavía no son seguros.
    if actual is Estado.ERROR:
        # K17: el reintento debe apoyarse en reintentos de la fila, no en un valor del
        # llamador. Llega con el UPDATE que lo compruebe.
        raise TransicionInvalida("el reintento todavía no está disponible")
    if actual is Estado.EN_CUARENTENA:
        # INV-08: la liberación y su evento_auditoria van en la misma transacción, y esa
        # tabla llega con el dashboard.
        raise TransicionInvalida("la liberación exige la bitácora de auditoría")

    contexto = {} if tipo_error is None else {"tipo_error": tipo_error}
    transicionar(actual, nuevo, **contexto)

    # El dominio deja tipo_error opcional, pero ck_archivo_tipo_error_solo_en_error no.
    if (nuevo is Estado.ERROR) != (tipo_error is not None):
        raise TransicionInvalida(
            "tipo_error se indica solo y siempre al entrar a error"
        )


async def cambiar_estado(
    sesion: AsyncSession,
    aplicacion_id: uuid.UUID,
    archivo_id: uuid.UUID,
    actual: Estado,
    nuevo: Estado,
    *,
    tipo_detectado: str | None = None,
    tipo_error: str | None = None,
) -> DatosArchivo:
    """Aplica un veredicto sobre un archivo ``pendiente`` en un solo ``UPDATE`` atómico.

    - ``tipo_detectado``: obligatorio en la práctica para ``limpio``, porque
      ``ck_archivo_limpio_en_lista_blanca`` rechaza el ``limpio`` sin un tipo permitido.
    - ``tipo_error``: obligatorio al entrar a ``error``.
    - ``analizado_en`` no se recibe: lo pone siempre la BD, para que quien llama no pueda
      falsear M2 ni dejar un veredicto sin fecha. ``clock_timestamp()`` y no ``now()``, que
      sería la hora en que empezó la transacción.

    Hacia ``limpio`` el mismo ``UPDATE`` exige un resultado ``limpio`` de la capa ``cdr``
    de ese archivo (K16). Vale el que se haya guardado en esta misma transacción.

    Lanza ``TransicionInvalida`` si el cambio no se permite (sin tocar la BD),
    ``ArchivoNoEncontrado`` si el archivo no existe o es de otra aplicación,
    ``ConflictoDeEstado`` si otro proceso cambió el estado antes, ``SinEvidenciaCDR`` si
    falta la evidencia, ``ViolacionDeRestriccion`` si los valores rompen una restricción y
    ``DatoRechazado`` si no se pueden guardar.
    """
    _validar_cambio(actual, nuevo, tipo_error)

    valores: dict[str, Any] = {
        "estado": nuevo.value,
        "analizado_en": func.clock_timestamp(),
    }
    if tipo_detectado is not None:
        valores["tipo_detectado"] = tipo_detectado
    if tipo_error is not None:
        valores["tipo_error"] = tipo_error

    condiciones = [
        Archivo.id == archivo_id,
        Archivo.aplicacion_id == aplicacion_id,
        Archivo.estado == actual.value,
    ]
    if nuevo is Estado.LIMPIO:
        condiciones.append(_CDR_LIMPIO)

    sentencia = (
        update(Archivo)
        .where(*condiciones)
        .values(**valores)
        .returning(*_COLUMNAS_ARCHIVO)
        .execution_options(synchronize_session=False)
    )
    fila = (await _escribir(sesion, sentencia)).one_or_none()
    if fila is not None:
        return _a_datos_archivo(fila)

    # Sin fila hay tres causas y cada una se trata distinto. Esta lectura solo las separa,
    # filtrada por aplicación: un archivo ajeno da 404, igual que uno que no existe, y no
    # se puede usar para saber qué ids hay en otra aplicación. Nunca reintenta.
    leido = await obtener_archivo(sesion, aplicacion_id, archivo_id)
    if leido is None:
        raise ArchivoNoEncontrado
    # Si el estado sigue igual, lo que falló del WHERE fue la evidencia. Si otro proceso
    # lo cambió, es un conflicto aunque tampoco hubiera evidencia.
    if nuevo is Estado.LIMPIO and leido.estado is actual:
        raise SinEvidenciaCDR
    raise ConflictoDeEstado


async def registrar_resultado(
    sesion: AsyncSession,
    aplicacion_id: uuid.UUID,
    archivo_id: uuid.UUID,
    capa: str,
    veredicto: str,
    detalle: dict[str, object],
    duracion_ms: int | None,
) -> int:
    """Guarda el resultado de una capa y devuelve su id.

    La fila sale de un ``INSERT ... SELECT`` sobre el archivo filtrado por aplicación: si
    no es de esa aplicación no se inserta nada y se lanza ``ArchivoNoEncontrado``. Si los
    valores rompen una restricción se lanza ``ViolacionDeRestriccion``, y si no se pueden
    guardar (un NUL o un NaN en ``detalle``, por ejemplo), ``DatoRechazado``.
    """
    fuente = select(
        Archivo.id,
        literal(capa, Text),
        literal(veredicto, Text),
        literal(detalle, JSONB(none_as_null=True)),
        literal(duracion_ms, Integer),
    ).where(Archivo.id == archivo_id, Archivo.aplicacion_id == aplicacion_id)
    sentencia = (
        insert(ResultadoAnalisis)
        .from_select(
            ["archivo_id", "capa", "veredicto", "detalle", "duracion_ms"], fuente
        )
        .returning(ResultadoAnalisis.id)
    )
    resultado_id = (await _escribir(sesion, sentencia)).scalar_one_or_none()
    if resultado_id is None:
        raise ArchivoNoEncontrado
    return resultado_id
