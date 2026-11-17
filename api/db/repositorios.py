"""Repositorios de la API: las únicas consultas de la capa pública (F2.02, F2.04, F2.06).

Reglas de este módulo:

- **Transacción:** ninguna función confirma. La abre quien llama (``async with
  fabrica.begin() as sesion``), para poder juntar operaciones en una sola.
- **INV-10:** toda función sobre un ``archivo`` o sus resultados recibe ``aplicacion_id``
  sin valor por defecto y lo usa en el ``WHERE``. Un archivo ajeno se comporta igual que
  uno inexistente. La única excepción es ``cerrar_pendientes_huerfanos`` (K51), que es
  mantenimiento del arranque y devuelve solo ids.
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
    BigInteger,
    ColumnElement,
    Executable,
    Integer,
    Result,
    Row,
    Select,
    Text,
    exists,
    func,
    insert,
    literal,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
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


class CupoDePendientesAgotado(Exception):
    """La aplicación ya tiene el máximo de archivos en ``pendiente`` (K48): la API responde 429.

    No se insertó nada. No lleva datos: ni la aplicación, ni el archivo, ni la cuenta.
    """

    def __init__(self) -> None:
        super().__init__("la aplicación no tiene cupo de archivos pendientes")


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


# Límite del tipo, no política: K48 lo fija quien llama. Más allá de un int4 el valor no es
# un tope sino un error de configuración, y no debe llegar a la BD como un DatoRechazado.
_MAX_TOPE = 2**31 - 1


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


def _cuenta_pendientes(aplicacion_id: uuid.UUID) -> Select[tuple[int]]:
    # La sirve ix_archivo_aplicacion_id_estado (las dos columnas, por igualdad).
    return select(func.count()).where(
        Archivo.aplicacion_id == aplicacion_id,
        Archivo.estado == Estado.PENDIENTE.value,
    )


async def contar_pendientes(sesion: AsyncSession, aplicacion_id: uuid.UUID) -> int:
    """Cuántos archivos de esa aplicación están en ``pendiente`` (K48).

    Solo cuenta los de esa aplicación (INV-10); una aplicación inexistente da 0. Es una
    lectura sin bloqueo: sirve para informar, no para decidir si cabe otro archivo. Esa
    decisión la toma ``crear_archivo_con_cupo`` en el mismo paso que inserta.
    """
    return (await sesion.execute(_cuenta_pendientes(aplicacion_id))).scalar_one()


# Toma el turno de altas de la aplicación. FOR NO KEY UPDATE choca consigo mismo, pero no con
# el FOR KEY SHARE que toman las FK al insertar un archivo o una key de esa aplicación, ni
# con nada de otra aplicación. La columna sirve para comprobar el aislamiento sin otra ida y
# vuelta a la BD.
def _turno_de_altas(aplicacion_id: uuid.UUID) -> Select[tuple[str]]:
    return (
        select(func.current_setting("transaction_isolation"))
        .select_from(Aplicacion)
        .where(Aplicacion.id == aplicacion_id)
        .with_for_update(key_share=True)
    )


async def crear_archivo_con_cupo(
    sesion: AsyncSession,
    aplicacion_id: uuid.UUID,
    archivo_id: uuid.UUID,
    nombre_original: str,
    tamano_bytes: int,
    sha256: str,
    *,
    tope_pendientes: int,
) -> DatosArchivo:
    """Igual que ``crear_archivo``, pero solo si la aplicación tiene cupo (K48).

    Inserta si la aplicación tiene menos de ``tope_pendientes`` archivos en ``pendiente``;
    los que ya tienen veredicto no cuentan, ni los de otra aplicación (INV-10). El tope lo
    pasa la API: aquí no hay un valor por defecto.

    **Atomicidad.** Dos sentencias dentro de la transacción de quien llama:

    1. ``SELECT ... FROM aplicacion WHERE id = :app FOR NO KEY UPDATE``: bloquea la fila de
       la aplicación. Las altas con cupo de la misma aplicación se forman en fila; las de
       otra aplicación, los veredictos y las keys nuevas no esperan.
    2. ``INSERT ... SELECT ... WHERE (cuenta de pendientes) < :tope RETURNING ...``.

    Van separadas a propósito: en ``READ COMMITTED`` cada sentencia toma su foto al empezar,
    así que la cuenta del paso 2 ya ve lo que confirmó quien tenía el turno antes. En una
    sola sentencia la foto sería anterior a la espera y dos altas podrían pasar el tope. Por
    lo mismo, fuera de ``READ COMMITTED`` se lanza ``RuntimeError`` sin insertar.

    El bloqueo dura hasta el ``COMMIT`` o el ``ROLLBACK``: llámala en una transacción corta y
    confirma enseguida (nada de E/S de archivos ni de encolar dentro). Una sola alta con
    cupo por transacción.

    Lanza ``TypeError`` o ``ValueError`` si ``tope_pendientes`` no es un ``int`` (``bool`` no
    vale) entre 1 y 2**31 - 1, sin tocar la BD; ``CupoDePendientesAgotado`` si no hay cupo
    (no se insertó nada); y ``ViolacionDeRestriccion`` o ``DatoRechazado`` igual que
    ``crear_archivo`` (una aplicación inexistente es ``fk_archivo_aplicacion_id_aplicacion``).
    """
    _validar_tope(tope_pendientes)

    aislamiento = (
        await sesion.execute(_turno_de_altas(aplicacion_id))
    ).scalar_one_or_none()
    # Sin fila, la aplicación no existe: no hay nada que bloquear y el INSERT falla por FK.
    if aislamiento is not None and aislamiento != "read committed":
        raise RuntimeError("crear_archivo_con_cupo exige READ COMMITTED")

    # Literales con tipo amplio (Text, no String(255) ni CHAR(64)): un CAST explícito a
    # varchar(n) trunca en silencio, y aquí la longitud la debe rechazar la columna.
    fuente = select(
        literal(archivo_id, UUID(as_uuid=True)),
        literal(aplicacion_id, UUID(as_uuid=True)),
        literal(nombre_original, Text),
        literal(tamano_bytes, BigInteger),
        literal(sha256, Text),
    ).where(_cuenta_pendientes(aplicacion_id).scalar_subquery() < tope_pendientes)
    sentencia = (
        insert(Archivo)
        .from_select(
            ["id", "aplicacion_id", "nombre_original", "tamano_bytes", "sha256"],
            fuente,
        )
        .returning(*_COLUMNAS_ARCHIVO)
    )
    fila = (await _escribir(sesion, sentencia)).one_or_none()
    if fila is None:
        raise CupoDePendientesAgotado
    return _a_datos_archivo(fila)


def _validar_tope(tope_pendientes: object) -> None:
    if type(tope_pendientes) is not int:
        raise TypeError("tope_pendientes debe ser int")
    if not 1 <= tope_pendientes <= _MAX_TOPE:
        raise ValueError("tope_pendientes fuera de rango")


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


async def cerrar_pendientes_huerfanos(
    sesion: AsyncSession, *, tipo_error: str
) -> list[uuid.UUID]:
    """Pasa a ``error`` todo archivo en ``pendiente`` y devuelve sus ids (K51).

    **Es la única función sobre archivos que no filtra por aplicación (excepción a
    INV-10).** Es mantenimiento del sistema, no una lectura para un cliente: la API la
    llama al arrancar, antes de aceptar peticiones, para cerrar lo que quedó a medias
    cuando se detuvo. Por eso devuelve solo los ids, sin dueño ni datos del archivo, y
    nunca debe llamarse con un dato que venga de una petición.

    - Toca solo ``pendiente``: ``limpio``, ``rechazado``, ``en_cuarentena`` y ``error``
      quedan como estaban. ``reintentos`` no cambia.
    - ``tipo_error`` (por nombre, sin valor por defecto) se valida con el dominio antes de
      tocar la BD: ``transitorio`` o ``final``; si no, ``TransicionInvalida``.
    - ``analizado_en`` lo pone la BD con ``clock_timestamp()``, como ``cambiar_estado``.
    - Los ids salen sin un orden definido. No confirma: la transacción es de quien llama.

    Recorre ``archivo`` completo (``ix_archivo_aplicacion_id_estado`` empieza por la
    aplicación); corre una vez por arranque y fuera del camino del 202.
    """
    _validar_cambio(Estado.PENDIENTE, Estado.ERROR, tipo_error)
    sentencia = (
        update(Archivo)
        .where(Archivo.estado == Estado.PENDIENTE.value)
        .values(
            estado=Estado.ERROR.value,
            tipo_error=tipo_error,
            analizado_en=func.clock_timestamp(),
        )
        .returning(Archivo.id)
        .execution_options(synchronize_session=False)
    )
    return list((await _escribir(sesion, sentencia)).scalars())
