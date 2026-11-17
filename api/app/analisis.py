"""Análisis en segundo plano (diseño §5, K09, K16, K28, F3.08, F3.09).

La API lanza un proceso hijo por archivo y decide con lo que este dice, sin fiarse de nada:

- **Entorno por lista blanca** y grupo de procesos propio: el hijo no hereda secretos, y al
  terminar se mata el grupo entero. Los descriptores los cierra el propio hijo al arrancar:
  ``close_fds`` no sirve bajo uvloop, que es con lo que arranca uvicorn.
- **Tubería propia para stdout:** con ``stdout=PIPE``, ``Process.wait()`` espera también a
  que se cierre la tubería, y un nieto que la retiene dejaría al padre colgado después del
  ``kill``. Aquí el transporte se cierra a mano. ``stderr`` va a ``/dev/null``: nunca llega
  al cliente y no se puede llenar.
- **Veredicto estricto:** una sola línea, con las claves exactas. Cualquier otra cosa, un
  código distinto de 0 o el timeout terminan en ``error``, nunca en ``limpio`` (INV-09).
- **Publicación por el padre:** el padre crea ``clean_store/<uuid>.parcial/`` (0700) y el hijo
  escribe dentro, en ``<uuid>.parcial/<uuid>``: con Landlock (K53) no puede escribir en
  ningún otro sitio. Es un directorio y no un archivo creado de antemano porque el hijo crea
  su salida con ``"xb"``. ``clean_store/<uuid>``
  solo aparece si el padre validó todo, y antes de confirmar el ``limpio``. El padre aplica
  también el tope de K46: una salida de más de 32 MiB es ``rechazado`` y no se publica. Si el
  ``limpio`` no llega a confirmarse, por un error o por una cancelación, la salida se borra.

Si la decisión falla, la excepción sale del bloque ``begin()``, que revierte, y ``error`` se
escribe en otra transacción: tras un rechazo de la BD no se sigue usando esa sesión.

Un apagado a mitad deja el archivo en ``pendiente``, sin descargarse (falla cerrado); el
barrido del siguiente arranque lo pasa a ``error`` (``arranque.py``).
"""

import asyncio
import contextlib
import json
import logging
import os
import shutil
import signal
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from api.app.cdr_salida import TOPE_SALIDA, SalidaDemasiadoGrande
from api.app.estados import Estado, TransicionInvalida
from api.app.tipos import TIPOS_PERMITIDOS
from api.db.repositorios import (
    ArchivoNoEncontrado,
    ConflictoDeEstado,
    DatoRechazado,
    ViolacionDeRestriccion,
    cambiar_estado,
    registrar_resultado,
)

logger = logging.getLogger("gatekeeper.api")

# Un veredicto ocupa menos de 200 bytes. Sin tope, un hijo podría llenar la memoria del padre.
TOPE_SALIDA_HIJO = 4096
# Valores fijos, no copiados del entorno de la API: una lista negra dejaría pasar lo que nadie
# pensó, como PGPASSWORD. No hay PYTHONPATH: `-m` encuentra `api` por el directorio de trabajo.
ENTORNO_HIJO = {"PATH": os.defpath}
_RAIZ_DEL_PROYECTO = Path(__file__).resolve().parents[2]
_SUFIJO_PARCIAL = ".parcial"
_MODO_TRABAJO = 0o700
_CLAVES_VEREDICTO = {"veredicto", "tipo", "motivo"}
LIMPIO = "limpio"
RECHAZADO = "rechazado"
_VEREDICTOS = {LIMPIO, RECHAZADO}
_FIRMA = "firma"
_CDR = "cdr"
_ERROR = "error"
_NO_EVALUADA = "no_evaluada"
_ERROR_FINAL = "final"  # No hay reintentos en la rebanada (K26, K11).
_MOTIVO_INTERNO = "interno"
_MOTIVO_SALIDA_GRANDE = "salida_grande"
# Si la BD no responde al registrar un `error`, el archivo se quedaría en `pendiente` ocupando
# cupo de K48 hasta el siguiente arranque. Se reintenta poco y con espera acotada: cada intento
# puede tardar además el connect_timeout de K32. Si aun así falla, queda para el barrido.
INTENTOS_REGISTRO_ERROR = 3
ESPERAS_REGISTRO_ERROR_S: tuple[float, ...] = (0.5, 1.0)
# Rechazos de la BD por el dato o por el estado: repetir no los arregla.
_NO_REINTENTABLES = (
    ArchivoNoEncontrado,
    ConflictoDeEstado,
    DatoRechazado,
    TransicionInvalida,
    ViolacionDeRestriccion,
)


class FalloDelHijo(Exception):
    """El hijo no dio un veredicto válido. ``motivo`` es un código fijo, sin datos suyos."""

    def __init__(self, motivo: str) -> None:
        super().__init__(motivo)
        self.motivo = motivo


@dataclass(frozen=True, slots=True)
class Veredicto:
    veredicto: str
    tipo: str
    # Lo escribe un proceso que procesa archivos hostiles: fuera del repr, por si acaba en un log.
    motivo: str = field(repr=False)


def _rechazar_duplicadas(pares: list[tuple[str, Any]]) -> dict[str, Any]:
    datos = dict(pares)
    if len(datos) != len(pares):
        raise ValueError("clave repetida")
    return datos


def _invalida() -> NoReturn:
    raise FalloDelHijo("salida_invalida")


def interpretar_salida(salida: bytes) -> Veredicto:
    """Exactamente una línea JSON con ``veredicto``, ``tipo`` y ``motivo``, todos texto.

    Con claves repetidas gana la última, y por eso se rechazan: dos lecturas de la misma
    línea no pueden dar dos veredictos. Se decodifica aquí porque ``json.loads`` sobre bytes
    aceptaría también UTF-16. El ``raise`` queda fuera del ``except``: dentro, el error
    original seguiría en ``__context__`` con la salida del hijo.
    """
    if salida.count(b"\n") != 1 or not salida.endswith(b"\n"):
        _invalida()
    try:
        datos = json.loads(
            salida.decode("utf-8"), object_pairs_hook=_rechazar_duplicadas
        )
    except (ValueError, RecursionError):
        datos = None
    if type(datos) is not dict or set(datos) != _CLAVES_VEREDICTO:
        _invalida()
    if not all(type(valor) is str for valor in datos.values()):
        _invalida()
    if datos["veredicto"] not in _VEREDICTOS:
        _invalida()
    if datos["veredicto"] == LIMPIO and datos["tipo"] not in TIPOS_PERMITIDOS:
        _invalida()
    return Veredicto(**datos)


async def _lanzar(comando: tuple[str, ...], stdout: int) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        *comando,
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=subprocess.DEVNULL,
        env=ENTORNO_HIJO,
        cwd=_RAIZ_DEL_PROYECTO,
        start_new_session=True,
    )


async def _abrir_tuberia(
    descriptor: int,
) -> tuple[asyncio.StreamReader, asyncio.BaseTransport]:
    lector = asyncio.StreamReader(limit=TOPE_SALIDA_HIJO)
    transporte, _ = await asyncio.get_running_loop().connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(lector),
        os.fdopen(descriptor, "rb", buffering=0),
    )
    return lector, transporte


async def _leer_acotado(lector: asyncio.StreamReader) -> bytes:
    salida = bytearray()
    while len(salida) <= TOPE_SALIDA_HIJO:
        trozo = await lector.read(TOPE_SALIDA_HIJO + 1 - len(salida))
        if not trozo:
            return bytes(salida)
        salida += trozo
    _invalida()


async def _terminar(proceso: asyncio.subprocess.Process) -> None:
    """``SIGKILL`` al grupo entero, no solo al hijo. Sin grupo vivo no hay nada que matar."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proceso.pid, signal.SIGKILL)
    await proceso.wait()


async def correr_hijo(comando: tuple[str, ...], timeout_s: float) -> Veredicto:
    """Lanza el comando y devuelve su veredicto, o ``FalloDelHijo`` con el motivo.

    El timeout corre desde el padre y cubre la lectura y la espera. Al salir, por el motivo
    que sea (cancelación incluida), no queda ni proceso del grupo ni tubería.
    """
    lectura, escritura = os.pipe()
    try:
        proceso = await _lanzar(comando, escritura)
    except BaseException as error:
        os.close(lectura)
        if isinstance(error, OSError):
            raise FalloDelHijo("no_arranco") from None
        raise
    finally:
        os.close(escritura)

    transporte = None
    try:
        lector, transporte = await _abrir_tuberia(lectura)
        async with asyncio.timeout(timeout_s):
            salida = await _leer_acotado(lector)
            codigo = await proceso.wait()
    except TimeoutError:
        raise FalloDelHijo("timeout") from None
    finally:
        if transporte is not None:
            transporte.close()
        await _terminar(proceso)

    if codigo != 0:
        raise FalloDelHijo("codigo_salida")
    return interpretar_salida(salida)


def publicar_salida(parcial: Path, final: Path) -> None:
    """Deja la salida en su nombre definitivo, si es un archivo de verdad y cabe en K46.

    ``lstat`` y no ``stat``: un hijo comprometido no puede dejar un enlace a otro archivo del
    disco para que la API lo sirva. Al llegar aquí el hijo y su grupo ya están muertos: nadie
    puede hacer crecer el archivo entre la comprobación y el ``replace``. Lanza
    ``FalloDelHijo`` si no hay salida válida y ``SalidaDemasiadoGrande`` si pasa del tope.
    """
    info = None
    with contextlib.suppress(FileNotFoundError):
        info = os.lstat(parcial)
    if info is None or not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        raise FalloDelHijo("sin_salida")
    if info.st_size > TOPE_SALIDA:
        raise SalidaDemasiadoGrande
    os.replace(parcial, final)


async def _registrar_veredicto(
    sesiones: async_sessionmaker[AsyncSession],
    aplicacion_id: uuid.UUID,
    archivo_id: uuid.UUID,
    resultado: Veredicto,
    duracion_ms: int,
) -> None:
    """Resultados y estado en una sola transacción (K16)."""
    limpio = resultado.veredicto == LIMPIO
    firma_valida = resultado.tipo in TIPOS_PERMITIDOS
    if limpio:
        veredicto_cdr, destino = LIMPIO, Estado.LIMPIO
    else:
        veredicto_cdr = RECHAZADO if firma_valida else _NO_EVALUADA
        destino = Estado.RECHAZADO
    async with sesiones.begin() as sesion:
        await registrar_resultado(
            sesion,
            aplicacion_id,
            archivo_id,
            _FIRMA,
            LIMPIO if firma_valida else RECHAZADO,
            {"tipo": resultado.tipo},
            None,
        )
        await registrar_resultado(
            sesion,
            aplicacion_id,
            archivo_id,
            _CDR,
            veredicto_cdr,
            {"motivo": resultado.motivo},
            duracion_ms,
        )
        await cambiar_estado(
            sesion,
            aplicacion_id,
            archivo_id,
            Estado.PENDIENTE,
            destino,
            tipo_detectado=resultado.tipo,
        )


async def _registrar_error(
    sesiones: async_sessionmaker[AsyncSession],
    aplicacion_id: uuid.UUID,
    archivo_id: uuid.UUID,
    motivo: str,
    duracion_ms: int,
) -> None:
    """Último recurso. Si la BD no responde, reintenta unas pocas veces y luego se rinde.

    El archivo sigue sin descargarse en cualquier caso; si no se pudo registrar, lo cierra el
    barrido del siguiente arranque.
    """
    for intento in range(INTENTOS_REGISTRO_ERROR):
        try:
            async with sesiones.begin() as sesion:
                await registrar_resultado(
                    sesion,
                    aplicacion_id,
                    archivo_id,
                    _CDR,
                    _ERROR,
                    {"motivo": motivo},
                    duracion_ms,
                )
                await cambiar_estado(
                    sesion,
                    aplicacion_id,
                    archivo_id,
                    Estado.PENDIENTE,
                    Estado.ERROR,
                    tipo_error=_ERROR_FINAL,
                )
        except _NO_REINTENTABLES as error:
            logger.error(
                "No se pudo registrar el error de %s (%s)",
                archivo_id,
                type(error).__name__,
            )
            return
        except Exception as error:  # noqa: BLE001
            logger.error(
                "No se pudo registrar el error de %s, intento %d (%s)",
                archivo_id,
                intento + 1,
                type(error).__name__,
            )
            if intento < len(ESPERAS_REGISTRO_ERROR_S):
                await asyncio.sleep(ESPERAS_REGISTRO_ERROR_S[intento])
        else:
            return


def _borrar(ruta: Path) -> None:
    try:
        ruta.unlink(missing_ok=True)
    except OSError as error:
        logger.error("No se pudo borrar un temporal (%s)", type(error).__name__)


def _borrar_trabajo(trabajo: Path) -> None:
    """Borra el directorio de trabajo del hijo con lo que haya dejado dentro.

    ``rmtree`` trabaja con descriptores y no sigue enlaces: un hijo sin Landlock (un
    sustituto, o un kernel que no lo tenga y no llegara a analizar) no consigue que se borre
    nada de fuera.
    """
    try:
        shutil.rmtree(trabajo)
    except FileNotFoundError:
        pass
    except OSError as error:
        logger.error(
            "No se pudo borrar un directorio de trabajo (%s)", type(error).__name__
        )


async def analizar_archivo(
    estado: Any, aplicacion_id: uuid.UUID, archivo_id: uuid.UUID
) -> None:
    """Lleva un archivo ``pendiente`` a su estado final y borra el original (F3.09).

    Amplio a propósito: cualquier fallo aquí, conocido o no, debe acabar en ``error`` y no
    dejar el archivo en ``pendiente`` para siempre. El log lleva solo el id y el tipo de la
    excepción: su texto puede traer datos de la BD o del hijo.
    """
    ajustes = estado.ajustes
    entrada = ajustes.uploads_tmp / str(archivo_id)
    trabajo = ajustes.clean_store / f"{archivo_id}{_SUFIJO_PARCIAL}"
    parcial = trabajo / str(archivo_id)
    final = ajustes.clean_store / str(archivo_id)
    inicio = time.perf_counter()

    def _duracion_ms() -> int:
        return round((time.perf_counter() - inicio) * 1000)

    confirmado = False
    try:
        async with estado.cupos:
            inicio = time.perf_counter()
            # Exclusivo: si ya existiera, no es de este análisis.
            trabajo.mkdir(mode=_MODO_TRABAJO)
            resultado = await correr_hijo(
                (*ajustes.comando_cdr, str(entrada), str(parcial)),
                ajustes.timeout_cdr_s,
            )
        duracion_ms = _duracion_ms()
        if resultado.veredicto == LIMPIO:
            try:
                publicar_salida(parcial, final)
            except SalidaDemasiadoGrande:
                resultado = Veredicto(RECHAZADO, resultado.tipo, _MOTIVO_SALIDA_GRANDE)
        await _registrar_veredicto(
            estado.sesiones, aplicacion_id, archivo_id, resultado, duracion_ms
        )
        confirmado = True
    except Exception as error:  # noqa: BLE001
        motivo = error.motivo if isinstance(error, FalloDelHijo) else _MOTIVO_INTERNO
        logger.warning(
            "El análisis de %s terminó en error: %s (%s)",
            archivo_id,
            motivo,
            type(error).__name__,
        )
        _borrar(final)
        await _registrar_error(
            estado.sesiones, aplicacion_id, archivo_id, motivo, _duracion_ms()
        )
    finally:
        # También al cancelar entre publicar y confirmar: sin `limpio` no hay salida.
        if not confirmado:
            _borrar(final)
        _borrar(entrada)
        _borrar_trabajo(trabajo)


def agendar_analisis(
    estado: Any, aplicacion_id: uuid.UUID, archivo_id: uuid.UUID
) -> None:
    """Crea la tarea y la guarda: el bucle solo guarda una referencia débil."""
    tarea = asyncio.create_task(analizar_archivo(estado, aplicacion_id, archivo_id))
    estado.tareas.add(tarea)
    tarea.add_done_callback(estado.tareas.discard)


async def cancelar_analisis(estado: Any) -> None:
    """Al apagar: mata a los hijos en curso y espera a que limpien sus temporales."""
    tareas = list(estado.tareas)
    for tarea in tareas:
        tarea.cancel()
    await asyncio.gather(*tareas, return_exceptions=True)
