"""Ejecución aislada del proceso hijo del CDR (K09, K42, K46, K53, K54, K64).

Módulo sin dependencias de ``api.db`` ni de FastAPI: lo usa el ``worker`` aislado (y se
re-exporta desde ``api.app.analisis`` para compatibilidad de pruebas unitarias).
"""

import asyncio
import contextlib
import json
import os
import signal
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

from api.app.cdr_salida import TOPE_SALIDA, SalidaDemasiadoGrande
from api.app.tipos import TIPOS_PERMITIDOS

# Un veredicto ocupa menos de 200 bytes. Sin tope, un hijo podría llenar la memoria del padre.
TOPE_SALIDA_HIJO = 4096
# Valores fijos, no copiados del entorno del padre: una lista negra dejaría pasar lo que nadie
# pensó. No hay PYTHONPATH: `-m` encuentra los paquetes por el directorio de trabajo.
ENTORNO_HIJO = {"PATH": os.defpath}
_RAIZ_DEL_PROYECTO = Path(__file__).resolve().parents[1]
_CLAVES_VEREDICTO = {"veredicto", "tipo", "motivo"}
LIMPIO = "limpio"
RECHAZADO = "rechazado"
_VEREDICTOS = {LIMPIO, RECHAZADO}
# K64: legible por el GID compartido (10010) entre worker (UID 10003) y api (UID 10001).
MODO_SALIDA_PUBLICADA = 0o640


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
    """Exactamente una línea JSON con ``veredicto``, ``tipo`` y ``motivo``, todos texto."""
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
    """Lanza el comando y devuelve su veredicto, o ``FalloDelHijo`` con el motivo."""
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
    """Deja la salida en su nombre definitivo, si es un archivo regular y cabe en K46."""
    info = None
    with contextlib.suppress(FileNotFoundError):
        info = os.lstat(parcial)
    if info is None or not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        raise FalloDelHijo("sin_salida")
    if info.st_size > TOPE_SALIDA:
        raise SalidaDemasiadoGrande
    # K64: modo 0640 sobre descriptor sin seguir enlaces para que api (GID 10010) pueda leerlo.
    fd = os.open(parcial, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fchmod(fd, MODO_SALIDA_PUBLICADA)
    finally:
        os.close(fd)
    os.replace(parcial, final)
