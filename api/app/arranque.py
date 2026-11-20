"""Lo que la API hace al arrancar, antes de aceptar peticiones (F3.09, K28, K51).

- **Proceso protegido (K28):** ``PR_SET_DUMPABLE=0``. El hijo del CDR corre con el mismo UID
  que la API; sin esto podría leer de ``/proc/<ppid>/environ`` el pepper y la URL de la BD, o
  su memoria. Se hace en el arranque de la app y no al importar: así vale en cada proceso que
  la sirve, arranque uvicorn como arranque. ``execve`` lo restablece, así que no hay que
  deshacerlo para los hijos.
- **Ningún ancestro con los secretos (K52):** ``PR_SET_DUMPABLE`` protege el entorno de la
  API, no el de quien la lanzó. Con ``uv run``, ``uv`` es el padre y guarda en su entorno el
  pepper y la URL de la BD, legibles por el hijo del CDR. Si algún ancestro los tiene
  legibles en ``/proc/<pid>/environ``, la API no arranca. Uno ilegible (otro usuario, no
  volcable) no cuenta: tampoco el hijo lo podría leer.
- **Barrido (F3.09, K51):** tras un apagado anómalo quedan originales en ``uploads_tmp``,
  ``.parcial`` en ``clean_store`` (archivos, o los directorios de trabajo de K53) y filas en ``pendiente`` que nada terminaría nunca, y que
  además ocuparían el cupo de K48. Al arrancar no hay ningún análisis en curso, así que todo
  eso es resto: los pendientes pasan a ``error`` y se borran sus archivos. Lo terminado no se
  toca. Supone un solo proceso de API: con varios, uno que arranca cerraría los análisis de
  otro.

Si el barrido no puede hablar con la BD, la API no arranca: seguir dejaría los huérfanos en
``pendiente`` para siempre. El error no lleva nada de la conexión.
"""

import ctypes
import logging
import os
import shutil
import stat
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from api.app.ajustes import VARIABLE_HMAC, VARIABLE_REDIS, Ajustes, ConfiguracionError
from api.db.config import VARIABLE_URL_BD, VARIABLE_URL_MIGRACION
from api.db.repositorios import cerrar_pendientes_huerfanos

logger = logging.getLogger("gatekeeper.api")

TIPO_ERROR_BARRIDO = "final"  # K51
# K52: lo que no puede quedar a la vista en el entorno de un ancestro.
# La de migración lleva la misma contraseña en el README. La de Redis, la de su usuario (K59).
VARIABLES_SECRETAS = (
    VARIABLE_HMAC,
    VARIABLE_URL_BD,
    VARIABLE_URL_MIGRACION,
    VARIABLE_REDIS,
)
SUFIJO_PARCIAL = ".parcial"
_PR_SET_DUMPABLE = 4  # <linux/prctl.h>


def proteger_proceso() -> None:
    """``PR_SET_DUMPABLE=0``: ni el hijo ni otro proceso del mismo UID leen ``/proc`` de este."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        numero = ctypes.get_errno()
        raise OSError(numero, os.strerror(numero))


def _padre_de(pid: int) -> int | None:
    """El ppid de ``pid`` según ``/proc/<pid>/stat``, o ``None`` si ya no se puede leer.

    El nombre del proceso va entre paréntesis y puede llevar espacios y paréntesis: se corta
    por el último ``)``.
    """
    try:
        estado = Path(f"/proc/{pid}/stat").read_bytes()
    except OSError:
        return None
    campos = estado.rpartition(b")")[2].split()
    return int(campos[1]) if len(campos) > 1 else None


def _secretos_a_la_vista(pid: int) -> list[str]:
    """Qué variables de ``VARIABLES_SECRETAS`` tiene ``pid`` legibles. Nunca su valor."""
    try:
        entorno = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError:
        return []
    nombres = {entrada.partition(b"=")[0] for entrada in entorno.split(b"\0")}
    return [v for v in VARIABLES_SECRETAS if os.fsencode(v) in nombres]


def comprobar_ancestros() -> None:
    """K52: ``ConfiguracionError`` si un ancestro expone el pepper o una URL con contraseña.

    Recorre desde el padre hasta el pid 1. El mensaje nombra la variable y el pid, nunca el
    valor.
    """
    vistos: set[int] = set()
    pid: int | None = os.getppid()
    while pid is not None and pid > 0 and pid not in vistos:
        vistos.add(pid)
        expuestas = _secretos_a_la_vista(pid)
        if expuestas:
            raise ConfiguracionError(
                f"El proceso {pid}, que lanzó a la API, tiene {', '.join(expuestas)} en su "
                "entorno, legible por el proceso hijo del CDR. Lanza uvicorn directamente "
                "(.venv/bin/uvicorn, no uv run) y no pongas esas variables en el entorno con "
                "el que se abrió la shell (el valor no se muestra)."
            )
        pid = _padre_de(pid)


def _borrar(ruta: Path) -> bool:
    """Borra un archivo o un enlace sin seguirlo. Un directorio no se toca.

    Un ``.parcial`` de ``clean_store`` que sea un directorio de verdad (el de trabajo de un
    hijo, K53) se borra con lo que tenga dentro: ``rmtree`` no sigue enlaces.
    """
    try:
        if ruta.name.endswith(SUFIJO_PARCIAL) and stat.S_ISDIR(os.lstat(ruta).st_mode):
            shutil.rmtree(ruta)
            return True
        os.unlink(ruta)
    except FileNotFoundError:
        return False
    except OSError as error:
        logger.error("El barrido no pudo borrar un resto (%s)", type(error).__name__)
        return False
    return True


def _restos_del_disco(ajustes: Ajustes) -> list[Path]:
    restos = []
    with os.scandir(ajustes.uploads_tmp) as entradas:
        restos += [
            Path(e.path) for e in entradas if not e.is_dir(follow_symlinks=False)
        ]
    with os.scandir(ajustes.clean_store) as entradas:
        restos += [Path(e.path) for e in entradas if e.name.endswith(SUFIJO_PARCIAL)]
    return restos


async def _cerrar_pendientes(
    ajustes: Ajustes, sesiones: async_sessionmaker[AsyncSession]
) -> int:
    """Pasa los pendientes a ``error`` y borra su salida publicada sin confirmar.

    La salida se borra antes del ``COMMIT``: si este fallara, las filas seguirían en
    ``pendiente`` y el siguiente arranque las cerraría.
    """
    async with sesiones.begin() as sesion:
        ids = await cerrar_pendientes_huerfanos(sesion, tipo_error=TIPO_ERROR_BARRIDO)
        for archivo_id in ids:
            _borrar(ajustes.clean_store / str(archivo_id))
    return len(ids)


async def barrer_restos(
    ajustes: Ajustes, sesiones: async_sessionmaker[AsyncSession]
) -> None:
    """Cierra los pendientes huérfanos y borra originales y ``.parcial``. Ver el módulo."""
    cerrados = None
    # Amplio a propósito: cualquier fallo aquí viene de la conexión y su texto puede traerla.
    try:
        cerrados = await _cerrar_pendientes(ajustes, sesiones)
    except Exception as error:  # noqa: BLE001
        logger.error("El barrido del arranque falló (%s)", type(error).__name__)
    if cerrados is None:
        raise ConfiguracionError(
            "No se pudo cerrar los análisis pendientes al arrancar: revisa que la base de "
            "datos responda (el valor de la conexión no se muestra)."
        )
    borrados = sum(_borrar(ruta) for ruta in _restos_del_disco(ajustes))
    if cerrados or borrados:
        logger.warning(
            "Barrido del arranque: %d pendientes pasaron a error, %d restos borrados",
            cerrados,
            borrados,
        )
