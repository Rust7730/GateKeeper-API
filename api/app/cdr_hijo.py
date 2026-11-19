"""Proceso hijo del CDR: ``python -m api.app.cdr_hijo <entrada> <salida>`` (K09, K28, K31).

Es lo único que abre un archivo no confiable. Por eso, en este orden:

1. Cierra todo descriptor que no sea stdio. No basta con ``close_fds`` del padre: uvicorn
   arranca con uvloop, que crea el proceso con ``uv_spawn`` y no lo aplica, así que un socket
   heredable de la API llegaría hasta aquí (K28).
2. Se ata a la API con ``PR_SET_PDEATHSIG`` (K42): si la API muere, el kernel le manda
   ``SIGKILL``. Lo hace el propio hijo porque uvloop no admite ``preexec_fn``. Si la API murió
   antes de que la señal quedara puesta, el hijo ya es huérfano y no sigue.
3. Fija ``RLIMIT_AS``, ``RLIMIT_CORE`` y ``RLIMIT_CPU``, en los dos límites: uno blando se
   podría subir. El timeout de 30 s lo lleva la API; ``RLIMIT_CPU`` (K50) es el tope que queda
   si la API no está para aplicarlo.
4. Solo entonces importa python-magic, Pillow y pikepdf. Por eso esos imports van dentro de
   las funciones, y por eso cada parser se importa solo si el tipo lo necesita (arrancar
   pikepdf cuesta 30 ms que un JPEG no tiene por qué pagar).
5. Se aísla con Landlock (K53, ``aislamiento.py``) justo antes de abrir la entrada, al
   principio de ``analizar``. Antes carga python-magic y su base de datos, que no leen nada
   del archivo: así la base no tiene que quedar legible. Pillow y pikepdf se importan después,
   según el tipo: por eso Landlock deja leer Python, el entorno virtual, el código de
   ``api/app`` y las bibliotecas del sistema (Pillow importa sus plugins al abrir, así que el
   entorno virtual tendría que quedar legible de todos modos). La salida va en el directorio
   de trabajo ``<uuid>.parcial`` que crea la API: es lo único donde puede escribir. Si
   Landlock no se puede aplicar, el hijo termina sin analizar y la API lo deja en ``error``.

No importa ``api.db`` ni nada que lo arrastre (K28). Da su veredicto en una sola línea JSON
por stdout. Un fallo que no sea culpa del archivo no se atrapa: el proceso termina con
código distinto de 0 y el padre lo convierte en ``error`` (INV-09).
"""

import contextlib
import ctypes
import json
import os
import resource
import signal
import sys
from pathlib import Path

from api.app.aislamiento import aplicar
from api.app.tipos import TIPOS_PERMITIDOS

LIMITE_MEMORIA = 1024 * 1024 * 1024  # K31
LIMITE_CPU_S = 35  # K50: por encima del timeout de 30 s que aplica la API
_PR_SET_PDEATHSIG = 1  # <linux/prctl.h>
# Bibliotecas compartidas que pueden cargar Pillow, pikepdf o libmagic. Las que no existan se
# saltan al aplicar Landlock.
_BIBLIOTECAS_DEL_SISTEMA = (
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/usr/local/lib",
)
# qpdf lo lee al abrir un PDF cifrado con AES; sin él, el rechazo de vec:06 sería un `error`.
_ALEATORIO = "/dev/urandom"
_HUERFANO = 3
LIMPIO = "limpio"
RECHAZADO = "rechazado"
MOTIVO_LIMPIO = "ok"
PDF = "application/pdf"
USO = "Uso: python -m api.app.cdr_hijo <entrada> <salida>"


def cerrar_descriptores_heredados() -> None:
    """Cierra lo que haya abierto más allá de stdio.

    Recorre ``/proc/self/fd`` y no usa ``os.closerange``: sin ``close_range`` en el binario de
    Python, esa función hace una llamada por cada número hasta ``SC_OPEN_MAX``, 350 ms con el
    límite de esta máquina. Si ``/proc`` faltara, el hijo termina mal y el archivo, en
    ``error``: nunca se analiza con descriptores ajenos. El descriptor del propio ``listdir``
    ya estará cerrado al llegar a él, de ahí el ``suppress``.
    """
    for nombre in os.listdir("/proc/self/fd"):
        descriptor = int(nombre)
        if descriptor > 2:
            with contextlib.suppress(OSError):
                os.close(descriptor)


def _fijar_senal_de_muerte() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        numero = ctypes.get_errno()
        raise OSError(numero, os.strerror(numero))


def atar_al_padre(padre: int) -> None:
    """``SIGKILL`` al morir ``padre``. Si ya no es el padre, murió antes: se sale sin analizar.

    ``padre`` es el ``getppid()`` del principio de ``main``. La comprobación cubre la muerte
    entre ese momento y ``prctl``; antes de eso (el arranque del intérprete) la cubre
    ``RLIMIT_CPU``.
    """
    _fijar_senal_de_muerte()
    if os.getppid() != padre:
        sys.exit(_HUERFANO)


def fijar_limites() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (LIMITE_MEMORIA, LIMITE_MEMORIA))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (LIMITE_CPU_S, LIMITE_CPU_S))


def directorios_de_lectura() -> list[str]:
    """Lo único que el hijo puede leer además de su entrada (K53): directorios y archivos."""
    return sorted(
        {
            sys.prefix,
            sys.exec_prefix,
            sys.base_prefix,
            sys.base_exec_prefix,
            str(Path(__file__).resolve().parent),
            *_BIBLIOTECAS_DEL_SISTEMA,
            _ALEATORIO,
        }
    )


def aislar(entrada: Path, salida: Path) -> None:
    """Landlock: lee lo de ``directorios_de_lectura`` y ``entrada``; escribe en su ``.parcial``."""
    aplicar(directorios_de_lectura(), entrada, salida.parent)


def _reconstruir(entrada: Path, salida: Path, tipo: str) -> str | None:
    if tipo == PDF:
        from api.app.cdr_pdf import sanear_pdf

        return sanear_pdf(entrada, salida)
    from api.app.cdr_imagen import reconstruir_imagen

    return reconstruir_imagen(entrada, salida, tipo)


def analizar(entrada: Path, salida: Path) -> dict[str, str]:
    """Firma con python-magic sobre los bytes (INV-02) y, si pasa, reconstrucción.

    Landlock va antes de abrir la entrada; python-magic y su base, antes de Landlock.
    """
    import magic

    detector = magic.Magic(mime=True)
    # Ya no se podría escribir el bytecode de lo que se importe después: que no lo intente.
    sys.dont_write_bytecode = True
    aislar(entrada, salida)
    tipo = detector.from_file(str(entrada))
    if tipo not in TIPOS_PERMITIDOS:
        return {"veredicto": RECHAZADO, "tipo": tipo, "motivo": "tipo_no_permitido"}
    motivo = _reconstruir(entrada, salida, tipo)
    if motivo is not None:
        return {"veredicto": RECHAZADO, "tipo": tipo, "motivo": motivo}
    return {"veredicto": LIMPIO, "tipo": tipo, "motivo": MOTIVO_LIMPIO}


def main(argumentos: list[str]) -> int:
    padre = os.getppid()
    if len(argumentos) != 2:
        print(USO, file=sys.stderr)
        return 2
    cerrar_descriptores_heredados()
    atar_al_padre(padre)
    fijar_limites()
    veredicto = analizar(Path(argumentos[0]), Path(argumentos[1]))
    print(json.dumps(veredicto), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
