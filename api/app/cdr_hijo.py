"""Proceso hijo del CDR: ``python -m api.app.cdr_hijo <entrada> <salida>`` (K09, K28, K31).

Es lo único que abre un archivo no confiable. Por eso, en este orden:

1. Cierra todo descriptor que no sea stdio. No basta con ``close_fds`` del padre: uvicorn
   arranca con uvloop, que crea el proceso con ``uv_spawn`` y no lo aplica, así que un socket
   heredable de la API llegaría hasta aquí (K28).
2. Fija ``RLIMIT_AS`` y ``RLIMIT_CORE``, en los dos límites: uno blando se podría subir.
3. Solo entonces importa python-magic, Pillow y pikepdf. Por eso esos imports van dentro de
   las funciones, y por eso cada parser se importa solo si el tipo lo necesita (arrancar
   pikepdf cuesta 30 ms que un JPEG no tiene por qué pagar).

No importa ``api.db`` ni nada que lo arrastre (K28). Da su veredicto en una sola línea JSON
por stdout. Un fallo que no sea culpa del archivo no se atrapa: el proceso termina con
código distinto de 0 y el padre lo convierte en ``error`` (INV-09).
"""

import contextlib
import json
import os
import resource
import sys
from pathlib import Path

from api.app.tipos import TIPOS_PERMITIDOS

LIMITE_MEMORIA = 1024 * 1024 * 1024  # K31
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


def fijar_limites() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (LIMITE_MEMORIA, LIMITE_MEMORIA))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _reconstruir(entrada: Path, salida: Path, tipo: str) -> str | None:
    if tipo == PDF:
        from api.app.cdr_pdf import sanear_pdf

        return sanear_pdf(entrada, salida)
    from api.app.cdr_imagen import reconstruir_imagen

    return reconstruir_imagen(entrada, salida, tipo)


def analizar(entrada: Path, salida: Path) -> dict[str, str]:
    """Firma con python-magic sobre los bytes (INV-02) y, si pasa, reconstrucción."""
    import magic

    tipo = magic.from_file(str(entrada), mime=True)
    if tipo not in TIPOS_PERMITIDOS:
        return {"veredicto": RECHAZADO, "tipo": tipo, "motivo": "tipo_no_permitido"}
    motivo = _reconstruir(entrada, salida, tipo)
    if motivo is not None:
        return {"veredicto": RECHAZADO, "tipo": tipo, "motivo": motivo}
    return {"veredicto": LIMPIO, "tipo": tipo, "motivo": MOTIVO_LIMPIO}


def main(argumentos: list[str]) -> int:
    if len(argumentos) != 2:
        print(USO, file=sys.stderr)
        return 2
    cerrar_descriptores_heredados()
    fijar_limites()
    veredicto = analizar(Path(argumentos[0]), Path(argumentos[1]))
    print(json.dumps(veredicto), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
