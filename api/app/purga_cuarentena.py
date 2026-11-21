"""Purga diaria de archivos expirados en ``quarantine/`` tras 30 días (F4.09, INV-07).

Uso: ``python -m api.app.purga_cuarentena`` (se ejecuta dentro de ``coordinator`` desde
``gatekeeper-purga.timer``; la API nunca monta ``quarantine/``).
"""

import logging
import os
import stat
import sys
import time
from pathlib import Path

from api.app.ajustes import VARIABLE_DATOS
from worker.ajustes import QUARANTINE

logger = logging.getLogger("gatekeeper.purga")

DIAS_RETENCION_CUARENTENA = 30
_SEGUNDOS_POR_DIA = 86_400


def purgar_cuarentena(
    directorio: Path,
    *,
    dias: int = DIAS_RETENCION_CUARENTENA,
    ahora: float | None = None,
) -> int:
    """Elimina archivos regulares en ``directorio`` con antigüedad >= ``dias``.

    Nunca sigue enlaces simbólicos ni entra en subdirectorios. Devuelve la cantidad eliminada.
    """
    if dias < 1:
        raise ValueError("dias debe ser >= 1")
    try:
        info_dir = os.lstat(directorio)
    except FileNotFoundError:
        return 0
    if not stat.S_ISDIR(info_dir.st_mode):
        return 0

    referencia = time.time() if ahora is None else ahora
    corte = referencia - (dias * _SEGUNDOS_POR_DIA)
    eliminados = 0

    with os.scandir(directorio) as entradas:
        for entrada in entradas:
            try:
                info = entrada.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            if info.st_mtime <= corte:
                try:
                    os.unlink(entrada.path)
                    eliminados += 1
                except FileNotFoundError:
                    continue
                except OSError as error:
                    logger.warning(
                        "No se pudo purgar un archivo en cuarentena (%s)",
                        type(error).__name__,
                    )
    return eliminados


def main() -> int:
    datos = os.environ.get(VARIABLE_DATOS, "").strip()
    if not datos:
        print(f"Falta la variable de entorno {VARIABLE_DATOS}.", file=sys.stderr)
        return 2
    eliminados = purgar_cuarentena(Path(datos) / QUARANTINE)
    print(f"purga_cuarentena: eliminados={eliminados}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
