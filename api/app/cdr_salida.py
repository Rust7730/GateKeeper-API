"""K46: tope de la salida del CDR, aplicado mientras se escribe.

Solo biblioteca estándar: lo usan el proceso hijo (al escribir) y la API (al publicar, porque
el hijo no es de fiar, K28). El hijo corta en cuanto la salida pasaría del tope, antes de
escribir ese trozo: una reconstrucción que crece no llega a ocupar el disco.

``fileno()`` no se ofrece a propósito: con él, Pillow le pasaría el descriptor al codificador
y escribiría sin pasar por ``write``. pikepdf y Pillow propagan la excepción de ``write``.
"""

import io
import os
from collections.abc import Buffer, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

TOPE_SALIDA = 32 * 1024 * 1024  # K46: 33 554 432 bytes


class SalidaDemasiadoGrande(Exception):
    """La salida del CDR pasaría del tope de K46."""


class _EscrituraAcotada(io.RawIOBase):
    def __init__(self, destino: BinaryIO, tope: int) -> None:
        self._destino = destino
        self._tope = tope
        self._escritos = 0

    def writable(self) -> bool:
        return True

    def write(self, datos: Buffer) -> int:
        largo = memoryview(datos).nbytes
        if self._escritos + largo > self._tope:
            raise SalidaDemasiadoGrande
        self._escritos += largo
        return self._destino.write(datos)

    def tell(self) -> int:
        return self._escritos


@contextmanager
def escribir_acotado(salida: Path, tope: int = TOPE_SALIDA) -> Iterator[BinaryIO]:
    """Crea ``salida`` y da un destino que no admite más de ``tope`` bytes.

    ``"xb"``: crea el archivo y falla si ya existe, también si es un enlace simbólico. Si
    algo falla después de crearlo, por el tope o por otra cosa, el archivo se borra.
    """
    with open(salida, "xb") as destino:
        try:
            yield _EscrituraAcotada(destino, tope)  # type: ignore[misc]
        except BaseException:
            destino.close()
            os.unlink(salida)
            raise
