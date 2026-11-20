"""Configuración del worker aislado (INV-04, F1.05, K02).

Solo lee la URL de ``redis-queue`` y el directorio de datos. Nunca lee credenciales de
PostgreSQL, el pepper ni ``redis-main``: no existen en su entorno.
"""

import math
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

VARIABLE_REDIS_QUEUE = "GATEKEEPER_REDIS_QUEUE_URL"
VARIABLE_DATOS = "GATEKEEPER_DATOS"
UPLOADS_TMP = "uploads_tmp"
CLEAN_STORE = "clean_store"


class ConfiguracionWorkerError(RuntimeError):
    """Falta un ajuste del worker o no es válido. Nunca incluye el valor."""


def _validar_url(url: object) -> None:
    if type(url) is not str or not url.strip():
        raise ConfiguracionWorkerError(
            f"Falta la URL de Redis de cola ({VARIABLE_REDIS_QUEUE}) o está vacía; "
            "no hay valor por defecto."
        )
    if url != url.strip():
        raise ConfiguracionWorkerError(
            f"La URL de Redis de cola ({VARIABLE_REDIS_QUEUE}) tiene espacios en los bordes "
            "(el valor no se muestra)."
        )


def _validar_comando(comando: object) -> None:
    if (
        type(comando) is not tuple
        or not comando
        or not all(type(parte) is str and parte for parte in comando)
    ):
        raise ConfiguracionWorkerError(
            "El comando del CDR debe ser una tupla de textos."
        )


def _validar_timeout(timeout: object) -> None:
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ConfiguracionWorkerError(
            "El timeout del CDR debe ser un número positivo."
        )


@dataclass(frozen=True, slots=True)
class AjustesWorker:
    """Ajustes validados del worker. ``url_redis_queue`` va fuera del ``repr`` (CWE-532)."""

    url_redis_queue: str = field(repr=False)
    datos: Path
    # Costura de pruebas: ``leer_ajustes_worker()`` nunca los lee del entorno (K42).
    comando_cdr: tuple[str, ...] = (sys.executable, "-m", "api.app.cdr_hijo")
    timeout_cdr_s: float = 30.0
    max_jobs: int = field(default_factory=lambda: os.cpu_count() or 1)

    def __post_init__(self) -> None:
        _validar_url(self.url_redis_queue)
        if not isinstance(self.datos, Path) or not self.datos.is_absolute():
            raise ConfiguracionWorkerError(
                f"El directorio ({VARIABLE_DATOS}) debe ser una ruta absoluta "
                "(la ruta no se muestra)."
            )
        _validar_comando(self.comando_cdr)
        _validar_timeout(self.timeout_cdr_s)
        if type(self.max_jobs) is not int or self.max_jobs < 1:
            raise ConfiguracionWorkerError("max_jobs debe ser un entero positivo.")

    @property
    def uploads_tmp(self) -> Path:
        return self.datos / UPLOADS_TMP

    @property
    def clean_store(self) -> Path:
        return self.datos / CLEAN_STORE


def leer_ajustes_worker() -> AjustesWorker:
    """Lee solo ``GATEKEEPER_REDIS_QUEUE_URL`` y ``GATEKEEPER_DATOS`` del entorno."""
    url = os.environ.get(VARIABLE_REDIS_QUEUE)
    if url is None or not url.strip():
        raise ConfiguracionWorkerError(
            f"Falta la variable de entorno {VARIABLE_REDIS_QUEUE} o está vacía; "
            "no hay valor por defecto."
        )
    datos = os.environ.get(VARIABLE_DATOS)
    if datos is None or not datos.strip():
        raise ConfiguracionWorkerError(
            f"Falta la variable de entorno {VARIABLE_DATOS} o está vacía; "
            "no hay valor por defecto."
        )
    if datos != datos.strip():
        raise ConfiguracionWorkerError(
            f"La variable de entorno {VARIABLE_DATOS} tiene espacios en los bordes."
        )
    return AjustesWorker(url_redis_queue=url, datos=Path(datos))
