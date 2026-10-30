"""Soporte del PostgreSQL desechable de las pruebas: lo usa ``conftest.py``.

Está aparte para poder probar sin Docker los dos caminos de falla (no hay Docker; el
contenedor no arranca) y comprobar que ninguno se omite ni muestra la contraseña.
"""

import contextlib
from typing import Protocol

import pytest
from testcontainers.core.docker_client import DockerClient

IMAGEN_POSTGRES = "postgres:16"
PUERTO_POSTGRES = 5432
USUARIO_SUPERUSUARIO = "gk_pruebas"
NOMBRE_BD = "gatekeeper_pruebas"


class Contenedor(Protocol):
    def start(self) -> object: ...

    def stop(self) -> None: ...


def exigir_docker() -> None:
    """Falla (no omite) si no hay un daemon de Docker que responda."""
    detalle = None
    try:
        DockerClient().client.ping()
    # Amplio a propósito: docker-py lanza DockerException o errores de requests según
    # dónde falle, y cualquiera de ellos significa "no hay Docker". Nada se silencia:
    # todos terminan en pytest.fail.
    except Exception as exc:  # noqa: BLE001
        detalle = f"{type(exc).__name__}: {exc}"
    # Fuera del except para que la salida muestre solo el mensaje, sin tracebacks.
    if detalle is not None:
        pytest.fail(
            "Docker no está disponible: las pruebas de la BD necesitan PostgreSQL 16 real "
            "en un contenedor (testcontainers) y no se omiten ni se cambian por SQLite. "
            f"Arranca Docker o revisa DOCKER_HOST. Detalle: {detalle}",
            pytrace=False,
        )


def arrancar_contenedor(contenedor: Contenedor, contrasena: str) -> None:
    """Arranca el contenedor o falla con un mensaje que no incluye la contraseña.

    Si la espera vence, testcontainers lanza un error con el comando de comprobación
    (``PGPASSWORD='<contraseña>' psql ...``); aquí se reemplaza por ``***``.
    """
    error_arranque = None
    try:
        contenedor.start()
    # Amplio a propósito: cualquier error de arranque puede traer la contraseña en el
    # mensaje, así que todos pasan por el saneado y terminan en pytest.fail.
    except Exception as exc:  # noqa: BLE001
        error_arranque = f"{type(exc).__name__}: {exc}".replace(contrasena, "***")
    if error_arranque is not None:
        # Si el contenedor llegó a crearse, se quita; si no, lo quita el reaper.
        with contextlib.suppress(Exception):
            contenedor.stop()
        pytest.fail(
            f"El PostgreSQL desechable no arrancó. Detalle: {error_arranque}",
            pytrace=False,
        )
