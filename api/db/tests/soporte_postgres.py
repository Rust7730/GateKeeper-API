"""Soporte del PostgreSQL desechable de las pruebas: lo usa ``conftest.py``.

Está aparte para poder probar sin Docker los dos caminos de falla (no hay Docker; el
contenedor no arranca) y comprobar que ninguno se omite ni muestra la contraseña.
También concentra en un solo lugar cómo se genera la contraseña y cómo se construye el
contenedor, para que las pruebas de endurecimiento (``test_postgres_endurecido.py``)
fallen si alguien cambia una de las dos cosas.
"""

import contextlib
import secrets
from typing import Protocol

import pytest
from testcontainers.community.postgres import PostgresContainer
from testcontainers.core.docker_client import DockerClient

IMAGEN_POSTGRES = "postgres:16"
PUERTO_POSTGRES = 5432
USUARIO_SUPERUSUARIO = "gk_pruebas"
NOMBRE_BD = "gatekeeper_pruebas"
# CWE-668: el puerto del contenedor se publica solo en loopback, no en 0.0.0.0/::, para
# que nadie en la red alcance el PostgreSQL de las pruebas mientras corren. Por eso
# el Docker debe ser local: con un DOCKER_HOST remoto el puerto quedaría en el loopback
# de ese otro equipo y las pruebas fallarían al conectar (no se omiten).
IP_PUBLICACION = "127.0.0.1"
# 24 bytes aleatorios -> 32 caracteres urlsafe (192 bits).
_BYTES_CONTRASENA = 24


def generar_contrasena() -> str:
    """Contraseña aleatoria del superusuario del contenedor: única fuente de contraseñas.

    El alfabeto **debe** ser urlsafe (``A-Z a-z 0-9 - _``): sin comillas ni barras. Al
    esperar el arranque, testcontainers mete la contraseña entre comillas simples en un
    comando de shell y escapa cada ``'`` como ``'"'"'``; si la contraseña tuviera una,
    el texto del error ya no la contendría literal y ``arrancar_contenedor`` no la
    podría sanear (CWE-532). ``test_postgres_endurecido.py`` exige este alfabeto, así
    que cambiar el generador rompe esa prueba.
    """
    return secrets.token_urlsafe(_BYTES_CONTRASENA)


def crear_contenedor() -> PostgresContainer:
    """``PostgresContainer`` de PostgreSQL 16 con contraseña nueva, sin arrancar.

    La contraseña solo vive en el atributo ``password`` del contenedor (cuyo ``repr``
    no la muestra); quien la necesite la lee de ahí, sin copiarla a una variable local.
    """
    contenedor = PostgresContainer(
        IMAGEN_POSTGRES,
        port=PUERTO_POSTGRES,
        username=USUARIO_SUPERUSUARIO,
        password=generar_contrasena(),
        dbname=NOMBRE_BD,
        driver="psycopg",
    )
    # Publica 5432 en IP_PUBLICACION con un puerto del host libre (HostPort vacío). Se
    # asigna directo porque ``with_bind_ports`` de testcontainers 4.15 solo acepta un
    # número de puerto, no la IP; docker-py traduce la tupla (ip, None) a
    # ``{"HostIp": "127.0.0.1", "HostPort": ""}``. La prueba de endurecimiento consulta
    # a Docker que quedó así.
    contenedor.ports[str(PUERTO_POSTGRES)] = (IP_PUBLICACION, None)  # type: ignore[assignment]
    return contenedor


class Contenedor(Protocol):
    password: str

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


def arrancar_contenedor(contenedor: Contenedor) -> None:
    """Arranca el contenedor o falla con un mensaje que no incluye la contraseña.

    Si la espera vence, testcontainers lanza un error con el comando de comprobación
    (``PGPASSWORD='<contraseña>' psql ...``); aquí se reemplaza por ``***``. El saneado
    busca la contraseña literal, lo que solo funciona porque ``generar_contrasena`` no
    produce ``'``. La contraseña se lee de ``contenedor.password`` sin guardarla en una
    variable local, para que ``pytest -l`` no la muestre.
    """
    error_arranque = None
    try:
        contenedor.start()
    # Amplio a propósito: cualquier error de arranque puede traer la contraseña en el
    # mensaje, así que todos pasan por el saneado y terminan en pytest.fail.
    except Exception as exc:  # noqa: BLE001
        error_arranque = f"{type(exc).__name__}: {exc}".replace(
            contenedor.password, "***"
        )
    if error_arranque is not None:
        # Si el contenedor llegó a crearse, se quita; si no, lo quita el reaper.
        with contextlib.suppress(Exception):
            contenedor.stop()
        pytest.fail(
            f"El PostgreSQL desechable no arrancó. Detalle: {error_arranque}",
            pytrace=False,
        )
