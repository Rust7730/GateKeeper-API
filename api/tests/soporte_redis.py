"""Redis desechable de las pruebas de la API (K59), con los usuarios de producción.

- Usuario ``gatekeeper`` con la ACL de ``deploy/instalar.sh`` (``~* +@all -@dangerous``): la API
  entra con él, así que toda prueba que pasa demuestra también que el rate limit no usa ningún
  comando peligroso (``CONFIG``, ``KEYS``, ``FLUSHALL``, ``INFO``...).
- Usuario ``default`` con contraseña y todos los permisos: solo para las pruebas (vaciar, ver
  las claves, ``CONFIG SET maxmemory``). testcontainers lo usa para saber que arrancó.
- Su 6379 se publica solo en 127.0.0.1 (CWE-668), con el reaper ya creado en loopback.
- Contraseñas aleatorias, sin persistencia. Las dos se registran en ``SECRETOS`` para que el
  saneado de reportes de ``conftest.py`` las cambie por ``***`` (CWE-532).
"""

import contextlib
import secrets
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

import pytest
import redis
from testcontainers.community.redis import RedisContainer

from api.db.tests.soporte_postgres import (
    IP_PUBLICACION,
    arrancar_reaper_en_loopback,
    exigir_docker,
)

IMAGEN_REDIS = "redis:8.10.3-alpine3.23"  # la de `redis-main` (deploy/docker-compose.yml)
PUERTO_REDIS = 6379
USUARIO_API = "gatekeeper"
ACL_API = "~* +@all -@dangerous"  # deploy/instalar.sh
TIMEOUT_ADMIN_S = 5

SECRETOS: list[str] = []


def registrar_secreto(valor: str) -> None:
    if valor and valor not in SECRETOS:
        SECRETOS.append(valor)


@dataclass(frozen=True)
class RedisDePrueba:
    contenedor: RedisContainer = field(repr=False)
    clave_api: str = field(repr=False)

    @property
    def puerto(self) -> int:
        return int(self.contenedor.get_exposed_port(PUERTO_REDIS))

    def url_api(self) -> str:
        """URL del usuario ``gatekeeper``, como ``GATEKEEPER_REDIS_URL`` en producción."""
        url = f"redis://{USUARIO_API}:{self.clave_api}@{IP_PUBLICACION}:{self.puerto}/0"
        registrar_secreto(url)
        return url

    def admin(self) -> redis.Redis:
        """Cliente con todos los permisos. Solo para preparar y mirar."""
        return redis.Redis(
            host=IP_PUBLICACION,
            port=self.puerto,
            password=self.contenedor.password,
            socket_timeout=TIMEOUT_ADMIN_S,
            socket_connect_timeout=TIMEOUT_ADMIN_S,
        )


@contextmanager
def redis_desechable() -> Iterator[RedisDePrueba]:
    exigir_docker()
    arrancar_reaper_en_loopback()
    # Hexadecimal: va tal cual en la URL y en la línea de comandos.
    clave_admin = secrets.token_hex(24)
    clave_api = secrets.token_hex(24)
    registrar_secreto(clave_admin)
    registrar_secreto(clave_api)
    contenedor = RedisContainer(IMAGEN_REDIS, port=PUERTO_REDIS, password=clave_admin)
    contenedor.with_command(
        f"redis-server --requirepass {clave_admin}"
        f" --user {USUARIO_API} on >{clave_api} {ACL_API}"
        " --save '' --appendonly no"
    )
    contenedor.ports.clear()
    contenedor.ports[str(PUERTO_REDIS)] = (IP_PUBLICACION, None)  # type: ignore[assignment]
    error = None
    try:
        contenedor.start()
    # Amplio a propósito: el error puede traer la contraseña; todo termina en pytest.fail.
    except Exception as exc:  # noqa: BLE001
        error = type(exc).__name__
    if error is not None:
        with contextlib.suppress(Exception):
            contenedor.stop()
        pytest.fail(f"El Redis desechable no arrancó ({error}).", pytrace=False)
    try:
        yield RedisDePrueba(contenedor, clave_api)
    finally:
        with contextlib.suppress(Exception):
            contenedor.stop()


@contextmanager
def redis_colgado() -> Iterator[str]:
    """Un "Redis" que acepta la conexión y nunca responde. Devuelve su URL.

    Un hilo acepta y retiene las conexiones abiertas: lo que manda el cliente (``AUTH``) se queda
    sin respuesta, como con un Redis colgado.
    """
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    abiertas: list[socket.socket] = []
    parar = threading.Event()

    def _aceptar() -> None:
        servidor.settimeout(0.05)
        while not parar.is_set():
            with contextlib.suppress(OSError):
                conexion, _ = servidor.accept()
                abiertas.append(conexion)

    servidor.bind((IP_PUBLICACION, 0))
    servidor.listen(64)
    hilo = threading.Thread(target=_aceptar, daemon=True)
    hilo.start()
    try:
        puerto = servidor.getsockname()[1]
        yield f"redis://{USUARIO_API}:{secrets.token_hex(8)}@{IP_PUBLICACION}:{puerto}/0"
    finally:
        parar.set()
        hilo.join()
        for conexion in abiertas:
            conexion.close()
        servidor.close()


def puerto_cerrado() -> str:
    """URL de un puerto en el que no escucha nadie (conexión rechazada)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as libre:
        libre.bind((IP_PUBLICACION, 0))
        puerto = libre.getsockname()[1]
    return f"redis://{USUARIO_API}:{secrets.token_hex(8)}@{IP_PUBLICACION}:{puerto}/0"


class RelojFalso:
    """Segundos de época que solo avanzan con ``avanzar`` (costura ``Ajustes.reloj_limite``)."""

    def __init__(self, inicio: float) -> None:
        self.ahora = inicio

    def __call__(self) -> float:
        return self.ahora

    def avanzar(self, segundos: float) -> None:
        self.ahora += segundos


class RelojQueCorre:
    """Cada lectura avanza 1 s: el rate limit nunca se agota en las pruebas de otra cosa.

    Las peticiones siguen haciendo su ida a Redis; solo el ritmo deja de importar.
    """

    def __init__(self, inicio: float) -> None:
        self.ahora = inicio

    def __call__(self) -> float:
        self.ahora += 1.0
        return self.ahora
