"""Redis desechable de la matriz de ataque (K59), con las mismas reglas que el PostgreSQL de gk-db.

- Su 6379 se publica solo en 127.0.0.1 (CWE-668) y el reaper de testcontainers se crea antes, también
  en loopback (``arrancar_reaper_en_loopback``).
- Contraseña aleatoria por contenedor, sin persistencia (``--save ''``, ``--appendonly no``), como el
  ``redis-main`` de producción.
- La contraseña vive en ``contenedor.password`` y en la URL. Las dos se registran en ``SECRETOS``
  para que el saneado de reportes de ``conftest.py`` las cambie por ``***`` (CWE-532).
"""

import contextlib
import secrets
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
import redis
from testcontainers.community.redis import RedisContainer

from api.db.tests.soporte_postgres import (
    IP_PUBLICACION,
    arrancar_reaper_en_loopback,
    exigir_docker,
)

# La imagen de `redis-main` en producción (diseño de la apertura, §4); aquí sin digest.
IMAGEN_REDIS = "redis:8.10.3-alpine3.23"
PUERTO_REDIS = 6379
_BYTES_CONTRASENA = 24
TIMEOUT_REDIS_S = 5

# Secretos de esta sesión de pytest; el saneado de reportes los reemplaza por ``***``.
SECRETOS: list[str] = []


def registrar_secreto(valor: str) -> None:
    if valor and valor not in SECRETOS:
        SECRETOS.append(valor)


def _crear() -> RedisContainer:
    # urlsafe: sin comillas, barras ni `@`, así va tal cual en la URL y en el comando.
    contrasena = secrets.token_urlsafe(_BYTES_CONTRASENA)
    registrar_secreto(contrasena)
    contenedor = RedisContainer(IMAGEN_REDIS, port=PUERTO_REDIS, password=contrasena)
    contenedor.with_command(
        f"redis-server --requirepass {contrasena} --save '' --appendonly no"
    )
    # Solo en loopback: `with_exposed_ports` lo publicaría en 0.0.0.0 y ::.
    contenedor.ports.clear()
    contenedor.ports[str(PUERTO_REDIS)] = (IP_PUBLICACION, None)  # type: ignore[assignment]
    return contenedor


def url_de(contenedor: RedisContainer) -> str:
    url = (
        f"redis://:{contenedor.password}@{IP_PUBLICACION}:"
        f"{contenedor.get_exposed_port(PUERTO_REDIS)}/0"
    )
    registrar_secreto(url)
    return url


def cliente_de(contenedor: RedisContainer) -> redis.Redis:
    return redis.Redis(
        host=IP_PUBLICACION,
        port=int(contenedor.get_exposed_port(PUERTO_REDIS)),
        password=contenedor.password,
        socket_timeout=TIMEOUT_REDIS_S,
        socket_connect_timeout=TIMEOUT_REDIS_S,
    )


@contextmanager
def redis_desechable() -> Iterator[RedisContainer]:
    """Un Redis nuevo, que se quita al salir (aunque la prueba ya lo haya detenido)."""
    exigir_docker()
    arrancar_reaper_en_loopback()
    contenedor = _crear()
    error = None
    try:
        contenedor.start()
    # Amplio a propósito: el error puede traer la contraseña; todo termina en pytest.fail.
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}".replace(contenedor.password, "***")
    if error is not None:
        with contextlib.suppress(Exception):
            contenedor.stop()
        pytest.fail(f"El Redis desechable no arrancó. Detalle: {error}", pytrace=False)
    try:
        yield contenedor
    finally:
        with contextlib.suppress(Exception):
            contenedor.stop()


def detener(contenedor: RedisContainer) -> None:
    """Simula la caída de Redis: el contenedor desaparece y su puerto deja de escuchar."""
    contenedor.stop()


def volcar_claves(cliente: redis.Redis) -> dict[bytes, tuple[bytes, int]]:
    """Cada clave con todo su contenido serializado y su PTTL."""
    claves: dict[bytes, tuple[bytes, int]] = {}
    for clave in cliente.scan_iter(count=500):
        tipo = cliente.type(clave)
        if tipo == b"string":
            contenido = cliente.get(clave) or b""
        elif tipo == b"hash":
            contenido = repr(cliente.hgetall(clave)).encode()
        elif tipo == b"zset":
            contenido = repr(cliente.zrange(clave, 0, -1, withscores=True)).encode()
        elif tipo == b"list":
            contenido = repr(cliente.lrange(clave, 0, -1)).encode()
        elif tipo == b"set":
            contenido = repr(cliente.smembers(clave)).encode()
        else:
            contenido = repr(cliente.dump(clave)).encode()
        claves[clave] = (contenido, cliente.pttl(clave))
    return claves
