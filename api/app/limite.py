"""Rate limit (F2.07): contadores en Redis (K59), valores de K58, falla cerrado (K60).

- **Subidas, por aplicación (K10, K58):** token bucket por ``aplicacion_id`` de capacidad 20 que
  se recarga a 2 fichas por segundo (120/min sostenidos). Solo lo gasta ``POST /v1/files``: las
  consultas de estado y las descargas no tienen cupo (decisión del usuario del 2026-11-19).
- **Sin autenticar o con key inválida, por IP (K58):** ventana deslizante de 60 peticiones en
  60 s, en cualquier ruta de ``/v1``. Una ventana fija por minuto de reloj dejaría pasar 120 en
  pocos segundos alrededor del cambio de minuto. Las IPv6 cuentan por su /64 (quien tiene una
  tiene 2^64); las IPv4, por dirección; ``::ffff:a.b.c.d`` es la IPv4 ``a.b.c.d``.
- **Atómico:** cada operación es un único script Lua: leer, decidir y escribir sin carreras entre
  peticiones simultáneas, en una sola ida y vuelta. Todas las claves llevan TTL de un minuto y
  no contienen la key, su secreto ni su hash: solo el ``aplicacion_id`` o la IP.
- **El reloj** es ``Ajustes.reloj_limite`` (``time.time`` en producción), no ``TIME`` de Redis:
  así las pruebas prueban el ritmo sin dormir. Con un solo proceso de API (K51) no hay relojes
  que se contradigan; aun así, uno que retrocede no regala fichas.
- **Redis que no responde (K60):** 1 s como mucho para conectar o para operar, sin reintentos;
  pasado ese tiempo, o con cualquier error (caído, contraseña, ``OOM`` de ``noeviction``), la
  petición recibe 503. Nunca pasa sin límite. Los errores no se registran con su texto: puede
  llevar la dirección o, en algunas versiones, la URL.
- **Comandos:** solo ``EVALSHA`` y, si Redis olvidó el script, ``EVAL``. Nada de
  ``@dangerous`` (la ACL del usuario ``gatekeeper`` lo niega), ni ``SCRIPT LOAD`` ni
  ``CLIENT SETINFO``.
"""

import asyncio
import contextlib
import hashlib
import http
import ipaddress
import logging
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import HTTPException
from redis.asyncio import BlockingConnectionPool, Redis
from redis.backoff import NoBackoff
from redis.exceptions import NoScriptError, RedisError
from redis.retry import Retry

from api.app.ajustes import VARIABLE_REDIS, ConfiguracionError

logger = logging.getLogger("gatekeeper.api")

CAPACIDAD_SUBIDAS = 20  # K58: ráfaga
RECARGA_POR_S = 2.0  # K58: 120 por minuto sostenidos
LIMITE_IP = 60  # K58: sin autenticar o con key inválida
VENTANA_IP_S = 60
# Un bucket que no se toca en 10 s ya está lleno, y una ventana de 60 s ya está vacía: borrar la
# clave a los 60 s no cambia ninguna decisión y la memoria se libera sola.
TTL_S = 60
TIMEOUT_REDIS_S = 1.0  # decisión del usuario del 2026-11-19
CONEXIONES_REDIS = 16  # propuesta: cada operación tarda menos de 1 ms
PREFIJO_IPV6 = 64
_CLAVE_SUBIDAS = "gk:subidas:"
_CLAVE_IP = "gk:ip:"
_SIN_IP = "sin-ip"

# KEYS[1]: hash {f: fichas, t: instante}. ARGV: ahora, capacidad, recarga/s, ttl_ms.
# Devuelve {1, 0} si pasa o {0, segundos enteros hasta la próxima ficha}. Los números se guardan
# con %.17g: tostring() de Lua usa %.14g y perdería las décimas de milisegundo del instante.
_SCRIPT_BUCKET = """
local ahora = tonumber(ARGV[1])
local capacidad = tonumber(ARGV[2])
local recarga = tonumber(ARGV[3])
local guardado = redis.call('HMGET', KEYS[1], 'f', 't')
local fichas = tonumber(guardado[1])
local desde = tonumber(guardado[2])
if fichas == nil or desde == nil then
  fichas = capacidad
  desde = ahora
end
if ahora > desde then
  fichas = math.min(capacidad, fichas + (ahora - desde) * recarga)
  desde = ahora
end
local permitido = 0
local espera = 0
if fichas >= 1 then
  fichas = fichas - 1
  permitido = 1
else
  espera = math.ceil((1 - fichas) / recarga)
end
redis.call('HSET', KEYS[1], 'f', string.format('%.17g', fichas),
  't', string.format('%.17g', desde))
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return {permitido, espera}
"""

# KEYS[1]: zset de instantes. ARGV: ahora, ventana, límite, miembro único, ttl_ms.
# Lo que no pasa no se anota: la ventana nunca guarda más de `límite` miembros.
_SCRIPT_VENTANA = """
local ahora = tonumber(ARGV[1])
local ventana = tonumber(ARGV[2])
local limite = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', string.format('%.17g', ahora - ventana))
if redis.call('ZCARD', KEYS[1]) < limite then
  redis.call('ZADD', KEYS[1], string.format('%.17g', ahora), ARGV[4])
  redis.call('PEXPIRE', KEYS[1], ARGV[5])
  return {1, 0}
end
local primero = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
local espera = math.ceil(tonumber(primero[2]) + ventana - ahora)
if espera < 1 then
  espera = 1
end
return {0, espera}
"""


class RedisNoDisponible(Exception):
    """Redis no respondió a tiempo o rechazó la operación. Sin el error original (K60)."""


@dataclass(frozen=True, slots=True)
class Veredicto:
    permitido: bool
    reintentar_en_s: int = 0


def clave_ip(host: str | None) -> str:
    """La cuenta de una IP: IPv4 exacta, IPv6 por su /64, IPv4 mapeada como IPv4.

    Lo que no es una IP (sin conexión TCP, o un ``client`` de prueba) comparte una sola cuenta:
    no se abre una por texto, que haría crecer Redis a gusto de quien lo mande.
    """
    try:
        direccion = ipaddress.ip_address(host or "")
    except ValueError:
        return _SIN_IP
    if isinstance(direccion, ipaddress.IPv6Address):
        if direccion.ipv4_mapped is not None:
            return str(direccion.ipv4_mapped)
        # int() descarta la zona (%eth0) y la máscara deja solo el /64.
        red = int(direccion) >> (128 - PREFIJO_IPV6) << (128 - PREFIJO_IPV6)
        return f"{ipaddress.IPv6Address(red)}/{PREFIJO_IPV6}"
    return str(direccion)


class _Script:
    """``EVALSHA`` y, si Redis no lo tiene (reinicio), ``EVAL``, que además lo deja en caché."""

    def __init__(self, cuerpo: str) -> None:
        self.cuerpo = cuerpo
        # Huella del script, que Redis usa como nombre; no protege nada.
        self.sha = hashlib.sha1(cuerpo.encode(), usedforsecurity=False).hexdigest()

    async def __call__(self, cliente: Redis, clave: str, *argumentos: object) -> list:
        try:
            return await cliente.evalsha(self.sha, 1, clave, *argumentos)
        except NoScriptError:
            return await cliente.eval(self.cuerpo, 1, clave, *argumentos)


_BUCKET = _Script(_SCRIPT_BUCKET)
_VENTANA = _Script(_SCRIPT_VENTANA)


class Limitador:
    """Las dos cuentas del rate limit sobre un cliente de Redis. Ver el módulo."""

    def __init__(self, cliente: Redis, reloj: Callable[[], float]) -> None:
        self._cliente = cliente
        self._reloj = reloj

    async def _ejecutar(self, script: _Script, clave: str, *argumentos: object) -> Veredicto:
        fallo = None
        try:
            async with asyncio.timeout(TIMEOUT_REDIS_S):
                permitido, espera = await script(self._cliente, clave, *argumentos)
        # TimeoutError: el de asyncio.timeout; OSError: el socket, por si redis-py no lo envuelve.
        except (RedisError, OSError, TimeoutError) as error:
            fallo = type(error).__name__
        if fallo is not None:
            logger.error("Redis no disponible para el rate limit (%s)", fallo)
            raise RedisNoDisponible
        return Veredicto(bool(permitido), int(espera))

    async def gastar_subida(self, aplicacion_id: uuid.UUID) -> Veredicto:
        """Una ficha del bucket de la aplicación (K58)."""
        return await self._ejecutar(
            _BUCKET,
            f"{_CLAVE_SUBIDAS}{aplicacion_id}",
            repr(float(self._reloj())),
            CAPACIDAD_SUBIDAS,
            repr(RECARGA_POR_S),
            TTL_S * 1000,
        )

    async def contar_sin_autenticar(self, host: str | None) -> Veredicto:
        """Una petición sin key válida en la ventana de la IP (K58)."""
        return await self._ejecutar(
            _VENTANA,
            f"{_CLAVE_IP}{clave_ip(host)}",
            repr(float(self._reloj())),
            VENTANA_IP_S,
            LIMITE_IP,
            # Solo distingue dos peticiones del mismo instante; no identifica a nadie.
            secrets.token_hex(8),
            TTL_S * 1000,
        )

    async def cerrar(self) -> None:
        await self._cliente.aclose()
        await self._cliente.connection_pool.aclose()


def abrir_limitador(url: str, reloj: Callable[[], float]) -> Limitador:
    """Crea el cliente sin conectar todavía: si Redis no está, la API arranca igual (K60).

    Un error al leer la URL no muestra ningún trozo de ella (puede traer la contraseña).
    """
    pool = None
    # Amplio a propósito: cualquier error aquí viene de leer la URL y puede traerla.
    with contextlib.suppress(Exception):
        pool = BlockingConnectionPool.from_url(
            url,
            max_connections=CONEXIONES_REDIS,
            # Esperar una conexión libre del pool también cuenta dentro del segundo.
            timeout=TIMEOUT_REDIS_S,
            socket_timeout=TIMEOUT_REDIS_S,
            socket_connect_timeout=TIMEOUT_REDIS_S,
            retry=Retry(NoBackoff(), 0),
            protocol=2,
            driver_info=None,
            health_check_interval=0,
        )
    if pool is None:
        raise ConfiguracionError(
            f"La URL de Redis ({VARIABLE_REDIS}) no es válida "
            "(el valor no se muestra porque puede contener credenciales)."
        )
    return Limitador(Redis(connection_pool=pool), reloj)


def demasiadas_peticiones(reintentar_en_s: int) -> HTTPException:
    """429 de K58: ``Retry-After`` en segundos enteros y la conexión cerrada (no se leyó el
    cuerpo). El 429 de K48 no lleva ``Retry-After``."""
    codigo = http.HTTPStatus.TOO_MANY_REQUESTS
    return HTTPException(
        status_code=codigo,
        detail=codigo.phrase,
        headers={"Retry-After": str(max(1, reintentar_en_s)), "Connection": "close"},
    )


def no_disponible() -> HTTPException:
    """503 de K60. Sin ``Retry-After``: no se sabe cuándo vuelve Redis."""
    codigo = http.HTTPStatus.SERVICE_UNAVAILABLE
    return HTTPException(
        status_code=codigo, detail=codigo.phrase, headers={"Connection": "close"}
    )
