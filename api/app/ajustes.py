"""Configuración de la API (diseño §2): se valida al arrancar y nunca muestra un valor.

Sin valores por defecto: un pepper o un directorio inventado en el código sería una
credencial en el repositorio o un dato guardado donde nadie lo espera. Los errores nombran
la variable y nunca el valor. Como en ``api/db/config.py``, un valor con espacio en blanco
en los bordes se rechaza y no se recorta: un salto de línea final cambiaría el pepper y
dejaría inválidas todas las keys sin ninguna pista. El directorio de datos debe ser una ruta
absoluta: una relativa depende de dónde se arranque y puede caer dentro del repositorio.

Los ``raise`` que siguen a un ``except`` van fuera de él a propósito: dentro, el error
original quedaría en ``__context__``, y el de ``make_url`` puede traer un trozo de la
contraseña de la URL.
"""

import contextlib
import math
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine

from api.db.config import url_bd
from api.db.sesion import crear_motor

VARIABLE_HMAC = "GATEKEEPER_PEPPER"
VARIABLE_DATOS = "GATEKEEPER_DATOS"
# K59: contadores del rate limit. Lleva usuario y contraseña: nunca se muestra.
VARIABLE_REDIS = "GATEKEEPER_REDIS_URL"
MIN_BYTES_HMAC = 32
UPLOADS_TMP = "uploads_tmp"
CLEAN_STORE = "clean_store"
MODO_PRIVADO = 0o700


class ConfiguracionError(RuntimeError):
    """Falta un ajuste o no es válido. El mensaje no incluye el valor."""


def _validar_pepper(pepper: object) -> None:
    if type(pepper) is not bytes:
        raise ConfiguracionError(f"El pepper ({VARIABLE_HMAC}) debe ser bytes.")
    if pepper != pepper.strip():
        raise ConfiguracionError(
            f"El pepper ({VARIABLE_HMAC}) tiene espacios en blanco al inicio o al final."
        )
    if len(pepper) < MIN_BYTES_HMAC:
        raise ConfiguracionError(
            f"El pepper ({VARIABLE_HMAC}) debe tener al menos {MIN_BYTES_HMAC} bytes."
        )


def _validar_comando(comando: object) -> None:
    if (
        type(comando) is not tuple
        or not comando
        or not all(type(parte) is str and parte for parte in comando)
    ):
        raise ConfiguracionError("El comando del CDR debe ser una tupla de textos.")


def _validar_url_redis(url: object) -> None:
    if type(url) is not str or not url.strip():
        raise ConfiguracionError(
            f"Falta la URL de Redis ({VARIABLE_REDIS}) o está vacía; no hay valor por "
            "defecto."
        )
    if url != url.strip():
        raise ConfiguracionError(
            f"La URL de Redis ({VARIABLE_REDIS}) tiene espacios en blanco al inicio o al "
            "final (el valor no se muestra)."
        )


def _validar_timeout(nombre: str, timeout: object) -> None:
    # type() y no isinstance(): True pasaría por 1.
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ConfiguracionError(f"El {nombre} debe ser un número positivo.")


@dataclass(frozen=True, slots=True)
class Ajustes:
    """Ajustes ya válidos: si el objeto existe, sus valores se pueden usar.

    ``pepper``, ``url_bd`` y ``url_redis`` van fuera del ``repr`` para que un log o un
    traceback con variables locales no se los lleve (CWE-532).
    """

    url_bd: str | URL = field(repr=False)
    pepper: bytes = field(repr=False, compare=False)
    datos: Path
    url_redis: str = field(repr=False)  # K59
    # Costura de pruebas: ``leer_ajustes()`` nunca los lee del entorno. Una variable que
    # cambiara el comando sería ejecución de código por configuración.
    comando_cdr: tuple[str, ...] = (sys.executable, "-m", "api.app.cdr_hijo")
    timeout_cdr_s: float = 30  # param:timeout_analisis_por_archivo
    timeout_recepcion_s: float = 60  # K40
    # Instante actual en segundos de época, con el que el rate limit recarga y cuenta. Con uno
    # leído del entorno, quien tocara la configuración podría desactivar el límite.
    reloj_limite: Callable[[], float] = field(
        default=time.time, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if not self.url_bd:
            raise ConfiguracionError("Falta la URL de la base de datos.")
        _validar_pepper(self.pepper)
        if not isinstance(self.datos, Path):
            raise ConfiguracionError(f"El directorio ({VARIABLE_DATOS}) debe ser Path.")
        if not self.datos.is_absolute():
            raise ConfiguracionError(
                f"El directorio ({VARIABLE_DATOS}) debe ser una ruta absoluta "
                "(la ruta no se muestra)."
            )
        _validar_url_redis(self.url_redis)
        _validar_comando(self.comando_cdr)
        if not callable(self.reloj_limite):
            raise ConfiguracionError("El reloj del rate limit debe ser invocable.")
        _validar_timeout("timeout del CDR", self.timeout_cdr_s)
        _validar_timeout("timeout de la recepción", self.timeout_recepcion_s)

    @property
    def uploads_tmp(self) -> Path:
        return self.datos / UPLOADS_TMP

    @property
    def clean_store(self) -> Path:
        return self.datos / CLEAN_STORE


def leer_pepper() -> bytes:
    """Pepper de ``GATEKEEPER_PEPPER``, en los bytes exactos del entorno.

    ``fsencode`` no falla con un valor que no sea UTF-8, y el largo se cuenta en bytes.
    """
    valor = os.environ.get(VARIABLE_HMAC)
    if valor is None or not valor.strip():
        raise ConfiguracionError(
            f"Falta la variable de entorno {VARIABLE_HMAC} o está vacía; "
            "no hay valor por defecto."
        )
    pepper = os.fsencode(valor)
    _validar_pepper(pepper)
    return pepper


def _leer_datos() -> Path:
    valor = os.environ.get(VARIABLE_DATOS)
    if valor is None or not valor.strip():
        raise ConfiguracionError(
            f"Falta la variable de entorno {VARIABLE_DATOS} o está vacía; "
            "no hay valor por defecto."
        )
    if valor != valor.strip():
        raise ConfiguracionError(
            f"La variable de entorno {VARIABLE_DATOS} tiene espacios en blanco al inicio "
            "o al final."
        )
    return Path(valor)


def _leer_url_redis() -> str:
    valor = os.environ.get(VARIABLE_REDIS)
    if valor is None or not valor.strip():
        raise ConfiguracionError(
            f"Falta la variable de entorno {VARIABLE_REDIS} o está vacía; "
            "no hay valor por defecto."
        )
    return valor


def leer_ajustes() -> Ajustes:
    """Lee los ajustes del entorno. Lo llama el arranque, no el import."""
    return Ajustes(
        url_bd=url_bd(),
        pepper=leer_pepper(),
        datos=_leer_datos(),
        url_redis=_leer_url_redis(),
    )


def _asegurar_directorio_privado(ruta: Path) -> None:
    """Deja ``ruta`` como directorio real con modo 0700, exista o no.

    ``mkdir`` no basta: su modo pasa por la umask y no toca un directorio que ya existe. El
    ``fchmod`` va sobre un descriptor abierto con ``O_NOFOLLOW`` porque ``chmod`` seguiría
    un enlace simbólico y dejaría el almacén apuntando fuera del directorio de datos.
    """
    with contextlib.suppress(FileExistsError):
        ruta.mkdir(mode=MODO_PRIVADO)
    descriptor = os.open(ruta, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchmod(descriptor, MODO_PRIVADO)
    finally:
        os.close(descriptor)


def preparar_directorios(datos: Path) -> None:
    """Crea ``uploads_tmp/`` y ``clean_store/`` con modo 0700 dentro de ``datos`` (INV-03).

    El modo de una base que ya existe no se cambia: puede ser un volumen montado. Si hay
    que crearla, nace también con 0700.
    """
    fallo = False
    try:
        datos.mkdir(mode=MODO_PRIVADO, parents=True, exist_ok=True)
        _asegurar_directorio_privado(datos / UPLOADS_TMP)
        _asegurar_directorio_privado(datos / CLEAN_STORE)
    except (OSError, ValueError):
        fallo = True
    if fallo:
        raise ConfiguracionError(
            f"No se pudo preparar el directorio de datos ({VARIABLE_DATOS}): revisa que "
            "sea un directorio con permisos y que sus subdirectorios no sean enlaces "
            "(la ruta no se muestra)."
        )


def abrir_motor(url: str | URL) -> AsyncEngine:
    """Crea el motor sin que un error de la URL muestre ningún trozo de ella.

    ``make_url`` lanza ``ValueError`` con el texto del puerto, y una contraseña con ``@`` o
    ``:`` sin escapar termina justo ahí.
    """
    motor = None
    # Amplio a propósito: cualquier error aquí viene de leer la URL y puede traerla.
    with contextlib.suppress(Exception):
        motor = crear_motor(url)
    if motor is None:
        raise ConfiguracionError(
            "La URL de la base de datos no es válida "
            "(el valor no se muestra porque puede contener credenciales)."
        )
    return motor
