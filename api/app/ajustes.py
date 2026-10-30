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
import os
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine

from api.db.config import url_bd
from api.db.sesion import crear_motor

VARIABLE_HMAC = "GATEKEEPER_PEPPER"
VARIABLE_DATOS = "GATEKEEPER_DATOS"
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


@dataclass(frozen=True, slots=True)
class Ajustes:
    """Ajustes ya válidos: si el objeto existe, sus valores se pueden usar.

    ``pepper`` y ``url_bd`` van fuera del ``repr`` para que un log o un traceback con
    variables locales no se los lleve (CWE-532).
    """

    url_bd: str | URL = field(repr=False)
    pepper: bytes = field(repr=False, compare=False)
    datos: Path

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


def leer_ajustes() -> Ajustes:
    """Lee los ajustes del entorno. Lo llama el arranque, no el import."""
    return Ajustes(url_bd=url_bd(), pepper=leer_pepper(), datos=_leer_datos())


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
