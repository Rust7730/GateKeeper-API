"""Alta de una aplicación y su primera key: ``python -m api.app.alta "<nombre>"`` (diseño §6).

Lee ``GATEKEEPER_DATABASE_URL`` y ``GATEKEEPER_PEPPER``; no necesita ``GATEKEEPER_DATOS``.
La key completa solo existe aquí: sale una vez por stdout, ya confirmada la transacción, y
de ahí no se puede recuperar. Los errores van a stderr y nunca repiten el nombre recibido,
que podría traer secuencias de escape, ni el texto de una excepción de la BD.
"""

import asyncio
import sys

from sqlalchemy.engine import URL

from api.app.ajustes import ConfiguracionError, abrir_motor, leer_pepper
from api.app.autenticacion import calcular_hash, generar_key
from api.db.config import ConfiguracionBDError, url_bd
from api.db.repositorios import (
    ViolacionDeRestriccion,
    crear_api_key,
    crear_aplicacion,
)
from api.db.sesion import fabrica_sesiones

USO = 'Uso: python -m api.app.alta "<nombre>"'
_NOMBRE_INVALIDO = (
    "El nombre no es válido: debe tener de 1 a 100 caracteres, sin espacios en los bordes "
    "ni caracteres de control."
)
_MENSAJES_DE_RESTRICCION = {
    "uq_aplicacion_nombre_lower": (
        "Ya existe una aplicación con ese nombre (sin distinguir mayúsculas). "
        "No se creó nada."
    ),
    "ck_aplicacion_nombre_valido": _NOMBRE_INVALIDO,
    "ck_aplicacion_nombre_sin_control": _NOMBRE_INVALIDO,
}


def _se_puede_enviar(nombre: str) -> bool:
    """Lo que ni llega a la BD: un NUL o un surrogate, que es como llega un byte no UTF-8."""
    if "\x00" in nombre:
        return False
    try:
        nombre.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


async def _crear(url: str | URL, pepper: bytes, nombre: str) -> str:
    """Crea aplicación y key en una sola transacción y devuelve la key.

    Si la key falla, tampoco queda la aplicación. Una ``ViolacionDeRestriccion`` sale del
    bloque ``begin()``, que revierte: la transacción ya está abortada en PostgreSQL.
    """
    prefijo, key = generar_key()
    motor = abrir_motor(url)
    try:
        async with fabrica_sesiones(motor).begin() as sesion:
            aplicacion_id = await crear_aplicacion(sesion, nombre)
            await crear_api_key(
                sesion, aplicacion_id, prefijo, calcular_hash(pepper, key)
            )
    finally:
        await motor.dispose()
    return key


def _fallo(mensaje: str) -> int:
    print(mensaje, file=sys.stderr)
    return 1


def main(argumentos: list[str] | None = None) -> int:
    argumentos = sys.argv[1:] if argumentos is None else argumentos
    if len(argumentos) != 1:
        print(USO, file=sys.stderr)
        return 2
    nombre = argumentos[0]
    if not _se_puede_enviar(nombre):
        return _fallo(_NOMBRE_INVALIDO)

    try:
        key = asyncio.run(_crear(url_bd(), leer_pepper(), nombre))
    except (ConfiguracionError, ConfiguracionBDError) as error:
        return _fallo(str(error))
    except ViolacionDeRestriccion as error:
        return _fallo(
            _MENSAJES_DE_RESTRICCION.get(
                error.restriccion or "",
                f"La BD rechazó el alta ({error.restriccion}). No se creó nada.",
            )
        )
    # Amplio a propósito: el texto de un error de conexión trae host y usuario, y un
    # traceback aquí no ayuda a quien corre el comando. Solo se muestra el tipo.
    except Exception as error:  # noqa: BLE001
        return _fallo(f"No se pudo completar el alta ({type(error).__name__}).")

    # Fuera del bloque de la transacción: nunca se imprime una key que no quedó guardada.
    print(key)
    print("Guarda la key: no se volverá a mostrar.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
