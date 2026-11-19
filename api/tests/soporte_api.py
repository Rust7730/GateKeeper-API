"""Ayudas de las pruebas de la API que escriben en la BD con los repositorios reales."""

import asyncio
import uuid
from dataclasses import dataclass

from sqlalchemy.engine import URL

from api.app.autenticacion import calcular_hash, generar_key
from api.db.repositorios import crear_api_key, crear_aplicacion
from api.db.sesion import crear_motor, fabrica_sesiones


@dataclass(frozen=True)
class KeySembrada:
    aplicacion_id: uuid.UUID
    prefijo: str
    key: str = ""


def url_sin_servidor(contrasena: str) -> str:
    """URL válida y con la contraseña dada. En el puerto 1 no escucha nadie."""
    return URL.create(
        "postgresql+psycopg",
        username="gk_app",
        password=contrasena,
        host="127.0.0.1",
        port=1,
        database="gk",
    ).render_as_string(hide_password=False)


def url_cruda(esquema: str, credenciales: str, destino: str) -> str:
    """Une una URL tal cual, sin escapar nada, para probar las mal escritas."""
    return f"{esquema}://{credenciales}@{destino}"


def sembrar_key(url: URL, pepper: bytes, nombre: str = "portal") -> KeySembrada:
    """Crea una aplicación y una key. Para pruebas síncronas, fuera de todo bucle de eventos."""

    async def _sembrar() -> KeySembrada:
        motor = crear_motor(url)
        try:
            prefijo, key = generar_key()
            async with fabrica_sesiones(motor).begin() as sesion:
                aplicacion_id = await crear_aplicacion(sesion, nombre)
                await crear_api_key(
                    sesion, aplicacion_id, prefijo, calcular_hash(pepper, key)
                )
            return KeySembrada(aplicacion_id, prefijo, key)
        finally:
            await motor.dispose()

    return asyncio.run(_sembrar())
