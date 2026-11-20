"""Alta por CLI de un usuario del dashboard (``admin`` o ``analista``) (F5.01).

Uso: ``python -m api.app.alta_usuario <correo> <admin|analista>`` (pide la contraseña por
``getpass`` o stdin; si es ``admin``, genera un secreto TOTP y muestra el ``otpauth_uri`` una
sola vez).
"""

import asyncio
import getpass
import sys

import pyotp

from api.app.ajustes import abrir_motor, leer_pepper
from api.app.auth_usuarios import cifrar_totp, hashear_contrasena
from api.db.config import url_bd
from api.db.repositorios_admin import crear_usuario
from api.db.sesion import fabrica_sesiones


async def _crear(correo: str, rol: str, contrasena: str) -> tuple[str, str | None]:
    pepper = leer_pepper()
    motor = abrir_motor(url_bd())
    secreto_totp = pyotp.random_base32() if rol == "admin" else None
    totp_cifrado = cifrar_totp(pepper, secreto_totp) if secreto_totp else None
    try:
        async with fabrica_sesiones(motor).begin() as sesion:
            uid = await crear_usuario(
                sesion,
                email=correo,
                hash_password=hashear_contrasena(contrasena),
                rol=rol,
                totp_secreto_cifrado=totp_cifrado,
            )
    finally:
        await motor.dispose()
    uri = (
        pyotp.TOTP(secreto_totp).provisioning_uri(name=correo, issuer_name="Gatekeeper")
        if secreto_totp
        else None
    )
    return str(uid), uri


def main(argumentos: list[str]) -> int:
    if len(argumentos) != 2 or argumentos[1] not in ("admin", "analista"):
        print(
            "Uso: python -m api.app.alta_usuario <correo> <admin|analista>",
            file=sys.stderr,
        )
        return 2
    correo, rol = argumentos[0].strip(), argumentos[1]
    contrasena = (
        getpass.getpass("Contraseña: ")
        if sys.stdin.isatty()
        else sys.stdin.readline().rstrip("\r\n")
    )
    if len(contrasena) < 12:
        print("La contraseña debe tener al menos 12 caracteres.", file=sys.stderr)
        return 2
    uid, uri = asyncio.run(_crear(correo, rol, contrasena))
    print(f"Usuario creado: {uid} ({rol})")
    if uri:
        print(f"TOTP (guárdalo una sola vez): {uri}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
