"""Autenticación de usuarios del dashboard, TOTP cifrado, JWT, CSRF y RBAC (F5.01–F5.05)."""

import hashlib
import hmac
import http
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import Depends, HTTPException, Request, status

from api.db.repositorios_admin import DatosUsuario, obtener_usuario_por_id

_HASHER = PasswordHasher()
# Hash dummy precalculado para igualar el tiempo cuando el correo no existe.
_HASH_DUMMY = _HASHER.hash("gatekeeper-dummy-password-timing-pad")

JWT_ALGORITMO = "HS256"
JWT_TTL_S = 15 * 60  # F5.02: 15 minutos
REFRESH_TTL_DIAS = 7
DESAFIO_TOTP_TTL_S = 300
COOKIE_REFRESH = "gk_refresh"
COOKIE_CSRF = "gk_csrf"  # K66: alineado con GateKeeper-Frontend (csrf.ts)
HEADER_CSRF = "x-csrf-token"


@dataclass(frozen=True, slots=True)
class UsuarioActual:
    id: uuid.UUID
    correo: str
    rol: str
    mfa_activo: bool


def _derivar_clave(pepper: bytes, info: bytes, largo: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=largo,
        salt=b"gatekeeper-hkdf-v1",
        info=info,
    ).derive(pepper)


def hashear_contrasena(contrasena: str) -> str:
    return _HASHER.hash(contrasena)


def verificar_contrasena(hash_guardado: str, contrasena: str) -> bool:
    try:
        return _HASHER.verify(hash_guardado, contrasena)
    except VerifyMismatchError:
        return False


def verificar_dummy(contrasena: str) -> None:
    try:
        _HASHER.verify(_HASH_DUMMY, contrasena)
    except VerifyMismatchError:
        pass


def cifrar_totp(pepper: bytes, secreto_base32: str) -> bytes:
    """Cifra el secreto TOTP con AES-256-GCM (nonce de 12 bytes + ciphertext)."""
    clave = _derivar_clave(pepper, b"gatekeeper-totp-v1")
    nonce = os.urandom(12)
    return nonce + AESGCM(clave).encrypt(nonce, secreto_base32.encode("ascii"), None)


def descifrar_totp(pepper: bytes, datos: bytes) -> str:
    clave = _derivar_clave(pepper, b"gatekeeper-totp-v1")
    nonce, cifrado = datos[:12], datos[12:]
    return AESGCM(clave).decrypt(nonce, cifrado, None).decode("ascii")


def verificar_codigo_totp(pepper: bytes, totp_cifrado: bytes, codigo: str) -> bool:
    if not (codigo.isascii() and codigo.isdigit() and len(codigo) == 6):
        return False
    secreto = descifrar_totp(pepper, totp_cifrado)
    return pyotp.TOTP(secreto).verify(codigo, valid_window=1)


def emitir_jwt(pepper: bytes, usuario: DatosUsuario) -> str:
    ahora = datetime.now(UTC)
    clave = _derivar_clave(pepper, b"gatekeeper-jwt-v1")
    carga = {
        "sub": str(usuario.id),
        "email": usuario.email,
        "rol": usuario.rol,
        "mfa": usuario.totp_secreto_cifrado is not None,
        "iat": int(ahora.timestamp()),
        "exp": int((ahora + timedelta(seconds=JWT_TTL_S)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(carga, clave, algorithm=JWT_ALGORITMO)


def emitir_refresh_jwt(
    pepper: bytes, *, jti: uuid.UUID, usuario_id: uuid.UUID, expira_en: datetime
) -> str:
    clave = _derivar_clave(pepper, b"gatekeeper-refresh-v1")
    carga = {
        "sub": str(usuario_id),
        "jti": str(jti),
        "tipo": "refresh",
        "exp": int(expira_en.timestamp()),
    }
    return jwt.encode(carga, clave, algorithm=JWT_ALGORITMO)


def decodificar_refresh_jwt(
    pepper: bytes, token: str
) -> tuple[uuid.UUID, uuid.UUID] | None:
    clave = _derivar_clave(pepper, b"gatekeeper-refresh-v1")
    try:
        datos = jwt.decode(token, clave, algorithms=[JWT_ALGORITMO])
        if datos.get("tipo") != "refresh":
            return None
        return uuid.UUID(datos["jti"]), uuid.UUID(datos["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        return None


def generar_csrf() -> str:
    return secrets.token_urlsafe(32)


def exigir_csrf(request: Request) -> None:
    """F5.04 / K66: exige double-submit cookie ``gk_csrf`` == header ``X-CSRF-Token``."""
    cookie_val = request.cookies.get(COOKIE_CSRF, "")
    header_val = request.headers.get(HEADER_CSRF, "")
    if (
        len(cookie_val) < 16
        or len(header_val) < 16
        or not hmac.compare_digest(cookie_val, header_val)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=http.HTTPStatus.FORBIDDEN.phrase,
        )
    # Si el navegador manda Origin, debe coincidir con el Host (o lista blanca en el futuro).
    origen = request.headers.get("origin")
    if origen:
        host = request.headers.get("host", "")
        esquema = request.headers.get("x-forwarded-proto", request.url.scheme)
        esperado = f"{esquema}://{host}"
        if origen.rstrip("/") != esperado.rstrip("/"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=http.HTTPStatus.FORBIDDEN.phrase,
            )


def _no_autorizado() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=http.HTTPStatus.UNAUTHORIZED.phrase,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def autenticar_usuario(request: Request) -> UsuarioActual:
    """Valida JWT Bearer (F5.02) y comprueba que el usuario sigue activo en BD."""
    cabeceras = request.headers.getlist("authorization")
    if len(cabeceras) != 1 or not cabeceras[0].startswith("Bearer "):
        raise _no_autorizado()
    token = cabeceras[0].removeprefix("Bearer ")
    clave = _derivar_clave(request.app.state.ajustes.pepper, b"gatekeeper-jwt-v1")
    try:
        datos = jwt.decode(token, clave, algorithms=[JWT_ALGORITMO])
        usuario_id = uuid.UUID(datos["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise _no_autorizado() from None

    async with request.app.state.sesiones() as sesion:
        usuario = await obtener_usuario_por_id(sesion, usuario_id)
    if usuario is None or not usuario.activo:
        raise _no_autorizado()
    return UsuarioActual(
        id=usuario.id,
        correo=usuario.email,
        rol=usuario.rol,
        mfa_activo=usuario.totp_secreto_cifrado is not None,
    )


UsuarioAutenticado = Annotated[UsuarioActual, Depends(autenticar_usuario)]


async def exigir_admin(usuario: UsuarioAutenticado) -> UsuarioActual:
    """F5.05 / K06: solo ``admin``; un ``analista`` recibe ``403 Forbidden``."""
    if usuario.rol != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=http.HTTPStatus.FORBIDDEN.phrase,
        )
    return usuario


AdminAutenticado = Annotated[UsuarioActual, Depends(exigir_admin)]


def huella_ip(request: Request) -> str | None:
    host = request.client.host if request.client is not None else None
    if not host:
        return None
    # Validar que sea IP real para tipo INET de PostgreSQL.
    import ipaddress

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def _hash_token(valor: str) -> str:
    return hashlib.sha256(valor.encode("utf-8")).hexdigest()
