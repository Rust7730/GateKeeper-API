"""Repositorios de administración: usuarios, refresh tokens rotativos y bitácora (F5, K21)."""

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.db.modelos import EventoAuditoria, RefreshToken, Usuario


@dataclass(frozen=True, slots=True)
class DatosUsuario:
    id: uuid.UUID
    email: str
    hash_password: str
    rol: str
    totp_secreto_cifrado: bytes | None
    activo: bool


@dataclass(frozen=True, slots=True)
class DatosRefreshToken:
    jti: uuid.UUID
    usuario_id: uuid.UUID
    familia: uuid.UUID
    expira_en: datetime
    revocado: bool


def _a_datos_usuario(fila: Usuario) -> DatosUsuario:
    return DatosUsuario(
        id=fila.id,
        email=fila.email,
        hash_password=fila.hash_password,
        rol=fila.rol,
        totp_secreto_cifrado=fila.totp_secreto_cifrado,
        activo=fila.activo,
    )


async def crear_usuario(
    sesion: AsyncSession,
    *,
    email: str,
    hash_password: str,
    rol: str,
    totp_secreto_cifrado: bytes | None = None,
) -> uuid.UUID:
    usuario = Usuario(
        email=email,
        hash_password=hash_password,
        rol=rol,
        totp_secreto_cifrado=totp_secreto_cifrado,
    )
    sesion.add(usuario)
    await sesion.flush()
    return usuario.id


async def obtener_usuario_por_email(
    sesion: AsyncSession, email: str
) -> DatosUsuario | None:
    fila = await sesion.scalar(
        select(Usuario).where(func.lower(Usuario.email) == email.lower())
    )
    return None if fila is None else _a_datos_usuario(fila)


async def obtener_usuario_por_id(
    sesion: AsyncSession, usuario_id: uuid.UUID
) -> DatosUsuario | None:
    fila = await sesion.scalar(select(Usuario).where(Usuario.id == usuario_id))
    return None if fila is None else _a_datos_usuario(fila)


async def actualizar_totp_usuario(
    sesion: AsyncSession, usuario_id: uuid.UUID, totp_secreto_cifrado: bytes
) -> None:
    await sesion.execute(
        update(Usuario)
        .where(Usuario.id == usuario_id)
        .values(totp_secreto_cifrado=totp_secreto_cifrado)
    )


async def crear_refresh_token(
    sesion: AsyncSession,
    *,
    jti: uuid.UUID,
    usuario_id: uuid.UUID,
    familia: uuid.UUID,
    expira_en: datetime,
) -> None:
    sesion.add(
        RefreshToken(
            jti=jti,
            usuario_id=usuario_id,
            familia=familia,
            expira_en=expira_en,
            revocado=False,
        )
    )
    await sesion.flush()


async def obtener_refresh_token_para_rotar(
    sesion: AsyncSession, jti: uuid.UUID
) -> DatosRefreshToken | None:
    fila = await sesion.scalar(
        select(RefreshToken).where(RefreshToken.jti == jti).with_for_update()
    )
    if fila is None:
        return None
    return DatosRefreshToken(
        jti=fila.jti,
        usuario_id=fila.usuario_id,
        familia=fila.familia,
        expira_en=fila.expira_en,
        revocado=fila.revocado,
    )


async def marcar_refresh_revocado(sesion: AsyncSession, jti: uuid.UUID) -> None:
    await sesion.execute(
        update(RefreshToken).where(RefreshToken.jti == jti).values(revocado=True)
    )


async def revocar_familia_refresh(sesion: AsyncSession, familia: uuid.UUID) -> None:
    await sesion.execute(
        update(RefreshToken)
        .where(RefreshToken.familia == familia)
        .values(revocado=True)
    )


async def registrar_evento_auditoria(
    sesion: AsyncSession,
    *,
    usuario_id: uuid.UUID | None,
    accion: str,
    objetivo_id: uuid.UUID | None = None,
    motivo: str | None = None,
    ip: str | None = None,
) -> int:
    evento = EventoAuditoria(
        usuario_id=usuario_id,
        accion=accion,
        objetivo_id=objetivo_id,
        motivo=motivo,
        ip=ip,
    )
    sesion.add(evento)
    await sesion.flush()
    return evento.id
