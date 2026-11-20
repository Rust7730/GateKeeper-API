"""Router ``/v1/auth``: login Argon2+TOTP, refresh rotativo con CSRF, logout y RBAC (F5.01–F5.05)."""

import http
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pyotp
from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from api.app.auth_usuarios import (
    COOKIE_CSRF,
    COOKIE_REFRESH,
    DESAFIO_TOTP_TTL_S,
    JWT_TTL_S,
    REFRESH_TTL_DIAS,
    AdminAutenticado,
    UsuarioAutenticado,
    cifrar_totp,
    decodificar_refresh_jwt,
    emitir_jwt,
    emitir_refresh_jwt,
    exigir_csrf,
    generar_csrf,
    huella_ip,
    verificar_codigo_totp,
    verificar_contrasena,
    verificar_dummy,
)
from api.db.repositorios_admin import (
    DatosUsuario,
    actualizar_totp_usuario,
    crear_refresh_token,
    marcar_refresh_revocado,
    obtener_refresh_token_para_rotar,
    obtener_usuario_por_email,
    obtener_usuario_por_id,
    registrar_evento_auditoria,
    revocar_familia_refresh,
)

_CLAVE_MFA = "gk:mfa:"


class InicioSesionEntrada(BaseModel):
    correo: str = Field(min_length=3, max_length=254)
    contrasena: str = Field(min_length=1, max_length=256)


class VerificacionTotpEntrada(BaseModel):
    desafio_id: str = Field(min_length=16, max_length=128)
    codigo: str = Field(min_length=6, max_length=6)


def _usuario_dto(usuario: DatosUsuario) -> dict[str, Any]:
    return {
        "id": str(usuario.id),
        "correo": usuario.email,
        "rol": usuario.rol,
        "mfa_activo": usuario.totp_secreto_cifrado is not None,
    }


def _cookie_segura(request: Request) -> bool:
    esquema = request.headers.get("x-forwarded-proto", request.url.scheme)
    return esquema == "https"


def _fijar_cookies_sesion(
    response: Response,
    request: Request,
    refresh_jwt: str,
    csrf_token: str,
) -> None:
    segura = _cookie_segura(request)
    max_age = REFRESH_TTL_DIAS * 86_400
    response.set_cookie(
        key=COOKIE_REFRESH,
        value=refresh_jwt,
        max_age=max_age,
        path="/v1/auth",
        httponly=True,
        secure=segura,
        samesite="strict",
    )
    response.set_cookie(
        key=COOKIE_CSRF,
        value=csrf_token,
        max_age=max_age,
        path="/",
        httponly=False,
        secure=segura,
        samesite="strict",
    )


def _borrar_cookies_sesion(response: Response, request: Request) -> None:
    segura = _cookie_segura(request)
    response.delete_cookie(
        key=COOKIE_REFRESH,
        path="/v1/auth",
        httponly=True,
        secure=segura,
        samesite="strict",
    )
    response.delete_cookie(
        key=COOKIE_CSRF, path="/", httponly=False, secure=segura, samesite="strict"
    )


async def _abrir_sesion(
    request: Request, response: Response, usuario: DatosUsuario
) -> dict[str, Any]:
    pepper = request.app.state.ajustes.pepper
    jti = uuid.uuid4()
    familia = uuid.uuid4()
    expira_en = datetime.now(UTC) + timedelta(days=REFRESH_TTL_DIAS)
    async with request.app.state.sesiones.begin() as sesion:
        await crear_refresh_token(
            sesion, jti=jti, usuario_id=usuario.id, familia=familia, expira_en=expira_en
        )
        await registrar_evento_auditoria(
            sesion,
            usuario_id=usuario.id,
            accion="inicio_sesion",
            ip=huella_ip(request),
        )
    token_acceso = emitir_jwt(pepper, usuario)
    refresh_jwt = emitir_refresh_jwt(
        pepper, jti=jti, usuario_id=usuario.id, expira_en=expira_en
    )
    _fijar_cookies_sesion(response, request, refresh_jwt, generar_csrf())
    return {
        "token_acceso": token_acceso,
        "expira_en": JWT_TTL_S,
        "usuario": _usuario_dto(usuario),
    }


def _no_autorizado() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=http.HTTPStatus.UNAUTHORIZED.phrase,
    )


def crear_router_auth() -> APIRouter:
    router = APIRouter(prefix="/v1/auth")

    @router.post("/login")
    async def login(
        datos: InicioSesionEntrada, request: Request, response: Response
    ) -> dict[str, Any]:
        ip = huella_ip(request)
        async with request.app.state.sesiones() as sesion:
            usuario = await obtener_usuario_por_email(sesion, datos.correo.strip())
        if usuario is None:
            verificar_dummy(datos.contrasena)
            async with request.app.state.sesiones.begin() as sesion:
                await registrar_evento_auditoria(
                    sesion, usuario_id=None, accion="inicio_fallido", ip=ip
                )
            raise _no_autorizado()

        if not usuario.activo or not verificar_contrasena(
            usuario.hash_password, datos.contrasena
        ):
            async with request.app.state.sesiones.begin() as sesion:
                await registrar_evento_auditoria(
                    sesion, usuario_id=usuario.id, accion="inicio_fallido", ip=ip
                )
            raise _no_autorizado()

        # F5.01: si el usuario tiene TOTP activo (obligatorio para admin), paso 2 requerido.
        if usuario.totp_secreto_cifrado is not None:
            desafio_id = secrets.token_urlsafe(32)
            redis = request.app.state.cola_orquestar
            await redis.set(
                f"{_CLAVE_MFA}{desafio_id}",
                json.dumps({"usuario_id": str(usuario.id), "intentos": 0}).encode(
                    "utf-8"
                ),
                ex=DESAFIO_TOTP_TTL_S,
            )
            return {"mfa_requerido": True, "desafio_id": desafio_id}

        return await _abrir_sesion(request, response, usuario)

    @router.post("/totp")
    async def verificar_totp(
        datos: VerificacionTotpEntrada, request: Request, response: Response
    ) -> dict[str, Any]:
        redis = request.app.state.cola_orquestar
        clave = f"{_CLAVE_MFA}{datos.desafio_id}"
        bruto = await redis.get(clave)
        if not bruto:
            raise _no_autorizado()
        carga = json.loads(bruto.decode("utf-8"))
        usuario_id = uuid.UUID(carga["usuario_id"])
        intentos = int(carga.get("intentos", 0))
        if intentos >= 5:
            await redis.delete(clave)
            raise _no_autorizado()

        async with request.app.state.sesiones() as sesion:
            usuario = await obtener_usuario_por_id(sesion, usuario_id)
        if (
            usuario is None
            or not usuario.activo
            or usuario.totp_secreto_cifrado is None
        ):
            await redis.delete(clave)
            raise _no_autorizado()

        pepper = request.app.state.ajustes.pepper
        if not verificar_codigo_totp(
            pepper, usuario.totp_secreto_cifrado, datos.codigo
        ):
            await redis.set(
                clave,
                json.dumps(
                    {"usuario_id": str(usuario_id), "intentos": intentos + 1}
                ).encode("utf-8"),
                keepttl=True,
            )
            async with request.app.state.sesiones.begin() as sesion:
                await registrar_evento_auditoria(
                    sesion,
                    usuario_id=usuario.id,
                    accion="inicio_fallido",
                    motivo="totp_invalido",
                    ip=huella_ip(request),
                )
            raise _no_autorizado()

        # Consumo de un solo uso del desafío.
        borradas = await redis.delete(clave)
        if borradas != 1:
            raise _no_autorizado()
        return await _abrir_sesion(request, response, usuario)

    @router.post("/totp/enroll")
    async def enroll_totp(
        request: Request, actual: UsuarioAutenticado
    ) -> dict[str, str]:
        secreto = pyotp.random_base32()
        cifrado = cifrar_totp(request.app.state.ajustes.pepper, secreto)
        async with request.app.state.sesiones.begin() as sesion:
            await actualizar_totp_usuario(sesion, actual.id, cifrado)
        uri = pyotp.TOTP(secreto).provisioning_uri(
            name=actual.correo, issuer_name="Gatekeeper"
        )
        return {"secreto": secreto, "otpauth_uri": uri}

    @router.post("/refresh")
    async def refresh(request: Request, response: Response) -> dict[str, Any]:
        exigir_csrf(request)
        cookie_token = request.cookies.get(COOKIE_REFRESH)
        if not cookie_token:
            raise _no_autorizado()
        pepper = request.app.state.ajustes.pepper
        decodificado = decodificar_refresh_jwt(pepper, cookie_token)
        if decodificado is None:
            _borrar_cookies_sesion(response, request)
            raise _no_autorizado()
        jti, usuario_id = decodificado

        ahora = datetime.now(UTC)
        nuevo_jti = uuid.uuid4()
        nueva_exp = ahora + timedelta(days=REFRESH_TTL_DIAS)
        usuario: DatosUsuario | None = None

        async with request.app.state.sesiones.begin() as sesion:
            fila = await obtener_refresh_token_para_rotar(sesion, jti)
            if fila is None or fila.usuario_id != usuario_id:
                pass
            elif fila.revocado:
                # F5.03 / vecx:refresh_reutilizado: confirmar la revocación de toda la familia
                # ANTES de lanzar 401 (un raise dentro de begin() haría ROLLBACK).
                await revocar_familia_refresh(sesion, fila.familia)
            elif fila.expira_en <= ahora:
                await marcar_refresh_revocado(sesion, jti)
            else:
                encontrado = await obtener_usuario_por_id(sesion, usuario_id)
                if encontrado is None or not encontrado.activo:
                    await revocar_familia_refresh(sesion, fila.familia)
                else:
                    await marcar_refresh_revocado(sesion, jti)
                    await crear_refresh_token(
                        sesion,
                        jti=nuevo_jti,
                        usuario_id=encontrado.id,
                        familia=fila.familia,
                        expira_en=nueva_exp,
                    )
                    usuario = encontrado

        if usuario is None:
            _borrar_cookies_sesion(response, request)
            raise _no_autorizado()

        token_acceso = emitir_jwt(pepper, usuario)
        nuevo_refresh = emitir_refresh_jwt(
            pepper, jti=nuevo_jti, usuario_id=usuario.id, expira_en=nueva_exp
        )
        _fijar_cookies_sesion(response, request, nuevo_refresh, generar_csrf())
        return {
            "token_acceso": token_acceso,
            "expira_en": JWT_TTL_S,
            "usuario": _usuario_dto(usuario),
        }

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(request: Request, response: Response) -> Response:
        exigir_csrf(request)
        cookie_token = request.cookies.get(COOKIE_REFRESH)
        if cookie_token:
            decodificado = decodificar_refresh_jwt(
                request.app.state.ajustes.pepper, cookie_token
            )
            if decodificado is not None:
                jti, usuario_id = decodificado
                async with request.app.state.sesiones.begin() as sesion:
                    fila = await obtener_refresh_token_para_rotar(sesion, jti)
                    if fila is not None:
                        await revocar_familia_refresh(sesion, fila.familia)
                    await registrar_evento_auditoria(
                        sesion,
                        usuario_id=usuario_id,
                        accion="cierre_sesion",
                        ip=huella_ip(request),
                    )
        _borrar_cookies_sesion(response, request)
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    @router.get("/me")
    async def me(actual: UsuarioAutenticado) -> dict[str, Any]:
        return {
            "id": str(actual.id),
            "correo": actual.correo,
            "rol": actual.rol,
            "mfa_activo": actual.mfa_activo,
        }

    @router.get("/admin-check")
    async def admin_check(actual: AdminAutenticado) -> dict[str, Any]:
        return {"ok": True, "rol": actual.rol}

    return router
