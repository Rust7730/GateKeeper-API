"""Router ``/v1/auth``: login Argon2+TOTP, refresh rotativo con CSRF, logout y RBAC (F5.01–F5.05)."""

import hashlib
import http
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pyotp
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
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
    verificar_codigo_totp_con_paso,
    verificar_contrasena_async,
    verificar_dummy_async,
)
from api.app.limite import RedisNoDisponible, demasiadas_peticiones, no_disponible
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
_CLAVE_ENROLL = "gk:mfa:enroll:"
_CLAVE_TOTP_USADO = "gk:totp:usado:"
_CLAVE_LIMITE_CUENTA = "gk:auth:cuenta:"
_MAX_INTENTOS_MFA = 5
_TTL_TOTP_USADO_S = 120
_MAX_INTENTOS_CUENTA_MIN = 10
# H-09: incremento atómico de intentos de desafío MFA en Redis (sin TOCTOU).
_SCRIPT_CONSUMIR_INTENTO_MFA = """
local val = redis.call('GET', KEYS[1])
if not val then
    return nil
end
local sep = string.find(val, '|', 1, true)
if not sep then
    redis.call('DEL', KEYS[1])
    return nil
end
local uid = string.sub(val, 1, sep - 1)
local intentos = tonumber(string.sub(val, sep + 1)) or 0
local max_intentos = tonumber(ARGV[1])
if intentos >= max_intentos then
    redis.call('DEL', KEYS[1])
    return nil
end
local pttl = redis.call('PTTL', KEYS[1])
if pttl <= 0 then
    redis.call('DEL', KEYS[1])
    return nil
end
redis.call('SET', KEYS[1], uid .. '|' .. tostring(intentos + 1), 'PX', pttl)
return uid
"""
_SCRIPT_LIMITE_CUENTA = """
local c = redis.call('INCR', KEYS[1])
if c == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {c, ttl}
"""


async def _exigir_cupo_ip_auth(request: Request) -> None:
    """Aplica el limitador por IP a intentos de autenticación (H-06)."""
    host = request.client.host if request.client is not None else None
    try:
        veredicto = await request.app.state.limitador.contar_sin_autenticar(host)
    except RedisNoDisponible:
        raise no_disponible() from None
    if not veredicto.permitido:
        raise demasiadas_peticiones(veredicto.reintentar_en_s)


async def _exigir_cupo_cuenta(request: Request, correo_norm: str) -> None:
    """Limita intentos por cuenta en /v1/auth/login (10/min) para frenar brute-force y llenado de Redis."""
    huella = hashlib.sha256(correo_norm.encode("utf-8")).hexdigest()[:32]
    clave = f"{_CLAVE_LIMITE_CUENTA}{huella}"
    try:
        cuenta, ttl = await request.app.state.cola_orquestar.eval(
            _SCRIPT_LIMITE_CUENTA, 1, clave, 60
        )
    except Exception:  # noqa: BLE001
        raise no_disponible() from None
    if int(cuenta) > _MAX_INTENTOS_CUENTA_MIN:
        raise demasiadas_peticiones(max(1, int(ttl)))


class InicioSesionEntrada(BaseModel):
    correo: str = Field(min_length=3, max_length=254)
    contrasena: str = Field(min_length=1, max_length=256)


class VerificacionTotpEntrada(BaseModel):
    desafio_id: str = Field(min_length=16, max_length=128)
    codigo: str = Field(min_length=6, max_length=6)


class ConfirmarTotpEntrada(BaseModel):
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
        correo_norm = datos.correo.strip().lower()
        await _exigir_cupo_ip_auth(request)
        await _exigir_cupo_cuenta(request, correo_norm)
        ip = huella_ip(request)
        async with request.app.state.sesiones() as sesion:
            usuario = await obtener_usuario_por_email(sesion, correo_norm)
        if usuario is None:
            await verificar_dummy_async(datos.contrasena)
            async with request.app.state.sesiones.begin() as sesion:
                await registrar_evento_auditoria(
                    sesion, usuario_id=None, accion="inicio_fallido", ip=ip
                )
            raise _no_autorizado()

        # M-6: evaluar Argon2id siempre antes de comprobar usuario.activo (sin timing oracle).
        contrasena_ok = await verificar_contrasena_async(
            usuario.hash_password, datos.contrasena
        )
        if not usuario.activo or not contrasena_ok:
            async with request.app.state.sesiones.begin() as sesion:
                await registrar_evento_auditoria(
                    sesion, usuario_id=usuario.id, accion="inicio_fallido", ip=ip
                )
            raise _no_autorizado()

        # F5.01: admin sin TOTP configurado no puede abrir sesión (fail-closed).
        if usuario.rol == "admin" and usuario.totp_secreto_cifrado is None:
            raise _no_autorizado()

        # F5.01: si el usuario tiene TOTP activo (obligatorio para admin), paso 2 requerido.
        if usuario.totp_secreto_cifrado is not None:
            desafio_id = secrets.token_urlsafe(32)
            redis = request.app.state.cola_orquestar
            await redis.set(
                f"{_CLAVE_MFA}{desafio_id}",
                f"{usuario.id}|0".encode("ascii"),
                ex=DESAFIO_TOTP_TTL_S,
            )
            return {"mfa_requerido": True, "desafio_id": desafio_id}

        return await _abrir_sesion(request, response, usuario)

    @router.post("/totp")
    async def verificar_totp(
        datos: VerificacionTotpEntrada, request: Request, response: Response
    ) -> dict[str, Any]:
        await _exigir_cupo_ip_auth(request)
        redis = request.app.state.cola_orquestar
        clave = f"{_CLAVE_MFA}{datos.desafio_id}"
        uid_bruto = await redis.eval(
            _SCRIPT_CONSUMIR_INTENTO_MFA, 1, clave, _MAX_INTENTOS_MFA
        )
        if not uid_bruto:
            raise _no_autorizado()
        uid_texto = (
            uid_bruto.decode("ascii")
            if isinstance(uid_bruto, bytes)
            else str(uid_bruto)
        )
        usuario_id = uuid.UUID(uid_texto)

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
        paso = verificar_codigo_totp_con_paso(
            pepper, usuario.totp_secreto_cifrado, datos.codigo
        )
        if paso is None:
            async with request.app.state.sesiones.begin() as sesion:
                await registrar_evento_auditoria(
                    sesion,
                    usuario_id=usuario.id,
                    accion="inicio_fallido",
                    motivo="totp_invalido",
                    ip=huella_ip(request),
                )
            raise _no_autorizado()

        # H-09 (RFC 6238 §5.2): impedir reutilización del mismo código en la ventana de 90 s.
        aceptado = await redis.set(
            f"{_CLAVE_TOTP_USADO}{usuario.id}:{paso}",
            b"1",
            nx=True,
            ex=_TTL_TOTP_USADO_S,
        )
        if not aceptado:
            async with request.app.state.sesiones.begin() as sesion:
                await registrar_evento_auditoria(
                    sesion,
                    usuario_id=usuario.id,
                    accion="inicio_fallido",
                    motivo="totp_reutilizado",
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
        # H-08: nunca sobrescribir un TOTP ya activo desde autoservicio (impide MFA takeover).
        if actual.mfa_activo:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=http.HTTPStatus.FORBIDDEN.phrase,
            )
        secreto = pyotp.random_base32()
        cifrado = cifrar_totp(request.app.state.ajustes.pepper, secreto)
        # Fase 1: guardar secreto cifrado temporal en Redis hasta confirmar un código válido.
        await request.app.state.cola_orquestar.set(
            f"{_CLAVE_ENROLL}{actual.id}",
            cifrado,
            ex=DESAFIO_TOTP_TTL_S,
        )
        uri = pyotp.TOTP(secreto).provisioning_uri(
            name=actual.correo, issuer_name="Gatekeeper"
        )
        return {"secreto": secreto, "otpauth_uri": uri}

    @router.post("/totp/confirm")
    async def confirmar_totp(
        datos: ConfirmarTotpEntrada, request: Request, actual: UsuarioAutenticado
    ) -> dict[str, bool]:
        """Fase 2 de enrolamiento TOTP (H-08): verifica el código antes de persistir en BD."""
        if actual.mfa_activo:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=http.HTTPStatus.FORBIDDEN.phrase,
            )
        redis = request.app.state.cola_orquestar
        clave = f"{_CLAVE_ENROLL}{actual.id}"
        cifrado = await redis.get(clave)
        if not isinstance(cifrado, bytes) or len(cifrado) <= 12:
            raise _no_autorizado()
        paso = verificar_codigo_totp_con_paso(
            request.app.state.ajustes.pepper, cifrado, datos.codigo
        )
        if paso is None:
            raise _no_autorizado()
        async with request.app.state.sesiones.begin() as sesion:
            await actualizar_totp_usuario(sesion, actual.id, cifrado)
            await registrar_evento_auditoria(
                sesion,
                usuario_id=actual.id,
                accion="activar_totp",
                ip=huella_ip(request),
            )
        await redis.delete(clave)
        await redis.set(
            f"{_CLAVE_TOTP_USADO}{actual.id}:{paso}",
            b"1",
            nx=True,
            ex=_TTL_TOTP_USADO_S,
        )
        return {"mfa_activo": True}

    @router.post("/refresh", response_model=None)
    async def refresh(
        request: Request, response: Response
    ) -> Response | dict[str, Any]:
        exigir_csrf(request)
        cookie_token = request.cookies.get(COOKIE_REFRESH)
        if not cookie_token:
            raise _no_autorizado()
        pepper = request.app.state.ajustes.pepper
        decodificado = decodificar_refresh_jwt(pepper, cookie_token)
        if decodificado is None:
            resp_err = JSONResponse(
                {"detail": http.HTTPStatus.UNAUTHORIZED.phrase},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            _borrar_cookies_sesion(resp_err, request)
            return resp_err
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
                # F5.03 / vecx:refresh_reutilizado: revocar toda la familia y auditar (M-8).
                await revocar_familia_refresh(sesion, fila.familia)
                await registrar_evento_auditoria(
                    sesion,
                    usuario_id=usuario_id,
                    accion="inicio_fallido",
                    motivo="refresh_reutilizado",
                    ip=huella_ip(request),
                )
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
            resp_err = JSONResponse(
                {"detail": http.HTTPStatus.UNAUTHORIZED.phrase},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            _borrar_cookies_sesion(resp_err, request)
            return resp_err

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
