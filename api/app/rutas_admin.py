"""Endpoints de administración del dashboard SecOps ``/v1/admin/*`` (F5.06–F5.11, K06, K18–K20)."""

import asyncio
import http
import re
import time
import uuid
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from api.app.autenticacion import calcular_hash, generar_key
from api.app.auth_usuarios import (
    AdminAutenticado,
    UsuarioAutenticado,
    huella_ip,
)
from api.app.cola import COLA_ORQUESTAR, TIMEOUT_COLA_S
from api.app.estados import Estado
from api.app.eventos_sse import LimiteClientesSSE
from api.db.repositorios import ViolacionDeRestriccion, crear_api_key
from api.db.repositorios_admin import (
    ArchivoAdmin,
    listar_api_keys_admin,
    listar_aplicaciones_admin,
    listar_archivos_admin,
    listar_auditoria_admin,
    obtener_aplicacion_por_id,
    obtener_archivo_admin,
    obtener_metricas_admin,
    obtener_o_crear_aplicacion,
    registrar_evento_auditoria,
    revocar_api_key,
)

# K18: motivo de liberación entre 20 y 500 caracteres sin controles C0/DEL/C1.
_CONTROLES = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_MIN_MOTIVO = 20
_MAX_MOTIVO = 500
_MAX_TAMANO_PAGINA = 100
_KEEPALIVE_SSE_S = 15.0


class _LiberacionPeticion(BaseModel):
    motivo: str = Field(min_length=_MIN_MOTIVO, max_length=_MAX_MOTIVO)


class _NuevaApiKeyPeticion(BaseModel):
    aplicacion_id: uuid.UUID | None = None
    aplicacion_nombre: str | None = Field(default=None, min_length=1, max_length=100)


def _iso(valor: datetime | None) -> str | None:
    return None if valor is None else valor.isoformat().replace("+00:00", "Z")


def _serializar_archivo(a: ArchivoAdmin) -> dict[str, Any]:
    """Serializa ``ArchivoDto`` respetando K20: sin campos sensibles si no es divulgable."""
    cuerpo: dict[str, Any] = {
        "id": str(a.id),
        "aplicacion_id": str(a.aplicacion_id),
        "aplicacion_nombre": a.aplicacion_nombre,
        "estado": a.estado,
        "tipo_detectado": a.tipo_detectado,
        "tamano_bytes": a.tamano_bytes,
        "creado_en": _iso(a.creado_en),
        "analizado_en": _iso(a.analizado_en),
    }
    if a.divulgable:
        cuerpo["nombre_original"] = a.nombre_original
        cuerpo["sha256"] = a.sha256
        cuerpo["cuarentena_expira_en"] = _iso(a.cuarentena_expira_en)
        cuerpo["resultados"] = [
            {
                "capa": r.capa,
                "veredicto": r.veredicto,
                "detalle": r.detalle,
                "duracion_ms": r.duracion_ms,
            }
            for r in a.resultados
        ]
    return cuerpo


def _error(codigo: int) -> HTTPException:
    return HTTPException(status_code=codigo, detail=http.HTTPStatus(codigo).phrase)


def crear_router_admin() -> APIRouter:
    router = APIRouter(prefix="/v1/admin", tags=["admin"])

    @router.get("/files")
    async def listar_archivos(
        request: Request,
        _usuario: UsuarioAutenticado,
        estado: Annotated[list[str] | None, Query()] = None,
        aplicacion_id: uuid.UUID | None = None,
        desde: datetime | None = None,
        hasta: datetime | None = None,
        q: Annotated[str | None, Query(max_length=200)] = None,
        orden: Literal["creado_en", "tamano_bytes", "estado"] = "creado_en",
        dir: Literal["asc", "desc"] = "desc",
        pagina: Annotated[int, Query(ge=1)] = 1,
        tamano_pagina: Annotated[int, Query(ge=1, le=_MAX_TAMANO_PAGINA)] = 25,
    ) -> dict[str, Any]:
        estados_validos = {e.value for e in Estado}
        if estado is not None:
            for item in estado:
                if item not in estados_validos:
                    raise _error(status.HTTP_400_BAD_REQUEST)
        if q is not None and "\x00" in q:
            raise _error(status.HTTP_400_BAD_REQUEST)
        async with request.app.state.sesiones() as sesion:
            elementos, total = await listar_archivos_admin(
                sesion,
                estados=estado,
                aplicacion_id=aplicacion_id,
                desde=desde,
                hasta=hasta,
                q=q,
                orden=orden,
                direccion=dir,
                pagina=pagina,
                tamano_pagina=tamano_pagina,
            )
        return {
            "elementos": [_serializar_archivo(a) for a in elementos],
            "pagina": pagina,
            "tamano_pagina": tamano_pagina,
            "total": total,
        }

    @router.get("/files/{archivo_id}")
    async def detalle_archivo(
        request: Request,
        archivo_id: uuid.UUID,
        _usuario: UsuarioAutenticado,
    ) -> dict[str, Any]:
        async with request.app.state.sesiones() as sesion:
            archivo = await obtener_archivo_admin(sesion, archivo_id)
        if archivo is None:
            raise _error(status.HTTP_404_NOT_FOUND)
        return _serializar_archivo(archivo)

    @router.post("/files/{archivo_id}/release", status_code=status.HTTP_202_ACCEPTED)
    async def liberar_archivo(
        request: Request,
        archivo_id: uuid.UUID,
        cuerpo: _LiberacionPeticion,
        admin: AdminAutenticado,
    ) -> dict[str, Any]:
        motivo = cuerpo.motivo.strip()
        if (
            len(motivo) < _MIN_MOTIVO
            or len(motivo) > _MAX_MOTIVO
            or _CONTROLES.search(motivo) is not None
        ):
            raise _error(status.HTTP_400_BAD_REQUEST)

        async with request.app.state.sesiones.begin() as sesion:
            archivo = await obtener_archivo_admin(sesion, archivo_id)
            if archivo is None:
                raise _error(status.HTTP_404_NOT_FOUND)
            if archivo.estado != Estado.EN_CUARENTENA.value:
                raise _error(status.HTTP_409_CONFLICT)
            await registrar_evento_auditoria(
                sesion,
                usuario_id=admin.id,
                accion="liberar_archivo",
                objetivo_id=archivo_id,
                motivo=motivo,
                ip=huella_ip(request),
            )
            aplicacion_id = archivo.aplicacion_id

        # INV-07 / D4 / M-10: _job_id determinista para deduplicar liberaciones concurrentes.
        trabajo_id = f"liberar:{archivo_id}"
        try:
            async with asyncio.timeout(TIMEOUT_COLA_S):
                await request.app.state.cola_orquestar.enqueue_job(
                    "orquestar",
                    str(aplicacion_id),
                    str(archivo_id),
                    "",
                    True,
                    str(admin.id),
                    motivo,
                    _job_id=trabajo_id,
                    _queue_name=COLA_ORQUESTAR,
                )
        except Exception:  # noqa: BLE001
            raise _error(status.HTTP_503_SERVICE_UNAVAILABLE) from None
        return {
            "id": str(archivo_id),
            "estado": Estado.EN_CUARENTENA.value,
            "reencolado": True,
        }

    @router.get("/metrics")
    async def obtener_metricas(
        request: Request,
        _usuario: UsuarioAutenticado,
        periodo: Literal["24h", "7d", "30d"] = "7d",
    ) -> dict[str, Any]:
        async with request.app.state.sesiones() as sesion:
            return await obtener_metricas_admin(sesion, periodo)

    @router.get("/audit")
    async def listar_auditoria(
        request: Request,
        _admin: AdminAutenticado,
        pagina: Annotated[int, Query(ge=1)] = 1,
        tamano_pagina: Annotated[int, Query(ge=1, le=_MAX_TAMANO_PAGINA)] = 50,
    ) -> dict[str, Any]:
        async with request.app.state.sesiones() as sesion:
            elementos, total = await listar_auditoria_admin(
                sesion, pagina=pagina, tamano_pagina=tamano_pagina
            )
        return {
            "elementos": [
                {
                    "id": str(e.id),
                    "actor": {
                        "id": str(e.actor_id) if e.actor_id is not None else "",
                        "correo": e.actor_correo,
                        "rol": e.actor_rol,
                    },
                    "accion": e.accion,
                    "recurso": e.recurso,
                    "motivo": e.motivo,
                    "ip": e.ip,
                    "en": _iso(e.en),
                }
                for e in elementos
            ],
            "pagina": pagina,
            "tamano_pagina": tamano_pagina,
            "total": total,
        }

    @router.get("/api-keys")
    async def listar_api_keys(
        request: Request,
        _admin: AdminAutenticado,
    ) -> list[dict[str, Any]]:
        async with request.app.state.sesiones() as sesion:
            claves = await listar_api_keys_admin(sesion)
        return [
            {
                "id": str(k.id),
                "aplicacion_id": str(k.aplicacion_id),
                "aplicacion_nombre": k.aplicacion_nombre,
                "prefijo": k.prefijo,
                "creada_en": _iso(k.creada_en),
                "ultimo_uso_en": None,
                "revocada_en": _iso(k.revocada_en),
            }
            for k in claves
        ]

    @router.post("/api-keys", status_code=status.HTTP_201_CREATED)
    async def crear_api_key_admin(
        request: Request,
        cuerpo: _NuevaApiKeyPeticion,
        admin: AdminAutenticado,
    ) -> dict[str, Any]:
        if cuerpo.aplicacion_id is None and cuerpo.aplicacion_nombre is None:
            raise _error(status.HTTP_400_BAD_REQUEST)
        prefijo, secreto = generar_key()
        hash_key = calcular_hash(request.app.state.ajustes.pepper, secreto)
        try:
            async with request.app.state.sesiones.begin() as sesion:
                if cuerpo.aplicacion_id is not None:
                    app_info = await obtener_aplicacion_por_id(
                        sesion, cuerpo.aplicacion_id
                    )
                    if app_info is None:
                        raise _error(status.HTTP_404_NOT_FOUND)
                else:
                    assert cuerpo.aplicacion_nombre is not None
                    nombre = cuerpo.aplicacion_nombre.strip()
                    if not nombre or _CONTROLES.search(nombre) is not None:
                        raise _error(status.HTTP_400_BAD_REQUEST)
                    app_info = await obtener_o_crear_aplicacion(sesion, nombre)

                key_id = await crear_api_key(sesion, app_info.id, prefijo, hash_key)
                await registrar_evento_auditoria(
                    sesion,
                    usuario_id=admin.id,
                    accion="crear_api_key",
                    objetivo_id=key_id,
                    motivo=f"Aplicación: {app_info.nombre} ({prefijo})",
                    ip=huella_ip(request),
                )
        except ViolacionDeRestriccion:
            raise _error(status.HTTP_400_BAD_REQUEST) from None

        async with request.app.state.sesiones() as sesion:
            claves = await listar_api_keys_admin(sesion)
            creada = next((k for k in claves if k.id == key_id), None)
        return {
            "id": str(key_id),
            "aplicacion_id": str(app_info.id),
            "aplicacion_nombre": app_info.nombre,
            "prefijo": prefijo,
            "creada_en": _iso(creada.creada_en) if creada is not None else None,
            "ultimo_uso_en": None,
            "revocada_en": None,
            "secreto": secreto,
        }

    @router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def eliminar_api_key_admin(
        request: Request,
        key_id: uuid.UUID,
        admin: AdminAutenticado,
    ) -> Response:
        async with request.app.state.sesiones.begin() as sesion:
            revocada = await revocar_api_key(sesion, key_id)
            if not revocada:
                raise _error(status.HTTP_404_NOT_FOUND)
            await registrar_evento_auditoria(
                sesion,
                usuario_id=admin.id,
                accion="revocar_api_key",
                objetivo_id=key_id,
                motivo=None,
                ip=huella_ip(request),
            )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.get("/applications")
    async def listar_aplicaciones(
        request: Request,
        _usuario: UsuarioAutenticado,
    ) -> list[dict[str, Any]]:
        async with request.app.state.sesiones() as sesion:
            apps = await listar_aplicaciones_admin(sesion)
        return [
            {
                "id": str(a.id),
                "nombre": a.nombre,
                "activa": a.activa,
                "creada_en": _iso(a.creada_en),
            }
            for a in apps
        ]

    @router.get("/events")
    async def stream_eventos(
        request: Request,
        usuario: UsuarioAutenticado,
    ) -> StreamingResponse:
        """Flujo SSE en tiempo real sobre ``HubEventosSSE`` dedicado (H-07, M-7, F5.11, K20)."""
        hub = request.app.state.hub_sse

        async def _generador() -> AsyncIterator[str]:
            try:
                async with hub.suscribir() as cola:
                    yield ": conectado\n\n"
                    while not await request.is_disconnected():
                        # M-7: cortar el stream al expirar el JWT (obliga a refrescar sesión).
                        if usuario.exp and time.time() >= usuario.exp:
                            yield ": token_expirado\n\n"
                            break
                        try:
                            evento = await asyncio.wait_for(
                                cola.get(), timeout=_KEEPALIVE_SSE_S
                            )
                        except TimeoutError:
                            yield ": keepalive\n\n"
                            continue
                        yield f"data: {evento}\n\n"
            except LimiteClientesSSE:
                yield ": limite_clientes\n\n"

        # Comprobación rápida previa para responder 503 si el hub ya está lleno.
        if len(hub._clientes) >= hub._max_clientes:
            raise _error(status.HTTP_503_SERVICE_UNAVAILABLE)

        return StreamingResponse(
            _generador(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    return router
