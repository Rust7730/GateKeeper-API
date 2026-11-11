"""Router de ``/v1``: toda ruta de aquí exige autenticación (diseño §3, §4).

La dependencia va en el router para que una ruta nueva no pueda olvidarla. Ojo: FastAPI lee
el cuerpo **antes** de resolver las dependencias si la ruta declara un parámetro de cuerpo
(``Body``, ``Form``, ``File`` o un modelo). Por eso ninguna ruta de ``/v1`` los declara: lee
de ``request.stream()`` dentro de la función. ``test_autenticacion.py`` lo comprueba.

Un archivo ajeno y uno inexistente pasan por el mismo camino y responden lo mismo (INV-10).
El id es ``str`` y se valida aquí: declararlo ``uuid.UUID`` daría un 422, que revelaría el
formato de los ids.
"""

import asyncio
import http
import logging
import os
import stat
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse

from api.app.analisis import agendar_analisis
from api.app.autenticacion import AplicacionAutenticada, autenticar
from api.app.estados import Estado, es_descargable
from api.app.recepcion import recibir_archivo
from api.app.tipos import EXTENSIONES
from api.db.repositorios import DatosArchivo, crear_archivo, obtener_archivo

logger = logging.getLogger("gatekeeper.api")


def _no_encontrado() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail=http.HTTPStatus.NOT_FOUND.phrase
    )


def _id_canonico(valor: str) -> uuid.UUID | None:
    """El UUID solo en su forma canónica. ``uuid.UUID`` admite también llaves y ``urn:``."""
    try:
        identificador = uuid.UUID(valor)
    except ValueError:
        return None
    return identificador if str(identificador) == valor else None


async def _archivo_propio(
    request: Request, aplicacion_id: uuid.UUID, archivo_id: str
) -> DatosArchivo:
    identificador = _id_canonico(archivo_id)
    if identificador is None:
        raise _no_encontrado()
    async with request.app.state.sesiones() as sesion:
        archivo = await obtener_archivo(sesion, aplicacion_id, identificador)
    if archivo is None:
        raise _no_encontrado()
    return archivo


def crear_router_v1() -> APIRouter:
    router = APIRouter(prefix="/v1", dependencies=[Depends(autenticar)])

    @router.post("/files", status_code=status.HTTP_202_ACCEPTED)
    async def subir_archivo(
        request: Request, aplicacion_id: AplicacionAutenticada
    ) -> dict[str, str]:
        """Antes del 202 solo hay streaming a disco, SHA-256 e ``INSERT`` (M1)."""
        estado = request.app.state
        ajustes = estado.ajustes
        recibido = await recibir_archivo(
            request, ajustes.uploads_tmp, ajustes.timeout_recepcion_s
        )
        try:
            async with estado.sesiones.begin() as sesion:
                await crear_archivo(
                    sesion,
                    aplicacion_id,
                    recibido.id,
                    recibido.nombre,
                    recibido.tamano,
                    recibido.sha256,
                )
        except BaseException:
            recibido.ruta.unlink(missing_ok=True)
            raise
        agendar_analisis(estado, aplicacion_id, recibido.id)
        return {"id": str(recibido.id), "estado": Estado.PENDIENTE.value}

    @router.get("/files/{archivo_id}")
    async def ver_archivo(
        request: Request, aplicacion_id: AplicacionAutenticada, archivo_id: str
    ) -> dict[str, Any]:
        archivo = await _archivo_propio(request, aplicacion_id, archivo_id)
        return {
            "id": str(archivo.id),
            "estado": archivo.estado.value,
            "tipo_detectado": archivo.tipo_detectado,
            "tamano_bytes": archivo.tamano_bytes,
            "sha256": archivo.sha256,
            "creado_en": archivo.creado_en,
            "analizado_en": archivo.analizado_en,
        }

    @router.get("/files/{archivo_id}/content")
    async def descargar_archivo(
        request: Request, aplicacion_id: AplicacionAutenticada, archivo_id: str
    ) -> FileResponse:
        """Solo la reconstrucción y solo en ``limpio`` (INV-01, INV-06).

        Si falta, nunca se recurre al original. ``lstat`` para no seguir un enlace.
        """
        archivo = await _archivo_propio(request, aplicacion_id, archivo_id)
        if not es_descargable(archivo.estado):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=http.HTTPStatus.CONFLICT.phrase,
            )
        ruta = request.app.state.ajustes.clean_store / str(archivo.id)
        try:
            info = await asyncio.to_thread(os.lstat, ruta)
        except OSError:
            info = None
        if info is None or not stat.S_ISREG(info.st_mode):
            logger.error("Falta la reconstrucción de %s", archivo.id)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
        extension = EXTENSIONES[archivo.tipo_detectado]
        return FileResponse(
            ruta,
            media_type=archivo.tipo_detectado,
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{archivo.id}.{extension}"'
                )
            },
            stat_result=info,
        )

    return router
