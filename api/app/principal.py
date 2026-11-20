"""Fábrica de la aplicación FastAPI de Gatekeeper."""

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response
from starlette.middleware import Middleware

from api.app.ajustes import Ajustes, abrir_motor, leer_ajustes, preparar_directorios
from api.app.analisis import cancelar_analisis
from api.app.arranque import barrer_restos, comprobar_ancestros, proteger_proceso
from api.app.limite import abrir_limitador
from api.app.seguridad import HeadersSeguridad
from api.app.v1 import crear_router_v1
from api.db.sesion import fabrica_sesiones

# Middlewares de la app, del más externo al más interno. Todo middleware nuevo se añade AQUÍ, no con
# `app.add_middleware` después de `crear_app()`: así queda por dentro de HeadersSeguridad y sus respuestas,
# incluidos los 500, llevan los headers de seguridad y el error genérico.
MIDDLEWARES_INTERNOS: tuple[Middleware, ...] = ()


def _openapi_encendido() -> bool:
    # Solo el valor exacto "1" lo enciende; cualquier otro (incluido ausente) lo deja apagado.
    return os.environ.get("GATEKEEPER_DOCS") == "1"


def crear_app(ajustes: Ajustes | None = None) -> FastAPI:
    """Crea la app. Con ``ajustes`` usa esos valores; sin ellos, los lee del entorno al arrancar."""

    @asynccontextmanager
    async def ciclo_de_vida(app: FastAPI) -> AsyncIterator[None]:
        # Todo aquí y no en crear_app: importar o crear la app no toca el entorno ni el disco.
        # Lo primero: desde aquí, ni el hijo del CDR lee el entorno de este proceso (K28).
        proteger_proceso()
        # K52: de nada sirve si quien la lanzó tiene los secretos a la vista.
        comprobar_ancestros()
        vigentes = leer_ajustes() if ajustes is None else ajustes
        preparar_directorios(vigentes.datos)
        # Sin conectar: si Redis no responde, la API arranca y /health contesta (K60).
        limitador = abrir_limitador(vigentes.url_redis, vigentes.reloj_limite)
        try:
            motor = abrir_motor(vigentes.url_bd)
        except BaseException:
            await limitador.cerrar()
            raise
        app.state.ajustes = vigentes
        app.state.motor = motor
        app.state.sesiones = fabrica_sesiones(motor)
        app.state.limitador = limitador
        try:
            # Antes de aceptar peticiones: después cerraría análisis que sí están en curso.
            await barrer_restos(vigentes, app.state.sesiones)
        except BaseException:
            await motor.dispose()
            await limitador.cerrar()
            raise
        # K09: un proceso hijo por archivo, y como mucho uno por núcleo a la vez.
        app.state.cupos = asyncio.Semaphore(os.cpu_count() or 1)
        app.state.tareas = set()
        try:
            yield
        finally:
            await cancelar_analisis(app.state)
            await motor.dispose()
            await limitador.cerrar()

    app = FastAPI(
        title="Gatekeeper",
        debug=False,
        # /docs y /redoc no se sirven nunca: cargan JS de un CDN y no hacen falta. Solo /openapi.json,
        # y solo con GATEKEEPER_DOCS=1.
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json" if _openapi_encendido() else None,
        middleware=list(MIDDLEWARES_INTERNOS),
        lifespan=ciclo_de_vida,
    )
    # HeadersSeguridad tiene que ser el middleware más externo: `add_middleware` inserta en la posición 0.
    # Por eso va al final y ningún middleware se añade después de esta línea (ver MIDDLEWARES_INTERNOS).
    app.add_middleware(HeadersSeguridad)

    app.include_router(crear_router_v1())

    @app.get("/health")
    def health() -> dict[str, str]:
        # Solo indica que el proceso responde: no consulta la BD, Redis (K60) ni otros servicios.
        return {"estado": "ok"}

    @app.head("/health", include_in_schema=False)
    def health_head() -> Response:
        # Para healthchecks que usan HEAD; mismo significado que GET, sin cuerpo.
        return Response(status_code=200)

    return app
