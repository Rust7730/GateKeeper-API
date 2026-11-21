"""Fábrica de la aplicación FastAPI de Gatekeeper."""

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response
from starlette.middleware import Middleware

from api.app.ajustes import (
    VARIABLE_REDIS,
    Ajustes,
    abrir_motor,
    leer_ajustes,
    preparar_directorios,
)
from api.app.arranque import (
    barrer_restos,
    comprobar_ancestros,
    comprobar_bd,
    proteger_proceso,
)
from api.app.cola import COLA_ORQUESTAR, abrir_cola, cerrar_cola
from api.app.eventos_sse import HubEventosSSE
from api.app.limite import abrir_limitador
from api.app.rutas_admin import crear_router_admin
from api.app.rutas_auth import crear_router_auth
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
            cola_orquestar = abrir_cola(
                vigentes.url_redis,
                cola=COLA_ORQUESTAR,
                nombre_variable=VARIABLE_REDIS,
            )
        except BaseException:
            await limitador.cerrar()
            raise
        try:
            motor = abrir_motor(vigentes.url_bd)
        except BaseException:
            await cerrar_cola(cola_orquestar)
            await limitador.cerrar()
            raise
        app.state.ajustes = vigentes
        app.state.motor = motor
        app.state.sesiones = fabrica_sesiones(motor)
        app.state.limitador = limitador
        app.state.cola_orquestar = cola_orquestar
        app.state.hub_sse = HubEventosSSE(vigentes.url_redis)
        try:
            # Con clean_store montado :ro (K64), el barrido de restos lo hace coordinator;
            # la API solo comprueba que PostgreSQL responde.
            if os.access(vigentes.clean_store, os.W_OK):
                await barrer_restos(vigentes, app.state.sesiones)
            else:
                await comprobar_bd(app.state.sesiones)
        except BaseException:
            await app.state.hub_sse.cerrar()
            await motor.dispose()
            await cerrar_cola(cola_orquestar)
            await limitador.cerrar()
            raise
        try:
            yield
        finally:
            await app.state.hub_sse.cerrar()
            await motor.dispose()
            await cerrar_cola(cola_orquestar)
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
    app.include_router(crear_router_auth())
    app.include_router(crear_router_admin())

    @app.get("/health")
    def health() -> dict[str, str]:
        # Solo indica que el proceso responde: no consulta la BD, Redis (K60) ni otros servicios.
        return {"estado": "ok"}

    @app.head("/health", include_in_schema=False)
    def health_head() -> Response:
        # Para healthchecks que usan HEAD; mismo significado que GET, sin cuerpo.
        return Response(status_code=200)

    return app
