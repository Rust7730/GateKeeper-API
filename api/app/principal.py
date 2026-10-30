"""Fábrica de la aplicación FastAPI de Gatekeeper."""

import os

from fastapi import FastAPI, Response
from starlette.middleware import Middleware

from api.app.seguridad import HeadersSeguridad

# Middlewares de la app, del más externo al más interno. Todo middleware nuevo se añade AQUÍ, no con
# `app.add_middleware` después de `crear_app()`: así queda por dentro de HeadersSeguridad y sus respuestas,
# incluidos los 500, llevan los headers de seguridad y el error genérico.
MIDDLEWARES_INTERNOS: tuple[Middleware, ...] = ()


def _openapi_encendido() -> bool:
    # Solo el valor exacto "1" lo enciende; cualquier otro (incluido ausente) lo deja apagado.
    return os.environ.get("GATEKEEPER_DOCS") == "1"


def crear_app() -> FastAPI:
    app = FastAPI(
        title="Gatekeeper",
        debug=False,
        # /docs y /redoc no se sirven nunca: cargan JS de un CDN y no hacen falta. Solo /openapi.json,
        # y solo con GATEKEEPER_DOCS=1.
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json" if _openapi_encendido() else None,
        middleware=list(MIDDLEWARES_INTERNOS),
    )
    # HeadersSeguridad tiene que ser el middleware más externo: `add_middleware` inserta en la posición 0.
    # Por eso va al final y ningún middleware se añade después de esta línea (ver MIDDLEWARES_INTERNOS).
    app.add_middleware(HeadersSeguridad)

    @app.get("/health")
    def health() -> dict[str, str]:
        # Solo indica que el proceso responde: no consulta la BD ni otros servicios.
        return {"estado": "ok"}

    @app.head("/health", include_in_schema=False)
    def health_head() -> Response:
        # Para healthchecks que usan HEAD; mismo significado que GET, sin cuerpo.
        return Response(status_code=200)

    return app
