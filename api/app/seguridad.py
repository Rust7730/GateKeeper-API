"""Headers de seguridad y errores genéricos en todas las respuestas (defensa en profundidad además de Nginx)."""

import logging

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("gatekeeper.api")

HEADERS_SEGURIDAD: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
)


def _para_log(valor: object) -> str:
    """Representación de un valor del cliente apta para una sola línea de log.

    `ascii()` escapa los caracteres de control (`\\r`, `\\n`, < 0x20, 0x7f) y todo lo que no es ASCII, incluidos
    los separadores de línea Unicode (U+0085, U+2028, U+2029), así que el resultado nunca parte la línea.
    """
    return ascii(valor)


class HeadersSeguridad:
    """Middleware ASGI puro.

    - Fija los headers de seguridad en toda respuesta HTTP, incluidas 404, 405 y 500, y quita `Server`.
    - Si una excepción no controlada llega aquí antes de empezar la respuesta, la registra y responde un 500
      genérico, sin tipo ni mensaje de la excepción. Va por dentro de `ServerErrorMiddleware` de Starlette, cuya
      respuesta 500 no pasaría por este middleware y saldría sin los headers.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        respuesta_iniciada = False

        async def enviar(mensaje: Message) -> None:
            nonlocal respuesta_iniciada
            if mensaje["type"] == "http.response.start":
                respuesta_iniciada = True
                mensaje.setdefault("headers", [])
                headers = MutableHeaders(scope=mensaje)
                for nombre, valor in HEADERS_SEGURIDAD:
                    headers[nombre] = valor
                if "server" in headers:
                    del headers["server"]
            await send(mensaje)

        try:
            await self.app(scope, receive, enviar)
        except Exception:
            # Solo método y ruta, escapados: `scope["path"]` ya viene decodificado y un `%0A` en la URL
            # inyectaría líneas falsas en el log (CWE-117). Nunca se registran scope, cabeceras ni cuerpo.
            logger.exception(
                "Excepción no controlada en %s %s",
                _para_log(scope.get("method")),
                _para_log(scope.get("path")),
            )
            if respuesta_iniciada:
                raise
            generica = JSONResponse(
                {"detail": "Internal Server Error"}, status_code=500
            )
            await generica(scope, receive, enviar)
