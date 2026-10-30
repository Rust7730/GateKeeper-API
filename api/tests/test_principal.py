"""Esqueleto de la API (F1.08): /health, headers de seguridad, docs apagados y errores genéricos."""

import pytest
from fastapi.testclient import TestClient

from api.app.principal import crear_app

HEADERS_SEGURIDAD = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
}

RUTAS_DOCS = ("/docs", "/redoc", "/openapi.json")
# /docs y /redoc no existen nunca; solo /openapi.json puede encenderse.
RUTAS_DOCS_SIEMPRE_APAGADAS = ("/docs", "/docs/oauth2-redirect", "/redoc")


@pytest.fixture
def cliente(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.delenv("GATEKEEPER_DOCS", raising=False)
    return TestClient(crear_app())


def _assert_headers_seguridad(respuesta) -> None:
    for nombre, valor in HEADERS_SEGURIDAD.items():
        assert respuesta.headers.get(nombre) == valor, nombre


def test_health_responde_200_con_estado_ok(cliente: TestClient) -> None:
    respuesta = cliente.get("/health")
    assert respuesta.status_code == 200
    assert respuesta.json() == {"estado": "ok"}


def test_health_lleva_los_headers_de_seguridad(cliente: TestClient) -> None:
    _assert_headers_seguridad(cliente.get("/health"))


def test_404_lleva_los_headers_de_seguridad(cliente: TestClient) -> None:
    respuesta = cliente.get("/no-existe")
    assert respuesta.status_code == 404
    _assert_headers_seguridad(respuesta)


def test_405_lleva_los_headers_de_seguridad(cliente: TestClient) -> None:
    respuesta = cliente.post("/health")
    assert respuesta.status_code == 405
    _assert_headers_seguridad(respuesta)


@pytest.mark.parametrize("ruta", RUTAS_DOCS)
def test_docs_apagados_por_defecto(cliente: TestClient, ruta: str) -> None:
    respuesta = cliente.get(ruta)
    assert respuesta.status_code == 404
    _assert_headers_seguridad(respuesta)


@pytest.mark.parametrize(
    "valor", ["0", "", "true", "TRUE", "yes", "1 ", " 1", "01", "11"]
)
@pytest.mark.parametrize("ruta", RUTAS_DOCS)
def test_docs_apagados_con_cualquier_valor_distinto_de_1(
    monkeypatch: pytest.MonkeyPatch, ruta: str, valor: str
) -> None:
    monkeypatch.setenv("GATEKEEPER_DOCS", valor)
    assert TestClient(crear_app()).get(ruta).status_code == 404


def test_openapi_json_encendido_solo_con_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GATEKEEPER_DOCS", "1")
    respuesta = TestClient(crear_app()).get("/openapi.json")
    assert respuesta.status_code == 200
    _assert_headers_seguridad(respuesta)


@pytest.mark.parametrize("ruta", RUTAS_DOCS_SIEMPRE_APAGADAS)
def test_docs_y_redoc_apagados_incluso_con_1(
    monkeypatch: pytest.MonkeyPatch, ruta: str
) -> None:
    monkeypatch.setenv("GATEKEEPER_DOCS", "1")
    respuesta = TestClient(crear_app()).get(ruta)
    assert respuesta.status_code == 404
    _assert_headers_seguridad(respuesta)


def test_sin_otras_rutas_que_health(cliente: TestClient) -> None:
    rutas = {getattr(r, "path", None) for r in cliente.app.routes}
    assert rutas == {"/health"}


def test_sin_otras_rutas_que_health_y_docs_con_docs_encendidos(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GATEKEEPER_DOCS", "1")
    rutas = {getattr(r, "path", None) for r in crear_app().routes}
    assert rutas == {"/health", "/openapi.json"}


def test_sin_header_server(cliente: TestClient) -> None:
    for respuesta in (cliente.get("/health"), cliente.get("/no-existe")):
        assert "server" not in respuesta.headers


class _ErrorSecreto(RuntimeError):
    pass


@pytest.fixture
def cliente_con_error(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.delenv("GATEKEEPER_DOCS", raising=False)
    app = crear_app()

    @app.get("/_prueba_error")
    def _falla() -> None:
        raise _ErrorSecreto("detalle-interno /srv/secreto password=xyz")

    return TestClient(app, raise_server_exceptions=False)


def test_error_500_es_generico_y_sin_detalle(cliente_con_error: TestClient) -> None:
    respuesta = cliente_con_error.get("/_prueba_error")
    assert respuesta.status_code == 500
    assert respuesta.json() == {"detail": "Internal Server Error"}
    texto = respuesta.text
    for fuga in (
        "detalle-interno",
        "/srv/secreto",
        "password",
        "_ErrorSecreto",
        "Traceback",
    ):
        assert fuga not in texto
    assert "server" not in respuesta.headers
    _assert_headers_seguridad(respuesta)


def test_error_500_se_registra_en_el_log(
    cliente_con_error: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("ERROR"):
        cliente_con_error.get("/_prueba_error")
    assert any(r.exc_info and r.exc_info[0] is _ErrorSecreto for r in caplog.records)


def test_app_sin_modo_debug(cliente: TestClient) -> None:
    assert cliente.app.debug is False


def test_middleware_quita_server_puesto_por_la_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fastapi import Response

    monkeypatch.delenv("GATEKEEPER_DOCS", raising=False)
    app = crear_app()

    @app.get("/_prueba_server")
    def _con_server() -> Response:
        return Response("x", headers={"Server": "uvicorn/0.54.0 Python/3.12"})

    respuesta = TestClient(app).get("/_prueba_server")
    assert "server" not in respuesta.headers
    _assert_headers_seguridad(respuesta)


def test_head_health_responde_200_con_headers(cliente: TestClient) -> None:
    respuesta = cliente.head("/health")
    assert respuesta.status_code == 200
    assert respuesta.content == b""
    _assert_headers_seguridad(respuesta)


def test_headers_seguridad_es_el_middleware_mas_externo(cliente: TestClient) -> None:
    from api.app.seguridad import HeadersSeguridad

    assert cliente.app.user_middleware[0].cls is HeadersSeguridad


class _MiddlewareQueFalla:
    """Middleware ASGI de prueba que falla antes de empezar la respuesta."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            raise _ErrorSecreto("detalle-interno del middleware")
        await self.app(scope, receive, send)


@pytest.fixture
def cliente_middleware_que_falla(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    # Camino documentado en crear_app: los middlewares nuevos van en MIDDLEWARES_INTERNOS,
    # que quedan por dentro de HeadersSeguridad.
    from starlette.middleware import Middleware

    from api.app import principal

    monkeypatch.delenv("GATEKEEPER_DOCS", raising=False)
    monkeypatch.setattr(
        principal, "MIDDLEWARES_INTERNOS", (Middleware(_MiddlewareQueFalla),)
    )
    return TestClient(principal.crear_app(), raise_server_exceptions=False)


def test_middleware_interno_que_falla_da_500_con_headers(
    cliente_middleware_que_falla: TestClient,
) -> None:
    app = cliente_middleware_que_falla.app
    from api.app.seguridad import HeadersSeguridad

    assert app.user_middleware[0].cls is HeadersSeguridad
    assert app.user_middleware[1].cls is _MiddlewareQueFalla
    respuesta = cliente_middleware_que_falla.get("/health")
    assert respuesta.status_code == 500
    assert respuesta.json() == {"detail": "Internal Server Error"}
    assert "detalle-interno" not in respuesta.text
    assert "server" not in respuesta.headers
    _assert_headers_seguridad(respuesta)


@pytest.mark.parametrize(
    "ruta",
    [
        "/a%0AERROR%20linea%20falsa",
        "/a%0DERROR%20linea%20falsa",
        "/a%0D%0AERROR%20linea%20falsa",
        "/a%1B%5B31m%00%7F",
        "/a%C2%85b%E2%80%A8c%E2%80%A9d",
    ],
)
def test_log_de_la_traza_no_admite_caracteres_de_control(
    cliente_middleware_que_falla: TestClient,
    caplog: pytest.LogCaptureFixture,
    ruta: str,
) -> None:
    with caplog.at_level("ERROR", logger="gatekeeper.api"):
        respuesta = cliente_middleware_que_falla.get(ruta)
    assert respuesta.status_code == 500
    registros = [r for r in caplog.records if r.name == "gatekeeper.api"]
    assert registros, "la excepción debe registrarse"
    for registro in registros:
        mensaje = registro.getMessage()
        assert len(mensaje.splitlines()) == 1, mensaje
        assert "\n" not in mensaje and "\r" not in mensaje
        assert not any(ord(c) < 0x20 or ord(c) == 0x7F for c in mensaje), mensaje
        # La ruta queda reconocible, escapada.
        assert "/a" in mensaje


def test_log_de_la_traza_no_incluye_cabeceras_ni_cuerpo(
    cliente_middleware_que_falla: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("ERROR", logger="gatekeeper.api"):
        cliente_middleware_que_falla.post(
            "/x",
            headers={"Authorization": "Bearer clave-secreta-123"},
            content=b"cuerpo-secreto-456",
        )
    texto = caplog.text
    assert "clave-secreta-123" not in texto
    assert "cuerpo-secreto-456" not in texto
