"""Autenticación por API key (F2.01, diseño §3)."""

import hashlib
import hmac
import logging
import re
import secrets
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import pytest
from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, update
from sqlalchemy.engine import URL

from api.app import autenticacion
from api.app.ajustes import Ajustes
from api.app.autenticacion import (
    AplicacionAutenticada,
    autenticar,
    calcular_hash,
    generar_key,
)
from api.app.principal import crear_app
from api.app.v1 import crear_router_v1
from api.db.modelos import ApiKey, Aplicacion
from api.tests.soporte_api import KeySembrada, sembrar_key, url_sin_servidor

RUTA = "/v1/_prueba"
URL_SIN_SERVIDOR = url_sin_servidor(secrets.token_urlsafe(24))
# Con el formato exacto, pero generados aquí y no con generar_key(): así esa función no es
# su propio oráculo. token_urlsafe(32) da siempre 43 caracteres.
PREFIJO_CON_FORMATO = f"gk_{secrets.token_hex(6)}"
SECRETO_VALIDO = secrets.token_urlsafe(32)
KEY_CON_FORMATO = f"{PREFIJO_CON_FORMATO}.{SECRETO_VALIDO}"
PEPPER_FICTICIO = secrets.token_hex(16).encode()
CABECERAS_MAL_FORMADAS: list[tuple[bytes, bytes]] = [
    (b"authorization", b""),
    (b"authorization", b"Bearer"),
    (b"authorization", b"Bearer "),
    (b"authorization", b"bearer " + KEY_CON_FORMATO.encode()),
    (b"authorization", b"Basic " + KEY_CON_FORMATO.encode()),
    (b"authorization", b"Bearer  " + KEY_CON_FORMATO.encode()),
    (b"authorization", b" Bearer " + KEY_CON_FORMATO.encode()),
    (b"authorization", KEY_CON_FORMATO.encode()),
    (b"authorization", b"Bearer " + KEY_CON_FORMATO.encode() + b" "),
    (b"authorization", b"Bearer " + KEY_CON_FORMATO.encode() + b"\n"),
    (b"authorization", b"Bearer " + KEY_CON_FORMATO.encode() + b"\x00"),
    (b"authorization", b"Bearer gk_" + b"a" * 11 + b"." + b"A" * 43),
    (b"authorization", b"Bearer gk_" + b"a" * 13 + b"." + b"A" * 43),
    (b"authorization", b"Bearer gk_" + b"A" * 12 + b"." + b"A" * 43),
    (b"authorization", b"Bearer gk_" + b"g" * 12 + b"." + b"A" * 43),
    (b"authorization", b"Bearer xx_" + b"a" * 12 + b"." + b"A" * 43),
    (b"authorization", b"Bearer gk_" + b"a" * 12 + b"." + b"A" * 42),
    (b"authorization", b"Bearer gk_" + b"a" * 12 + b"." + b"A" * 44),
    (b"authorization", b"Bearer gk_" + b"a" * 12 + b"." + b"A" * 42 + b"="),
    (b"authorization", b"Bearer gk_" + b"a" * 12 + b"." + b"A" * 42 + b"\x00"),
    (b"authorization", b"Bearer gk_" + b"a" * 12 + b"." + b"A" * 42 + b"\xff"),
    (b"authorization", b"Bearer gk_" + b"a" * 12 + b"_" + b"A" * 43),
    (b"authorization", b"Bearer gk_" + b"\xd9\xa3" * 6 + b"." + b"A" * 43),
    (b"authorization", b"Bearer ' OR 1=1 --"),
]


def _ajustes(url: URL | str, pepper: bytes, tmp_path: Path) -> Ajustes:
    return Ajustes(url_bd=url, pepper=pepper, datos=tmp_path / "datos")


def _app_de_prueba(ajustes: Ajustes) -> FastAPI:
    """La app real con una ruta solo de prueba colgada del router real de ``/v1``."""
    app = crear_app(ajustes)
    router = crear_router_v1()

    @router.get("/_prueba")
    async def _prueba(aplicacion_id: AplicacionAutenticada) -> dict[str, str]:
        return {"aplicacion_id": str(aplicacion_id)}

    app.include_router(router)
    return app


def _bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _firma_de_respuesta(respuesta: Any) -> tuple[int, bytes, list[tuple[str, str]]]:
    return respuesta.status_code, respuesta.content, sorted(respuesta.headers.items())


def _assert_401_exacto(respuesta: Any) -> None:
    assert respuesta.status_code == 401
    assert respuesta.json() == {"detail": "Unauthorized"}
    assert respuesta.headers["www-authenticate"] == "Bearer"
    assert respuesta.headers["cache-control"] == "no-store"


# ------------------------------------------------------------- formato y generación


def test_el_hash_es_hmac_sha256_de_la_key_completa_en_hex() -> None:
    esperado = hmac.new(
        PEPPER_FICTICIO, KEY_CON_FORMATO.encode(), hashlib.sha256
    ).hexdigest()
    assert calcular_hash(PEPPER_FICTICIO, KEY_CON_FORMATO) == esperado
    assert re.fullmatch(r"[0-9a-f]{64}", esperado)


def test_generar_key_cumple_el_formato_siempre() -> None:
    for _ in range(2000):  # token_urlsafe produce - y _ en parte de las muestras
        prefijo, key = generar_key()
        assert re.fullmatch(r"gk_[0-9a-f]{12}", prefijo)
        assert key.startswith(f"{prefijo}.")
        assert autenticacion._FORMATO_CREDENCIAL.fullmatch(key)


def test_generar_key_no_repite() -> None:
    assert generar_key() != generar_key()


# ------------------------------------------- rechazos antes de consultar (sin BD real)


@pytest.fixture
def consultas(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Registra las consultas; responde "no hay fila", así que no hace falta BD."""
    registradas: list[str] = []

    async def _obtener(_sesion: object, prefijo: str) -> None:
        registradas.append(prefijo)

    monkeypatch.setattr(autenticacion, "obtener_api_key_activa", _obtener)
    return registradas


class _SesionFalsa:
    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None


def _request(headers: list[tuple[bytes, bytes]]) -> Request:
    app = SimpleNamespace(
        state=SimpleNamespace(
            sesiones=_SesionFalsa, ajustes=SimpleNamespace(pepper=PEPPER_FICTICIO)
        )
    )
    return Request({"type": "http", "headers": headers, "app": app})


@pytest.mark.anyio
@pytest.mark.parametrize("cabecera", CABECERAS_MAL_FORMADAS)
async def test_mal_formada_da_401_sin_consultar(
    cabecera: tuple[bytes, bytes], consultas: list[str]
) -> None:
    with pytest.raises(HTTPException) as error:
        await autenticar(_request([cabecera]))
    assert error.value.status_code == 401
    assert consultas == []


@pytest.mark.anyio
async def test_sin_cabecera_da_401_sin_consultar(consultas: list[str]) -> None:
    with pytest.raises(HTTPException) as error:
        await autenticar(_request([]))
    assert error.value.status_code == 401
    assert consultas == []


@pytest.mark.anyio
async def test_dos_cabeceras_authorization_dan_401_sin_consultar(
    consultas: list[str],
) -> None:
    valida = b"Bearer " + KEY_CON_FORMATO.encode()
    with pytest.raises(HTTPException) as error:
        await autenticar(
            _request([(b"authorization", valida), (b"authorization", valida)])
        )
    assert error.value.status_code == 401
    assert consultas == []


@pytest.mark.anyio
async def test_un_surrogate_no_llega_a_la_consulta(
    consultas: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Una cabecera HTTP no lo trae (se decodifica en latin-1), pero la regex es la que
    # responde por él, no esa decodificación.
    peticion = _request([])
    monkeypatch.setattr(
        peticion.headers.__class__,
        "getlist",
        lambda _self, _nombre: [f"Bearer gk_{'a' * 12}.{'A' * 42}\ud800"],
    )
    with pytest.raises(HTTPException):
        await autenticar(peticion)
    assert consultas == []


@pytest.mark.anyio
async def test_con_formato_valido_si_consulta_por_el_prefijo(
    consultas: list[str],
) -> None:
    cabecera = (b"authorization", b"Bearer " + KEY_CON_FORMATO.encode())
    with pytest.raises(HTTPException):
        await autenticar(_request([cabecera]))
    assert consultas == [PREFIJO_CON_FORMATO]


@pytest.fixture
def espias(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Cuenta los HMAC y las comparaciones, sin cambiar lo que hacen."""
    registro = SimpleNamespace(hmacs=0, comparaciones=[])
    calcular_original = autenticacion.calcular_hash
    comparar_original = hmac.compare_digest

    def _calcular(pepper: bytes, key: str) -> str:
        registro.hmacs += 1
        return calcular_original(pepper, key)

    def _comparar(a: str, b: str) -> bool:
        registro.comparaciones.append((a, b))
        return comparar_original(a, b)

    monkeypatch.setattr(autenticacion, "calcular_hash", _calcular)
    monkeypatch.setattr(autenticacion.hmac, "compare_digest", _comparar)
    return registro


@pytest.mark.anyio
async def test_sin_fila_se_calcula_y_se_compara_el_hmac_igual(
    consultas: list[str], espias: SimpleNamespace
) -> None:
    cabecera = (b"authorization", b"Bearer " + KEY_CON_FORMATO.encode())
    with pytest.raises(HTTPException):
        await autenticar(_request([cabecera]))
    assert espias.hmacs == 1
    assert len(espias.comparaciones) == 1


@pytest.mark.anyio
async def test_sin_fila_rechaza_aunque_la_comparacion_diera_verdadero(
    consultas: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # El hash de relleno no decide nada: sin fila no hay autenticación posible.
    monkeypatch.setattr(autenticacion.hmac, "compare_digest", lambda _a, _b: True)
    cabecera = (b"authorization", b"Bearer " + KEY_CON_FORMATO.encode())
    with pytest.raises(HTTPException) as error:
        await autenticar(_request([cabecera]))
    assert error.value.status_code == 401


# ------------------------------------------------------------------- HTTP y BD real


@pytest.fixture
def pepper() -> bytes:
    return secrets.token_hex(32).encode()


@pytest.fixture
def ajustes(bd_limpia: URL, pepper: bytes, tmp_path: Path) -> Ajustes:
    return _ajustes(bd_limpia, pepper, tmp_path)


@pytest.fixture
def cliente(ajustes: Ajustes) -> Iterator[TestClient]:
    with TestClient(_app_de_prueba(ajustes)) as con_ciclo_de_vida:
        yield con_ciclo_de_vida


@pytest.fixture
def sembrada(bd_limpia: URL, pepper: bytes) -> KeySembrada:
    return sembrar_key(bd_limpia, pepper)


def _actualizar(url: URL, sentencia: Any) -> None:
    motor = create_engine(url)
    try:
        with motor.begin() as con:
            con.execute(sentencia)
    finally:
        motor.dispose()


def test_key_valida_devuelve_su_aplicacion(
    cliente: TestClient, sembrada: KeySembrada
) -> None:
    respuesta = cliente.get(RUTA, headers=_bearer(sembrada.key))
    assert respuesta.status_code == 200
    assert respuesta.json() == {"aplicacion_id": str(sembrada.aplicacion_id)}


def test_cada_key_resuelve_su_propia_aplicacion(
    cliente: TestClient, bd_limpia: URL, pepper: bytes
) -> None:
    una = sembrar_key(bd_limpia, pepper, "una")
    otra = sembrar_key(bd_limpia, pepper, "otra")
    for sembrada in (una, otra):
        respuesta = cliente.get(RUTA, headers=_bearer(sembrada.key))
        assert respuesta.json() == {"aplicacion_id": str(sembrada.aplicacion_id)}


def _casos_de_rechazo(
    url: URL, pepper: bytes
) -> dict[str, Callable[[KeySembrada], dict[str, str]]]:
    def _revocada(sembrada: KeySembrada) -> dict[str, str]:
        _actualizar(
            url,
            update(ApiKey)
            .where(ApiKey.prefijo == sembrada.prefijo)
            .values(revocada_en=func.now()),
        )
        return _bearer(sembrada.key)

    def _inactiva(sembrada: KeySembrada) -> dict[str, str]:
        _actualizar(
            url,
            update(Aplicacion)
            .where(Aplicacion.id == sembrada.aplicacion_id)
            .values(activa=False),
        )
        return _bearer(sembrada.key)

    def _secreto_de_otra(sembrada: KeySembrada) -> dict[str, str]:
        otra = sembrar_key(url, pepper, "otra")
        return _bearer(f"{sembrada.prefijo}.{otra.key.split('.')[1]}")

    return {
        "sin_cabecera": lambda _s: {},
        "mal_formada": lambda _s: {"Authorization": "Bearer nada"},
        "esquema_basic": lambda s: {"Authorization": f"Basic {s.key}"},
        "prefijo_inexistente": lambda _s: _bearer(KEY_CON_FORMATO),
        "secreto_incorrecto": lambda s: _bearer(f"{s.prefijo}.{SECRETO_VALIDO}"),
        "secreto_de_otra_key": _secreto_de_otra,
        "revocada": _revocada,
        "aplicacion_inactiva": _inactiva,
    }


CASOS = (
    "sin_cabecera",
    "mal_formada",
    "esquema_basic",
    "prefijo_inexistente",
    "secreto_incorrecto",
    "secreto_de_otra_key",
    "revocada",
    "aplicacion_inactiva",
)


@pytest.mark.parametrize("caso", CASOS)
def test_todo_rechazo_es_el_mismo_401(
    cliente: TestClient,
    sembrada: KeySembrada,
    bd_limpia: URL,
    pepper: bytes,
    caso: str,
) -> None:
    referencia = cliente.get(RUTA)
    _assert_401_exacto(referencia)

    cabeceras = _casos_de_rechazo(bd_limpia, pepper)[caso](sembrada)
    respuesta = cliente.get(RUTA, headers=cabeceras)

    _assert_401_exacto(respuesta)
    assert _firma_de_respuesta(respuesta) == _firma_de_respuesta(referencia)


def test_un_pepper_distinto_no_autentica(
    bd_limpia: URL, sembrada: KeySembrada, tmp_path: Path
) -> None:
    otro_pepper = secrets.token_hex(32).encode()
    app = _app_de_prueba(_ajustes(bd_limpia, otro_pepper, tmp_path))
    with TestClient(app) as cliente:
        _assert_401_exacto(cliente.get(RUTA, headers=_bearer(sembrada.key)))


@pytest.mark.parametrize("caso", ["revocada", "aplicacion_inactiva"])
def test_revocada_e_inactiva_tambien_pagan_el_hmac(
    cliente: TestClient,
    sembrada: KeySembrada,
    bd_limpia: URL,
    pepper: bytes,
    espias: SimpleNamespace,
    caso: str,
) -> None:
    cabeceras = _casos_de_rechazo(bd_limpia, pepper)[caso](sembrada)
    cliente.get(RUTA, headers=cabeceras)
    assert espias.hmacs == 1
    assert len(espias.comparaciones) == 1


def test_la_comparacion_usa_compare_digest_con_el_hash_guardado(
    cliente: TestClient,
    sembrada: KeySembrada,
    pepper: bytes,
    espias: SimpleNamespace,
) -> None:
    cliente.get(RUTA, headers=_bearer(sembrada.key))
    esperado = calcular_hash(pepper, sembrada.key)
    assert espias.comparaciones == [(esperado, esperado)]


def test_la_dependencia_del_router_y_la_del_parametro_son_una_sola_consulta(
    cliente: TestClient, sembrada: KeySembrada, monkeypatch: pytest.MonkeyPatch
) -> None:
    llamadas = []
    original = autenticacion.obtener_api_key_activa

    async def _contar(sesion: Any, prefijo: str) -> Any:
        llamadas.append(prefijo)
        return await original(sesion, prefijo)

    monkeypatch.setattr(autenticacion, "obtener_api_key_activa", _contar)
    assert cliente.get(RUTA, headers=_bearer(sembrada.key)).status_code == 200
    assert llamadas == [sembrada.prefijo]


def test_la_sesion_no_queda_abierta_al_entrar_a_la_ruta(
    ajustes: Ajustes, sembrada: KeySembrada
) -> None:
    # La conexión vuelve al pool antes de la ruta: una subida lenta no la retiene.
    app = crear_app(ajustes)
    router = crear_router_v1()

    @router.get("/_prueba")
    async def _prueba(request: Request) -> dict[str, int]:
        return {"ocupadas": request.app.state.motor.pool.checkedout()}

    app.include_router(router)
    with TestClient(app) as cliente:
        respuesta = cliente.get(RUTA, headers=_bearer(sembrada.key))
    assert respuesta.json() == {"ocupadas": 0}


def test_si_la_bd_no_responde_es_500_generico_y_no_autentica(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Un fallo de la BD no es un rechazo de la key (K29): no se dice 401 ni deja pasar.
    app = _app_de_prueba(_ajustes(URL_SIN_SERVIDOR, PEPPER_FICTICIO, tmp_path))
    with TestClient(app, raise_server_exceptions=False) as cliente:
        respuesta = cliente.get(RUTA, headers=_bearer(KEY_CON_FORMATO))
    assert respuesta.status_code == 500
    assert respuesta.json() == {"detail": "Internal Server Error"}
    assert SECRETO_VALIDO not in caplog.text


def test_nada_se_registra_de_la_key_ni_del_hash(
    cliente: TestClient,
    sembrada: KeySembrada,
    pepper: bytes,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        cliente.get(RUTA, headers=_bearer(sembrada.key))
        cliente.get(RUTA, headers=_bearer(f"{sembrada.prefijo}.{SECRETO_VALIDO}"))
    secreto = sembrada.key.split(".")[1]
    assert secreto not in caplog.text
    assert SECRETO_VALIDO not in caplog.text
    assert calcular_hash(pepper, sembrada.key) not in caplog.text


# --------------------------------------------------------------- el cuerpo no se toca


def _peticion_asgi(cabeceras: list[tuple[bytes, bytes]]) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "path": "/v1/_subida",
        "raw_path": b"/v1/_subida",
        "query_string": b"",
        "root_path": "",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("testclient", 1),
        "headers": cabeceras,
    }


@pytest.mark.parametrize(
    "cabeceras",
    [[], [(b"authorization", b"Bearer " + KEY_CON_FORMATO.encode())]],
    ids=["sin_cabecera", "key_inexistente"],
)
def test_un_rechazo_no_lee_ni_un_byte_del_cuerpo(
    ajustes: Ajustes, cabeceras: list[tuple[bytes, bytes]]
) -> None:
    app = crear_app(ajustes)
    router = crear_router_v1()

    @router.post("/_subida")
    async def _subida(request: Request) -> int:
        return len(await request.body())

    app.include_router(router)
    lecturas = []
    enviados: list[dict[str, Any]] = []

    async def _recibir() -> dict[str, Any]:
        lecturas.append(1)
        return {"type": "http.request", "body": b"x", "more_body": False}

    async def _enviar(mensaje: dict[str, Any]) -> None:
        enviados.append(mensaje)

    with TestClient(app) as cliente:
        assert cliente.portal is not None
        cliente.portal.call(app, _peticion_asgi(cabeceras), _recibir, _enviar)

    assert enviados[0]["status"] == 401
    assert lecturas == []


def test_el_router_v1_nace_con_la_autenticacion_puesta() -> None:
    router = crear_router_v1()
    assert router.prefix == "/v1"
    assert [d.dependency for d in router.dependencies] == [autenticar]


def test_ninguna_ruta_de_v1_olvida_autenticar_ni_declara_cuerpo() -> None:
    # Vigila los endpoints que vayan llegando a crear_router_v1. Con cuerpo declarado,
    # FastAPI lo leería antes de resolver `autenticar` (ver test siguiente).
    for ruta in crear_router_v1().routes:
        assert isinstance(ruta, APIRoute), ruta
        assert autenticar in {d.call for d in ruta.dependant.dependencies}, ruta.path
        assert ruta.body_field is None, ruta.path


def test_fastapi_lee_el_cuerpo_declarado_antes_de_las_dependencias() -> None:
    # Documenta por qué la prueba anterior exige body_field None: si FastAPI cambia esto,
    # esta prueba avisa de que la regla se puede relajar.
    orden: list[str] = []
    app = FastAPI()

    def _dependencia() -> None:
        orden.append("dependencia")

    @app.post("/x", dependencies=[Depends(_dependencia)])
    async def _ruta(_dato: dict[str, int] = Body()) -> None:  # noqa: B008
        return None

    async def _recibir() -> dict[str, Any]:
        orden.append("cuerpo")
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def _enviar(_mensaje: dict[str, Any]) -> None:
        return None

    with TestClient(app) as cliente:
        assert cliente.portal is not None
        alcance = {
            **_peticion_asgi([(b"content-type", b"application/json")]),
            "path": "/x",
            "raw_path": b"/x",
        }
        cliente.portal.call(app, alcance, _recibir, _enviar)
    assert orden.index("cuerpo") < orden.index("dependencia")
