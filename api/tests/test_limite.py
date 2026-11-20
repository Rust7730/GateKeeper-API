"""Rate limit (F2.07; K10, K58, K59, K60) y las tres decisiones del usuario del 2026-11-19.

1. Solo ``POST /v1/files`` gasta el cupo por key (bucket por aplicación de 20 que recarga 2/s).
   ``GET /v1/files/{id}`` y ``/content`` no lo gastan. El límite por IP (60/min) vale para toda
   petición sin autenticar o con key inválida en cualquier ruta de ``/v1``.
2. Redis tiene 1 s para responder (conexión u operación); si no, 503.
3. IPv6 se agrupa por su /64; IPv4 por dirección exacta; ``::ffff:a.b.c.d`` cuenta como IPv4.

Las pruebas de ataque del mismo control están en ``tests/attack-matrix`` (vec:14, K58, K59).
Aquí van las del diseño: el limitador contra un Redis real con la ACL de producción y las
respuestas HTTP que la matriz no fija.
"""

import asyncio
import secrets
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import URL

from api.app import limite
from api.app.ajustes import Ajustes, ConfiguracionError
from api.app.limite import (
    CAPACIDAD_SUBIDAS,
    LIMITE_IP,
    TIMEOUT_REDIS_S,
    TTL_S,
    VENTANA_IP_S,
    Limitador,
    RedisNoDisponible,
    abrir_limitador,
    clave_ip,
)
from api.app.principal import crear_app
from api.tests.soporte_api import KeySembrada, sembrar_key
from api.tests.soporte_redis import (
    USUARIO_API,
    RedisDePrueba,
    RelojFalso,
    puerto_cerrado,
    redis_colgado,
)

IP_A = "192.0.2.10"
PNG_MINIMO = b"\x89PNG\r\n\x1a\n" + bytes(64)
LIMITE_MULTIPART = "limitegk"
# Holgura sobre el segundo de Redis para el resto de la petición (no es un tope de rendimiento).
HOLGURA_TIMEOUT_S = 0.5


def _cuerpo(contenido: bytes = PNG_MINIMO) -> bytes:
    limite_mp = LIMITE_MULTIPART.encode()
    return (
        b'--%s\r\nContent-Disposition: form-data; name="file"; filename="a"\r\n\r\n'
        b"%s\r\n--%s--\r\n" % (limite_mp, contenido, limite_mp)
    )


# ------------------------------------------------------------------ decisión 3: la IP


@pytest.mark.parametrize(
    ("una", "otra"),
    [
        ("2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:ffff"),
        ("2001:db8:1:2::1", "2001:0db8:0001:0002:0000:0000:0000:0009"),
        ("fe80::1%eth0", "fe80::2"),
        ("::ffff:192.0.2.7", "192.0.2.7"),
        ("::ffff:c000:207", "192.0.2.7"),
    ],
    ids=["mismo_64", "misma_forma_larga", "con_zona", "ipv4_mapeada", "mapeada_en_hex"],
)
def test_comparten_cuenta(una: str, otra: str) -> None:
    assert clave_ip(una) == clave_ip(otra)


@pytest.mark.parametrize(
    ("una", "otra"),
    [
        ("2001:db8:1:2::1", "2001:db8:1:3::1"),
        ("2001:db8:1:2::1", "2001:db9:1:2::1"),
        ("192.0.2.7", "192.0.2.8"),
        ("192.0.2.7", "::ffff:192.0.2.8"),
        ("192.0.2.7", "::c000:207"),
        ("192.0.2.7", "garbage"),
    ],
    ids=[
        "otro_64",
        "otro_prefijo",
        "ipv4_vecina",
        "mapeada_distinta",
        "compatible_no_es_mapeada",
        "texto",
    ],
)
def test_no_comparten_cuenta(una: str, otra: str) -> None:
    assert clave_ip(una) != clave_ip(otra)


def test_lo_que_no_es_ip_comparte_una_sola_cuenta() -> None:
    """Sin una IP que agrupar, todo cae en la misma cuenta: falla cerrado, no abre una por texto."""
    assert clave_ip(None) == clave_ip("testclient") == clave_ip("x" * 300)
    assert len(clave_ip("x" * 300)) < 64


# ---------------------------------------------------------- el limitador, con Redis real


@pytest.fixture
def reloj() -> RelojFalso:
    return RelojFalso(time.time())


@pytest.fixture
async def limitador(url_redis: str, reloj: RelojFalso) -> AsyncIterator[Limitador]:
    abierto = abrir_limitador(url_redis, reloj)
    try:
        yield abierto
    finally:
        await abierto.cerrar()


async def _gastar(limitador: Limitador, app: uuid.UUID, veces: int) -> list[bool]:
    return [(await limitador.gastar_subida(app)).permitido for _ in range(veces)]


@pytest.mark.anyio
async def test_el_bucket_da_20_y_la_21_espera_al_menos_un_segundo(
    limitador: Limitador,
) -> None:
    app = uuid.uuid4()
    assert await _gastar(limitador, app, CAPACIDAD_SUBIDAS) == [True] * 20
    negado = await limitador.gastar_subida(app)
    assert not negado.permitido
    assert negado.reintentar_en_s == 1  # media ficha a 2/s: 0.5 s, redondeado arriba


@pytest.mark.anyio
async def test_el_bucket_recarga_2_por_segundo(
    limitador: Limitador, reloj: RelojFalso
) -> None:
    app = uuid.uuid4()
    await _gastar(limitador, app, CAPACIDAD_SUBIDAS)
    reloj.avanzar(0.49)
    assert not (await limitador.gastar_subida(app)).permitido
    reloj.avanzar(0.02)
    assert (await limitador.gastar_subida(app)).permitido
    reloj.avanzar(5)
    assert await _gastar(limitador, app, 11) == [True] * 10 + [False]


@pytest.mark.anyio
async def test_un_reloj_que_retrocede_no_regala_fichas(
    limitador: Limitador, reloj: RelojFalso
) -> None:
    app = uuid.uuid4()
    await _gastar(limitador, app, CAPACIDAD_SUBIDAS)
    reloj.avanzar(-30)
    assert not (await limitador.gastar_subida(app)).permitido
    reloj.avanzar(30)
    assert not (await limitador.gastar_subida(app)).permitido


@pytest.mark.anyio
async def test_cada_aplicacion_tiene_su_bucket(limitador: Limitador) -> None:
    una, otra = uuid.uuid4(), uuid.uuid4()
    await _gastar(limitador, una, CAPACIDAD_SUBIDAS)
    assert (await limitador.gastar_subida(otra)).permitido


@pytest.mark.anyio
async def test_la_ventana_por_ip_da_60_y_se_reabre_al_minuto(
    limitador: Limitador, reloj: RelojFalso
) -> None:
    for _ in range(LIMITE_IP):
        assert (await limitador.contar_sin_autenticar(IP_A)).permitido
    negado = await limitador.contar_sin_autenticar(IP_A)
    assert not negado.permitido
    assert negado.reintentar_en_s == VENTANA_IP_S
    reloj.avanzar(VENTANA_IP_S - 0.5)
    negado = await limitador.contar_sin_autenticar(IP_A)
    assert not negado.permitido
    assert negado.reintentar_en_s == 1
    reloj.avanzar(0.5)
    assert (await limitador.contar_sin_autenticar(IP_A)).permitido


@pytest.mark.anyio
async def test_la_ventana_es_deslizante_no_por_minuto_de_reloj(
    limitador: Limitador, reloj: RelojFalso
) -> None:
    """30 al final de un minuto y 30 al principio del siguiente: no hay 60 más de regalo."""
    for _ in range(30):
        assert (await limitador.contar_sin_autenticar(IP_A)).permitido
    reloj.avanzar(30)
    for _ in range(30):
        assert (await limitador.contar_sin_autenticar(IP_A)).permitido
    reloj.avanzar(29)
    assert not (await limitador.contar_sin_autenticar(IP_A)).permitido
    reloj.avanzar(1)
    assert (await limitador.contar_sin_autenticar(IP_A)).permitido


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("agotar_desde", "comparte", "no_comparte"),
    [
        ("2001:db8:a:b::1", "2001:db8:a:b:ffff::2", "2001:db8:a:c::1"),
        ("::ffff:198.51.100.7", "198.51.100.7", "198.51.100.8"),
    ],
    ids=["ipv6_por_64", "ipv4_mapeada"],
)
async def test_decision_3_en_el_limitador(
    limitador: Limitador, agotar_desde: str, comparte: str, no_comparte: str
) -> None:
    for _ in range(LIMITE_IP):
        assert (await limitador.contar_sin_autenticar(agotar_desde)).permitido
    assert not (await limitador.contar_sin_autenticar(comparte)).permitido
    assert (await limitador.contar_sin_autenticar(no_comparte)).permitido


@pytest.mark.anyio
async def test_las_claves_tienen_ttl_acotado_y_solo_el_id_o_la_ip(
    limitador: Limitador, redis_prueba: RedisDePrueba
) -> None:
    app = uuid.uuid4()
    await limitador.gastar_subida(app)
    await limitador.contar_sin_autenticar("2001:db8:a:b::1")
    admin = redis_prueba.admin()
    try:
        claves = {clave: admin.pttl(clave) for clave in admin.scan_iter()}
    finally:
        admin.close()
    assert len(claves) == 2
    assert {clave.decode().split(":")[1] for clave in claves} == {"subidas", "ip"}
    assert any(str(app).encode() in clave for clave in claves)
    for clave, pttl in claves.items():
        assert 0 < pttl <= TTL_S * 1000, (clave, pttl)


@pytest.mark.anyio
async def test_funciona_aunque_redis_haya_olvidado_el_script(
    limitador: Limitador, redis_prueba: RedisDePrueba
) -> None:
    """Tras un reinicio de Redis la caché de scripts está vacía (NOSCRIPT)."""
    app = uuid.uuid4()
    assert (await limitador.gastar_subida(app)).permitido
    admin = redis_prueba.admin()
    try:
        admin.script_flush()
    finally:
        admin.close()
    assert (await limitador.gastar_subida(app)).permitido
    assert (await limitador.contar_sin_autenticar(IP_A)).permitido


@pytest.mark.anyio
async def test_el_pool_esta_acotado(
    limitador: Limitador, redis_prueba: RedisDePrueba
) -> None:
    await asyncio.gather(
        *(limitador.contar_sin_autenticar(f"198.51.100.{n}") for n in range(200))
    )
    admin = redis_prueba.admin()
    try:
        propias = [c for c in admin.client_list() if c["user"] == USUARIO_API]
    finally:
        admin.close()
    assert 1 <= len(propias) <= limite.CONEXIONES_REDIS


@pytest.mark.anyio
async def test_cerrar_suelta_todas_las_conexiones(
    url_redis: str, reloj: RelojFalso, redis_prueba: RedisDePrueba
) -> None:
    abierto = abrir_limitador(url_redis, reloj)
    await abierto.contar_sin_autenticar(IP_A)
    await abierto.cerrar()
    admin = redis_prueba.admin()
    try:
        propias = [c for c in admin.client_list() if c["user"] == USUARIO_API]
    finally:
        admin.close()
    assert propias == []


# ----------------------------------------------------- K60 y decisión 2: Redis no responde


async def _exigir_no_disponible(limitador: Limitador) -> float:
    inicio = time.monotonic()
    with pytest.raises(RedisNoDisponible) as error:
        await limitador.gastar_subida(uuid.uuid4())
    assert error.value.__cause__ is None and error.value.__context__ is None
    inicio_ip = time.monotonic()
    with pytest.raises(RedisNoDisponible):
        await limitador.contar_sin_autenticar(IP_A)
    return max(inicio_ip - inicio, time.monotonic() - inicio_ip)


@pytest.mark.anyio
async def test_decision_2_redis_colgado_no_retiene_mas_de_un_segundo(
    reloj: RelojFalso,
) -> None:
    with redis_colgado() as url:
        colgado = abrir_limitador(url, reloj)
        try:
            peor = await _exigir_no_disponible(colgado)
        finally:
            await colgado.cerrar()
    assert peor < TIMEOUT_REDIS_S + HOLGURA_TIMEOUT_S, f"retuvo {peor:.2f} s"


@pytest.mark.anyio
async def test_redis_que_rechaza_la_conexion_no_esta_disponible(
    reloj: RelojFalso,
) -> None:
    cerrado = abrir_limitador(puerto_cerrado(), reloj)
    try:
        peor = await _exigir_no_disponible(cerrado)
    finally:
        await cerrado.cerrar()
    assert peor < TIMEOUT_REDIS_S


@pytest.mark.anyio
async def test_una_contrasena_incorrecta_no_esta_disponible(
    redis_prueba: RedisDePrueba, reloj: RelojFalso
) -> None:
    url = f"redis://{USUARIO_API}:{secrets.token_hex(8)}@127.0.0.1:{redis_prueba.puerto}/0"
    ajeno = abrir_limitador(url, reloj)
    try:
        await _exigir_no_disponible(ajeno)
    finally:
        await ajeno.cerrar()


@pytest.mark.anyio
async def test_redis_lleno_con_noeviction_no_esta_disponible(
    limitador: Limitador, redis_prueba: RedisDePrueba
) -> None:
    """Con ``maxmemory`` y ``noeviction`` Redis rechaza las escrituras (OOM): 503, no pasa."""
    admin = redis_prueba.admin()
    try:
        admin.config_set("maxmemory-policy", "noeviction")
        admin.config_set("maxmemory", "1")
        await _exigir_no_disponible(limitador)
    finally:
        admin.config_set("maxmemory", "0")
        admin.close()


def test_una_url_de_redis_invalida_no_se_muestra() -> None:
    clave = secrets.token_hex(12)
    with pytest.raises(ConfiguracionError) as error:
        abrir_limitador(f"http://{USUARIO_API}:{clave}@127.0.0.1:1/0", time.time)
    assert clave not in str(error.value)
    assert error.value.__context__ is None and error.value.__cause__ is None


# ------------------------------------------------------------------------- HTTP completo


@pytest.fixture
def pepper() -> bytes:
    return secrets.token_hex(32).encode()


@pytest.fixture
def sembrada(bd_limpia: URL, pepper: bytes) -> KeySembrada:
    return sembrar_key(bd_limpia, pepper)


def _app(
    bd_limpia: URL, pepper: bytes, tmp_path: Path, url_redis: str, **costura: Any
) -> Any:
    return crear_app(
        Ajustes(
            url_bd=bd_limpia,
            pepper=pepper,
            datos=tmp_path / "datos",
            url_redis=url_redis,
            # El análisis termina en `error` enseguida: aquí no importa su resultado.
            comando_cdr=("/bin/true",),
            **costura,
        )
    )


@pytest.fixture
def cliente(
    bd_limpia: URL, pepper: bytes, tmp_path: Path, url_redis: str, reloj: RelojFalso
) -> Iterator[TestClient]:
    app = _app(bd_limpia, pepper, tmp_path, url_redis, reloj_limite=reloj)
    with TestClient(app, raise_server_exceptions=False, client=(IP_A, 50000)) as http:
        yield http


def _asgi(
    cliente: TestClient,
    metodo: str,
    ruta: str,
    cabeceras: dict[str, str],
    cuerpo: bytes = b"",
    origen: str = IP_A,
) -> tuple[int, dict[str, str], bytes, int]:
    """Petición ASGI directa: ``(estado, cabeceras, cuerpo, bytes leídos del cuerpo)``."""
    leidos = 0
    entregado = False
    estado = 0
    recibidas: dict[str, str] = {}
    respuesta = b""

    async def _recibir() -> dict[str, Any]:
        nonlocal leidos, entregado
        if entregado:
            await asyncio.sleep(3600)
        entregado = True
        leidos += len(cuerpo)
        return {"type": "http.request", "body": cuerpo, "more_body": False}

    async def _enviar(mensaje: dict[str, Any]) -> None:
        nonlocal estado, respuesta
        if mensaje["type"] == "http.response.start":
            estado = mensaje["status"]
            recibidas.update(
                {n.decode().lower(): v.decode() for n, v in mensaje["headers"]}
            )
        elif mensaje["type"] == "http.response.body":
            respuesta += mensaje.get("body", b"")

    alcance = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": metodo,
        "path": ruta,
        "raw_path": ruta.encode(),
        "query_string": b"",
        "root_path": "",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": (origen, 50001),
        "headers": [(n.lower().encode(), v.encode()) for n, v in cabeceras.items()],
    }
    assert cliente.portal is not None
    cliente.portal.call(cliente.app, alcance, _recibir, _enviar)
    return estado, recibidas, respuesta, leidos


def _subir(cliente: TestClient, key: str, origen: str = IP_A) -> tuple[int, dict]:
    estado, cabeceras, _, _ = _asgi(
        cliente,
        "POST",
        "/v1/files",
        {
            "authorization": f"Bearer {key}",
            "content-type": f"multipart/form-data; boundary={LIMITE_MULTIPART}",
        },
        _cuerpo(),
        origen,
    )
    return estado, cabeceras


def _exigir_429(estado: int, cabeceras: dict[str, str], cuerpo: bytes | None) -> None:
    assert estado == 429
    if cuerpo is not None:
        assert cuerpo == b'{"detail":"Too Many Requests"}'
    assert int(cabeceras["retry-after"]) >= 1
    assert cabeceras["connection"] == "close"


def test_decision_1_los_get_no_gastan_el_cupo_de_subidas(
    cliente: TestClient, sembrada: KeySembrada
) -> None:
    ids = []
    for _ in range(CAPACIDAD_SUBIDAS - 1):
        estado, _ = _subir(cliente, sembrada.key)
        assert estado == 202
    respuesta = cliente.post(
        "/v1/files",
        content=_cuerpo(),
        headers={
            "Authorization": f"Bearer {sembrada.key}",
            "Content-Type": f"multipart/form-data; boundary={LIMITE_MULTIPART}",
        },
    )
    assert respuesta.status_code == 202
    ids.append(respuesta.json()["id"])
    # Ya no queda ninguna ficha: si un GET gastara, el último POST no pasaría... ni el GET.
    bearer = {"Authorization": f"Bearer {sembrada.key}"}
    for _ in range(3 * CAPACIDAD_SUBIDAS):
        assert cliente.get(f"/v1/files/{ids[0]}", headers=bearer).status_code == 200
        contenido = cliente.get(f"/v1/files/{ids[0]}/content", headers=bearer)
        assert contenido.status_code == 409
        assert (
            cliente.get(f"/v1/files/{uuid.uuid4()}", headers=bearer).status_code == 404
        )
    estado, cabeceras = _subir(cliente, sembrada.key)
    _exigir_429(estado, cabeceras, None)


def test_decision_1_un_get_con_key_valida_no_toca_redis(
    cliente: TestClient, sembrada: KeySembrada, redis_prueba: RedisDePrueba
) -> None:
    bearer = {"Authorization": f"Bearer {sembrada.key}"}
    assert cliente.get(f"/v1/files/{uuid.uuid4()}", headers=bearer).status_code == 404
    admin = redis_prueba.admin()
    try:
        assert admin.dbsize() == 0
    finally:
        admin.close()


@pytest.mark.parametrize(
    "ruta",
    ["/v1/files", "/v1/files/{id}", "/v1/files/{id}/content", "/v1/no-existe"],
)
def test_decision_1_sin_key_cuenta_por_ip_en_cualquier_ruta_de_v1(
    cliente: TestClient, ruta: str
) -> None:
    ruta = ruta.format(id=uuid.uuid4())
    metodo = "POST" if ruta == "/v1/files" else "GET"
    for _ in range(LIMITE_IP):
        estado, _, _, _ = _asgi(cliente, metodo, ruta, {})
        assert estado in (401, 404)
    estado, cabeceras, cuerpo, leidos = _asgi(cliente, metodo, ruta, {}, b"x" * 100)
    if ruta == "/v1/no-existe":
        # Sin ruta no hay dependencia: 404 de siempre, sin tocar el cupo.
        assert estado == 404
        return
    _exigir_429(estado, cabeceras, cuerpo)
    assert leidos == 0


def test_el_401_no_lleva_cabeceras_del_rate_limit(cliente: TestClient) -> None:
    estado, cabeceras, _, _ = _asgi(cliente, "GET", f"/v1/files/{uuid.uuid4()}", {})
    assert estado == 401
    assert set(cabeceras) == {
        "content-length",
        "content-type",
        "www-authenticate",
        "connection",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "cache-control",
        "content-security-policy",
    }


@pytest.mark.parametrize(
    ("agotar_desde", "comparte", "no_comparte"),
    [
        ("2001:db8:a:b::1", "2001:db8:a:b:ffff::2", "2001:db8:a:c::1"),
        ("::ffff:198.51.100.7", "198.51.100.7", "198.51.100.8"),
    ],
    ids=["ipv6_por_64", "ipv4_mapeada"],
)
def test_decision_3_por_http(
    cliente: TestClient, agotar_desde: str, comparte: str, no_comparte: str
) -> None:
    for _ in range(LIMITE_IP):
        assert _asgi(cliente, "POST", "/v1/files", {}, origen=agotar_desde)[0] == 401
    estado, cabeceras, cuerpo, _ = _asgi(cliente, "POST", "/v1/files", {}, origen=comparte)
    _exigir_429(estado, cabeceras, cuerpo)
    assert _asgi(cliente, "POST", "/v1/files", {}, origen=no_comparte)[0] == 401


@pytest.fixture
def colgada(
    bd_limpia: URL, pepper: bytes, tmp_path: Path
) -> Iterator[TestClient]:
    with redis_colgado() as url:
        app = _app(bd_limpia, pepper, tmp_path, url)
        with TestClient(app, raise_server_exceptions=False) as http:
            yield http


def _exigir_503_a_tiempo(
    cliente: TestClient, cabeceras: dict[str, str], metodo: str = "POST"
) -> None:
    inicio = time.monotonic()
    estado, recibidas, cuerpo, leidos = _asgi(
        cliente, metodo, "/v1/files", cabeceras, _cuerpo()
    )
    transcurrido = time.monotonic() - inicio
    assert estado == 503
    assert cuerpo == b'{"detail":"Service Unavailable"}'
    assert recibidas["connection"] == "close"
    assert "retry-after" not in recibidas
    assert leidos == 0
    assert transcurrido < TIMEOUT_REDIS_S + HOLGURA_TIMEOUT_S, f"{transcurrido:.2f} s"


def test_decision_2_con_redis_colgado_la_subida_da_503_en_un_segundo(
    colgada: TestClient, sembrada: KeySembrada
) -> None:
    _exigir_503_a_tiempo(
        colgada,
        {
            "authorization": f"Bearer {sembrada.key}",
            "content-type": f"multipart/form-data; boundary={LIMITE_MULTIPART}",
        },
    )


def test_decision_2_con_redis_colgado_sin_key_da_503_en_un_segundo(
    colgada: TestClient,
) -> None:
    _exigir_503_a_tiempo(colgada, {})


def test_con_redis_colgado_health_y_las_consultas_siguen(
    colgada: TestClient, sembrada: KeySembrada
) -> None:
    """/health no depende de Redis (K60); un GET con key válida no tiene cupo que gastar."""
    inicio = time.monotonic()
    assert colgada.get("/health").status_code == 200
    respuesta = colgada.get(
        f"/v1/files/{uuid.uuid4()}",
        headers={"Authorization": f"Bearer {sembrada.key}"},
    )
    assert respuesta.status_code == 404
    assert time.monotonic() - inicio < TIMEOUT_REDIS_S


def test_sin_redis_al_arrancar_la_api_arranca_y_health_responde(
    bd_limpia: URL, pepper: bytes, tmp_path: Path
) -> None:
    app = _app(bd_limpia, pepper, tmp_path, puerto_cerrado())
    with TestClient(app, raise_server_exceptions=False) as http:
        assert http.get("/health").status_code == 200
        assert http.get("/v1/files/x").status_code == 503


def test_el_apagado_cierra_las_conexiones_a_redis(
    bd_limpia: URL,
    pepper: bytes,
    tmp_path: Path,
    url_redis: str,
    redis_prueba: RedisDePrueba,
) -> None:
    app = _app(bd_limpia, pepper, tmp_path, url_redis)
    with TestClient(app, raise_server_exceptions=False) as http:
        assert http.get("/v1/files/x").status_code == 401
    admin = redis_prueba.admin()
    try:
        assert [c for c in admin.client_list() if c["user"] == USUARIO_API] == []
    finally:
        admin.close()


def test_una_url_de_redis_invalida_no_deja_arrancar(
    bd_limpia: URL, pepper: bytes, tmp_path: Path
) -> None:
    clave = secrets.token_hex(12)
    app = _app(bd_limpia, pepper, tmp_path, f"esto no es {clave}")
    with pytest.raises(ConfiguracionError) as error, TestClient(app):
        pass  # pragma: no cover
    assert clave not in str(error.value)
