"""M1 y M2 medidos con la API real, PostgreSQL real y el proceso hijo real.

M1 va por ASGI directo para poder fijar el instante en que termina la recepción: TestClient
no deja ver ese momento. M2 sale de ``creado_en`` y ``analizado_en``, como lo define
``docs/decisiones.md`` §7. Los archivos son los peores de cada tipo: lo que cuesta en una imagen
son sus píxeles, no sus bytes, y por eso van de 40 MP. Con ``pytest -s`` se imprimen los números.
"""

import io
import random
import secrets
import statistics
import time
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import anyio
import pikepdf
import pytest
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

from api.app.ajustes import Ajustes
from api.app.principal import crear_app
from api.app.recepcion import TOPE_ARCHIVO
from api.app.v1 import TOPE_PENDIENTES
from api.tests.soporte_api import sembrar_key

MUESTRAS_M1 = 200
MUESTRAS_M2 = 20
TOPE_M1_MS = 1000.0
MUESTRAS_PEOR_CASO = 6
TOPE_M2_MS = 2000.0
TROZO = 64 * 1024
TOPE_ESPERA_S = 40.0
LIMITE = "limitegk"
SIMULTANEAS = 8


def _p95(muestras: list[float]) -> float:
    return statistics.quantiles(muestras, n=100)[94]


def _multipart(contenido: bytes) -> bytes:
    limite = LIMITE.encode()
    return (
        b'--%s\r\nContent-Disposition: form-data; name="file"; filename="a"\r\n\r\n'
        b"%s\r\n--%s--\r\n" % (limite, contenido, limite)
    )


def _ruido(ancho: int, alto: int, sigma: float = 60) -> Image.Image:
    return Image.effect_noise((ancho, alto), sigma)


def _png(imagen: Image.Image, nivel: int) -> bytes:
    salida = io.BytesIO()
    imagen.save(salida, "PNG", compress_level=nivel)
    return salida.getvalue()


def _png_de_ruido() -> bytes:
    """Ruido: PNG casi sin compresión, justo por debajo del tope."""
    canales = [_ruido(1780, 1780) for _ in range(3)]
    contenido = _png(Image.merge("RGB", canales), 1)
    assert 0.8 * TOPE_ARCHIVO < len(contenido) <= TOPE_ARCHIVO
    return contenido


def _png_de_40_mp() -> bytes:
    """El peor caso de M2: 40 MP en gris suave, que comprimidos caben en 10 MB."""
    contenido = _png(_ruido(300, 190, 45).resize((8000, 5000), Image.BICUBIC), 9)
    assert len(contenido) <= TOPE_ARCHIVO
    return contenido


def _jpeg_de_40_mp() -> bytes:
    """Foto suave con grano, en el límite de píxeles y con la mayor calidad que cabe."""
    canales = [_ruido(300, 190, 45).resize((8000, 5000)) for _ in range(3)]
    grano = _ruido(8000, 5000, 30)
    foto = Image.blend(
        Image.merge("RGB", canales), Image.merge("RGB", [grano] * 3), 0.1
    )
    for calidad in range(98, 40, -3):
        salida = io.BytesIO()
        foto.save(salida, "JPEG", quality=calidad)
        if len(salida.getvalue()) <= TOPE_ARCHIVO:
            return salida.getvalue()
    raise AssertionError("no cupo en el tope")


def _pdf_de_200_paginas() -> bytes:
    """200 páginas con su contenido: el límite de páginas y casi el de tamaño."""
    generador = random.Random(13)
    pdf = pikepdf.new()
    por_pagina = TOPE_ARCHIVO // 220
    for _ in range(200):
        pagina = pdf.add_blank_page(page_size=(200, 200))
        pagina.Contents = pdf.make_stream(generador.randbytes(por_pagina))
    salida = io.BytesIO()
    pdf.save(salida)
    assert 0.8 * TOPE_ARCHIVO < len(salida.getvalue()) <= TOPE_ARCHIVO
    return salida.getvalue()


@pytest.fixture
def api(bd_limpia: URL, tmp_path: Path) -> Any:
    pepper = secrets.token_hex(32).encode()
    sembrada = sembrar_key(bd_limpia, pepper)
    app = crear_app(Ajustes(url_bd=bd_limpia, pepper=pepper, datos=tmp_path / "datos"))
    with TestClient(app, raise_server_exceptions=False) as cliente:
        cliente.headers["Authorization"] = f"Bearer {sembrada.key}"
        yield cliente, app, sembrada.key


def _medir_m1(cliente: TestClient, app: Any, key: str, cuerpo: bytes) -> float:
    """Milisegundos desde que se entrega el último byte hasta el inicio de la respuesta."""
    assert cliente.portal is not None
    return cliente.portal.call(_m1_asgi, app, key, cuerpo)


async def _m1_asgi(app: Any, key: str, cuerpo: bytes) -> float:
    trozos = [cuerpo[i : i + TROZO] for i in range(0, len(cuerpo), TROZO)]
    pendientes = iter(trozos)
    fin_recepcion = respuesta = 0.0
    estado = 0
    alcance = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "path": "/v1/files",
        "raw_path": b"/v1/files",
        "query_string": b"",
        "root_path": "",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("testclient", 1),
        "headers": [
            (b"authorization", f"Bearer {key}".encode()),
            (b"content-type", f"multipart/form-data; boundary={LIMITE}".encode()),
        ],
    }

    async def recibir() -> dict[str, Any]:
        nonlocal fin_recepcion
        trozo = next(pendientes, None)
        if trozo is None:
            fin_recepcion = time.perf_counter()
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.request", "body": trozo, "more_body": True}

    async def enviar(mensaje: dict[str, Any]) -> None:
        nonlocal respuesta, estado
        if mensaje["type"] == "http.response.start":
            respuesta = time.perf_counter()
            estado = mensaje["status"]

    await app(alcance, recibir, enviar)
    assert estado == 202
    return (respuesta - fin_recepcion) * 1000


@pytest.mark.parametrize(
    "tamano", [1024, TOPE_ARCHIVO], ids=["1_kib", "10_mib_en_el_tope"]
)
def test_m1_202_desde_el_fin_de_la_recepcion(
    api: Any, tamano: int, bd_limpia: URL
) -> None:
    cliente, app, key = api
    cuerpo = _multipart(b"\x89PNG\r\n\x1a\n" + bytes(tamano - 8))
    # Sin esperar al análisis: el 202 no puede depender de lo que haya en cola. Sí a que haya
    # cupo (K48): en una máquina lenta, 200 subidas seguidas llegarían al 429.
    muestras = []
    for _ in range(MUESTRAS_M1):
        _esperar_cupo(bd_limpia, 1)
        muestras.append(_medir_m1(cliente, app, key, cuerpo))
    p95 = _p95(muestras)
    print(
        f"\nM1 {tamano} B ({MUESTRAS_M1}): p95 = {p95:.2f} ms, máx = {max(muestras):.2f} ms"
    )
    assert p95 < TOPE_M1_MS


def _pendientes(url: URL) -> int:
    motor = create_engine(url)
    try:
        with motor.connect() as con:
            return con.execute(
                text("SELECT count(*) FROM archivo WHERE estado = 'pendiente'")
            ).scalar_one()
    finally:
        motor.dispose()


def _esperar_cupo(url: URL, subidas: int) -> None:
    """Hasta que quepan ``subidas`` más sin pasar de K48. Aquí se mide el 202, no el 429."""
    limite = time.monotonic() + TOPE_ESPERA_S
    while _pendientes(url) > TOPE_PENDIENTES - subidas:
        assert time.monotonic() < limite, "el análisis no libera cupo"
        time.sleep(0.02)


def test_m1_con_subidas_simultaneas_de_una_aplicacion(api: Any, bd_limpia: URL) -> None:
    """K48: el alta con cupo pone en fila las altas de una misma aplicación.

    Rondas de ``SIMULTANEAS`` subidas a la vez. Entre ronda y ronda se espera a que haya
    cupo: aquí se mide la fila del alta, no el 429.
    """
    cliente, app, key = api
    cuerpo = _multipart(b"\x89PNG\r\n\x1a\n" + bytes(1024 - 8))

    async def _ronda() -> list[float]:
        muestras: list[float] = []

        async def _una() -> None:
            muestras.append(await _m1_asgi(app, key, cuerpo))

        async with anyio.create_task_group() as grupo:
            for _ in range(SIMULTANEAS):
                grupo.start_soon(_una)
        return muestras

    muestras: list[float] = []
    assert cliente.portal is not None
    while len(muestras) < MUESTRAS_M1:
        _esperar_cupo(bd_limpia, SIMULTANEAS)
        muestras += cliente.portal.call(_ronda)
    p95 = _p95(muestras)
    print(
        f"\nM1 {SIMULTANEAS} simultáneas ({len(muestras)}): p95 = {p95:.2f} ms, "
        f"máx = {max(muestras):.2f} ms"
    )
    assert p95 < TOPE_M1_MS


def _esperar_m2(cliente: TestClient, archivo_id: str) -> dict[str, Any]:
    limite = time.monotonic() + TOPE_ESPERA_S
    while True:
        cuerpo = cliente.get(f"/v1/files/{archivo_id}").json()
        if cuerpo["estado"] != "pendiente":
            return cuerpo
        assert time.monotonic() < limite
        time.sleep(0.005)


def _medir_m2(
    cliente: TestClient, contenido: bytes, tipo: str, muestras: int
) -> tuple[list[float], str]:
    cuerpo = _multipart(contenido)
    cabeceras = {"Content-Type": f"multipart/form-data; boundary={LIMITE}"}
    tiempos = []
    archivo_id = ""
    for _ in range(muestras):
        respuesta = cliente.post("/v1/files", content=cuerpo, headers=cabeceras)
        assert respuesta.status_code == 202
        archivo_id = respuesta.json()["id"]
        final = _esperar_m2(cliente, archivo_id)
        assert final["estado"] == "limpio"
        assert final["tipo_detectado"] == tipo
        creado = datetime.fromisoformat(final["creado_en"])
        analizado = datetime.fromisoformat(final["analizado_en"])
        tiempos.append((analizado - creado).total_seconds() * 1000)
    return tiempos, archivo_id


def _duracion_hijo(url: URL, archivo_id: str) -> int:
    motor = create_engine(url)
    try:
        with motor.connect() as con:
            return con.execute(
                text(
                    "SELECT duracion_ms FROM resultado_analisis WHERE capa = 'cdr'"
                    " AND archivo_id = :id"
                ),
                {"id": uuid.UUID(archivo_id)},
            ).scalar_one()
    finally:
        motor.dispose()


def _informar(nombre: str, contenido: bytes, tiempos: list[float], hijo: int) -> float:
    p95 = _p95(tiempos)
    print(
        f"\nM2 {nombre} {len(contenido)} B ({len(tiempos)}): "
        f"p50 = {statistics.median(tiempos):.0f} ms, p95 = {p95:.0f} ms, "
        f"máx = {max(tiempos):.0f} ms; proceso hijo = {hijo} ms"
    )
    return p95


@pytest.mark.parametrize(
    ("generar", "tipo"),
    [
        (_jpeg_de_40_mp, "image/jpeg"),
        (_png_de_ruido, "image/png"),
        (_pdf_de_200_paginas, "application/pdf"),
    ],
    ids=["jpeg_40_mp", "png_ruido", "pdf_200_paginas"],
)
def test_m2_veredicto_de_un_archivo_de_10_mb(
    api: Any, generar: Callable[[], bytes], tipo: str, bd_limpia: URL
) -> None:
    cliente, _, _ = api
    contenido = generar()
    tiempos, archivo_id = _medir_m2(cliente, contenido, tipo, MUESTRAS_M2)
    hijo = _duracion_hijo(bd_limpia, archivo_id)
    assert _informar(tipo, contenido, tiempos, hijo) <= TOPE_M2_MS


def test_m2_peor_caso_png_de_40_mp(api: Any, bd_limpia: URL) -> None:
    """El peor caso de M2: lo que cuesta es codificar, y K37 lo baja con el nivel 3."""
    cliente, _, _ = api
    contenido = _png_de_40_mp()
    tiempos, archivo_id = _medir_m2(cliente, contenido, "image/png", MUESTRAS_PEOR_CASO)
    hijo = _duracion_hijo(bd_limpia, archivo_id)
    assert _informar("PNG 40 MP", contenido, tiempos, hijo) <= TOPE_M2_MS
