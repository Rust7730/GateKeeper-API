"""Endpoints de archivos contra PostgreSQL real: lo que la matriz de ataque no fija.

La matriz cubre los vectores por HTTP. Aquí van los códigos del contrato (§4) que no son un
ataque y los caminos de fallo del padre que hay que provocar por dentro.
"""

import json
import secrets
import sys
import time
import uuid
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import anyio
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

from api.app import analisis, v1
from api.app.ajustes import Ajustes
from api.app.principal import crear_app
from api.db.repositorios import DatoRechazado, ViolacionDeRestriccion, crear_archivo
from api.db.sesion import crear_motor, fabrica_sesiones
from api.tests.soporte_api import KeySembrada, sembrar_key

PNG_MINIMO = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x00\x00"
    b"\x00\x00:~\x9bU\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q\x00\x00"
    b"\x00\x00IEND\xaeB`\x82"
)
LIMPIO = {"veredicto": "limpio", "tipo": "image/png", "motivo": "ok"}
COPIAR = "import shutil, sys\nshutil.copyfile(sys.argv[1], sys.argv[2])\n"
TOPE_S = 10.0


def _cuerpo(contenido: bytes = PNG_MINIMO) -> tuple[bytes, str]:
    limite = secrets.token_hex(8).encode()
    cuerpo = (
        b'--%s\r\nContent-Disposition: form-data; name="file"; filename="a.png"\r\n\r\n'
        b"%s\r\n--%s--\r\n" % (limite, contenido, limite)
    )
    return cuerpo, f"multipart/form-data; boundary={limite.decode()}"


@dataclass
class Banco:
    url: URL
    pepper: bytes
    datos: Path
    app_a: KeySembrada

    def fila(self, archivo_id: str) -> dict[str, Any]:
        motor = create_engine(self.url)
        try:
            with motor.connect() as con:
                return dict(
                    con.execute(
                        text("SELECT estado, tipo_error FROM archivo WHERE id = :id"),
                        {"id": uuid.UUID(archivo_id)},
                    )
                    .mappings()
                    .one()
                )
        finally:
            motor.dispose()

    def resultados(self, archivo_id: str) -> set[tuple[str, str]]:
        motor = create_engine(self.url)
        try:
            with motor.connect() as con:
                filas = con.execute(
                    text(
                        "SELECT capa, veredicto FROM resultado_analisis"
                        " WHERE archivo_id = :id"
                    ),
                    {"id": uuid.UUID(archivo_id)},
                ).all()
        finally:
            motor.dispose()
        return {(fila.capa, fila.veredicto) for fila in filas}

    def contar(self) -> int:
        motor = create_engine(self.url)
        try:
            with motor.connect() as con:
                return con.execute(text("SELECT count(*) FROM archivo")).scalar_one()
        finally:
            motor.dispose()

    @contextmanager
    def api(self, **costura: Any) -> Iterator[TestClient]:
        ajustes = Ajustes(
            url_bd=self.url, pepper=self.pepper, datos=self.datos, **costura
        )
        with TestClient(crear_app(ajustes), raise_server_exceptions=False) as cliente:
            cliente.headers["Authorization"] = f"Bearer {self.app_a.key}"
            yield cliente

    @property
    def uploads(self) -> Path:
        return self.datos / "uploads_tmp"

    @property
    def clean(self) -> Path:
        return self.datos / "clean_store"


@pytest.fixture
def banco(bd_limpia: URL, tmp_path: Path) -> Banco:
    pepper = secrets.token_hex(32).encode()
    return Banco(bd_limpia, pepper, tmp_path / "datos", sembrar_key(bd_limpia, pepper))


def _comando(tmp_path: Path, cuerpo: str) -> tuple[str, ...]:
    ruta = tmp_path / "hijo.py"
    ruta.write_text(cuerpo)
    return (sys.executable, "-I", str(ruta))


def _subir(cliente: TestClient, contenido: bytes = PNG_MINIMO) -> str:
    cuerpo, tipo = _cuerpo(contenido)
    respuesta = cliente.post(
        "/v1/files", content=cuerpo, headers={"Content-Type": tipo}
    )
    assert respuesta.status_code == 202
    return respuesta.json()["id"]


def _esperar(cliente: TestClient, archivo_id: str) -> dict[str, Any]:
    limite = time.monotonic() + TOPE_S
    while True:
        cuerpo = cliente.get(f"/v1/files/{archivo_id}").json()
        if cuerpo["estado"] != "pendiente":
            return cuerpo
        assert time.monotonic() < limite, "sigue en pendiente"
        time.sleep(0.01)


def _hijo_limpio(tmp_path: Path) -> tuple[str, ...]:
    return _comando(tmp_path, f"{COPIAR}print({json.dumps(json.dumps(LIMPIO))})\n")


# --------------------------------------------------------------------- códigos del POST


@pytest.mark.parametrize(
    ("tipo", "codigo"),
    [
        ("application/json", 415),
        ("text/plain", 415),
        ("multipart/form-data", 400),
    ],
    ids=["json", "texto", "sin_limite"],
)
def test_post_con_content_type_invalido(banco: Banco, tipo: str, codigo: int) -> None:
    with banco.api() as cliente:
        respuesta = cliente.post(
            "/v1/files", content=b"{}", headers={"Content-Type": tipo}
        )
    assert respuesta.status_code == codigo
    assert set(respuesta.json()) == {"detail"}
    assert respuesta.headers["connection"] == "close"
    assert banco.contar() == 0


def test_post_sin_cuerpo_ni_content_type_es_415(banco: Banco) -> None:
    with banco.api() as cliente:
        assert cliente.post("/v1/files").status_code == 415


def test_post_con_archivo_vacio_es_400(banco: Banco) -> None:
    cuerpo, tipo = _cuerpo(b"")
    with banco.api() as cliente:
        respuesta = cliente.post(
            "/v1/files", content=cuerpo, headers={"Content-Type": tipo}
        )
    assert respuesta.status_code == 400
    assert respuesta.json() == {"detail": "Bad Request"}
    assert list(banco.uploads.iterdir()) == []
    assert banco.contar() == 0


@pytest.mark.parametrize(
    "error",
    [RuntimeError("fallo interno"), DatoRechazado(), ViolacionDeRestriccion("x")],
    ids=["inesperado", "dato", "restriccion"],
)
def test_si_el_insert_falla_no_queda_temporal_ni_analisis(
    banco: Banco, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: Exception
) -> None:
    async def _falla(*_: object, **__: object) -> None:
        raise error

    monkeypatch.setattr(v1, "crear_archivo_con_cupo", _falla)
    cuerpo, tipo = _cuerpo()
    with banco.api() as cliente:
        respuesta = cliente.post(
            "/v1/files", content=cuerpo, headers={"Content-Type": tipo}
        )
        assert cliente.app.state.tareas == set()
    assert respuesta.status_code == 500
    assert respuesta.json() == {"detail": "Internal Server Error"}
    assert list(banco.uploads.iterdir()) == []


# ------------------------------------------------------------------- K40: tope de recepción


def _post_asgi(
    cliente: TestClient, recibir: Callable[[], Awaitable[dict[str, Any]]]
) -> tuple[int, bytes, dict[bytes, bytes], float]:
    """`POST /v1/files` por ASGI: TestClient entrega el cuerpo entero de una vez."""
    estado = 0
    cuerpo = b""
    cabeceras: dict[bytes, bytes] = {}
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
            (b"authorization", cliente.headers["Authorization"].encode()),
            (b"content-type", b"multipart/form-data; boundary=limite"),
        ],
    }

    async def enviar(mensaje: dict[str, Any]) -> None:
        nonlocal estado, cuerpo, cabeceras
        if mensaje["type"] == "http.response.start":
            estado = mensaje["status"]
            cabeceras = dict(mensaje["headers"])
        elif mensaje["type"] == "http.response.body":
            cuerpo += mensaje.get("body", b"")

    assert cliente.portal is not None
    inicio = time.monotonic()
    cliente.portal.call(cliente.app, alcance, recibir, enviar)
    return estado, cuerpo, cabeceras, time.monotonic() - inicio


_CABECERA_PARTE = (
    b'--limite\r\nContent-Disposition: form-data; name="file"; filename="g"\r\n\r\n'
)


def _exigir_408_sin_rastro(banco: Banco, respuesta: tuple[Any, ...]) -> None:
    estado, cuerpo, cabeceras, _ = respuesta
    assert estado == 408
    assert json.loads(cuerpo) == {"detail": "Request Timeout"}
    assert cabeceras[b"connection"] == b"close"
    assert list(banco.uploads.iterdir()) == []
    assert banco.contar() == 0


def test_k40_un_goteo_no_renueva_el_tope(banco: Banco) -> None:
    """Cada trozo llega mucho antes del tope: un timeout por trozo no lo cortaría nunca."""
    temporales_durante: list[int] = []
    entregados = 0

    async def recibir() -> dict[str, Any]:
        nonlocal entregados
        entregados += 1
        if entregados == 1:
            return {"type": "http.request", "body": _CABECERA_PARTE, "more_body": True}
        await anyio.sleep(0.02)
        temporales_durante.append(len(list(banco.uploads.iterdir())))
        return {"type": "http.request", "body": b"x", "more_body": True}

    with banco.api(timeout_recepcion_s=0.3) as cliente:
        respuesta = _post_asgi(cliente, recibir)

    _exigir_408_sin_rastro(banco, respuesta)
    assert entregados > 5, "control: el goteo debe llegar a avanzar"
    assert max(temporales_durante) == 1, "control: el temporal llegó a existir"
    assert respuesta[3] < 3


def test_k40_un_cliente_que_calla_se_corta(banco: Banco) -> None:
    entregados = 0

    async def recibir() -> dict[str, Any]:
        nonlocal entregados
        entregados += 1
        if entregados == 1:
            return {"type": "http.request", "body": _CABECERA_PARTE, "more_body": True}
        await anyio.sleep_forever()
        raise AssertionError("inalcanzable")

    with banco.api(timeout_recepcion_s=0.2) as cliente:
        respuesta = _post_asgi(cliente, recibir)

    _exigir_408_sin_rastro(banco, respuesta)


def test_k40_tambien_corta_si_recibir_nunca_suspende(banco: Banco) -> None:
    """Un timeout de asyncio solo salta al suspender: hace falta mirar el reloj."""
    entregados = 0

    async def recibir() -> dict[str, Any]:
        nonlocal entregados
        entregados += 1
        if entregados == 1:
            return {"type": "http.request", "body": _CABECERA_PARTE, "more_body": True}
        time.sleep(0.02)  # noqa: ASYNC251
        return {"type": "http.request", "body": b"x", "more_body": True}

    with banco.api(timeout_recepcion_s=0.2) as cliente:
        respuesta = _post_asgi(cliente, recibir)

    _exigir_408_sin_rastro(banco, respuesta)


def test_k40_una_subida_a_tiempo_no_se_ve_afectada(
    banco: Banco, tmp_path: Path
) -> None:
    trozos = iter(
        [_CABECERA_PARTE, PNG_MINIMO[:20], PNG_MINIMO[20:], b"\r\n--limite--\r\n"]
    )

    async def recibir() -> dict[str, Any]:
        await anyio.sleep(0.01)
        trozo = next(trozos, None)
        if trozo is None:
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.request", "body": trozo, "more_body": True}

    with banco.api(
        comando_cdr=_hijo_limpio(tmp_path), timeout_recepcion_s=5
    ) as cliente:
        estado, _, _, _ = _post_asgi(cliente, recibir)
    assert estado == 202


# -------------------------------------------------------------------------- GET y content


def test_estado_tiene_exactamente_los_campos_del_contrato(
    banco: Banco, tmp_path: Path
) -> None:
    with banco.api(comando_cdr=_hijo_limpio(tmp_path)) as cliente:
        archivo_id = _subir(cliente)
        final = _esperar(cliente, archivo_id)
    assert set(final) == {
        "id",
        "estado",
        "tipo_detectado",
        "tamano_bytes",
        "sha256",
        "creado_en",
        "analizado_en",
    }
    assert datetime.fromisoformat(final["creado_en"]).utcoffset() is not None


@pytest.mark.parametrize(
    "archivo_id",
    [
        "{12345678-1234-5678-1234-567812345678}",
        "urn:uuid:12345678-1234-5678-1234-567812345678",
        "12345678123456781234567812345678",
        "12345678-1234-5678-1234-56781234567A",
    ],
    ids=["llaves", "urn", "sin_guiones", "mayuscula"],
)
def test_solo_la_forma_canonica_del_uuid_es_un_id(
    banco: Banco, archivo_id: str
) -> None:
    with banco.api() as cliente:
        for ruta in (f"/v1/files/{archivo_id}", f"/v1/files/{archivo_id}/content"):
            respuesta = cliente.get(ruta)
            assert respuesta.status_code == 404
            assert respuesta.json() == {"detail": "Not Found"}


def test_limpio_con_un_enlace_en_el_almacen_no_lo_sigue(
    banco: Banco, tmp_path: Path
) -> None:
    secreto = tmp_path / "secreto"
    secreto.write_bytes(b"secreto")
    with banco.api(comando_cdr=_hijo_limpio(tmp_path)) as cliente:
        archivo_id = _subir(cliente)
        assert _esperar(cliente, archivo_id)["estado"] == "limpio"
        (banco.clean / archivo_id).unlink()
        (banco.clean / archivo_id).symlink_to(secreto)

        respuesta = cliente.get(f"/v1/files/{archivo_id}/content")

    assert respuesta.status_code == 500
    assert respuesta.json() == {"detail": "Internal Server Error"}
    assert b"secreto" not in respuesta.content


# ------------------------------------------------------------------- decisión en el padre


def test_rechazo_por_tipo_deja_firma_rechazada_y_cdr_sin_evaluar(
    banco: Banco, tmp_path: Path
) -> None:
    respuesta = {"veredicto": "rechazado", "tipo": "text/x-php", "motivo": "tipo"}
    comando = _comando(tmp_path, f"print({json.dumps(json.dumps(respuesta))})\n")
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id = _subir(cliente)
        final = _esperar(cliente, archivo_id)
    assert final["tipo_detectado"] == "text/x-php"
    assert banco.resultados(archivo_id) == {
        ("firma", "rechazado"),
        ("cdr", "no_evaluada"),
    }


def test_rechazo_del_cdr_deja_firma_limpia(banco: Banco, tmp_path: Path) -> None:
    respuesta = {"veredicto": "rechazado", "tipo": "image/png", "motivo": "x"}
    comando = _comando(tmp_path, f"print({json.dumps(json.dumps(respuesta))})\n")
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id = _subir(cliente)
        _esperar(cliente, archivo_id)
    assert banco.resultados(archivo_id) == {
        ("firma", "limpio"),
        ("cdr", "rechazado"),
    }


def test_lo_que_la_bd_no_admite_revierte_y_termina_en_error(
    banco: Banco, tmp_path: Path
) -> None:
    """La primera transacción no deja nada: `firma` no sobrevive sin su veredicto."""
    respuesta = {"veredicto": "rechazado", "tipo": "image/png", "motivo": "\u0000"}
    comando = _comando(tmp_path, f"print({json.dumps(json.dumps(respuesta))})\n")
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id = _subir(cliente)
        assert _esperar(cliente, archivo_id)["estado"] == "error"
    assert banco.fila(archivo_id)["tipo_error"] == "final"
    assert banco.resultados(archivo_id) == {("cdr", "error")}


def test_sin_evidencia_del_cdr_es_error_y_no_queda_salida(
    banco: Banco, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """INV-09: un fallo interno del padre nunca da `limpio`, aunque el hijo lo dijera."""
    original = analisis.registrar_resultado

    async def _sin_cdr(sesion: Any, app: Any, archivo: Any, capa: str, *resto: Any):
        if capa == "cdr" and resto[0] == "limpio":
            return 0
        return await original(sesion, app, archivo, capa, *resto)

    monkeypatch.setattr(analisis, "registrar_resultado", _sin_cdr)
    with banco.api(comando_cdr=_hijo_limpio(tmp_path)) as cliente:
        archivo_id = _subir(cliente)
        assert _esperar(cliente, archivo_id)["estado"] == "error"
        assert cliente.get(f"/v1/files/{archivo_id}/content").status_code == 409
    assert banco.fila(archivo_id)["tipo_error"] == "final"
    assert ("cdr", "limpio") not in banco.resultados(archivo_id)
    assert list(banco.clean.iterdir()) == []
    assert list(banco.uploads.iterdir()) == []


def test_un_error_inesperado_al_decidir_termina_en_error(
    banco: Banco, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = analisis.cambiar_estado

    async def _falla_la_primera(*argumentos: Any, **opciones: Any) -> Any:
        if opciones.get("tipo_error") is None:
            raise RuntimeError("fallo interno")
        return await original(*argumentos, **opciones)

    monkeypatch.setattr(analisis, "cambiar_estado", _falla_la_primera)
    with banco.api(comando_cdr=_hijo_limpio(tmp_path)) as cliente:
        archivo_id = _subir(cliente)
        assert _esperar(cliente, archivo_id)["estado"] == "error"
    assert list(banco.clean.iterdir()) == []


def test_salida_que_es_un_enlace_termina_en_error(banco: Banco, tmp_path: Path) -> None:
    objetivo = tmp_path / "objetivo"
    objetivo.write_bytes(PNG_MINIMO)
    cuerpo = (
        f"import os, sys\nos.symlink({str(objetivo)!r}, sys.argv[2])\n"
        f"print({json.dumps(json.dumps(LIMPIO))})\n"
    )
    with banco.api(comando_cdr=_comando(tmp_path, cuerpo)) as cliente:
        archivo_id = _subir(cliente)
        assert _esperar(cliente, archivo_id)["estado"] == "error"
    assert list(banco.clean.iterdir()) == []


def test_el_motivo_del_error_no_trae_nada_del_hijo(
    banco: Banco, tmp_path: Path
) -> None:
    marca = secrets.token_hex(8)
    comando = _comando(tmp_path, f"print({marca!r})\n")
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id = _subir(cliente)
        _esperar(cliente, archivo_id)
    motor = create_engine(banco.url)
    try:
        with motor.connect() as con:
            detalle = con.execute(
                text("SELECT detalle FROM resultado_analisis WHERE archivo_id = :id"),
                {"id": uuid.UUID(archivo_id)},
            ).scalar_one()
    finally:
        motor.dispose()
    assert detalle == {"motivo": "salida_invalida"}


def test_el_log_del_fallo_no_trae_la_excepcion(
    banco: Banco,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    marca = secrets.token_hex(8)

    async def _falla(*_: object, **__: object) -> None:
        raise RuntimeError(marca)

    monkeypatch.setattr(analisis, "registrar_resultado", _falla)
    with (
        caplog.at_level("WARNING", logger="gatekeeper.api"),
        banco.api(comando_cdr=_hijo_limpio(tmp_path)) as cliente,
    ):
        archivo_id = _subir(cliente)
        limite = time.monotonic() + TOPE_S
        while list(banco.uploads.iterdir()) and time.monotonic() < limite:
            time.sleep(0.01)
    assert archivo_id in caplog.text
    assert marca not in caplog.text


def test_apagar_a_mitad_mata_al_hijo_y_borra_los_temporales(
    banco: Banco, tmp_path: Path
) -> None:
    """Diseño §5: queda en `pendiente` (falla cerrado), sin proceso ni archivos sueltos."""
    pid = tmp_path / "pid"
    comando = _comando(
        tmp_path,
        "import os, time\n"
        f"open({str(pid)!r}, 'w').write(str(os.getpid()))\n"
        "time.sleep(30)\n",
    )
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id = _subir(cliente)
        limite = time.monotonic() + TOPE_S
        while not (pid.exists() and pid.read_text()):
            assert time.monotonic() < limite
            time.sleep(0.01)
    assert not Path(f"/proc/{pid.read_text()}").exists()
    assert banco.fila(archivo_id)["estado"] == "pendiente"
    assert list(banco.uploads.iterdir()) == []
    assert list(banco.clean.iterdir()) == []


def test_la_tarea_se_guarda_y_se_retira_al_terminar(
    banco: Banco, tmp_path: Path
) -> None:
    with banco.api(comando_cdr=_hijo_limpio(tmp_path)) as cliente:
        archivo_id = _subir(cliente)
        _esperar(cliente, archivo_id)
        limite = time.monotonic() + TOPE_S
        while cliente.app.state.tareas and time.monotonic() < limite:
            time.sleep(0.01)
        assert cliente.app.state.tareas == set()


# ------------------------------------------------------------- K46 al publicar


def test_k46_salida_sobre_el_tope_es_rechazado_sin_rastro(
    banco: Banco, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(analisis, "TOPE_SALIDA", 100)
    comando = _comando(
        tmp_path,
        "import sys\n"
        "open(sys.argv[2], 'xb').write(b'x' * 101)\n"
        f"print({json.dumps(json.dumps(LIMPIO))})\n",
    )
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id = _subir(cliente)
        assert _esperar(cliente, archivo_id)["estado"] == "rechazado"
        assert cliente.get(f"/v1/files/{archivo_id}/content").status_code == 409
    assert list(banco.clean.iterdir()) == []
    assert ("cdr", "limpio") not in banco.resultados(archivo_id)
    assert ("cdr", "rechazado") in banco.resultados(archivo_id)


# ----------------------------------------- cancelación entre publicar y confirmar


def test_cancelar_entre_publicar_y_confirmar_no_deja_la_salida(
    banco: Banco, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sin el `limpio` confirmado, `clean_store/<uuid>` no puede quedarse."""
    publicado = anyio.Event()

    async def _colgado(*_: object) -> None:
        publicado.set()
        await anyio.sleep(30)

    monkeypatch.setattr(analisis, "_registrar_veredicto", _colgado)
    with banco.api(comando_cdr=_hijo_limpio(tmp_path)) as cliente:
        archivo_id = _subir(cliente)
        limite = time.monotonic() + TOPE_S
        while not (banco.clean / archivo_id).exists():
            assert time.monotonic() < limite, "no llegó a publicarse"
            time.sleep(0.01)
    assert banco.fila(archivo_id)["estado"] == "pendiente"
    assert list(banco.clean.iterdir()) == []


# ------------------------------------------------------------------ K48: 429


def _sembrar_pendientes(banco: Banco, cantidad: int) -> None:
    async def _sembrar() -> None:
        motor = crear_motor(banco.url)
        try:
            async with fabrica_sesiones(motor).begin() as sesion:
                for _ in range(cantidad):
                    await crear_archivo(
                        sesion,
                        banco.app_a.aplicacion_id,
                        uuid.uuid4(),
                        "sembrado",
                        1,
                        "0" * 64,
                    )
        finally:
            await motor.dispose()

    anyio.run(_sembrar)


def _exigir_429(respuesta: Any) -> None:
    assert respuesta.status_code == 429
    assert respuesta.json() == {"detail": "Too Many Requests"}
    assert respuesta.headers["connection"] == "close"


def test_k48_el_tope_es_el_de_la_decision() -> None:
    assert v1.TOPE_PENDIENTES == 20


def test_k48_con_el_cupo_lleno_429_sin_leer_ni_guardar(banco: Banco) -> None:
    # Se siembra con la API ya arrancada: el barrido del arranque cerraría los pendientes.
    with banco.api() as cliente:
        _sembrar_pendientes(banco, 20)
        cuerpo, tipo = _cuerpo()
        _exigir_429(
            cliente.post("/v1/files", content=cuerpo, headers={"Content-Type": tipo})
        )
    assert list(banco.uploads.iterdir()) == []
    assert banco.contar() == 20


def test_k48_con_19_pendientes_entra_una_mas(banco: Banco, tmp_path: Path) -> None:
    with banco.api(comando_cdr=_hijo_limpio(tmp_path)) as cliente:
        _sembrar_pendientes(banco, 19)
        _subir(cliente)


def test_k48_el_alta_con_cupo_decide_aunque_la_lectura_previa_diga_que_cabe(
    banco: Banco, monkeypatch: pytest.MonkeyPatch
) -> None:
    """La lectura previa es un atajo: entre ella y el alta cabe otra subida entera."""

    async def _cero(*_: object) -> int:
        return 0

    monkeypatch.setattr(v1, "contar_pendientes", _cero)
    with banco.api() as cliente:
        _sembrar_pendientes(banco, 20)
        cuerpo, tipo = _cuerpo()
        _exigir_429(
            cliente.post("/v1/files", content=cuerpo, headers={"Content-Type": tipo})
        )
    assert list(banco.uploads.iterdir()) == []
    assert banco.contar() == 20


def test_k48_la_subida_usa_solo_el_alta_con_cupo() -> None:
    assert "crear_archivo" not in vars(v1)


# ------------------------------------------- K53: directorio de trabajo de cada hijo


def test_k53_el_hijo_escribe_en_un_parcial_privado_que_luego_desaparece(
    banco: Banco, tmp_path: Path
) -> None:
    registro = tmp_path / "trabajo.json"
    comando = _comando(
        tmp_path,
        "import json, os, shutil, stat, sys\n"
        "trabajo = os.path.dirname(sys.argv[2])\n"
        "info = os.lstat(trabajo)\n"
        f"open({str(registro)!r}, 'w').write(json.dumps({{\n"
        "    'trabajo': trabajo, 'salida': sys.argv[2],\n"
        "    'es_dir': stat.S_ISDIR(info.st_mode), 'modo': stat.S_IMODE(info.st_mode),\n"
        "    'vacio': os.listdir(trabajo) == []}))\n"
        "shutil.copyfile(sys.argv[1], sys.argv[2])\n"
        f"print({json.dumps(json.dumps(LIMPIO))})\n",
    )
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id = _subir(cliente)
        assert _esperar(cliente, archivo_id)["estado"] == "limpio"
    visto = json.loads(registro.read_text())
    assert visto["trabajo"] == str(banco.clean / f"{archivo_id}.parcial")
    assert Path(visto["salida"]).parent == Path(visto["trabajo"])
    assert visto["es_dir"] and visto["vacio"]
    assert visto["modo"] == 0o700
    assert sorted(p.name for p in banco.clean.iterdir()) == [archivo_id]


def test_k53_lo_que_deje_el_hijo_en_su_parcial_se_borra(
    banco: Banco, tmp_path: Path
) -> None:
    comando = _comando(
        tmp_path,
        "import os, sys\n"
        "trabajo = os.path.dirname(sys.argv[2])\n"
        "for nombre in ('a', 'b'):\n"
        "    open(os.path.join(trabajo, nombre), 'w').write('x')\n"
        "os.mkdir(os.path.join(trabajo, 'sub'))\n"
        "open(os.path.join(trabajo, 'sub', 'c'), 'w').write('x')\n"
        "sys.exit(3)\n",
    )
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id = _subir(cliente)
        assert _esperar(cliente, archivo_id)["estado"] == "error"
    assert list(banco.clean.iterdir()) == []
