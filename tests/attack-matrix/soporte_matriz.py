"""Banco de la matriz de ataque: la API real, PostgreSQL 16 real y disco real.

Todo va por HTTP contra ``crear_app(Ajustes(...))``. El multipart se arma a mano porque un cliente
HTTP normal escapa justo lo que se quiere mandar (bytes nulos, nombres sin UTF-8 válido).
``ClienteMatriz.asgi`` llama a la app por ASGI para contar los bytes que lee: TestClient entrega el
cuerpo entero de una vez y no deja ver si se cortó a tiempo.

Costura de pruebas que debe dar gk-api-dev:
``Ajustes`` con dos campos con valor por defecto que ``leer_ajustes()`` nunca lee del entorno:

- ``comando_cdr: tuple[str, ...] = (sys.executable, "-m", "api.app.cdr_hijo")``. La API añade
  ``<entrada> <salida>`` al final.
- ``timeout_cdr_s: float = 30``.

Sin esa costura, ``Banco.api`` hace fallar la prueba con un mensaje claro, no con un TypeError.
"""

import asyncio
import dataclasses
import hashlib
import re
import secrets
import time
import uuid
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import URL

from api.app.ajustes import Ajustes
from api.app.autenticacion import calcular_hash, generar_key
from api.app.estados import Estado
from api.app.principal import crear_app
from api.db.repositorios import (
    SinEvidenciaCDR,
    cambiar_estado,
    crear_api_key,
    crear_archivo,
    registrar_resultado,
)
from api.db.sesion import crear_motor, fabrica_sesiones
from api.tests.soporte_api import KeySembrada, sembrar_key

TOPE_ARCHIVO = 10_485_760  # param:tamano_maximo_archivo
MARGEN_CONTENT_LENGTH = 65_536  # diseño §4
# Tope de sondeo por defecto: el timeout de análisis (30 s) más un margen. No es una espera fija.
TOPE_ANALISIS_S = 45.0
# Tope para hijos sustitutos, que responden en milisegundos.
TOPE_HIJO_FALSO_S = 12.0
INTERVALO_SONDEO_S = 0.02
# Los mensajes de error son los textos estándar de HTTP (K29). Python 3.12 llama al 413
# "Request Entity Too Large"; RFC 9110, "Content Too Large".
DETALLES_413 = ("Request Entity Too Large", "Content Too Large")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
CAMPOS_ESTADO = {
    "id",
    "estado",
    "tipo_detectado",
    "tamano_bytes",
    "sha256",
    "creado_en",
    "analizado_en",
}

# Se deja de alimentar a la app al pasar de aquí: si no corta, no hace falta mandarle 500 MB.
_ALARMA_BYTES = 32 * 1024 * 1024
DESCONEXION = object()


def multipart(
    contenido: bytes,
    nombre: bytes = b"archivo.bin",
    tipo: bytes | None = b"application/octet-stream",
    campo: bytes = b"file",
) -> tuple[bytes, str]:
    """Cuerpo multipart con los bytes tal cual, y su Content-Type."""
    limite = secrets.token_hex(16).encode()
    cabeceras = b'Content-Disposition: form-data; name="%s"; filename="%s"\r\n' % (
        campo,
        nombre,
    )
    if tipo is not None:
        cabeceras += b"Content-Type: %s\r\n" % tipo
    cuerpo = b"--%s\r\n%s\r\n%s\r\n--%s--\r\n" % (limite, cabeceras, contenido, limite)
    return cuerpo, f"multipart/form-data; boundary={limite.decode()}"


def esperar_que(condicion: Callable[[], bool], mensaje: str, tope: float = 5.0) -> None:
    limite = time.monotonic() + tope
    while not condicion():
        if time.monotonic() > limite:
            pytest.fail(mensaje)
        time.sleep(INTERVALO_SONDEO_S)


def nombres(directorio: Path) -> set[str]:
    return (
        {ruta.name for ruta in directorio.iterdir()} if directorio.exists() else set()
    )


@dataclass(frozen=True)
class RespuestaAsgi:
    estado: int
    cuerpo: bytes
    leidos: int
    excedio_alarma: bool


class ClienteMatriz:
    """Lo que puede hacer una aplicación cliente, con la key de ``banco.app_a`` por defecto."""

    def __init__(self, http: TestClient, app: Any, banco: "Banco") -> None:
        self._http = http
        self._app = app
        self._banco = banco

    def cabeceras(self, key: str | None = None) -> dict[str, str]:
        return {"Authorization": f"Bearer {key or self._banco.app_a.key}"}

    def post_archivo(
        self,
        contenido: bytes,
        nombre: bytes = b"archivo.bin",
        tipo: bytes | None = b"application/octet-stream",
        key: str | None = None,
    ) -> httpx.Response:
        cuerpo, content_type = multipart(contenido, nombre, tipo)
        return self._http.post(
            "/v1/files",
            content=cuerpo,
            headers={**self.cabeceras(key), "Content-Type": content_type},
        )

    def subir(
        self,
        contenido: bytes,
        nombre: bytes = b"archivo.bin",
        tipo: bytes | None = b"application/octet-stream",
        key: str | None = None,
    ) -> str:
        respuesta = self.post_archivo(contenido, nombre, tipo, key)
        assert respuesta.status_code == 202, (
            f"POST /v1/files debe responder 202 y respondió {respuesta.status_code}"
        )
        cuerpo = respuesta.json()
        assert set(cuerpo) == {"id", "estado"}
        assert cuerpo["estado"] == "pendiente"
        assert UUID_RE.fullmatch(cuerpo["id"]), "el id debe ser un UUID del servidor"
        return cuerpo["id"]

    def ver(self, archivo_id: str, key: str | None = None) -> httpx.Response:
        return self._http.get(f"/v1/files/{archivo_id}", headers=self.cabeceras(key))

    def descargar(self, archivo_id: str, key: str | None = None) -> httpx.Response:
        return self._http.get(
            f"/v1/files/{archivo_id}/content", headers=self.cabeceras(key)
        )

    def esperar(
        self, archivo_id: str, key: str | None = None, tope: float = TOPE_ANALISIS_S
    ) -> dict[str, Any]:
        """Sondea el estado hasta que deja de ser ``pendiente``."""
        limite = time.monotonic() + tope
        while True:
            respuesta = self.ver(archivo_id, key)
            assert respuesta.status_code == 200, (
                f"GET /v1/files/{{id}} respondió {respuesta.status_code}"
            )
            cuerpo = respuesta.json()
            if cuerpo["estado"] != "pendiente":
                return cuerpo
            if time.monotonic() > limite:
                pytest.fail(f"el archivo sigue en pendiente tras {tope} s")
            time.sleep(INTERVALO_SONDEO_S)

    def analizar(
        self,
        contenido: bytes,
        nombre: bytes = b"archivo.bin",
        tipo: bytes | None = b"application/octet-stream",
        tope: float = TOPE_ANALISIS_S,
    ) -> tuple[str, dict[str, Any]]:
        archivo_id = self.subir(contenido, nombre, tipo)
        return archivo_id, self.esperar(archivo_id, tope=tope)

    def asgi(
        self,
        metodo: str,
        ruta: str,
        cabeceras: dict[str, str],
        trozos: Iterable[Any] = (),
    ) -> RespuestaAsgi:
        """Una petición ASGI cuyo cuerpo se entrega trozo a trozo, contando lo que se lee.

        Un trozo ``DESCONEXION`` simula que el cliente corta la conexión.
        """
        leidos = 0
        excedio = False
        agotado = False
        estado = 0
        cuerpo = b""
        iterador = iter(trozos)
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
            "client": ("testclient", 1),
            "headers": [
                (nombre.lower().encode(), valor.encode())
                for nombre, valor in cabeceras.items()
            ],
        }

        async def _llamar() -> None:
            fin = anyio.Event()

            async def recibir() -> dict[str, Any]:
                nonlocal leidos, excedio, agotado
                if agotado:
                    await fin.wait()
                    return {"type": "http.disconnect"}
                trozo = next(iterador, None)
                if trozo is None:
                    agotado = True
                    return {"type": "http.request", "body": b"", "more_body": False}
                if trozo is DESCONEXION:
                    agotado = True
                    fin.set()
                    return {"type": "http.disconnect"}
                leidos += len(trozo)
                if leidos > _ALARMA_BYTES:
                    excedio = agotado = True
                    fin.set()
                    return {"type": "http.disconnect"}
                return {"type": "http.request", "body": trozo, "more_body": True}

            async def enviar(mensaje: dict[str, Any]) -> None:
                nonlocal estado, cuerpo
                if mensaje["type"] == "http.response.start":
                    estado = mensaje["status"]
                elif mensaje["type"] == "http.response.body":
                    cuerpo += mensaje.get("body", b"")
                    if not mensaje.get("more_body", False):
                        fin.set()

            with anyio.fail_after(60):
                await self._app(alcance, recibir, enviar)

        assert self._http.portal is not None
        self._http.portal.call(_llamar)
        return RespuestaAsgi(estado, cuerpo, leidos, excedio)


@dataclass
class Banco:
    """Una base vacía con dos aplicaciones, y un directorio de datos propio."""

    url: URL
    pepper: bytes = field(repr=False)
    raiz: Path
    app_a: KeySembrada = field(repr=False)
    app_b: KeySembrada = field(repr=False)
    motor: Engine = field(repr=False)

    @property
    def datos(self) -> Path:
        return self.raiz / "datos"

    @property
    def uploads_tmp(self) -> Path:
        return self.datos / "uploads_tmp"

    @property
    def clean_store(self) -> Path:
        return self.datos / "clean_store"

    def ajustes(self, **costura: Any) -> Ajustes:
        faltan = set(costura) - {campo.name for campo in dataclasses.fields(Ajustes)}
        if faltan:
            pytest.fail(
                f"control ausente: falta la costura de prueba {sorted(faltan)} en Ajustes "
                "(ver soporte_matriz.py)"
            )
        return Ajustes(url_bd=self.url, pepper=self.pepper, datos=self.datos, **costura)

    @contextmanager
    def api(self, **costura: Any) -> Iterator[ClienteMatriz]:
        app = crear_app(self.ajustes(**costura))
        with TestClient(app, raise_server_exceptions=False) as http:
            yield ClienteMatriz(http, app, self)

    # ------------------------------------------------------------------------ lecturas de la BD

    def fila(self, archivo_id: str) -> dict[str, Any] | None:
        with self.motor.connect() as con:
            fila = (
                con.execute(
                    text(
                        "SELECT nombre_original, estado, tipo_error, tipo_detectado,"
                        " tamano_bytes, sha256, analizado_en FROM archivo WHERE id = :id"
                    ),
                    {"id": uuid.UUID(archivo_id)},
                )
                .mappings()
                .one_or_none()
            )
        return None if fila is None else dict(fila)

    def resultados(self, archivo_id: str) -> list[tuple[str, str]]:
        with self.motor.connect() as con:
            filas = con.execute(
                text(
                    "SELECT capa, veredicto FROM resultado_analisis WHERE archivo_id = :id"
                ),
                {"id": uuid.UUID(archivo_id)},
            ).all()
        return [(fila.capa, fila.veredicto) for fila in filas]

    def contar_archivos(self) -> int:
        with self.motor.connect() as con:
            return con.execute(text("SELECT count(*) FROM archivo")).scalar_one()

    def revocar(self, prefijo: str) -> None:
        with self.motor.begin() as con:
            con.execute(
                text("UPDATE api_key SET revocada_en = now() WHERE prefijo = :prefijo"),
                {"prefijo": prefijo},
            )

    # -------------------------------------------------------------------------- estados sembrados

    def sembrar_archivo(self, estado: str, app: KeySembrada) -> str:
        """Un archivo en ``estado``, escrito con los repositorios reales y sin pasar por el análisis.

        Sirve para fijar un estado sin carreras. ``limpio`` lleva su evidencia de CDR (K16).
        """
        destino = Estado(estado)

        async def _sembrar() -> str:
            motor = crear_motor(self.url)
            archivo_id = uuid.uuid4()
            sha256 = hashlib.sha256(archivo_id.bytes).hexdigest()
            try:
                async with fabrica_sesiones(motor).begin() as sesion:
                    await crear_archivo(
                        sesion, app.aplicacion_id, archivo_id, "sembrado", 1, sha256
                    )
                    if destino is Estado.LIMPIO:
                        await registrar_resultado(
                            sesion,
                            app.aplicacion_id,
                            archivo_id,
                            "cdr",
                            "limpio",
                            {},
                            1,
                        )
                    if destino is not Estado.PENDIENTE:
                        await cambiar_estado(
                            sesion,
                            app.aplicacion_id,
                            archivo_id,
                            Estado.PENDIENTE,
                            destino,
                            tipo_detectado="image/png",
                            tipo_error="final" if destino is Estado.ERROR else None,
                        )
            finally:
                await motor.dispose()
            return str(archivo_id)

        return asyncio.run(_sembrar())

    def intentar_limpio(
        self,
        archivo_id: str,
        app: KeySembrada,
        evidencia: tuple[str, str] | None,
    ) -> None:
        """Pide `pendiente -> limpio` con esa evidencia y exige que el `UPDATE` lo rechace (K16)."""

        async def _intentar() -> None:
            motor = crear_motor(self.url)
            identificador = uuid.UUID(archivo_id)
            try:
                if evidencia is not None:
                    async with fabrica_sesiones(motor).begin() as sesion:
                        await registrar_resultado(
                            sesion, app.aplicacion_id, identificador, *evidencia, {}, 1
                        )
                async with fabrica_sesiones(motor).begin() as sesion:
                    await cambiar_estado(
                        sesion,
                        app.aplicacion_id,
                        identificador,
                        Estado.PENDIENTE,
                        Estado.LIMPIO,
                        tipo_detectado="image/png",
                    )
            finally:
                await motor.dispose()

        with pytest.raises(SinEvidenciaCDR):
            asyncio.run(_intentar())

    def key_nueva_para(self, aplicacion_id: uuid.UUID) -> str:
        async def _crear() -> str:
            motor = crear_motor(self.url)
            prefijo, key = generar_key()
            try:
                async with fabrica_sesiones(motor).begin() as sesion:
                    await crear_api_key(
                        sesion, aplicacion_id, prefijo, calcular_hash(self.pepper, key)
                    )
            finally:
                await motor.dispose()
            return key

        return asyncio.run(_crear())


@contextmanager
def abrir_banco(url: URL, raiz: Path) -> Iterator[Banco]:
    pepper = secrets.token_hex(32).encode()
    motor = create_engine(url)
    try:
        yield Banco(
            url=url,
            pepper=pepper,
            raiz=raiz,
            app_a=sembrar_key(url, pepper, "app_a"),
            app_b=sembrar_key(url, pepper, "app_b"),
            motor=motor,
        )
    finally:
        motor.dispose()


# ------------------------------------------------------------------------- comprobaciones comunes


def exigir_conflicto(respuesta: httpx.Response) -> None:
    """INV-06: cualquier estado que no sea ``limpio`` responde exactamente este 409."""
    assert respuesta.status_code == 409, (
        f"debe responder 409 y respondió {respuesta.status_code}"
    )
    assert respuesta.json() == {"detail": "Conflict"}


def exigir_sin_original(banco: Banco) -> None:
    """F3.09: al terminar el análisis no queda el original en disco."""
    esperar_que(
        lambda: not nombres(banco.uploads_tmp),
        "el original sigue en uploads_tmp tras terminar el análisis",
    )


def exigir_rechazado(
    cliente: ClienteMatriz,
    banco: Banco,
    contenido: bytes,
    nombre: bytes = b"archivo.bin",
    tipo: bytes | None = b"application/octet-stream",
) -> str:
    """`rechazado`, con `/content` en 409, sin salida entregable y sin el original."""
    archivo_id, final = cliente.analizar(contenido, nombre, tipo)
    assert final["estado"] == "rechazado", f"estado final: {final['estado']}"
    assert final["analizado_en"] is not None
    exigir_conflicto(cliente.descargar(archivo_id))
    assert archivo_id not in nombres(banco.clean_store)
    exigir_sin_original(banco)
    assert ("cdr", "limpio") not in banco.resultados(archivo_id)
    return archivo_id


def exigir_limpio(
    cliente: ClienteMatriz,
    banco: Banco,
    contenido: bytes,
    nombre: bytes = b"archivo.bin",
    tipo: bytes | None = b"application/octet-stream",
    tipo_esperado: str | None = None,
) -> tuple[str, bytes]:
    """`limpio`, con evidencia de CDR y descarga en 200. Devuelve el id y los bytes entregados."""
    archivo_id, final = cliente.analizar(contenido, nombre, tipo)
    assert final["estado"] == "limpio", f"estado final: {final['estado']}"
    if tipo_esperado is not None:
        assert final["tipo_detectado"] == tipo_esperado
    assert ("cdr", "limpio") in banco.resultados(archivo_id), "K16: falta la evidencia"
    descarga = cliente.descargar(archivo_id)
    assert descarga.status_code == 200
    # Sale del almacén de reconstruidos. Con un archivo sin nada que quitar, la reconstrucción
    # puede coincidir byte a byte con el original: compararlos no prueba nada aquí.
    assert descarga.content == (banco.clean_store / archivo_id).read_bytes()
    exigir_sin_original(banco)
    return archivo_id, descarga.content
