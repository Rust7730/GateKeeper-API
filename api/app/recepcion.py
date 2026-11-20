"""Recepción de ``POST /v1/files`` (F2.02, diseño §4): multipart en streaming hacia disco.

El cuerpo no se acumula en memoria: cada trozo pasa al parser y de ahí al temporal, mientras
se calcula el SHA-256. El temporal se llama con un UUID del servidor (INV-03) y solo se crea
al llegar la parte ``file``, así que una petición sin archivo no toca el disco.

Dos topes, y hacen falta los dos: el del archivo (413 al pasarlo) y el del cuerpo entero, que
frena también un campo de texto enorme o un cuerpo ``chunked`` sin ``Content-Length``. El
tamaño de cada cabecera de una parte lo acota el propio parser. Un tercero acota el tiempo:
K40 fija una sola fecha límite para toda la recepción, y un cliente que gotea no la renueva.

Todo error lleva ``Connection: close``: se responde sin haber leído el cuerpo, y sin esa
cabecera el servidor seguiría recibiendo lo que quede para reutilizar la conexión.

``Content-Type`` de la parte, extensión y nombre no deciden nada (INV-02): el nombre solo se
guarda para mostrarlo (K25).
"""

import asyncio
import hashlib
import http
import os
import re
import threading
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from fastapi import HTTPException, Request
from python_multipart import MultipartParser
from python_multipart.exceptions import FormParserError, MultipartParseError
from python_multipart.multipart import parse_options_header
from starlette.requests import ClientDisconnect

TOPE_ARCHIVO = 10_485_760  # param:tamano_maximo_archivo
MARGEN_CUERPO = 65_536  # diseño §4: cabeceras multipart y campos pequeños
TOPE_CUERPO = TOPE_ARCHIVO + MARGEN_CUERPO
LARGO_NOMBRE = 255  # archivo.nombre_original es varchar(255)
NOMBRE_VACIO = "sin_nombre"
TIPO_MULTIPART = b"multipart/form-data"
CAMPO_ARCHIVO = b"file"
_CABECERA_DISPOSICION = b"content-disposition"
# K64: 0640 permite que worker (UID 10003, GID 10010) lea el original en uploads_tmp (:ro).
_MODO_TEMPORAL = 0o640
# C0, U+007F y C1 (K25, K30). Un UTF-8 inválido ya viene como U+FFFD: decodificar no deja
# surrogates, que PostgreSQL no podría guardar.
_NO_GUARDABLES = re.compile("[\x00-\x1f\x7f-\x9f]")


def rechazo(codigo: http.HTTPStatus) -> HTTPException:
    """Error con el texto estándar de HTTP (K29) y la conexión cerrada al responder."""
    return HTTPException(
        status_code=codigo, detail=codigo.phrase, headers={"Connection": "close"}
    )


def sanear_nombre(crudo: bytes) -> str:
    """K25: quita lo no guardable, luego trunca y, si no queda nada, ``sin_nombre``."""
    texto = crudo.decode("utf-8", errors="replace")
    return _NO_GUARDABLES.sub("", texto)[:LARGO_NOMBRE] or NOMBRE_VACIO


def extraer_limite(content_type: str | None) -> bytes:
    """El ``boundary`` de un ``multipart/form-data``: 415 si no lo es, 400 si no lo trae."""
    tipo, opciones = parse_options_header(content_type)
    if tipo.lower() != TIPO_MULTIPART:
        raise rechazo(http.HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
    limite = opciones.get(b"boundary")
    if not limite:
        raise rechazo(http.HTTPStatus.BAD_REQUEST)
    return limite


def comprobar_longitud(content_length: str | None) -> None:
    """Rechaza sin leer un ``Content-Length`` por encima del tope, o que no sea un número."""
    if content_length is None:
        return
    if not (content_length.isascii() and content_length.isdigit()):
        raise rechazo(http.HTTPStatus.BAD_REQUEST)
    # Por el largo primero: int() no acepta textos de miles de dígitos.
    if len(content_length) > len(str(TOPE_CUERPO)) or int(content_length) > TOPE_CUERPO:
        raise rechazo(http.HTTPStatus.REQUEST_ENTITY_TOO_LARGE)


def _abrir_exclusivo(ruta: str, banderas: int) -> int:
    return os.open(ruta, banderas | os.O_NOFOLLOW, _MODO_TEMPORAL)


@dataclass(frozen=True, slots=True)
class ArchivoRecibido:
    id: uuid.UUID
    ruta: Path
    nombre: str = field(repr=False)
    tamano: int
    sha256: str = field(repr=False)


class Receptor:
    """Convierte los trozos del cuerpo en un temporal. Síncrono: corre en un hilo.

    Quien lo usa debe llamar a ``descartar()`` si algo falla, también si el error viene de
    fuera (el cliente cortó): el temporal es suyo hasta que lo reciba el análisis.

    Cancelar la petición no detiene el hilo de un ``alimentar`` en curso, que podría crear el
    temporal después de ``descartar()``. Por eso los dos toman el mismo cerrojo y, una vez
    descartado, ``alimentar`` no hace nada. ``descartar`` espera como mucho a que termine el
    trozo en curso.
    """

    def __init__(self, limite: bytes, directorio: Path) -> None:
        self._cerrojo = threading.Lock()
        self._descartado = False
        self._directorio = directorio
        self._id = uuid.uuid4()
        self._ruta: Path | None = None
        self._archivo: BinaryIO | None = None
        self._hash = hashlib.sha256()
        self._tamano = 0
        self._nombre = NOMBRE_VACIO
        self._terminado = False
        self._reiniciar_parte()
        try:
            self._parser = MultipartParser(
                limite,
                callbacks={
                    "on_part_begin": self._reiniciar_parte,
                    "on_header_field": self._leer_campo,
                    "on_header_value": self._leer_valor,
                    "on_header_end": self._cerrar_cabecera,
                    "on_headers_finished": self._empezar_datos,
                    "on_part_data": self._escribir,
                    "on_part_end": self._cerrar_parte,
                    "on_end": self._marcar_fin,
                },
            )
        except FormParserError:
            raise rechazo(http.HTTPStatus.BAD_REQUEST) from None

    # ------------------------------------------------------------------------ callbacks

    def _reiniciar_parte(self) -> None:
        self._campo = bytearray()
        self._valor = bytearray()
        self._disposicion: bytes | None = None
        self._en_archivo = False

    def _leer_campo(self, datos: bytes, inicio: int, fin: int) -> None:
        self._campo += datos[inicio:fin]

    def _leer_valor(self, datos: bytes, inicio: int, fin: int) -> None:
        self._valor += datos[inicio:fin]

    def _cerrar_cabecera(self) -> None:
        if self._campo.lower() == _CABECERA_DISPOSICION:
            # Dos cabeceras se podrían leer distinto aquí y en un proxy.
            if self._disposicion is not None:
                raise rechazo(http.HTTPStatus.BAD_REQUEST)
            self._disposicion = bytes(self._valor)
        self._campo.clear()
        self._valor.clear()

    def _empezar_datos(self) -> None:
        if self._disposicion is None:
            raise rechazo(http.HTTPStatus.BAD_REQUEST)
        _, opciones = parse_options_header(self._disposicion)
        if opciones.get(b"name") != CAMPO_ARCHIVO:
            return
        # Con dos partes `file` no habría forma de saber cuál es la que se analiza.
        if self._ruta is not None:
            raise rechazo(http.HTTPStatus.BAD_REQUEST)
        self._nombre = sanear_nombre(opciones.get(b"filename", b""))
        self._ruta = self._directorio / str(self._id)
        self._archivo = open(self._ruta, "xb", opener=_abrir_exclusivo)  # noqa: SIM115
        self._en_archivo = True

    def _escribir(self, datos: bytes, inicio: int, fin: int) -> None:
        if not self._en_archivo:
            return
        self._tamano += fin - inicio
        if self._tamano > TOPE_ARCHIVO:
            raise rechazo(http.HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        trozo = memoryview(datos)[inicio:fin]
        self._hash.update(trozo)
        self._archivo.write(trozo)

    def _cerrar_parte(self) -> None:
        self._en_archivo = False

    def _marcar_fin(self) -> None:
        self._terminado = True

    # -------------------------------------------------------------------------- interfaz

    def alimentar(self, trozo: bytes) -> None:
        """Procesa un trozo del cuerpo. 413 al pasar el tope, 400 si no es multipart."""
        with self._cerrojo:
            if self._descartado:
                return
            try:
                self._parser.write(trozo)
            except MultipartParseError:
                raise rechazo(http.HTTPStatus.BAD_REQUEST) from None

    def terminar(self) -> ArchivoRecibido:
        """Cierra el temporal. 400 si el cuerpo acabó sin cierre, sin archivo o vacío.

        ``finalize()`` del parser no comprueba nada: el fin lo marca ``on_end``.
        """
        self._cerrar_archivo()
        if self._ruta is None or not self._terminado or self._tamano == 0:
            raise rechazo(http.HTTPStatus.BAD_REQUEST)
        return ArchivoRecibido(
            id=self._id,
            ruta=self._ruta,
            nombre=self._nombre,
            tamano=self._tamano,
            sha256=self._hash.hexdigest(),
        )

    def _cerrar_archivo(self) -> None:
        if self._archivo is not None:
            self._archivo.close()
            self._archivo = None

    def descartar(self) -> None:
        """Borra el temporal, exista o no, y deja sin efecto todo ``alimentar`` posterior."""
        with self._cerrojo:
            self._descartado = True
            self._cerrar_archivo()
            if self._ruta is not None:
                self._ruta.unlink(missing_ok=True)


async def _siguiente_trozo(
    trozos: AsyncIterator[bytes], fecha_limite: float
) -> bytes | None:
    """Espera el siguiente trozo sin pasar de ``fecha_limite``. 408 al vencer (K40).

    La fecha es una sola para toda la recepción: un goteo no la renueva. Se mira también el
    reloj porque un timeout de asyncio solo salta al suspender, y ``receive`` puede devolver
    sin suspender. El plazo cubre solo esta espera y no ``alimentar``: cancelar un hilo no lo
    detiene, y podría crear el temporal después de ``descartar()``.
    """
    if asyncio.get_running_loop().time() < fecha_limite:
        try:
            async with asyncio.timeout_at(fecha_limite):
                return await anext(trozos, None)
        except TimeoutError:
            pass
    raise rechazo(http.HTTPStatus.REQUEST_TIMEOUT)


async def recibir_archivo(
    request: Request, directorio: Path, timeout_s: float
) -> ArchivoRecibido:
    """Lee el cuerpo de ``request`` hasta el temporal, sin dejar rastro si algo falla.

    ``alimentar`` va en un hilo para que disco y SHA-256 no paren el bucle de eventos. Ese
    salto no cuenta para M1, que se mide desde el fin de la recepción.
    """
    limite = extraer_limite(request.headers.get("content-type"))
    comprobar_longitud(request.headers.get("content-length"))
    receptor = Receptor(limite, directorio)
    fecha_limite = asyncio.get_running_loop().time() + timeout_s
    trozos = aiter(request.stream())
    recibidos = 0
    try:
        while (trozo := await _siguiente_trozo(trozos, fecha_limite)) is not None:
            recibidos += len(trozo)
            if recibidos > TOPE_CUERPO:
                raise rechazo(http.HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            if trozo:
                await asyncio.to_thread(receptor.alimentar, trozo)
        return receptor.terminar()
    except ClientDisconnect:
        receptor.descartar()
        raise rechazo(http.HTTPStatus.BAD_REQUEST) from None
    except BaseException:
        receptor.descartar()
        raise
