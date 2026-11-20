"""Servicio ``coordinator``: orquesta worker + reputation y consolida el veredicto (K01, K08, F4.07).

Corre en la red interna ``backend`` (sin contacto con archivos hostiles, sin salida a internet):
1. Consume ``orquestar(aplicacion_id, archivo_id, sha256)`` desde ``redis-main``.
2. Encola en paralelo:
   - ``analizar(archivo_id)`` en ``redis-queue`` hacia ``worker`` (ClamAV ∥ firma + CDR, D1);
   - ``consultar_hash(sha256)`` en ``redis-main`` hacia ``reputation`` (VirusTotal solo hash, INV-05).
3. Espera al ``worker`` y, a partir de ahí, como máximo 1 s más a ``reputation`` (K07, D3).
4. Aplica la prioridad estricta ``en_cuarentena > rechazado > error > limpio`` (F4.07, INV-09),
   mueve el original a ``quarantine/`` si VT detectó malware, registra las capas en PostgreSQL
   como ``gk_app`` (K16), borra ``uploads_tmp/<uuid>`` (F3.09) y publica el evento en ``redis-main``.
"""

import asyncio
import contextlib
import json
import logging
import math
import os
import shutil
import stat
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from arq.jobs import Job
from arq.worker import func
from sqlalchemy.engine import URL

from api.app import analisis
from api.app.ajustes import (
    CLEAN_STORE,
    UPLOADS_TMP,
    VARIABLE_DATOS,
    VARIABLE_REDIS,
    ConfiguracionError,
    abrir_motor,
)
from api.app.analisis import _ERROR, _MOTIVO_INTERNO
from api.app.arranque import barrer_restos, comprobar_ancestros, proteger_proceso
from api.app.cdr_salida import TOPE_SALIDA
from api.app.cola import (
    CANAL_EVENTOS,
    COLA_ANALIZAR,
    COLA_ORQUESTAR,
    COLA_REPUTACION,
    POLL_DELAY_S,
    PRESUPUESTO_VT_S,
    TIMEOUT_JOB_COORDINATOR_S,
    TIMEOUT_JOB_WORKER_S,
    WorkerSinInfo,
    abrir_cola,
    cerrar_cola,
    deserializar_json,
    serializar_json,
)
from api.app.estados import Estado
from api.app.tipos import TIPOS_PERMITIDOS
from api.db.config import url_bd
from api.db.repositorios import cambiar_estado, registrar_resultado
from api.db.repositorios_admin import liberar_estado_archivo, obtener_metadatos_evento
from api.db.sesion import fabrica_sesiones
from worker.ajustes import QUARANTINE, VARIABLE_REDIS_QUEUE
from worker.ejecutor import LIMPIO, RECHAZADO, Veredicto

logger = logging.getLogger("gatekeeper.coordinator")

_CLAVES_BASE_WORKER = {"veredicto", "tipo", "motivo", "duracion_ms"}
_VEREDICTOS_WORKER = {LIMPIO, RECHAZADO, _ERROR}
_VEREDICTOS_ANTIMALWARE = {LIMPIO, "malicioso", _ERROR, "no_evaluada"}
_MOTIVO_TIMEOUT_WORKER = "timeout_worker"
_MOTIVO_RESPUESTA_INVALIDA = "respuesta_worker_invalida"
_MOTIVO_SIN_SALIDA = "sin_salida"
_MOTIVO_SALIDA_GRANDE = "salida_grande"
_MALICIOSO = "malicioso"
_NO_EVALUADA = "no_evaluada"
_MODO_CUARENTENA = 0o600


@dataclass(frozen=True, slots=True)
class AjustesCoordinador:
    """Ajustes del servicio ``coordinator``. Secretos fuera del ``repr`` (CWE-532)."""

    url_bd: str | URL = field(repr=False)
    url_redis: str = field(repr=False)
    url_redis_queue: str = field(repr=False)
    datos: Path
    timeout_worker_s: float = float(TIMEOUT_JOB_WORKER_S)
    poll_delay_s: float = POLL_DELAY_S
    presupuesto_vt_s: float = PRESUPUESTO_VT_S
    consultar_reputacion: bool = True
    max_jobs: int = field(default_factory=lambda: max(4, (os.cpu_count() or 1) * 2))

    def __post_init__(self) -> None:
        if not self.url_bd:
            raise ConfiguracionError("Falta la URL de la base de datos.")
        for nombre, valor in (
            (VARIABLE_REDIS, self.url_redis),
            (VARIABLE_REDIS_QUEUE, self.url_redis_queue),
        ):
            if type(valor) is not str or not valor.strip() or valor != valor.strip():
                raise ConfiguracionError(
                    f"La URL de Redis ({nombre}) falta o es inválida "
                    "(el valor no se muestra)."
                )
        if not isinstance(self.datos, Path) or not self.datos.is_absolute():
            raise ConfiguracionError(
                f"El directorio ({VARIABLE_DATOS}) debe ser una ruta absoluta "
                "(la ruta no se muestra)."
            )
        if (
            type(self.timeout_worker_s) not in (int, float)
            or not math.isfinite(self.timeout_worker_s)
            or self.timeout_worker_s <= 0
        ):
            raise ConfiguracionError("timeout_worker_s debe ser un número positivo.")

    @property
    def uploads_tmp(self) -> Path:
        return self.datos / UPLOADS_TMP

    @property
    def clean_store(self) -> Path:
        return self.datos / CLEAN_STORE

    @property
    def quarantine(self) -> Path:
        return self.datos / QUARANTINE


def leer_ajustes_coordinador() -> AjustesCoordinador:
    """Lee la configuración del ``coordinator`` desde el entorno."""
    url_redis = os.environ.get(VARIABLE_REDIS)
    url_queue = os.environ.get(VARIABLE_REDIS_QUEUE)
    datos = os.environ.get(VARIABLE_DATOS)
    for nombre, valor in (
        (VARIABLE_REDIS, url_redis),
        (VARIABLE_REDIS_QUEUE, url_queue),
        (VARIABLE_DATOS, datos),
    ):
        if valor is None or not valor.strip():
            raise ConfiguracionError(
                f"Falta la variable de entorno {nombre} o está vacía; "
                "no hay valor por defecto."
            )
    assert url_redis is not None and url_queue is not None and datos is not None
    if datos != datos.strip():
        raise ConfiguracionError(
            f"La variable de entorno {VARIABLE_DATOS} tiene espacios en los bordes."
        )
    return AjustesCoordinador(
        url_bd=url_bd(),
        url_redis=url_redis,
        url_redis_queue=url_queue,
        datos=Path(datos),
    )


def _validar_capa_antimalware(bruto: Any) -> dict[str, Any]:
    if type(bruto) is not dict:
        return {"veredicto": _NO_EVALUADA, "motivo": "sin_datos", "duracion_ms": 0}
    veredicto = bruto.get("veredicto")
    if type(veredicto) is not str or veredicto not in _VEREDICTOS_ANTIMALWARE:
        return {
            "veredicto": _ERROR,
            "motivo": _MOTIVO_RESPUESTA_INVALIDA,
            "duracion_ms": 0,
        }
    duracion = bruto.get("duracion_ms", 0)
    if type(duracion) is not int or duracion < 0:
        duracion = 0
    detalle: dict[str, Any] = {
        "veredicto": veredicto,
        "motivo": str(bruto.get("motivo", ""))[:200],
        "duracion_ms": duracion,
    }
    if "firma" in bruto and type(bruto["firma"]) is str:
        detalle["firma"] = bruto["firma"][:200]
    if "motores_maliciosos" in bruto and type(bruto["motores_maliciosos"]) is int:
        detalle["motores_maliciosos"] = bruto["motores_maliciosos"]
    if "desconocido" in bruto and type(bruto["desconocido"]) is bool:
        detalle["desconocido"] = bruto["desconocido"]
    return detalle


def validar_resultado_worker(
    bruto: Any,
) -> tuple[str, Veredicto | None, int, str]:
    """Valida el dict devuelto por el worker, sin confiar en él (K02, INV-09)."""
    if type(bruto) is not dict:
        return _ERROR, None, 0, _MOTIVO_RESPUESTA_INVALIDA
    claves = set(bruto)
    if not (_CLAVES_BASE_WORKER <= claves <= (_CLAVES_BASE_WORKER | {"clamav"})):
        return _ERROR, None, 0, _MOTIVO_RESPUESTA_INVALIDA
    veredicto = bruto["veredicto"]
    tipo = bruto["tipo"]
    motivo = bruto["motivo"]
    duracion_ms = bruto["duracion_ms"]
    if (
        type(veredicto) is not str
        or type(tipo) is not str
        or type(motivo) is not str
        or type(duracion_ms) is not int
        or duracion_ms < 0
    ):
        return _ERROR, None, 0, _MOTIVO_RESPUESTA_INVALIDA
    if veredicto not in _VEREDICTOS_WORKER:
        return _ERROR, None, duracion_ms, _MOTIVO_RESPUESTA_INVALIDA
    if veredicto == _ERROR:
        return _ERROR, None, duracion_ms, motivo or _MOTIVO_INTERNO
    if veredicto == LIMPIO and tipo not in TIPOS_PERMITIDOS:
        return _ERROR, None, duracion_ms, _MOTIVO_RESPUESTA_INVALIDA
    return (
        veredicto,
        Veredicto(veredicto=veredicto, tipo=tipo, motivo=motivo),
        duracion_ms,
        "",
    )


def decidir(veredicto_cdr: str, veredicto_clamav: str, veredicto_vt: str) -> Estado:
    """Prioridad estricta F4.07: ``en_cuarentena > rechazado > error > limpio`` (INV-09)."""
    if veredicto_clamav == _MALICIOSO or veredicto_vt == _MALICIOSO:
        return Estado.EN_CUARENTENA
    if veredicto_cdr == RECHAZADO:
        return Estado.RECHAZADO
    if veredicto_clamav == _ERROR or veredicto_cdr == _ERROR:
        return Estado.ERROR
    if (
        veredicto_cdr == LIMPIO
        and veredicto_clamav in (LIMPIO, _NO_EVALUADA)
        and veredicto_vt in (LIMPIO, _NO_EVALUADA)
    ):
        return Estado.LIMPIO
    return Estado.ERROR


def _verificar_salida_limpia(final: Path) -> str | None:
    """Comprueba en disco que ``clean_store/<uuid>`` es un archivo regular y cabe en K46."""
    info = None
    with contextlib.suppress(FileNotFoundError):
        info = os.lstat(final)
    if info is None or not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        return _MOTIVO_SIN_SALIDA
    if info.st_size > TOPE_SALIDA:
        return _MOTIVO_SALIDA_GRANDE
    return None


def _asegurar_en_cuarentena(origen: Path, destino: Path) -> None:
    """Copia el original a ``quarantine/<uuid>`` (0600) si aún no lo copió el worker (F4.09)."""
    if destino.exists() or not origen.exists():
        return
    destino.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd = os.open(
        destino, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, _MODO_CUARENTENA
    )
    try:
        with os.fdopen(fd, "wb") as salida, origen.open("rb") as entrada:
            shutil.copyfileobj(entrada, salida)
    except BaseException:
        _borrar(destino)
        raise


def _copiar_desde_cuarentena(cuarentena: Path, destino_uploads: Path) -> bool:
    """Copia ``quarantine/<uuid>`` a ``uploads_tmp/<uuid>`` (0640) para re-CDR en liberación (INV-07, D4)."""
    if not cuarentena.exists():
        return False
    destino_uploads.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd = os.open(
        destino_uploads,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
        0o640,
    )
    try:
        with os.fdopen(fd, "wb") as salida, cuarentena.open("rb") as entrada:
            shutil.copyfileobj(entrada, salida)
    except BaseException:
        _borrar(destino_uploads)
        raise
    return True


def _borrar(ruta: Path) -> None:
    try:
        ruta.unlink(missing_ok=True)
    except OSError as error:
        logger.error("No se pudo borrar temporal (%s)", type(error).__name__)


async def _publicar_evento(
    cola_main: Any,
    sesiones: Any,
    archivo_id: uuid.UUID,
    estado: str,
    *,
    liberacion: bool = False,
) -> None:
    """Notifica el cambio de estado por pub/sub de ``redis-main`` en formato ``EventoDto`` (K20)."""
    tipo: str | None = None
    severidad = "baja"
    incluir_nombre = False
    if liberacion and estado == Estado.LIMPIO.value:
        tipo = "archivo_liberado"
        severidad = "media"
        incluir_nombre = True
    elif estado == Estado.EN_CUARENTENA.value:
        tipo = "malware_detectado"
        severidad = "critica"
        incluir_nombre = True
    elif estado == Estado.RECHAZADO.value:
        tipo = "rechazo_politica"
        severidad = "baja"

    payload: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "archivo_id": str(archivo_id),
        "estado": estado,
        "en": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    if tipo is not None:
        app_nombre: str | None = None
        nombre_original: str | None = None
        with contextlib.suppress(Exception):
            async with sesiones() as sesion:
                app_nombre, nombre_original = await obtener_metadatos_evento(
                    sesion, archivo_id
                )
        payload["tipo"] = tipo
        payload["severidad"] = severidad
        payload["aplicacion_nombre"] = app_nombre
        if incluir_nombre and nombre_original is not None:
            payload["nombre_archivo"] = nombre_original

    try:
        async with asyncio.timeout(1.0):
            await cola_main.publish(CANAL_EVENTOS, json.dumps(payload))
    except Exception as error:  # noqa: BLE001
        logger.warning(
            "No se pudo publicar evento de %s (%s)", archivo_id, type(error).__name__
        )


async def _esperar_resultado(
    trabajo: Job, timeout_s: float, poll_delay_s: float
) -> Any:
    """Espera el resultado del job sin la carrera de ``Job.result()`` en ARQ 0.25."""
    limite = time.monotonic() + timeout_s
    while True:
        info = await trabajo.result_info()
        if info is not None:
            if info.success:
                return info.result
            raise RuntimeError(str(info.result))
        if time.monotonic() >= limite:
            raise TimeoutError
        await asyncio.sleep(poll_delay_s)


async def _registrar_capas_antimalware(
    sesiones: Any,
    aplicacion_id: uuid.UUID,
    archivo_id: uuid.UUID,
    clamav: dict[str, Any],
    vt: dict[str, Any],
    destino: Estado,
    tipo_detectado: str | None,
    veredicto_cdr: Veredicto | None,
    duracion_cdr_ms: int,
) -> None:
    """Registra resultados de todas las capas y aplica la transición en una transacción."""
    async with sesiones.begin() as sesion:
        if veredicto_cdr is not None:
            firma_valida = veredicto_cdr.tipo in TIPOS_PERMITIDOS
            await registrar_resultado(
                sesion,
                aplicacion_id,
                archivo_id,
                "firma",
                LIMPIO if firma_valida else RECHAZADO,
                {"tipo": veredicto_cdr.tipo},
                None,
            )
            ver_cdr = (
                LIMPIO
                if veredicto_cdr.veredicto == LIMPIO
                else (RECHAZADO if firma_valida else _NO_EVALUADA)
            )
            await registrar_resultado(
                sesion,
                aplicacion_id,
                archivo_id,
                "cdr",
                ver_cdr,
                {"motivo": veredicto_cdr.motivo},
                duracion_cdr_ms,
            )
        if clamav["veredicto"] != _NO_EVALUADA or destino is Estado.EN_CUARENTENA:
            detalle_clam = {
                k: v for k, v in clamav.items() if k not in ("veredicto", "duracion_ms")
            }
            await registrar_resultado(
                sesion,
                aplicacion_id,
                archivo_id,
                "clamav",
                clamav["veredicto"],
                detalle_clam,
                clamav["duracion_ms"],
            )
        if (
            vt["veredicto"] != _NO_EVALUADA
            or destino is Estado.EN_CUARENTENA
            or vt.get("motivo")
            in ("presupuesto_vt", "sin_cuota", "sin_api_key", "vt_no_disponible")
        ):
            detalle_vt = {
                k: v for k, v in vt.items() if k not in ("veredicto", "duracion_ms")
            }
            await registrar_resultado(
                sesion,
                aplicacion_id,
                archivo_id,
                "virustotal",
                vt["veredicto"],
                detalle_vt,
                vt["duracion_ms"],
            )
        await cambiar_estado(
            sesion,
            aplicacion_id,
            archivo_id,
            Estado.PENDIENTE,
            destino,
            tipo_detectado=tipo_detectado or None,
            tipo_error="final" if destino is Estado.ERROR else None,
        )


async def _registrar_liberacion(
    sesiones: Any,
    aplicacion_id: uuid.UUID,
    archivo_id: uuid.UUID,
    destino: Estado,
    veredicto_cdr: Veredicto | None,
    duracion_cdr_ms: int,
    *,
    usuario: str,
    motivo: str,
) -> None:
    """Registra el re-CDR de liberación y aplica ``en_cuarentena -> destino`` (INV-08, K16, K19)."""
    async with sesiones.begin() as sesion:
        if veredicto_cdr is not None:
            firma_valida = veredicto_cdr.tipo in TIPOS_PERMITIDOS
            await registrar_resultado(
                sesion,
                aplicacion_id,
                archivo_id,
                "firma",
                LIMPIO if firma_valida else RECHAZADO,
                {"tipo": veredicto_cdr.tipo},
                None,
            )
            ver_cdr = (
                LIMPIO
                if veredicto_cdr.veredicto == LIMPIO
                else (RECHAZADO if firma_valida else _NO_EVALUADA)
            )
            await registrar_resultado(
                sesion,
                aplicacion_id,
                archivo_id,
                "cdr",
                ver_cdr,
                {"motivo": veredicto_cdr.motivo},
                duracion_cdr_ms,
            )
        await liberar_estado_archivo(
            sesion,
            aplicacion_id,
            archivo_id,
            destino,
            usuario=usuario,
            motivo=motivo,
            liberado_en=datetime.now(UTC),
            tipo_detectado=veredicto_cdr.tipo if veredicto_cdr else None,
            tipo_error="final" if destino is Estado.ERROR else None,
        )


async def orquestar(
    ctx: dict[str, Any],
    aplicacion_id_str: str,
    archivo_id_str: str,
    sha256: str = "",
    liberacion: bool = False,
    usuario_liberacion: str = "",
    motivo_liberacion: str = "",
) -> str:
    """Orquesta worker + reputation y consolida el veredicto en PostgreSQL (K01, K07, F4.07, D4)."""
    ajustes: AjustesCoordinador = ctx["ajustes"]
    sesiones = ctx["sesiones"]
    cola_queue = ctx["cola_queue"]
    cola_main = ctx["cola_main"]

    aplicacion_id = uuid.UUID(aplicacion_id_str)
    archivo_id = uuid.UUID(archivo_id_str)
    entrada = ajustes.uploads_tmp / str(archivo_id)
    final = ajustes.clean_store / str(archivo_id)
    cuarentena = ajustes.quarantine / str(archivo_id)
    inicio = time.perf_counter()

    def _duracion_ms() -> int:
        return round((time.perf_counter() - inicio) * 1000)

    confirmado = False
    estado_final = Estado.ERROR.value
    try:
        if liberacion:
            if not _copiar_desde_cuarentena(cuarentena, entrada):
                await _registrar_liberacion(
                    sesiones,
                    aplicacion_id,
                    archivo_id,
                    Estado.ERROR,
                    None,
                    _duracion_ms(),
                    usuario=usuario_liberacion,
                    motivo=motivo_liberacion,
                )
                return Estado.ERROR.value

            trabajo_worker = await cola_queue.enqueue_job(
                "analizar",
                str(archivo_id),
                True,
                _job_id=f"analizar:liberar:{archivo_id}:{uuid.uuid4().hex[:8]}",
                _queue_name=COLA_ANALIZAR,
            )
            if trabajo_worker is None:
                raise RuntimeError("job duplicado en redis-queue")
            try:
                bruto = await _esperar_resultado(
                    trabajo_worker,
                    ajustes.timeout_worker_s,
                    ajustes.poll_delay_s,
                )
            except TimeoutError:
                _borrar(final)
                await _registrar_liberacion(
                    sesiones,
                    aplicacion_id,
                    archivo_id,
                    Estado.ERROR,
                    None,
                    _duracion_ms(),
                    usuario=usuario_liberacion,
                    motivo=motivo_liberacion,
                )
                return Estado.ERROR.value

            categoria, veredicto, duracion_ms, _motivo_err = validar_resultado_worker(
                bruto
            )
            if categoria == LIMPIO and veredicto is not None:
                problema = _verificar_salida_limpia(final)
                if problema == _MOTIVO_SALIDA_GRANDE:
                    _borrar(final)
                    veredicto = Veredicto(
                        RECHAZADO, veredicto.tipo, _MOTIVO_SALIDA_GRANDE
                    )
                    destino_lib = Estado.RECHAZADO
                elif problema is not None:
                    _borrar(final)
                    destino_lib = Estado.ERROR
                else:
                    destino_lib = Estado.LIMPIO
            elif categoria == RECHAZADO and veredicto is not None:
                _borrar(final)
                destino_lib = Estado.RECHAZADO
            else:
                _borrar(final)
                destino_lib = Estado.ERROR

            await _registrar_liberacion(
                sesiones,
                aplicacion_id,
                archivo_id,
                destino_lib,
                veredicto,
                duracion_ms or _duracion_ms(),
                usuario=usuario_liberacion,
                motivo=motivo_liberacion,
            )
            if destino_lib is Estado.LIMPIO:
                _borrar(cuarentena)
            confirmado = True
            estado_final = destino_lib.value
            return estado_final

        # Encolar worker y reputation en paralelo (D1, K01).
        trabajo_worker = await cola_queue.enqueue_job(
            "analizar",
            str(archivo_id),
            _job_id=f"analizar:{archivo_id}",
            _queue_name=COLA_ANALIZAR,
        )
        if trabajo_worker is None:
            raise RuntimeError("job duplicado en redis-queue")

        trabajo_vt: Job | None = None
        if ajustes.consultar_reputacion and sha256:
            with contextlib.suppress(Exception):
                trabajo_vt = await cola_main.enqueue_job(
                    "consultar_hash",
                    sha256,
                    _job_id=f"vt:{archivo_id}",
                    _queue_name=COLA_REPUTACION,
                )

        try:
            bruto = await _esperar_resultado(
                trabajo_worker,
                ajustes.timeout_worker_s,
                ajustes.poll_delay_s,
            )
        except TimeoutError:
            _borrar(final)
            await analisis._registrar_error(
                sesiones,
                aplicacion_id,
                archivo_id,
                _MOTIVO_TIMEOUT_WORKER,
                _duracion_ms(),
            )
            return Estado.ERROR.value

        # K07: presupuesto máximo de 1 s tras terminar el worker para VirusTotal.
        res_vt: dict[str, Any] = {
            "veredicto": _NO_EVALUADA,
            "motivo": "no_solicitada",
            "duracion_ms": 0,
        }
        if trabajo_vt is not None:
            try:
                bruto_vt = await _esperar_resultado(
                    trabajo_vt,
                    ajustes.presupuesto_vt_s,
                    ajustes.poll_delay_s,
                )
                res_vt = _validar_capa_antimalware(bruto_vt)
            except (TimeoutError, Exception):  # noqa: BLE001
                res_vt = {
                    "veredicto": _NO_EVALUADA,
                    "motivo": "presupuesto_vt",
                    "duracion_ms": round(ajustes.presupuesto_vt_s * 1000),
                }

        res_clamav = (
            _validar_capa_antimalware(bruto.get("clamav"))
            if isinstance(bruto, dict) and "clamav" in bruto
            else {"veredicto": _NO_EVALUADA, "motivo": "no_evaluada", "duracion_ms": 0}
        )
        categoria, veredicto, duracion_ms, motivo_error = validar_resultado_worker(
            bruto
        )

        # Prioridad F4.07: en_cuarentena > rechazado > error > limpio.
        destino = decidir(categoria, res_clamav["veredicto"], res_vt["veredicto"])

        if destino is Estado.EN_CUARENTENA:
            _borrar(final)
            _asegurar_en_cuarentena(entrada, cuarentena)
            await _registrar_capas_antimalware(
                sesiones,
                aplicacion_id,
                archivo_id,
                res_clamav,
                res_vt,
                Estado.EN_CUARENTENA,
                veredicto.tipo if veredicto else None,
                veredicto,
                duracion_ms or _duracion_ms(),
            )
            confirmado = True
            estado_final = Estado.EN_CUARENTENA.value
            return estado_final

        if destino is Estado.ERROR or veredicto is None:
            _borrar(final)
            motivo = (
                res_clamav["motivo"]
                if res_clamav["veredicto"] == _ERROR
                else (motivo_error or _MOTIVO_INTERNO)
            )
            await analisis._registrar_error(
                sesiones,
                aplicacion_id,
                archivo_id,
                motivo,
                duracion_ms or _duracion_ms(),
            )
            return Estado.ERROR.value

        if destino is Estado.LIMPIO:
            problema = _verificar_salida_limpia(final)
            if problema == _MOTIVO_SALIDA_GRANDE:
                _borrar(final)
                veredicto = Veredicto(RECHAZADO, veredicto.tipo, _MOTIVO_SALIDA_GRANDE)
                destino = Estado.RECHAZADO
            elif problema is not None:
                _borrar(final)
                await analisis._registrar_error(
                    sesiones, aplicacion_id, archivo_id, problema, duracion_ms
                )
                return Estado.ERROR.value

        hay_antimalware = (
            res_clamav["veredicto"] != _NO_EVALUADA
            or res_vt["veredicto"] != _NO_EVALUADA
            or trabajo_vt is not None
        )
        if hay_antimalware:
            await _registrar_capas_antimalware(
                sesiones,
                aplicacion_id,
                archivo_id,
                res_clamav,
                res_vt,
                destino,
                veredicto.tipo,
                veredicto,
                duracion_ms,
            )
        else:
            await analisis._registrar_veredicto(
                sesiones, aplicacion_id, archivo_id, veredicto, duracion_ms
            )
        confirmado = True
        estado_final = destino.value
        return estado_final
    except Exception as error:  # noqa: BLE001
        logger.warning(
            "Orquestación de %s terminó en error (%s)",
            archivo_id,
            type(error).__name__,
        )
        _borrar(final)
        await analisis._registrar_error(
            sesiones, aplicacion_id, archivo_id, _MOTIVO_INTERNO, _duracion_ms()
        )
        return Estado.ERROR.value
    finally:
        if not confirmado:
            _borrar(final)
        _borrar(entrada)
        await _publicar_evento(
            cola_main, sesiones, archivo_id, estado_final, liberacion=liberacion
        )


def crear_coordinador(
    ajustes: AjustesCoordinador,
    *,
    handle_signals: bool = True,
    barrer_al_arrancar: bool = True,
) -> WorkerSinInfo:
    """Construye el ``Worker`` de ARQ del ``coordinator`` sobre ``redis-main``."""
    cola_main = abrir_cola(
        ajustes.url_redis,
        cola=COLA_ORQUESTAR,
        nombre_variable=VARIABLE_REDIS,
        max_conexiones=max(16, ajustes.max_jobs * 2),
    )
    cola_queue = abrir_cola(
        ajustes.url_redis_queue,
        cola=COLA_ANALIZAR,
        nombre_variable=VARIABLE_REDIS_QUEUE,
        max_conexiones=max(16, ajustes.max_jobs * 2),
    )
    motor = abrir_motor(ajustes.url_bd)
    sesiones = fabrica_sesiones(motor)

    async def al_arrancar(_ctx: dict[str, Any]) -> None:
        if barrer_al_arrancar:
            await barrer_restos(ajustes, sesiones)

    async def al_apagar(_ctx: dict[str, Any]) -> None:
        await motor.dispose()
        await cerrar_cola(cola_queue)

    return WorkerSinInfo(
        functions=[func(orquestar, name="orquestar")],
        queue_name=COLA_ORQUESTAR,
        redis_pool=cola_main,
        on_startup=al_arrancar,
        on_shutdown=al_apagar,
        handle_signals=handle_signals,
        max_jobs=ajustes.max_jobs,
        job_timeout=TIMEOUT_JOB_COORDINATOR_S,
        keep_result=60,
        poll_delay=ajustes.poll_delay_s,
        health_check_key="gk:salud:coordinator",
        max_tries=1,
        retry_jobs=False,
        job_serializer=serializar_json,
        job_deserializer=deserializar_json,
        ctx={
            "ajustes": ajustes,
            "sesiones": sesiones,
            "cola_main": cola_main,
            "cola_queue": cola_queue,
        },
        log_results=False,
    )


def main() -> int:
    proteger_proceso()
    comprobar_ancestros()
    ajustes = leer_ajustes_coordinador()

    async def _correr() -> None:
        coordinador = crear_coordinador(ajustes, handle_signals=True)
        await coordinador.async_run()

    asyncio.run(_correr())
    return 0


if __name__ == "__main__":
    sys.exit(main())
