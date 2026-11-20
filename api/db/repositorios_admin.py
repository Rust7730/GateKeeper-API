"""Repositorios de administración: usuarios, refresh tokens, bitácora y consultas del dashboard (F5, K20, K21)."""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import (
    String,
    and_,
    case,
    cast,
    exists,
    func,
    or_,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncSession

from api.app.estados import Estado, TransicionInvalida, transicionar
from api.db.modelos import (
    ApiKey,
    Aplicacion,
    Archivo,
    EventoAuditoria,
    RefreshToken,
    ResultadoAnalisis,
    Usuario,
)
from api.db.repositorios import (
    _CDR_LIMPIO,
    _COLUMNAS_ARCHIVO,
    ArchivoNoEncontrado,
    ConflictoDeEstado,
    DatosArchivo,
    SinEvidenciaCDR,
    _a_datos_archivo,
    _escribir,
    crear_aplicacion,
    obtener_archivo,
)

# Días de retención en cuarentena (F4.09 / backend.dto.ts).
DIAS_CUARENTENA = 30

# K20: condición SQL que determina si un archivo puede divulgar nombre_original, sha256 y resultados.
_ES_DIVULGABLE_K20 = or_(
    Archivo.estado == Estado.EN_CUARENTENA.value,
    exists().where(
        ResultadoAnalisis.archivo_id == Archivo.id,
        ResultadoAnalisis.veredicto == "malicioso",
    ),
)


@dataclass(frozen=True, slots=True)
class DatosUsuario:
    id: uuid.UUID
    email: str
    hash_password: str
    rol: str
    totp_secreto_cifrado: bytes | None
    activo: bool


@dataclass(frozen=True, slots=True)
class DatosRefreshToken:
    jti: uuid.UUID
    usuario_id: uuid.UUID
    familia: uuid.UUID
    expira_en: datetime
    revocado: bool


@dataclass(frozen=True, slots=True)
class ResultadoCapaAdmin:
    capa: str
    veredicto: str
    detalle: dict[str, object]
    duracion_ms: int | None


@dataclass(frozen=True, slots=True)
class ArchivoAdmin:
    id: uuid.UUID
    aplicacion_id: uuid.UUID
    aplicacion_nombre: str
    estado: str
    tipo_detectado: str | None
    tamano_bytes: int
    creado_en: datetime
    analizado_en: datetime | None
    divulgable: bool
    nombre_original: str | None = None
    sha256: str | None = None
    cuarentena_expira_en: datetime | None = None
    resultados: tuple[ResultadoCapaAdmin, ...] = ()


@dataclass(frozen=True, slots=True)
class AuditoriaAdmin:
    id: int
    actor_id: uuid.UUID | None
    actor_correo: str
    actor_rol: str
    accion: str
    recurso: str | None
    motivo: str | None
    ip: str
    en: datetime


@dataclass(frozen=True, slots=True)
class ApiKeyAdmin:
    id: uuid.UUID
    aplicacion_id: uuid.UUID
    aplicacion_nombre: str
    prefijo: str
    creada_en: datetime
    revocada_en: datetime | None


@dataclass(frozen=True, slots=True)
class AplicacionAdmin:
    id: uuid.UUID
    nombre: str
    activa: bool
    creada_en: datetime


def _a_datos_usuario(fila: Usuario) -> DatosUsuario:
    return DatosUsuario(
        id=fila.id,
        email=fila.email,
        hash_password=fila.hash_password,
        rol=fila.rol,
        totp_secreto_cifrado=fila.totp_secreto_cifrado,
        activo=fila.activo,
    )


async def crear_usuario(
    sesion: AsyncSession,
    *,
    email: str,
    hash_password: str,
    rol: str,
    totp_secreto_cifrado: bytes | None = None,
) -> uuid.UUID:
    usuario = Usuario(
        email=email,
        hash_password=hash_password,
        rol=rol,
        totp_secreto_cifrado=totp_secreto_cifrado,
    )
    sesion.add(usuario)
    await sesion.flush()
    return usuario.id


async def obtener_usuario_por_email(
    sesion: AsyncSession, email: str
) -> DatosUsuario | None:
    fila = await sesion.scalar(
        select(Usuario).where(func.lower(Usuario.email) == email.lower())
    )
    return None if fila is None else _a_datos_usuario(fila)


async def obtener_usuario_por_id(
    sesion: AsyncSession, usuario_id: uuid.UUID
) -> DatosUsuario | None:
    fila = await sesion.scalar(select(Usuario).where(Usuario.id == usuario_id))
    return None if fila is None else _a_datos_usuario(fila)


async def actualizar_totp_usuario(
    sesion: AsyncSession, usuario_id: uuid.UUID, totp_secreto_cifrado: bytes
) -> None:
    await sesion.execute(
        update(Usuario)
        .where(Usuario.id == usuario_id)
        .values(totp_secreto_cifrado=totp_secreto_cifrado)
    )


async def crear_refresh_token(
    sesion: AsyncSession,
    *,
    jti: uuid.UUID,
    usuario_id: uuid.UUID,
    familia: uuid.UUID,
    expira_en: datetime,
) -> None:
    sesion.add(
        RefreshToken(
            jti=jti,
            usuario_id=usuario_id,
            familia=familia,
            expira_en=expira_en,
            revocado=False,
        )
    )
    await sesion.flush()


async def obtener_refresh_token_para_rotar(
    sesion: AsyncSession, jti: uuid.UUID
) -> DatosRefreshToken | None:
    fila = await sesion.scalar(
        select(RefreshToken).where(RefreshToken.jti == jti).with_for_update()
    )
    if fila is None:
        return None
    return DatosRefreshToken(
        jti=fila.jti,
        usuario_id=fila.usuario_id,
        familia=fila.familia,
        expira_en=fila.expira_en,
        revocado=fila.revocado,
    )


async def marcar_refresh_revocado(sesion: AsyncSession, jti: uuid.UUID) -> None:
    await sesion.execute(
        update(RefreshToken).where(RefreshToken.jti == jti).values(revocado=True)
    )


async def revocar_familia_refresh(sesion: AsyncSession, familia: uuid.UUID) -> None:
    await sesion.execute(
        update(RefreshToken)
        .where(RefreshToken.familia == familia)
        .values(revocado=True)
    )


async def registrar_evento_auditoria(
    sesion: AsyncSession,
    *,
    usuario_id: uuid.UUID | None,
    accion: str,
    objetivo_id: uuid.UUID | None = None,
    motivo: str | None = None,
    ip: str | None = None,
) -> int:
    evento = EventoAuditoria(
        usuario_id=usuario_id,
        accion=accion,
        objetivo_id=objetivo_id,
        motivo=motivo,
        ip=ip,
    )
    sesion.add(evento)
    await sesion.flush()
    return evento.id


# ------------------------------------------------------------------ liberación (F5.06, K16, K19)


async def liberar_estado_archivo(
    sesion: AsyncSession,
    aplicacion_id: uuid.UUID,
    archivo_id: uuid.UUID,
    nuevo: Estado,
    *,
    usuario: str,
    motivo: str,
    liberado_en: datetime,
    tipo_detectado: str | None = None,
    tipo_error: str | None = None,
) -> DatosArchivo:
    """Aplica la transición ``en_cuarentena -> limpio | rechazado | error`` tras re-CDR (D4, INV-08, K16)."""
    contexto: dict[str, object] = {
        "usuario": usuario,
        "motivo": motivo,
        "liberado_en": liberado_en,
    }
    if tipo_error is not None:
        contexto["tipo_error"] = tipo_error
    transicionar(Estado.EN_CUARENTENA, nuevo, **contexto)
    if (nuevo is Estado.ERROR) != (tipo_error is not None):
        raise TransicionInvalida(
            "tipo_error se indica solo y siempre al entrar a error"
        )

    valores: dict[str, Any] = {
        "estado": nuevo.value,
        "analizado_en": func.clock_timestamp(),
    }
    if tipo_detectado is not None:
        valores["tipo_detectado"] = tipo_detectado
    if tipo_error is not None:
        valores["tipo_error"] = tipo_error

    condiciones = [
        Archivo.id == archivo_id,
        Archivo.aplicacion_id == aplicacion_id,
        Archivo.estado == Estado.EN_CUARENTENA.value,
    ]
    if nuevo is Estado.LIMPIO:
        condiciones.append(_CDR_LIMPIO)

    sentencia = (
        update(Archivo)
        .where(*condiciones)
        .values(**valores)
        .returning(*_COLUMNAS_ARCHIVO)
        .execution_options(synchronize_session=False)
    )
    fila = (await _escribir(sesion, sentencia)).one_or_none()
    if fila is not None:
        return _a_datos_archivo(fila)

    leido = await obtener_archivo(sesion, aplicacion_id, archivo_id)
    if leido is None:
        raise ArchivoNoEncontrado
    if nuevo is Estado.LIMPIO and leido.estado is Estado.EN_CUARENTENA:
        raise SinEvidenciaCDR
    raise ConflictoDeEstado


# ---------------------------------------------------------------------- consultas del dashboard


def _escapar_like(texto: str) -> str:
    return texto.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def _cargar_resultados_por_archivo(
    sesion: AsyncSession, ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[ResultadoCapaAdmin, ...]]:
    if not ids:
        return {}
    filas = (
        await sesion.execute(
            select(
                ResultadoAnalisis.archivo_id,
                ResultadoAnalisis.capa,
                ResultadoAnalisis.veredicto,
                ResultadoAnalisis.detalle,
                ResultadoAnalisis.duracion_ms,
            )
            .where(ResultadoAnalisis.archivo_id.in_(ids))
            .order_by(ResultadoAnalisis.id.asc())
        )
    ).all()
    agrupado: dict[uuid.UUID, list[ResultadoCapaAdmin]] = {}
    for f in filas:
        agrupado.setdefault(f.archivo_id, []).append(
            ResultadoCapaAdmin(
                capa=f.capa,
                veredicto=f.veredicto,
                detalle=dict(f.detalle or {}),
                duracion_ms=f.duracion_ms,
            )
        )
    return {k: tuple(v) for k, v in agrupado.items()}


def _construir_archivo_admin(
    fila: Any,
    resultados_por_archivo: dict[uuid.UUID, tuple[ResultadoCapaAdmin, ...]],
) -> ArchivoAdmin:
    divulgable = bool(fila.divulgable)
    if not divulgable:
        return ArchivoAdmin(
            id=fila.id,
            aplicacion_id=fila.aplicacion_id,
            aplicacion_nombre=fila.aplicacion_nombre,
            estado=fila.estado,
            tipo_detectado=fila.tipo_detectado,
            tamano_bytes=fila.tamano_bytes,
            creado_en=fila.creado_en,
            analizado_en=fila.analizado_en,
            divulgable=False,
        )
    expira: datetime | None = None
    if fila.estado == Estado.EN_CUARENTENA.value:
        base = fila.analizado_en or fila.creado_en
        expira = base + timedelta(days=DIAS_CUARENTENA)
    return ArchivoAdmin(
        id=fila.id,
        aplicacion_id=fila.aplicacion_id,
        aplicacion_nombre=fila.aplicacion_nombre,
        estado=fila.estado,
        tipo_detectado=fila.tipo_detectado,
        tamano_bytes=fila.tamano_bytes,
        creado_en=fila.creado_en,
        analizado_en=fila.analizado_en,
        divulgable=True,
        nombre_original=fila.nombre_original,
        sha256=fila.sha256,
        cuarentena_expira_en=expira,
        resultados=resultados_por_archivo.get(fila.id, ()),
    )


async def obtener_archivo_admin(
    sesion: AsyncSession, archivo_id: uuid.UUID
) -> ArchivoAdmin | None:
    sentencia = (
        select(
            Archivo.id,
            Archivo.aplicacion_id,
            Aplicacion.nombre.label("aplicacion_nombre"),
            Archivo.estado,
            Archivo.tipo_detectado,
            Archivo.tamano_bytes,
            Archivo.creado_en,
            Archivo.analizado_en,
            Archivo.nombre_original,
            Archivo.sha256,
            _ES_DIVULGABLE_K20.label("divulgable"),
        )
        .join(Aplicacion, Aplicacion.id == Archivo.aplicacion_id)
        .where(Archivo.id == archivo_id)
    )
    fila = (await sesion.execute(sentencia)).one_or_none()
    if fila is None:
        return None
    resultados = (
        await _cargar_resultados_por_archivo(sesion, [fila.id])
        if fila.divulgable
        else {}
    )
    return _construir_archivo_admin(fila, resultados)


async def listar_archivos_admin(
    sesion: AsyncSession,
    *,
    estados: list[str] | None = None,
    aplicacion_id: uuid.UUID | None = None,
    desde: datetime | None = None,
    hasta: datetime | None = None,
    q: str | None = None,
    orden: str = "creado_en",
    direccion: str = "desc",
    pagina: int = 1,
    tamano_pagina: int = 25,
) -> tuple[list[ArchivoAdmin], int]:
    condiciones: list[Any] = []
    if estados:
        condiciones.append(Archivo.estado.in_(estados))
    if aplicacion_id is not None:
        condiciones.append(Archivo.aplicacion_id == aplicacion_id)
    if desde is not None:
        condiciones.append(Archivo.creado_en >= desde)
    if hasta is not None:
        condiciones.append(Archivo.creado_en <= hasta)
    if q is not None and q.strip():
        patron = _escapar_like(q.strip())
        # K20 anti-oráculo: prefijo de UUID en todos; nombre_original y sha256 SOLO en divulgables.
        condiciones.append(
            or_(
                cast(Archivo.id, String).ilike(f"{patron}%", escape="\\"),
                and_(
                    _ES_DIVULGABLE_K20,
                    or_(
                        Archivo.nombre_original.ilike(f"%{patron}%", escape="\\"),
                        Archivo.sha256.ilike(f"{patron}%", escape="\\"),
                    ),
                ),
            )
        )

    total = (
        await sesion.execute(
            select(func.count()).select_from(Archivo).where(*condiciones)
        )
    ).scalar_one()

    col_orden = {
        "creado_en": Archivo.creado_en,
        "tamano_bytes": Archivo.tamano_bytes,
        "estado": Archivo.estado,
    }.get(orden, Archivo.creado_en)
    orden_expr = col_orden.asc() if direccion == "asc" else col_orden.desc()

    sentencia = (
        select(
            Archivo.id,
            Archivo.aplicacion_id,
            Aplicacion.nombre.label("aplicacion_nombre"),
            Archivo.estado,
            Archivo.tipo_detectado,
            Archivo.tamano_bytes,
            Archivo.creado_en,
            Archivo.analizado_en,
            Archivo.nombre_original,
            Archivo.sha256,
            _ES_DIVULGABLE_K20.label("divulgable"),
        )
        .join(Aplicacion, Aplicacion.id == Archivo.aplicacion_id)
        .where(*condiciones)
        .order_by(orden_expr, Archivo.id.desc())
        .offset((pagina - 1) * tamano_pagina)
        .limit(tamano_pagina)
    )
    filas = (await sesion.execute(sentencia)).all()
    ids_divulgables = [f.id for f in filas if f.divulgable]
    resultados = await _cargar_resultados_por_archivo(sesion, ids_divulgables)
    return [_construir_archivo_admin(f, resultados) for f in filas], int(total)


async def obtener_metricas_admin(sesion: AsyncSession, periodo: str) -> dict[str, Any]:
    deltas = {
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    desde = datetime.now(UTC) - deltas[periodo]

    # 1. Totales por estado
    filas_estado = (
        await sesion.execute(
            select(Archivo.estado, func.count())
            .where(Archivo.creado_en >= desde)
            .group_by(Archivo.estado)
        )
    ).all()
    totales: dict[str, int] = {e.value: 0 for e in Estado}
    for est, cuenta in filas_estado:
        if est in totales:
            totales[est] = int(cuenta)
    totales["procesados"] = (
        totales["limpio"]
        + totales["en_cuarentena"]
        + totales["rechazado"]
        + totales["error"]
    )

    # 2. Amenazas por día
    dia_col = func.date_trunc("day", Archivo.creado_en)
    filas_dia = (
        await sesion.execute(
            select(
                dia_col.label("dia"),
                func.sum(
                    case(
                        (
                            Archivo.estado.in_(
                                [Estado.RECHAZADO.value, Estado.EN_CUARENTENA.value]
                            ),
                            1,
                        ),
                        else_=0,
                    )
                ).label("bloqueados"),
                func.sum(
                    case((Archivo.estado == Estado.EN_CUARENTENA.value, 1), else_=0)
                ).label("en_cuarentena"),
            )
            .where(Archivo.creado_en >= desde)
            .group_by(dia_col)
            .order_by(dia_col.asc())
        )
    ).all()
    amenazas_por_dia = [
        {
            "fecha": f.dia.date().isoformat(),
            "bloqueados": int(f.bloqueados or 0),
            "en_cuarentena": int(f.en_cuarentena or 0),
        }
        for f in filas_dia
    ]

    # 3. Bloqueos por capa y motivo
    motivo_col = ResultadoAnalisis.detalle["motivo"].astext
    filas_capa = (
        await sesion.execute(
            select(
                ResultadoAnalisis.capa,
                motivo_col.label("motivo"),
                func.count().label("total"),
            )
            .join(Archivo, Archivo.id == ResultadoAnalisis.archivo_id)
            .where(
                Archivo.creado_en >= desde,
                ResultadoAnalisis.veredicto.in_(["malicioso", "rechazado"]),
            )
            .group_by(ResultadoAnalisis.capa, motivo_col)
            .order_by(func.count().desc())
        )
    ).all()
    por_capa = [
        {"capa": f.capa, "motivo": f.motivo, "total": int(f.total)} for f in filas_capa
    ]

    # 4. Top aplicaciones con bloqueos
    filas_apps = (
        await sesion.execute(
            select(
                Aplicacion.id,
                Aplicacion.nombre,
                func.count().label("bloqueados"),
            )
            .join(Archivo, Archivo.aplicacion_id == Aplicacion.id)
            .where(
                Archivo.creado_en >= desde,
                Archivo.estado.in_(
                    [Estado.RECHAZADO.value, Estado.EN_CUARENTENA.value]
                ),
            )
            .group_by(Aplicacion.id, Aplicacion.nombre)
            .order_by(func.count().desc())
            .limit(5)
        )
    ).all()
    top_apps = [
        {
            "aplicacion_id": str(f.id),
            "aplicacion_nombre": f.nombre,
            "bloqueados": int(f.bloqueados),
        }
        for f in filas_apps
    ]

    return {
        "periodo": periodo,
        "totales": totales,
        "amenazas_por_dia": amenazas_por_dia,
        "por_capa": por_capa,
        "top_apps": top_apps,
    }


async def listar_auditoria_admin(
    sesion: AsyncSession, *, pagina: int = 1, tamano_pagina: int = 50
) -> tuple[list[AuditoriaAdmin], int]:
    total = (
        await sesion.execute(select(func.count()).select_from(EventoAuditoria))
    ).scalar_one()
    filas = (
        await sesion.execute(
            select(
                EventoAuditoria.id,
                EventoAuditoria.usuario_id,
                Usuario.email,
                Usuario.rol,
                EventoAuditoria.accion,
                EventoAuditoria.objetivo_id,
                EventoAuditoria.motivo,
                EventoAuditoria.ip,
                EventoAuditoria.fecha,
            )
            .outerjoin(Usuario, Usuario.id == EventoAuditoria.usuario_id)
            .order_by(EventoAuditoria.id.desc())
            .offset((pagina - 1) * tamano_pagina)
            .limit(tamano_pagina)
        )
    ).all()
    elementos = [
        AuditoriaAdmin(
            id=f.id,
            actor_id=f.usuario_id,
            actor_correo=f.email or "sistema",
            actor_rol=f.rol or "admin",
            accion=f.accion,
            recurso=str(f.objetivo_id) if f.objetivo_id is not None else None,
            motivo=f.motivo,
            ip=str(f.ip) if f.ip is not None else "",
            en=f.fecha,
        )
        for f in filas
    ]
    return elementos, int(total)


async def listar_api_keys_admin(sesion: AsyncSession) -> list[ApiKeyAdmin]:
    filas = (
        await sesion.execute(
            select(
                ApiKey.id,
                ApiKey.aplicacion_id,
                Aplicacion.nombre.label("aplicacion_nombre"),
                ApiKey.prefijo,
                ApiKey.creada_en,
                ApiKey.revocada_en,
            )
            .join(Aplicacion, Aplicacion.id == ApiKey.aplicacion_id)
            .order_by(ApiKey.creada_en.desc())
        )
    ).all()
    return [
        ApiKeyAdmin(
            id=f.id,
            aplicacion_id=f.aplicacion_id,
            aplicacion_nombre=f.aplicacion_nombre,
            prefijo=f.prefijo,
            creada_en=f.creada_en,
            revocada_en=f.revocada_en,
        )
        for f in filas
    ]


async def revocar_api_key(sesion: AsyncSession, key_id: uuid.UUID) -> bool:
    res = await sesion.execute(
        update(ApiKey)
        .where(ApiKey.id == key_id, ApiKey.revocada_en.is_(None))
        .values(revocada_en=func.clock_timestamp())
        .returning(ApiKey.id)
    )
    return res.scalar_one_or_none() is not None


async def obtener_aplicacion_por_id(
    sesion: AsyncSession, aplicacion_id: uuid.UUID
) -> AplicacionAdmin | None:
    fila = await sesion.scalar(select(Aplicacion).where(Aplicacion.id == aplicacion_id))
    if fila is None:
        return None
    return AplicacionAdmin(
        id=fila.id, nombre=fila.nombre, activa=fila.activa, creada_en=fila.creada_en
    )


async def obtener_o_crear_aplicacion(
    sesion: AsyncSession, nombre: str
) -> AplicacionAdmin:
    fila = await sesion.scalar(
        select(Aplicacion).where(func.lower(Aplicacion.nombre) == nombre.lower())
    )
    if fila is not None:
        return AplicacionAdmin(
            id=fila.id,
            nombre=fila.nombre,
            activa=fila.activa,
            creada_en=fila.creada_en,
        )
    app_id = await crear_aplicacion(sesion, nombre)
    creada = await obtener_aplicacion_por_id(sesion, app_id)
    assert creada is not None
    return creada


async def listar_aplicaciones_admin(sesion: AsyncSession) -> list[AplicacionAdmin]:
    filas = (
        await sesion.execute(select(Aplicacion).order_by(Aplicacion.nombre.asc()))
    ).scalars()
    return [
        AplicacionAdmin(
            id=f.id, nombre=f.nombre, activa=f.activa, creada_en=f.creada_en
        )
        for f in filas
    ]


async def obtener_metadatos_evento(
    sesion: AsyncSession, archivo_id: uuid.UUID
) -> tuple[str | None, str | None]:
    """Devuelve ``(aplicacion_nombre, nombre_original)`` para publicar ``EventoDto``."""
    fila = (
        await sesion.execute(
            select(Aplicacion.nombre, Archivo.nombre_original)
            .join(Aplicacion, Aplicacion.id == Archivo.aplicacion_id)
            .where(Archivo.id == archivo_id)
        )
    ).one_or_none()
    if fila is None:
        return None, None
    return fila.nombre, fila.nombre_original
