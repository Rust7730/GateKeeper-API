"""Máquina de estados del archivo (F2.04): dominio puro, sin E/S.

Tabla de transiciones (docs/decisiones.md §4)::

    pendiente     -> limpio | en_cuarentena | rechazado | error
    error         -> pendiente                 reintento de un error transitorio, máx. 2 (K11, K14, K17)
    en_cuarentena -> limpio | rechazado | error  liberación por admin: usuario, motivo, liberado_en (INV-08)

Toda transición pasa por `transicionar`, que la valida. Solo `limpio` es descargable (INV-06); de aquí sale el
409 del endpoint de descarga. Un `error` nunca llega a `limpio` (INV-09).

Pendientes de confirmar y NO aplicadas aquí: K15 (tipos estrictos), K16 (evidencia del análisis en
`pendiente -> *`) y K24 (`resultado_cdr` coincidente y rechazo de claves extra en la liberación). Las claves de
contexto que esta versión no usa se ignoran.
"""

from collections.abc import Callable, Mapping
from datetime import datetime
from enum import StrEnum, unique
from types import MappingProxyType


@unique
class Estado(StrEnum):
    PENDIENTE = "pendiente"
    LIMPIO = "limpio"
    EN_CUARENTENA = "en_cuarentena"
    RECHAZADO = "rechazado"
    ERROR = "error"


ESTADO_INICIAL = Estado.PENDIENTE

# param:max_reintentos (confirmado): 2 reintentos automáticos, solo para errores transitorios (K11).
MAX_REINTENTOS = 2
TIPOS_ERROR = frozenset(
    {"transitorio", "final"}
)  # CHECK de archivo.tipo_error (K14, parte BD)


class TransicionInvalida(Exception):
    """El cambio de estado no está en la tabla o su contexto no lo autoriza."""


def es_descargable(estado: object) -> bool:
    """True solo para el miembro `Estado.LIMPIO` (INV-06). Cualquier otro valor, incluido el texto, da False."""
    return estado is Estado.LIMPIO


# ------------------------------------------------------------------------------------- validadores de contexto
# Devuelven el motivo del rechazo (sin datos del contexto, por si llega a un log) o None si el contexto vale.

type _Validador = Callable[[Mapping[str, object]], str | None]


def _sin_requisitos(_contexto: Mapping[str, object]) -> str | None:
    return None


def _entrada_a_error(contexto: Mapping[str, object]) -> str | None:
    """`tipo_error` es opcional al entrar a error; si viene, debe ser transitorio | final."""
    if "tipo_error" in contexto and not _es_tipo_error(contexto["tipo_error"]):
        return "tipo_error desconocido"
    return None


def _reintento(contexto: Mapping[str, object]) -> str | None:
    """K11 + K14 + K17: solo un error transitorio con reintentos (int) en [0, MAX_REINTENTOS)."""
    tipo_error = contexto.get("tipo_error")
    if not _es_tipo_error(tipo_error) or tipo_error != "transitorio":
        return "solo se reintenta un error transitorio"
    reintentos = contexto.get("reintentos")
    # type() y no isinstance(): bool es subclase de int y True colaría como 1.
    if type(reintentos) is not int or not 0 <= reintentos < MAX_REINTENTOS:
        return "reintentos fuera de rango"
    return None


def _liberacion(contexto: Mapping[str, object]) -> str | None:
    """INV-08 / D4: liberación con usuario y motivo no vacíos y liberado_en datetime con zona horaria."""
    if not _texto_no_vacio(contexto.get("usuario")):
        return "liberación sin usuario"
    if not _texto_no_vacio(contexto.get("motivo")):
        return "liberación sin motivo"
    liberado_en = contexto.get("liberado_en")
    if not isinstance(liberado_en, datetime) or liberado_en.utcoffset() is None:
        return "liberado_en debe ser un datetime con zona horaria"
    return None


def _es_tipo_error(valor: object) -> bool:
    return type(valor) is str and valor in TIPOS_ERROR


def _texto_no_vacio(valor: object) -> bool:
    return isinstance(valor, str) and bool(valor.strip())


_TRANSICIONES: Mapping[tuple[Estado, Estado], _Validador] = MappingProxyType(
    {
        (Estado.PENDIENTE, Estado.LIMPIO): _sin_requisitos,
        (Estado.PENDIENTE, Estado.EN_CUARENTENA): _sin_requisitos,
        (Estado.PENDIENTE, Estado.RECHAZADO): _sin_requisitos,
        (Estado.PENDIENTE, Estado.ERROR): _entrada_a_error,
        (Estado.ERROR, Estado.PENDIENTE): _reintento,
        (Estado.EN_CUARENTENA, Estado.LIMPIO): _liberacion,
        (Estado.EN_CUARENTENA, Estado.RECHAZADO): _liberacion,
        (Estado.EN_CUARENTENA, Estado.ERROR): _liberacion,
    }
)


def transicionar(actual: Estado, nuevo: Estado, **contexto: object) -> Estado:
    """Valida el cambio `actual -> nuevo` y devuelve el miembro `nuevo`.

    Lanza `TransicionInvalida` (y ninguna otra excepción) si el cambio no está en la tabla, si `actual` o
    `nuevo` no son miembros de `Estado`, o si el contexto no lo autoriza.
    """
    if not isinstance(actual, Estado) or not isinstance(nuevo, Estado):
        raise TransicionInvalida("estado desconocido")
    validador = _TRANSICIONES.get((actual, nuevo))
    if validador is None:
        raise TransicionInvalida(
            f"transición no permitida: {actual.value} -> {nuevo.value}"
        )
    try:
        motivo = validador(contexto)
    # Sin lista cerrada posible: un tzinfo hostil lanza lo que quiera en utcoffset(); falla cerrado (INV-09).
    except Exception:  # noqa: BLE001
        motivo = "contexto inválido"
    if motivo is not None:
        raise TransicionInvalida(f"{actual.value} -> {nuevo.value}: {motivo}")
    return nuevo
