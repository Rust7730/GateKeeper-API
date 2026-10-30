"""vec:15 — Descarga de un archivo en estado `pendiente` (F2.04, dominio).

Resultado esperado en el KG: HTTP 409. El 409 lo da el endpoint de descarga de F2.05, que todavía no existe;
aquí se fija la regla de dominio de la que sale ese 409: solo `limpio` es descargable (INV-06) y la única forma
de llegar a `limpio` es una transición permitida por la tabla de `docs/decisiones.md` §4, que pasa por una sola
función (`transicionar`).

Reglas firmes que se prueban:
- INV-06 / §4: solo `limpio` es descargable; cualquier otro estado (incluido el inicial) no.
- D4: existe el estado `error` y nunca es descargable.
- INV-09: nada llega a `limpio` desde `error`, con ningún contexto.
- K03 + K11 + K14 (parte confirmada) + K17: `error -> pendiente` solo con `tipo_error` transitorio y
  `reintentos` entero en [0, 2).
- INV-08 / D4: salir de `en_cuarentena` exige una liberación con `usuario`, `liberado_en` (datetime con zona
  horaria) y `motivo` no vacío.

No se exigen aquí (pendientes de confirmar): K24 (`resultado_cdr` coincidente y rechazo de claves extra en la
liberación), K15 (tipos estrictos) ni K16 (evidencia del análisis en `pendiente -> *`). Las pruebas aceptan una
implementación que los aplique y una que no.

Contrato: `from api.app.estados import Estado, ESTADO_INICIAL, es_descargable, transicionar, TransicionInvalida`.
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from itertools import product
from types import ModuleType

import pytest

VALORES = ("pendiente", "limpio", "en_cuarentena", "rechazado", "error")

# Tabla de transiciones de docs/decisiones.md §4. Todo lo demás está prohibido.
PERMITIDAS = {
    ("pendiente", "limpio"),
    ("pendiente", "en_cuarentena"),
    ("pendiente", "rechazado"),
    ("pendiente", "error"),
    ("error", "pendiente"),
    ("en_cuarentena", "limpio"),
    ("en_cuarentena", "rechazado"),
    ("en_cuarentena", "error"),
}
PROHIBIDAS = sorted(set(product(VALORES, VALORES)) - PERMITIDAS)
SALIDAS_DE_CUARENTENA = ("limpio", "rechazado", "error")

AHORA_UTC = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
REINTENTO_VALIDO = {"tipo_error": "transitorio", "reintentos": 0}
LIBERACION_VALIDA = {
    "usuario": "admin@gatekeeper.test",
    "motivo": "Falso positivo confirmado por el analista",
    "liberado_en": AHORA_UTC,
}


def _importar() -> ModuleType:
    try:
        return importlib.import_module("api.app.estados")
    except ModuleNotFoundError as exc:
        pytest.fail(f"control ausente: no existe api.app.estados ({exc})")


class _ModuloPerezoso:
    """Importa `api.app.estados` dentro del cuerpo de la prueba, para que su ausencia sea FAILED y no ERROR."""

    def __getattr__(self, nombre: str):
        return getattr(_importar(), nombre)


@pytest.fixture
def est() -> _ModuloPerezoso:
    return _ModuloPerezoso()


def _aceptado(est: ModuleType, actual: str, nuevo: str, *candidatos: dict) -> dict:
    """Devuelve el primer contexto con el que `transicionar` acepta el cambio.

    Sirve de control positivo y deja neutrales las propuestas pendientes (K16, K24): si la implementación
    las aplica, se prueba con el contexto que las cumple; si no, con el mínimo.
    """
    rechazos = []
    for contexto in candidatos:
        try:
            resultado = est.transicionar(
                est.Estado(actual), est.Estado(nuevo), **contexto
            )
        except est.TransicionInvalida as exc:
            rechazos.append(f"{sorted(contexto)}: {exc}")
            continue
        assert resultado is est.Estado(nuevo), (
            f"{actual} -> {nuevo} debe devolver Estado.{nuevo.upper()}, devolvió {resultado!r}"
        )
        return contexto
    pytest.fail(
        f"{actual} -> {nuevo} es una transición válida (§4) y se rechazó: {rechazos}"
    )


def _liberacion_aceptada(est: ModuleType, destino: str) -> dict:
    con_cdr = {
        **LIBERACION_VALIDA,
        "resultado_cdr": est.Estado(destino),
    }  # forma de K24 (pendiente)
    return _aceptado(est, "en_cuarentena", destino, dict(LIBERACION_VALIDA), con_cdr)


def _rechaza(est: ModuleType, actual: str, nuevo: str, **contexto) -> None:
    with pytest.raises(est.TransicionInvalida):
        est.transicionar(est.Estado(actual), est.Estado(nuevo), **contexto)


# --------------------------------------------------------------------------------------------- vec:15 núcleo


def test_vec15_pendiente_no_es_descargable(est):
    """vec:15: un archivo en `pendiente` no se puede descargar (de aquí sale el 409 de F2.05)."""
    assert est.es_descargable(est.Estado.PENDIENTE) is False


def test_vec15_el_estado_inicial_es_pendiente_y_no_descargable(est):
    assert est.ESTADO_INICIAL is est.Estado.PENDIENTE
    assert est.es_descargable(est.ESTADO_INICIAL) is False


def test_vec15_control_positivo_limpio_es_descargable(est):
    """Control positivo: una implementación que nunca deja descargar no pasa."""
    assert est.es_descargable(est.Estado.LIMPIO) is True


@pytest.mark.parametrize("valor", [v for v in VALORES if v != "limpio"])
def test_vec15_solo_limpio_es_descargable(est, valor):
    """INV-06 y D4: ningún estado distinto de `limpio` es descargable (incluido `error`)."""
    assert est.es_descargable(est.Estado(valor)) is False


@pytest.mark.parametrize(
    "valor",
    [
        "LIMPIO",
        "Limpio",
        " limpio",
        "limpio ",
        "limpio\x00",
        "",
        "descargable",
        None,
        1,
    ],
)
def test_vec15_valor_desconocido_no_es_descargable(est, valor):
    """Un valor que no es un estado no abre la descarga: devuelve False o lanza una excepción."""
    try:
        resultado = est.es_descargable(valor)
    except Exception:  # noqa: BLE001 — el contrato admite cualquier excepción ante un valor desconocido
        return
    assert resultado is False, f"es_descargable({valor!r}) devolvió {resultado!r}"


# ---------------------------------------------------------------------------------------- modelo de estados


def test_estado_es_strenum_con_los_cinco_estados(est):
    """D4: los cuatro estados del plan más `error`, y nada más."""
    assert issubclass(est.Estado, StrEnum)
    assert {e.value for e in est.Estado} == set(VALORES)
    for valor in VALORES:
        assert est.Estado[valor.upper()] is est.Estado(valor)


def test_transicion_invalida_es_excepcion(est):
    assert issubclass(est.TransicionInvalida, Exception)


# -------------------------------------------------------------------------------- transiciones permitidas (§4)


@pytest.mark.parametrize("nuevo", ["limpio", "en_cuarentena", "rechazado"])
def test_pendiente_pasa_al_veredicto(est, nuevo):
    """Control positivo: `pendiente -> limpio | en_cuarentena | rechazado` se acepta y devuelve el destino."""
    _aceptado(est, "pendiente", nuevo, {})


def test_pendiente_pasa_a_error(est):
    """Control positivo de D4. El contexto de entrada a `error` no está fijado: se acepta con o sin `tipo_error`."""
    _aceptado(
        est,
        "pendiente",
        "error",
        {},
        {"tipo_error": "final"},
        {"tipo_error": "transitorio"},
    )


@pytest.mark.parametrize("reintentos", [0, 1])
def test_error_transitorio_con_reintentos_disponibles_vuelve_a_pendiente(
    est, reintentos
):
    """K03 + K11 + K14 + K17: el reintento de un error transitorio con reintentos < 2 se acepta."""
    _aceptado(
        est,
        "error",
        "pendiente",
        {"tipo_error": "transitorio", "reintentos": reintentos},
    )


@pytest.mark.parametrize("destino", SALIDAS_DE_CUARENTENA)
def test_liberacion_completa_sale_de_cuarentena(est, destino):
    """Control positivo de INV-08: con usuario, fecha con zona y motivo, la liberación se acepta."""
    _liberacion_aceptada(est, destino)


# ------------------------------------------------------------------------------- transiciones prohibidas (§4)


@pytest.mark.parametrize(
    ("actual", "nuevo"), PROHIBIDAS, ids=[f"{a}->{n}" for a, n in PROHIBIDAS]
)
def test_transicion_fuera_de_la_tabla_se_rechaza(est, actual, nuevo):
    """Todo cambio que no está en §4 se rechaza, sin contexto y con todo el contexto posible."""
    _rechaza(est, actual, nuevo)
    _rechaza(est, actual, nuevo, **REINTENTO_VALIDO)
    _rechaza(est, actual, nuevo, **LIBERACION_VALIDA)
    _rechaza(est, actual, nuevo, **LIBERACION_VALIDA, resultado_cdr=est.Estado(nuevo))


@pytest.mark.parametrize(
    "contexto",
    [
        {},
        REINTENTO_VALIDO,
        LIBERACION_VALIDA,
        {**LIBERACION_VALIDA, "resultado_cdr": "limpio"},
        {**LIBERACION_VALIDA, **REINTENTO_VALIDO, "resultado_cdr": "limpio"},
    ],
    ids=["sin_contexto", "reintento", "liberacion", "liberacion_cdr", "todo"],
)
def test_inv09_error_nunca_llega_a_limpio(est, contexto):
    """INV-09: un error nunca termina en `limpio`, ni con contexto de reintento ni de liberación."""
    _rechaza(est, "error", "limpio", **contexto)


@pytest.mark.parametrize("nuevo", ["limpio", "en_cuarentena", "rechazado", "error"])
def test_limpio_es_terminal(est, nuevo):
    """Un archivo ya entregado como `limpio` no vuelve atrás ni cambia de veredicto."""
    _rechaza(est, "limpio", nuevo)


def test_vec15_pendiente_a_limpio_no_se_salta_con_otro_estado(est):
    """`rechazado` no vuelve a `pendiente`: no hay atajo para reanalizar y terminar en `limpio`."""
    _rechaza(est, "rechazado", "pendiente")
    _rechaza(est, "rechazado", "limpio")


# ------------------------------------------------------------------------- error -> pendiente (K11/K14/K17)


def test_error_final_no_se_reintenta(est):
    """K11: un timeout de procesamiento (p. ej. una bomba) es error final y no vuelve a `pendiente`."""
    _rechaza(est, "error", "pendiente", tipo_error="final", reintentos=0)


@pytest.mark.parametrize("reintentos", [2, 3, 99])
def test_error_sin_reintentos_disponibles_no_vuelve(est, reintentos):
    """K11 + param:max_reintentos = 2: con 2 reintentos agotados ya no hay vuelta a `pendiente`."""
    _rechaza(est, "error", "pendiente", tipo_error="transitorio", reintentos=reintentos)


def test_error_reintentos_negativos_se_rechazan(est):
    """K14: `reintentos` es un entero ≥ 0; un valor negativo no compra reintentos extra."""
    _rechaza(est, "error", "pendiente", tipo_error="transitorio", reintentos=-1)


@pytest.mark.parametrize(
    "contexto",
    [
        {},
        {"tipo_error": "transitorio"},
        {"reintentos": 0},
        {"tipo_error": "otro", "reintentos": 0},
    ],
    ids=["sin_contexto", "sin_reintentos", "sin_tipo_error", "tipo_error_desconocido"],
)
def test_error_a_pendiente_sin_contexto_completo_se_rechaza(est, contexto):
    """K14: el reintento exige `tipo_error` transitorio y `reintentos`; si falta algo, no hay reintento."""
    _rechaza(est, "error", "pendiente", **contexto)


# ------------------------------------------------------------------- liberación de cuarentena (INV-08, D4)


@pytest.mark.parametrize("destino", SALIDAS_DE_CUARENTENA)
def test_inv08_cuarentena_sin_liberacion_se_rechaza(est, destino):
    """INV-08: salir de `en_cuarentena` sin liberación se rechaza (en especial hacia `limpio`)."""
    _rechaza(est, "en_cuarentena", destino)


@pytest.mark.parametrize("destino", SALIDAS_DE_CUARENTENA)
@pytest.mark.parametrize("falta", ["usuario", "motivo", "liberado_en"])
def test_inv08_liberacion_incompleta_se_rechaza(est, destino, falta):
    """INV-08: falta el usuario, el motivo o la fecha ⇒ no hay liberación."""
    contexto = dict(_liberacion_aceptada(est, destino))
    del contexto[falta]
    _rechaza(est, "en_cuarentena", destino, **contexto)


@pytest.mark.parametrize("destino", SALIDAS_DE_CUARENTENA)
@pytest.mark.parametrize("motivo", ["", "   ", "\t\n", None])
def test_inv08_motivo_vacio_se_rechaza(est, destino, motivo):
    """INV-08: el motivo no puede estar vacío (ni ser solo espacios, ni None)."""
    contexto = {**_liberacion_aceptada(est, destino), "motivo": motivo}
    _rechaza(est, "en_cuarentena", destino, **contexto)


@pytest.mark.parametrize("destino", SALIDAS_DE_CUARENTENA)
@pytest.mark.parametrize("usuario", ["", None])
def test_inv08_usuario_vacio_se_rechaza(est, destino, usuario):
    """INV-08: la liberación tiene un usuario identificable."""
    contexto = {**_liberacion_aceptada(est, destino), "usuario": usuario}
    _rechaza(est, "en_cuarentena", destino, **contexto)


@pytest.mark.parametrize("destino", SALIDAS_DE_CUARENTENA)
@pytest.mark.parametrize(
    "liberado_en",
    [
        datetime(2026, 10, 30, 12, 0),  # sin zona horaria
        "2026-10-30T12:00:00+00:00",  # texto, no datetime
        AHORA_UTC.timestamp(),  # número, no datetime
        None,
    ],
    ids=["naive", "texto", "timestamp", "none"],
)
def test_inv08_fecha_sin_zona_o_no_datetime_se_rechaza(est, destino, liberado_en):
    """INV-08: la fecha de la liberación es un datetime con zona horaria."""
    contexto = {**_liberacion_aceptada(est, destino), "liberado_en": liberado_en}
    _rechaza(est, "en_cuarentena", destino, **contexto)


def test_inv08_fecha_con_otra_zona_se_acepta(est):
    """Control positivo: cualquier zona horaria explícita vale, no solo UTC."""
    contexto = {
        **_liberacion_aceptada(est, "limpio"),
        "liberado_en": AHORA_UTC.astimezone(timezone(timedelta(hours=-6))),
    }
    _aceptado(est, "en_cuarentena", "limpio", contexto)
