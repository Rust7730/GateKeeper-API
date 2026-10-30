"""Máquina de estados del archivo (F2.04): pruebas unitarias del dominio puro.

Complementan la matriz de ataque (tests/attack-matrix/test_vec15_descarga_pendiente.py, de gk-security) con
casos de robustez: tipos inesperados en el contexto, valores que no son miembros de `Estado` y la garantía de
que una transición rechazada lanza `TransicionInvalida`, con los límites que declara `transicionar`.

K15 (tipos estrictos) sigue pendiente de confirmar, pero estas pruebas sí fijan su comportamiento estricto, que
ya se aplica de forma provisional. No fijan K16 ni K24 (contexto de la liberación), también pendientes.
"""

from datetime import UTC, date, datetime, timedelta, timezone, tzinfo

import pytest

from api.app.estados import (
    ESTADO_INICIAL,
    Estado,
    TransicionInvalida,
    es_descargable,
    transicionar,
)

AHORA = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
LIBERACION = {
    "usuario": "admin@gatekeeper.test",
    "motivo": "Falso positivo",
    "liberado_en": AHORA,
}
REINTENTO = {"tipo_error": "transitorio", "reintentos": 0}


class _ZonaSinOffset(tzinfo):
    """tzinfo cuyo utcoffset() es None: para Python equivale a un datetime sin zona."""

    def utcoffset(self, dt):
        return None


# ------------------------------------------------------------------------------------------- es_descargable


def test_solo_limpio_es_descargable():
    assert [e for e in Estado if es_descargable(e)] == [Estado.LIMPIO]


def test_estado_inicial():
    assert ESTADO_INICIAL is Estado.PENDIENTE
    assert es_descargable(ESTADO_INICIAL) is False


@pytest.mark.parametrize(
    "valor", ["limpio", b"limpio", object(), 0, True, Estado, [Estado.LIMPIO]]
)
def test_es_descargable_falla_cerrado_ante_lo_que_no_es_un_miembro(valor):
    """INV-06: solo el miembro Estado.LIMPIO abre la descarga; cualquier otra cosa devuelve False."""
    assert es_descargable(valor) is False


# ---------------------------------------------------------------------------------------------- transiciones


@pytest.mark.parametrize(
    ("actual", "nuevo", "contexto"),
    [
        (Estado.PENDIENTE, Estado.LIMPIO, {}),
        (Estado.PENDIENTE, Estado.EN_CUARENTENA, {}),
        (Estado.PENDIENTE, Estado.RECHAZADO, {}),
        (Estado.PENDIENTE, Estado.ERROR, {}),
        (Estado.PENDIENTE, Estado.ERROR, {"tipo_error": "final"}),
        (Estado.PENDIENTE, Estado.ERROR, {"tipo_error": "transitorio"}),
        (
            Estado.ERROR,
            Estado.PENDIENTE,
            {"tipo_error": "transitorio", "reintentos": 0},
        ),
        (
            Estado.ERROR,
            Estado.PENDIENTE,
            {"tipo_error": "transitorio", "reintentos": 1},
        ),
        (Estado.EN_CUARENTENA, Estado.LIMPIO, LIBERACION),
        (Estado.EN_CUARENTENA, Estado.RECHAZADO, LIBERACION),
        (Estado.EN_CUARENTENA, Estado.ERROR, LIBERACION),
    ],
)
def test_transiciones_permitidas_devuelven_el_miembro_destino(actual, nuevo, contexto):
    assert transicionar(actual, nuevo, **contexto) is nuevo


def test_hay_exactamente_ocho_transiciones_permitidas():
    """§4 de docs/decisiones.md: 4 desde pendiente, 1 desde error y 3 desde en_cuarentena."""
    contextos = ({}, REINTENTO, LIBERACION)
    aceptadas = set()
    for actual in Estado:
        for nuevo in Estado:
            for contexto in contextos:
                try:
                    transicionar(actual, nuevo, **contexto)
                except TransicionInvalida:
                    continue
                aceptadas.add((actual, nuevo))
    assert aceptadas == {
        (Estado.PENDIENTE, Estado.LIMPIO),
        (Estado.PENDIENTE, Estado.EN_CUARENTENA),
        (Estado.PENDIENTE, Estado.RECHAZADO),
        (Estado.PENDIENTE, Estado.ERROR),
        (Estado.ERROR, Estado.PENDIENTE),
        (Estado.EN_CUARENTENA, Estado.LIMPIO),
        (Estado.EN_CUARENTENA, Estado.RECHAZADO),
        (Estado.EN_CUARENTENA, Estado.ERROR),
    }


@pytest.mark.parametrize("actual", ["pendiente", None, 0, object()])
@pytest.mark.parametrize("nuevo", ["limpio", None, 1])
def test_valores_que_no_son_miembros_lanzan_transicion_invalida(actual, nuevo):
    """Nunca TypeError/AttributeError: quien llama solo tiene que capturar TransicionInvalida."""
    with pytest.raises(TransicionInvalida):
        transicionar(actual, nuevo)


class _ImitaEstado:
    """Se hace pasar por `miembro`: isinstance() lo acepta y en un dict cae en la misma clave."""

    def __init__(self, miembro):
        self.miembro = miembro

    @property
    def __class__(self):
        return Estado

    def __hash__(self):
        return hash(self.miembro)

    def __eq__(self, otro):
        return otro is self.miembro


class _ClaseQueLanza:
    """isinstance() consulta `__class__` y propaga lo que lance."""

    @property
    def __class__(self):
        raise RuntimeError("__class__ hostil")


def test_el_imitador_engana_a_isinstance():
    """Control de la prueba: sin esto, las de abajo no demostrarían nada sobre isinstance()."""
    assert isinstance(_ImitaEstado(Estado.PENDIENTE), Estado)
    with pytest.raises(RuntimeError):
        isinstance(_ClaseQueLanza(), Estado)


# Se parametrizan fábricas, no instancias: pytest usa isinstance() al generar los ids y _ClaseQueLanza lo rompería.
@pytest.mark.parametrize(
    "fabrica",
    [lambda: _ImitaEstado(Estado.PENDIENTE), _ClaseQueLanza],
    ids=["imita_pendiente", "clase_que_lanza"],
)
def test_actual_hostil_lanza_transicion_invalida(fabrica):
    """Hallazgo de gk-security: el imitador pasaba isinstance() y salía el Estado.LIMPIO real (falla abierto)."""
    with pytest.raises(TransicionInvalida):
        transicionar(fabrica(), Estado.LIMPIO)


@pytest.mark.parametrize(
    "fabrica",
    [lambda: _ImitaEstado(Estado.LIMPIO), _ClaseQueLanza],
    ids=["imita_limpio", "clase_que_lanza"],
)
def test_nuevo_hostil_lanza_transicion_invalida(fabrica):
    with pytest.raises(TransicionInvalida):
        transicionar(Estado.PENDIENTE, fabrica())


def test_actual_y_nuevo_en_el_contexto_son_claves_ordinarias():
    """Son posicionales: como claves de contexto no chocan con los parámetros (antes, TypeError)."""
    assert (
        transicionar(Estado.PENDIENTE, Estado.LIMPIO, actual="x", nuevo="y")
        is Estado.LIMPIO
    )
    with pytest.raises(TransicionInvalida):
        transicionar(Estado.LIMPIO, Estado.PENDIENTE, actual="x", nuevo="y")


# ---------------------------------------------------------------------------------------- pendiente -> error


@pytest.mark.parametrize("tipo_error", ["otro", "", "TRANSITORIO", None, 1, ["final"]])
def test_pendiente_a_error_con_tipo_error_desconocido_se_rechaza(tipo_error):
    """K14 (parte BD): si se informa `tipo_error`, solo vale transitorio | final (CHECK de la tabla archivo)."""
    with pytest.raises(TransicionInvalida):
        transicionar(Estado.PENDIENTE, Estado.ERROR, tipo_error=tipo_error)


# -------------------------------------------------------------------------------------- error -> pendiente


@pytest.mark.parametrize(
    "reintentos",
    [True, False, 0.0, 1.0, "0", "1", None, -1, 2, 10**100, [0]],
)
def test_reintentos_debe_ser_int_en_rango(reintentos):
    """K14 + K17: `reintentos` es int en [0, 2). bool no cuenta como int (True == 1 colaría un reintento)."""
    with pytest.raises(TransicionInvalida):
        transicionar(
            Estado.ERROR,
            Estado.PENDIENTE,
            tipo_error="transitorio",
            reintentos=reintentos,
        )


@pytest.mark.parametrize(
    "tipo_error", ["final", "Transitorio", "transitorio ", None, 0, ["transitorio"]]
)
def test_reintento_solo_con_tipo_error_transitorio_exacto(tipo_error):
    """K11: solo un error transitorio de infraestructura se reintenta."""
    with pytest.raises(TransicionInvalida):
        transicionar(
            Estado.ERROR, Estado.PENDIENTE, tipo_error=tipo_error, reintentos=0
        )


# ----------------------------------------------------------------------------- liberación de cuarentena


@pytest.mark.parametrize("destino", [Estado.LIMPIO, Estado.RECHAZADO, Estado.ERROR])
@pytest.mark.parametrize(
    ("campo", "valor"),
    [
        ("usuario", ""),
        ("usuario", "   "),
        ("usuario", None),
        ("usuario", 42),
        ("usuario", b"admin"),
        ("motivo", ""),
        ("motivo", " \t\r\n "),
        ("motivo", "　"),  # espacio ideográfico: str.strip() lo quita
        ("motivo", None),
        ("motivo", ["Falso positivo"]),
        ("liberado_en", datetime(2026, 10, 30, 12, 0)),
        ("liberado_en", datetime(2026, 10, 30, 12, 0, tzinfo=_ZonaSinOffset())),
        ("liberado_en", date(2026, 10, 30)),
        ("liberado_en", "2026-10-30T12:00:00+00:00"),
        ("liberado_en", 1_792_000_000),
        ("liberado_en", None),
    ],
)
def test_liberacion_invalida_se_rechaza(destino, campo, valor):
    """INV-08: usuario y motivo no vacíos (solo espacios = vacío) y liberado_en datetime con zona."""
    with pytest.raises(TransicionInvalida):
        transicionar(Estado.EN_CUARENTENA, destino, **{**LIBERACION, campo: valor})


class _TextoHostil(str):
    """Subclase de str cuyo strip() dice que hay texto aunque no lo haya."""

    def strip(self, chars=None):
        return "hay texto"


@pytest.mark.parametrize("destino", [Estado.LIMPIO, Estado.RECHAZADO, Estado.ERROR])
@pytest.mark.parametrize("campo", ["usuario", "motivo"])
@pytest.mark.parametrize("valor", ["", "   ", "admin"])
def test_liberacion_rechaza_subclases_de_str(destino, campo, valor):
    """Solo `str` exacto: una subclase decide por sí misma qué devuelve strip() (INV-08)."""
    with pytest.raises(TransicionInvalida):
        transicionar(
            Estado.EN_CUARENTENA,
            destino,
            **{**LIBERACION, campo: _TextoHostil(valor)},
        )


@pytest.mark.parametrize("tipo_error", ["transitorio", "final"])
def test_liberacion_a_error_acepta_tipo_error_valido(tipo_error):
    assert (
        transicionar(
            Estado.EN_CUARENTENA, Estado.ERROR, **LIBERACION, tipo_error=tipo_error
        )
        is Estado.ERROR
    )


@pytest.mark.parametrize(
    "tipo_error", ["basura", "", "TRANSITORIO", None, 1, ["final"]]
)
def test_liberacion_a_error_con_tipo_error_desconocido_se_rechaza(tipo_error):
    """Misma regla que `pendiente -> error`. Si no llega, se acepta: hacerlo obligatorio está por decidir."""
    with pytest.raises(TransicionInvalida):
        transicionar(
            Estado.EN_CUARENTENA, Estado.ERROR, **LIBERACION, tipo_error=tipo_error
        )


def test_liberacion_a_error_sigue_exigiendo_la_liberacion():
    """Un tipo_error válido no suple usuario, motivo ni liberado_en."""
    with pytest.raises(TransicionInvalida):
        transicionar(Estado.EN_CUARENTENA, Estado.ERROR, tipo_error="final")


class _ZonaQueFalla(tzinfo):
    def utcoffset(self, dt):
        raise RuntimeError("tzinfo roto")


class _ZonaFueraDeRango(tzinfo):
    def utcoffset(self, dt):
        return timedelta(hours=30)  # datetime.utcoffset() lanza ValueError


@pytest.mark.parametrize("zona", [_ZonaQueFalla(), _ZonaFueraDeRango()])
def test_liberado_en_con_tzinfo_roto_lanza_transicion_invalida(zona):
    """Una excepción dentro de la validación del contexto también sale como TransicionInvalida."""
    liberado_en = datetime(2026, 10, 30, 12, 0, tzinfo=zona)
    with pytest.raises(TransicionInvalida):
        transicionar(
            Estado.EN_CUARENTENA,
            Estado.LIMPIO,
            **{**LIBERACION, "liberado_en": liberado_en},
        )


class _ZonaQueInterrumpe(tzinfo):
    def utcoffset(self, dt):
        raise KeyboardInterrupt


def test_base_exception_no_se_convierte_en_transicion_invalida():
    """Límite que declara `transicionar`: solo atrapa Exception; un Ctrl-C o un SystemExit se propagan."""
    liberado_en = datetime(2026, 10, 30, 12, 0, tzinfo=_ZonaQueInterrumpe())
    with pytest.raises(KeyboardInterrupt):
        transicionar(
            Estado.EN_CUARENTENA,
            Estado.LIMPIO,
            **{**LIBERACION, "liberado_en": liberado_en},
        )


@pytest.mark.parametrize("horas", [-12, -6, 0, 5.5, 14])
def test_liberacion_acepta_cualquier_zona_explicita(horas):
    liberado_en = AHORA.astimezone(timezone(timedelta(hours=horas)))
    assert transicionar(
        Estado.EN_CUARENTENA,
        Estado.LIMPIO,
        **{**LIBERACION, "liberado_en": liberado_en},
    ) is (Estado.LIMPIO)


def test_el_mensaje_de_error_no_incluye_datos_de_la_liberacion():
    """El mensaje puede acabar en un log: lleva los estados, no el usuario ni el motivo."""
    with pytest.raises(TransicionInvalida) as exc:
        transicionar(
            Estado.EN_CUARENTENA,
            Estado.LIMPIO,
            usuario="admin@gatekeeper.test",
            motivo="  ",
        )
    mensaje = str(exc.value)
    assert "en_cuarentena" in mensaje and "limpio" in mensaje
    assert "admin@gatekeeper.test" not in mensaje
