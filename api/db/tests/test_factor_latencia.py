"""Factor de los topes de latencia por entorno (K56).

En GitHub Actions el runner compartido es más lento, así que los topes de rendimiento
(p95/p50) se multiplican por ``GATEKEEPER_FACTOR_LATENCIA``. Sin la variable el factor
es 1. Solo se acepta un número finito entre 1 y 10, ambos incluidos; cualquier otro
valor hace fallar la prueba, nunca cae en silencio a 1 ni a 10. El factor multiplica el
tope, no la medición.
"""

import pytest

from api.db.tests.latencia import (
    VARIABLE_FACTOR_LATENCIA,
    exigir_tope_ms,
    factor_latencia,
)


def test_la_variable_se_llama_gatekeeper_factor_latencia() -> None:
    assert VARIABLE_FACTOR_LATENCIA == "GATEKEEPER_FACTOR_LATENCIA"


def test_sin_la_variable_el_factor_es_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(VARIABLE_FACTOR_LATENCIA, raising=False)
    assert factor_latencia() == 1


@pytest.mark.parametrize(
    ("valor", "esperado"),
    [("1", 1.0), ("2.5", 2.5), ("10", 10.0), ("10.0", 10.0)],
)
def test_acepta_numeros_entre_1_y_10(
    monkeypatch: pytest.MonkeyPatch, valor: str, esperado: float
) -> None:
    monkeypatch.setenv(VARIABLE_FACTOR_LATENCIA, valor)
    assert factor_latencia() == esperado


@pytest.mark.parametrize(
    "valor",
    [
        "0.5",
        "11",
        "nan",
        "abc",
        "",
        "0",
        "-1",
        "10.01",
        "inf",
        "-inf",
        "Infinity",
        "1e1",
        " 10",
        "10 ",
        "1_0",
    ],
)
def test_rechaza_valores_fuera_de_rango_o_que_no_son_numero(
    monkeypatch: pytest.MonkeyPatch, valor: str
) -> None:
    monkeypatch.setenv(VARIABLE_FACTOR_LATENCIA, valor)
    with pytest.raises(pytest.fail.Exception) as error:
        factor_latencia()
    mensaje = str(error.value)
    # El mensaje nombra la variable, muestra el valor recibido y el rango aceptado.
    assert VARIABLE_FACTOR_LATENCIA in mensaje
    assert repr(valor) in mensaje
    assert "entre 1 y 10" in mensaje


def test_el_factor_multiplica_el_tope_y_no_la_medicion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(VARIABLE_FACTOR_LATENCIA, "10")
    # 150 ms con tope base de 20 ms: pasa solo si el tope efectivo es 200 ms. El tope
    # es estricto: igualarlo no pasa. Que la medición no se toca lo demuestra el mensaje
    # (test_el_mensaje_muestra_el_tope_efectivo_y_el_factor): muestra el p95 medido.
    exigir_tope_ms("p95 de prueba", 150.0, 20.0)
    exigir_tope_ms("p95 de prueba", 199.9, 20.0)
    with pytest.raises(AssertionError):
        exigir_tope_ms("p95 de prueba", 200.0, 20.0)


def test_sin_la_variable_el_tope_queda_igual(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(VARIABLE_FACTOR_LATENCIA, raising=False)
    exigir_tope_ms("p95 de prueba", 19.9, 20.0)
    with pytest.raises(AssertionError):
        exigir_tope_ms("p95 de prueba", 20.0, 20.0)


def test_el_mensaje_muestra_el_tope_efectivo_y_el_factor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(VARIABLE_FACTOR_LATENCIA, "10")
    with pytest.raises(AssertionError) as error:
        exigir_tope_ms("p95 de crear_archivo", 250.0, 20.0)
    mensaje = str(error.value)
    assert "p95 de crear_archivo = 250.00 ms" in mensaje
    assert "tope efectivo 200.00 ms" in mensaje
    assert "20.00 ms x factor 10" in mensaje
    assert VARIABLE_FACTOR_LATENCIA in mensaje


def test_un_factor_invalido_hace_fallar_la_comprobacion_del_tope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Aunque la medición estuviera dentro del tope base, un factor inválido no se ignora.
    monkeypatch.setenv(VARIABLE_FACTOR_LATENCIA, "nan")
    with pytest.raises(pytest.fail.Exception):
        exigir_tope_ms("p95 de prueba", 1.0, 20.0)
