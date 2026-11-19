"""Topes de latencia de las pruebas con el factor del entorno (K56).

En GitHub Actions el runner compartido es más lento que esta máquina: allí
``GATEKEEPER_FACTOR_LATENCIA=10`` multiplica los topes de **rendimiento** (p95/p50). En
local y en gk-commit la variable no existe y el factor es 1. Los límites de tiempo de
seguridad o de comportamiento (timeouts, ``TOPE_DE_LA_PRUEBA_S``) no pasan por aquí.

Solo se acepta un número decimal simple (``1``, ``2.5``, ``10``) entre 1 y 10, ambos
incluidos. Cualquier otro valor (fuera de rango, ``nan``, ``inf``, exponentes, espacios,
texto o vacío) hace fallar la prueba: un error de configuración no debe aflojar ni
apretar los topes en silencio.
"""

import math
import os
import re

import pytest

VARIABLE_FACTOR_LATENCIA = "GATEKEEPER_FACTOR_LATENCIA"
FACTOR_MINIMO = 1.0
FACTOR_MAXIMO = 10.0
# Dígitos con parte decimal opcional: sin signo, exponente, guion bajo ni espacios.
_NUMERO = re.compile(r"[0-9]+(\.[0-9]+)?")


def factor_latencia() -> float:
    """Factor de ``GATEKEEPER_FACTOR_LATENCIA``; 1 sin la variable.

    Falla la prueba (``pytest.fail``) si el valor no es un número finito entre 1 y 10.
    """
    valor = os.environ.get(VARIABLE_FACTOR_LATENCIA)
    if valor is None:
        return FACTOR_MINIMO
    factor = float(valor) if _NUMERO.fullmatch(valor) else math.nan
    if not (math.isfinite(factor) and FACTOR_MINIMO <= factor <= FACTOR_MAXIMO):
        pytest.fail(
            f"{VARIABLE_FACTOR_LATENCIA}={valor!r} no es válido: debe ser un número "
            "entre 1 y 10, ambos incluidos (p. ej. 10 en GitHub Actions, K56), o no "
            "estar definida (factor 1).",
            pytrace=False,
        )
    return factor


def exigir_tope_ms(nombre: str, medido_ms: float, tope_base_ms: float) -> None:
    """Exige ``medido_ms < tope_base_ms x factor``. El factor multiplica el tope, no la medición."""
    factor = factor_latencia()
    tope_ms = tope_base_ms * factor
    assert medido_ms < tope_ms, (
        f"{nombre} = {medido_ms:.2f} ms; tope efectivo {tope_ms:.2f} ms "
        f"= {tope_base_ms:.2f} ms x factor {factor:g} ({VARIABLE_FACTOR_LATENCIA})"
    )
