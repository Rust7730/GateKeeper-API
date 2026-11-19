"""K52 — La API no arranca si un proceso ancestro expone sus secretos.

Origen: revisión de la vuelta 1 (2026-11-10). `PR_SET_DUMPABLE=0` protege el entorno de la API,
pero no el de quien la lanzó. Con `uv run uvicorn ...`, como decía el README, el padre de la API es
`uv`: tiene el mismo entorno (`GATEKEEPER_PEPPER`, `GATEKEEPER_DATABASE_URL`), el mismo UID y es
volcable. Un hijo del CDR leyó `/proc/<abuelo>/environ` sin ningún permiso especial.

Decisión del usuario (K52): al arrancar, la API recorre sus ancestros y, si alguno tiene esas
variables legibles en `/proc/<pid>/environ`, no arranca, con un error que no muestra valores. El
README lanza uvicorn directo (`.venv/bin/uvicorn`), sin `uv run`.

Se lanza como en producción: los secretos en `GATEKEEPER_*` y el comando del README. Un
intermediario "sin exec" se queda vivo con el entorno entero; con `exec`, desaparece.
"""

import json

import pytest
from generadores import png
from proceso_api import (
    ancestros_que_exponen,
    api_por_entorno,
    hijo_lee_ancestros,
    huellas_de,
)
from soporte_matriz import esperar_que

CON_SECRETOS_EXPUESTOS = ["sh_sin_exec", "uv_run"]
SIN_INTERMEDIARIO_VIVO = ["directo", "sh_con_exec"]


def _secretos(banco) -> list[bytes]:
    return [banco.pepper, banco.url.password.encode()]


def _sin_secretos_en(registro: bytes, banco) -> None:
    for secreto in _secretos(banco):
        assert secreto not in registro, "el error del arranque muestra un secreto"


@pytest.mark.parametrize("intermediario", CON_SECRETOS_EXPUESTOS)
def test_k52_lanzada_tras_un_intermediario_con_el_entorno_no_arranca(
    banco, tmp_path, intermediario
):
    with api_por_entorno(banco, tmp_path, intermediario) as lanzamiento:
        assert not lanzamiento.arranco, (
            f"la API arrancó aunque {intermediario} expone sus secretos en /proc"
        )
        assert lanzamiento.codigo not in (None, 0)
        _sin_secretos_en(lanzamiento.log(), banco)


@pytest.mark.parametrize("intermediario", SIN_INTERMEDIARIO_VIVO)
def test_k52_control_lanzada_directa_arranca(banco, tmp_path, intermediario):
    """Con el comando del README, o tras un `exec`, ningún ancestro guarda los secretos."""
    with api_por_entorno(banco, tmp_path, intermediario) as lanzamiento:
        assert lanzamiento.arranco, (
            f"la API no arrancó ({intermediario}); salida: {lanzamiento.codigo}"
        )


@pytest.mark.parametrize("intermediario", ["directo", *CON_SECRETOS_EXPUESTOS])
def test_k52_k28_ningun_ancestro_de_la_api_expone_secretos_al_hijo(
    banco, tmp_path, intermediario
):
    """Lance como se lance: o la API no arranca, o el hijo no lee los secretos en su cadena."""
    comando, registro = hijo_lee_ancestros(tmp_path, huellas_de(*_secretos(banco)))
    with api_por_entorno(banco, tmp_path, intermediario, comando) as lanzamiento:
        if not lanzamiento.arranco:
            assert intermediario != "directo", "la API no arrancó lanzada directamente"
            return
        archivo_id = lanzamiento.api.subir(png())
        esperar_que(registro.exists, "el hijo no dejó registro", tope=15)
        lectura = registro.read_text()
        esperar_que(
            lambda: lanzamiento.api.estado(archivo_id) != "pendiente",
            "el análisis no terminó",
        )
    expuestos = ancestros_que_exponen(json.loads(lectura))
    assert not expuestos, f"el hijo leyó secretos de la API en: {expuestos}"
