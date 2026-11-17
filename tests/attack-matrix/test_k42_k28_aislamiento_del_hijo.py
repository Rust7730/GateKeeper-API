"""K42 y K28 — Lo que le queda al hijo cuando falla el padre, y lo que no puede ver de él.

- **`RLIMIT_CPU`** (K42): el timeout de 30 s lo lleva el padre. Si el padre muere, un hijo atascado
  en un parser no tenía ningún límite. Debe fijarse, como `RLIMIT_AS`, antes de importar los parsers.
- **`PR_SET_PDEATHSIG`** (K42): en la revisión, tras un SIGKILL a la API los hijos siguieron vivos y
  huérfanos. Se prueba de verdad: la API corre en su propio proceso, con uvicorn y uvloop, y se mata.
- **`PR_SET_DUMPABLE=0`** en la API (K28, aceptada con su alcance real: mismo UID). En la revisión,
  un hijo leyó de `/proc/<ppid>/environ` el pepper y la URL de la BD.
"""

import errno
import json
import resource
import signal

import pytest
from generadores import guardar, pdf_base, png
from hijos import leer_registro_marcado
from proceso_api import (
    ancestros_que_exponen,
    api_en_proceso,
    hijo_lee_ancestros,
    hijo_lee_el_padre,
    hijo_que_espera,
    huellas_de,
    matar,
    proceso_vivo,
    sonda_limites,
)
from soporte_matriz import esperar_que

TIPOS = [
    pytest.param(png, b"foto.png", b"image/png", "PIL", id="png"),
    pytest.param(
        lambda: guardar(pdf_base()), b"doc.pdf", b"application/pdf", "pikepdf", id="pdf"
    ),
]
SIN_LIMITE = resource.RLIM_INFINITY
TOPE_MUERTE_S = 5.0


@pytest.mark.parametrize(("generar", "nombre", "tipo", "modulo"), TIPOS)
def test_k42_rlimit_cpu_finito_antes_de_importar_los_parsers(
    banco, tmp_path, generar, nombre, tipo, modulo
):
    comando, registro = sonda_limites(tmp_path)
    with banco.api(comando_cdr=comando) as cliente:
        _, final = cliente.analizar(generar(), nombre, tipo)
    assert final["estado"] == "limpio"
    sonda = leer_registro_marcado(registro)

    blando, duro = sonda["cpu_final"]
    assert blando != SIN_LIMITE and duro != SIN_LIMITE, "el hijo corre sin RLIMIT_CPU"
    assert blando > 0
    al_importar = sonda["cpu_al_importar"].get(modulo)
    assert al_importar is not None, f"el hijo real no importó {modulo}"
    assert al_importar == [blando, duro], (
        f"{modulo} se importó antes de fijar RLIMIT_CPU"
    )


def test_k42_el_hijo_tiene_senal_de_muerte_del_padre(banco, tmp_path):
    comando, registro = sonda_limites(tmp_path)
    with banco.api(comando_cdr=comando) as cliente:
        _, final = cliente.analizar(png(), b"foto.png", b"image/png")
    assert final["estado"] == "limpio"
    assert leer_registro_marcado(registro)["pdeathsig"] != 0, (
        "el hijo no tiene PR_SET_PDEATHSIG: sobrevive a la API"
    )


def test_k42_el_hijo_muere_si_la_api_muere_de_golpe(banco, tmp_path):
    """API real con uvloop: se le manda SIGKILL con un análisis en curso."""
    comando, registro = hijo_que_espera(tmp_path)
    hijo = None
    with api_en_proceso(banco, tmp_path, comando) as api:
        try:
            api.subir(png())
            esperar_que(registro.exists, "el hijo no llegó a arrancar", tope=15)
            hijo = int(registro.read_text())
            assert proceso_vivo(hijo)

            api.proceso.send_signal(signal.SIGKILL)
            api.proceso.wait(timeout=10)

            esperar_que(
                lambda: not proceso_vivo(hijo),
                "el hijo sigue vivo tras morir la API: queda sin ningún límite de tiempo",
                tope=TOPE_MUERTE_S,
            )
        finally:
            if hijo is not None:
                matar(hijo)


def test_k28_el_hijo_no_puede_leer_el_entorno_de_la_api(banco, tmp_path):
    """Mismo UID: sin `PR_SET_DUMPABLE=0`, `/proc/<ppid>/environ` trae el pepper y la URL."""
    comando, registro = hijo_lee_el_padre(tmp_path)
    with api_en_proceso(banco, tmp_path, comando) as api:
        archivo_id = api.subir(png())
        esperar_que(registro.exists, "el hijo no dejó registro", tope=15)
        lectura = json.loads(registro.read_text())
        assert lectura["ppid"] == api.pid, "la sonda no es hija del proceso de la API"
        assert not lectura["legible"], "el hijo leyó el entorno de la API"
        assert lectura["errno"] == errno.EACCES

        # Ni siquiera el proceso que la lanzó, con el mismo UID, puede leerlo.
        with pytest.raises(PermissionError), open(f"/proc/{api.pid}/environ", "rb"):
            pass
        esperar_que(
            lambda: api.estado(archivo_id) != "pendiente", "el análisis no terminó"
        )


def test_k28_k52_el_hijo_no_lee_los_secretos_en_ningun_ancestro(banco, tmp_path):
    """Toda la cadena, no solo el padre: en la revisión, `uv` (el abuelo) los tenía a la vista.

    Busca el pepper y la contraseña de la BD por huella (largo y SHA-256), dentro de cualquier
    variable, y los nombres `GATEKEEPER_*`. Las variantes con intermediario están en
    `test_k52_secretos_en_ancestros.py`.
    """
    comando, registro = hijo_lee_ancestros(
        tmp_path, huellas_de(banco.pepper, banco.url.password.encode())
    )
    with api_en_proceso(banco, tmp_path, comando) as api:
        archivo_id = api.subir(png())
        esperar_que(registro.exists, "el hijo no dejó registro", tope=15)
        lectura = json.loads(registro.read_text())
        esperar_que(
            lambda: api.estado(archivo_id) != "pendiente", "el análisis no terminó"
        )
    assert lectura["ppid"] == api.pid, "la sonda no es hija del proceso de la API"
    assert len(lectura["cadena"]) >= 2, "la sonda no recorrió la cadena de ancestros"
    expuestos = ancestros_que_exponen(lectura)
    assert not expuestos, f"el hijo leyó secretos de la API en: {expuestos}"
