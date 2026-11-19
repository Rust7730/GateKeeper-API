"""vec:13 — Acceso a un archivo de otra aplicación (IDOR, CWE-639). Resultado esperado en el KG: 404.

La respuesta a un archivo ajeno es idéntica a la de un id inexistente (INV-10): mismo estado, mismo
cuerpo y mismas cabeceras. Sin rutas, todo responde 404 y la comparación pasaría sola, así que cada
prueba comprueba antes que el dueño sí llega al archivo.
"""

import uuid

import pytest
from generadores import png
from soporte_matriz import exigir_conflicto


def _firma(respuesta) -> tuple:
    return respuesta.status_code, respuesta.content, sorted(respuesta.headers.items())


def _exigir_identico_a_inexistente(cliente, banco, archivo_id: str) -> None:
    ajena = banco.app_b.key
    inexistente = str(uuid.uuid4())
    for ruta in (cliente.ver, cliente.descargar):
        respuesta = ruta(archivo_id, key=ajena)
        assert respuesta.status_code == 404
        assert respuesta.json() == {"detail": "Not Found"}
        assert _firma(respuesta) == _firma(ruta(inexistente, key=ajena))


def test_vec13_archivo_limpio_ajeno_responde_404(cliente, banco):
    archivo_id, final = cliente.analizar(png(), b"foto.png", b"image/png")
    assert final["estado"] == "limpio"
    assert cliente.descargar(archivo_id).status_code == 200

    _exigir_identico_a_inexistente(cliente, banco, archivo_id)


@pytest.mark.parametrize("estado", ["pendiente", "rechazado", "error"])
def test_vec13_estado_ajeno_no_se_filtra_por_el_409(cliente, banco, estado):
    """El dueño recibe 409; el ajeno, 404: un 409 revelaría que el id existe."""
    archivo_id = banco.sembrar_archivo(estado, banco.app_a)
    exigir_conflicto(cliente.descargar(archivo_id))

    _exigir_identico_a_inexistente(cliente, banco, archivo_id)


def test_vec13_la_aplicacion_ajena_ve_lo_suyo(cliente, banco):
    """Control positivo: un filtro que da 404 a todos también pasaría las pruebas de arriba."""
    archivo_id = cliente.subir(png(), key=banco.app_b.key)
    assert cliente.ver(archivo_id, key=banco.app_b.key).status_code == 200
    assert cliente.ver(archivo_id).status_code == 404


def test_vec13_una_segunda_key_de_la_misma_aplicacion_si_accede(cliente, banco):
    """INV-10 es por aplicación: el filtro va por `aplicacion_id`, no por la key."""
    archivo_id = cliente.subir(png())
    segunda = banco.key_nueva_para(banco.app_a.aplicacion_id)
    assert cliente.ver(archivo_id, key=segunda).status_code == 200


@pytest.mark.parametrize(
    "archivo_id",
    [
        "no-es-uuid",
        "1",
        "..%2f..%2fetc%2fpasswd",
        "00000000-0000-0000-0000-00000000000g",
    ],
    ids=["texto", "numero", "traversal", "casi_uuid"],
)
def test_vec13_id_que_no_es_uuid_responde_404_no_422(cliente, archivo_id):
    """Diseño §4: un 422 revelaría el formato de los ids y las rutas internas de validación."""
    assert cliente.subir(png()), "control: la ruta debe existir"
    for ruta in (cliente.ver, cliente.descargar):
        respuesta = ruta(archivo_id)
        assert respuesta.status_code == 404
        assert respuesta.json() == {"detail": "Not Found"}
