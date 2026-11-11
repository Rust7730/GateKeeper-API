"""INV-06 e INV-01 — Nada se descarga antes del veredicto, y lo que se entrega es la reconstrucción.

La API responde el 202 sin esperar al análisis (M1): se comprueba con un hijo que no termina hasta que
la prueba lo deja, porque un POST que analizara antes de responder no vería nunca `pendiente`.
"""

import hashlib

import pytest
from generadores import marca, png, png_con_texto
from hijos import hijo_con_puerta
from soporte_matriz import (
    CAMPOS_ESTADO,
    UUID_RE,
    esperar_que,
    exigir_conflicto,
    exigir_limpio,
    exigir_rechazado,
    nombres,
)


def test_inv06_el_original_no_se_descarga_durante_el_analisis(banco, tmp_path):
    comando, puerta, registro = hijo_con_puerta(tmp_path)
    contenido = png()
    with banco.api(comando_cdr=comando, timeout_cdr_s=25) as cliente:
        try:
            archivo_id = cliente.subir(contenido)
            esperar_que(lambda: bool(nombres(registro)), "el análisis no arrancó")

            assert cliente.ver(archivo_id).json()["estado"] == "pendiente"
            assert banco.fila(archivo_id)["analizado_en"] is None
            # Los bytes existen en disco, y aun así no se sirven.
            assert any(UUID_RE.fullmatch(n) for n in nombres(banco.uploads_tmp))
            exigir_conflicto(cliente.descargar(archivo_id))
        finally:
            puerta.touch()
        assert cliente.esperar(archivo_id, tope=25)["estado"] == "limpio"


def test_inv01_limpio_entrega_la_reconstruccion(cliente, banco):
    token = marca()
    original = png_con_texto(token)

    archivo_id, entregado = exigir_limpio(
        cliente, banco, original, b"foto.png", b"image/png", "image/png"
    )

    assert entregado == (banco.clean_store / archivo_id).read_bytes()
    assert hashlib.sha256(entregado).hexdigest() != hashlib.sha256(original).hexdigest()
    assert token.encode() not in entregado


def test_f202_estado_describe_el_archivo_recibido(cliente, banco):
    """El SHA-256 y el tamaño son los de lo recibido: del archivo, no del cuerpo multipart."""
    original = png_con_texto(marca())

    archivo_id, final = cliente.analizar(original, b"foto.png", b"image/png")

    assert set(final) == CAMPOS_ESTADO
    assert final["id"] == archivo_id
    assert final["sha256"] == hashlib.sha256(original).hexdigest()
    assert final["tamano_bytes"] == len(original)
    assert ("firma", "limpio") in banco.resultados(archivo_id)


def test_inv01_limpio_sin_reconstruccion_no_recurre_al_original(cliente, banco):
    """Si falta la salida, el original no es un plan B."""
    assert cliente.subir(png()), "control: la ruta debe existir"
    archivo_id = banco.sembrar_archivo("limpio", banco.app_a)
    original = marca().encode()
    (banco.uploads_tmp / archivo_id).write_bytes(original)

    respuesta = cliente.descargar(archivo_id)

    assert respuesta.status_code != 200
    assert original not in respuesta.content


@pytest.mark.parametrize(
    "ruta",
    [
        "/v1/files/{id}/original",
        "/v1/files/{id}/raw",
        "/v1/files/{id}/content/original",
        "/v1/files/{id}/content?original=1",
        "/v1/files/{id}/content?version=original",
    ],
    ids=["original", "raw", "subruta", "consulta", "consulta_version"],
)
def test_inv01_no_hay_otra_ruta_al_original(cliente, banco, ruta):
    token = marca()
    original = png_con_texto(token)
    archivo_id, _ = cliente.analizar(original, b"foto.png", b"image/png")
    assert cliente.descargar(archivo_id).status_code == 200, (
        "control: la ruta debe existir"
    )

    respuesta = cliente._http.get(
        ruta.format(id=archivo_id), headers=cliente.cabeceras()
    )

    assert token.encode() not in respuesta.content
    assert respuesta.content != original


def test_f309_el_original_se_borra_al_terminar_el_analisis(cliente, banco):
    """Vale para `limpio` y `rechazado`; `error` se comprueba en test_inv09_falla_cerrado.py."""
    exigir_limpio(cliente, banco, png_con_texto(marca()), b"foto.png", b"image/png")
    exigir_rechazado(
        cliente, banco, b"<?php phpinfo(); ?>\n", b"foto.png", b"image/png"
    )

    assert nombres(banco.uploads_tmp) == set()
    assert len(nombres(banco.clean_store)) == 1, (
        "solo queda la salida del archivo limpio"
    )
