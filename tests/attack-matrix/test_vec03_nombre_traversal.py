"""vec:03 — Nombre con `../` o byte nulo (CWE-22). Resultado esperado en el KG: el archivo se guarda
solo con UUID y ninguna ruta escapa del almacenamiento.

Sigue K25: el nombre se sanea y se acepta (se quitan C0, U+007F, C1 y surrogates, se trunca a 255
caracteres y, si queda vacío, `sin_nombre`). La comprobación se hace en disco: tras analizar, todo lo
que hay bajo el directorio de la prueba es un único archivo, `clean_store/<uuid>`.
"""

import os
import re
import unicodedata
from pathlib import Path

import pytest
from generadores import marca, png
from soporte_matriz import (
    CAMPOS_ESTADO,
    UUID_RE,
    exigir_limpio,
    nombres,
)


def _comprobar_almacen(
    cliente, banco, archivo_id: str, nombre: bytes, token: str
) -> None:
    assert nombres(banco.uploads_tmp) == set()
    assert nombres(banco.clean_store) == {archivo_id}

    for ruta in banco.raiz.rglob("*"):
        assert not ruta.is_symlink(), f"enlace simbólico en el almacén: {ruta}"
        if ruta.is_file():
            assert ruta == banco.clean_store / archivo_id, f"archivo inesperado: {ruta}"
            assert UUID_RE.fullmatch(ruta.name)
        assert token not in str(ruta), f"el nombre original llegó a una ruta: {ruta}"

    # Las bases desde las que una concatenación ingenua habría resuelto el nombre.
    relativo = os.fsdecode(nombre.replace(b"\x00", b"").replace(b"\\", b"/"))
    for base in (banco.uploads_tmp, banco.clean_store, Path.cwd()):
        destino = Path(os.path.normpath(base / relativo))
        assert not destino.exists(), f"el nombre escapó del almacén: {destino}"

    disposicion = cliente.descargar(archivo_id).headers["content-disposition"]
    assert disposicion == f'attachment; filename="{archivo_id}.png"'
    estado = cliente.ver(archivo_id)
    assert set(estado.json()) == CAMPOS_ESTADO
    assert token not in estado.text


@pytest.mark.parametrize(
    "plantilla",
    [
        "../{t}.png",
        "../../{t}.png",
        "../../../../../../../../tmp/{t}.png",
        "..\\..\\{t}.png",
        "....//....//{t}.png",
        "uploads_tmp/../../{t}.png",
        "clean_store/{t}.png",
        "%2e%2e%2f%2e%2e%2f{t}.png",
    ],
    ids=[
        "un_nivel",
        "dos_niveles",
        "raiz_tmp",
        "barra_invertida",
        "barras_dobles",
        "con_subdirectorio",
        "dentro_del_almacen",
        "codificado",
    ],
)
def test_vec03_nombre_con_ruta_se_guarda_solo_con_uuid(cliente, banco, plantilla):
    token = marca()
    nombre = plantilla.format(t=token).encode()
    archivo_id, _ = exigir_limpio(
        cliente, banco, png(), nombre, b"image/png", "image/png"
    )
    _comprobar_almacen(cliente, banco, archivo_id, nombre, token)


def test_vec03_nombre_con_ruta_absoluta_se_guarda_solo_con_uuid(
    cliente, banco, tmp_path
):
    """`Path(base) / "/absoluta"` descarta la base: el peor caso de una concatenación ingenua."""
    token = marca()
    nombre = str(tmp_path / f"{token}.png").encode()
    archivo_id, _ = exigir_limpio(
        cliente, banco, png(), nombre, b"image/png", "image/png"
    )
    _comprobar_almacen(cliente, banco, archivo_id, nombre, token)


@pytest.mark.parametrize(
    "plantilla",
    [b"%s.png\x00.exe", b"../../%s\x00.png", b"\x00%s.png"],
    ids=["nulo_en_medio", "nulo_y_ruta", "nulo_al_inicio"],
)
def test_vec03_nombre_con_byte_nulo_se_acepta_y_no_llega_a_la_bd(
    cliente, banco, plantilla
):
    """K25: no es 400 ni 500. PostgreSQL rechaza un NUL en texto, así que hay que quitarlo antes."""
    token = marca()
    nombre = plantilla % token.encode()
    archivo_id, _ = exigir_limpio(
        cliente, banco, png(), nombre, b"image/png", "image/png"
    )
    assert "\x00" not in banco.fila(archivo_id)["nombre_original"]
    _comprobar_almacen(cliente, banco, archivo_id, nombre, token)


@pytest.mark.parametrize(
    ("nombre", "guardado"),
    [
        (b"foto\x00.png", "foto.png"),
        (b"\x1b[31mfoto.png", "[31mfoto.png"),
        (b"fo\ttoo\x7f.png", "fotoo.png"),
        ("fo\u0085to\u009f.png".encode(), "foto.png"),
        (b"\x01\x02\x03", "sin_nombre"),
        (b"", "sin_nombre"),
        (b"a" * 300 + b".png", "a" * 255),
        ("ñ".encode() * 300, "ñ" * 255),
        (b"\x00" * 10 + b"b" * 255, "b" * 255),
    ],
    ids=[
        "nulo",
        "ansi",
        "c0_y_del",
        "c1",
        "solo_control",
        "vacio",
        "largo",
        "largo_multibyte",
        "primero_quita_luego_trunca",
    ],
)
def test_k25_nombre_saneado(cliente, banco, nombre, guardado):
    archivo_id = cliente.subir(png(), nombre, b"image/png")
    assert banco.fila(archivo_id)["nombre_original"] == guardado
    assert cliente.esperar(archivo_id)["estado"] == "limpio"


@pytest.mark.parametrize(
    "nombre",
    [b"foto\xff.png", b"\xed\xa0\x80foto.png", b"\xc3"],
    ids=["byte_invalido", "surrogate", "utf8_cortado"],
)
def test_k25_nombre_sin_utf8_valido_no_rompe_la_subida(cliente, banco, nombre):
    """Un surrogate no se puede guardar en PostgreSQL. Reemplazarlo por U+FFFD o quitarlo vale."""
    archivo_id = cliente.subir(png(), nombre, b"image/png")
    guardado = banco.fila(archivo_id)["nombre_original"]
    assert not re.search("[\x00-\x1f\x7f-\x9f]", guardado)
    assert not any(unicodedata.category(c) == "Cs" for c in guardado)
    assert cliente.esperar(archivo_id)["estado"] == "limpio"
