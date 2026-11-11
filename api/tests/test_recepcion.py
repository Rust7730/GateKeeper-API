"""Recepción de ``POST /v1/files`` sin HTTP: multipart en streaming hacia disco (F2.02)."""

import hashlib
import secrets
import stat
from pathlib import Path

import pytest
from fastapi import HTTPException

from api.app.recepcion import (
    MARGEN_CUERPO,
    TOPE_ARCHIVO,
    TOPE_CUERPO,
    Receptor,
    comprobar_longitud,
    extraer_limite,
    sanear_nombre,
)

LIMITE = b"limite123"
PNG = b"\x89PNG\r\n\x1a\nnada mas"


def _parte(nombre: bytes, datos: bytes, filename: bytes | None = b"a.png") -> bytes:
    cabecera = b'Content-Disposition: form-data; name="%s"' % nombre
    if filename is not None:
        cabecera += b'; filename="%s"' % filename
    return b"--%s\r\n%s\r\n\r\n%s\r\n" % (LIMITE, cabecera, datos)


def _cuerpo(*partes: bytes) -> bytes:
    return b"".join(partes) + b"--%s--\r\n" % LIMITE


def _exigir_codigo(error: pytest.ExceptionInfo[HTTPException], codigo: int) -> None:
    assert error.value.status_code == codigo
    assert error.value.headers == {"Connection": "close"}


def test_los_topes_son_los_del_diseno() -> None:
    assert TOPE_ARCHIVO == 10_485_760
    assert MARGEN_CUERPO == 65_536
    assert TOPE_CUERPO == TOPE_ARCHIVO + MARGEN_CUERPO


# -------------------------------------------------------------------------------- K25


@pytest.mark.parametrize(
    ("crudo", "guardado"),
    [
        (b"foto.png", "foto.png"),
        ("fotó ñ.png".encode(), "fotó ñ.png"),
        (b"a\x00b\x1fc\x7fd", "abcd"),
        ("a\u0080b\u009fc".encode(), "abc"),
        (b"", "sin_nombre"),
        (b"\x00\x01", "sin_nombre"),
        (b"x" * 300, "x" * 255),
        (b"\x00" * 5 + b"y" * 255, "y" * 255),
        (b"../../etc/passwd", "../../etc/passwd"),
    ],
)
def test_sanear_nombre(crudo: bytes, guardado: str) -> None:
    assert sanear_nombre(crudo) == guardado


@pytest.mark.parametrize("crudo", [b"a\xffb", b"\xed\xa0\x80", b"\xc3"])
def test_sanear_nombre_sin_utf8_valido_no_deja_surrogates(crudo: bytes) -> None:
    saneado = sanear_nombre(crudo)
    saneado.encode("utf-8")
    assert saneado


# --------------------------------------------------------------------- cabeceras HTTP


def test_extraer_limite() -> None:
    assert extraer_limite("multipart/form-data; boundary=abc") == b"abc"
    assert extraer_limite('Multipart/Form-Data; boundary="a b"') == b"a b"


@pytest.mark.parametrize(
    "tipo", [None, "", "application/json", "text/plain; boundary=x", "multipart/mixed"]
)
def test_lo_que_no_es_multipart_form_data_es_415(tipo: str | None) -> None:
    with pytest.raises(HTTPException) as error:
        extraer_limite(tipo)
    _exigir_codigo(error, 415)


@pytest.mark.parametrize(
    "tipo",
    [
        "multipart/form-data",
        "multipart/form-data; boundary=",
        'multipart/form-data; boundary=""',
    ],
    ids=["sin_limite", "vacio", "comillas_vacias"],
)
def test_un_limite_invalido_es_400(tipo: str) -> None:
    with pytest.raises(HTTPException) as error:
        extraer_limite(tipo)
    _exigir_codigo(error, 400)


def test_un_limite_demasiado_largo_es_400(tmp_path: Path) -> None:
    with pytest.raises(HTTPException) as error:
        Receptor(b"x" * 257, tmp_path)
    _exigir_codigo(error, 400)


@pytest.mark.parametrize("valor", [None, "0", "10", str(TOPE_CUERPO)])
def test_longitud_admitida(valor: str | None) -> None:
    comprobar_longitud(valor)


@pytest.mark.parametrize("valor", [str(TOPE_CUERPO + 1), "9" * 5000])
def test_longitud_excesiva_es_413(valor: str) -> None:
    with pytest.raises(HTTPException) as error:
        comprobar_longitud(valor)
    _exigir_codigo(error, 413)


@pytest.mark.parametrize("valor", ["-1", "abc", "1e3", " 10", "١٢", ""])
def test_longitud_mal_formada_es_400(valor: str) -> None:
    with pytest.raises(HTTPException) as error:
        comprobar_longitud(valor)
    _exigir_codigo(error, 400)


# --------------------------------------------------------------------------- Receptor


def _recibir(directorio: Path, cuerpo: bytes, trozo: int = 65_536):
    receptor = Receptor(LIMITE, directorio)
    for inicio in range(0, len(cuerpo), trozo):
        receptor.alimentar(cuerpo[inicio : inicio + trozo])
    return receptor.terminar()


@pytest.mark.parametrize("trozo", [1, 7, 65_536], ids=["byte", "pequeno", "grande"])
def test_recibe_el_archivo_con_su_hash_y_su_nombre(tmp_path: Path, trozo: int) -> None:
    datos = secrets.token_bytes(5000) + b"\r\n--limite12" + secrets.token_bytes(100)
    recibido = _recibir(tmp_path, _cuerpo(_parte(b"file", datos)), trozo)

    assert recibido.ruta == tmp_path / str(recibido.id)
    assert recibido.ruta.read_bytes() == datos
    assert recibido.tamano == len(datos)
    assert recibido.sha256 == hashlib.sha256(datos).hexdigest()
    assert recibido.nombre == "a.png"


def test_el_temporal_nace_privado(tmp_path: Path) -> None:
    recibido = _recibir(tmp_path, _cuerpo(_parte(b"file", PNG)))
    assert stat.S_IMODE(recibido.ruta.stat().st_mode) == 0o600


def test_ignora_los_campos_que_no_son_file(tmp_path: Path) -> None:
    cuerpo = _cuerpo(
        _parte(b"otro", b"texto", None),
        _parte(b"file", PNG),
        _parte(b"mas", b"texto", None),
    )
    recibido = _recibir(tmp_path, cuerpo)
    assert recibido.ruta.read_bytes() == PNG


def test_el_nombre_de_la_cabecera_no_llega_a_la_ruta(tmp_path: Path) -> None:
    recibido = _recibir(tmp_path, _cuerpo(_parte(b"file", PNG, b"../../x.png")))
    assert recibido.ruta.parent == tmp_path
    assert recibido.nombre == "../../x.png"


def test_parte_file_sin_filename_se_llama_sin_nombre(tmp_path: Path) -> None:
    recibido = _recibir(tmp_path, _cuerpo(_parte(b"file", PNG, None)))
    assert recibido.nombre == "sin_nombre"


def test_no_crea_nada_hasta_ver_la_parte_file(tmp_path: Path) -> None:
    receptor = Receptor(LIMITE, tmp_path)
    receptor.alimentar(_parte(b"otro", b"texto", None))
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "cuerpo",
    [
        _cuerpo(_parte(b"otro", PNG)),
        _cuerpo(_parte(b"file", b"")),
        _cuerpo(_parte(b"file", PNG), _parte(b"file", PNG)),
        _parte(b"file", PNG),
        _parte(b"file", PNG)[:40],
        b"",
        b"esto no es multipart",
        b"--%s\r\nsin dos puntos\r\n\r\ndatos\r\n--%s--\r\n" % (LIMITE, LIMITE),
        b'--%s\r\nContent-Disposition: form-data; name="file"\r\n'
        b'Content-Disposition: form-data; name="otro"\r\n\r\nx\r\n--%s--\r\n'
        % (LIMITE, LIMITE),
        b"--%s\r\nContent-Type: text/plain\r\n\r\nx\r\n--%s--\r\n" % (LIMITE, LIMITE),
        _cuerpo(_parte(b"file", PNG, b"x" * 5000)),
    ],
    ids=[
        "sin_parte_file",
        "archivo_vacio",
        "dos_partes_file",
        "sin_cierre",
        "cortado_en_cabeceras",
        "vacio",
        "basura",
        "cabecera_rota",
        "disposicion_duplicada",
        "sin_disposicion",
        "cabecera_enorme",
    ],
)
def test_multipart_invalido_es_400_y_no_deja_temporal(
    tmp_path: Path, cuerpo: bytes
) -> None:
    receptor = Receptor(LIMITE, tmp_path)
    with pytest.raises(HTTPException) as error:
        receptor.alimentar(cuerpo)
        receptor.terminar()
    _exigir_codigo(error, 400)
    receptor.descartar()
    assert list(tmp_path.iterdir()) == []


def test_un_byte_sobre_el_tope_es_413_y_corta_antes_de_escribirlo(
    tmp_path: Path,
) -> None:
    receptor = Receptor(LIMITE, tmp_path)
    receptor.alimentar(
        b'--%s\r\nContent-Disposition: form-data; name="file"\r\n\r\n' % LIMITE
    )
    receptor.alimentar(bytes(TOPE_ARCHIVO))
    with pytest.raises(HTTPException) as error:
        receptor.alimentar(b"\xff" * 4096)
    _exigir_codigo(error, 413)
    assert all(ruta.stat().st_size <= TOPE_ARCHIVO for ruta in tmp_path.iterdir())
    receptor.descartar()
    assert list(tmp_path.iterdir()) == []


def test_exactamente_en_el_tope_se_acepta(tmp_path: Path) -> None:
    recibido = _recibir(tmp_path, _cuerpo(_parte(b"file", bytes(TOPE_ARCHIVO))))
    assert recibido.tamano == TOPE_ARCHIVO


def test_descartar_es_idempotente_y_borra_lo_ya_terminado(tmp_path: Path) -> None:
    receptor = Receptor(LIMITE, tmp_path)
    receptor.alimentar(_cuerpo(_parte(b"file", PNG)))
    receptor.terminar()
    receptor.descartar()
    receptor.descartar()
    assert list(tmp_path.iterdir()) == []
