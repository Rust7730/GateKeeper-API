"""K13: descompresión acotada, por PDF y a través de cadenas de filtros."""

import base64
import binascii
import zlib

import pytest

from api.app.cdr_flujos import (
    FiltroNoAdmitido,
    FlujoInvalido,
    Presupuesto,
    TopeDescompresion,
    medir_flujo,
)

MIB = 1024 * 1024
FLATE = "/FlateDecode"


def _lzw(datos: bytes, temprano: int = 1) -> bytes:
    """Codificador LZW de PDF, MSB primero, con los códigos 256 (clear) y 257 (EOD)."""
    tabla = {bytes([i]): i for i in range(256)}
    siguiente, ancho, bits, cuenta = 258, 9, 0, 0
    salida = bytearray()

    def poner(codigo: int) -> None:
        nonlocal bits, cuenta
        bits = (bits << ancho) | codigo
        cuenta += ancho
        while cuenta >= 8:
            cuenta -= 8
            salida.append((bits >> cuenta) & 0xFF)
            bits &= (1 << cuenta) - 1

    poner(256)
    actual = b""
    for valor in datos:
        candidato = actual + bytes([valor])
        if candidato in tabla:
            actual = candidato
            continue
        poner(tabla[actual])
        tabla[candidato] = siguiente
        siguiente += 1
        if siguiente + temprano > (1 << ancho) and ancho < 12:
            ancho += 1
        if siguiente >= 4094:
            poner(256)
            tabla = {bytes([i]): i for i in range(256)}
            siguiente, ancho = 258, 9
        actual = bytes([valor])
    if actual:
        poner(tabla[actual])
    poner(257)
    if cuenta:
        salida.append((bits << (8 - cuenta)) & 0xFF)
    return bytes(salida)


def _gastado(crudo: bytes, filtros: list[str], tope: int = 100 * MIB, **extra) -> int:
    presupuesto = Presupuesto(tope)
    medir_flujo(crudo, filtros, presupuesto, **extra)
    return tope - presupuesto.restante


def test_un_flujo_sin_filtros_no_gasta() -> None:
    assert _gastado(b"x" * 1000, []) == 0


@pytest.mark.parametrize("nombre", ["/FlateDecode", "/Fl"])
def test_flate_cuenta_lo_descomprimido(nombre: str) -> None:
    assert _gastado(zlib.compress(bytes(5000)), [nombre]) == 5000


def test_flate_por_encima_del_tope_corta() -> None:
    with pytest.raises(TopeDescompresion):
        _gastado(zlib.compress(bytes(2 * MIB)), [FLATE], tope=MIB)


def test_flate_corta_sin_descomprimir_todo() -> None:
    """Con un tope pequeño, una bomba de 1 GiB no llega a producirse entera."""
    compresor = zlib.compressobj(9)
    bomba = b"".join(compresor.compress(bytes(MIB)) for _ in range(1024))
    bomba += compresor.flush()
    presupuesto = Presupuesto(MIB)
    with pytest.raises(TopeDescompresion):
        medir_flujo(bomba, [FLATE], presupuesto)
    assert presupuesto.restante >= -256 * 1024


def test_el_tope_es_del_presupuesto_no_del_flujo() -> None:
    presupuesto = Presupuesto(MIB)
    crudo = zlib.compress(bytes(600 * 1024))
    medir_flujo(crudo, [FLATE], presupuesto)
    with pytest.raises(TopeDescompresion):
        medir_flujo(crudo, [FLATE], presupuesto)


def test_cada_etapa_de_la_cadena_gasta() -> None:
    interior = zlib.compress(bytes(MIB))
    doble = zlib.compress(interior)
    assert _gastado(doble, [FLATE, FLATE]) == len(interior) + MIB


def test_flate_doble_con_la_bomba_en_la_segunda_capa() -> None:
    doble = zlib.compress(zlib.compress(bytes(3 * MIB)))
    with pytest.raises(TopeDescompresion):
        _gastado(doble, [FLATE, FLATE], tope=MIB)


@pytest.mark.parametrize("nombre", ["/ASCIIHexDecode", "/AHx"])
def test_hex_seguido_de_flate(nombre: str) -> None:
    crudo = binascii.hexlify(zlib.compress(bytes(3 * MIB))) + b">"
    with pytest.raises(TopeDescompresion):
        _gastado(crudo, [nombre, FLATE], tope=MIB)


def test_hex_con_espacios_y_nibble_final() -> None:
    assert _gastado(b"41 42\n4>basura", ["/AHx"]) == 3


def test_hex_invalido_es_flujo_invalido() -> None:
    with pytest.raises(FlujoInvalido):
        _gastado(b"zz>", ["/AHx"])


@pytest.mark.parametrize("nombre", ["/ASCII85Decode", "/A85"])
def test_ascii85_seguido_de_flate(nombre: str) -> None:
    crudo = base64.a85encode(zlib.compress(bytes(3 * MIB))) + b"~>"
    with pytest.raises(TopeDescompresion):
        _gastado(crudo, [nombre, FLATE], tope=MIB)


def test_ascii85_cuenta_las_z_como_cuatro_ceros() -> None:
    assert _gastado(b"z z\nz~>", ["/A85"]) == 12


@pytest.mark.parametrize("nombre", ["/RunLengthDecode", "/RL"])
def test_run_length(nombre: str) -> None:
    # 100 copias de "a" (257 - 157), 3 bytes literales y el fin de datos.
    crudo = bytes([157]) + b"a" + bytes([2]) + b"xyz" + bytes([128])
    assert _gastado(crudo, [nombre]) == 103


def test_run_length_bomba_corta() -> None:
    crudo = (bytes([129]) + b"\0") * 10_000  # 128 bytes por cada 2
    with pytest.raises(TopeDescompresion):
        _gastado(crudo, ["/RunLengthDecode"], tope=100_000)


@pytest.mark.parametrize("temprano", [1, 0], ids=["temprano", "tardio"])
def test_lzw_cuenta_lo_descomprimido(temprano: int) -> None:
    datos = b"abcabcabcabd" * 3000 + bytes(range(256)) * 20
    gastado = _gastado(
        _lzw(datos, temprano), ["/LZWDecode"], cambio_temprano=(temprano,)
    )
    assert gastado == len(datos)


def test_lzw_bomba_corta_sin_producirla_entera() -> None:
    presupuesto = Presupuesto(MIB)
    with pytest.raises(TopeDescompresion):
        medir_flujo(_lzw(bytes(20 * MIB)), ["/LZW"], presupuesto)
    assert presupuesto.restante >= -256 * 1024


def test_lzw_con_un_codigo_imposible_es_flujo_invalido() -> None:
    # clear (256) y luego 300, que no está en la tabla: 9 bits cada uno, MSB primero.
    crudo = int(f"{256:09b}{300:09b}000000", 2).to_bytes(3, "big")
    with pytest.raises(FlujoInvalido):
        _gastado(crudo, ["/LZWDecode"])


def test_flate_corrupto_es_flujo_invalido() -> None:
    with pytest.raises(FlujoInvalido):
        _gastado(b"esto no es zlib", [FLATE])


def test_flate_truncado_no_es_error() -> None:
    assert _gastado(zlib.compress(bytes(100_000))[:-6], [FLATE]) > 0


@pytest.mark.parametrize(
    "terminal", ["/DCTDecode", "/DCT", "/JPXDecode", "/CCITTFaxDecode", "/CCF"]
)
def test_los_codecs_de_imagen_no_se_decodifican(terminal: str) -> None:
    assert _gastado(b"bytes de imagen", [terminal]) == 0


def test_codec_de_imagen_tras_flate_cuenta_solo_flate() -> None:
    assert _gastado(zlib.compress(bytes(1000)), [FLATE, "/DCTDecode"]) == 1000


@pytest.mark.parametrize("filtro", ["/Inventado", "/Crypt", ""])
def test_filtro_desconocido_no_se_da_por_bueno(filtro: str) -> None:
    with pytest.raises(FiltroNoAdmitido):
        _gastado(b"x", [filtro])
