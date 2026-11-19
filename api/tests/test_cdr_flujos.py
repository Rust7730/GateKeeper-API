"""K13: descompresión acotada, por PDF y a través de cadenas de filtros."""

import base64
import binascii
import zlib

import pytest

from api.app.cdr_flujos import (
    BLOQUE,
    FiltroNoAdmitido,
    FlujoInvalido,
    Presupuesto,
    TopeDescompresion,
    medir_en_linea,
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


# ------------------------------------------------- K49: filtro detrás de un códec de imagen


@pytest.mark.parametrize(
    "cadena",
    [
        ["/DCTDecode", FLATE],
        ["/DCT", "/Fl"],
        ["/JPXDecode", "/ASCIIHexDecode"],
        [FLATE, "/CCITTFaxDecode", FLATE],
    ],
    ids=["dct_flate", "abreviados", "jpx_hex", "en_medio"],
)
def test_k49_un_filtro_tras_un_codec_de_imagen_no_se_admite(cadena: list[str]) -> None:
    """No se puede medir sin decodificar el códec: no se da por bueno."""
    with pytest.raises(FiltroNoAdmitido):
        _gastado(zlib.compress(bytes(1000)), cadena)


# ------------------------------------------------------------ K49: búsqueda en la salida


def test_buscar_encuentra_el_texto_en_la_salida_decodificada() -> None:
    presupuesto = Presupuesto()
    datos = zlib.compress(b"q 1 0 0 1 0 0 cm BI /W 1 /H 1 ID x EI Q")
    assert medir_flujo(datos, [FLATE], presupuesto, buscar=b"BI") is True


def test_buscar_sin_coincidencia_es_falso() -> None:
    presupuesto = Presupuesto()
    datos = zlib.compress(b"BT /F1 12 Tf (Hola) Tj ET" * 1000)
    assert medir_flujo(datos, [FLATE], presupuesto, buscar=b"BI") is False


def test_buscar_ve_el_texto_partido_entre_dos_bloques() -> None:
    """La salida llega en bloques de 64 KiB: `B` al final de uno, `I` al principio del otro."""
    claro = b"x" * (BLOQUE - 1) + b"BI" + b"x" * 10
    presupuesto = Presupuesto()
    assert medir_flujo(zlib.compress(claro), [FLATE], presupuesto, buscar=b"BI")


def test_buscar_en_un_flujo_sin_filtros() -> None:
    assert medir_flujo(b"q BI ID EI Q", [], Presupuesto(), buscar=b"BI") is True


def test_buscar_con_codec_de_imagen_al_final_responde_que_no_se_sabe() -> None:
    """La salida real es la del códec, que aquí no se decodifica: se trata como presente."""
    datos = zlib.compress(b"nada")
    assert medir_flujo(datos, [FLATE, "/DCTDecode"], Presupuesto(), buscar=b"BI")


def test_sin_buscar_devuelve_falso() -> None:
    assert medir_flujo(b"BI", [], Presupuesto()) is False


# ------------------------------------- K49: dónde acaban los datos de una imagen en línea


def _en_linea(crudo: bytes, filtros: list[str], **extra) -> int | None:
    return medir_en_linea(crudo, filtros, Presupuesto(), **extra)


@pytest.mark.parametrize(
    ("crudo", "filtros", "producidos"),
    [
        (zlib.compress(b"abcd") + b" \n", [FLATE], 4),
        (b"61 62 63>\n", ["/ASCIIHexDecode"], 3),
        (base64.a85encode(b"abcd") + b"~> ", ["/ASCII85Decode"], 4),
        (b"\x02abc\x80\r", ["/RunLengthDecode"], 3),
        (_lzw(b"abcd") + b"\n", ["/LZWDecode"], 4),
        (binascii.hexlify(zlib.compress(b"ab")) + b">", ["/AHx", "/Fl"], 2),
    ],
    ids=["flate", "hex", "a85", "run_length", "lzw", "hex_y_flate"],
)
def test_en_linea_bien_cerrada_devuelve_lo_producido(
    crudo: bytes, filtros: list[str], producidos: int
) -> None:
    assert _en_linea(crudo, filtros) == producidos


@pytest.mark.parametrize(
    ("crudo", "filtros"),
    [
        (zlib.compress(b"X") + b"\nEI\n\x01\nBI", [FLATE]),
        (b"58>\nEI\nx1\nBI", ["/AHx"]),
        (base64.a85encode(b"X") + b"~>\nEI BI", ["/A85"]),
        (b"\x00X\x80\nEI BI", ["/RL"]),
        (_lzw(b"X") + b"\nEI BI", ["/LZW"]),
    ],
    ids=["flate", "hex", "a85", "run_length", "lzw"],
)
def test_en_linea_con_algo_tras_el_fin_es_invalida(
    crudo: bytes, filtros: list[str]
) -> None:
    """Lo que sigue al fin de los datos lo lee el lector como contenido: otra imagen, quizá."""
    with pytest.raises(FlujoInvalido):
        _en_linea(crudo, filtros)


@pytest.mark.parametrize(
    ("crudo", "filtros"),
    [
        (zlib.compress(bytes(100))[:-8], [FLATE]),
        (b"616263", ["/AHx"]),
        (base64.a85encode(b"abcd"), ["/A85"]),
        (b"\x02abc", ["/RL"]),
        (_lzw(b"abcd")[:-1], ["/LZW"]),
    ],
    ids=["flate", "hex", "a85", "run_length", "lzw"],
)
def test_en_linea_sin_fin_es_invalida(crudo: bytes, filtros: list[str]) -> None:
    """Sin fin, el lector seguiría leyendo más allá del `EI` que vio qpdf."""
    with pytest.raises(FlujoInvalido):
        _en_linea(crudo, filtros)


def test_en_linea_sobre_el_tope_sigue_siendo_tope() -> None:
    with pytest.raises(TopeDescompresion):
        medir_en_linea(zlib.compress(bytes(2 * MIB)), [FLATE], Presupuesto(MIB))


def test_en_linea_dct_acaba_en_su_eoi() -> None:
    jpeg = b"\xff\xd8\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x12\xff\xd9"
    assert _en_linea(jpeg + b" \n", ["/DCTDecode"]) is None
    with pytest.raises(FlujoInvalido):
        _en_linea(jpeg + b"\nEI BI", ["/DCT"])
    with pytest.raises(FlujoInvalido):
        _en_linea(jpeg[:-2], ["/DCT"])


def test_en_linea_flate_y_luego_dct_no_cuenta_lo_producido() -> None:
    assert _en_linea(zlib.compress(b"\xff\xd8") + b"\n", [FLATE, "/DCTDecode"]) is None


@pytest.mark.parametrize(
    "codec", ["/CCITTFaxDecode", "/CCF", "/JPXDecode", "/JBIG2Decode"]
)
def test_en_linea_con_un_codec_sin_fin_conocido_no_se_admite(codec: str) -> None:
    with pytest.raises(FiltroNoAdmitido):
        _en_linea(b"datos", [codec])
