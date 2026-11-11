"""Saneamiento de PDF (F3.04–F3.07, K13): casos que la matriz de ataque no fija."""

import io
import zlib
from pathlib import Path

import pikepdf
import pytest
from pikepdf import Array, Dictionary, Name, String

from api.app.cdr_pdf import MAX_PAGINAS, sanear_pdf
from api.tests.test_cdr_flujos import _lzw

MIB = 1024 * 1024


def _pdf() -> pikepdf.Pdf:
    pdf = pikepdf.new()
    pagina = pdf.add_blank_page(page_size=(200, 200))
    pagina.Contents = pdf.make_stream(b"BT ET")
    return pdf


def _a_disco(pdf: pikepdf.Pdf, tmp_path: Path) -> Path:
    ruta = tmp_path / "entrada"
    pdf.save(
        ruta,
        stream_decode_level=pikepdf.StreamDecodeLevel.none,
        compress_streams=False,
    )
    return ruta


def _sanear(pdf: pikepdf.Pdf, tmp_path: Path) -> tuple[str | None, Path]:
    entrada = _a_disco(pdf, tmp_path)
    salida = tmp_path / "salida"
    return sanear_pdf(entrada, salida), salida


def _nombres(pdf: pikepdf.Pdf) -> set[str]:
    hallados: set[str] = set()
    pila = [*pdf.objects, pdf.trailer]
    while pila:
        objeto = pila.pop()
        if isinstance(objeto, pikepdf.Name):
            hallados.add(str(objeto))
        elif isinstance(objeto, pikepdf.Array):
            pila.extend(v for v in objeto if _directo(v))
        elif isinstance(objeto, pikepdf.Dictionary | pikepdf.Stream):
            hallados.update(objeto.keys())
            pila.extend(objeto[k] for k in objeto.keys() if _directo(objeto[k]))  # noqa: SIM118
    return hallados


def _directo(valor: object) -> bool:
    return isinstance(valor, pikepdf.Object) and not valor.is_indirect


def _accion(codigo: str = "app.alert(1)") -> Dictionary:
    return Dictionary(S=Name.JavaScript, JS=String(codigo))


def _flujo_crudo(numero: int, claves: bytes, datos: bytes) -> bytes:
    cabecera = b"%d 0 obj\n<< %s /Length %d >>\nstream\n" % (numero, claves, len(datos))
    return cabecera + datos + b"\nendstream\nendobj\n"


def _ceros_comprimidos(mib: int) -> bytes:
    compresor = zlib.compressobj(9)
    partes = [compresor.compress(bytes(MIB)) for _ in range(mib)]
    return b"".join(partes) + compresor.flush()


def _pdf_con_pagina_en_objstm(mib: int) -> bytes:
    """La página vive dentro del `/ObjStm`: contar páginas ya obliga a abrir la bomba."""
    cabecera = b"3 0 "
    pagina = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 9 9] >> "
    compresor = zlib.compressobj(9)
    comprimido = compresor.compress(cabecera + pagina)
    comprimido += b"".join(compresor.compress(bytes(MIB)) for _ in range(mib))
    comprimido += compresor.flush()

    salida = bytearray(b"%PDF-1.7\n")
    posiciones = [len(salida)]
    salida += b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    posiciones.append(len(salida))
    salida += b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    posiciones.append(len(salida))
    salida += _flujo_crudo(
        4,
        b"/Type /ObjStm /N 1 /First %d /Filter /FlateDecode" % len(cabecera),
        comprimido,
    )
    inicio_xref = len(salida)
    filas = [
        (0, 0, 65535),
        (1, posiciones[0], 0),
        (1, posiciones[1], 0),
        (2, 4, 0),
        (1, posiciones[2], 0),
        (1, inicio_xref, 0),
    ]
    tabla = b"".join(
        bytes([tipo]) + uno.to_bytes(4, "big") + dos.to_bytes(2, "big")
        for tipo, uno, dos in filas
    )
    salida += _flujo_crudo(5, b"/Type /XRef /Size 6 /W [1 4 2] /Root 1 0 R", tabla)
    salida += b"startxref\n%d\n%%%%EOF\n" % inicio_xref
    return bytes(salida)


def _pdf_con_xref_bomba(mib: int) -> bytes:
    salida = bytearray(b"%PDF-1.7\n")
    inicio = len(salida)
    salida += _flujo_crudo(
        1,
        b"/Type /XRef /Size 2 /W [1 4 2] /Root 1 0 R /Filter /FlateDecode",
        _ceros_comprimidos(mib),
    )
    salida += b"startxref\n%d\n%%%%EOF\n" % inicio
    return bytes(salida)


def _pdf_a_mano(extra: bytes = b"", accion: bytes = b"/S /JavaScript") -> bytes:
    """PDF escrito a mano: `pikepdf.Name` no deja crear nombres que no sean UTF-8."""
    return (
        b"%%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R %s >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 9 9] >>\nendobj\n"
        b"4 0 obj\n<< %s /JS (app.alert\\(1\\)) >>\nendobj\n"
        b"5 0 obj\n<< /Length 1 /Filter /Fl#E4 >>\nstream\nx\nendstream\nendobj\n"
        b"trailer\n<< /Size 6 /Root 1 0 R >>\n" % (extra, accion)
    )


def _sanear_crudo(contenido: bytes, tmp_path: Path) -> tuple[str | None, Path]:
    entrada = tmp_path / "entrada"
    entrada.write_bytes(contenido)
    salida = tmp_path / "salida"
    return sanear_pdf(entrada, salida), salida


def test_el_limite_es_el_del_parametro() -> None:
    assert MAX_PAGINAS == 200


def test_pdf_legitimo_conserva_lo_inofensivo(tmp_path: Path) -> None:
    pdf = _pdf()
    pdf.Root.PageMode = Name.UseOutlines
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo is None
    with pikepdf.open(salida) as resultado:
        assert len(resultado.pages) == 1
        assert resultado.Root.PageMode == Name.UseOutlines
        assert resultado.pages[0].Contents.read_bytes() == b"BT ET"


def test_cadena_de_acciones_por_next_directa_e_indirecta(tmp_path: Path) -> None:
    """Una acción inofensiva puede llevar la peligrosa colgada de `/Next`."""
    pdf = _pdf()
    indirecta = pdf.make_indirect(_accion("indirecta"))
    salto = Dictionary(
        S=Name.GoTo, D=Array([pdf.pages[0].obj, Name.Fit]), Next=indirecta
    )
    entrada = pdf.make_indirect(Dictionary(Title=String("x"), A=salto))
    entrada.Parent = pdf.make_indirect(
        Dictionary(Type=Name.Outlines, First=entrada, Last=entrada, Count=1)
    )
    pdf.Root.Outlines = entrada.Parent

    motivo, salida = _sanear(pdf, tmp_path)

    assert motivo is None
    assert b"indirecta" not in salida.read_bytes()
    with pikepdf.open(salida) as resultado:
        assert "/Outlines" in resultado.Root
        assert not {"/JS", "/Next", "/A"} & _nombres(resultado)


def test_accion_dentro_de_un_array_sin_nombre_conocido(tmp_path: Path) -> None:
    pdf = _pdf()
    pdf.Root.GkLista = Array(
        [1, _accion("en_lista"), pdf.make_indirect(_accion("otra"))]
    )
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo is None
    assert b"en_lista" not in salida.read_bytes()
    assert b"otra" not in salida.read_bytes()
    with pikepdf.open(salida) as resultado:
        assert list(resultado.Root.GkLista) == [1]


def test_accion_con_type_action_y_s_desconocido(tmp_path: Path) -> None:
    pdf = _pdf()
    pdf.Root.Gk = Dictionary(Type=Name.Action, S=Name.Inventada, X=String("marca"))
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo is None
    assert b"marca" not in salida.read_bytes()


def test_pa_de_una_anotacion_huerfana_tambien_se_quita(tmp_path: Path) -> None:
    pdf = _pdf()
    pdf.Root.Gk = pdf.make_indirect(
        Dictionary(PA=Dictionary(S=Name.URI, URI=String("http://atacante.test/x")))
    )
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo is None
    assert b"atacante.test" not in salida.read_bytes()


def test_s_de_otro_contexto_no_se_toma_por_accion(tmp_path: Path) -> None:
    """`/S /Transparency` en `/Group` no es una acción: quitarlo cambiaría el render."""
    pdf = _pdf()
    pdf.pages[0].Group = Dictionary(Type=Name.Group, S=Name.Transparency)
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo is None
    with pikepdf.open(salida) as resultado:
        assert resultado.pages[0].Group.S == Name.Transparency


def test_xmp_de_una_imagen_tambien_se_quita(tmp_path: Path) -> None:
    pdf = _pdf()
    pdf.pages[0].Resources = Dictionary(
        XObject=Dictionary(
            Im0=pdf.make_stream(
                b"\0",
                Type=Name.XObject,
                Subtype=Name.Image,
                Width=1,
                Height=1,
                BitsPerComponent=8,
                ColorSpace=Name.DeviceGray,
                Metadata=pdf.make_stream(b"<xmp>marca</xmp>"),
            )
        )
    )
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo is None
    assert b"marca" not in salida.read_bytes()


def test_trailer_con_una_accion_en_clave_propia(tmp_path: Path) -> None:
    pdf = _pdf()
    pdf.trailer.GkTrailer = pdf.make_indirect(_accion("en_trailer"))
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo is None
    assert b"en_trailer" not in salida.read_bytes()


def test_sin_info_aunque_qpdf_pudiera_crearlo(tmp_path: Path) -> None:
    pdf = _pdf()
    pdf.docinfo["/Author"] = "autor-marca"
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo is None
    assert b"autor-marca" not in salida.read_bytes()
    with pikepdf.open(salida) as resultado:
        assert "/Info" not in resultado.trailer


def test_bomba_lzw_rechazada(tmp_path: Path) -> None:
    """El tope de K13 también vale para LZW: 110 flujos de 1 MiB, y qpdf no interviene."""
    pdf = _pdf()
    comprimido = _lzw(bytes(MIB))
    flujos = []
    for _ in range(110):
        flujo = pdf.make_stream(b"")
        flujo.write(comprimido, filter=Name.LZWDecode)
        flujos.append(pdf.make_indirect(flujo))
    pdf.Root.Gk = pdf.make_indirect(Array(flujos))
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo == "descompresion"
    assert not salida.exists()


def test_lzw_con_early_change_cero_se_mide_con_su_parametro(tmp_path: Path) -> None:
    pdf = _pdf()
    flujo = pdf.make_stream(b"")
    flujo.write(
        _lzw(b"abcabcabd" * 5000, 0),
        filter=Name.LZWDecode,
        decode_parms=Dictionary(EarlyChange=0),
    )
    pdf.Root.Gk = pdf.make_indirect(flujo)
    assert _sanear(pdf, tmp_path)[0] is None


def test_filtro_abreviado_cuenta(tmp_path: Path) -> None:
    pdf = _pdf()
    flujo = pdf.make_stream(b"")
    flujo.write(zlib.compress(bytes(120 * MIB)), filter=Name.Fl)
    pdf.Root.Gk = pdf.make_indirect(flujo)
    assert _sanear(pdf, tmp_path)[0] == "descompresion"


def test_filtro_indirecto_cuenta(tmp_path: Path) -> None:
    pdf = _pdf()
    flujo = pdf.make_stream(b"")
    flujo.write(zlib.compress(bytes(120 * MIB)), filter=Name.FlateDecode)
    flujo.Filter = pdf.make_indirect(Array([Name.FlateDecode]))
    pdf.Root.Gk = pdf.make_indirect(flujo)
    assert _sanear(pdf, tmp_path)[0] == "descompresion"


def test_filtro_desconocido_rechazado(tmp_path: Path) -> None:
    pdf = _pdf()
    flujo = pdf.make_stream(b"")
    flujo.write(b"datos", filter=Name.Inventado)
    pdf.Root.Gk = pdf.make_indirect(flujo)
    assert _sanear(pdf, tmp_path)[0] == "flujo_invalido"


def test_filtro_que_no_es_un_nombre_rechazado(tmp_path: Path) -> None:
    pdf = _pdf()
    pdf.Root.Gk = pdf.make_indirect(pdf.make_stream(b"datos", Filter=String("/Fl")))
    assert _sanear(pdf, tmp_path)[0] == "flujo_invalido"


def test_flate_corrupto_rechazado(tmp_path: Path) -> None:
    pdf = _pdf()
    flujo = pdf.make_stream(b"")
    flujo.write(b"esto no es zlib", filter=Name.FlateDecode)
    pdf.Root.Gk = pdf.make_indirect(flujo)
    assert _sanear(pdf, tmp_path)[0] == "flujo_invalido"


def test_una_imagen_embebida_no_se_decodifica_ni_gasta(tmp_path: Path) -> None:
    pdf = _pdf()
    pdf.Root.Gk = pdf.make_indirect(
        pdf.make_stream(b"\xff\xd8\xff", Filter=Name.DCTDecode)
    )
    assert _sanear(pdf, tmp_path)[0] is None


def test_bomba_en_objstm_con_la_pagina_dentro_se_rechaza(tmp_path: Path) -> None:
    """1100 MiB, más que `RLIMIT_AS`: tampoco aquí se descomprime entero."""
    motivo, salida = _sanear_crudo(_pdf_con_pagina_en_objstm(1100), tmp_path)
    assert motivo == "descompresion"
    assert not salida.exists()


def test_bomba_en_el_flujo_xref_se_rechaza(tmp_path: Path) -> None:
    motivo, salida = _sanear_crudo(_pdf_con_xref_bomba(1100), tmp_path)
    assert motivo == "pdf_invalido"
    assert not salida.exists()


def test_clave_que_no_es_utf8_no_esconde_una_accion(tmp_path: Path) -> None:
    contenido = _pdf_a_mano(b"/G#E4x 4 0 R").replace(b"/Filter /Fl#E4", b"")
    motivo, salida = _sanear_crudo(contenido, tmp_path)
    assert motivo is None
    assert b"app.alert" not in salida.read_bytes()
    with pikepdf.open(salida) as resultado:
        assert not {"/JS", "/JavaScript"} & _nombres(resultado)


def test_filtro_que_no_es_utf8_se_rechaza(tmp_path: Path) -> None:
    motivo, salida = _sanear_crudo(_pdf_a_mano(b"/Gk 5 0 R"), tmp_path)
    assert motivo == "pdf_invalido"
    assert not salida.exists()


def test_tipo_de_accion_que_no_es_utf8_se_rechaza(tmp_path: Path) -> None:
    contenido = _pdf_a_mano(b"/Gk 4 0 R", b"/S /Java#E4cript")
    motivo, salida = _sanear_crudo(contenido.replace(b"/Filter /Fl#E4", b""), tmp_path)
    assert motivo == "pdf_invalido"
    assert not salida.exists()


@pytest.mark.parametrize(
    ("contenido", "motivo"),
    [
        (b"%PDF-1.7\n<?php system($_GET['c']); ?>", "pdf_invalido"),
        (b"%PDF-1.7\n", "pdf_invalido"),
    ],
    ids=["firma_falsa", "solo_cabecera"],
)
def test_lo_que_no_abre_se_rechaza(
    tmp_path: Path, contenido: bytes, motivo: str
) -> None:
    entrada = tmp_path / "entrada"
    entrada.write_bytes(contenido)
    salida = tmp_path / "salida"
    assert sanear_pdf(entrada, salida) == motivo
    assert not salida.exists()


def test_cifrado_con_contrasena_de_usuario_se_rechaza(tmp_path: Path) -> None:
    salida_cifrada = io.BytesIO()
    _pdf().save(
        salida_cifrada, encryption=pikepdf.Encryption(owner="dueno", user="lector")
    )
    entrada = tmp_path / "entrada"
    entrada.write_bytes(salida_cifrada.getvalue())
    assert sanear_pdf(entrada, tmp_path / "salida") == "pdf_cifrado"


def test_cifrado_solo_de_propietario_se_rechaza(tmp_path: Path) -> None:
    salida_cifrada = io.BytesIO()
    _pdf().save(salida_cifrada, encryption=pikepdf.Encryption(owner="dueno", user=""))
    entrada = tmp_path / "entrada"
    entrada.write_bytes(salida_cifrada.getvalue())
    assert sanear_pdf(entrada, tmp_path / "salida") == "pdf_cifrado"


def test_mas_paginas_que_el_limite(tmp_path: Path) -> None:
    pdf = pikepdf.new()
    for _ in range(MAX_PAGINAS + 1):
        pdf.add_blank_page()
    assert _sanear(pdf, tmp_path)[0] == "paginas"


def test_la_salida_no_sigue_un_enlace(tmp_path: Path) -> None:
    entrada = _a_disco(_pdf(), tmp_path)
    victima = tmp_path / "victima"
    victima.write_bytes(b"intacto")
    salida = tmp_path / "salida"
    salida.symlink_to(victima)
    with pytest.raises(OSError):
        sanear_pdf(entrada, salida)
    assert victima.read_bytes() == b"intacto"
