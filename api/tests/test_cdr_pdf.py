"""Saneamiento de PDF (F3.04–F3.07, K13): casos que la matriz de ataque no fija."""

import io
import os
import zlib
from pathlib import Path

import pikepdf
import pytest
from pikepdf import Array, Dictionary, Name, String

from api.app import cdr_pdf
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


# ------------------------------------------------------------------ K46: tamaño de la salida


def test_k46_un_objstm_no_se_reescribe_sin_comprimir(tmp_path: Path) -> None:
    """Regresión: 5 MB de cadena dentro de un /ObjStm comprimido salían sin comprimir."""
    pdf = _pdf()
    pdf.Root.GkDatos = pdf.make_indirect(String("a" * 5_000_000))
    entrada = tmp_path / "entrada"
    pdf.save(entrada, object_stream_mode=pikepdf.ObjectStreamMode.generate)
    assert entrada.stat().st_size < 100_000
    salida = tmp_path / "salida"

    assert sanear_pdf(entrada, salida) is None
    assert salida.stat().st_size <= 2 * entrada.stat().st_size


def test_k46_los_flujos_se_siguen_copiando_sin_decodificar(tmp_path: Path) -> None:
    """`compress_streams` no puede llevar a decodificar lo que ya venía comprimido (K13)."""
    pdf = _pdf()
    crudo = zlib.compress(b"datos de prueba " * 100, 1)
    flujo = pdf.make_stream(b"")
    flujo.write(crudo, filter=Name.FlateDecode)
    pdf.Root.Gk = pdf.make_indirect(flujo)
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo is None
    with pikepdf.open(salida) as resultado:
        assert resultado.Root.Gk.read_raw_bytes() == crudo


def test_k46_salida_sobre_el_tope_se_rechaza_sin_dejarla(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cdr_pdf, "TOPE_SALIDA", 200)
    pdf = _pdf()
    pdf.Root.Gk = pdf.make_indirect(pdf.make_stream(os.urandom(4096)))
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo == "salida_grande"
    assert not salida.exists()


def test_k46_el_tope_de_salida_es_el_de_la_decision() -> None:
    assert cdr_pdf.TOPE_SALIDA == 32 * MIB


# ------------------------------------------------------- F3.04: referencias externas


def _exigir_sin_claves(salida: Path, claves: set[str]) -> None:
    with pikepdf.open(salida) as resultado:
        assert not _nombres(resultado) & claves


def test_f304_flujo_con_datos_externos_pierde_f_ffilter_y_fdecodeparms(
    tmp_path: Path,
) -> None:
    pdf = _pdf()
    flujo = pdf.make_stream(b"datos")
    flujo.F = Dictionary(FS=Name.URL, F=String("http://ejemplo.invalid/x"))
    flujo.FFilter = Name.FlateDecode
    flujo.FDecodeParms = Dictionary()
    pdf.Root.Gk = pdf.make_indirect(flujo)
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo is None
    with pikepdf.open(salida) as resultado:
        gk = resultado.Root.Gk
        assert not {"/F", "/FFilter", "/FDecodeParms"} & set(gk.keys())
        assert gk.read_bytes() == b"datos"


def test_f304_f_de_un_diccionario_que_no_es_flujo_se_conserva(tmp_path: Path) -> None:
    """`/F` solo es una referencia externa en un flujo; en un diccionario puede ser otra cosa."""
    pdf = _pdf()
    pdf.Root.Gk = Dictionary(F=4)
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo is None
    with pikepdf.open(salida) as resultado:
        assert resultado.Root.Gk.F == 4


@pytest.mark.parametrize("clave", ["/Ref", "/OPI"])
def test_f304_ref_y_opi_se_quitan(tmp_path: Path, clave: str) -> None:
    pdf = _pdf()
    formulario = pdf.make_stream(b"q Q")
    formulario.Type = Name.XObject
    formulario.Subtype = Name.Form
    formulario[clave] = Dictionary(F=String("http://ejemplo.invalid/x"))
    pdf.Root.Gk = pdf.make_indirect(formulario)
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo is None
    _exigir_sin_claves(salida, {clave})


def _incrustado(pdf: pikepdf.Pdf) -> pikepdf.Stream:
    return pdf.make_stream(b"MZ carga", Type=Name.EmbeddedFile)


def test_f304_embeddedfile_en_clave_propia_se_quita(tmp_path: Path) -> None:
    pdf = _pdf()
    pdf.Root.GkOculto = _incrustado(pdf)
    pdf.Root.GkLista = Array([1, _incrustado(pdf)])
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo is None
    with pikepdf.open(salida) as resultado:
        assert "/GkOculto" not in resultado.Root
        assert list(resultado.Root.GkLista) == [1]
        for objeto in resultado.objects:
            if isinstance(objeto, pikepdf.Stream):
                assert objeto.get("/Type") != Name.EmbeddedFile
    assert b"MZ carga" not in salida.read_bytes()


# ------------------------------------------------------------ K49: imágenes en línea


def _en_linea(datos: bytes, alto: int, filtro: bytes = b"/F /Fl") -> bytes:
    return (
        b"q 100 0 0 100 0 0 cm\nBI /W 1024 /H %d /CS /G /BPC 8 %s /L %d ID "
        % (alto, filtro, len(datos))
        + datos
        + b"\nEI Q\n"
    )


def _bomba_en_linea(mib: int, filtro: bytes = b"/F /Fl") -> bytes:
    return _en_linea(_ceros_comprimidos(mib), mib * 1024, filtro)


def _pdf_con_contenido(contenido: bytes) -> pikepdf.Pdf:
    pdf = _pdf()
    pdf.pages[0].Contents = pdf.make_stream(contenido)
    return pdf


def test_k49_en_linea_sobre_el_tope_en_la_pagina(tmp_path: Path) -> None:
    pdf = _pdf_con_contenido(_bomba_en_linea(120))
    motivo, salida = _sanear(pdf, tmp_path)
    assert motivo == "descompresion"
    assert not salida.exists()


@pytest.mark.parametrize(
    "filtro",
    [b"/F /Fl", b"/Filter /FlateDecode", b"/F [/Fl]", b"/Filter [/FlateDecode]"],
)
def test_k49_en_linea_entiende_las_abreviaturas(tmp_path: Path, filtro: bytes) -> None:
    assert _sanear(_pdf_con_contenido(_bomba_en_linea(120, filtro)), tmp_path)[0] == (
        "descompresion"
    )


def test_k49_en_linea_en_un_contenido_comprimido(tmp_path: Path) -> None:
    pdf = _pdf()
    contenido = pdf.make_stream(b"")
    contenido.write(zlib.compress(_bomba_en_linea(120)), filter=Name.FlateDecode)
    pdf.pages[0].Contents = contenido
    assert _sanear(pdf, tmp_path)[0] == "descompresion"


def test_k49_en_linea_en_un_contenido_con_predictor(tmp_path: Path) -> None:
    """Con predictor PNG de una columna, `BI` no aparece en la salida de Flate: se parsea igual."""
    claro = _bomba_en_linea(120)
    filas = b"".join(b"\x00" + bytes([byte]) for byte in claro)
    assert b"BI" not in filas
    pdf = _pdf()
    contenido = pdf.make_stream(b"")
    contenido.write(
        zlib.compress(filas),
        filter=Name.FlateDecode,
        decode_parms=Dictionary(Predictor=12, Columns=1),
    )
    pdf.pages[0].Contents = contenido
    assert _sanear(pdf, tmp_path)[0] == "descompresion"


def test_k49_en_linea_partida_entre_dos_contenidos_de_la_pagina(tmp_path: Path) -> None:
    contenido = _bomba_en_linea(120)
    corte = contenido.index(b" ID ") + 1
    pdf = _pdf()
    pdf.pages[0].Contents = Array(
        [
            pdf.make_stream(contenido[:corte]),
            pdf.make_stream(contenido[corte:]),
        ]
    )
    assert _sanear(pdf, tmp_path)[0] in ("descompresion", "pdf_invalido")


def _formulario(pdf: pikepdf.Pdf, contenido: bytes) -> pikepdf.Stream:
    formulario = pdf.make_stream(contenido)
    formulario.Type = Name.XObject
    formulario.Subtype = Name.Form
    formulario.BBox = Array([0, 0, 100, 100])
    return formulario


def test_k49_en_linea_en_un_formulario(tmp_path: Path) -> None:
    pdf = _pdf_con_contenido(b"q /GkForm Do Q\n")
    pdf.pages[0].Resources = Dictionary(
        XObject=Dictionary(GkForm=_formulario(pdf, _bomba_en_linea(120)))
    )
    assert _sanear(pdf, tmp_path)[0] == "descompresion"


def test_k49_en_linea_en_un_patron_de_mosaico(tmp_path: Path) -> None:
    pdf = _pdf_con_contenido(b"/Pattern cs /GkP scn 0 0 100 100 re f\n")
    patron = pdf.make_stream(_bomba_en_linea(120))
    patron.PatternType = 1
    patron.PaintType = 1
    patron.TilingType = 1
    patron.BBox = Array([0, 0, 10, 10])
    patron.XStep = 10
    patron.YStep = 10
    patron.Resources = Dictionary()
    pdf.pages[0].Resources = Dictionary(Pattern=Dictionary(GkP=patron))
    assert _sanear(pdf, tmp_path)[0] == "descompresion"


def test_k49_en_linea_en_un_glifo_de_type3(tmp_path: Path) -> None:
    pdf = _pdf_con_contenido(b"BT /GkT3 12 Tf (a) Tj ET\n")
    fuente = Dictionary(
        Type=Name.Font,
        Subtype=Name.Type3,
        FontBBox=Array([0, 0, 1, 1]),
        FontMatrix=Array([1, 0, 0, 1, 0, 0]),
        CharProcs=Dictionary(a=pdf.make_stream(b"1 0 d0 " + _bomba_en_linea(120))),
        Encoding=Dictionary(Differences=Array([97, Name("/a")])),
        FirstChar=97,
        LastChar=97,
        Widths=Array([1]),
    )
    pdf.pages[0].Resources = Dictionary(Font=Dictionary(GkT3=fuente))
    assert _sanear(pdf, tmp_path)[0] == "descompresion"


def test_k49_en_linea_y_flujo_suman_un_solo_presupuesto(tmp_path: Path) -> None:
    pdf = _pdf_con_contenido(_bomba_en_linea(60))
    flujo = pdf.make_stream(b"")
    flujo.write(_ceros_comprimidos(60), filter=Name.FlateDecode)
    pdf.Root.Gk = pdf.make_indirect(flujo)
    assert _sanear(pdf, tmp_path)[0] == "descompresion"


def test_k49_filtro_tras_un_codec_en_un_flujo(tmp_path: Path) -> None:
    pdf = _pdf()
    flujo = pdf.make_stream(zlib.compress(b"\xff\xd8\xff"))
    flujo.Filter = Array([Name.DCTDecode, Name.FlateDecode])
    pdf.Root.Gk = pdf.make_indirect(flujo)
    assert _sanear(pdf, tmp_path)[0] == "flujo_invalido"


def test_k49_filtro_tras_un_codec_en_linea(tmp_path: Path) -> None:
    datos = zlib.compress(b"\xff\xd8\xff")
    pdf = _pdf_con_contenido(_en_linea(datos, 1, b"/F [/DCT /Fl]"))
    assert _sanear(pdf, tmp_path)[0] == "flujo_invalido"


def test_k49_filtro_en_linea_desconocido(tmp_path: Path) -> None:
    pdf = _pdf_con_contenido(_en_linea(b"xx", 1, b"/F /Inventado"))
    assert _sanear(pdf, tmp_path)[0] == "flujo_invalido"


def test_k49_en_linea_pequena_se_conserva(tmp_path: Path) -> None:
    contenido = _en_linea(zlib.compress(bytes(1024)), 1)
    motivo, salida = _sanear(_pdf_con_contenido(contenido), tmp_path)
    assert motivo is None
    with pikepdf.open(salida) as resultado:
        assert resultado.pages[0].Contents.read_bytes() == contenido


def test_k49_un_contenido_sin_bi_no_se_parsea(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Parsear el contenido cuesta ~70 ms en 200 páginas de texto: solo si puede haber `BI`."""
    llamadas: list[object] = []
    original = pikepdf.parse_content_stream

    def _espia(*argumentos: object, **opciones: object) -> object:
        llamadas.append(argumentos[0])
        return original(*argumentos, **opciones)

    monkeypatch.setattr(pikepdf, "parse_content_stream", _espia)
    pdf = _pdf_con_contenido(b"BT /F1 12 Tf (Hola) Tj ET\n" * 100)
    pdf.add_blank_page().Contents = pdf.make_stream(_en_linea(bytes(1024), 1, b""))
    assert _sanear(pdf, tmp_path)[0] is None
    assert len(llamadas) == 1


# ------------------------------------- K49: imagen en línea escondida dentro de otra


def _escondida(mib: int) -> bytes:
    return (
        b"BI /W 1024 /H %d /BPC 8 /CS /G /F /Fl ID\n" % (mib * 1024)
        + _ceros_comprimidos(mib)
        + b"\nEI\nQ\n"
    )


@pytest.mark.parametrize(
    "primera",
    [
        b"BI /W 1 /H 1 /BPC 8 /CS /G ID\nX\nEI\n\x01\x02\n",
        b"BI /W 1 /H 1 /BPC 8 /CS /G ID\nX\nEI\nx1\n",
        b"BI /W 1 /H 1 /BPC 8 /CS /G /F /Fl ID\n"
        + zlib.compress(b"X")
        + b"\nEI\n\x01\n",
        b"BI /W 1 /H 1 /BPC 8 /CS /G /F /AHx ID\n58>\nEI\n\x01\n",
    ],
    ids=["sin_filtro_control", "sin_filtro_palabra", "flate", "hex"],
)
def test_k49_imagen_escondida_tras_el_fin_de_otra(
    tmp_path: Path, primera: bytes
) -> None:
    pdf = _pdf_con_contenido(b"q\n" + primera + _escondida(1))
    assert _sanear(pdf, tmp_path)[0] == "flujo_invalido"


def test_k49_dos_imagenes_en_linea_legitimas(tmp_path: Path) -> None:
    imagen = (
        b"BI /W 2 /H 2 /BPC 8 /CS /G /F /Fl ID\n"
        + zlib.compress(b"\x10\x20\x30\x40")
        + b"\nEI\nQ\n"
    )
    motivo, _ = _sanear(_pdf_con_contenido(b"q\n" + imagen + b"q\n" + imagen), tmp_path)
    assert motivo is None


@pytest.mark.parametrize(
    ("diccionario", "datos"),
    [
        (b"/W 2 /H 2 /BPC 8 /CS /G", b"abcd"),
        (b"/W 2 /H 1 /BPC 8 /CS /RGB", b"abcdef"),
        (b"/W 1 /H 1 /BPC 8 /CS /CMYK", b"abcd"),
        (b"/W 9 /H 2 /IM true", b"\x01\x02\x03\x04"),
        (b"/W 3 /H 1 /BPC 4 /CS /G", b"\x12\x30"),
        (b"/W 2 /H 1 /BPC 8 /CS [/I /RGB 1 <000000FFFFFF>]", b"\x00\x01"),
    ],
    ids=["gris", "rgb", "cmyk", "mascara", "4_bits", "indexado"],
)
def test_k49_sin_filtro_con_el_tamano_justo_se_conserva(
    tmp_path: Path, diccionario: bytes, datos: bytes
) -> None:
    contenido = b"q BI " + diccionario + b" ID " + datos + b" EI Q\n"
    motivo, salida = _sanear(_pdf_con_contenido(contenido), tmp_path)
    assert motivo is None
    with pikepdf.open(salida) as resultado:
        assert resultado.pages[0].Contents.read_bytes() == contenido


@pytest.mark.parametrize(
    "contenido",
    [
        b"q BI /W 2 /H 2 /BPC 8 /CS /G ID ab EI Q\n",
        b"q BI /W 2 /H 1 /BPC 8 /CS /CS0 ID ab EI Q\n",
        b"q BI /W 2 /H 1 /BPC 8 ID ab EI Q\n",
    ],
    ids=["corta", "espacio_con_nombre", "sin_espacio"],
)
def test_k49_sin_filtro_sin_tamano_conocido_se_rechaza(
    tmp_path: Path, contenido: bytes
) -> None:
    """Si no se sabe cuántos bytes lee el lector, no se sabe dónde vuelve al contenido."""
    assert _sanear(_pdf_con_contenido(contenido), tmp_path)[0] == "flujo_invalido"


def test_k49_flate_que_produce_mas_de_lo_que_pide_la_imagen(tmp_path: Path) -> None:
    """El lector deja de leer a mitad de zlib y busca `EI` en los bytes comprimidos."""
    datos = zlib.compress(b"X" * 100)
    contenido = b"q BI /W 1 /H 1 /BPC 8 /CS /G /F /Fl ID\n" + datos + b"\nEI Q\n"
    assert _sanear(_pdf_con_contenido(contenido), tmp_path)[0] == "flujo_invalido"


def test_k49_con_predictor_png_cuenta_un_byte_por_fila(tmp_path: Path) -> None:
    filas = b"\x00ab\x00cd"
    contenido = (
        b"q BI /W 2 /H 2 /BPC 8 /CS /G /F /Fl /DP << /Predictor 12 /Columns 2 >> ID\n"
        + zlib.compress(filas)
        + b"\nEI Q\n"
    )
    assert _sanear(_pdf_con_contenido(contenido), tmp_path)[0] is None


def test_k49_espacio_con_nombre_y_filtro_no_se_rechaza(tmp_path: Path) -> None:
    """Con filtro el fin lo da el filtro; el tamaño solo se compara si se conoce."""
    contenido = (
        b"q BI /W 2 /H 1 /BPC 8 /CS /CS0 /F /Fl ID\n"
        + zlib.compress(b"ab")
        + b"\nEI Q\n"
    )
    assert _sanear(_pdf_con_contenido(contenido), tmp_path)[0] is None


def test_k49_ei_entre_blancos_dentro_de_los_datos_se_rechaza(tmp_path: Path) -> None:
    """Defensa en profundidad: un lector que corte en el primer `EI` vería otra cosa."""
    datos = b"ab\nEI\nef"
    contenido = b"q BI /W 8 /H 1 /BPC 8 /CS /G ID " + datos + b" EI Q\n"
    assert _sanear(_pdf_con_contenido(contenido), tmp_path)[0] == "flujo_invalido"


def test_k49_en_linea_ccitt_se_rechaza(tmp_path: Path) -> None:
    contenido = b"q BI /W 8 /H 1 /IM true /F /CCF ID \x00\x00 EI Q\n"
    assert _sanear(_pdf_con_contenido(contenido), tmp_path)[0] == "flujo_invalido"
