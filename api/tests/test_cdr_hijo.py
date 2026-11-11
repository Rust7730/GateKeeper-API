"""Proceso hijo real: stdout de una línea y límites puestos antes de cualquier parser."""

import ast
import json
import subprocess
import sys
from pathlib import Path

import pikepdf
import pytest
from PIL import Image

from api.app import cdr_hijo
from api.app.tipos import TIPOS_PERMITIDOS

RAIZ = Path(__file__).resolve().parents[2]
PROHIBIDOS_AL_IMPORTAR = {"PIL", "pikepdf", "magic", "sqlalchemy", "fastapi"}


def _correr(*argumentos: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "api.app.cdr_hijo", *argumentos],
        check=False,
        cwd=RAIZ,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        timeout=30,
    )


def _veredicto(entrada: Path, salida: Path) -> dict[str, str]:
    resultado = _correr(str(entrada), str(salida))
    assert resultado.returncode == 0, resultado.stderr
    assert resultado.stdout.count(b"\n") == 1
    assert resultado.stdout.endswith(b"\n")
    return json.loads(resultado.stdout)


def test_importar_el_modulo_no_carga_parsers_ni_la_bd() -> None:
    """Sin esto, `RLIMIT_AS` llegaría tarde: el import corre antes de `main`."""
    arbol = ast.parse(Path(cdr_hijo.__file__).read_text())
    importados = set()
    for nodo in arbol.body:
        if isinstance(nodo, ast.Import):
            importados.update(alias.name.partition(".")[0] for alias in nodo.names)
        elif isinstance(nodo, ast.ImportFrom):
            importados.add((nodo.module or "").partition(".")[0])
    assert not importados & PROHIBIDOS_AL_IMPORTAR


def test_main_cierra_y_limita_antes_de_analizar(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """El archivo hostil no se abre con un descriptor ajeno abierto ni sin límites."""
    orden: list[str] = []

    def _analizar(*_: object) -> dict[str, str]:
        orden.append("analizar")
        return {"veredicto": "rechazado", "tipo": "x", "motivo": "y"}

    monkeypatch.setattr(
        cdr_hijo, "cerrar_descriptores_heredados", lambda: orden.append("cerrar")
    )
    monkeypatch.setattr(cdr_hijo, "fijar_limites", lambda: orden.append("limitar"))
    monkeypatch.setattr(cdr_hijo, "analizar", _analizar)

    assert cdr_hijo.main(["entrada", "salida"]) == 0
    assert orden == ["cerrar", "limitar", "analizar"]
    capsys.readouterr()


def test_cerrar_descriptores_no_recorre_todo_el_rango() -> None:
    """Este Python no usa `close_range`: `os.closerange` hace una llamada por cada número.

    Con 1 048 576 de `SC_OPEN_MAX` eso son 350 ms en cada archivo, un 20 % de M2.
    """
    codigo = (
        "import time\n"
        "from api.app.cdr_hijo import cerrar_descriptores_heredados as cerrar\n"
        "inicio = time.perf_counter()\n"
        "cerrar()\n"
        "print((time.perf_counter() - inicio) * 1000)\n"
    )
    resultado = subprocess.run(
        [sys.executable, "-c", codigo],
        check=True,
        cwd=RAIZ,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert float(resultado.stdout) < 5


def test_sin_dos_argumentos_sale_con_2() -> None:
    assert _correr().returncode == 2
    assert _correr("uno").returncode == 2
    assert _correr("uno", "dos", "tres").returncode == 2


def test_entrada_inexistente_no_es_veredicto(tmp_path: Path) -> None:
    resultado = _correr(str(tmp_path / "no_existe"), str(tmp_path / "salida"))
    assert resultado.returncode != 0
    assert resultado.stdout == b""


def test_tipo_fuera_de_la_lista_blanca(tmp_path: Path) -> None:
    entrada = tmp_path / "entrada"
    entrada.write_bytes(b"#!/bin/sh\nid\n")
    salida = tmp_path / "salida"
    veredicto = _veredicto(entrada, salida)
    assert veredicto["veredicto"] == "rechazado"
    assert veredicto["motivo"] == "tipo_no_permitido"
    assert veredicto["tipo"] not in TIPOS_PERMITIDOS
    assert not salida.exists()


def test_png_limpio(tmp_path: Path) -> None:
    entrada = tmp_path / "entrada"
    Image.new("RGB", (4, 4)).save(entrada, "PNG")
    salida = tmp_path / "salida"
    assert _veredicto(entrada, salida) == {
        "veredicto": "limpio",
        "tipo": "image/png",
        "motivo": "ok",
    }
    assert salida.exists()


def test_k39_girar_40_mp_rgba_cabe_en_rlimit_as(tmp_path: Path) -> None:
    """El peor caso de K39, con el hijo real: 40 MP a 4 bytes por píxel, girados."""
    exif = Image.Exif()
    exif[0x0112] = 6
    entrada = tmp_path / "entrada"
    Image.new("RGBA", (8000, 5000), (9, 9, 9, 9)).save(entrada, "PNG", exif=exif)
    salida = tmp_path / "salida"

    assert _veredicto(entrada, salida)["veredicto"] == "limpio"

    with Image.open(salida) as resultado:
        assert resultado.size == (5000, 8000)


def test_pdf_limpio(tmp_path: Path) -> None:
    entrada = tmp_path / "entrada"
    pdf = pikepdf.new()
    pdf.add_blank_page()
    pdf.save(entrada)
    salida = tmp_path / "salida"
    assert _veredicto(entrada, salida)["tipo"] == "application/pdf"
    assert salida.exists()


@pytest.mark.parametrize(
    ("firma", "motivo"),
    [(b"\xff\xd8\xff\xe0", "imagen_invalida"), (b"%PDF-1.7\n", "pdf_invalido")],
    ids=["jpeg", "pdf"],
)
def test_firma_falsa_es_rechazado_con_su_tipo(
    tmp_path: Path, firma: bytes, motivo: str
) -> None:
    entrada = tmp_path / "entrada"
    entrada.write_bytes(firma + b"<?php phpinfo(); ?>" * 8)
    veredicto = _veredicto(entrada, tmp_path / "salida")
    assert veredicto["veredicto"] == "rechazado"
    assert veredicto["motivo"] == motivo
    assert veredicto["tipo"] in TIPOS_PERMITIDOS
