"""K46: la salida del CDR no pasa de 32 MiB, y lo que pase no llega a escribirse."""

from pathlib import Path

import pytest

from api.app.cdr_salida import (
    TOPE_SALIDA,
    SalidaDemasiadoGrande,
    escribir_acotado,
)


def test_el_tope_es_el_de_la_decision() -> None:
    assert TOPE_SALIDA == 32 * 1024 * 1024


def test_escribe_lo_que_cabe(tmp_path: Path) -> None:
    salida = tmp_path / "salida"
    with escribir_acotado(salida, tope=10) as destino:
        destino.write(b"12345")
        destino.write(b"67890")
    assert salida.read_bytes() == b"1234567890"


def test_al_pasar_el_tope_se_corta_y_no_queda_nada(tmp_path: Path) -> None:
    salida = tmp_path / "salida"
    with (
        pytest.raises(SalidaDemasiadoGrande),
        escribir_acotado(salida, tope=10) as destino,
    ):
        destino.write(b"12345")
        destino.write(b"678901")
    assert not salida.exists()


def test_el_trozo_que_pasa_el_tope_no_se_escribe(tmp_path: Path) -> None:
    """Se comprueba antes de escribir: el disco nunca recibe más que el tope."""
    salida = tmp_path / "salida"
    escritos: list[int] = []
    with (
        pytest.raises(SalidaDemasiadoGrande),
        escribir_acotado(salida, tope=10) as destino,
    ):
        destino.write(b"12345")
        try:
            destino.write(b"x" * 1000)
        finally:
            escritos.append(destino.tell())
    assert escritos == [5]


def test_otro_error_al_escribir_tambien_borra_la_salida(tmp_path: Path) -> None:
    salida = tmp_path / "salida"
    with pytest.raises(RuntimeError), escribir_acotado(salida, tope=10) as destino:
        destino.write(b"123")
        raise RuntimeError
    assert not salida.exists()


def test_no_ofrece_descriptor(tmp_path: Path) -> None:
    """Pillow escribiría directo al descriptor y se saltaría la cuenta."""
    with (
        escribir_acotado(tmp_path / "salida", tope=10) as destino,
        pytest.raises(OSError),
    ):
        destino.fileno()


def test_no_sigue_un_enlace_ni_pisa_un_archivo(tmp_path: Path) -> None:
    victima = tmp_path / "victima"
    victima.write_bytes(b"intacto")
    enlace = tmp_path / "enlace"
    enlace.symlink_to(victima)
    for ruta in (enlace, victima):
        with pytest.raises(FileExistsError), escribir_acotado(ruta, tope=10):
            pass  # pragma: no cover
    assert victima.read_bytes() == b"intacto"
    assert enlace.is_symlink()
