"""Pruebas de purga automática de cuarentena (F4.09) y contrato OpenAPI exportado (F1.06)."""

import json
import os
from pathlib import Path

import pytest

from api.app.exportar_openapi import RUTA_POR_DEFECTO, generar_esquema
from api.app.purga_cuarentena import DIAS_RETENCION_CUARENTENA, purgar_cuarentena
from api.tests.test_principal import RUTAS_V1


def test_purgar_cuarentena_borra_expirados_y_conserva_recientes(
    tmp_path: Path,
) -> None:
    ahora = 2_000_000_000.0
    cuarentena = tmp_path / "quarantine"
    cuarentena.mkdir()

    viejo = cuarentena / "expirado.bin"
    reciente = cuarentena / "reciente.bin"
    fuera = tmp_path / "objetivo_externo.bin"
    enlace = cuarentena / "enlace_hostil"
    subdir = cuarentena / "subdir"

    viejo.write_bytes(b"malware-viejo")
    reciente.write_bytes(b"malware-nuevo")
    fuera.write_bytes(b"no-tocar")
    os.symlink(fuera, enlace)
    subdir.mkdir()

    hace_31_dias = ahora - (DIAS_RETENCION_CUARENTENA + 1) * 86_400
    hace_5_dias = ahora - 5 * 86_400
    os.utime(viejo, (hace_31_dias, hace_31_dias))
    os.utime(reciente, (hace_5_dias, hace_5_dias))
    os.utime(fuera, (hace_31_dias, hace_31_dias))

    eliminados = purgar_cuarentena(cuarentena, ahora=ahora)

    assert eliminados == 1
    assert not viejo.exists()
    assert reciente.exists()
    assert fuera.exists()
    assert enlace.is_symlink()
    assert subdir.is_dir()


def test_purgar_cuarentena_directorio_inexistente_y_dias_invalidos(
    tmp_path: Path,
) -> None:
    assert purgar_cuarentena(tmp_path / "no-existe") == 0
    with pytest.raises(ValueError, match="dias"):
        purgar_cuarentena(tmp_path, dias=0)


def test_openapi_exportado_esta_actualizado_y_cubre_rutas_v1() -> None:
    assert RUTA_POR_DEFECTO.is_file(), (
        "Falta api/openapi.json; ejecuta `python -m api.app.exportar_openapi`"
    )
    en_disco = json.loads(RUTA_POR_DEFECTO.read_text(encoding="utf-8"))
    generado = generar_esquema()
    assert en_disco == generado
    rutas_openapi = set(en_disco["paths"].keys())
    assert ({"/health"} | RUTAS_V1) <= rutas_openapi
