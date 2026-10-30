"""El control 3 de gk-commit se apoya en detect-secrets y en el .gitignore: esto comprueba que de verdad atrapan
los casos que la revisión final señaló (nombres en español, DSN con contraseña, variantes de .env)."""

import json
import secrets
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]


def _escanear(tmp_path, contenido):
    # Mismo comando que usa gk-commit: --all-files para que la cobertura no dependa de qué sigue git.
    (tmp_path / "config.py").write_text(contenido)
    salida = subprocess.run(
        [sys.executable, "-m", "detect_secrets", "scan", "--all-files", "config.py"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return json.loads(salida)["results"]


def test_detecta_llave_hex_con_nombre_en_espanol(tmp_path):
    assert _escanear(tmp_path, f'CLAVE_API = "{secrets.token_hex(32)}"\n')


def test_detecta_contrasena_en_dsn(tmp_path):
    assert _escanear(
        tmp_path,
        'DSN = "postgresql://gk:S3cr3t0-Larg0-9x@db:5432/gatekeeper"\n',  # pragma: allowlist secret (dato de prueba inventado)
    )


def test_codigo_normal_no_da_falsos_positivos(tmp_path):
    assert not _escanear(tmp_path, 'ESTADO_INICIAL = "pendiente"\nMAX_REINTENTOS = 2\n')


def test_variantes_de_env_ignoradas_y_ejemplo_versionado():
    def ignorado(ruta):
        return (
            subprocess.run(
                ["git", "check-ignore", "-q", ruta], cwd=RAIZ, check=False
            ).returncode
            == 0
        )

    assert (
        ignorado(".env") and ignorado(".env.local") and ignorado("api/.env.production")
    )
    assert not ignorado(".env.example")
