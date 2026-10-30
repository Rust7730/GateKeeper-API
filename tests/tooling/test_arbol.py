import importlib.util
import subprocess
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / ".claude/skills/gatekeeper-guardian/scripts/arbol.py"
)


def _modulo():
    spec = importlib.util.spec_from_file_location("arbol", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / "a.py").write_text("x = 1\n")
    return tmp_path


def test_mismo_contenido_mismo_hash(repo):
    arbol = _modulo()
    assert arbol.hash_arbol(repo) == arbol.hash_arbol(repo)


def test_cambio_cambia_hash(repo):
    arbol = _modulo()
    antes = arbol.hash_arbol(repo)
    (repo / "a.py").write_text("x = 2\n")
    assert arbol.hash_arbol(repo) != antes


def test_archivo_nuevo_sin_seguimiento_cambia_hash(repo):
    arbol = _modulo()
    antes = arbol.hash_arbol(repo)
    (repo / "b.py").write_text("y = 1\n")
    assert arbol.hash_arbol(repo) != antes


def test_ignorado_no_cambia_hash(repo):
    arbol = _modulo()
    antes = arbol.hash_arbol(repo)
    (repo / ".env").write_text("VT_API_KEY=secreto\n")
    assert arbol.hash_arbol(repo) == antes


def test_no_toca_indice_real(repo):
    arbol = _modulo()
    assert _git(repo, "diff", "--cached", "--name-only") == ""
    arbol.hash_arbol(repo)
    assert _git(repo, "diff", "--cached", "--name-only") == ""


def test_archivos_de_gk_kg_no_cambian_hash(repo):
    arbol = _modulo()
    (repo / "context").mkdir()
    (repo / "docs").mkdir()
    (repo / "context/gatekeeper_kg.json").write_text("{}\n")
    (repo / "docs/decisiones.md").write_text("# v1\n")
    antes = arbol.hash_arbol(repo)
    (repo / "context/gatekeeper_kg.json").write_text('{"estado": "en_progreso"}\n')
    (repo / "docs/decisiones.md").write_text("# v2\n")
    assert arbol.hash_arbol(repo) == antes
