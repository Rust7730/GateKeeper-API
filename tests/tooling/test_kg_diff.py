"""kg.py diff-permitido: solo deja pasar los cambios del KG que gk-kg puede hacer sin aprobación del usuario."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

KG_PY = (
    Path(__file__).resolve().parents[2]
    / ".claude/skills/gatekeeper-guardian/scripts/kg.py"
)

BASE = {
    "meta": {"conteos": {}},
    "nodos": [
        {"id": "F1", "tipo": "Fase", "label": "F1", "props": {"estado": "pendiente"}},
        {"id": "F2", "tipo": "Fase", "label": "F2", "props": {"estado": "pendiente"}},
        {
            "id": "F2.01",
            "tipo": "Paso",
            "label": "paso",
            "props": {"estado": "pendiente"},
        },
        {
            "id": "param:x",
            "tipo": "Parametro",
            "label": "x",
            "props": {"valor": "10"},
        },
        {
            "id": "K03",
            "tipo": "Observacion",
            "label": "k3",
            "props": {"decision": "pendiente"},
        },
    ],
    "aristas": [
        {"de": "F2", "rel": "depende_de", "a": "F1"},
        {"de": "F2", "rel": "contiene", "a": "F2.01"},
        {"de": "K03", "rel": "afecta", "a": "F2.01"},
    ],
}


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "context").mkdir()
    (tmp_path / "context/gatekeeper_kg.json").write_text(json.dumps(BASE))
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "b")
    return tmp_path


def _cambiar(repo, f):
    p = repo / "context/gatekeeper_kg.json"
    kg = json.loads(p.read_text())
    f(kg)
    p.write_text(json.dumps(kg))


def _nodo(kg, i):
    return next(n for n in kg["nodos"] if n["id"] == i)


def _diff(repo):
    return subprocess.run(
        [sys.executable, str(KG_PY), "--kg", "context/gatekeeper_kg.json"]
        + ["diff-permitido", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )


def test_sin_cambios_pasa(repo):
    assert _diff(repo).returncode == 0


def test_estado_de_paso_en_progreso_pasa(repo):
    _cambiar(repo, lambda kg: _nodo(kg, "F2.01")["props"].update(estado="en_progreso"))
    assert _diff(repo).returncode == 0


def test_propuesta_pendiente_nueva_pasa(repo):
    def f(kg):
        kg["nodos"].append(
            {
                "id": "K04",
                "tipo": "Observacion",
                "label": "k4",
                "props": {"decision": "pendiente", "propuesta": "algo"},
            }
        )
        kg["aristas"].append({"de": "K04", "rel": "afecta", "a": "F2.01"})

    _cambiar(repo, f)
    assert _diff(repo).returncode == 0


def test_cambiar_un_parametro_requiere_aprobacion(repo):
    _cambiar(repo, lambda kg: _nodo(kg, "param:x")["props"].update(valor="20"))
    r = _diff(repo)
    assert r.returncode == 1 and "param:x" in r.stdout


def test_confirmar_una_propuesta_requiere_aprobacion(repo):
    _cambiar(repo, lambda kg: _nodo(kg, "K03")["props"].update(decision="confirmada"))
    r = _diff(repo)
    assert r.returncode == 1 and "K03" in r.stdout


def test_nodo_nuevo_ya_confirmado_requiere_aprobacion(repo):
    _cambiar(
        repo,
        lambda kg: kg["nodos"].append(
            {
                "id": "K05",
                "tipo": "Observacion",
                "label": "k5",
                "props": {"decision": "confirmada"},
            }
        ),
    )
    r = _diff(repo)
    assert r.returncode == 1 and "K05" in r.stdout


def test_borrar_un_nodo_requiere_aprobacion(repo):
    _cambiar(
        repo, lambda kg: kg.update(nodos=[n for n in kg["nodos"] if n["id"] != "K03"])
    )
    r = _diff(repo)
    assert r.returncode == 1 and "K03" in r.stdout


def test_paso_hecho_con_fase_dependiente_abierta_requiere_aprobacion(repo):
    _cambiar(repo, lambda kg: _nodo(kg, "F2.01")["props"].update(estado="hecho"))
    r = _diff(repo)
    assert r.returncode == 1 and "F2.01" in r.stdout


def test_arista_nueva_entre_nodos_existentes_requiere_aprobacion(repo):
    _cambiar(
        repo,
        lambda kg: kg["aristas"].append({"de": "F1", "rel": "depende_de", "a": "F2"}),
    )
    r = _diff(repo)
    assert r.returncode == 1 and "F1" in r.stdout
