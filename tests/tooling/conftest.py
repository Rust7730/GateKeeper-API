from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

RAIZ = Path(__file__).resolve().parents[2]
AGENTES = RAIZ / ".claude" / "agents"


@dataclass
class Agente:
    nombre: str
    tools: set[str]
    model: str
    descripcion: str
    cuerpo: str


def cargar_agente(nombre: str) -> Agente:
    # .claude/agents/ está en .gitignore: en un clon limpio (CI) no existe y no hay contrato que probar.
    if not AGENTES.is_dir():
        pytest.skip(".claude/agents/ no existe en este clon (está en .gitignore)")
    texto = (AGENTES / f"{nombre}.md").read_text(encoding="utf-8")
    _, frontmatter, cuerpo = texto.split("---", 2)
    meta = yaml.safe_load(frontmatter)
    return Agente(
        nombre=meta["name"],
        tools={t.strip() for t in meta["tools"].split(",")},
        model=meta["model"],
        descripcion=meta["description"],
        cuerpo=cuerpo,
    )


@pytest.fixture
def agente():
    return cargar_agente
