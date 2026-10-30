from pathlib import Path

import pytest

SKILL = (
    Path(__file__).resolve().parents[2] / ".claude/skills/gatekeeper-guardian/SKILL.md"
)

# La skill está en .gitignore: en un clon limpio no existe y no hay script que probar.
if not SKILL.exists():
    pytest.skip(
        "la skill gatekeeper-guardian no está en este clon", allow_module_level=True
    )


def test_skill_trabajo_con_agentes():
    c = SKILL.read_text(encoding="utf-8")
    assert "## Trabajo con agentes" in c
    s = c.split("## Trabajo con agentes")[1]
    assert "Solo gk-kg" in s and "gk-security" in s and "tests/attack-matrix/" in s
    assert "nunca lances dos gk-kg a la vez" in s
    assert (
        "seguridad escribe las pruebas → api-dev implementa → seguridad revisa → commit"
        in s
    )


def test_skill_flujo_con_bd():
    s = SKILL.read_text(encoding="utf-8").split("## Trabajo con agentes")[1]
    assert (
        "seguridad escribe las pruebas → gk-db → api-dev implementa → seguridad revisa → commit"
        in s
    )
