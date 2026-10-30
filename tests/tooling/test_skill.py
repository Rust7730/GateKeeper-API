from pathlib import Path

SKILL = (
    Path(__file__).resolve().parents[2] / ".claude/skills/gatekeeper-guardian/SKILL.md"
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
