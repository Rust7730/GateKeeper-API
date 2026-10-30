def test_gk_kg_frontmatter(agente):
    a = agente("gk-kg")
    assert a.tools == {"Read", "Grep", "Glob", "Edit", "Bash"}
    assert a.model == "sonnet"


def test_gk_kg_es_unico_escritor(agente):
    c = agente("gk-kg").cuerpo
    assert (
        "único escritor" in c
        and "context/gatekeeper_kg.json" in c
        and "docs/decisiones.md" in c
    )
    assert "no edites el JSON a mano" in c


def test_gk_kg_confirma_solo_con_aprobacion(agente):
    c = agente("gk-kg").cuerpo
    assert 'Aprobación del usuario: "' in c and "kg.py confirmar" in c


def test_gk_kg_reporte(agente):
    assert "Reporte · gk-kg · <paso>" in agente("gk-kg").cuerpo


def test_gk_security_frontmatter(agente):
    a = agente("gk-security")
    assert a.tools == {"Read", "Grep", "Glob", "Write", "Edit", "Bash"}
    assert a.model == "opus"


def test_gk_security_dos_fases(agente):
    c = agente("gk-security").cuerpo
    assert "tests/attack-matrix/" in c and "deben fallar" in c
    for x in (
        "INV-01",
        "INV-10",
        "CWE-434",
        "CWE-22",
        "CWE-79",
        "CWE-770",
        "CWE-639",
        "CWE-862",
        "bandit -r api/",
    ):
        assert x in c


def test_gk_security_veredicto(agente):
    c = agente("gk-security").cuerpo
    assert "Árbol revisado:" in c and "arbol.py" in c
    assert "[alta|media|baja]" in c and "cambios requeridos" in c
    assert "antes del 202" in c


def test_gk_security_reporte(agente):
    assert "Reporte · gk-security · <paso>" in agente("gk-security").cuerpo


def test_gk_api_dev_frontmatter(agente):
    a = agente("gk-api-dev")
    assert a.tools == {"Read", "Grep", "Glob", "Edit", "Write", "Bash"}
    assert a.model == "opus"


def test_gk_api_dev_reglas(agente):
    c = agente("gk-api-dev").cuerpo
    for x in (
        "gatekeeper-guardian",
        "api/tests/",
        "no modifiques tests/attack-matrix/",
        "detenido",
        "Para gk-kg",
    ):
        assert x in c


def test_gk_api_dev_latencia(agente):
    c = agente("gk-api-dev").cuerpo
    assert "M1" in c and "p95 < 1 s" in c and "números" in c


def test_gk_api_dev_reporte(agente):
    assert "Reporte · gk-api-dev · <paso>" in agente("gk-api-dev").cuerpo


def test_gk_commit_frontmatter(agente):
    a = agente("gk-commit")
    assert a.tools == {"Read", "Grep", "Glob", "Bash"}
    assert a.model == "sonnet"


def test_gk_commit_controles(agente):
    c = agente("gk-commit").cuerpo
    for x in (
        "main",
        "<fase>/<paso>-<slug>",
        ".env",
        "ruff check",
        "ruff format --check",
        "bandit -r api/",
        "kg.py validar",
        "Árbol revisado",
        "arbol.py",
        "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
    ):
        assert x in c


def test_gk_commit_prohibiciones(agente):
    c = agente("gk-commit").cuerpo
    for x in ("--no-verify", "--amend", "push", "--force", "reset --hard"):
        assert x in c


def test_gk_commit_fail_closed_y_no_descarta(agente):
    c = agente("gk-commit").cuerpo
    assert "si una herramienta no está disponible" in c
    assert "nunca borres, reviertas ni saques de staging" in c


def test_gk_commit_reporte(agente):
    assert "Reporte · gk-commit · <paso>" in agente("gk-commit").cuerpo
