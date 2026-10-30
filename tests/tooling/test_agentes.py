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
