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
