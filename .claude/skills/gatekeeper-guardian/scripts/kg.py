#!/usr/bin/env python3
"""Consulta y actualiza el knowledge graph de Gatekeeper (context/gatekeeper_kg.json).

Uso:
  kg.py contexto <id>                   Todo lo que aplica a un paso, fase o nodo antes de tocarlo
  kg.py vecinos <id>                    Aristas de entrada y salida de un nodo
  kg.py buscar <texto>                  Nodos cuyo id, label o props contienen el texto
  kg.py pendientes [fase]               Pasos no terminados, en orden, con su fase
  kg.py estado <id> <valor> [--nota T] [--forzar]
                                        Cambia props.estado (pendiente|en_progreso|hecho|bloqueado).
                                        Un paso no pasa a 'hecho' si su fase tiene dependencias abiertas,
                                        salvo --forzar con --nota (solo si el usuario lo pidió).
  kg.py decision --label T --eleccion T --afecta id[,id...] [--motivo T]
                                        Registra una decisión nueva como K## PROPUESTA (pendiente)
  kg.py confirmar <id> [--eleccion T]   Marca como confirmada una D#/K## que el usuario aprobó
  kg.py validar                         Aristas rotas, huérfanos y conteos
  kg.py diff-permitido <ref>            Compara el KG contra <ref> (p. ej. HEAD) y rechaza todo cambio que
                                        no esté en la lista blanca de gk-kg (ver diff_permitido)

Opciones globales: --kg RUTA (por defecto busca context/gatekeeper_kg.json subiendo desde el cwd).
"""

import argparse
import datetime
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ESTADOS = ["pendiente", "en_progreso", "hecho", "bloqueado"]


def find_kg(explicit):
    if explicit:
        return Path(explicit)
    for d in [Path.cwd(), *Path.cwd().parents]:
        p = d / "context" / "gatekeeper_kg.json"
        if p.exists():
            return p
    here = Path(__file__).resolve()
    for d in here.parents:
        p = d / "context" / "gatekeeper_kg.json"
        if p.exists():
            return p
    sys.exit("No encontré context/gatekeeper_kg.json; usa --kg RUTA")


class KG:
    def __init__(self, path):
        self.path = path
        self.data = json.loads(path.read_text())
        self.reindex()

    def reindex(self):
        self.N = {n["id"]: n for n in self.data["nodos"]}
        self.out, self.inn = defaultdict(list), defaultdict(list)
        for e in self.data["aristas"]:
            self.out[e["de"]].append(e)
            self.inn[e["a"]].append(e)

    def save(self):
        d = self.data
        d["meta"]["conteos"] = {
            "nodos": len(d["nodos"]),
            "aristas": len(d["aristas"]),
            "por_tipo": dict(sorted(Counter(n["tipo"] for n in d["nodos"]).items())),
            "por_relacion": dict(
                sorted(Counter(e["rel"] for e in d["aristas"]).items())
            ),
        }
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)  # escritura atómica: nunca queda un KG a medias

    def get(self, i):
        if i not in self.N:
            sys.exit(f"No existe el nodo '{i}'. Prueba: kg.py buscar {i}")
        return self.N[i]

    def tgt(self, i, rel=None):
        return [e["a"] for e in self.out[i] if rel is None or e["rel"] == rel]

    def src(self, i, rel=None):
        return [e["de"] for e in self.inn[i] if rel is None or e["rel"] == rel]


def short(
    n,
    keys=(
        "estado",
        "decision",
        "valor",
        "propuesta",
        "eleccion",
        "resultado_esperado",
        "severidad",
    ),
):
    p = n["props"]
    if p.get("eleccion"):
        keys = tuple(k for k in keys if k != "propuesta")
    extra = "; ".join(f"{k}={p[k]}" for k in keys if p.get(k) not in (None, ""))
    return f"{n['id']} — {n['label']}" + (f"  [{extra}]" if extra else "")


def section(title, ids, kg):
    ids = list(dict.fromkeys(i for i in ids if i in kg.N))
    if not ids:
        return
    print(f"\n## {title}")
    for i in ids:
        print("- " + short(kg.N[i]))


def contexto(kg, i):
    n = kg.get(i)
    print(f"# {short(n)}\n(tipo: {n['tipo']})")
    pasos, fase = [], None
    if n["tipo"] == "Paso":
        pasos = [i]
        fase = next(iter(kg.src(i, "contiene")), None)
    elif n["tipo"] == "Fase":
        fase, pasos = i, kg.tgt(i, "contiene")
    focus = [i] + pasos

    if fase:
        f = kg.N[fase]
        print(f"\n## Fase {fase} — {f['label']} [estado={f['props'].get('estado')}]")
        print(f"Criterio de salida: {f['props'].get('criterio_salida')}")
        for dep in kg.tgt(fase, "depende_de"):
            d = kg.N[dep]
            mark = "OK" if d["props"].get("estado") == "hecho" else "NO TERMINADA"
            print(f"- depende de {dep} ({d['label']}): {mark}")
        bloq = [
            d
            for d in kg.src(fase, "bloquea")
            if kg.N[d]["props"].get("estado") != "confirmada"
        ]
        if bloq:
            print(f"- BLOQUEADA por decisiones sin confirmar: {', '.join(bloq)}")
        print("Objetivos: " + ", ".join(kg.tgt(fase, "cumple")))

    controles = [c for p in focus for c in kg.tgt(p, "implementa")]
    params = [x for p in focus for x in kg.tgt(p, "usa_parametro")]
    tocados = focus + controles + params
    invs = [x for t in tocados for x in kg.tgt(t, "hace_cumplir")]
    invs += [x for t in tocados for x in kg.src(t, "restringe")]
    for c in controles:
        invs += [
            x for s in kg.tgt(c, "implementado_en") for x in kg.src(s, "restringe")
        ]
    section(
        "Invariantes que no se pueden romper",
        sorted(set(invs), key=lambda s: (len(s), s)),
        kg,
    )

    afect = [
        x
        for t in tocados
        for x in kg.src(t, "afecta")
        if kg.N[x]["tipo"] in ("Decision", "Observacion")
    ]
    vers = [x for t in tocados for x in kg.tgt(t, "verificado_en")]
    afect += [x for v in vers for x in kg.src(v, "resuelve")]
    section(
        "Decisiones y observaciones que aplican (docs/decisiones.md manda)", afect, kg
    )
    section("Verificaciones CoV relacionadas", vers, kg)
    section("Parámetros a usar (no inventes valores)", params, kg)
    section("Controles que implementa", controles, kg)

    def print_vecs(title, vs):
        vs = list(dict.fromkeys(vs))
        if not vs:
            return
        print(f"\n## {title}")
        for v in vs:
            cwe = ", ".join(kg.tgt(v, "ejercita"))
            desde = ", ".join(kg.tgt(v, "debe_pasar_desde"))
            print(
                f"- {short(kg.N[v])}"
                + (f"  CWE: {cwe}" if cwe else "")
                + (f"  desde {desde}" if desde else "")
            )

    propios = [v for c in controles for v in kg.src(c, "detenido_por")]
    print_vecs(
        "Vectores de ataque de este trabajo (escribe su prueba ANTES del control)",
        propios,
    )
    de_fase = [
        v
        for v in (kg.src(fase, "debe_pasar_desde") if fase else [])
        if v not in propios
    ]
    print_vecs(
        f"Otros vectores de {fase} que deben seguir en verde" if fase else "", de_fase
    )

    riesgos = [
        r
        for t in focus + ([fase] if fase else [])
        for r in kg.src(t, "afecta")
        if kg.N[r]["tipo"] == "Riesgo"
    ]
    section("Riesgos con señal temprana", riesgos, kg)
    patrones = [p for p in kg.N if p.startswith("patron:")]
    section("Patrones vigilados en el código", patrones, kg)
    mets = [m for m in kg.N if kg.N[m]["tipo"] == "Metrica"]
    if mets:
        print(
            "\n## Métricas de rendimiento (Gatekeeper es intermediario: cada ms lo paga la app cliente)"
        )
        for m in mets:
            print(f"- {m}: {kg.N[m]['label']} → {kg.N[m]['props'].get('objetivo')}")
    if n["tipo"] not in ("Paso", "Fase"):
        print()
        vecinos(kg, i)


def vecinos(kg, i):
    kg.get(i)
    for e in kg.out[i]:
        print(
            f"  {i} -{e['rel']}-> {short(kg.N[e['a']]) if e['a'] in kg.N else e['a']}"
        )
    for e in kg.inn[i]:
        print(f"  {short(kg.N[e['de']])} -{e['rel']}-> {i}")


def buscar(kg, texto):
    t = texto.lower()
    hits = [
        n
        for n in kg.data["nodos"]
        if t in n["id"].lower()
        or t in n["label"].lower()
        or t in json.dumps(n["props"], ensure_ascii=False).lower()
    ]
    orden = {"Paso": 0, "Control": 1, "Fase": 2, "Invariante": 3}
    for n in sorted(hits, key=lambda n: orden.get(n["tipo"], 9))[:40]:
        print(f"[{n['tipo']}] {short(n)}")
    if not hits:
        print("Sin resultados.")


def pendientes(kg, fase=None):
    fases = [
        f for f in kg.N if kg.N[f]["tipo"] == "Fase" and (fase is None or f == fase)
    ]
    for f in sorted(fases):
        pasos = [
            p
            for p in kg.tgt(f, "contiene")
            if kg.N[p]["props"].get("estado") != "hecho"
        ]
        if pasos:
            print(f"{f} — {kg.N[f]['label']} [{kg.N[f]['props'].get('estado')}]")
            for p in sorted(pasos, key=lambda p: kg.N[p]["props"].get("orden", 0)):
                print("  - " + short(kg.N[p]))


def estado(kg, i, valor, nota, forzar=False):
    if valor not in ESTADOS:
        sys.exit(f"Estado inválido '{valor}'. Usa: {', '.join(ESTADOS)}")
    n = kg.get(i)
    if n["tipo"] == "Fase" and valor == "hecho":
        faltan = [
            p
            for p in kg.tgt(i, "contiene")
            if kg.N[p]["props"].get("estado") != "hecho"
        ]
        if faltan:
            sys.exit(f"No marco {i} como hecho: faltan {', '.join(faltan)}")
    if n["tipo"] == "Paso" and valor in ("en_progreso", "hecho"):
        fase = next(iter(kg.src(i, "contiene")), None)
        if fase:
            deps = [
                d
                for d in kg.tgt(fase, "depende_de")
                if kg.N[d]["props"].get("estado") != "hecho"
            ]
            if deps and valor == "hecho":
                # Un paso "hecho" se da por integrado; sin sus dependencias no puede probarse de punta a punta.
                if not forzar:
                    sys.exit(
                        f"No marco {i} como hecho: {fase} depende de {', '.join(deps)}, sin terminar. "
                        f"Déjalo en_progreso con una nota de lo que falta, o usa --forzar --nota si el usuario lo pidió."
                    )
                if not nota:
                    sys.exit(
                        "--forzar exige --nota explicando por qué el usuario aceptó cerrarlo sin sus dependencias."
                    )
            elif deps:
                print(
                    f"AVISO: {fase} depende de fases no terminadas: {', '.join(deps)}",
                    file=sys.stderr,
                )
            if kg.N[fase]["props"].get("estado") == "pendiente":
                kg.N[fase]["props"]["estado"] = "en_progreso"
    anterior = n["props"].get("estado")
    n["props"]["estado"] = valor
    hist = n["props"].setdefault("historial", [])
    hist.append(
        {
            "fecha": datetime.date.today().isoformat(),
            "de": anterior,
            "a": valor,
            **({"nota": nota} if nota else {}),
        }
    )
    kg.save()
    print(f"{i}: {anterior} → {valor}")


def decision(kg, label, eleccion, afecta, motivo):
    ks = [int(k[1:]) for k in kg.N if k.startswith("K") and k[1:].isdigit()]
    nid = f"K{max(ks, default=0) + 1:02d}"
    destinos = [a.strip() for a in afecta.split(",") if a.strip()]
    for a in destinos:
        kg.get(a)
    hoy = datetime.date.today().isoformat()
    kg.data["nodos"].append(
        {
            "id": nid,
            "tipo": "Observacion",
            "label": label,
            "props": {
                "propuesta": eleccion,
                "hallazgo": motivo,
                "decision": "pendiente",
                "fecha_propuesta": hoy,
                "origen": "gatekeeper-guardian",
            },
        }
    )
    kg.data["aristas"] += [{"de": nid, "rel": "afecta", "a": a} for a in destinos]
    kg.save()
    print(
        f"{nid} registrada como PROPUESTA (pendiente). Pide al usuario que la confirme; "
        f"cuando lo haga: kg.py confirmar {nid}. Anótala en docs/decisiones.md como pendiente."
    )


def confirmar(kg, i, eleccion):
    n = kg.get(i)
    if n["tipo"] not in ("Decision", "Observacion"):
        sys.exit(
            f"{i} es {n['tipo']}; solo se confirman decisiones (D#) u observaciones (K##)."
        )
    p = n["props"]
    p["eleccion"] = eleccion or p.get("eleccion") or p.get("propuesta")
    p["fecha_decision"] = datetime.date.today().isoformat()
    if n["tipo"] == "Decision":
        p["estado"] = "confirmada"
    else:
        p["decision"] = "confirmada"
    kg.save()
    print(f"{i} confirmada: {p['eleccion']}")


def validar(kg):
    rotas = [
        e
        for e in kg.data["aristas"]
        if e["de"] not in kg.N or (e["a"] not in kg.N and e["a"] != "vec:*")
    ]
    usados = {x for e in kg.data["aristas"] for x in (e["de"], e["a"])}
    huerf = [i for i in kg.N if i not in usados]
    print(
        f"nodos={len(kg.N)} aristas={len(kg.data['aristas'])} rotas={len(rotas)} huérfanos={len(huerf)}"
    )
    for e in rotas[:20]:
        print("  rota:", e)
    for h in huerf[:20]:
        print("  huérfano:", h)
    sys.exit(1 if rotas else 0)


CAMPOS_DE_ESTADO = {"estado", "historial", "nota"}


def _kg_en(ref, ruta):
    top = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=ruta.resolve().parent,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    rel = ruta.resolve().relative_to(top).as_posix()
    r = subprocess.run(
        ["git", "show", f"{ref}:{rel}"],
        cwd=top,
        capture_output=True,
        text=True,
        check=False,
    )
    return json.loads(r.stdout) if r.returncode == 0 else {"nodos": [], "aristas": []}


def diff_permitido(kg, ref):
    """Lista blanca de lo que gk-kg puede cambiar sin aprobación del usuario.

    Pasa: estado/historial/nota de pasos y fases (respetando las reglas de 'hecho'), propuestas nuevas K## en
    'pendiente' con sus aristas 'afecta', y meta.conteos. Todo lo demás (parámetros, decisiones, confirmaciones,
    borrados, aristas entre nodos existentes) requiere 'Aprobación del usuario (<id>)' y se reporta.
    """
    base = _kg_en(ref, kg.path)
    nb = {n["id"]: n for n in base["nodos"]}
    na = kg.N
    malos = []
    for i in sorted(set(nb) - set(na)):
        malos.append(f"{i}: nodo borrado")
    nuevos_ok = set()
    for i in sorted(set(na) - set(nb)):
        p = na[i]["props"]
        if (
            na[i]["tipo"] == "Observacion"
            and p.get("decision") == "pendiente"
            and not p.get("eleccion")
        ):
            nuevos_ok.add(i)
        else:
            malos.append(f"{i}: nodo nuevo que no es una propuesta pendiente")
    for i in sorted(set(na) & set(nb)):
        a, b = na[i], nb[i]
        if a == b:
            continue
        claves = {
            k
            for k in set(a["props"]) | set(b["props"])
            if a["props"].get(k) != b["props"].get(k)
        }
        if (
            a["tipo"] not in ("Paso", "Fase")
            or a["tipo"] != b["tipo"]
            or a["label"] != b["label"]
            or not claves <= CAMPOS_DE_ESTADO
        ):
            malos.append(f"{i}: cambia {sorted(claves) or ['tipo/label']}")
            continue
        if a["props"].get("estado") == "hecho" and b["props"].get("estado") != "hecho":
            if a["tipo"] == "Paso":
                fase = next(iter(kg.src(i, "contiene")), None)
                deps = [
                    d
                    for d in (kg.tgt(fase, "depende_de") if fase else [])
                    if na[d]["props"].get("estado") != "hecho"
                ]
                if deps:
                    malos.append(f"{i}: 'hecho' con dependencias abiertas {deps}")
            else:
                faltan = [
                    x
                    for x in kg.tgt(i, "contiene")
                    if na[x]["props"].get("estado") != "hecho"
                ]
                if faltan:
                    malos.append(f"{i}: fase 'hecho' con pasos sin terminar {faltan}")
    eb = {(e["de"], e["rel"], e["a"]) for e in base["aristas"]}
    ea = {(e["de"], e["rel"], e["a"]) for e in kg.data["aristas"]}
    for e in sorted(eb - ea):
        malos.append(f"{e[0]}: arista borrada {e}")
    for e in sorted(ea - eb):
        if not (e[0] in nuevos_ok and e[1] == "afecta"):
            malos.append(f"{e[0]}: arista nueva fuera de la lista blanca {e}")
    mb = {k: v for k, v in base.get("meta", {}).items() if k != "conteos"}
    ma = {k: v for k, v in kg.data.get("meta", {}).items() if k != "conteos"}
    if mb and mb != ma:
        malos.append("meta: cambia fuera de meta.conteos")
    for m in malos:
        print(f"REQUIERE Aprobación del usuario — {m}")
    if not malos:
        print("sin cambios fuera de la lista blanca")
    sys.exit(1 if malos else 0)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--kg")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("contexto", "vecinos"):
        sub.add_parser(c).add_argument("id")
    sub.add_parser("buscar").add_argument("texto")
    sub.add_parser("pendientes").add_argument("fase", nargs="?")
    s = sub.add_parser("estado")
    s.add_argument("id")
    s.add_argument("valor")
    s.add_argument("--nota")
    s.add_argument("--forzar", action="store_true")
    s = sub.add_parser("decision")
    s.add_argument("--label", required=True)
    s.add_argument("--eleccion", required=True)
    s.add_argument("--afecta", required=True)
    s.add_argument("--motivo")
    s = sub.add_parser("confirmar")
    s.add_argument("id")
    s.add_argument("--eleccion")
    sub.add_parser("validar")
    sub.add_parser("diff-permitido").add_argument("ref")
    a = ap.parse_args()
    kg = KG(find_kg(a.kg))
    {
        "contexto": lambda: contexto(kg, a.id),
        "vecinos": lambda: vecinos(kg, a.id),
        "buscar": lambda: buscar(kg, a.texto),
        "pendientes": lambda: pendientes(kg, a.fase),
        "estado": lambda: estado(kg, a.id, a.valor, a.nota, a.forzar),
        "decision": lambda: decision(kg, a.label, a.eleccion, a.afecta, a.motivo),
        "confirmar": lambda: confirmar(kg, a.id, a.eleccion),
        "validar": lambda: validar(kg),
        "diff-permitido": lambda: diff_permitido(kg, a.ref),
    }[a.cmd]()


if __name__ == "__main__":
    main()
