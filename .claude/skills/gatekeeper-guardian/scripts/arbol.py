#!/usr/bin/env python3
"""Imprime el hash del árbol de trabajo del repo (git write-tree con un índice temporal).

gk-security lo anota como "Árbol revisado" en su veredicto y gk-commit lo compara antes de commitear: si cualquier
archivo cambió después de la revisión, el hash difiere y el veredicto deja de valer. Incluye archivos sin seguimiento,
respeta .gitignore y no toca el índice real.

Excluye los archivos de gk-kg: los escribe después de la revisión de seguridad (el flujo registra el estado antes
del commit) y su contenido lo valida gk-commit con `kg.py validar`, no la revisión de seguridad.

Uso:
  arbol.py [repo]                         hash del árbol ("Árbol revisado")
  arbol.py [repo] --diff                  diff de HEAD al árbol: exactamente lo que el hash cubre (staging incluido)
  arbol.py [repo] --archivos              rutas de ese diff, una por línea
  arbol.py [repo] --sello tests/attack-matrix   hash de un subárbol ("Pruebas de ataque")

Revisar con `git diff` no basta: compara el árbol de trabajo con el índice y no muestra lo que ya está en staging.
"""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

EXCLUIDOS_GK_KG = ("context/gatekeeper_kg.json", "docs/decisiones.md")
ARBOL_VACIO = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # pragma: allowlist secret (hash del árbol vacío de git)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout


def _base(repo: Path) -> str:
    r = subprocess.run(
        ["git", "rev-parse", "--verify", "-q", "HEAD"],
        check=False,
        cwd=repo,
        capture_output=True,
        text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else ARBOL_VACIO


def _sin_gk_kg() -> list[str]:
    return ["--", ".", *(f":(exclude){x}" for x in EXCLUIDOS_GK_KG)]


def hash_arbol(repo: Path) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(tmp) / "index")}
        subprocess.run(
            ["git", "add", "-A"], cwd=repo, env=env, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "rm", "--cached", "-q", "--ignore-unmatch", "--", *EXCLUIDOS_GK_KG],
            cwd=repo,
            env=env,
            check=True,
            capture_output=True,
        )
        salida = subprocess.run(
            ["git", "write-tree"],
            cwd=repo,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
    return salida.stdout.strip()


def diff_revisado(repo: Path) -> str:
    return _git(repo, "diff", _base(repo), hash_arbol(repo), *_sin_gk_kg())


def archivos_revisados(repo: Path) -> list[str]:
    salida = _git(
        repo, "diff", "--name-only", _base(repo), hash_arbol(repo), *_sin_gk_kg()
    )
    return sorted(linea for linea in salida.splitlines() if linea)


def sello(repo: Path, ruta: str) -> str:
    r = subprocess.run(
        ["git", "rev-parse", f"{hash_arbol(repo)}:{ruta}"],
        check=False,
        cwd=repo,
        capture_output=True,
        text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else "ausente"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", nargs="?", default=".")
    grupo = ap.add_mutually_exclusive_group()
    grupo.add_argument("--diff", action="store_true")
    grupo.add_argument("--archivos", action="store_true")
    grupo.add_argument("--sello", metavar="RUTA")
    a = ap.parse_args()
    repo = Path(a.repo)
    if a.diff:
        sys.stdout.write(diff_revisado(repo))
    elif a.archivos:
        print("\n".join(archivos_revisados(repo)))
    elif a.sello:
        print(sello(repo, a.sello))
    else:
        print(hash_arbol(repo))
