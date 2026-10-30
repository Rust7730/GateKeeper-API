#!/usr/bin/env python3
"""Imprime el hash del árbol de trabajo del repo (git write-tree con un índice temporal).

gk-security lo anota como "Árbol revisado" en su veredicto y gk-commit lo compara antes de commitear: si cualquier
archivo cambió después de la revisión, el hash difiere y el veredicto deja de valer. Incluye archivos sin seguimiento,
respeta .gitignore y no toca el índice real.

Excluye los archivos de gk-kg: los escribe después de la revisión de seguridad (el flujo registra el estado antes
del commit) y su contenido lo valida gk-commit con `kg.py validar`, no la revisión de seguridad.

Uso: arbol.py [ruta del repo]   (por defecto, el directorio actual)
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

EXCLUIDOS_GK_KG = ("context/gatekeeper_kg.json", "docs/decisiones.md")


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


if __name__ == "__main__":
    print(hash_arbol(Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()))
