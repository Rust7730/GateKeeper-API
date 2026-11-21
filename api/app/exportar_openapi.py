"""Exporta la especificación OpenAPI de Gatekeeper a ``api/openapi.json`` (F1.06, F6.02)."""

import json
import sys
from pathlib import Path
from typing import Any

from api.app.principal import crear_app

RUTA_POR_DEFECTO = Path("api/openapi.json")


def generar_esquema() -> dict[str, Any]:
    """Genera el diccionario OpenAPI directamente desde FastAPI, sin tocar BD ni Redis."""
    app = crear_app()
    return app.openapi()


def exportar_openapi(destino: Path = RUTA_POR_DEFECTO) -> Path:
    esquema = generar_esquema()
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(
        json.dumps(esquema, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return destino


def main(argumentos: list[str]) -> int:
    destino = Path(argumentos[0]) if argumentos else RUTA_POR_DEFECTO
    ruta = exportar_openapi(destino)
    print(f"OpenAPI exportado en {ruta}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
