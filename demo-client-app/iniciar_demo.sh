#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"

echo "Iniciando monolito consumidor de Gatekeeper en http://127.0.0.1:8090 ..."
exec "$ROOT/.venv/bin/uvicorn" app:app --app-dir "$DIR" --host 127.0.0.1 --port 8090
