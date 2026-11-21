#!/bin/bash
# Actualización automática por pull del dashboard SPA desde la rama `dist-main` de GateKeeper-Frontend.
# Lo ejecuta gatekeeper-actualizar.timer cada 5 minutos junto con actualizar.sh.
set -euo pipefail
umask 022

readonly REPO_FRONT="${GK_REPO_FRONT:-https://github.com/Rust7730/GateKeeper-Frontend.git}"
readonly RAMA_DIST="${GK_RAMA_DIST:-dist-main}"
readonly DESTINO="${GK_DASHBOARD_DIR:-/opt/gatekeeper/dashboard}"
readonly ESTADO="${GK_ESTADO:-/var/lib/gatekeeper}"
readonly REGISTRO="${GK_REGISTRO:-/var/log/gatekeeper/despliegues.log}"
readonly REVISION_DASHBOARD="$ESTADO/dashboard.revision"

registrar() {
    local linea
    linea="$(date -u +%Y-%m-%dT%H:%M:%SZ) [dashboard] $*"
    echo "$linea"
    echo "$linea" >>"$REGISTRO"
}

principal() {
    mkdir -p "$ESTADO" "$(dirname "$REGISTRO")" "$DESTINO"

    local remoto actual temporal
    remoto=$(git ls-remote --heads "$REPO_FRONT" "refs/heads/$RAMA_DIST" 2>/dev/null | awk '{print $1}' | head -n 1 || true)
    if [[ ! $remoto =~ ^[0-9a-f]{40}$ ]]; then
        # La rama dist-main aún no existe o GitHub no respondió: no se toca el dashboard actual.
        return 0
    fi

    actual=$(cat "$REVISION_DASHBOARD" 2>/dev/null || true)
    if [[ $remoto == "$actual" && -f "$DESTINO/index.html" ]]; then
        return 0
    fi

    temporal=$(mktemp -d "$ESTADO/.dashboard.XXXXXX")
    trap 'rm -rf "$temporal"' EXIT

    if ! git clone --quiet --depth 1 --branch "$RAMA_DIST" "$REPO_FRONT" "$temporal/repo" 2>/dev/null; then
        registrar "no se pudo descargar $RAMA_DIST de $REPO_FRONT"
        return 1
    fi

    rm -rf "$temporal/repo/.git"
    if [[ ! -f "$temporal/repo/index.html" ]]; then
        registrar "RECHAZADO: $remoto no contiene index.html"
        return 1
    fi
    if [[ -n $(find "$temporal/repo" -type l -print -quit) ]]; then
        registrar "RECHAZADO: $remoto contiene enlaces simbólicos"
        return 1
    fi

    chown -R root:root "$temporal/repo"
    chmod -R u=rwX,go=rX "$temporal/repo"
    rsync -a --delete --no-links "$temporal/repo"/ "$DESTINO"/

    printf '%s\n' "$remoto" >"$REVISION_DASHBOARD"
    chmod 0600 "$REVISION_DASHBOARD"
    registrar "actualizado ${actual:-ninguno} -> $remoto"
}

principal "$@"
