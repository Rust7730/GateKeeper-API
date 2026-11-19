#!/bin/bash
# Despliegue por pull de Gatekeeper (K55). Lo corre gatekeeper-actualizar.timer cada 5 minutos.
#
# El servidor está restringido a las IP del usuario, así que GitHub no entra por SSH: es el servidor
# el que consulta GHCR. Si el digest de ghcr.io/rust7730/gatekeeper-api:main cambió:
#   1. verifica la firma de ese digest con cosign, sin llaves: tiene que venir del workflow
#      despliegue.yml de la rama main de Rust7730/GateKeeper-API (emisor: GitHub Actions). Si no, nada
#      más corre con esa imagen;
#   2. sonda del aislamiento con la imagen nueva (Landlock y seccomp), sin red ni secretos;
#   3. respaldo de la base (pg_dump -Fc) y revisión de Alembic antes de migrar;
#   4. migraciones con la URL de migración (servicio `migrate`);
#   5. levanta la API con la imagen nueva, fijada por digest, y comprueba /health por nginx y TLS;
#   6. si algo falla después de migrar, baja el esquema a la revisión anterior con la imagen nueva y
#      vuelve a la imagen anterior. Si el downgrade falla, deja la API detenida y escribe el marcador
#      $ESTADO/detenido: mientras exista, ni este script ni instalar.sh levantan la API ni migran (se
#      borra a mano al final de la restauración, ver README). Nunca corre la versión vieja sobre un esquema
#      que no conoce. Lo que falla después de verificar la firma queda retenido para no reintentarlo en
#      bucle; una firma que no se pudo verificar se vuelve a intentar en cada corrida.
# Cada paso queda en /var/log/gatekeeper/despliegues.log y en el journal.
#
# Uso:
#   actualizar.sh              despliega :main si cambió (lo que hace el timer)
#   actualizar.sh --revertir   vuelve a la imagen anterior (bajando el esquema si hace falta) y
#                              retiene la actual hasta que :main cambie
set -euo pipefail
umask 077

# Rutas fijas en el servidor; las variables GK_* existen solo para probar el script en local.
readonly REPOSITORIO="${GK_REPOSITORIO:-ghcr.io/rust7730/gatekeeper-api}"
readonly ETIQUETA="main"
readonly ESTADO="${GK_ESTADO:-/var/lib/gatekeeper}"
readonly REGISTRO="${GK_REGISTRO:-/var/log/gatekeeper/despliegues.log}"
readonly COMPOSE="${GK_COMPOSE:-/usr/local/sbin/gk-compose}"
readonly COSIGN="${GK_COSIGN:-/usr/local/bin/cosign}"
readonly CONFIG="${GK_CONFIG:-/etc/gatekeeper/compose.env}"
readonly SONDA="${GK_SONDA:-/opt/gatekeeper/sonda_aislamiento.py}"
readonly IMAGEN_ENV="$ESTADO/imagen.env"
readonly REVISION="$ESTADO/revision"
readonly ANTERIOR="$ESTADO/anterior"
readonly RETENIDO="$ESTADO/retenido"
readonly DETENIDO="$ESTADO/detenido"
readonly FIRMA_FALLIDA="$ESTADO/firma_fallida"
readonly RESPALDOS="$ESTADO/respaldos"
readonly RESPALDOS_A_CONSERVAR=5
readonly ESPERA_SALUD_S=60
# Quién puede firmar una imagen desplegable: solo ese workflow, en main, con el OIDC de GitHub Actions.
readonly IDENTIDAD="https://github.com/Rust7730/GateKeeper-API/.github/workflows/despliegue.yml@refs/heads/main"
readonly EMISOR="https://token.actions.githubusercontent.com"
readonly ALEMBIC=(/app/.venv/bin/alembic -c api/migrations/alembic.ini)

# cosign guarda aquí la raíz de confianza de Sigstore (TUF); el servicio no puede escribir en /root.
export TUF_ROOT="${TUF_ROOT:-$ESTADO/sigstore}"

registrar() {
    local linea
    linea="$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"
    echo "$linea"
    echo "$linea" >>"$REGISTRO"
}

# Valor de una variable en un archivo KEY=valor, sin ejecutarlo.
leer_variable() {
    sed -n "s/^$1=//p" "$2" 2>/dev/null | head -n 1
}

imagen_actual() {
    local imagen
    imagen=$(leer_variable GATEKEEPER_IMAGEN "$IMAGEN_ENV")
    # Antes del primer despliegue la imagen es la etiqueta, no un digest: no hay a qué volver.
    if [[ $imagen == "$REPOSITORIO"@sha256:* ]]; then
        echo "$imagen"
    fi
}

guardar() {
    local temporal
    temporal=$(mktemp "$ESTADO/.estado.XXXXXX")
    printf '%s\n' "$2" >"$temporal"
    mv -f "$temporal" "$1"
}

fijar_imagen() {
    guardar "$IMAGEN_ENV" "GATEKEEPER_IMAGEN=$1"
}

# Digest con el que se conoce en el registro la imagen que acaba de bajarse.
digest_de() {
    docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$1" |
        grep -m 1 "^$REPOSITORIO@sha256:[0-9a-f]\{64\}$"
}

# --- Comprobaciones de la imagen ----------------------------------------------------------------

# 0 si la firma es válida. Si no, imprime la clase del fallo según el código de cosign (v3.1.4):
# 10 y 11 (no hay firma), 12 (ninguna firma de la identidad esperada) son "invalida"; cualquier otro
# código (red, Rekor, TUF, registro) es "error", posiblemente transitorio. Las dos clases fallan cerrado.
verificar_firma() {
    local codigo=0
    "$COSIGN" verify \
        --certificate-identity "$IDENTIDAD" \
        --certificate-oidc-issuer "$EMISOR" \
        "$1" >/dev/null || codigo=$?
    case $codigo in
    0) return 0 ;;
    10 | 11 | 12) echo invalida ;;
    *) echo "error (código $codigo)" ;;
    esac
    return 1
}

# Falla cerrado: sin código de sonda, con cualquier código de salida distinto de 0 o sin la línea
# exacta de éxito, la imagen no pasa.
sondear() {
    local codigo salida
    codigo=$(<"$SONDA")
    if [[ -z $codigo ]]; then
        registrar "la sonda $SONDA está vacía"
        return 1
    fi
    salida=$(GATEKEEPER_IMAGEN="$1" "$COMPOSE" --profile sonda run --rm -T sonda \
        /app/.venv/bin/python -c "$codigo") || return 1
    echo "$salida"
    grep -qx 'sonda: landlock_abi=[0-9]\{1,\} fallos=ninguno' <<<"$salida"
}

# --- Base de datos ------------------------------------------------------------------------------

alembic_con() {
    local imagen=$1
    shift
    GATEKEEPER_IMAGEN="$imagen" "$COMPOSE" --profile migrar run --rm -T migrate "${ALEMBIC[@]}" "$@"
}

# Revisión de Alembic de la base, leída con `imagen` (tiene que conocerla). `base` si está vacía.
revision_con() {
    local salida revision
    salida=$(alembic_con "$1" current) || return 1
    revision=$(awk 'NF { ultima = $1 } END { print ultima }' <<<"$salida")
    echo "${revision:-base}"
}

respaldar() {
    local etiqueta=$1 destino temporal
    mkdir -p "$RESPALDOS" || return 1
    destino="$RESPALDOS/$(date -u +%Y%m%dT%H%M%SZ)-$etiqueta.dump"
    temporal=$(mktemp "$RESPALDOS/.respaldo.XXXXXX") || return 1
    # shellcheck disable=SC2016 # las variables se expanden dentro del contenedor de postgres
    if ! "$COMPOSE" exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' >"$temporal" ||
        [[ ! -s $temporal ]]; then
        rm -f "$temporal"
        return 1
    fi
    mv -f "$temporal" "$destino" || return 1
    # Solo los últimos N.
    find "$RESPALDOS" -maxdepth 1 -name '*.dump' -printf '%f\n' | sort -r |
        tail -n +$((RESPALDOS_A_CONSERVAR + 1)) | while read -r viejo; do rm -f "$RESPALDOS/$viejo"; done
    echo "$destino"
}

# Deja la base en `objetivo`, la revisión que espera `destino`. Normalmente es un downgrade con
# `conocida`, la imagen que conoce la revisión actual (la más nueva). Si `objetivo` es más nueva que la
# actual (un --revertir hacia una imagen más reciente), el downgrade no aplica y se hace upgrade con
# `destino`, que sí la conoce. Alembic corre cada intento en una transacción: uno fallido no deja nada a
# medias. 0 si la base ya está o queda en `objetivo`.
ajustar_esquema() {
    local conocida=$1 objetivo=$2 destino=$3 actual
    actual=$(revision_con "$conocida") || return 1
    if [[ $actual == "$objetivo" ]]; then
        return 0
    fi
    registrar "downgrade del esquema $actual -> $objetivo con $conocida"
    if ! alembic_con "$conocida" downgrade "$objetivo"; then
        registrar "el downgrade no aplica o falló; upgrade $actual -> $objetivo con $destino"
        alembic_con "$destino" upgrade "$objetivo" || return 1
    fi
    actual=$(revision_con "$destino") || return 1
    [[ $actual == "$objetivo" ]]
}

# Para la API y deja el marcador: hasta que alguien restaure la base y lo borre, nada la vuelve a
# levantar ni migra (principal() e instalar.sh lo comprueban).
detener() {
    guardar "$DETENIDO" "$(date -u +%Y-%m-%dT%H:%M:%SZ) $* respaldo=${RESPALDO:-ninguno}"
    registrar "DETENIDO: $*. La API queda parada; respaldo en ${RESPALDO:-ninguno}. Ver README, Rollback."
    GATEKEEPER_IMAGEN="$REPOSITORIO:$ETIQUETA" "$COMPOSE" stop api || true
}

# --- API ----------------------------------------------------------------------------------------

url_salud() {
    if [[ -n ${GK_URL_SALUD:-} ]]; then
        echo "$GK_URL_SALUD"
    else
        echo "https://$(leer_variable GATEKEEPER_DOMINIO "$CONFIG")/health"
    fi
}

# /health a través de nginx y TLS, desde la propia máquina: prueba la cadena entera.
salud() {
    local url dominio resolver=() limite
    url=$(url_salud)
    if [[ -z ${GK_URL_SALUD:-} ]]; then
        dominio=$(leer_variable GATEKEEPER_DOMINIO "$CONFIG")
        resolver=(--resolve "$dominio:443:127.0.0.1")
    fi
    limite=$((SECONDS + ESPERA_SALUD_S))
    while ((SECONDS < limite)); do
        if curl -fsS --max-time 5 "${resolver[@]}" -o /dev/null "$url"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

levantar() {
    GATEKEEPER_IMAGEN="$1" "$COMPOSE" up -d --wait --wait-timeout 120 postgres api nginx nginx-http
}

# Vuelve a `imagen`, que espera el esquema en `revision`. Antes deja el esquema en esa revisión con
# `nueva`, la imagen que conoce la revisión actual (ver ajustar_esquema). Si no puede, no levanta nada.
volver_a() {
    local imagen=$1 revision=$2 nueva=$3
    if [[ -z $imagen ]]; then
        detener "no hay imagen anterior a la que volver"
        return 1
    fi
    if ! ajustar_esquema "$nueva" "$revision" "$imagen"; then
        detener "no se pudo llevar el esquema a $revision"
        return 1
    fi
    if levantar "$imagen" && salud; then
        registrar "rollback ok imagen=$imagen revision=$revision"
        return 0
    fi
    detener "la imagen anterior $imagen tampoco responde"
    return 1
}

# --- Flujos -------------------------------------------------------------------------------------

desplegar() {
    local nuevo=$1 actual=$2 revision_antes revision_despues
    RESPALDO=""
    echo "inicio actual=${actual:-ninguna} nuevo=$nuevo"

    local clase
    # Sin retener: se reintenta en cada corrida, y nada usa la imagen hasta que la firma valga. Para no
    # llenar el registro cada 5 minutos, solo se registra cuando cambia el digest o la clase del fallo.
    if ! clase=$(verificar_firma "$nuevo"); then
        local mensaje
        if [[ $clase == invalida ]]; then
            mensaje="RECHAZADA: $nuevo no tiene una firma del workflow de main; no se usó la imagen"
        else
            mensaje="no se pudo verificar la firma de $nuevo ($clase: red, Rekor o TUF); se reintenta en la próxima corrida"
        fi
        if [[ "$nuevo $clase" != "$(cat "$FIRMA_FALLIDA" 2>/dev/null || true)" ]]; then
            guardar "$FIRMA_FALLIDA" "$nuevo $clase"
            registrar "$mensaje"
        else
            echo "$mensaje"
        fi
        return 1
    fi
    rm -f "$FIRMA_FALLIDA"
    registrar "inicio actual=${actual:-ninguna} nuevo=$nuevo (firma verificada)"
    if ! sondear "$nuevo"; then
        guardar "$RETENIDO" "$nuevo"
        registrar "fallo sonda de aislamiento (Landlock/seccomp) nuevo=$nuevo; no se cambió nada"
        return 1
    fi
    if ! revision_antes=$(revision_con "$nuevo"); then
        registrar "no se pudo leer la revisión de Alembic; no se cambió nada"
        return 1
    fi
    if ! RESPALDO=$(respaldar "$revision_antes"); then
        registrar "fallo el respaldo de la base; no se migra ni se cambia nada"
        return 1
    fi
    registrar "respaldo $RESPALDO (revision=$revision_antes)"

    if ! migrar_y_levantar "$nuevo"; then
        guardar "$RETENIDO" "$nuevo"
        registrar "fallo el despliegue de $nuevo; vuelta a ${actual:-ninguna} (revision=$revision_antes)"
        volver_a "$actual" "$revision_antes" "$nuevo" || true
        return 1
    fi

    if ! revision_despues=$(revision_con "$nuevo"); then
        # La API nueva ya responde: se registra igual, pero sin revisión no habrá --revertir automático.
        revision_despues=desconocida
    fi
    registrar "esquema $revision_antes -> $revision_despues"
    if [[ -n $actual ]]; then
        guardar "$ANTERIOR" "$actual $revision_antes"
    fi
    fijar_imagen "$nuevo"
    guardar "$REVISION" "$revision_despues"
    rm -f "$RETENIDO"
    registrar "ok imagen=$nuevo revision=$revision_despues"
    # Imágenes sin etiqueta de más de 7 días; si hiciera falta volver a una, se baja por digest.
    docker image prune -f --filter "until=168h" >/dev/null || true
}

migrar_y_levantar() {
    if ! alembic_con "$1" upgrade head; then
        registrar "fallo la migración"
        return 1
    fi
    if ! levantar "$1" || ! salud; then
        registrar "fallo la salud de la API"
        return 1
    fi
}

revertir() {
    local actual revision_actual anterior revision_anterior
    actual=$(imagen_actual)
    revision_actual=$(cat "$REVISION" 2>/dev/null || true)
    if [[ -z $actual || -z $revision_actual ]]; then
        echo "No hay una imagen desplegada con su revisión registrada." >&2
        return 1
    fi
    anterior=""
    revision_anterior=""
    if [[ -f $ANTERIOR ]]; then
        read -r anterior revision_anterior <"$ANTERIOR" || true
    fi
    if [[ -z $anterior || -z $revision_anterior || $revision_anterior == desconocida ]]; then
        echo "No hay imagen anterior a la que volver." >&2
        return 1
    fi
    RESPALDO=""
    registrar "revertir manual actual=${actual:-ninguna} anterior=$anterior revision=$revision_anterior"
    if ! RESPALDO=$(respaldar "$revision_actual"); then
        registrar "fallo el respaldo de la base; no se revierte"
        return 1
    fi
    registrar "respaldo $RESPALDO (revision=$revision_actual)"
    if volver_a "$anterior" "$revision_anterior" "$actual"; then
        fijar_imagen "$anterior"
        guardar "$REVISION" "$revision_anterior"
        guardar "$RETENIDO" "$actual"
        guardar "$ANTERIOR" "$actual $revision_actual"
        registrar "revertir ok imagen=$anterior (retenida $actual hasta que :main cambie)"
        return 0
    fi
    return 1
}

principal() {
    mkdir -p "$ESTADO" "$(dirname "$REGISTRO")"
    exec 9>"$ESTADO/.cerrojo"
    if ! flock -n 9; then
        echo "Ya hay un despliegue o una instalación en curso."
        return 0
    fi
    if [[ -e $DETENIDO ]]; then
        echo "DETENIDO desde $(cat "$DETENIDO")." >&2
        echo "No se despliega, no se migra ni se revierte hasta restaurar la base y borrar $DETENIDO (README, Rollback)." >&2
        return 3
    fi

    case "${1:-}" in
    --revertir)
        revertir
        ;;
    "")
        local nuevo actual
        docker pull -q "$REPOSITORIO:$ETIQUETA" >/dev/null
        nuevo=$(digest_de "$REPOSITORIO:$ETIQUETA")
        actual=$(imagen_actual)
        if [[ $nuevo == "$actual" ]]; then
            return 0
        fi
        if [[ $nuevo == "$(cat "$RETENIDO" 2>/dev/null || true)" ]]; then
            # Ya falló o se revirtió a mano: se espera a un :main nuevo.
            return 0
        fi
        desplegar "$nuevo" "$actual"
        ;;
    *)
        echo "Uso: $0 [--revertir]" >&2
        return 2
        ;;
    esac
}

principal "$@"
