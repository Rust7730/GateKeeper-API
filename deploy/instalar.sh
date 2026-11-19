#!/bin/bash
# Instalación de Gatekeeper en una instancia AWS EC2 nueva (Ubuntu 24.04, x86_64), K55.
#
# Uso, por SSH en la instancia y desde un clon del repositorio:
#   sudo ./deploy/instalar.sh <IP elástica | dominio> [correo para Let's Encrypt]
#
# Con una IP, el dominio es <ip-con-guiones>.sslip.io. Se puede correr otra vez: no regenera los
# secretos, no reinstala lo que ya está y solo pide otro certificado si el dominio cambió o vence.
#
# Hace, en orden: comprobaciones, Docker Engine desde su repositorio oficial (solo la llave con la
# huella publicada), cosign (versión y checksum fijados), actualizaciones automáticas, swap, usuario de
# servicio y directorios, copia de deploy/ a /opt/gatekeeper, límite de conexiones por IP al puerto 80,
# secretos en /etc/gatekeeper/*.env (0600, nunca se imprimen), certificado de Let's Encrypt (HTTP-01
# por webroot), primer despliegue (con la firma de la imagen verificada) y timers de systemd.
set -euo pipefail
umask 022

ORIGEN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ORIGEN
readonly OPT=/opt/gatekeeper
readonly ETC=/etc/gatekeeper
readonly VAR=/var/lib/gatekeeper
readonly LOG=/var/log/gatekeeper
readonly IMAGEN_INICIAL="ghcr.io/rust7730/gatekeeper-api:main"
readonly UID_SERVICIO=10001 # el mismo usuario que corre la API dentro de la imagen
# Huella publicada por Docker para su llave de firma de paquetes (docs.docker.com/engine/install/ubuntu).
readonly HUELLA_DOCKER="9DC858229FC7DD38854AE2D88D81803C0EBFCD88" # pragma: allowlist secret (huella pública)
# cosign verifica la firma de cada imagen antes de desplegarla. SHA-256 de cosign-linux-amd64 según
# cosign_checksums.txt de la release (github.com/sigstore/cosign/releases/tag/v3.1.4).
readonly COSIGN_VERSION="v3.1.4"
readonly COSIGN_SHA256="424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa" # pragma: allowlist secret (checksum público)

paso() { printf '\n==> %s\n' "$*"; }
fallar() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

uso() {
    echo "Uso: sudo $0 <IP elástica | dominio> [correo para Let's Encrypt]" >&2
    exit 2
}

# --- Argumentos ---------------------------------------------------------------------------------

[[ $EUID -eq 0 ]] || fallar "hay que correrlo como root (sudo)."
(($# >= 1 && $# <= 2)) || uso

argumento=${1,,}
correo=${2:-}

if [[ $argumento =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    for octeto in "${BASH_REMATCH[@]:1}"; do
        ((10#$octeto <= 255)) || fallar "IP no válida: $argumento"
    done
    dominio="${argumento//./-}.sslip.io"
elif [[ $argumento =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]; then
    dominio=$argumento
else
    fallar "ni IP ni dominio válido: $argumento"
fi

if [[ -n $correo && ! $correo =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
    fallar "correo no válido: $correo"
fi

# --- Comprobaciones -----------------------------------------------------------------------------

paso "Comprobando el sistema"
# shellcheck source=/dev/null
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || fallar "este script es para Ubuntu (24.04); el sistema es ${ID:-desconocido}."
[[ ${VERSION_ID:-} == 24.04 ]] || echo "AVISO: probado en Ubuntu 24.04; este es ${VERSION_ID:-desconocido}."
[[ $(dpkg --print-architecture) == amd64 ]] ||
    fallar "la imagen se publica solo para x86_64 (amd64)."
# Sin Landlock, el hijo del CDR no se aísla y todos los archivos terminan en `error` (K53).
grep -qw landlock /sys/kernel/security/lsm ||
    fallar "Landlock no está activo en este kernel (/sys/kernel/security/lsm)."
for archivo in docker-compose.yml actualizar.sh cortafuegos.sh gk-compose sonda_aislamiento.py \
    nginx/nginx.conf nginx/http.conf; do
    [[ -f $ORIGEN/$archivo ]] || fallar "falta $ORIGEN/$archivo: corre el script desde el clon."
done
echo "Dominio: $dominio"

# El mismo cerrojo que actualizar.sh: se para el timer y se espera a que termine un despliegue en
# curso. Al salir, por error o no, el timer vuelve a quedar como estaba.
install -d -o root -g root -m 0700 "$VAR"
timer_activo=no
if systemctl is-active --quiet gatekeeper-actualizar.timer 2>/dev/null; then
    timer_activo=si
    systemctl stop gatekeeper-actualizar.timer
fi
restaurar_timer() {
    if [[ $timer_activo == si ]]; then
        systemctl start gatekeeper-actualizar.timer || true
    fi
}
trap restaurar_timer EXIT
exec 9>"$VAR/.cerrojo"
echo "Esperando a que termine cualquier despliegue en curso..."
flock 9

# --- Paquetes -----------------------------------------------------------------------------------

paso "Instalando paquetes base"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q ca-certificates curl gnupg openssl unattended-upgrades

# Deja en `destino` solo la llave con la huella de Docker, y solo si el archivo descargado trae
# exactamente una llave principal y es esa. Un archivo con otra llave añadida se rechaza.
llave_docker() {
    local descargada=$1 destino=$2 hogar listado
    hogar=$(mktemp -d)
    listado=$(gpg --homedir "$hogar" --batch --show-keys --with-colons "$descargada")
    if [[ $(grep -c '^pub:' <<<"$listado") != 1 ]] ||
        [[ $(awk -F: '/^pub:/ { p = 1; next } p && /^fpr:/ { print $10; exit }' <<<"$listado") != "$HUELLA_DOCKER" ]]; then
        rm -rf "$hogar"
        fallar "la llave de Docker no es exactamente una llave con la huella esperada."
    fi
    gpg --homedir "$hogar" --batch --quiet --import "$descargada"
    gpg --homedir "$hogar" --batch --armor --export "$HUELLA_DOCKER" >"$destino"
    rm -rf "$hogar"
}

paso "Instalando Docker Engine desde su repositorio oficial"
if [[ ! -f /etc/apt/sources.list.d/docker.sources ]]; then
    descargada=$(mktemp)
    exportada=$(mktemp)
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "$descargada"
    llave_docker "$descargada" "$exportada"
    install -d -m 0755 /etc/apt/keyrings
    install -m 0644 "$exportada" /etc/apt/keyrings/docker.asc
    rm -f "$descargada" "$exportada"
    cat >/etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME:-$VERSION_CODENAME}
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.asc
EOF
    apt-get update -q
fi
apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

paso "Instalando cosign $COSIGN_VERSION"
if [[ ! -x /usr/local/bin/cosign ]] ||
    [[ $(sha256sum /usr/local/bin/cosign | cut -d' ' -f1) != "$COSIGN_SHA256" ]]; then
    binario=$(mktemp)
    curl -fsSL -o "$binario" \
        "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-amd64"
    echo "$COSIGN_SHA256  $binario" | sha256sum --check --quiet ||
        fallar "el checksum de cosign no coincide; no se instala."
    install -o root -g root -m 0755 "$binario" /usr/local/bin/cosign
    rm -f "$binario"
else
    echo "Ya está instalado."
fi

paso "Activando las actualizaciones automáticas de seguridad"
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
# Docker Engine también: su repositorio no está entre los orígenes de Ubuntu. Al actualizarse, Docker
# se reinicia y con él los contenedores (unos segundos sin servicio).
cat >/etc/apt/apt.conf.d/51gatekeeper-docker <<'EOF'
Unattended-Upgrade::Origins-Pattern {
        "origin=Docker,label=Docker CE,archive=${distro_codename}";
};
EOF
systemctl enable --now unattended-upgrades

# 2 GiB de RAM: la swap es para el sistema y Docker. Los contenedores no la usan (memswap_limit).
paso "Swap de 1 GiB"
if [[ -z $(swapon --show --noheadings) ]]; then
    if [[ ! -f /swapfile ]]; then
        fallocate -l 1G /swapfile
        chmod 0600 /swapfile
        mkswap /swapfile >/dev/null
    fi
    swapon /swapfile
    grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
    echo 'vm.swappiness=10' >/etc/sysctl.d/99-gatekeeper.conf
    sysctl -q -p /etc/sysctl.d/99-gatekeeper.conf
else
    echo "Ya hay swap."
fi

# --- Usuario y directorios ----------------------------------------------------------------------

# La API corre en el contenedor como UID 10001. Se reserva en el host con nombre propio para que
# ninguna cuenta del sistema reciba ese UID y sus archivos en los volúmenes se vean como `gatekeeper`.
# No tiene shell ni está en el grupo docker.
paso "Usuario de servicio"
if id gatekeeper >/dev/null 2>&1; then
    [[ $(id -u gatekeeper) == "$UID_SERVICIO" ]] ||
        fallar "el usuario gatekeeper existe con otro UID ($(id -u gatekeeper))."
else
    if getent passwd "$UID_SERVICIO" >/dev/null || getent group "$UID_SERVICIO" >/dev/null; then
        fallar "el UID o GID $UID_SERVICIO ya está en uso."
    fi
    groupadd --system --gid "$UID_SERVICIO" gatekeeper
    useradd --system --uid "$UID_SERVICIO" --gid "$UID_SERVICIO" --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin gatekeeper
fi

paso "Directorios y archivos del despliegue"
install -d -o root -g root -m 0755 "$OPT"
install -d -o root -g root -m 0700 "$ETC" "$VAR" "$VAR/docker" "$VAR/sigstore" "$VAR/respaldos"
install -d -o root -g root -m 0750 "$LOG"
install -o root -g root -m 0644 "$ORIGEN/docker-compose.yml" "$OPT/docker-compose.yml"
install -o root -g root -m 0644 "$ORIGEN/sonda_aislamiento.py" "$OPT/sonda_aislamiento.py"
install -o root -g root -m 0755 "$ORIGEN/actualizar.sh" "$OPT/actualizar.sh"
install -o root -g root -m 0755 "$ORIGEN/cortafuegos.sh" "$OPT/cortafuegos.sh"
install -o root -g root -m 0755 "$ORIGEN/gk-compose" /usr/local/sbin/gk-compose
# En el sitio y no borrando antes: nginx monta estos archivos y directorios; uno borrado y vuelto a
# crear dejaría al contenedor viendo el viejo hasta recrearlo (se recrea al final).
install -d -o root -g root -m 0755 "$OPT/nginx"
cp -rT "$ORIGEN/nginx" "$OPT/nginx"
rm -f "$OPT/nginx/sitios/local.conf" "$OPT/nginx/sitios/dominio-local.conf"
# El dominio de la redirección del puerto 80 (validado arriba): nunca el Host del cliente.
install -d -o root -g root -m 0755 "$OPT/nginx/generado"
printf 'server_name %s;\n' "$dominio" >"$OPT/nginx/generado/dominio.conf"
chown -R root:root "$OPT/nginx"
chmod -R u=rwX,go=rX "$OPT/nginx"
for unidad in "$ORIGEN"/systemd/*.service "$ORIGEN"/systemd/*.timer; do
    install -o root -g root -m 0644 "$unidad" /etc/systemd/system/
done
systemctl daemon-reload

paso "Límite de conexiones por IP al puerto 80"
systemctl enable gatekeeper-cortafuegos.service
systemctl restart gatekeeper-cortafuegos.service

cat >/etc/logrotate.d/gatekeeper <<'EOF'
/var/log/gatekeeper/*.log {
    monthly
    rotate 12
    compress
    missingok
    notifempty
}
EOF

# --- Secretos -----------------------------------------------------------------------------------

# Se generan una sola vez. Regenerarlos rompería la base (la contraseña vive en su volumen) y todas
# las API keys (dependen del pepper). Los valores solo pasan por variables de esta shell y por
# printf, que es interno de bash: nunca por la línea de comandos de otro proceso ni por la salida.
escribir_secreto() {
    local destino=$1 temporal
    shift
    temporal=$(mktemp "$ETC/.secreto.XXXXXX")
    chmod 0600 "$temporal"
    printf '%s\n' "$@" >"$temporal"
    mv -f "$temporal" "$destino"
}

paso "Secretos en $ETC"
secretos=(postgres.env api.env migrate.env)
presentes=0
for archivo in "${secretos[@]}"; do
    [[ -f $ETC/$archivo ]] && presentes=$((presentes + 1))
done
if ((presentes == ${#secretos[@]})); then
    echo "Ya existen; no se tocan."
elif ((presentes > 0)); then
    fallar "faltan algunos de ${secretos[*]} en $ETC; no se regeneran a medias."
elif docker volume inspect gatekeeper_pgdata >/dev/null 2>&1; then
    fallar "existe el volumen gatekeeper_pgdata pero no sus secretos: la contraseña no coincidiría."
else
    usuario_bd=gatekeeper
    clave_bd=$(openssl rand -hex 32)
    pepper=$(openssl rand -hex 32)
    # Mientras no exista gk_app (migración 0002), la API y las migraciones usan el mismo rol, dueño
    # del esquema: es una limitación declarada en el README.
    url_bd="postgresql+psycopg://${usuario_bd}:${clave_bd}@postgres:5432/gatekeeper"
    escribir_secreto "$ETC/postgres.env" \
        "POSTGRES_USER=${usuario_bd}" "POSTGRES_DB=gatekeeper" "POSTGRES_PASSWORD=${clave_bd}"
    escribir_secreto "$ETC/api.env" \
        "GATEKEEPER_DATABASE_URL=${url_bd}" "GATEKEEPER_PEPPER=${pepper}"
    escribir_secreto "$ETC/migrate.env" "GATEKEEPER_DATABASE_URL_MIGRACION=${url_bd}"
    unset clave_bd pepper url_bd
    echo "Generados (no se muestran)."
fi
escribir_secreto "$ETC/compose.env" "GATEKEEPER_DOMINIO=${dominio}"
if [[ ! -f $VAR/imagen.env ]]; then
    printf 'GATEKEEPER_IMAGEN=%s\n' "$IMAGEN_INICIAL" >"$VAR/imagen.env"
fi

# --- Certificado --------------------------------------------------------------------------------

paso "Certificado de Let's Encrypt para $dominio"
certbot_args=(certonly --webroot -w /var/www/certbot --cert-name gatekeeper -d "$dominio"
    --non-interactive --agree-tos --keep-until-expiring)
if [[ -n $correo ]]; then
    certbot_args+=(--email "$correo" --no-eff-email)
else
    certbot_args+=(--register-unsafely-without-email)
fi

# nginx-http sirve el desafío; no depende de la API ni del certificado. Se recrea para que lea el
# dominio y la configuración recién copiados.
gk-compose up -d --force-recreate nginx-http
gk-compose --profile certbot run --rm -T certbot "${certbot_args[@]}" ||
    fallar "no se obtuvo el certificado. Revisa que el puerto 80 esté abierto a internet en el grupo de seguridad y que $dominio apunte a esta IP."
if [[ -n $(gk-compose ps --status running --quiet nginx 2>/dev/null) ]]; then
    gk-compose exec -T nginx nginx -s reload
fi

# --- Primer despliegue y timers -----------------------------------------------------------------

paso "Despliegue"
# Tras un downgrade fallido, actualizar.sh deja la API parada y este marcador. Levantarla aquí la pondría
# a correr sobre un esquema que no conoce: primero hay que restaurar la base (README, Rollback).
if [[ -e $VAR/detenido ]]; then
    fallar "la API está DETENIDA desde $(cat "$VAR/detenido"). Restaura la base y borra $VAR/detenido (README, Rollback); no se levanta nada."
fi
# actualizar.sh toma el mismo cerrojo: se suelta aquí; el timer sigue parado hasta el final.
flock -u 9
if ! "$OPT/actualizar.sh"; then
    fallar "el despliegue falló; revisa $LOG/despliegues.log y 'gk-compose logs api'."
fi
# Si la imagen ya estaba desplegada, actualizar.sh no hace nada: esto aplica los cambios de
# configuración de una nueva corrida (compose o nginx). Solo con una imagen ya fijada por digest.
if grep -q '^GATEKEEPER_IMAGEN=.*@sha256:' "$VAR/imagen.env"; then
    gk-compose up -d --wait --wait-timeout 120 postgres api
    gk-compose up -d --wait --wait-timeout 120 --force-recreate nginx nginx-http
else
    fallar "no hay ninguna imagen desplegada; revisa $LOG/despliegues.log."
fi

paso "Timers de systemd"
systemctl enable --now gatekeeper-actualizar.timer gatekeeper-certificados.timer
timer_activo=no

paso "Listo"
cat <<EOF
Gatekeeper responde en https://$dominio (solo desde las IP permitidas por el grupo de seguridad).

Crear una aplicación y su API key (se muestra una sola vez):
  sudo gk-compose run --rm api /app/.venv/bin/python -m api.app.alta "Mi aplicación"

Despliegues: $LOG/despliegues.log  ·  sudo systemctl list-timers 'gatekeeper-*'
EOF
