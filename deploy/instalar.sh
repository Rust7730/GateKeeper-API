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
# huella publicada), cosign (versión y checksum fijados), actualizaciones automáticas, swap, usuarios de
# servicio y directorios, copia de deploy/ a /opt/gatekeeper, límite de conexiones por IP al puerto 80,
# secretos en /etc/gatekeeper/ (nunca se imprimen), certificado de Let's Encrypt (HTTP-01 por webroot),
# rol gk_app de PostgreSQL, primer despliegue (con la firma de la imagen verificada) y timers de systemd.
#
# Sobre una instalación anterior a gk_app y Redis (la API conectada como dueña del esquema), conserva
# la base, el pepper y las contraseñas que ya existen, y añade las nuevas. La API pasa a gk_app en
# cuanto el esquema le da permisos (migración 0002); hasta entonces sigue como dueña (actualizar.sh).
set -euo pipefail
umask 022

ORIGEN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ORIGEN
readonly OPT=/opt/gatekeeper
readonly ETC=/etc/gatekeeper
readonly VAR=/var/lib/gatekeeper
readonly LOG=/var/log/gatekeeper
readonly IMAGEN_INICIAL="ghcr.io/rust7730/gatekeeper-api:main"
readonly UID_SERVICIO=10001 # el mismo usuario que corre la API y coordinator dentro de la imagen
readonly UID_REDIS=10002    # el usuario de redis-main y redis-queue en el compose
readonly UID_WORKER=10003   # el usuario del worker aislado de CDR (K64, INV-04)
readonly GID_DATOS=10010    # grupo compartido entre api/coordinator (10001) y worker (10003) (K64)
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
for archivo in docker-compose.yml actualizar.sh actualizar_dashboard.sh cortafuegos.sh gk-compose sonda_aislamiento.py \
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
# python3: calcula el verificador SCRAM de la contraseña de gk_app (ver "Rol gk_app").
apt-get install -y -q ca-certificates curl gnupg openssl python3 unattended-upgrades

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

# La API corre en el contenedor como UID 10001 y redis-main como 10002. Se reservan en el host con
# nombre propio para que ninguna cuenta del sistema reciba esos UID: la configuración de redis-main es
# del 10002, y los archivos de la API en los volúmenes se ven como `gatekeeper`. No tienen shell ni
# están en el grupo docker.
reservar_usuario() {
    local nombre=$1 uid=$2
    if id "$nombre" >/dev/null 2>&1; then
        [[ $(id -u "$nombre") == "$uid" ]] ||
            fallar "el usuario $nombre existe con otro UID ($(id -u "$nombre"))."
    else
        if getent passwd "$uid" >/dev/null || getent group "$uid" >/dev/null; then
            fallar "el UID o GID $uid ya está en uso."
        fi
        groupadd --system --gid "$uid" "$nombre"
        useradd --system --uid "$uid" --gid "$uid" --no-create-home \
            --home-dir /nonexistent --shell /usr/sbin/nologin "$nombre"
    fi
}

paso "Usuarios de servicio"
reservar_usuario gatekeeper "$UID_SERVICIO"
reservar_usuario gatekeeper-redis "$UID_REDIS"
reservar_usuario gatekeeper-worker "$UID_WORKER"
if getent group gatekeeper-datos >/dev/null 2>&1; then
    [[ $(getent group gatekeeper-datos | cut -d: -f3) == "$GID_DATOS" ]] ||
        fallar "el grupo gatekeeper-datos existe con otro GID."
else
    if getent group "$GID_DATOS" >/dev/null; then
        fallar "el GID $GID_DATOS ya está en uso."
    fi
    groupadd --system --gid "$GID_DATOS" gatekeeper-datos
fi

paso "Directorios y archivos del despliegue"
install -d -o root -g root -m 0755 "$OPT" "$OPT/dashboard"
install -d -o root -g root -m 0700 "$ETC" "$VAR" "$VAR/docker" "$VAR/sigstore" "$VAR/respaldos"
install -d -o root -g root -m 0750 "$LOG"
install -o root -g root -m 0644 "$ORIGEN/docker-compose.yml" "$OPT/docker-compose.yml"
install -o root -g root -m 0644 "$ORIGEN/sonda_aislamiento.py" "$OPT/sonda_aislamiento.py"
install -o root -g root -m 0755 "$ORIGEN/actualizar.sh" "$OPT/actualizar.sh"
install -o root -g root -m 0755 "$ORIGEN/actualizar_dashboard.sh" "$OPT/actualizar_dashboard.sh"
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
    # La URL del dueño del esquema es solo para las migraciones (y el respaldo, que corre dentro del
    # contenedor de postgres). La API recibe la suya en api-bd.env (abajo y actualizar.sh).
    url_bd="postgresql+psycopg://${usuario_bd}:${clave_bd}@postgres:5432/gatekeeper"
    escribir_secreto "$ETC/postgres.env" \
        "POSTGRES_USER=${usuario_bd}" "POSTGRES_DB=gatekeeper" "POSTGRES_PASSWORD=${clave_bd}"
    escribir_secreto "$ETC/api.env" "GATEKEEPER_PEPPER=${pepper}"
    escribir_secreto "$ETC/migrate.env" "GATEKEEPER_DATABASE_URL_MIGRACION=${url_bd}"
    unset clave_bd pepper url_bd
    echo "Generados (no se muestran)."
fi

# Las contraseñas de gk_app y de redis-main (K59), una sola vez cada una; en una instalación anterior
# se añaden sin tocar las demás. La de gk_app se vuelve a fijar en la base en cada corrida (ver "Rol
# gk_app"), y Redis no guarda nada: regenerar una que falte no rompe nada. Hexadecimal de 256 bits:
# va tal cual dentro de una URL, sin escapar.
for archivo in gk_app.clave redis.clave redis-queue-coord.clave redis-queue-worker.clave; do
    if [[ ! -s $ETC/$archivo ]]; then
        escribir_secreto "$ETC/$archivo" "$(openssl rand -hex 32)"
        echo "Generada $archivo (no se muestra)."
    fi
    [[ $(<"$ETC/$archivo") =~ ^[0-9a-f]{64}$ ]] || fallar "$ETC/$archivo no tiene el formato esperado."
done

# $VAR/api-bd.env lleva GATEKEEPER_DATABASE_URL de la API. Lo reescribe actualizar.sh antes de cada
# arranque de la API (gk_app si el esquema ya le da permisos), y va en $VAR porque el timer no puede
# escribir en /etc. Si aún no existe, empieza con la URL del dueño, que es con la que corre hoy una
# instalación anterior. Se escribe antes de quitar esa URL de api.env: la API nunca se queda sin ella.
if [[ ! -f $VAR/api-bd.env ]]; then
    url_dueno=$(sed -n 's/^GATEKEEPER_DATABASE_URL_MIGRACION=//p' "$ETC/migrate.env")
    [[ $url_dueno == postgresql+psycopg://* ]] || fallar "$ETC/migrate.env no tiene la URL de migración."
    temporal=$(mktemp "$VAR/.secreto.XXXXXX")
    chmod 0600 "$temporal"
    printf 'GATEKEEPER_DATABASE_URL=%s\n' "$url_dueno" >"$temporal"
    mv -f "$temporal" "$VAR/api-bd.env"
    unset url_dueno
fi

# api.env: todo lo que ya tenía, tal cual (el pepper nunca se toca), menos GATEKEEPER_DATABASE_URL, que
# pasa a api-bd.env, y con GATEKEEPER_REDIS_URL, que se escribe a partir de redis.clave. El usuario
# `gatekeeper` de Redis es el de la API (ver redis.conf, abajo).
lineas_api=()
while IFS= read -r linea || [[ -n $linea ]]; do
    case $linea in
    GATEKEEPER_DATABASE_URL=* | GATEKEEPER_REDIS_URL=*) ;;
    *) lineas_api+=("$linea") ;;
    esac
done <"$ETC/api.env"
[[ $(printf '%s\n' "${lineas_api[@]}" | grep -c '^GATEKEEPER_PEPPER=') == 1 ]] ||
    fallar "$ETC/api.env debe tener exactamente un GATEKEEPER_PEPPER; no se toca."
clave_redis=$(<"$ETC/redis.clave")
url_redis_main="redis://gatekeeper:${clave_redis}@redis-main:6379/0"
lineas_api+=("GATEKEEPER_REDIS_URL=${url_redis_main}")
if [[ $(printf '%s\n' "${lineas_api[@]}") != "$(<"$ETC/api.env")" ]]; then
    escribir_secreto "$ETC/api.env" "${lineas_api[@]}"
    echo "api.env actualizado (no se muestra)."
fi
# H-05: coordinator y reputation solo reciben GATEKEEPER_REDIS_URL, nunca GATEKEEPER_PEPPER.
escribir_secreto "$ETC/redis-main.env" "GATEKEEPER_REDIS_URL=${url_redis_main}"
unset url_redis_main

# redis.conf: los usuarios de redis-main. Lleva el SHA-256 de la contraseña, no la contraseña, y es del
# usuario del contenedor (10002) con modo 0400: el compose la monta en solo lectura.
#   default    desactivado: sin AUTH, Redis no ejecuta nada.
#   salud      sin contraseña, solo PING: lo usa el healthcheck, que así no necesita el secreto.
#   gatekeeper la API. Todas las claves, todo menos @dangerous (CONFIG, DEBUG, MODULE, SAVE, KEYS,
#              FLUSHALL, SHUTDOWN, MONITOR...): una API comprometida no reconfigura ni vacía Redis.
huella_redis=$(printf '%s' "$clave_redis" | sha256sum | cut -d' ' -f1)
unset clave_redis lineas_api
temporal=$(mktemp "$ETC/.secreto.XXXXXX")
chmod 0600 "$temporal"
printf '%s\n' "# Generado por instalar.sh; no se edita a mano." \
    "user default off" \
    "user salud on nopass -@all +ping" \
    "user gatekeeper on #${huella_redis} ~* &gk:eventos:* +@all -@dangerous" >"$temporal"
chown "$UID_REDIS:$UID_REDIS" "$temporal"
chmod 0400 "$temporal"
mv -f "$temporal" "$ETC/redis.conf"
unset huella_redis

# redis-queue (K02, F1.02): cola aislada entre coordinator y worker, con credenciales distintas.
clave_q_coord=$(<"$ETC/redis-queue-coord.clave")
clave_q_worker=$(<"$ETC/redis-queue-worker.clave")
escribir_secreto "$ETC/cola.env" \
    "GATEKEEPER_REDIS_QUEUE_URL=redis://coordinator:${clave_q_coord}@redis-queue:6379/0"
escribir_secreto "$ETC/worker.env" \
    "GATEKEEPER_REDIS_QUEUE_URL=redis://worker:${clave_q_worker}@redis-queue:6379/0"
huella_q_coord=$(printf '%s' "$clave_q_coord" | sha256sum | cut -d' ' -f1)
huella_q_worker=$(printf '%s' "$clave_q_worker" | sha256sum | cut -d' ' -f1)
unset clave_q_coord clave_q_worker
temporal=$(mktemp "$ETC/.secreto.XXXXXX")
chmod 0600 "$temporal"
printf '%s\n' "# Generado por instalar.sh; no se edita a mano." \
    "user default off" \
    "user salud on nopass -@all +ping" \
    "user coordinator on #${huella_q_coord} ~* +@all -@dangerous" \
    "user worker on #${huella_q_worker} ~* +@all -@dangerous" >"$temporal"
chown "$UID_REDIS:$UID_REDIS" "$temporal"
chmod 0400 "$temporal"
mv -f "$temporal" "$ETC/redis-queue.conf"
unset huella_q_coord huella_q_worker

# reputation.env (F4.03, K65): opcional; si VIRUSTOTAL_API_KEY queda vacía, D3 marca VT no_evaluada.
if [[ ! -f $ETC/reputation.env ]]; then
    escribir_secreto "$ETC/reputation.env" "VIRUSTOTAL_API_KEY="
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

paso "Estado del despliegue"
# Tras un downgrade fallido, actualizar.sh deja la API parada y este marcador. Levantarla aquí la pondría
# a correr sobre un esquema que no conoce: primero hay que restaurar la base (README, Rollback).
if [[ -e $VAR/detenido ]]; then
    fallar "la API está DETENIDA desde $(cat "$VAR/detenido"). Restaura la base y borra $VAR/detenido (README, Rollback); no se levanta nada."
fi

# El rol de la API, antes de migrar: la migración 0002 (que corre con el dueño) le da sus permisos, y
# hace falta que el rol ya exista. Aquí solo se crea y se fija su contraseña y sus atributos: nada de
# superusuario, ni crear bases o roles, ni replicación, ni saltarse RLS, ni heredar permisos de otros.
# Se puede correr siempre: crea el rol si falta y si no, solo lo ajusta.
#
# La contraseña no llega al servidor: se envía su verificador SCRAM-SHA-256 (sal aleatoria, 4096
# iteraciones), así que ni el log de PostgreSQL ni pg_stat_activity la ven. Entra a python3 por stdin,
# nunca como argumento. Límite de 25 conexiones: el pool de la API (5 + 10) y alguna `alta`, dejando
# sitio al dueño en las 40 de max_connections.
paso "Rol gk_app de PostgreSQL"
# shellcheck disable=SC2016 # código Python: sus $ son literales
verificador_scram='
import base64, hashlib, hmac, os, sys
clave = sys.stdin.readline().strip().encode()
if len(clave) != 64:
    sys.exit("contraseña de gk_app vacía o con otro formato")
sal, iteraciones = os.urandom(16), 4096
salada = hashlib.pbkdf2_hmac("sha256", clave, sal, iteraciones)
cliente = hmac.new(salada, b"Client Key", "sha256").digest()
servidor = hmac.new(salada, b"Server Key", "sha256").digest()
b64 = lambda datos: base64.b64encode(datos).decode()
print(f"SCRAM-SHA-256${iteraciones}:{b64(sal)}${b64(hashlib.sha256(cliente).digest())}:{b64(servidor)}")
'
verificador=$(python3 -I -c "$verificador_scram" <"$ETC/gk_app.clave")
[[ $verificador =~ ^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$ ]] ||
    fallar "no se pudo calcular el verificador de la contraseña de gk_app."
gk-compose up -d --wait --wait-timeout 120 postgres
# shellcheck disable=SC2016 # las variables de sh -c se expanden dentro del contenedor de postgres
gk-compose exec -T postgres sh -c 'psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<EOF ||
SELECT 'CREATE ROLE gk_app' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gk_app') \gexec
ALTER ROLE gk_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
    CONNECTION LIMIT 25 PASSWORD '${verificador}';
EOF
    fallar "no se pudo crear o ajustar el rol gk_app."
unset verificador
echo "Listo (la contraseña no se muestra)."

paso "Despliegue de la imagen"
# actualizar.sh toma el mismo cerrojo: se suelta aquí; el timer sigue parado hasta el final.
flock -u 9
if ! "$OPT/actualizar.sh"; then
    fallar "el despliegue falló; revisa $LOG/despliegues.log y 'gk-compose logs api'."
fi
# Si la imagen ya estaba desplegada, actualizar.sh no hace nada: --reaplicar aplica los cambios de
# configuración de esta corrida (compose, secretos, redis.conf y el rol de la API) a la imagen
# desplegada y comprueba /health. Solo con una imagen ya fijada por digest.
if ! grep -q '^GATEKEEPER_IMAGEN=.*@sha256:' "$VAR/imagen.env"; then
    fallar "no hay ninguna imagen desplegada; revisa $LOG/despliegues.log."
fi
if ! "$OPT/actualizar.sh" --reaplicar; then
    fallar "la API no quedó en servicio con la configuración nueva; revisa $LOG/despliegues.log y 'gk-compose logs api'."
fi
gk-compose up -d --wait --wait-timeout 120 --force-recreate nginx nginx-http
"$OPT/actualizar_dashboard.sh" || true

paso "Timers de systemd"
systemctl enable --now gatekeeper-actualizar.timer gatekeeper-certificados.timer gatekeeper-purga.timer
timer_activo=no

paso "Listo"
cat <<EOF
Gatekeeper responde en https://$dominio para quien deje pasar el grupo de seguridad
(K57: 443 abierto a todos, 22 solo desde tus IP).

Crear una aplicación y su API key (se muestra una sola vez):
  sudo gk-compose run --rm api /app/.venv/bin/python -m api.app.alta "Mi aplicación"

Despliegues: $LOG/despliegues.log  ·  sudo systemctl list-timers 'gatekeeper-*'
EOF
