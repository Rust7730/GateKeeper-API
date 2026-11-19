#!/bin/bash
# Límite de conexiones TCP simultáneas por IP al puerto 80 (nginx-http), en la cadena DOCKER-USER.
#
# El 80 está abierto a todo internet por Let's Encrypt. nginx-http tiene su propio pool, pero una sola
# IP podría ocuparlo entero con conexiones a medias; esto la corta antes de llegar a nginx. Docker no
# toca DOCKER-USER, pero sus reglas no sobreviven a un reinicio: lo aplica gatekeeper-cortafuegos.service
# cada vez que arranca Docker. Se puede correr las veces que haga falta: no duplica la regla.
set -euo pipefail

readonly LIMITE=32 # conexiones abiertas a la vez por IP de origen

aplicar() {
    local herramienta=$1 mascara=$2
    local regla=(-p tcp --syn -m conntrack --ctdir ORIGINAL --ctorigdstport 80
        -m connlimit --connlimit-above "$LIMITE" --connlimit-mask "$mascara"
        -j REJECT --reject-with tcp-reset)
    if ! "$herramienta" -n -L DOCKER-USER >/dev/null 2>&1; then
        return 1
    fi
    # Explícito: aplicar() corre dentro de `||`, donde `set -e` no actúa.
    if ! "$herramienta" -C DOCKER-USER "${regla[@]}" 2>/dev/null; then
        "$herramienta" -I DOCKER-USER 1 "${regla[@]}" || return 2
    fi
    echo "$herramienta: máximo $LIMITE conexiones por IP al puerto 80"
}

# 1: no existe la cadena DOCKER-USER. 2: existe pero no se pudo insertar la regla.
# IPv4 es obligatorio: sin la cadena, Docker no usa iptables y el límite no existiría.
codigo=0
aplicar iptables 32 || codigo=$?
case $codigo in
0) ;;
1)
    echo "ERROR: no existe la cadena DOCKER-USER de iptables (¿Docker corre con otro cortafuegos?)." >&2
    exit 1
    ;;
*)
    echo "ERROR: no se pudo insertar la regla en DOCKER-USER de iptables." >&2
    exit 1
    ;;
esac
# IPv6 solo si Docker gestiona ip6tables; si la cadena existe, la regla es obligatoria.
if command -v ip6tables >/dev/null 2>&1; then
    codigo=0
    aplicar ip6tables 128 || codigo=$?
    case $codigo in
    0) ;;
    1) echo "ip6tables: sin cadena DOCKER-USER; Docker no publica por IPv6." ;;
    *)
        echo "ERROR: no se pudo insertar la regla en DOCKER-USER de ip6tables." >&2
        exit 1
        ;;
    esac
fi
