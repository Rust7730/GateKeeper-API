"""Cliente HTTP de VirusTotal v3 solo por hash SHA-256 con caché y cuota en Redis (INV-05).

- **INV-05:** únicamente ``GET {base_url}/files/{sha256}`` con cuerpo vacío; jamás ``POST`` ni
  archivos.
- **Caché (F4.04):** ``gk:vt:cache:{sha256}`` en ``redis-main`` con TTL de 24 h.
- **Cuota (F4.05, K07):** script Lua atómico en ``redis-main`` (4/min, 500/día). Sin cuota
  disponible responde ``no_evaluada`` de inmediato (D3).
- **404 (F4.03):** hash desconocido → ``limpio`` (no malicioso), cacheado 24 h.
"""

import contextlib
import json
import re
import time
from typing import Any

import httpx

from reputation.ajustes import AjustesReputacion

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CLAVE_CACHE = "gk:vt:cache:"
_CLAVE_CUOTA_MIN = "gk:vt:cuota:min"
_CLAVE_CUOTA_DIA = "gk:vt:cuota:dia"

# Consume 1 unidad de cuota minuto (60 s) y día (86400 s) de forma atómica si ambas caben.
_SCRIPT_CUOTA = """
local c_min = tonumber(redis.call('GET', KEYS[1]) or '0')
local c_dia = tonumber(redis.call('GET', KEYS[2]) or '0')
local max_min = tonumber(ARGV[1])
local max_dia = tonumber(ARGV[2])
if c_min >= max_min or c_dia >= max_dia then
  return 0
end
if redis.call('INCR', KEYS[1]) == 1 then
  redis.call('EXPIRE', KEYS[1], 60)
end
if redis.call('INCR', KEYS[2]) == 1 then
  redis.call('EXPIRE', KEYS[2], 86400)
end
return 1
"""


async def _consumir_cuota(redis: Any, cuota_min: int, cuota_dia: int) -> bool:
    resultado = await redis.eval(
        _SCRIPT_CUOTA, 2, _CLAVE_CUOTA_MIN, _CLAVE_CUOTA_DIA, cuota_min, cuota_dia
    )
    return bool(resultado)


async def consultar_virustotal(
    sha256: str,
    ajustes: AjustesReputacion,
    redis: Any,
    cliente_http: httpx.AsyncClient,
) -> dict[str, Any]:
    """Consulta la reputación de ``sha256`` usando caché, cuota y ``GET /files/{sha256}``."""
    inicio = time.perf_counter()

    def _ms() -> int:
        return round((time.perf_counter() - inicio) * 1000)

    if type(sha256) is not str or _SHA256_RE.fullmatch(sha256) is None:
        return {
            "veredicto": "no_evaluada",
            "motivo": "sha256_invalido",
            "duracion_ms": _ms(),
        }

    clave_cache = f"{_CLAVE_CACHE}{sha256}"
    try:
        cacheado = await redis.get(clave_cache)
    except Exception:  # noqa: BLE001
        cacheado = None
    if cacheado:
        try:
            datos = json.loads(cacheado.decode("utf-8"))
            if isinstance(datos, dict) and "veredicto" in datos:
                return {**datos, "cache": True, "duracion_ms": _ms()}
        except ValueError:
            pass

    if not ajustes.vt_api_key:
        return {
            "veredicto": "no_evaluada",
            "motivo": "sin_api_key",
            "duracion_ms": _ms(),
        }

    try:
        tiene_cuota = await _consumir_cuota(
            redis, ajustes.cuota_minuto, ajustes.cuota_dia
        )
    except Exception:  # noqa: BLE001
        return {
            "veredicto": "no_evaluada",
            "motivo": "error_cuota",
            "duracion_ms": _ms(),
        }
    if not tiene_cuota:
        return {
            "veredicto": "no_evaluada",
            "motivo": "sin_cuota",
            "duracion_ms": _ms(),
        }

    url = f"{ajustes.vt_base_url.rstrip('/')}/files/{sha256}"
    try:
        respuesta = await cliente_http.get(
            url,
            headers={"x-apikey": ajustes.vt_api_key, "Accept": "application/json"},
            timeout=ajustes.timeout_http_s,
        )
    except httpx.HTTPError:
        return {
            "veredicto": "no_evaluada",
            "motivo": "vt_no_disponible",
            "duracion_ms": _ms(),
        }

    if respuesta.status_code == 404:
        resultado: dict[str, Any] = {
            "veredicto": "limpio",
            "motivo": "hash_desconocido",
            "desconocido": True,
            "motores_maliciosos": 0,
        }
    elif respuesta.status_code == 200:
        try:
            cuerpo = respuesta.json()
            stats = cuerpo["data"]["attributes"]["last_analysis_stats"]
            maliciosos = int(stats.get("malicious", 0))
            total_motores = sum(
                int(v) for v in stats.values() if isinstance(v, (int, float))
            )
        except (ValueError, KeyError, TypeError):
            return {
                "veredicto": "no_evaluada",
                "motivo": "respuesta_vt_invalida",
                "duracion_ms": _ms(),
            }
        veredicto = "malicioso" if maliciosos >= ajustes.umbral_malicioso else "limpio"
        resultado = {
            "veredicto": veredicto,
            "motivo": "malware_detectado" if veredicto == "malicioso" else "ok",
            "motores_maliciosos": maliciosos,
            "positivos": maliciosos,
            "total": total_motores or maliciosos,
        }
    else:
        return {
            "veredicto": "no_evaluada",
            "motivo": f"http_{respuesta.status_code}",
            "duracion_ms": _ms(),
        }

    with contextlib.suppress(Exception):
        await redis.set(
            clave_cache,
            json.dumps(resultado, separators=(",", ":")).encode("utf-8"),
            ex=ajustes.ttl_cache_s,
        )
    return {**resultado, "duracion_ms": _ms()}
