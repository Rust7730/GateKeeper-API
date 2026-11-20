"""Configuración del servicio ``reputation`` (INV-05, F4.03–F4.08, K65)."""

import os
from dataclasses import dataclass, field

VARIABLE_REDIS = "GATEKEEPER_REDIS_URL"
VARIABLE_VT_API_KEY = (
    "VIRUSTOTAL_API_KEY"  # pragma: allowlist secret (nombre de variable)
)
VARIABLE_VT_BASE_URL = "VIRUSTOTAL_BASE_URL"
VT_BASE_URL_DEFECTO = "https://www.virustotal.com/api/v3"

CUOTA_MINUTO_DEFECTO = 4  # F4.05: cuota pública de VirusTotal
CUOTA_DIA_DEFECTO = 500
TTL_CACHE_S_DEFECTO = 86_400  # 24 h (docs/decisiones.md §6)
UMBRAL_MALICIOSO_DEFECTO = 1  # >= 1 motor malicious -> en_cuarentena
TIMEOUT_HTTP_S_DEFECTO = 5.0


class ConfiguracionReputacionError(RuntimeError):
    """Falta un ajuste obligatorio del servicio ``reputation``. Sin secretos en el texto."""


@dataclass(frozen=True, slots=True)
class AjustesReputacion:
    """Ajustes de ``reputation``. ``url_redis`` y ``vt_api_key`` van fuera del ``repr``."""

    url_redis: str = field(repr=False)
    vt_api_key: str | None = field(default=None, repr=False)
    vt_base_url: str = VT_BASE_URL_DEFECTO
    cuota_minuto: int = CUOTA_MINUTO_DEFECTO
    cuota_dia: int = CUOTA_DIA_DEFECTO
    ttl_cache_s: int = TTL_CACHE_S_DEFECTO
    umbral_malicioso: int = UMBRAL_MALICIOSO_DEFECTO
    timeout_http_s: float = TIMEOUT_HTTP_S_DEFECTO

    def __post_init__(self) -> None:
        if (
            type(self.url_redis) is not str
            or not self.url_redis.strip()
            or self.url_redis != self.url_redis.strip()
        ):
            raise ConfiguracionReputacionError(
                f"Falta la URL de Redis ({VARIABLE_REDIS}) o es inválida."
            )
        if not self.vt_base_url.startswith(("http://", "https://")):
            raise ConfiguracionReputacionError(
                "vt_base_url debe empezar por http(s)://."
            )


def leer_ajustes_reputacion() -> AjustesReputacion:
    url = os.environ.get(VARIABLE_REDIS)
    if url is None or not url.strip():
        raise ConfiguracionReputacionError(
            f"Falta la variable de entorno {VARIABLE_REDIS} o está vacía."
        )
    key_raw = os.environ.get(VARIABLE_VT_API_KEY)
    vt_api_key = key_raw.strip() if key_raw and key_raw.strip() else None
    base_raw = os.environ.get(VARIABLE_VT_BASE_URL)
    vt_base_url = (
        base_raw.strip().rstrip("/")
        if base_raw and base_raw.strip()
        else VT_BASE_URL_DEFECTO
    )
    return AjustesReputacion(
        url_redis=url,
        vt_api_key=vt_api_key,
        vt_base_url=vt_base_url,
    )
