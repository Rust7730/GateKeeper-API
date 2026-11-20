"""K58 / K10 — Sin autenticar o con key inválida: 60 peticiones por minuto por IP (CWE-307, CWE-770).

Las 60 primeras responden el 401 de siempre, idéntico en todos los casos (sin cabecera, mal formada,
inexistente, revocada, otro esquema). La 61 responde `429 {"detail": "Too Many Requests"}` con
`Retry-After` y `Connection: close`, sin leer el cuerpo. Otra IP no se ve afectada, y una key válida
desde esa misma IP tampoco: el límite por IP es solo para lo no autenticado (K10).

La IP es la de la conexión. Sin proxy de confianza delante, `X-Forwarded-For`, `X-Real-IP` y
`Forwarded` son texto del cliente y no deciden nada: si decidieran, cada petición de fuerza bruta
llegaría con una IP inventada distinta.
"""

import base64
import dataclasses
import secrets
import time

import pytest
from generadores import png
from soporte_limite import (
    LIMITE_IP_POR_MIN,
    UNAUTHORIZED,
    RelojFalso,
    drenar,
    exigir_429_del_limite,
    exigir_sin_rastro,
    hijo_rapido,
)
from soporte_matriz import IP_CLIENTE, multipart, nombres

from api.app.ajustes import Ajustes, leer_ajustes

OTRA_IP = "198.51.100.23"  # RFC 5737, TEST-NET-2


def _ip_falsa() -> str:
    return f"203.0.113.{secrets.randbelow(254) + 1}"


@pytest.fixture
def reloj() -> RelojFalso:
    return RelojFalso(time.time())


@pytest.fixture
def abrir(banco, tmp_path, reloj):
    """Abre la API con el reloj congelado. Se abre dentro de la prueba, no en un fixture: si falta
    la costura, la prueba falla (no da error de preparación)."""

    def _abrir():
        return banco.api(comando_cdr=hijo_rapido(tmp_path), reloj_limite=reloj)

    return _abrir


def _variantes(banco) -> list[dict[str, str]]:
    """Las formas de no estar autenticado: todas deben dar el mismo 401."""
    revocada = banco.key_nueva_para(banco.app_b.aplicacion_id)
    banco.revocar(revocada.partition(".")[0])
    inexistente = f"gk_{secrets.token_hex(6)}.{secrets.token_urlsafe(32)}"
    secreto_cambiado = (
        f"{banco.app_a.key.partition('.')[0]}.{secrets.token_urlsafe(32)}"
    )
    basic = base64.b64encode(secrets.token_bytes(12)).decode()
    return [
        {},
        {"authorization": "Bearer no-es-una-key"},
        {"authorization": f"Bearer {inexistente}"},
        {"authorization": f"Bearer {secreto_cambiado}"},
        {"authorization": f"Bearer {revocada}"},
        {"authorization": f"Basic {basic}"},
    ]


def _post(cliente, cabeceras: dict[str, str], origen: str = IP_CLIENTE, extra=None):
    cuerpo, content_type = multipart(png())
    return cliente.asgi(
        "POST",
        "/v1/files",
        {**cabeceras, **(extra or {}), "content-type": content_type},
        [cuerpo],
        origen=origen,
    )


def _agotar_ip(cliente, banco, origen: str = IP_CLIENTE, falsificar: bool = False):
    """60 peticiones sin key válida desde ``origen``: todas el mismo 401, sin leer el cuerpo."""
    variantes = _variantes(banco)
    vistas = set()
    for numero in range(LIMITE_IP_POR_MIN):
        extra = None
        if falsificar:
            falsa = _ip_falsa()
            extra = {
                "x-forwarded-for": falsa,
                "x-real-ip": falsa,
                "forwarded": f"for={falsa}",
            }
        respuesta = _post(cliente, variantes[numero % len(variantes)], origen, extra)
        assert respuesta.estado == 401, (
            f"la petición {numero + 1} sin key válida respondió {respuesta.estado}"
        )
        assert respuesta.cuerpo == UNAUTHORIZED
        assert respuesta.leidos == 0, "se leyó el cuerpo sin autenticar"
        vistas.add((respuesta.cuerpo, tuple(sorted(respuesta.cabeceras.items()))))
    assert len(vistas) == 1, f"los 401 no son idénticos: {vistas}"


def _exigir_429_ip(cliente, banco, origen: str = IP_CLIENTE, extra=None) -> None:
    antes_disco, antes_filas = nombres(banco.uploads_tmp), banco.contar_archivos()
    respuesta = _post(cliente, {}, origen, extra)
    exigir_429_del_limite(respuesta)
    assert respuesta.leidos == 0, "se leyó el cuerpo antes del 429"
    exigir_sin_rastro(banco, antes_disco, antes_filas)


def test_k58_60_peticiones_sin_key_valida_dan_401_identico_y_la_61_da_429(abrir, banco):
    with abrir() as limitada:
        _agotar_ip(limitada, banco)
        _exigir_429_ip(limitada, banco)
        # Con cualquier variante de key inválida, también 429: no hay forma de reabrir la ventana.
        for cabeceras in _variantes(banco):
            exigir_429_del_limite(_post(limitada, cabeceras))


def test_k58_otra_ip_no_se_ve_afectada(abrir, banco):
    with abrir() as limitada:
        _agotar_ip(limitada, banco)
        _exigir_429_ip(limitada, banco)
        respuesta = _post(limitada, {}, OTRA_IP)
        assert respuesta.estado == 401, f"otra IP respondió {respuesta.estado}"


def test_k58_una_key_valida_desde_la_ip_bloqueada_no_queda_bloqueada(abrir, banco):
    with abrir() as limitada:
        _agotar_ip(limitada, banco)
        _exigir_429_ip(limitada, banco)
        respuesta = _post(limitada, limitada.cabeceras(banco.app_a.key))
        assert respuesta.estado == 202, (
            f"una key válida desde la IP limitada respondió {respuesta.estado}"
        )
        drenar(banco, banco.app_a)


def test_k58_la_ventana_se_reabre_al_pasar_el_minuto(abrir, banco, reloj):
    with abrir() as limitada:
        _agotar_ip(limitada, banco)
        _exigir_429_ip(limitada, banco)
        reloj.avanzar(61)
        respuesta = _post(limitada, {})
        assert respuesta.estado == 401, f"pasado el minuto respondió {respuesta.estado}"


def test_k58_x_forwarded_for_falso_no_salta_el_limite(abrir, banco):
    """Cada petición trae otra IP inventada en las cabeceras de proxy: la 61 sigue siendo 429."""
    with abrir() as limitada:
        _agotar_ip(limitada, banco, falsificar=True)
        falsa = _ip_falsa()
        _exigir_429_ip(
            limitada,
            banco,
            extra={
                "x-forwarded-for": falsa,
                "x-real-ip": falsa,
                "forwarded": f"for={falsa}",
            },
        )


def test_k58_x_forwarded_for_falso_no_gasta_el_cupo_de_otra_ip(abrir, banco):
    """Quien manda `X-Forwarded-For: <IP de otro>` no lo deja bloqueado."""
    with abrir() as limitada:
        for _ in range(LIMITE_IP_POR_MIN + 5):
            _post(
                limitada,
                {},
                IP_CLIENTE,
                {
                    "x-forwarded-for": OTRA_IP,
                    "x-real-ip": OTRA_IP,
                    "forwarded": f"for={OTRA_IP}",
                },
            )
        respuesta = _post(limitada, {}, OTRA_IP)
        assert respuesta.estado == 401, (
            f"la IP suplantada quedó limitada: respondió {respuesta.estado}"
        )
        # Y quien la suplantó sí quedó limitado.
        exigir_429_del_limite(_post(limitada, {}, IP_CLIENTE))


def test_k58_sin_costura_el_reloj_real_tambien_limita(banco):
    """La API de producción: 61 peticiones seguidas sin key, la última 429.

    Si la ventana fuera fija por minuto de reloj, cruzar el cambio de minuto la reiniciaría: se
    empieza lejos de él.
    """
    if time.time() % 60 > 50:
        time.sleep(60 - time.time() % 60 + 0.1)
    origen = _ip_falsa()
    with banco.api(reloj_real=True) as cliente:
        _agotar_ip(cliente, banco, origen=origen)
        _exigir_429_ip(cliente, banco, origen=origen)
        assert _post(cliente, {}, OTRA_IP).estado == 401


def test_k58_la_costura_del_reloj_no_se_abre_desde_el_entorno(banco, monkeypatch):
    """Con un reloj del entorno, cualquiera con acceso a la configuración desactivaría el límite."""
    campos = {campo.name: campo for campo in dataclasses.fields(Ajustes)}
    assert "reloj_limite" in campos, (
        "control ausente: falta la costura de prueba reloj_limite en Ajustes"
    )
    monkeypatch.setenv(
        "GATEKEEPER_DATABASE_URL", banco.url.render_as_string(hide_password=False)
    )
    monkeypatch.setenv("GATEKEEPER_PEPPER", banco.pepper.decode())
    monkeypatch.setenv("GATEKEEPER_DATOS", str(banco.datos))
    monkeypatch.setenv("GATEKEEPER_REDIS_URL", banco.url_redis)
    monkeypatch.setenv("GATEKEEPER_RELOJ_LIMITE", "0")
    monkeypatch.setenv("GATEKEEPER_RATE_LIMIT", "0")

    assert leer_ajustes().reloj_limite is campos["reloj_limite"].default
