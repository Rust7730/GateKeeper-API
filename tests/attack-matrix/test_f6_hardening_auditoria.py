"""Pruebas de regresión de seguridad de Fase F6 (H-01..H-09) y cabeceras vec:12 (F6.06)."""

import asyncio
import os
import secrets
from pathlib import Path

import pyotp
import pytest
import yaml
from generadores import png
from sqlalchemy import text
from test_f5_auth_rbac_y_auditoria import _sembrar_usuario

from api.app.coordinador import (
    _copiar_desde_cuarentena,
    _validar_capa_antimalware,
    decidir,
)
from api.app.estados import Estado
from api.app.eventos_sse import HubEventosSSE, LimiteClientesSSE, _sanear_evento_k20
from worker.ajustes import (
    VARIABLE_CLAMAV_HOST,
    VARIABLE_DATOS,
    VARIABLE_REDIS_QUEUE,
    ConfiguracionWorkerError,
    leer_ajustes_worker,
)
from worker.clamav import escanear_clamav


def test_h01_symlink_en_cuarentena_no_copia_secretos_a_uploads(tmp_path: Path) -> None:
    """H-01 [Crítico]: symlink en quarantine/<uuid> -> archivo sensible es rechazado (O_NOFOLLOW)."""
    secreto = tmp_path / "entorno_falso"
    secreto.write_bytes(b"GATEKEEPER_PEPPER=supersecreto")
    cuarentena = tmp_path / "quarantine" / "archivo"
    cuarentena.parent.mkdir()
    os.symlink(secreto, cuarentena)
    destino = tmp_path / "uploads_tmp" / "archivo"

    assert _copiar_desde_cuarentena(cuarentena, destino) is False
    assert not destino.exists()


def test_h01_clamav_rechaza_symlink_fail_closed(tmp_path: Path) -> None:
    """H-01 [Crítico]: escanear_clamav rechaza symlinks sin leer ni abrir conexión."""
    objetivo = tmp_path / "secreto"
    objetivo.write_bytes(b"datos")
    enlace = tmp_path / "symlink_malicioso"
    os.symlink(objetivo, enlace)

    res = asyncio.run(escanear_clamav(enlace, "127.0.0.1", 3310))
    assert res.veredicto == "error"


def test_h03_clamav_fail_closed_y_obligatorio_en_produccion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """H-03 [Alto]: ClamAV ausente o corrupto nunca permite Estado.LIMPIO (INV-09)."""
    assert _validar_capa_antimalware(None, fallo_cerrado=True)["veredicto"] == "error"
    assert _validar_capa_antimalware("ok", fallo_cerrado=True)["veredicto"] == "error"
    assert (
        decidir("limpio", "no_evaluada", "limpio", exigir_clamav=True) is Estado.ERROR
    )
    assert (
        decidir("limpio", "limpio", "no_evaluada", exigir_clamav=True) is Estado.LIMPIO
    )

    monkeypatch.setenv(VARIABLE_REDIS_QUEUE, "redis://worker:x@127.0.0.1:6379/0")
    monkeypatch.setenv(VARIABLE_DATOS, str(tmp_path))
    monkeypatch.delenv(VARIABLE_CLAMAV_HOST, raising=False)
    monkeypatch.delenv("GATEKEEPER_CLAMAV_OPCIONAL", raising=False)
    with pytest.raises(ConfiguracionWorkerError):
        leer_ajustes_worker()


def test_h04_y_h05_compose_endurece_clamav_freshclam_y_aisla_pepper() -> None:
    """H-04 y H-05 [Altos]: clamav/freshclam endurecidos + sin api.env en reputation/coordinator."""
    datos = yaml.safe_load(
        Path("deploy/docker-compose.yml").read_text(encoding="utf-8")
    )
    servicios = datos["services"]

    for nombre in ("clamav", "freshclam"):
        svc = servicios[nombre]
        assert svc.get("read_only") is True, nombre
        assert "ALL" in (svc.get("cap_drop") or []), nombre
        assert "no-new-privileges:true" in (svc.get("security_opt") or []), nombre
        assert svc.get("user") == "100:101", nombre
        assert "@sha256:" in svc["image"], nombre

    for nombre in ("coordinator", "reputation"):
        env_files = servicios[nombre].get("env_file") or []
        assert all("api.env" not in str(e) for e in env_files), (
            f"{nombre} no debe montar api.env (contiene GATEKEEPER_PEPPER)"
        )
        assert any("redis-main.env" in str(e) for e in env_files), nombre


def test_h07_hub_sse_sanea_k20_y_aplica_tope_de_clientes() -> None:
    """H-07 [Alto]: HubEventosSSE aplica lista blanca K20 y rechaza exceso de clientes."""
    import json

    rechazo = json.loads(
        _sanear_evento_k20(
            json.dumps(
                {
                    "id": "1",
                    "severidad": "baja",
                    "tipo": "rechazo_politica",
                    "archivo_id": "abc",
                    "aplicacion_nombre": "App",
                    "nombre_archivo": "secreto.pdf",
                    "en": "2026-11-20T00:00:00Z",
                    "campo_extra": "ignorar",
                }
            )
        )
        or "{}"
    )
    assert "nombre_archivo" not in rechazo
    assert "campo_extra" not in rechazo

    malware = json.loads(
        _sanear_evento_k20(
            json.dumps(
                {
                    "id": "2",
                    "severidad": "critica",
                    "tipo": "malware_detectado",
                    "archivo_id": "abc",
                    "aplicacion_nombre": "App",
                    "nombre_archivo": "eicar.txt",
                    "en": "2026-11-20T00:00:00Z",
                }
            )
        )
        or "{}"
    )
    assert malware["nombre_archivo"] == "eicar.txt"

    hub = HubEventosSSE("redis://127.0.0.1:6379/0", max_clientes=0)

    async def _probar() -> None:
        with pytest.raises(LimiteClientesSSE):
            async with hub.suscribir():
                pass

    asyncio.run(_probar())


def test_h06_h08_h09_y_vec12_auth_rate_limit_enroll_antireplay_y_xss_headers(
    banco,
) -> None:
    """Prueba integrada contra PostgreSQL+Redis reales: H-06, H-08, H-09 y cabeceras vec:12."""
    correo_adm = f"adm-f6-{secrets.token_hex(4)}@gatekeeper.test"
    correo_ana = f"ana-f6-{secrets.token_hex(4)}@gatekeeper.test"
    pw_adm = f"Adm-{secrets.token_hex(8)}!"
    pw_ana = f"Ana-{secrets.token_hex(8)}!"
    secreto_adm = pyotp.random_base32()

    _sembrar_usuario(
        banco,
        correo=correo_adm,
        contrasena=pw_adm,
        rol="admin",
        secreto_totp=secreto_adm,
    )
    _sembrar_usuario(banco, correo=correo_ana, contrasena=pw_ana, rol="analista")

    with banco.api() as cliente:
        # H-09: primer login TOTP pasa; reusar el mismo código en un segundo desafío falla (401).
        d1 = cliente._http.post(
            "/v1/auth/login", json={"correo": correo_adm, "contrasena": pw_adm}
        ).json()["desafio_id"]
        codigo = pyotp.TOTP(secreto_adm).now()
        r_ok = cliente._http.post(
            "/v1/auth/totp", json={"desafio_id": d1, "codigo": codigo}
        )
        assert r_ok.status_code == 200
        tok_adm = r_ok.json()["token_acceso"]

        d2 = cliente._http.post(
            "/v1/auth/login", json={"correo": correo_adm, "contrasena": pw_adm}
        ).json()["desafio_id"]
        r_replay = cliente._http.post(
            "/v1/auth/totp", json={"desafio_id": d2, "codigo": codigo}
        )
        assert r_replay.status_code == 401

        # H-08: admin con MFA activo NO puede sobrescribir su TOTP por /totp/enroll -> 403.
        assert (
            cliente._http.post(
                "/v1/auth/totp/enroll", headers={"Authorization": f"Bearer {tok_adm}"}
            ).status_code
            == 403
        )

        # H-08: analista sin MFA -> fase 1 (enroll) no activa MFA hasta fase 2 (confirm).
        tok_ana = cliente._http.post(
            "/v1/auth/login", json={"correo": correo_ana, "contrasena": pw_ana}
        ).json()["token_acceso"]
        hdr_ana = {"Authorization": f"Bearer {tok_ana}"}
        r_enr = cliente._http.post("/v1/auth/totp/enroll", headers=hdr_ana)
        assert r_enr.status_code == 200
        nuevo_sec = r_enr.json()["secreto"]
        assert (
            cliente._http.get("/v1/auth/me", headers=hdr_ana).json()["mfa_activo"]
            is False
        )
        r_conf = cliente._http.post(
            "/v1/auth/totp/confirm",
            json={"codigo": pyotp.TOTP(nuevo_sec).now()},
            headers=hdr_ana,
        )
        assert r_conf.status_code == 200
        assert r_conf.json()["mfa_activo"] is True
        assert (
            cliente._http.get("/v1/auth/me", headers=hdr_ana).json()["mfa_activo"]
            is True
        )

        # H-06: rate limit por cuenta en /v1/auth/login (11º intento -> 429 con Retry-After).
        correo_bf = f"bf-{secrets.token_hex(4)}@gatekeeper.test"
        codigos_bf = []
        for _ in range(11):
            resp = cliente._http.post(
                "/v1/auth/login",
                json={"correo": correo_bf, "contrasena": "PasswordIncorrecto123!"},
            )
            codigos_bf.append(resp.status_code)
            if resp.status_code == 429:
                assert int(resp.headers.get("retry-after", "0")) >= 1
        assert 429 in codigos_bf

        # vec:12 (defensa API): archivo con nombre HTML/JS responde JSON + nosniff + CSP none.
        id_xss = cliente.subir(png(), b"<script>alert(1)</script>.png", b"image/png")
        r_det = cliente._http.get(
            f"/v1/admin/files/{id_xss}", headers={"Authorization": f"Bearer {tok_adm}"}
        )
        assert r_det.status_code == 200
        assert r_det.headers["content-type"].startswith("application/json")
        assert r_det.headers["x-content-type-options"] == "nosniff"
        assert "default-src 'none'" in r_det.headers["content-security-policy"]

        # Confirmar auditoría de activar_totp y totp_reutilizado en BD.
        with banco.motor.connect() as con:
            acciones = set(
                con.execute(text("SELECT accion FROM evento_auditoria")).scalars()
            )
            motivos = set(
                con.execute(
                    text("SELECT motivo FROM evento_auditoria WHERE motivo IS NOT NULL")
                ).scalars()
            )
        assert "activar_totp" in acciones
        assert "totp_reutilizado" in motivos
