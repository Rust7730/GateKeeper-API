"""F5.06–F5.11 / K06 / K18 / K19 / K20 / F2.01 — Endpoints /v1/admin/*, K20 y liberación.

Comprueba:
1. **K20 (privacidad en el dashboard):** archivos sin malware ni cuarentena solo exponen
   metadatos mínimos (nunca ``nombre_original``, ``sha256``, ``cuarentena_expira_en`` ni
   ``resultados``), y la búsqueda ``q`` no sirve de oráculo sobre nombres restringidos.
2. **RBAC (K06, F5.05):** analista accede a lecturas permitidas y recibe ``403`` en release,
   audit y api-keys; admin accede a todo.
3. **Liberación de cuarentena (F5.06, INV-08, K18, K19, D4):** exige motivo 20–500 chars sin
   controles, ``409`` si no está en cuarentena, registra en ``/v1/admin/audit`` y reencola en
   el CDR (pasa a ``limpio`` reconstruido, nunca entrega el original).
4. **API keys (F2.01, K05):** alta, listado sin secreto, revocación inmediata (``401``) y
   registro en bitácora.
5. **Métricas y aplicaciones:** ``GET /v1/admin/metrics`` y ``GET /v1/admin/applications``.
"""

import hashlib
import secrets
import time

import pyotp
from generadores import png
from sqlalchemy import text
from test_f5_auth_rbac_y_auditoria import _sembrar_usuario
from test_vec11_eicar_y_reputacion import EICAR, EICAR_SHA256, clamd_falso, vt_falso


def _token_analista(cliente, banco) -> str:
    correo = f"ana-{secrets.token_hex(4)}@gatekeeper.test"
    pw = f"Ana-{secrets.token_hex(8)}!"
    _sembrar_usuario(banco, correo=correo, contrasena=pw, rol="analista")
    r = cliente._http.post("/v1/auth/login", json={"correo": correo, "contrasena": pw})
    assert r.status_code == 200
    return r.json()["token_acceso"]


def _token_admin(cliente, banco) -> str:
    correo = f"adm-{secrets.token_hex(4)}@gatekeeper.test"
    pw = f"Adm-{secrets.token_hex(8)}!"
    secreto = pyotp.random_base32()
    _sembrar_usuario(
        banco,
        correo=correo,
        contrasena=pw,
        rol="admin",
        secreto_totp=secreto,
    )
    desafio = cliente._http.post(
        "/v1/auth/login", json={"correo": correo, "contrasena": pw}
    ).json()["desafio_id"]
    r = cliente._http.post(
        "/v1/auth/totp",
        json={"desafio_id": desafio, "codigo": pyotp.TOTP(secreto).now()},
    )
    assert r.status_code == 200
    return r.json()["token_acceso"]


def test_k20_dashboard_oculta_detalle_de_archivos_sin_malware_y_no_filtra_por_nombre(
    banco,
) -> None:
    respuestas_vt = {
        EICAR_SHA256: (
            200,
            {"data": {"attributes": {"last_analysis_stats": {"malicious": 58}}}},
        )
    }
    with (
        clamd_falso() as (clam_host, clam_puerto),
        vt_falso(respuestas_vt) as (vt_url, _),
        banco.api(
            clamav_host=clam_host,
            clamav_puerto=clam_puerto,
            vt_base_url=vt_url,
            vt_api_key=secrets.token_hex(16),
        ) as cliente,
    ):
        id_limpio = cliente.subir(png(), b"nomina_secreta_2026.png", b"image/png")
        id_eicar = cliente.subir(EICAR, b"<script>alert(1)</script>.txt", b"text/plain")
        assert cliente.esperar(id_limpio)["estado"] == "limpio"
        assert cliente.esperar(id_eicar)["estado"] == "en_cuarentena"

        tok = _token_analista(cliente, banco)
        hdr = {"Authorization": f"Bearer {tok}"}

        # Detalle de archivo limpio: K20 prohíbe nombre_original, sha256, resultados y cuarentena.
        d_limpio = cliente._http.get(f"/v1/admin/files/{id_limpio}", headers=hdr)
        assert d_limpio.status_code == 200
        cuerpo_limpio = d_limpio.json()
        assert cuerpo_limpio["estado"] == "limpio"
        for prohibido in (
            "nombre_original",
            "sha256",
            "resultados",
            "cuarentena_expira_en",
        ):
            assert prohibido not in cuerpo_limpio, f"K20 violada: expuso {prohibido}"

        # Detalle de archivo en cuarentena: SÍ trae nombre, hash, caducidad y resultados.
        d_eicar = cliente._http.get(f"/v1/admin/files/{id_eicar}", headers=hdr)
        assert d_eicar.status_code == 200
        cuerpo_eicar = d_eicar.json()
        assert cuerpo_eicar["nombre_original"] == "<script>alert(1)</script>.txt"
        assert cuerpo_eicar["sha256"] == EICAR_SHA256
        assert cuerpo_eicar["cuarentena_expira_en"] is not None
        assert len(cuerpo_eicar["resultados"]) >= 2

        # Búsqueda q por nombre de archivo restringido NO debe encontrarlo (anti-oráculo K20).
        busqueda_secreta = cliente._http.get(
            "/v1/admin/files", params={"q": "nomina_secreta"}, headers=hdr
        ).json()
        assert busqueda_secreta["elementos"] == []

        # Búsqueda q por nombre de archivo en cuarentena SÍ lo encuentra.
        busqueda_eicar = cliente._http.get(
            "/v1/admin/files", params={"q": "script"}, headers=hdr
        ).json()
        assert [e["id"] for e in busqueda_eicar["elementos"]] == [id_eicar]


def test_f506_liberacion_de_cuarentena_audita_y_reencola_al_cdr(banco) -> None:
    imagen = png()
    sha = hashlib.sha256(imagen).hexdigest()
    respuestas_vt = {
        sha: (200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}})
    }
    with (
        clamd_falso() as (clam_host, clam_puerto),
        vt_falso(respuestas_vt) as (vt_url, _),
        banco.api(
            clamav_host=clam_host,
            clamav_puerto=clam_puerto,
            vt_base_url=vt_url,
            vt_api_key=secrets.token_hex(16),
        ) as cliente,
    ):
        archivo_id = cliente.subir(imagen, b"falso_positivo.png", b"image/png")
        assert cliente.esperar(archivo_id)["estado"] == "en_cuarentena"
        assert cliente.descargar(archivo_id).status_code == 409

        tok_ana = _token_analista(cliente, banco)
        tok_adm = _token_admin(cliente, banco)
        hdr_ana = {"Authorization": f"Bearer {tok_ana}"}
        hdr_adm = {"Authorization": f"Bearer {tok_adm}"}

        # Analista no puede liberar -> 403 (F5.05, K06)
        r_ana = cliente._http.post(
            f"/v1/admin/files/{archivo_id}/release",
            json={"motivo": "Falso positivo confirmado por el equipo de SecOps."},
            headers=hdr_ana,
        )
        assert r_ana.status_code == 403

        # Motivo demasiado corto (< 20 chars, K18) -> 400/422
        r_corto = cliente._http.post(
            f"/v1/admin/files/{archivo_id}/release",
            json={"motivo": "muy corto"},
            headers=hdr_adm,
        )
        assert r_corto.status_code in (400, 422)

        # Admin libera con motivo válido -> 202 y se reencola en el CDR
        motivo_valido = "Falso positivo verificado manualmente por SecOps #ticket-42"
        r_ok = cliente._http.post(
            f"/v1/admin/files/{archivo_id}/release",
            json={"motivo": motivo_valido},
            headers=hdr_adm,
        )
        assert r_ok.status_code == 202

        # Esperar a que el CDR reconstruya y lo pase a limpio
        limite = time.monotonic() + 10.0
        while time.monotonic() < limite:
            if banco.fila(archivo_id)["estado"] == "limpio":
                break
            time.sleep(0.05)
        assert banco.fila(archivo_id)["estado"] == "limpio"
        assert cliente.descargar(archivo_id).status_code == 200

        # Liberar de nuevo cuando ya está limpio -> 409
        r_dup = cliente._http.post(
            f"/v1/admin/files/{archivo_id}/release",
            json={"motivo": motivo_valido},
            headers=hdr_adm,
        )
        assert r_dup.status_code == 409

        # Aparece en /v1/admin/audit (INV-08) y analista recibe 403 en audit
        assert cliente._http.get("/v1/admin/audit", headers=hdr_ana).status_code == 403
        audit = cliente._http.get("/v1/admin/audit", headers=hdr_adm)
        assert audit.status_code == 200
        acciones = [
            (e["accion"], e["recurso"], e["motivo"]) for e in audit.json()["elementos"]
        ]
        assert ("liberar_archivo", archivo_id, motivo_valido) in acciones


def test_f201_y_f5_gestion_api_keys_metricas_y_aplicaciones(banco) -> None:
    with banco.api() as cliente:
        tok_ana = _token_analista(cliente, banco)
        tok_adm = _token_admin(cliente, banco)
        hdr_ana = {"Authorization": f"Bearer {tok_ana}"}
        hdr_adm = {"Authorization": f"Bearer {tok_adm}"}

        # Analista no puede gestionar API keys -> 403
        assert (
            cliente._http.get("/v1/admin/api-keys", headers=hdr_ana).status_code == 403
        )
        assert (
            cliente._http.post(
                "/v1/admin/api-keys",
                json={"aplicacion_nombre": "App Nueva"},
                headers=hdr_ana,
            ).status_code
            == 403
        )

        # Admin crea API key para aplicación nueva
        r_creada = cliente._http.post(
            "/v1/admin/api-keys",
            json={"aplicacion_nombre": "Portal Escolar"},
            headers=hdr_adm,
        )
        assert r_creada.status_code == 201
        creada = r_creada.json()
        assert creada["secreto"].startswith("gk_")
        assert creada["aplicacion_nombre"] == "Portal Escolar"

        # La key nueva funciona para subir
        r_sub = cliente._http.post(
            "/v1/files",
            headers={"Authorization": f"Bearer {creada['secreto']}"},
            files={"file": ("ok.png", png(), "image/png")},
        )
        assert r_sub.status_code == 202

        # Listado nunca expone el secreto
        r_lista = cliente._http.get("/v1/admin/api-keys", headers=hdr_adm)
        assert r_lista.status_code == 200
        assert all("secreto" not in k for k in r_lista.json())

        # Revocar -> 204 y la key deja de autenticar (401)
        r_rev = cliente._http.delete(
            f"/v1/admin/api-keys/{creada['id']}", headers=hdr_adm
        )
        assert r_rev.status_code == 204
        r_tras_rev = cliente._http.get(
            f"/v1/files/{r_sub.json()['id']}",
            headers={"Authorization": f"Bearer {creada['secreto']}"},
        )
        assert r_tras_rev.status_code == 401

        # Métricas y aplicaciones accesibles para analista
        r_met = cliente._http.get(
            "/v1/admin/metrics", params={"periodo": "7d"}, headers=hdr_ana
        )
        assert r_met.status_code == 200
        met = r_met.json()
        assert met["periodo"] == "7d"
        assert "totales" in met and "amenazas_por_dia" in met and "por_capa" in met

        r_apps = cliente._http.get("/v1/admin/applications", headers=hdr_ana)
        assert r_apps.status_code == 200
        assert any(a["nombre"] == "Portal Escolar" for a in r_apps.json())

        # Confirmar en BD que hay eventos de auditoría de crear y revocar api_key
        with banco.motor.connect() as con:
            acciones = set(
                con.execute(text("SELECT accion FROM evento_auditoria")).scalars()
            )
        assert {"crear_api_key", "revocar_api_key"} <= acciones
