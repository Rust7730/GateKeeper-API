"""F5.01–F5.05 / K06 / K21 / K66 — Autenticación Argon2+TOTP, refresh rotativo, CSRF, RBAC y bitácora.

Cubre los vectores de F5 (parte de autenticación y autorización):
- ``vecx:refresh_reutilizado``: reutilizar un refresh token ya rotado revoca toda su familia.
- ``vecx:analista_endpoint_admin``: un analista recibe ``403`` en endpoints de admin; admin hereda analista.
- TOTP obligatorio para admin: paso 1 devuelve desafío sin sesión; el desafío es de un solo uso.
- CSRF double-submit (``gk_csrf`` + ``X-CSRF-Token``) en ``/v1/auth/refresh`` y ``/v1/auth/logout``.
- ``evento_auditoria`` de solo inserción: ``UPDATE``, ``DELETE`` y ``TRUNCATE`` fallan en PostgreSQL.
"""

import secrets

import pyotp
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError


def _sembrar_usuario(
    banco, *, correo: str, contrasena: str, rol: str, secreto_totp: str | None = None
) -> str:
    from api.app.auth_usuarios import cifrar_totp, hashear_contrasena

    hash_pw = hashear_contrasena(contrasena)
    totp_cifrado = (
        cifrar_totp(banco.pepper, secreto_totp) if secreto_totp is not None else None
    )
    with banco.motor.begin() as con:
        uid = con.execute(
            text(
                "INSERT INTO usuario (email, hash_password, rol, totp_secreto_cifrado, activo)"
                " VALUES (:email, :hash_pw, :rol, :totp, true) RETURNING id"
            ),
            {
                "email": correo,
                "hash_pw": hash_pw,
                "rol": rol,
                "totp": totp_cifrado,
            },
        ).scalar_one()
    return str(uid)


def test_f5_evento_auditoria_es_de_solo_insercion(banco) -> None:
    """Los triggers de PostgreSQL impiden UPDATE, DELETE y TRUNCATE en evento_auditoria."""
    with banco.motor.begin() as con:
        ev_id = con.execute(
            text(
                "INSERT INTO evento_auditoria (accion, motivo, ip)"
                " VALUES ('inicio_sesion', 'prueba', '192.0.2.10'::inet) RETURNING id"
            )
        ).scalar_one()

    with pytest.raises(DBAPIError), banco.motor.begin() as con:
        con.execute(
            text("UPDATE evento_auditoria SET motivo = 'alterado' WHERE id = :id"),
            {"id": ev_id},
        )

    with pytest.raises(DBAPIError), banco.motor.begin() as con:
        con.execute(text("DELETE FROM evento_auditoria WHERE id = :id"), {"id": ev_id})

    with pytest.raises(DBAPIError), banco.motor.begin() as con:
        con.execute(text("TRUNCATE TABLE evento_auditoria"))


def test_f501_admin_con_totp_no_obtiene_sesion_sin_segundo_factor(banco) -> None:
    secreto = pyotp.random_base32()
    contrasena = f"Admin-{secrets.token_hex(8)}!"
    _sembrar_usuario(
        banco,
        correo="admin@gatekeeper.test",
        contrasena=contrasena,
        rol="admin",
        secreto_totp=secreto,
    )

    with banco.api() as cliente:
        paso1 = cliente._http.post(
            "/v1/auth/login",
            json={"correo": "admin@gatekeeper.test", "contrasena": contrasena},
        )
        assert paso1.status_code == 200
        cuerpo1 = paso1.json()
        assert cuerpo1["mfa_requerido"] is True
        assert "token_acceso" not in cuerpo1
        assert "gk_refresh" not in paso1.cookies

        # Código incorrecto -> 401
        malo = cliente._http.post(
            "/v1/auth/totp",
            json={"desafio_id": cuerpo1["desafio_id"], "codigo": "000000"},
        )
        assert malo.status_code == 401

        # Código válido -> 200 con JWT y cookies HttpOnly + CSRF
        codigo = pyotp.TOTP(secreto).now()
        paso2 = cliente._http.post(
            "/v1/auth/totp",
            json={"desafio_id": cuerpo1["desafio_id"], "codigo": codigo},
        )
        assert paso2.status_code == 200
        cuerpo2 = paso2.json()
        assert cuerpo2["token_acceso"]
        assert cuerpo2["usuario"]["rol"] == "admin"
        assert cuerpo2["usuario"]["mfa_activo"] is True
        assert "gk_refresh" in paso2.cookies
        assert "gk_csrf" in paso2.cookies

        # Reutilizar el mismo desafío -> 401
        reuso = cliente._http.post(
            "/v1/auth/totp",
            json={"desafio_id": cuerpo1["desafio_id"], "codigo": codigo},
        )
        assert reuso.status_code == 401


def test_vecx_refresh_reutilizado_revoca_toda_la_familia_y_exige_csrf(banco) -> None:
    """vecx:refresh_reutilizado (F5.03, F5.04, K21): reuso de token rotado revoca la familia."""
    contrasena = f"Analista-{secrets.token_hex(8)}!"
    _sembrar_usuario(
        banco, correo="analista@gatekeeper.test", contrasena=contrasena, rol="analista"
    )

    with banco.api() as cliente:
        r_login = cliente._http.post(
            "/v1/auth/login",
            json={"correo": "analista@gatekeeper.test", "contrasena": contrasena},
        )
        assert r_login.status_code == 200
        refresh_1 = r_login.cookies["gk_refresh"]
        csrf_1 = r_login.cookies["gk_csrf"]

        # F5.04: sin X-CSRF-Token -> 403
        sin_csrf = cliente._http.post(
            "/v1/auth/refresh",
            cookies={"gk_refresh": refresh_1, "gk_csrf": csrf_1},
        )
        assert sin_csrf.status_code == 403

        # Refresh legítimo: rota refresh_1 -> refresh_2
        r_rot = cliente._http.post(
            "/v1/auth/refresh",
            cookies={"gk_refresh": refresh_1, "gk_csrf": csrf_1},
            headers={"X-CSRF-Token": csrf_1},
        )
        assert r_rot.status_code == 200
        refresh_2 = r_rot.cookies["gk_refresh"]
        csrf_2 = r_rot.cookies["gk_csrf"]
        assert refresh_2 != refresh_1

        # Atacante reutiliza refresh_1 ya rotado -> 401 y revoca toda la familia
        r_robo = cliente._http.post(
            "/v1/auth/refresh",
            cookies={"gk_refresh": refresh_1, "gk_csrf": csrf_1},
            headers={"X-CSRF-Token": csrf_1},
        )
        assert r_robo.status_code == 401

        # refresh_2 (de la misma familia) también quedó revocado -> 401
        r_victima = cliente._http.post(
            "/v1/auth/refresh",
            cookies={"gk_refresh": refresh_2, "gk_csrf": csrf_2},
            headers={"X-CSRF-Token": csrf_2},
        )
        assert r_victima.status_code == 401


def test_vecx_analista_endpoint_admin_responde_403(banco) -> None:
    """vecx:analista_endpoint_admin (F5.05, K06): analista -> 403 en ruta de admin; admin -> 200."""
    pw_analista = f"Ana-{secrets.token_hex(8)}!"
    pw_admin = f"Adm-{secrets.token_hex(8)}!"
    secreto = pyotp.random_base32()
    _sembrar_usuario(
        banco, correo="ana@gatekeeper.test", contrasena=pw_analista, rol="analista"
    )
    _sembrar_usuario(
        banco,
        correo="adm@gatekeeper.test",
        contrasena=pw_admin,
        rol="admin",
        secreto_totp=secreto,
    )

    with banco.api() as cliente:
        tok_ana = cliente._http.post(
            "/v1/auth/login",
            json={"correo": "ana@gatekeeper.test", "contrasena": pw_analista},
        ).json()["token_acceso"]

        # Analista puede consultar su propia sesión (/v1/auth/me) pero NO una ruta de admin.
        assert (
            cliente._http.get(
                "/v1/auth/me", headers={"Authorization": f"Bearer {tok_ana}"}
            ).status_code
            == 200
        )
        assert (
            cliente._http.get(
                "/v1/auth/admin-check", headers={"Authorization": f"Bearer {tok_ana}"}
            ).status_code
            == 403
        )

        # Admin (con TOTP) accede tanto a /v1/auth/me (K06: admin ⊇ analista) como a admin-check.
        desafio = cliente._http.post(
            "/v1/auth/login",
            json={"correo": "adm@gatekeeper.test", "contrasena": pw_admin},
        ).json()["desafio_id"]
        tok_adm = cliente._http.post(
            "/v1/auth/totp",
            json={"desafio_id": desafio, "codigo": pyotp.TOTP(secreto).now()},
        ).json()["token_acceso"]

        assert (
            cliente._http.get(
                "/v1/auth/me", headers={"Authorization": f"Bearer {tok_adm}"}
            ).status_code
            == 200
        )
        assert (
            cliente._http.get(
                "/v1/auth/admin-check", headers={"Authorization": f"Bearer {tok_adm}"}
            ).status_code
            == 200
        )
