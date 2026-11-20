"""K59 — Los contadores del rate limit viven en Redis: falla cerrado, sin secretos y con TTL.

- Redis caído (propuesta K60, pendiente de confirmar): una subida autenticada no pasa sin límite;
  responde `503 {"detail": "Service Unavailable"}` sin leer el cuerpo, sin temporal ni fila.
  `/health` no depende de Redis y sigue en 200 (INV-09: un error nunca deja pasar).
- Claves: ni la API key, ni su secreto, ni su prefijo, ni su hash aparecen en una clave o en su
  valor; solo el ``aplicacion_id`` o la IP. Todas tienen TTL, y las keys inventadas no crean claves
  nuevas: un atacante no hace crecer Redis sin límite (CWE-770).
- ``GATEKEEPER_REDIS_URL`` es obligatoria, lleva la contraseña y se trata como secreto: no sale en el
  ``repr`` de ``Ajustes`` (CWE-532) y, con K52, un ancestro que la tenga en su entorno impide arrancar.
"""

import dataclasses
import hashlib
import secrets
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

import httpx
import pytest
from generadores import png
from hijos import RAIZ_API
from proceso_api import _matar_grupo, _puerto_libre
from soporte_limite import drenar, hijo_rapido, subir
from soporte_matriz import INTERVALO_SONDEO_S, multipart, nombres
from soporte_redis import cliente_de, detener, redis_desechable, url_de, volcar_claves

from api.app.ajustes import Ajustes, ConfiguracionError, leer_ajustes
from api.app.autenticacion import calcular_hash

VARIABLE_REDIS = "GATEKEEPER_REDIS_URL"
SERVICE_UNAVAILABLE = b'{"detail":"Service Unavailable"}'


# ------------------------------------------------------------------------------- Redis caído


def test_k59_con_redis_caido_la_subida_autenticada_falla_cerrado_y_health_responde(
    banco, tmp_path
):
    with (
        redis_desechable() as propio,
        banco.api(
            reloj_real=True, comando_cdr=hijo_rapido(tmp_path), url_redis=url_de(propio)
        ) as cliente,
    ):
        # Control: con Redis arriba, la subida pasa.
        assert cliente.post_archivo(png()).status_code == 202
        drenar(banco, banco.app_a)

        detener(propio)

        antes_disco, antes_filas = (
            nombres(banco.uploads_tmp),
            banco.contar_archivos(),
        )
        cuerpo, content_type = multipart(png())
        respuesta = cliente.asgi(
            "POST",
            "/v1/files",
            {**cliente.cabeceras(), "content-type": content_type},
            [cuerpo],
        )
        assert respuesta.estado == 503, (
            f"con Redis caído la subida respondió {respuesta.estado}: debe fallar cerrado"
        )
        assert respuesta.cuerpo == SERVICE_UNAVAILABLE
        assert respuesta.leidos == 0, "se leyó el cuerpo sin poder aplicar el límite"
        assert nombres(banco.uploads_tmp) <= antes_disco, "quedó un temporal"
        assert banco.contar_archivos() == antes_filas, "quedó una fila"

        salud = cliente._http.get("/health")
        assert salud.status_code == 200, "/health no debe depender de Redis"


# ------------------------------------------------------------------------------------ claves


def _huellas_de(banco, key: str) -> list[bytes]:
    prefijo, _, secreto = key.partition(".")
    return [
        key.encode(),
        secreto.encode(),
        prefijo.encode(),
        calcular_hash(banco.pepper, key).encode(),
        hashlib.sha256(key.encode()).hexdigest().encode(),
        hashlib.sha256(key.encode()).digest(),
    ]


def test_k59_las_claves_no_llevan_la_key_ni_su_hash_y_todas_tienen_ttl(
    banco, tmp_path, contenedor_redis
):
    inexistente = f"gk_{secrets.token_hex(6)}.{secrets.token_urlsafe(32)}"
    with banco.api(reloj_real=True, comando_cdr=hijo_rapido(tmp_path)) as cliente:
        for _ in range(3):
            assert subir(cliente, banco, banco.app_a).status_code == 202
        assert cliente.post_archivo(png(), key=banco.app_b.key).status_code == 202
        assert cliente.post_archivo(png(), key=inexistente).status_code == 401
        drenar(banco, banco.app_a)
        drenar(banco, banco.app_b)

    redis = cliente_de(contenedor_redis)
    try:
        claves = volcar_claves(redis)
    finally:
        redis.close()
    assert claves, "el rate limit no dejó ningún contador en Redis"
    huellas = [
        *_huellas_de(banco, banco.app_a.key),
        *_huellas_de(banco, banco.app_b.key),
        *_huellas_de(banco, inexistente),
    ]
    for clave, (contenido, pttl) in claves.items():
        for huella in huellas:
            assert huella not in clave, (
                "una clave de Redis contiene la API key o su hash"
            )
            assert huella not in contenido, (
                "un valor de Redis contiene la API key o su hash"
            )
        assert pttl > 0, f"la clave {clave!r} no tiene TTL (PTTL={pttl})"


def test_k59_las_keys_inventadas_no_crean_claves_nuevas(banco, contenedor_redis):
    """Una IP que prueba 40 keys distintas usa los mismos contadores que si probara una."""
    redis = cliente_de(contenedor_redis)
    try:
        with banco.api(reloj_real=True) as cliente:
            primera = f"gk_{secrets.token_hex(6)}.{secrets.token_urlsafe(32)}"
            assert cliente.post_archivo(png(), key=primera).status_code == 401
            con_una = redis.dbsize()
            assert con_una >= 1, "el límite por IP no dejó ningún contador en Redis"
            for _ in range(40):
                otra = f"gk_{secrets.token_hex(6)}.{secrets.token_urlsafe(32)}"
                cliente.post_archivo(png(), key=otra)
            # +1 de margen: con el reloj real, la ventana por IP puede cambiar de minuto en medio.
            assert redis.dbsize() <= con_una + 1, (
                f"las keys inventadas crearon claves: {con_una} -> {redis.dbsize()}"
            )
    finally:
        redis.close()


# ----------------------------------------------------------------------------- configuración


def test_k59_ajustes_exige_la_url_de_redis_y_no_la_muestra(banco):
    campos = {campo.name: campo for campo in dataclasses.fields(Ajustes)}
    assert "url_redis" in campos, "control ausente: Ajustes no tiene url_redis (K59)"
    assert campos["url_redis"].repr is False, "url_redis saldría en el repr (CWE-532)"
    ajustes = banco.ajustes()
    contrasena = banco.url_redis.split("@")[0].rpartition(":")[2]
    assert contrasena not in repr(ajustes)
    assert contrasena not in str(ajustes)


def test_k59_sin_gatekeeper_redis_url_no_arranca(banco, monkeypatch):
    monkeypatch.setenv(
        "GATEKEEPER_DATABASE_URL", banco.url.render_as_string(hide_password=False)
    )
    monkeypatch.setenv("GATEKEEPER_PEPPER", banco.pepper.decode())
    monkeypatch.setenv("GATEKEEPER_DATOS", str(banco.datos))
    monkeypatch.delenv(VARIABLE_REDIS, raising=False)
    with pytest.raises(ConfiguracionError) as error:
        leer_ajustes()
    assert VARIABLE_REDIS in str(error.value)


# ------------------------------------------------------------------------------- K52 + Redis

# El intermediario recibe por stdin los secretos que no deben quedar en su entorno, los exporta y
# lanza la API sin `exec`: en su /proc/<pid>/environ queda solo lo que recibió al arrancar.
_INTERMEDIARIO = (
    "IFS= read -r a; IFS= read -r b; IFS= read -r c; IFS= read -r d; "
    'export GATEKEEPER_DATABASE_URL="$a" GATEKEEPER_PEPPER="$b" GATEKEEPER_DATOS="$c"; '
    'if [ -n "$d" ]; then export GATEKEEPER_REDIS_URL="$d"; fi; '
    '"$@"; exit $?'
)


def _lanzar_con_redis_en_el_ancestro(banco, directorio: Path, en_el_ancestro: bool):
    puerto = _puerto_libre()
    uvicorn = Path(sys.executable).parent / "uvicorn"
    comando = [
        str(uvicorn), "--factory", "api.app.principal:crear_app",
        "--host", "127.0.0.1", "--port", str(puerto),
        "--no-server-header", "--log-level", "warning",
    ]  # fmt: skip
    entorno = {"PATH": "/usr/bin:/bin", "HOME": "/"}
    if en_el_ancestro:
        entorno[VARIABLE_REDIS] = banco.url_redis
    lineas = [
        banco.url.render_as_string(hide_password=False),
        banco.pepper.decode(),
        str(banco.datos),
        "" if en_el_ancestro else banco.url_redis,
    ]
    registro = directorio / "api.log"
    with registro.open("wb") as salida:
        proceso = subprocess.Popen(
            ["/bin/sh", "-c", _INTERMEDIARIO, "sh", *comando],
            cwd=RAIZ_API,
            env=entorno,
            stdin=subprocess.PIPE,
            stdout=salida,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    assert proceso.stdin is not None
    proceso.stdin.write(("\n".join(lineas) + "\n").encode())
    proceso.stdin.close()
    base = f"http://127.0.0.1:{puerto}"
    try:
        limite = time.monotonic() + 30
        while time.monotonic() < limite:
            if proceso.poll() is not None:
                return False, registro.read_bytes()
            with suppress(httpx.HTTPError):
                if httpx.get(f"{base}/health", timeout=1).status_code == 200:
                    return True, registro.read_bytes()
            time.sleep(INTERVALO_SONDEO_S)
        pytest.fail("la API ni respondió /health ni terminó en 30 s")
    finally:
        _matar_grupo(proceso)


def test_k59_k52_un_ancestro_con_la_url_de_redis_impide_arrancar(banco, tmp_path):
    arranco, registro = _lanzar_con_redis_en_el_ancestro(banco, tmp_path, True)
    assert not arranco, (
        "la API arrancó aunque un ancestro expone GATEKEEPER_REDIS_URL en /proc (K52)"
    )
    assert banco.url_redis.encode() not in registro, "el error muestra la URL de Redis"


def test_k59_k52_control_sin_la_url_en_el_ancestro_arranca(banco, tmp_path):
    arranco, _ = _lanzar_con_redis_en_el_ancestro(banco, tmp_path, False)
    assert arranco, "la API no arrancó aunque ningún ancestro expone secretos"
