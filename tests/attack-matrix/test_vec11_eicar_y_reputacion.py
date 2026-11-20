"""vec:11 y vecx:reputacion_solo_get — Antimalware en dos capas (F4, D1, D2, D3, INV-05, INV-07).

Comprueba:
1. **vec:11 (EICAR):** aunque EICAR es texto plano (fuera de lista blanca), ClamAV lo escanea
   sobre el ORIGINAL en paralelo con firma+CDR (D1) y VirusTotal consulta su SHA-256; la
   prioridad ``en_cuarentena > rechazado > error > limpio`` (F4.07) deja el archivo
   ``en_cuarentena`` con detección en ambas capas, original movido a ``quarantine/``, sin
   salida en ``clean_store/`` y descarga bloqueada con ``409`` (INV-06, INV-07).
2. **vecx:reputacion_solo_get (INV-05):** ``reputation/`` solo hace ``GET /api/v3/files/{sha256}``
   sin cuerpo y nunca lee archivos ni importa ``api.db``.
3. **Fail-closed y presupuesto VT (INV-09, D3, K07):** un fallo de ClamAV termina en ``error``
   (nunca ``limpio``); un VirusTotal sin cuota o lento (> 1 s) deja la capa ``no_evaluada`` y
   no bloquea un archivo limpio; un PNG válido detectado por VT pasa a ``en_cuarentena``.
"""

import ast
import hashlib
import json
import secrets
import socket
import struct
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import yaml
from generadores import png
from soporte_matriz import nombres

RAIZ = Path(__file__).resolve().parents[2]
COMPOSE = RAIZ / "deploy" / "docker-compose.yml"
DIR_REPUTATION = RAIZ / "reputation"

# Cadena estándar de prueba EICAR construida por partes para no disparar antivirus locales en disco.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = hashlib.sha256(EICAR).hexdigest()


# --------------------------------------------------------------- Servidores locales de prueba


@contextmanager
def clamd_falso(
    *, firma_si_eicar: str = "Win.Test.EICAR_HDB-1"
) -> Iterator[tuple[str, int]]:
    """Servidor TCP real del protocolo ``zINSTREAM\\0`` de clamd."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    srv.settimeout(0.2)
    puerto = srv.getsockname()[1]
    parar = threading.Event()

    def _atender(conn: socket.socket) -> None:
        with conn:
            conn.settimeout(5.0)
            cab = b""
            while b"\0" not in cab and len(cab) < 32:
                trozo = conn.recv(32)
                if not trozo:
                    return
                cab += trozo
            if not cab.startswith(b"zINSTREAM\0"):
                conn.sendall(b"UNKNOWN COMMAND\0")
                return
            resto = cab.split(b"\0", 1)[1]
            datos = bytearray()

            def _leer_exacto(n: int) -> bytes:
                nonlocal resto
                while len(resto) < n:
                    trozo = conn.recv(65536)
                    if not trozo:
                        return b""
                    resto += trozo
                salida, resto = resto[:n], resto[n:]
                return salida

            while True:
                largo_b = _leer_exacto(4)
                if len(largo_b) < 4:
                    return
                (largo,) = struct.unpack("!I", largo_b)
                if largo == 0:
                    break
                datos += _leer_exacto(largo)
            if EICAR in datos:
                conn.sendall(f"stream: {firma_si_eicar} FOUND\0".encode())
            else:
                conn.sendall(b"stream: OK\0")

    def _bucle() -> None:
        while not parar.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=_atender, args=(conn,), daemon=True).start()

    hilo = threading.Thread(target=_bucle, daemon=True)
    hilo.start()
    try:
        yield "127.0.0.1", puerto
    finally:
        parar.set()
        srv.close()
        hilo.join(timeout=3.0)


@contextmanager
def vt_falso(
    respuestas: dict[str, tuple[int, dict]], *, retardo_s: float = 0.0
) -> Iterator[tuple[str, list[tuple[str, str, bytes]]]]:
    """Servidor HTTP real que imita ``GET /api/v3/files/{sha256}`` y registra cada petición."""
    peticiones: list[tuple[str, str, bytes]] = []

    class Manejador(BaseHTTPRequestHandler):
        def _manejar(self) -> None:
            largo = int(self.headers.get("Content-Length", "0"))
            cuerpo = self.rfile.read(largo) if largo > 0 else b""
            peticiones.append((self.command, self.path, cuerpo))
            if retardo_s > 0:
                time.sleep(retardo_s)
            sha = self.path.rsplit("/", 1)[-1]
            codigo, payload = respuestas.get(
                sha, (404, {"error": {"code": "NotFoundError"}})
            )
            datos = json.dumps(payload).encode("utf-8")
            self.send_response(codigo)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(datos)))
            self.end_headers()
            self.wfile.write(datos)

        do_GET = _manejar
        do_POST = _manejar
        do_PUT = _manejar

        def log_message(self, format: str, *args: object) -> None:
            return None

    servidor = HTTPServer(("127.0.0.1", 0), Manejador)
    puerto = servidor.server_address[1]
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    try:
        yield f"http://127.0.0.1:{puerto}/api/v3", peticiones
    finally:
        servidor.shutdown()
        servidor.server_close()
        hilo.join(timeout=3.0)


# ------------------------------------------------------------ vecx:reputacion_solo_get (INV-05)


def test_vecx_reputacion_no_importa_bd_ni_accede_a_archivos() -> None:
    """INV-05: el servicio ``reputation/`` solo consulta hashes y nunca toca BD ni archivos."""
    assert DIR_REPUTATION.is_dir(), "falta el paquete reputation/"
    archivos = sorted(DIR_REPUTATION.rglob("*.py"))
    assert archivos, "reputation/ no contiene módulos Python"
    prohibidos = ("api.db", "sqlalchemy", "psycopg", "PIL", "pikepdf", "magic")
    for ruta in archivos:
        if "tests" in ruta.parts:
            continue
        arbol = ast.parse(ruta.read_text(encoding="utf-8"), filename=str(ruta))
        for nodo in ast.walk(arbol):
            if isinstance(nodo, ast.Import):
                nombres_imp = [a.name for a in nodo.names]
            elif isinstance(nodo, ast.ImportFrom) and nodo.module:
                nombres_imp = [nodo.module]
            else:
                continue
            for nombre in nombres_imp:
                assert not any(
                    nombre == p or nombre.startswith(f"{p}.") for p in prohibidos
                ), f"{ruta.relative_to(RAIZ)} importa {nombre!r} (viola INV-05)"


def test_f4_compose_define_clamav_freshclam_y_reputation_aislados() -> None:
    """D2 / F1.02 / K65: clamav sin internet en isolated, freshclam y reputation en egress."""
    datos = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    servicios = datos["services"]
    redes = datos["networks"]

    assert "egress" in redes
    assert "clamav" in servicios
    assert "freshclam" in servicios
    assert "reputation" in servicios
    assert servicios["clamav"]["networks"] == ["isolated"]
    assert servicios["freshclam"]["networks"] == ["egress"]
    assert set(servicios["reputation"]["networks"]) == {"backend", "egress"}
    assert any(
        "clamav_db" in v and v.endswith(":ro") for v in servicios["clamav"]["volumes"]
    )
    assert any(
        "clamav_db" in v and not v.endswith(":ro")
        for v in servicios["freshclam"]["volumes"]
    )
    assert servicios["reputation"].get("volumes") in (None, [])


# ------------------------------------------------------------------ vec:11 EICAR en dos capas


def test_vec11_eicar_en_cuarentena_detectado_por_clamav_y_virustotal(banco) -> None:
    """vec:11 / D1 / F4.07 / INV-05 / INV-07: EICAR termina en_cuarentena en ambas capas."""
    respuestas_vt = {
        EICAR_SHA256: (
            200,
            {"data": {"attributes": {"last_analysis_stats": {"malicious": 58}}}},
        )
    }
    with (
        clamd_falso() as (clam_host, clam_puerto),
        vt_falso(respuestas_vt) as (vt_url, peticiones),
        banco.api(
            clamav_host=clam_host,
            clamav_puerto=clam_puerto,
            vt_base_url=vt_url,
            vt_api_key=secrets.token_hex(16),
        ) as cliente,
    ):
        archivo_id = cliente.subir(EICAR, b"eicar.txt", b"text/plain")
        estado = cliente.esperar(archivo_id)
        assert estado["estado"] == "en_cuarentena"
        assert cliente.descargar(archivo_id).status_code == 409

    capas = dict(banco.resultados(archivo_id))
    assert capas["clamav"] == "malicioso"
    assert capas["virustotal"] == "malicioso"
    assert archivo_id in nombres(banco.datos / "quarantine")
    assert archivo_id not in nombres(banco.uploads_tmp)
    assert archivo_id not in nombres(banco.clean_store)

    # vecx:reputacion_solo_get: solo GET por hash y cero cuerpo enviado.
    assert peticiones, "reputation no consultó VirusTotal"
    for metodo, ruta, cuerpo in peticiones:
        assert metodo == "GET"
        assert ruta == f"/api/v3/files/{EICAR_SHA256}"
        assert cuerpo == b""


def test_vec11_vt_detecta_png_malicioso_y_lo_manda_a_cuarentena(banco) -> None:
    """F4.07 / INV-01: un PNG válido que pasa CDR pero detecta VT termina en_cuarentena sin salida."""
    imagen = png()
    sha = hashlib.sha256(imagen).hexdigest()
    respuestas_vt = {
        sha: (200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 2}}}})
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
        archivo_id = cliente.subir(imagen, b"foto.png", b"image/png")
        estado = cliente.esperar(archivo_id)
        assert estado["estado"] == "en_cuarentena"
        assert cliente.descargar(archivo_id).status_code == 409

    assert archivo_id in nombres(banco.datos / "quarantine")
    assert archivo_id not in nombres(banco.clean_store)


def test_f4_clamav_caido_falla_cerrado_a_error(banco) -> None:
    """INV-09: si clamd está configurado y no responde, nunca termina en limpio."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        puerto_cerrado = s.getsockname()[1]

    with banco.api(clamav_host="127.0.0.1", clamav_puerto=puerto_cerrado) as cliente:
        archivo_id = cliente.subir(png(), b"foto.png", b"image/png")
        estado = cliente.esperar(archivo_id)
        assert estado["estado"] == "error"
        assert cliente.descargar(archivo_id).status_code == 409
    assert archivo_id not in nombres(banco.clean_store)


def test_f4_vt_lento_queda_no_evaluada_y_no_bloquea_un_archivo_limpio(banco) -> None:
    """D3 / K07: si VT tarda más de 1 s tras el worker, queda no_evaluada y pasa a limpio."""
    with (
        clamd_falso() as (clam_host, clam_puerto),
        vt_falso({}, retardo_s=3.0) as (vt_url, _),
        banco.api(
            clamav_host=clam_host,
            clamav_puerto=clam_puerto,
            vt_base_url=vt_url,
            vt_api_key=secrets.token_hex(16),
        ) as cliente,
    ):
        inicio = time.monotonic()
        archivo_id = cliente.subir(png(), b"foto.png", b"image/png")
        estado = cliente.esperar(archivo_id)
        duracion = time.monotonic() - inicio
        assert estado["estado"] == "limpio"
        assert duracion < 2.8, (
            f"VT lento bloqueó el veredicto {duracion:.2f} s (viola K07)"
        )

    capas = dict(banco.resultados(archivo_id))
    assert capas["clamav"] == "limpio"
    assert capas["virustotal"] == "no_evaluada"
