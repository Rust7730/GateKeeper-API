"""La API real en su propio proceso, con uvicorn y uvloop, y sondas del hijo para K42 y K28.

Hace falta otro proceso para lo que TestClient no deja ver: matar a la API con SIGKILL
(``PR_SET_PDEATHSIG``) o leer su ``/proc/<pid>/environ`` desde el hijo (``PR_SET_DUMPABLE``).
La configuración, con la contraseña de la BD y el pepper, llega por el entorno del lanzador:
nunca por argumentos ni por disco.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
from hijos import RAIZ_API
from soporte_matriz import INTERVALO_SONDEO_S, UUID_RE, multipart

_LANZADOR = """
import json, os, sys
sys.path.insert(0, {raiz!r})
from pathlib import Path
import uvicorn
from api.app.ajustes import Ajustes
from api.app.principal import crear_app
cfg = json.loads(os.environ.pop("GK_MATRIZ_CFG"))
app = crear_app(Ajustes(
    url_bd=cfg["url"],
    pepper=cfg["pepper"].encode(),
    datos=Path(cfg["datos"]),
    comando_cdr=tuple(cfg["comando"]),
    timeout_cdr_s=cfg["timeout"],
))
uvicorn.run(app, host="127.0.0.1", port=cfg["puerto"], log_level="warning",
            server_header=False, loop="uvloop")
"""


def _puerto_libre() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@dataclass
class ApiProceso:
    proceso: subprocess.Popen = field(repr=False)
    base: str
    key: str = field(repr=False)

    @property
    def pid(self) -> int:
        return self.proceso.pid

    def subir(self, contenido: bytes) -> str:
        cuerpo, content_type = multipart(contenido, b"a.bin")
        respuesta = httpx.post(
            f"{self.base}/v1/files",
            content=cuerpo,
            headers={
                "Authorization": f"Bearer {self.key}",
                "Content-Type": content_type,
            },
            timeout=20,
        )
        assert respuesta.status_code == 202, f"respondió {respuesta.status_code}"
        archivo_id = respuesta.json()["id"]
        assert UUID_RE.fullmatch(archivo_id)
        return archivo_id

    def estado(self, archivo_id: str) -> str:
        respuesta = httpx.get(
            f"{self.base}/v1/files/{archivo_id}",
            headers={"Authorization": f"Bearer {self.key}"},
            timeout=10,
        )
        assert respuesta.status_code == 200
        return respuesta.json()["estado"]


@contextmanager
def api_en_proceso(
    banco, directorio: Path, comando: tuple[str, ...], timeout_cdr_s: float = 30
) -> Iterator[ApiProceso]:
    puerto = _puerto_libre()
    lanzador = directorio / "lanzador_api.py"
    lanzador.write_text(_LANZADOR.format(raiz=str(RAIZ_API)))
    configuracion = {
        "url": banco.url.render_as_string(hide_password=False),
        "pepper": banco.pepper.decode(),
        "datos": str(banco.datos),
        "comando": list(comando),
        "timeout": timeout_cdr_s,
        "puerto": puerto,
    }
    registro = (directorio / "api.log").open("wb")
    proceso = subprocess.Popen(
        [sys.executable, str(lanzador)],
        env={
            "PATH": os.environ.get("PATH", os.defpath),
            "GK_MATRIZ_CFG": json.dumps(configuracion),
        },
        stdin=subprocess.DEVNULL,
        stdout=registro,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{puerto}"
    try:
        limite = time.monotonic() + 30
        while True:
            if proceso.poll() is not None:
                pytest.fail(f"la API terminó al arrancar (código {proceso.returncode})")
            with suppress(httpx.HTTPError):
                if httpx.get(f"{base}/health", timeout=1).status_code == 200:
                    break
            if time.monotonic() > limite:
                pytest.fail("la API no respondió /health en 30 s")
            time.sleep(INTERVALO_SONDEO_S)
        yield ApiProceso(proceso, base, banco.app_a.key)
    finally:
        if proceso.poll() is None:
            proceso.send_signal(signal.SIGTERM)
            try:
                proceso.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proceso.kill()
                proceso.wait()
        registro.close()


def proceso_vivo(pid: int) -> bool:
    """Vivo y no zombi. Un huérfano zombi ya murió: solo espera a que alguien lo recoja."""
    try:
        estado = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return False
    return estado not in ("Z", "X")


def matar(pid: int) -> None:
    with suppress(ProcessLookupError, PermissionError):
        os.kill(pid, signal.SIGKILL)


# --------------------------------------------------------------------------------------- sondas

_SONDA_LIMITES = """
import ctypes, json, os, resource, runpy, sys
REGISTRO = {registro!r}
sys.path.insert(0, {raiz!r})
datos = {{"cpu_al_importar": {{}}}}


class Vigia:
    def find_spec(self, nombre, ruta=None, objetivo=None):
        base = nombre.partition(".")[0]
        if base in ("PIL", "pikepdf"):
            datos["cpu_al_importar"].setdefault(base, resource.getrlimit(resource.RLIMIT_CPU))
        return None


sys.meta_path.insert(0, Vigia())
sys.argv = ["api.app.cdr_hijo", *sys.argv[1:]]


def volcar():
    senal = ctypes.c_int(0)
    ctypes.CDLL(None).prctl(2, ctypes.byref(senal), 0, 0, 0)  # PR_GET_PDEATHSIG
    datos.update(cpu_final=resource.getrlimit(resource.RLIMIT_CPU), pdeathsig=senal.value)
    with open(REGISTRO, "w") as salida:
        json.dump(datos, salida)


salir = os._exit


def salir_volcando(codigo):
    volcar()
    salir(codigo)


os._exit = salir_volcando
try:
    runpy.run_module("api.app.cdr_hijo", run_name="__main__", alter_sys=True)
finally:
    volcar()
"""


def sonda_limites(directorio: Path) -> tuple[tuple[str, ...], Path]:
    """El hijo real bajo una sonda que anota ``RLIMIT_CPU`` y ``PR_GET_PDEATHSIG``."""
    registro = directorio / "sonda_limites.json"
    ruta = directorio / "sonda_limites.py"
    ruta.write_text(_SONDA_LIMITES.format(registro=str(registro), raiz=str(RAIZ_API)))
    return (sys.executable, str(ruta)), registro


_HIJO_QUE_ESPERA = """
import os, sys, time
sys.path.insert(0, {raiz!r})
from api.app import cdr_hijo


def esperar(entrada, salida):
    with open({registro!r}, "w") as marca:
        marca.write(str(os.getpid()))
    limite = time.monotonic() + 40
    while time.monotonic() < limite:
        time.sleep(0.05)
    return {{"veredicto": "rechazado", "tipo": "text/plain", "motivo": "sonda"}}


# `main` hace todo lo suyo (descriptores, límites) y luego llama aquí en vez de analizar.
cdr_hijo.analizar = esperar
sys.exit(cdr_hijo.main(sys.argv[1:]))
"""


def hijo_que_espera(directorio: Path) -> tuple[tuple[str, ...], Path]:
    """El ``main`` real del hijo, con un análisis que se queda 40 s esperando."""
    registro = directorio / "pid_hijo"
    ruta = directorio / "hijo_que_espera.py"
    ruta.write_text(_HIJO_QUE_ESPERA.format(raiz=str(RAIZ_API), registro=str(registro)))
    return (sys.executable, str(ruta)), registro


_HIJO_LEE_EL_PADRE = """
import json, os
resultado = {{"ppid": os.getppid()}}
try:
    with open(f"/proc/{{os.getppid()}}/environ", "rb") as entorno:
        contenido = entorno.read()
    resultado["legible"] = True
    resultado["bytes"] = len(contenido)
except OSError as error:
    resultado["legible"] = False
    resultado["errno"] = error.errno
with open({registro!r}, "w") as salida:
    json.dump(resultado, salida)
print('{{"veredicto": "rechazado", "tipo": "text/plain", "motivo": "sonda"}}', flush=True)
"""


def hijo_lee_el_padre(directorio: Path) -> tuple[tuple[str, ...], Path]:
    """Un hijo del mismo UID que intenta leer el entorno de la API, como haría uno comprometido."""
    registro = directorio / "lectura_del_padre.json"
    ruta = directorio / "hijo_lee_el_padre.py"
    ruta.write_text(_HIJO_LEE_EL_PADRE.format(registro=str(registro)))
    return (sys.executable, "-I", str(ruta)), registro
