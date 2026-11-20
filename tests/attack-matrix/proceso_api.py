"""La API real en su propio proceso, con uvicorn y uvloop, y sondas del hijo para K42 y K28.

Hace falta otro proceso para lo que TestClient no deja ver: matar a la API con SIGKILL
(``PR_SET_PDEATHSIG``) o leer su ``/proc/<pid>/environ`` desde el hijo (``PR_SET_DUMPABLE``).
La configuración, con la contraseña de la BD y el pepper, llega por el entorno del lanzador:
nunca por argumentos ni por disco.
"""

import dataclasses
import hashlib
import json
import os
import shutil
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
from hijos import MARCA, RAIZ_API
from soporte_matriz import INTERVALO_SONDEO_S, UUID_RE, multipart

from api.app.ajustes import Ajustes

# K59: la URL de Redis (con su contraseña) llega igual que las demás, por el entorno.
VARIABLE_REDIS = "GATEKEEPER_REDIS_URL"


def _con_redis(banco) -> bool:
    """La API ya pide Redis y el banco tiene uno."""
    campos = {campo.name for campo in dataclasses.fields(Ajustes)}
    return "url_redis" in campos and banco.url_redis is not None


_LANZADOR = """
import json, os, sys
sys.path.insert(0, {raiz!r})
from pathlib import Path
import uvicorn
from api.app.ajustes import Ajustes
from api.app.principal import crear_app
cfg = json.loads(os.environ.pop("GK_MATRIZ_CFG"))
redis = {{"url_redis": cfg["url_redis"]}} if "url_redis" in cfg else {{}}
if cfg.get("reloj_que_corre"):
    # Ver soporte_matriz.RelojQueCorre: el rate limit no se mezcla con lo que se prueba.
    import time
    class RelojQueCorre:
        ahora = time.time()
        def __call__(self):
            RelojQueCorre.ahora += 1.0
            return RelojQueCorre.ahora
    redis["reloj_limite"] = RelojQueCorre()
app = crear_app(Ajustes(
    url_bd=cfg["url"],
    pepper=cfg["pepper"].encode(),
    datos=Path(cfg["datos"]),
    comando_cdr=tuple(cfg["comando"]),
    timeout_cdr_s=cfg["timeout"],
    **redis,
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
    if _con_redis(banco):
        configuracion["url_redis"] = banco.url_redis
    if "reloj_limite" in {campo.name for campo in dataclasses.fields(Ajustes)}:
        configuracion["reloj_que_corre"] = True
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

# Bajo Landlock (K53) el hijo ya no escribe fuera de su directorio de trabajo: el registro va por el
# descriptor 2, abierto antes de que arranque el hijo, en una línea con la marca (ver hijos.py).
_SONDA_LIMITES = """
import ctypes, json, os, resource, runpy, sys
_registro = os.open({registro!r}, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.dup2(_registro, 2)
os.close(_registro)
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
    os.write(2, ({marca!r} + json.dumps(datos) + "\\n").encode())


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
    ruta.write_text(
        _SONDA_LIMITES.format(registro=str(registro), raiz=str(RAIZ_API), marca=MARCA)
    )
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


# ------------------------------------------------------------------ K52: secretos en los ancestros

NOMBRES_SECRETOS = (
    "GATEKEEPER_PEPPER",
    "GATEKEEPER_DATABASE_URL",
    "GATEKEEPER_DATABASE_URL_MIGRACION",
)

# El hijo no recibe los secretos: solo su largo y su SHA-256. Busca en el entorno de cada ancestro
# los nombres de las variables y cualquier trozo de ese largo con esa huella (el pepper puede ir
# dentro de otra variable, como el JSON del lanzador de la matriz).
_HIJO_LEE_ANCESTROS = """
import hashlib, json, os
HUELLAS = {huellas!r}
NOMBRES = {nombres!r}


def expone(contenido):
    hallado = set()
    for entrada in contenido.split(b"\\0"):
        nombre, _, valor = entrada.partition(b"=")
        if nombre.decode(errors="replace") in NOMBRES:
            hallado.add("nombre " + nombre.decode())
        for largo, huella in HUELLAS:
            for inicio in range(len(valor) - largo + 1):
                if hashlib.sha256(valor[inicio:inicio + largo]).hexdigest() == huella:
                    hallado.add("valor")
                    break
    return sorted(hallado)


cadena = []
pid = os.getppid()
for _ in range(64):
    if pid <= 1:
        break
    paso = {{"pid": pid}}
    try:
        with open(f"/proc/{{pid}}/comm") as comm:
            paso["comm"] = comm.read().strip()
        with open(f"/proc/{{pid}}/environ", "rb") as entorno:
            paso["expone"] = expone(entorno.read())
        paso["legible"] = True
    except OSError as error:
        paso["legible"] = False
        paso["errno"] = error.errno
    cadena.append(paso)
    try:
        with open(f"/proc/{{pid}}/stat") as stat:
            pid = int(stat.read().rpartition(")")[2].split()[1])
    except OSError:
        break
with open({registro!r}, "w") as salida:
    json.dump({{"ppid": os.getppid(), "cadena": cadena}}, salida)
print('{{"veredicto": "rechazado", "tipo": "text/plain", "motivo": "sonda"}}', flush=True)
"""


def huellas_de(*secretos: bytes) -> list[tuple[int, str]]:
    return [(len(s), hashlib.sha256(s).hexdigest()) for s in secretos]


def hijo_lee_ancestros(
    directorio: Path, huellas: list[tuple[int, str]]
) -> tuple[tuple[str, ...], Path]:
    """Hijo del mismo UID que busca los secretos de la API en el entorno de toda su cadena."""
    registro = directorio / "lectura_de_ancestros.json"
    ruta = directorio / "hijo_lee_ancestros.py"
    ruta.write_text(
        _HIJO_LEE_ANCESTROS.format(
            huellas=huellas, nombres=NOMBRES_SECRETOS, registro=str(registro)
        )
    )
    return (sys.executable, "-I", str(ruta)), registro


def ancestros_que_exponen(lectura: dict) -> list[str]:
    """Los ancestros cuyo entorno legible trae un secreto, sin mostrar ningún valor."""
    return [
        f"{paso['comm']} (pid {paso['pid']}): {', '.join(paso['expone'])}"
        for paso in lectura["cadena"]
        if paso.get("legible") and paso.get("expone")
    ]


# Lanzamiento como en producción: los secretos llegan en GATEKEEPER_*, no en un JSON de la matriz.
# Sin `comando_cdr`, es el comando del README: uvicorn directo con `--factory`. Con él, un lanzador
# lee los ajustes del entorno y solo cambia el hijo (``Ajustes.comando_cdr`` nunca sale del entorno).
_LANZADOR_POR_ENTORNO = """
import dataclasses, json, sys
sys.path.insert(0, {raiz!r})
import uvicorn
from api.app.ajustes import leer_ajustes
from api.app.principal import crear_app
ajustes = dataclasses.replace(leer_ajustes(), comando_cdr=tuple(json.loads(sys.argv[1])))
uvicorn.run(crear_app(ajustes), host="127.0.0.1", port=int(sys.argv[2]), log_level="warning",
            server_header=False, loop="uvloop")
"""

# Intermediarios entre quien lanza y la API. Los "sin exec" se quedan vivos con el entorno entero.
INTERMEDIARIOS = {
    "directo": lambda comando: list(comando),
    "sh_con_exec": lambda comando: ["/bin/sh", "-c", 'exec "$@"', "sh", *comando],
    "sh_sin_exec": lambda comando: ["/bin/sh", "-c", '"$@"; exit $?', "sh", *comando],
    "uv_run": lambda comando: ["uv", "run", "--no-sync", "--", *comando],
}


@dataclass
class Lanzamiento:
    arranco: bool
    codigo: int | None
    registro: Path = field(repr=False)
    api: ApiProceso | None = field(default=None, repr=False)

    def log(self) -> bytes:
        return self.registro.read_bytes()


def _matar_grupo(proceso: subprocess.Popen) -> None:
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(proceso.pid, signal.SIGTERM)
    try:
        proceso.wait(timeout=15)
    except subprocess.TimeoutExpired:
        pass
    # El grupo entero: con un intermediario, la API es nieta de quien la lanzó.
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(proceso.pid, signal.SIGKILL)
    with suppress(subprocess.TimeoutExpired):
        proceso.wait(timeout=5)


@contextmanager
def api_por_entorno(
    banco,
    directorio: Path,
    intermediario: str,
    comando_cdr: tuple[str, ...] | None = None,
    tope_s: float = 30,
) -> Iterator[Lanzamiento]:
    """Lanza la API con sus secretos en el entorno, a través de ``intermediario``.

    Espera a que responda ``/health`` o a que el proceso termine. No falla si no arranca: lo que
    se espera lo dice la prueba. Al salir mata el grupo de procesos entero.
    """
    if intermediario == "uv_run" and shutil.which("uv") is None:
        pytest.skip("uv no está en el PATH")
    puerto = _puerto_libre()
    if comando_cdr is None:
        uvicorn = Path(sys.executable).parent / "uvicorn"
        comando = [
            str(uvicorn), "--factory", "api.app.principal:crear_app",
            "--host", "127.0.0.1", "--port", str(puerto),
            "--no-server-header", "--log-level", "warning",
        ]  # fmt: skip
    else:
        lanzador = directorio / "lanzador_por_entorno.py"
        lanzador.write_text(_LANZADOR_POR_ENTORNO.format(raiz=str(RAIZ_API)))
        comando = [sys.executable, str(lanzador), json.dumps(comando_cdr), str(puerto)]
    entorno = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": os.environ.get("HOME", "/"),
        "GATEKEEPER_DATABASE_URL": banco.url.render_as_string(hide_password=False),
        "GATEKEEPER_PEPPER": banco.pepper.decode(),
        "GATEKEEPER_DATOS": str(banco.datos),
    }
    if banco.url_redis is not None:
        entorno[VARIABLE_REDIS] = banco.url_redis
    registro = directorio / f"api_{intermediario}.log"
    with registro.open("wb") as salida:
        proceso = subprocess.Popen(
            INTERMEDIARIOS[intermediario](comando),
            cwd=RAIZ_API,
            env=entorno,
            stdin=subprocess.DEVNULL,
            stdout=salida,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    base = f"http://127.0.0.1:{puerto}"
    try:
        arranco = False
        limite = time.monotonic() + tope_s
        while time.monotonic() < limite:
            if proceso.poll() is not None:
                break
            with suppress(httpx.HTTPError):
                if httpx.get(f"{base}/health", timeout=1).status_code == 200:
                    arranco = True
                    break
            time.sleep(INTERVALO_SONDEO_S)
        else:
            pytest.fail(f"la API ni respondió /health ni terminó en {tope_s} s")
        yield Lanzamiento(
            arranco=arranco,
            codigo=proceso.poll(),
            registro=registro,
            api=ApiProceso(proceso, base, banco.app_a.key) if arranco else None,
        )
    finally:
        _matar_grupo(proceso)
