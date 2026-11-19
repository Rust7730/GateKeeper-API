"""Procesos hijo para las pruebas: sustitutos del CDR y una sonda alrededor del hijo real.

Los sustitutos se pasan por la costura ``Ajustes.comando_cdr`` (ver soporte_matriz.py) y solo usan la
biblioteca estándar: arrancan en milisegundos. La sonda corre el ``api.app.cdr_hijo`` real sin
cambiarlo y anota lo que el hijo no puede decir de sí mismo por stdout: su entorno, sus límites y lo
que importó. Ningún sustituto puede comprobar `RLIMIT_AS`, porque lo fija el propio hijo.
"""

import json
import sys
from pathlib import Path

import api

# Donde está el `api` que se está probando, no donde está este archivo.
RAIZ_API = Path(api.__file__).resolve().parents[1]

RESPUESTA_LIMPIO = '{"veredicto": "limpio", "tipo": "image/png", "motivo": "ok"}'
RESPUESTA_RECHAZADO = (
    '{"veredicto": "rechazado", "tipo": "image/png", "motivo": "tipo"}'
)
COPIAR_SALIDA = "import shutil, sys\nshutil.copyfile(sys.argv[1], sys.argv[2])\n"


def hijo_falso(directorio: Path, cuerpo: str) -> tuple[str, ...]:
    """Comando de un hijo con este cuerpo de Python."""
    ruta = directorio / "hijo_falso.py"
    ruta.write_text(cuerpo)
    return (sys.executable, "-I", str(ruta))


def hijo_con_puerta(
    directorio: Path, respuesta: str = RESPUESTA_LIMPIO
) -> tuple[tuple[str, ...], Path, Path]:
    """Hijo que espera a que exista ``puerta``: fija un análisis en curso sin carreras.

    Devuelve ``(comando, puerta, registro)``. Cada hijo crea en ``registro`` un archivo con su pid.
    Se rinde a los 20 s para no quedar suelto si la prueba falla.
    """
    puerta = directorio / "puerta"
    registro = directorio / "iniciados"
    registro.mkdir()
    cuerpo = f"""
import os, pathlib, shutil, sys, time
puerta = pathlib.Path({str(puerta)!r})
pathlib.Path({str(registro)!r}, str(os.getpid())).touch()
limite = time.monotonic() + 20
while not puerta.exists() and time.monotonic() < limite:
    time.sleep(0.01)
shutil.copyfile(sys.argv[1], sys.argv[2])
print({respuesta!r})
"""
    return hijo_falso(directorio, cuerpo), puerta, registro


# Con K53 el hijo termina bajo Landlock: ya no puede abrir rutas en `/proc` ni escribir fuera de su
# directorio de trabajo. La sonda abre lo que necesita antes de que arranque el hijo y lo deja en
# los descriptores que el hijo conserva (stdio): el registro en el 2 (el padre lo manda a
# /dev/null) y `/proc/self/status` en el 0 (el hijo no lee stdin). Landlock no limita un descriptor
# ya abierto. El registro va en una línea con `MARCA`: el hijo puede escribir otras en stderr.
MARCA = "GKSONDA "

_SONDA = """
import json, os, resource, runpy, stat, sys

_registro = os.open({registro!r}, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.dup2(_registro, 2)
os.close(_registro)
_estado = os.open("/proc/self/status", os.O_RDONLY)
os.dup2(_estado, 0)
os.close(_estado)
sys.path.insert(0, {raiz!r})
datos = {{"limites_al_importar": {{}}}}


class Vigia:
    def find_spec(self, nombre, ruta=None, objetivo=None):
        base = nombre.partition(".")[0]
        if base in ("PIL", "pikepdf"):
            datos["limites_al_importar"].setdefault(
                base,
                {{
                    "as": resource.getrlimit(resource.RLIMIT_AS),
                    "core": resource.getrlimit(resource.RLIMIT_CORE),
                }},
            )
        return None


sys.meta_path.insert(0, Vigia())
sys.argv = ["api.app.cdr_hijo", *sys.argv[1:]]


def pico_rss_kib():
    # VmHWM es el pico de este proceso desde su exec. ru_maxrss no sirve: al hacer exec, Linux
    # le copia el pico del proceso que lo lanzó (exec_mmap), y con TestClient ese es pytest.
    # Se relee desde el principio por el descriptor 0, abierto antes de Landlock.
    os.lseek(0, 0, os.SEEK_SET)
    contenido = b""
    while trozo := os.read(0, 65536):
        contenido += trozo
    for linea in contenido.decode().splitlines():
        if linea.startswith("VmHWM:"):
            return int(linea.split()[1])
    raise RuntimeError("sin VmHWM en /proc/self/status")


def _tipo(modo):
    for prueba, nombre in ((stat.S_ISSOCK, "socket"), (stat.S_ISFIFO, "pipe"),
                           (stat.S_ISREG, "archivo"), (stat.S_ISDIR, "directorio"),
                           (stat.S_ISCHR, "caracter")):
        if prueba(modo):
            return nombre
    return "otro"


def descriptores_abiertos():
    # Con /proc a la vista, el destino de cada descriptor. Bajo Landlock, `fstat` sobre cada
    # número posible: no abre ninguna ruta y da el mismo `socket:[inodo]` que `readlink`.
    descriptores = {{}}
    try:
        numeros = os.listdir("/proc/self/fd")
    except PermissionError:
        for numero in range(resource.getrlimit(resource.RLIMIT_NOFILE)[0]):
            try:
                info = os.fstat(numero)
            except OSError:
                continue
            descriptores[str(numero)] = f"{{_tipo(info.st_mode)}}:[{{info.st_ino}}]"
        return descriptores
    for numero in numeros:
        try:
            descriptores[numero] = os.readlink(f"/proc/self/fd/{{numero}}")
        except OSError:
            pass
    return descriptores


def volcar():
    descriptores = descriptores_abiertos()
    datos.update(
        entorno=dict(os.environ),
        argv=sys.argv[1:],
        modulos=sorted(sys.modules),
        limite_as_final=resource.getrlimit(resource.RLIMIT_AS),
        limite_core_final=resource.getrlimit(resource.RLIMIT_CORE),
        descriptores=descriptores,
        rss_max_kib=pico_rss_kib(),
    )
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


def sonda_hijo_real(directorio: Path) -> tuple[tuple[str, ...], Path]:
    """Comando que corre el hijo real bajo la sonda, y dónde deja lo que vio."""
    registro = directorio / "sonda.json"
    ruta = directorio / "sonda.py"
    ruta.write_text(
        _SONDA.format(registro=str(registro), raiz=str(RAIZ_API), marca=MARCA)
    )
    return (sys.executable, str(ruta)), registro


def leer_registro_marcado(registro: Path) -> dict:
    """La última línea con ``MARCA`` del registro; el resto es lo que el hijo escribió en stderr."""
    assert registro.exists(), (
        "la sonda no dejó registro: el hijo real no llegó a correr"
    )
    lineas = [
        linea[len(MARCA) :]
        for linea in registro.read_text(errors="replace").splitlines()
        if linea.startswith(MARCA)
    ]
    assert lineas, "la sonda no llegó a volcar lo que vio"
    return json.loads(lineas[-1])


def leer_sonda(registro: Path) -> dict:
    return leer_registro_marcado(registro)
