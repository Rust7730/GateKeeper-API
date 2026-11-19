"""Sondas de K53 (Landlock en el hijo del CDR), alrededor del ``api.app.cdr_hijo`` real.

**Sonda de accesos.** Corre el hijo real sin cambiarlo y hace lo que haría un parser
comprometido justo cuando el hijo abre su archivo de entrada, que es el momento en que K53 exige
Landlock puesto ("antes de leer el archivo no confiable"). El disparo es un audit hook sobre el
evento ``open`` de esa ruta: no depende de cómo ni dónde se aplique Landlock. Si el hijo nunca
abre la entrada por su ruta, la sonda lo anota y la prueba lo dice.

El resultado sale por el descriptor 2, que la sonda redirige a su registro antes de arrancar el
hijo: el hijo conserva stdio al cerrar descriptores, y Landlock no limita un descriptor ya abierto.
Así la sonda no necesita escribir en ninguna ruta una vez restringida. Cada intento se anota como
``permitido`` o con el nombre del errno; nada de lo leído se guarda.

**Hijo sin Landlock.** Un envoltorio instala un filtro seccomp que hace fallar las llamadas de
Landlock (444 a 446 en x86_64) y hace ``exec`` del hijo real con los mismos argumentos. El filtro
pasa el ``exec``: es un kernel sin Landlock, o uno que no deja aplicarlo, simulado sin tocar el
código del hijo.
"""

import json
import platform
import sys
from pathlib import Path

from hijos import RAIZ_API

MARCA = "GKSONDA "
DENEGADO = {"EACCES", "EPERM"}

_SONDA_ACCESOS = """
import ctypes, errno, json, mmap, os, runpy, socket, struct, sys
CFG = json.loads({cfg!r})
_registro = os.open(CFG["registro"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.dup2(_registro, 2)
os.close(_registro)
sys.path.insert(0, CFG["raiz"])
ENTRADA = os.path.abspath(sys.argv[1])
estado = {{"disparada": False, "dentro": False}}


def _anotar(datos):
    os.write(2, (CFG["marca"] + json.dumps(datos) + "\\n").encode())


def _intento(funcion):
    try:
        funcion()
    except OSError as error:
        return errno.errorcode.get(error.errno, str(error.errno))
    return "permitido"


def _leer(ruta):
    def f():
        with open(ruta, "rb") as archivo:
            archivo.read(1)
    return f


def _escribir(ruta):
    # Abrir para escribir basta para que Landlock decida; no se escribe ni se trunca nada.
    return lambda: os.close(os.open(ruta, os.O_WRONLY))


def _crear(ruta):
    def f():
        os.close(os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        os.unlink(ruta)
    return f


def _crear_directorio(ruta):
    def f():
        os.mkdir(ruta)
        os.rmdir(ruta)
    return f


def _conectar(destino):
    def f():
        with socket.create_connection(tuple(destino), timeout=2):
            pass
    return f


def _crear_socket(*argumentos):
    def f():
        socket.socket(*argumentos).close()
    return f


def _socket_por_io_uring(familia, tipo):
    # IORING_OP_SOCKET (Linux >= 5.19) crea un socket sin pasar por la llamada socket(): un
    # filtro seccomp que solo mire socket() y socketpair() no lo ve. Anillo de una entrada.
    def f():
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        parametros = ctypes.create_string_buffer(120)  # struct io_uring_params
        anillo_fd = libc.syscall(425, 1, parametros)  # io_uring_setup
        if anillo_fd < 0:
            numero = ctypes.get_errno()
            raise OSError(numero, os.strerror(numero))
        try:
            entradas_sq, entradas_cq, _, _, _, rasgos = struct.unpack_from("6I", parametros, 0)
            sq = struct.unpack_from("7I", parametros, 40)  # head tail mask entries flags dropped array
            cq = struct.unpack_from("6I", parametros, 80)  # head tail mask entries overflow cqes
            permisos = mmap.PROT_READ | mmap.PROT_WRITE
            tam = max(sq[6] + entradas_sq * 4, cq[5] + entradas_cq * 16)
            anillo = mmap.mmap(anillo_fd, tam, mmap.MAP_SHARED, permisos, offset=0)
            anillo_cq = anillo
            if not rasgos & 1:  # sin IORING_FEAT_SINGLE_MMAP
                anillo_cq = mmap.mmap(anillo_fd, tam, mmap.MAP_SHARED, permisos, offset=0x8000000)
            sqes = mmap.mmap(anillo_fd, entradas_sq * 64, mmap.MAP_SHARED, permisos, offset=0x10000000)
            sqe = bytearray(64)
            struct.pack_into("BBHiQQIIQ", sqe, 0, 45, 0, 0, familia, tipo, 0, 0, 0, 7)
            sqes[0:64] = bytes(sqe)
            cola = struct.unpack_from("I", anillo, sq[1])[0]
            struct.pack_into("I", anillo, sq[6] + (cola & sq[2]) * 4, 0)
            struct.pack_into("I", anillo, sq[1], cola + 1)
            if libc.syscall(426, anillo_fd, 1, 1, 1, None, 0) < 0:  # io_uring_enter
                numero = ctypes.get_errno()
                raise OSError(numero, os.strerror(numero))
            cabeza = struct.unpack_from("I", anillo_cq, cq[0])[0]
            _, resultado, _ = struct.unpack_from("QiI", anillo_cq, cq[5] + (cabeza & cq[2]) * 16)
            if resultado < 0:
                raise OSError(-resultado, os.strerror(-resultado))
            os.close(resultado)
        finally:
            os.close(anillo_fd)
    return f


def _par_de_sockets():
    for extremo in socket.socketpair():
        extremo.close()


def _conectar_unix(ruta):
    # Una ruta que empieza por NUL es del espacio abstracto: no pasa por el sistema de archivos.
    def f():
        with socket.socket(socket.AF_UNIX) as cliente:
            cliente.settimeout(2)
            cliente.connect(ruta)
    return f


def _ancestros():
    cadena, pid = {{}}, os.getppid()
    for _ in range(64):
        if pid <= 1:
            break
        cadena[str(pid)] = _intento(_leer(f"/proc/{{pid}}/environ"))
        try:
            with open(f"/proc/{{pid}}/stat") as stat:
                pid = int(stat.read().rpartition(")")[2].split()[1])
        except OSError:
            break
    return cadena


def sondear():
    r = {{"disparada": True}}
    lectura = {{
        "uploads_tmp de otro archivo": _leer(CFG["uploads_otro"]),
        "clean_store de otro archivo": _leer(CFG["clean_otro"]),
        ".parcial de un hermano": _leer(CFG["parcial_hermano"]),
        "listar uploads_tmp": lambda: os.listdir(CFG["uploads_tmp"]),
        "listar clean_store": lambda: os.listdir(CFG["clean_store"]),
        "listar el directorio personal": lambda: os.listdir(CFG["home"]),
        "environ de un proceso ajeno": _leer(f"/proc/{{CFG['ajeno']}}/environ"),
    }}
    if CFG["home_archivo"]:
        lectura["archivo del directorio personal"] = _leer(CFG["home_archivo"])
    r["lectura"] = {{nombre: _intento(f) for nombre, f in lectura.items()}}
    r["environ_ancestros"] = _ancestros()
    escritura = {{
        "abrir para escribir clean_store de otro": _escribir(CFG["clean_otro"]),
        "abrir para escribir el .parcial de un hermano": _escribir(CFG["parcial_hermano"]),
        "abrir para escribir uploads_tmp de otro": _escribir(CFG["uploads_otro"]),
        "borrar en clean_store": lambda: os.unlink(CFG["clean_borrable"]),
        "crear en clean_store": _crear(CFG["nuevo_clean"]),
        "crear en uploads_tmp": _crear(CFG["nuevo_uploads"]),
        "crear fuera del directorio de datos": _crear(CFG["nuevo_fuera"]),
        "crear un directorio en clean_store": _crear_directorio(CFG["nuevo_clean"] + ".d"),
    }}
    r["escritura"] = {{nombre: _intento(f) for nombre, f in escritura.items()}}
    r["red"] = {{
        f"TCP {{h}}:{{p}}": _intento(_conectar((h, p))) for h, p in CFG["tcp"]
    }}
    r["sockets"] = {{
        nombre: _intento(_crear_socket(*argumentos))
        for nombre, argumentos in (
            ("AF_INET TCP", (socket.AF_INET, socket.SOCK_STREAM)),
            ("AF_INET UDP", (socket.AF_INET, socket.SOCK_DGRAM)),
            ("AF_INET6 TCP", (socket.AF_INET6, socket.SOCK_STREAM)),
            ("AF_INET6 UDP", (socket.AF_INET6, socket.SOCK_DGRAM)),
            ("AF_UNIX flujo", (socket.AF_UNIX, socket.SOCK_STREAM)),
            ("AF_UNIX datagrama", (socket.AF_UNIX, socket.SOCK_DGRAM)),
            ("AF_NETLINK", (socket.AF_NETLINK, socket.SOCK_RAW, 0)),
        )
    }}
    r["sockets"]["socketpair AF_UNIX"] = _intento(_par_de_sockets)
    r["sockets"]["io_uring AF_INET UDP"] = _intento(
        _socket_por_io_uring(socket.AF_INET, socket.SOCK_DGRAM)
    )
    r["sockets"]["io_uring AF_UNIX"] = _intento(
        _socket_por_io_uring(socket.AF_UNIX, socket.SOCK_STREAM)
    )
    r["unix"] = {{
        f"Unix {{ruta!r}}": _intento(_conectar_unix(ruta)) for ruta in CFG.get("unix", [])
    }}
    return r


def gancho(evento, argumentos):
    if evento != "open" or estado["disparada"] or estado["dentro"]:
        return
    ruta = argumentos[0]
    if not isinstance(ruta, (str, bytes)):
        return
    if os.path.abspath(os.fsdecode(ruta)) != ENTRADA:
        return
    estado["disparada"] = estado["dentro"] = True
    try:
        _anotar(sondear())
    except BaseException as error:  # la sonda nunca debe romper al hijo
        _anotar({{"disparada": True, "fallo_de_la_sonda": type(error).__name__}})
    finally:
        estado["dentro"] = False


sys.addaudithook(gancho)
sys.argv = ["api.app.cdr_hijo", *sys.argv[1:]]
try:
    runpy.run_module("api.app.cdr_hijo", run_name="__main__", alter_sys=True)
finally:
    if not estado["disparada"]:
        _anotar({{"disparada": False}})
"""


def sonda_accesos(directorio: Path, objetivos: dict) -> tuple[tuple[str, ...], Path]:
    """El hijo real bajo la sonda. ``objetivos`` trae las rutas, el pid ajeno y los destinos TCP."""
    registro = directorio / "sonda_accesos.log"
    cfg = {
        **objetivos,
        "registro": str(registro),
        "raiz": str(RAIZ_API),
        "marca": MARCA,
    }
    ruta = directorio / "sonda_accesos.py"
    ruta.write_text(_SONDA_ACCESOS.format(cfg=json.dumps(cfg)))
    return (sys.executable, str(ruta)), registro


def leer_sonda(registro: Path) -> dict:
    """La línea de la sonda dentro del registro; el hijo puede haber escrito otras en stderr."""
    lineas = [
        linea[len(MARCA) :]
        for linea in registro.read_text(errors="replace").splitlines()
        if linea.startswith(MARCA)
    ]
    assert lineas, "la sonda no dejó resultado: el hijo no llegó a arrancar"
    return json.loads(lineas[0])


# ---------------------------------------------------------------------------- hijo sin Landlock

ES_X86_64 = platform.machine() == "x86_64"

# Envoltorio: instala un filtro seccomp con ``REGLAS`` y hace ``exec`` del hijo real. Cada regla es
# ``(número de llamada, primer argumento o None, errno)``; cada una es un bloque que recarga el
# número, así que no hay saltos entre bloques. El filtro sobrevive al ``exec`` y se apila con el
# que instale el hijo (K54): seccomp aplica el resultado más restrictivo de todos.
_SIN_LANDLOCK = """
import ctypes, errno, os, sys
REGLAS = {reglas!r}


class Instruccion(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class Programa(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Instruccion))]


CARGAR, SI_IGUAL, VOLVER = 0x20, 0x15, 0x06
PERMITIR, CON_ERRNO = 0x7FFF0000, 0x00050000
AUDIT_ARCH_X86_64 = 0xC000003E
NUMERO, ARQUITECTURA, ARGUMENTO_0 = 0, 4, 16  # seccomp_data; args[0], 32 bits bajos
programa = [
    Instruccion(CARGAR, 0, 0, ARQUITECTURA),
    Instruccion(SI_IGUAL, 1, 0, AUDIT_ARCH_X86_64),
    Instruccion(VOLVER, 0, 0, PERMITIR),
]
for numero, argumento, nombre in REGLAS:
    devolver = Instruccion(VOLVER, 0, 0, CON_ERRNO | getattr(errno, nombre))
    if argumento is None:
        programa += [Instruccion(CARGAR, 0, 0, NUMERO), Instruccion(SI_IGUAL, 0, 1, numero), devolver]
    else:
        programa += [
            Instruccion(CARGAR, 0, 0, NUMERO),
            Instruccion(SI_IGUAL, 0, 3, numero),
            Instruccion(CARGAR, 0, 0, ARGUMENTO_0),
            Instruccion(SI_IGUAL, 0, 1, argumento),
            devolver,
        ]
programa.append(Instruccion(VOLVER, 0, 0, PERMITIR))
filtro = (Instruccion * len(programa))(*programa)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
    sys.exit(90)
if libc.prctl(22, 2, ctypes.byref(Programa(len(programa), filtro)), 0, 0) != 0:  # SECCOMP
    sys.exit(91)
os.execv(sys.executable, [sys.executable, "-m", "api.app.cdr_hijo", *sys.argv[1:]])
"""

# landlock_create_ruleset, landlock_add_rule, landlock_restrict_self
SIN_LANDLOCK = {
    "no_disponible": [
        (444, None, "ENOSYS"),
        (445, None, "ENOSYS"),
        (446, None, "ENOSYS"),
    ],
    "no_se_puede_aplicar": [(446, None, "EPERM")],
}
# K54: un kernel sin filtros seccomp responde EINVAL a `seccomp()` (317) y a
# `prctl(PR_SET_SECCOMP)` (157 con primer argumento 22). Se niegan las dos vías: el hijo puede usar
# cualquiera. Este envoltorio instala su propio filtro antes de negarlas, con el `prctl` del final.
SIN_SECCOMP = {
    "no_disponible": [(317, None, "EINVAL"), (157, 22, "EINVAL")],
}


def _envoltorio(directorio: Path, nombre: str, reglas: list) -> tuple[str, ...]:
    ruta = directorio / f"hijo_{nombre}.py"
    ruta.write_text(_SIN_LANDLOCK.format(reglas=reglas))
    return (sys.executable, str(ruta))


def hijo_sin_landlock(directorio: Path, caso: str) -> tuple[str, ...]:
    return _envoltorio(directorio, f"sin_landlock_{caso}", SIN_LANDLOCK[caso])


def hijo_sin_seccomp(directorio: Path, caso: str) -> tuple[str, ...]:
    return _envoltorio(directorio, f"sin_seccomp_{caso}", SIN_SECCOMP[caso])


def abi_landlock() -> int:
    """Versión de la ABI de Landlock del kernel, o 0 si no hay Landlock."""
    import ctypes

    if not ES_X86_64:
        return 0
    libc = ctypes.CDLL(None, use_errno=True)
    version = libc.syscall(444, None, 0, 1)  # LANDLOCK_CREATE_RULESET_VERSION
    return max(version, 0)
