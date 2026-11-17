"""K53: Landlock en el proceso hijo, probado en un proceso aparte (no se puede deshacer)."""

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from api.app import aislamiento

RAIZ = Path(__file__).resolve().parents[2]

_PROBAR = """
import errno, json, os, socket, subprocess, sys
sys.path.insert(0, {raiz!r})
from api.app.aislamiento import abi, aplicar
cfg = json.loads(sys.argv[1])


def intento(funcion):
    try:
        funcion()
    except OSError as error:
        return errno.errorcode.get(error.errno, str(error.errno))
    return "permitido"


def leer(ruta):
    return lambda: open(ruta, "rb").close()


def crear(ruta):
    def f():
        with open(ruta, "xb") as archivo:
            archivo.write(b"x")
    return f


# Creado antes de aislarse: seccomp (K54) ya no deja crear otro, y aquí se prueba Landlock.
previo_tcp = socket.socket()


def conectar():
    previo_tcp.settimeout(2)
    previo_tcp.connect(("127.0.0.1", cfg["puerto"]))


aplicar(
    lectura=[cfg["leible_dir"], cfg["leible_suelto"], "/dev/urandom"],
    entrada=cfg["entrada"],
    trabajo=cfg["trabajo"],
)
print(json.dumps({{
    "abi": abi(),
    "leer_entrada": intento(leer(cfg["entrada"])),
    "leer_en_dir_leible": intento(leer(cfg["en_leible"])),
    "leer_ajeno": intento(leer(cfg["ajeno"])),
    "leer_suelto": intento(leer(cfg["leible_suelto"])),
    "urandom": intento(lambda: open("/dev/urandom", "rb").read(1)),
    "escribir_suelto": intento(lambda: os.close(os.open(cfg["leible_suelto"], os.O_WRONLY))),
    "listar_padre": intento(lambda: os.listdir(cfg["padre"])),
    "crear_en_trabajo": intento(crear(os.path.join(cfg["trabajo"], "salida"))),
    "borrar_en_trabajo": intento(lambda: os.unlink(os.path.join(cfg["trabajo"], "salida"))),
    "crear_fuera": intento(crear(cfg["fuera"])),
    "escribir_ajeno": intento(lambda: os.close(os.open(cfg["ajeno"], os.O_WRONLY))),
    "dir_en_trabajo": intento(lambda: os.mkdir(os.path.join(cfg["trabajo"], "d"))),
    "enlace_en_trabajo": intento(
        lambda: os.symlink(cfg["ajeno"], os.path.join(cfg["trabajo"], "e"))
    ),
    "ejecutar": intento(lambda: subprocess.run(["/bin/true"], check=False)),
    "tcp": intento(conectar),
}}))
"""


@pytest.fixture
def resultado(tmp_path: Path) -> dict[str, str]:
    leible = tmp_path / "leible"
    leible.mkdir()
    (leible / "a").write_bytes(b"a")
    trabajo = tmp_path / "x.parcial"
    trabajo.mkdir()
    entrada = tmp_path / "entrada"
    entrada.write_bytes(b"e")
    ajeno = tmp_path / "ajeno"
    ajeno.write_bytes(b"secreto")
    suelto = tmp_path / "suelto"
    suelto.write_bytes(b"s")
    with socket.socket() as servidor:
        servidor.bind(("127.0.0.1", 0))
        servidor.listen(1)
        cfg = {
            "leible_dir": str(leible),
            "en_leible": str(leible / "a"),
            "leible_suelto": str(suelto),
            "entrada": str(entrada),
            "trabajo": str(trabajo),
            "ajeno": str(ajeno),
            "padre": str(tmp_path),
            "fuera": str(tmp_path / "nuevo"),
            "puerto": servidor.getsockname()[1],
        }
        codigo = _PROBAR.format(raiz=str(RAIZ))
        salida = subprocess.run(
            [sys.executable, "-c", codigo, json.dumps(cfg)],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    return json.loads(salida.stdout)


def test_k53_lee_solo_lo_permitido(resultado: dict[str, str]) -> None:
    assert resultado["leer_entrada"] == "permitido"
    assert resultado["leer_en_dir_leible"] == "permitido"
    assert resultado["leer_ajeno"] == "EACCES"
    assert resultado["listar_padre"] == "EACCES"


def test_k53_un_archivo_suelto_de_la_lista_se_lee_y_no_se_escribe(
    resultado: dict[str, str],
) -> None:
    """qpdf necesita /dev/urandom para el AES de un PDF cifrado."""
    assert resultado["leer_suelto"] == "permitido"
    assert resultado["urandom"] == "permitido"
    assert resultado["escribir_suelto"] == "EACCES"


def test_k53_escribe_solo_archivos_en_su_directorio_de_trabajo(
    resultado: dict[str, str],
) -> None:
    assert resultado["crear_en_trabajo"] == "permitido"
    assert resultado["borrar_en_trabajo"] == "permitido"
    assert resultado["crear_fuera"] == "EACCES"
    assert resultado["escribir_ajeno"] == "EACCES"
    assert resultado["dir_en_trabajo"] == "EACCES"
    assert resultado["enlace_en_trabajo"] == "EACCES"


def test_k53_no_ejecuta_nada(resultado: dict[str, str]) -> None:
    assert resultado["ejecutar"] == "EACCES"


def test_k53_sin_tcp_si_la_abi_lo_permite(resultado: dict[str, str]) -> None:
    if int(resultado["abi"]) < 4:
        pytest.skip("la ABI de Landlock de este kernel no restringe TCP")
    assert resultado["tcp"] == "EACCES"


def test_k53_este_kernel_tiene_landlock() -> None:
    """El README lo exige: sin Landlock, todo archivo termina en `error`."""
    assert aislamiento.abi() >= 1


def test_k53_un_directorio_de_trabajo_que_no_es_parcial_se_rechaza(
    tmp_path: Path,
) -> None:
    """Dar escritura sobre `clean_store` entero sería dársela sobre lo ya publicado."""
    entrada = tmp_path / "entrada"
    entrada.write_bytes(b"e")
    with pytest.raises(aislamiento.AislamientoFallido):
        aislamiento.comprobar_trabajo(tmp_path)


@pytest.mark.parametrize("falta", ["entrada", "trabajo"])
def test_k53_sin_entrada_o_sin_trabajo_falla(tmp_path: Path, falta: str) -> None:
    rutas = {"entrada": tmp_path / "entrada", "trabajo": tmp_path / "t.parcial"}
    rutas["entrada"].write_bytes(b"e")
    rutas["trabajo"].mkdir()
    rutas[falta].rename(tmp_path / "otro")
    codigo = (
        f"import sys; sys.path.insert(0, {str(RAIZ)!r})\n"
        "from api.app.aislamiento import aplicar\n"
        f"aplicar(lectura=[], entrada={str(rutas['entrada'])!r},"
        f" trabajo={str(rutas['trabajo'])!r})\n"
    )
    salida = subprocess.run(
        [sys.executable, "-c", codigo], capture_output=True, timeout=30, check=False
    )
    assert salida.returncode != 0


def test_k53_una_entrada_que_es_un_enlace_no_se_acepta(tmp_path: Path) -> None:
    """La regla de lectura no puede acabar sobre el destino de un enlace."""
    destino = tmp_path / "destino"
    destino.write_bytes(b"secreto")
    entrada = tmp_path / "entrada"
    entrada.symlink_to(destino)
    trabajo = tmp_path / "t.parcial"
    trabajo.mkdir()
    codigo = (
        f"import sys; sys.path.insert(0, {str(RAIZ)!r})\n"
        "from api.app.aislamiento import aplicar\n"
        f"aplicar(lectura=[], entrada={str(entrada)!r}, trabajo={str(trabajo)!r})\n"
    )
    salida = subprocess.run(
        [sys.executable, "-c", codigo], capture_output=True, timeout=30, check=False
    )
    assert salida.returncode != 0


# --------------------------------------------- K54: ningún socket, Unix incluido

_SOCKETS = """
import errno, json, os, socket, sys
sys.path.insert(0, {raiz!r})
from api.app.aislamiento import aplicar
cfg = json.loads(sys.argv[1])
# Creado antes de aislarse: así se prueba la capa de Landlock aunque seccomp impida crear otro.
previo = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
aplicar(lectura=[cfg["leible"]], entrada=cfg["entrada"], trabajo=cfg["trabajo"])


def intento(funcion):
    try:
        funcion()
    except OSError as error:
        return errno.errorcode.get(error.errno, str(error.errno))
    return "permitido"


print(json.dumps({{
    "unix": intento(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()),
    "udp": intento(lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).close()),
    "tcp": intento(lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()),
    "socketpair": intento(lambda: [s.close() for s in socket.socketpair()]),
    "conectar_unix_por_ruta": intento(lambda: previo.connect(cfg["escucha"])),
}}))
"""


@pytest.fixture
def sockets(tmp_path: Path) -> dict[str, str]:
    leible = tmp_path / "leible"
    leible.mkdir()
    entrada = tmp_path / "entrada"
    entrada.write_bytes(b"e")
    trabajo = tmp_path / "t.parcial"
    trabajo.mkdir()
    escucha = leible / "escucha.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as servidor:
        servidor.bind(str(escucha))
        servidor.listen(1)
        cfg = {
            "leible": str(leible),
            "entrada": str(entrada),
            "trabajo": str(trabajo),
            "escucha": str(escucha),
        }
        salida = subprocess.run(
            [sys.executable, "-c", _SOCKETS.format(raiz=str(RAIZ)), json.dumps(cfg)],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    return json.loads(salida.stdout)


@pytest.mark.parametrize("tipo", ["unix", "udp", "tcp", "socketpair"])
def test_k54_seccomp_impide_crear_cualquier_socket(
    sockets: dict[str, str], tipo: str
) -> None:
    assert sockets[tipo] == "EPERM"


def test_k54_landlock_impide_resolver_un_socket_unix_por_ruta(
    sockets: dict[str, str],
) -> None:
    """La primera capa: aunque el socket ya exista, no se conecta a una ruta legible."""
    if aislamiento.abi() < 9:
        pytest.skip("la ABI de Landlock de este kernel no gestiona RESOLVE_UNIX")
    assert sockets["conectar_unix_por_ruta"] == "EACCES"


def test_k54_filtro_por_arquitectura() -> None:
    for maquina in ("x86_64", "aarch64"):
        programa = aislamiento.filtro_sin_sockets(maquina)
        assert len(programa) % 8 == 0 and programa


@pytest.mark.parametrize("maquina", ["i686", "riscv64", "armv7l", ""])
def test_k54_arquitectura_no_soportada_falla_cerrado(maquina: str) -> None:
    with pytest.raises(aislamiento.AislamientoFallido):
        aislamiento.filtro_sin_sockets(maquina)


def test_k54_tambien_bloquea_las_llamadas_x32(tmp_path: Path) -> None:
    """En x86_64, una llamada con el bit x32 entra con la misma arquitectura en el filtro."""
    if aislamiento.platform.machine() != "x86_64":
        pytest.skip("solo en x86_64")
    trabajo = tmp_path / "t.parcial"
    trabajo.mkdir()
    entrada = tmp_path / "entrada"
    entrada.write_bytes(b"e")
    codigo = (
        f"import ctypes, errno, sys; sys.path.insert(0, {str(RAIZ)!r})\n"
        "from api.app.aislamiento import aplicar\n"
        f"aplicar(lectura=[], entrada={str(entrada)!r}, trabajo={str(trabajo)!r})\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "r = libc.syscall(0x40000000 | 41, 1, 1, 0)\n"  # socket() por la ABI x32
        "print(r, errno.errorcode.get(ctypes.get_errno()))\n"
    )
    salida = subprocess.run(
        [sys.executable, "-c", codigo],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert salida.stdout.split() == ["-1", "EPERM"]


@pytest.mark.parametrize(
    ("nombre", "numero"),
    [("io_uring_setup", 425), ("io_uring_enter", 426), ("io_uring_register", 427)],
)
def test_k54_io_uring_negado(tmp_path: Path, nombre: str, numero: int) -> None:
    """`IORING_OP_SOCKET` crea sockets sin pasar por `socket()`: io_uring entero queda fuera."""
    trabajo = tmp_path / "t.parcial"
    trabajo.mkdir()
    entrada = tmp_path / "entrada"
    entrada.write_bytes(b"e")
    codigo = (
        f"import ctypes, errno, sys; sys.path.insert(0, {str(RAIZ)!r})\n"
        "from api.app.aislamiento import aplicar\n"
        f"aplicar(lectura=[], entrada={str(entrada)!r}, trabajo={str(trabajo)!r})\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "parametros = ctypes.create_string_buffer(120)\n"
        f"r = libc.syscall({numero}, 8, parametros, 0, 0, 0, 0)\n"
        "print(r, errno.errorcode.get(ctypes.get_errno()))\n"
    )
    salida = subprocess.run(
        [sys.executable, "-c", codigo],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert salida.stdout.split() == ["-1", "EPERM"], nombre
