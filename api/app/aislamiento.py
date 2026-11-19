"""K53: Landlock para el proceso hijo del CDR, con ``ctypes`` y sin dependencias.

El hijo corre con el mismo UID que la API (K28). Landlock le quita, para sí y para todo lo
que lance, lo que ese usuario podría hacer y el hijo no necesita:

- **Lectura:** solo los directorios que se le pasan (Python, el entorno virtual, el código del
  CDR, las bibliotecas del sistema) y su archivo de entrada. Ni ``uploads_tmp`` ni
  ``clean_store`` ni el directorio personal ni ``/proc``: no lee originales ni reconstruidos de
  otros archivos, ni el entorno de ningún proceso.
- **Escritura:** solo crear, escribir, truncar y borrar archivos regulares dentro de su
  directorio de trabajo (``clean_store/<uuid>.parcial/``), que crea el padre. Sin directorios,
  enlaces, sockets ni dispositivos, en ningún sitio.
- **Ejecución:** ninguna.
- **Red (ABI ≥ 4):** ni ``bind`` ni ``connect`` por TCP. UDP no lo cubre Landlock.
- **Ámbito (ABI ≥ 6):** ni señales ni sockets Unix abstractos fuera de su dominio.
- **Sockets Unix por ruta (ABI ≥ 9, K54):** ``RESOLVE_UNIX`` se gestiona sin concederse: no
  conecta a ``/var/run/docker.sock`` ni al D-Bus de la sesión aunque estén en una ruta legible.
- **Ningún socket, en cualquier kernel (K54):** un filtro seccomp niega ``socket()``,
  ``socketpair()`` e io_uring (``io_uring_setup``, ``_enter`` y ``_register``: con
  ``IORING_OP_SOCKET`` crea sockets sin pasar por ``socket()``) con ``EPERM``, también UDP. El hijo no necesita ninguno. El filtro comprueba
  la arquitectura: una llamada de otra ABI (i386 o x32 en x86_64) recibe ``EPERM`` sea la que
  sea. Solo se arma para x86_64 y aarch64; en otra máquina el hijo falla cerrado.

Se usa todo lo que ofrezca la ABI del kernel, sin exigir más que la 1. Si Landlock no está o
cualquier llamada falla, ``aplicar`` lanza: el hijo termina sin analizar y el archivo queda en
``error`` (falla cerrado). ``PR_SET_NO_NEW_PRIVS`` es requisito de ``landlock_restrict_self``.
"""

import ctypes
import errno
import os
import platform
import stat
import struct
from collections.abc import Iterable
from pathlib import Path

# Números de llamada: iguales en todas las arquitecturas desde Linux 5.13.
_SYS_CREATE_RULESET = 444
_SYS_ADD_RULE = 445
_SYS_RESTRICT_SELF = 446
_CREATE_RULESET_VERSION = 1 << 0
_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
SUFIJO_TRABAJO = ".parcial"

# <linux/landlock.h>, LANDLOCK_ACCESS_FS_*
_EXECUTE = 1 << 0
_WRITE_FILE = 1 << 1
_READ_FILE = 1 << 2
_READ_DIR = 1 << 3
_REMOVE_FILE = 1 << 5
_MAKE_REG = 1 << 8
_FS_ABI_1 = (1 << 13) - 1  # de EXECUTE a MAKE_SYM
_REFER = 1 << 13  # ABI 2
_TRUNCATE = 1 << 14  # ABI 3
_IOCTL_DEV = 1 << 15  # ABI 5
_RESOLVE_UNIX = 1 << 16  # ABI 9
# LANDLOCK_ACCESS_NET_* (ABI 4) y LANDLOCK_SCOPE_* (ABI 6)
_BIND_TCP = 1 << 0
_CONNECT_TCP = 1 << 1
_SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0
_SCOPE_SIGNAL = 1 << 1

_LECTURA_DIRECTORIO = _READ_FILE | _READ_DIR


# seccomp (K54). <linux/audit.h>, <linux/seccomp.h>, <linux/filter.h>
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_RET_ALLOW = 0x7FFF0000
_RET_EPERM = 0x00050000 | errno.EPERM
_LD_W_ABS = 0x20  # BPF_LD | BPF_W | BPF_ABS
_JEQ_K = 0x15  # BPF_JMP | BPF_JEQ | BPF_K
_JGE_K = 0x35  # BPF_JMP | BPF_JGE | BPF_K
_RET_K = 0x06  # BPF_RET | BPF_K
_OFFSET_NR = 0  # struct seccomp_data: nr, arch, ...
_OFFSET_ARCH = 4
_X32 = 0x40000000
# io_uring_setup, io_uring_enter e io_uring_register: mismos números en las dos máquinas.
# Con IORING_OP_SOCKET, io_uring crea sockets sin pasar por socket().
_IO_URING = (425, 426, 427)
# Máquina: (AUDIT_ARCH_*, llamadas negadas, ¿tiene ABI x32?). Las primeras, socket y socketpair.
_ARQUITECTURAS = {
    "x86_64": (0xC000003E, (41, 53, *_IO_URING), True),
    "aarch64": (0xC00000B7, (198, 199, *_IO_URING), False),
}


class AislamientoFallido(Exception):
    """Landlock no está disponible o no se pudo aplicar. El hijo no debe analizar."""


class _AtributosRuleset(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    ]


class _BajoRuta(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


def _fallo(llamada: str) -> AislamientoFallido:
    numero = ctypes.get_errno()
    return AislamientoFallido(f"{llamada}: {os.strerror(numero)}")


class _Programa(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def _instruccion(codigo: int, si: int, no: int, valor: int) -> bytes:
    return struct.pack("=HBBI", codigo, si, no, valor)


def filtro_sin_sockets(maquina: str) -> bytes:
    """Programa BPF que niega ``socket``, ``socketpair`` e io_uring con ``EPERM`` en ``maquina``.

    Una arquitectura que no sea la de la máquina (i386 por ``int 0x80``) recibe ``EPERM`` en
    todo. En x86_64 también todo número con el bit x32. Lanza ``AislamientoFallido`` si no se
    sabe armar para ``maquina``: sin filtro, el hijo no debe analizar.
    """
    if maquina not in _ARQUITECTURAS:
        raise AislamientoFallido("arquitectura sin filtro seccomp")
    arquitectura, negadas, x32 = _ARQUITECTURAS[maquina]
    cuerpo = [(_JEQ_K, numero) for numero in negadas]
    if x32:
        cuerpo.insert(0, (_JGE_K, _X32))
    programa = [
        _instruccion(_LD_W_ABS, 0, 0, _OFFSET_ARCH),
        _instruccion(_JEQ_K, 1, 0, arquitectura),
        _instruccion(_RET_K, 0, 0, _RET_EPERM),
        _instruccion(_LD_W_ABS, 0, 0, _OFFSET_NR),
    ]
    # Cada comparación salta, si se cumple, a la última instrucción (EPERM).
    for indice, (codigo, valor) in enumerate(cuerpo):
        programa.append(_instruccion(codigo, len(cuerpo) - indice, 0, valor))
    programa += [
        _instruccion(_RET_K, 0, 0, _RET_ALLOW),
        _instruccion(_RET_K, 0, 0, _RET_EPERM),
    ]
    return b"".join(programa)


def _instalar_filtro(programa: bytes) -> None:
    """Instala el filtro. Requiere ``PR_SET_NO_NEW_PRIVS``, que ya puso Landlock."""
    instrucciones = ctypes.create_string_buffer(programa, len(programa))
    descriptor = _Programa(len(programa) // 8, ctypes.addressof(instrucciones))
    if (
        _libc.prctl(
            _PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(descriptor), 0, 0
        )
        != 0
    ):
        raise _fallo("PR_SET_SECCOMP")


def abi() -> int:
    """Versión de la ABI de Landlock, o 0 si el kernel no lo tiene o no lo deja usar."""
    version = _libc.syscall(
        ctypes.c_long(_SYS_CREATE_RULESET),
        None,
        ctypes.c_size_t(0),
        ctypes.c_uint32(_CREATE_RULESET_VERSION),
    )
    return max(version, 0)


def comprobar_trabajo(trabajo: Path) -> None:
    """El directorio de trabajo tiene que ser el ``<uuid>.parcial`` que crea el padre.

    Dar escritura sobre otro (``clean_store`` entero, por un error de configuración) sería
    darla sobre los archivos ya publicados.
    """
    if not trabajo.name.endswith(SUFIJO_TRABAJO) or trabajo.is_symlink():
        raise AislamientoFallido("el directorio de trabajo no es un .parcial")


def _descriptor_de_ruta(ruta: str | Path) -> int:
    return os.open(ruta, os.O_PATH | os.O_CLOEXEC)


def _descriptor_de_la_entrada(entrada: str | Path) -> int:
    """``O_PATH`` de la entrada, sin seguir un enlace en su último componente.

    Se abre relativo a su directorio: el descriptor solo identifica el archivo para la regla
    (con ``O_PATH`` no se puede leer). La lectura de verdad llega después de Landlock.
    """
    entrada = Path(entrada)
    directorio = os.open(entrada.parent, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        return os.open(
            entrada.name,
            os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directorio,
        )
    finally:
        os.close(directorio)


def _regla(ruleset: int, descriptor: int, permitido: int) -> None:
    """Añade la regla sobre ``descriptor`` y lo cierra."""
    try:
        regla = _BajoRuta(permitido, descriptor)
        if (
            _libc.syscall(
                ctypes.c_long(_SYS_ADD_RULE),
                ctypes.c_int(ruleset),
                ctypes.c_int(_RULE_PATH_BENEATH),
                ctypes.byref(regla),
                ctypes.c_uint32(0),
            )
            != 0
        ):
            raise _fallo("landlock_add_rule")
    finally:
        os.close(descriptor)


def aplicar(
    lectura: Iterable[str | Path], entrada: str | Path, trabajo: str | Path
) -> None:
    """Restringe este proceso: lee ``lectura`` y ``entrada``, escribe solo en ``trabajo``.

    ``lectura`` admite directorios (se lee todo lo que cuelga de ellos) y archivos sueltos,
    como ``/dev/urandom``. Lo que no exista se salta (``/lib64`` no está en todas partes);
    ``entrada`` y ``trabajo`` tienen que existir. Lanza ``AislamientoFallido`` u
    ``OSError``; en los dos casos el proceso no queda restringido y no debe seguir.
    """
    trabajo = Path(trabajo)
    comprobar_trabajo(trabajo)
    version = abi()
    if version < 1:
        raise AislamientoFallido("Landlock no está disponible")

    acceso_fs = _FS_ABI_1
    if version >= 2:
        acceso_fs |= _REFER
    if version >= 3:
        acceso_fs |= _TRUNCATE
    if version >= 5:
        acceso_fs |= _IOCTL_DEV
    if version >= 9:
        acceso_fs |= _RESOLVE_UNIX
    atributos = _AtributosRuleset(acceso_fs, 0, 0)
    tamano = 8
    if version >= 4:
        atributos.handled_access_net = _BIND_TCP | _CONNECT_TCP
        tamano = 16
    if version >= 6:
        atributos.scoped = _SCOPE_ABSTRACT_UNIX_SOCKET | _SCOPE_SIGNAL
        tamano = 24

    ruleset = _libc.syscall(
        ctypes.c_long(_SYS_CREATE_RULESET),
        ctypes.byref(atributos),
        ctypes.c_size_t(tamano),
        ctypes.c_uint32(0),
    )
    if ruleset < 0:
        raise _fallo("landlock_create_ruleset")
    try:
        for ruta in lectura:
            if os.path.isdir(ruta):
                _regla(ruleset, _descriptor_de_ruta(ruta), _LECTURA_DIRECTORIO)
            elif os.path.exists(ruta):
                _regla(ruleset, _descriptor_de_ruta(ruta), _READ_FILE)
        descriptor = _descriptor_de_la_entrada(entrada)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise AislamientoFallido("la entrada no es un archivo regular")
        _regla(ruleset, descriptor, _READ_FILE)
        escritura = _WRITE_FILE | _MAKE_REG | _REMOVE_FILE
        if version >= 3:
            escritura |= _TRUNCATE
        _regla(ruleset, _descriptor_de_ruta(trabajo), escritura)
        if _libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise _fallo("PR_SET_NO_NEW_PRIVS")
        if (
            _libc.syscall(
                ctypes.c_long(_SYS_RESTRICT_SELF),
                ctypes.c_int(ruleset),
                ctypes.c_uint32(0),
            )
            != 0
        ):
            raise _fallo("landlock_restrict_self")
    finally:
        os.close(ruleset)
    _instalar_filtro(filtro_sin_sockets(platform.machine()))
