"""K53 — Landlock en el proceso hijo del CDR.

Origen: revisión de la vuelta 1 (2026-11-10). El hijo corre con el mismo UID que la API, así que
uno comprometido podía leer y modificar todo lo que ese usuario alcanza: originales de otras
aplicaciones en `uploads_tmp`, archivos ya `limpio` de otras aplicaciones en `clean_store` (que la
API entrega sin volver a mirarlos), el `.parcial` de un hermano antes de publicarse, el entorno de
los procesos del usuario y la base de datos por TCP.

Decisión del usuario (K53): Landlock en el hijo, aplicado tras cerrar descriptores y fijar límites,
antes de leer el archivo no confiable. Solo lee lo que necesita (Python, el entorno virtual, las
bibliotecas del sistema, la base de libmagic y su entrada) y solo escribe su propia salida. Sin TCP
si la ABI lo permite (>= 4). Si Landlock no está o falla al aplicarse, el hijo termina sin analizar
y el archivo queda en `error` (falla cerrado).

Lo observable se fija así: cuando el hijo abre su archivo de entrada, todo lo de abajo ya debe
estar denegado (EACCES o EPERM). Ver `sondas_landlock.py`.
"""

import shutil
import socket
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from generadores import guardar, jpeg, pdf_base, png
from sondas_landlock import (
    DENEGADO,
    ES_X86_64,
    SIN_LANDLOCK,
    SIN_SECCOMP,
    abi_landlock,
    hijo_sin_landlock,
    hijo_sin_seccomp,
    leer_sonda,
    sonda_accesos,
)
from soporte_matriz import esperar_que, exigir_limpio

SENUELO = b"senuelo de otra aplicacion"
ABI_CON_TCP = 4


def _primer_archivo_del_home() -> str | None:
    """Un archivo cualquiera directamente en el directorio personal; solo se intenta abrir."""
    home = Path.home()
    try:
        for entrada in sorted(home.iterdir()):
            if entrada.is_file() and not entrada.is_symlink():
                return str(entrada)
    except OSError:
        return None
    return None


@contextmanager
def _proceso_ajeno() -> Iterator[int]:
    """Un proceso del mismo UID que no es ancestro del hijo: su `/proc/<pid>/environ` es legible."""
    proceso = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        env={"PATH": "/usr/bin:/bin"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield proceso.pid
    finally:
        proceso.kill()
        proceso.wait(timeout=10)


@contextmanager
def _escucha_tcp() -> Iterator[tuple[str, int]]:
    """Un puerto local que acepta conexiones: un rechazo no puede pasar por denegación."""
    with socket.socket() as servidor:
        servidor.bind(("127.0.0.1", 0))
        servidor.listen(8)
        yield servidor.getsockname()


@contextmanager
def _escucha_unix() -> Iterator[list[str]]:
    """Un socket Unix por ruta y otro abstracto, escuchando: lo que serían `docker.sock` o el
    bus de sesión de D-Bus, que dan salida del sandbox (root en el host, o `systemd-run --user`).

    La ruta va en un directorio corto de /tmp: `sun_path` admite 108 bytes.
    """
    directorio = Path(tempfile.mkdtemp(prefix="gk53-", dir="/tmp"))
    ruta = str(directorio / "servicio.sock")
    abstracto = f"\0gk53-{uuid.uuid4().hex}"
    with (
        socket.socket(socket.AF_UNIX) as por_ruta,
        socket.socket(socket.AF_UNIX) as sin_ruta,
    ):
        por_ruta.bind(ruta)
        por_ruta.listen(8)
        sin_ruta.bind(abstracto)
        sin_ruta.listen(8)
        try:
            yield [ruta, abstracto]
        finally:
            shutil.rmtree(directorio, ignore_errors=True)


@pytest.fixture
def sondeo(banco, tmp_path):
    """Corre el hijo real bajo la sonda con un PNG y devuelve lo que pudo hacer.

    Los señuelos se crean con la API ya arrancada: el barrido del arranque los borraría.
    """
    with _proceso_ajeno() as ajeno, _escucha_tcp() as local, _escucha_unix() as unix:
        fuera = tmp_path / "fuera"
        fuera.mkdir()
        otro, borrable = str(uuid.uuid4()), str(uuid.uuid4())
        objetivos = {
            "uploads_tmp": str(banco.uploads_tmp),
            "clean_store": str(banco.clean_store),
            "uploads_otro": str(banco.uploads_tmp / otro),
            "clean_otro": str(banco.clean_store / otro),
            "parcial_hermano": str(banco.clean_store / f"{otro}.parcial"),
            "clean_borrable": str(banco.clean_store / borrable),
            "nuevo_clean": str(banco.clean_store / str(uuid.uuid4())),
            "nuevo_uploads": str(banco.uploads_tmp / str(uuid.uuid4())),
            "nuevo_fuera": str(fuera / "creado_por_el_hijo"),
            "home": str(Path.home()),
            "home_archivo": _primer_archivo_del_home(),
            "ajeno": ajeno,
            "unix": unix,
            "tcp": [
                [banco.url.host, banco.url.port],
                list(local),
            ],
        }
        comando, registro = sonda_accesos(tmp_path, objetivos)
        with banco.api(comando_cdr=comando) as cliente:
            senuelos = [
                Path(objetivos[clave])
                for clave in (
                    "uploads_otro",
                    "clean_otro",
                    "parcial_hermano",
                    "clean_borrable",
                )
            ]
            for senuelo in senuelos:
                senuelo.write_bytes(SENUELO)
            cliente.analizar(png(), b"foto.png", b"image/png")
            esperar_que(registro.exists, "la sonda no dejó registro", tope=15)
            resultado = leer_sonda(registro)
            for senuelo in senuelos[:3]:
                assert senuelo.read_bytes() == SENUELO, (
                    f"el hijo modificó {senuelo.name}"
                )
    assert resultado.get("disparada"), (
        "la sonda no vio al hijo abrir su archivo de entrada por su ruta: falta la costura"
    )
    assert "fallo_de_la_sonda" not in resultado, resultado
    return resultado


def _permitidos(intentos: dict[str, str]) -> list[str]:
    return [
        f"{nombre}: {valor}"
        for nombre, valor in intentos.items()
        if valor not in DENEGADO
    ]


def test_k53_el_hijo_no_lee_archivos_ajenos_ni_el_directorio_personal(sondeo):
    permitidos = _permitidos(sondeo["lectura"])
    assert not permitidos, f"el hijo pudo leer: {permitidos}"


def test_k53_el_hijo_no_lee_el_entorno_de_ningun_ancestro(sondeo):
    ancestros = sondeo["environ_ancestros"]
    assert ancestros, "la sonda no recorrió los ancestros"
    permitidos = _permitidos(
        {f"/proc/{pid}/environ": v for pid, v in ancestros.items()}
    )
    assert not permitidos, f"el hijo pudo leer: {permitidos}"


def test_k53_el_hijo_no_escribe_ni_crea_nada_fuera_de_su_salida(sondeo):
    permitidos = _permitidos(sondeo["escritura"])
    assert not permitidos, f"el hijo pudo: {permitidos}"


@pytest.mark.skipif(
    abi_landlock() < ABI_CON_TCP,
    reason="la ABI de Landlock de este kernel no restringe TCP",
)
def test_k53_el_hijo_no_abre_conexiones_tcp(sondeo):
    permitidos = _permitidos(sondeo["red"])
    assert not permitidos, f"el hijo pudo conectar: {permitidos}"


def test_k53_el_hijo_no_conecta_a_sockets_unix(sondeo):
    """Revisión de la vuelta 2: con TCP cerrado, el hijo aún hablaba con `docker.sock` (el usuario
    está en el grupo `docker`: root en el host) y con el bus de sesión de D-Bus (`systemd-run
    --user` lanza procesos fuera de Landlock). El kernel ofrece `LANDLOCK_ACCESS_FS_RESOLVE_UNIX`
    para los de ruta, y el ámbito de la ABI 6 para los abstractos."""
    intentos = sondeo["unix"]
    assert len(intentos) == 2, "la sonda no intentó los dos sockets Unix"
    permitidos = _permitidos(intentos)
    assert not permitidos, f"el hijo pudo conectar: {permitidos}"


@pytest.mark.skipif(not ES_X86_64, reason="el filtro seccomp usa los números de x86_64")
@pytest.mark.parametrize("caso", list(SIN_LANDLOCK))
def test_k53_hijo_sin_landlock_termina_en_error(banco, tmp_path, caso):
    """Falla cerrado: sin Landlock el hijo no analiza; el archivo no queda `limpio` ni `rechazado`."""
    comando = hijo_sin_landlock(tmp_path, caso)
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id, final = cliente.analizar(png(), b"foto.png", b"image/png")
    assert final["estado"] == "error", f"estado final: {final['estado']}"
    assert archivo_id not in [p.name for p in banco.clean_store.iterdir()]


def test_k54_el_hijo_no_crea_sockets_de_ninguna_familia(sondeo):
    """K54 (decisión del usuario tras la tercera revisión): el hijo no puede crear ningún socket,
    en ningún kernel. Landlock no cubre UDP ni la creación; lo hace un filtro seccomp sobre
    `socket()` y `socketpair()`. Al abrir la entrada, cada intento debe fallar con EPERM o
    EACCES (un errno de familia no soportada no demostraría el control).

    También por `io_uring` (`IORING_OP_SOCKET`, Linux >= 5.19), que crea sockets sin la llamada
    `socket()`. En la cuarta revisión, con el filtro de K54 puesto, creaba sockets UDP y netlink, y
    en un kernel sin `RESOLVE_UNIX` habría alcanzado `docker.sock`."""
    intentos = sondeo["sockets"]
    assert len(intentos) == 10, "la sonda no intentó todas las familias y vías"
    permitidos = _permitidos(intentos)
    assert not permitidos, f"el hijo pudo crear: {permitidos}"


@pytest.mark.skipif(not ES_X86_64, reason="el filtro seccomp usa los números de x86_64")
@pytest.mark.parametrize("caso", list(SIN_SECCOMP))
def test_k54_hijo_sin_seccomp_termina_en_error(banco, tmp_path, caso):
    """Falla cerrado: si el filtro de sockets no se puede instalar, el hijo no analiza."""
    comando = hijo_sin_seccomp(tmp_path, caso)
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id, final = cliente.analizar(png(), b"foto.png", b"image/png")
    assert final["estado"] == "error", f"estado final: {final['estado']}"
    assert archivo_id not in [p.name for p in banco.clean_store.iterdir()]


# ------------------------------------------------------------------------------ controles positivos


@pytest.mark.parametrize(
    ("generar", "nombre", "tipo"),
    [
        (jpeg, b"foto.jpg", "image/jpeg"),
        (png, b"foto.png", "image/png"),
        (lambda: guardar(pdf_base()), b"doc.pdf", "application/pdf"),
    ],
    ids=["jpeg", "png", "pdf"],
)
def test_k53_control_los_tres_tipos_legitimos_siguen_limpios(
    cliente, banco, generar, nombre, tipo
):
    """Con el hijo real y sin costuras: Landlock no debe impedir leer la entrada ni escribir la salida."""
    exigir_limpio(cliente, banco, generar(), nombre, tipo.encode(), tipo)
