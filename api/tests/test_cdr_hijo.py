"""Proceso hijo real: stdout de una línea y límites puestos antes de cualquier parser."""

import ast
import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pikepdf
import pytest
from PIL import Image

from api.app import cdr_hijo
from api.app.tipos import TIPOS_PERMITIDOS

RAIZ = Path(__file__).resolve().parents[2]
UN_GIB = 1024 * 1024 * 1024
PROHIBIDOS_AL_IMPORTAR = {"PIL", "pikepdf", "magic", "sqlalchemy", "fastapi"}


def _correr(*argumentos: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "api.app.cdr_hijo", *argumentos],
        check=False,
        cwd=RAIZ,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        timeout=30,
    )


def _trabajo(tmp_path: Path) -> Path:
    """Directorio de trabajo como el que crea la API para cada hijo (K53)."""
    trabajo = tmp_path / "archivo.parcial"
    trabajo.mkdir(mode=0o700, exist_ok=True)
    return trabajo


def _veredicto(entrada: Path, salida: Path) -> dict[str, str]:
    resultado = _correr(str(entrada), str(salida))
    assert resultado.returncode == 0, resultado.stderr
    assert resultado.stdout.count(b"\n") == 1
    assert resultado.stdout.endswith(b"\n")
    return json.loads(resultado.stdout)


def test_importar_el_modulo_no_carga_parsers_ni_la_bd() -> None:
    """Sin esto, `RLIMIT_AS` llegaría tarde: el import corre antes de `main`."""
    arbol = ast.parse(Path(cdr_hijo.__file__).read_text())
    importados = set()
    for nodo in arbol.body:
        if isinstance(nodo, ast.Import):
            importados.update(alias.name.partition(".")[0] for alias in nodo.names)
        elif isinstance(nodo, ast.ImportFrom):
            importados.add((nodo.module or "").partition(".")[0])
    assert not importados & PROHIBIDOS_AL_IMPORTAR


def test_main_cierra_y_limita_antes_de_analizar(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """El archivo hostil no se abre con un descriptor ajeno abierto ni sin límites."""
    orden: list[str] = []

    def _analizar(*_: object) -> dict[str, str]:
        orden.append("analizar")
        return {"veredicto": "rechazado", "tipo": "x", "motivo": "y"}

    monkeypatch.setattr(
        cdr_hijo, "cerrar_descriptores_heredados", lambda: orden.append("cerrar")
    )
    monkeypatch.setattr(
        cdr_hijo, "atar_al_padre", lambda padre: orden.append(f"atar {padre}")
    )
    monkeypatch.setattr(cdr_hijo, "fijar_limites", lambda: orden.append("limitar"))
    monkeypatch.setattr(cdr_hijo, "analizar", _analizar)
    monkeypatch.setattr(cdr_hijo.os, "getppid", lambda: 4242)

    assert cdr_hijo.main(["entrada", "salida"]) == 0
    assert orden == ["cerrar", "atar 4242", "limitar", "analizar"]
    capsys.readouterr()


def _en_un_hijo(codigo: str) -> str:
    resultado = subprocess.run(
        [sys.executable, "-c", codigo],
        check=True,
        cwd=RAIZ,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=30,
    )
    return resultado.stdout.strip()


def test_k50_k42_limites_en_los_dos_valores() -> None:
    """K31 y K50: un límite blando solo se podría subir hasta el duro, así que van iguales."""
    salida = _en_un_hijo(
        "import json, resource\n"
        "from api.app.cdr_hijo import fijar_limites\n"
        "fijar_limites()\n"
        "print(json.dumps([resource.getrlimit(r) for r in"
        " (resource.RLIMIT_AS, resource.RLIMIT_CORE, resource.RLIMIT_CPU)]))\n"
    )
    assert json.loads(salida) == [[UN_GIB, UN_GIB], [0, 0], [35, 35]]


def test_k50_el_valor_de_rlimit_cpu_es_el_de_la_decision() -> None:
    assert cdr_hijo.LIMITE_CPU_S == 35


def test_k42_atar_al_padre_deja_pdeathsig_en_sigkill() -> None:
    salida = _en_un_hijo(
        "import ctypes, os\n"
        "from api.app.cdr_hijo import atar_al_padre\n"
        "atar_al_padre(os.getppid())\n"
        "senal = ctypes.c_int(0)\n"
        "ctypes.CDLL(None).prctl(2, ctypes.byref(senal), 0, 0, 0)\n"
        "print(senal.value)\n"
    )
    assert int(salida) == signal.SIGKILL


def test_k42_si_el_padre_ya_murio_no_sigue(monkeypatch: pytest.MonkeyPatch) -> None:
    """Si muere antes de fijar la señal, el hijo ya es huérfano y la señal no llegaría nunca."""
    monkeypatch.setattr(cdr_hijo, "_fijar_senal_de_muerte", lambda: None)
    monkeypatch.setattr(cdr_hijo.os, "getppid", lambda: 1)
    with pytest.raises(SystemExit) as salida:
        cdr_hijo.atar_al_padre(4242)
    assert salida.value.code != 0


def test_k42_el_hijo_real_muere_con_su_padre(tmp_path: Path) -> None:
    """Un padre intermedio lanza el hijo real con un análisis que no termina y muere."""
    registro = tmp_path / "pid"
    hijo = (
        "import os, sys, time\n"
        f"sys.path.insert(0, {str(RAIZ)!r})\n"
        "from api.app import cdr_hijo\n"
        "def esperar(*_):\n"
        f"    open({str(registro)!r}, 'w').write(str(os.getpid()))\n"
        "    time.sleep(30)\n"
        "cdr_hijo.analizar = esperar\n"
        "sys.exit(cdr_hijo.main(['a', 'b']))\n"
    )
    padre = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {hijo!r}])\n"
        "time.sleep(30)\n"
    )
    intermedio = subprocess.Popen(
        [sys.executable, "-c", padre], env={"PATH": "/usr/bin:/bin"}
    )
    try:
        limite = time.monotonic() + 15
        while not (registro.exists() and registro.read_text()):
            assert time.monotonic() < limite, "el hijo no arrancó"
            time.sleep(0.01)
        pid = int(registro.read_text())
        intermedio.kill()
        intermedio.wait()
        limite = time.monotonic() + 5
        while _vivo(pid):
            assert time.monotonic() < limite, "el hijo sobrevivió a su padre"
            time.sleep(0.01)
    finally:
        intermedio.kill()
        intermedio.wait()
        # Si la prueba falla, el hijo no puede quedar suelto.
        if registro.exists() and registro.read_text():
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(registro.read_text()), signal.SIGKILL)


def _vivo(pid: int) -> bool:
    try:
        estado = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
    except FileNotFoundError:
        return False
    return estado not in ("Z", "X")


def test_cerrar_descriptores_no_recorre_todo_el_rango() -> None:
    """Este Python no usa `close_range`: `os.closerange` hace una llamada por cada número.

    Con 1 048 576 de `SC_OPEN_MAX` eso son 350 ms en cada archivo, un 20 % de M2.
    """
    codigo = (
        "import time\n"
        "from api.app.cdr_hijo import cerrar_descriptores_heredados as cerrar\n"
        "inicio = time.perf_counter()\n"
        "cerrar()\n"
        "print((time.perf_counter() - inicio) * 1000)\n"
    )
    resultado = subprocess.run(
        [sys.executable, "-c", codigo],
        check=True,
        cwd=RAIZ,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert float(resultado.stdout) < 5


def test_sin_dos_argumentos_sale_con_2() -> None:
    assert _correr().returncode == 2
    assert _correr("uno").returncode == 2
    assert _correr("uno", "dos", "tres").returncode == 2


def test_entrada_inexistente_no_es_veredicto(tmp_path: Path) -> None:
    resultado = _correr(str(tmp_path / "no_existe"), str(tmp_path / "salida"))
    assert resultado.returncode != 0
    assert resultado.stdout == b""


def test_tipo_fuera_de_la_lista_blanca(tmp_path: Path) -> None:
    entrada = tmp_path / "entrada"
    entrada.write_bytes(b"#!/bin/sh\nid\n")
    salida = _trabajo(tmp_path) / "salida"
    veredicto = _veredicto(entrada, salida)
    assert veredicto["veredicto"] == "rechazado"
    assert veredicto["motivo"] == "tipo_no_permitido"
    assert veredicto["tipo"] not in TIPOS_PERMITIDOS
    assert not salida.exists()


def test_png_limpio(tmp_path: Path) -> None:
    entrada = tmp_path / "entrada"
    Image.new("RGB", (4, 4)).save(entrada, "PNG")
    salida = _trabajo(tmp_path) / "salida"
    assert _veredicto(entrada, salida) == {
        "veredicto": "limpio",
        "tipo": "image/png",
        "motivo": "ok",
    }
    assert salida.exists()


def test_k39_girar_40_mp_rgba_cabe_en_rlimit_as(tmp_path: Path) -> None:
    """El peor caso de K39, con el hijo real: 40 MP a 4 bytes por píxel, girados."""
    exif = Image.Exif()
    exif[0x0112] = 6
    entrada = tmp_path / "entrada"
    Image.new("RGBA", (8000, 5000), (9, 9, 9, 9)).save(entrada, "PNG", exif=exif)
    salida = _trabajo(tmp_path) / "salida"

    assert _veredicto(entrada, salida)["veredicto"] == "limpio"

    with Image.open(salida) as resultado:
        assert resultado.size == (5000, 8000)


def test_pdf_limpio(tmp_path: Path) -> None:
    entrada = tmp_path / "entrada"
    pdf = pikepdf.new()
    pdf.add_blank_page()
    pdf.save(entrada)
    salida = _trabajo(tmp_path) / "salida"
    assert _veredicto(entrada, salida)["tipo"] == "application/pdf"
    assert salida.exists()


@pytest.mark.parametrize(
    ("firma", "motivo"),
    [(b"\xff\xd8\xff\xe0", "imagen_invalida"), (b"%PDF-1.7\n", "pdf_invalido")],
    ids=["jpeg", "pdf"],
)
def test_firma_falsa_es_rechazado_con_su_tipo(
    tmp_path: Path, firma: bytes, motivo: str
) -> None:
    entrada = tmp_path / "entrada"
    entrada.write_bytes(firma + b"<?php phpinfo(); ?>" * 8)
    veredicto = _veredicto(entrada, _trabajo(tmp_path) / "salida")
    assert veredicto["veredicto"] == "rechazado"
    assert veredicto["motivo"] == motivo
    assert veredicto["tipo"] in TIPOS_PERMITIDOS


# ----------------------------------------------------------------------- K53: Landlock


def test_k53_analizar_aisla_antes_de_abrir_la_entrada(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Aplicarlo después de abrir no serviría: el descriptor abierto no lo limita."""
    import magic

    orden: list[str] = []
    monkeypatch.setattr(cdr_hijo, "aislar", lambda *_: orden.append("aislar"))

    def _desde_archivo(_self: object, ruta: str) -> str:
        orden.append(f"leer {Path(ruta).name}")
        return "text/plain"

    monkeypatch.setattr(magic.Magic, "from_file", _desde_archivo)
    entrada = tmp_path / "entrada"
    entrada.write_bytes(b"x")
    cdr_hijo.analizar(entrada, _trabajo(tmp_path) / "salida")
    assert orden == ["aislar", "leer entrada"]


def test_k53_lee_python_el_entorno_y_su_codigo() -> None:
    lectura = cdr_hijo.directorios_de_lectura()
    for prefijo in (sys.prefix, sys.base_prefix):
        assert prefijo in lectura
    assert str(RAIZ / "api" / "app") in lectura
    assert str(RAIZ) not in lectura
    assert "/dev/urandom" in lectura
    assert str(Path.home()) not in lectura


def test_k53_salida_fuera_de_un_parcial_no_se_analiza(tmp_path: Path) -> None:
    entrada = tmp_path / "entrada"
    Image.new("RGB", (4, 4)).save(entrada, "PNG")
    resultado = _correr(str(entrada), str(tmp_path / "salida"))
    assert resultado.returncode != 0
    assert resultado.stdout == b""


def test_k53_el_hijo_real_no_lee_un_archivo_vecino(tmp_path: Path) -> None:
    """Un PNG cuya reconstrucción no importa: lo que cuenta es lo que el hijo pudo abrir."""
    vecino = tmp_path / "vecino"
    vecino.write_bytes(b"secreto")
    entrada = tmp_path / "entrada"
    Image.new("RGB", (4, 4)).save(entrada, "PNG")
    codigo = (
        "import sys\n"
        "from api.app import cdr_hijo\n"
        "original = cdr_hijo._reconstruir\n"
        "def _espia(entrada, salida, tipo):\n"
        "    try:\n"
        f"        open({str(vecino)!r}, 'rb').close()\n"
        "        sys.stderr.write('LEIDO')\n"
        "    except PermissionError:\n"
        "        sys.stderr.write('DENEGADO')\n"
        "    return original(entrada, salida, tipo)\n"
        "cdr_hijo._reconstruir = _espia\n"
        "sys.exit(cdr_hijo.main(sys.argv[1:]))\n"
    )
    resultado = subprocess.run(
        [sys.executable, "-c", codigo, str(entrada), str(_trabajo(tmp_path) / "s")],
        check=False,
        cwd=RAIZ,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        timeout=30,
    )
    assert resultado.returncode == 0, resultado.stderr
    assert resultado.stderr.endswith(b"DENEGADO")


def test_k53_pdf_cifrado_con_aes_256_se_rechaza_y_no_falla(tmp_path: Path) -> None:
    """qpdf lee /dev/urandom al abrir un PDF con AES: sin él, terminaba en `error`."""
    entrada = tmp_path / "entrada"
    pdf = pikepdf.new()
    pdf.add_blank_page()
    pdf.save(entrada, encryption=pikepdf.Encryption(owner="x", user="", R=6))
    veredicto = _veredicto(entrada, _trabajo(tmp_path) / "salida")
    assert veredicto["veredicto"] == "rechazado"
    assert veredicto["motivo"] == "pdf_cifrado"


def test_k54_jpeg_limpio_sin_sockets(tmp_path: Path) -> None:
    """Con seccomp (K54) libmagic y Pillow no necesitan ningún socket en el camino normal."""
    entrada = tmp_path / "entrada"
    Image.new("RGB", (16, 16), (200, 10, 10)).save(entrada, "JPEG", quality=90)
    salida = _trabajo(tmp_path) / "salida"
    assert _veredicto(entrada, salida) == {
        "veredicto": "limpio",
        "tipo": "image/jpeg",
        "motivo": "ok",
    }
    assert salida.exists()


def test_k54_sin_filtro_seccomp_el_hijo_no_analiza(tmp_path: Path) -> None:
    """Una máquina sin filtro armado falla cerrado: no hay veredicto y la API pone `error`."""
    entrada = tmp_path / "entrada"
    Image.new("RGB", (4, 4)).save(entrada, "PNG")
    salida = _trabajo(tmp_path) / "salida"
    codigo = (
        "import platform, sys\n"
        "platform.machine = lambda: 'riscv64'\n"
        "from api.app import cdr_hijo\n"
        "sys.exit(cdr_hijo.main(sys.argv[1:]))\n"
    )
    resultado = subprocess.run(
        [sys.executable, "-c", codigo, str(entrada), str(salida)],
        check=False,
        cwd=RAIZ,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        timeout=30,
    )
    assert resultado.returncode != 0
    assert resultado.stdout == b""
    assert not salida.exists()
