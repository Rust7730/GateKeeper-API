"""INV-09 y F3.08 — Fail-closed: un timeout, un hijo que muere o una salida inválida terminan en `error`.

Los fallos se provocan sustituyendo el comando del hijo por la costura `Ajustes.comando_cdr`. El
sustituto siempre deja un archivo de salida válido, salvo cuando eso es lo que se prueba: así el
único motivo para no llegar a `limpio` es que el padre no se fíe de lo que recibió.

El control positivo (`test_inv09_control_...`) demuestra que la costura funciona. Sin él, una API que
ignora el comando, o que lo manda todo a `error`, pasaría el resto.
"""

import dataclasses
import json
import os
from pathlib import Path

import pytest
from generadores import jpeg, marca, png
from hijos import (
    COPIAR_SALIDA,
    RESPUESTA_LIMPIO,
    RESPUESTA_RECHAZADO,
    hijo_falso,
)
from soporte_matriz import (
    TOPE_HIJO_FALSO_S,
    esperar_que,
    exigir_conflicto,
    exigir_sin_original,
    nombres,
)

from api.app.ajustes import Ajustes, leer_ajustes


def _imprimir(texto: str) -> str:
    return f"{COPIAR_SALIDA}print({texto!r})\n"


def _limpio_con(**campos: object) -> str:
    return _imprimir(
        json.dumps(
            {"veredicto": "limpio", "tipo": "image/png", "motivo": "ok", **campos}
        )
    )


LIMPIO_Y_LUEGO = f"{COPIAR_SALIDA}print({RESPUESTA_LIMPIO!r}, flush=True)\n"

FALLOS = {
    # El proceso termina mal, aunque haya dicho `limpio` antes.
    "codigo_1": LIMPIO_Y_LUEGO + "sys.exit(1)\n",
    "codigo_3": LIMPIO_Y_LUEGO + "sys.exit(3)\n",
    "excepcion": LIMPIO_Y_LUEGO + "raise RuntimeError('fallo')\n",
    "muere_por_sigkill": LIMPIO_Y_LUEGO + "import os\nos.kill(os.getpid(), 9)\n",
    "muere_por_sigsegv": LIMPIO_Y_LUEGO + "import os\nos.kill(os.getpid(), 11)\n",
    "memoria_agotada": (
        LIMPIO_Y_LUEGO
        + "import resource\nresource.setrlimit(resource.RLIMIT_AS, (1 << 28, 1 << 28))\n"
        + "bytearray(1 << 29)\n"
    ),
    # El proceso termina bien, pero lo que dice no vale.
    "sin_salida": COPIAR_SALIDA,
    "no_es_json": _imprimir("limpio"),
    "json_lista": _imprimir('["limpio"]'),
    "json_nulo": _imprimir("null"),
    "sin_veredicto": _imprimir('{"tipo": "image/png", "motivo": "ok"}'),
    "veredicto_desconocido": _limpio_con(veredicto="aprobado"),
    "veredicto_en_mayusculas": _limpio_con(veredicto="LIMPIO"),
    "veredicto_con_espacio": _limpio_con(veredicto="limpio "),
    "veredicto_no_texto": _limpio_con(veredicto=["limpio"]),
    "veredicto_booleano": _limpio_con(veredicto=True),
    "sin_tipo": _imprimir('{"veredicto": "limpio", "motivo": "ok"}'),
    "tipo_nulo": _limpio_con(tipo=None),
    "tipo_fuera_de_la_lista_blanca": _limpio_con(tipo="text/html"),
    "tipo_no_texto": _limpio_con(tipo=["image/png"]),
    "dos_lineas_limpio_al_final": _imprimir(
        f"{RESPUESTA_RECHAZADO}\n{RESPUESTA_LIMPIO}"
    ),
    "dos_lineas_limpio_al_inicio": _imprimir(
        f"{RESPUESTA_LIMPIO}\n{RESPUESTA_RECHAZADO}"
    ),
    "bytes_invalidos": COPIAR_SALIDA + "sys.stdout.buffer.write(b'\\xff\\xfe\\n')\n",
    "anidamiento_profundo": COPIAR_SALIDA + "print('[' * 200000)\n",
    "salida_enorme": COPIAR_SALIDA + "print('a' * (20 * 1024 * 1024))\n",
    # Dice `limpio`, pero no dejó nada que entregar.
    "limpio_sin_archivo_de_salida": f"print({RESPUESTA_LIMPIO!r})\n",
}


def _exigir_error(
    cliente, banco, archivo_id: str, tope: float = TOPE_HIJO_FALSO_S
) -> None:
    final = cliente.esperar(archivo_id, tope=tope)
    assert final["estado"] == "error", f"estado final: {final['estado']}"
    assert final["analizado_en"] is not None
    # K11: un fallo del análisis es final y no se reintenta. No hay reintentos en la rebanada.
    assert banco.fila(archivo_id)["tipo_error"] == "final"
    exigir_conflicto(cliente.descargar(archivo_id))
    assert ("cdr", "limpio") not in banco.resultados(archivo_id)
    esperar_que(
        lambda: not nombres(banco.clean_store),
        "quedó una salida parcial en clean_store",
    )
    exigir_sin_original(banco)


def _vivo(pid: int) -> bool:
    return Path(f"/proc/{pid}").exists()


def _matar(pid: int) -> None:
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass


def test_inv09_control_un_hijo_valido_termina_en_limpio(banco, tmp_path):
    """Control positivo: el sustituto llega a `limpio` y se entrega lo que él escribió."""
    comando = hijo_falso(tmp_path, _imprimir(RESPUESTA_LIMPIO))
    contenido = png()
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id, final = cliente.analizar(contenido, tope=TOPE_HIJO_FALSO_S)
        assert final["estado"] == "limpio"
        assert final["tipo_detectado"] == "image/png"
        assert cliente.descargar(archivo_id).content == contenido


def test_inv09_control_un_hijo_que_rechaza_termina_en_rechazado(banco, tmp_path):
    comando = hijo_falso(tmp_path, _imprimir(RESPUESTA_RECHAZADO))
    with banco.api(comando_cdr=comando) as cliente:
        _, final = cliente.analizar(png(), tope=TOPE_HIJO_FALSO_S)
    assert final["estado"] == "rechazado"


@pytest.mark.parametrize("cuerpo", FALLOS.values(), ids=FALLOS.keys())
def test_inv09_fallo_del_hijo_termina_en_error(banco, tmp_path, cuerpo):
    comando = hijo_falso(tmp_path, cuerpo)
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id = cliente.subir(png())
        _exigir_error(cliente, banco, archivo_id)


def test_inv09_comando_que_no_arranca_termina_en_error(banco, tmp_path):
    """Una excepción en el padre, antes de haber hijo: el archivo no queda en `pendiente`."""
    with banco.api(comando_cdr=(str(tmp_path / "no_existe"),)) as cliente:
        archivo_id = cliente.subir(png())
        _exigir_error(cliente, banco, archivo_id)


@pytest.mark.parametrize(
    "respuesta",
    [
        {"veredicto": "rechazado", "tipo": "image/png", "motivo": "\u0000"},
        {"veredicto": "rechazado", "tipo": "x" * 5000, "motivo": "tipo"},
        {"veredicto": "rechazado", "tipo": "image/png", "motivo": "m" * 100_000},
    ],
    ids=[
        "motivo_con_nul",
        "tipo_mas_largo_que_la_columna",
        "motivo_mayor_que_el_tope_de_detalle",
    ],
)
def test_inv09_lo_que_la_bd_no_admite_no_deja_el_archivo_en_pendiente(
    banco, tmp_path, respuesta
):
    """Un `DataError` al guardar no es un `IntegrityError`: si nadie lo maneja, la tarea muere."""
    comando = hijo_falso(tmp_path, _imprimir(json.dumps(respuesta)))
    with banco.api(comando_cdr=comando) as cliente:
        archivo_id = cliente.subir(png())
        final = cliente.esperar(archivo_id, tope=TOPE_HIJO_FALSO_S)
        assert final["estado"] in ("rechazado", "error"), (
            f"estado final: {final['estado']}"
        )
        exigir_conflicto(cliente.descargar(archivo_id))


def test_inv09_stderr_no_llega_al_cliente_ni_atasca_el_analisis(banco, tmp_path):
    """Diseño §5. 2 MiB no caben en el búfer de una tubería: quien no la lee se queda esperando."""
    token = marca()
    cuerpo = (
        f"{COPIAR_SALIDA}sys.stderr.write({token!r} * 200000)\nsys.stderr.flush()\n"
        f"print({RESPUESTA_RECHAZADO!r})\n"
    )
    with banco.api(comando_cdr=hijo_falso(tmp_path, cuerpo)) as cliente:
        archivo_id = cliente.subir(png())
        final = cliente.esperar(archivo_id, tope=TOPE_HIJO_FALSO_S)
        assert final["estado"] == "rechazado"
        assert token not in cliente.ver(archivo_id).text
        assert token not in cliente.descargar(archivo_id).text


# ------------------------------------------------------------------------------- F3.08: el timeout


@pytest.mark.parametrize(
    "preparar",
    ["", "import signal\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n"],
    ids=["normal", "ignora_sigterm"],
)
def test_f308_al_vencer_el_timeout_se_mata_al_hijo_y_termina_en_error(
    banco, tmp_path, preparar
):
    """K09: `kill`, no `terminate`. El límite corre desde el padre, no en el hijo."""
    archivo_pid = tmp_path / "pid"
    cuerpo = (
        f"{COPIAR_SALIDA}{preparar}import os, pathlib, time\n"
        f"pathlib.Path({str(archivo_pid)!r}).write_text(str(os.getpid()))\n"
        f"print({RESPUESTA_LIMPIO!r}, flush=True)\n"
        "time.sleep(20)\n"
    )
    with banco.api(
        comando_cdr=hijo_falso(tmp_path, cuerpo), timeout_cdr_s=0.5
    ) as cliente:
        archivo_id = cliente.subir(png())
        _exigir_error(cliente, banco, archivo_id)
        pid = int(archivo_pid.read_text())
        try:
            esperar_que(lambda: not _vivo(pid), "el hijo sigue vivo tras el timeout")
        finally:
            _matar(pid)


def test_f308_un_nieto_con_stdout_abierto_no_impide_el_error(banco, tmp_path):
    """Matar al hijo no cierra la tubería si un nieto la conserva: el padre no debe esperarla."""
    archivo_pid = tmp_path / "pid_nieto"
    cuerpo = (
        f"{COPIAR_SALIDA}import os, pathlib, time\n"
        "if os.fork() == 0:\n"
        f"    pathlib.Path({str(archivo_pid)!r}).write_text(str(os.getpid()))\n"
        "    time.sleep(20)\n"
        "    os._exit(0)\n"
        "time.sleep(20)\n"
    )
    with banco.api(
        comando_cdr=hijo_falso(tmp_path, cuerpo), timeout_cdr_s=0.5
    ) as cliente:
        archivo_id = cliente.subir(png())
        try:
            _exigir_error(cliente, banco, archivo_id)
        finally:
            if archivo_pid.exists():
                _matar(int(archivo_pid.read_text()))


def test_f308_el_timeout_por_defecto_es_30_s():
    """param:timeout_analisis_por_archivo. Las pruebas lo acortan solo por la costura."""
    campos = {campo.name: campo for campo in dataclasses.fields(Ajustes)}
    if "timeout_cdr_s" not in campos:
        pytest.fail(
            "control ausente: falta la costura de prueba timeout_cdr_s en Ajustes"
        )
    assert campos["timeout_cdr_s"].default == 30
    assert campos["comando_cdr"].default[-2:] == ("-m", "api.app.cdr_hijo")


def test_f308_la_costura_no_se_abre_desde_el_entorno(banco, monkeypatch):
    """Una variable de entorno que cambiara el comando sería ejecución de código por configuración."""
    campos = {campo.name: campo for campo in dataclasses.fields(Ajustes)}
    if "comando_cdr" not in campos:
        pytest.fail(
            "control ausente: falta la costura de prueba comando_cdr en Ajustes"
        )
    monkeypatch.setenv(
        "GATEKEEPER_DATABASE_URL", banco.url.render_as_string(hide_password=False)
    )
    monkeypatch.setenv("GATEKEEPER_PEPPER", banco.pepper.decode())
    monkeypatch.setenv("GATEKEEPER_DATOS", str(banco.datos))
    if banco.url_redis is not None:
        monkeypatch.setenv("GATEKEEPER_REDIS_URL", banco.url_redis)  # K59
    monkeypatch.setenv("GATEKEEPER_COMANDO_CDR", "/bin/true")
    monkeypatch.setenv("GATEKEEPER_TIMEOUT_CDR_S", "9999")

    ajustes = leer_ajustes()

    assert ajustes.comando_cdr == campos["comando_cdr"].default
    assert ajustes.timeout_cdr_s == campos["timeout_cdr_s"].default


# ------------------------------------------------------------------------------- con el hijo real


@pytest.mark.parametrize(
    ("contenido", "nombre"),
    [
        (png()[:40], b"foto.png"),
        (png()[: len(png()) // 2], b"foto.png"),
        (jpeg()[: len(jpeg()) // 2], b"foto.jpg"),
    ],
    ids=["png_sin_datos", "png_cortado", "jpeg_cortado"],
)
def test_inv09_imagen_truncada_nunca_termina_en_limpio(
    cliente, banco, contenido, nombre
):
    """`ImageFile.LOAD_TRUNCATED_IMAGES` rellenaría lo que falta y daría por buena la imagen."""
    archivo_id, final = cliente.analizar(contenido, nombre)
    assert final["estado"] in ("rechazado", "error"), f"estado final: {final['estado']}"
    exigir_conflicto(cliente.descargar(archivo_id))
    exigir_sin_original(banco)
