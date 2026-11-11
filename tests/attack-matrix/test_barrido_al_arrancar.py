"""F3.09 y retención (§6) — Al arrancar, la API barre los restos de un apagado anómalo.

Hallazgo media de la revisión de cierre: tras un SIGKILL quedaban los originales en `uploads_tmp`, los
`.parcial` en `clean_store` y las filas en `pendiente`, sin nada que los borrara nunca. Un original
que se queda para siempre contradice F3.09 ("el original se borra al terminar").

Esperado al arrancar: `uploads_tmp` vacío, ningún `.parcial`, y las filas `pendiente` en `error`.
Lo que ya terminó no se toca: un `limpio` se sigue descargando.

Los restos se siembran con la API apagada, como los dejaría el SIGKILL.
"""

import secrets

from generadores import png
from soporte_matriz import esperar_que, exigir_limpio, nombres

SUFIJO_PARCIAL = ".parcial"


def _preparar_directorios(banco) -> None:
    for directorio in (banco.uploads_tmp, banco.clean_store):
        directorio.mkdir(mode=0o700, parents=True, exist_ok=True)


def _restos_de_un_sigkill(banco) -> list[str]:
    """Filas `pendiente` de las dos aplicaciones, con su original y su `.parcial` en disco."""
    _preparar_directorios(banco)
    ids = []
    for app in (banco.app_a, banco.app_a, banco.app_b):
        archivo_id = banco.sembrar_archivo("pendiente", app)
        (banco.uploads_tmp / archivo_id).write_bytes(png())
        (banco.clean_store / f"{archivo_id}{SUFIJO_PARCIAL}").write_bytes(png())
        ids.append(archivo_id)
    return ids


def test_al_arrancar_se_borran_originales_y_parciales(banco):
    ids = _restos_de_un_sigkill(banco)
    # Un `.parcial` sin fila, de un hijo que ni llegó a dar veredicto.
    huerfano = f"{secrets.token_hex(16)}{SUFIJO_PARCIAL}"
    (banco.clean_store / huerfano).write_bytes(b"x")

    with banco.api():
        esperar_que(
            lambda: not nombres(banco.uploads_tmp) & set(ids),
            "los originales de un apagado anómalo siguen en uploads_tmp",
        )
        esperar_que(
            lambda: (
                not [
                    n for n in nombres(banco.clean_store) if n.endswith(SUFIJO_PARCIAL)
                ]
            ),
            "quedan .parcial en clean_store",
        )


def test_al_arrancar_los_pendientes_huerfanos_pasan_a_error(banco):
    ids = _restos_de_un_sigkill(banco)

    with banco.api() as cliente:
        esperar_que(
            lambda: all(banco.fila(i)["estado"] == "error" for i in ids),
            "las filas pendiente de antes del arranque no pasaron a error",
        )
        for archivo_id in ids:
            fila = banco.fila(archivo_id)
            assert fila["tipo_error"] is not None
            assert fila["analizado_en"] is not None
        assert cliente.descargar(ids[0]).status_code == 409


def test_control_el_barrido_no_toca_lo_terminado(banco):
    """Un `limpio` con su reconstrucción sigue descargándose; un `error` sigue igual."""
    _preparar_directorios(banco)
    limpio = banco.sembrar_archivo("limpio", banco.app_a)
    reconstruido = png()
    (banco.clean_store / limpio).write_bytes(reconstruido)
    con_error = banco.sembrar_archivo("error", banco.app_b)
    _restos_de_un_sigkill(banco)

    with banco.api() as cliente:
        esperar_que(lambda: not nombres(banco.uploads_tmp), "el barrido no se ejecutó")
        assert banco.fila(limpio)["estado"] == "limpio"
        descarga = cliente.descargar(limpio)
        assert descarga.status_code == 200
        assert descarga.content == reconstruido
        assert banco.fila(con_error)["estado"] == "error"


def test_control_tras_el_barrido_una_subida_nueva_se_analiza(banco):
    """El barrido es del arranque: no se lleva por delante lo que llega después."""
    _restos_de_un_sigkill(banco)
    with banco.api() as cliente:
        esperar_que(lambda: not nombres(banco.uploads_tmp), "el barrido no se ejecutó")
        exigir_limpio(cliente, banco, png(), b"foto.png", b"image/png", "image/png")
