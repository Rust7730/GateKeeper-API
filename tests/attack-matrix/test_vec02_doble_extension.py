"""vec:02 — Doble extensión (CWE-434). Resultado esperado en el KG: `rechazado`.

La extensión no decide nada (INV-02): un ejecutable con `.pdf` en medio se rechaza por sus bytes, y
una imagen real con `.php` al final no se rechaza por el nombre ni conserva esa extensión al
descargarse: la extensión de salida sale del tipo detectado (F3.03).
"""

import re

import pytest
from generadores import carga_php, jpeg, marca
from soporte_matriz import exigir_limpio, exigir_rechazado

PHP = carga_php("doble")
SHELL = b"#!/bin/sh\nid\n"
EJECUTABLE = b"\x7fELF\x02\x01\x01" + bytes(57)


@pytest.mark.parametrize(
    ("contenido", "nombre", "tipo"),
    [
        (PHP, b"foto.jpg.php", b"image/jpeg"),
        (PHP, b"shell.php.jpg", b"image/jpeg"),
        (EJECUTABLE, b"factura.pdf.exe", b"application/pdf"),
        (SHELL, b"imagen.png.sh", b"image/png"),
        (PHP, b"foto.php%00.jpg", b"image/jpeg"),
    ],
    ids=["jpg_php", "php_jpg", "pdf_exe", "png_sh", "nulo_codificado"],
)
def test_vec02_doble_extension_rechazado(cliente, banco, contenido, nombre, tipo):
    exigir_rechazado(cliente, banco, contenido, nombre, tipo)


def test_vec02_imagen_real_con_php_final_sale_con_la_extension_del_tipo(cliente, banco):
    """Control positivo de INV-02: el nombre no rechaza, y tampoco llega a la descarga."""
    token = marca()
    nombre = f"{token}.jpg.php".encode()
    archivo_id, _ = exigir_limpio(
        cliente, banco, jpeg(), nombre, b"application/x-php", "image/jpeg"
    )
    disposicion = cliente.descargar(archivo_id).headers["content-disposition"]
    assert re.fullmatch(rf'attachment; filename="{archivo_id}\.jpe?g"', disposicion)
