"""K28, K31 y K09 — El CDR corre en un proceso hijo sin secretos, sin BD y con memoria limitada.

Estas pruebas usan el `api.app.cdr_hijo` real, envuelto en la sonda de `hijos.py`: solo así se ve lo que
el proceso tiene de verdad, porque `RLIMIT_AS` lo fija el propio hijo y un sustituto no lo tendría.

K28 cierra de forma temporal la desviación de INV-04: no hay aislamiento de red ni de sistema de
archivos, así que el hijo vale lo que valgan estos límites.
"""

import os
import secrets
import time
from pathlib import Path

import pytest
from generadores import guardar, marca, pdf_base, png
from hijos import hijo_con_puerta, leer_sonda, sonda_hijo_real
from soporte_matriz import UUID_RE, esperar_que, nombres

UN_GIB = 1024 * 1024 * 1024
TIPOS = [
    pytest.param(png, b"foto.png", b"image/png", "PIL", id="png"),
    pytest.param(
        lambda: guardar(pdf_base()), b"doc.pdf", b"application/pdf", "pikepdf", id="pdf"
    ),
]
MODULOS_DE_BD = ("api.db", "sqlalchemy", "psycopg", "psycopg_binary", "alembic")


@pytest.fixture
def entorno_sensible(banco, monkeypatch) -> dict[str, str]:
    """Todo lo que el proceso de la API tiene en su entorno y el hijo no debe heredar."""
    url = banco.url.render_as_string(hide_password=False)
    variables = {
        "GATEKEEPER_DATABASE_URL": url,
        "GATEKEEPER_DATABASE_URL_MIGRACION": url,
        "GATEKEEPER_PEPPER": banco.pepper.decode(),
        "GATEKEEPER_DATOS": str(banco.datos),
        "GATEKEEPER_DOCS": "1",
        "GATEKEEPER_CANARIO": marca(),
        # Nombres sin prefijo: una lista negra de `GATEKEEPER_*` los dejaría pasar.
        "DATABASE_URL": url,
        "PGPASSWORD": secrets.token_hex(16),
        "CANARIO_HEREDADO": marca(),
    }
    for nombre, valor in variables.items():
        monkeypatch.setenv(nombre, valor)
    return variables


def _correr_con_sonda(
    banco, tmp_path: Path, generar, nombre: bytes, tipo: bytes
) -> dict:
    comando, registro = sonda_hijo_real(tmp_path)
    with banco.api(comando_cdr=comando) as cliente:
        _, final = cliente.analizar(generar(), nombre, tipo)
    assert final["estado"] == "limpio"
    return leer_sonda(registro)


@pytest.mark.parametrize(("generar", "nombre", "tipo", "_modulo"), TIPOS)
def test_k28_el_hijo_no_hereda_secretos(
    banco, tmp_path, entorno_sensible, generar, nombre, tipo, _modulo
):
    sonda = _correr_con_sonda(banco, tmp_path, generar, nombre, tipo)

    entorno = sonda["entorno"]
    assert not [n for n in entorno if n.startswith("GATEKEEPER_")]
    heredadas = sorted(set(entorno_sensible) & set(entorno))
    assert not heredadas, f"variables heredadas: {heredadas}"
    # Por el valor, y sin mostrarlo: un secreto puede llegar con otro nombre. Los valores cortos,
    # como el `1` de GATEKEEPER_DOCS, aparecerían por casualidad en cualquier PATH.
    secretos = [valor for valor in entorno_sensible.values() if len(valor) >= 16]
    con_secreto = sorted(
        nombre_variable
        for nombre_variable, valor in entorno.items()
        if any(secreto in valor for secreto in secretos)
    )
    assert not con_secreto, f"variables con un valor secreto: {con_secreto}"


@pytest.mark.parametrize(("generar", "nombre", "tipo", "_modulo"), TIPOS)
def test_k28_el_hijo_no_tiene_acceso_a_la_bd(
    banco, tmp_path, generar, nombre, tipo, _modulo
):
    sonda = _correr_con_sonda(banco, tmp_path, generar, nombre, tipo)

    modulos = [m for m in sonda["modulos"] if m.startswith(MODULOS_DE_BD)]
    assert not modulos, f"el hijo importó la capa de BD: {modulos[:5]}"
    sockets = [
        destino
        for numero, destino in sonda["descriptores"].items()
        if int(numero) > 2 and destino.startswith("socket:")
    ]
    assert not sockets, (
        "el hijo heredó sockets abiertos (la conexión a la BD, por ejemplo)"
    )


@pytest.mark.parametrize(("generar", "nombre", "tipo", "modulo"), TIPOS)
def test_k31_rlimit_as_de_1_gib_antes_de_importar_los_parsers(
    banco, tmp_path, generar, nombre, tipo, modulo
):
    """K31: el valor es 1 GiB. Se exige también el límite duro: uno blando se puede subir."""
    sonda = _correr_con_sonda(banco, tmp_path, generar, nombre, tipo)

    assert sonda["limite_as_final"] == [UN_GIB, UN_GIB]
    assert sonda["limite_core_final"] == [0, 0]
    al_importar = sonda["limites_al_importar"].get(modulo)
    assert al_importar is not None, f"el hijo real no importó {modulo}"
    assert al_importar["as"] == [UN_GIB, UN_GIB], f"{modulo} se importó sin el límite"
    assert al_importar["core"] == [0, 0]


def test_k28_el_hijo_solo_recibe_rutas_con_uuid(banco, tmp_path):
    """INV-03: el nombre original no llega ni como argumento, y sin shell no hay inyección."""
    comando, registro = sonda_hijo_real(tmp_path)
    token = marca()
    nombre = f"; touch {token} #.png".encode()
    with banco.api(comando_cdr=comando) as cliente:
        _, final = cliente.analizar(png(), nombre, b"image/png")
    assert final["estado"] == "limpio"

    argumentos = leer_sonda(registro)["argv"]
    assert len(argumentos) == 2
    assert UUID_RE.fullmatch(Path(argumentos[0]).name), (
        "la entrada debe ser uploads_tmp/<uuid>"
    )
    assert token not in " ".join(argumentos)
    assert not Path(token).exists()


def test_k09_como_mucho_un_hijo_por_nucleo(banco, tmp_path):
    """K09 (CWE-770): subir mucho a la vez no lanza procesos sin límite."""
    nucleos = os.cpu_count()
    comando, puerta, registro = hijo_con_puerta(tmp_path)
    with banco.api(comando_cdr=comando, timeout_cdr_s=25) as cliente:
        try:
            ids = [cliente.subir(png()) for _ in range(nucleos + 4)]
            esperar_que(
                lambda: len(nombres(registro)) >= nucleos,
                f"no llegaron a arrancar {nucleos} hijos a la vez",
            )
            # El semáforo se nota en lo que NO arranca: se da tiempo a que aparezca un hijo de más.
            time.sleep(0.3)
            assert len(nombres(registro)) == nucleos
        finally:
            puerta.touch()
        for archivo_id in ids:
            assert cliente.esperar(archivo_id, tope=25)["estado"] == "limpio"
