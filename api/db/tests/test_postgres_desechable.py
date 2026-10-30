"""Prueba de humo del PostgreSQL desechable de las pruebas (F1.07, commit 3).

Todas las pruebas de ``api/db/tests/`` corren contra un PostgreSQL 16 real en un
contenedor de Docker (testcontainers), uno por sesión de pytest. Nunca SQLite: tipos,
bloqueos y ``RETURNING`` se comportan distinto y la prueba no demostraría nada.

Aquí se comprueba que:
- el servidor es PostgreSQL 16 (``server_version_num`` en [160000, 170000));
- cada prueba corre en su propia transacción, que se revierte al terminar, de modo
  que lo que escribe una prueba no lo ve la siguiente;
- sin Docker, las pruebas que piden la BD fallan con un mensaje claro y nunca se omiten.
"""

import os
import secrets

# subprocess solo corre pytest en un proceso hijo, con argumentos fijos y sin shell.
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest
from sqlalchemy import Connection, text
from sqlalchemy.engine import URL

from api.db.tests.soporte_postgres import arrancar_contenedor

RAIZ_REPO = Path(__file__).resolve().parents[3]


def test_la_url_es_de_psycopg_y_no_muestra_la_contrasena(url_postgres: URL) -> None:
    assert url_postgres.drivername == "postgresql+psycopg"
    assert url_postgres.password, "el contenedor debe tener contraseña"
    # str() y repr() de la URL ocultan la contraseña: así no se filtra en un
    # traceback ni en un log por accidente.
    assert url_postgres.password not in str(url_postgres)
    assert url_postgres.password not in repr(url_postgres)


def test_el_servidor_es_postgresql_16(conexion: Connection) -> None:
    version = int(conexion.execute(text("SHOW server_version_num")).scalar_one())
    assert 160000 <= version < 170000, (
        f"se esperaba PostgreSQL 16, server_version_num={version}"
    )


@pytest.mark.parametrize("vuelta", ["primera", "segunda"])
def test_lo_escrito_en_una_prueba_no_se_ve_en_la_siguiente(
    conexion: Connection, vuelta: str
) -> None:
    """Las dos vueltas hacen lo mismo, así que el orden no importa.

    Cada una exige que la tabla no exista, la crea y escribe una fila. Si la
    transacción de la vuelta anterior no se hubiera revertido, la que corra después
    encontraría la tabla y fallaría.
    """
    # El nombre de la tabla va literal en cada sentencia: nada de armar SQL con texto (CWE-89).
    existente = conexion.execute(
        text("SELECT to_regclass('humo_aislamiento')")
    ).scalar_one()
    assert existente is None, f"humo_aislamiento quedó de otra prueba ({vuelta} vuelta)"

    conexion.execute(
        text(
            "CREATE TABLE humo_aislamiento (id integer PRIMARY KEY, vuelta text NOT NULL)"
        )
    )
    conexion.execute(
        text("INSERT INTO humo_aislamiento (id, vuelta) VALUES (1, :vuelta)"),
        {"vuelta": vuelta},
    )
    leida = conexion.execute(text("SELECT vuelta FROM humo_aislamiento")).scalar_one()
    assert leida == vuelta


def test_la_conexion_esta_dentro_de_una_transaccion(conexion: Connection) -> None:
    assert conexion.in_transaction()


def _correr_prueba_de_version_en_otro_pytest(entorno_extra: dict[str, str]) -> str:
    """Corre ``test_el_servidor_es_postgresql_16`` en un pytest hijo; exige que falle."""
    entorno = {**os.environ, **entorno_extra}
    prueba = (
        f"{Path(__file__).relative_to(RAIZ_REPO)}::test_el_servidor_es_postgresql_16"
    )
    resultado = subprocess.run(  # nosec B603
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rA", prueba],
        cwd=RAIZ_REPO,
        env=entorno,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    salida = resultado.stdout + resultado.stderr
    assert resultado.returncode != 0, salida
    assert "skipped" not in salida.lower(), salida
    assert "1 error" in salida or "1 failed" in salida, salida
    return salida


def test_sin_docker_las_pruebas_fallan_y_no_se_omiten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for variable in (
        "TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE",
        "TESTCONTAINERS_HOST_OVERRIDE",
        "TC_HOST",
    ):
        monkeypatch.delenv(variable, raising=False)
    salida = _correr_prueba_de_version_en_otro_pytest(
        {"DOCKER_HOST": f"unix://{tmp_path / 'no-hay-docker.sock'}"}
    )
    assert "Docker no está disponible" in salida, salida


class _ContenedorQueNoArranca:
    """Imita el error real de testcontainers 4.15 cuando vence la espera de PostgreSQL."""

    def __init__(self, contrasena: str) -> None:
        self.contrasena = contrasena
        self.detenido = False

    def start(self) -> object:
        raise TimeoutError(
            "Command execution did not succeed within 0.000 seconds. Command: sh -c "
            f"PGPASSWORD='{self.contrasena}' psql --username gk_pruebas --dbname gatekeeper_pruebas "
            "--host 127.0.0.1 -c 'select version();'."
        )

    def stop(self) -> None:
        self.detenido = True


def test_si_el_contenedor_no_arranca_falla_sin_mostrar_la_contrasena() -> None:
    contrasena = secrets.token_urlsafe(24)
    contenedor = _ContenedorQueNoArranca(contrasena)

    with pytest.raises(pytest.fail.Exception) as falla:
        arrancar_contenedor(contenedor, contrasena)

    mensaje = str(falla.value)
    assert "El PostgreSQL desechable no arrancó" in mensaje
    assert "TimeoutError" in mensaje
    assert "PGPASSWORD='***'" in mensaje
    assert contrasena not in mensaje
    assert contenedor.detenido, "el contenedor a medio crear se debe quitar"
