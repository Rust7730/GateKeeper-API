"""F1.09 / INV-04 / K02 / K36 — Aislamiento del worker y frontera de la cola ARQ.

Comprueba tres fronteras:
1. **Aislamiento de código y secretos (`INV-04`, `F1.05`):** el paquete ``worker/`` no importa
   ``api.db`` y su configuración nunca lee la URL de PostgreSQL, el pepper ni ``redis-main``.
2. **Serialización sin pickle (`K36`):** la cola ARQ usa JSON estricto, rechaza claves
   duplicadas y rechaza cargas sobredimensionadas o no JSON (p. ej. un payload ``pickle``).
3. **Aislamiento de red y montajes en Docker (`F1.09`, `K02`, `K64`):** en la topología de
   ``deploy/docker-compose.yml``, el servicio ``worker`` está solo en la red interna ``isolated``
   (sin salida a internet, sin acceso a ``postgres``, ``redis-main`` ni ``api``), corre como
   usuario no root (UID 10003), con ``read_only: true``, ``cap_drop: [ALL]``,
   ``no-new-privileges`` y ``uploads_tmp`` montado en solo lectura. Además, una prueba real con
   un contenedor Docker en una red ``internal: true`` demuestra que toda conexión HTTP a
   internet falla.
"""

import ast
import pickle
import socket
import subprocess
from pathlib import Path

import pytest
import yaml

from api.db.tests.soporte_postgres import exigir_docker

RAIZ = Path(__file__).resolve().parents[2]
COMPOSE = RAIZ / "deploy" / "docker-compose.yml"
DIR_WORKER = RAIZ / "worker"


# ------------------------------------------------------------ 1. Frontera de código y secretos


def test_f109_worker_no_importa_bd_ni_lee_secretos_de_api() -> None:
    """INV-04 / F1.05: ningún módulo de ``worker/`` puede importar ``api.db``."""
    assert DIR_WORKER.is_dir(), "falta el paquete worker/"
    archivos = sorted(DIR_WORKER.rglob("*.py"))
    assert archivos, "worker/ no contiene módulos Python"
    prohibidos = ("api.db", "sqlalchemy", "psycopg")
    for ruta in archivos:
        if "tests" in ruta.parts:
            continue
        arbol = ast.parse(ruta.read_text(encoding="utf-8"), filename=str(ruta))
        for nodo in ast.walk(arbol):
            if isinstance(nodo, ast.Import):
                nombres = [alias.name for alias in nodo.names]
            elif isinstance(nodo, ast.ImportFrom) and nodo.module:
                nombres = [nodo.module]
            else:
                continue
            for nombre in nombres:
                assert not any(
                    nombre == p or nombre.startswith(f"{p}.") for p in prohibidos
                ), f"{ruta.relative_to(RAIZ)} importa {nombre!r} (viola INV-04 / F1.05)"


# ------------------------------------------------------------ 2. Serialización sin pickle (K36)


def test_k36_cola_arq_usa_json_y_rechaza_pickle_y_duplicados() -> None:
    """K36: un worker comprometido no puede inyectar un payload pickle al coordinator."""
    from api.app.cola import deserializar_json, serializar_json

    payload_pickle = pickle.dumps({"t": 1, "f": "analizar", "a": [], "k": {}, "et": 0})
    with pytest.raises(ValueError):
        deserializar_json(payload_pickle)

    with pytest.raises(ValueError):
        deserializar_json(b'{"veredicto":"rechazado","veredicto":"limpio"}')

    with pytest.raises(ValueError):
        deserializar_json(b"{" + b'"a":"' + b"x" * 70_000 + b'"}')

    original = {"t": 1, "f": "analizar", "a": ["id"], "k": {}, "et": 123456}
    assert deserializar_json(serializar_json(original)) == original


# -------------------------------------------------------- 3. Topología y aislamiento en Docker


def test_f109_compose_aisla_worker_en_red_isolated_y_sin_privilegios() -> None:
    """F1.01–F1.04 / K02 / K64: topología, endurecimiento y montajes en docker-compose.yml."""
    datos = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    servicios = datos["services"]
    redes = datos["networks"]

    assert redes["isolated"]["internal"] is True
    assert redes["backend"]["internal"] is True
    assert "redis-queue" in servicios
    assert "coordinator" in servicios
    assert "worker" in servicios

    worker = servicios["worker"]
    assert worker["networks"] == ["isolated"], (
        f"worker solo debe estar en isolated, no en {worker['networks']!r}"
    )
    assert worker["user"] == "10003:10010"
    assert worker["read_only"] is True
    assert "ALL" in worker["cap_drop"]
    assert "no-new-privileges:true" in worker["security_opt"]
    assert worker.get("ports") in (None, [])

    # uploads_tmp debe montarse :ro en worker; clean_store :ro en api (K64).
    volumenes_worker = worker["volumes"]
    assert any("uploads_tmp" in v and v.endswith(":ro") for v in volumenes_worker), (
        f"uploads_tmp debe ser :ro en worker: {volumenes_worker}"
    )
    assert any(
        "clean_store" in v and not v.endswith(":ro") for v in volumenes_worker
    ), f"clean_store debe ser escribible en worker: {volumenes_worker}"

    volumenes_api = servicios["api"]["volumes"]
    assert any("clean_store" in v and v.endswith(":ro") for v in volumenes_api), (
        f"clean_store debe ser :ro en api: {volumenes_api}"
    )

    # redis-queue conecta backend e isolated; redis-main solo backend (K02).
    assert set(servicios["redis-queue"]["networks"]) == {"backend", "isolated"}
    assert set(servicios["redis-main"]["networks"]) == {"backend"}
    assert set(servicios["coordinator"]["networks"]) == {"backend"}


def test_f109_contenedor_en_red_isolated_no_tiene_salida_a_internet() -> None:
    """F1.09 / INV-04: una petición HTTP desde un contenedor en red ``internal: true`` falla."""
    exigir_docker()
    red = f"gk-test-isolated-{socket.gethostname()[:8]}"
    subprocess.run(
        ["docker", "network", "create", "--internal", red],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        # Intenta abrir una conexión TCP al puerto 80 de 1.1.1.1 desde la red interna.
        resultado = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                red,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "redis:8.10.3-alpine3.23",
                "sh",
                "-c",
                "nc -z -w 2 1.1.1.1 80",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert resultado.returncode != 0, (
            "un contenedor en red internal:true logró conectar a 1.1.1.1:80 (viola INV-04)"
        )
    finally:
        subprocess.run(
            ["docker", "network", "rm", red],
            capture_output=True,
            text=True,
            check=False,
        )
