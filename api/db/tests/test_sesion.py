"""Sesión asíncrona (F1.07, K23): motor con ``postgresql+psycopg`` y fábrica de sesiones."""

import asyncio
import secrets
import socket
import time

import pytest
from sqlalchemy import insert, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.exc import TimeoutError as TimeoutDelPool
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)

from api.db.config import ConfiguracionBDError
from api.db.modelos import ApiKey, Aplicacion
from api.db.sesion import crear_motor

pytestmark = pytest.mark.anyio

# Por encima de los 5 s de cada timeout y por debajo de los 30 s del pool por omisión.
TOPE_DE_LA_PRUEBA_S = 8


async def test_el_motor_es_asincrono_y_habla_con_postgres_16(
    motor: AsyncEngine,
) -> None:
    assert isinstance(motor, AsyncEngine)
    assert motor.dialect.driver == "psycopg"
    async with motor.connect() as con:
        version = (await con.execute(text("SHOW server_version"))).scalar_one()
    assert version.startswith("16.")


async def test_la_fabrica_entrega_sesiones_que_confirman(
    sesiones: async_sessionmaker[AsyncSession],
) -> None:
    async with sesiones() as sesion:
        assert isinstance(sesion, AsyncSession)
        resultado = await sesion.execute(text("SELECT 1"))
        assert resultado.scalar_one() == 1


async def test_las_filas_no_caducan_al_confirmar(
    sesiones: async_sessionmaker[AsyncSession],
) -> None:
    # Con asyncio, leer un atributo caducado dispara E/S implícita y falla.
    assert sesiones.kw["expire_on_commit"] is False


def _url_con_credencial(driver: str, contrasena: str) -> URL:
    # Se arma en ejecución: el control de secretos no admite esta forma como literal.
    return URL.create(
        driver,
        username="usuario",
        password=contrasena,
        host="127.0.0.1",
        database="gk",
    )


def _url_con_ruta(driver: str, contrasena: str) -> URL:
    # SQLite no tiene credenciales: lo sensible puede venir en la ruta.
    return URL.create(driver, database=f"usuario:{contrasena}")


@pytest.mark.parametrize(
    ("armar", "driver"),
    [
        (_url_con_credencial, "postgresql"),
        (_url_con_credencial, "postgresql+asyncpg"),
        (_url_con_ruta, "sqlite+aiosqlite"),
    ],
)
@pytest.mark.parametrize("como_texto", [True, False], ids=["texto", "objeto"])
def test_otro_driver_se_rechaza_sin_mostrar_la_url(
    armar, driver: str, como_texto: bool
) -> None:
    contrasena = secrets.token_urlsafe(16)
    url = armar(driver, contrasena)
    texto = url.render_as_string(hide_password=False)
    assert contrasena in texto, "la prueba debe llevar la contraseña al error"

    with pytest.raises(ConfiguracionBDError) as error:
        crear_motor(texto if como_texto else url)

    assert contrasena not in str(error.value)
    assert contrasena not in repr(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_acepta_url_como_objeto() -> None:
    # Las pruebas la pasan como URL porque ese objeto oculta la contraseña en su repr.
    url = URL.create("postgresql+psycopg", host="127.0.0.1", database="gk")
    assert crear_motor(url).dialect.driver == "psycopg"


# --- CWE-532: los parámetros no salen en los errores ---------------------------------


async def test_un_choque_de_restriccion_no_muestra_el_hash(
    sesiones: async_sessionmaker[AsyncSession],
) -> None:
    # Va por SQL directo, sin el repositorio, para probar el motor. El choque es por el
    # prefijo: el DETAIL de PostgreSQL solo nombra esa clave, así que el hash solo podría
    # salir por los [parameters] que SQLAlchemy agrega al texto del error.
    prefijo = f"gk_{secrets.token_hex(6)}"
    hash_nuevo = secrets.token_hex(32)
    async with sesiones.begin() as sesion:
        app_id = (
            await sesion.execute(
                insert(Aplicacion).values(nombre="motor").returning(Aplicacion.id)
            )
        ).scalar_one()
        await sesion.execute(
            insert(ApiKey).values(
                aplicacion_id=app_id, prefijo=prefijo, hash=secrets.token_hex(32)
            )
        )

    with pytest.raises(IntegrityError) as error:
        async with sesiones.begin() as sesion:
            await sesion.execute(
                insert(ApiKey).values(
                    aplicacion_id=app_id, prefijo=prefijo, hash=hash_nuevo
                )
            )

    assert hash_nuevo not in str(error.value)
    assert "hidden" in str(error.value), "SQLAlchemy debe decir que los ocultó"


async def test_un_error_cualquiera_tampoco_muestra_los_parametros(
    sesiones: async_sessionmaker[AsyncSession],
) -> None:
    marca = secrets.token_hex(16)
    with pytest.raises(DBAPIError) as error:
        async with sesiones() as sesion:
            await sesion.execute(
                text("SELECT 1 / 0, CAST(:marca AS text)"), {"marca": marca}
            )
    assert marca not in str(error.value)


# --- Timeouts: 5 s en los tres (decisión del usuario) --------------------------------


async def test_cada_sesion_lee_statement_timeout_de_5_s(
    sesiones: async_sessionmaker[AsyncSession],
) -> None:
    async with sesiones() as sesion:
        valor = (await sesion.execute(text("SHOW statement_timeout"))).scalar_one()
    assert valor == "5s"


async def test_el_statement_timeout_sobrevive_al_volver_al_pool(
    motor: AsyncEngine,
) -> None:
    # Se pone al conectar: no debe perderse con el rollback al devolver la conexión.
    for _ in range(2):
        async with motor.connect() as con:
            valor = (await con.execute(text("SHOW statement_timeout"))).scalar_one()
            assert valor == "5s"
            await con.rollback()


async def test_una_consulta_de_6_s_se_corta(
    sesiones: async_sessionmaker[AsyncSession],
) -> None:
    inicio = time.perf_counter()
    with pytest.raises(OperationalError) as error:
        async with sesiones() as sesion:
            await sesion.execute(text("SELECT pg_sleep(6)"))
    transcurrido = time.perf_counter() - inicio

    assert error.value.orig is not None
    assert error.value.orig.sqlstate == "57014"  # type: ignore[attr-defined]
    assert 4.5 < transcurrido < 5.9


async def test_conectar_a_un_servidor_mudo_se_corta_a_los_5_s() -> None:
    # Un socket que escucha y nunca responde: el TCP conecta, PostgreSQL no contesta.
    with socket.socket() as mudo:
        mudo.bind(("127.0.0.1", 0))
        mudo.listen()
        motor = crear_motor(
            URL.create(
                "postgresql+psycopg",
                username="nadie",
                host="127.0.0.1",
                port=mudo.getsockname()[1],
                database="gk",
            )
        )
        inicio = time.perf_counter()
        try:
            # Sin connect_timeout esto esperaría para siempre: el tope hace que la prueba
            # falle en vez de colgar la suite.
            async with asyncio.timeout(TOPE_DE_LA_PRUEBA_S):
                with pytest.raises(OperationalError):
                    async with motor.connect():
                        pytest.fail("no debió conectar")
        finally:
            await motor.dispose()
    assert 4.5 < time.perf_counter() - inicio < 5.9


async def test_esperar_una_conexion_del_pool_se_corta_a_los_5_s(
    motor: AsyncEngine,
) -> None:
    abiertas: list[AsyncConnection] = []
    try:
        # Tamaño del pool por omisión de SQLAlchemy: 5 + 10 de desborde.
        for _ in range(15):
            abiertas.append(await motor.connect())

        inicio = time.perf_counter()
        async with asyncio.timeout(TOPE_DE_LA_PRUEBA_S):
            with pytest.raises(TimeoutDelPool):
                await motor.connect()
        assert 4.5 < time.perf_counter() - inicio < 5.9
    finally:
        for con in abiertas:
            await con.close()
