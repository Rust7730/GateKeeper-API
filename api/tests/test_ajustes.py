"""Configuración de la API (diseño §2): falla al arrancar y nunca muestra un valor."""

import dataclasses
import math
import os
import secrets
import stat
import string
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from api.app.ajustes import (
    CLEAN_STORE,
    UPLOADS_TMP,
    VARIABLE_DATOS,
    VARIABLE_HMAC,
    VARIABLE_REDIS,
    Ajustes,
    ConfiguracionError,
    leer_ajustes,
    leer_pepper,
    preparar_directorios,
)
from api.app.arranque import VARIABLES_SECRETAS
from api.db.config import VARIABLE_URL_BD, ConfiguracionBDError
from api.tests.soporte_api import url_sin_servidor

# Datos de prueba generados en cada corrida. PEPPER_VALIDO mide 32 bytes y PEPPER_CORTO, 30.
CONTRASENA_BD = secrets.token_urlsafe(24)
URL_FALSA = url_sin_servidor(CONTRASENA_BD)
PEPPER_VALIDO = secrets.token_hex(16).encode()
PEPPER_CORTO = secrets.token_hex(15)
RUTA_SECRETA = secrets.token_hex(11)
CONTRASENA_REDIS = secrets.token_hex(16)
# En el puerto 1 no escucha nadie; aquí solo se construyen ajustes.
URL_REDIS_FALSA = f"redis://gatekeeper:{CONTRASENA_REDIS}@127.0.0.1:1/0"


def _ajustes(pepper: object = PEPPER_VALIDO, datos: Path = Path("/x/d")) -> Ajustes:
    return Ajustes(url_bd=URL_FALSA, pepper=pepper, datos=datos, url_redis=URL_REDIS_FALSA)  # type: ignore[arg-type]


def _multibyte(caracteres: int) -> str:
    """Texto aleatorio en el que cada carácter ocupa dos bytes en UTF-8."""
    return "".join(secrets.choice("áéíóúñ") for _ in range(caracteres))


def _texto_completo(error: BaseException) -> str:
    """El mensaje del error y el de toda su cadena, donde también se fugaría un valor."""
    partes = []
    actual: BaseException | None = error
    while actual is not None:
        partes.append(f"{actual!r} {actual}")
        actual = actual.__cause__ or actual.__context__
    return " ".join(partes)


@pytest.fixture
def entorno(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> pytest.MonkeyPatch:
    monkeypatch.setenv(VARIABLE_URL_BD, URL_FALSA)
    monkeypatch.setenv(VARIABLE_HMAC, PEPPER_VALIDO.decode())
    monkeypatch.setenv(VARIABLE_DATOS, str(tmp_path / "datos"))
    monkeypatch.setenv(VARIABLE_REDIS, URL_REDIS_FALSA)
    return monkeypatch


# ------------------------------------------------------------------------ Ajustes


def test_ajustes_guarda_los_valores() -> None:
    ajustes = _ajustes(datos=Path("/x/d"))
    assert ajustes.url_bd == URL_FALSA
    assert ajustes.pepper == PEPPER_VALIDO
    assert ajustes.datos == Path("/x/d")


def test_ajustes_deriva_las_rutas_de_los_directorios() -> None:
    ajustes = _ajustes(datos=Path("/x/d"))
    assert ajustes.uploads_tmp == Path("/x/d") / UPLOADS_TMP
    assert ajustes.clean_store == Path("/x/d") / CLEAN_STORE


def test_el_repr_no_muestra_pepper_ni_url() -> None:
    pepper = secrets.token_hex(20).encode()
    texto = repr(_ajustes(pepper=pepper))
    assert pepper.decode()[:8] not in texto
    assert CONTRASENA_BD not in texto


def test_pepper_de_32_bytes_es_el_minimo() -> None:
    assert len(PEPPER_VALIDO) == 32
    assert _ajustes(pepper=PEPPER_VALIDO).pepper == PEPPER_VALIDO
    with pytest.raises(ConfiguracionError):
        _ajustes(pepper=PEPPER_VALIDO[:31])


@pytest.mark.parametrize(
    "pepper",
    [PEPPER_VALIDO.decode(), None, secrets.randbits(32), bytearray(PEPPER_VALIDO)],
    ids=["texto", "nada", "numero", "bytearray"],
)
def test_pepper_que_no_es_bytes_se_rechaza(pepper: object) -> None:
    with pytest.raises(ConfiguracionError):
        _ajustes(pepper=pepper)


@pytest.mark.parametrize(
    ("antes", "despues"), [(b" ", b""), (b"", b"\n")], ids=["inicio", "final"]
)
def test_pepper_con_bordes_en_blanco_se_rechaza(antes: bytes, despues: bytes) -> None:
    # Sin el borde mide 32 bytes: lo único que puede rechazarlo es el espacio en blanco.
    with pytest.raises(ConfiguracionError) as error:
        _ajustes(pepper=antes + PEPPER_VALIDO + despues)
    assert PEPPER_VALIDO.decode()[:8] not in _texto_completo(error.value)


@pytest.mark.parametrize("url", ["", None])
def test_url_faltante_se_rechaza(url: object) -> None:
    with pytest.raises(ConfiguracionError):
        Ajustes(url_bd=url, pepper=PEPPER_VALIDO, datos=Path("/x/d"), url_redis=URL_REDIS_FALSA)  # type: ignore[arg-type]


@pytest.mark.parametrize("datos", ["", "/x/d", None])
def test_datos_que_no_es_path_se_rechaza(datos: object) -> None:
    with pytest.raises(ConfiguracionError):
        Ajustes(url_bd=URL_FALSA, pepper=PEPPER_VALIDO, datos=datos, url_redis=URL_REDIS_FALSA)  # type: ignore[arg-type]


@pytest.mark.parametrize("relativa", ["datos", "./datos", "../datos", "~/datos", ""])
def test_datos_relativo_se_rechaza(relativa: str) -> None:
    # Dependería del directorio de arranque y podría caer dentro del repositorio.
    with pytest.raises(ConfiguracionError, match=VARIABLE_DATOS):
        _ajustes(datos=Path(relativa))


# ------------------------------------------------------------------- lectura del entorno


def test_leer_ajustes_toma_los_tres_valores(
    entorno: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ajustes = leer_ajustes()
    assert ajustes.url_bd == URL_FALSA
    assert ajustes.pepper == PEPPER_VALIDO
    assert ajustes.datos == tmp_path / "datos"
    assert ajustes.url_redis == URL_REDIS_FALSA


@pytest.mark.parametrize("variable", [VARIABLE_HMAC, VARIABLE_DATOS, VARIABLE_REDIS])
@pytest.mark.parametrize("valor", [None, "", "   "])
def test_dato_faltante_nombra_la_variable(
    entorno: pytest.MonkeyPatch, variable: str, valor: str | None
) -> None:
    if valor is None:
        entorno.delenv(variable)
    else:
        entorno.setenv(variable, valor)
    with pytest.raises(ConfiguracionError, match=variable):
        leer_ajustes()


def test_url_faltante_en_el_entorno_falla_sin_mostrar_valores(
    entorno: pytest.MonkeyPatch,
) -> None:
    entorno.delenv(VARIABLE_URL_BD)
    with pytest.raises(ConfiguracionBDError) as error:
        leer_ajustes()
    assert PEPPER_VALIDO.decode() not in _texto_completo(error.value)


def test_pepper_corto_falla_sin_mostrarlo(entorno: pytest.MonkeyPatch) -> None:
    entorno.setenv(VARIABLE_HMAC, PEPPER_CORTO)
    with pytest.raises(ConfiguracionError) as error:
        leer_ajustes()
    texto = _texto_completo(error.value)
    assert VARIABLE_HMAC in texto
    assert PEPPER_CORTO not in texto
    assert str(len(PEPPER_CORTO)) not in texto


def test_el_largo_del_pepper_se_cuenta_en_bytes_no_en_caracteres(
    entorno: pytest.MonkeyPatch,
) -> None:
    # 31 bytes en 16 caracteres: ni el conteo de caracteres ni el de bytes coinciden.
    entorno.setenv(VARIABLE_HMAC, _multibyte(15) + secrets.choice(string.ascii_letters))
    with pytest.raises(ConfiguracionError):
        leer_ajustes()
    exacto = _multibyte(16)
    entorno.setenv(VARIABLE_HMAC, exacto)
    assert leer_ajustes().pepper == exacto.encode()


def test_pepper_que_no_es_utf8_se_lee_como_bytes_crudos(
    entorno: pytest.MonkeyPatch,
) -> None:
    # 0xFF nunca es UTF-8 válido, y un byte alto no es NUL ni espacio en blanco.
    crudo = b"\xff" + bytes(0x80 + secrets.randbelow(0x80) for _ in range(39))
    entorno.setenv(VARIABLE_HMAC, os.fsdecode(crudo))
    assert leer_ajustes().pepper == crudo


def test_pepper_con_bordes_en_blanco_en_el_entorno_no_se_recorta(
    entorno: pytest.MonkeyPatch,
) -> None:
    entorno.setenv(VARIABLE_HMAC, PEPPER_VALIDO.decode() + "\n")
    with pytest.raises(ConfiguracionError, match=VARIABLE_HMAC):
        leer_ajustes()


def test_datos_con_bordes_en_blanco_falla_sin_mostrarlo(
    entorno: pytest.MonkeyPatch,
) -> None:
    entorno.setenv(VARIABLE_DATOS, f"/x/{RUTA_SECRETA}\n")
    with pytest.raises(ConfiguracionError) as error:
        leer_ajustes()
    assert RUTA_SECRETA not in _texto_completo(error.value)


def test_datos_relativo_en_el_entorno_falla_sin_mostrarlo(
    entorno: pytest.MonkeyPatch,
) -> None:
    entorno.setenv(VARIABLE_DATOS, f"{RUTA_SECRETA}/datos")
    with pytest.raises(ConfiguracionError) as error:
        leer_ajustes()
    texto = _texto_completo(error.value)
    assert VARIABLE_DATOS in texto
    assert RUTA_SECRETA not in texto


def test_leer_pepper_no_exige_las_otras_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(VARIABLE_DATOS, raising=False)
    monkeypatch.delenv(VARIABLE_URL_BD, raising=False)
    monkeypatch.setenv(VARIABLE_HMAC, PEPPER_VALIDO.decode())
    assert leer_pepper() == PEPPER_VALIDO


# --------------------------------------------------------------------------- directorios


def _modo(ruta: Path) -> int:
    return stat.S_IMODE(ruta.lstat().st_mode)


@pytest.fixture
def umask_abierta() -> Iterator[None]:
    anterior = os.umask(0)
    try:
        yield
    finally:
        os.umask(anterior)


@pytest.mark.usefixtures("umask_abierta")
def test_crea_los_directorios_con_0700_aunque_la_umask_sea_0(tmp_path: Path) -> None:
    datos = tmp_path / "base" / "datos"
    preparar_directorios(datos)
    assert _modo(datos / UPLOADS_TMP) == 0o700
    assert _modo(datos / CLEAN_STORE) == 0o700


def test_el_directorio_base_nuevo_nace_0700(tmp_path: Path) -> None:
    preparar_directorios(tmp_path / "datos")
    assert _modo(tmp_path / "datos") == 0o700


def test_no_cambia_el_modo_de_una_base_que_ya_existe(tmp_path: Path) -> None:
    tmp_path.chmod(0o750)
    preparar_directorios(tmp_path)
    assert _modo(tmp_path) == 0o750


def test_corrige_el_modo_de_directorios_que_ya_existian(tmp_path: Path) -> None:
    (tmp_path / UPLOADS_TMP).mkdir(mode=0o755)
    (tmp_path / CLEAN_STORE).mkdir(mode=0o777)
    preparar_directorios(tmp_path)
    assert _modo(tmp_path / UPLOADS_TMP) == 0o700
    assert _modo(tmp_path / CLEAN_STORE) == 0o700


def test_conserva_lo_que_ya_habia_en_los_directorios(tmp_path: Path) -> None:
    (tmp_path / CLEAN_STORE).mkdir()
    (tmp_path / CLEAN_STORE / "guardado").write_bytes(b"x")
    preparar_directorios(tmp_path)
    assert (tmp_path / CLEAN_STORE / "guardado").read_bytes() == b"x"


def test_es_idempotente(tmp_path: Path) -> None:
    preparar_directorios(tmp_path)
    preparar_directorios(tmp_path)
    assert _modo(tmp_path / UPLOADS_TMP) == 0o700


def test_un_enlace_simbolico_se_rechaza_y_no_toca_su_destino(tmp_path: Path) -> None:
    # Con chmod normal, el 0700 caería sobre el destino y uploads_tmp apuntaría fuera.
    destino = tmp_path / "publico"
    destino.mkdir(mode=0o755)
    datos = tmp_path / "datos"
    datos.mkdir()
    (datos / UPLOADS_TMP).symlink_to(destino)
    with pytest.raises(ConfiguracionError):
        preparar_directorios(datos)
    assert _modo(destino) == 0o755


def test_un_archivo_en_lugar_del_directorio_falla_sin_mostrar_la_ruta(
    tmp_path: Path,
) -> None:
    datos = tmp_path / RUTA_SECRETA
    datos.mkdir()
    (datos / CLEAN_STORE).write_bytes(b"x")
    with pytest.raises(ConfiguracionError) as error:
        preparar_directorios(datos)
    assert RUTA_SECRETA not in _texto_completo(error.value)


def test_una_base_que_es_archivo_falla_sin_mostrar_la_ruta(tmp_path: Path) -> None:
    datos = tmp_path / RUTA_SECRETA
    datos.write_bytes(b"x")
    with pytest.raises(ConfiguracionError) as error:
        preparar_directorios(datos)
    assert RUTA_SECRETA not in _texto_completo(error.value)


def test_una_ruta_con_nul_falla_como_configuracion(tmp_path: Path) -> None:
    with pytest.raises(ConfiguracionError):
        preparar_directorios(tmp_path / "con\0nul")


# ----------------------------------------------------------------- costura del proceso hijo


def test_el_comando_y_el_timeout_del_cdr_tienen_valor_por_defecto() -> None:
    ajustes = _ajustes()
    assert ajustes.comando_cdr == (sys.executable, "-m", "api.app.cdr_hijo")
    assert ajustes.timeout_cdr_s == 30


def test_el_tope_de_recepcion_tiene_valor_por_defecto() -> None:
    """K40: 60 s para recibir el cuerpo de `POST /v1/files`."""
    assert _ajustes().timeout_recepcion_s == 60


@pytest.mark.usefixtures("entorno")
def test_leer_ajustes_deja_la_costura_en_su_valor_por_defecto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GATEKEEPER_COMANDO_CDR", "/bin/true")
    monkeypatch.setenv("GATEKEEPER_TIMEOUT_CDR_S", "1")
    monkeypatch.setenv("GATEKEEPER_TIMEOUT_RECEPCION_S", "9999")
    assert leer_ajustes().comando_cdr == _ajustes().comando_cdr
    assert leer_ajustes().timeout_cdr_s == _ajustes().timeout_cdr_s
    assert leer_ajustes().timeout_recepcion_s == _ajustes().timeout_recepcion_s


@pytest.mark.parametrize(
    "comando",
    [(), [sys.executable], "python", ("",), (sys.executable, 1)],
    ids=["vacio", "lista", "texto", "vacio_dentro", "no_texto"],
)
def test_un_comando_invalido_no_crea_ajustes(comando: object) -> None:
    with pytest.raises(ConfiguracionError):
        Ajustes(
            url_bd=URL_FALSA,
            pepper=PEPPER_VALIDO,
            datos=Path("/x/d"),
            url_redis=URL_REDIS_FALSA,
            comando_cdr=comando,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "timeout",
    [0, -1, math.nan, math.inf, "30", True, None],
    ids=["cero", "negativo", "nan", "infinito", "texto", "booleano", "nulo"],
)
@pytest.mark.parametrize("campo", ["timeout_cdr_s", "timeout_recepcion_s"])
def test_un_timeout_invalido_no_crea_ajustes(timeout: object, campo: str) -> None:
    with pytest.raises(ConfiguracionError):
        Ajustes(
            url_bd=URL_FALSA,
            pepper=PEPPER_VALIDO,
            datos=Path("/x/d"),
            url_redis=URL_REDIS_FALSA,
            **{campo: timeout},  # type: ignore[arg-type]
        )


# ------------------------------------------------------------------ Redis (K59, K52)


def test_la_url_de_redis_es_obligatoria_y_no_sale_en_el_repr() -> None:
    campos = {campo.name: campo for campo in dataclasses.fields(Ajustes)}
    assert campos["url_redis"].repr is False
    assert campos["url_redis"].default is dataclasses.MISSING
    texto = repr(_ajustes())
    assert CONTRASENA_REDIS not in texto
    assert CONTRASENA_REDIS not in str(_ajustes())


@pytest.mark.parametrize(
    "url",
    ["", None, b"redis://x", f" {URL_REDIS_FALSA}", f"{URL_REDIS_FALSA}\n"],
    ids=["vacia", "nada", "bytes", "espacio_inicial", "salto_final"],
)
def test_una_url_de_redis_invalida_no_crea_ajustes_ni_se_muestra(url: object) -> None:
    with pytest.raises(ConfiguracionError, match=VARIABLE_REDIS) as error:
        Ajustes(
            url_bd=URL_FALSA,
            pepper=PEPPER_VALIDO,
            datos=Path("/x/d"),
            url_redis=url,  # type: ignore[arg-type]
        )
    assert CONTRASENA_REDIS not in _texto_completo(error.value)


@pytest.mark.parametrize("valor", [f" {URL_REDIS_FALSA}", f"{URL_REDIS_FALSA}\n"])
def test_la_url_de_redis_del_entorno_no_se_recorta_ni_se_muestra(
    entorno: pytest.MonkeyPatch, valor: str
) -> None:
    entorno.setenv(VARIABLE_REDIS, valor)
    with pytest.raises(ConfiguracionError, match=VARIABLE_REDIS) as error:
        leer_ajustes()
    assert CONTRASENA_REDIS not in _texto_completo(error.value)


def test_el_reloj_del_limite_es_time_time_y_no_se_lee_del_entorno(
    entorno: pytest.MonkeyPatch,
) -> None:
    entorno.setenv("GATEKEEPER_RELOJ_LIMITE", "0")
    assert _ajustes().reloj_limite is time.time
    assert leer_ajustes().reloj_limite is time.time


@pytest.mark.parametrize("reloj", [None, 0, "time.time"], ids=["nada", "numero", "texto"])
def test_un_reloj_que_no_se_puede_llamar_no_crea_ajustes(reloj: object) -> None:
    with pytest.raises(ConfiguracionError):
        Ajustes(
            url_bd=URL_FALSA,
            pepper=PEPPER_VALIDO,
            datos=Path("/x/d"),
            url_redis=URL_REDIS_FALSA,
            reloj_limite=reloj,  # type: ignore[arg-type]
        )


def test_k52_la_url_de_redis_es_un_secreto_de_los_ancestros() -> None:
    assert VARIABLE_REDIS == "GATEKEEPER_REDIS_URL"
    assert VARIABLE_REDIS in VARIABLES_SECRETAS
