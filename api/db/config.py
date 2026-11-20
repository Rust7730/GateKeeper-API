"""URLs de la base de datos, leídas solo del entorno.

- ``url_bd()``: la usa la API con el rol ``gk_app`` (permisos mínimos, nunca dueño).
- ``url_migraciones()``: la usa Alembic con el rol dueño del esquema.

No hay valor por defecto: una URL inventada en el código sería una credencial en el
repositorio o una conexión silenciosa a la base equivocada. Los mensajes de error
nombran la variable pero nunca muestran su valor, porque la URL lleva la contraseña.
El único esquema aceptado es ``postgresql+psycopg://`` (K23: psycopg 3, asíncrono).
Un valor con espacio en blanco al inicio o al final se rechaza; no se recorta.

- ``rol_app()``: el nombre del rol de la API al que la migración 0002 da permisos. Este sí
  tiene valor por defecto (``gk_app``, el del diseño de F1.07 §4): no es una credencial.
"""

import os
import re

VARIABLE_URL_BD = "GATEKEEPER_DATABASE_URL"
VARIABLE_URL_MIGRACION = "GATEKEEPER_DATABASE_URL_MIGRACION"
ESQUEMA_PERMITIDO = "postgresql+psycopg://"
VARIABLE_ROL_APP = "GATEKEEPER_ROL_APP"
ROL_APP_POR_DEFECTO = "gk_app"
# Identificador simple de PostgreSQL en minúsculas y ASCII: no necesita comillas y cabe en
# los 63 bytes de NAMEDATALEN. Así lo que se valida es exactamente lo que se cita después.
_ROL_VALIDO = re.compile(r"[a-z_][a-z0-9_]{0,62}")
# pg_* lo reserva PostgreSQL para sus roles; public es la palabra de PUBLIC en un GRANT.
_ROLES_RESERVADOS = ("public", "none", "current_role", "current_user", "session_user")


class ConfiguracionBDError(RuntimeError):
    """Falta la URL de la base de datos o no es válida. El mensaje no incluye el valor."""


def _leer_url(variable: str) -> str:
    valor = os.environ.get(variable)
    if valor is None or not valor.strip():
        raise ConfiguracionBDError(
            f"Falta la variable de entorno {variable} o está vacía; "
            "no hay valor por defecto para la URL de la base de datos."
        )
    if valor != valor.strip():
        # Se rechaza en vez de recortar: un salto de línea final suele venir de un
        # archivo de secretos mal escrito, y recortarlo en silencio ocultaría el error.
        # Va antes de la del esquema para que un espacio al inicio se reporte como tal.
        raise ConfiguracionBDError(
            f"La variable de entorno {variable} tiene espacios en blanco al inicio o al "
            "final (espacios, tabuladores o saltos de línea) "
            "(el valor no se muestra porque puede contener credenciales)."
        )
    if not valor.startswith(ESQUEMA_PERMITIDO):
        raise ConfiguracionBDError(
            f"La variable de entorno {variable} debe empezar con {ESQUEMA_PERMITIDO} "
            "(el valor no se muestra porque puede contener credenciales)."
        )
    return valor


def url_bd() -> str:
    """URL de la API (rol ``gk_app``), desde ``GATEKEEPER_DATABASE_URL``."""
    return _leer_url(VARIABLE_URL_BD)


def url_migraciones() -> str:
    """URL de Alembic (rol dueño), desde ``GATEKEEPER_DATABASE_URL_MIGRACION``."""
    return _leer_url(VARIABLE_URL_MIGRACION)


def _validar_rol(valor: str) -> str:
    if (
        not _ROL_VALIDO.fullmatch(valor)
        or valor.startswith("pg_")
        or valor in _ROLES_RESERVADOS
    ):
        # Sin el valor: puede traer saltos de línea o texto de otro (CWE-117).
        raise ConfiguracionBDError(
            f"La variable de entorno {VARIABLE_ROL_APP} no es un nombre de rol válido: "
            "debe ser un identificador simple de PostgreSQL (a-z, 0-9 y _, sin empezar "
            "con dígito ni con pg_, hasta 63 caracteres)."
        )
    return valor


def rol_app() -> str:
    """Rol de la API para la migración 0002, desde ``GATEKEEPER_ROL_APP``.

    Sin la variable es ``gk_app``. Definida, se valida tal cual (vacía también es error:
    una variable vacía es un error de configuración, no una petición del valor por
    defecto). Lanza ``ConfiguracionBDError`` sin repetir el valor.
    """
    valor = os.environ.get(VARIABLE_ROL_APP)
    if valor is None:
        return ROL_APP_POR_DEFECTO
    return _validar_rol(valor)
