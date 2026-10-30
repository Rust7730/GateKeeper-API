"""URLs de la base de datos, leídas solo del entorno.

- ``url_bd()``: la usa la API con el rol ``gk_app`` (permisos mínimos, nunca dueño).
- ``url_migraciones()``: la usa Alembic con el rol dueño del esquema.

No hay valor por defecto: una URL inventada en el código sería una credencial en el
repositorio o una conexión silenciosa a la base equivocada. Los mensajes de error
nombran la variable pero nunca muestran su valor, porque la URL lleva la contraseña.
El único esquema aceptado es ``postgresql+psycopg://`` (K23: psycopg 3, asíncrono).
Un valor con espacio en blanco al inicio o al final se rechaza; no se recorta.
"""

import os

VARIABLE_URL_BD = "GATEKEEPER_DATABASE_URL"
VARIABLE_URL_MIGRACION = "GATEKEEPER_DATABASE_URL_MIGRACION"
ESQUEMA_PERMITIDO = "postgresql+psycopg://"


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
