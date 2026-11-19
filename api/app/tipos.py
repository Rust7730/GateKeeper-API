"""Lista blanca de tipos reales (INV-02). Sin dependencias: la usan la API y el proceso hijo."""

from collections.abc import Mapping
from types import MappingProxyType

# La extensión de la descarga sale de aquí y nunca del nombre que mandó el cliente.
EXTENSIONES: Mapping[str, str] = MappingProxyType(
    {"image/jpeg": "jpg", "image/png": "png", "application/pdf": "pdf"}
)
TIPOS_PERMITIDOS = frozenset(EXTENSIONES)
