"""Worker aislado de Gatekeeper (INV-04, K02, K09, K64).

Corre en la red interna ``isolated`` sin salida a internet, sin acceso a PostgreSQL ni a
``redis-main``, como usuario no root (UID 10003) con sistema de archivos de solo lectura.
"""
