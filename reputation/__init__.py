"""Servicio ``reputation``: consulta VirusTotal v3 solo por hash SHA-256 (INV-05, D3, K07).

Corre en las redes ``backend`` y ``egress``. Nunca tiene acceso a PostgreSQL ni a ningún
volumen de archivos: solo recibe hashes SHA-256 por la cola ARQ ``gk:cola:reputacion``.
"""
