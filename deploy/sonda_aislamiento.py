"""Sonda del aislamiento del CDR dentro del contenedor (K53, K54). La corre actualizar.sh.

Antes de cambiar de imagen, comprueba con la misma configuración del servicio `api` (seccomp por
defecto de Docker, `cap_drop: ALL`, `no-new-privileges`, solo lectura) que Landlock y el filtro
seccomp se aplican y cortan lo que deben. Si no, la imagen nueva no se despliega: con el aislamiento
roto, todos los archivos terminarían en `error` (falla cerrado, pero el servicio no sirve).

Se pasa con ``python -c``, sin instalarse en la imagen. Termina con 0 si todo está bien.
"""

import socket
import sys
import tempfile
from pathlib import Path

from api.app.aislamiento import abi, aplicar
from api.app.cdr_hijo import directorios_de_lectura

base = Path(tempfile.mkdtemp())
entrada = base / "entrada"
entrada.write_bytes(b"x")
trabajo = base / "sonda.parcial"
trabajo.mkdir()
version = abi()
aplicar(directorios_de_lectura(), entrada, trabajo)

fallos = []
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fallos.append("seccomp: socket() permitido")
except PermissionError:
    pass
try:
    Path("/proc/self/environ").read_bytes()
    fallos.append("landlock: /proc legible")
except PermissionError:
    pass
try:
    (base / "fuera").write_bytes(b"x")
    fallos.append("landlock: escritura fuera del .parcial")
except PermissionError:
    pass

print(f"sonda: landlock_abi={version} fallos={fallos or 'ninguno'}")
sys.exit(1 if fallos or version < 1 else 0)
