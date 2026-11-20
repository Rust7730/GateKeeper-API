"""Cliente asíncrono de ClamAV (``clamd``) por protocolo ``INSTREAM`` (D1, F4.02, INV-09).

Envía el archivo ORIGINAL por trozos de 64 KiB sobre TCP al demonio ``clamd`` en la red
interna ``isolated``. Cualquier error de red, timeout o respuesta inesperada devuelve
``error`` (fail-closed, INV-09): nunca ``limpio``.
"""

import asyncio
import contextlib
import os
import stat
import struct
import time
from dataclasses import dataclass
from pathlib import Path

TAMANO_TROZO_INSTREAM = 65_536
TOPE_INSTREAM_BYTES = 10 * 1024 * 1024  # 10 MiB (K41 / CWE-400)
TIMEOUT_CLAMAV_S = 10.0
_COMANDO_INSTREAM = b"zINSTREAM\0"
_FIN_INSTREAM = b"\x00\x00\x00\x00"
_TOPE_RESPUESTA = 4096


@dataclass(frozen=True, slots=True)
class ResultadoClamav:
    veredicto: str  # "limpio" | "malicioso" | "error" | "no_evaluada"
    firma: str | None
    motivo: str
    duracion_ms: int

    def como_dict(self) -> dict[str, object]:
        datos: dict[str, object] = {
            "veredicto": self.veredicto,
            "motivo": self.motivo,
            "duracion_ms": self.duracion_ms,
        }
        if self.firma is not None:
            datos["firma"] = self.firma
        return datos


def _interpretar_respuesta(bruta: bytes, duracion_ms: int) -> ResultadoClamav:
    texto = bruta.rstrip(b"\x00\r\n ").decode("utf-8", errors="replace")
    if texto == "stream: OK":
        return ResultadoClamav("limpio", None, "ok", duracion_ms)
    if texto.startswith("stream: ") and texto.endswith(" FOUND"):
        firma = texto.removeprefix("stream: ").removesuffix(" FOUND").strip()
        if firma:
            return ResultadoClamav(
                "malicioso", firma[:200], "malware_detectado", duracion_ms
            )
    return ResultadoClamav("error", None, "respuesta_clamav_invalida", duracion_ms)


async def escanear_clamav(
    ruta: Path,
    host: str,
    puerto: int,
    *,
    timeout_s: float = TIMEOUT_CLAMAV_S,
) -> ResultadoClamav:
    """Escanea ``ruta`` enviando sus bytes por ``zINSTREAM`` a ``host:puerto``."""
    inicio = time.perf_counter()

    def _ms() -> int:
        return round((time.perf_counter() - inicio) * 1000)

    escritor = None
    fd_in: int | None = None
    try:
        fd_in = os.open(ruta, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(fd_in)
        if not stat.S_ISREG(info.st_mode) or info.st_size > TOPE_INSTREAM_BYTES:
            return ResultadoClamav("error", None, "archivo_invalido", _ms())

        async with asyncio.timeout(timeout_s):
            lector, escritor = await asyncio.open_connection(host, puerto)
            escritor.write(_COMANDO_INSTREAM)
            enviados = 0
            while True:
                trozo = os.read(fd_in, TAMANO_TROZO_INSTREAM)
                if not trozo:
                    break
                enviados += len(trozo)
                if enviados > TOPE_INSTREAM_BYTES:
                    return ResultadoClamav("error", None, "archivo_invalido", _ms())
                escritor.write(struct.pack("!I", len(trozo)))
                escritor.write(trozo)
                await escritor.drain()
            escritor.write(_FIN_INSTREAM)
            await escritor.drain()
            respuesta = await lector.read(_TOPE_RESPUESTA)
        return _interpretar_respuesta(respuesta, _ms())
    except TimeoutError:
        return ResultadoClamav("error", None, "timeout_clamav", _ms())
    except OSError:
        return ResultadoClamav("error", None, "clamav_no_disponible", _ms())
    finally:
        if fd_in is not None:
            os.close(fd_in)
        if escritor is not None:
            escritor.close()
            with contextlib.suppress(OSError):
                await escritor.wait_closed()
