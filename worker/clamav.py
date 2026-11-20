"""Cliente asíncrono de ClamAV (``clamd``) por protocolo ``INSTREAM`` (D1, F4.02, INV-09).

Envía el archivo ORIGINAL por trozos de 64 KiB sobre TCP al demonio ``clamd`` en la red
interna ``isolated``. Cualquier error de red, timeout o respuesta inesperada devuelve
``error`` (fail-closed, INV-09): nunca ``limpio``.
"""

import asyncio
import contextlib
import struct
import time
from dataclasses import dataclass
from pathlib import Path

TAMANO_TROZO_INSTREAM = 65_536
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
    try:
        async with asyncio.timeout(timeout_s):
            lector, escritor = await asyncio.open_connection(host, puerto)
            escritor.write(_COMANDO_INSTREAM)
            with ruta.open("rb") as archivo:
                while True:
                    trozo = archivo.read(TAMANO_TROZO_INSTREAM)
                    if not trozo:
                        break
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
        if escritor is not None:
            escritor.close()
            with contextlib.suppress(OSError):
                await escritor.wait_closed()
