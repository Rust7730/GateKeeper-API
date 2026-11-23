"""Lumina · Mesa de Gastos y Reembolsos (Monolito SaaS).

Una aplicación real de gestión de gastos y reembolsos para equipos donde los
colaboradores registran un gasto (concepto, categoría, monto, fecha) y adjuntan
su comprobante (factura PDF o foto del ticket PNG/JPEG).

Por debajo, antes de aceptar cualquier comprobante en la bóveda contable de Lumina,
el backend lo envía a Gatekeeper (/v1/files), espera el veredicto y solo almacena
la versión reconstruida libre de amenazas (/v1/files/{id}/content).
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_INDEX = BASE_DIR / "templates" / "index.html"
BOVEDA_DIR = BASE_DIR / "boveda_comprobantes"
BOVEDA_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_GATEKEEPER_URL = os.environ.get(
    "GATEKEEPER_API_URL", "https://35-168-228-65.sslip.io"
).rstrip("/")
DEFAULT_API_KEY = os.environ.get("GATEKEEPER_API_KEY", "")

app = FastAPI(
    title="Lumina · Gastos y Reembolsos",
    description="App de gastos corporativos y reembolsos con bóveda de comprobantes",
    version="1.0.0",
)

# Gastos precargados de ejemplo + los que el usuario registre en vivo
GASTOS: list[dict[str, Any]] = []


def _normalizar_url(base_url: str) -> str:
    limpia = base_url.strip().rstrip("/")
    if not limpia.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="La URL del motor de validación debe iniciar con https:// o http://",
        )
    return limpia


def _cabeceras_gk(api_key: str) -> dict[str, str]:
    clave = api_key.strip()
    if not clave:
        raise HTTPException(
            status_code=400,
            detail="Configura la API Key en el panel de integración (arriba a la derecha).",
        )
    return {"Authorization": f"Bearer {clave}"}


@app.get("/", response_class=HTMLResponse)
async def pagina_principal() -> HTMLResponse:
    html = TEMPLATE_INDEX.read_text(encoding="utf-8")
    html = html.replace("{{ default_url }}", DEFAULT_GATEKEEPER_URL).replace(
        "{{ default_api_key }}", DEFAULT_API_KEY
    )
    return HTMLResponse(content=html)


@app.get("/api/gastos")
async def listar_gastos() -> JSONResponse:
    aprobados = [g for g in GASTOS if g["estado_comprobante"] == "aprobado"]
    retenidos = [g for g in GASTOS if g["estado_comprobante"] == "retenido"]
    en_revision = [g for g in GASTOS if g["estado_comprobante"] == "verificando"]
    total_mxn = round(sum(float(g["monto"]) for g in aprobados), 2)
    return JSONResponse(
        {
            "resumen": {
                "total_reembolsable": total_mxn,
                "aprobados": len(aprobados),
                "en_revision": len(en_revision),
                "retenidos": len(retenidos),
            },
            "gastos": GASTOS,
        }
    )


async def _procesar_en_segundo_plano(
    gasto_id: str,
    archivo_gk_id: str,
    base_url: str,
    api_key: str,
) -> None:
    """Consulta el estado del comprobante en Gatekeeper y, si queda limpio, descarga la copia reconstruida."""
    url = _normalizar_url(base_url)
    cabeceras = _cabeceras_gk(api_key)
    gasto = next((g for g in GASTOS if g["gasto_id"] == gasto_id), None)
    if gasto is None:
        return

    async with httpx.AsyncClient(timeout=20.0) as cliente:
        for _ in range(40):
            await asyncio.sleep(1.0)
            try:
                resp = await cliente.get(
                    f"{url}/v1/files/{archivo_gk_id}",
                    headers=cabeceras,
                )
            except httpx.RequestError:
                continue

            if resp.status_code != 200:
                continue

            datos = resp.json()
            estado_gk = datos.get("estado", "pendiente")
            gasto["estado_motor"] = estado_gk
            gasto["tipo_detectado"] = datos.get("tipo_detectado")

            if estado_gk in ("pendiente", "analizando"):
                continue

            if estado_gk == "limpio":
                desc = await cliente.get(
                    f"{url}/v1/files/{archivo_gk_id}/content",
                    headers=cabeceras,
                )
                if desc.status_code == 200:
                    sha_limpio = hashlib.sha256(desc.content).hexdigest()
                    ext = "pdf" if datos.get("tipo_detectado") == "application/pdf" else (
                        "png" if datos.get("tipo_detectado") == "image/png" else "jpg"
                    )
                    nombre_limpio = f"{gasto_id}.{ext}"
                    ruta_boveda = BOVEDA_DIR / nombre_limpio
                    ruta_boveda.write_bytes(desc.content)

                    gasto["estado_comprobante"] = "aprobado"
                    gasto["sha256_boveda"] = sha_limpio
                    gasto["tamano_boveda"] = len(desc.content)
                    gasto["archivo_boveda"] = nombre_limpio
                    gasto["media_type_boveda"] = datos.get("tipo_detectado") or "application/octet-stream"
                    gasto["nota_auditoria"] = (
                        "Comprobante verificado y reconstruido en bóveda contable "
                        f"({len(desc.content):,} bytes)."
                    )
                else:
                    gasto["estado_comprobante"] = "retenido"
                    gasto["nota_auditoria"] = f"Error al recuperar comprobante limpio (HTTP {desc.status_code})."
            else:
                gasto["estado_comprobante"] = "retenido"
                motivo = (
                    "Amenaza detectada por motor antimalware"
                    if estado_gk == "infectado"
                    else "Estructura activa o insegura bloqueada al reconstruir el documento"
                )
                gasto["nota_auditoria"] = f"Reembolso bloqueado: {motivo} ({estado_gk})."
            return


@app.post("/api/gastos")
async def registrar_gasto(
    concepto: str = Form(...),
    categoria: str = Form(...),
    monto: float = Form(...),
    colaborador: str = Form(...),
    base_url: str = Form(...),
    api_key: str = Form(...),
    comprobante: UploadFile = File(...),
) -> JSONResponse:
    url = _normalizar_url(base_url)
    cabeceras = _cabeceras_gk(api_key)
    contenido = await comprobante.read()
    nombre_archivo = comprobante.filename or "ticket"
    mime = comprobante.content_type or "application/octet-stream"
    sha_original = hashlib.sha256(contenido).hexdigest()
    gasto_id = f"EXP-{uuid.uuid4().hex[:6].upper()}"

    try:
        async with httpx.AsyncClient(timeout=25.0) as cliente:
            respuesta = await cliente.post(
                f"{url}/v1/files",
                headers=cabeceras,
                files={"file": (nombre_archivo, contenido, mime)},
            )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"No fue posible conectar con el servicio de validación: {exc}",
        ) from exc

    try:
        cuerpo = respuesta.json()
    except ValueError:
        cuerpo = {"detail": respuesta.text}

    # Si Gatekeeper rechaza en el borde (por ejemplo 415 archivo inválido/ejecutable, 401 API Key inválida, 413 tamaño)
    if respuesta.status_code != 202:
        if respuesta.status_code == 401:
            raise HTTPException(
                status_code=401,
                detail="La API Key configurada no es válida o fue revocada.",
            )
        motivo_http = (
            "Formato de archivo falso o no permitido (solo PDF, PNG o JPEG reales)"
            if respuesta.status_code == 415
            else f"Rechazado en recepción (HTTP {respuesta.status_code})"
        )
        nuevo_gasto = {
            "gasto_id": gasto_id,
            "concepto": concepto.strip(),
            "categoria": categoria.strip(),
            "monto": round(monto, 2),
            "colaborador": colaborador.strip(),
            "fecha": time.strftime("%d/%m/%Y %H:%M"),
            "nombre_original": nombre_archivo,
            "tamano_original": len(contenido),
            "sha256_original": sha_original,
            "archivo_gk_id": None,
            "estado_comprobante": "retenido",
            "estado_motor": f"http_{respuesta.status_code}",
            "nota_auditoria": f"Reembolso rechazado al subir comprobante: {motivo_http}.",
            "sha256_boveda": None,
            "tamano_boveda": None,
            "archivo_boveda": None,
        }
        GASTOS.insert(0, nuevo_gasto)
        return JSONResponse(nuevo_gasto, status_code=200)

    archivo_gk_id = cuerpo["id"]
    nuevo_gasto = {
        "gasto_id": gasto_id,
        "concepto": concepto.strip(),
        "categoria": categoria.strip(),
        "monto": round(monto, 2),
        "colaborador": colaborador.strip(),
        "fecha": time.strftime("%d/%m/%Y %H:%M"),
        "nombre_original": nombre_archivo,
        "tamano_original": len(contenido),
        "sha256_original": sha_original,
        "archivo_gk_id": archivo_gk_id,
        "estado_comprobante": "verificando",
        "estado_motor": cuerpo.get("estado", "pendiente"),
        "nota_auditoria": "Validando autenticidad y sanitizando comprobante adjunto...",
        "sha256_boveda": None,
        "tamano_boveda": None,
        "archivo_boveda": None,
    }
    GASTOS.insert(0, nuevo_gasto)

    asyncio.create_task(
        _procesar_en_segundo_plano(
            gasto_id=gasto_id,
            archivo_gk_id=archivo_gk_id,
            base_url=base_url,
            api_key=api_key,
        )
    )
    return JSONResponse(nuevo_gasto, status_code=201)


@app.get("/api/gastos/{gasto_id}/comprobante")
async def ver_comprobante_boveda(gasto_id: str) -> Response:
    gasto = next((g for g in GASTOS if g["gasto_id"] == gasto_id), None)
    if gasto is None or not gasto.get("archivo_boveda"):
        raise HTTPException(
            status_code=404,
            detail="El comprobante no está disponible en la bóveda (aún en revisión o bloqueado).",
        )
    ruta = BOVEDA_DIR / gasto["archivo_boveda"]
    if not ruta.is_file():
        raise HTTPException(status_code=404, detail="Archivo no encontrado en bóveda.")
    return Response(
        content=ruta.read_bytes(),
        media_type=gasto.get("media_type_boveda", "application/octet-stream"),
        headers={
            "Content-Disposition": f'inline; filename="{gasto["archivo_boveda"]}"'
        },
    )
