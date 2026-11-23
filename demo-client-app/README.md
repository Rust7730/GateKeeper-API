# AcmeFin · Monolito Consumidor de Prueba para Gatekeeper API

Mini aplicación monolítica (FastAPI + Jinja2) con la estética de Gatekeeper (`IBM Plex Sans` + `IBM Plex Mono`, paleta oscura/clara, verde lima `#bfff5a` y azul cobalto `#1a67fd`) diseñada para simular un cliente real B2B que integra `POST /v1/files`, `GET /v1/files/{id}` y `GET /v1/files/{id}/content`.

## Cómo levantarlo localmente

Desde `/home/rustless/Gatekeeper`:

```bash
./.venv/bin/uvicorn demo-client-app.app:app --app-dir /home/rustless/Gatekeeper/demo-client-app --host 127.0.0.1 --port 8090 --reload
```

O con el script incluido:

```bash
./demo-client-app/iniciar_demo.sh
```

Luego abre: **http://127.0.0.1:8090**

## Qué puedes probar en vivo

1. **Subida de archivos reales (`PDF`, `PNG`, `JPEG`)**:
   - Arrastra cualquier archivo de tu computadora y observa en vivo el cambio de estado (`pendiente` → `analizando` → `limpio` / `infectado` / `rechazado_cdr`).
2. **Laboratorio 1-Click de muestras sintéticas**:
   - **PNG con EXIF/GPS (`CDR Limpio`)**: Genera un PNG con chunks `tEXt` de autor, coordenadas GPS y XMP. Al descargar el archivo reconstruido (`GET /v1/files/{id}/content`), el panel compara el **SHA-256 Original** vs. el **SHA-256 Reconstruido por CDR**, demostrando que Gatekeeper desarmó y reconstruyó la imagen eliminando los metadatos.
   - **PDF corporativo (`CDR Limpio`)**: Genera un PDF válido que atraviesa ClamAV, YARA y reconstrucción CDR.
   - **PDF con `/JavaScript` (`Rechazo CDR`)**: Genera un PDF con `/OpenAction /JS`. Gatekeeper lo acepta en streaming (`202 Accepted`), pero el motor CDR lo detecta, lo rechaza (`rechazado_cdr`) y lo envía a cuarentena (podrás verlo en tu SecOps Dashboard en `https://35-168-228-65.sslip.io/`).
   - **ELF camuflado como `.png` (`HTTP 415`)**: Genera un binario con cabecera mágica `\x7fELF` pero extensión `.png`. Gatekeeper lo rechaza de forma síncrona (`415 Unsupported Media Type`) en los primeros bytes del stream sin siquiera encolarlo.
