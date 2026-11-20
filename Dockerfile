# Imagen de la API de Gatekeeper (K55: despliegue en AWS EC2 con Docker Compose).
#
# Dos etapas: la primera instala las dependencias con uv en /app/.venv; la final copia solo ese
# entorno y el código de api/, sin uv, sin pip y sin compiladores.
#
# Imágenes base fijadas por versión y digest. Para actualizarlas, cambia ambos a la vez.

FROM ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 AS uv

FROM python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS dependencias
COPY --from=uv /uv /usr/local/bin/uv
# El entorno se crea con el Python de la imagen base (el mismo de la etapa final), nunca con uno
# descargado; bytecode compilado aquí porque en producción el sistema de archivos es de solo lectura.
ENV UV_PYTHON=/usr/local/bin/python3.12 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
WORKDIR /app
COPY pyproject.toml uv.lock ./
# --frozen: exactamente lo de uv.lock. Sin el grupo dev (pytest, ruff, bandit...).
RUN uv sync --frozen --no-dev --no-install-project

FROM python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

# libmagic1 (con su base de firmas) para python-magic (INV-02). pip no hace falta en ejecución.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip uninstall -y pip \
    && groupadd --system --gid 10001 gatekeeper \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin gatekeeper \
    && install -d -o 10001 -g 10001 -m 0700 /datos

WORKDIR /app
# El código y el entorno son de root: la API los lee pero no puede modificarlos.
COPY --from=dependencias /app/.venv /app/.venv
COPY api ./api

ENV PATH=/app/.venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
EXPOSE 8000

# env -i: el proceso del healthcheck no conserva el pepper ni la URL de la BD en su entorno (K52).
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --start-interval=2s --retries=3 \
    CMD ["/usr/bin/env", "-i", "/app/.venv/bin/python", "-I", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"]

# K52: uvicorn es el PID 1, sin uv run, sin shell y sin init intermedios. Un proceso padre con el
# pepper o la URL de la BD en su entorno haría que la API se negara a arrancar.
# Un solo proceso (sin --workers): el barrido del arranque supone una sola API (K51).
# Así, uvicorn solo acepta X-Forwarded-For de 127.0.0.1 (su valor por defecto). En el despliegue, el
# compose (deploy/docker-compose.yml) repite este comando con --forwarded-allow-ips = la IP fija de nginx.
CMD ["/app/.venv/bin/uvicorn", "--factory", "api.app.principal:crear_app", "--no-server-header", "--host", "0.0.0.0", "--port", "8000"]
