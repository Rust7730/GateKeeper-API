# Gatekeeper

API intermediaria que valida, sanea y analiza los archivos que suben los usuarios finales antes de que lleguen a la
aplicación cliente. Acepta JPEG, PNG y PDF de hasta 10 MiB, y la aplicación cliente solo descarga la versión
reconstruida del archivo, nunca el original.

## Estado

Ya funciona una **rebanada vertical local**: subir un archivo con API key, consultar su estado y descargar la versión
reconstruida. Es para uso local y no debe usarse en producción (ver [Limitaciones](#limitaciones)).

| Parte | Estado |
|---|---|
| Autenticación | API keys por aplicación, guardadas como HMAC; falta revocarlas y rotarlas |
| Archivos | Subida en streaming, consulta de estado y descarga |
| CDR | Reconstrucción de JPEG y PNG con Pillow y saneamiento de PDF con pikepdf, en un proceso hijo limitado |
| Base de datos | `aplicacion`, `api_key`, `archivo` y `resultado_analisis`, con la migración `0001` |
| Pendiente | ClamAV, VirusTotal, Redis, worker en contenedor, rate limit, Nginx y dashboard |

## Cómo funciona

En la rebanada local:

1. La aplicación cliente sube el archivo con su API key. La API lo recibe en streaming, calcula su SHA-256, lo guarda
   con un UUID generado por el servidor y responde `202` con el id.
2. Un proceso hijo sin acceso a la base de datos y con memoria limitada comprueba el tipo real con python-magic y
   reconstruye el archivo. El nombre, la extensión y el `Content-Type` no deciden nada.
3. La API registra el resultado: `limpio`, `rechazado` o `error`. Un fallo o un timeout nunca termina en `limpio`.
4. La aplicación cliente consulta el estado y descarga la versión reconstruida cuando el archivo queda `limpio`.

En el diseño final, el CDR corre en un `worker` aislado sin internet junto con ClamAV, el servicio `reputation` consulta
VirusTotal solo por hash, y un `coordinator` combina los resultados y puede dejar el archivo `en_cuarentena`.

## Modelo de datos

El diagrama muestra el modelo completo diseñado sobre PostgreSQL 16. La tabla de abajo indica qué parte ya existe.

```mermaid
erDiagram
    aplicacion ||--o{ api_key : "tiene"
    aplicacion ||--o{ archivo : "es dueña de"
    archivo ||--o{ resultado_analisis : "acumula"
    usuario ||--o{ refresh_token : "tiene"
    usuario |o--o{ evento_auditoria : "realiza"

    aplicacion {
        uuid id PK
        text nombre UK
        boolean activa
        timestamptz creada_en
    }

    api_key {
        uuid id PK
        uuid aplicacion_id FK
        text prefijo UK "parte visible de la key"
        char(64) hash UK "HMAC-SHA-256; nunca la key"
        timestamptz creada_en
        timestamptz revocada_en "nulo mientras esté activa"
    }

    archivo {
        uuid id PK
        uuid aplicacion_id FK
        varchar(255) nombre_original "solo para mostrar"
        varchar(100) tipo_detectado "MIME real, detectado por firma"
        bigint tamano_bytes "de 1 a 10 485 760"
        char(64) sha256
        text estado "pendiente, limpio, en_cuarentena, rechazado, error"
        text tipo_error "transitorio o final; solo con estado error"
        smallint reintentos "de 0 a 2"
        timestamptz creado_en
        timestamptz analizado_en "nulo hasta el veredicto"
    }

    resultado_analisis {
        bigint id PK
        uuid archivo_id FK
        text capa "firma, cdr, clamav, virustotal"
        text veredicto "limpio, malicioso, rechazado, error, no_evaluada"
        jsonb detalle "64 KB como máximo"
        integer duracion_ms
        timestamptz creado_en
    }

    usuario {
        uuid id PK
        text email UK "único sin distinguir mayúsculas"
        text hash_password "Argon2"
        text rol "admin o analista"
        bytea totp_secreto_cifrado
        boolean activo
        timestamptz creado_en
    }

    refresh_token {
        uuid jti PK
        uuid usuario_id FK
        uuid familia
        timestamptz expira_en
        boolean revocado
        timestamptz creado_en
    }

    evento_auditoria {
        bigint id PK
        uuid usuario_id FK "nulo en eventos del sistema"
        text accion
        uuid objetivo_id "id del objeto afectado"
        text motivo
        inet ip
        timestamptz fecha
    }
```

| Tablas | Estado |
|---|---|
| `aplicacion`, `api_key`, `archivo`, `resultado_analisis` | Implementadas, con la migración `0001` |
| `usuario`, `refresh_token`, `evento_auditoria` | Diseñadas; llegan con el dashboard de administración |

Reglas del modelo:

- Las claves son UUID generados por el servidor, salvo en `resultado_analisis` y `evento_auditoria`, que usan `bigint`.
- Todas las fechas son `timestamptz`.
- Toda consulta de un archivo se filtra por `aplicacion_id`: una aplicación nunca ve los archivos de otra.
- `evento_auditoria` es de solo inserción. Dos triggers impiden modificarla o vaciarla.

## Uso local

Requisitos: Python 3.12, [uv](https://docs.astral.sh/uv/), Docker y `libmagic` (paquete `file` en Arch, `libmagic1` en
Debian y Ubuntu). Los comandos son para bash o zsh.

### 1. Preparar el entorno

```bash
uv sync

CLAVE_BD=$(openssl rand -hex 16)
docker run -d --name gatekeeper-pg -p 127.0.0.1:5433:5432 \
  -e POSTGRES_USER=gatekeeper -e POSTGRES_PASSWORD="$CLAVE_BD" -e POSTGRES_DB=gatekeeper postgres:16

export GATEKEEPER_DATABASE_URL="postgresql+psycopg://gatekeeper:${CLAVE_BD}@127.0.0.1:5433/gatekeeper"
export GATEKEEPER_DATABASE_URL_MIGRACION="$GATEKEEPER_DATABASE_URL"
export GATEKEEPER_PEPPER=$(openssl rand -hex 32)
export GATEKEEPER_DATOS="$HOME/.local/share/gatekeeper"
```

`GATEKEEPER_DATOS` debe ser una ruta absoluta, y el directorio debe existir o poder crearse. El pepper debe conservarse:
si cambia, las API keys creadas con el anterior dejan de valer.

### 2. Crear el esquema y una API key

Espera unos segundos a que PostgreSQL arranque y luego:

```bash
uv run alembic -c api/migrations/alembic.ini upgrade head
API_KEY=$(uv run python -m api.app.alta "Mi aplicación")
```

La key se muestra una sola vez y no se puede recuperar.

### 3. Levantar la API

```bash
uv run uvicorn --factory api.app.principal:crear_app --no-server-header
```

### 4. Subir, consultar y descargar

En otra terminal, con `API_KEY` definida:

```bash
curl -s -H "Authorization: Bearer $API_KEY" -F file=@foto.jpg http://127.0.0.1:8000/v1/files
# {"id":"<uuid>","estado":"pendiente"}

curl -s -H "Authorization: Bearer $API_KEY" http://127.0.0.1:8000/v1/files/<uuid>
# {"id":"<uuid>","estado":"limpio","tipo_detectado":"image/jpeg",...}

curl -s -H "Authorization: Bearer $API_KEY" -o salida.jpg http://127.0.0.1:8000/v1/files/<uuid>/content
```

| Código | Significado |
|---|---|
| `202` | Archivo recibido; el análisis sigue en segundo plano |
| `400` | Multipart inválido, sin parte `file` o archivo vacío |
| `401` | API key ausente, inválida o revocada |
| `404` | El archivo no existe o es de otra aplicación |
| `408` | La subida tardó más de 60 s |
| `409` | El archivo no está `limpio` y no se puede descargar |
| `413` | El archivo supera 10 MiB |
| `415` | La petición no es `multipart/form-data` |

## Desarrollo

```bash
uv run pytest
```

Las pruebas de la base de datos y de la API levantan un PostgreSQL 16 desechable en Docker. Si Docker no responde, esas
pruebas fallan.

## Limitaciones

- Solo se aceptan JPEG, PNG y PDF. SVG, ZIP, Office y el análisis semántico quedan fuera del alcance.
- La rebanada vertical es solo para uso local. No incluye ClamAV, VirusTotal, Redis, rate limit, TLS ni dashboard, y el
  CDR corre en un proceso hijo limitado en lugar de un worker en contenedor aislado. **No debe usarse en producción.**
- La API se conecta como dueña del esquema, porque el rol `gk_app` con permisos mínimos aún no existe.
- Las API keys no se pueden revocar ni rotar todavía.
- Si la API se apaga a mitad de un análisis, el archivo queda en `pendiente`: no se puede descargar, pero no se reanuda.
- En un PDF no se recodifican las imágenes embebidas.
- Un marcador de PDF que navega con una acción pierde el salto, porque se eliminan todas las acciones.
