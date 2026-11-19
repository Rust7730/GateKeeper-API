# Gatekeeper

API intermediaria que valida, sanea y analiza los archivos que suben los usuarios finales antes de que lleguen a la
aplicación cliente. Acepta JPEG, PNG y PDF de hasta 10 MiB, y la aplicación cliente nunca descarga el original: de una
imagen recibe la versión reconstruida desde los píxeles, y de un PDF, la versión saneada estructuralmente.

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
2. Un proceso hijo comprueba el tipo real con python-magic y reconstruye el archivo. No tiene acceso a la base de datos
   y no recibe credenciales, pero corre con el mismo usuario del sistema que la API (ver [Limitaciones](#limitaciones)),
   con memoria y CPU limitadas, aislado con Landlock y un filtro seccomp que no le deja crear sockets, y muere si
   muere la API. El nombre, la extensión y el
   `Content-Type` no deciden nada.
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
- `evento_auditoria` será de solo inserción: llegará con dos triggers que impedirán modificarla o vaciarla.

## Uso local

Requisitos: Linux con Landlock (kernel 5.13 o posterior, activado), Python 3.12, [uv](https://docs.astral.sh/uv/),
Docker y `libmagic` (paquete `file` en Arch, `libmagic1` en Debian y Ubuntu). Los comandos son para bash o zsh.

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

Defínelas con `export` dentro de la shell, como arriba: así no aparecen en el entorno inicial de la shell, que es el que
se lee en `/proc/<pid>/environ`. No las pongas en el entorno con el que se abre la shell (`.profile`, `env VAR=... bash`,
la configuración de la terminal): la API no arranca si algún proceso que la lanza tiene a la vista el pepper o la URL de
la base de datos (K52).

### 2. Crear el esquema y una API key

Espera unos segundos a que PostgreSQL arranque y luego:

```bash
uv run alembic -c api/migrations/alembic.ini upgrade head
API_KEY=$(uv run python -m api.app.alta "Mi aplicación")
```

La key se muestra una sola vez y no se puede recuperar.

### 3. Levantar la API

```bash
.venv/bin/uvicorn --factory api.app.principal:crear_app --no-server-header
```

Directamente y no con `uv run`: `uv` quedaría como proceso padre de la API con el pepper y la URL de la base de datos en
su entorno, legibles por el proceso hijo del CDR, y la API se niega a arrancar así (K52). `alembic` y `api.app.alta` no
arrancan la API y pueden seguir corriendo con `uv run`.

Con un solo proceso: sin `--workers` ni `--reload` (ver [Limitaciones](#limitaciones)). Al arrancar, la API pasa a `error` los
archivos que quedaron en `pendiente` y borra los temporales de un apagado anterior. Si la base de datos no responde, no
arranca.

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
| `429` | La aplicación ya tiene 20 archivos en análisis (`pendiente`); se puede reintentar cuando termine alguno |

## Desarrollo

```bash
uv run pytest
```

Las pruebas de la base de datos y de la API levantan un PostgreSQL 16 desechable en Docker. Si Docker no responde, esas
pruebas fallan.

Las pruebas que arrancan la API no pasan si `uv run pytest` se lanza desde una shell abierta con alguna variable
`GATEKEEPER_*` en su entorno: la API se niega a arrancar (K52). Usa una shell limpia o `.venv/bin/pytest`.

## Limitaciones

- Solo se aceptan JPEG, PNG y PDF. SVG, ZIP, Office y el análisis semántico quedan fuera del alcance.
- La rebanada vertical es solo para uso local. No incluye ClamAV, VirusTotal, Redis, rate limit, TLS ni dashboard, y el
  CDR corre en un proceso hijo limitado en lugar de un worker en contenedor aislado. **No debe usarse en producción.**
- La API se conecta como dueña del esquema, porque el rol `gk_app` con permisos mínimos aún no existe.
- Las API keys no se pueden revocar ni rotar todavía.
- El proceso hijo del CDR corre con el mismo usuario del sistema (UID) que la API (K28). Está mitigado, no cerrado:
  - No recibe credenciales. La API se marca como no volcable (`PR_SET_DUMPABLE=0`) y no arranca si un proceso que la
    lanza tiene el pepper o la URL de la base de datos a la vista (K52).
  - Landlock (K53) le deja leer solo Python, el entorno virtual, el código de `api/app`, las bibliotecas del sistema,
    `/dev/urandom` y su archivo de entrada, y escribir solo en su directorio de trabajo `clean_store/<uuid>.parcial/`.
    No puede ejecutar ningún archivo del disco. Con un kernel que lo ofrezca (ABI 9 de Landlock), tampoco resuelve
    sockets Unix por ruta.
  - Un filtro seccomp (K54) le niega `socket()`, `socketpair()` e `io_uring` (que crea sockets por su cuenta) en cualquier
    kernel: no abre ningún socket, ni TCP ni UDP ni Unix (`/var/run/docker.sock`, el D-Bus de la sesión) ni netlink.
    Solo se arma para x86_64 y aarch64.
  - Si Landlock o el filtro no se pueden aplicar, ningún archivo se analiza: todos terminan en `error`.
  - Sigue sin aislamiento de usuario, y puede leer todo lo legible en esos directorios del sistema. Se cierra del todo
    con el worker en contenedor.
- El hijo se ata a la API con `PR_SET_PDEATHSIG` en cuanto arranca. Si la API muere justo mientras arranca el
  intérprete del hijo, antes de esa llamada, el hijo no recibe la señal: lo frena solo su límite de 35 s de CPU.
- La API debe correr con un solo proceso de uvicorn (sin `--workers` ni `--reload`): el barrido del arranque cierra todo lo que esté en
  `pendiente`, y con varios procesos uno que arranca cerraría los análisis de otro.
- Cada aplicación puede tener como máximo 20 archivos en `pendiente` a la vez; la subida siguiente recibe `429`.
- Si la API se apaga a mitad de un análisis, el archivo queda en `pendiente` hasta el siguiente arranque, que lo pasa a
  `error`: no se reanuda. Lo mismo si, al terminar un análisis, la base de datos no responde ni tras tres intentos
  (unos 1.5 s de espera entre ellos): el archivo sigue en `pendiente`, ocupando cupo, hasta el siguiente arranque.
- Si la API se cancela justo mientras confirma un `limpio`, puede quedar el archivo `limpio` sin su versión reconstruida.
  La descarga responde entonces `500` y nunca entrega el original: falla cerrado.
- El saneamiento de PDF es estructural. Se eliminan las acciones, JavaScript, formularios, anotaciones, archivos
  incrustados, metadatos y referencias externas, pero el contenido de las páginas, las fuentes y las imágenes
  embebidas pasan sin cambios: no protege contra una vulnerabilidad del lector en esas partes.
- Un marcador de PDF que navega con una acción pierde el salto, porque se eliminan todas las acciones.
- Dos casos legítimos de imágenes en línea de PDF (`BI ... ID ... EI`) se rechazan para que el CDR y el lector no lean
  cosas distintas (K49): una imagen cuyos datos contengan un `EI` entre blancos, como el que cierra la imagen, y una
  imagen sin filtro cuyo espacio de color (`/CS`) remite a un recurso de la página, porque sin él no se sabe dónde
  acaban sus datos.
