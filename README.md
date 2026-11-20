# Gatekeeper

API intermediaria que valida, sanea y analiza los archivos que suben los usuarios finales antes de que lleguen a la
aplicación cliente. Acepta JPEG, PNG y PDF de hasta 10 MiB, y la aplicación cliente nunca descarga el original: de una
imagen recibe la versión reconstruida desde los píxeles, y de un PDF, la versión saneada estructuralmente.

## Estado

Ya funciona una **rebanada vertical**: subir un archivo con API key, consultar su estado y descargar la versión
reconstruida. Corre en local o en una instancia EC2 abierta al público en el 443 (K57, ver
[Despliegue en AWS EC2](#despliegue-en-aws-ec2)), con rate limit, el rol `gk_app` y las limitaciones declaradas en
[Limitaciones](#limitaciones), en particular K28.

| Parte | Estado |
|---|---|
| Autenticación | API keys por aplicación, guardadas como HMAC; falta revocarlas y rotarlas |
| Archivos | Subida en streaming, consulta de estado y descarga |
| CDR | Reconstrucción de JPEG y PNG con Pillow y saneamiento de PDF con pikepdf, en un proceso hijo limitado |
| Base de datos | `aplicacion`, `api_key`, `archivo` y `resultado_analisis`, con la migración `0001` |
| Rate limit | Por API key, 120/min con ráfaga de 20; por IP sin autenticar, 60/min; contadores en Redis (K58, K59) |
| Despliegue | Imagen Docker, Docker Compose con Nginx, TLS y Redis, publicación en GHCR y actualización por pull en EC2 |
| Pendiente | ClamAV, VirusTotal, worker en contenedor y dashboard |

## Cómo funciona

En la rebanada local:

1. La aplicación cliente sube el archivo con su API key. Antes de leer el cuerpo, la API comprueba la key y el rate
   limit. Lo recibe en streaming, calcula su SHA-256, lo guarda con un UUID generado por el servidor y responde `202`
   con el id.
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

CLAVE_REDIS=$(openssl rand -hex 16)
docker run -d --name gatekeeper-redis -p 127.0.0.1:6380:6379 redis:8.10.3-alpine3.23 \
  redis-server --requirepass "$CLAVE_REDIS" --save "" --appendonly no

export GATEKEEPER_DATABASE_URL="postgresql+psycopg://gatekeeper:${CLAVE_BD}@127.0.0.1:5433/gatekeeper"
export GATEKEEPER_DATABASE_URL_MIGRACION="$GATEKEEPER_DATABASE_URL"
export GATEKEEPER_REDIS_URL="redis://:${CLAVE_REDIS}@127.0.0.1:6380/0"
export GATEKEEPER_PEPPER=$(openssl rand -hex 32)
export GATEKEEPER_DATOS="$HOME/.local/share/gatekeeper"
```

`GATEKEEPER_DATOS` debe ser una ruta absoluta, y el directorio debe existir o poder crearse. El pepper debe conservarse:
si cambia, las API keys creadas con el anterior dejan de valer. `GATEKEEPER_REDIS_URL` es obligatoria: sin Redis no hay
rate limit, y la API no arranca sin ella. En local, la API usa el mismo rol que las migraciones; en el servidor usa
`gk_app` (ver [Despliegue en AWS EC2](#despliegue-en-aws-ec2)). La contraseña de Redis queda en la línea de comandos del
contenedor (`docker inspect`): sirve para local, no para un servidor.

Defínelas con `export` dentro de la shell, como arriba: así no aparecen en el entorno inicial de la shell, que es el que
se lee en `/proc/<pid>/environ`. No las pongas en el entorno con el que se abre la shell (`.profile`, `env VAR=... bash`,
la configuración de la terminal): la API no arranca si algún proceso que la lanza tiene a la vista el pepper o las URL de
la base de datos o de Redis (K52).

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

Directamente y no con `uv run`: `uv` quedaría como proceso padre de la API con el pepper y las URL de la base de datos y
de Redis en su entorno, legibles por el proceso hijo del CDR, y la API se niega a arrancar así (K52). `alembic` y `api.app.alta` no
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
| `429` | Rate limit superado (con `Retry-After` en segundos), o la aplicación ya tiene 20 archivos en análisis (`pendiente`) y se puede reintentar cuando termine alguno |
| `503` | Redis no responde en 1 s o está lleno: el rate limit falla cerrado y la petición no pasa (K60, K61) |

## Desarrollo

```bash
uv run pytest
```

Las pruebas de la base de datos y de la API levantan un PostgreSQL 16 desechable en Docker. Si Docker no responde, esas
pruebas fallan.

Las pruebas que arrancan la API no pasan si `uv run pytest` se lanza desde una shell abierta con alguna variable
`GATEKEEPER_*` en su entorno: la API se niega a arrancar (K52). Usa una shell limpia o `.venv/bin/pytest`.

## Despliegue en AWS EC2

El backend corre en una instancia EC2 con Docker Compose (K55) y está abierto al público en el 443 (K57). El SSH sigue
restringido a tus IP. La apertura llega con el rate limit en Redis (K10, K58, K59) y la API conectada como `gk_app`, y
con K28 vigente en producción (ver [Limitaciones de esta etapa](#limitaciones-de-esta-etapa)).

```
internet ──443──> nginx (TLS, límites, headers) ──frontend (interna)──> api ──backend (interna)──> postgres
internet ──80───> nginx-http (solo desafío ACME y redirección)            │                    └──> redis-main
                                                                         └─ proceso hijo del CDR (Landlock + seccomp)
```

| Pieza | Archivo |
|---|---|
| Imagen de la API (multi-stage, usuario no root, uvicorn como PID 1) | `Dockerfile`, `.dockerignore` |
| Servicios `nginx`, `nginx-http`, `api`, `postgres`, `redis-main`, `migrate`, `sonda` y `certbot` | `deploy/docker-compose.yml` |
| TLS, rutas, límites, timeouts y headers | `deploy/nginx/` |
| Instalación en la instancia | `deploy/instalar.sh` |
| Límite de conexiones por IP al puerto 80 | `deploy/cortafuegos.sh` |
| Actualización por pull con firma, respaldo y rollback; renovación del certificado | `deploy/actualizar.sh`, `deploy/systemd/` |
| Pruebas, publicación en GHCR y firma de la imagen | `.github/workflows/despliegue.yml` |

### 1. Crear la instancia (consola de AWS)

1. **EC2 → Launch instance:** Ubuntu Server 24.04 LTS, arquitectura x86_64, tipo `t3.small`, disco gp3 de 20 GiB y tu
   par de llaves SSH.
   - **Sin rol de IAM** (IAM instance profile vacío): Gatekeeper no usa ningún servicio de AWS, y así no hay
     credenciales que robar desde la instancia.
   - **Metadatos:** IMDSv2 obligatorio y **hop limit 1** (Advanced details → Metadata response hop limit). Con 1, un
     contenedor no llega al servicio de metadatos.
2. **Grupo de seguridad**, reglas de entrada:

   | Puerto | Origen | Para qué |
   |---|---|---|
   | 22/tcp | tu IP (`x.x.x.x/32`) | SSH |
   | 443/tcp | `0.0.0.0/0` | La API, abierta al público (K57) |
   | 80/tcp | `0.0.0.0/0` | Solo el desafío de Let's Encrypt y la redirección a HTTPS |

   Nada más: PostgreSQL y Redis no publican puertos. Solo IPv4: no añadas reglas para `::/0`. Docker atiende las
   conexiones IPv6 con su proxy, y nginx las vería todas con la misma IP, la de Docker: compartirían el límite por IP. Abre el 443 a todos solo con la API ya conectada como `gk_app` y
   con Redis en servicio (lo deja así `instalar.sh`; para una instancia anterior, ver
   [Apertura al público de una instancia ya instalada](#7-apertura-al-público-de-una-instancia-ya-instalada)).

   El puerto 80 queda abierto porque Let's Encrypt valida desde direcciones que no se conocen de antemano. Lo sirve
   `nginx-http`, un contenedor aparte del nginx del 443, con su propio pool de conexiones, timeouts cortos y un
   límite de 32 conexiones por IP en el cortafuegos del host. No habla con la API y solo redirige al dominio del
   servidor, nunca al `Host` que manda el cliente. La salida queda abierta: la instancia necesita el repositorio de
   Docker, GHCR, Sigstore y Let's Encrypt. Si tu IP cambia, actualiza la regla del 22.
3. **IP elástica:** asígnala y asóciala a la instancia. El nombre del servidor sale de ella: con la IP `3.14.15.92`,
   el dominio es `3-14-15-92.sslip.io`.

### 2. Publicar la imagen en GHCR

El workflow `despliegue` corre en cada push a `main`: `ruff`, `pytest`, Bandit y, si todo pasa, publica
`ghcr.io/rust7730/gatekeeper-api` con las etiquetas `main` y el SHA del commit, y **firma su digest con cosign sin
llaves** (Sigstore, con el token OIDC de GitHub Actions). El servidor no despliega ninguna imagen cuya firma no sea del
workflow `.github/workflows/despliegue.yml` en `refs/heads/main` de `Rust7730/GateKeeper-API`.

Por eso, quien puede publicar en `main` puede desplegar en el servidor. Antes del primer despliegue, en GitHub:

1. **Settings → Branches (o Rules) → protección de `main`:** exige pull request con revisión, que pase el workflow,
   y que nadie haga push directo ni force-push, administradores incluidos.
2. Revisa quién tiene permiso de escritura en el repositorio: cualquiera con escritura que salte esa protección
   puede publicar una imagen firmada.

Después del **primer** merge a `main`:

1. **Tu perfil → Packages → gatekeeper-api → Package settings → Change visibility → Public.** GHCR crea el paquete
   como privado aunque el repositorio sea público, y el servidor lo descarga y verifica sin credenciales.
2. Comprueba que `docker pull ghcr.io/rust7730/gatekeeper-api:main` funciona sin `docker login`.

Las pruebas del CDR necesitan Landlock en el runner. Si `ubuntu-24.04` no lo ofreciera, el workflow falla en el paso
"Landlock en el runner" con un mensaje claro; las pruebas no se saltan.

### 3. Instalar

```bash
ssh -i tu-llave.pem ubuntu@<IP elástica>
git clone https://github.com/Rust7730/GateKeeper-API.git
cd GateKeeper-API
sudo ./deploy/instalar.sh <IP elástica> [correo para avisos de Let's Encrypt]
```

El script se puede correr otra vez sin perder nada. Hace lo siguiente:

- Instala Docker Engine desde su repositorio oficial. Solo acepta un archivo de llave que traiga exactamente una
  llave, con la huella publicada por Docker, y guarda solo esa.
- Instala cosign con versión y checksum fijados.
- Activa `unattended-upgrades`, también para Docker Engine, y añade 1 GiB de swap para el sistema.
- Reserva los usuarios de servicio `gatekeeper` (UID 10001, el de la API en el contenedor) y `gatekeeper-redis`
  (UID 10002, el de `redis-main`), y crea los directorios.
- Activa el límite de conexiones por IP al puerto 80 (`gatekeeper-cortafuegos.service`, que se reaplica cada vez que
  arranca Docker).
- Genera los secretos en `/etc/gatekeeper/`, sin mostrarlos: las contraseñas del dueño del esquema, de `gk_app` y de
  Redis, y el pepper. Los que ya existen no se regeneran.
- Obtiene el certificado.
- Crea el rol `gk_app` de PostgreSQL, o lo ajusta si ya existe, antes de migrar: puede conectarse y nada más. No es
  superusuario, no crea bases ni roles y tiene un límite de 25 conexiones. Sus permisos sobre las tablas los da la
  migración `0002`. La contraseña viaja como verificador SCRAM, así que no aparece en el log de PostgreSQL.
- Hace el primer despliegue, vuelve a levantar la imagen desplegada con la configuración nueva y activa los timers.

Mientras corre, para el timer de actualización y espera a que termine cualquier despliegue en curso.

| Ruta | Contenido |
|---|---|
| `/opt/gatekeeper/` | Compose, configuración de nginx, scripts y la sonda del aislamiento |
| `/etc/gatekeeper/` | Secretos, modo 0600: `postgres.env` y `migrate.env` (dueño del esquema), `api.env` (pepper y `GATEKEEPER_REDIS_URL`), `gk_app.clave` y `redis.clave`. `redis.conf` (usuarios de Redis, con solo el SHA-256 de su contraseña; del UID 10002, modo 0400). `compose.env` (dominio) |
| `/var/lib/gatekeeper/` | Imagen y revisión del esquema desplegadas, la anterior, la retenida, la raíz de confianza de Sigstore y `api-bd.env` (`GATEKEEPER_DATABASE_URL` de la API, secreto, 0600; lo escribe `actualizar.sh`) |
| `/var/lib/gatekeeper/respaldos/` | Los últimos 5 respaldos de la base (`pg_dump -Fc`, modo 0600), uno antes de cada migración |
| `/var/log/gatekeeper/despliegues.log` | Un registro por despliegue |

**Guarda una copia de `/etc/gatekeeper/` fuera de la instancia.** Si se pierde el pepper, ninguna API key vuelve a
valer.

Quién usa qué rol de PostgreSQL:

| Proceso | Rol | De dónde |
|---|---|---|
| API y `alta` | `gk_app`: lee y escribe las 4 tablas, sin `DELETE`, `TRUNCATE` ni DDL | `/var/lib/gatekeeper/api-bd.env` |
| Migraciones (`upgrade` y `downgrade`) | Dueño del esquema | `migrate.env` |
| Respaldo (`pg_dump`) y restauración | Dueño del esquema, dentro del contenedor de postgres | `postgres.env` |

`actualizar.sh` escribe `api-bd.env` antes de cada arranque de la API. Usa `gk_app` en cuanto el esquema le da
permisos, desde la migración `0002`. Con un esquema anterior, al que solo se llega volviendo a una imagen previa a la
`0002`, usa el dueño, como esa imagen esperaba, y lo registra con un `AVISO`.

Para crear una aplicación y su API key (se muestra una sola vez):

```bash
sudo gk-compose run --rm api /app/.venv/bin/python -m api.app.alta "Mi aplicación"
```

`gk-compose` es `docker compose` con el proyecto, el archivo y las variables del despliegue. La key se crea en un
contenedor aparte, no dentro del de la API. Después, desde tu máquina:

```bash
curl -s -H "Authorization: Bearer $API_KEY" -F file=@foto.jpg https://<ip-con-guiones>.sslip.io/v1/files
```

### 4. Cómo se actualiza

1. Haces merge a `main`. El workflow prueba, construye, publica y firma la imagen.
2. En el servidor, `gatekeeper-actualizar.timer` corre `actualizar.sh` cada 5 minutos. Si el digest de `:main`
   cambió:
   1. **Verifica la firma** de ese digest con cosign: identidad del workflow de `main` y emisor de GitHub Actions.
      Si no coincide, la imagen no se usa para nada más.
   2. Prueba con la imagen nueva, sin red ni secretos, que Landlock y seccomp se aplican dentro del contenedor.
   3. Respalda la base (`pg_dump -Fc`) y anota la revisión de Alembic.
   4. Corre las migraciones (servicio `migrate`, con la URL de migración).
   5. Elige el rol de la API (`api-bd.env`), la levanta con la imagen nueva, fijada por digest, y comprueba
      `/health` a través de nginx y TLS.
   6. Si algo falla después de migrar, baja el esquema a la revisión anterior (`alembic downgrade`, con la imagen
      nueva) y vuelve a la imagen anterior. Si el downgrade falla, **deja la API detenida**, lo registra y
      escribe el marcador `/var/lib/gatekeeper/detenido`: mientras exista, ni `actualizar.sh` ni `instalar.sh`
      levantan la API ni migran, aunque `:main` cambie. Nunca corre la versión vieja sobre un esquema que no
      conoce. En los dos casos retiene el digest nuevo y no lo reintenta hasta que `:main` cambie otra vez.
   Si la firma no se pudo verificar, la imagen no se usa y no se retiene: se vuelve a verificar en cada corrida,
   porque el fallo puede ser de red, de Rekor o de TUF. El registro distingue una firma ausente o de otra
   identidad (`RECHAZADA`) de un error al verificar.
3. El cambio deja la API unos segundos sin servicio. Un análisis en curso en ese momento termina en `error` (K51).

Los cambios en `deploy/` (compose, nginx, scripts) **no** llegan con la imagen. Para aplicarlos:
`git pull && sudo ./deploy/instalar.sh <IP elástica>`. Al final, `instalar.sh` corre `actualizar.sh --reaplicar`, que
recrea `redis-main` y vuelve a levantar la imagen desplegada con la configuración nueva. Se pierden los contadores del
rate limit del minuto en curso.

`gatekeeper-certificados.timer` intenta renovar el certificado dos veces al día y recarga nginx. Certbot solo lo
renueva cuando le quedan menos de 30 días.

### 5. Registros

```bash
sudo cat /var/log/gatekeeper/despliegues.log          # despliegues, firmas, respaldos, fallos y rollbacks
sudo journalctl -u gatekeeper-actualizar.service      # salida completa de cada corrida
sudo journalctl -u gatekeeper-certificados.service
sudo journalctl -u gatekeeper-cortafuegos.service
sudo gk-compose ps
sudo gk-compose logs -f api                           # también: nginx, nginx-http, postgres, redis-main
systemctl list-timers 'gatekeeper-*'
```

### 6. Rollback

```bash
sudo /opt/gatekeeper/actualizar.sh --revertir
```

Respalda la base, baja el esquema a la revisión con la que corría la imagen anterior (con la imagen actual, que
conoce la migración más nueva) y vuelve a la imagen anterior. La actual queda retenida hasta el siguiente merge a
`main`. Si el downgrade falla, la API queda detenida. Para eso cada migración necesita un `downgrade()` que funcione.
Para pausar las actualizaciones: `sudo systemctl stop gatekeeper-actualizar.timer`.

Si la API quedó **detenida** tras un downgrade fallido, restaura el respaldo más reciente (su nombre lleva la
revisión del esquema) con la API parada, y vuelve a la imagen anterior:

```bash
sudo systemctl stop gatekeeper-actualizar.timer
sudo ls -t /var/lib/gatekeeper/respaldos/
sudo gk-compose stop api
# Base vacía y luego el respaldo: --clean solo no borra las tablas que creó la migración fallida.
sudo gk-compose exec -T postgres sh -c 'dropdb -U "$POSTGRES_USER" "$POSTGRES_DB" && createdb -U "$POSTGRES_USER" "$POSTGRES_DB"'
sudo gk-compose exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  < /var/lib/gatekeeper/respaldos/<respaldo>.dump
# Solo con la base restaurada: mientras exista este marcador, ni actualizar.sh ni instalar.sh
# levantan la API ni migran.
sudo rm /var/lib/gatekeeper/detenido
sudo gk-compose up -d --wait api      # imagen.env sigue apuntando a la imagen anterior
sudo systemctl start gatekeeper-actualizar.timer
```

Si cambia la IP elástica, cambia el dominio: corre `sudo ./deploy/instalar.sh <IP nueva>` para pedir el certificado
del nombre nuevo.

El volcado incluye los permisos de `gk_app` sobre las tablas, pero no el rol, que es del servidor y no de la base. En
la misma instancia el rol ya existe. En una instancia nueva, `instalar.sh` lo crea antes de que restaures nada.

Volver con `--revertir` a una imagen anterior a la `0002` deja la API conectada como dueña y **sin rate limit**. Con el
443 abierto, vuelve a restringirlo a tus IP en el grupo de seguridad antes de revertir a esa imagen.

### 7. Apertura al público de una instancia ya instalada

Para la instancia instalada antes de K57 (API conectada como dueña, sin Redis). El orden importa: si el timer despliega
la imagen nueva con la configuración vieja, la API no arranca sin `GATEKEEPER_REDIS_URL`. `actualizar.sh` vuelve a la
imagen anterior y retiene la nueva, sin perder datos, pero el paso 4 ya no la desplegaría.

1. Antes del merge, en la instancia: `sudo systemctl stop gatekeeper-actualizar.timer`.
2. Haz merge a `main` y espera a que el workflow publique y firme la imagen.
3. En la instancia: `cd GateKeeper-API && git pull`.
4. `sudo ./deploy/instalar.sh <IP elástica>`. Conserva la base, el pepper y la contraseña del dueño. Genera las
   contraseñas de `gk_app` y de Redis y crea el rol. Despliega la imagen nueva: respaldo, migración `0002` con el dueño
   y la API como `gk_app`. Al terminar vuelve a activar el timer.
5. Comprueba el rol de la API (debe responder `gk_app`):

   ```bash
   sudo gk-compose exec -T api /app/.venv/bin/python -I -c "import os, psycopg; print(psycopg.connect(os.environ['GATEKEEPER_DATABASE_URL'].replace('+psycopg', '')).execute('SELECT current_user').fetchone()[0])"
   sudo grep -E 'gk_app|AVISO' /var/log/gatekeeper/despliegues.log
   ```

6. Solo entonces, en el grupo de seguridad, cambia el origen del 443 a `0.0.0.0/0`. El 22 sigue con tu IP.

Si el timer ya había desplegado la imagen nueva antes del paso 4 y la había retenido, `despliegues.log` lo muestra.
Corre `sudo rm /var/lib/gatekeeper/retenido` antes del paso 4.

### Probarlo en local, sin TLS

```bash
docker build -t gatekeeper-api:prueba .
# En un directorio propio (chmod 700), crea postgres.env, migrate.env, api.env, api-bd.env y redis.conf como los
# genera instalar.sh. redis.conf tiene que ser legible por el UID 10002 (sudo chown 10002:10002, chmod 0400).
export GATEKEEPER_IMAGEN=gatekeeper-api:prueba GATEKEEPER_ETC=<ese directorio> GATEKEEPER_ESTADO=<ese directorio>
cd deploy
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --wait postgres
# Aquí, el rol gk_app como en instalar.sh ("Rol gk_app de PostgreSQL"), y en api-bd.env su URL.
docker compose -f docker-compose.yml -f docker-compose.local.yml --profile migrar run --rm migrate
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --wait redis-main api nginx nginx-http
```

`docker-compose.local.yml` cambia solo los dos nginx: la API por HTTP en `127.0.0.1:8080`, sin certificado ni HSTS, y
`nginx-http` en `127.0.0.1:8081` con el dominio `localhost`. Nunca en el servidor.

### Limitaciones de esta etapa

- **Abierto al público (K57).** El 443 acepta conexiones de cualquier IP; el 22 solo de las tuyas. Cualquiera puede
  probar keys o mandar peticiones sin autenticar: los frena el rate limit, no el cortafuegos.
- **Quién puede desplegar.** Cualquiera que logre publicar en `main` de `Rust7730/GateKeeper-API` (directamente o con
  un workflow modificado en esa rama) produce una imagen firmada que el servidor despliega. La protección de `main`
  y los permisos de escritura del repositorio son parte del control (ver el paso 2).
- **La API se conecta como `gk_app`.** Lee y escribe las 4 tablas, pero no puede borrar, vaciar, alterar ni crear
  tablas. Una API comprometida aún puede leer y modificar los datos de todas las aplicaciones (INV-10 lo aplica el
  código, no la base). Con una imagen anterior a la `0002` (solo tras `--revertir`), vuelve a conectarse como dueña.
- **Rate limit (K10, K58).** Por API key, 120 por minuto sostenidos con ráfaga de 20 (token bucket por aplicación). Sin
  autenticar o con una key inválida, 60 por minuto por IP. Al pasarse, `429` con `Retry-After`. Se suma al tope de 20
  archivos pendientes por aplicación (K48), al de 10 MiB y al de 60 s por subida. La IP es la que ve nginx: reescribe
  `X-Forwarded-For` con la IP de la conexión, y la API solo acepta esa cabecera de la IP fija de nginx (172.29.80.2,
  red `frontend`). Quien controle muchas direcciones puede repartir entre ellas sus peticiones sin autenticar.
- **Redis (`redis-main`, K59).** Guarda solo los contadores del rate limit, en memoria y sin persistencia: al
  reiniciarse los contadores empiezan de cero. Está en la red interna `backend`, sin puertos publicados. Sin contraseña
  no ejecuta ningún comando, y la API no puede usar `CONFIG`, `FLUSHALL`, `KEYS`, `DEBUG` ni `MODULE`. Tiene 32 MiB
  con `noeviction`: si se llenaran, Redis rechaza las escrituras y la API responde `503` en lugar de dejar pasar sin
  límite. Si Redis no responde en 1 s, también `503` (K60, K61); `/health` no depende de Redis.
- **Puerto 80 abierto a todos.** `nginx-http` tiene su propio pool (1024 conexiones), un timeout de cabeceras de 5 s y
  el límite de 32 conexiones por IP. Un ataque distribuido desde muchas IP aún podría llenarlo y retrasar la
  renovación del certificado, pero no afecta al 443.
- **K28 en producción, aceptada y mitigada (K57).** Con la API abierta al público, el CDR sigue corriendo en un
  proceso hijo con el mismo UID que la API, dentro del mismo contenedor, y no en un worker aislado (desviación temporal
  de INV-04, hasta que llegue el worker en contenedor). Un archivo malicioso que explotara Pillow o pikepdf correría
  con ese UID. Lo mitigan Landlock (K53), el filtro seccomp (K54), `PR_SET_DUMPABLE=0` y la negativa a arrancar con
  secretos en un ancestro (K52). El contenedor añade `cap_drop: ALL`, `no-new-privileges`, sistema de archivos de solo
  lectura, sin salida a internet, y límites de memoria (1 GiB) y procesos. El perfil seccomp es el de Docker por
  defecto, que permite Landlock.
- **La API no tiene salida a internet.** Las redes `frontend` y `backend` son internas; solo los dos nginx (puertos) y
  certbot (Let's Encrypt) tienen salida. Cuando llegue VirusTotal, irá por el servicio `reputation`, no por la API.
- **Respaldos solo locales y solo antes de migrar.** Se guardan los últimos 5 en el disco de la instancia. No hay
  respaldos periódicos ni fuera de la instancia: usa snapshots de EBS y guarda `/etc/gatekeeper/` aparte.
- **El dominio depende de la IP elástica y de sslip.io.** Si liberas la IP o cambias de instancia, el nombre cambia y
  hace falta otro certificado. Si el DNS de sslip.io falla, el nombre deja de resolver. HSTS se envía sin
  `includeSubDomains`.
- **Una sola instancia**, sin alta disponibilidad.
- **Los secretos de la API van por variables de entorno** (el pepper y las URL de la base y de Redis, con sus
  contraseñas). Los ve cualquiera que hable con Docker: root, cualquier usuario del grupo `docker` (que equivale a
  root), `docker inspect` y `gk-compose config`, que imprime el compose con sus valores. La contraseña de Redis no
  está en el contenedor de Redis: allí solo está su SHA-256, en un archivo montado. No añadas usuarios al grupo `docker`. El healthcheck los descarta con `env -i` al arrancar, pero durante
  ese instante su proceso los tiene en el entorno.
- **Memoria justa.** `t3.small` tiene 2 GiB: la API tiene 1 GiB, contando los dos hijos del CDR que corren a la vez, y
  Redis 64 MiB. Si un archivo se pasa, el sistema mata al hijo y ese archivo termina en `error`.
- **Las actualizaciones de Docker reinician los contenedores.** `unattended-upgrades` incluye Docker Engine; al
  actualizarse, la API queda unos segundos sin servicio.
- **nginx envía `Server: nginx`, sin versión** (`server_tokens off`, K29). Quitarlo del todo exige el módulo
  headers-more, que la imagen oficial no trae.

## Limitaciones

- Solo se aceptan JPEG, PNG y PDF. SVG, ZIP, Office y el análisis semántico quedan fuera del alcance.
- La rebanada vertical está abierta al público en EC2 (K57). No incluye ClamAV, VirusTotal ni dashboard, y el CDR corre
  en un proceso hijo limitado en lugar de un worker en contenedor aislado (K28, aceptada en producción). El despliegue
  tiene sus propias limitaciones (ver [Limitaciones de esta etapa](#limitaciones-de-esta-etapa)).
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
