# Gatekeeper — Decisiones de diseño

Registro de las decisiones de F0.01, confirmadas el 2026-10-28. Complementa a `gatekeeper_contexto.json` y
`gatekeeper_plan.json`. Cuando este documento los contradice, **manda este documento**. El estado vivo de cada
decisión está en `context/gatekeeper_kg.json` (v1.3.0, nodos `D#` y `K##`). La evidencia de la revisión CoV y del
adversario está en `context/revision_cov_adversarial.md`.

## 1. Resumen

| Id | Tema | Elección |
|---|---|---|
| D1 | Orden del pipeline | ClamAV sobre el original **en paralelo** con firma + CDR; la decisión espera a ambos |
| D2 | ClamAV sin internet | Contenedor `freshclam` separado que escribe `clamav_db`; clamd lo monta en solo lectura |
| D3 | VirusTotal sin cuota o sin respuesta | La capa queda `no_evaluada`; se decide con ClamAV + CDR (con el presupuesto de K07) |
| D4 | Estados | Se agrega `error`; liberar de cuarentena reencola en el CDR |
| D5 | Parámetros | Sección 6 |
| D6 | Propuesta escrita | Se corrige una sola vez en F6 (CHK4) |
| K01 | Quién decide | Fuera del worker: el `coordinator` combina los resultados |
| K02 | Aislamiento de Redis | Dos instancias: `redis-queue` y `redis-main` |
| K03 | Transiciones faltantes | `error → pendiente` y `en_cuarentena → rechazado \| error` |
| K04 | Nombre | `reputation` en código, Compose y directorios |
| K05 | Alta de aplicaciones | `POST /v1/admin/api-keys` recibe la aplicación |
| K06 | Roles | admin ⊇ analista |
| K07 | Latencia de VT | Presupuesto no bloqueante |
| K08 | Fan-in en ARQ | Servicio `coordinator`, polling de 50 ms |
| K09 | CDR síncrono | Proceso hijo por CDR, con límite de memoria y kill al vencer el timeout |
| K10 | Rate limit | Por API key, configurable por aplicación; el límite por IP solo aplica sin autenticar |
| K11 | Reintentos | Solo para errores transitorios |
| K12 | Rendimiento | Métricas M1–M5 y long-poll |
| K13 | Bomba FlateDecode | Descompresión acotada a 100 MB y rechazo |

## 2. Arquitectura: 10 servicios

| Servicio | Redes | Función |
|---|---|---|
| nginx | frontend | TLS, `client_max_body_size 10m`, headers; sirve el dashboard; `proxy_buffering off` en `/v1/admin/events` |
| api | frontend, backend | Autenticación, rate limit, recepción con SHA-256 en streaming, estados, endpoints, SSE |
| coordinator | backend | `orquestar(archivo_id)` → encola `analyze` y `lookup`, espera ambos y ejecuta `decidir()`; escribe en PostgreSQL |
| postgres | backend | Metadatos, resultados, usuarios, API keys (HMAC), bitácora |
| redis-main | backend | Rate limit, caché de VT y cola `lookup` |
| redis-queue | backend, isolated | Solo la cola `analyze` |
| reputation | backend, egress | `lookup(sha256)` → VT v3 `GET /api/v3/files/{sha256}`; nunca envía archivos |
| worker | isolated | ClamAV + firma + CDR; sin internet, sin BD, no root, FS de solo lectura con tmpfs |
| clamav | isolated | clamd con `CLAMAV_NO_FRESHCLAMD=true`; healthcheck; memoria ≥ 2.5 GiB |
| freshclam | egress | `CLAMAV_NO_CLAMD=true`; escribe `clamav_db` |

`backend` e `isolated` llevan `internal: true`. Desde el worker **deben fallar** las conexiones a internet, a
`redis-main` y a `api` (prueba F1.09).

**Volúmenes:**

| Volumen | Escribe | Lee |
|---|---|---|
| `uploads_tmp` | api | worker |
| `clean_store` | worker | api |
| `quarantine` | worker | nadie por la API pública |
| `clamav_db` | freshclam | clamav (solo lectura) |

clamd recarga las firmas por `SelfCheck 300`. El worker arranca con `depends_on: clamav: service_healthy`.

**Riesgo residual declarado (K02):** un worker comprometido podría escribir resultados falsos de otros jobs en
`redis-queue`. Esto se limita porque `decidir()` también exige el veredicto de VT, que el worker no controla.

## 3. Flujo de análisis

1. **nginx** corta con 413 las peticiones de más de 10 MB.
2. **api** autentica la API key, aplica el rate limit (K10) y guarda en `uploads_tmp/<uuid>` mientras calcula el
   SHA-256. Después registra `pendiente`, encola `orquestar` en `redis-main` y responde **202** (M1).
3. **coordinator** encola en paralelo:
   - `analyze(uuid)` en `redis-queue` → worker;
   - `lookup(sha256)` en `redis-main` → reputation.
4. **worker**, en paralelo dentro del job (D1):
   - a. clamd `INSTREAM` del original (I/O por socket);
   - b. en un proceso hijo con `RLIMIT_AS` (K09): firma con python-magic → políticas → CDR.
5. **reputation** consulta la caché de Redis. Si no está, consulta VT **solo si hay cuota disponible en ese
   momento**. Si no hay cuota, responde `no_evaluada` de inmediato (K07).
6. **coordinator** espera el resultado de `analyze` y, a partir de ahí, como máximo **1 s** más a `lookup`. Si
   no llega, la capa de VT queda `no_evaluada`.
7. `decidir()` aplica la prioridad **en_cuarentena > rechazado > error > limpio**:
   - ClamAV detecta, o VT reporta ≥ 1 motor `malicious` → `en_cuarentena`; el original se mueve a `quarantine`.
   - El tipo no está en la lista blanca o se viola una política (PDF cifrado, píxeles, páginas, K13) → `rechazado`;
     se guardan solo el hash y los metadatos.
   - Error o timeout → `error`. **Nunca `limpio`** (INV-09).
   - Todo correcto → `limpio`: la versión reconstruida queda en `clean_store` y se borra el original.

   En todos los casos, `decidir()` escribe el estado en PostgreSQL y publica el cambio en un canal pub/sub de
   `redis-main`. La api se suscribe a ese canal para el SSE del dashboard y para responder a los long-poll.
8. El cliente consulta `GET /v1/files/{id}` (con `?wait=N`, long-poll de hasta 20 s) y descarga con
   `GET /v1/files/{id}/content` solo si el estado es `limpio`.

## 4. Máquina de estados

```
pendiente ──▶ limpio | en_cuarentena | rechazado | error
error ──────▶ pendiente        reintento: solo errores transitorios, máx. 2 (K11)
en_cuarentena ──▶ limpio       liberación por admin con motivo + CDR exitoso; el veredicto
                               antimalware queda anulado y registrado en la bitácora (V15)
en_cuarentena ──▶ rechazado    liberación + el CDR rechaza el tipo o la política
en_cuarentena ──▶ error        liberación + el CDR falla
```

- Solo `limpio` es descargable. Cualquier otro estado responde **409**.
- Toda transición pasa por una sola función que la valida.
- Un **timeout de procesamiento** (p. ej. una bomba) es un `error` final y no se reintenta. Son **transitorios**:
  clamd no disponible, caída del worker o error de red con Redis.
- ARQ se configura con `job_timeout` y `max_tries` explícitos; sus valores por defecto (300 s y 5) no aplican.

## 5. CDR

- **Imágenes:** `Image.MAX_IMAGE_PIXELS` se fija explícitamente y `DecompressionBombWarning` se trata como
  error. Las dimensiones se validan antes de `load()`. La imagen se reconstruye desde los píxeles, sin EXIF, ICC ni
  chunks de texto.
- **PDF (saneamiento estructural):**
  - Se rechazan los PDF cifrados, incluidos los que solo tienen contraseña de propietario.
  - Se eliminan `/OpenAction`, `/AA` (documento y páginas), `/Names` (`/JavaScript` y `/EmbeddedFiles`),
    `/AcroForm`, `/Annots` (`/URI`, `/Launch`, `/SubmitForm`), `/Info` y `/Metadata`.
  - Se aplica el límite de páginas.
- **K13:** antes de guardar, se recorren los flujos con zlib por bloques y un tope total de 100 MB; si se supera,
  el archivo se rechaza. Nunca se llama `read_bytes()` sin tope sobre un flujo no confiable.
- **Imágenes embebidas en PDF:** pendiente de F3.07 (recodificar o declarar como limitación).
- **clamd:** `MaxFileSize 10M`, `MaxScanSize 100M` (igual al tope de K13; un PDF legítimo puede descomprimirse
  por encima de su tamaño) y `MaxRecursion` bajo, porque escanea originales que pueden ser contenedores hostiles.

## 6. Parámetros

| Parámetro | Valor |
|---|---|
| Tamaño máximo | 10 MB en Nginx y en la API |
| Rate limit | Por API key, configurable por aplicación: 120/min por defecto, con ráfaga. Por IP: solo peticiones sin autenticar o con key inválida |
| Píxeles máximos | 40 000 000 |
| Páginas máximas de PDF | 200 |
| Descompresión máxima de un PDF | 100 MB |
| Timeout de análisis | 30 s (tope del peor caso, no un objetivo) |
| Umbral de VT | ≥ 1 motor `malicious` → `en_cuarentena`; el conteo se guarda en `resultado_analisis.detalle` |
| Presupuesto de VT | Sin cuota → `no_evaluada` inmediata; con cuota, ≤ 1 s después del worker |
| Caché de VT | 24 h |
| Polling de ARQ | 0.05 s en los workers y en `Job.result()` |
| Long-poll | `?wait=N`, N ≤ 20 s |
| Reintentos | 2, solo errores transitorios |
| Retención | Limpio: se borra el original tras el CDR · Rechazado: solo hash y metadatos · Cuarentena: 30 días |

## 7. Métricas de rendimiento

| SLI | Definición | Objetivo |
|---|---|---|
| M1 | Fin de la recepción del cuerpo → 202 | p95 < 1 s |
| M2 | `creado_en` → `analizado_en`, por tipo | JPEG/PNG/PDF ≤ 10 MB: p95 ≤ 2 s |
| M3 | Archivos/min sostenidos sin que M2 se degrade más de un 20 % | se reporta en F6 |
| M4 | % de archivos con VT `no_evaluada` | se reporta |
| M5 | Profundidad de la cola y espera en ella | alerta si la espera > 2 s |

Se calculan con `archivo.creado_en`, `archivo.analizado_en` y `resultado_analisis.duracion_ms`, y se exponen en
`GET /v1/admin/metrics`. Las referencias medidas el 2026-10-28 (CDR de un JPEG de 12 MP: ~214 ms; PDF de 200
páginas: 36 ms) están en el informe de revisión. Las latencias de ClamAV y VT se miden por primera vez en F2–F4.

## 8. API y autorización

- `POST /v1/admin/api-keys` recibe `{aplicacion_id}` o `{aplicacion_nombre}` (en este caso crea la aplicación).
  Revocación: `DELETE /v1/admin/api-keys/{id}`. Listado: `GET /v1/admin/api-keys`.
- `POST /v1/auth/totp/enroll` lo exige F5.01. `POST /v1/auth/logout` sigue siendo una sugerencia de
  `api.endpoints_sugeridos` **sin decidir**; se confirma en F1.06.
- RBAC: admin ⊇ analista. Un analista recibe **403** en los endpoints de admin.
- TOTP obligatorio para admin.
- API keys guardadas como HMAC-SHA-256 con pepper, con un prefijo visible.

## 9. Limitaciones declaradas

- La API pública de VT está limitada a 4 consultas/min y 500/día y no permite uso comercial; en producción haría
  falta la API Premium. Cualquier cliente puede agotar la cuota diaria, y entonces VT queda `no_evaluada` para
  todos.
- El saneamiento de PDF es estructural: conserva los flujos de contenido y no protege contra vulnerabilidades del
  lector.
- Los nuevos resultados de VT no se aplican de forma retroactiva a archivos que ya se entregaron.
- No se reutilizan resultados por hash entre aplicaciones, para evitar el canal lateral de tiempo (INV-10).
