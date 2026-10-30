# Revisión CoV + adversario del diseño consolidado — 2026-10-28

Revisión de las decisiones D1–D6 y K01–K06 (KG v1.1.0) antes de aceptarlas. El criterio principal es la
**latencia que percibe el usuario de la aplicación cliente**, porque Gatekeeper es un intermediario. Los hallazgos
nuevos están en el KG v1.2.0 como K07–K13, en estado `pendiente`.

## 1. Chain-of-Verification

Cada afirmación se verificó por separado: ejecutando código en local, leyendo el código fuente de la librería o
consultando la documentación oficial. **Fuentes leídas hoy:** docs.virustotal.com (Public vs Premium API),
docs.clamav.net (Docker), `clamd.conf.sample` del repositorio Cisco-Talos/clamav, el código de ARQ 0.28.0 (PyPI)
y Pillow 13.0.0 instalado.

| # | Afirmación del diseño | Cómo se verificó | Estado |
|---|---|---|---|
| C1 | EICAR mide 68 bytes, libmagic lo detecta como texto y la lista blanca lo rechaza (base de D1) | Local: `len` = 68, `file` → `text/plain` | verificado |
| C2 | El SHA-256 de EICAR es `275a021b…51fd0f` | Local: hashlib | verificado |
| C3 | Pillow advierte por encima de 89 478 485 px y lanza error solo por encima del doble (V26) | Código de `_decompression_bomb_check`, Pillow 13.0.0 | verificado |
| C4 | VT pública: 4/min y 500/día, sin uso comercial | docs.virustotal.com | verificado |
| C5 | Un contenedor freshclam separado es viable (D2) | Imagen oficial: `CLAMAV_NO_CLAMD` / `CLAMAV_NO_FRESHCLAMD` | verificado con matiz: la documentación lo llama "less recommended" porque freshclam no puede avisar a clamd; clamd recarga solo con `SelfCheck` (por defecto cada 600 s) |
| C6 | clamd INSTREAM acepta archivos de 10 MB | `StreamMaxLength` por defecto 100M | verificado |
| C7 | ClamAV corre sin problema junto a los demás servicios | docs.clamav.net: 1.2 GiB para cargar firmas, 2.4 GiB durante la recarga diaria (`ConcurrentDatabaseReload` por defecto `yes`); se recomiendan 3–4 GiB | **matiz nuevo**: es el servicio más pesado; necesita healthcheck y límite de memoria |
| C8 | "La API orquesta dos jobs en paralelo y decide cuando llegan ambos" (K01) | Código de ARQ: no hay fan-in; `Job.result()` hace polling cada 0.5 s por defecto | **inconsistente**: falta el mecanismo → K08 |
| C9 | El worker ARQ ejecuta el CDR | Código de ARQ: `func()` exige funciones async (`RuntimeError` si no lo son) | **inconsistente**: el CDR de CPU bloquea el loop y el timeout no lo detiene → K09 |
| C10 | El timeout de 30 s y los reintentos de D4 se aplican tal cual | ARQ: `job_timeout` por defecto 300 s y `max_tries` 5 | verificado con matiz: hay que fijar ambos explícitamente |
| C11 | El worker solo alcanza a clamav y redis-queue (K02) | Tabla de redes: worker ∈ {isolated}; isolated = {worker, clamav, redis-queue} | verificado lógicamente; la confirmación empírica es la prueba F1.09 |
| C12 | Un worker comprometido podría falsificar resultados de otros jobs | ARQ guarda los resultados como claves en el mismo Redis, sin ACL | verificado (riesgo residual declarado en K02) |
| C13 | Son 9 servicios | Conteo | verificado; pasan a 10 si se adopta K08 |

**Afirmaciones mías anteriores que se corrigen:** C8 y C9. No eran datos inventados, pero el diseño daba por
hecho algo que ARQ no hace.

## 2. Mediciones de CDR (Pillow 13, 12 núcleos, en esta máquina)

Las imágenes son ruido aleatorio, que es el peor caso para el códec: una foto real comprime mejor y pesa menos
para la misma resolución.

| Entrada | CDR (decodificar → reconstruir desde píxeles → codificar), mediana |
|---|---|
| JPEG 2 MP, 1.9 MB | 32 ms |
| JPEG 12 MP (foto de celular), 10.9 MB | 214 ms |
| PNG 12 MP, compress_level 6 / 1 | 835–974 ms / 598 ms |
| JPEG 40 MP (límite de D5) | 695 ms; pico de memoria ≈ 0.5 GB |
| PDF 5 págs con imágenes, 1.6 MB (pikepdf 10.17) | 1 ms |
| PDF 200 págs con imágenes, 64.5 MB | 36 ms; sin restos de /OpenAction, /AA, /JavaScript ni /Info |
| PDF con bomba FlateDecode (400 MB descomprimidos) | guardar: 0 ms, 0 MB extra (no la descomprime) |
| Detectar esa bomba con zlib acotado a 100 MB | 10 ms, ≤ 1 MB por bloque |

El saneamiento estructural de PDF es casi gratis porque copia los flujos sin decodificarlos. **Hallazgo K13:**
por la misma razón, una bomba FlateDecode no afecta a Gatekeeper, pero se entrega intacta y estalla en el lector
del usuario final. Propuesta: descompresión acotada (tope de 100 MB por PDF) y rechazo; cuesta ~10 ms. Si después
se decide recodificar las imágenes embebidas (F3.07), cada imagen cuesta lo mismo que en la tabla de Pillow.

Conclusión: para el caso típico, el CDR de imágenes cuesta décimas de segundo y el de PDF milisegundos. **La latencia no la domina el
CDR: la dominan las esperas del diseño** (VT, polling de ARQ, polling del cliente).

## 3. Adversario: cada decisión vista desde la latencia y el ataque

### Presupuesto de latencia: tiempo hasta el veredicto de un JPEG de 5 MB

| Tramo | Diseño actual | Con los ajustes |
|---|---|---|
| Recepción + SHA-256 + 202 | < 1 s (O2) | igual |
| Recoger el job (ARQ `poll_delay`) | hasta 0.5 s por salto × 2–3 saltos | ≤ 0.05 s por salto (K08) |
| ClamAV + firma + CDR | secuencial: ClamAV + CDR | **en paralelo**: max(ClamAV, CDR) (D1) |
| VirusTotal | espera hasta 30 s si no hay cuota | 0 s sin cuota; ≤ 1 s de gracia con cuota (K07) |
| Decisión + PostgreSQL | ≈ 10 ms | igual |
| Polling del cliente | + la mitad de su intervalo | 0 con long-poll (K12, opcional) |
| **Total estimado** | ~1.5–3 s con cuota; **~30 s sin cuota** | **~0.5–1.5 s** (por confirmar con M2) |

Las cifras de ClamAV y VT son estimaciones: no se pudieron medir sin clamd ni una API key. Se confirman con M2 en
F2–F4.

### Veredicto por decisión

| Decisión | Ataque del adversario | Veredicto |
|---|---|---|
| **D1** flujo recomendado | Con ClamAV y CDR en secuencia, la latencia es la suma de ambos. Escanear el original también hace que clamd desempaque contenedores hostiles (ZIP). | **Mantener + ajuste:** ClamAV (I/O por socket) en paralelo con firma + CDR, y decidir con ambos; la prioridad no cambia. Fijar en clamd `MaxFileSize`/`MaxScanSize` = 10 MB y `MaxRecursion` bajo. |
| **D2** freshclam separado | ClamAV lo considera "less recommended". | **Mantener.** La alternativa (clamd + freshclam en un contenedor) le daría internet a clamd mientras comparte red con el worker, lo que V08 prohíbe. Ajuste: `SelfCheck` 300 s, healthcheck, worker `depends_on: service_healthy` y memoria ≥ 2.5 GiB para clamav. La latencia no cambia. |
| **D3** no_evaluada | Tal como está escrito, D3 deja el archivo esperando hasta el timeout de 30 s. Además, cualquier cliente puede agotar los 500/día y dejar a todos sin VT. | **Ajustar (K07):** presupuesto no bloqueante. El agotamiento de cuota se declara como limitación académica. |
| **D4 + K03** estados y reintentos | Reintentar un timeout de procesamiento amplifica una bomba. | **Ajustar (K11):** solo se reintentan errores transitorios. |
| **D5** parámetros | 30/min por key y 60/min por IP limitan a toda la aplicación cliente, porque todas sus subidas llegan desde una misma IP. Un umbral de VT ≥ 1 sube los falsos positivos. | **Ajustar (K10)** el rate limit. El umbral se mantiene: la cuarentena tiene un flujo de liberación y la mayoría de los hashes de usuarios son desconocidos para VT. |
| **D6** | — | Mantener. |
| **K01** la API orquesta | ARQ no tiene fan-in y su polling añade 0.5 s por salto. Si se orquesta dentro del proceso FastAPI, un reinicio deja archivos en `pendiente` para siempre. | **Ajustar (K08):** servicio `coordinator` con jobs ARQ y polling de 50 ms. |
| **K02** dos Redis | Otro contenedor (unos MB de RAM). | **Mantener:** no afecta la latencia y aísla la caché de VT. |
| **K04–K06** | — | Mantener. |

### Alternativas evaluadas y descartadas

- **Reutilizar el resultado por hash entre aplicaciones** (si el SHA-256 ya fue analizado, devolver el resultado
  al instante): baja mucho la latencia, pero abre un canal lateral, porque la aplicación B podría saber por el tiempo de respuesta
  si la aplicación A subió cierto archivo. Además choca con INV-10. **No se adopta.**
- **Webhook en lugar de polling:** el cliente se entera de inmediato, pero obliga a Gatekeeper a hacer peticiones
  salientes a URLs del cliente (riesgo de SSRF) y abre una nueva salida a internet. **Se prefiere el long-poll.**
- **Sacar VT del camino crítico** (entregar el archivo y analizarlo después): latencia mínima, pero viola INV-06 si
  VT detecta algo cuando el archivo ya se entregó. **No se adopta.**

## 4. Métricas de rendimiento propuestas (K12)

| SLI | Definición | Objetivo propuesto |
|---|---|---|
| M1 | Fin de la recepción del cuerpo → 202 | p95 < 1 s (O2) |
| M2 | `creado_en` → `analizado_en`, por tipo | JPEG/PNG/PDF ≤ 10 MB: p95 ≤ 2 s (el CDR medido usa < 0.25 s del presupuesto en el caso típico) |
| M3 | Archivos/min sostenidos sin que M2 se degrade más de un 20 % | se mide en F6 con N workers |
| M4 | % de archivos con VT `no_evaluada` | se reporta; no es objetivo |
| M5 | Profundidad de la cola y espera en cola | alerta si la espera supera 2 s |

Se calculan con los campos que ya existen (`archivo.creado_en`, `analizado_en`, `resultado_analisis.duracion_ms`)
y se exponen en `GET /v1/admin/metrics`. No hace falta infraestructura nueva. La prueba de carga se hace en F6.
