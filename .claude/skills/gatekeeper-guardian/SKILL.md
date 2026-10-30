---
name: gatekeeper-guardian
description: Guardián del proyecto Gatekeeper (API FastAPI + worker + dashboard Angular que valida, sanea y analiza archivos). Úsala SIEMPRE antes de escribir, cambiar o revisar código, infraestructura (Docker Compose, Nginx, ClamAV, redes, volúmenes), pruebas o configuración de este repositorio, aunque el pedido no nombre un paso del plan (F#.##) ni el knowledge graph. También cuando se pida avanzar una fase, implementar un endpoint, un control, el CDR, la máquina de estados, el rate limit, el dashboard, o ajustar timeouts y rendimiento. Ubica el trabajo en el KG, junta invariantes, decisiones, parámetros, vectores de ataque y métricas de latencia, exige la prueba antes del control, se detiene ante contradicciones y actualiza el estado al terminar.
---

# Guardián de Gatekeeper

Gatekeeper es un intermediario de seguridad: cada archivo que sube un usuario final pasa por aquí antes de llegar
a la aplicación cliente. De ahí salen sus dos exigencias, que esta skill protege en cada cambio:

1. **No dejar pasar nada peligroso.** Las invariantes INV-01…INV-10 y las decisiones confirmadas son el contrato
   de seguridad del proyecto. Romper una "porque era más fácil" anula el sentido del sistema.
2. **No hacer esperar al usuario final.** Cada milisegundo que tarda Gatekeeper lo paga la aplicación cliente.
   Las métricas M1–M5 son tan parte del diseño como la seguridad.

La fuente de verdad es el knowledge graph `context/gatekeeper_kg.json`. Lo complementa `docs/decisiones.md`,
que **manda** sobre `context/gatekeeper_contexto.json` y `context/gatekeeper_plan.json` cuando difieren. Todo se
consulta y se actualiza con `scripts/kg.py` (ruta relativa a esta skill), no editando el JSON a mano: el script
valida, recalcula conteos y escribe de forma atómica.

Trabaja y responde en español.

## Flujo

### 1. Ubicar el trabajo en el KG

Si el pedido nombra un paso (`F2.04`) o una fase, úsalo. Si no, búscalo:

```bash
python3 .claude/skills/gatekeeper-guardian/scripts/kg.py buscar "rate limit"
python3 .claude/skills/gatekeeper-guardian/scripts/kg.py pendientes F2
```

Si el trabajo no corresponde a ningún paso, dilo antes de seguir: puede ser trabajo legítimo que falta en el plan
o una ampliación de alcance. El alcance está cerrado a JPEG, PNG y PDF; SVG, ZIP, Office y el análisis semántico
quedan fuera por diseño. Pregunta al usuario en lugar de decidir por tu cuenta.

### 2. Juntar el contexto antes de tocar nada

```bash
python3 .claude/skills/gatekeeper-guardian/scripts/kg.py contexto F2.04      # o un nodo: svc:worker, ep:POST /v1/files
```

La salida trae la fase y sus dependencias, las invariantes, las decisiones y observaciones (D#/K##), las
verificaciones CoV, los parámetros con sus valores, los controles, los vectores de ataque, los riesgos, los
patrones vigilados y las métricas. Lee también la sección de `docs/decisiones.md` que corresponda al tema.

- **Dependencias:** si la fase depende de otra que no está `hecho`, o está bloqueada por decisiones sin
  confirmar, avísalo. El plan exige ese orden porque las pruebas de una fase suponen la infraestructura de la
  anterior. Adelantar lógica que no depende de esa infraestructura (p. ej. un módulo de dominio puro) está bien,
  pero el paso queda `en_progreso` hasta que sus dependencias existan (ver paso 6).
- **Parámetros y huecos:** usa los valores del KG o de `docs/decisiones.md` (10 MB, 40 MP, 200 páginas, 100 MB de
  descompresión, 30 s de timeout, 120/min por key, poll de 0.05 s, gracia de VT ≤ 1 s, etc.). Si el trabajo
  necesita un valor o una regla que **no** está definida (un tamaño de ráfaga, una política para un caso no
  previsto, un campo nuevo en el modelo), no lo inventes en silencio: un número inventado se vuelve una decisión
  que nadie tomó. Propónlo con su justificación, regístralo como propuesta (paso 6) y pregunta. Puedes avanzar
  en lo que no depende de ese valor.

### 3. Detenerse ante una contradicción

Si el pedido, o la forma más directa de cumplirlo, choca con una invariante o una decisión confirmada, **no
implementes**. Explica el choque citando los ids (p. ej. "esto viola INV-02 y K09"), ofrece la alternativa que
sí respeta el diseño y deja que el usuario decida. Cambiar una decisión es legítimo, pero lo decide el usuario y
queda registrado (paso 6). No es algo que se cuele en un commit.

Choques típicos en este proyecto:

| Tentación | Qué rompe | Alternativa |
|---|---|---|
| Decidir por `file.content_type`, la extensión o `file.filename` | INV-02 | python-magic sobre los bytes |
| Guardar con el nombre original | INV-03 | UUID generado por el servidor |
| Darle al worker red, acceso a la BD o a `redis-main` | INV-04, K02, F1.05 | Resultado por la cola ARQ; decide el `coordinator` |
| Mandar el archivo a VirusTotal | INV-05 | Solo `GET /api/v3/files/{sha256}` |
| Servir o leer `quarantine` desde la API pública | INV-07 | Solo la liberación de admin, que reencola en el CDR |
| Que un error o timeout termine en `limpio` | INV-09 | `error`; reintento solo si es transitorio (K11) |
| `Image.MAX_IMAGE_PIXELS = None` o ignorar `DecompressionBombWarning` | V26 | Límite explícito; la advertencia es error |
| `read_bytes()` sin tope sobre flujos de un PDF | K13 | zlib por bloques con tope de 100 MB |
| CDR síncrono dentro del job ARQ o en un hilo | K09 | Proceso hijo con `RLIMIT_AS`, kill al vencer |
| Esperar a VT hasta el timeout | K07 | Sin cuota → `no_evaluada` ya; con cuota, ≤ 1 s de gracia |
| Rate limit por IP para clientes autenticados | K10 | Por API key; IP solo sin autenticar |
| `bypassSecurityTrust*` o `innerHTML` en Angular | V28 | Interpolación |

### 4. La prueba primero

Antes de implementar un control, escribe la prueba del vector que lo comprueba y córrela para verla **fallar**.
Las pruebas de la matriz van en `tests/attack-matrix/`, una por vector, con el número y el resultado esperado
que da el KG (p. ej. `test_vec15_descarga_pendiente_409`). Así queda demostrado que la prueba detecta el problema
y que el control lo resuelve. Si no hay vector, escribe una prueba normal del comportamiento. Si existe la skill
`superpowers:test-driven-development`, síguela para este ciclo.

### 5. Implementar cuidando la latencia

Si el cambio toca el camino de un archivo (nginx → api → coordinator → worker / reputation → decisión →
descarga), indica qué métrica mueve y en qué dirección:

- **M1:** 202 en p95 < 1 s desde el fin de la recepción. Nada pesado antes del 202: solo streaming a disco +
  SHA-256 + insertar en la BD + encolar.
- **M2:** veredicto en p95 ≤ 2 s para archivos de hasta 10 MB. Paraleliza lo independiente (ClamAV ∥
  firma+CDR; worker ∥ reputation) y evita esperas fijas o polling lento.
- **M3–M5:** throughput, % de VT `no_evaluada` y espera en cola.

Cuando el impacto no sea obvio, mídelo: un tiempo dentro de la prueba o un micro-benchmark basta. Reporta el
número; no adivines. Referencias medidas: CDR de un JPEG de 12 MP ≈ 214 ms, de 40 MP ≈ 0.7 s; saneamiento de
un PDF de 200 páginas ≈ 36 ms.

Si una mejora de latencia exigiera debilitar la seguridad, o al revés, es una decisión del usuario (paso 3).

### 6. Verificar y cerrar

1. Corre las pruebas del paso y las de la fase que deben seguir en verde. Muestra la salida. Si algo falla,
   dilo; no marques el paso como hecho.
2. Actualiza el estado. Usa `en_progreso` al empezar, `bloqueado` (con nota) si algo externo lo impide y
   `hecho` solo cuando el paso cumple lo que pide **y** su fase ya tiene las dependencias terminadas:
   ```bash
   python3 .claude/skills/gatekeeper-guardian/scripts/kg.py estado F2.04 en_progreso --nota "dominio listo y probado; falta integrar con F1.07"
   ```
   Un paso marcado `hecho` le dice a quien lea el KG que puede construir encima sin revisar. Si su base (F1)
   no existe, esa promesa es falsa. El script rechaza `hecho` en ese caso; `--forzar --nota` existe solo para
   cuando el usuario lo pide explícitamente.
3. Si el trabajo produjo una decisión nueva (un valor, una regla, un campo que nadie había definido), regístrala
   como **propuesta**, nunca como confirmada:
   ```bash
   python3 .claude/skills/gatekeeper-guardian/scripts/kg.py decision --label "..." --eleccion "..." --afecta F2.04,svc:api --motivo "..."
   ```
   Anótala en `docs/decisiones.md` marcada como *pendiente de confirmar* y pregúntale al usuario en tu respuesta.
   Solo cuando él la apruebe, en un turno posterior, se ejecuta `kg.py confirmar K##`. Confirmar tus propias
   propuestas es la forma más fácil de romper el paso 3 sin darte cuenta: las decisiones del proyecto son del
   usuario.
4. `kg.py validar` debe terminar sin aristas rotas.

## Cierre

Termina tu respuesta con este bloque, para que el usuario vea de un vistazo qué se protegió:

```
Guardián · <paso o nodo>
- Invariantes: <ids respetados, o el choque detectado>
- Decisiones aplicadas: <D#/K##>
- Vectores: <vec:NN en verde / pendientes>
- Latencia: <métrica afectada y número medido, o "fuera del camino del archivo">
- KG: <estado anterior → nuevo; propuestas registradas como pendientes>
- Necesito tu decisión: <preguntas abiertas, o "nada">
```
