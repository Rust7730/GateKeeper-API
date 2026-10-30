# Agentes para el desarrollo de la API — Diseño

**Fecha:** 2026-10-29 · **Estado:** aprobada; ampliada el mismo día con `gk-db` (aprobado por el usuario tras el análisis
`docs/superpowers/analisis/2026-10-29-bd-repo-y-motor.md`: PostgreSQL en un solo repositorio)

## 1. Objetivo y alcance

Definir los subagentes de Claude Code con los que se va a construir Gatekeeper, con roles separados para que nadie
apruebe su propio trabajo y para que la seguridad y el KG no dependan de la disciplina de un solo agente.

- **Dentro del alcance ahora:** el servicio `api` (FastAPI: autenticación, recepción, máquina de estados,
  endpoints, rate limit, SSE) y el `coordinator`, que según K08 usa la misma imagen y vive en `api/`.
- **Fuera por ahora:** worker, reputation, nginx, ClamAV/freshclam y el dashboard Angular.
- **Pospuesto:** un agente de rendimiento (`gk-performance`). Se agrega cuando F2 pueda medirse de punta a
  punta. Mientras tanto, la latencia la cubren `gk-api-dev` y `gk-security` (sección 4).

## 2. Agentes

Se definen como archivos en `.claude/agents/` dentro del repositorio, para que viajen con el proyecto.

| Agente | Responsabilidad | Escribe en | Herramientas | Modelo |
|---|---|---|---|---|
| `gk-api-dev` | Implementa los pasos de api y coordinator siguiendo `gatekeeper-guardian`: pruebas unitarias primero, parámetros del KG, nada inventado, latencia medida. Usa los repositorios de gk-db sin escribir SQL | `api/` excepto `api/db/` y `api/migrations/` (código y `api/tests/`) | Read, Grep, Glob, Edit, Write, Bash | opus |
| `gk-security` | **Antes:** escribe las pruebas de los vectores del paso en `tests/attack-matrix/` y comprueba que fallen. **Después:** revisa el diff contra INV-01…INV-10, decisiones, OWASP y CWE, y corre Bandit. Veredicto `aprobado` o `cambios requeridos` | `tests/attack-matrix/` | Read, Grep, Glob, Write, Edit, Bash | opus |
| `gk-db` | Base de datos (PostgreSQL 16): modelos SQLAlchemy, migraciones Alembic reversibles y capa de acceso. `aplicacion_id` obligatorio en toda consulta de archivos (INV-10), transición atómica, bitácora en la misma transacción (INV-08), nada sensible en claro. Prueba contra PostgreSQL real en Docker, nunca SQLite | `api/db/`, `api/migrations/` | Read, Grep, Glob, Edit, Write, Bash | opus |
| `gk-kg` | **Único escritor** del KG y de `docs/decisiones.md`: contexto del paso, estados y decisiones como propuestas pendientes. Confirma solo con la aprobación textual del usuario que le pasa la sesión principal | `context/gatekeeper_kg.json`, `docs/decisiones.md` | Read, Grep, Glob, Edit, Bash (solo `kg.py`) | sonnet |
| `gk-commit` | Controles del diff y commit local en una rama (sección 5) | git local | Read, Grep, Glob, Bash | sonnet |

**Por qué un único escritor del KG:** `kg.py` reemplaza el archivo completo en cada escritura. Si dos agentes lo
corrieran en paralelo, el último borraría los cambios del otro. Con un solo escritor, el KG tiene un único
responsable y los demás solo lo leen.

**La sesión principal** (el usuario + Claude) orquesta: decide el orden, lanza los agentes, les pasa los
relevos, habla con el usuario y es la única vía para confirmar decisiones. **Ningún agente le pregunta a otro ni
decide por el usuario.**

## 3. Reglas comunes a los cuatro agentes

1. Al empezar, leer `.claude/skills/gatekeeper-guardian/SKILL.md` y seguirla, con estas adaptaciones al trabajo
   con varios agentes:
   - Solo `gk-kg` ejecuta las escrituras de `kg.py` (`estado`, `decision`, `confirmar`). Los demás usan solo
     `contexto`, `buscar`, `vecinos`, `pendientes` y `validar`, y ponen en su reporte lo que hay que registrar.
   - Las pruebas de los vectores de la matriz las escribe `gk-security`. Las pruebas unitarias del código las
     escribe `gk-api-dev`. Así, el autor del control no escribe la prueba que lo aprueba.
2. `docs/decisiones.md` manda sobre `context/gatekeeper_contexto.json` y `context/gatekeeper_plan.json`.
3. Ante un choque con una invariante o una decisión, o ante un valor que falta: detenerse y reportarlo. Nunca
   resolverlo solo.
4. Nunca confirmar una decisión. Las decisiones nuevas son propuestas hasta que el usuario las aprueba.
5. Escribir solo en las carpetas propias (sección 2). Lo demás es de solo lectura.
6. Trabajar y reportar en español.
7. Cerrar siempre con el reporte de la sección 4.3.

## 4. Flujo de un paso

### 4.1 Secuencia (ejemplo: F2.07)

1. **`gk-kg`**: `kg.py contexto F2.07`; marca el paso como `en_progreso` y entrega el contexto.
2. **`gk-security`**: escribe las pruebas de los vectores del paso (p. ej. `tests/attack-matrix/test_vec14_*.py`)
   y las corre. Deben **fallar**; si pasan sin implementación, la prueba no detecta nada y se corrige.
3. **`gk-api-dev`**: escribe sus pruebas unitarias y luego el código, hasta que pasen sus pruebas y las de
   seguridad. Mide la latencia (4.4).
4. **`gk-security`**: revisa el diff. Si el veredicto es `cambios requeridos`, vuelve al punto 3, **con un
   máximo de 2 vueltas**. Si a la tercera revisión sigue sin aprobarse, la sesión principal lleva el caso al
   usuario.
   Si el paso toca la base de datos, **`gk-db`** trabaja entre el punto 2 y el 3: esquema, migración y repositorios,
   que gk-api-dev usa después.
5. **`gk-kg`**: registra el estado del paso y, si las hay, las decisiones nuevas como propuestas. El usuario
   decide.
6. **`gk-commit`**: controles y commit local.

Si en cualquier punto un agente responde `detenido`, el flujo se pausa y la sesión principal le presenta al usuario
el bloqueo o la pregunta.

### 4.2 Estado del paso

`gk-kg` aplica las reglas de `kg.py`. Un paso no queda `hecho` mientras su fase tenga dependencias abiertas (hoy F1
para todo F2): queda `en_progreso` con una nota de lo que falta. `--forzar` se usa solo si el usuario lo pide.

### 4.3 Reporte de cada agente

```
Reporte · <agente> · <paso>
- Resultado: listo | detenido | cambios requeridos | aprobado | rechazado
- Archivos: <rutas tocadas>
- Pruebas: <comando + resumen de la salida real>
- Latencia: <M1 o función medida, con número; o "no aplica">
- Para gk-kg: <estado sugerido; propuestas de decisión>
- Bloqueos / preguntas para el usuario: <o "ninguno">
```

El veredicto de `gk-security` incluye además una lista de hallazgos con este formato:

```
- [alta|media|baja] <archivo:línea> — <problema> — <INV/CWE/decisión afectada> — <corrección sugerida>
```

Con un solo hallazgo de severidad **alta**, el resultado es `cambios requeridos`.

El veredicto también incluye la línea `Árbol revisado: <hash>`, que es el hash del árbol de trabajo que se revisó
y lo calcula `.claude/skills/gatekeeper-guardian/scripts/arbol.py`. Así la aprobación queda atada a ese contenido
exacto. Si después cambia un solo archivo, el veredicto deja de valer. El hash excluye `context/gatekeeper_kg.json`
y `docs/decisiones.md`: gk-kg los escribe después de la revisión (paso 5 del flujo) y su validez la comprueba el
control 6 de gk-commit.

### 4.4 Latencia mientras no exista `gk-performance`

- `gk-api-dev` mide en cada paso lo que toca del camino del archivo: M1 (202 en p95 < 1 s, medido desde el fin de
  la recepción del cuerpo) con un cliente de pruebas, y el tiempo de cada función nueva. Reporta números, no
  estimaciones.
- `gk-security` incluye en su revisión que antes del 202 no se haga nada pesado: solo streaming a disco, SHA-256,
  insertar en la BD y encolar.
- `gk-commit` exige que el reporte de `gk-api-dev` traiga la línea de latencia con números, o "no aplica" con
  la razón.

## 5. Controles de `gk-commit`

Se aplican en orden. El primero que falla detiene el commit y el reporte explica la causa:

1. **Repositorio y rama.** El repo existe. Nunca se hace commit en `main`/`master`: si estamos ahí, se crea la rama
   `<fase>/<paso>-<slug>` (p. ej. `f2/f2.07-rate-limit`).
2. **Alcance.** Cada archivo cambiado pertenece a la carpeta de un agente: `api/` → gk-api-dev,
   `tests/attack-matrix/` → gk-security, `api/db/` y `api/migrations/` → gk-db, `context/gatekeeper_kg.json` y `docs/decisiones.md` → gk-kg. Cualquier
   otro archivo se rechaza y se lista. Lo de infraestructura y configuración (p. ej. `pyproject.toml` en la raíz,
   CI) requiere que la sesión principal lo autorice de forma explícita para ese commit.
3. **Secretos.** `.env` no está en staging y figura en `.gitignore`. El diff no contiene llaves privadas,
   cadenas con forma de API key de VirusTotal (64 hex) ni asignaciones `*_KEY=`, `*_SECRET=`, `*_TOKEN=` con
   valor literal.
4. **Calidad.** Se ejecutan `ruff check`, `ruff format --check`, `pytest` (sobre `api/` y `tests/attack-matrix/`) y
   `bandit -r api/` sin hallazgos de severidad media o alta. Se usa la salida propia de `gk-commit`, no la de
   otro agente.
5. **Relevos.** Existe el veredicto `aprobado` de `gk-security` para este paso y el reporte de `gk-api-dev` con
   latencia. Después del staging, el hash de `arbol.py` tiene que coincidir con el `Árbol revisado` del veredicto;
   si difiere, se pide una nueva revisión. Si falta alguna herramienta de los controles, el resultado es
   `rechazado`: nunca se salta un control. Los cambios ajenos al alcance se listan, pero nunca se borran, revierten
   ni sacan de staging.
6. **KG.** `kg.py validar` sin aristas rotas. Una decisión que aparece `confirmada` en el diff solo pasa si la
   sesión principal declara que el usuario la aprobó.
7. **Mensaje.** Conventional Commits, con el paso en el asunto (p. ej. `feat(api): rate limit por API key [F2.07]`),
   y un cuerpo con invariantes tocadas, vectores en verde, latencia medida y decisiones pendientes. Termina con:
   `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`

**Nunca:** `--no-verify`, `--amend` sobre commits ajenos, `push`, `--force`, `reset --hard`.

## 6. Cómo se hacen cumplir los límites

| Límite | Mecanismo |
|---|---|
| Qué herramientas usa cada agente | Campo `tools` del agente (lo aplica Claude Code) |
| En qué carpetas escribe | Instrucciones del agente + control 2 de `gk-commit` |
| Quién escribe el KG | Instrucciones + control 6 de `gk-commit` + `kg.py` (las decisiones nacen pendientes) |
| Que no se confirme nada sin el usuario | `kg.py decision` crea propuestas; `confirmar` solo lo corre `gk-kg` con la aprobación citada |

**Limitación declarada:** Claude Code no restringe la escritura por carpeta. Un agente que ignore sus instrucciones
podría escribir fuera de su carpeta, pero el control 2 lo detecta antes del commit. Si hace falta, más adelante
se puede reforzar con un hook `PreToolUse` que valide las rutas.

## 7. Requisitos previos

| Requisito | Paso del plan | Estado |
|---|---|---|
| Repositorio git con la estructura del plan | F0.02 | pendiente |
| uv, Python 3.12, ruff, pytest, Bandit (en esta máquina faltan uv y Python 3.12) | F0.03 | pendiente |
| `.gitignore` con `.env` | F0.05 | pendiente |

Sin F0.02, `gk-commit` no puede funcionar. Sin F0.03, los controles 4 de commit y la medición de latencia no son
reproducibles.

## 8. Validación de los agentes

Antes de usarlos en el proyecto real, se prueban sobre una copia del proyecto:

1. **Flujo completo sobre F2.04** (máquina de estados). Resultado esperado:
   - las pruebas de `gk-security` fallan primero;
   - `gk-api-dev` las hace pasar y reporta latencia;
   - `gk-security` aprueba;
   - `gk-kg` deja F2.04 en `en_progreso`, porque F1 está abierta;
   - `gk-commit` hace el commit en una rama `f2/…`.
2. **Rechazos de `gk-commit`:** debe negarse con
   - un diff que incluye `.env`;
   - un diff con un archivo fuera de alcance;
   - un diff sin veredicto de seguridad.
3. **Choque:** pedirle a `gk-api-dev` que decida el tipo por Content-Type. Debe responder `detenido` citando INV-02.

Cada prueba se da por buena con evidencia (salida de comandos, diff, estado del KG) y no por lo que diga el reporte
del agente.

## 9. Archivos

- `.claude/agents/gk-api-dev.md`
- `.claude/agents/gk-security.md`
- `.claude/agents/gk-kg.md`
- `.claude/agents/gk-commit.md`
- `.claude/agents/gk-db.md`
- Ajuste en `.claude/skills/gatekeeper-guardian/SKILL.md`: una sección "Trabajo con agentes" con las dos
  adaptaciones de la regla 3.1.

## 10. Pendiente relacionado

La iteración 2 de la evaluación de `gatekeeper-guardian` quedó incompleta: dos ejecuciones, máquina de estados y
rate limit, ambas con la skill, no terminaron al cerrarse la sesión. Se retoma aparte; no bloquea este diseño.

## 11. Correcciones de la revisión final (2026-10-29)

La revisión de toda la rama encontró un hallazgo crítico y cuatro importantes. Se corrigieron así; donde esta
sección contradice a las anteriores, manda esta.

| Id | Problema | Corrección |
|---|---|---|
| C1 | La revisión y la búsqueda de secretos usaban `git diff`, que no muestra lo que ya está en staging, aunque el hash sí lo incluía | `arbol.py --diff` y `--archivos` muestran de HEAD al árbol exactamente lo que cubre el hash; seguridad revisa eso y gk-commit lo escanea. Ningún agente salvo gk-commit hace `git add` |
| I1 | Los archivos de gk-kg, excluidos del hash, no tenían lista blanca | `kg.py diff-permitido HEAD`: solo pasan estado, historial y nota de pasos y fases (con las reglas de `hecho`), propuestas K## nuevas en `pendiente` con sus aristas `afecta`, y `meta.conteos`. Todo lo demás exige `Aprobación del usuario (<id>): "…"` con el id exacto. gk-kg cierra con `KG registrado: <hashes>` y gk-commit los compara |
| I2 | Las pruebas de ataque no tenían sello | En la fase A, gk-security reporta `Pruebas de ataque: <arbol.py --sello tests/attack-matrix>`; la fase B y gk-commit verifican que no cambió |
| I3 | Huecos en la búsqueda de secretos | `detect-secrets scan --all-files` (determinista) sobre los archivos del diff, más nombres en español, contraseñas, DSN y URLs con credenciales; `.gitignore` cubre `.env.*` excepto `.env.example` |
| I4 | El control 5 exigía siempre un reporte de gk-api-dev | Se exige el reporte del implementador real (gk-api-dev y/o gk-db). Un commit de solo documentación o KG no requiere reporte de implementador, pero sí el veredicto de seguridad |

Además, desde el 2026-10-29 `.claude/agents/` está en `.gitignore` por decisión del usuario. Las pruebas de contrato
de `tests/tooling/` se omiten si la carpeta no existe.
