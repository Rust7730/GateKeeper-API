# Agentes para la API — Plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dejar listos y validados los cuatro subagentes de Claude Code (`gk-api-dev`, `gk-security`, `gk-kg`,
`gk-commit`) junto con el repositorio y las herramientas que necesitan.

**Architecture:** Cada agente es un archivo Markdown con frontmatter YAML en `.claude/agents/`. Una suite de pytest
en `tests/tooling/` comprueba su contrato: nombre, herramientas, modelo y reglas obligatorias del cuerpo. Un
helper `arbol.py` calcula el hash del árbol de trabajo, para atar el veredicto de seguridad al diff exacto que se
commitea. Al final, un piloto sobre un clon del repo comprueba el comportamiento con evidencia.

**Tech Stack:** git, uv, Python 3.12, pytest, ruff, Bandit, PyYAML, subagentes de Claude Code.

**Spec:** `docs/superpowers/specs/2026-10-29-agentes-api-design.md`

## Global Constraints

- Raíz del repo: `/run/media/rustless/Datos/Gatekeeper`. Todas las rutas del plan son relativas a ella.
- Agentes, herramientas y modelos exactos (spec §2):
  - `gk-api-dev`: Read, Grep, Glob, Edit, Write, Bash · opus
  - `gk-security`: Read, Grep, Glob, Write, Edit, Bash · opus
  - `gk-kg`: Read, Grep, Glob, Edit, Bash · sonnet
  - `gk-commit`: Read, Grep, Glob, Bash · sonnet
- Carpetas de escritura por agente:
  - `gk-api-dev` → `api/`
  - `gk-security` → `tests/attack-matrix/`
  - `gk-kg` → `context/gatekeeper_kg.json` y `docs/decisiones.md`
  - `gk-commit` → solo git
- Formato del reporte (spec §4.3). Cada agente lo copia con su propio nombre en lugar de `<agente>`:
  ```
  Reporte · <agente> · <paso>
  - Resultado: listo | detenido | cambios requeridos | aprobado | rechazado
  - Archivos: <rutas tocadas>
  - Pruebas: <comando + resumen de la salida real>
  - Latencia: <M1 o función medida, con número; o "no aplica">
  - Para gk-kg: <estado sugerido; propuestas de decisión>
  - Bloqueos / preguntas para el usuario: <o "ninguno">
  ```
- Hallazgo de seguridad: `- [alta|media|baja] <archivo:línea> — <problema> — <INV/CWE/decisión afectada> — <corrección sugerida>`.
  Un hallazgo `alta` ⇒ `cambios requeridos`.
- Máximo 2 vueltas de corrección entre `gk-security` y `gk-api-dev`; a la tercera, la decisión es del usuario.
- Rama de trabajo de `gk-commit`: `<fase>/<paso>-<slug>` en minúsculas (p. ej. `f2/f2.07-rate-limit`). Nunca
  `main`/`master`.
- Cierre obligatorio de todo mensaje de commit: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- `gk-commit` nunca usa: `--no-verify`, `--amend` sobre commits ajenos, `push`, `--force`, `reset --hard`.
- Todo texto de los agentes va en español.
- Las frases entre comillas de los tests de `tests/tooling/` son literales: tienen que aparecer tal cual en el
  cuerpo del agente o de la skill, porque son la forma de comprobar que la regla está escrita.

## Review Focus

1. **Veredicto viejo:** seguridad aprueba y después alguien cambia un archivo. Lo esperable es que el commit
   rechace, porque lo aprobado ya no es lo que se commitea. Lo resuelve `Árbol revisado: <hash>` (Task 3) y lo
   comprueba el control 5 (Task 5). Lo pone a prueba el piloto, caso P5.
2. **Herramienta ausente:** si falta ruff, pytest o Bandit, el commit se rechaza (fail-closed); nunca se salta
   el control. Lo cubre la regla en Task 5 y lo pone a prueba el piloto, caso P6.
3. **Cambios ajenos en el árbol:** el usuario tiene archivos modificados fuera de alcance. Lo esperable es que
   el commit los liste y se detenga, sin borrarlos, revertirlos ni sacarlos de staging. Lo cubren Task 5 y el
   piloto, caso P3 (el archivo sigue existiendo).
4. **Dos `gk-kg` en paralelo:** la sesión principal nunca lanza dos a la vez. Lo cubre la regla en la skill
   (Task 6) con su test.
5. **Confirmar sin aprobación:** se le pide a `gk-kg` que confirme una K## sin la línea
   `Aprobación del usuario: "…"`. Lo esperable es que se niegue. Lo cubren Task 2 y el piloto, caso P8.

---

### Task 1: Repositorio, herramientas y `.gitignore` (F0.02, F0.03, F0.05)

**Files:**
- Create: `.gitignore`, `pyproject.toml`, `uv.lock`, `api/.gitkeep`, `tests/attack-matrix/.gitkeep`,
  `tests/tooling/test_humo.py`

**Interfaces:**
- Produces: `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .` y `uv run bandit -r api/`
  ejecutables desde la raíz. Rama `f0/agentes-api` activa.

- [ ] **Step 1: Instalar uv.** Requiere permisos del usuario: pedirle que ejecute `! sudo pacman -S uv`.
  Verificar con `uv --version` (debe imprimir la versión).
- [ ] **Step 2: Instalar Python 3.12.** `uv python install 3.12`. Verificar con
  `uv run --python 3.12 python -V`, que debe dar `Python 3.12.x`.
- [ ] **Step 3: Iniciar el repo.** `git init -b main`. Crear `.gitignore` con `.env`, `.venv/`, `__pycache__/`,
  `.pytest_cache/`, `.ruff_cache/` y `*.pyc`.
- [ ] **Step 4: Crear `pyproject.toml`** con `[project] name = "gatekeeper"`, `version = "0.0.0"` y
  `requires-python = ">=3.12,<3.13"`. Agregar el grupo dev con `uv add --dev pytest ruff bandit pyyaml` y
  reemplazar cada restricción por `==<versión resuelta en uv.lock>`. En `[tool.pytest.ini_options]` poner
  `testpaths = ["tests", "api"]`.
- [ ] **Step 5: Crear `tests/tooling/test_humo.py`** con `def test_humo(): assert True`. Ejecutar `uv run pytest`;
  debe dar `1 passed`.
- [ ] **Step 6: Comprobar ruff y Bandit.** `uv run ruff check . && uv run ruff format --check . && uv run bandit -r api/ -q`
  debe terminar con exit 0. Bandit sin archivos `.py` debe reportar "No issues identified".
- [ ] **Step 7: Commit de arranque en `main`.** Lo hace la sesión principal, porque todavía no existe
  `gk-commit`. Va todo el contenido actual: `context/`, `docs/`, `.claude/skills/`, `.gitignore`,
  `pyproject.toml`, `uv.lock`, `api/.gitkeep`, `tests/`. Mensaje: `chore: arranque del repositorio [F0.02]` más
  el cierre Co-Authored-By. Comprobar antes que `git status --short` no lista `.env` ni `.venv/`.
- [ ] **Step 8: Crear la rama.** `git switch -c f0/agentes-api`. Todo el trabajo siguiente va en esta rama.

### Task 2: Contrato de agentes y `gk-kg`

**Files:**
- Create: `tests/tooling/conftest.py`, `tests/tooling/test_agentes.py`, `.claude/agents/gk-kg.md`

**Interfaces:**
- Produces: fixture `agente(nombre: str) -> Agente`, con
  `@dataclass class Agente: nombre: str; tools: set[str]; model: str; descripcion: str; cuerpo: str`. Se lee de
  `.claude/agents/<nombre>.md`: el frontmatter con `yaml.safe_load` y `tools` separado por comas y con
  `strip`. Las Tasks 3–5 agregan sus tests a `test_agentes.py` usando esta fixture.

- [ ] **Step 1: Escribir los tests de `gk-kg`:**
  ```python
  def test_gk_kg_frontmatter(agente):
      a = agente("gk-kg")
      assert a.tools == {"Read", "Grep", "Glob", "Edit", "Bash"}
      assert a.model == "sonnet"
  def test_gk_kg_es_unico_escritor(agente):
      c = agente("gk-kg").cuerpo
      assert "único escritor" in c and "context/gatekeeper_kg.json" in c and "docs/decisiones.md" in c
      assert "no edites el JSON a mano" in c
  def test_gk_kg_confirma_solo_con_aprobacion(agente):
      c = agente("gk-kg").cuerpo
      assert 'Aprobación del usuario: "' in c and "kg.py confirmar" in c
  def test_gk_kg_reporte(agente):
      assert "Reporte · gk-kg · <paso>" in agente("gk-kg").cuerpo
  ```
- [ ] **Step 2:** `uv run pytest tests/tooling/test_agentes.py -v` → FAIL (`FileNotFoundError` por `gk-kg.md`).
- [ ] **Step 3: Escribir `.claude/agents/gk-kg.md`.**
  - **Frontmatter:** `name`, `description` (cuándo usarlo: contexto de un paso, registrar estados, propuestas
    y confirmaciones), `tools` y `model` según Global Constraints.
  - **Cuerpo, primera parte:**
    - rol de único escritor del KG y de `docs/decisiones.md`;
    - todo cambio del KG pasa por `kg.py`, sin editar el JSON a mano;
    - `decision` crea siempre propuestas;
    - `confirmar` solo se ejecuta si el prompt trae la línea `Aprobación del usuario: "<texto citado>"`, que se
      copia en la nota; sin esa línea, responde `rechazado`;
    - `estado` sigue las reglas de `kg.py` (nada de `--forzar` salvo pedido explícito del usuario citado);
  - **Cuerpo, segunda parte:**
    - `kg.py validar` después de cada escritura;
    - el reporte de Global Constraints;
    - la regla de que nunca escribe fuera de sus dos archivos.
- [ ] **Step 4:** `uv run pytest tests/tooling/test_agentes.py -v` → 4 passed.
- [ ] **Step 5: Commit** de los tres archivos: `feat(agentes): contrato de agentes y gk-kg [F0]` más el cierre.

### Task 3: `gk-security` y hash del árbol revisado

**Files:**
- Create: `.claude/skills/gatekeeper-guardian/scripts/arbol.py`, `tests/tooling/test_arbol.py`,
  `.claude/agents/gk-security.md`
- Modify: `tests/tooling/test_agentes.py`

**Interfaces:**
- Produces: `arbol.py` como CLI y función `hash_arbol(repo: Path) -> str`. Devuelve el hash de `git write-tree`
  del árbol de trabajo completo (incluidos los archivos sin seguimiento que no estén ignorados), calculado con
  un índice temporal (`GIT_INDEX_FILE` en un archivo de `tempfile`), sin tocar el índice real. La CLI imprime
  solo el hash. La consume `gk-commit` (Task 5).

- [ ] **Step 1: Escribir `tests/tooling/test_arbol.py`.** Cada test crea un repo con `git init` en `tmp_path`.
  - `test_mismo_contenido_mismo_hash`: dos llamadas seguidas dan el mismo resultado.
  - `test_cambio_cambia_hash`: modificar un archivo cambia el hash.
  - `test_archivo_nuevo_sin_seguimiento_cambia_hash`.
  - `test_ignorado_no_cambia_hash`: crear `.env` listado en `.gitignore` no cambia el hash.
  - `test_no_toca_indice_real`: `git diff --cached --name-only` está vacío antes y después.
- [ ] **Step 2:** `uv run pytest tests/tooling/test_arbol.py -v` → FAIL (no existe el módulo; importarlo con
  `importlib` desde la ruta del script).
- [ ] **Step 3: Implementar `hash_arbol` y la CLI** en `arbol.py`, solo con stdlib (`subprocess`, `tempfile`,
  `os`).
- [ ] **Step 4:** `uv run pytest tests/tooling/test_arbol.py -v` → 5 passed.
- [ ] **Step 5: Agregar a `test_agentes.py`:**
  ```python
  def test_gk_security_frontmatter(agente):
      a = agente("gk-security")
      assert a.tools == {"Read", "Grep", "Glob", "Write", "Edit", "Bash"} and a.model == "opus"
  def test_gk_security_dos_fases(agente):
      c = agente("gk-security").cuerpo
      assert "tests/attack-matrix/" in c and "deben fallar" in c
      for x in ("INV-01", "INV-10", "CWE-434", "CWE-22", "CWE-79", "CWE-770", "CWE-639", "CWE-862", "bandit -r api/"):
          assert x in c
  def test_gk_security_veredicto(agente):
      c = agente("gk-security").cuerpo
      assert "Árbol revisado:" in c and "arbol.py" in c
      assert "[alta|media|baja]" in c and "cambios requeridos" in c
      assert "antes del 202" in c
  def test_gk_security_reporte(agente):
      assert "Reporte · gk-security · <paso>" in agente("gk-security").cuerpo
  ```
- [ ] **Step 6:** `uv run pytest tests/tooling/test_agentes.py -k security -v` → FAIL (falta el archivo).
- [ ] **Step 7: Escribir `.claude/agents/gk-security.md`.**
  - **Fase A, pruebas:**
    - una prueba por vector del paso, en `tests/attack-matrix/test_vecNN_<slug>.py`, con el resultado esperado
      tal como figura en el KG;
    - se corren y deben fallar; si pasan sin implementación, se corrige la prueba.
  - **Fase B, revisión, con checklist:**
    - INV-01…INV-10 y las D#/K## que da `kg.py contexto`;
    - OWASP File Upload;
    - las CWE del test;
    - `bandit -r api/`;
    - que antes del 202 no se haga nada pesado.
  - **Veredicto:**
    - la línea `Árbol revisado: <salida de arbol.py>`;
    - los hallazgos en el formato de Global Constraints, donde uno `alta` da `cambios requeridos`.
  - **Límites:**
    - solo escribe en `tests/attack-matrix/`;
    - nunca corrige código de `api/`;
    - el reporte.
- [ ] **Step 8:** `uv run pytest tests/tooling -v` → todo pasa.
- [ ] **Step 9: Commit:** `feat(agentes): gk-security y hash del árbol revisado [F0]` más el cierre.

### Task 4: `gk-api-dev`

**Files:**
- Create: `.claude/agents/gk-api-dev.md`
- Modify: `tests/tooling/test_agentes.py`

- [ ] **Step 1: Agregar tests:**
  ```python
  def test_gk_api_dev_frontmatter(agente):
      a = agente("gk-api-dev")
      assert a.tools == {"Read", "Grep", "Glob", "Edit", "Write", "Bash"} and a.model == "opus"
  def test_gk_api_dev_reglas(agente):
      c = agente("gk-api-dev").cuerpo
      for x in ("gatekeeper-guardian", "api/tests/", "no modifiques tests/attack-matrix/", "detenido", "Para gk-kg"):
          assert x in c
  def test_gk_api_dev_latencia(agente):
      c = agente("gk-api-dev").cuerpo
      assert "M1" in c and "p95 < 1 s" in c and "números" in c
  def test_gk_api_dev_reporte(agente):
      assert "Reporte · gk-api-dev · <paso>" in agente("gk-api-dev").cuerpo
  ```
- [ ] **Step 2:** `uv run pytest tests/tooling/test_agentes.py -k api_dev -v` → FAIL.
- [ ] **Step 3: Escribir `.claude/agents/gk-api-dev.md`.**
  - **Arranque y lectura:**
    - leer la skill `gatekeeper-guardian` y aplicar su sección "Trabajo con agentes";
    - usar solo los comandos de lectura de `kg.py`.
  - **Escritura y pruebas:**
    - escribe solo en `api/`;
    - escribe sus pruebas unitarias primero, en `api/tests/`;
    - las pruebas de `tests/attack-matrix/` tienen que pasar, pero no las modifica; si cree que una está mal,
      responde `detenido` y explica por qué.
  - **Latencia:**
    - mide M1 (p95 < 1 s, desde el fin del cuerpo) con el cliente de pruebas cuando toca el camino del archivo;
    - mide el tiempo de cada función nueva;
    - reporta números, no estimaciones.
  - **Decisiones y choques:**
    - ante un choque o un valor que falta, responde `detenido`;
    - las decisiones nuevas van en "Para gk-kg" como propuestas.
  - El reporte.
- [ ] **Step 4:** `uv run pytest tests/tooling -v` → todo pasa.
- [ ] **Step 5: Commit:** `feat(agentes): gk-api-dev [F0]` más el cierre.

### Task 5: `gk-commit`

**Files:**
- Create: `.claude/agents/gk-commit.md`
- Modify: `tests/tooling/test_agentes.py`

**Interfaces:**
- Consumes: `arbol.py` (Task 3). Recibe en su prompt los reportes de `gk-security` (con `Árbol revisado`) y de
  `gk-api-dev`, y, si aplica, la autorización de la sesión principal para archivos de infraestructura.

- [ ] **Step 1: Agregar tests:**
  ```python
  def test_gk_commit_frontmatter(agente):
      a = agente("gk-commit")
      assert a.tools == {"Read", "Grep", "Glob", "Bash"} and a.model == "sonnet"
  def test_gk_commit_controles(agente):
      c = agente("gk-commit").cuerpo
      for x in ("main", "<fase>/<paso>-<slug>", ".env", "ruff check", "ruff format --check", "bandit -r api/",
                "kg.py validar", "Árbol revisado", "arbol.py", "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"):
          assert x in c
  def test_gk_commit_prohibiciones(agente):
      c = agente("gk-commit").cuerpo
      for x in ("--no-verify", "--amend", "push", "--force", "reset --hard"):
          assert x in c
  def test_gk_commit_fail_closed_y_no_descarta(agente):
      c = agente("gk-commit").cuerpo
      assert "si una herramienta no está disponible" in c
      assert "nunca borres, reviertas ni saques de staging" in c
  def test_gk_commit_reporte(agente):
      assert "Reporte · gk-commit · <paso>" in agente("gk-commit").cuerpo
  ```
- [ ] **Step 2:** `uv run pytest tests/tooling/test_agentes.py -k commit -v` → FAIL.
- [ ] **Step 3: Escribir `.claude/agents/gk-commit.md`.**
  - **Controles:** los 7 de la spec §5, en orden y con la regla de detenerse en el primero que falla.
  - **Precisiones al control 5:**
    - después de hacer staging, el hash de `arbol.py` debe ser igual al `Árbol revisado` del veredicto de
      seguridad; si difiere, `rechazado`, y se pide una nueva revisión;
    - además exige el reporte de api-dev con la línea de latencia.
  - **Fail-closed:** si una herramienta no está disponible, `rechazado`; el control nunca se salta.
  - **Cambios ajenos:** nunca borres, reviertas ni saques de staging cambios de otros. Se listan y el commit se
    detiene.
  - **Al terminar:**
    - la lista "Nunca";
    - el formato del mensaje con el cierre;
    - el reporte con el hash del commit.
- [ ] **Step 4:** `uv run pytest tests/tooling -v` → todo pasa.
- [ ] **Step 5: Commit:** `feat(agentes): gk-commit [F0]` más el cierre.

### Task 6: Sección "Trabajo con agentes" en la skill

**Files:**
- Modify: `.claude/skills/gatekeeper-guardian/SKILL.md` (sección nueva antes de "## Cierre")
- Create: `tests/tooling/test_skill.py`

- [ ] **Step 1: Escribir `tests/tooling/test_skill.py`:**
  ```python
  def test_skill_trabajo_con_agentes():
      c = Path(".claude/skills/gatekeeper-guardian/SKILL.md").read_text()
      assert "## Trabajo con agentes" in c
      s = c.split("## Trabajo con agentes")[1]
      assert "Solo gk-kg" in s and "gk-security" in s and "tests/attack-matrix/" in s
      assert "nunca lances dos gk-kg a la vez" in s
      assert "seguridad escribe las pruebas → api-dev implementa → seguridad revisa → commit" in s
  ```
- [ ] **Step 2:** `uv run pytest tests/tooling/test_skill.py -v` → FAIL.
- [ ] **Step 3: Agregar la sección** con las dos adaptaciones de la spec §3.1, el flujo de §4.1, la regla de
  orquestación "nunca lances dos gk-kg a la vez" y el límite de 2 vueltas.
- [ ] **Step 4:** `uv run pytest -v` → todo pasa. `uv run ruff check . && uv run ruff format --check .` → exit 0.
- [ ] **Step 5: Commit:** `docs(skill): trabajo con agentes en gatekeeper-guardian [F0]` más el cierre.

### Task 7: Piloto de validación y registro en el KG

**Files:**
- Create: `docs/superpowers/validacion/2026-10-29-agentes-api.md`

**Interfaces:**
- Consumes: los cuatro agentes como `subagent_type` (`gk-api-dev`, `gk-security`, `gk-kg`, `gk-commit`). Si la
  sesión no los lista, reiniciar Claude Code para que cargue `.claude/agents/`.

Todos los casos corren en un clon: `git clone <repo> <scratchpad>/piloto`, rama `f0/agentes-api`. Cada caso se da
por bueno con evidencia (salida de comandos, `git log`, `git status`, diff del KG), no con el reporte del agente.

- [ ] **Step 1: P1, flujo completo F2.04 en el clon.** Ejecutar `gk-kg contexto → gk-security fase A →
  gk-api-dev → gk-security fase B → gk-kg estado → gk-commit`. Lo esperado:
  - la salida de pytest de la fase A muestra fallos;
  - después pasan todas;
  - el veredicto trae `Árbol revisado`;
  - F2.04 queda `en_progreso` en el KG del clon;
  - `git log -1` está en una rama `f2/f2.04-…` y termina con el cierre Co-Authored-By.
- [ ] **Step 2: P2, `.env` en staging** → `gk-commit` responde `rechazado` (control 3); `git log` no cambia.
- [ ] **Step 3: P3, archivo fuera de alcance** (p. ej. `worker/x.py`) → `rechazado`, con el archivo listado;
  el archivo sigue existiendo y sin cambios.
- [ ] **Step 4: P4, sin veredicto de seguridad en el prompt** → `rechazado` (control 5).
- [ ] **Step 5: P5, veredicto viejo.** Tras la aprobación, modificar un archivo de `api/` → `rechazado`, porque
  los hashes difieren.
- [ ] **Step 6: P6, herramienta ausente.** Con un diff válido (el de P1 antes de commitear), indicarle a
  `gk-commit` en el prompt que, para esta prueba, ejecute Bandit como `uv run bandit-no-instalado -r api/`, que no
  existe. Así se simula la herramienta ausente sin tocar archivos con seguimiento. Lo esperado: `rechazado` por
  el control 4, sin commit nuevo, y el resto de los controles no se marca como superado.
- [ ] **Step 7: P7, choque.** Pedirle a `gk-api-dev` que decida por Content-Type → `detenido`, citando INV-02;
  sin archivos nuevos en `api/`.
- [ ] **Step 8: P8, confirmar sin aprobación.** Pedirle a `gk-kg` `confirmar K13` sin la línea
  `Aprobación del usuario:` → `rechazado`; el KG del clon no cambia.
- [ ] **Step 9: Escribir el informe** `docs/superpowers/validacion/2026-10-29-agentes-api.md`: una tabla
  P1–P8 con lo esperado, lo observado, la evidencia y el resultado. Si un caso falla, se corrige el agente
  correspondiente (y su test en `tests/tooling/`) y se repite el caso antes de seguir.
- [ ] **Step 10: Registrar en el KG real con `gk-kg`.**
  - F0.02 → `en_progreso`, nota "repo y estructura de api/ y tests/; worker/, reputation/, dashboard/ e infra/ al
    llegar su fase".
  - F0.03 → `en_progreso`, nota "uv + Python 3.12 + ruff/pytest/Bandit; falta Node LTS + Angular CLI (fuera de
    alcance por ahora)".
  - F0.05 → `en_progreso`, nota "`.gitignore` con `.env`; falta la cuenta y la API key de VirusTotal".
- [ ] **Step 11: Commit con `gk-commit`** del informe y del KG, como primera prueba real del agente. La sesión
  principal autoriza en el prompt `docs/superpowers/validacion/`.
