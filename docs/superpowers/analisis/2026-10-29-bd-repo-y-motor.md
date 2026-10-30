# Análisis: repo separado para la BD y MongoDB vs PostgreSQL — 2026-10-29

Pregunta del usuario: ¿convendría tener la base de datos en un repositorio aparte? ¿Y usar MongoDB en lugar de
PostgreSQL? Método: primero Chain-of-Verification (cada afirmación verificada por separado contra documentación
oficial, el KG o una medición) y después un adversario que ataca las opciones con esos datos.

## 1. Chain-of-Verification

### Hechos del proyecto (fuente: KG v1.3.0 y `docs/decisiones.md`)

| # | Afirmación | Verificación | Estado |
|---|---|---|---|
| P1 | Solo api y coordinator acceden a PostgreSQL; el worker no tiene acceso a la BD | F1.05 y K08 en el KG; el coordinator usa la imagen de la API | verificado |
| P2 | Las 7 entidades son relacionales: aplicacion → api_key, archivo → resultado_analisis, usuario → refresh_token, evento_auditoria | `kg.py vecinos svc:postgres` y aristas `referencia` del modelo de datos | verificado |
| P3 | La propuesta escrita y el stack fijan PostgreSQL | `tec:postgresql`, origen *documento* | verificado; cambiarlo implica corregir la propuesta (D6) |
| P4 | La estructura del plan es un solo repositorio con `api/`, `worker/`, `tests/attack-matrix/`, `docs/`, `.claude/` | `estructura_repositorio` del plan | verificado |
| P5 | `arbol.py`, los controles de gk-commit, el KG y la matriz de ataque funcionan por repositorio | código de esta rama | verificado |

### Hechos externos (fuente: documentación oficial, leída hoy)

| # | Afirmación | Fuente | Estado |
|---|---|---|---|
| E1 | En MongoDB una operación sobre **un** documento es atómica | mongodb.com/docs/manual/core/transactions | verificado |
| E2 | Las transacciones multi-documento de MongoDB funcionan en replica sets y clusters sharded | misma página | verificado, con un matiz: la página no dice que funcionen en un `mongod` standalone, así que en Docker hace falta un replica set de un nodo |
| E3 | MongoDB no resuelve ni hace cumplir referencias entre colecciones: "your application can resolve them" | mongodb.com/docs/manual/reference/database-references | verificado; no menciona claves foráneas ni restricciones |
| E4 | MongoDB tiene validación de esquema por colección | mongodb.com/docs/manual/core/schema-validation | verificado, aunque la página no detalla `$jsonSchema` |
| E5 | MongoDB Community usa SSPL desde el 16-10-2018, licencia no aprobada por la OSI; obliga a publicar el código del servicio si se ofrece *la funcionalidad de MongoDB* como servicio | FAQ de SSPL en mongodb.com | verificado. A Gatekeeper no le aplica: no ofrece MongoDB como servicio |
| E6 | PostgreSQL tiene seguridad por fila (RLS): políticas que limitan qué filas ve y modifica cada rol, con denegación por defecto; el dueño de la tabla la salta salvo con `FORCE ROW LEVEL SECURITY` | postgresql.org/docs/16/ddl-rowsecurity | verificado |
| E7 | CWE-943 cubre la inyección en consultas NoSQL, MongoDB incluido | cwe.mitre.org/data/definitions/943 | verificado |
| E8 | Alembic, que el plan fija para F1.07, migra bases a través de SQLAlchemy; no sirve para MongoDB | conocimiento técnico, no consultado hoy | verificado con matiz |

### Medición (PostgreSQL 16 vs MongoDB 7 en Docker, esta máquina, 2000 operaciones por caso)

Son las tres operaciones de BD del camino del archivo: insertar el archivo (antes del 202), el cambio de estado
condicional (`… WHERE id AND aplicacion_id AND estado = 'pendiente'`) y la lectura filtrada por aplicación.

| Operación | PostgreSQL (commit durable) | MongoDB `j:false` (por defecto, standalone) | MongoDB `j:true` (durable) |
|---|---|---|---|
| Insertar | p50 1.52 · p95 2.50 ms | p50 0.22 · p95 0.28 ms | p50 1.67 · p95 2.58 ms |
| Transición | p50 1.68 · p95 2.81 ms | p50 0.32 · p95 0.38 ms | p50 1.84 · p95 2.86 ms |
| Leer | p50 0.10 · p95 0.14 ms | p50 0.28 · p95 0.34 ms | p50 0.28 · p95 0.34 ms |

**Lectura del resultado:**
- La ventaja de 7× de MongoDB en escrituras viene **solo** de confirmar antes de escribir en el journal. Con
  durabilidad equivalente, las escrituras tardan prácticamente lo mismo y PostgreSQL lee unas 3 veces más rápido.
- Esa misma ventaja la puede obtener PostgreSQL con `synchronous_commit = off`, a cambio del mismo riesgo: perder
  las últimas escrituras confirmadas si se cae el servidor.
- En cualquiera de los motores, la BD consume menos del 0.3 % del presupuesto de M1 (< 1 s) y del de M2 (≤ 2 s).
  El motor no es lo que decide la latencia de Gatekeeper.

## 2. Adversario

### Repo separado para la BD

- **A favor:** la propiedad del esquema queda separada, podría tener su propio equipo y su propio ritmo de
  versiones, y otros servicios podrían reutilizarlo.
- **En contra, con evidencia:**
  - Solo hay un consumidor, la imagen de la API (P1).
  - Cada cambio de esquema viaja con el código que lo usa. Con dos repos, una columna nueva y su endpoint serían dos
    PR que hay que fusionar y desplegar en orden. Si se desfasan, la API queda contra un esquema distinto y falla en
    producción.
  - La aprobación de seguridad está atada a **un** árbol de trabajo (P5). Con dos repos habría que aprobar dos
    árboles y coordinar sus hashes.
  - Habría que duplicar el KG, la skill, los agentes y la CI, o mantener referencias cruzadas.
  - La estructura del plan es un solo repositorio (P4).
- **Lo que el usuario puede estar buscando, y ya existe:**
  - La **BD ya corre separada**, en su propio contenedor (`postgres`), en la red `backend`.
  - La separación de **responsabilidades** la da la carpeta `api/db/`: solo la escribe gk-db y la hace cumplir el
    control 2 de gk-commit.
  - Si en el futuro otro servicio necesitara los mismos modelos, `api/db/` se puede extraer como paquete. El límite
    de carpeta lo deja preparado.
- **Veredicto:** no conviene. Un solo repo, con la frontera `api/db/` y `api/migrations/` para gk-db.

### MongoDB en lugar de PostgreSQL

- **A favor:**
  - Esquema flexible para `resultado_analisis.detalle`, que varía según la capa.
  - Escrituras muy rápidas con `j:false`.
  - El documento `archivo` podría embeber sus resultados y su bitácora, y así ganar atomicidad de un solo documento
    (E1).
- **En contra, con evidencia:**
  - **INV-10 y la integridad dependerían solo de la aplicación.** MongoDB no hace cumplir referencias (E3). Una
    api_key de una aplicación borrada o un `archivo` huérfano no los frena nadie. PostgreSQL tiene claves foráneas
    y `CHECK` sobre los 5 estados, y además RLS (E6), que puede hacer cumplir INV-10 dentro de la propia BD como
    segunda barrera.
  - **INV-08 necesita atomicidad entre registros.** La liberación cambia el estado del archivo y escribe el evento
    de auditoría. En MongoDB eso exige transacciones, y por lo tanto un replica set incluso en desarrollo (E2), o
    embeber la bitácora dentro del archivo, lo que rompe las consultas de auditoría globales
    (`GET /v1/admin/audit`).
  - **La latencia no mejora con durabilidad equivalente** (medición). La única forma de ganar es aceptar perder
    escrituras confirmadas, y en un sistema de seguridad eso incluye veredictos y bitácora.
  - **Cambia el plan y la propuesta:** Alembic deja de servir (E8), el modelo ER pasa a ser de documentos y hay que
    corregir la propuesta escrita (P3).
  - **La inyección no desaparece, cambia de forma:** con PostgreSQL es CWE-89, que se previene con consultas
    parametrizadas; con MongoDB es CWE-943, inyección de operadores como `{"$ne": null}` (E7). Ambas se controlan,
    pero en MongoDB hay que validar los tipos con cuidado en cada filtro.
  - La licencia SSPL (E5) no afecta a Gatekeeper.
- **El esquema flexible ya está cubierto:** PostgreSQL tiene `JSONB` para `resultado_analisis.detalle`, con
  índices si hicieran falta.
- **Veredicto:** quedarse con PostgreSQL. Los datos son relacionales, las invariantes se benefician de restricciones
  dentro de la BD y la latencia no cambia.

### Ataque a la propia recomendación

- **Si las pruebas dependen de Docker, son más lentas.** Levantar el contenedor tarda unos segundos. Mitigación: un
  único contenedor por sesión de pytest (fixture de alcance `session`), con limpieza entre pruebas por transacción.
- **RLS agrega complejidad** (roles, `SET` de la aplicación por conexión, `FORCE ROW LEVEL SECURITY` para que el
  dueño no la salte).
- **Propuesta:**
  - empezar con el filtro obligatorio en el repositorio, el `aplicacion_id` sin valor por defecto que ya está en el
    diseño de gk-db;
  - dejar RLS como **propuesta pendiente** de defensa en profundidad para F2.06, sin implementarla ahora.

## 3. Recomendación

1. **Un solo repositorio**, con `api/db/` y `api/migrations/` como territorio de gk-db.
2. **PostgreSQL 16**, como fija la propuesta.
3. **Propuestas pendientes de tu decisión:**
   - RLS como segunda barrera de INV-10 en F2.06;
   - el fixture de PostgreSQL de alcance `session` para las pruebas de BD.
