# Informe de Harness X-Ray

- **Objetivo:** `repo`
- **Commit:** ninguno
- **Fecha del escaneo (UTC):** 2026-10-18
- **Ejes revisados:** Instrucciones, Contexto, Seguridad, Verificación, Estructura, Código
- **Herramienta:** `harness-x-ray@0.0.0`
- **Catálogo:** 16 reglas, SHA-256 `756b61ef038a`

**Agentes detectados:**

| Agente | Evaluado | Detectado, contenido no evaluado |
| --- | --- | --- |
| Claude Code | configuración, subagentes | ninguno |

---

## Resumen por eje

| Eje | Alto | Medio | Bajo |
| --- | --- | --- | --- |
| Instrucciones | 0 | 0 | 1 |
| Contexto | 0 | 0 | 0 |
| Seguridad | 2 | 2 | 0 |
| Verificación | 0 | 1 | 0 |
| Estructura | 0 | 0 | 0 |
| Código | 0 | 0 | 0 |
| Total | 2 | 3 | 1 |

**Hallazgos más importantes:**

- `SEC-01` Project permissions are broader than the defaults (Alto)
- `SEC-02` Destructive commands pass or depend only on manual confirmation (Alto)
- `SEC-03` Secrets are versioned, written into the harness, or readable without a prompt (Medio)
- `SEC-05` Security rules exist only as text (Medio)
- `VER-01` No documented way to verify a change (Medio)

---

## Hallazgos por eje

### Instrucciones

#### RUL-01 · Generic rules the model already follows

- **Tipo:** criterio
- **Impacto:** Bajo, una opinión: un hallazgo de criterio no tiene una medición detrás
- **Nivel de evidencia de la regla:** estudio
- **Resumen:** The subagent body is one generic sentence that the agent would follow without being told, and it repeats the description above it.
- **Recomendación:** Delete the sentence; the description already names the task.
- **Prueba en la función 2:** no propuesta

| Evidencia | Cita |
| --- | --- |
| `.claude/agents/fast-runner.md:7` | `Run the requested script and report the result.` |

**Fuentes:**

- [Evaluating AGENTS.md: Are Repository-Level Context Files Helpful for Coding Agents?](https://arxiv.org/abs/2602.11988), estudio
- [How Claude remembers your project](https://code.claude.com/docs/en/memory), documentación oficial
- [AGENTS.md: persistent project instructions](https://agentatlas-dev.vercel.app/en/techniques/agents-md/), Agent Atlas, la base de conocimiento del autor

### Contexto

No hay hallazgos en este eje.

### Seguridad

#### SEC-01 · Project permissions are broader than the defaults

- **Tipo:** medido (`mf-1`)
- **Impacto:** Alto
- **Nivel de evidencia de la regla:** documentación oficial
- **Resumen:** The project allows every git command without a prompt, and the project mode accepts edits without asking. Both subagents that have shell tools run in that mode.
- **Recomendación:** Narrow the git allow rule to the commands the team runs, and remove defaultMode acceptEdits from the project settings.
- **Prueba en la función 2:** no propuesta

| Evidencia | Cita |
| --- | --- |
| `.claude/settings.json:3` | `"allow": ["Bash(git *)"]` |
| `.claude/agents/edit-helper.md:5` | `permissionMode: acceptEdits` |

Medido en `/security/permissions/allow/0`: objeto con 2 claves

| Disparador | Cantidad | Impacto | Valor | Umbral |
| --- | --- | --- | --- | --- |
| `accept-edits-in-project` | 1 | Alto | — | — |
| `destructive-allow-passes` | 1 | Alto | — | — |
| `subagent-accept-edits-shell` | 2 | Alto | — | — |

**Fuentes:**

- [Configure permissions](https://code.claude.com/docs/en/permissions), documentación oficial
- [Choose a permission mode](https://code.claude.com/docs/en/permission-modes), documentación oficial
- [Choose a permission mode: protected paths](https://code.claude.com/docs/en/permission-modes#protected-paths), documentación oficial
- [Create custom subagents](https://code.claude.com/docs/en/sub-agents), documentación oficial
- [Security](https://code.claude.com/docs/en/security), documentación oficial
- [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/), guía de una organización reconocida
- [Tools and permissions](https://agentatlas-dev.vercel.app/en/techniques/tool-use-permissions/), Agent Atlas, la base de conocimiento del autor

#### SEC-02 · Destructive commands pass or depend only on manual confirmation

- **Tipo:** medido (`mf-2`)
- **Impacto:** Alto
- **Nivel de evidencia de la regla:** documentación oficial
- **Resumen:** Git commands that discard work or rewrite shared history pass without a prompt, because the allow rule for git covers them. The project mode also accepts edits without asking.
- **Recomendación:** Add deny rules for the destructive git forms, ask rules for rm, and a PreToolUse hook on Bash that fails closed, then remove acceptEdits from the project settings.
- **Prueba en la función 2:** Run each destructive command of the scan in a scratch copy of the project and record whether it runs, asks or is blocked.

| Evidencia | Cita |
| --- | --- |
| `.claude/settings.json:3` | `"allow": ["Bash(git *)"]` |
| `.claude/settings.json:4` | `"defaultMode": "acceptEdits"` |

Medido en `/security/destructiveCoverage/commands/0`: objeto con 13 claves

| Disparador | Cantidad | Impacto | Valor | Umbral |
| --- | --- | --- | --- | --- |
| `destructive-command-passes` | 26 | Alto | — | — |

**Fuentes:**

- [Configure permissions](https://code.claude.com/docs/en/permissions), documentación oficial
- [Choose a permission mode](https://code.claude.com/docs/en/permission-modes), documentación oficial
- [Choose a permission mode: boundaries you state in conversation](https://code.claude.com/docs/en/permission-modes#boundaries-you-state-in-conversation), documentación oficial
- [Choose a permission mode: critical paths](https://code.claude.com/docs/en/permission-modes#critical-paths), documentación oficial
- [Hooks reference](https://code.claude.com/docs/en/hooks), documentación oficial
- [Security](https://code.claude.com/docs/en/security), documentación oficial
- [Configure the sandboxed Bash tool](https://code.claude.com/docs/en/sandboxing), documentación oficial
- [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/), guía de una organización reconocida
- [Safe agent execution](https://agentatlas-dev.vercel.app/en/techniques/safe-agent-execution/), Agent Atlas, la base de conocimiento del autor
- [Piece: security](https://agentatlas-dev.vercel.app/en/harnesses/security/), Agent Atlas, la base de conocimiento del autor

#### SEC-03 · Secrets are versioned, written into the harness, or readable without a prompt

El escaneo lo midió, pero findings.json no lo cita. El agente no decide si un hallazgo medido existe.

- **Tipo:** medido (`mf-3`)
- **Impacto:** Medio
- **Nivel de evidencia de la regla:** documentación oficial

No hay archivo que citar.

Medido en `/security/secrets/readProtection/envAtRoot/decision`: `default`

| Disparador | Cantidad | Impacto | Valor | Umbral |
| --- | --- | --- | --- | --- |
| `env-at-root-readable` | 1 | Medio | `default` | — |

**Fuentes:**

- [Configure permissions](https://code.claude.com/docs/en/permissions), documentación oficial
- [Explore the .claude directory](https://code.claude.com/docs/en/claude-directory), documentación oficial
- [How Claude remembers your project](https://code.claude.com/docs/en/memory), documentación oficial
- [LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/), guía de una organización reconocida
- [Safe agent execution](https://agentatlas-dev.vercel.app/en/techniques/safe-agent-execution/), Agent Atlas, la base de conocimiento del autor
- [Piece: security](https://agentatlas-dev.vercel.app/en/harnesses/security/), Agent Atlas, la base de conocimiento del autor

#### SEC-05 · Security rules exist only as text

- **Tipo:** criterio
- **Impacto:** Medio, una opinión: un hallazgo de criterio no tiene una medición detrás
- **Nivel de evidencia de la regla:** documentación oficial
- **Resumen:** The subagent body forbids destructive commands in plain text. Its shell tools inherit the project's acceptEdits mode, so nothing asks before those commands run, and no setting enforces the sentence.
- **Recomendación:** Put the forbidden forms in deny rules in the project settings, and keep the sentence only as an explanation for the reader.
- **Prueba en la función 2:** Ask the subagent to run each forbidden form and record whether the call asks, runs or is blocked, with and without the sentence.
- **Respaldado por medidas:** `mf-1` (SEC-01, impacto Alto), `mf-2` (SEC-02, impacto Alto)

| Evidencia | Cita |
| --- | --- |
| `.claude/agents/edit-helper.md:9` | ``Never run `rm -rf \| git reset --hard` without asking first.`` |

**Fuentes:**

- [How Claude remembers your project](https://code.claude.com/docs/en/memory), documentación oficial
- [Choose a permission mode](https://code.claude.com/docs/en/permission-modes), documentación oficial
- [Choose a permission mode: boundaries you state in conversation](https://code.claude.com/docs/en/permission-modes#boundaries-you-state-in-conversation), documentación oficial
- [Configure permissions](https://code.claude.com/docs/en/permissions), documentación oficial
- [Safe agent execution](https://agentatlas-dev.vercel.app/en/techniques/safe-agent-execution/), Agent Atlas, la base de conocimiento del autor
- [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/), guía de una organización reconocida

### Verificación

#### VER-01 · No documented way to verify a change

- **Tipo:** criterio
- **Impacto:** Medio, una opinión: un hallazgo de criterio no tiene una medición detrás
- **Nivel de evidencia de la regla:** documentación oficial
- **Resumen:** No memory file names a command that checks a change, and the harness gives the agent no check to run after an edit.
- **Recomendación:** Name the one command that checks a change in CLAUDE.md, and say when to run it, so the agent runs it before it reports an edit.
- **Prueba en la función 2:** Run the same edit task with and without the verification line and compare the failed checks that each run leaves.

| Evidencia | Cita |
| --- | --- |
| `.claude/settings.json` | — |

**Fuentes:**

- [Best practices for Claude Code](https://code.claude.com/docs/en/best-practices), documentación oficial
- [Verification and evaluation](https://agentatlas-dev.vercel.app/en/techniques/verification-evaluation/), Agent Atlas, la base de conocimiento del autor
- [AGENTS.md: persistent project instructions](https://agentatlas-dev.vercel.app/en/techniques/agents-md/), Agent Atlas, la base de conocimiento del autor

### Estructura

No hay hallazgos en este eje.

### Código

No hay hallazgos en este eje.

---

## Presupuesto de contexto

| Componente | Modo de carga | Archivos | Tokens estimados |
| --- | --- | --- | --- |
| Comandos | siempre | 0 | 0 |
| Memoria | siempre | 0 | 0 |
| Skills | siempre | 0 | 0 |
| Subagentes | siempre | 2 | 27 |

Total: ≈ 27 tokens (estimados, chars/4)

Se cuenta: los archivos del objetivo que se cargan siempre y que el escaneo lee. No se cuenta: la memoria de usuario, la memoria de las carpetas padre (la lista el escaneo, pero no la mide), la memoria automática y la memoria de las subcarpetas, que se carga cuando Claude trabaja en su carpeta.

AGENTS.md: el escaneo supone que Claude Code lee AGENTS.md solo cuando no existe CLAUDE.md ni CLAUDE.local.md en el objetivo ni en una carpeta padre, que es el valor por defecto. Solo la configuración de usuario o la administrada puede cambiarlo; la del proyecto no. Si el supuesto falla, la tabla no incluye ese archivo.

---

## Qué probar en la función 2

### Elementos cuyo tamaño se desconoce

Ninguno registrado.

### Pruebas propuestas por los hallazgos

- SEC-02 Destructive commands pass or depend only on manual confirmation: Run each destructive command of the scan in a scratch copy of the project and record whether it runs, asks or is blocked.
- SEC-05 Security rules exist only as text: Ask the subagent to run each forbidden form and record whether the call asks, runs or is blocked, with and without the sentence.
- VER-01 No documented way to verify a change: Run the same edit task with and without the verification line and compare the failed checks that each run leaves.

### Scripts de hooks para ejecutar con comandos reales

Ninguno registrado.

### Señales de verificación ruidosa

El escaneo no mide cuán ruidosa es la salida de la verificación, así que no registra ninguna señal de ese tipo.

---

## Límites de este escaneo

No leído: la capa de usuario (memoria y configuración en la carpeta de Claude del usuario), las carpetas padre del objetivo y los archivos que el escaneo saltó, listados abajo.

Los tokens son estimados, nunca contados. Método: chars/4.

Los valores de los umbrales son de carácter provisional: cada uno es un supuesto que la calibración todavía no confirmó.

Los disparadores de SEC-02 suponen el `defaultMode` del proyecto, o `default` cuando el proyecto no fija ninguno. El escaneo usó `acceptEdits`. Una sesión puede arrancar en otro modo (no verificado contra la documentación). La matriz muestra cada modo.

Resultado de cada comando destructivo para una sesión iniciada en cada modo. Es contexto, no un disparador: los hallazgos de SEC-02 no lo usan.

| Comando | `default` | `acceptEdits` | `auto` | `bypassPermissions` |
| --- | --- | --- | --- | --- |
| `rm-recursive-force` | `asks` | `passes` | `classifier` | `passes` |
| `git-push-force-long` | `passes` | `passes` | `passes` | `passes` |
| `git-push-force-short` | `passes` | `passes` | `passes` | `passes` |
| `git-reset-hard` | `passes` | `passes` | `passes` | `passes` |
| `git-clean-force` | `passes` | `passes` | `passes` | `passes` |
| `git-checkout-discard` | `passes` | `passes` | `passes` | `passes` |
| `git-restore-discard` | `passes` | `passes` | `passes` | `passes` |
| `git-branch-force-delete` | `passes` | `passes` | `passes` | `passes` |
| `curl-pipe-shell` | `asks` | `asks` | `classifier` | `passes` |
| `wget-pipe-bash` | `asks` | `asks` | `classifier` | `passes` |
| `chmod-recursive-777` | `asks` | `asks` | `classifier` | `passes` |
| `npm-publish` | `asks` | `asks` | `classifier` | `passes` |
| `docker-system-prune` | `asks` | `asks` | `classifier` | `passes` |
| `remove-item-recurse-force` | `asks` | `passes` | `classifier` | `passes` |
| `cmd-rd-recurse-quiet` | `asks` | `asks` | `classifier` | `passes` |
| `cmd-del-recurse-quiet` | `asks` | `asks` | `classifier` | `passes` |

`auto` = lo decide un clasificador de modelo, no se simula; las reglas decidan antes que el modo, no verificado para `auto` ni `bypassPermissions` (solo deny se afirma en todos los modos); no se usan hooks; `dontAsk` y `plan` no se muestran.

Elementos saltados o ilegibles:

| Fuente | Ruta | Motivo | Detalle |
| --- | --- | --- | --- |
| `git` | `.` | `file-list-from-walk` | `not-a-repository` |

No quedó ningún caso sin decidir.

---

## Fuentes

| Id | Título | Nivel de evidencia | URL |
| --- | --- | --- | --- |
| `atlas-agents-md` | AGENTS.md: persistent project instructions | Agent Atlas, la base de conocimiento del autor | [https://agentatlas-dev.vercel.app/en/techniques/agents-md/](https://agentatlas-dev.vercel.app/en/techniques/agents-md/) |
| `atlas-safe-agent-execution` | Safe agent execution | Agent Atlas, la base de conocimiento del autor | [https://agentatlas-dev.vercel.app/en/techniques/safe-agent-execution/](https://agentatlas-dev.vercel.app/en/techniques/safe-agent-execution/) |
| `atlas-security` | Piece: security | Agent Atlas, la base de conocimiento del autor | [https://agentatlas-dev.vercel.app/en/harnesses/security/](https://agentatlas-dev.vercel.app/en/harnesses/security/) |
| `atlas-tool-use-permissions` | Tools and permissions | Agent Atlas, la base de conocimiento del autor | [https://agentatlas-dev.vercel.app/en/techniques/tool-use-permissions/](https://agentatlas-dev.vercel.app/en/techniques/tool-use-permissions/) |
| `atlas-verification-evaluation` | Verification and evaluation | Agent Atlas, la base de conocimiento del autor | [https://agentatlas-dev.vercel.app/en/techniques/verification-evaluation/](https://agentatlas-dev.vercel.app/en/techniques/verification-evaluation/) |
| `cc-docs-best-practices` | Best practices for Claude Code | documentación oficial | [https://code.claude.com/docs/en/best-practices](https://code.claude.com/docs/en/best-practices) |
| `cc-docs-claude-directory` | Explore the .claude directory | documentación oficial | [https://code.claude.com/docs/en/claude-directory](https://code.claude.com/docs/en/claude-directory) |
| `cc-docs-hooks` | Hooks reference | documentación oficial | [https://code.claude.com/docs/en/hooks](https://code.claude.com/docs/en/hooks) |
| `cc-docs-memory` | How Claude remembers your project | documentación oficial | [https://code.claude.com/docs/en/memory](https://code.claude.com/docs/en/memory) |
| `cc-docs-permission-modes` | Choose a permission mode | documentación oficial | [https://code.claude.com/docs/en/permission-modes](https://code.claude.com/docs/en/permission-modes) |
| `cc-docs-permission-modes-classifier-boundaries` | Choose a permission mode: boundaries you state in conversation | documentación oficial | [https://code.claude.com/docs/en/permission-modes#boundaries-you-state-in-conversation](https://code.claude.com/docs/en/permission-modes#boundaries-you-state-in-conversation) |
| `cc-docs-permission-modes-critical-paths` | Choose a permission mode: critical paths | documentación oficial | [https://code.claude.com/docs/en/permission-modes#critical-paths](https://code.claude.com/docs/en/permission-modes#critical-paths) |
| `cc-docs-permission-modes-protected-paths` | Choose a permission mode: protected paths | documentación oficial | [https://code.claude.com/docs/en/permission-modes#protected-paths](https://code.claude.com/docs/en/permission-modes#protected-paths) |
| `cc-docs-permissions` | Configure permissions | documentación oficial | [https://code.claude.com/docs/en/permissions](https://code.claude.com/docs/en/permissions) |
| `cc-docs-sandboxing` | Configure the sandboxed Bash tool | documentación oficial | [https://code.claude.com/docs/en/sandboxing](https://code.claude.com/docs/en/sandboxing) |
| `cc-docs-security` | Security | documentación oficial | [https://code.claude.com/docs/en/security](https://code.claude.com/docs/en/security) |
| `cc-docs-sub-agents` | Create custom subagents | documentación oficial | [https://code.claude.com/docs/en/sub-agents](https://code.claude.com/docs/en/sub-agents) |
| `eth-agents-md-evaluation` | Evaluating AGENTS.md: Are Repository-Level Context Files Helpful for Coding Agents? | estudio | [https://arxiv.org/abs/2602.11988](https://arxiv.org/abs/2602.11988) |
| `owasp-llm-excessive-agency` | LLM06:2025 Excessive Agency | guía de una organización reconocida | [https://genai.owasp.org/llmrisk/llm062025-excessive-agency/](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) |
| `owasp-llm-sensitive-information-disclosure` | LLM02:2025 Sensitive Information Disclosure | guía de una organización reconocida | [https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/) |

---

## Apéndice: medidas en bruto

### Hallazgos medidos

| Hallazgo | Regla | Referencia | Valor |
| --- | --- | --- | --- |
| `mf-1` | SEC-01 | `/security/permissions/allow/0` | objeto con 2 claves |
| `mf-2` | SEC-02 | `/security/destructiveCoverage/commands/0` | objeto con 13 claves |
| `mf-3` | SEC-03 | `/security/secrets/readProtection/envAtRoot/decision` | `default` |

### Valores principales

| Medida | Valor |
| --- | --- |
| Archivos listados | 3 |
| Avisos | 1 |
| Total que se carga siempre | ≈ 27 tokens (estimados, chars/4) |
| Líneas duplicadas | 0 % |
| Archivos revisados para duplicación | 0 |
| Carpetas de primer nivel que mencionan los archivos de memoria | 0 de 1 |
