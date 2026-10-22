# Harness X-Ray report

- **Target:** `repo`
- **Commit:** none
- **Scan date (UTC):** 2026-10-18
- **Axes reviewed:** Instructions, Context, Security, Verification, Structure, Code
- **Tool:** `harness-x-ray@0.0.0`
- **Catalog:** 16 rules, SHA-256 `47bd793f7516`

---

## Summary by axis

| Axis | High | Medium | Low |
| --- | --- | --- | --- |
| Instructions | 0 | 0 | 1 |
| Context | 0 | 0 | 0 |
| Security | 2 | 2 | 0 |
| Verification | 0 | 1 | 0 |
| Structure | 0 | 0 | 0 |
| Code | 0 | 0 | 0 |
| Total | 2 | 3 | 1 |

**Most important findings:**

- `SEC-01` Project permissions are broader than the defaults (High)
- `SEC-02` Destructive commands pass or depend only on manual confirmation (High)
- `SEC-03` Secrets are versioned, written into the harness, or readable without a prompt (Medium)
- `SEC-05` Security rules exist only as text (Medium)
- `VER-01` No documented way to verify a change (Medium)

---

## Findings by axis

### Instructions

#### RUL-01 · Generic rules the model already follows

- **Type:** judgment
- **Impact:** Low, an opinion: a judgment finding has no measurement behind it
- **Evidence level of the rule:** study
- **Summary:** The subagent body is one generic sentence that the agent would follow without being told, and it repeats the description above it.
- **Recommendation:** Delete the sentence; the description already names the task.
- **Test in function 2:** not proposed

| Evidence | Quote |
| --- | --- |
| `.claude/agents/fast-runner.md:7` | `Run the requested script and report the result.` |

**Sources:**

- [Evaluating AGENTS.md: Are Repository-Level Context Files Helpful for Coding Agents?](https://arxiv.org/abs/2602.11988), study
- [How Claude remembers your project](https://code.claude.com/docs/en/memory), official documentation
- [AGENTS.md: persistent project instructions](https://agentatlas-dev.vercel.app/en/techniques/agents-md/), Agent Atlas, the author's knowledge base

### Context

No finding on this axis.

### Security

#### SEC-01 · Project permissions are broader than the defaults

- **Type:** measured (`mf-1`)
- **Impact:** High
- **Evidence level of the rule:** official documentation
- **Summary:** The project allows every git command without a prompt, and the project mode accepts edits without asking. Both subagents that have shell tools run in that mode.
- **Recommendation:** Narrow the git allow rule to the commands the team runs, and remove defaultMode acceptEdits from the project settings.
- **Test in function 2:** not proposed

| Evidence | Quote |
| --- | --- |
| `.claude/settings.json:3` | `"allow": ["Bash(git *)"]` |
| `.claude/agents/edit-helper.md:5` | `permissionMode: acceptEdits` |

Measured at `/security/permissions/allow/0`: object with 2 keys

| Trigger | Count | Impact | Value | Threshold |
| --- | --- | --- | --- | --- |
| `accept-edits-in-project` | 1 | High | — | — |
| `destructive-allow-passes` | 1 | High | — | — |
| `subagent-accept-edits-shell` | 2 | High | — | — |

**Sources:**

- [Configure permissions](https://code.claude.com/docs/en/permissions), official documentation
- [Choose a permission mode](https://code.claude.com/docs/en/permission-modes), official documentation
- [Choose a permission mode: protected paths](https://code.claude.com/docs/en/permission-modes#protected-paths), official documentation
- [Create custom subagents](https://code.claude.com/docs/en/sub-agents), official documentation
- [Security](https://code.claude.com/docs/en/security), official documentation
- [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/), industry guidance
- [Tools and permissions](https://agentatlas-dev.vercel.app/en/techniques/tool-use-permissions/), Agent Atlas, the author's knowledge base

#### SEC-02 · Destructive commands pass or depend only on manual confirmation

- **Type:** measured (`mf-2`)
- **Impact:** High
- **Evidence level of the rule:** official documentation
- **Summary:** Git commands that discard work or rewrite shared history pass without a prompt, because the allow rule for git covers them. The project mode also accepts edits without asking.
- **Recommendation:** Add deny rules for the destructive git forms, ask rules for rm, and a PreToolUse hook on Bash that fails closed, then remove acceptEdits from the project settings.
- **Test in function 2:** Run each destructive command of the scan in a scratch copy of the project and record whether it runs, asks or is blocked.

| Evidence | Quote |
| --- | --- |
| `.claude/settings.json:3` | `"allow": ["Bash(git *)"]` |
| `.claude/settings.json:4` | `"defaultMode": "acceptEdits"` |

Measured at `/security/destructiveCoverage/commands/0`: object with 13 keys

| Trigger | Count | Impact | Value | Threshold |
| --- | --- | --- | --- | --- |
| `destructive-command-passes` | 26 | High | — | — |

**Sources:**

- [Configure permissions](https://code.claude.com/docs/en/permissions), official documentation
- [Choose a permission mode](https://code.claude.com/docs/en/permission-modes), official documentation
- [Choose a permission mode: boundaries you state in conversation](https://code.claude.com/docs/en/permission-modes#boundaries-you-state-in-conversation), official documentation
- [Choose a permission mode: critical paths](https://code.claude.com/docs/en/permission-modes#critical-paths), official documentation
- [Hooks reference](https://code.claude.com/docs/en/hooks), official documentation
- [Security](https://code.claude.com/docs/en/security), official documentation
- [Configure the sandboxed Bash tool](https://code.claude.com/docs/en/sandboxing), official documentation
- [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/), industry guidance
- [Safe agent execution](https://agentatlas-dev.vercel.app/en/techniques/safe-agent-execution/), Agent Atlas, the author's knowledge base
- [Piece: security](https://agentatlas-dev.vercel.app/en/harnesses/security/), Agent Atlas, the author's knowledge base

#### SEC-03 · Secrets are versioned, written into the harness, or readable without a prompt

The scan measured this, but findings.json does not cite it. The agent does not decide whether a measured finding exists.

- **Type:** measured (`mf-3`)
- **Impact:** Medium
- **Evidence level of the rule:** official documentation

No file to cite.

Measured at `/security/secrets/readProtection/envAtRoot/decision`: `default`

| Trigger | Count | Impact | Value | Threshold |
| --- | --- | --- | --- | --- |
| `env-at-root-readable` | 1 | Medium | `default` | — |

**Sources:**

- [Configure permissions](https://code.claude.com/docs/en/permissions), official documentation
- [Explore the .claude directory](https://code.claude.com/docs/en/claude-directory), official documentation
- [How Claude remembers your project](https://code.claude.com/docs/en/memory), official documentation
- [LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/), industry guidance
- [Safe agent execution](https://agentatlas-dev.vercel.app/en/techniques/safe-agent-execution/), Agent Atlas, the author's knowledge base
- [Piece: security](https://agentatlas-dev.vercel.app/en/harnesses/security/), Agent Atlas, the author's knowledge base

#### SEC-05 · Security rules exist only as text

- **Type:** judgment
- **Impact:** Medium, an opinion: a judgment finding has no measurement behind it
- **Evidence level of the rule:** official documentation
- **Summary:** The subagent body forbids destructive commands in plain text. Its shell tools inherit the project's acceptEdits mode, so nothing asks before those commands run, and no setting enforces the sentence.
- **Recommendation:** Put the forbidden forms in deny rules in the project settings, and keep the sentence only as an explanation for the reader.
- **Test in function 2:** Ask the subagent to run each forbidden form and record whether the call asks, runs or is blocked, with and without the sentence.
- **Supported by measured findings:** `mf-1` (SEC-01, High impact), `mf-2` (SEC-02, High impact)

| Evidence | Quote |
| --- | --- |
| `.claude/agents/edit-helper.md:9` | ``Never run `rm -rf \| git reset --hard` without asking first.`` |

**Sources:**

- [How Claude remembers your project](https://code.claude.com/docs/en/memory), official documentation
- [Choose a permission mode](https://code.claude.com/docs/en/permission-modes), official documentation
- [Choose a permission mode: boundaries you state in conversation](https://code.claude.com/docs/en/permission-modes#boundaries-you-state-in-conversation), official documentation
- [Configure permissions](https://code.claude.com/docs/en/permissions), official documentation
- [Safe agent execution](https://agentatlas-dev.vercel.app/en/techniques/safe-agent-execution/), Agent Atlas, the author's knowledge base
- [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/), industry guidance

### Verification

#### VER-01 · No documented way to verify a change

- **Type:** judgment
- **Impact:** Medium, an opinion: a judgment finding has no measurement behind it
- **Evidence level of the rule:** official documentation
- **Summary:** No memory file names a command that checks a change, and the harness gives the agent no check to run after an edit.
- **Recommendation:** Name the one command that checks a change in CLAUDE.md, and say when to run it, so the agent runs it before it reports an edit.
- **Test in function 2:** Run the same edit task with and without the verification line and compare the failed checks that each run leaves.

| Evidence | Quote |
| --- | --- |
| `.claude/settings.json` | — |

**Sources:**

- [Best practices for Claude Code](https://code.claude.com/docs/en/best-practices), official documentation
- [Verification and evaluation](https://agentatlas-dev.vercel.app/en/techniques/verification-evaluation/), Agent Atlas, the author's knowledge base
- [AGENTS.md: persistent project instructions](https://agentatlas-dev.vercel.app/en/techniques/agents-md/), Agent Atlas, the author's knowledge base

### Structure

No finding on this axis.

### Code

No finding on this axis.

---

## Context budget

| Component | Load mode | Files | Estimated tokens |
| --- | --- | --- | --- |
| Commands | always | 0 | 0 |
| Memory | always | 0 | 0 |
| Skills | always | 0 | 0 |
| Subagents | always | 2 | 27 |

Total: ≈ 27 tokens (estimated, chars/4)

Counted: the always-loaded files of the target that the scan reads. Not counted: the user memory, the memory of the parent folders (listed by the scan, not measured), the auto memory, and the memory of subfolders, which loads when Claude works in its folder.

AGENTS.md: the scan assumes that Claude Code reads AGENTS.md only when no CLAUDE.md or CLAUDE.local.md exists in the target or in a parent folder, which is the default. Only the user or managed settings can change that, so project settings cannot. If the assumption is wrong, the table misses that file.

---

## What to test in function 2

### Items whose size is unknown

None recorded.

### Tests proposed by the findings

- SEC-02 Destructive commands pass or depend only on manual confirmation: Run each destructive command of the scan in a scratch copy of the project and record whether it runs, asks or is blocked.
- SEC-05 Security rules exist only as text: Ask the subagent to run each forbidden form and record whether the call asks, runs or is blocked, with and without the sentence.
- VER-01 No documented way to verify a change: Run the same edit task with and without the verification line and compare the failed checks that each run leaves.

### Hook scripts to run with real commands

None recorded.

### Noisy verification signals

The scan does not measure how noisy the verification output is, so it records no such signal.

---

## Limits of this scan

Not read: the user layer (memory and settings in the user's Claude folder), the parent folders of the target, and the files that the scan skipped, listed below.

Tokens are estimated, never counted. Method: chars/4.

The thresholds are provisional: each value is an assumption that calibration has not confirmed.

The SEC-02 triggers assume the project's `defaultMode`, or `default` when the project sets none. The scan used `acceptEdits`. A session may start in another mode (not verified against the documentation). The matrix shows each mode.

Outcome of each destructive command for a session started in each mode. It is context, not a trigger: the SEC-02 findings do not use it.

| Command | `default` | `acceptEdits` | `auto` | `bypassPermissions` |
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

`auto` = decided by a model classifier, not simulated; rules deciding before the mode is not verified for `auto` and `bypassPermissions` (only deny is stated to apply in every mode); hooks are not used; `dontAsk` and `plan` are not shown.

Skipped or unreadable items:

| Source | Path | Reason | Detail |
| --- | --- | --- | --- |
| `git` | `.` | `file-list-from-walk` | `not-a-repository` |

No case was left undecided.

---

## Sources

| Id | Title | Evidence level | URL |
| --- | --- | --- | --- |
| `atlas-agents-md` | AGENTS.md: persistent project instructions | Agent Atlas, the author's knowledge base | [https://agentatlas-dev.vercel.app/en/techniques/agents-md/](https://agentatlas-dev.vercel.app/en/techniques/agents-md/) |
| `atlas-safe-agent-execution` | Safe agent execution | Agent Atlas, the author's knowledge base | [https://agentatlas-dev.vercel.app/en/techniques/safe-agent-execution/](https://agentatlas-dev.vercel.app/en/techniques/safe-agent-execution/) |
| `atlas-security` | Piece: security | Agent Atlas, the author's knowledge base | [https://agentatlas-dev.vercel.app/en/harnesses/security/](https://agentatlas-dev.vercel.app/en/harnesses/security/) |
| `atlas-tool-use-permissions` | Tools and permissions | Agent Atlas, the author's knowledge base | [https://agentatlas-dev.vercel.app/en/techniques/tool-use-permissions/](https://agentatlas-dev.vercel.app/en/techniques/tool-use-permissions/) |
| `atlas-verification-evaluation` | Verification and evaluation | Agent Atlas, the author's knowledge base | [https://agentatlas-dev.vercel.app/en/techniques/verification-evaluation/](https://agentatlas-dev.vercel.app/en/techniques/verification-evaluation/) |
| `cc-docs-best-practices` | Best practices for Claude Code | official documentation | [https://code.claude.com/docs/en/best-practices](https://code.claude.com/docs/en/best-practices) |
| `cc-docs-claude-directory` | Explore the .claude directory | official documentation | [https://code.claude.com/docs/en/claude-directory](https://code.claude.com/docs/en/claude-directory) |
| `cc-docs-hooks` | Hooks reference | official documentation | [https://code.claude.com/docs/en/hooks](https://code.claude.com/docs/en/hooks) |
| `cc-docs-memory` | How Claude remembers your project | official documentation | [https://code.claude.com/docs/en/memory](https://code.claude.com/docs/en/memory) |
| `cc-docs-permission-modes` | Choose a permission mode | official documentation | [https://code.claude.com/docs/en/permission-modes](https://code.claude.com/docs/en/permission-modes) |
| `cc-docs-permission-modes-classifier-boundaries` | Choose a permission mode: boundaries you state in conversation | official documentation | [https://code.claude.com/docs/en/permission-modes#boundaries-you-state-in-conversation](https://code.claude.com/docs/en/permission-modes#boundaries-you-state-in-conversation) |
| `cc-docs-permission-modes-critical-paths` | Choose a permission mode: critical paths | official documentation | [https://code.claude.com/docs/en/permission-modes#critical-paths](https://code.claude.com/docs/en/permission-modes#critical-paths) |
| `cc-docs-permission-modes-protected-paths` | Choose a permission mode: protected paths | official documentation | [https://code.claude.com/docs/en/permission-modes#protected-paths](https://code.claude.com/docs/en/permission-modes#protected-paths) |
| `cc-docs-permissions` | Configure permissions | official documentation | [https://code.claude.com/docs/en/permissions](https://code.claude.com/docs/en/permissions) |
| `cc-docs-sandboxing` | Configure the sandboxed Bash tool | official documentation | [https://code.claude.com/docs/en/sandboxing](https://code.claude.com/docs/en/sandboxing) |
| `cc-docs-security` | Security | official documentation | [https://code.claude.com/docs/en/security](https://code.claude.com/docs/en/security) |
| `cc-docs-sub-agents` | Create custom subagents | official documentation | [https://code.claude.com/docs/en/sub-agents](https://code.claude.com/docs/en/sub-agents) |
| `eth-agents-md-evaluation` | Evaluating AGENTS.md: Are Repository-Level Context Files Helpful for Coding Agents? | study | [https://arxiv.org/abs/2602.11988](https://arxiv.org/abs/2602.11988) |
| `owasp-llm-excessive-agency` | LLM06:2025 Excessive Agency | industry guidance | [https://genai.owasp.org/llmrisk/llm062025-excessive-agency/](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) |
| `owasp-llm-sensitive-information-disclosure` | LLM02:2025 Sensitive Information Disclosure | industry guidance | [https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/) |

---

## Appendix: raw measures

### Measured findings

| Finding | Rule | Reference | Value |
| --- | --- | --- | --- |
| `mf-1` | SEC-01 | `/security/permissions/allow/0` | object with 2 keys |
| `mf-2` | SEC-02 | `/security/destructiveCoverage/commands/0` | object with 13 keys |
| `mf-3` | SEC-03 | `/security/secrets/readProtection/envAtRoot/decision` | `default` |

### Headline values

| Measure | Value |
| --- | --- |
| Files listed | 3 |
| Warnings | 1 |
| Always-loaded total | ≈ 27 tokens (estimated, chars/4) |
| Duplicated lines | 0% |
| Files scanned for duplication | 0 |
| Top-level folders mentioned by the memory files | 0 of 1 |
