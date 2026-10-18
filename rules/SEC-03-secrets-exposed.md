---
id: SEC-03
title: Secrets are versioned, written into the harness, or readable without a prompt
axis: security
kind: measured
measuredSupport: []
defaultImpact: high
sources: [cc-docs-permissions, cc-docs-claude-directory, cc-docs-memory, owasp-llm-sensitive-information-disclosure, atlas-safe-agent-execution, atlas-security]
evidence: official-docs
since: mvp
status: draft
---

## What it checks

Three things about secrets in the repository:

1. **Secret-named files under version control.** Files such as `.env` and `.env.*` (except `.example`, `.sample` and `.template`), `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa`, `id_ed25519` and `credentials.json`. The scanner reads their names only; it never reads their content.
2. **Literal secret values in harness files:** memory, the `env` of the settings files, the `env`, `headers` and `args` of `.mcp.json`, and skills, commands and subagents. The report shows each value masked, such as `sk-ant-…3f9a`, never in full.
3. **Whether the agent can read a secret-named file without a prompt,** including a `.env` at the project root that the scanner cannot list. This depends on the `Read` deny rules and on PreToolUse hooks that cover reads.

A static scan is not a security audit. It sees names and text in the repository. It does not see secrets in the person's environment or credential store, and it does not read the session transcripts where a read leaves its content.

## Why it matters

A secret file that is under version control stays in the repository's history and in every clone. A literal value in the harness is loaded into context: memory files load at the start of every conversation, so a token written into `CLAUDE.md` is part of every session, not only the sessions that need it.

Reads inside the working directory need no approval. Unless a `Read` deny rule covers it, a `.env` at the project root can be read without a prompt. The permissions documentation gives `Read(./.env)` for the working directory and `Read(**/.env)` for any depth. The same page says that a `Read` deny rule covers Claude's file tools, the file commands that Claude Code recognizes in Bash (such as `cat`, `head`, `tail`, `sed` and `tee`), and the targets of Bash redirections such as `< file`. It also blocks `Edit` and `Write` on the same path. It does not cover a command that reads files without naming them, such as `grep -r pattern .`, or a script or subprocess that opens a file itself. For that, the page points to the sandbox, which enforces at the operating-system level on macOS, Linux and WSL2.

Whatever a tool reads is written to a transcript in `~/.claude`, and those files are plaintext. The contents of a file that a tool read are in the transcript until the cleanup period removes it, which is 30 days by default. A read of `.env` therefore leaves its values on disk, even after the file is protected from later reads.

## How it is detected

This is a measured rule. No `THRESHOLDS` key applies.

Fields the scanner reads:

- `security.secrets.fileListSource`: `git` means the listed files are versioned; `walk` means they are present on disk, versioned or not.
- `security.secrets.files[]`: `path`, `kind` and `readDecision`, whose `decision` is `allow`, `ask`, `deny`, `default` (no rule matched) or `undeterminable`.
- `security.secrets.literals[]`: `file`, `line`, `kind`, `masked` and `location`.
- `security.secrets.readProtection.envAtRoot`: `decision` (`deny`, `ask`, `allow`, `default` or `undeterminable`) for a read of `.env` at the project root, whether or not that file exists.
- `security.secrets.readProtection.preToolUseReadHooks[]`: `runsForEnv` (`runs`, `none` or `undeterminable`) and `failsOpen` for each PreToolUse hook that covers `Read`.

Triggers:

| Trigger | Field | Impact |
|---|---|---|
| A `files[]` entry while `fileListSource` is `git` | `security.secrets.files[]`, `security.secrets.fileListSource` | High |
| Any `literals[]` entry | `security.secrets.literals[]` | High |
| A `files[]` entry whose `readDecision.decision` is `default` or `allow`: the agent reads it without a prompt | `security.secrets.files[].readDecision` | High |
| A `files[]` entry whose `readDecision.decision` is `ask` | `security.secrets.files[].readDecision` | Medium |
| `readProtection.envAtRoot.decision` is `default` or `allow`, and no `preToolUseReadHooks[]` entry has `runsForEnv` `runs` with `failsOpen` `false` | `security.secrets.readProtection` | Medium |

A finding takes the highest impact of the triggers it matches. Notes:

- With `fileListSource` set to `walk`, the file may be untracked. The report says that the file is present on disk and does not call it versioned. The read triggers still apply.
- A `deny` decision for a file adds no read finding. A file that is versioned still triggers the versioned row.
- `undeterminable` is listed with its `reason` and is not a finding.
- Files named `.env.example`, `.env.sample` and `.env.template` are not in `files[]`.
- The `envAtRoot` row covers a local `.env` at the root that git ignores, which `files[]` cannot list. A `deny` or `ask` decision gives no finding from that row. If `envAtRoot.decision` is `undeterminable`, or a hook has `runsForEnv` `undeterminable` and no running hook fails closed, the case is listed with its reason and is not a finding. The scanner cannot tell whether the file exists, so the report says that the row describes a file that may exist.

## Recommendation

Change the harness and the repository, in this order:

1. **Deny reads of secret-named files** in `.claude/settings.json`:

```json
{
  "permissions": {
    "deny": ["Read(**/.env)", "Read(**/.env.*)", "Read(**/*.pem)", "Read(**/*.key)"]
  }
}
```

`Read(**/.env.*)` also matches `.env.example`. Narrow the pattern if the team wants the examples readable.

2. **A PreToolUse hook on `Read` and `Bash`**, shaped as in SEC-02, with `"matcher": "Read|Bash"` and `"onFailure": "block"`. The hook blocks a call that names a secret file. The Atlas `security` template does this for commands that name a `.env` file, and it is a reference for the shape of the hook. The deny rule in step 1 already covers the file tools, the file commands that Claude Code recognizes in Bash, and the redirection targets. A hook that reads the full command text can add patterns that the rule does not match. Neither the rule nor the hook stops a script that opens the file itself; only the sandbox does that, at the operating-system level, and it does not run on native Windows.

3. **Remove literal values from the harness.** Take them out of memory, the `env` of the settings files, and `.mcp.json`, and supply them from outside the repository. Treat any value that was ever committed as exposed, and replace it at its source.

4. **Remove committed secret files from version control** and keep them in the ignore rules. This is a repository change, not a harness change.

## When not to apply

- A placeholder that looks like a secret, such as `API_KEY=changeme` in documentation. The generic rule matches a long assignment; a reviewer confirms that the value is real before the report treats it as a secret.
- Example files: `.env.example`, `.env.sample` and `.env.template` are not listed.
- A secret-named file that git ignores, when `fileListSource` is `git`, other than a root `.env`. It is not listed, and a root `.env` is covered by the `envAtRoot` row. With `walk`, it appears as present on disk, not as versioned.
- A project whose team confirms that no `.env` is ever created at the project root. The scanner cannot see local files, so the reviewer confirms this, and the report says so.
- Secrets in the person's user settings, in managed settings, or in the session transcripts. The scanner does not read them.
- A secret-named file that holds no secret, such as a file of public values. The rule cannot tell. The report says that the file is secret-named, not that it contains secrets.

## Examples

The values in these examples are illustrative and masked; none of them is real.

### Applies: a versioned .env that the agent can read (high)

Bad: `.env` is under version control, and no `Read` deny rule covers it. The `files[]` entry has `fileListSource: git` and `readDecision.decision: default`. Two high triggers apply: the file is versioned, and it is readable without a prompt. Good: remove the file from version control, add `Read(**/.env)` to `deny`, and keep the values outside the repository.

### Applies: a local .env that git ignores (medium)

Bad: `.gitignore` lists `.env`, and a developer keeps a local `.env` at the project root. No `Read` deny rule covers it, and no PreToolUse hook covers `Read`. `files[]` does not list the file, because git does not version it, so the file rows stay silent. `envAtRoot.decision` is `default`, though, so a read of that file needs no prompt. The finding is medium, and the report says that the scanner cannot see the file. Good: add `Read(**/.env)` to `deny`, or add a PreToolUse hook on `Read` and `Bash` with `onFailure` set to `"block"`.

### Applies: a token written into .mcp.json (high)

Bad: `.mcp.json` contains `"env": { "GITHUB_TOKEN": "ghp_…" }`. The `literals[]` entry has `location: mcpServers.NAME.env.KEY` and `masked: ghp_…a1b2`. The value is in a versioned file that every clone receives. Good: remove the value from the file and supply it from outside the repository.

### Does not apply: an example file and a denied read

Good: `.env.example` contains `API_KEY=` with an empty value. It is not in `files[]`, and an empty assignment is not a literal. `Read(**/.env)` is in `deny`. No trigger applies.
