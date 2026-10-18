# Expected findings: security

Written on 2026-10-18, before any scan of this target. The target is `harness-templates/security` in the agentAtlas repository. It is a reusable security piece, not an app: a set of security rules in `AGENTS.md`, two hooks, a permission file, a secretlint configuration and tests for the hooks. The folder has no git repository of its own; it sits inside the agentAtlas repository.

## Harness observed

- `AGENTS.md` (about 40 lines). Its "Security" section is written to be pasted into other harnesses. It has a file table and verification commands. It says "Use npm in this folder, not pnpm."
- No `CLAUDE.md`, `.claude/` or `CLAUDE.local.md` in the folder. The parent folders hold only the agentAtlas `AGENTS.md`, which loads as layer 3 in these sessions. It says pnpm for the site; this folder has its own `package-lock.json`.
- `.agents/permissions.json`: deny reads of `.env` and `.env.*`; ask before `git push`, `npm install`, `npm i` and `npm add`. The file's own description says no agent reads it on its own.
- `.agents/hooks/`: `block-dangerous-commands.mjs` (runs before a shell command, exit code 2 to block) and `check-secrets-before-stop.mjs` (runs when the agent tries to finish).
- `.secretlintrc.json` (recommended preset), `.gitignore`, `test/` (tests of the two hooks) and `package.json` with `test`, `typecheck`, `check:secrets` and `verify`.
- The README says that the files in `.agents/` "do nothing on their own" until each agent's own settings point to them. No settings file exists here.
- The `Security` section promises four things: the dangerous-command hook blocks before each shell command; the secret scan runs when the agent tries to finish; `.env` files are never read; `git push` and dependency installs require asking the user.

## Expected findings

| Rule | Kind | Expected impact | Reason (file) | Confidence |
|---|---|---|---|---|
| SEC-04 | judgment | medium | `AGENTS.md`, "Security", promises a PreToolUse block and a stop-time secret scan. No settings file connects `block-dangerous-commands.mjs` or `check-secrets-before-stop.mjs`, and the permission rules are not connected. The README says these connections are made by hand. The finding should explain the missing wiring in this repository and should not call it a template error. This is the central finding of the target. | high |
| SEC-02 | measured | medium | No deny, ask or hook is connected to Claude Code. With the assumed `default` mode, each destructive command asks, and nothing else stops it. | high |
| SEC-03 | measured | medium | No `Read` deny and no `Read` hook, so the root `.env` read decision is `default`. The promise "never read .env" is text only. | medium |
| SEC-05 | judgment | medium | "Never read, print or change `.env` or `.env.*` files" and "Ask the user before you run `git push` or install a dependency" have no deny or ask rule behind them. | medium |
| COD-04 | judgment | low | No reuse step appears in `AGENTS.md`. COD-01 is expected below its medium threshold for this small code base, so the impact is low. | medium |
| RUL-02 | judgment | low | "Never write a real secret" restates what secretlint checks across every file that `.gitignore` keeps. The line also adds a procedure (read it from the environment, list the name in `.env.example`), which the tool does not express, so the rule may flag only part of the line. | low |
| RUL-04 | measured | medium | `AGENTS.md` names `.env.example` (in the secret line) and `.secretlintignore` (in a prohibition). Neither exists in this folder. The same question as in `layered` applies: whether an instruction to write a file counts as a broken reference. | low |

Changes from the initial hypothesis:

- Agreed: SEC-04 is the finding that matters. The hypothesis expected it, and this file says the cause is the manual connection the README describes, not a defect in the template.
- Added: SEC-02, SEC-03 and SEC-05 from the rule text. SEC-02 is at medium because nothing is connected, not because a command passes.
- Added at low confidence: COD-04, RUL-02 and RUL-04.

## Findings that should not appear

- **SEC-01**: no settings file, so no allow rule, no default mode and no additional directory is set by the project. The `.agents/permissions.json` rules are not read by Claude Code, so they are not controls.
- **SEC-03 at high**: no versioned `.env` and no literal secret appear in this folder's files. The `.env` line in the text is a rule, not a value.
- **CTX-01**: `AGENTS.md` is small and far below the medium threshold. Confidence high.
- **CTX-07**: `AGENTS.md` loads by default, because no `CLAUDE.md` exists in the folder or in any parent folder.
- **STR-01**: few folders (`.agents/`, `test/`), and the file table in `AGENTS.md` explains them.
- **VER-01**: `AGENTS.md` names `npm test`, `npm run typecheck`, `npm run check:secrets` and `npm run verify`, and says to run `npm run verify` before finishing.
- **RUL-03**: "npm in this folder" against pnpm in the ancestor is a scoped exception, with its own lockfile. Confidence medium.
- **RUL-01**: every line names a file, a command or a hook. Confidence medium.
- **STR-02**: no generated or large tracked file is expected in this folder. Confidence medium.
- **COD-01** at medium or high: the code is small. Confidence low.

## Open questions

- **Hook coverage is not judged here.** The hook scripts were not read for their patterns. SEC-04 expects a wiring finding, which does not depend on the scripts being correct. If the wiring is added later, the reviewer must check that the script blocks the forms named in the text.
- **Ancestor file.** The agentAtlas `AGENTS.md` loads in these sessions as layer 3, with pnpm and site rules. It is not a finding of this folder.
- **`.gitignore` was not read.** It is said to keep `.env` files out of git. No `.env` file is visible at the top level of the folder.
- **Subfolder view in the root scan.** In the agentAtlas scan, this folder's `AGENTS.md` may appear as on-demand memory under `harness-templates/security/`. Its findings there must carry that path.
- **Permissions in a template.** The file `.agents/permissions.json` has the same content as the one in `layered`. The expectation for both is the same: not connected for Claude Code.
