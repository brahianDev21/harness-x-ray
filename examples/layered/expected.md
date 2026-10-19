# Expected findings: layered

Written on 2026-10-18, before any scan of this target. The target is `harness-templates/layered` in the agentAtlas repository. It is the same Express library API as `starting-point`, organized in layers (models, repositories, services, controllers) and protected by an agent harness. The folder has no git repository of its own; it sits inside the agentAtlas repository.

## Harness observed

- `AGENTS.md` at the folder root, about 105 lines (under the 200-line limit). It has a layer table, a "key rule", "where new code goes", verification commands, a list of harness files, "never" rules, and sections on security, quality, clean code and conventions.
- No `CLAUDE.md`, `CLAUDE.local.md` or `.claude/` in the folder or in any parent folder (checked by existence). The agentAtlas `AGENTS.md` loads as layer 3 in these sessions. It says pnpm, while this folder says "Use npm in this folder, not pnpm", and this folder has its own `package-lock.json`.
- `.agents/permissions.json`: deny reads of `.env` and `.env.*`; ask before `git push`, `npm install`, `npm i` and `npm add`.
- `.agents/hooks/`: six scripts (`block-dangerous-commands.mjs`, `check-architecture-before-stop.mjs`, `check-quality-before-stop.mjs`, `check-secrets-before-stop.mjs`, `format-after-edit.mjs`, `report-duplicates-before-stop.mjs`).
- `.agents/skills/`: `add-endpoint` and `clean-code-review`. They are outside `.claude/skills/`, so Claude Code does not load them as skills.
- Nothing connects any of this to Claude Code: there is no `.claude/settings.json`. The README says: "Until you connect them, the files in .agents/ do nothing on their own."
- Checks in `package.json`: `typecheck`, `check:architecture` (dependency-cruiser on `src`), `check:secrets` (secretlint on every file that `.gitignore` keeps), `check:duplicates` (jscpd, a report that never fails), `lint` (ESLint), `format` and `format:check` (Prettier), and `test`. `verify` runs all of them except `check:duplicates`, in order.
- `.dependency-cruiser.cjs` forbids: controllers importing repositories; repositories and services importing upper layers; models importing other layers; Express outside controllers; cycles. It does not forbid controllers importing `app.ts`, although the layer table says so.
- `eslint.config.js` enables the ESLint and typescript-eslint recommended sets and sets four limits: complexity 10, nesting depth 3, 4 parameters, 50 lines per function. It also sets `eqeqeq`, and `noInlineConfig`, which makes `eslint-disable` comments ineffective.
- `.secretlintrc.json` uses secretlint's recommended preset. `.jscpd.json` configures the duplicate detector.

## Expected findings

| Rule | Kind | Expected impact | Reason (file) | Confidence |
|---|---|---|---|---|
| SEC-04 | judgment | medium | `AGENTS.md`, "Security", says that `block-dangerous-commands.mjs` blocks commands before each shell command, and that the stop hook runs secretlint. No settings file names either script, and the permission rules are not connected either. The README says the connection is made by hand. The finding should say that the wiring is missing in this repository, not that the template is wrong. The stop-hook promise is a second entry and will probably be grouped with the first. | high |
| SEC-02 | measured | medium | No deny, ask or hook is connected to Claude Code, so the assumed `default` mode asks for each destructive command and nothing else stops it. | high |
| SEC-03 | measured | medium | No `Read` deny and no `Read` hook: the root `.env` read decision is `default`. `AGENTS.md` says "never read .env", but nothing enforces it for Claude Code. | medium |
| SEC-05 | judgment | medium | "Never read, print or change `.env` or `.env.*` files" and "Ask the user before you run `git push` or install a dependency" have no deny or ask rule behind them. | medium |
| RUL-02 | judgment | medium | The layer table and "The key rule" restate dependency-cruiser rules that `check:architecture` runs. "No `any`" restates `no-explicit-any` from the recommended typescript-eslint set. The limits paragraph restates the four ESLint limits. "Never write a real secret" overlaps secretlint's recommended preset. The rule flags a line on the tool's coverage alone. The part of the layer table about `app.ts` is not enforced by the dependency-cruiser config, so that part of the table is not covered. | medium |
| RUL-04 | measured | medium | `AGENTS.md` names `.env.example` as the file for variable names, and `.secretlintignore` in a prohibition. Neither exists in this folder. Whether an instruction to write a file counts as a broken reference is a judgment; the literal check will report it. | low |
| RUL-01 | judgment | low | "A function does one thing. If you need 'and' to describe what it does, split it." and "Keep the error messages short and human-readable." Both are generic, with no repository referent. | low |

Changes from the initial hypothesis:

- Agreed: SEC-04 applies and repeats, as in the initial hypothesis. The explanation is the missing manual wiring, as the README describes it.
- Agreed: RUL-02 is a case here. The case is partial, because the dependency-cruiser config does not cover every line of the layer table.
- STR-03 is out of scope for this version. Its conventions (layer rules that a tool could enforce) are mentioned here only as context.
- Added: SEC-02, SEC-03, SEC-05 and RUL-04, from the rule text and the files above.

## Findings that should not appear

- **VER-01**: every command is listed in the Verification section, and "Run npm run verify before you say a task is done." A documented way exists.
- **STR-01**: the layer table and "Where new code goes" map the folders. The second criterion fails.
- **COD-04**: "Before you write a new function, search the code for one that already does the job, and reuse it." (Clean code) is a reuse step.
- **RUL-03**: "npm in this folder" against pnpm in the ancestor file is a scoped exception. The folder has its own lockfile and says so. A contradiction needs two statements about the same scope.
- **CTX-07**: `AGENTS.md` loads by default, because no `CLAUDE.md` exists in the folder or in any parent folder.
- **CTX-01**: the only always-loaded repository memory is `AGENTS.md`, under 200 lines. Its estimate should fall below the medium threshold. Confidence low, because the layer table and code blocks add characters, which the estimate counts.
- **SEC-01**: no project settings. The `deny` and `ask` in `.agents/permissions.json` are not controls for Claude Code, because the file is not read. If the scan counts them, record that as a scanner issue.
- **STR-02**: no generated or large tracked file is expected. `node_modules` is not walked and is not tracked; `package-lock.json` is a lockfile and is excluded. Confidence medium.
- **COD-01** at medium or high: the `src/` size is not known. Confidence low. The controllers could repeat an error-mapping block.

## Open questions

- **Scope of the ancestor file.** The agentAtlas `AGENTS.md` loads in these sessions too. Its pnpm rule covers the site, and this folder's npm rule covers only this folder. The report should show the ancestor file as layer 3, not as a finding of this folder.
- **Stop hooks.** The stop hooks run only if someone connects them. The expectation for SEC-04 does not depend on whether the scripts are correct, because nothing is connected.
- **RUL-02 coverage.** Whether the scanner counts a partly covered line as flagged is a question for the rule. This file expects a flag on the parts the tools check.
- **RUL-04 existence.** `src/` was not listed below the top level. The layer folders and `src/controllers/http.ts` are named by the README and I expect them to exist, so they are not expected as findings.
- **COD-01 level.** Whether the controllers repeat enough text to matter is unknown. `jscpd` is configured in the folder, but nothing runs it automatically. The rule's impact comes from the number, not from whether the tool is configured.
- **`.agents/skills/`.** These are not Claude Code skills, so they are not always-loaded and do not count for CTX-04, which is out of scope for this version.
