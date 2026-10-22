# Expected findings: multi-agent

Written on 2026-10-22, before any scan of this target. The target is a small hypothetical repository, not a folder of this repository, so these notes describe its input files instead of versioning them. It is a TypeScript library with a `src/` folder, set up for several coding agents at once. It has no git repository in these notes.

## Input files

- `package.json`: scripts `test` (Vitest) and `build` (`tsc`), with `vitest` and `typescript` as dev dependencies. No `test:unit` script, no `packageManager` field, and no linter or formatter in the dependencies or the config files.
- `pnpm-lock.yaml` at the root. No other lockfile.
- `src/`: the library code. Not described further.
- `AGENTS.md`, about 60 lines, shared by all agents. It says "Use pnpm for every command." and "Before you report a change as done, run `pnpm test`." It also says "The hook in `.agents/hooks/block-dangerous-commands.mjs` blocks `rm -rf` before each shell command." The other lines name folders and naming rules, all specific.
- `CLAUDE.md`, about 10 lines of Claude-specific notes, for example "Use the Read tool to open files, not `cat`." It has no `@AGENTS.md` import and names no package manager.
- `.cursorrules`, the legacy root file of Cursor, 3 lines: "Run `npm install` before you run the tests.", "Write clean, readable code and handle errors properly." and "Keep changes under `src/`."
- `.github/copilot-instructions.md`, the root file of GitHub Copilot, 2 lines: "Use npm to run the scripts." and "Before you report a change as done, run `npm run test:unit`."
- `GEMINI.md`, the root file of Gemini CLI, 3 lines: "Keep changes under `src/`.", "Never run `git push` without asking." and "The settings in `.gemini/settings.json` deny `rm -rf`."
- `.gemini/settings.json`: a file whose tool list excludes `rm -rf`. The registry gives the folder `.gemini/` an unknown kind, and the scan does not verify that Gemini CLI reads the file.
- `.agents/hooks/block-dangerous-commands.mjs`: the only file in `.agents/`. It is a script that blocks `rm -rf`. Nothing in this repository connects it to an agent.
- No `.claude/` folder, so no `.claude/settings.json`. No `.cursor/`, `.codex/`, `.windsurfrules` or `.clinerules`.

## Expected agents table

The report header lists the detected agents, with what the scan evaluated for each. The layout may differ; the content should match.

| Agent | Evaluated | Detected, content not evaluated |
|---|---|---|
| Claude Code (`claude-code`) | instructions (`CLAUDE.md`) | none |
| AGENTS.md and .agents/ (shared convention) (`agents-md`) | instructions (`AGENTS.md`) | hooks (`.agents/hooks/block-dangerous-commands.mjs`) |
| Cursor (`cursor`) | instructions (`.cursorrules`) | none |
| GitHub Copilot (`github-copilot`) | instructions (`.github/copilot-instructions.md`) | none |
| Gemini CLI (`gemini-cli`) | instructions (`GEMINI.md`) | unknown (`.gemini/settings.json`) |

Codex, Windsurf and Cline are not listed, because no file of theirs exists in the input. `AGENTS.md` is listed under the shared convention, not under Codex.

## Expected findings

| Rule | Kind | Expected impact | Agents | Reason (file) | Confidence |
|---|---|---|---|---|---|
| RUL-03 | judgment | high | `agents-md`, `cursor`, `github-copilot` | A contradiction between agents, from `instructions.packageManager.byFile[]`. `AGENTS.md` says pnpm. `.cursorrules` (`npm install`) and `.github/copilot-instructions.md` (`npm`) say npm. The root lockfile is `pnpm-lock.yaml`, and no other lockfile exists, so the repository says pnpm. The fix is in the two files of Cursor and GitHub Copilot. The impact is high, because the table gives high to a contradiction that leads to running the wrong commands. | high |
| RUL-04 | measured | high | `github-copilot` | `.github/copilot-instructions.md` names `npm run test:unit` as the step before a change is reported as done. `package.json` has `test` and no `test:unit`. The command is a verification command, so the impact is high. | high |
| CTX-07 | measured | medium | `claude-code` | `CLAUDE.md` is at the root and nothing imports `AGENTS.md`, so `AGENTS.md` is `not-loaded` for Claude Code. The title is "Claude Code does not load AGENTS.md next to a CLAUDE.md". The finding names no other agent. | high |
| SEC-04 | judgment | medium | `agents-md`, `claude-code` | `AGENTS.md` says that `.agents/hooks/block-dangerous-commands.mjs` blocks `rm -rf`. The script is an unloaded control of kind hooks. Claude Code is verified not to load `.agents/`, and the convention is unknown, so the status is `not-verified`. The finding says that the block is not verified, and does not say that the script is missing. The reviewer does not read the script. Claude Code also does not load `AGENTS.md` here (CTX-07), so no verified agent reads the promise. | high |
| SEC-05 | judgment | medium | `gemini-cli` | `GEMINI.md` says "Never run `git push` without asking." No deny, ask or PreToolUse hook in any file that the scan reads covers the push, so the line has no control. The finding is about the text: it does not depend on `.gemini/settings.json`, which the scan does not classify. | medium |
| SEC-02 | measured | medium | `claude-code` | No `.claude/settings.json` exists, so no deny, ask or hook is connected to Claude Code, and the assumed `default` mode asks for each destructive command. The same reasoning as in `examples/layered`. | high |
| RUL-01 | judgment | low | `cursor` | The `.cursorrules` line "Write clean, readable code and handle errors properly." has no repository referent. | medium |

## Findings that should not appear

- **VER-01**: `AGENTS.md` names `pnpm test`, and the `test` script exists. A way exists and is documented.
- **RUL-02**: no formatter, linter or secret-scanner configuration, and no lint script. No line restates a tool.
- **RUL-03 for `CLAUDE.md` and `GEMINI.md`**: neither names a package manager, so neither takes part in the contradiction.
- **RUL-04 for the other references**: `pnpm test`, `src/`, `.gemini/settings.json` and `.agents/hooks/block-dangerous-commands.mjs` all exist. The built-in `npm install` is discussed under the open questions.
- **RUL-01 for `AGENTS.md` and `CLAUDE.md`**: every line names a folder, a command or a tool.
- **CTX-07 for the other agents**: the finding is about Claude Code only.
- **CTX-01**: the only file that Claude Code always loads is a short `CLAUDE.md`, about 10 lines.
- **SEC-01**: no allow rule exists in any Claude Code settings file.
- **SEC-04 for Claude Code's settings**: none, because there are no Claude Code settings.
- **SEC-04 or SEC-05 candidate for `.gemini/settings.json`**: none. The registry gives `.gemini/**` the kind `unknown`, so the scan does not classify the file as settings and names no unloaded control for it. The file is listed as detected, not evaluated, in the Gemini CLI row.
- **SEC-04 for the `GEMINI.md` sentence that `.gemini/settings.json` denies `rm -rf`**: not expected. The scan gives no candidate and no status for that file, so the reviewer has nothing to report from the scan. A reviewer could still question the sentence from the text alone; this file does not expect that.
- **STR rules**: outside this example.

## Open questions

- **`npm install` in `.cursorrules`.** The rule text does not say whether a built-in command such as `npm install` counts as a script reference. The expectation is no RUL-04 entry for it. If the scanner reports one, record it as a scanner issue.
- **SEC-03.** The input names no `.env` file, and SEC-03 is not in the table. Whether the root `.env` read decision yields a finding here is not predicted by this file. Compare it with the result when the scan runs.
- **Kind of files in `.gemini/`.** The registry marks `.gemini/**` as kind `unknown`. If the registry later gives a kind to `.gemini/settings.json`, the scan may name it as an unloaded control, and this file's expectation for it must change.
- **Status of the unloaded controls.** The `.agents/hooks/` script is `not-verified`, because the convention is unknown. A verified load in the registry would change the status and the wording of its finding.
