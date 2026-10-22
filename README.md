# Harness X-Ray

Harness X-Ray is a static audit of the harness around an AI coding agent: the instructions, permissions, hooks, skills and tools that shape what the agent reads, runs and remembers in a repository. It is meant to be used from Claude Code. Pointed at another repository (the target), it reports what the harness seems to waste (context loaded on every session), what it leaves exposed (commands or secrets the agent can reach without a barrier) and what it lacks (verification steps, structure, reuse), with each recommendation tied to its source. It never executes code from the target and never writes to it.

## Requirements

- Node.js 22 or later. There are no npm dependencies.
- Claude Code, to run the audit with the `xray-scan` skill.

## Usage

Open Claude Code at the root of this repository and ask it to scan a target, for example "scan this repo's harness: <path>", or run the `/xray-scan` skill.

- The target must be a folder outside this repository.
- Do not add the target with the add-dir command or the `--add-dir` option: Claude Code would load the target's own memory, skills and agents into the session.

The skill runs the scanner, reads only the files the scan names, applies the rule catalog, writes `findings.json` and renders `report.md` in a new folder under `runs/`. It ends with a short summary per axis in the chat. Reports are in English unless you explicitly ask for Spanish.

## What it checks

The findings are grouped in six axes: instructions, context, security, verification, structure and code. Each rule is a file in `rules/`, and its sources are in `rules/sources.json`. A measured rule is decided by the scanner from its numbers; a judgment rule is applied by the agent, which cites the scanner's numbers instead of typing them.

## Scripts

- `node scripts/scan.mjs <target> [--out <dir>] [--include-user-layer] [--include-ancestors] [--scope <folder>]... [--layers <runDir>]`: scans a target and writes `<runDir>/measurements.json`. Without `--out`, `<runDir>` is a new folder under `runs/`. `--out` must lie inside `runs/` or the system temp folder (exit 2 otherwise). `--include-user-layer` also reads the user's Claude files in `~/.claude`, and `--include-ancestors` also reads the memory files of the parent folders of the target. Both are opt-in: without them, nothing outside the target is read. `--scope` limits the scan to a folder of the target, such as `apps/web`, and can be repeated (see Scope below). `--layers <runDir>` adds the context that Claude Code loads in each layer of a layer plan from `map.mjs` (see Scope below).

Privacy: with these flags, home paths are written as `~/...`, never as the home folder itself; the strings copied from the user's files are redacted, and the parent-folder files give only their counts.
- `node scripts/render-report.mjs <runDir>`: validates `<runDir>/findings.json` against the rule catalog, the scan and the target, then writes `<runDir>/report.md`. Exit 0 when written, 1 when validation fails (nothing is written), 2 for a usage or input error. `<runDir>` must lie inside `runs/` or the system temp folder (exit 2 otherwise).
- `node scripts/map.mjs <target> [--out <dir>]`: maps the possible layers of a target (its candidate folders, its workspaces and a folder tree) and writes `<runDir>/layers.json`. Without `--out`, `<runDir>` is a new folder under `runs/`. `--out` must lie inside `runs/` or the system temp folder (exit 2 otherwise). It reads the file list, the manifests and the root harness files (through the agent inventory) as data, never source code, and never runs anything from the target. Exit 0 when written, 2 for a usage or input error, 1 for anything unexpected.
- `node scripts/open.mjs <file|url>`: opens an `.html` file inside `runs/` (not the system temp folder; lower-case `.html`, and only letters, digits, `.`, `_`, `-`, spaces and `/` in its path below `runs/`) or an `http://127.0.0.1:<port>/...` URL with the platform's opener command (`xdg-open` on Linux, `open` on macOS), through a child process and never a shell. It writes nothing. Exit 0 when the opener was launched, 2 for a refused input or a usage error, 3 when there is no graphical environment (on Linux, neither `DISPLAY` nor `WAYLAND_DISPLAY`) or the opener command is missing, so the caller can print the path or URL instead, 1 for anything unexpected.
- `node scripts/intake.mjs <runDir> [--timeout <seconds>] [--lang en|es]`: starts a local form on 127.0.0.1 for the layers of `<runDir>/layer-plan.json` and prints its address, with a one-use token. The form asks for the depth, the layers to scan, the axes to prioritize, the report language and whether the user layer and the parent folders may be read. A valid answer is written to `<runDir>/intake.json`, and the command stops. It refuses to start when `<runDir>/intake.json` already exists. `--timeout` is the wait in seconds, from 1 to 3600 (default 600); `--lang` is the language of the pages (default en). Nothing is opened in a browser, and the skill does not use it yet. `<runDir>` must lie inside `runs/` or the system temp folder. Exit 0 when written, 4 when the wait ran out (nothing written), 2 for a usage or input error, 1 for anything unexpected.
- `npm test`: runs the test suite.
- `npm run check`: validates the rule catalog, the `data/` files (including `data/agent-harness.json` and `data/layer-signals.json`) and the measured rules.

## Scope

With `--scope <folder>`, the scan looks at one part of the target, for example one layer of a monorepo. The folder is relative to the target and must exist inside it; a folder that does not exist, is not a folder, leaves the target or is reached through a link exits with 2. The option can be repeated, and a folder inside another scope folder adds nothing.

- Analyzed only inside the scope: the structure measures (folder tree, map coverage, large and generated files) and the duplication measure, so `duplicatedLinesPct` is the share within the scope.
- Read outside the scope, because the scope inherits it: the harness of the root and of each folder between the root and the scope (CLAUDE.md, AGENTS.md, rules, skills and the files of every agent in the registry). The CLAUDE.md and AGENTS.md files of those folders and of the scope are read, not only listed. A harness file belongs to the folder that holds its agent folder (`.claude`, `.agents`, `.cursor` and the other folders that the registry names), so `apps/.claude/skills/x/SKILL.md` is part of the harness of `apps`. The project permissions and hooks are global, and so are the secret checks.
- Verification is looked for in the whole target: the root `package.json`, the root tool configs, the CI workflows, and the `package.json` files of the scope, of the folders on the way and of other layers (`verification.packages`) with the tool configs next to them, so a check that lives outside the scope still counts. A command named in a CLAUDE.md or AGENTS.md below the root is checked against the `package.json` of its folder and of the folders above it.
- Not analyzed: the files outside the scope, and the harness of the folders that are neither on the way to the scope nor inside it. `measurements.json` records the scope in its `scope` section, and the report says what was analyzed and what was not.
- `--include-ancestors` still reads the parent folders of the target, not those of the scope.

With `--layers <runDir>`, the run folder holds the layer plan of a `map.mjs` run (`layers.json` and `layer-plan.json`), and the scan adds `context.byLayer`: for each layer, the files that Claude Code loads on demand when it works there, and its nested skills. The on-demand files are the CLAUDE.md files of the folders on the way to the layer and inside it, and the rules whose `paths` match a file of the layer. Nested skills are listed apart, because their load model is not verified; nested AGENTS.md files are not counted, and imports are not followed. The always-loaded total is the same for every layer. The plan must match the target: a layer folder that is gone, or a `layers.json` written for another target, exits with 2.

## Limits

- The scan reads the target's project files only, unless a flag is given. `--include-user-layer` reads the user's `CLAUDE.md`, rules, `settings.json`, skills and subagents in `~/.claude`. `--include-ancestors` reads the memory files of the parent folders, for their counts only. Managed settings are never read.
- Not verified by a note: how the user, project and local permission rules combine. With `--include-user-layer`, the scan takes the union of the three lists and checks deny first, then ask, then allow.
- With `--include-user-layer`, the user's `defaultMode` is recorded but not applied, and the user's hooks are counted but not evaluated.
- The `@imports` in the user's files, in the parent folders and in the CLAUDE.md and AGENTS.md files that a scope reads below the root are not followed.
- Tokens are estimated from characters, never counted.
- The destructive-command checks assume the project's `defaultMode`, or `default` when the project sets none. A real session may start in another mode, which is not verified against the documentation. The report's limits section shows each command's outcome in each mode (the matrix, as context).
- The thresholds in `scripts/lib/thresholds.mjs` are provisional and not yet calibrated.
- The scanner, the renderer and the map write only inside `runs/` or the system temp folder, checked on real paths. The intake writes only `intake.json` in its run folder, which must lie there too. Any other folder is refused with exit code 2, and nothing is written.
- The scan inventories the harness files of every agent that `data/agent-harness.json` lists (`agentHarness` in `measurements.json`). The instruction rules (RUL-01 to RUL-04) cover the root instruction files of every agent, and SEC-04 and SEC-05 name the permission and hook files that no known agent loads, as not verified when an agent's load model is unknown. The content of the other agents' settings, hooks and skills is not evaluated: SEC-04 and SEC-05 check only whether a known agent loads them. The report header lists what was evaluated for each agent. The files of the root harness, including those in root folders such as `.agents/`, `.cursor/rules/` or `.github/instructions/`, are read to measure their size, within a cap of 2000 files and 32 MiB. Files in a subproject folder, such as `packages/api/AGENTS.md`, are only listed, unless `--scope` reaches them (see Scope), and secret-named files are never read. Only Claude Code has a verified load model, so only its files count in the context budget; the files of the other agents go to `agentHarness.unknownStatic`. Only Claude Code entries cite sources, and only where the source notes cover them; the rest, including some Claude Code entries, the shared `AGENTS.md` convention and every other agent, are unverified candidates (`loadModel` unknown).

`examples/harness-x-ray/review.md` records a scan of this repository's own harness.

## License

MIT. See `LICENSE`.
