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

- `node scripts/scan.mjs <target> [--out <dir>] [--include-user-layer] [--include-ancestors]`: scans a target and writes `<runDir>/measurements.json`. Without `--out`, `<runDir>` is a new folder under `runs/`. `--out` must lie inside `runs/` or the system temp folder (exit 2 otherwise). `--include-user-layer` also reads the user's Claude files in `~/.claude`, and `--include-ancestors` also reads the memory files of the parent folders of the target. Both are opt-in: without them, nothing outside the target is read.

Privacy: with these flags, home paths are written as `~/...`, never as the home folder itself; the strings copied from the user's files are redacted, and the parent-folder files give only their counts.
- `node scripts/render-report.mjs <runDir>`: validates `<runDir>/findings.json` against the rule catalog, the scan and the target, then writes `<runDir>/report.md`. Exit 0 when written, 1 when validation fails (nothing is written), 2 for a usage or input error. `<runDir>` must lie inside `runs/` or the system temp folder (exit 2 otherwise).
- `node scripts/map.mjs <target> [--out <dir>]`: maps the possible layers of a target (its candidate folders, its workspaces and a folder tree) and writes `<runDir>/layers.json`. Without `--out`, `<runDir>` is a new folder under `runs/`. `--out` must lie inside `runs/` or the system temp folder (exit 2 otherwise). It reads the file list, the manifests and the root harness files (through the agent inventory) as data, never source code, and never runs anything from the target. Exit 0 when written, 2 for a usage or input error, 1 for anything unexpected.
- `npm test`: runs the test suite.
- `npm run check`: validates the rule catalog, the `data/` files (including `data/agent-harness.json` and `data/layer-signals.json`) and the measured rules.

## Limits

- The scan reads the target's project files only, unless a flag is given. `--include-user-layer` reads the user's `CLAUDE.md`, rules, `settings.json`, skills and subagents in `~/.claude`. `--include-ancestors` reads the memory files of the parent folders, for their counts only. Managed settings are never read.
- Not verified by a note: how the user, project and local permission rules combine. With `--include-user-layer`, the scan takes the union of the three lists and checks deny first, then ask, then allow.
- With `--include-user-layer`, the user's `defaultMode` is recorded but not applied, and the user's hooks are counted but not evaluated.
- The `@imports` in the user's files and in the parent folders are not followed.
- Tokens are estimated from characters, never counted.
- The destructive-command checks assume the project's `defaultMode`, or `default` when the project sets none. A real session may start in another mode, which is not verified against the documentation. The report's limits section shows each command's outcome in each mode (the matrix, as context).
- The thresholds in `scripts/lib/thresholds.mjs` are provisional and not yet calibrated.
- The scanner, the renderer and the map write only inside `runs/` or the system temp folder, checked on real paths. Any other folder is refused with exit code 2, and nothing is written.
- The scan inventories the harness files of every agent that `data/agent-harness.json` lists (`agentHarness` in `measurements.json`). The instruction rules (RUL-01 to RUL-04) cover the root instruction files of every agent, and SEC-04 and SEC-05 name the permission and hook files that no known agent loads, as not verified when an agent's load model is unknown. The content of the other agents' settings, hooks and skills is not evaluated: SEC-04 and SEC-05 check only whether a known agent loads them. The report header lists what was evaluated for each agent. The files of the root harness, including those in root folders such as `.agents/`, `.cursor/rules/` or `.github/instructions/`, are read to measure their size, within a cap of 2000 files and 32 MiB. Files in a subproject folder, such as `packages/api/AGENTS.md`, are only listed, and secret-named files are never read. Only Claude Code has a verified load model, so only its files count in the context budget; the files of the other agents go to `agentHarness.unknownStatic`. Only Claude Code entries cite sources, and only where the source notes cover them; the rest, including some Claude Code entries, the shared `AGENTS.md` convention and every other agent, are unverified candidates (`loadModel` unknown).

`examples/harness-x-ray/review.md` records a scan of this repository's own harness.

## License

MIT. See `LICENSE`.
