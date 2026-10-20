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

- `node scripts/scan.mjs <target> [--out <dir>]`: scans a target and writes `<runDir>/measurements.json`. Without `--out`, `<runDir>` is a new folder under `runs/`.
- `node scripts/render-report.mjs <runDir>`: validates `<runDir>/findings.json` against the rule catalog, the scan and the target, then writes `<runDir>/report.md`. Exit 0 when written, 1 when validation fails (nothing is written), 2 for a usage or input error.
- `npm test`: runs the test suite.
- `npm run check`: validates the rule catalog, the `data/` files and the measured rules.

## Limits

- The scan reads the target's project files only. It does not read the user layer (memory and settings in the user's Claude folder) or the parent folders of the target.
- Tokens are estimated from characters, never counted.
- The destructive-command checks assume the project's `defaultMode`, or `default` when the project sets none. A real session may start in another mode.
- The thresholds in `scripts/lib/thresholds.mjs` are provisional and not yet calibrated.

`examples/harness-x-ray/review.md` records a scan of this repository's own harness.

## License

MIT. See `LICENSE`.
