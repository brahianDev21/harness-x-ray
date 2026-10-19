# Expected findings: starting-point

Written on 2026-10-18, before any scan of this target. The target is `harness-templates/starting-point` in the agentAtlas repository. It is a small Express API for books, members and loans, with no agent harness. Its README calls it "the starting point" of the harness series. The folder has no git repository of its own; it sits inside the agentAtlas repository.

## Harness observed

- No `AGENTS.md`, `CLAUDE.md`, `CLAUDE.local.md`, `.claude/` or `.agents/` at the folder root. The README states that this is on purpose: no agent instructions, no hooks, no permission rules, no architecture rules or linters.
- Parent folders: the agentAtlas root has an `AGENTS.md`. No folder above the template has a `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md` or `AGENTS.md`, so by the default load model the agentAtlas `AGENTS.md` loads in sessions that start in this folder. It belongs to layer 3 (an ancestor), not to this folder.
- `package.json` scripts: `dev`, `start`, `test` (Vitest) and `typecheck` (`tsc --noEmit`). There are no lint, format, dependency or secret-scanner scripts, and no such config file in the top-level listing.
- Top level: `src/` (app and server), `test/` (one acceptance test file), `tsconfig.json`, `package.json` and an npm lockfile.
- No `.env` is visible at the top level.

## Expected findings

| Rule | Kind | Expected impact | Reason (file) | Confidence |
|---|---|---|---|---|
| VER-01 | judgment | medium | `test` and `typecheck` exist, but no instruction file in the folder mentions them or tells the agent to run a check. The only instruction file that loads is the ancestor one, which names another project's commands. The README names them, but the README is not memory. | medium |
| SEC-02 | measured | medium | No `.claude/settings.json`, no deny, ask or hook. With the assumed `default` mode, each destructive command asks and nothing else stops it. | high |
| SEC-03 | measured | medium | No `Read` deny and no `Read` hook, so the root `.env` read decision is `default`. No `.env` is visible here, but the row covers a local file that git may ignore. | medium |
| COD-04 | judgment | low | No reuse step exists in the folder's instruction files, because there are none. The impact follows COD-01, which I expect to be low for a code base this small. | medium |

Changes from the initial hypothesis:

- Agreed: VER-01 at medium, and SEC-02 at medium.
- Disagreed on STR-01, which I do not expect. The top level has two folders, `src/` and `test/`, whose names say what they hold, and the tests mirror the source. STR-01 needs several roles with unmapped folders (its first criterion fails). The missing memory satisfies only the second criterion.
- Disagreed on the level of COD-04. Its impact follows the COD-01 share, so with small code it is low, not medium. The finding itself stays.
- Added: SEC-03 at medium. Its `envAtRoot` row fires for every target without a `Read` deny.

## Findings that should not appear

- **CTX-01**: the repository has no always-loaded memory, so its own budget is zero. The ancestor `AGENTS.md` is layer 3. It is flagged by existence and size, and it is not a finding against this folder.
- **CTX-07**: there is no `AGENTS.md` in the folder, so there is no file for Claude Code to skip.
- **STR-01**: see the changes above.
- **SEC-01**: no settings file, so no permission rule and no default mode are set by the project.
- **SEC-04** and **SEC-05**: no memory text claims a protection or states a security rule.
- **RUL-01**, **RUL-02**, **RUL-03** and **RUL-04**: no instruction file in the folder to check.
- **STR-02**: `package-lock.json` is a lockfile and is excluded. `node_modules` is not walked and is not tracked. No large or generated tracked file is expected. Confidence medium.
- **COD-01** at medium or high: the code is small. Confidence low, because the route handlers in `src/app.ts` may repeat some text.

## Open questions

- **Listing through the parent repository.** The scanner lists files with git, run in this folder. Git then lists only the tracked files of the agentAtlas repository under this folder. If these files were not tracked, the list would be empty and no warning would be raised. Check the file count in the scan output first.
- **Commit.** The commit recorded for this folder is the agentAtlas commit, not a commit of its own.
- **VER-01 and the ancestor file.** The ancestor `AGENTS.md` mentions `pnpm test` for the Astro site. A plain word match could count that as a mention of this folder's `test` script. I expect it not to count, because it is another project's instruction. If the scan counts it, record that as a scanner issue.
- **Ancestor content.** The agentAtlas rules (Astro, pnpm, visual identity) enter the sessions of this folder. The report should show them as layer 3.
- **COD-01 level.** The source size is not known. Whether the route handlers repeat blocks long enough to matter is also unknown.
