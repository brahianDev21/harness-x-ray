# Expected findings: agentAtlas

Written on 2026-10-18, before any scan of this target. The target is the agentAtlas repository (branch `main`, commit `ff61e7ef67e55c27ac1994ebb541a7aab2a2605b`, read from the branch ref as text). It is a content-first Astro website about harness engineering for AI agents. Its `harness-templates/` folder holds standalone npm projects (`starting-point`, `layered`, `security`, plus other folders not covered here). The three named templates are scanned as their own targets. This file covers the repository's own harness and notes where template files can show up in the root scan.

## Harness observed

- Instruction files: `AGENTS.md` at the root, under 200 lines (about 166, as read). No `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` in the repository, and none in any parent folder up to the drive root (checked by existence only). By the default load model, `AGENTS.md` loads for every session in the repository.
- Subfolder memory: `harness-templates/layered/AGENTS.md` and `harness-templates/security/AGENTS.md` exist. `harness-templates/starting-point` has no instruction file.
- `.claude/` contains only `launch.json`, one preview entry for `astro preview`. There is no `settings.json`, `settings.local.json`, skill, agent, command or `.mcp.json`. No hook and no permission rule is configured for Claude Code.
- No `.agents/` folder at the root.
- Tooling: `package.json` defines `dev`, `check`, `lint`, `format:check`, `test`, `test:e2e`, `build`, `verify:search` and `preview`. The lockfile is `pnpm-lock.yaml` and `packageManager` is pnpm; there is no npm lockfile at the root. The ESLint flat config uses the recommended sets of `@eslint/js` and `typescript-eslint`, plus the Astro plugin. Prettier sets single quotes, semicolons and trailing commas. Vitest and Playwright are configured. A `.github/` folder exists (CI, not read).
- `.env.example` exists at the root and no `.env` is visible. The README (not memory) tells developers to copy `.env.example` to `.env` for local work.
- The root `AGENTS.md` names `pnpm check`, `pnpm lint`, `pnpm test`, `pnpm test:e2e` and `pnpm build`. All of them exist in `package.json`.

## Expected findings

| Rule | Kind | Expected impact | Reason (file) | Confidence |
|---|---|---|---|---|
| SEC-02 | measured | medium | No deny, ask or hook is configured for Claude Code. With the scanner's assumed `default` mode, each destructive command asks, and only the manual prompt stops it. | high |
| SEC-03 | measured | medium | No `Read` deny and no `Read` hook, so the root `.env` read decision is `default`. The README has developers create a local `.env`, so a local file is realistic. This row fires without any file; `.env.example` is excluded by name. | medium |
| RUL-04 | measured | medium | `AGENTS.md` names two files in inline code that are not at the repository root: `visual-identities.html` and `agent-engineering-platform.md` (Sources of truth). Neither is a verification command, so the impact is medium. | medium |
| RUL-02 | judgment | medium | `AGENTS.md`, "TypeScript and Astro": "Avoid `any`" restates `@typescript-eslint/no-explicit-any`, which the recommended set in `eslint.config.js` enables for code outside the ignored folders. The clause that asks to validate unknown data adds a reason the tool does not express, so only the first clause is flagged. | medium |
| RUL-01 | judgment | low | Generic lines with no repository referent, such as "Prefer concise comments that explain non-obvious decisions rather than restating code" and "Preserve accessibility, responsive behavior, and semantic HTML." | low |

Changes from the initial hypothesis:

- Agreed: SEC-02 at medium.
- Question answered: CTX-07 does not apply. No `CLAUDE.md` exists in the repository or in any parent folder, so `AGENTS.md` loads by default (see below).
- Added, not in the initial hypothesis: SEC-03 (the `envAtRoot` row) and RUL-04 (two missing files). Both follow from the rule text, not from a guess about the content.

## Findings that should not appear

- **CTX-07**: `AGENTS.md` is always loaded, because no `CLAUDE.md` exists in the repository or in any ancestor folder. The rule's condition does not hold.
- **CTX-01**: the root `AGENTS.md` is under 200 lines, and it is the only always-loaded memory (no skills, rules or imports). Its size puts it near the medium threshold, because the estimate is based on characters. I expect no finding; confidence low. If it fires at medium, check the estimate method first. Subfolder `AGENTS.md` files are on-demand and must not be counted.
- **SEC-01**: no settings file exists, so there is no `allow`, no `defaultMode` and no `additionalDirectories`.
- **SEC-04**: the root `AGENTS.md` does not promise a hook or a permission. The template sections describe the templates, not this repository's protections.
- **SEC-05**: the root `AGENTS.md` has no security prohibition (no "never" about commands, files, secrets or pushes).
- **VER-01**: the instructions name the test, lint, check and build commands and tell the agent to run the narrowest checks and to report the ones not run. A documented way exists.
- **RUL-03**: pnpm appears consistently in the lockfile, in `packageManager` and in the instructions. The line "Until the application is scaffolded, no package commands should be assumed to work" is stale, but it does not name a wrong command, so it is not a contradiction. Confidence medium.
- **COD-04**: "Reuse existing components and tokens before creating new abstractions" (Development principles) names places in the repository, so a reuse step exists. Confidence medium.
- **STR-01**: the root instructions map `src/content/` and `harness-templates/`. The other top-level folders (`public/`, `scripts/`, `tests/`) have names that explain them. `experiments/` is not mapped, which could give a low finding; confidence low.
- **STR-02**: the target is its own git repository, so the scanner lists tracked files only. Build output (`dist/`), `.astro/`, `playwright-report/` and `test-results/` are normally not tracked. Confidence medium; see open questions.
- **RUL-04 (convention paths)**: `test/library.test.ts`, `.agents/...` paths, `package-lock.json`, `CLAUDE.md`, `.codex/`, `.cursor/` and `.codex/hooks.json` appear in the `harness-templates` conventions. They name files of template folders, files the instructions forbid, or illustrative examples. They are not broken references of the root. If the literal check reports them, record it as a rule false positive for review, not as an Atlas defect. Confidence medium.

## Open questions

- **Subfolder memory in the root scan.** The memory model reads `AGENTS.md` files in subfolders as on-demand memory. If the root scan reads `harness-templates/layered/AGENTS.md` and `harness-templates/security/AGENTS.md`, then RUL-04, RUL-02, SEC-04 and SEC-05 may report lines from them under their own paths. Those are findings about the template folders, not about the root harness, and they must not change the root's CTX-01 total.
- **COD-01 and intentional copies.** The root `AGENTS.md` says every base harness keeps an identical copy of its pieces. The security piece exists in `layered` and in `security`, and the hook scripts have the same size in both folders, so they are probably identical. If the code scope includes `harness-templates/*/.agents/hooks/*.mjs`, COD-01 may find copies. I have no prediction for its level (low confidence for medium or high). If it fires, the copies are by design and the report should say so; the rule has no exception for intentional copies.
- **`.gitignore` was not read** (outside the allowed reads). It decides whether `dist/`, `.astro/`, `playwright-report/` and `test-results/` are tracked (STR-02) and whether a local `.env` is ignored (SEC-03 context).
- **Existence below the top level** was not checked beyond the top-level listing. `src/components/harness/FileExplorer.astro`, `src/components/harness/RunInBrowser.astro`, `tests/unit/harness-templates.test.ts`, `scripts/verify-search.mjs` and `public/robots.txt` are named by the instructions or scripts. If they are missing, RUL-04 gains entries; I expect them to exist.
- **Default mode.** SEC-02 uses the scanner's assumed `default` mode. Interactive sessions may start in another mode; the report should say that the assumption was made.
