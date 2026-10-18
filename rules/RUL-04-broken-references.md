---
id: RUL-04
title: Broken references to paths, commands or scripts
axis: instructions
kind: measured
measuredSupport: []
defaultImpact: medium
sources: [cc-docs-memory-maintenance, atlas-agents-md]
evidence: official-docs
since: mvp
status: draft
---

## What it checks

Instruction files that point to something the repository does not have:

- a path to a file or folder that was renamed, moved or deleted (`src/lib/api-client.ts` after a rename);
- a command or package script that is not defined (`npm run test:e2e` when `package.json` has no `test:e2e` script).

Each broken reference is reported with its file, line, exact text and type.

## Why it matters

The agent follows instructions literally. A command that does not exist fails, and the agent spends turns recovering or guesses at the replacement. A broken verification command is worse: the agent cannot check its own change, and it may report the change as verified anyway.

Claude Code's memory documentation describes a prompt audit that flags references to files or commands that do not exist, so this problem is recognized by the tool's own guidance.

## How it is detected

This is a measured rule. The threshold is not numeric: every entry is a finding.

- Field: `instructions.brokenRefs[]`. Each entry has the file, the line, the exact text and the type of the reference.
- Threshold: at least one entry. No `THRESHOLDS` key applies.
- Impact: high when the entry names a verification command (a test, lint, typecheck, check or verify command). Medium otherwise.

The scanner checks these references:

- paths in inline code, in relative Markdown links and in `@path` imports;
- commands (`npm run x`, `npm test`, `pnpm x`, `yarn x`, `bun run x`) in inline code and code blocks, against the `scripts` of the root `package.json`.

It ignores URLs, globs, placeholders and absolute paths. Absolute paths are reported as external, not as broken.

## Recommendation

Fix the reference in the instruction file, or delete it.

- For a renamed or moved path, change the line to the new path.
- For a command that should exist, add the script to `package.json` if the command is the team's standard. A verification command that does not exist is a gap in the harness, so restoring it is the change to make.
- For a command for a tool that is no longer used, delete the line.

Fixing or deleting a line removes text. Adding a script is a repository change, not memory text.

## When not to apply

- Placeholders in templates or examples: `<project-name>`, `path/to/file`, `your-app`.
- Globs (`src/**`), URLs and absolute paths outside the repository.
- Files created by a build or a tool that has not run: `dist/`, `coverage/`, `.next/`. They are expected to be missing in a clean clone.
- Files that are ignored by git and exist on the developer's machine, such as `.env` after copying `.env.example`.
- Scripts defined in a workspace package (`packages/web/package.json`). The scanner reads only the root `package.json`, so a script that exists in a workspace is reported as missing.
- A path shown inside sample output or an example the instructions explicitly label as illustrative.

## Examples

### Applies: verification command that does not exist (high)

Bad, `CLAUDE.md`:

```markdown
- Before opening a pull request, run `npm run test:e2e`.
```

`package.json` has no `test:e2e` script. Good:

```markdown
- Before opening a pull request, run `npm test`.
```

The `test` script exists, so the reference resolves.

### Applies: renamed path (medium)

Bad, `CLAUDE.md`:

```markdown
- The API client is in `src/lib/api-client.ts`.
```

The file was renamed to `src/lib/apiClient.ts`. Good:

```markdown
- The API client is in `src/lib/apiClient.ts`.
```

### Does not apply: placeholder in a template

Good, `CLAUDE.md`:

```markdown
- Name the branch `<type>/<ticket-id>-<short-description>`.
```

The angle brackets mark a placeholder, not a path.

### Does not apply: build output

Good, `CLAUDE.md`:

```markdown
- Build output goes to `dist/`. Do not edit it by hand.
```

`dist/` is created by the build and is absent in a clean clone. It is not a broken reference.
