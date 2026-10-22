---
id: RUL-03
title: Contradictory or outdated instructions
axis: instructions
kind: judgment
measuredSupport: [M9]
defaultImpact: high
sources: [cc-docs-memory-maintenance, atlas-agents-md]
evidence: official-docs
since: mvp
status: draft
---

## What it checks

Two kinds of problems in instruction files:

- **Contradiction:** two statements give different answers for the same thing. Examples: one file says `npm ci` and another says `pnpm install`; one says tests sit next to the source and another says they live in `__tests__/`. The two files can belong to different agents: `AGENTS.md` can say pnpm while `.cursorrules` says npm.
- **Outdated:** a statement names a tool, command or convention the repository no longer uses. Example: "run `jest --watch`" when `package.json` has `vitest` and no `jest`.

A contradiction or an outdated statement is a problem only when the files disagree with each other or with the repository. A statement that merely names a missing file or script is RUL-04.

## Why it matters

Claude Code's memory documentation says that if two instructions contradict each other, Claude may pick one arbitrarily. The memory documentation also asks for periodic review of outdated or conflicting instructions. The agent then runs the wrong package manager, the wrong test command or the wrong layout, and nobody sees which instruction it followed.

## How it is detected

This is a judgment rule. Collect the instruction files that load for the same scope: the always-loaded files, the path-scoped rules that match the same folder, and any subdirectory file the agent reads. The root instruction files of every agent apply to the root scope, whichever agent reads them, so they are compared with the root memory of Claude Code and with each other. Compare their statements about the same subject.

Supporting data:

- `instructions.packageManager` gives the package managers the instructions name, the lockfiles present and the `packageManager` field of `package.json`. The names include those of the other agents' root files. A mismatch between a name and the lockfile or the field is the clearest contradiction.
- `instructions.packageManager.byFile[]` lists each instruction file that names a manager, with its `file`, its `managers` and its `agents`. Two files of different agents that name different managers for the root scope are a contradiction between agents, such as `AGENTS.md` with pnpm and `.cursorrules` with npm.
- The `scripts` of `package.json` and the tool configuration files show what the repository actually uses. Use them to decide which statement is outdated.

Flag a statement when all of these hold:

1. It answers a question that another statement, or the repository, answers differently. The subjects are the same: the package manager, a command, a folder, a naming or export style, a version.
2. The difference is not an intended scope. A subfolder file that says "in `legacy/`, use npm" with its own lockfile is a scoped exception, not a contradiction.
3. The reviewer can name which statement is correct from the repository, or can say that the team must decide.

## Recommendation

Make the repository the single source of truth, then fix the text.

- For the package manager, declare it in `package.json` (the `packageManager` field), keep one lockfile for that manager, and delete the sentence that names the other manager.
- For a contradiction between agents, correct the file that does not match the repository, whichever agent reads it. After that, every root instruction file should name the manager of the lockfile.
- For an outdated command or tool, change the line to the command that exists, or delete it.
- When the wrong choice must fail, a check in a script or hook is a control. A sentence is not. Choose the control when the team needs a hard failure.

Removing or correcting lines removes text and adds none. A new check in `package.json` or a hook is a harness change, not memory text.

## When not to apply

- A scoped exception: a subfolder with its own lockfile and its own instructions that say so. This holds for a file of any agent.
- A statement about a tool the team is migrating to, that marks the old tool as "being removed" and names the date or the task. The old reference is intended.
- Two statements that differ in wording but agree on the action, such as "run tests" and "run `npm test`" when `npm test` is the test script.

## Examples

### Applies: package manager contradiction

Bad, `CLAUDE.md`:

```markdown
- Install dependencies with `npm ci`.
```

Repository: `pnpm-lock.yaml` is present and `package.json` sets `"packageManager": "pnpm@9.12.0"`. The instruction names a different manager than the lockfile. Good: the line says `pnpm install`, or the team decides which tool wins and the other lockfile is removed.

### Applies: package manager contradiction between agents

Bad, `AGENTS.md`:

```markdown
- Install dependencies with `pnpm install`.
```

Bad, `.cursorrules`, the root instruction file of Cursor:

```text
Run `npm install` before you run the tests.
```

Repository: `pnpm-lock.yaml` is at the root, and no other lockfile exists. The two files name different managers for the same root scope, and the lockfile says pnpm. Good: change the `.cursorrules` line to `pnpm install`, or delete it.

### Applies: outdated tool name

Bad, `CLAUDE.md`:

```markdown
- For quick feedback, run `jest --watch`.
```

Repository: `package.json` lists `vitest` in `devDependencies` and has no `jest`. Good, `CLAUDE.md`:

```markdown
- For quick feedback, run `npm run test:watch`, which runs vitest.
```

### Applies: contradiction between two instruction files

Bad, `CLAUDE.md`:

```markdown
- Use default exports for components.
```

Bad, `.claude/rules/components.md` (no `paths` field, so always loaded):

```markdown
- Use named exports only. Never use default exports.
```

The two files give opposite answers. Good: keep one statement and delete the other.

### Does not apply: scoped exception

Good, `CLAUDE.md`:

```markdown
- Use pnpm for all scripts.
```

Good, `legacy/CLAUDE.md`:

```markdown
- `legacy/` has its own `package-lock.json`. Run `npm test` inside `legacy/`.
```

The subfolder file is an intended exception, and its own lockfile supports it.

### Does not apply: consistent statements

Good, `CLAUDE.md`:

```markdown
- Install with `pnpm install`. Run tests with `pnpm test`.
```

The repository has `pnpm-lock.yaml`, `"packageManager": "pnpm@9.12.0"` and a `test` script that runs. Every statement agrees.
