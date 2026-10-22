---
id: RUL-02
title: Rules that a linter, formatter or hook already enforces
axis: instructions
kind: judgment
measuredSupport: [M7, M19]
defaultImpact: medium
sources: [cc-docs-memory, cc-docs-hooks-events, cc-docs-hooks, atlas-hooks]
evidence: official-docs
since: mvp
status: draft
---

## What it checks

Instruction lines that restate a check a tool already runs on the repository: a formatter's style choice, a linter's rule, an import-order or layering rule, a type check, or a secret scanner. The memory file repeats the tool's rule as text, so the agent gets the same rule twice, once as a sentence and once as a tool. The line can sit in `CLAUDE.md`, `AGENTS.md` or the root instruction file of another agent, such as `.cursorrules`.

## Why it matters

Claude Code's memory documentation says that CLAUDE.md content is context, not enforced configuration, and that there is no guarantee of strict compliance. A tool that runs on every edit is a control. A sentence is a request. When the same rule exists as both, the sentence costs tokens in every session and adds nothing the tool does not already check.

Hooks are the documented way to make a step happen every time. A hook on the `PreToolUse` event can block an action, and a hook on `PostToolUse` runs after a tool call succeeds, so it can check or format each edit. A written instruction can be skipped; a hook runs without the model's cooperation, though a failing hook lets the action proceed unless it is set to block on failure.

## How it is detected

This is a judgment rule. Use the measured support to find the tools and hooks, then compare them with the instruction lines.

- `structure.enforcementTools` lists the tools present in the repository (for example eslint, prettier, biome, tsconfig, secretlint or gitleaks).
- `claudeConfig.hooks[]` lists each hook with its `event`, `matcher` and `command`. These are the hooks of Claude Code only.
- `candidates` of kind `agent-instructions` name the root instruction files of the other agents, with their `agents`. Read each one as a memory file.

Flag an instruction line when all of these hold:

1. A tool in `structure.enforcementTools` checks the same thing. Examples: quote style, semicolons, unused variables, import order, type errors, secrets in code.
2. The tool's configuration covers the files the line is about. A tool turned off or overridden for a folder does not cover that folder.
3. The line does not add a reason, exception or context that the tool cannot express.

Check the hook only to decide the recommendation. A line is flagged on the tool's coverage alone, not on whether a hook exists. The tools in `structure.enforcementTools` run on the repository, so they cover a line in any agent's file. The scan does not evaluate the settings or hooks of the other agents, so for them it cannot say whether a hook runs.

## Recommendation

First, make the control reach the agent. Add a `PostToolUse` hook for file edits that runs the formatter or linter on the changed file, or make sure the verification command the agent runs includes the check (see VER-01). A check that runs only in CI does not show the agent its output while it works, so do not rely on it for this. For a line in another agent's file, the control goes in that agent's own settings, which the scan does not evaluate.

Then delete the duplicate line from the memory file. The line costs tokens in every session, and the tool keeps enforcing the rule.

If the agent cannot reach the tool during its work, keep the line until a hook or verification command exists. Then remove it.

## When not to apply

- The tool is not configured for the path the line talks about, for example a linter ignoring `scripts/`, and the line talks about `scripts/`.
- The line explains why a rule exists or when an exception applies. A tool can check the rule, not the reason.
- The line states a convention the tools do not check, such as a naming pattern for event handlers. Nothing enforces it, so RUL-01 or a control recommendation applies, not this rule.
- A layering rule written as text when no dependency or import check exists. Keep the text; a tool would be a separate recommendation.

## Examples

### Applies: formatter style repeated in memory

Bad, `.prettierrc.json` with `"singleQuote": true` and `"semi": false`, and in `CLAUDE.md`:

```markdown
- Use single quotes and no semicolons.
```

Good: the line is deleted, and a `PostToolUse` hook runs `prettier --write` on the edited file. The formatter enforces the style on every edit.

### Applies: formatter style in another agent's file

Bad, `.prettierrc.json` with `"singleQuote": true` and `"semi": false`, and in `.cursorrules`, the root instruction file of Cursor:

```text
Use single quotes and no semicolons.
```

Good: the line is deleted. The formatter runs on each edit through a `PostToolUse` hook in `.claude/settings.json`, or through the verification command. The scan does not evaluate Cursor's settings, so it cannot confirm a formatter step for Cursor.

### Applies: import order repeated in memory

Bad, an ESLint config that enables the `import/order` rule, and in `CLAUDE.md`:

```markdown
- Sort imports: built-ins, then external packages, then internal modules, then relative paths.
```

Good: the line is deleted once the lint command runs during verification.

### Applies only after a control is connected: secret scanning in CI

Bad, a `gitleaks` job in `.github/workflows/`, and in `CLAUDE.md`:

```markdown
- Never put API keys in source files.
```

The tool runs only in CI, so the agent never sees its result while it works. Connect a hook or a verification command first, then delete the line.

### Does not apply: no tool checks the rule

Good, in `CLAUDE.md`, with no dependency-rule or lint configuration for layers:

```markdown
- Business logic lives in `src/domain/`. Do not import from `src/ui/` into it.
```

Nothing in the repository enforces the layering, so the line is the only control. Keep it.

### Does not apply: the tool does not cover the folder

Good, in `CLAUDE.md`, while `.eslintrc` turns the `no-console` rule off for `scripts/**`:

```markdown
- Do not leave `console.log` in code under `scripts/`; use the `logger` module.
```

The tool does not check `scripts/`, so the line is not duplicated. Keep it.
