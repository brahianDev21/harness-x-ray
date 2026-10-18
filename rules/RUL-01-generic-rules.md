---
id: RUL-01
title: Generic rules the model already follows
axis: instructions
kind: judgment
measuredSupport: []
defaultImpact: low
sources: [eth-agents-md-evaluation, cc-docs-memory, atlas-agents-md]
evidence: study
since: mvp
status: draft
---

## What it checks

Lines in always-loaded instruction files that state a general practice any capable coding agent already follows, and say nothing specific to this repository. Typical lines: "write clean code", "use meaningful names", "handle errors properly", "keep functions small", "follow SOLID principles".

A line matches when deleting it would not change any decision the agent makes in this repository.

## Why it matters

Every line of an always-loaded memory file is read at the start of every session, so a generic line costs tokens in every session and tells the agent nothing it needs. A study of repository-level context files reports that they do not generally raise task success and raise inference cost by more than 20% on average.

Claude Code's memory documentation says that more specific and concise instructions are followed more consistently. A generic line therefore adds cost without adding guidance.

## How it is detected

This is a judgment rule. Read every always-loaded memory file: `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md` when it loads, and the rules files under `.claude/rules/` that have no `paths` field. Flag a line only when all of these hold:

1. It states a general practice (naming, error handling, testing, structure, style) without naming a file, folder, command, library, service or decision of this repository.
2. The repository does not enforce it with a tool. If a linter or hook enforces the line, the line belongs to RUL-02.
3. Removing it would not change a choice the agent has to make here.

Supporting data: `inventory[]` entries with `kind: "memory"` and `loadMode: "always"` give the file and its `estTokens`, so the report can show what the generic lines cost. This rule does not use a numeric threshold.

## Recommendation

Delete the line. The change is in the memory file, and it removes text, so it adds no cost to later sessions.

If the practice must hold, use a control rather than a sentence. A lint rule or a hook that runs on edits enforces it on every change, which the agent cannot skip (see RUL-02).

Removing a line can change the agent's behavior. Treat the effect as a hypothesis to check in a controlled comparison, not as a proven gain.

## When not to apply

- A phrase that sounds generic but names a local meaning. "Keep changes small" followed by "a pull request touches at most three modules" is specific.
- A line the team has seen the agent ignore in this repository. The agent does not already follow it, so it is not redundant. Check the control options before keeping it as text.
- A line that a tool enforces. The finding belongs to RUL-02, not to this rule.

## Examples

### Applies: generic practices with no repository referent

Bad, in `CLAUDE.md`:

```markdown
## Code style
- Write clean, readable code.
- Use meaningful variable names.
- Handle errors properly.
- Follow SOLID principles and keep classes small.
```

None of the four lines names a file, command, library or decision. Delete them.

### Applies: one generic line among specific ones

Bad, in `CLAUDE.md`:

```markdown
- Run `npm test` before reporting a change as done.
- Write good tests.
```

The first line is specific and stays. The second is generic and is flagged.

### Does not apply: a specific line that sounds like a general rule

Good, in `CLAUDE.md`:

```markdown
- Validate request bodies with `zod` schemas in `src/api/schemas/`. Do not write hand-made parsers.
```

It names a library and a folder. A general practice cannot tell the agent which library or which folder to use, so the line is specific.

### Does not apply: a specific value

Good, in `CLAUDE.md`:

```markdown
- Use 2-space indentation and single quotes.
```

A concrete value that the agent cannot guess is not generic. If a formatter enforces it, RUL-02 applies instead.
