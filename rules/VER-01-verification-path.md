---
id: VER-01
title: No documented way to verify a change
axis: verification
kind: judgment
measuredSupport: [M15, M19]
defaultImpact: medium
sources: [cc-docs-best-practices, atlas-verification-evaluation, atlas-agents-md]
evidence: official-docs
since: mvp
status: draft
---

## What it checks

Whether the agent has a way to check its own change, and whether the instructions say to use it. Two cases:

- **No way at all:** the repository has no test, lint, typecheck or check command, no configured checking tool and no CI workflow, and the instructions describe no manual check.
- **A way exists but is not mentioned:** the repository has verification commands, and the instruction files never mention them or tell the agent to run a check before reporting a change as done.

## Why it matters

Claude Code's best-practices guidance says to give Claude a check it can run, such as tests, a build, a linter or a screenshot, so that it can verify its own changes. Without one, the only check on the agent's claim that a change works is the agent's own reading. A check that the instructions never mention gives the agent no reason to run it.

## How it is detected

This is a judgment rule. Use the measured support to find what exists, and read the instruction files to find what they say.

- `verification.commands` lists the verification scripts in `package.json` (test, lint, typecheck, format, verify or check, build).
- `structure.enforcementTools` lists the checking tools configured in the repository, and the CI workflows that run them.
- `verification.mentioned` lists which of those scripts the instruction files mention.

Flag the repository when one of these holds:

1. **No way at all.** `verification.commands` is empty, `structure.enforcementTools` lists no checking tool and no CI workflow, and no instruction file describes a manual way to confirm a change. Impact: high.
2. **Not mentioned.** `verification.commands` lists a test, lint or typecheck command, and `verification.mentioned` does not include it, and no instruction file tells the agent to run any check before finishing. Impact: medium.

Do not flag a repository in which a documented way exists:

- a manual check written out step by step, even when no automated test exists;
- a skill whose description says when to run the checks, so the agent loads it when the work is done.

## Recommendation

Change the harness first, then the text.

1. **If no check exists,** add one: a `test`, `lint` or `typecheck` script in `package.json`, or a CI job that runs it. This is a control. A sentence in memory cannot run a check.
2. **If the check must run every time,** connect it to the agent's loop. A `PostToolUse` hook can run a fast check after edits, and a `Stop` hook can run one at the end of a turn. Choose a hook only when the check is fast enough to run that often.
3. **Then add one line** to `CLAUDE.md` that names the command or commands to run before the agent reports a change as done. For example: "Before reporting a change as done, run `npm test` and `npm run lint`."

Step 3 adds text that loads into every session. Treat it as a hypothesis to measure in a controlled comparison, not as a proven improvement. Prefer steps 1 and 2 when they are enough.

## When not to apply

- A check that exists and is documented in a skill whose description says when to use it.
- A repository whose only change type cannot be checked automatically, when the instructions state that and give a manual check.
- A `build` script as the only check. The second case counts test, lint and typecheck commands, so a build alone does not trigger it. Say in the report that the build is a weak check.
- Scripts such as `start` or `dev`. They run the program but do not check a change.

## Examples

### Applies: no way to verify a change (high)

Bad, `package.json`:

```json
{
  "scripts": {
    "start": "node server.js"
  }
}
```

`structure.enforcementTools` lists no checking tool and there is no CI workflow. `CLAUDE.md` describes the folder layout and says nothing about checks. Good: add a `test` script and a CI job that runs it, then add the line from step 3 of the recommendation.

### Applies: checks exist but are not mentioned (medium)

Bad, `package.json`:

```json
{
  "scripts": {
    "test": "vitest run",
    "lint": "eslint .",
    "typecheck": "tsc --noEmit"
  }
}
```

Bad, `CLAUDE.md`:

```markdown
## Architecture
The API layer lives in `src/api/`. The database layer lives in `src/db/`.
```

Three verification commands exist, and the instructions mention none of them. Good: add to `CLAUDE.md`:

```markdown
- Before reporting a change as done, run `npm test`, `npm run lint` and `npm run typecheck`.
```

### Does not apply: a documented manual check

Good, `CLAUDE.md`:

```markdown
There are no automated tests yet. To verify a change to the import flow, run `npm start`, upload `fixtures/sample.csv` and confirm the table shows 42 rows.
```

The instructions describe a way to confirm the change. Nothing is missing.

### Does not apply: the check is in a skill

Good, `.claude/skills/verify/SKILL.md` has this frontmatter description:

```markdown
---
description: Run the test, lint and typecheck commands for this repository and report the results. Use before reporting a change as done.
---
```

The check is documented, and the description tells the agent when to load it. `CLAUDE.md` does not need to repeat it.
