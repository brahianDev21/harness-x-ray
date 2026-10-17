---
id: CTX-07
title: AGENTS.md is not loaded next to a CLAUDE.md
axis: context
kind: measured
measuredSupport: []
defaultImpact: medium
sources: [cc-docs-memory-agents-md, cc-docs-memory-agents-import, cc-docs-memory-agents-setting, atlas-agents-md]
evidence: official-docs
since: mvp
status: draft
---

## What it checks

Whether the repository has an `AGENTS.md` (or `.claude/AGENTS.md`) that Claude Code will not read, because a `CLAUDE.md` exists next to it or above it and nothing imports the `AGENTS.md` file.

The check covers a `CLAUDE.md` in the repository and a `CLAUDE.md` in an ancestor folder of the repository. Both cause the same result.

## Why it matters

Many teams write their instructions in `AGENTS.md` so that every coding agent reads them. Claude Code reads `AGENTS.md` by default only when no `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` exists in the working directory or above it. When one does exist, Claude Code reads the `CLAUDE.md` files and skips the `AGENTS.md`. The instructions in `AGENTS.md` are then absent from the session, and nothing reports it. The two files drift apart, and the team assumes Claude follows a file it never sees.

A user-level `~/.claude/CLAUDE.md` does not count for this check, because it is personal memory and not a project file.

### Assumption about settings

The scanner assumes the default value of the **Project instructions** setting, `claude-md-or-agents-md`. A person can change that value in a user, command-line or managed settings file. Claude Code ignores the entry in project and local settings files. The scanner reads none of the three settings files that can change it, so for a person who changed the value the finding may be wrong. The report must say that the scanner assumed the default.

## How it is detected

This is a measured rule. The threshold is not numeric: any matching entry is a finding.

- Field: the `inventory[]` entry for `AGENTS.md` or `.claude/AGENTS.md` with `loadMode: "not-loaded"`.
- `loadReason` says whether the `CLAUDE.md` that causes this sits in the target repository or in an ancestor folder. Cite it in the finding.
- Threshold: no `THRESHOLDS` key applies. Any such entry is a finding.

The scanner sets `not-loaded` only when no `CLAUDE.md` imports the `AGENTS.md` file. If `loadMode` is `always`, Claude Code reads the file, and the rule does not apply.

Impact: medium. The impact table has no row for silently missing instructions. Medium is used because the instructions are absent from every session, although no size threshold is involved.

## Recommendation

Make one of these changes. Each makes the `AGENTS.md` content load.

1. **Import it from `CLAUDE.md`.** Put `@AGENTS.md` as the first line of `CLAUDE.md`, and put Claude-specific instructions below it. Claude reads the imported file first. Use this when other tools must read `AGENTS.md` too.
2. **Merge the files.** Move the content of `AGENTS.md` into `CLAUDE.md` and remove `AGENTS.md`. Use this only when no other tool needs `AGENTS.md`.
3. **For an ancestor `CLAUDE.md`,** add a `CLAUDE.md` in the repository with the `@AGENTS.md` import. The repository's own `CLAUDE.md` then loads the file, and the ancestor file is a separate item for CTX-01.

Option 1 and option 3 add the whole `AGENTS.md` to every session. Its size is measured by the always-loaded budget (CTX-01). Load it on purpose: the cost is paid in every session, and the study of repository context files reports higher inference cost without a general gain in task success. Treat the change as a hypothesis to measure in a controlled comparison, not as a proven improvement.

## When not to apply

- A `CLAUDE.md` that already imports `@AGENTS.md`. The file loads once through the import.
- A `CLAUDE.md` that is a symlink to `AGENTS.md`. The content loads once, through the link.
- A person who set the **Project instructions** value to `claude-md-and-agents-md` or `claude-md` in a settings file the scanner does not read.
- A team that has decided Claude must not use `AGENTS.md`. The state is then correct. Report it as a fact, not as a defect.

## Examples

### Applies: repository CLAUDE.md with no import (medium)

Bad, repository files:

```text
AGENTS.md       120 lines, shared by all coding agents
CLAUDE.md        30 lines, Claude-specific, no import
```

Inventory entry: `AGENTS.md`, `loadMode: "not-loaded"`, with a `loadReason` that names the `CLAUDE.md` in the target. The 120 lines are not in any session.

Good, `CLAUDE.md`:

```markdown
@AGENTS.md

## Claude Code
- Keep Claude-only notes in this section. Shared rules stay in AGENTS.md.
```

The shared file loads first, and the Claude-specific section follows it.

### Applies: CLAUDE.md in an ancestor folder

Bad: the repository is `work/app/`, it has an `AGENTS.md`, and `work/CLAUDE.md` exists above it. The repository has no `CLAUDE.md`. The inventory entry is `not-loaded`, and its `loadReason` names an ancestor.

Good: add `CLAUDE.md` to `work/app/` containing `@AGENTS.md`. The repository's own file is in the working directory, so Claude reads it, and the import loads `AGENTS.md`.

### Does not apply: the import is present

Good, `CLAUDE.md`:

```markdown
@AGENTS.md
```

The inventory entry for `AGENTS.md` shows `loadMode: "always"` through the import, so there is no finding.

### Does not apply: no CLAUDE.md exists above the repository

Good: the repository has `AGENTS.md`, and neither the repository nor any folder above it has a `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md`. The inventory entry is `always`, so Claude reads the file by default.
