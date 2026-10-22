---
id: CTX-01
title: Always-loaded memory is too large
axis: context
kind: measured
measuredSupport: []
defaultImpact: medium
sources: [cc-docs-memory, cc-docs-memory-layers, cc-docs-memory-loading, cc-docs-memory-imports, eth-agents-md-evaluation, atlas-context-engineering]
evidence: study
since: mvp
status: draft
---

## What it checks

Whether the instruction files that load at the start of every session are too large. The rule looks at two things: a single always-loaded memory file longer than 200 lines, and the total always-loaded budget of the repository in estimated tokens.

### Context layers

Claude Code loads context in layers. The scanner sees only one of them, so the rule must not blame the repository for the others.

1. **Claude Code's base:** the system prompt, the built-in tools, the environment and the git status summary.
2. **Managed and user layers:** the organization's managed `CLAUDE.md`, the user's `~/.claude/CLAUDE.md`, the user's `~/.claude/rules/`, auto memory (the first 200 lines or 25 KB of `MEMORY.md`), user skills, and other user-level configuration that the scanner does not read.
3. **Ancestor folders:** `CLAUDE.md` and `CLAUDE.local.md` files in the folders above the repository, loaded at launch.
4. **The repository:** its `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md`, the rules under `.claude/rules/` without a `paths` field, the `@path` imports they contain, the descriptions of its skills, commands and subagents, and `AGENTS.md` when Claude Code reads it.

The scanner measures layer 4 and flags layer 3. It cannot see layers 1 and 2. A report that says "this repository loads 9,000 tokens" is wrong when most of that comes from the user's settings, so the finding must name the layer of each item.

## Why it matters

Claude Code's memory documentation says that files over 200 lines consume more context and may reduce adherence. A study of repository-level context files reports that they raise inference cost by more than 20% on average without generally raising task success. Every token of always-loaded memory is paid in every session, including the sessions where it is irrelevant.

## How it is detected

This is a measured rule with two thresholds. Both are provisional estimates, not measurements, until calibration sets them.

### Thresholds

| Key | Value | Meaning |
|---|---|---|
| `THRESHOLDS.memoryFileMaxLines` | 200 lines | Per always-loaded memory file. From the size target in the memory documentation. |
| `THRESHOLDS.alwaysLoadedTokensMedium` | 3,000 tokens (Y) | Estimated total of the always-loaded budget. |
| `THRESHOLDS.alwaysLoadedTokensHigh` | 6,000 tokens (X) | Estimated total. X = 2 × Y. |

Derivation of Y: 200 lines × about 60 characters per line ÷ 4 characters per token = 3,000 tokens. X is twice Y. The 60 characters per line is an assumption, and the 4 characters per token is the estimate used by the scanner. Both are provisional.

### Fields

- Memory files: the `inventory[]` entries with `kind: "memory"` and `loadMode: "always"`. Read their `lines` and `estTokens`.
- Total: `context.alwaysLoaded.estTokensTotal`, with its method in `context.alwaysLoaded.estMethod`. The total is the sum of `context.alwaysLoaded.byComponent[]`. Cite the breakdown by component.
- `context.alwaysLoaded.unknownStatic[]` lists items whose size cannot be known without running Claude Code, such as MCP server instructions. They are listed, never estimated, and they are not in the total.

### Finding and impact

Raise a finding when any of these holds:

- an always-loaded memory file has more than `memoryFileMaxLines` lines;
- `estTokensTotal` is above `alwaysLoadedTokensMedium`.

Impact:

- **High:** `estTokensTotal` is above `alwaysLoadedTokensHigh`.
- **Medium:** `estTokensTotal` is above `alwaysLoadedTokensMedium` and not above `alwaysLoadedTokensHigh`, or any always-loaded memory file has more than 200 lines.
- **Low:** the total is at or below `alwaysLoadedTokensMedium` and no file is over 200 lines. No finding is raised; the report states the budget as low.

Ancestor files (layer 3) are flagged by their existence and size. They are not counted as the repository's cost.

If most of the total comes from skill descriptions, commands or subagents rather than memory, the finding still stands, but it cites that component and points the recommendation at it.

## Recommendation

Change the files, not the thresholds. Each option removes text from every session or moves it to where it loads only when needed.

1. **Move part-specific instructions to `.claude/rules/`** with a `paths` field. A path-scoped rule loads only when Claude works with a matching file. Keep general rules in `CLAUDE.md`.
2. **Move long procedures into a skill.** Only the skill's description stays in context; its body loads when the skill is invoked. Check that the description says when to use the skill, or the agent will not load it in the sessions that need it.
3. **Delete duplicated, generic or stale lines** (see RUL-01 and RUL-03).
4. **Do not split a long file with imports to save tokens.** Imports organize a file, but imported files load at launch, so the cost is the same.
5. **For a layer 3 file,** change the file in that ancestor folder. The repository cannot fix it.

None of these adds text to memory. A rules file or a skill is new text in the harness, but it is loaded only when it applies.

## When not to apply

- A `CLAUDE.md` in a subfolder over 200 lines. It loads on demand, when Claude works in that folder, so it is not always-loaded.
- A file that the `claudeMdExcludes` setting skips. The scanner reads that setting from `.claude/settings.json` and `.claude/settings.local.json` only, so a value set in another settings file is not seen, and the file may appear loaded when it is not. Which settings files Claude Code honours the setting in is not verified. This is most common for ancestor files, which the patterns are not checked against.
- A rules file that the scanner lists in `warnings` because it could not parse its frontmatter. Open it and check its `paths` field before reporting it as always-loaded.
- An estimate close to a threshold. The estimate is based on characters, so tables, code and long identifiers can be over- or under-counted. Say that the figure is approximate.
- A file in layer 3 or layer 2 presented as the repository's cost.

## Examples

Numbers in these examples are illustrative, not measurements.

### Applies: one memory file over 200 lines (medium)

Bad, `CLAUDE.md` with 260 lines. The inventory entry has `lines: 260`, `loadMode: "always"` and an estimate of about 3,900 tokens. The finding is medium because the file is over 200 lines.

Good, the same content split: `CLAUDE.md` with 140 lines, and `.claude/rules/api.md` with:

```markdown
---
paths:
  - "src/api/**"
---

- Handlers return the `ApiError` type for every failure.
```

The API rule now loads only when Claude opens a file under `src/api/`.

### Applies: total above the high threshold (high)

Bad: three always-loaded memory files of 150 lines each, with an estimate of about 2,250 tokens each. The total is about 6,750 tokens, above X, so the finding is high. The three files repeat the same setup section.

Good: one file of 200 lines that holds the setup section once, with the other two files reduced to what is not in it.

### Does not apply: a long file in a subfolder

Good, `packages/web/CLAUDE.md` has 300 lines. Its `loadMode` is `on-demand`, so it is not always-loaded and is not counted. The rule does not apply to it.

### Does not apply: a long ancestor file outside the repository

Good, a `CLAUDE.md` 400 lines long in the folder above the repository. It is layer 3. The report flags it as an item outside the repository. It is not a finding against the repository.
