---
id: CTX-04
title: Skill descriptions that are long, cut or too many
axis: context
kind: measured
measuredSupport: []
defaultImpact: low
sources: [cc-docs-skills]
evidence: official-docs
since: v0.2
status: draft
---

## What it checks

Each skill of the repository that Claude Code lists at the start of every session, one by one: whether its description is longer than the listing shows, whether it is long, and whether the repository lists too many skills.

The rule covers Claude Code skills only, because only for them does a source say what is always in context. Commands and subagents are measured too, and `measurements.json` holds the length of their descriptions, but they give no finding: no note in `rules/sources.json` says which part of a command or a subagent loads at the start of a session. That is pending verification.

## Why it matters

The skills page says that a skill's description stays in context, while the full SKILL.md loads only when the skill is invoked. Every description therefore costs context in every session, whether the skill is used or not. The same page says that the skill listing cuts a description at 1,536 characters. Text past that point never reaches the model, so the part of the description that says when to use the skill may be lost.

CTX-01 sums the whole always-loaded budget, skill descriptions included. CTX-04 looks at each skill instead. A long description is worth fixing even when the total is low, because it is paid in every session and it is the text that decides when the skill loads.

## How it is detected

This is a measured rule. The scanner reads `claudeConfig.skills[]` and keeps the skills with `loadMode: "always"`: the skills of the root `.claude/skills/` that the model may invoke. A nested skill is on demand, and a skill with `disable-model-invocation` is not loaded, so neither counts. The user's skills, with `--include-user-layer`, are another layer and are not counted.

For each skill, `descriptionChars` is the length of what the listing shows: the description, or the first line of the body when there is none, joined by a line break to the `when_to_use` text. The scanner counts UTF-16 code units, so a character outside the Basic Multilingual Plane, such as an emoji, counts as two. Whether the listing measures its cut the same way, or applies it to each field, is not verified by a note.

| Trigger | Condition | Impact |
|---|---|---|
| `skill-description-truncated` | `overLimit` is true: `descriptionChars` is above 1,536, the cut of the listing | medium |
| `skill-description-long` | `descriptionChars` is above `THRESHOLDS.skillDescriptionMaxChars` (1,024) and not above 1,536 | low |
| `skill-count-high` | more than `THRESHOLDS.skillCountMax` (30) skills are listed; `detail.count` gives the count | low |

The finding has one trigger per skill whose description is long or cut, and one count trigger, which names every listed skill as evidence. Its impact is the highest of its triggers. A root skill whose frontmatter cannot be read is not counted, so the count is a lower bound. Both thresholds are provisional, in `scripts/lib/thresholds.mjs`. 1,024 is two thirds of the cut, so a long description is flagged while it still has room before the cut. 30 is Y of CTX-01 (3,000 tokens) divided by an assumed 100 tokens per listed skill (a description of about 400 characters), the count at which the listing alone would reach Y. Skills with longer descriptions reach Y with fewer skills; that total is CTX-01's. A root skill whose frontmatter cannot be read is listed in `undeterminable`, because the length of its description is not known.

Boundary with CTX-01: CTX-01 counts the total in tokens and the size of each always-loaded memory file. CTX-04 counts no tokens: it judges each skill's description and the number of skills. An excess is reported by one rule only.

## Recommendation

1. **Shorten a cut description below 1,536 characters.** Put first what the skill does and when to use it, since the end of the text is what the listing drops. Move the details into the body of SKILL.md, which loads only when the skill runs.
2. **Shorten a long description.** Keep the trigger words and the purpose; move examples and procedures into the body or into files next to SKILL.md.
3. **Reduce the number of listed skills.** Merge skills that cover the same task, or set `disable-model-invocation: true` on a skill that a person runs by name, so its description leaves the listing.

Each change edits a skill file, which is part of the harness. A shorter description changes when the agent picks the skill, so check that it is still invoked in the sessions that need it.

## When not to apply

- A skill under `.claude/skills/` of a subfolder. It is on demand, and its load model is not verified.
- A skill with `disable-model-invocation: true`. Its description is not in the listing.
- A command or a subagent with a long description. It is measured, but no source says that it loads at the start.
- The total cost of the listing. That is CTX-01's: CTX-04 does not count the tokens of the skills.
- A description close to a threshold. The thresholds are provisional, and the count is in characters, not tokens.

## Examples

File names and lengths in these examples are illustrative, not measurements.

### Applies: a description past the cut (medium)

`.claude/skills/release/SKILL.md` has a description of 2,100 characters, and the sentence that says when to use the skill comes last. The listing shows the first 1,536 characters, so that sentence never reaches the model. Good: put the purpose and the trigger first, move the steps into the body, and keep the description under 1,024 characters.

### Applies: many small skills (low)

The repository lists 42 skills, each with a short description. No description is long, and the total may be under CTX-01's threshold, but the count is above 30. Good: merge the skills that overlap, and mark the ones that people run by name with `disable-model-invocation: true`.

### Does not apply: a long subagent description

`.claude/agents/reviewer.md` has a description of 1,800 characters. The scanner measures it, but CTX-04 does not report it, because no source says what of a subagent is always in context.
