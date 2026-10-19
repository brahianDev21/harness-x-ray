---
id: COD-04
title: No reuse step before writing new code
axis: code
kind: judgment
measuredSupport: [M20]
defaultImpact: low
sources: [ponytail, cc-docs-memory, cc-docs-memory-layers, cc-docs-skills, atlas-context-engineering]
evidence: benchmark
since: mvp
status: draft
---

## What it checks

Whether the instruction files tell the agent to look for existing code before it writes something new. A reuse step asks the agent to check, in order, the repository, the standard library or platform, and the dependencies the project already installs, before it adds a function, a module or a dependency.

The rule finds the absence of that step. It does not judge the code the agent writes.

## Why it matters

An agent that is not told to search tends to write what is quick to write: a helper that already exists in the repository, a small function the standard library provides, or a copy of a block next to the code that uses it. COD-01 measures the result when it becomes duplication. This rule looks at the cause in the harness.

Adding the step is a text change, and text costs tokens. The memory documentation says that CLAUDE.md is loaded at the start of every session, and that longer files consume more context and may reduce adherence. Every line of reuse guidance in the project CLAUDE.md is paid in every session, including sessions that never write code. Skill descriptions also stay in context in every session, while the body of a skill loads only when it is used.

The ladder proposed here is inspired by Ponytail, a skill with a six-step decision ladder for writing less code. Ponytail's README reports a benchmark of its own, 39 tasks over 5 runs, with less code and fewer tokens. Those figures are the author's claims. This rule has not verified them, and the skill file itself contains no figures. The evidence level of this rule is therefore benchmark: third-party, unreviewed, and unverified here. A controlled test on the target repository is needed before the step is treated as an improvement.

## How it is detected

This is a judgment rule. The measure sets the impact, and the reviewer reads the instruction files to decide whether the step exists.

Fields:

- `code.duplication.duplicatedLinesPct` (measure M20): the share of redundant lines from COD-01. It sets the impact, not the finding.
- `inventory[]`: the entries for the memory files, the rule files in `.claude/rules/` and the skill files. These are the instruction files to read.

Flag the repository when no reuse step exists in the instruction files, rules or skills. A reuse step tells the agent to search for an existing function, module or dependency before it writes new code. A generic line such as "keep code clean" or "avoid duplication" is not a step, because it names no place to look. A step counts when it names at least one place: the repository, the standard library or platform, or the installed dependencies. A skill counts when its description says it applies before writing new code.

Impact follows the code row of the impact table, through the COD-01 share:

- **Low:** COD-01 is at or below its medium threshold. The finding is a proposal about guidance only.
- **Medium:** COD-01 is medium.
- **High:** COD-01 is high. The table's high row is "duplication far above the threshold, with no guidance on reuse", and this rule is the missing guidance.

The report must say that the impact is an opinion, with the COD-01 figure next to it.

## Recommendation

Controls first, then text.

1. **Control: a duplication check.** When COD-01 is above the medium threshold, a duplication check in CI or in a hook catches new copies, which no sentence can. Do this before the text.

2. **Put the ladder where it loads only when it applies.** Two options cost less than a line in the project CLAUDE.md:
   - A path-scoped rule in `.claude/rules/` whose `paths` list the source folders. The memory documentation says a rule with `paths` loads only when Claude works with a matching file.
   - A skill whose description says when to use it, for example "Use before writing a new helper, function or module." The memory documentation says skills load when Claude determines they are relevant to the prompt. The description stays in context every session, so keep it to one line.

3. **If the project CLAUDE.md is the only option, keep the ladder to four lines.** The ladder is a paraphrase inspired by Ponytail's steps:

```markdown
Before writing new code:
1. Ask whether the change needs to exist at all, and drop anything nobody asked for.
2. Search this repository for an existing function, component or module.
3. Check the standard library, the platform and the dependencies the project already installs.
4. Otherwise write the smallest code that works, and add no dependency for a few lines.
```

4. **Measure it before claiming a result.** Adding the step is a hypothesis. Run the same tasks in a controlled test with and without the step, and compare the lines changed, the tokens used, and how many new helpers duplicate existing code (COD-01 applied to the diff). Until that test shows an effect, the report presents the step as a hypothesis, not as a proven gain. Ponytail's own figures are not evidence of the effect on this repository.

## When not to apply

- The repository already has the step in a file the agent loads, even as one line. Criterion 1 fails.
- The step is in a skill whose description says when to use it before writing new code. The step is documented and loads when it is relevant, the same way VER-01 treats a skill that describes a check.
- A repository in which the agent does not write code, such as a repository of documentation only.
- A team that wants independent scripts with intentional copies, such as one-off tooling where each script stands alone. The finding is still a fact about the instructions, but the team can decide that the step does not fit.

## Examples

Numbers in these examples are illustrative, not measurements.

### Applies: a request for more code, no step (medium)

Bad: `CLAUDE.md` says "Add a helper for every new feature." and contains no reuse step. COD-01 reports 7 %, which is medium. The instruction pushes toward new code, and nothing points to existing code. Impact is medium. Good: add the duplication check, and put the four-line ladder in a path-scoped rule for `src/`.

### Applies: a generic line only (low)

Bad: `CLAUDE.md` says "Keep code clean and well structured." That is a generic line that names no place to look. COD-01 is below the medium threshold, so the impact is low. Good: replace the line with the step, or leave it and record the finding as low.

### Applies: an installed dependency that goes unused (high)

Bad: the project installs `date-fns`, and `CLAUDE.md` has no reuse step. COD-01 reports 18 %, with a 30-line date-formatting block copied into five files. Impact is high. Good: add the duplication check in CI, and name the shared date module and the installed dependency in the shared-code map.

### Does not apply: the step exists in memory

Good: `CLAUDE.md` says "Before adding a function, search `src/lib/` and the dependencies in `package.json` for one that already does the job." The step exists, so criterion 1 fails. No finding.

### Does not apply: the step is in a skill with a clear description

Good: `.claude/skills/new-code/SKILL.md` has the description "Use before writing a new helper, function or module. Searches the repository and the installed dependencies first." The step is documented and loads when it is relevant. No finding.
