---
id: COD-01
title: Duplicated code is above the threshold
axis: code
kind: measured
measuredSupport: []
defaultImpact: medium
sources: [gitclear-ai-copilot-code-quality-2025, gitclear-coding-on-copilot-2023, ponytail, cc-docs-best-practices, cc-docs-hooks-events]
evidence: study
since: mvp
status: draft
---

## What it checks

Whether blocks of code repeat too often in the main code of the repository. The scanner looks for runs of identical normalized lines, first across files and then within one file, and reports the share of lines that are repeats.

Duplication is a symptom. Two copies of a block are not a defect by themselves, and fixing existing copies is a code change that the team makes. The recommendation of this rule is a change in the harness that stops new copies from appearing and shows the agent the shared code it should reuse.

## Why it matters

A repeated block has to be fixed in every copy, and the copies drift apart. An agent that writes new code without seeing the shared code tends to write another copy.

GitClear, a vendor of code analytics, reports a rise in copy-pasted and cloned lines in code changes from 2020 to 2024, in a report about AI coding assistants. A 2023 report from the same vendor reports copy-pasted code rising relative to moved code. Both are vendor data, not peer-reviewed studies. They describe many repositories and do not measure the effect of an agent on one repository. `sources.json` types them as studies, so the evidence level of this rule reads as study. Read that as a vendor's correlation.

## How it is detected

This is a measured rule. The scanner writes the `code.duplication` output, and the rule reads these fields:

- `code.duplication.duplicatedLinesPct`: the share of normalized lines that are redundant, in percent.
- `code.duplication.groups[]`: the 20 largest groups, each with the `file:line` of every copy.
- `code.duplication.inTests`: the same measures for test files, counted apart. They do not enter the percentage.
- `code.duplication.filesScanned`: the number of main-code files scanned. Files skipped because of the caps appear in `warnings`.

### Metric

Normalization comes before matching. Each line loses its leading and trailing spaces. Empty lines, one-line comments, import lines and lines made only of punctuation, such as `}` or `);`, are dropped. Each kept line keeps its original line number, so a copy can be cited by file and line.

The scanner compares windows of 8 normalized lines by hash, merges overlapping windows into blocks, and groups identical blocks. The window size is a scanner parameter, not a threshold. It is long enough that short idioms do not form groups, and it is provisional until it is calibrated on Agent Atlas.

- **Redundant lines** of a group: the lines of all its copies minus one copy. A block of L normalized lines that appears k times adds (k - 1) x L redundant lines.
- **`duplicatedLinesPct`**: total redundant lines divided by the normalized lines of the main-code files, times 100.

Example of the metric: a 12-line block copied into three files adds (3 - 1) x 12 = 24 redundant lines. If the main code has 1,200 normalized lines in total and that is the only group, the share is 2 %.

### Thresholds

| Key | Value | Meaning |
|---|---|---|
| `THRESHOLDS.duplicationPctMedium` | 5 % | Redundant share above which the finding is medium |
| `THRESHOLDS.duplicationPctHigh` | 15 % | Redundant share above which the finding is high ("far above") |

Derivation: an assumption, not a measurement. 5 % is a level at which a reviewer would expect repeated blocks to be noticed in a project of a few thousand normalized lines. 15 % is three times that. Both stay provisional until calibration on Agent Atlas and at least one more repository.

### Finding and impact

The impact comes from the number alone. The scanner emits the finding, and this rule does not ask the agent to judge it.

- **High:** `duplicatedLinesPct` is above `THRESHOLDS.duplicationPctHigh`.
- **Medium:** `duplicatedLinesPct` is above `THRESHOLDS.duplicationPctMedium` and not above `THRESHOLDS.duplicationPctHigh`.
- **Low:** `duplicatedLinesPct` is at or below `THRESHOLDS.duplicationPctMedium`. No finding is raised, and the report states the figure.

Whether the harness guides reuse is not judged here. The "no guidance on reuse" condition of the impact table's code row is carried by COD-04, whose impact follows this rule's share. The report shows the COD-01 finding and the COD-04 finding together, each with its own impact.

Groups in test files are not part of the percentage. Duplication that appears only under `inTests` does not raise a finding.

With a scope (the `scope` section of measurements.json is present), only the code inside the scope is read. `duplicatedLinesPct` is then the share of the normalized lines inside the scope, and a copy outside the scope is not seen. A low share does not show that the rest of the repository has no copies.

## Recommendation

Change the harness, in this order. Refactoring the existing copies is a code task for the team, and it is not what this rule recommends.

1. **Control: a duplication check that runs.** Add a copy-paste detector to CI, such as jscpd, and make the job fail when the share passes the limit the team picks. jscpd is one example; other detectors do the same job, and the choice depends on the team's languages. A `PostToolUse` hook runs after a tool call succeeds, so it can run a check after each edit. Use a hook only when the check is fast enough to run that often. The agent should also be able to run the check itself, so that it sees the result before it reports a change as done, as with the verification rule (VER-01).

2. **Guidance: a map of shared code in memory.** Name the folder where shared helpers live, following the map described in STR-01, and say that a helper needed in two places moves there. Two or three lines are enough. This adds text to every session, so treat it as a hypothesis to test.

3. **Reuse rule.** Add the short reuse step described in COD-04, in a path-scoped rule or a skill, so that the agent checks for existing code before it writes a new helper.

The duplication check and the shared-code map act on the harness, which is the cause. The copies that already exist are the symptom, and the team removes them in the code.

## When not to apply

- Copies that must stay separate: generated clients, schemas, per-platform copies, and boilerplate the framework requires, such as migration files or route registrations.
- Duplication only in tests and fixtures. It is counted apart under `inTests` and does not enter the percentage.
- Generated, minified or vendored files. The scanner excludes them before matching.
- Short repeated lines. Normalization removes braces and imports, and a group needs a window of 8 normalized lines, so short idioms do not form groups.
- A repository where the scanner hit its file or byte caps. The percentage covers only the files it scanned, and the report must say so.

## Examples

Numbers in these examples are illustrative, not measurements.

### Applies: high share (high)

Bad: `duplicatedLinesPct` is 18.4. The largest group is a 40-line error-mapping block copied into four handlers. The memory files describe the build and the test command and say nothing about shared code. Impact is high from the number. COD-04 also applies, because no reuse step exists, and the report shows both findings. Good: add the CI check and the shared-code map from the Recommendation, then check the share again in the next scan.

### Applies: medium share (medium)

Bad: `duplicatedLinesPct` is 7.2. The groups include a 12-line date-parsing block copied into three files. Impact is medium. Good: name the shared folder in memory, so that the next date helper is written there.

### Applies: high share, guidance already in memory (high)

Bad: `duplicatedLinesPct` is 18.4, and `CLAUDE.md` names `src/lib/` for shared helpers and asks the agent to check it before writing a helper. This rule's impact is still high, because it follows the number. COD-04 does not apply, because the reuse step exists, so the report shows only the COD-01 finding. Good: add the CI check. The copies that already exist remain the symptom, and the report says so.

### Does not apply: duplication below the medium level

Good: `duplicatedLinesPct` is 3.1. The largest group is a 9-line setup block in two test files, counted under `inTests`. Below the medium threshold, no finding is raised, and the report states the figure.

### Does not apply: only punctuation lines repeat

Good: the same lines of closing braces and `);` repeat across many functions. Normalization drops punctuation-only lines, so no window of 8 normalized lines forms, and no group is reported.
