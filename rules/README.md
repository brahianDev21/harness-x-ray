# Rule catalog

Each `.md` file in this folder is one rule that the scanner can report, except this README. Files that are not `.md` are not rules. `scripts/check-catalog.mjs` checks the whole folder; run `npm run check` after every change.

## File names

- `<ID>-<slug>.md`, for example `RUL-01-generic-rules.md`, or `<ID>.md`.
- `<ID>` is an axis prefix, a hyphen and two digits: `RUL`, `CTX`, `SEC`, `VER`, `STR` or `COD`.
- `<slug>` is lowercase words joined by hyphens.
- The `id` in the frontmatter must equal the `<ID>` of the file name.
- Two rule files may not share an id.

## Axes

The axis is the part of the harness the rule is about. Its prefix must match.

| Prefix | Axis | What it looks at |
|---|---|---|
| `RUL` | `instructions` | What the memory and instruction files say, and whether it is correct and enforceable |
| `CTX` | `context` | How much context loads, and when |
| `SEC` | `security` | What the agent can do or reach without a barrier |
| `VER` | `verification` | How a change gets checked |
| `STR` | `structure` | How the repository is laid out for the agent |
| `COD` | `code` | Duplication and reuse in the code itself |

## Frontmatter

Every field is required. An unknown field is an error.

| Field | Allowed values |
|---|---|
| `id` | A rule id, such as `RUL-01` |
| `title` | A non-empty string |
| `axis` | `instructions`, `context`, `security`, `verification`, `structure`, `code` |
| `kind` | `measured` or `judgment` |
| `measuredSupport` | A list, possibly empty, of measure ids such as `[M11, M20]`. Used by judgment rules to cite the measures that support them |
| `defaultImpact` | `high`, `medium` or `low` |
| `sources` | A list, possibly empty, of ids from `sources.json` |
| `evidence` | The strongest type among `sources`, or `common-practice` when `sources` is empty |
| `since` | `mvp`, `v0.2` or `v0.3` |
| `status` | `draft` or `validated` |

## Body sections

The body has these H2 headings, each once, in this order, each with content:

1. `## What it checks`
2. `## Why it matters`
3. `## How it is detected`
4. `## Recommendation`
5. `## When not to apply`
6. `## Examples`

No other H2 is allowed. Headings inside fenced code blocks do not count.

- **Measured rules** (`kind: measured`): `How it is detected` names the JSON field the scanner reads and the threshold that triggers the finding.
- **Judgment rules** (`kind: judgment`): `How it is detected` gives concrete criteria and examples that a reviewer can apply to the files.

## Evidence levels

From strongest to weakest:

| Level | Meaning |
|---|---|
| `study` | A study with data, such as a paper or preprint |
| `benchmark` | A reproducible benchmark, without peer review, by the author or a third party |
| `official-docs` | Documentation from the vendor of the tool |
| `industry-guidance` | Guidance published by a recognized organization |
| `atlas` | A page of the author's knowledge base, Agent Atlas |
| `common-practice` | Widely repeated practice with no evidence behind it. The report says so |

A rule's `evidence` must equal the strongest type among its sources. A rule with no sources must use `common-practice`.

Agent Atlas is the author's own knowledge base, so it cannot be the only proof of a rule. A rule should cite at least one primary source (`study`, `benchmark`, `official-docs` or `industry-guidance`) and may cite Atlas as further reading. This convention is not checked by the script.

## sources.json

`rules/sources.json` is the only place with source titles, URLs and access dates. Rules cite source ids. `data/agent-harness.json` also cites sources by id, and only sources of type `official-docs`.

```json
{
  "sources": [
    {
      "id": "example-docs",
      "title": "Example configuration guide",
      "url": "https://example.com/docs/configuration",
      "type": "official-docs",
      "accessed": "2026-10-17",
      "note": "Section that describes the setting the rule relies on."
    }
  ]
}
```

- Every field is required and is a non-empty string. No other fields are allowed.
- `id`: unique, kebab-case (lowercase letters and digits joined by single hyphens).
- `url`: starts with `https://`.
- `accessed`: a real date in `YYYY-MM-DD` form.
- `type`: one of `study`, `benchmark`, `official-docs`, `industry-guidance`, `atlas`.

## Impact by axis

The impact of a finding is `high`, `medium` or `low`. Measured findings take their impact from the numbers. Judgment findings take it from this table, and the report says that it is an opinion.

X and Y are thresholds in tokens of always-loaded context. They are provisional: calibration sets them, and they are not set yet.

| Axis | High | Medium | Low |
|---|---|---|---|
| instructions | A broken reference in a verification command; a contradiction that leads to running the wrong commands | Rules that a linter, formatter or hook already enforces | Generic rules on their own |
| context | More than X tokens of always-loaded context | Between Y and X tokens; large imports or duplicated text | Below Y tokens |
| security | The agent can cause irreversible damage or expose secrets without anyone confirming: an `allow` that covers a destructive command, `acceptEdits` in the project, versioned secrets or literal secrets in the harness | Only manual confirmation stops it; the protection exists only as text, is not connected, or fails open | Hardening, such as a sandbox or denying reads of credentials outside the repository |
| verification | No documented or configured way to verify a change | A way exists but the instructions do not mention it; very noisy output | Output that could be shorter |
| structure | None | A map is missing in a repository with many folders; generated files are not marked | Conventions that a tool could enforce |
| code | Duplication far above the threshold, with no guidance on reuse | Duplication above the threshold; helpers that reinvent existing ones | Isolated cases |

## Principles

- **Every recommendation is a change to the harness.** It names a permission, hook, tool, setting or memory file to change. Advice about the code alone is not a recommendation.
- **Control before text.** When a permission, hook or tool can enforce a behavior, recommend it before a written instruction. Memory files are context that the model reads, not configuration that is enforced. Blocking an action requires a `PreToolUse` hook or a permission rule.
- **Recommendations that add text cost tokens.** Text loads into every session that matches it. Such recommendations are hypotheses to measure in a controlled test, not proven improvements.

## Checking the catalog

`npm run check` validates the rule files, `sources.json` and the files in `data/`. It exits with 0 when there are no errors, 1 when there are errors and 2 for a usage error. A warning does not fail the check. Each error prints as `<file>: <field>: <message>`, so the file and the field can be found directly.
