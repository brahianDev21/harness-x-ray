---
id: STR-02
title: Generated, large or vendored files are not protected
axis: structure
kind: measured
measuredSupport: []
defaultImpact: medium
sources: [cc-docs-permissions, cc-docs-permission-modes, cc-docs-tools-reference, cc-docs-memory]
evidence: official-docs
since: mvp
status: draft
---

## What it checks

Whether files that people do not write by hand are left open to the agent. The scanner builds two lists of versioned files:

- **Generated files:** files that match a generated-file pattern, such as `dist/`, `build/`, `coverage/`, `vendor/`, `*.min.js` or `*.map`.
- **Large files:** files above a size threshold.

Lockfiles are excluded from both lists. The package manager writes them, and an agent often has to change them through it.

A file is unprotected when no `deny` rule for `Read` or `Edit` covers it and no instruction file marks it "do not touch".

## Why it matters

A generated file is overwritten by the next build, so an edit to it is lost, and the diff it creates is noise for the reviewer. A vendored copy of another project drifts from its source once someone edits it. A large file is expensive to read whole. The Read tool refuses a whole-file read above 256 KB and asks for a range with `offset` and `limit`, so an agent that reads such a file in pieces spends several calls on it.

Instruction files are not a control. Claude Code's memory documentation says CLAUDE.md content is context, not enforced configuration. A line that says "do not edit `dist/`" is a request the agent may not follow. A deny rule in the settings is enforced in every session. The permission modes documentation says deny rules apply in every mode, including `bypassPermissions`.

## How it is detected

This is a measured rule. The findings come from these fields:

- `structure.generatedFiles[]`: versioned files that match a pattern from `data/generated-patterns.json`, with lockfiles excluded.
- `structure.largeFiles[]`: versioned files larger than `THRESHOLDS.largeFileBytes`, with lockfiles excluded.

Each entry has its path and size. The scanner also sets two flags, which are described here in words because their final names are not fixed yet:

- whether an instruction file marks the path or its folder "do not touch", with the sentence that does so;
- whether a `Read` or `Edit` deny rule covers the path.

`security.permissions.deny[]` gives the deny entries, merged from the shared and the local settings. A rule covers a path when its pattern matches the path under gitignore syntax.

### Thresholds

| Key | Value | Meaning |
|---|---|---|
| `THRESHOLDS.largeFileBytes` | 262,144 bytes (256 KB) | Size of a versioned file above which it counts as large |

Derivation: the Read tool refuses a whole-file read above 256 KB, so a file of that size cannot be read in one call. The value is taken from that limit. It is an assumption, not a measurement on real repositories, and it stays provisional until calibration on Agent Atlas and on a repository with generated files.

The generated-file patterns are a list, not a threshold, so they have no `THRESHOLDS` key.

### Finding and impact

Raise a finding for each listed file that has neither a deny rule nor a "do not touch" mark.

- **Medium:** a file in `generatedFiles`, including a large file that also matches a generated pattern. This follows the impact table: generated files that are not marked.
- **Low:** a large file that matches no generated pattern. Size alone does not make a file generated, so the finding is weaker. The impact table has no row for this case, so low is a proposal.

A file that memory marks but no deny covers is not a finding of this rule, because the mark is text. The report may say that a deny would add a control.

## Recommendation

Put the control first, then the text.

1. **Add `Read` and `Edit` deny rules for the paths.** A `Read` deny also blocks the Edit and Write tools on the same path, including creating a new file there. The `Edit` deny is still needed for NotebookEdit, which the `Read` deny does not cover. The `Read` deny also keeps whole-file reads of large files out of the context. Claude Code v2.1.208 or later is needed for the edit check, and v2.1.228 or later for the write check.

```json
{
  "permissions": {
    "deny": [
      "Read(./dist/**)",
      "Edit(./dist/**)",
      "Read(./vendor/**)",
      "Edit(./vendor/**)",
      "Read(**/*.min.js)",
      "Edit(**/*.min.js)"
    ]
  }
}
```

Put the rules in the shared `.claude/settings.json`, so that every session in the repository gets them. Only list the paths the repository actually has.

2. **Then add a memory line that names the right command.** A line such as "`dist/` is build output; regenerate it with `npm run build`" tells the agent how to get a change into the output, which the deny does not do. The line adds text to every session, so treat it as a small hypothesis, not a fix.

3. **Know what these rules do not stop.** Bash rules match command text. The permissions documentation says a Bash rule is not a security boundary around the program. A build step that rewrites `dist/` through Bash is not stopped by these deny rules. A shell redirect such as `> dist/app.js` is checked against the `Edit` rules, but a tool that writes the file itself is not.

4. **Lockfiles are not part of this rule.** If the team wants the agent kept away from them, that is a separate permission decision.

## When not to apply

- A file that matches a generated pattern but that the team edits by hand on purpose, such as a hand-maintained script in a folder named `build/`. A deny would block the work the team wants.
- Lockfiles, which are excluded from both lists.
- A file that memory marks "do not touch" but that no deny covers. The mark is text, and this rule does not flag it.
- A large data file that the agent must edit as part of its work. Denying `Edit` would block that work. The finding is low by definition, and the report should say that the file may need to stay editable.

## Examples

Paths and sizes in these examples are illustrative, not measurements.

### Applies: committed build output, unmarked and unprotected (medium)

Bad: `dist/main.js` is 1.3 MB and tracked in git. `CLAUDE.md` does not mention it, and `.claude/settings.json` has no deny rule for it. The file is in `generatedFiles` and no rule covers it. Good: add the `Read` and `Edit` denies from the Recommendation, then the memory line.

### Applies: vendored code (medium)

Bad: `vendor/parser/index.js` is a 300 KB copy of an upstream library. Memory does not mention it, and no deny covers it. Good: deny `Read` and `Edit` on `./vendor/**`. If the team refreshes the copy with a script, say so in one memory line.

### Applies: large data file with no generated pattern (low)

Bad: `data/countries.json` is 410 KB, versioned, and neither marked nor denied. It matches no generated pattern, so it appears in `largeFiles` only, and the finding is low. Good: decide whether the agent should edit it. If not, deny `Read` and `Edit`. If yes, leave it, and the report records that the file is editable on purpose.

### Does not apply: already denied

Good: `dist/main.js` is in `generatedFiles`, and `.claude/settings.json` denies `Read(./dist/**)` and `Edit(./dist/**)`. A deny covers it. No finding.

### Does not apply: lockfile

Good: `package-lock.json` is 900 KB and written by npm. It is excluded from both lists. No finding.

### Does not apply: marked in memory, no deny

Good: `CLAUDE.md` says "do not edit anything in `coverage/`", and no deny rule exists. The mark is text, so the rule does not flag the file. The report may say that a deny would add a control.
