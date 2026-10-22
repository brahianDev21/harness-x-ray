---
id: STR-03
title: Architecture rules that exist only as text
axis: structure
kind: judgment
measuredSupport: [M17, M19]
defaultImpact: low
sources: [cc-docs-memory, cc-docs-best-practices, cc-docs-hooks-events, cc-docs-hooks, atlas-hooks]
evidence: official-docs
since: v0.2
status: draft
---

## What it checks

Rules about dependencies between layers or folders, written in the instruction files, that no tool in the repository enforces, although a known tool could. Examples: "controllers must not import repositories", "nothing in `src/domain/` imports from `src/ui/`", "only `app.ts` wires the routes". The line can sit in `CLAUDE.md`, `AGENTS.md`, a rule file, or the root instruction file of another agent, such as `.cursorrules`.

This rule is the inverse of RUL-02:

- RUL-02 is a rule written as text that a tool already enforces. The text is a duplicate.
- STR-03 is a dependency rule between layers or folders that no tool enforces, although a known tool could. The text is the only control.
- SEC-05 covers security rules that no control backs; a security rule that a tool enforces is RUL-02, and a security rule is never STR-03. This holds even when the security rule names a folder.
- One line can hold both cases. In a layer table, the parts that a dependency checker enforces are RUL-02, and the parts that it does not are STR-03.

## Why it matters

Claude Code's memory documentation says that CLAUDE.md content is context, not enforced configuration. A layering rule written as text is a request that the model may not follow in every edit. The best-practices page asks to give Claude a check it can run, such as a linter, so that it can verify its own changes. A dependency rule is a check that a tool can run: a forbidden import fails the check instead of depending on the model's attention.

Hooks are the documented way to make a step happen every time. A hook on `PostToolUse` runs after an edit succeeds, so it can run the dependency check on each change and show the agent a failure; it cannot stop the edit. A `PreToolUse` hook can block a tool call, but a dependency rule is about the code after the edit, so the check usually runs after it.

## How it is detected

This is a judgment rule. The measured support gives the tools; the reviewer reads the lines.

- `structure.enforcementTools` (measure M19) lists the tools that the repository configures. The architecture tools are `dependency-cruiser` (a `.dependency-cruiser.*` config), `eslint-plugin-boundaries` (a `package.json` that lists it as a dependency), `import-linter` (a `.importlinter` file, or an import-linter section in `pyproject.toml` or `setup.cfg`) and `archunit` (ArchUnit in `pom.xml`, `build.gradle` or `build.gradle.kts`). ESLint can also hold import restrictions, in its own config (for example the `no-restricted-imports` rule).
- Only the configs and manifests at the root are found, or with `--scope` those of the inherited folders, the scope folders and the listed packages. A tool configured only in a subproject, such as `packages/api/package.json`, is not listed: open the subproject's manifest and config before flagging a rule about its folders.
- The folder tree and the map coverage (`structure.tree`, `structure.mapCoverage`, measure M17) show the folders that the rules name. With a layer plan from `map.mjs`, `layers.json` shows the layers.
- `candidates` of kind `memory-file` and `agent-instructions` list STR-03 among their `rules`. Read the instruction files there.

Flag a line when all of these hold:

1. The line states a dependency rule between layers or folders: which folder may import or call which, or which module is the only entry point. A naming convention or a style rule is not one.
2. No tool enforces that rule for the folders it names. A tool in `structure.enforcementTools` is a lead, not proof: the scan finds it by a file name or a marker, which can also sit in a comment. Open its config and compare its rules with the line; for ArchUnit the rules are Java or Kotlin test classes, so open those. A tool that is configured but has no rule for those folders does not cover the line.
3. A known tool could enforce it for the language of those folders: dependency-cruiser or eslint-plugin-boundaries for JavaScript and TypeScript, import-linter for Python, ArchUnit for Java and Kotlin.
4. The line is not a security rule. That is SEC-05.

When a line is partly covered, flag only the part that no tool enforces, and cite RUL-02 for the rest. The impact is low, as the impact table gives for conventions that a tool could enforce, and the report says that it is an opinion.

## Recommendation

1. **Add the rule to the tool.** Write the dependency rule in the tool the repository already has, or add one: a `forbidden` rule in `.dependency-cruiser.cjs`, an element rule in eslint-plugin-boundaries, a contract in import-linter, or an ArchUnit test.
2. **Make the check reach the agent.** Run it in the verification command that the instructions name, or in a `PostToolUse` hook for file edits, so the agent sees a failure while it works. A check that runs only in CI does not show the agent its output.
3. **Then shorten the line.** Once the tool enforces it, the line is RUL-02: keep the reason, and drop the rule that the tool now checks.

A new tool rule changes the repository's checks, not only its text, so run it once on the current code before you rely on it: existing code may already break it.

## When not to apply

- A tool already enforces the rule for those folders. That is RUL-02.
- A security rule, such as "never read `.env` files" or "do not call the payments API from tests". That is SEC-05.
- A rule that no known tool can express, such as "keep controllers thin". It is a convention, not a dependency rule.
- A language for which the reviewer knows no dependency checker. The rule needs a tool that could enforce it.
- A rule about a folder that does not exist. That is RUL-04.

## Examples

File names and rules in these examples are illustrative, not measurements.

### Applies: part of a layer table that the dependency checker leaves out (low)

`AGENTS.md` has a layer table that says controllers may not import repositories or `app.ts`. `.dependency-cruiser.cjs` forbids controllers importing repositories, and has no rule for `app.ts`. The first part is RUL-02. The part about `app.ts` is STR-03: dependency-cruiser could forbid it with one more rule. Good: add a `forbidden` rule from `src/controllers` to `src/app.ts`, keep it in the `check:architecture` command, and shorten the table to the reason.

### Applies: a Python layering rule with no import contract (low)

`CLAUDE.md` says "Nothing in `app/domain/` imports from `app/api/`." The repository has no import-linter configuration. Good: add an import-linter contract for the two packages, run `lint-imports` in the verification command, and keep the reason in `CLAUDE.md`.

### Does not apply: the rule is enforced

`CLAUDE.md` says "Repositories never import services." `.dependency-cruiser.cjs` has a `forbidden` rule from `src/repositories` to `src/services`, and `npm run verify` runs it. That is RUL-02, not STR-03.
