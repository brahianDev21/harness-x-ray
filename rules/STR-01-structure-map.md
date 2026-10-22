---
id: STR-01
title: No map of where things live in the repository
axis: structure
kind: judgment
measuredSupport: [M17]
defaultImpact: medium
sources: [cc-docs-memory, cc-docs-memory-layers, cc-docs-memory-loading, atlas-context-engineering]
evidence: official-docs
since: mvp
status: draft
---

## What it checks

Whether the instruction files tell the agent where things live in the repository. A useful map says which first-level folder holds which kind of code or content, where a new file of each kind goes, which naming conventions apply, and which folders are not to be touched.

The rule fires when the repository has several first-level folders with different roles and the instruction files say little or nothing about them. It does not judge the folder layout itself. A layout that the names already explain needs no map.

## Why it matters

An agent that does not know where a kind of file belongs has to guess. A guess often creates a new folder, or puts a helper next to the code that calls it when it belongs in a shared folder. A reviewer then moves the file by hand.

Claude Code's memory documentation lists project architecture among the things a project CLAUDE.md is for. The same page says that CLAUDE.md files are context, not enforced configuration, and that more specific and concise instructions are followed more consistently. A map helps when it is short and says things the folder names do not.

The documentation also argues against a long map. Its `/doctor` checkup for a checked-in CLAUDE.md proposes trims that remove directory layouts and architecture overviews Claude can derive from the codebase. A tree copied into memory is loaded in every session, costs tokens each time, and goes stale when a folder is renamed.

## How it is detected

This is a judgment rule. The measure gives the counts, and the reviewer reads the instruction files to decide whether the map exists.

Fields:

- `structure.tree`: the first two levels of folders, with their file counts.
- `structure.mapCoverage`: how many first-level folders exist, and which of them the memory mentions.
- `inventory[]`: the entries with `kind: "memory"`, with their `loadMode`. These are the instruction files to read. A nested file with `loadMode: "on-demand"` loads when Claude works in its folder, and it counts as part of the map.

Flag the repository when these criteria hold:

1. **Several roles.** Several first-level folders hold different kinds of things, such as application code, tests, scripts, data, build tools and documentation. Folders that hold only generated output, and dotfolders, do not count.
2. **No mapping.** For most of those folders, no instruction file says what the folder holds or where a new file goes. A folder name in a list does not count. The sentence must add something the name does not say.
3. **The names do not explain it.** A new reader could not work out the placement from the names alone.

Impact: medium when criteria 1 and 2 hold for many first-level folders. Low when they hold for only a few. The impact table has no row for the low case, so low is a proposal.

A memory file that pastes a full directory tree is also flagged. The map is there, but the tree costs tokens in every session and goes stale. Its impact is low, and the recommendation is to replace the tree with a few lines per folder.

With a scope (the `scope` section of measurements.json is present), the tree and the map are relative to the scope folders: `structure.tree` lists the first two folder levels below each scope folder, by full path, and `structure.mapCoverage` counts the first-level folders below each scope folder. The memory files of the root, of the inherited folders and of the scope count as mapping: a root line that names `apps/web/src/` maps that folder, and so does `apps/web/CLAUDE.md` when it names `src/`. Folders outside the scope are not judged.

## Recommendation

Each change below edits a memory file, which is a harness change. Take them in this order.

1. **Put part-specific conventions in path-scoped rules.** A file in `.claude/rules/` whose `paths` field lists a folder loads only when Claude reads, writes or edits a matching file. The memory documentation says that rules without `paths` load at launch and that path-scoped rules load only with matching files. A convention for one folder belongs in such a rule, not in the project CLAUDE.md:

```markdown
---
paths:
  - "apps/api/**"
---

- Each handler file exports one route. Shared request types come from `packages/shared/`.
```

2. **Keep the general map in the project CLAUDE.md, a few lines per first-level folder.** For each folder, say what it holds, where a new file of that kind goes, and whether it is off limits. Write only what the name does not say. Files in subdirectories load on demand, so a large workspace can keep its own map in its own folder.

3. **Do not paste a directory tree.** The tree can be derived from the repository, it goes stale, and it costs tokens in every session.

4. **A convention that a tool can check is a control, not text.** An import restriction between folders is better enforced by a tool than described in memory. That is a separate recommendation, for a rule about conventions a tool could enforce, which is not written yet.

Step 2 adds text, and the text loads into every session that matches it. A map is therefore a hypothesis, not a proven improvement. Measure it in a controlled test: run the same tasks with and without the map, and compare where new files are created, how many files the agent opens before its first edit, and the tokens used. Path-scoped rules cost less, because they load only when they apply, but the same test applies to them.

## When not to apply

- A repository with few first-level folders whose names say what they hold, for example `src/` and `test/`, where the tests mirror the source. Criterion 3 fails.
- A repository whose instruction files already map the folders, even briefly. Criterion 2 fails.
- A monorepo whose workspaces each have a nested `CLAUDE.md` that maps them. The mapping exists, and it loads when Claude works in that workspace. The root file only needs to point to the workspaces.
- A convention that a tool already enforces. The missing piece is the tool, which another rule covers.

## Examples

Folder names and line counts in these examples are illustrative, not measurements.

### Applies: several roles, no mapping (medium)

Bad: a repository with `apps/web/`, `apps/api/`, `packages/shared/`, `infra/`, `scripts/` and `docs/`. The root `CLAUDE.md` says only "Run `npm test` before reporting a change as done." The agent cannot tell where a new shared type belongs, or whether `infra/` is safe to edit. The finding is medium because six folders with different roles are unmapped.

Good: the same file with a short map:

```markdown
## Layout
- `apps/web/`: the React front end. New pages go in `apps/web/src/pages/`.
- `apps/api/`: HTTP handlers. Shared types come from `packages/shared/`.
- `packages/shared/`: types and validation used by both apps. Do not import from `apps/` into it.
- `infra/`: deployment files. Do not edit by hand; the pipeline generates them.
- `scripts/`: Node scripts run by `npm run`. Keep them dependency-free.
```

Each line says something the folder names do not.

### Applies: a few unclear folders (low)

Bad: a repository with `src/`, `tests/`, `data/`, `tools/` and `vendor/`, and a `CLAUDE.md` that says nothing about any folder. The names of `tools/` and `vendor/` do not say whether `tools/` runs at build time or whether `vendor/` holds copies of other code. Only two folders are unclear, so the impact is low.

Good: two lines that map `tools/` and `vendor/`.

### Applies: a tree pasted into memory (low)

Bad: `CLAUDE.md` contains a 140-line output of `tree`. The map is complete, but it is loaded in every session, goes stale when a folder is renamed, and says nothing about the role of any folder.

Good: replace the tree with a few lines per folder, as in the first example.

### Does not apply: a small repository with clear names

Good: a repository with `src/` and `test/`, where `test/` mirrors `src/`, and a `CLAUDE.md` that gives only the test command. Criteria 1 and 3 fail, because the names already explain the layout. No finding.

### Does not apply: the workspaces map themselves

Good: a monorepo with `apps/web/CLAUDE.md` and `apps/api/CLAUDE.md`, each describing its own folder, and a root `CLAUDE.md` that lists the two workspaces in one line. The mapping exists, and the nested files load when Claude works in each workspace. No finding.
