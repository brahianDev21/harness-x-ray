---
id: SEC-01
title: Project permissions are broader than the defaults
axis: security
kind: measured
measuredSupport: []
defaultImpact: high
sources: [cc-docs-permissions, cc-docs-permission-modes, cc-docs-permission-modes-protected-paths, cc-docs-sub-agents, cc-docs-security, owasp-llm-excessive-agency, atlas-tool-use-permissions]
evidence: official-docs
since: mvp
status: draft
---

## What it checks

Whether the project's settings files let the agent act without a prompt in ways the defaults do not. The rule looks at four things:

1. An `allow` rule for Bash or PowerShell with a wildcard: `Bash`, `Bash(*)`, or a pattern such as `Bash(git *)`.
2. `defaultMode: acceptEdits` in a project settings file. Claude Code applies that value.
3. A subagent with a shell tool that runs in `acceptEdits`.
4. An `additionalDirectories` entry that is the filesystem root, the home folder or a drive root.

The rule judges what the repository adds to Claude Code's defaults. It does not judge a mode that a person sets for their own sessions.

A static scan is not a security audit. It reads the settings files as text: it does not run a command, and it cannot see user or managed settings, where a person may have set other permissions.

## Why it matters

A permission rule decides which actions run without a prompt. A wildcard `allow` on Bash approves each command that the pattern matches. Bash rules compare the text of the command, not the program. The permissions documentation says that a rule covers the invocation Claude usually writes and is not a security boundary around the program, so a wildcard reaches further than it looks.

`acceptEdits` approves file edits, and the commands `mkdir`, `touch`, `rm`, `rmdir`, `mv`, `cp` and `sed`, for paths inside the working directory and the additional directories. The permission modes page shows the project's `.claude/settings.json` as the place to set a default mode for every terminal session in that project. A project file that sets `acceptEdits` therefore removes the prompt for those commands for everyone who opens the repository.

Claude Code ignores `auto` and `bypassPermissions` when a project settings file sets them. The rule does not count them as permissions. The scanner records them as ignored values.

Subagents have their own tools and permission mode. When the main conversation runs in `acceptEdits`, `auto` or `bypassPermissions`, a subagent runs in that mode and ignores its own `permissionMode` field. A reviewer subagent with Bash therefore takes the approvals of the main session.

Reads inside the working directory and the additional directories need no approval, and `acceptEdits` approves edits there too. A root or home entry is therefore a wide read scope even without `acceptEdits`.

Some paths are protected from auto-approval: writes to `.git`, `.claude`, `.husky`, `.vscode`, `.mcp.json` and `.npmrc`, among others, are never auto-approved except in `bypassPermissions` mode and some plan-mode sessions. An allow rule in a settings file does not pre-approve those writes, so an `allow` entry such as `Edit(.claude/**)` does not change them.

## How it is detected

This is a measured rule. No `THRESHOLDS` key applies: each trigger below is categorical.

Fields the scanner reads:

- `security.permissions.allow[]`, merged from the shared and the local project settings files.
- `security.permissions.additionalDirectories[]`.
- `security.permissions.defaultMode`: `value` and `effect`. The effect is `applies` for `default`, `acceptEdits`, `plan` and `dontAsk`, and `ignored-from-project` for `auto` and `bypassPermissions`. The value comes from the file with the higher precedence, local over shared.
- `security.destructiveCoverage.subagents[]`: `shellTools`, `effectiveMode`, and `ignoredMode` when the subagent's own mode does not apply.
- `security.destructiveCoverage.commands[]` and `security.destructiveCoverage.subagents[].results[]`: `outcome` and `decidedBy`. A `decidedBy` with `kind` `rule`, `list` `allow` and a `rule` naming an allow entry means that entry let the command through. For a compound command, `rule` joins its allow rules with ` && `.

Triggers:

| Trigger | Field | Impact |
|---|---|---|
| A bare allow for `Bash`, `Bash(*)`, `PowerShell` or `PowerShell(*)` | `security.permissions.allow[]` | High |
| A wildcard allow for Bash or PowerShell (a `*` inside the parentheses) that is the `decidedBy` rule of a `passes` outcome in `security.destructiveCoverage.commands[]` or `security.destructiveCoverage.subagents[].results[]`, so it lets a listed destructive command through | `security.destructiveCoverage` | High |
| Any other wildcard allow for Bash or PowerShell, such as `Bash(npm run *)`: broad, but no listed destructive command passes through it | `security.permissions.allow[]` | Medium |
| `defaultMode.value` is `acceptEdits` and `defaultMode.effect` is `applies` | `security.permissions.defaultMode` | High |
| A subagent whose `shellTools` includes `Bash` or `PowerShell` and whose `effectiveMode` is `acceptEdits` | `security.destructiveCoverage.subagents[]` | High |
| An `additionalDirectories` entry that is `/`, `~`, or a drive root such as `C:/` | `security.permissions.additionalDirectories[]` | Medium |

A finding takes the highest impact of the triggers it matches. A repository can match several; the report lists each one with its field.

The destructive list is short. A wildcard can pass a destructive command that the list does not contain; this rule rates such a wildcard medium, because the scanner cannot see that command.

These are not triggers:

- An `allow` entry with no wildcard, such as `Bash(npm test)`.
- A `deny` or `ask` entry. They only narrow what runs.
- A project `defaultMode` of `auto` or `bypassPermissions`. Its effect is `ignored-from-project`, and the report lists the value as ignored.

## Recommendation

Change the settings files, in this order:

1. **Replace wildcard `allow` entries with exact commands,** and put the destructive forms in `ask` or `deny` (SEC-02 lists them):

```json
{
  "permissions": {
    "allow": ["Bash(npm test)", "Bash(npm run lint)"],
    "ask": ["Bash(git push *)"],
    "deny": ["Bash(git push --force *)"]
  }
}
```

2. **Remove `"defaultMode": "acceptEdits"` from the shared `.claude/settings.json`.** Each person can switch modes for their own sessions with Shift+Tab.

3. **In a subagent file, remove `Bash` from `tools`** when the subagent does not need it. Changing its `permissionMode` does not help while the main conversation runs in `acceptEdits`, because the subagent ignores its own mode there.

4. **Narrow `additionalDirectories`** to the folders the work needs.

## When not to apply

- An `allow` entry with an exact command or script, such as `Bash(npm run build)`.
- A project `defaultMode` of `auto` or `bypassPermissions`. Claude Code ignores it, so it does not change what runs. The report records it as ignored.
- A subagent with `Bash` whose own `permissionMode` is `default`, in a project whose main mode is `default`. Its own mode applies, so it does not run in `acceptEdits`.
- A team that wants `acceptEdits` on purpose. The rule states what the setting lets through; it does not decide whether the team should accept that. The report says so.
- Permissions that a person sets in user settings or managed settings. The scanner does not read them.

## Examples

Commands and folders in these examples are illustrative, not measurements.

### Applies: wildcard Bash allow (high)

Bad, `.claude/settings.json`:

```json
{
  "permissions": {
    "allow": ["Bash(git *)"]
  }
}
```

The entry is a wildcard, and `git push --force` is decided by it with outcome `passes`, so the finding is high. SEC-02 reports the command. Good: list the commands the team runs, as in the Recommendation.

### Applies: a broad wildcard that passes no listed command (medium)

Bad, `.claude/settings.json`:

```json
{
  "permissions": {
    "allow": ["Bash(npm run *)"]
  }
}
```

The entry is a wildcard, but no listed destructive command passes through it: `npm publish` is not matched by `Bash(npm run *)`. The finding is medium. Any package script runs without a prompt, which is broader than the team needs. Good: narrow the entry to the scripts the team runs, such as `Bash(npm run lint)`.

### Applies: acceptEdits in the project (high)

Bad, `.claude/settings.json`:

```json
{
  "permissions": {
    "defaultMode": "acceptEdits"
  }
}
```

The effect is `applies`. Inside the project, `rm -rf build` and `mv` run without a prompt for everyone who opens the repository. Good: remove the line, and let each person choose the mode for their own session.

### Applies: reviewer subagent under acceptEdits (high)

Bad: the project sets `acceptEdits` as above, and `.claude/agents/reviewer.md` lists `tools: Read, Bash` with `permissionMode: default`. The scanner shows `effectiveMode: acceptEdits` and `ignoredMode: default` for the reviewer. Its own mode does not apply, so its Bash commands follow the main session's approvals. Good: remove `Bash` from its tools, or remove `acceptEdits` from the project.

### Does not apply: exact commands in default mode

Good, `.claude/settings.json`:

```json
{
  "permissions": {
    "allow": ["Bash(npm test)", "Bash(npm run lint)"],
    "defaultMode": "default"
  }
}
```

There is no wildcard and the mode is `default`. No trigger.

### Does not apply: a mode that a project file cannot set

Good, `.claude/settings.json` sets `"defaultMode": "bypassPermissions"`. Claude Code ignores that value in a project file, so the effect is `ignored-from-project`. The report lists it as an ignored value, not as a finding of this rule.
