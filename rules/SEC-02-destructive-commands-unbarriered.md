---
id: SEC-02
title: Destructive commands pass or depend only on manual confirmation
axis: security
kind: measured
measuredSupport: []
defaultImpact: high
sources: [cc-docs-permissions, cc-docs-permission-modes, cc-docs-permission-modes-classifier-boundaries, cc-docs-permission-modes-critical-paths, cc-docs-hooks, cc-docs-security, cc-docs-sandboxing, owasp-llm-excessive-agency, atlas-safe-agent-execution, atlas-security]
evidence: official-docs
since: mvp
status: draft
---

## What it checks

For each destructive command in the scanner's list, what the project's rules, mode and PreToolUse hooks would do with it. The list includes `rm -rf`, `git push --force`, `git push -f`, `git reset --hard`, `git clean -fdx`, `git checkout -- .`, `git restore .`, `git branch -D`, `curl ... | sh`, `wget ... | bash`, `chmod -R 777`, `npm publish`, `docker system prune -af`, and the PowerShell and cmd removals of a folder (`Remove-Item -Recurse -Force`, `rd /s /q`, `del /s /q`). Each command gets one outcome: `blocked`, `asks`, `passes` or `undeterminable`.

The rule also checks the same commands inside each subagent that has a shell tool.

A static scan is not a security audit. It simulates the rules and the modes; it does not run any command or any hook, so it cannot tell whether a hook script really blocks what it claims. The reviewer checks that by reading the script (SEC-04).

## Why it matters

Destructive commands are hard or impossible to undo. A force push rewrites shared history, `git reset --hard` and `git clean` discard uncommitted work, and `npm publish` releases a package. Whether the project is safe then depends on a barrier, and the rule asks which barrier exists.

The cited permission-mode notes do not list the commands that the classifier of `auto` mode blocks, so this rule names none. They say that a deny rule is the hard guarantee, and that it applies in every mode, including `bypassPermissions`. The built-in protection that holds even in modes that skip other prompts is the critical-path rule: an allow rule or an allow hook never approves `rm` or `rmdir` on the filesystem root, the home directory or the working directory, and a matching deny rule still blocks them. A removal inside a project folder such as `build` is not a critical path.

Rules compare text. The permissions page says a deny or ask rule covers the invocation Claude usually writes, not the program, so another form of the same command can pass.

The cited notes do not say which mode a session starts in, and a person can change the mode. The scanner does not see the mode that a person has chosen, so its outcomes assume the project's `defaultMode`, or `default` when the project sets none. A session may start in another mode; that is not verified against the documentation. The matrix in "How it is detected" shows the outcome of each command in each mode, as context.

## How it is detected

This is a measured rule. No `THRESHOLDS` key applies.

Fields the scanner reads:

- `security.destructiveCoverage.commands[]`: `tool`; `outcome`; `decidedBy`, which is `{ kind: "rule", list, rule }`, `{ kind: "mode", mode }` with an optional `ignoredMode`, or `{ kind: "critical-path" }`; `reason`; and `preToolUseHook`, which is `runs`, `none` or `undeterminable`.
- `security.destructiveCoverage.commands[].builtInProtection` and `criticalPath`, copied from the data file. The data marks `rm` with `critical-path-removal`, the PowerShell removal with `remove-item-system-paths`, and the cmd removals with `cmd-system-path-removal`. The scanner simulates the critical-path rule for `rm` and `rmdir` only, and applies it when `criticalPath` is `true`. The PowerShell and cmd marks describe protection of system paths, which the examples do not target, so they do not change an outcome here.
- `security.destructiveCoverage.subagents[].results[]`: the `outcome` of each shell command a subagent can run.
- `security.destructiveCoverage.preToolUseHooks[]`: `failsOpen`, `onFailure` and `tools` for each PreToolUse hook that covers Bash or PowerShell. `tools` is the list of the shell tools that the matcher covers, or `undeterminable`.

The matrix is context, not a trigger: no row of the table below reads it, and it does not change `outcome`.

- `security.destructiveCoverage.commands[].modes`: the outcome of the command in a session started in each mode. The keys are `default`, `acceptEdits`, `auto` and `bypassPermissions`. `measurements.json` writes them sorted, because `writeStableJson` sorts object keys; only the report uses the order of `security.destructiveCoverage.matrixModes`. Each value is `passes`, `asks`, `blocked`, `classifier` or `undeterminable`. `dontAsk` and `plan` are not in the matrix, and hooks are not used in it.
- A deny rule gives `blocked` in every mode, as the cited notes state, `bypassPermissions` included. An ask rule gives `asks`, and an allow rule gives `passes`, with the critical-path gate. The matrix applies both in every mode, but for `auto` and `bypassPermissions` that is not verified against the documentation. Without a rule, `default` gives `asks`, `acceptEdits` gives its own result (`passes` or `asks`, and `undeterminable` for a command the scan cannot settle), `auto` gives `classifier`, and `bypassPermissions` gives `passes`, except that a removal (`rm` or `rmdir`) gives `undeterminable` unless its `criticalPath` is `false`. A compound command without `parts`, or a read-only command, with no rule is `undeterminable` in every mode. A compound command with `parts` (for example `curl ... | sh`) follows its mode like any other command. The PowerShell cmdlets that the matrix also approves under `acceptEdits` (`Set-Content`, `Add-Content`, `Clear-Content`, `Remove-Item`) are not in the cited note and are pending verification.
- `classifier` means that a model classifier decides. The scan does not simulate that decision and writes no result for it.

If a session starts in `auto`, a model classifier decides the commands that `default` would ask for (`classifier` in `commands[].modes.auto`), and the scan does not simulate it. The medium row below would then describe a barrier that the session may not use. The row keeps assuming `default` until the starting mode is verified, and the report says that the mode was assumed.

Triggers:

| Finding | Trigger | Impact |
|---|---|---|
| Any command or subagent result with `outcome: passes` | `commands[].outcome`, `subagents[].results[].outcome` | High |
| No command passes, and a command has `outcome: asks` with `decidedBy.kind` `mode` and `mode` `default` (with or without `ignoredMode`), and its `preToolUseHook` is `none` | `commands[]` | Medium |
| No command passes, and a PreToolUse hook that covers a command has `failsOpen: true` | `preToolUseHooks[].failsOpen` | Medium |
| `hook-not-verified`: no command passes, and a command has `outcome: asks` with `decidedBy.kind` `mode` and `mode` `default` (with or without `ignoredMode`), its `preToolUseHook` is `runs`, at least one PreToolUse hook has a `tools` list that includes the command's `tool`, and none of those hooks has `failsOpen: true` | `commands[].outcome`, `commands[].tool`, `commands[].decidedBy`, `commands[].preToolUseHook`, `preToolUseHooks[].tools`, `preToolUseHooks[].failsOpen` | Low |
| Otherwise: the command is `blocked`, is decided by an `ask` or `deny` rule, by the critical-path rule or by a mode other than `default`, or its outcome or PreToolUse hook state is `undeterminable` | `commands[]` | No finding |

A hook covers a command when its `tools` list includes the command's tool. The `if` field of a hook does not narrow coverage in either row: a hook covers a tool through its matcher alone, so a covering fail-open hook gives medium even when its `if` would not select the command. That is the conservative reading. A hook whose `tools` is `undeterminable` is not counted as covering. Its matcher cannot be settled, so it does not make the low row. A failing-open one is listed as undeterminable, and it gives no finding. A command with an `ask` or `deny` rule that covers it is not part of the default-mode rows: the project has written a control for it. A fail-closed hook that runs for the command lowers the level from medium to low. A covering hook that fails open stays medium, as the `hook-fails-open` row. Medium means that the only barrier is the confirmation the mode asks for. The impact is an opinion of the rule, not a measurement of how often a prompt is skipped. An `undeterminable` outcome is listed with its `reason`, and it is not a finding.

The impact of this row is low, although the low row of the impact table in `rules/README.md` is for hardening. The hook runs for the command (its matcher and `if` select it) and fails closed, but the scan cannot tell whether it blocks the command; the simulated outcome stays `asks` by the mode. The row therefore asks the agent to read the script. For each covering hook whose script is a `hook-script` candidate (inside the target; a script outside it is not a candidate), the agent reads the file and says in the finding whether the script blocks the destructive commands of the scan, and which ones. The reading does not change the impact, which stays the measured one: low.

## Recommendation

Put the control in this order: rules first, then a hook, then the fail-closed setting, then hardening.

1. **Rules.** Put a destructive form in `deny` when the team never needs it, and in `ask` when a person may need it. Rules match text, so write the forms the team actually uses:

```json
{
  "permissions": {
    "deny": ["Bash(git push --force *)", "Bash(git push -f *)", "Bash(git reset --hard *)", "Bash(npm publish *)"],
    "ask": ["Bash(rm -rf *)", "Bash(git clean *)", "Bash(git push *)"]
  }
}
```

`Bash(git clean *)` also matches `git clean -n`, a dry run; narrow it if the team uses that.

2. **A PreToolUse hook on Bash and PowerShell.** The hook receives the call as JSON input and exits with code 2 to block it. The Atlas `security` template is a reference for this shape: its hook `block-dangerous-commands.mjs` blocks recursive deletion, force pushes, hard resets and forced cleans. Its list is the team's choice, not a copy to adopt unchanged. Connect it in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "command": "node",
            "args": ["${CLAUDE_PROJECT_DIR}/.claude/hooks/block-dangerous-commands.mjs"],
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

A hook that only logs the call, or that exits with code 0 in every case, does not block it.

3. **`onFailure: "block"`** in that hook, which needs Claude Code v2.1.295 or later. Without it, a hook that crashes, times out or exits with another code lets the command run.

4. **Remove `acceptEdits` from the project settings** (SEC-01), so that `rm` inside the project asks.

5. **Hardening, where the sandbox runs.** On macOS, Linux and WSL2, setting `sandbox.enabled` to `true` runs shell commands inside an operating-system boundary. The sandbox is off by default and does not run on native Windows, where WSL2 is the way to use it.

## When not to apply

- The person runs in `auto` mode. A model classifier decides the commands that the default mode would ask for. The scanner does not simulate it, and the matrix shows `classifier` for them. The finding still describes the project settings, and the report says that the mode was assumed.
- The outcome is `undeterminable`, for example because of a wrapper, an alias, a quote character or a compound command the scanner cannot split. The rule does not guess; it lists the outcome and its reason.
- A command that is not in the scanner's list. The list has examples, so a command missing from it is not measured.
- A command with an `ask` or `deny` rule that covers it. The project has a control for it. A hook that runs and fails closed does not end the check: that case is the low row, and the finding says what the hook covers.

## Examples

Commands and settings in these examples are illustrative, not measurements.

### Applies: an allow rule lets a force push pass (high)

Bad, `.claude/settings.json`:

```json
{
  "permissions": {
    "allow": ["Bash(git *)"]
  }
}
```

`git push --force` has outcome `passes`, decided by an `allow` rule. Good: allow the commands the team runs, such as `Bash(git status)` and `Bash(git diff *)`, and deny the force push.

### Applies: acceptEdits lets rm pass inside the project (high)

Bad: the project sets `"defaultMode": "acceptEdits"`. `rm -rf build` has outcome `passes`, decided by mode `acceptEdits`. The critical-path rule does not apply, because `build` is not the root, the home directory or the working directory. Good: remove `acceptEdits` from the project, and put `Bash(rm -rf *)` in `ask`.

### Applies: only the confirmation prompt is left (medium)

Bad: no `deny`, `ask` or hook in the project, and no `defaultMode`. Every command has outcome `asks` decided by mode `default`, and `preToolUseHook` is `none`. No command passes, so the finding is medium: the only barrier is the prompt. Good: add the `deny` and `ask` rules and the hook above with `onFailure: "block"`. The medium finding goes away. A command that still asks behind the hook alone gives the low finding of the next example.

### Applies, low: a hook runs, but nothing shows that it blocks the command

Bad: the project has the hook above with `onFailure: "block"`, and no `deny`, `ask` or `defaultMode`. `rm -rf build` asks by the default mode, its `preToolUseHook` is `runs` and the hook has `failsOpen: false`. No command passes, so the finding is low, not medium. The agent reads the hook script and says in the finding whether it blocks `rm -rf`; the impact stays low either way, because the scan did not run the script. Good: put `Bash(rm -rf *)` in `ask` or `deny`, as the rules above do. Then the command has a rule and no finding.

### Does not apply: each command is blocked by a rule

Good: the project has a `deny` rule for every command of the list, so each one is `blocked`. No command asks or passes, so the hook does not matter. No finding.
