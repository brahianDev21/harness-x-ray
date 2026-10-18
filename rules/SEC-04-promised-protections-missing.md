---
id: SEC-04
title: A protection that the text promises is missing or not connected
axis: security
kind: judgment
measuredSupport: [M7, M10, M11, M12]
defaultImpact: medium
sources: [cc-docs-hooks, cc-docs-hooks-events, cc-docs-memory, cc-docs-permissions, atlas-hooks, atlas-security]
evidence: official-docs
since: mvp
status: draft
---

## What it checks

Instruction text (memory, rules, skills and subagent prompts) that says a hook or a permission rule protects something, compared with the controls that the project configures. For a promise about a hook, the reviewer decides whether the hook exists and is connected, whether its script exists, whether the script blocks what the text says, and whether it fails closed. For a promise about a permission, the reviewer decides whether a rule in the project covers the promised action.

A static scan is not a security audit. The scanner reads the hook entries and their script paths; it does not run a hook and does not read what the script does. The reviewer reads the candidate scripts to judge that, and the reading is a judgment, not a measurement.

The boundary with SEC-05 is this. SEC-04 applies when the text claims that a control exists and the claim is false or the control does not work. SEC-05 applies when the text states the rule itself, such as "never push", claims no control, and no control backs it.

## Why it matters

Memory is context, not enforced configuration. The memory documentation says that to block an action regardless of what Claude decides, a PreToolUse hook is the mechanism. A sentence such as "the hook blocks force pushes" tells the team that a protection exists. If no hook is connected, nothing runs, and the team is less careful than it would be without the sentence.

A hook runs only when a settings file connects it. The hook entries in `.claude/settings.json` decide what runs, and a script in a folder does nothing until an entry names it.

A hook fails open unless its handler sets `onFailure` to `"block"`. The hooks documentation says that when a hook fails or times out, the action still proceeds by default. A promised block can therefore fail silently.

A hook on `PostToolUse` cannot stop the tool call, because the tool has already run. A protection described as a block but wired to that event does not block anything.

The `if` field of a hook filters the calls it runs for, using permission rule syntax. The hooks documentation calls it best-effort and says to use the permission system for a hard allow or deny. A hook with an `if` filter protects only the calls that the filter matches.

A permission rule works only on the calls it matches. The permissions documentation says that a deny or ask rule covers the invocation Claude usually writes, not the program, so a sentence such as "a deny rule blocks force pushes" has to be checked against the outcome of the commands that the scanner simulates, not against the sentence.

## How it is detected

This is a judgment rule. The measured support gives the hook inventory; the reviewer reads the text and the candidate scripts.

Inventory:

- `claudeConfig.hooks[]`: one entry per hook handler, with `source` (the settings file that connects it), `event`, `matcher`, `if`, `command`, `script` (`path`, `external`, `exists`), `failsOpen` and `onFailure`.
- `security.destructiveCoverage.preToolUseHooks[]`: the PreToolUse hooks whose matcher covers Bash or PowerShell, with the `tools` they cover.
- `security.permissions.deny[]` and `security.permissions.ask[]`: the rules of the project settings.
- `security.destructiveCoverage.commands[]`: `outcome` and `decidedBy` for each listed destructive command.
- `security.secrets.readProtection.envAtRoot` and `security.secrets.readProtection.preToolUseReadHooks[]`: the decision for a read of a root `.env`, and the hooks that cover `Read`.

For each promise in the memory or rules (a sentence that says a hook or check blocks, stops, guards or protects something):

1. **Find a connected hook.** Is there an entry in `claudeConfig.hooks[]` with `event` `PreToolUse` whose `matcher` covers the tool that the promise names? A hook on another event does not block a tool call. If there is none, the protection is not connected.
2. **Check the script.** `script.exists: false` means the file is missing. `script.external: true` means the path is outside the project, so the scanner did not check it; the report says that the reviewer could not check it.
3. **Read the candidate script,** only the file named by `script.path`, and only to read it. Decide whether its blocking path ends in exit code 2 (or a `deny` decision) for the calls the promise names, and whether its patterns cover them. For example, a script that matches `git push --force` but not `git push -f` does not cover the second form. A script that only logs, or always exits with 0, does not block.
4. **Check the fail mode.** `failsOpen: true` means that a crash or a timeout lets the action proceed.
5. **Check the filter.** When `if` is set, the hook covers only the calls that the filter matches.
6. **For a promise about a permission** ("a deny rule blocks force pushes", "reading .env is denied"), look for a `deny` or `ask` entry in `security.permissions` that covers the promised action. For a listed destructive command, `security.destructiveCoverage.commands[].outcome` settles it: `blocked` with `decidedBy.list` `deny` holds for that form, `asks` is a prompt only, and `passes` means the promise is false. For a `.env` read, `security.secrets.readProtection.envAtRoot.decision` settles it: `deny` holds, while `ask`, `default` or `allow` does not. If no entry covers the action, the promised control is missing.

Decide one of these states for each promise: connected and effective; connected but partial; connected but fails open; not connected; script missing; not checked; for a permission promise, holds, partial or missing. Flag the promise when it is not connected, the script is missing, it is not effective, it fails open, or the permission is missing. The impact is medium, and the report says that it is an opinion.

Template case. A template's README can say that the hooks and permission files must be connected by hand. Take a folder `.agents/hooks/block-dangerous-commands.mjs` with memory that says dangerous commands are blocked. No settings file names that script, so `claudeConfig.hooks[]` has no entry for it. The reviewer reports that the script exists but no settings file runs it, and that the README asks each agent's settings to point to it. The finding is the missing wiring in this repository. It is not a finding that the template is wrong, because the template says what it expects.

## Recommendation

1. **Connect the hook** in `.claude/settings.json`, with a matcher that covers the tool, in the shape shown in SEC-02.
2. **Set `onFailure` to `"block"`** (Claude Code v2.1.295 or later). The hooks documentation says that a PreToolUse failure then blocks the tool call.
3. **Make the script match the promise.** The patterns that the memory names are the patterns the script checks, and the exit path for a block is exit code 2.
4. **Where the protection must hold, use a deny rule as well.** The hooks documentation says the `if` filter is best-effort, so a permission rule is the hard control.
5. **Change the text last.** If the protection cannot be connected, change the sentence to say what is enforced and where, or remove the promise, so that the team does not rely on it.

## When not to apply

- A protection configured outside the project, in user settings, managed settings or a plugin. The scanner reads project settings only, so the reviewer reports it as not visible in the project, not as missing.
- A sentence that states the rule itself, such as "never push", and claims no control. That is SEC-05: this rule checks claims that a control exists, and SEC-05 checks rules that claim none.
- A promise about a check that runs in CI or by hand, outside Claude Code. That is a verification question, not a hook.
- A hook that only prints a reminder, on an event such as `SessionStart`. It makes no claim of protection.
- A protection that the reviewer has read and confirmed: the script blocks the promised calls, the hook fails closed, and it is connected. No finding.

## Examples

Commands and file names in these examples are illustrative, not measurements.

### Applies: text promises a hook that is not connected (medium)

Bad, `CLAUDE.md`: "The hook in `.claude/hooks/guard.mjs` blocks `rm -rf`." The file exists, but `claudeConfig.hooks[]` has no PreToolUse entry that names it, so nothing runs it. Good: connect it in `.claude/settings.json` with a `Bash` matcher and `onFailure: "block"`, and keep the promise.

### Applies: connected hook that fails open with a missing script (medium)

Bad, `.claude/settings.json`: a `PreToolUse` entry with matcher `Bash` and command `node scripts/guard.mjs`, with no `onFailure`. `script.exists` is `false` and `failsOpen` is `true`. The script cannot run, and a failure lets the command proceed, so the promised block never happens. Good: add the script, and set `onFailure` to `"block"`.

### Applies: a template wired by hand (medium)

Bad: the repository has `.agents/hooks/block-dangerous-commands.mjs`, and `CLAUDE.md` says dangerous commands are blocked. No settings entry names the script. The template's README says that each agent's settings must point to the hook. Good: add the PreToolUse entry to `.claude/settings.json` that points to that script, with `onFailure: "block"`.

### Applies: a promised deny with no matching rule (medium)

Bad, `CLAUDE.md`: "A deny rule blocks force pushes." `.claude/settings.json` has no `deny` entry for `git push --force`, and `security.destructiveCoverage.commands[]` shows `outcome: asks` for that command, decided by mode `default`. The promised control is missing: the push asks, and nothing denies it. Good: add `Bash(git push --force *)` to `deny`, as SEC-02 shows.

### Does not apply: connected, blocks and fails closed

Good: `.claude/settings.json` has a PreToolUse entry with matcher `Bash|PowerShell` and `onFailure: "block"`. `script.exists` is `true`. The reviewer reads the script and finds exit code 2 for `rm -rf` and for `git push --force`, the two forms that the text names. The promise is connected and effective. No finding.
