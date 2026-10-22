---
id: SEC-05
title: Security rules exist only as text
axis: security
kind: judgment
measuredSupport: [M7, M10]
defaultImpact: medium
sources: [cc-docs-memory, cc-docs-permission-modes, cc-docs-permission-modes-classifier-boundaries, cc-docs-permissions, atlas-safe-agent-execution, owasp-llm-excessive-agency]
evidence: official-docs
since: mvp
status: draft
---

## What it checks

Security prohibitions and requirements that are written in memory, rules, skill bodies or the root instruction files of the other agents, such as "never push", "do not read secrets" or "always ask before deleting", and that no permission rule or PreToolUse hook backs. The sentence may be right, but nothing in the configuration stops the agent from doing the action.

A static scan is not a security audit. The scanner finds the configuration and the text; it cannot tell how the agent weighs a sentence. The reviewer judges each line by reading it against the configuration.

This rule covers a sentence that states the rule itself and claims no control. A sentence that says a hook or a permission rule protects something is SEC-04, which checks whether the claimed control exists and works.

## Why it matters

Claude Code treats CLAUDE.md and auto memory as context, not as enforced configuration. The memory documentation says that to block an action regardless of what Claude decides, a PreToolUse hook is the mechanism. A written rule is therefore a request that the model reads at the start of each session. Atlas says the same in its guidance: written instructions cannot reliably stop an agent.

The mode changes the picture only a little. In `auto` mode, the classifier treats boundaries that a person states in the conversation as a block signal. Its requests include the CLAUDE.md content. The permission modes page does not say that CLAUDE.md text is a block signal, so this rule does not assume it. The page also says that stated boundaries are not stored as rules and can be lost when the context is compacted, and that a deny rule is the hard guarantee. In the other modes, the memory is context only.

A written rule can also make a team believe that a protection exists, so the team does not build the control. The text then looks like a protection and gives none. A permissions file that no known agent loads gives the same result for the agent that reads the rule: the file is there, and nothing runs it.

## How it is detected

This is a judgment rule. The measured support gives the controls; the reviewer reads the text.

Controls in the configuration:

- `security.permissions.deny[]` and `security.permissions.ask[]`: the rules of the project settings that Claude Code loads.
- `claudeConfig.hooks[]` with `event` `PreToolUse`, and its `matcher`.
- `candidates` of kind `unloaded-control` (`rules` SEC-05): a permissions or hooks file that no known agent loads. It is not a control. The finding gives its `status`, as SEC-04 explains, and the reviewer does not read the file.

Text: the memory and rule files that the inventory lists (`kind: memory` and `kind: rule`), the root instruction files of the other agents that the scan names as `agent-instructions` candidates, and the bodies of skills and commands when the reviewer reads them.

Flag a line when all of these hold:

1. The line is a security rule: a prohibition or requirement about a command, a file, a secret, a network call or a push, written with words such as "never", "do not", "always ask" or "must not". A preference, such as "prefer small commits", is not a security rule.
2. No `deny` or `ask` rule in `security.permissions` covers the same action. Compare the rule's pattern with the action that the line names. An unloaded control is not a rule for this purpose, so it does not clear the line.
3. No PreToolUse hook covers the same tool and blocks the action. SEC-04 describes how to check the script.

The impact is medium, and the report says that it is an opinion: the protection exists only as text, or as a file that no known agent loads. This rule does not raise the impact to high. The high findings come from SEC-01 to SEC-03, when the action actually passes without a prompt. When the only candidate is an unloaded control with status `not-verified`, the finding says that the control is not verified for the other agents. It does not say that the control is missing.

## Recommendation

1. **Add the control first.** To stop an action, `deny` it: for example `Bash(git push --force *)`, or `Read(**/.env)`. To keep an action available with confirmation, put it in `ask`: for example `Bash(git push *)`. For a control in a file that no known agent loads, move the rule into `.claude/settings.json`, which Claude Code loads, or into the settings of another agent after its load is verified.
2. **For what a rule cannot express,** add a PreToolUse hook with `onFailure` set to `"block"` (SEC-02 and SEC-04 describe the shape).
3. **Then shorten the line.** Keep the reason, for example "pushes need approval because the remote is shared", and delete the duplicate list of commands. A line that repeats a control costs tokens in every session and adds nothing.

## When not to apply

- A line that explains a control the configuration already has. The control is there; the line is context.
- A control that the scanner cannot read: managed settings, user settings or a plugin. The report says that the control is not visible in the project, and does not flag the line as unbacked.
- A prohibition about a judgment that no tool call reveals, such as "do not share unreleased features". Nothing in the harness can check it, so the text is the only control available. The rule does not flag it, and the report says that no control exists.
- A rule in a skill body. The line loads only when the skill runs; the report says so and checks the line the same way.
- A sentence that says a hook or a permission rule protects something, such as "the hook blocks force pushes". That claims a control, so SEC-04 checks it: the question there is whether the control exists and works.
- A permissions or hooks file that a known agent loads (`loadedBy` is not empty). It is a control for that agent, and the line is checked against it as against any other control.

## Examples

Commands and file names in these examples are illustrative, not measurements.

### Applies: "never push" with an allow rule behind it (medium)

Bad, `CLAUDE.md`: "Never push to the remote without asking." `.claude/settings.json` has `"allow": ["Bash(git *)"]`, and no `ask` or `deny` rule covers the push and no hook runs. The line is a request, and the allow rule lets the push run without a prompt. The push also appears as high in SEC-01 and SEC-02. Good: add `"ask": ["Bash(git push *)"]`, which takes precedence over the allow rule, and keep the line as the reason.

### Applies: data protection stated only in memory (medium)

Bad, `CLAUDE.md`: "Never read `.env` files." No `Read` deny rule and no hook cover `.env`. The sentence is the only control. Good: add `"deny": ["Read(**/.env)"]` and keep the line as the reason.

### Applies: a rule backed only by a file that no known agent loads (medium)

Bad, `AGENTS.md`: "Never read `.env` files." `.agents/permissions.json` has `Read(**/.env)` in its `deny` list. Claude Code does not load that file, and the shared convention is unknown, so the candidate has status `not-verified`. No control that Claude Code loads backs the line. The finding says that the deny is not verified for the other agents, and that for Claude Code the line is only text. Good: add `"deny": ["Read(**/.env)"]` to `.claude/settings.json`, which Claude Code loads, and keep the line as the reason.

### Does not apply: the line is backed by a deny rule

Good, `CLAUDE.md`: "Never run `git push --force`." `.claude/settings.json` has `"deny": ["Bash(git push --force *)"]`. The line is backed by a deny rule, so the rule does not flag it. Forms of the same command that the pattern does not match are a different question, and SEC-02 reports them.
