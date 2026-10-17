---
id: SEC-02
title: Destructive commands have no barrier
axis: security
kind: judgment
measuredSupport: [M11]
defaultImpact: high
sources: [example-study, example-docs]
evidence: study
since: mvp
status: draft
---

## What it checks

Whether commands that destroy work, such as a forced push or a recursive delete, can run without a confirmation.

## Why it matters

A model that runs one of these commands can lose changes that no one can recover. Asking in the prompt is not a barrier, because the model may not follow the request.

## How it is detected

Judgment, using the measured permission results. The rule applies when a destructive command is allowed, or when nothing denies it and no hook asks first. A reviewer reads the hook script and says so.

## Recommendation

Add a `deny` or `ask` permission for each destructive command, or a `PreToolUse` hook that blocks it. Then keep or remove the matching text in the instructions.

## When not to apply

A repository where every destructive command runs in a disposable sandbox that is reset after each session.

## Examples

Weak: a permission list that allows `Bash(git *)`, which includes `git push --force`.

Stronger: the same list with `deny` entries for `Bash(git push --force*)` and `Bash(git reset --hard*)`.
