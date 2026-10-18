---
id: CTX-01
title: Always-loaded memory file is too large
axis: context
kind: measured
measuredSupport: []
defaultImpact: medium
sources: [example-docs]
evidence: official-docs
since: v0.2
status: draft
---

## What it checks

Whether a memory file that loads in every session is longer than the recommended size.

## Why it matters

Everything in an always-loaded file is paid in every session, whether or not the task needs it.

## How it is detected

Measured. The scanner reads the line count of each always-loaded memory file. The finding triggers when a file has more lines than the threshold in the measurement table.

## Recommendation

Move the detailed material into skills or path-scoped rules, and keep the always-loaded file to the facts every task needs.

## When not to apply

A short project where the whole memory file is needed for every task.

## Examples

Large: one file with the full architecture, all commands and the release procedure.

Smaller: a short file with the commands, linking to a skill for the release procedure.
