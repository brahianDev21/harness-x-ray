---
id: RUL-01
title: Generic rules the model already follows
axis: instructions
kind: judgment
measuredSupport: []
defaultImpact: low
sources: []
evidence: common-practice
since: mvp
status: draft
---

## What it checks

Instructions that describe behavior a capable model already has, such as "write clean code" or "be careful with changes".

## Why it matters

Every session loads these lines, and they do not change what the model does. They cost tokens and push out the project-specific instructions that do.

## How it is detected

Judgment. Read the instruction file and flag a line when it could be deleted without changing the work. Examples of flagged lines are generic quality advice that applies to any project.

## Recommendation

Remove the generic lines and keep the project facts: commands, paths, conventions that differ from the defaults.

## When not to apply

A generic line that names a project rule in disguise, such as "never edit generated files in dist/", is project-specific and stays.

## Examples

Flagged: "Write clean, readable code and follow best practices."

Kept: "Generated files live in dist/. Edit the source in src/ instead."
