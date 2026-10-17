---
name: nested-value
description: Shows that a nested hooks block in the frontmatter does not stop the skill from counting.
hooks:
  PreToolUse:
    - matcher: Bash
---

# Nested value

The frontmatter above has a nested value under a key that the scanner does not read.
