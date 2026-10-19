---
paths: ["scripts/**", "test/**"]
---

# Development rules

- Modules are ES modules with the .mjs extension. Use Node.js >= 22 and its standard library only; no npm dependencies.
- Output is deterministic: write JSON with `writeStableJson` from `scripts/lib/json-out.mjs`, and sort every list the scanner emits.
- Read target files only through `scripts/lib/safe-fs.mjs`. Nothing from a target is executed or imported.
- Hooks read only the JSON they receive and their own data files, and they run nothing.
- One test file per module under `test/`, named after it: `test/safe-fs.test.mjs` tests `scripts/lib/safe-fs.mjs`.
- New fixtures that hold secrets, CRLF line endings or large files are built with `test/helpers/make-fixture.mjs`, in the system temp folder, and are never versioned.
- Every test of hostile input has a positive control: a normal input next to it that must pass.
- Everything is in English: code, comments, messages and test names.
- When a JSON output changes, update its schema in `schemas/` in the same change.
- Before reporting work as done, run `npm test` and `npm run check`.
