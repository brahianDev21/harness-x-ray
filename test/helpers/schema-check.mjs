// The schema checker of the scripts, re-exported for the tests. The checker itself lives in scripts/lib/schema-check.mjs, so the
// scripts that read a schema-checked input can use it too.

export { schemaProblems } from "../../scripts/lib/schema-check.mjs";
