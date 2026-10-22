// Tests for scripts/lib/report-catalog.mjs: the catalog version that the scanner writes to meta.catalog and that the report
// writes to its header. The version is computed from the rule files only, so the rule folders here are fixtures.

import assert from "node:assert/strict";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { loadRules } from "../scripts/lib/findings-validate.mjs";
import { catalogVersion, readCatalog } from "../scripts/lib/report-catalog.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const CTX_TEXT = "---\nid: CTX-01\ntitle: Budget\naxis: context\nkind: measured\n---\n\nBody.\n";
const COD_TEXT = "---\nid: COD-01\ntitle: Copies\naxis: code\nkind: measured\n---\n\nText.\n";

// A fixture with the given rule files under rules/. It returns the root and the rule list that loadRules would return for it.
function makeCatalog(t, files) {
  const fixture = makeFixture({
    files: Object.fromEntries(Object.entries(files).map(([name, text]) => [`rules/${name}`, text])),
  });
  t.after(fixture.cleanup);
  return { root: fixture.root, rules: Object.keys(files).map((name) => ({ file: `rules/${name}` })) };
}

test("catalogVersion gives the version that readCatalog reports for this harness", () => {
  const rules = loadRules(HARNESS_ROOT);
  const version = catalogVersion(HARNESS_ROOT, rules);

  assert.deepEqual(version, readCatalog(HARNESS_ROOT, rules).version);
  assert.equal(version.count, rules.length);
  assert.match(version.sha256, /^[0-9a-f]{12}$/);
});

test("catalogVersion is the same on each call, and whatever the order of the rules", () => {
  const rules = loadRules(HARNESS_ROOT);
  const forward = catalogVersion(HARNESS_ROOT, rules);

  assert.deepEqual(catalogVersion(HARNESS_ROOT, rules), forward);
  assert.deepEqual(catalogVersion(HARNESS_ROOT, [...rules].reverse()), forward);
});

test("catalogVersion reads line endings as LF, so CRLF and LF give one version (positive control: a changed word does not)", (t) => {
  const lf = makeCatalog(t, { "CTX-01-budget.md": CTX_TEXT, "COD-01-copies.md": COD_TEXT });
  const crlf = makeCatalog(t, {
    "CTX-01-budget.md": CTX_TEXT.replaceAll("\n", "\r\n"),
    "COD-01-copies.md": COD_TEXT.replaceAll("\n", "\r\n"),
  });
  const changed = makeCatalog(t, { "CTX-01-budget.md": CTX_TEXT.replace("Body.", "Body!"), "COD-01-copies.md": COD_TEXT });

  const version = catalogVersion(lf.root, lf.rules);
  assert.deepEqual(catalogVersion(crlf.root, crlf.rules), version);
  assert.notEqual(catalogVersion(changed.root, changed.rules).sha256, version.sha256);
});

test("catalogVersion changes when a rule is renamed, added or changed, and its count follows the rule files", (t) => {
  const base = makeCatalog(t, { "CTX-01-budget.md": CTX_TEXT, "COD-01-copies.md": COD_TEXT });
  const renamed = makeCatalog(t, { "CTX-02-budget.md": CTX_TEXT, "COD-01-copies.md": COD_TEXT });
  const added = makeCatalog(t, { "CTX-01-budget.md": CTX_TEXT, "COD-01-copies.md": COD_TEXT, "COD-04-reuse.md": COD_TEXT });
  const changed = makeCatalog(t, { "CTX-01-budget.md": CTX_TEXT.replace("Body.", "Body!"), "COD-01-copies.md": COD_TEXT });

  const version = catalogVersion(base.root, base.rules);
  assert.equal(version.count, 2);
  assert.equal(catalogVersion(added.root, added.rules).count, 3);
  assert.notEqual(catalogVersion(renamed.root, renamed.rules).sha256, version.sha256);
  assert.notEqual(catalogVersion(added.root, added.rules).sha256, version.sha256);
  assert.notEqual(catalogVersion(changed.root, changed.rules).sha256, version.sha256);
});

test("identical rule files in two folders give one version (positive control for the cases above)", (t) => {
  const first = makeCatalog(t, { "CTX-01-budget.md": CTX_TEXT, "COD-01-copies.md": COD_TEXT });
  const second = makeCatalog(t, { "CTX-01-budget.md": CTX_TEXT, "COD-01-copies.md": COD_TEXT });

  assert.deepEqual(catalogVersion(second.root, second.rules), catalogVersion(first.root, first.rules));
});
