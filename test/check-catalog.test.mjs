import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { checkCatalog, loadEmitters } from "../scripts/check-catalog.mjs";
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const CHECK_SCRIPT = path.join(HARNESS_ROOT, "scripts", "check-catalog.mjs");
const GOOD = path.join(TEST_DIR, "fixtures", "catalog-good");
const EMITTERS_FILE = "scripts/lib/measured-findings.mjs";
const MEASURED_FINDINGS = path.join(HARNESS_ROOT, EMITTERS_FILE);
const RULE_RUL01 = "rules/RUL-01-generic-rules.md";
const RULE_SEC02 = "rules/SEC-02-destructive-commands.md";
const RULE_CTX01 = "rules/CTX-01-always-loaded-size.md";
const SOURCES = "rules/sources.json";
const SIGNALS = "data/layer-signals.json";
// A valid layer-signals file. check-catalog requires one, and the good fixture has none, so each copy of the fixture gets it.
const MINIMAL_SIGNALS = {
  manifests: ["package.json", "Cargo.toml"],
  names: { frontend: ["web", "frontend"], "api-server": ["api", "server"] },
  languages: { ".ts": "TypeScript", ".c++": "C++", ".cs": "C#" },
};

// Helpers ---------------------------------------------------------------------------------------

// A copy of the good fixture in a temp folder. The copy also gets a valid data/layer-signals.json, which the fixture lacks
// and check-catalog requires. files are written over the copy; remove lists paths to delete from it.
function copyOfGood(t, { files = {}, remove = [] } = {}) {
  const signals = `${JSON.stringify(MINIMAL_SIGNALS, null, 2)}\n`;
  const fixture = makeFixture({ fromDir: GOOD, files: { [SIGNALS]: signals, ...files } });
  t.after(fixture.cleanup);
  for (const relPath of remove) fs.rmSync(path.join(fixture.root, relPath));
  return fixture.root;
}

function goodText(relPath) {
  return fs.readFileSync(path.join(GOOD, relPath), "utf8");
}

// The files object for one replacement in a fixture file. It fails if the text is not there, so a
// mutation can never silently do nothing.
function mutate(relPath, from, to) {
  const text = goodText(relPath);
  assert.ok(text.includes(from), `${relPath} does not contain ${JSON.stringify(from)}`);
  return { [relPath]: text.replace(from, to) };
}

// Splits a rule text at its H2 headings and swaps the blocks of two sections.
function swapSections(text, first, second) {
  const blocks = text.split(/^(?=## )/m);
  const i = blocks.findIndex((block) => block.startsWith(`## ${first}\n`));
  const j = blocks.findIndex((block) => block.startsWith(`## ${second}\n`));
  assert.ok(i !== -1 && j !== -1, "both sections must exist");
  [blocks[i], blocks[j]] = [blocks[j], blocks[i]];
  return blocks.join("");
}

function sourcesJson(entries) {
  return `${JSON.stringify({ sources: entries }, null, 2)}\n`;
}

const SOURCE = {
  id: "example-docs",
  title: "Example configuration guide",
  url: "https://example.com/docs/configuration",
  type: "official-docs",
  accessed: "2026-10-01",
  note: "Describes the memory file loading order.",
};

function describeIssues(list) {
  return list.map((item) => `${item.file}: ${item.field}: ${item.message}`).join("\n") || "(none)";
}

// The one issue for a file and a field. It fails if there is none, or if the message does not match.
function issueFor(list, file, field, pattern) {
  const found = list.find((item) => item.file === file && item.field === field);
  assert.ok(found, `expected an issue at ${file} field "${field}", got:\n${describeIssues(list)}`);
  if (pattern !== undefined) assert.match(found.message, pattern);
  return found;
}

function errorsOf(root, emitters = null) {
  return checkCatalog({ root, emitters }).errors;
}

// Runs the command line through execFile (never a shell). Resolves with the exit code and both streams.
async function runCheck(args, cwd = HARNESS_ROOT) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CHECK_SCRIPT, ...args], {
      cwd,
      encoding: "utf8",
      windowsHide: true,
      timeout: 120_000,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    if (typeof error.code !== "number") throw error; // The process did not start.
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

// Good catalog and repository ---------------------------------------------------------------------

test("the good fixture has no errors; without emitters it only warns that they are skipped", (t) => {
  const result = checkCatalog({ root: copyOfGood(t), emitters: null });
  assert.deepEqual(result.errors, []);
  assert.equal(result.warnings.length, 1, describeIssues(result.warnings));
  assert.equal(result.warnings[0].file, EMITTERS_FILE);
  assert.equal(result.warnings[0].field, "EMITTERS");
  // README.md and notes.txt are not rules, so only the three rule files count. The copy has two data files: the
  // fixture's example-patterns.json and the layer-signals.json that copyOfGood adds.
  assert.deepEqual(result.counts, { rules: 3, sources: 2, dataFiles: 2 });
});

test("rule and source files with CRLF or lone CR line endings and a BOM give no errors", (t) => {
  // Built at run time, not committed: a checked-in CRLF fixture could be converted by git's autocrlf.
  const BOM = String.fromCodePoint(0xfeff);
  const lf = (relPath) => goodText(relPath).replace(/\r\n?/g, "\n");
  const crlf = (text) => text.replace(/\n/g, "\r\n");
  const root = copyOfGood(t, {
    files: {
      [RULE_RUL01]: `${BOM}${crlf(lf(RULE_RUL01))}`,
      [RULE_SEC02]: crlf(lf(RULE_SEC02)),
      [RULE_CTX01]: lf(RULE_CTX01).replace(/\n/g, "\r"),
      [SOURCES]: `${BOM}${crlf(lf(SOURCES))}`,
      "data/example-patterns.json": crlf(lf("data/example-patterns.json")),
    },
  });
  assert.ok(fs.readFileSync(path.join(root, RULE_RUL01), "utf8").startsWith(BOM), "the BOM is in the fixture");
  assert.ok(fs.readFileSync(path.join(root, RULE_SEC02), "utf8").includes("\r\n"), "CRLF is in the fixture");
  assert.deepEqual(errorsOf(root), []);
});

test("the repository catalog has no errors", async () => {
  const loaded = await loadEmitters(HARNESS_ROOT);
  assert.deepEqual(loaded.errors, []);
  const result = checkCatalog({ root: HARNESS_ROOT, emitters: loaded.emitters });
  assert.deepEqual(result.errors, [], describeIssues(result.errors));
});

test("the repository emitters are exactly the measured rules, the MVP ones and CTX-04 of v0.2, and the check prints no emitter warning", async () => {
  const loaded = await loadEmitters(HARNESS_ROOT);
  const result = checkCatalog({ root: HARNESS_ROOT, emitters: loaded.emitters });
  const measured = ["RUL-04", "CTX-01", "CTX-04", "CTX-07", "SEC-01", "SEC-02", "SEC-03", "STR-02", "COD-01"];
  assert.deepEqual(Object.keys(loaded.emitters), measured);
  assert.deepEqual(result.warnings.filter((warning) => warning.field === "EMITTERS"), []);
});

test("a root without a rules folder is refused", (t) => {
  const fixture = makeFixture({});
  t.after(fixture.cleanup);
  assert.throws(() => checkCatalog({ root: fixture.root, emitters: null }), /no rules\/ folder/);
});

test("emitters must be null or a collection", () => {
  assert.throws(() => checkCatalog({ root: GOOD, emitters: "CTX-01" }), TypeError);
  assert.throws(() => checkCatalog({ root: GOOD, emitters: 3 }), TypeError);
});

// File names and frontmatter ------------------------------------------------------------------------

test("a rule file name must start with a rule id", (t) => {
  const root = copyOfGood(t, { files: { "rules/XYZ-01-odd.md": goodText(RULE_CTX01) } });
  issueFor(errorsOf(root), "rules/XYZ-01-odd.md", "file name", /must be <ID>\.md/);
});

test("a rule file without frontmatter is an error", (t) => {
  const body = goodText(RULE_RUL01).replace(/^---\n[\s\S]*?\n---\n/, "");
  const root = copyOfGood(t, { files: { [RULE_RUL01]: body } });
  issueFor(errorsOf(root), RULE_RUL01, "frontmatter", /missing/);
});

test("a frontmatter that is never closed is an error", (t) => {
  const text = goodText(RULE_RUL01).replace("\n---\n", "\n");
  const root = copyOfGood(t, { files: { [RULE_RUL01]: text } });
  issueFor(errorsOf(root), RULE_RUL01, "frontmatter", /never closed/);
});

test("broken frontmatter structure is an error on the frontmatter", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_RUL01, "axis: instructions", "\taxis: instructions") });
  issueFor(errorsOf(root), RULE_RUL01, "frontmatter", /tabs cannot be used/);
});

test("a value the frontmatter reader cannot read is reported under its own field only", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_RUL01, "measuredSupport: []", "measuredSupport:\n  nested: value") });
  const errors = errorsOf(root).filter((item) => item.file === RULE_RUL01);
  assert.deepEqual(errors.map((item) => item.field), ["measuredSupport"], describeIssues(errors));
  assert.match(errors[0].message, /nested mappings are not supported/);
});

test("an unknown frontmatter field is an error", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_RUL01, "status: draft\n", "status: draft\nowner: team-a\n") });
  issueFor(errorsOf(root), RULE_RUL01, "owner", /unknown field/);
});

test("a missing required frontmatter field is an error", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_RUL01, "status: draft\n", "") });
  issueFor(errorsOf(root), RULE_RUL01, "status", /missing required field/);
});

const ENUM_CASES = [
  ["axis", "axis: instructions", "axis: opinion"],
  ["kind", "kind: judgment", "kind: opinion"],
  ["defaultImpact", "defaultImpact: low", "defaultImpact: huge"],
  ["since", "since: mvp", "since: v9"],
  ["status", "status: draft", "status: final"],
  ["evidence", "evidence: common-practice", "evidence: guess"],
];
for (const [field, from, to] of ENUM_CASES) {
  test(`frontmatter ${field} accepts only its allowed values`, (t) => {
    const root = copyOfGood(t, { files: mutate(RULE_RUL01, from, to) });
    issueFor(errorsOf(root), RULE_RUL01, field, /must be one of/);
  });
}

test("the id must be a rule id", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_RUL01, "id: RUL-01", "id: RUL-1") });
  issueFor(errorsOf(root), RULE_RUL01, "id", /must be a rule id such as RUL-01/);
});

test("the frontmatter id must match the file name prefix", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_RUL01, "id: RUL-01", "id: RUL-02") });
  issueFor(errorsOf(root), RULE_RUL01, "id", /must match the file name prefix RUL-01/);
});

test("two rule files may not share an id", (t) => {
  const root = copyOfGood(t, { files: { "rules/RUL-01.md": goodText(RULE_RUL01) } });
  issueFor(errorsOf(root), "rules/RUL-01.md", "id", /duplicate id RUL-01/);
});

test("the axis must match the id prefix", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_RUL01, "axis: instructions", "axis: context") });
  issueFor(errorsOf(root), RULE_RUL01, "axis", /must be "instructions" for RUL-01/);
});

test("the title must be a non-empty string", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_RUL01, "title: Generic rules the model already follows", 'title: ""') });
  issueFor(errorsOf(root), RULE_RUL01, "title", /non-empty string/);
});

test("measuredSupport must be a list", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_RUL01, "measuredSupport: []", "measuredSupport: M11") });
  issueFor(errorsOf(root), RULE_RUL01, "measuredSupport", /must be a list/);
});

test("measuredSupport items must look like M11", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_SEC02, "measuredSupport: [M11]", "measuredSupport: [m11]") });
  issueFor(errorsOf(root), RULE_SEC02, "measuredSupport", /items must look like M11/);
});

test("sources must be a list", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_RUL01, "sources: []", "sources: example-docs") });
  issueFor(errorsOf(root), RULE_RUL01, "sources", /must be a list of source ids/);
});

test("sources items must be strings", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_RUL01, "sources: []", "sources: [1]") });
  issueFor(errorsOf(root), RULE_RUL01, "sources", /items must be source ids/);
});

test("a source id that is not in sources.json is an error", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_SEC02, "sources: [example-study, example-docs]", "sources: [example-study, missing-source]") });
  issueFor(errorsOf(root), RULE_SEC02, "sources", /unknown source id "missing-source"/);
});

test("evidence must equal the strongest type among the sources", (t) => {
  // example-study is a study, the strongest level, so evidence must be "study".
  const root = copyOfGood(t, { files: mutate(RULE_SEC02, "evidence: study", "evidence: official-docs") });
  issueFor(errorsOf(root), RULE_SEC02, "evidence", /must be "study", the strongest type among its sources/);
});

test("evidence must be common-practice when a rule has no sources", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_RUL01, "evidence: common-practice", "evidence: official-docs") });
  issueFor(errorsOf(root), RULE_RUL01, "evidence", /must be "common-practice" when sources is empty/);
});

test("a rule file that is not a regular file is a warning, not checked", (t) => {
  const root = copyOfGood(t, { files: { "rules/CTX-02-folder.md/inner.txt": "not a rule" } });
  const { errors, warnings } = checkCatalog({ root, emitters: null });
  assert.deepEqual(errors, []);
  issueFor(warnings, "rules/CTX-02-folder.md", "file", /not a regular file/);
});

// Body sections -----------------------------------------------------------------------------------

test("an H2 that is not a known section is an error", (t) => {
  const root = copyOfGood(t, { files: { [RULE_RUL01]: `${goodText(RULE_RUL01)}\n## Notes\n\nExtra text.\n` } });
  issueFor(errorsOf(root), RULE_RUL01, "Notes", /unknown section/);
});

test("a missing section is an error", (t) => {
  const text = goodText(RULE_RUL01).replace(/## When not to apply\n[\s\S]*?(?=## Examples)/, "");
  const root = copyOfGood(t, { files: { [RULE_RUL01]: text } });
  issueFor(errorsOf(root), RULE_RUL01, "When not to apply", /missing section/);
});

test("a section that appears twice is an error", (t) => {
  const root = copyOfGood(t, { files: { [RULE_RUL01]: `${goodText(RULE_RUL01)}\n## Examples\n\nMore examples.\n` } });
  issueFor(errorsOf(root), RULE_RUL01, "Examples", /appears more than once/);
});

test("sections out of the required order are an error", (t) => {
  const text = swapSections(goodText(RULE_RUL01), "Recommendation", "When not to apply");
  const root = copyOfGood(t, { files: { [RULE_RUL01]: text } });
  issueFor(errorsOf(root), RULE_RUL01, "Recommendation", /must come before "When not to apply"/);
});

test("an empty section is an error", (t) => {
  const text = goodText(RULE_RUL01).replace(/## Examples[\s\S]*$/, "## Examples\n");
  const root = copyOfGood(t, { files: { [RULE_RUL01]: text } });
  issueFor(errorsOf(root), RULE_RUL01, "Examples", /section is empty/);
});

test("headings inside a fenced code block are not sections", (t) => {
  const text = goodText(RULE_RUL01).replace(
    "## What it checks\n",
    "## What it checks\n\n```md\n## Notes\n## Examples\n```\n",
  );
  const root = copyOfGood(t, { files: { [RULE_RUL01]: text } });
  assert.deepEqual(errorsOf(root).filter((item) => item.file === RULE_RUL01), []);
});

// sources.json ---------------------------------------------------------------------------------------

test("a missing sources.json is an error", (t) => {
  const root = copyOfGood(t, { remove: [SOURCES] });
  issueFor(errorsOf(root), SOURCES, "sources", /file is missing/);
});

test("sources.json that is not valid JSON is an error", (t) => {
  const root = copyOfGood(t, { files: { [SOURCES]: "{ not json" } });
  issueFor(errorsOf(root), SOURCES, "json", /not valid JSON/);
});

test("sources.json must be an object at the top level", (t) => {
  const root = copyOfGood(t, { files: { [SOURCES]: "[]\n" } });
  issueFor(errorsOf(root), SOURCES, "json", /top level must be an object/);
});

test("sources.json has no field other than sources", (t) => {
  const root = copyOfGood(t, { files: { [SOURCES]: `{ "sources": [], "extra": 1 }\n` } });
  issueFor(errorsOf(root), SOURCES, "extra", /unknown field/);
});

test("sources must be a list", (t) => {
  const root = copyOfGood(t, { files: { [SOURCES]: `{ "sources": {} }\n` } });
  issueFor(errorsOf(root), SOURCES, "sources", /must be a list/);
});

test("each source must be an object", (t) => {
  const root = copyOfGood(t, { files: { [SOURCES]: sourcesJson(["example-docs"]) } });
  issueFor(errorsOf(root), SOURCES, "sources[0]", /must be an object/);
});

test("each source field is required", (t) => {
  const { note, ...withoutNote } = SOURCE;
  assert.equal(typeof note, "string");
  const root = copyOfGood(t, { files: { [SOURCES]: sourcesJson([withoutNote]) } });
  issueFor(errorsOf(root), SOURCES, "sources[0].note", /missing required field/);
});

test("each source field must be a non-empty string", (t) => {
  const root = copyOfGood(t, { files: { [SOURCES]: sourcesJson([{ ...SOURCE, title: "" }]) } });
  issueFor(errorsOf(root), SOURCES, "sources[0].title", /non-empty string/);
});

test("a source entry has no fields other than the six listed", (t) => {
  const root = copyOfGood(t, { files: { [SOURCES]: sourcesJson([{ ...SOURCE, extra: "x" }]) } });
  issueFor(errorsOf(root), SOURCES, "sources[0].extra", /unknown field/);
});

test("source ids are unique", (t) => {
  const root = copyOfGood(t, { files: { [SOURCES]: sourcesJson([SOURCE, { ...SOURCE, url: "https://example.com/other" }]) } });
  issueFor(errorsOf(root), SOURCES, "sources[1].id", /duplicate id "example-docs"/);
});

test("source ids are kebab-case", (t) => {
  const root = copyOfGood(t, { files: { [SOURCES]: sourcesJson([{ ...SOURCE, id: "Example_Docs" }]) } });
  issueFor(errorsOf(root), SOURCES, "sources[0].id", /kebab-case/);
});

test("a source url must be https", (t) => {
  const root = copyOfGood(t, { files: { [SOURCES]: sourcesJson([{ ...SOURCE, url: "http://example.com/docs" }]) } });
  issueFor(errorsOf(root), SOURCES, "sources[0].url", /must be an https:\/\/ URL/);
});

test("a source access date must be a real YYYY-MM-DD date", (t) => {
  const root = copyOfGood(t, { files: { [SOURCES]: sourcesJson([{ ...SOURCE, accessed: "2026-02-30" }]) } });
  issueFor(errorsOf(root), SOURCES, "sources[0].accessed", /real date in YYYY-MM-DD/);
});

test("a source type must be one of the evidence levels that sources can have", (t) => {
  const root = copyOfGood(t, { files: { [SOURCES]: sourcesJson([{ ...SOURCE, type: "common-practice" }]) } });
  issueFor(errorsOf(root), SOURCES, "sources[0].type", /must be one of study, benchmark/);
});

test("a source with an invalid type is reported once, not as unknown by the rules that cite it", (t) => {
  const sources = sourcesJson([
    { ...SOURCE, type: "blog" },
    { ...SOURCE, id: "example-study", type: "study" },
  ]);
  const root = copyOfGood(t, { files: { [SOURCES]: sources } });
  const errors = errorsOf(root);
  assert.deepEqual(errors.map((item) => item.field), ["sources[0].type"], describeIssues(errors));
});

// data/*.json ---------------------------------------------------------------------------------------

test("a data file that is not valid JSON is an error", (t) => {
  const root = copyOfGood(t, { files: { "data/broken.json": '{ "items": [ }' } });
  issueFor(errorsOf(root), "data/broken.json", "json", /not valid JSON/);
});

test("ids in a data file are unique at any depth", (t) => {
  const text = JSON.stringify({ id: "x", groups: [{ members: [{ id: "x" }] }] });
  const root = copyOfGood(t, { files: { "data/nested.json": text } });
  issueFor(errorsOf(root), "data/nested.json", "/groups/0/members/0/id", /duplicate id "x"; \/id has it too/);
});

test("a regex in a data file must compile", (t) => {
  const root = copyOfGood(t, {
    files: {
      "data/regex.json": JSON.stringify({ items: [{ id: "a", regex: "[unclosed" }] }),
      "data/list.json": JSON.stringify({ items: [{ id: "b", regex: ["ok", "(bad"] }] }),
    },
  });
  issueFor(errorsOf(root), "data/regex.json", "/items/0/regex", /not a valid regular expression/);
  issueFor(errorsOf(root), "data/list.json", "/items/0/regex/1", /not a valid regular expression/);
});

test("regex flags must be valid, and must be a string when a regex is next to them", (t) => {
  const root = copyOfGood(t, {
    files: {
      "data/flags.json": JSON.stringify({ items: [{ id: "a", regex: "a", flags: "q" }] }),
      "data/flagtype.json": JSON.stringify({ items: [{ id: "a", regex: "a", flags: 1 }] }),
    },
  });
  issueFor(errorsOf(root), "data/flags.json", "/items/0/regex", /not a valid regular expression/);
  issueFor(errorsOf(root), "data/flagtype.json", "/items/0/flags", /must be a string/);
});

test("keys other than regex are not compiled, and files that are not .json are ignored", (t) => {
  const root = copyOfGood(t, {
    files: {
      "data/patterns.json": JSON.stringify({ items: [{ id: "a", pattern: "[not compiled", globs: ["[also"] }] }),
      "data/notes.txt": "{ not json, and not checked",
    },
  });
  assert.deepEqual(errorsOf(root), []);
});

// data/agent-harness.json ---------------------------------------------------------------------------

const HARNESS = "data/agent-harness.json";

// One agent and one file entry that cites a good source. It is valid, so it is the positive control of this section.
const MINIMAL_REGISTRY = {
  agents: [{ id: "example-agent", name: "Example agent", type: "agent" }],
  files: [
    {
      id: "example-agent-settings",
      agent: "example-agent",
      glob: ".example/settings.json",
      kind: "settings",
      loadModel: "always",
      sources: ["example-docs"],
    },
  ],
};

// A good fixture with the registry changed by the callback (or with the copy of the minimal registry as it is).
function copyWithRegistry(t, change = () => {}, { remove = [] } = {}) {
  const registry = structuredClone(MINIMAL_REGISTRY);
  change(registry);
  return copyOfGood(t, { files: { [HARNESS]: `${JSON.stringify(registry, null, 2)}\n` }, remove });
}

test("a valid agent registry gives no errors (positive control)", (t) => {
  const root = copyWithRegistry(t);
  assert.deepEqual(errorsOf(root), []);
});

test("an agent registry that cites a nonexistent source is an error on that source", (t) => {
  const root = copyWithRegistry(t, (registry) => { registry.files[0].sources = ["no-such-source"]; });
  issueFor(errorsOf(root), HARNESS, "/files/0/sources/0", /does not exist in rules\/sources\.json/);
});

test("an agent registry source that is not official-docs is an error", (t) => {
  const root = copyWithRegistry(t, (registry) => { registry.files[0].sources = ["example-study"]; });
  issueFor(errorsOf(root), HARNESS, "/files/0/sources/0", /must have type official-docs, found "study"/);
});

test("an agent registry with a field that is not allowed is an error on that field", (t) => {
  const root = copyWithRegistry(t, (registry) => { registry.files[0].extra = true; });
  issueFor(errorsOf(root), HARNESS, "/files/0/extra", /unknown field/);
});

test("an agent registry with an invalid glob is an error on the glob", (t) => {
  const root = copyWithRegistry(t, (registry) => { registry.files[0].glob = ".example/**settings"; });
  issueFor(errorsOf(root), HARNESS, "/files/0/glob", /"\*\*" must be a whole segment/);
});

test("without rules/sources.json the registry source checks are skipped and the other checks still run", (t) => {
  const withSource = copyWithRegistry(t, (registry) => { registry.files[0].sources = ["no-such-source"]; });
  issueFor(errorsOf(withSource), HARNESS, "/files/0/sources/0", /does not exist/);

  const root = copyWithRegistry(
    t,
    (registry) => { registry.files[0].sources = ["no-such-source"]; },
    { remove: [SOURCES] },
  );
  const errors = errorsOf(root);
  issueFor(errors, SOURCES, "sources", /file is missing/);
  assert.equal(errors.some((item) => item.file === HARNESS && item.field === "/files/0/sources/0"), false);
});

test("an agent registry that is not valid JSON is reported by the data check only", (t) => {
  const root = copyOfGood(t, { files: { [HARNESS]: "{ not json" } });
  const errors = errorsOf(root);
  assert.equal(errors.length, 1, describeIssues(errors));
  issueFor(errors, HARNESS, "json", /not valid JSON/);
});

test("an absent agent registry is skipped with no error, and a valid one passes (positive control)", (t) => {
  assert.deepEqual(errorsOf(copyWithRegistry(t)), []);
  const root = copyOfGood(t);
  assert.equal(fs.existsSync(path.join(root, HARNESS)), false);
  assert.deepEqual(errorsOf(root), []);
});

test("a folder at the agent registry path is an error on the file", (t) => {
  assert.deepEqual(errorsOf(copyWithRegistry(t)), [], "positive control");
  const root = copyOfGood(t);
  fs.mkdirSync(path.join(root, HARNESS));
  issueFor(errorsOf(root), HARNESS, "(file)", /must be a regular file, not a folder/);
});

test("a dangling symbolic link at the agent registry path is an error on the file", {
  skip: symlinkSupport().supported ? false : symlinkSupport().reason,
}, (t) => {
  assert.deepEqual(errorsOf(copyWithRegistry(t)), [], "positive control");
  const root = copyOfGood(t);
  fs.symlinkSync("missing.json", path.join(root, HARNESS));
  issueFor(errorsOf(root), HARNESS, "(file)", /cannot be read: ENOENT/);
});

test("an agent registry that cannot be read is an error on the file", {
  skip: process.platform === "win32" || process.getuid?.() === 0 ? "file modes do not stop reads here" : false,
}, (t) => {
  assert.deepEqual(errorsOf(copyWithRegistry(t)), [], "positive control");
  const root = copyWithRegistry(t);
  fs.chmodSync(path.join(root, HARNESS), 0o000);
  issueFor(errorsOf(root), HARNESS, "(file)", /cannot be read: EACCES/);
});

test("the command line names the file and the field of an agent registry error", async (t) => {
  const valid = copyWithRegistry(t);
  const validResult = await runCheck(["--root", valid]);
  assert.equal(validResult.code, 0, validResult.stdout + validResult.stderr);

  const root = copyWithRegistry(t, (registry) => { registry.files[0].sources = ["no-such-source"]; });
  const result = await runCheck(["--root", root]);
  assert.equal(result.code, 1, result.stdout + result.stderr);
  assert.ok(
    result.stdout.split("\n").some((line) => line.startsWith(`${HARNESS}: /files/0/sources/0: `)),
    result.stdout,
  );
});

// Emitters ------------------------------------------------------------------------------------------

test("without emitters the check is skipped with one warning", () => {
  const { warnings } = checkCatalog({ root: GOOD, emitters: null });
  assert.equal(warnings.length, 1);
  assert.deepEqual(
    { file: warnings[0].file, field: warnings[0].field },
    { file: EMITTERS_FILE, field: "EMITTERS" },
  );
});

test("a measured rule with since mvp needs an emitter", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_CTX01, "since: v0.2", "since: mvp") });
  issueFor(errorsOf(root, []), RULE_CTX01, "kind", /no emitter in EMITTERS/);
  issueFor(errorsOf(root, ["SEC-02"]), RULE_CTX01, "kind", /no emitter in EMITTERS/);
  assert.deepEqual(errorsOf(root, ["CTX-01"]), []);
});

test("measured rules with a later since need no emitter yet", (t) => {
  assert.deepEqual(errorsOf(copyOfGood(t), []), []);
});

test("emitters can be an array, a Set, a Map or a plain object keyed by rule id", (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_CTX01, "since: v0.2", "since: mvp") });
  const shapes = [
    ["CTX-01"],
    new Set(["CTX-01"]),
    new Map([["CTX-01", () => []]]),
    { "CTX-01": () => [] },
  ];
  for (const emitters of shapes) assert.deepEqual(errorsOf(root, emitters), []);
});

test("loadEmitters returns null without an error when the harness has no file", async (t) => {
  const harness = makeFixture({ files: { "README.md": "no emitters\n" } });
  t.after(harness.cleanup);
  const loaded = await loadEmitters(harness.root);
  assert.deepEqual(loaded, { emitters: null, errors: [] });
});

test("loadEmitters returns the EMITTERS of the harness file", async (t) => {
  const harness = makeFixture({ files: { [EMITTERS_FILE]: 'export const EMITTERS = ["CTX-01"];\n' } });
  t.after(harness.cleanup);
  const loaded = await loadEmitters(harness.root);
  assert.deepEqual(loaded, { emitters: ["CTX-01"], errors: [] });
});

test("an emitter file that cannot be imported is an error on the module", async (t) => {
  const harness = makeFixture({ files: { [EMITTERS_FILE]: "export const EMITTERS = [;\n" } });
  t.after(harness.cleanup);
  const loaded = await loadEmitters(harness.root);
  assert.equal(loaded.emitters, null);
  issueFor(loaded.errors, EMITTERS_FILE, "module", /cannot be imported/);
});

test("an emitter file without an EMITTERS export is an error", async (t) => {
  const harness = makeFixture({ files: { [EMITTERS_FILE]: "export const OTHER = [];\n" } });
  t.after(harness.cleanup);
  const loaded = await loadEmitters(harness.root);
  assert.equal(loaded.emitters, null);
  issueFor(loaded.errors, EMITTERS_FILE, "EMITTERS", /does not export EMITTERS/);
});

test("an EMITTERS export of the wrong type is an error", async (t) => {
  const harness = makeFixture({ files: { [EMITTERS_FILE]: 'export const EMITTERS = "CTX-01";\n' } });
  t.after(harness.cleanup);
  const loaded = await loadEmitters(harness.root);
  assert.equal(loaded.emitters, null);
  issueFor(loaded.errors, EMITTERS_FILE, "EMITTERS", /must be an array, a Set, a Map or a plain object/);
});

// data/layer-signals.json ---------------------------------------------------------------------------

test("a layer-signals file that is valid gives no errors, and a bad one is an error on its field", (t) => {
  const good = copyOfGood(t, { files: { [SIGNALS]: `${JSON.stringify(MINIMAL_SIGNALS, null, 2)}\n` } });
  assert.deepEqual(errorsOf(good), [], "positive control");
  const bad = copyOfGood(t, { files: { [SIGNALS]: JSON.stringify({ ...MINIMAL_SIGNALS, manifests: [] }) } });
  issueFor(errorsOf(bad), SIGNALS, "/manifests", /non-empty list of file names/);
});

test("the layer-signals file is required: a missing one is an error on the file, and the fixture has none", (t) => {
  assert.deepEqual(errorsOf(copyOfGood(t)), [], "positive control: the copy has the file");
  issueFor(errorsOf(copyOfGood(t, { remove: [SIGNALS] })), SIGNALS, "(file)", /is missing; the layer mapping reads it/);
  const fixtureErrors = errorsOf(GOOD);
  assert.deepEqual(fixtureErrors.map((item) => [item.file, item.field]), [[SIGNALS, "(file)"]], describeIssues(fixtureErrors));
});

test("a layer-signals file that is not valid JSON is reported once, by the data check", (t) => {
  const root = copyOfGood(t, { files: { [SIGNALS]: "{ \"manifests\": [ }" } });
  const errors = errorsOf(root).filter((item) => item.file === SIGNALS);
  assert.equal(errors.length, 1, describeIssues(errors));
  assert.equal(errors[0].field, "json");
});

test("a folder at the layer-signals path is an error on the file", (t) => {
  const root = copyOfGood(t, { remove: [SIGNALS] });
  fs.mkdirSync(path.join(root, SIGNALS));
  issueFor(errorsOf(root), SIGNALS, "(file)", /must be a regular file, not a folder/);
});

// data/injection-patterns.json ------------------------------------------------------------------------

test("an injection-patterns file is optional; a valid one gives no errors, and a bad one is an error on its field", (t) => {
  const file = "data/injection-patterns.json";
  const valid = fs.readFileSync(path.join(HARNESS_ROOT, file), "utf8");
  assert.deepEqual(errorsOf(copyOfGood(t)), [], "positive control: the copy has no such file, and needs none");
  assert.deepEqual(errorsOf(copyOfGood(t, { files: { [file]: valid } })), [], "positive control: the file of this repository");
  const bad = JSON.parse(valid);
  bad.categories[0].patterns[0].text = "Ignore  Previous";
  issueFor(errorsOf(copyOfGood(t, { files: { [file]: JSON.stringify(bad) } })), file, "/categories/0/patterns/0/text", /must be folded/);
  issueFor(errorsOf(copyOfGood(t, { files: { [file]: JSON.stringify([]) } })), file, "(root)", /must be an object/);
});

// Output order ---------------------------------------------------------------------------------------

test("the issues are sorted and do not depend on the order the files are written", (t) => {
  const files = {
    "data/b.json": "{ bad",
    "data/a.json": JSON.stringify({ items: [{ id: 1 }, { id: 1 }] }),
    [SOURCES]: "[]\n",
    [RULE_RUL01]: mutate(RULE_RUL01, "title: Generic rules the model already follows", 'title: ""')[RULE_RUL01],
  };
  const reversed = Object.fromEntries(Object.entries(files).reverse());
  const forward = copyOfGood(t, { files });
  const backward = copyOfGood(t, { files: reversed });

  const first = errorsOf(forward);
  const second = errorsOf(backward);
  assert.ok(first.length >= 4, describeIssues(first));
  assert.deepEqual(first, second);
  assert.deepEqual(errorsOf(forward), first, "a second run gives the same issues");

  const keys = first.map((item) => [item.file, item.field, item.message].join("\0"));
  assert.deepEqual(keys, [...keys].sort(), "issues are sorted by file, field and message");
});

// Command line ---------------------------------------------------------------------------------------

test("the command line exits 0 on a copy of the good fixture and prints one summary line", async (t) => {
  const result = await runCheck(["--root", copyOfGood(t)]);
  assert.equal(result.code, 0, result.stdout + result.stderr);
  const lines = result.stdout.trimEnd().split("\n");
  assert.match(lines.at(-1), /^catalog: 3 rules, 2 sources, 2 data files; 0 errors, \d+ warnings?$/);
  if (!fs.existsSync(MEASURED_FINDINGS)) {
    assert.ok(lines.includes(`warning: ${EMITTERS_FILE}: EMITTERS: EMITTERS is not available, so the check that every measured MVP rule has an emitter is skipped`));
  }
});

test("the command line exits 1 and prints file, field and message for each error", async (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_RUL01, "title: Generic rules the model already follows", 'title: ""') });
  const result = await runCheck(["--root", root]);
  assert.equal(result.code, 1, result.stdout + result.stderr);
  const lines = result.stdout.trimEnd().split("\n");
  assert.ok(lines.includes(`${RULE_RUL01}: title: must be a non-empty string`), result.stdout);
  assert.match(lines.at(-1), /; 1 error, \d+ warnings?$/);
});

test("the command line exits 0 on the repository", async () => {
  const result = await runCheck([]);
  assert.equal(result.code, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /; 0 errors, /);
});

test("the command line exits 2 for usage errors", async (t) => {
  const empty = makeFixture({});
  t.after(empty.cleanup);
  const cases = [
    ["--bogus"],
    ["extra-argument"],
    ["--root"],
    ["--root", ""],
    ["--root", path.join(empty.base, "missing")],
    ["--root", empty.root],
  ];
  for (const args of cases) {
    const result = await runCheck(args);
    assert.equal(result.code, 2, `${args.join(" ")}\n${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /usage: node scripts\/check-catalog\.mjs/);
  }
});

test("the command line gives the same output on repeated runs", async (t) => {
  const root = copyOfGood(t, { files: mutate(RULE_SEC02, "evidence: study", "evidence: atlas") });
  const first = await runCheck(["--root", root]);
  const second = await runCheck(["--root", root]);
  assert.equal(first.stdout, second.stdout);
  assert.equal(first.code, 1);
});

test("--root does not change where the emitters are read from", async (t) => {
  if (fs.existsSync(MEASURED_FINDINGS)) return; // Only meaningful while the harness has no emitter file.
  const root = copyOfGood(t, { files: { [EMITTERS_FILE]: "export const EMITTERS = 5;\n" } });
  const result = await runCheck(["--root", root]);
  assert.equal(result.code, 0, result.stdout + result.stderr);
  assert.ok(result.stdout.includes(`warning: ${EMITTERS_FILE}: EMITTERS:`), result.stdout);
});
