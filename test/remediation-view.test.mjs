// Tests of lib/remediation-view.mjs: the blocks of a remediation, their Markdown and HTML, the escaping of an agent's text, and
// the label keys that the view reads. The remediation here is a hand-made object with every fixed code, so that each label of
// the section is rendered; the scans are covered by test/remediation.test.mjs.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { buildRemediationBlocks } from "../scripts/lib/remediation-view.mjs";
import { blocksMarkdown } from "../scripts/lib/report.mjs";
import { blocksHtml } from "../scripts/lib/report-html.mjs";
import { escapeMarkdown } from "../scripts/lib/report-markdown.mjs";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const LABELS = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "templates", "labels.en.json"), "utf8"));
const LABELS_ES = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "templates", "labels.es.json"), "utf8"));

const NOT_VERIFIED = ["auto", "bypassPermissions"];
const MODES_PASS = { default: "passes", acceptEdits: "passes", auto: "passes", bypassPermissions: "passes" };
const MODES_ASK = { default: "asks", acceptEdits: "asks", auto: "asks", bypassPermissions: "asks" };
const MODES_CLASSIFIER = { default: "asks", acceptEdits: "passes", auto: "classifier", bypassPermissions: "passes" };
const OMITTED_ZERO = { cap: 200, fragments: 0, commands: 0, reads: 0, notSimulated: 0 };

// A remediation with one row or fragment for each fixed code of the view: every rule, origin, result and reason.
function everyCode() {
  const settings = { permissions: { deny: ["Bash(rm -rf *)"], ask: ["Bash(git push --force *)"] } };
  // A run of three backticks in a rule: a fence of three would end inside it, so the block takes a fence of four.
  const agentSettings = { permissions: { deny: ["Bash(echo ``` *)"], ask: [] } };
  return {
    schemaVersion: 1,
    scan: { scannedAt: "2026-10-18T12:00:00.000Z", target: "fixture" },
    mode: "acceptEdits",
    fragments: [
      { id: "fr-1", origin: "measured", rule: "SEC-01", measuredFindingId: "mf-1", kind: "permissions", settings, title: null, text: null, coverNote: null, targets: [{ kind: "command", id: "git-push-force-long" }], simulated: true, reason: null },
      { id: "fr-2", origin: "measured", rule: "SEC-02", measuredFindingId: null, kind: "permissions", settings: { permissions: { deny: [], ask: ["Bash(npm publish *)"] } }, title: null, text: null, coverNote: "Covers every npm publish, with any arguments after it.", targets: [{ kind: "command", id: "npm-publish" }], simulated: false, reason: "simulation-mismatch" },
      { id: "fr-3", origin: "measured", rule: "SEC-03", measuredFindingId: "mf-4", kind: "permissions", settings: { permissions: { deny: ["Read(./config/server.pem)"], ask: [] } }, title: null, text: null, coverNote: null, targets: [{ kind: "read", path: "config/server.pem" }], simulated: true, reason: null },
      { id: "fr-4", origin: "measured", rule: "SEC-03", measuredFindingId: null, kind: "permissions", settings: null, title: null, text: null, coverNote: null, targets: [{ kind: "read", path: "a b*c" }], simulated: false, reason: "unsupported-path" },
      { id: "fr-5", origin: "agent", rule: "SEC-05", measuredFindingId: null, kind: "other", settings: null, title: "A *title* with _marks_", text: "See [this](x) and <b>tags</b>.", coverNote: null, targets: [], simulated: false, reason: "not-permission" },
      { id: "fr-6", origin: "agent", rule: "SEC-05", measuredFindingId: null, kind: "permissions", settings: agentSettings, title: "Fenced rule", text: "A rule with a backtick.", coverNote: null, targets: [], simulated: true, reason: null },
      { id: "fr-7", origin: "agent", rule: "SEC-05", measuredFindingId: null, kind: "permissions", settings: { permissions: { deny: ["WebFetch(domain:example.com)"], ask: [] } }, title: "Fetch", text: "A fetch rule.", coverNote: null, targets: [], simulated: false, reason: "not-modelled-rule" },
      { id: "fr-8", origin: "agent", rule: "SEC-05", measuredFindingId: null, kind: "permissions", settings: { permissions: { deny: ["Read(~/.ssh/**)"], ask: [] } }, title: "Home", text: "A home path.", coverNote: null, targets: [], simulated: false, reason: "undecidable-rule" },
      { id: "fr-9", origin: "agent", rule: "SEC-05", measuredFindingId: null, kind: "permissions", settings: { permissions: { deny: [], ask: [] } }, title: "Empty", text: "No rule.", coverNote: null, targets: [], simulated: false, reason: "no-rule" },
    ],
    commands: [
      { id: "git-push-force-long", command: "git push --force", measured: { outcome: "passes", modes: MODES_PASS }, after: { outcome: "asks", modes: MODES_ASK }, notVerified: NOT_VERIFIED, result: "moved", reason: null },
      { id: "git-reset-hard", command: "git reset --hard", measured: { outcome: "passes", modes: MODES_PASS }, after: { outcome: "passes", modes: MODES_PASS }, notVerified: NOT_VERIFIED, result: "still-passes", reason: null },
      { id: "rm-recursive-force", command: "rm -rf build", measured: { outcome: "asks", modes: MODES_CLASSIFIER }, after: { outcome: "asks", modes: MODES_ASK }, notVerified: NOT_VERIFIED, result: "unchanged", reason: null },
      { id: "chmod-recursive-777", command: "chmod -R 777 build", measured: { outcome: "undeterminable", modes: null }, after: { outcome: "undeterminable", modes: MODES_ASK }, notVerified: [], result: "undeterminable", reason: null },
      { id: "npm-publish", command: "npm publish", measured: { outcome: "asks", modes: null }, after: null, notVerified: [], result: "not-simulated", reason: "no-matrix" },
      { id: "docker-system-prune", command: "docker system prune -af", measured: { outcome: "asks", modes: MODES_ASK }, after: null, notVerified: NOT_VERIFIED, result: "not-simulated", reason: "not-in-data" },
      { id: "cmd-del-recurse-quiet", command: "cmd /c del /s /q build", measured: { outcome: "asks", modes: MODES_ASK }, after: null, notVerified: NOT_VERIFIED, result: "not-simulated", reason: "simulation-mismatch" },
      { id: "cmd-classifier", command: "make build", measured: { outcome: "passes", modes: MODES_CLASSIFIER }, after: { outcome: "asks", modes: MODES_CLASSIFIER }, notVerified: NOT_VERIFIED, result: "classifier", reason: null },
    ],
    reads: [
      { path: "config/server.pem", measured: "default", after: "deny", result: "moved", reason: null },
      { path: "CLAUDE.md", measured: "deny", after: "deny", result: "unchanged", reason: null },
      { path: "keys/id.key", measured: "undeterminable", after: "undeterminable", result: "undeterminable", reason: null },
      { path: "ask.env", measured: "ask", after: "ask", result: "still-readable", reason: null },
      { path: "a b*c", measured: "default", after: null, result: "not-simulated", reason: "unsupported-path" },
      { path: "x.pem", measured: "default", after: null, result: "not-simulated", reason: "simulation-mismatch" },
    ],
    notSimulated: [
      { rule: "SEC-03", kind: "literal-secret", file: "CLAUDE.md", line: 3, location: "text", secretKind: "anthropic-api-key", reason: "literal-secret" },
      { rule: "SEC-03", kind: "literal-secret", file: "config/notes.md", line: null, location: "text", secretKind: "generic-assignment", reason: "literal-secret" },
    ],
    omitted: { cap: 200, fragments: 3, commands: 0, reads: 0, notSimulated: 1 },
    summary: {
      fragments: 9, measuredFragments: 4, agentFragments: 5, simulatedFragments: 2, notSimulatedFragments: 7, commandsPassingToday: 3,
      commandsMoved: 1, commandsStillPassing: 1, commandsNotSimulated: 3, readsMoved: 1, readsNotSimulated: 2, notSimulatedItems: 2,
    },
  };
}

const EMPTY = {
  schemaVersion: 1,
  scan: { scannedAt: "2026-10-18T12:00:00.000Z", target: "fixture" },
  mode: null,
  fragments: [],
  commands: [],
  reads: [],
  notSimulated: [],
  omitted: OMITTED_ZERO,
  summary: {
    fragments: 0, measuredFragments: 0, agentFragments: 0, simulatedFragments: 0, notSimulatedFragments: 0,
    commandsPassingToday: 0, commandsMoved: 0, commandsStillPassing: 0, commandsNotSimulated: 0, readsMoved: 0,
    readsNotSimulated: 0, notSimulatedItems: 0,
  },
};

// The labels with a record of the keys that are read. The view reads a key only when it renders it.
function recording(labels, used) {
  return new Proxy(labels, {
    get(target, key, receiver) {
      if (typeof key === "string") used.add(key);
      return Reflect.get(target, key, receiver);
    },
  });
}

describe("the blocks of a remediation", () => {
  test("the section starts with its title at the given level, and the parts below it one level down", () => {
    const blocks = buildRemediationBlocks(everyCode(), { labels: LABELS, level: 2 });
    assert.equal(blocks[0].type, "heading");
    assert.equal(blocks[0].level, 2);
    const headings = blocks.filter((block) => block.type === "heading");
    assert.ok(headings.some((block) => block.level === 3), "the fragments section is level 3");
    assert.ok(headings.some((block) => block.level === 4), "a fragment is level 4");
    assert.ok(headings.every((block) => block.level >= 2 && block.level <= 4), "the report's heading levels");
  });

  test("the labels of the language are used: every remediation key of the labels is read", () => {
    const used = new Set();
    const labels = recording(LABELS, used);
    buildRemediationBlocks(everyCode(), { labels, level: 1 });
    buildRemediationBlocks(EMPTY, { labels, level: 1 });
    const keys = Object.keys(LABELS).filter((key) => key.startsWith("remediation."));
    assert.deepEqual(keys.filter((key) => !used.has(key)), [], "remediation label keys that no block reads");
  });

  test("the Spanish labels give the same keys as the English ones", () => {
    assert.deepEqual(
      Object.keys(LABELS_ES).filter((key) => key.startsWith("remediation.")).sort(),
      Object.keys(LABELS).filter((key) => key.startsWith("remediation.")).sort(),
    );
    const blocks = buildRemediationBlocks(everyCode(), { labels: LABELS_ES, level: 1 });
    assert.ok(blocksMarkdown(blocks).includes(LABELS_ES["remediation.intro"]));
  });

  test("a remediation without fragments says so, and the tables are still there", () => {
    const markdown = blocksMarkdown(buildRemediationBlocks(EMPTY, { labels: LABELS, level: 1 }));
    assert.ok(markdown.includes(LABELS["remediation.fragments.none"]));
    assert.ok(markdown.includes(LABELS["remediation.hooks"]));
  });
});

describe("the Markdown view of a remediation", () => {
  const markdown = () => blocksMarkdown(buildRemediationBlocks(everyCode(), { labels: LABELS, level: 1 }));

  test("the document starts with its title, and says that nothing is applied", () => {
    const text = markdown();
    assert.ok(text.startsWith(`# ${LABELS["remediation.title"]}`));
    assert.ok(text.includes(LABELS["remediation.limit.apply"]));
  });

  test("an agent's text is escaped, so that its markup reads as written", () => {
    const text = markdown();
    assert.ok(text.includes("A \\*title\\* with \\_marks\\_"), "the title is escaped");
    assert.ok(text.includes("See \\[this\\]\\(x\\) and \\<b\\>tags\\<\\/b\\>\\."), "the link and the tags are escaped");
    assert.ok(!text.includes("<b>tags</b>"), "no raw markup from the agent");
  });

  test("an agent's text is one line: a run of whitespace, line breaks included, is one space (positive control: the escaped text)", () => {
    const remediation = everyCode();
    remediation.fragments[4] = { ...remediation.fragments[4], title: "ok\n\n    x", text: "a\tb\r\n  c" };
    const text = blocksMarkdown(buildRemediationBlocks(remediation, { labels: LABELS, level: 1 }));
    assert.ok(text.includes("ok x"), "the title is one line");
    assert.ok(text.includes("a b c"), "the text is one line");
    assert.ok(!text.includes("\n    x"), "the text does not start an indented line, which would be a code block");
    assert.ok(!text.includes("ok\n"), "the title does not end its line");
    assert.ok(text.includes("A rule with a backtick\\."), "positive control: an untouched agent text is still escaped");
  });

  test("a code block is fenced longer than any backtick run in it", () => {
    const text = markdown();
    assert.ok(text.includes("\n````\n{\n  \"permissions\": {\n    \"deny\": [\n      \"Bash(echo ``` *)\""), "a block with a run of three backticks takes a four-backtick fence");
    assert.ok(text.includes("\n```\n{\n  \"permissions\": {\n    \"deny\": [\n      \"Bash(rm -rf *)\""), "a block without such a run takes a three-backtick fence");
  });

  test("a table cell escapes a pipe, and a row has one cell per header", () => {
    const text = blocksMarkdown(
      buildRemediationBlocks({ ...EMPTY, reads: [{ path: "a|b", measured: "default", after: null, result: "not-simulated", reason: "unsupported-path" }] }, { labels: LABELS, level: 1 }),
    );
    assert.ok(text.includes("a\\|b"));
  });

  test("the modes that are not verified are marked in the header and in each of their cells, and no other mode is", () => {
    const text = markdown();
    assert.ok(text.includes(`\`auto\` ${LABELS["remediation.notVerified"]}`), "the auto header is marked");
    assert.ok(text.includes(`\`bypassPermissions\` ${LABELS["remediation.notVerified"]}`), "the bypassPermissions header is marked");
    assert.ok(text.includes("`passes → asks` (not verified)"), "a cell of a marked mode is marked");
    assert.ok(!text.includes("`acceptEdits` (not verified)"), "acceptEdits is not marked");
    assert.ok(!text.includes("`default` (not verified)"), "default is not marked");
  });

  test("the summary says that the moves are not verified in auto and bypassPermissions, and the omitted count is written", () => {
    const text = markdown();
    assert.ok(
      text.includes(
        "9 fragments: 2 simulated, 7 not simulated. Destructive commands that pass today: 3. In the simulation with the patch applied: 1 move off passing (not verified in auto and bypassPermissions), 1 still pass, 3 are not simulated.",
      ),
      "the summary is written, with its moved count marked",
    );
    assert.ok(text.includes("Left out, because each list holds at most 200 items: 3 fragments, 0 commands, 0 secret reads and 1 literal secrets"));
  });

  test("a fragment's coverNote is shown as the scope of its rule", () => {
    const text = markdown();
    assert.ok(text.includes(`${LABELS["remediation.field.scope"]}`), "the scope field is labelled");
    assert.ok(text.includes("Covers every npm publish, with any arguments after it."), "the note is written as it is");
  });

  test("escapeMarkdown escapes every ASCII punctuation character and leaves letters and digits", () => {
    assert.equal(escapeMarkdown("a1 *b* [c] <d>"), "a1 \\*b\\* \\[c\\] \\<d\\>");
    assert.equal(escapeMarkdown("plain text 42"), "plain text 42");
  });
});

describe("the HTML view of a remediation", () => {
  const html = () => blocksHtml(buildRemediationBlocks(everyCode(), { labels: LABELS, level: 2 }));

  test("the settings are a preformatted code block, and an agent's text is escaped", () => {
    const text = html();
    assert.ok(text.includes("<pre><code>{\n  &quot;"), "a settings block, escaped");
    assert.ok(text.includes("See [this](x) and &lt;b&gt;tags&lt;/b&gt;."), "the agent's text, escaped");
    assert.ok(!text.includes("<b>tags</b>"));
    assert.ok(text.includes("<h2>"), "the title is a level-2 heading");
  });

  test("the agent's text is one line in the HTML view too", () => {
    const remediation = everyCode();
    remediation.fragments[4] = { ...remediation.fragments[4], title: "ok\n\n    x", text: "one\ntwo" };
    const text = blocksHtml(buildRemediationBlocks(remediation, { labels: LABELS, level: 2 }));
    assert.ok(text.includes("ok x"));
    assert.ok(text.includes("one two"));
    assert.ok(!text.includes("ok\n"));
  });

  test("the omitted count and the not-verified marks are in the HTML view", () => {
    const text = html();
    assert.ok(text.includes("Left out, because each list holds at most 200 items"));
    assert.ok(text.includes(`<code>auto</code> ${LABELS["remediation.notVerified"]}`));
  });

  test("a list and a table of the section are written with their elements", () => {
    const text = html();
    assert.ok(text.includes("<ul><li>"));
    assert.ok(text.includes('<div class="table-wrap" tabindex="0"><table>'));
  });
});
