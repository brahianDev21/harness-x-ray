import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { toStableJson } from "../scripts/lib/json-out.mjs";
import { decide, decisionRules } from "../scripts/lib/permissions.mjs";
import { scan } from "../scripts/lib/scanner.mjs";
import { DEFAULT_MAX_BYTES } from "../scripts/lib/safe-fs.mjs";
import { MEASURE_ID, createUserLayerMeasure } from "../scripts/lib/user-layer.mjs";
import { recordOpens, within } from "./helpers/record-opens.mjs";
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";

const FIXED_NOW = new Date("2026-10-17T12:00:00.000Z");
const support = symlinkSupport();
const symlinkSkip = support.supported ? false : support.reason;
// Text that the user layer must never show: it sits in files that the measure does not read.
const WITNESS = "WITNESS-USER-LAYER-7f3a";
const SETTINGS_SHOWN = "~/.claude/settings.json";

const SETTINGS = {
  permissions: {
    allow: ["Bash(npm test)"],
    ask: ["Bash(git push:*)"],
    deny: ["Read(./secrets/**)"],
    defaultMode: "acceptEdits",
  },
  hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "node hook.mjs" }] }] },
};

const ABSENT_LAYER = {
  root: "~/.claude",
  found: false,
  memory: [],
  settings: {
    path: SETTINGS_SHOWN,
    found: false,
    permissions: { allow: [], ask: [], deny: [] },
    defaultMode: null,
    hooks: { count: 0, evaluated: false },
  },
  skills: [],
  subagents: [],
  warnings: [],
  notes: [],
};

// A target and a fake home in the system temp folder. The home is <base>/outside/home, which lies outside the target.
// The keys of claude are paths inside ~/.claude; their values are texts or Buffers.
function fixtureWith(t, claude = {}) {
  const outside = {};
  for (const [rel, content] of Object.entries(claude)) outside[`home/.claude/${rel}`] = content;
  const fixture = makeFixture({ files: { "README.md": "# Target\n" }, outside });
  t.after(fixture.cleanup);
  return { ...fixture, home: path.join(fixture.outsideDir, "home") };
}

// Scans the target with the user layer only, and returns the user layer section. Empty claude means no ~/.claude at all.
async function userLayerOf(t, claude) {
  const fixture = fixtureWith(t, claude);
  const result = await scanWith(fixture, [createUserLayerMeasure({ home: fixture.home })]);
  return result.userLayer;
}

function scanWith(fixture, measures) {
  return scan({ root: fixture.root, measures, now: FIXED_NOW });
}

// A measure that records what the user layer put in ctx.outside, for the permission measures to read.
function probeOutside(seen) {
  return {
    id: "probe",
    collect(ctx) {
      seen.outside = ctx.outside.get("user") ?? null;
      return {};
    },
  };
}

// A measure that decides each call with the rules that decisionRules gives it, as the permission measures do, and keeps the results.
function decideProbe(calls) {
  const results = [];
  return {
    results,
    measure: {
      id: "decide-probe",
      collect(ctx) {
        const rules = decisionRules({ allow: [], ask: [], deny: [] }, ctx.outside);
        for (const call of calls) results.push(decide(rules, call));
        return {};
      },
    },
  };
}

test("user layer: CLAUDE.md, rules, settings, skills and subagents are read, and every path starts with ~/.claude", async (t) => {
  const fixture = fixtureWith(t, {
    "CLAUDE.md": "# Mine\n\nAnswer briefly.\n\n@~/notes/extra.md\n",
    "rules/always.md": "Always rule.\n",
    "rules/nested/scoped.md": '---\npaths: ["src/**"]\n---\nScoped rule.\n',
    "settings.json": JSON.stringify(SETTINGS, null, 2),
    "skills/review/SKILL.md": "---\nname: review\ndescription: Reviews code\n---\nBody.\n",
    "agents/helper.md": "---\nname: helper\ndescription: Helps\ntools: Read\n---\nBody.\n",
    // Decoys: none of these may be read or listed.
    "projects/p/x.jsonl": `{"text":"${WITNESS}"}\n`,
    "history.jsonl": `${WITNESS}\n`,
    "todos/t.json": `{"text":"${WITNESS}"}\n`,
    ".credentials.json": `{"token":"${WITNESS}"}\n`,
  });
  const seen = {};
  const claudeReal = fs.realpathSync(path.join(fixture.home, ".claude"));
  const opened = recordOpens(t);
  const result = await scanWith(fixture, [createUserLayerMeasure({ home: fixture.home }), probeOutside(seen)]);
  const layer = result.userLayer;

  // Only the files that the measure reads are opened under ~/.claude. Each decoy (projects, history, todos, credentials) is
  // never opened, so its text cannot reach the output whatever the output holds.
  const openedUnderClaude = opened.filter((file) => within(claudeReal, file)).map((file) => path.relative(claudeReal, file));
  assert.deepEqual(
    [...new Set(openedUnderClaude.map((rel) => rel.split(path.sep).join("/")))].sort(),
    [
      "CLAUDE.md",
      "agents/helper.md",
      "rules/always.md",
      "rules/nested/scoped.md",
      "settings.json",
      "skills/review/SKILL.md",
    ],
    "exactly the files of the layer are opened, and no decoy",
  );

  assert.equal(layer.found, true);
  assert.equal(layer.root, "~/.claude");
  assert.deepEqual(
    layer.memory.map((item) => [item.path, item.kind, item.loadMode]),
    [
      ["~/.claude/CLAUDE.md", "memory", "always"],
      ["~/.claude/rules/always.md", "rule", "always"],
      ["~/.claude/rules/nested/scoped.md", "rule", "on-demand"],
    ],
  );
  assert.equal(layer.memory[0].lines, 5);
  assert.deepEqual(layer.settings, {
    path: SETTINGS_SHOWN,
    found: true,
    lines: JSON.stringify(SETTINGS, null, 2).split("\n").length,
    permissions: {
      allow: [{ rule: "Bash(npm test)", source: SETTINGS_SHOWN }],
      ask: [{ rule: "Bash(git push:*)", source: SETTINGS_SHOWN }],
      deny: [{ rule: "Read(./secrets/**)", source: SETTINGS_SHOWN }],
    },
    defaultMode: { value: "acceptEdits", source: SETTINGS_SHOWN, applied: false },
    hooks: { count: 1, evaluated: false },
  });
  assert.deepEqual(layer.skills, [{ path: "~/.claude/skills/review/SKILL.md", name: "review", loadMode: "always" }]);
  assert.deepEqual(layer.subagents, [{ path: "~/.claude/agents/helper.md", name: "helper", loadMode: "always" }]);
  assert.deepEqual(layer.notes, [
    "default-mode-not-applied",
    "hooks-not-evaluated",
    "imports-not-followed",
    "layer-precedence-not-verified",
  ]);
  assert.deepEqual(layer.warnings, []);
  // ctx.outside keeps the raw rule text for matching, and the shown text of the same rule for the results.
  assert.deepEqual(seen.outside, {
    permissions: {
      allow: [{ rule: "Bash(npm test)", shown: "Bash(npm test)", source: SETTINGS_SHOWN }],
      ask: [{ rule: "Bash(git push:*)", shown: "Bash(git push:*)", source: SETTINGS_SHOWN }],
      deny: [{ rule: "Read(./secrets/**)", shown: "Read(./secrets/**)", source: SETTINGS_SHOWN }],
    },
  }, "the permission lists go to ctx.outside");

  const text = toStableJson(layer);
  assert.equal(text.includes(WITNESS), false, "the witness of the decoy files is never read");
  for (const decoy of ["x.jsonl", "history.jsonl", "todos", "credentials"]) {
    assert.equal(text.includes(decoy), false, `${decoy} is never listed`);
  }
});

test("user layer: without ~/.claude the layer is absent, and the permission lists handed over are empty", async (t) => {
  const fixture = fixtureWith(t, {});
  const seen = {};

  const result = await scanWith(fixture, [createUserLayerMeasure({ home: fixture.home }), probeOutside(seen)]);

  assert.deepEqual(result.userLayer, ABSENT_LAYER);
  assert.deepEqual(seen.outside, { permissions: { allow: [], ask: [], deny: [] } });
});

test("user layer: invalid settings JSON is a warning with empty lists, and a valid file still gives its rules", async (t) => {
  const broken = await userLayerOf(t, { "settings.json": '{"permissions": {"allow": ["Bash(npm test)"]' });

  assert.equal(broken.settings.found, true);
  assert.deepEqual(broken.settings.permissions, { allow: [], ask: [], deny: [] });
  assert.deepEqual(broken.warnings, [{ source: "user-layer", path: SETTINGS_SHOWN, reason: "invalid-json" }]);

  const valid = await userLayerOf(t, { "settings.json": JSON.stringify({ permissions: { allow: ["Bash(npm test)"] } }) });
  assert.deepEqual(valid.settings.permissions.allow, [{ rule: "Bash(npm test)", source: SETTINGS_SHOWN }], "positive control");
  assert.deepEqual(valid.warnings, []);
});

test("user layer: non-string rules and a wrong permissions list are warnings, and the strings that are fine still apply", async (t) => {
  const layer = await userLayerOf(t, {
    "settings.json": JSON.stringify({ permissions: { allow: [1, "Bash(ls)"], deny: "Read(x)" } }),
  });

  assert.deepEqual(layer.settings.permissions.allow, [{ rule: "Bash(ls)", source: SETTINGS_SHOWN }]);
  assert.deepEqual(layer.settings.permissions.deny, []);
  assert.deepEqual(layer.warnings, [
    { source: "user-layer", path: SETTINGS_SHOWN, reason: "unexpected-shape", detail: "permissions.allow" },
    { source: "user-layer", path: SETTINGS_SHOWN, reason: "unexpected-shape", detail: "permissions.deny" },
  ]);
});

test("user layer: a rule that is a link to a file outside ~/.claude is refused, and the file is never read", { skip: symlinkSkip }, async (t) => {
  const fixture = fixtureWith(t, { "rules/always.md": "Always rule.\n" });
  fs.writeFileSync(path.join(fixture.outsideDir, "leak-secret.md"), `${WITNESS}\n`);
  fs.symlinkSync(path.join(fixture.outsideDir, "leak-secret.md"), path.join(fixture.home, ".claude", "rules", "leak.md"));

  const result = await scanWith(fixture, [createUserLayerMeasure({ home: fixture.home })]);

  assert.deepEqual(
    result.userLayer.memory.map((item) => item.path),
    ["~/.claude/rules/always.md"],
    "positive control: the regular rule is read",
  );
  assert.deepEqual(result.userLayer.warnings, [{ source: "fs", path: "~/.claude/rules/leak.md", reason: "outside-root" }]);
  assert.equal(toStableJson(result.userLayer).includes(WITNESS), false);
});

test("user layer: a CLAUDE.md over the 4 MiB cap is a too-large warning and is not counted, and a small rule is still read", async (t) => {
  const layer = await userLayerOf(t, {
    "CLAUDE.md": Buffer.alloc(DEFAULT_MAX_BYTES + 1, 0x61),
    "rules/small.md": "Small rule.\n",
  });

  assert.deepEqual(
    layer.memory.map((item) => item.path),
    ["~/.claude/rules/small.md"],
    "positive control: the small rule is read",
  );
  assert.deepEqual(layer.warnings, [{ source: "fs", path: "~/.claude/CLAUDE.md", reason: "too-large" }]);
});

test("user layer: a rule that names the home folder shows it as ~/, and the other rule is unchanged", async (t) => {
  const fixture = fixtureWith(t, { "CLAUDE.md": "# Mine\n" });
  // The settings file is written after the fixture, because its text needs the home folder that the fixture chose.
  const settings = { permissions: { allow: [`Read(${path.join(fixture.home, "notes")}/**)`, "Bash(npm test)"] } };
  fs.writeFileSync(path.join(fixture.home, ".claude", "settings.json"), JSON.stringify(settings));

  const result = await scanWith(fixture, [createUserLayerMeasure({ home: fixture.home })]);

  assert.deepEqual(result.userLayer.settings.permissions.allow, [
    { rule: "Bash(npm test)", source: SETTINGS_SHOWN },
    { rule: "Read(~/notes/**)", source: SETTINGS_SHOWN },
  ]);
  assert.equal(toStableJson(result.userLayer).includes(fixture.home), false, "the home folder is not written");
});

test("user layer: a user rule with an absolute path of the target is undeterminable, the result shows its redacted text, and no raw path", async (t) => {
  const fixture = fixtureWith(t, { "CLAUDE.md": "# Mine\n" });
  // The settings file is written after the fixture, because its rule needs the target folder that the fixture chose.
  const absolute = `Read(${path.join(fixture.root, "x")})`;
  fs.writeFileSync(path.join(fixture.home, ".claude", "settings.json"), JSON.stringify({ permissions: { deny: [absolute, "Read(./notes/**)"] } }));
  const probe = decideProbe([
    { tool: "Read", path: "x" },
    { tool: "Read", path: "notes/a.md" },
  ]);

  await scanWith(fixture, [createUserLayerMeasure({ home: fixture.home }), probe.measure]);
  const [absoluteResult, relativeResult] = probe.results;

  // Before the fix, the redacted text was matched as a relative pattern, so this call was silently "default".
  assert.deepEqual(absoluteResult, {
    decision: "undeterminable",
    rule: "Read(<target>/x)",
    source: SETTINGS_SHOWN,
    reason: "anchor-unknown",
    list: "deny",
    layer: "user",
  });
  assert.deepEqual(
    relativeResult,
    { decision: "deny", rule: "Read(./notes/**)", source: SETTINGS_SHOWN, reason: "deny-rule", list: "deny", layer: "user" },
    "positive control: a relative user rule decides as before, and its shown text is its rule",
  );
  const text = JSON.stringify(probe.results);
  assert.equal(text.includes(fixture.root), false, "the target folder is not in a result");
  assert.equal(text.includes(fixture.home), false, "the home folder is not in a result");
});

test("createUserLayerMeasure: a home that is not an absolute folder is refused, and an absolute one is accepted", () => {
  assert.throws(() => createUserLayerMeasure({ home: "relative/home" }), TypeError);
  assert.throws(() => createUserLayerMeasure({ home: 42 }), TypeError);
  assert.equal(createUserLayerMeasure({ home: path.resolve("fake-home") }).id, MEASURE_ID, "positive control");
});
