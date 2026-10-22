import assert from "node:assert/strict";
import path from "node:path";
import { test } from "node:test";
import { claudeConfigMeasure } from "../scripts/lib/claude-config.mjs";
import { createLayerContextMeasure, layerFolderProblem } from "../scripts/lib/layer-context.mjs";
import { countsOf, createMemoryMeasure } from "../scripts/lib/memory.mjs";
import { scan } from "../scripts/lib/scanner.mjs";
import { estimateTokens } from "../scripts/lib/tokens.mjs";
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";

const FIXED_NOW = new Date("2026-10-17T12:00:00.000Z");
const WEB = { name: "web", folders: ["apps/web"] };
const API = { name: "api", folders: ["apps/api"] };
const support = symlinkSupport();
const symlinkSkip = support.supported ? false : support.reason;

// A fixture with the given files, removed when the test ends.
function fixtureOf(t, files, extra = {}) {
  const fixture = makeFixture({ files, ...extra });
  t.after(fixture.cleanup);
  return fixture;
}

// Scans the fixture with the memory and claude-config measures, then the layer-context measure. The ancestor walk stops at the
// fixture folder and the home folder does not exist, so nothing outside the fixture is read. Returns context.byLayer.
async function byLayerOf(t, files, layers, extra) {
  const fixture = fixtureOf(t, files, extra);
  const result = await scan({
    root: fixture.root,
    measures: [
      claudeConfigMeasure,
      createMemoryMeasure({ ancestorLimit: fixture.base, home: path.join(fixture.base, "no-home") }),
      createLayerContextMeasure({ layers }),
    ],
    now: FIXED_NOW,
  });
  return result.context.byLayer;
}

const layerNamed = (byLayer, name) => byLayer.find((layer) => layer.name === name);
const onDemandPaths = (layer) => layer.onDemand.items.map((item) => item.path);
const nestedPaths = (layer) => layer.nestedSkills.items.map((item) => item.path);
const notCountedOf = (layer) => layer.notCounted.map((item) => [item.path, item.reason]);
const SKILL = (description) => `---\nname: x\ndescription: ${description}\n---\nBody.\n`;

// The acceptance case: a nested CLAUDE.md in one layer adds the file to that layer, and the other layer does not list it.
test("layer-context: apps/web/CLAUDE.md is on demand in the web layer, and not in the api layer", async (t) => {
  const text = "# Web\n\nUse the web conventions.\n";
  const byLayer = await byLayerOf(
    t,
    {
      "CLAUDE.md": "# Root\n\nRoot memory.\n",
      "apps/web/CLAUDE.md": text,
      "apps/web/src/index.ts": "export {};\n",
      "apps/api/server.ts": "export {};\n",
    },
    [WEB, API],
  );

  const web = layerNamed(byLayer, "web");
  const api = layerNamed(byLayer, "api");
  assert.deepEqual(web.onDemand.items, [{ path: "apps/web/CLAUDE.md", kind: "memory", estTokens: countsOf(text).estTokens }]);
  assert.equal(web.onDemand.estTokens, countsOf(text).estTokens);
  assert.deepEqual(api.onDemand, { estTokens: 0, items: [] }, "the api layer does not add the web file");
});

test("layer-context: a CLAUDE.md of apps counts for both layers, because a folder on the way down loads it", async (t) => {
  const byLayer = await byLayerOf(
    t,
    {
      "apps/CLAUDE.md": "# Apps\n",
      "apps/web/src/index.ts": "export {};\n",
      "apps/api/server.ts": "export {};\n",
    },
    [WEB, API],
  );

  assert.deepEqual(onDemandPaths(layerNamed(byLayer, "web")), ["apps/CLAUDE.md"]);
  assert.deepEqual(onDemandPaths(layerNamed(byLayer, "api")), ["apps/CLAUDE.md"]);
});

test("layer-context: the layer of the root counts every subfolder CLAUDE file, and never the root files", async (t) => {
  const byLayer = await byLayerOf(
    t,
    {
      "CLAUDE.md": "# Root\n",
      "CLAUDE.local.md": "# Local root\n",
      "AGENTS.md": "# Agents\n",
      "apps/CLAUDE.md": "# Apps\n",
      "apps/web/CLAUDE.local.md": "# Web local\n",
      "apps/web/.claude/CLAUDE.md": "# Hidden in a .claude folder\n",
      "apps/web/src/index.ts": "export {};\n",
    },
    [{ name: "all", folders: ["."] }],
  );

  const all = layerNamed(byLayer, "all");
  assert.deepEqual(onDemandPaths(all), ["apps/CLAUDE.md", "apps/web/CLAUDE.local.md"]);
  assert.deepEqual(all.notCounted, [], "a file under a .claude folder is not a subfolder memory file, so it is not listed either");
  // Positive control: the same root without the file that is under a .claude folder still counts the other two.
  const plain = await byLayerOf(t, { "apps/CLAUDE.md": "# Apps\n", "apps/web/src/index.ts": "export {};\n" }, [
    { name: "all", folders: ["."] },
  ]);
  assert.deepEqual(onDemandPaths(layerNamed(plain, "all")), ["apps/CLAUDE.md"]);
});

test("layer-context: a rule with a paths field counts for the layer its pattern matches, and only for that one", async (t) => {
  const byLayer = await byLayerOf(
    t,
    {
      ".claude/rules/web.md": "---\npaths: apps/web/**\n---\nWeb rule.\n",
      ".claude/rules/api.md": "---\npaths:\n  - apps/api/**\n---\nApi rule.\n",
      ".claude/rules/always.md": "# Always loaded\n",
      "apps/web/src/index.ts": "export {};\n",
      "apps/api/server.ts": "export {};\n",
    },
    [WEB, API],
  );

  const web = layerNamed(byLayer, "web");
  const api = layerNamed(byLayer, "api");
  assert.deepEqual(onDemandPaths(web), [".claude/rules/web.md"]);
  assert.deepEqual(web.onDemand.items[0], { path: ".claude/rules/web.md", kind: "rule", estTokens: countsOf("---\npaths: apps/web/**\n---\nWeb rule.\n").estTokens });
  assert.deepEqual(onDemandPaths(api), [".claude/rules/api.md"], "a list of patterns works too");
  assert.equal(byLayer.some((layer) => onDemandPaths(layer).includes(".claude/rules/always.md")), false, "a rule without paths is not on demand");
});

test("layer-context: a rule whose pattern cannot be read is not counted, and is listed as unsupported-pattern", async (t) => {
  const byLayer = await byLayerOf(
    t,
    {
      ".claude/rules/odd.md": '---\npaths: "apps/[web]/**"\n---\nOdd rule.\n',
      "apps/web/src/index.ts": "export {};\n",
      "apps/api/server.ts": "export {};\n",
    },
    [WEB, API],
  );

  assert.deepEqual(notCountedOf(layerNamed(byLayer, "web")), [[".claude/rules/odd.md", "unsupported-pattern"]]);
  assert.deepEqual(notCountedOf(layerNamed(byLayer, "api")), [[".claude/rules/odd.md", "unsupported-pattern"]]);
  assert.deepEqual(onDemandPaths(layerNamed(byLayer, "web")), []);
});

test("layer-context: an unsupported pattern does not stop a rule that another pattern matches (positive control)", async (t) => {
  const byLayer = await byLayerOf(
    t,
    {
      ".claude/rules/mixed.md": '---\npaths:\n  - "apps/[web]/**"\n  - "apps/web/**"\n---\nMixed rule.\n',
      "apps/web/src/index.ts": "export {};\n",
    },
    [WEB],
  );

  const web = layerNamed(byLayer, "web");
  assert.deepEqual(onDemandPaths(web), [".claude/rules/mixed.md"]);
  assert.deepEqual(web.notCounted, []);
});

test("layer-context: a CLAUDE file that claudeMdExcludes matches is listed as claude-md-excludes, and is not read", async (t) => {
  const byLayer = await byLayerOf(
    t,
    {
      ".claude/settings.json": JSON.stringify({ claudeMdExcludes: ["apps/web/CLAUDE.md", "apps/web/vendor/CLAUDE.md"] }),
      // A binary file that is excluded: it is listed as excluded, not as binary, so it was never read.
      "apps/web/CLAUDE.md": "\u0000binary\n",
      "apps/web/vendor/CLAUDE.md": "# Vendor\n",
      "apps/web/notes/CLAUDE.md": "# Notes\n",
      "apps/web/src/index.ts": "export {};\n",
    },
    [WEB],
  );

  const web = layerNamed(byLayer, "web");
  assert.deepEqual(notCountedOf(web), [
    ["apps/web/CLAUDE.md", "claude-md-excludes"],
    ["apps/web/vendor/CLAUDE.md", "claude-md-excludes"],
  ]);
  // Positive control: the file that no pattern matches counts.
  assert.deepEqual(onDemandPaths(web), ["apps/web/notes/CLAUDE.md"]);
});

test("layer-context: a CLAUDE file that cannot be read is listed with its safe-fs reason, and a readable one counts (positive control)", async (t) => {
  const byLayer = await byLayerOf(
    t,
    {
      "apps/web/src/CLAUDE.md": "\u0000binary\n",
      "apps/web/notes/CLAUDE.md": "# Notes\n",
      "apps/web/src/index.ts": "export {};\n",
    },
    [WEB],
  );

  const web = layerNamed(byLayer, "web");
  assert.deepEqual(notCountedOf(web), [["apps/web/src/CLAUDE.md", "binary"]]);
  assert.deepEqual(onDemandPaths(web), ["apps/web/notes/CLAUDE.md"]);
});

test("layer-context: a nested skill counts in the layer it belongs to, and an inherited one counts in both layers", async (t) => {
  const description = "The x skill.";
  const byLayer = await byLayerOf(
    t,
    {
      "apps/web/.claude/skills/x/SKILL.md": SKILL(description),
      "apps/.claude/skills/shared/SKILL.md": SKILL("The shared skill."),
      "apps/api/src/index.ts": "export {};\n",
      "apps/web/src/index.ts": "export {};\n",
    },
    [WEB, API],
  );

  const web = layerNamed(byLayer, "web");
  const api = layerNamed(byLayer, "api");
  assert.deepEqual(nestedPaths(web), ["apps/.claude/skills/shared/SKILL.md", "apps/web/.claude/skills/x/SKILL.md"]);
  assert.deepEqual(web.nestedSkills.items[1], { path: "apps/web/.claude/skills/x/SKILL.md", estTokens: estimateTokens(description).estTokens });
  assert.deepEqual(nestedPaths(api), ["apps/.claude/skills/shared/SKILL.md"], "the api layer lists only the skill of apps");
  assert.equal(web.nestedSkills.estTokens, web.nestedSkills.items.reduce((sum, item) => sum + item.estTokens, 0));
  assert.deepEqual(web.onDemand.items, [], "nested skills are not added to the on-demand list");
});

test("layer-context: a nested skill outside the inherited folders, or with disable-model-invocation, is not listed (positive control: the one inside is)", async (t) => {
  const byLayer = await byLayerOf(
    t,
    {
      "packages/p/.claude/skills/z/SKILL.md": SKILL("Outside the layers."),
      "apps/web/.claude/skills/hidden/SKILL.md": `---\nname: hidden\ndescription: Never loaded.\ndisable-model-invocation: true\n---\nBody.\n`,
      "apps/web/.claude/skills/x/SKILL.md": SKILL("The x skill."),
      "apps/web/src/index.ts": "export {};\n",
    },
    [WEB],
  );

  assert.deepEqual(nestedPaths(layerNamed(byLayer, "web")), ["apps/web/.claude/skills/x/SKILL.md"]);
});

test("layer-context: nested AGENTS.md files and the imports of a subfolder CLAUDE file are not counted", async (t) => {
  const byLayer = await byLayerOf(
    t,
    {
      "apps/web/AGENTS.md": "# Agents\n",
      "apps/web/CLAUDE.md": "# Web\n\n@./notes.md\n",
      "apps/web/notes.md": "# Notes\n",
      "apps/web/src/index.ts": "export {};\n",
    },
    [WEB],
  );

  const web = layerNamed(byLayer, "web");
  assert.deepEqual(onDemandPaths(web), ["apps/web/CLAUDE.md"], "the import is not followed, and the AGENTS.md is not counted");
  assert.deepEqual(web.notCounted, []);
});

test("layer-context: a layer's list is sorted by path, and the layers keep the plan order", async (t) => {
  const byLayer = await byLayerOf(
    t,
    {
      "apps/web/src/CLAUDE.md": "# Src\n",
      "apps/web/CLAUDE.md": "# Web\n",
      "apps/CLAUDE.md": "# Apps\n",
      "apps/web/src/index.ts": "export {};\n",
    },
    [{ name: "zeta", folders: ["apps/web/src", "apps/web"] }, { name: "alpha", folders: ["apps/api"] }],
  );

  assert.deepEqual(byLayer.map((layer) => layer.name), ["zeta", "alpha"]);
  assert.deepEqual(onDemandPaths(byLayer[0]), ["apps/CLAUDE.md", "apps/web/CLAUDE.md", "apps/web/src/CLAUDE.md"]);
  assert.deepEqual(byLayer[0].folders, ["apps/web", "apps/web/src"], "the folders are sorted");
  assert.deepEqual(byLayer[1].folders, ["apps/api"]);
});

test("layer-context: the measure refuses a layer list that is not a list of named layers with folders", () => {
  for (const bad of [undefined, [], "web", [{ folders: ["apps"] }], [{ name: "web", folders: [] }], [{ name: "web", folders: [3] }]]) {
    assert.throws(() => createLayerContextMeasure({ layers: bad }), TypeError, `layers ${JSON.stringify(bad)}`);
  }
  // Positive control: a list with one named layer is accepted.
  assert.doesNotThrow(() => createLayerContextMeasure({ layers: [WEB] }));
  assert.equal(createLayerContextMeasure({ layers: [WEB] }).id, "layer-context");
});

test("layerFolderProblem: a folder that exists is fine, and the root is always fine (positive control)", (t) => {
  const { root } = fixtureOf(t, { "apps/web/src/index.ts": "export {};\n" });
  assert.equal(layerFolderProblem(root, [{ name: "all", folders: ["."] }, WEB]), null);
  assert.equal(layerFolderProblem(root, [{ name: "web", folders: ["apps/web/src"] }]), null);
});

test("layerFolderProblem: a missing folder, a file, and a folder reached through a link are problems, named in one line", (t) => {
  const { root } = fixtureOf(t, { "apps/web/src/index.ts": "export {};\n", "apps/notes.txt": "text\n" });

  assert.equal(layerFolderProblem(root, [{ name: "web", folders: ["apps/gone"] }]), 'layer "web": folder "apps/gone" does not exist in the target');
  assert.equal(layerFolderProblem(root, [{ name: "web", folders: ["apps/notes.txt"] }]), 'layer "web": folder "apps/notes.txt" is not a folder');
  // A name with another letter case is not the folder on disk: a case-sensitive disk does not find it, and a case-insensitive one
  // resolves it to another spelling. Either way it is a problem.
  assert.match(layerFolderProblem(root, [{ name: "web", folders: ["Apps/web"] }]), /^layer "web": folder "Apps\/web" (does not exist|is reached)/);
  // Hostile names: a newline and a quote in the layer name and the folder do not add a line to the message. JSON quoting shows them
  // as escapes.
  const hostile = layerFolderProblem(root, [{ name: 'we\nb "x"', folders: ["apps/gone\n"] }]);
  assert.equal(hostile.includes("\n"), false);
  assert.equal(hostile, 'layer "we\\nb \\"x\\"": folder "apps/gone\\n" does not exist in the target');
  // Positive control: the same message shape with a plain name.
  assert.equal(layerFolderProblem(root, [{ name: "web", folders: ["apps/gone"] }]), 'layer "web": folder "apps/gone" does not exist in the target');
});

test("layerFolderProblem: a folder reached through a link is a problem, and the real folder is not (positive control)", { skip: symlinkSkip }, (t) => {
  const fixture = fixtureOf(t, { "apps/web/src/index.ts": "export {};\n" }, { symlinks: [{ path: "apps/link", target: "web" }] });
  assert.match(layerFolderProblem(fixture.root, [{ name: "link", folders: ["apps/link"] }]), /reached through a link/);
  assert.equal(layerFolderProblem(fixture.root, [{ name: "web", folders: ["apps/web"] }]), null);
});
