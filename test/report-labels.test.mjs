// Checks the labels of the report: the two languages have the same keys and placeholders, every key is used by the
// renderer, and no visible word of the report comes from the code. The last check renders with pseudo-locale labels,
// where every label is a marker, and then looks for any letter that is not in the data of the report.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import { KINDS } from "../scripts/lib/agent-harness.mjs";
import { loadRules, validateFindings } from "../scripts/lib/findings-validate.mjs";
import { readCatalog } from "../scripts/lib/report-catalog.mjs";
import { loadLabels, parseLabels, placeholdersOf } from "../scripts/lib/report-labels.mjs";
import { renderReport } from "../scripts/lib/report.mjs";
import { HARNESS_ROOT, makeRun, readGoldenFindings } from "./helpers/report-run.mjs";

const TEMPLATE = path.join(HARNESS_ROOT, "templates", "report.md");
// The marker of a pseudo-locale label. Its key is inside, so a leaked key is never mistaken for text.
const MARKER = /⟦[^⟧]*⟧/gu;

let run;
let rules;
let catalog;
let labelsEn;
let labelsEs;
let scenarios;

// Read when a test needs it, so a missing template fails only the tests that render with it.
function realTemplate() {
  return fs.readFileSync(TEMPLATE, "utf8");
}

before(async () => {
  run = await makeRun();
  rules = loadRules(HARNESS_ROOT);
  catalog = readCatalog(HARNESS_ROOT, rules);
  labelsEn = loadLabels(HARNESS_ROOT, "en");
  labelsEs = loadLabels(HARNESS_ROOT, "es");
  scenarios = buildScenarios();
});

after(() => run?.cleanup());

describe("labels files", () => {
  test("English and Spanish have exactly the same keys", () => {
    assert.deepEqual(Object.keys(labelsEs).sort(), Object.keys(labelsEn).sort());
  });

  test("no label is empty", () => {
    for (const language of ["en", "es"]) {
      const raw = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "templates", `labels.${language}.json`), "utf8"));
      for (const [key, value] of Object.entries(raw)) {
        assert.ok(typeof value === "string" && value.trim() !== "", `${language}: "${key}" is empty`);
      }
    }
  });

  test("each key has the same placeholders in both languages", () => {
    for (const key of Object.keys(labelsEn)) {
      assert.deepEqual(placeholdersOf(labelsEs[key]), placeholdersOf(labelsEn[key]), `placeholders of "${key}"`);
    }
  });

  test("a label file with an empty value or a non-text value is refused", () => {
    assert.throws(() => parseLabels({ "a.b": "" }, "x"), /must be non-empty text/);
    assert.throws(() => parseLabels({ "a.b": 3 }, "x"), /must be non-empty text/);
    assert.throws(() => parseLabels([], "x"), /JSON object/);
  });

  test("every agent of the registry and every harness kind has a label in both languages", () => {
    const registry = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "data", "agent-harness.json"), "utf8"));
    for (const agent of registry.agents) {
      for (const labels of [labelsEn, labelsEs]) assert.ok(Object.hasOwn(labels, `agent.${agent.id}`), `agent.${agent.id}`);
      // The English label is the registry name, so the report names an agent as the registry does.
      assert.equal(labelsEn[`agent.${agent.id}`], agent.name, `the English label of ${agent.id}`);
    }
    for (const kind of KINDS) {
      for (const labels of [labelsEn, labelsEs]) assert.ok(Object.hasOwn(labels, `harnessKind.${kind}`), `harnessKind.${kind}`);
    }
  });
});

describe("label use", () => {
  test("every label key is used by the renderer over the test scenarios", () => {
    const used = new Set();
    const template = realTemplate();
    for (const scenario of Object.values(scenarios)) {
      renderReport({ ...scenario, labels: recording(labelsEn, used), template });
    }
    // The keys of the intake page (intake.*) are rendered by scripts/lib/intake-page.mjs, which its own test checks. The keys
    // of the HTML view (html.*) are read by scripts/lib/report-html.mjs, which test/report-html.test.mjs checks.
    const unused = Object.keys(labelsEn).filter(
      (key) => !key.startsWith("intake.") && !key.startsWith("html.") && !used.has(key),
    );
    assert.deepEqual(unused, [], "label keys that no scenario renders");
  });

  test("a key the labels do not have is an error, not a raw key in the report", () => {
    const { measurements, findings, catalog: cat } = scenarios.golden;
    const short = { ...labelsEn };
    delete short["header.title"];
    const template = realTemplate();
    assert.throws(() => renderReport({ measurements, findings, catalog: cat, labels: short, template }), /no text for "header.title"/);
  });
});

describe("pseudo-locale", () => {
  test("with every label replaced by a marker, no visible word comes from the code", () => {
    const pseudo = pseudoLabels(labelsEn);
    const template = realTemplate();
    for (const [name, scenario] of Object.entries(scenarios)) {
      const { markdown } = renderReport({ ...scenario, labels: pseudo, template });
      const leaked = leakedWords(markdown, dataTexts(scenario));
      assert.deepEqual(leaked, [], `words in the ${name} report that are not data`);
    }
  });

  test("the pseudo-locale report has markers where labels are", () => {
    const { markdown } = renderReport({ ...scenarios.golden, labels: pseudoLabels(labelsEn), template: realTemplate() });
    assert.ok(markdown.match(MARKER)?.length > 50, "expected many markers in the report");
  });
});

// The scenarios. golden is the English golden input. rich adds what the golden input does not reach: unknown static
// items, a hook candidate, an undeterminable case, a threshold, values of each kind, a finding with a benchmark rule,
// a rule with no source, and more measured findings than the appendix shows. empty has no finding and no measure.
function buildScenarios() {
  const golden = { measurements: cloneOf(run.measurements), findings: readGoldenFindings("findings.en.json"), catalog };

  const m = cloneOf(run.measurements);
  m.context.alwaysLoaded.unknownStatic.push(
    { kind: "mcp-server", source: ".mcp.json", name: "docs" },
    { kind: "hook-output", source: ".claude/settings.json", event: "SessionStart", matcher: null },
  );
  m.candidates.push({
    id: "cand-9",
    kind: "hook-script",
    rules: ["SEC-02", "SEC-04"],
    measurementRef: "/claudeConfig/hooks/0/script",
    file: ".claude/hooks/guard.mjs",
  });
  m.undeterminable.push({
    rule: "SEC-02",
    measurementRef: "/security/destructiveCoverage/commands/0/outcome",
    reason: "outcome undeterminable: a command wrapper",
  });
  m.warnings.push({ source: "fs", path: "notes/big.md", reason: "too-large", detail: { bytes: 300000 } });
  m.target.git.head = "0123456789abcdef0123456789abcdef01234567";
  m.probe = { yes: true, no: false, nothing: null, list: [1, 2], label: "text" };
  m.agentHarness = allAgentsHarness();
  // A measured finding that names agents, and that no finding cites: its agents are shown in its own block.
  m.measuredFindings.push({
    id: "mf-200",
    rule: "CTX-07",
    axis: "context",
    impact: "medium",
    measurementRef: "/agentHarness/agents/0/items",
    evidence: [{ file: ".claude/settings.json" }],
    triggers: [],
    agents: ["cursor"],
  });
  m.measuredFindings.push(
    {
      id: "mf-7",
      rule: "CTX-01",
      axis: "context",
      impact: "high",
      measurementRef: "/context/alwaysLoaded/estTokensTotal",
      evidence: [],
      triggers: [
        {
          trigger: "always-loaded-total-high",
          impact: "high",
          measurementRef: "/context/alwaysLoaded/estTokensTotal",
          threshold: { key: "alwaysLoadedTokensHigh", value: 6000 },
        },
      ],
    },
    probeFinding("mf-8", "/probe/yes", "probe-true"),
    probeFinding("mf-9", "/probe/no", "probe-false"),
    probeFinding("mf-10", "/probe/nothing", "probe-null"),
    probeFinding("mf-11", "/probe/list", "probe-list"),
    probeFinding("mf-12", "/probe/label", "probe-text"),
    {
      id: "mf-13",
      rule: "SEC-02",
      axis: "security",
      impact: "low",
      measurementRef: "/security/destructiveCoverage/commands/0",
      evidence: [{ file: ".claude/settings.json" }],
      triggers: [
        {
          trigger: "hook-not-verified",
          impact: "low",
          measurementRef: "/security/destructiveCoverage/commands/0",
        },
      ],
    },
  );
  for (let index = 0; index < 52; index += 1) {
    m.measuredFindings.push({
      id: `mf-${100 + index}`,
      rule: "STR-02",
      axis: "structure",
      impact: "low",
      measurementRef: "/structure/mapCoverage/dirs",
      evidence: [{ file: ".claude/settings.json" }],
      triggers: [{ trigger: "large-file-unprotected", impact: "low", measurementRef: "/structure/mapCoverage/dirs" }],
    });
  }
  const findings = readGoldenFindings("findings.en.json");
  findings.findings.push({
    rule: "COD-04",
    axis: "code",
    kind: "judgment",
    evidence: [{ file: ".claude/settings.json", line: 4 }],
    impact: "low",
    summary: "A reader for the permission settings may already exist in the code.",
    recommendation: "Reuse the existing reader before adding another.",
    testInFunction2: "Compare the diff size with and without the reuse rule.",
  });
  // A finding that names agents, so the Agents field is rendered from a finding (the other one comes from the measure above).
  findings.findings[0].agents = ["claude-code", "cursor"];
  const noSourceRules = new Map(catalog.rules);
  noSourceRules.set("SEC-05", { ...catalog.rules.get("SEC-05"), evidence: "common-practice", sources: [] });
  const rich = { measurements: m, findings, catalog: { ...catalog, rules: noSourceRules } };

  const e = cloneOf(run.measurements);
  e.measuredFindings = [];
  e.context.alwaysLoaded.byComponent = [];
  e.context.alwaysLoaded.unknownStatic = [];
  e.candidates = [];
  e.undeterminable = [];
  e.warnings = [];
  e.security.destructiveCoverage.mode = null;
  const empty = { measurements: e, findings: { findings: [] }, catalog };

  // The scans that read beyond the target: one flag each, then both. Each gives its own limits text, and the evidence of
  // the layer it reads is marked. The ancestors scenarios also give the context text of the parent folders.
  const flagged = (include, evidence) => {
    const measurements = cloneOf(run.measurements);
    measurements.meta.include = include;
    const findings = readGoldenFindings("findings.en.json");
    findings.findings[0].evidence.push(...evidence);
    return { measurements, findings, catalog };
  };
  const userEvidence = { file: "~/.claude/settings.json", layer: "user" };
  const ancestorEvidence = { file: "../CLAUDE.md", layer: "ancestor" };
  const userLayer = flagged({ userLayer: true, ancestors: false }, [userEvidence]);
  const ancestors = flagged({ userLayer: false, ancestors: true }, [ancestorEvidence]);
  const both = flagged({ userLayer: true, ancestors: true }, [userEvidence, ancestorEvidence]);

  // A scan with a scope: the header names it, and the limits say what was measured inside it and what was read outside.
  const scoped = cloneOf(run.measurements);
  scoped.scope = { folders: ["apps/web"], inherited: [".", "apps"], files: { inScope: 3, outside: 5 } };
  const scopedScenario = { measurements: scoped, findings: readGoldenFindings("findings.en.json"), catalog };

  // A scan with a layer plan: the context section has one row per layer, and the nested skills are shown apart. The layer name
  // has a pipe, which the table must escape.
  const layered = cloneOf(run.measurements);
  layered.context.byLayer = [
    {
      name: "web | front",
      folders: ["apps/web"],
      agent: "claude-code",
      onDemand: { estTokens: 120, items: [{ path: "apps/web/CLAUDE.md", kind: "memory", estTokens: 120 }] },
      nestedSkills: { estTokens: 30, items: [{ path: "apps/web/.claude/skills/x/SKILL.md", estTokens: 30 }] },
      notCounted: [{ path: "apps/web/vendor/CLAUDE.md", reason: "claude-md-excludes" }],
    },
    {
      name: "api",
      folders: ["apps/api"],
      agent: "claude-code",
      onDemand: { estTokens: 0, items: [] },
      nestedSkills: { estTokens: 0, items: [] },
      notCounted: [],
    },
  ];
  const layeredScenario = { measurements: layered, findings: readGoldenFindings("findings.en.json"), catalog };
  return { golden, rich, empty, userLayer, ancestors, both, scoped: scopedScenario, layered: layeredScenario };
}

// The agentHarness of a scan that detects every registry agent, sorted by id as the scan writes them. Claude Code has every
// kind, so every harness kind label is rendered; each other agent has instructions and hooks, and hooks is not evaluated.
function allAgentsHarness() {
  const registry = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "data", "agent-harness.json"), "utf8"));
  const agents = [...registry.agents].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const kindsOf = (id) => (id === "claude-code" ? KINDS : ["instructions", "hooks"]);
  return {
    registry: "data/agent-harness.json",
    agents: agents.map((agent) => ({
      id: agent.id,
      name: agent.name,
      type: agent.type,
      verified: agent.id === "claude-code",
      items: kindsOf(agent.id).length,
      budget: agent.id === "claude-code" ? "/context/alwaysLoaded" : "unknownStatic",
      unverifiedInBudget: [],
    })),
    items: agents.flatMap((agent) =>
      kindsOf(agent.id).map((kind) => ({ path: `${agent.id}/${kind}`, agent: agent.id, entry: `${agent.id}-${kind}`, kind })),
    ),
    files: [],
    unknownStatic: [],
  };
}

function probeFinding(id, measurementRef, trigger) {
  return {
    id,
    rule: "SEC-03",
    axis: "security",
    impact: "medium",
    measurementRef,
    evidence: [{ file: ".claude/settings.json", line: 4 }],
    triggers: [{ trigger, impact: "medium", measurementRef }],
  };
}

function cloneOf(value) {
  return structuredClone(value);
}

// A labels object whose reads are recorded: a read is a use of the key.
function recording(labels, used) {
  return new Proxy(labels, {
    get(target, key, receiver) {
      if (typeof key === "string") used.add(key);
      return Reflect.get(target, key, receiver);
    },
  });
}

// Each label becomes its key in markers, with its placeholders kept so the renderer can fill them.
function pseudoLabels(labels) {
  return Object.fromEntries(
    Object.entries(labels).map(([key, text]) => [
      key,
      `⟦${key}⟧${placeholdersOf(text).map((name) => ` {${name}}`).join("")}`,
    ]),
  );
}

// Every string of the scenario that comes from the data (the target, the measurements, the findings and the catalog).
function dataTexts(scenario) {
  const texts = [];
  const collect = (value) => {
    if (typeof value === "string") texts.push(value);
    else if (Array.isArray(value)) value.forEach(collect);
    else if (value !== null && typeof value === "object") Object.values(value).forEach(collect);
  };
  collect(scenario.measurements);
  collect(scenario.findings);
  for (const rule of scenario.catalog.rules.values()) collect(rule);
  for (const source of scenario.catalog.sources.values()) collect(source);
  // The catalog version is computed from the rule files, so it is data too: a hex digest is not a word.
  collect(scenario.catalog.version.sha256);
  return texts;
}

// The words of the markdown that are not marker text and not in the data. Numbers, punctuation and the escapes are not
// words. The word "target" is the replacement of the target folder, which is code, not label text.
function leakedWords(markdown, texts) {
  const allowed = new Set(["target"]);
  for (const text of texts) for (const word of text.match(/\p{L}+/gu) ?? []) allowed.add(word);
  const visible = markdown.replace(MARKER, " ");
  const words = visible.match(/\p{L}+/gu) ?? [];
  return [...new Set(words)].filter((word) => !allowed.has(word));
}

// Check the scenarios against the validator as well, so that the scenarios are the data a real run gives. The golden
// scenario must pass; the rich and empty scenarios are not validated, because they are built to reach every label.
describe("scenarios", () => {
  test("the golden scenario is valid findings for the scan", () => {
    const { measurements, findings } = scenarios.golden;
    const result = validateFindings({ findings, measurements, rules, targetRoot: measurements.meta.targetRoot });
    assert.equal(result.ok, true, JSON.stringify(result.errors));
  });
});
