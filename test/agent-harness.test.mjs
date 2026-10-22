import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  AGENT_TYPES,
  KINDS,
  LOAD_MODELS,
  globProblem,
  matchHarnessGlob,
  validateAgentHarness,
} from "../scripts/lib/agent-harness.mjs";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const REGISTRY = path.join(HARNESS_ROOT, "data", "agent-harness.json");
const SOURCES = path.join(HARNESS_ROOT, "rules", "sources.json");

// Helpers ---------------------------------------------------------------------------------------

function readRegistry() {
  return JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
}

// The source types of the real rules/sources.json, as check-catalog.mjs builds them.
const SOURCE_TYPES = new Map(
  JSON.parse(fs.readFileSync(SOURCES, "utf8")).sources.map((source) => [source.id, source.type]),
);

function check(data, sourceTypes = SOURCE_TYPES) {
  return validateAgentHarness(data, { sourceTypes });
}

// A copy of the real registry with one change made to it.
function mutated(change) {
  const data = readRegistry();
  change(data);
  return data;
}

// The index of a file entry in the real registry.
function indexOf(id) {
  const index = readRegistry().files.findIndex((entry) => entry.id === id);
  assert.notEqual(index, -1, `no file entry ${id}`);
  return index;
}

function describeIssues(issues) {
  return issues.map((item) => `${item.pointer}: ${item.message}`).join("\n") || "(none)";
}

// The one issue at a pointer. It fails if there is none, or if the message does not match.
function issueAt(issues, pointer, pattern) {
  const found = issues.find((item) => item.pointer === pointer);
  assert.ok(found, `expected an issue at ${pointer}, got:\n${describeIssues(issues)}`);
  if (pattern !== undefined) assert.match(found.message, pattern);
  return found;
}

// Applies one change to a copy of the real registry and expects the issue at the pointer. The real registry is checked
// first and must pass, so each rejected input has a valid input next to it.
function assertRejected(change, pointer, pattern) {
  assert.deepEqual(check(readRegistry()), [], "the real registry must pass before the change");
  issueAt(check(mutated(change)), pointer, pattern);
}

// Glob matching -------------------------------------------------------------------------------

test("** at the start of a glob matches zero or more folders", () => {
  assert.equal(matchHarnessGlob("**/AGENTS.md", "AGENTS.md"), true);
  assert.equal(matchHarnessGlob("**/AGENTS.md", "a/b/AGENTS.md"), true);
  assert.equal(matchHarnessGlob("**/AGENTS.md", "a/AGENTS.md.bak"), false);
  assert.equal(matchHarnessGlob("**/AGENTS.md", "a/xAGENTS.md"), false);
});

test("a ** after a folder needs a folder before the name, so */**/x does not match x", () => {
  assert.equal(matchHarnessGlob("*/**/x", "x"), false);
  assert.equal(matchHarnessGlob("*/**/x", "a/x"), true);
  assert.equal(matchHarnessGlob("*/**/x", "a/b/x"), true);
  assert.equal(matchHarnessGlob("*/**/.claude/skills/*/SKILL.md", ".claude/skills/x/SKILL.md"), false);
  assert.equal(matchHarnessGlob("*/**/.claude/skills/*/SKILL.md", "pkg/.claude/skills/x/SKILL.md"), true);
});

test("* does not cross a slash", () => {
  assert.equal(matchHarnessGlob("a/*", "a/b"), true);
  assert.equal(matchHarnessGlob("a/*", "a/b/c"), false);
  assert.equal(matchHarnessGlob("a*", "a/b"), false);
});

test("* matches a leading dot", () => {
  assert.equal(matchHarnessGlob("*.md", ".notes.md"), true);
  assert.equal(matchHarnessGlob("*", ".claude"), true);
  assert.equal(matchHarnessGlob(".claude/*", ".claude/x.json"), true);
});

test("a glob that ends in ** matches the folder and the files under it; a glob without ** matches only its own path", () => {
  assert.equal(matchHarnessGlob(".agents/**", ".agents/a/b.json"), true);
  assert.equal(matchHarnessGlob(".agents/**", ".agents"), true, "** matches zero segments, so the folder itself matches");
  assert.equal(matchHarnessGlob(".agents/**", ".agentsx/a/b.json"), false);
  assert.equal(matchHarnessGlob(".agents/hooks", ".agents/hooks"), true);
  assert.equal(matchHarnessGlob(".agents/hooks", ".agents/hooks/a.json"), false);
  assert.equal(matchHarnessGlob(".claude/rules/**/*.md", ".claude/rules/a.md"), true);
  assert.equal(matchHarnessGlob(".claude/rules/**/*.md", ".claude/rules/x/y/z.md"), true);
  assert.equal(matchHarnessGlob(".claude/rules/**/*.md", ".claude/rules/a.txt"), false);
});

test("a path that is not clean never matches, and a clean one does", () => {
  assert.equal(matchHarnessGlob("**/*", "a/b"), true);
  assert.equal(matchHarnessGlob("**/*", "/a/b"), false);
  assert.equal(matchHarnessGlob("**/*", "a//b"), false);
  assert.equal(matchHarnessGlob("**/*", "a/../b"), false);
  assert.equal(matchHarnessGlob("**/*", "a/./b"), false);
  assert.equal(matchHarnessGlob("**/*", "a/"), false);
  assert.equal(matchHarnessGlob("**/*", ""), false);
});

test("matchHarnessGlob throws for an invalid glob or a path that is not a string, and not for valid input", () => {
  assert.equal(matchHarnessGlob("a/*", "a/b"), true);
  assert.throws(() => matchHarnessGlob("a/", "a/b"), TypeError);
  assert.throws(() => matchHarnessGlob("**", "a/b"), TypeError);
  assert.throws(() => matchHarnessGlob("a/*", 5), TypeError);
});

test("globProblem accepts every form the dialect allows", () => {
  const valid = [
    "**/AGENTS.md", "*", "*.md", "a*c", ".agents/**", "a/**/**", "*/**/.claude/skills/*/SKILL.md",
    ".claude/rules/**/*.md", "GEMINI.md", ".clinerules/**", ".agents/hooks/**",
  ];
  for (const glob of valid) assert.equal(globProblem(glob), null, glob);
});

test("globProblem names each invalid form", () => {
  const invalid = [
    [5, /must be a string/],
    ["", /must not be empty/],
    ["/AGENTS.md", /must be relative to the repository root/],
    ["./AGENTS.md", /must not start with \.\//],
    ["a/", /must not end with \//],
    ["a\\b", /must not contain a backslash/],
    ["a//b", /must not contain an empty, "\." or "\.\." segment/],
    ["a/./b", /must not contain an empty, "\." or "\.\." segment/],
    ["a/../b", /must not contain an empty, "\." or "\.\." segment/],
    [".", /must not contain an empty, "\." or "\.\." segment/],
    ["..", /must not contain an empty, "\." or "\.\." segment/],
    ["a[1]", /must not contain any of the characters \[ \] \{ \} or !/],
    ["{a,b}", /must not contain any of the characters/],
    ["!a", /must not contain any of the characters/],
    ["a**", /"\*\*" must be a whole segment/],
    ["**a/b", /"\*\*" must be a whole segment/],
    ["**", /must not be made only of "\*\*" segments/],
    ["**/**", /must not be made only of "\*\*" segments/],
    ["a?c", /must not contain \? or \+/],
    ["?", /must not contain \? or \+/],
    ["a+", /must not contain \? or \+/],
    ["a\u0000b", /must not contain a control character/],
    ["a\u001fb", /must not contain a control character/],
  ];
  for (const [glob, pattern] of invalid) assert.match(globProblem(glob), pattern, String(glob));
});

test("a glob has at most 64 segments and 512 characters, and the limits themselves are valid", () => {
  const segments = (count) => Array.from({ length: count }, () => "a").join("/");
  assert.equal(globProblem(segments(64)), null, "64 segments (positive control)");
  assert.match(globProblem(segments(65)), /must have at most 64 segments/);
  assert.equal(globProblem("x".repeat(512)), null, "512 characters (positive control)");
  assert.match(globProblem("x".repeat(513)), /must be at most 512 characters/);
});

test("a 64-segment glob full of * matches a path of its depth, and is quick against a 10,000-segment path", () => {
  const glob = Array.from({ length: 64 }, () => "*a*a*a*").join("/");
  assert.equal(globProblem(glob), null);
  const pathOf = (count) => Array.from({ length: count }, () => "aaa").join("/");
  assert.equal(matchHarnessGlob(glob, pathOf(64)), true, "positive control: the glob matches a path of its own depth");
  const started = performance.now();
  assert.equal(matchHarnessGlob(glob, pathOf(10_000)), false);
  assert.ok(performance.now() - started < 2000, "matching against 10,000 segments took 2000 ms or more");
});

test("the value lists are the ones the format names", () => {
  assert.deepEqual(KINDS, ["instructions", "settings", "hooks", "skills", "commands", "subagents", "mcp", "unknown"]);
  assert.deepEqual(LOAD_MODELS, ["always", "ancestors", "folder", "glob", "invoked", "unknown"]);
  assert.deepEqual(AGENT_TYPES, ["agent", "convention"]);
});

// The registry -------------------------------------------------------------------------------------

test("the real registry validates with no issues against the real sources (positive control)", () => {
  assert.deepEqual(check(readRegistry()), [], describeIssues(check(readRegistry())));
});

test("the top level is an object with the fields agents and files, and nothing else", () => {
  assert.deepEqual(check([]).map((item) => item.pointer), [""]);
  assert.match(check(null)[0].message, /must be an object with the fields agents and files/);
  assertRejected((data) => { data.extra = true; }, "/extra", /unknown field; the fields are agents, files/);
  assertRejected((data) => { delete data.agents; }, "/agents", /missing required field/);
  assertRejected((data) => { data.files = []; }, "/files", /must be a non-empty list/);
});

test("an agent entry has exactly id, name and type, with valid values", () => {
  assertRejected((data) => { data.agents[0].extra = 1; }, "/agents/0/extra", /unknown field/);
  assertRejected((data) => { delete data.agents[0].name; }, "/agents/0/name", /missing required field/);
  assertRejected((data) => { data.agents[0].id = "Claude Code"; }, "/agents/0/id", /must be kebab-case/);
  assertRejected((data) => { data.agents[0].name = " "; }, "/agents/0/name", /must be a non-empty string/);
  assertRejected((data) => { data.agents[0].type = "other"; }, "/agents/0/type", /must be one of agent, convention/);
});

test("an agent with no entries in files is an error", () => {
  assertRejected((data) => { data.agents.push({ id: "zed", name: "Zed", type: "agent" }); }, "/agents/8/id", /no entries in files/);
});

test("an entry id must not start with the id of a longer agent, with agents claude and claude-code", () => {
  const withClaude = (change) => mutated((data) => {
    data.agents.push({ id: "claude", name: "Claude", type: "agent" });
    data.files.push({
      id: "claude-settings",
      agent: "claude",
      glob: ".claude-settings.json",
      kind: "settings",
      loadModel: "always",
      sources: ["cc-docs-settings"],
    });
    change(data);
  });
  assert.deepEqual(check(withClaude(() => {})), [], "positive control: claude-settings belongs to claude");
  const index = indexOf("claude-code-settings");
  issueAt(check(withClaude((data) => { data.files[index].agent = "claude"; })), `/files/${index}/id`,
    /starts with "claude-code-"/);
});

test("a file entry has exactly its listed fields", () => {
  assertRejected((data) => { data.files[0].extra = 1; }, "/files/0/extra", /unknown field/);
  assertRejected((data) => { delete data.files[0].kind; }, "/files/0/kind", /missing required field/);
});

test("the agent of a file entry is an entry of agents, and its id starts with that agent id", () => {
  assertRejected((data) => { data.files[0].agent = "no-such-agent"; }, "/files/0/agent", /must be the id of an entry of agents/);
  assertRejected((data) => { data.files[indexOf("claude-code-settings")].id = "settings"; }, "/files/0/id", /must start with its agent id/);
});

test("kind and loadModel must be listed values", () => {
  assertRejected((data) => { data.files[0].kind = "rules"; }, "/files/0/kind", /must be one of instructions, settings/);
  assertRejected((data) => { data.files[0].loadModel = "sometimes"; }, "/files/0/loadModel", /must be one of always, ancestors/);
});

test("a glob must be valid", () => {
  assertRejected((data) => { data.files[0].glob = "/.claude/settings.json"; }, "/files/0/glob", /must be relative to the repository root/);
  assertRejected((data) => { data.files[0].glob = ".claude/[settings].json"; }, "/files/0/glob", /must not contain any of the characters/);
});

test("sources is a list of distinct source ids that exist in rules/sources.json", () => {
  assertRejected((data) => { data.files[0].sources = "cc-docs-settings"; }, "/files/0/sources", /must be a list of source ids/);
  assertRejected((data) => { data.files[0].sources = ["cc-docs-settings", "cc-docs-settings"]; }, "/files/0/sources/1", /duplicate source id "cc-docs-settings"/);
  assertRejected((data) => { data.files[0].sources = ["no-such-source"]; }, "/files/0/sources/0", /does not exist in rules\/sources\.json/);
});

test("every source of a file entry must be official-docs", () => {
  assertRejected((data) => { data.files[0].sources = ["atlas-agents-md"]; }, "/files/0/sources/0", /must have type official-docs, found "atlas"/);
});

test("without the sources file, only the source checks are skipped", () => {
  const data = mutated((registry) => { registry.files[0].sources = ["no-such-source"]; });
  issueAt(check(data), "/files/0/sources/0", /does not exist/);
  assert.deepEqual(check(data, null), []);
  issueAt(check(mutated((registry) => { registry.files[0].extra = 1; }), null), "/files/0/extra", /unknown field/);
});

test("an empty sources list needs loadModel unknown", () => {
  assertRejected((data) => { data.files[indexOf("claude-code-claude-md")].sources = []; },
    `/files/${indexOf("claude-code-claude-md")}/loadModel`, /must be unknown when sources is empty/);
});

test("pending is a non-empty string, and it is required when sources is empty or loadModel is unknown", () => {
  assertRejected((data) => { data.files[0].pending = " "; }, "/files/0/pending", /must be a non-empty string/);
  assertRejected((data) => { delete data.files[indexOf("claude-code-commands")].pending; },
    `/files/${indexOf("claude-code-commands")}/pending`, /required when sources is empty or loadModel is unknown/);
  assertRejected((data) => { delete data.files[indexOf("claude-code-subagents")].pending; },
    `/files/${indexOf("claude-code-subagents")}/pending`, /required when sources is empty or loadModel is unknown/);
});

test("pathsField is required with loadModel glob and forbidden otherwise", () => {
  assertRejected((data) => { delete data.files[indexOf("claude-code-rules")].pathsField; },
    `/files/${indexOf("claude-code-rules")}/pathsField`, /required when loadModel is glob/);
  assertRejected((data) => { data.files[indexOf("claude-code-rules")].pathsField = ""; },
    `/files/${indexOf("claude-code-rules")}/pathsField`, /must be a non-empty string/);
  assertRejected((data) => { data.files[0].pathsField = "paths"; }, "/files/0/pathsField", /allowed only when loadModel is glob/);
});

test("unless names other entries of the same agent, and only with ancestors or folder", () => {
  const index = indexOf("claude-code-agents-md");
  assertRejected((data) => { data.files[index].unless = ["codex-config"]; }, `/files/${index}/unless/0`,
    /is an entry of agent "codex", not of "claude-code"/);
  assertRejected((data) => { data.files[index].unless = ["no-such-entry"]; }, `/files/${index}/unless/0`,
    /is not an entry in files/);
  assertRejected((data) => { data.files[index].unless = ["claude-code-agents-md"]; }, `/files/${index}/unless/0`,
    /must not name the entry itself/);
  assertRejected((data) => { data.files[index].unless = ["claude-code-claude-md", "claude-code-claude-md"]; },
    `/files/${index}/unless/1`, /duplicate entry id/);
  assertRejected((data) => { data.files[0].unless = ["claude-code-mcp"]; }, "/files/0/unless", /allowed only when loadModel is ancestors or folder/);
});

test("unless names only entries whose loading is verified, so an unknown target is an error", () => {
  const index = indexOf("claude-code-agents-md");
  assertRejected((data) => { data.files[index].unless = ["claude-code-dot-claude-claude-md"]; }, `/files/${index}/unless/0`,
    /has loadModel unknown/);
});

test("kind unknown needs loadModel unknown", () => {
  assertRejected((data) => { data.files[0].kind = "unknown"; }, "/files/0/loadModel", /must be unknown when kind is unknown/);
});

test("a file entry shadowed by an earlier entry of its agent is an error; the same entry placed last is not", () => {
  const general = {
    id: "claude-code-all",
    agent: "claude-code",
    glob: ".claude/**",
    kind: "unknown",
    loadModel: "unknown",
    sources: [],
    pending: "Test entry.",
  };
  assert.deepEqual(check(mutated((data) => { data.files.push(general); })), []);
  issueAt(check(mutated((data) => { data.files.unshift(general); })), "/files/1/glob", /shadowed by claude-code-all/);
});

// A registry of one agent with one entry per glob, in the given order. Each entry has no sources and loadModel unknown, so
// only the globs and their order decide the shadowing check. Entry i has the id claude-code-i.
function registryOfGlobs(globs) {
  return {
    agents: [{ id: "claude-code", name: "Claude Code", type: "agent" }],
    files: globs.map((glob, index) => ({
      id: `claude-code-${index}`,
      agent: "claude-code",
      glob,
      kind: "unknown",
      loadModel: "unknown",
      sources: [],
      pending: "Test entry.",
    })),
  };
}

test("the shadowing check passes a narrow entry before a general one, and reports the general one before the narrow one", () => {
  const narrowFirst = [[".a/*.md", ".a/**/*.md"], [".claude/CLAUDE.md", "**/CLAUDE.md"], ["x*.md", "*.md"]];
  for (const globs of narrowFirst) assert.deepEqual(check(registryOfGlobs(globs)), [], globs.join(" then "));
  issueAt(check(registryOfGlobs(["**/CLAUDE.md", ".claude/CLAUDE.md"])), "/files/1/glob", /shadowed by claude-code-0;/);
  issueAt(check(registryOfGlobs([".a/**", ".a/b.json"])), "/files/1/glob", /shadowed by claude-code-0;/);
});
