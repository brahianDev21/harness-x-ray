// Measure "layer-context": the context that Claude Code loads when it works in each layer of the layer plan. The scan reads the
// plan with --layers (<runDir>/layer-plan.json, checked by scan.mjs and lib/layer-plan.mjs). For each layer it lists the files
// that load on demand there, and the nested skills, with their estimates in tokens. Only Claude Code is computed: it is the only
// agent whose load model data/agent-harness.json verifies.
//
// The always-loaded files are not repeated here. They are the budget of the memory measure, and they are the same for every
// layer. For a layer with folders Fs, a folder lies in the layer when it is one of Fs or lies inside one ("." holds every
// folder). The inherited folders are the folders between the root and each folder of Fs (createScope in scope.mjs).
//
// The on-demand context of a layer is:
// - memory: each CLAUDE.md and CLAUDE.local.md below the root, outside every .claude folder, whose folder is an inherited folder
//   other than "." or lies in the layer. Claude Code loads a subfolder CLAUDE.md once it reads a file in that subtree (the
//   cc-docs-memory-loading note), so the files on the way down count too. The root files are in the always-loaded budget.
// - rule: each rule of .claude/rules that the memory measure loads on demand (a paths field), when a pattern of its paths
//   matches at least one file of the layer. The match is matchPathGlob's; NOT VERIFIED by a note that it matches the patterns
//   as Claude Code does. A rule that matches no file is not counted. Its estimate is the whole file, as the budget counts it.
// The nested skills of a layer are the skills of claude-config with scope nested and loadMode on-demand, whose harness folder
// (harnessFolderOf) is an inherited folder other than "." or lies in the layer. They are listed apart in nestedSkills and are not
// added to the on-demand total: the registry gives the load model of a nested skill as unknown.
//
// Not counted. The imports of a memory file are not followed, as the subfolder memory of the memory measure is not; NOT VERIFIED
// by a note whether Claude Code loads them. Nested AGENTS.md files are not counted: the registry gives Claude Code's model for
// **/AGENTS.md as "ancestors", which says nothing about a nested file loading when Claude works in its folder. A rule that
// claudeMdExcludes matches is not in ctx.memory, so it is neither counted nor listed. The
// notCounted list of a layer names the files that would count there but do not: a CLAUDE file that claudeMdExcludes matches
// (reason claude-md-excludes; it is not read), a file that safe-fs cannot read (its safe-fs reason), and a rule whose patterns
// all fail to match and at least one of which matchPathGlob cannot read (reason unsupported-pattern). A pattern is judged on
// the files of the layer only. With --scope, claude-config leaves out the nested skills outside the scope, so a layer outside
// the scope lists none of them; the memory files are read through ctx, so the scope does not change them.
//
// Output: context.byLayer, one entry per layer in plan order: { name, folders, agent, onDemand, nestedSkills, notCounted }. The
// folders are sorted; every list is sorted by path, and notCounted also by reason. Estimates are chars/4 (tokens.mjs).
//
// layerFolderProblem checks the folders of a plan against the target, for the command line, which refuses a plan that no longer
// matches the target. The target is read through safe-fs only: the folders are stat-ed and resolved, never opened.

import path from "node:path";
import { loadClaudeConfig } from "./claude-config.mjs";
import { parseFrontmatter } from "./frontmatter.mjs";
import { isPlainObject } from "./json-out.mjs";
import { quoteText } from "./layer-plan.mjs";
import { claudeMdExclusionOf, countsOf } from "./memory.mjs";
import { matchPathGlob } from "./permissions.mjs";
import { createTargetFs } from "./safe-fs.mjs";
import { createScope, harnessFolderOf } from "./scope.mjs";

export const MEASURE_ID = "layer-context";
// The agent whose load model is applied. data/agent-harness.json verifies only Claude Code.
const AGENT = "claude-code";
const ROOT = ".";
const CLAUDE_DIR = ".claude";
const MEMORY_NAMES = new Set(["CLAUDE.md", "CLAUDE.local.md"]);
const EXCLUDED_REASON = "claude-md-excludes";
const UNSUPPORTED_REASON = "unsupported-pattern";
// The outcome of one rule for the files of one layer. A rule that is neither matched nor unsupported is not counted, and not
// listed.
const MATCHED = "matched";
const UNSUPPORTED = "unsupported";
const NOT_MATCHED = "not-matched";

/**
 * Builds the layer-context measure.
 * @param {object} options
 * @param {Array<{ name: string, folders: string[] }>} options.layers The layers of the plan, in plan order. Each folder is a
 *   folder of the target, and "." holds the whole target. layerFolderProblem confirms the folders before the scan.
 * @returns {{ id: string, collect: (ctx: object) => object }}
 * @throws {TypeError} When layers is not a non-empty list of layers, each with a name and a non-empty list of folders.
 */
export function createLayerContextMeasure({ layers } = {}) {
  const list = layersOf(layers);
  return Object.freeze({ id: MEASURE_ID, collect: (ctx) => collectLayerContext(ctx, list) });
}

/**
 * The first folder of a layer plan that is not a folder of the target reached without a link, as a message, or null when every
 * folder is one. The root "." is the whole target and is always one. A folder is checked through safe-fs: it must exist, be a
 * folder and resolve to its own name, so a link on the way, or a name whose letter case differs from the disk, is a problem.
 * @param {string} root Absolute path of the target, as the scanner resolved it.
 * @param {Array<{ name: string, folders: string[] }>} layers The layers of the plan.
 * @returns {string | null} A message that quotes the layer name and the folder, or null.
 */
export function layerFolderProblem(root, layers) {
  const view = createTargetFs(root);
  for (const layer of layers) {
    for (const folder of layer.folders) {
      const problem = folderProblem(view, folder);
      if (problem !== null) return `layer ${quoteText(layer.name)}: folder ${quoteText(folder)} ${problem}`;
    }
  }
  return null;
}

function folderProblem(view, folder) {
  if (folder === ROOT) return null;
  const entry = view.stat(folder);
  if (!entry.ok) return entry.reason === "not-found" ? "does not exist in the target" : `cannot be used (${entry.reason})`;
  if (entry.type !== "dir") return "is not a folder";
  const resolved = view.resolve(folder);
  return resolved.ok && resolved.target === folder ? null : "is reached through a link, or its name differs from the disk";
}

function layersOf(layers) {
  if (!Array.isArray(layers) || layers.length === 0) throw new TypeError("layers must be a non-empty list of layers");
  return layers.map((layer) => {
    const valid =
      isPlainObject(layer) &&
      typeof layer.name === "string" &&
      Array.isArray(layer.folders) &&
      layer.folders.length > 0 &&
      layer.folders.every(isString);
    if (!valid) throw new TypeError("each layer needs a name and a non-empty list of folders");
    return { name: layer.name, folders: [...layer.folders].sort(compareText) };
  });
}

// What the layers share: the claudeMdExcludes patterns, the files of the target, the subfolder memory files, the rules that
// load on demand and the nested skills that load on demand. Each is read once. Only the memory files are read per layer,
// through ctx.
function collectLayerContext(ctx, layers) {
  const config = loadClaudeConfig(ctx);
  const shared = {
    excludes: config.claudeMdExcludes,
    files: ctx.files.map((file) => file.path).sort(compareText),
    memory: subfolderMemoryOf(ctx.files),
    rules: onDemandRulesOf(ctx),
    skills: onDemandNestedSkillsOf(config.skills),
  };
  return { context: { byLayer: layers.map((layer) => layerEntry(ctx, layer, shared)) } };
}

function layerEntry(ctx, layer, shared) {
  const scope = createScope(layer.folders);
  // The folders whose files this layer counts: the inherited folders other than the root, and the folders in the layer.
  const counts = (folder) => (folder !== ROOT && scope.isInherited(folder)) || liesIn(folder, layer.folders);
  const layerFiles = shared.files.filter((rel) => liesIn(path.posix.dirname(rel), layer.folders));
  const onDemand = [];
  const notCounted = [];

  for (const rel of shared.memory) {
    if (!counts(path.posix.dirname(rel))) continue;
    const outcome = memoryOutcome(ctx, rel, shared.excludes);
    if (outcome.item !== undefined) onDemand.push(outcome.item);
    else notCounted.push(outcome.notCounted);
  }
  for (const rule of shared.rules) {
    const outcome = outcomeOf(rule.patterns, layerFiles);
    if (outcome === MATCHED) onDemand.push({ path: rule.path, kind: "rule", estTokens: rule.estTokens });
    else if (outcome === UNSUPPORTED) notCounted.push({ path: rule.path, reason: UNSUPPORTED_REASON });
  }
  const nested = shared.skills.filter((skill) => counts(harnessFolderOf(skill.path)));

  return {
    name: layer.name,
    folders: layer.folders,
    agent: AGENT,
    onDemand: sectionOf(onDemand),
    nestedSkills: sectionOf(nested),
    notCounted: [...notCounted].sort((a, b) => compareText(a.path, b.path) || compareText(a.reason, b.reason)),
  };
}

// One subfolder memory file of a layer: the item it adds, or the notCounted entry that says why it does not count. A file that
// claudeMdExcludes matches is not read, as the memory measure does not read it.
function memoryOutcome(ctx, rel, excludes) {
  if (claudeMdExclusionOf(excludes, rel) !== null) return { notCounted: { path: rel, reason: EXCLUDED_REASON } };
  const read = ctx.readText(rel);
  if (!read.ok) return { notCounted: { path: rel, reason: read.reason } };
  return { item: { path: rel, kind: "memory", estTokens: countsOf(read.text).estTokens } };
}

// The outcome of one rule for the files of a layer. It is matched at the first pattern that matches a file, and unsupported when
// nothing matched and some pattern could not be read.
function outcomeOf(patterns, files) {
  let unsupported = false;
  for (const file of files) {
    for (const pattern of patterns) {
      const result = matchPathGlob(pattern, file);
      if (result === true) return MATCHED;
      if (result === "unsupported") unsupported = true;
    }
  }
  return unsupported ? UNSUPPORTED : NOT_MATCHED;
}

// A list of items with its estimate. Each item has an estTokens and a path, and the list is sorted by path.
function sectionOf(items) {
  const sorted = [...items].sort(byPath);
  return { estTokens: sorted.reduce((sum, item) => sum + item.estTokens, 0), items: sorted };
}

// The CLAUDE.md and CLAUDE.local.md files below the root, outside every .claude folder, sorted by path.
function subfolderMemoryOf(files) {
  return files.map((file) => file.path).filter(isSubfolderMemory).sort(compareText);
}

function isSubfolderMemory(rel) {
  const segments = rel.split("/");
  return segments.length > 1 && MEMORY_NAMES.has(segments.at(-1)) && !segments.includes(CLAUDE_DIR);
}

// The rules that the memory measure loads on demand, sorted by path, with the patterns of their paths field and the estimate of
// the whole file. A rule that claudeMdExcludes matches is not in ctx.memory, so it is not here.
function onDemandRulesOf(ctx) {
  return [...ctx.memory.entries()]
    .filter(([, node]) => node.kind === "rule" && node.loadMode === "on-demand")
    .map(([rel, node]) => ({ path: rel, patterns: pathsOf(node.text), estTokens: countsOf(node.text).estTokens }))
    .sort(byPath);
}

// The patterns of a paths field: a string, or a list of strings. Any other value gives no pattern.
function pathsOf(text) {
  const paths = parseFrontmatter(text).data?.paths;
  if (typeof paths === "string") return [paths];
  return Array.isArray(paths) ? paths.filter(isString) : [];
}

// The nested skills that claude-config lists on demand, sorted by path, with the estimate of their description.
function onDemandNestedSkillsOf(skills) {
  return skills
    .filter((skill) => skill.scope === "nested" && skill.loadMode === "on-demand")
    .map((skill) => ({ path: skill.path, estTokens: skill.estTokens }))
    .sort(byPath);
}

// Whether a folder lies in a layer: one of its folders, or inside one. "." holds every folder.
function liesIn(folder, layerFolders) {
  return layerFolders.some(
    (layerFolder) => layerFolder === ROOT || folder === layerFolder || folder.startsWith(`${layerFolder}/`),
  );
}

function byPath(a, b) {
  return compareText(a.path, b.path);
}

function isString(value) {
  return typeof value === "string";
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
