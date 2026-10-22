// Layer map of one target: the candidate units (folders that may be a layer of the target), the workspaces it declares, and a
// summarized tree of its folders. It reads the file list through safe-git, the root manifests and workspace files as data
// through safe-fs, and the harness folders through the agent inventory. It never opens code, and nothing from the target is
// run or imported. Every string that comes from the target goes through the redactor before it is returned.
//
// A unit is a folder with at least one signal: the root (always), a workspace member, a folder with its own manifest, a folder
// whose own name is typical of a layer (data/layer-signals.json, at depth 1 or 2), or a folder with its own harness files of any
// agent. The structure is "units" when a unit other than the root has a workspace, manifest or harness signal. A name alone does
// not make a structure: a repository whose sub-folders only match name hints, with no manifest, workspace or harness signal, is
// "flat" by design. A flat repository gets one suggested layer, "whole repository", whose options are its top-level folders.
//
// Harness folders come from the agent inventory (agent-inventory.mjs), run through the scanner core. The inventory reads the
// target's root-level harness files as data, and it walks the root-level harness names on disk at most MAX_WALK_DEPTH folders
// down (claude-config.mjs). A nested harness file is listed and never read; the folder that holds it is a harness folder.
//
// Caps. The tree has at most maxTreeDepth levels and at most maxTreeEntries children per node; truncated counts the child
// folders that are not shown, and a flat suggestion whose top-level folders are cut has an options-cut warning. The bytes of a
// unit are null when the repository has more than maxStats files. safe-git already stats every file it lists, so the bytes come
// from that listing, and the cap bounds the output, not the reads. A manifest over MAX_MANIFEST_BYTES is not read.
//
// Workspaces are declared only by root files: package.json (npm, or yarn with a yarn.lock), pnpm-workspace.yaml, lerna.json,
// Cargo.toml ([workspace] members and exclude), go.work (use) and pyproject.toml ([tool.uv.workspace] members and exclude).
// Their patterns are matched against the folders of the file list, and the excludes remove folders from the members. A negated
// pattern and a pattern the glob dialect cannot express are skipped with a warning. At most MAX_WORKSPACE_PATTERNS patterns (and as
// many excludes) per manifest are read; the rest are counted in one warning. The parsers use string operations and a line costs
// its length, so a hostile manifest cannot make them slow.
//
// Two raw names can redact to the same text: a masked token keeps its prefix and last four characters. In units and in the
// children of a tree node, the first name in raw path order stays, and each redacted path that lost an entry gets one
// redacted-duplicate warning.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { globProblem, loadAgentHarness, matchHarnessGlob } from "./agent-harness.mjs";
import { agentInventoryMeasure } from "./agent-inventory.mjs";
import { isPlainObject } from "./json-out.mjs";
import { loadLayerSignals } from "./layer-signals.mjs";
import { wildcardMatches } from "./permissions.mjs";
import { createRedactor } from "./redact.mjs";
import { createTargetFs } from "./safe-fs.mjs";
import { listFiles } from "./safe-git.mjs";
import { scan } from "./scanner.mjs";

/** Layout version of layers.json. Change it only when an existing field changes meaning. */
export const SCHEMA_VERSION = 1;
/** Files above which the bytes of the units are not given (they are null). */
export const MAX_STATS = 20_000;
/** Levels below the root that the tree shows. */
export const MAX_TREE_DEPTH = 3;
/** Child folders that the tree shows per node, and top-level options of a flat suggestion. */
export const MAX_TREE_ENTRIES = 30;
/** Largest manifest that is read for its workspaces. */
export const MAX_MANIFEST_BYTES = 1024 * 1024;
/** Patterns, and as many excludes, that are read per workspace manifest. */
export const MAX_WORKSPACE_PATTERNS = 200;
// The longest glob that the dialect of agent-harness.mjs accepts. A longer pattern is skipped before it is parsed.
const MAX_PATTERN_CHARS = 512;

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const ROOT = ".";
const WHOLE_REPOSITORY = "whole repository";
const LIMIT_KEYS = new Set(["maxStats", "maxTreeDepth", "maxTreeEntries"]);
const STRUCTURAL_SIGNALS = new Set(["workspace", "manifest", "harness"]);

/**
 * Maps the layers of a target.
 * @param {object} options
 * @param {string} options.root The target folder. The caller has validated it.
 * @param {Date} [options.now] The time of the run, written to meta.mappedAt.
 * @param {{ maxStats?: number, maxTreeDepth?: number, maxTreeEntries?: number }} [options.limits] Caps, for tests. Default:
 *   MAX_STATS, MAX_TREE_DEPTH and MAX_TREE_ENTRIES.
 * @returns {Promise<object>} The layers object, ready for toStableJson (see the schema in schemas/layers.schema.json).
 * @throws {TypeError | Error} For invalid options, or when the target cannot be read.
 */
export async function mapLayers({ root, now = new Date(), limits = {} } = {}) {
  if (typeof root !== "string" || root === "") throw new TypeError("mapLayers needs the path of the target folder");
  const caps = capsOf(limits);
  const signals = loadLayerSignals();
  const target = path.resolve(root);
  const listing = await listFiles(target);
  const files = listing.files;
  const counts = countDirectories(files, signals.languageOf);
  const folders = [...counts.keys()].filter((dir) => dir !== ROOT).sort(compareText);
  const fileSet = new Set(files.map((file) => file.path));
  const warnings = [...listing.warnings];

  const fsView = createTargetFs(target);
  const workspaces = readWorkspaces({ fsView, fileSet, folders, warnings });
  const harness = await harnessFolders(target, new Set(folders));
  warnings.push(...harness.warnings);

  const byFolder = signalsByFolder({ files, folders, workspaces, harness: harness.agentsOf, signals });
  const unitPaths = [...byFolder.keys()].sort(compareText);
  const bytesKnown = files.length <= caps.maxStats;
  const units = unitPaths.map((unitPath) => {
    const count = counts.get(unitPath);
    return {
      path: unitPath,
      signals: byFolder.get(unitPath),
      files: count.files,
      bytes: bytesKnown ? count.bytes : null,
      languages: [...count.languages]
        .map(([language, number]) => ({ language, files: number }))
        .sort((a, b) => b.files - a.files || compareText(a.language, b.language)),
    };
  });
  if (!bytesKnown) warnings.push({ path: ROOT, reason: "bytes-cut", detail: `count=${files.length}` });

  const tree = buildTree(counts, folders, caps.maxTreeDepth, caps.maxTreeEntries);
  const structure = units.some(
    (unit) => unit.path !== ROOT && unit.signals.some((signal) => STRUCTURAL_SIGNALS.has(signal.type)),
  )
    ? "units"
    : "flat";
  const suggestion =
    structure === "flat"
      ? { layers: [{ name: WHOLE_REPOSITORY, folders: [ROOT], options: tree.children.map((child) => child.path) }] }
      : null;
  if (suggestion !== null && tree.truncated > 0) {
    warnings.push({ path: ROOT, reason: "options-cut", detail: `count=${tree.truncated}` });
  }
  const raw = {
    structure,
    units,
    workspaces: workspaces.map(({ manager, manifest, patterns, members }) => ({ manager, manifest, patterns, members })),
    tree,
    folders: [ROOT, ...unitPaths, ...treePaths(tree)],
    suggestion,
    warnings: warnings.concat(fsView.warnings()),
  };
  return finish(raw, { root: target, now, tool: readToolName() });
}

function capsOf(limits) {
  if (!isPlainObject(limits)) throw new TypeError("limits must be an object");
  for (const key of Object.keys(limits)) {
    if (!LIMIT_KEYS.has(key)) throw new TypeError(`Unknown limit: "${key}"`);
  }
  const caps = { maxStats: MAX_STATS, maxTreeDepth: MAX_TREE_DEPTH, maxTreeEntries: MAX_TREE_ENTRIES, ...limits };
  for (const [key, value] of Object.entries(caps)) {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${key} must be a non-negative safe integer`);
  }
  return caps;
}

function readToolName() {
  const manifest = JSON.parse(fs.readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
  return `${manifest.name}@${manifest.version}`;
}

// ---------------------------------------------------------------------------------------------------
// Counts per folder: the files, bytes and languages below each folder, the root included.

// Every folder of the file list (and the root) gets the totals of the files below it, at any depth.
function countDirectories(files, languageOf) {
  const counts = new Map();
  const entryOf = (dir) => {
    if (!counts.has(dir)) counts.set(dir, { files: 0, bytes: 0, languages: new Map() });
    return counts.get(dir);
  };
  entryOf(ROOT);
  for (const file of files) {
    const language = languageOf.get(path.posix.extname(file.path).toLowerCase()) ?? null;
    for (const dir of ancestorsOf(file.path)) {
      const count = entryOf(dir);
      count.files += 1;
      count.bytes += file.bytes;
      if (language !== null) count.languages.set(language, (count.languages.get(language) ?? 0) + 1);
    }
  }
  return counts;
}

// The root and every folder above a file, nearest to the root first.
function ancestorsOf(rel) {
  const parts = rel.split("/");
  const dirs = [ROOT];
  for (let index = 1; index < parts.length; index += 1) dirs.push(parts.slice(0, index).join("/"));
  return dirs;
}

// ---------------------------------------------------------------------------------------------------
// Signals and units

// The signals of each folder: a manifest per manifest file below the root, a name per typical folder name, a workspace per
// member and a harness per folder with the agents that own files in it. The root always has one signal, root.
function signalsByFolder({ files, folders, workspaces, harness, signals }) {
  const byFolder = new Map([[ROOT, [{ type: "root" }]]]);
  const add = (folder, signal) => {
    if (!byFolder.has(folder)) byFolder.set(folder, []);
    byFolder.get(folder).push(signal);
  };
  for (const file of files) {
    const dir = path.posix.dirname(file.path);
    const base = path.posix.basename(file.path);
    if (dir !== ROOT && signals.manifests.has(base)) add(dir, { type: "manifest", file: base });
  }
  for (const folder of folders) {
    const segments = folder.split("/");
    const hint = segments.length <= 2 ? signals.hintOf.get(segments[segments.length - 1].toLowerCase()) : undefined;
    if (hint !== undefined) add(folder, { type: "name", hint });
  }
  for (const workspace of workspaces) {
    for (const member of workspace.members) {
      add(member, { type: "workspace", manager: workspace.manager, manifest: workspace.manifest });
    }
  }
  for (const [folder, agents] of harness) {
    add(folder, { type: "harness", agents: [...agents].sort(compareText) });
  }
  return byFolder;
}

// The tree of folders from the root. A node shows at most maxEntries children, sorted by path, and stops at maxDepth levels;
// truncated counts the child folders that are not shown, for either reason.
function buildTree(counts, folders, maxDepth, maxEntries) {
  const childrenOf = new Map();
  for (const folder of folders) {
    const parent = path.posix.dirname(folder);
    if (!childrenOf.has(parent)) childrenOf.set(parent, []);
    childrenOf.get(parent).push(folder);
  }
  for (const list of childrenOf.values()) list.sort(compareText);
  const node = (dir, depth) => {
    const children = childrenOf.get(dir) ?? [];
    const result = { path: dir, files: counts.get(dir).files, children: [], truncated: 0 };
    if (depth >= maxDepth) {
      result.truncated = children.length;
      return result;
    }
    const shown = children.slice(0, maxEntries);
    result.children = shown.map((child) => node(child, depth + 1));
    result.truncated = children.length - shown.length;
    return result;
  };
  return node(ROOT, 0);
}

function treePaths(node) {
  return [node.path, ...node.children.flatMap(treePaths)];
}

// ---------------------------------------------------------------------------------------------------
// Workspaces

// Each declaration reads one root file as text. manager is a function of the file set (package.json is yarn when a yarn.lock is
// at the root). read returns { patterns, excludes } from the text, or throws a ManifestError with a fixed detail.
const DECLARATIONS = Object.freeze([
  { file: "package.json", manager: (fileSet) => (fileSet.has("yarn.lock") ? "yarn" : "npm"), read: readPackageJson },
  { file: "pnpm-workspace.yaml", manager: () => "pnpm", read: readPnpmWorkspace },
  { file: "lerna.json", manager: () => "lerna", read: readLernaJson },
  { file: "Cargo.toml", manager: () => "cargo", read: (text) => readTomlWorkspace(text, "workspace") },
  { file: "go.work", manager: () => "go", read: readGoWork },
  { file: "pyproject.toml", manager: () => "uv", read: (text) => readTomlWorkspace(text, "tool.uv.workspace") },
]);

class ManifestError extends Error {
  constructor(detail) {
    super(detail);
    this.detail = detail;
  }
}

/**
 * The workspace declaration of one root file, read from its text. It never throws for bad data: a text that cannot be parsed
 * gives { ok: false, detail } with a fixed detail code. Nothing in the text is run.
 * @param {string} file One of the workspace files, such as "package.json" or "Cargo.toml".
 * @param {string} text The file as text.
 * @returns {{ ok: true, patterns: unknown[], excludes: unknown[] } | { ok: false, detail: string }}
 */
export function readWorkspaceFile(file, text) {
  const declaration = DECLARATIONS.find((item) => item.file === file);
  if (declaration === undefined) throw new TypeError(`${file} is not a workspace file`);
  try {
    return { ok: true, ...declaration.read(text) };
  } catch (error) {
    if (!(error instanceof ManifestError)) throw error;
    return { ok: false, detail: error.detail };
  }
}

// The workspaces declared by the root files, in the order of DECLARATIONS. A file that cannot be read or parsed gives a
// manifest-unparsed warning. A declaration with no pattern is not a workspace.
function readWorkspaces({ fsView, fileSet, folders, warnings }) {
  const workspaces = [];
  for (const declaration of DECLARATIONS) {
    if (!fileSet.has(declaration.file)) continue;
    const read = fsView.readText(declaration.file, { maxBytes: MAX_MANIFEST_BYTES });
    if (!read.ok) {
      warnings.push({ path: declaration.file, reason: "manifest-unparsed", detail: read.reason });
      continue;
    }
    const declared = readWorkspaceFile(declaration.file, read.text);
    if (!declared.ok) {
      warnings.push({ path: declaration.file, reason: "manifest-unparsed", detail: declared.detail });
      continue;
    }
    if (declared.patterns.length === 0) continue;
    const manager = declaration.manager(fileSet);
    workspaces.push(workspaceOf({ declaration, manager, declared, folders, warnings }));
  }
  return workspaces;
}

// The members of one workspace: the folders that a pattern matches and no exclude matches. The root "." is a member of nothing.
// patterns lists the declared patterns that were read, including the skipped ones, so the file can be compared with the output.
function workspaceOf({ declaration, manager, declared, folders, warnings }) {
  const included = matchersOf(declaration.file, declared.patterns, warnings);
  const excluded = matchersOf(declaration.file, declared.excludes, warnings);
  const members = folders.filter(
    (folder) => included.matchers.some((matches) => matches(folder)) && !excluded.matchers.some((matches) => matches(folder)),
  );
  return { manager, manifest: declaration.file, patterns: included.kept, members };
}

// The matchers of one list of patterns, read as far as MAX_WORKSPACE_PATTERNS. A pattern that is not a string, that is too long,
// that is negated or that the glob dialect cannot express gives a warning and no matcher. kept holds the strings that were read.
function matchersOf(file, list, warnings) {
  const kept = [];
  const matchers = [];
  const skip = (detail) => warnings.push({ path: file, reason: "workspace-pattern-skipped", detail });
  const read = list.length > MAX_WORKSPACE_PATTERNS ? list.slice(0, MAX_WORKSPACE_PATTERNS) : list;
  if (list.length > MAX_WORKSPACE_PATTERNS) {
    warnings.push({ path: file, reason: "workspace-patterns-cut", detail: `count=${list.length - MAX_WORKSPACE_PATTERNS}` });
  }
  for (const item of read) {
    if (typeof item !== "string") {
      skip("not-a-string");
      continue;
    }
    if (item.length > MAX_PATTERN_CHARS) {
      skip("unsupported");
      continue;
    }
    kept.push(item);
    const parsed = patternOf(item);
    if (parsed.skip !== undefined) skip(parsed.skip);
    else if (parsed.pattern !== undefined) matchers.push(matcherOf(parsed.pattern));
  }
  return { kept, matchers };
}

// The glob of one declared pattern: leading "./" and trailing "/" are dropped, and the glob dialect is checked here, once per
// pattern. { root: true } for "." (the root is not a member), { skip } for a negated pattern or one the dialect cannot express,
// and { pattern } otherwise. Every step is linear in the length of the pattern.
function patternOf(item) {
  const text = item.trim();
  if (text.startsWith("!")) return { skip: "negated" };
  let start = 0;
  while (text.startsWith("./", start)) start += 2;
  let end = text.length;
  while (end > start && text[end - 1] === "/") end -= 1;
  const pattern = text.slice(start, end);
  if (pattern === "" || pattern === ".") return { root: true };
  if (globProblem(pattern) !== null) return { skip: "unsupported" };
  return { pattern };
}

// The matcher of one pattern that patternOf has checked. The dialect is the one of agent-harness.mjs: "**" matches zero or more
// whole segments, and "*" any run of characters inside one segment. matchHarnessGlob would check the glob again for every folder.
function matcherOf(pattern) {
  const segments = pattern.split("/");
  return (folder) => {
    const names = folder.split("/");
    let reach = Array.from({ length: names.length + 1 }, (_, count) => count === 0);
    for (const segment of segments) {
      const next = [segment === "**" && reach[0]];
      for (let count = 1; count <= names.length; count += 1) {
        next.push(
          segment === "**"
            ? next[count - 1] || reach[count]
            : reach[count - 1] && wildcardMatches(segment, names[count - 1]),
        );
      }
      reach = next;
    }
    return reach[names.length];
  };
}

function declaredLists(patterns, excludes = []) {
  return { patterns, excludes };
}

function readPackageJson(text) {
  const data = parseJson(text);
  if (!Object.hasOwn(data, "workspaces")) return declaredLists([]);
  const value = data.workspaces;
  if (Array.isArray(value)) return declaredLists(value);
  if (isPlainObject(value) && Array.isArray(value.packages)) return declaredLists(value.packages);
  throw new ManifestError("invalid-shape");
}

function readLernaJson(text) {
  const data = parseJson(text);
  if (!Object.hasOwn(data, "packages")) return declaredLists([]);
  if (!Array.isArray(data.packages)) throw new ManifestError("invalid-shape");
  return declaredLists(data.packages);
}

function parseJson(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new ManifestError("invalid-json");
  }
  if (!isPlainObject(data)) throw new ManifestError("invalid-shape");
  return data;
}

// The packages list of pnpm-workspace.yaml: a block sequence under packages:, or one inline list on the same line. Each line is
// read with string operations, so a long line costs its length.
function readPnpmWorkspace(text) {
  const lines = text.split("\n");
  const index = lines.findIndex(isPackagesKey);
  if (index === -1) return declaredLists([]);
  const afterKey = lines[index].slice("packages".length).trimStart().slice(1);
  const rest = stripComment(afterKey.trim());
  if (rest.startsWith("[")) {
    const list = readStringList(rest, 0);
    if (list === null) throw new ManifestError("invalid-yaml");
    return declaredLists(list.items);
  }
  if (rest !== "") throw new ManifestError("invalid-yaml");
  const patterns = [];
  for (let line = index + 1; line < lines.length; line += 1) {
    const trimmed = lines[line].trimStart();
    if (trimmed === "" || trimmed.startsWith("#")) continue;
    if (trimmed === "-" || (trimmed.startsWith("-") && /\s/.test(trimmed.charAt(1)))) {
      patterns.push(yamlScalar(stripComment(trimmed.slice(1).trim())));
    } else if (!/^\s/.test(lines[line])) {
      break;
    } else {
      throw new ManifestError("invalid-yaml");
    }
  }
  return declaredLists(patterns);
}

// A line that opens the packages key: "packages", optional spaces, then a colon.
function isPackagesKey(line) {
  return line.startsWith("packages") && line.slice("packages".length).trimStart().startsWith(":");
}

// The members and the excludes of a workspace table of a TOML file.
function readTomlWorkspace(text, table) {
  return declaredLists(readTomlList(text, table, "members"), readTomlList(text, table, "exclude"));
}

// The strings of one key of one table in a TOML file, such as members or exclude of [workspace]. The table is the last header
// above the key. The value is a list that may span lines (readStringList reads it). A file without the table or the key has an
// empty list. The header and the key are found with string operations, not with patterns.
function readTomlList(text, table, key) {
  const lines = text.split("\n");
  let current = "";
  for (let index = 0; index < lines.length; index += 1) {
    const header = tomlHeaderOf(lines[index]);
    if (header !== null) {
      current = header;
      continue;
    }
    if (current !== table) continue;
    const value = valueOfKey(lines[index], key);
    if (value === null) continue;
    if (!value.startsWith("[")) throw new ManifestError("invalid-toml");
    const rest = lines.slice(index).join("\n");
    const list = readStringList(rest, rest.indexOf("["));
    if (list === null) throw new ManifestError("invalid-toml");
    return list.items;
  }
  return [];
}

// The table name of a TOML header line, "[name]" or "[[name]]", with an optional comment. Null for any other line.
function tomlHeaderOf(line) {
  const trimmed = line.trim();
  if (!trimmed.startsWith("[")) return null;
  let rest = trimmed.slice(1);
  if (rest.startsWith("[")) rest = rest.slice(1);
  const close = rest.indexOf("]");
  if (close === -1) return null;
  const name = rest.slice(0, close).trim();
  if (name === "" || name.includes("[")) return null;
  let after = rest.slice(close + 1);
  if (after.startsWith("]")) after = after.slice(1);
  after = after.trim();
  return after === "" || after.startsWith("#") ? name : null;
}

// The text after "=" when the line sets the key (after optional spaces), or null.
function valueOfKey(line, key) {
  const trimmed = line.trimStart();
  if (!trimmed.startsWith(key)) return null;
  const after = trimmed.slice(key.length).trimStart();
  return after.startsWith("=") ? after.slice(1).trimStart() : null;
}

// The use directives of go.work: "use ./dir" on one line, or the lines of a "use (" block. A comment runs from "//" to the end of
// its line, and it is found with indexOf.
function readGoWork(text) {
  const patterns = [];
  let block = false;
  for (const raw of text.split("\n")) {
    const cut = raw.indexOf("//");
    const line = (cut === -1 ? raw : raw.slice(0, cut)).trim();
    if (block) {
      if (line === ")") block = false;
      else if (line !== "") patterns.push(unquote(line));
      continue;
    }
    const argument = useArgumentOf(line);
    if (argument === null) continue;
    if (argument === "(") block = true;
    else if (argument !== "") patterns.push(unquote(argument));
  }
  return declaredLists(patterns);
}

// The text after the word "use" of a go.work line, or null when the line is not a use directive.
function useArgumentOf(line) {
  if (!line.startsWith("use")) return null;
  const after = line.slice("use".length);
  if (after !== "" && !/^[\s(]/.test(after)) return null;
  return after.trim();
}

// Reads a list that starts at text[start], which is "[", and ends at its "]". Items are quoted or plain tokens, separated by
// commas and whitespace; a "#" comment runs to the end of its line. Returns { items, end } or null when the list is not closed
// or has something else in it.
function readStringList(text, start) {
  const items = [];
  let index = start + 1;
  while (index < text.length) {
    const char = text[index];
    if (char === "," || /\s/.test(char)) {
      index += 1;
    } else if (char === "#") {
      const newline = text.indexOf("\n", index);
      if (newline === -1) return null;
      index = newline + 1;
    } else if (char === "]") {
      return { items, end: index + 1 };
    } else {
      const item = char === '"' || char === "'" ? readQuoted(text, index) : readPlain(text, index);
      if (item === null) return null;
      items.push(item.value);
      index = item.end;
    }
  }
  return null;
}

// A quoted string that starts at text[index]. A double-quoted string takes a backslash as an escape for the next character.
// Returns { value, end } or null when it is not closed on its line.
function readQuoted(text, index) {
  const quote = text[index];
  let value = "";
  for (let at = index + 1; at < text.length; at += 1) {
    const char = text[at];
    if (char === "\n") return null;
    if (quote === '"' && char === "\\" && at + 1 < text.length) {
      value += text[at + 1];
      at += 1;
    } else if (char === quote) {
      return { value, end: at + 1 };
    } else {
      value += char;
    }
  }
  return null;
}

function readPlain(text, index) {
  const pattern = /[^\s,[\]"'#]+/y;
  pattern.lastIndex = index;
  const match = pattern.exec(text);
  return match === null ? null : { value: match[0], end: index + match[0].length };
}

// The text before a comment. A quoted value keeps its quotes and loses what follows the closing quote.
function stripComment(text) {
  if (text[0] === '"' || text[0] === "'") {
    const end = text.indexOf(text[0], 1);
    return end === -1 ? text : text.slice(0, end + 1);
  }
  const hash = text.search(/(^|\s)#/);
  return hash === -1 ? text : text.slice(0, hash);
}

function yamlScalar(text) {
  const value = text.trim();
  if (value[0] === '"' || value[0] === "'") {
    const quoted = readQuoted(value, 0);
    if (quoted === null) throw new ManifestError("invalid-yaml");
    return quoted.value;
  }
  return value;
}

function unquote(text) {
  const first = text[0];
  if (text.length >= 2 && (first === '"' || first === "'" || first === "`") && text.endsWith(first)) {
    return text.slice(1, -1);
  }
  return text;
}

// ---------------------------------------------------------------------------------------------------
// Harness folders

// The folders below the root that hold harness files of an agent, with the agents. It runs the agent inventory on the target
// through the scanner core. That measure reads the target's root-level harness files and the settings of Claude Code; a nested
// file is listed and never read.
async function harnessFolders(root, folderSet) {
  const globOf = new Map(loadAgentHarness(HARNESS_ROOT).files.map((entry) => [entry.id, entry.glob]));
  const measured = await scan({ root, measures: [agentInventoryMeasure] });
  const agentsOf = new Map();
  for (const item of measured.agentHarness.items) {
    if (!item.nested) continue;
    const folder = nestedFolderOf(item.path, globOf.get(item.entry));
    if (folder === null || !folderSet.has(folder)) continue;
    if (!agentsOf.has(folder)) agentsOf.set(folder, new Set());
    agentsOf.get(folder).add(item.agent);
  }
  const warnings = measured.warnings.map(({ path: where, reason, detail }) =>
    detail === undefined ? { path: where, reason } : { path: where, reason, detail },
  );
  return { agentsOf, warnings };
}

// The folder of a nested file: the part of its path that the leading wildcard segments of its glob match. The rest of the glob
// (from its first literal segment) must match the rest of the path. For "**/AGENTS.md" that is the dirname; for
// "*/**/.claude/skills/*/SKILL.md" it is the part before ".claude". The shortest such folder wins.
function nestedFolderOf(rel, glob) {
  const names = rel.split("/");
  const segments = glob.split("/");
  const first = segments.findIndex((segment) => !segment.includes("*"));
  if (first === -1) return names.length > 1 ? names.slice(0, -1).join("/") : null;
  if (first === 0) return null;
  const leadingSegments = segments.slice(0, first);
  // A leading run of "**" alone matches any folder, and the matcher refuses a glob made only of "**" segments.
  const anyFolder = leadingSegments.every((segment) => segment === "**");
  const leading = leadingSegments.join("/");
  const rest = segments.slice(first).join("/");
  for (let count = 1; count < names.length; count += 1) {
    const folder = names.slice(0, count).join("/");
    const leadingFits = anyFolder || matchHarnessGlob(leading, folder);
    if (leadingFits && matchHarnessGlob(rest, names.slice(count).join("/"))) return folder;
  }
  return null;
}

// ---------------------------------------------------------------------------------------------------
// Output

// Redacts every string of the raw result (meta is not in it: targetRoot is the one absolute path). The lists are still in raw
// path order at this point, so the first name of each redacted path is the first in raw order. The duplicates that the
// redaction made are dropped from units and from the children of each tree node, with one redacted-duplicate warning per
// redacted path. Then the lists are sorted by their redacted values.
function finish(raw, { root, now, tool }) {
  const redact = createRedactor({ root });
  const clean = redactDeep(raw, redact);
  const dropped = new Set();
  const units = firstPerPath(clean.units, (unit) => unit.path, dropped)
    .map((unit) => ({ ...unit, signals: [...unit.signals].sort(compareSignals) }))
    .sort((a, b) => compareText(a.path, b.path));
  const tree = sortTree(dedupeChildren(clean.tree, dropped));
  const workspaces = clean.workspaces
    .map((workspace) => ({
      manager: workspace.manager,
      manifest: workspace.manifest,
      patterns: sortedUnique(workspace.patterns),
      members: sortedUnique(workspace.members),
    }))
    .sort((a, b) => compareText(a.manifest, b.manifest) || compareText(a.manager, b.manager));
  const folders = sortedUnique(clean.folders);
  const suggestion =
    clean.suggestion === null
      ? null
      : { layers: clean.suggestion.layers.map((layer) => ({ ...layer, options: sortedUnique(layer.options) })) };
  const duplicates = [...dropped].sort(compareText).map((where) => ({ path: where, reason: "redacted-duplicate" }));
  return {
    schemaVersion: SCHEMA_VERSION,
    meta: { tool, mappedAt: now.toISOString(), targetRoot: root },
    structure: clean.structure,
    units,
    workspaces,
    tree,
    folders,
    suggestion,
    warnings: sortWarnings([...clean.warnings, ...duplicates]),
  };
}

// The items whose key is new, in their order. An item whose key was already kept is dropped, and its key is added to dropped.
function firstPerPath(items, keyOf, dropped) {
  const seen = new Set();
  return items.filter((item) => {
    const key = keyOf(item);
    if (seen.has(key)) {
      dropped.add(key);
      return false;
    }
    seen.add(key);
    return true;
  });
}

// The tree with the duplicate children dropped at every node (see firstPerPath). The order of the nodes is kept.
function dedupeChildren(node, dropped) {
  const children = firstPerPath(node.children, (child) => child.path, dropped);
  return { ...node, children: children.map((child) => dedupeChildren(child, dropped)) };
}

function redactDeep(value, redact) {
  if (typeof value === "string") return redact(value);
  if (Array.isArray(value)) return value.map((item) => redactDeep(item, redact));
  if (value !== null && typeof value === "object") {
    const copy = {};
    for (const key of Object.keys(value)) copy[key] = redactDeep(value[key], redact);
    return copy;
  }
  return value;
}

function compareSignals(a, b) {
  return compareText(a.type, b.type) || compareText(JSON.stringify(a), JSON.stringify(b));
}

function sortTree(node) {
  return { ...node, children: node.children.map(sortTree).sort((a, b) => compareText(a.path, b.path)) };
}

function sortWarnings(warnings) {
  const unique = new Map();
  for (const warning of warnings) {
    const key = JSON.stringify([warning.path, warning.reason, warning.detail ?? null]);
    if (!unique.has(key)) unique.set(key, warning);
  }
  return [...unique.values()].sort(
    (a, b) =>
      compareText(a.path, b.path) || compareText(a.reason, b.reason) || compareText(a.detail ?? "", b.detail ?? ""),
  );
}

function sortedUnique(list) {
  return [...new Set(list)].sort(compareText);
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
