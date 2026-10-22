// Measure "memory": the memory files that Claude Code loads at the start of a session, and how much
// they weigh. It finds CLAUDE.md, .claude/CLAUDE.md, CLAUDE.local.md, AGENTS.md and .claude/AGENTS.md at
// the root, the rules of .claude/rules/ (with and without paths), and the files that the loaded memory
// files import with @path. The CLAUDE.md and AGENTS.md files of subfolders are listed and never read.
// The parent folders of the target are checked by existence and size only.
//
// The target is read only through ctx.fs and ctx.readText, with root-relative paths. An import that
// leaves the target, or that points to the home folder, is recorded as external: it is never read and
// never stat-ed. Nothing from the target is run.
//
// Output: one inventory item per memory or rule file, the "memory" component of the always-loaded
// budget, and context.ancestors, context.imports and context.limits. The text of each file that was
// read goes to ctx.memory, for the measures that come after.
//
// claudeMdExcludes (read by claude-config) stops the memory and rule files that its patterns match from loading. Such a
// file is listed as not-loaded with loadReason "claude-md-excludes" and excludedBy, and it is never read: it is not in
// the budget, not in ctx.memory and its imports are not followed. NOT VERIFIED, none of these by a note: that
// claudeMdExcludes covers .claude/rules/ (applying it there follows this repository's CLAUDE.md); that it covers AGENTS.md
// (AGENTS.md is treated as covered); that matching is case-sensitive; that a trailing slash is dropped (gitignore's
// directory-only meaning is not kept); that ancestor files are not checked against the patterns; and that Claude Code does
// not load an import of an excluded file (an import of one is given status "excluded" and is not followed).
// Excluding a CLAUDE file at the root does not count it as a CLAUDE file for the AGENTS rule: when the excluded files are
// the only root CLAUDE files, the root AGENTS file is not-loaded with loadReason CLAUDE_EXCLUDED_AGENTS_REASON, which
// CTX-07 reports as undeterminable. Whether Claude Code then loads AGENTS.md is not verified.
// The secrets measure still scans an excluded file for secret values, on purpose: Claude's Read can open it. This measure
// does not read it.

import os from "node:os";
import path from "node:path";
import { loadClaudeConfig } from "./claude-config.mjs";
import { parseFrontmatter } from "./frontmatter.mjs";
import { closesFence, maskCodeSpans, opensFence } from "./markdown.mjs";
import { matchPathGlob } from "./permissions.mjs";
import { createRedactor } from "./redact.mjs";
import { DEFAULT_MAX_BYTES, statOutside } from "./safe-fs.mjs";
import { estimateTokens } from "./tokens.mjs";

export const MEASURE_ID = "memory";
// The loadReason of a memory or rule file that claudeMdExcludes matches. CTX-07 and the memory candidates read it.
export const EXCLUDED_REASON = "claude-md-excludes";
// The loadReason of a root AGENTS file when the only root CLAUDE files are excluded, and no CLAUDE file is found above. The
// file is not-loaded, as it would be with a CLAUDE file that does not import it, but the cause is not verified. CTX-07 reads it.
export const CLAUDE_EXCLUDED_AGENTS_REASON = "claude-md-excluded-agents-unverified";

// Import hops below a memory file. The file that Claude Code loads is hop 0; an import that would be
// hop 5 is not read (docs: memory).
const MAX_IMPORT_DEPTH = 4;
// Recommended length of a CLAUDE.md file (docs: memory).
const MAX_LINES = 200;

// Memory files that the target folder itself can hold. The three CLAUDE files are the ones that stop
// AGENTS.md from loading by default (docs: memory).
const CLAUDE_FILES = ["CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md"];
const AGENTS_FILES = ["AGENTS.md", ".claude/AGENTS.md"];
const ROOT_FILES = [...CLAUDE_FILES, ...AGENTS_FILES];
const RULES_DIR = ".claude/rules";
const SUBFOLDER_NAMES = new Set(["CLAUDE.md", "AGENTS.md"]);
// Files under these folders are read by the claude-config measure as agents and commands.
const CONFIG_FOLDERS = [".claude/agents/", ".claude/commands/"];

const ROOT_REASON = "memory file at the root, loaded at session start";
const NO_CLAUDE_REASON = "no CLAUDE.md in the target or its ancestors";
const NOT_LOADED_REASON = "a CLAUDE.md exists and does not import it";
const RULE_ALWAYS_REASON = "rule without paths, loaded at session start";
const RULE_PATHS_REASON = "rule with paths, loaded when a matching file is read";
const RULE_INVALID_REASON = "rule with invalid frontmatter, loaded at session start";
const SUBFOLDER_REASON = "subfolder memory, loaded when a file in its folder is read";
const TOO_LARGE_REASON = "not read: larger than 4 MiB";

// Reason code of a memory file that is skipped because it is larger than the cap.
const TOO_LARGE = "too-large";

// "@" at the start of a line or after whitespace, then the path up to the next whitespace. The mask
// character (see markdown.mjs) stands for a code span, so an import never starts inside one.
const IMPORT_PATTERN = /(?<!\S)@([^\s\u0001]+)/gu;
const TRAILING_PUNCTUATION = /[.,;:!?)]+$/;

export const memoryMeasure = createMemoryMeasure();

/**
 * Builds the memory measure. The defaults are the production values; the options are a test seam.
 * @param {object} [options]
 * @param {string} [options.ancestorLimit] Absolute folder where the walk over the parent folders stops,
 *   inclusive. It must be the target or one of its parents. Default: walk up to the file system root.
 * @param {string} [options.home] Home folder. Its .claude/CLAUDE.md is user memory and is not counted.
 *   Default: os.homedir().
 * @returns {{ id: string, collect: (ctx: object) => object }}
 */
export function createMemoryMeasure({ ancestorLimit, home = os.homedir() } = {}) {
  if (ancestorLimit !== undefined && (typeof ancestorLimit !== "string" || !path.isAbsolute(ancestorLimit))) {
    throw new TypeError("ancestorLimit must be an absolute folder");
  }
  if (typeof home !== "string" || !path.isAbsolute(home)) throw new TypeError("home must be an absolute folder");
  return Object.freeze({
    id: MEASURE_ID,
    collect: (ctx) => collectMemory(ctx, { ancestorLimit, home }),
  });
}

function collectMemory(ctx, options) {
  const root = path.resolve(ctx.root);
  const state = {
    ctx,
    root,
    redact: createRedactor({ root, home: options.home }),
    // Keyed by key(path). A node keeps the spelling of the first path that reached it.
    nodes: new Map(),
    queue: [],
    imports: [],
    warnings: [],
    // The valid claudeMdExcludes patterns, in file order: { pattern, shown, source }. Read once, through claude-config.
    excludes: loadClaudeConfig(ctx).claudeMdExcludes,
  };

  // 1. The CLAUDE files of the root, and every file that a loaded one imports.
  const rootClaude = CLAUDE_FILES.filter((rel) => probeFile(ctx, rel).state !== "absent");
  for (const rel of CLAUDE_FILES) {
    admit(state, rel, { kind: "memory", loadMode: "always", reason: ROOT_REASON, depth: 0, parent: null });
  }
  traverse(state);

  // 2. The AGENTS files of the root. Ancestors are checked by existence only. An AGENTS file that a
  // loaded file imports has already been admitted above, so it is loaded once. The root CLAUDE files that
  // claudeMdExcludes matches are not CLAUDE files for this rule: they are not loaded, so they do not keep AGENTS.md from
  // loading. Their absence leaves the case unverified, which the loadReason says.
  const ancestors = collectAncestors(root, options);
  const claudeAtRoot = rootClaude.some((rel) => exclusionOf(state, rel) === null);
  const claudeAtRootExcluded = rootClaude.length > 0 && !claudeAtRoot;
  const agents = agentsSpecOf({ claudeAtRoot, claudeAtRootExcluded, ancestorClaude: ancestors.claudePresent });
  for (const rel of AGENTS_FILES) {
    if (state.nodes.has(key(rel))) continue;
    admit(state, rel, { kind: "memory", ...agents, depth: 0, parent: null });
  }
  traverse(state);

  // 3. Rules. They run after the imports, so a rule that a memory file imports is an import instead.
  for (const rel of findRuleFiles(ctx)) {
    if (state.nodes.has(key(rel))) continue;
    admit(state, rel, { kind: "rule", loadMode: null, reason: null, depth: null, parent: null });
  }

  // 4. Memory files of subfolders. They come from the file list, and they are never read.
  for (const entry of ctx.files) {
    if (!isSubfolderMemory(entry.path) || state.nodes.has(key(entry.path))) continue;
    const node = {
      path: entry.path,
      kind: "memory",
      loadMode: "on-demand",
      loadReason: SUBFOLDER_REASON,
      bytes: entry.bytes,
      lines: null,
      estTokens: null,
      text: null,
      depth: null,
      parent: null,
      skipped: null,
      excludedBy: null,
    };
    const excluded = exclusionOf(state, entry.path);
    if (excluded !== null) excludeNode(node, excluded);
    state.nodes.set(key(entry.path), node);
  }

  const nodes = [...state.nodes.values()].sort(byPath);
  for (const node of nodes) {
    if (node.text !== null) ctx.memory.set(node.path, { text: node.text, kind: node.kind, loadMode: node.loadMode });
  }
  return {
    inventory: nodes.map(inventoryItem),
    warnings: state.warnings,
    context: {
      alwaysLoaded: { byComponent: [budgetOf(nodes)] },
      ancestors: ancestors.entries,
      imports: state.imports.sort(compareImports),
      limits: limitsOf(nodes),
    },
  };
}

// How a root AGENTS file loads. A CLAUDE file that loads in the root or in an ancestor keeps it from loading. When the only
// root CLAUDE files are excluded and no ancestor has one, the result is not verified, so it has its own loadReason.
// Otherwise no CLAUDE file exists and the file loads.
function agentsSpecOf({ claudeAtRoot, claudeAtRootExcluded, ancestorClaude }) {
  if (claudeAtRoot || ancestorClaude) return { loadMode: "not-loaded", reason: NOT_LOADED_REASON };
  if (claudeAtRootExcluded) return { loadMode: "not-loaded", reason: CLAUDE_EXCLUDED_AGENTS_REASON };
  return { loadMode: "always", reason: NO_CLAUDE_REASON };
}

// ---------------------------------------------------------------------------------------------------
// Nodes: the memory and rule files that the measure knows about

// Reads one memory or rule file, when it is a file of the target, and records it as a node. A file
// larger than the cap is not read. A file that cannot be read is kept as not loaded. Returns the node,
// or null when the path is not a file that this measure can use.
function admit(state, rel, spec) {
  const probe = probeFile(state.ctx, rel);
  if (probe.state !== "file") return null;
  const node = {
    path: rel,
    kind: spec.kind,
    loadMode: spec.loadMode,
    loadReason: spec.reason,
    bytes: probe.bytes,
    lines: null,
    estTokens: null,
    text: null,
    depth: spec.depth,
    parent: spec.parent,
    skipped: null,
    excludedBy: null,
  };
  state.nodes.set(key(rel), node);

  const excluded = exclusionOf(state, rel);
  if (excluded !== null) {
    excludeNode(node, excluded);
    return node;
  }
  if (probe.bytes > DEFAULT_MAX_BYTES) {
    skip(state, node, TOO_LARGE, TOO_LARGE_REASON);
    return node;
  }
  const read = state.ctx.readText(rel);
  if (!read.ok) {
    skip(state, node, read.reason, `not read: ${read.reason}`);
    return node;
  }
  node.text = read.text;
  node.bytes = read.bytes;
  node.lines = countLines(read.text);
  node.estTokens = estimateTokens(read.text).estTokens;
  if (node.kind === "rule") applyRuleMode(state, node);
  if (node.kind === "memory" && node.loadMode === "always") state.queue.push(node);
  return node;
}

function skip(state, node, reason, loadReason) {
  node.skipped = reason;
  node.loadMode = "not-loaded";
  node.loadReason = loadReason;
  if (reason === TOO_LARGE) state.warnings.push({ path: node.path, reason: TOO_LARGE });
}

// The mode of a rule comes from its frontmatter: a rule with paths loads when a matching file is read,
// any other rule loads at the start. Broken frontmatter, or a paths value of the wrong type, is a
// warning, and the rule is treated as a rule without paths.
function applyRuleMode(state, node) {
  const parsed = parseFrontmatter(node.text);
  const paths = parsed.data?.paths;
  if (parsed.error !== undefined || isInvalidPaths(paths)) {
    state.warnings.push({ path: node.path, reason: "invalid-frontmatter" });
    setMode(node, "always", RULE_INVALID_REASON);
  } else if (paths === undefined || paths === null) {
    setMode(node, "always", RULE_ALWAYS_REASON);
  } else {
    setMode(node, "on-demand", RULE_PATHS_REASON);
  }
}

// A string, or a list of strings, is a valid paths value. Anything else that is set is not.
function isInvalidPaths(value) {
  if (value === undefined || value === null || typeof value === "string") return false;
  if (Array.isArray(value)) return !value.every((item) => typeof item === "string");
  return true;
}

function setMode(node, loadMode, loadReason) {
  node.loadMode = loadMode;
  node.loadReason = loadReason;
}

// The first claudeMdExcludes pattern, in file order, that matches the root-relative path of the file. Null when none matches.
// Every pattern here is relative: claude-config refuses a pattern with a leading "/" or a drive letter, because its meaning
// is not verified. Matching is case-sensitive (NOT VERIFIED by a note).
function exclusionOf(state, rel) {
  for (const entry of state.excludes) {
    if (matchPathGlob(entry.pattern, rel) === true) return entry;
  }
  return null;
}

// A node that claudeMdExcludes matches: not loaded, and never read. The pattern is shown in its redacted form.
function excludeNode(node, entry) {
  node.loadMode = "not-loaded";
  node.loadReason = EXCLUDED_REASON;
  node.excludedBy = entry.shown;
}

// One inventory item. excludedBy is present only on a file that claudeMdExcludes matches.
function inventoryItem(node) {
  const item = {
    path: node.path,
    kind: node.kind,
    loadMode: node.loadMode,
    loadReason: node.loadReason,
    bytes: node.bytes,
    lines: node.lines,
    estTokens: node.estTokens,
  };
  if (node.excludedBy !== null) item.excludedBy = node.excludedBy;
  return item;
}

// Follows the imports of every loaded memory file, breadth first, so that each file gets the smallest
// depth at which it can be reached.
function traverse(state) {
  while (state.queue.length > 0) {
    const node = state.queue.shift();
    for (const found of importsOf(node.text)) recordImport(state, node, found);
  }
}

// Classifies one import of a loaded file. The checks run in this order: external, broken, cycle,
// too deep. A file that is already loaded is not read again, and its import status is ok.
function recordImport(state, from, { line, ref }) {
  const depth = from.depth + 1;
  const shown = refOf(state, ref);
  const record = (status, filePath) =>
    state.imports.push({ from: from.path, line, ref: shown, path: filePath, depth, status });

  const target = resolveImport(state.root, from.path, ref);
  if (target === null) return record("external", null);

  const entry = state.ctx.fs.stat(target);
  if (!entry.ok) {
    if (entry.reason === "outside-root") return record("external", null);
    return record("broken", target);
  }
  if (entry.type !== "file") return record("broken", target);
  if (isOnChain(state, from, target)) return record("cycle", target);
  if (depth > MAX_IMPORT_DEPTH) return record("too-deep", target);

  let node = state.nodes.get(key(target));
  if (node === undefined) {
    node = admit(state, target, { kind: "memory", loadMode: "always", reason: `imported by ${from.path}`, depth, parent: from.path });
  }
  // An excluded file is listed and never read, so an import of it is not followed. NOT VERIFIED by a note: whether Claude Code
  // loads an import of an excluded file.
  return record(node !== null && node.excludedBy !== null ? "excluded" : "ok", target);
}

// The import as it is shown: redacted, and never an absolute path.
function refOf(state, ref) {
  const shown = state.redact(ref);
  return isAbsoluteRef(shown) ? "<outside>" : shown;
}

// The root-relative path that an import names. Returns null when the import is external: a "~" path,
// an absolute path outside the target, or a relative path that leaves the target. Nothing is read or
// stat-ed here.
function resolveImport(root, fromPath, ref) {
  if (ref.startsWith("~")) return null;
  if (isAbsoluteRef(ref)) return absoluteInside(root, ref);
  const windows = process.platform === "win32";
  const relative = windows ? ref.replaceAll("\\", "/") : ref;
  const joined = path.posix.normalize(path.posix.join(path.posix.dirname(fromPath), relative));
  if (joined === ".." || joined.startsWith("../")) return null;
  return joined.length > 1 ? joined.replace(/\/+$/, "") : joined;
}

// The root-relative path of an absolute import that lies inside the target, or null when it does not.
// Only a drive path is absolute on Windows, so "/x" there is not inside the target by this rule.
function absoluteInside(root, ref) {
  const windows = process.platform === "win32";
  const pathApi = windows ? path.win32 : path.posix;
  if (windows ? !/^[A-Za-z]:[\\/]/.test(ref) : !ref.startsWith("/")) return null;
  const rel = pathApi.relative(root, pathApi.normalize(ref));
  if (rel === "") return ".";
  if (pathApi.isAbsolute(rel) || rel === ".." || rel.startsWith(`..${pathApi.sep}`)) return null;
  return rel.split(pathApi.sep).join("/");
}

function isAbsoluteRef(text) {
  return text.startsWith("/") || text.startsWith("\\") || /^[A-Za-z]:/.test(text);
}

// True when the target is the file itself or one of the files that led to it. A file reached twice
// by different routes is not a cycle.
function isOnChain(state, from, target) {
  const wanted = key(target);
  for (let node = from; node !== null; node = node.parent === null ? null : state.nodes.get(key(node.parent))) {
    if (key(node.path) === wanted) return true;
  }
  return false;
}

// Node keys. Windows paths are compared without letter case.
function key(rel) {
  return process.platform === "win32" ? rel.toLowerCase() : rel;
}

// What the file system says about one path: a file (with its size), an absent path, or a path that
// exists but cannot be used (a link that leaves the target, for example).
function probeFile(ctx, rel) {
  const entry = ctx.fs.stat(rel);
  if (entry.ok) return entry.type === "file" ? { state: "file", bytes: entry.bytes } : { state: "absent" };
  return entry.reason === "not-found" ? { state: "absent" } : { state: "unusable" };
}

// The rule files: every .md file under .claude/rules, at any depth. Links to folders are not followed.
function findRuleFiles(ctx) {
  const found = [];
  const visit = (dir) => {
    const listing = ctx.fs.listDir(dir);
    if (!listing.ok) return;
    for (const entry of listing.entries) {
      const rel = `${dir}/${entry.name}`;
      if (entry.type === "dir") visit(rel);
      else if (entry.name.endsWith(".md") && isRegularFile(ctx, rel, entry.type)) found.push(rel);
    }
  };
  visit(RULES_DIR);
  return found.sort(compareText);
}

function isRegularFile(ctx, rel, type) {
  return type === "file" || (type === "symlink" && ctx.fs.stat(rel).type === "file");
}

// A CLAUDE.md or AGENTS.md below the root that the measure does not otherwise own.
function isSubfolderMemory(rel) {
  const base = rel.slice(rel.lastIndexOf("/") + 1);
  if (!SUBFOLDER_NAMES.has(base) || ROOT_FILES.includes(rel)) return false;
  return !CONFIG_FOLDERS.some((folder) => rel.startsWith(folder));
}

// ---------------------------------------------------------------------------------------------------
// Parent folders

// The memory files of the parent folders, by existence and size. The .claude/CLAUDE.md of the home
// folder is user memory, so it is skipped. claudePresent tells whether a CLAUDE file exists in any
// parent folder, which the AGENTS rule needs. Ancestors are not checked against claudeMdExcludes (NOT VERIFIED by a note),
// so an ancestor CLAUDE file counts here even when a pattern would match it.
function collectAncestors(root, { ancestorLimit, home }) {
  const entries = [];
  let claudePresent = false;
  for (const folder of ancestorFolders(root, ancestorLimit)) {
    for (const rel of ROOT_FILES) {
      if (rel === ".claude/CLAUDE.md" && samePath(folder, home)) continue;
      const abs = path.join(folder, rel);
      const stat = statOutside(abs);
      if (!stat.exists || stat.type === "dir") continue;
      entries.push({ path: toPosix(path.relative(root, abs)), bytes: stat.bytes });
      if (CLAUDE_FILES.includes(rel)) claudePresent = true;
    }
  }
  return { entries: entries.sort(byPath), claudePresent };
}

// The parent folders of the target, nearest first, up to and including the limit. Without a limit the
// walk goes up to the file system root. A limit that is not a parent of the target is a mistake.
function ancestorFolders(root, limit) {
  if (limit !== undefined && samePath(root, limit)) return [];
  const folders = [];
  let folder = root;
  for (;;) {
    const parent = path.dirname(folder);
    if (parent === folder) break;
    folders.push(parent);
    if (limit !== undefined && samePath(parent, limit)) return folders;
    folder = parent;
  }
  if (limit !== undefined) throw new Error("ancestorLimit is not the target or one of its parent folders");
  return folders;
}

function samePath(a, b) {
  return path.relative(a, b) === "";
}

function toPosix(text) {
  return text.split(path.sep).join("/");
}

// ---------------------------------------------------------------------------------------------------
// Imports

// The imports of a memory text, as { line, ref }. Imports inside fenced code blocks and inside code
// spans are ignored. An "@" counts only at the start of a line or after whitespace, and the token must
// look like a path: it contains "/" or ".", or it starts with "~". Trailing punctuation is not part of
// the path.
function importsOf(text) {
  const found = [];
  let fence = null;
  text.split("\n").forEach((line, index) => {
    if (fence !== null) {
      if (closesFence(line, fence)) fence = null;
      return;
    }
    fence = opensFence(line);
    if (fence !== null) return;
    for (const match of maskCodeSpans(line).matchAll(IMPORT_PATTERN)) {
      const ref = match[1].replace(TRAILING_PUNCTUATION, "");
      if (ref.includes("/") || ref.includes(".") || ref.startsWith("~")) found.push({ line: index + 1, ref });
    }
  });
  return found;
}

// ---------------------------------------------------------------------------------------------------
// Output

// The always-loaded memory: every node that loads at the start, each counted once, sorted by path.
function budgetOf(nodes) {
  const counted = nodes
    .filter((node) => node.loadMode === "always")
    .map((node) => ({ path: node.path, estTokens: node.estTokens }));
  return {
    component: "memory",
    estTokens: counted.reduce((sum, item) => sum + item.estTokens, 0),
    items: counted,
  };
}

// A memory file over the cap is skipped and reported; an always-loaded file over the line guide is
// reported. Each item names the limit it breaks.
function limitsOf(nodes) {
  const limits = [];
  for (const node of nodes) {
    if (node.skipped === TOO_LARGE) {
      limits.push({ path: node.path, limit: "memory-bytes", value: node.bytes, threshold: DEFAULT_MAX_BYTES });
    } else if (node.loadMode === "always" && node.lines > MAX_LINES) {
      limits.push({ path: node.path, limit: "memory-lines", value: node.lines, threshold: MAX_LINES });
    }
  }
  return limits;
}

function countLines(text) {
  if (text === "") return 0;
  const lines = text.split("\n").length;
  return text.endsWith("\n") ? lines - 1 : lines;
}

const byPath = (a, b) => compareText(a.path, b.path);

function compareImports(a, b) {
  return compareText(a.from, b.from) || a.line - b.line || compareText(a.ref, b.ref);
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
