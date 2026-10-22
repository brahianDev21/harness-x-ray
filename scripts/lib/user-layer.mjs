// Measure "user-layer": the Claude Code files of the user, in ~/.claude. It runs only when scan is given --include-user-layer.
// It reads ~/.claude/CLAUDE.md, the rules under ~/.claude/rules/, ~/.claude/settings.json, the skills (skills/<name>/SKILL.md)
// and the subagents (agents/**/*.md). Nothing else in that folder is listed or read: not projects, history, todos, credentials
// or caches. Managed settings are out of scope. The reads go through their own safe-fs view, rooted at ~/.claude, so a link
// that leads out of that folder is refused (outside-root). Nothing is run, and @imports are not followed.
//
// Every path in the output starts with ~/.claude/. Every string copied from a file goes through the redactor, with the home
// folder. The permission rules of settings.json are not written to security.permissions: they go to ctx.outside, and the
// measures that simulate permissions add them to the project's rules (decisionRules in permissions.mjs). There each rule
// keeps its raw text, which is matched, and its redacted text as shown, which is the only text a result names. The user's
// defaultMode and hooks are recorded but never applied or evaluated, because their precedence over the project is not
// verified by a note.
//
// Output: userLayer = { root, found, memory, settings, skills, subagents, warnings, notes }. The warnings of this folder
// have the same shape as the top-level ones.

import os from "node:os";
import path from "node:path";
import {
  countLines,
  describeMarkdown,
  findFiles,
  hookEntriesOf,
  parseObject,
  scalarOf,
  stringsOf,
} from "./claude-config.mjs";
import { isPlainObject } from "./json-out.mjs";
import { RULE_INVALID_REASON, countsOf, ruleModeOf } from "./memory.mjs";
import { USER_LAYER } from "./permissions.mjs";
import { createRedactor } from "./redact.mjs";
import { createTargetFs, statOutside } from "./safe-fs.mjs";

export const MEASURE_ID = "user-layer";

// The folder that the output shows for the user layer, and the paths relative to it that the measure reads.
const SHOWN_ROOT = "~/.claude";
const CLAUDE_DIR = ".claude";
const MEMORY_FILE = "CLAUDE.md";
const RULES_DIR = "rules";
const SETTINGS_FILE = "settings.json";
const SKILLS_DIR = "skills";
const AGENTS_DIR = "agents";
const SETTINGS_SHOWN = `${SHOWN_ROOT}/${SETTINGS_FILE}`;
const USER_MEMORY_REASON = "user memory, loaded at session start";
// The source of the warnings that come from the reads of ~/.claude, and of the parse warnings of this measure.
const FS_SOURCE = "fs";
// Notes of the user layer, in code order. A note says what the measure does not do with a part of the user layer.
const NOTES = ["default-mode-not-applied", "hooks-not-evaluated", "imports-not-followed", "layer-precedence-not-verified"];

/**
 * Builds the user-layer measure.
 * @param {object} [options]
 * @param {string} [options.home] Home folder whose .claude folder is read. Default: os.homedir().
 * @returns {{ id: string, collect: (ctx: object) => object }}
 */
export function createUserLayerMeasure({ home = os.homedir() } = {}) {
  if (typeof home !== "string" || !path.isAbsolute(home)) throw new TypeError("home must be an absolute folder");
  return Object.freeze({
    id: MEASURE_ID,
    collect: (ctx) => collectUserLayer(ctx, home),
  });
}

// Reads the user layer, and hands its permission lists to the measures that simulate permissions.
function collectUserLayer(ctx, home) {
  const { userLayer, permissions } = readUserLayer(ctx, home);
  ctx.outside.set(USER_LAYER, { permissions });
  return { userLayer };
}

// Reads ~/.claude. When that folder is not a folder, nothing is read. The paths passed to the warn callback are already in
// the shown form, so a path is never shown twice.
function readUserLayer(ctx, home) {
  const claudeDir = path.join(home, CLAUDE_DIR);
  if (statOutside(claudeDir).type !== "dir") return { userLayer: absentLayer(), permissions: emptyPermissions() };

  const view = createTargetFs(claudeDir);
  const redact = createRedactor({ root: ctx.root, home });
  const warnings = [];
  const warn = (shown, reason, detail) => warnings.push(parseWarning(shown, reason, detail));

  const memory = [...readMemory(view), ...readRules(view, warn)];
  const settings = readSettings(view, redact, warn);
  const skillFiles = findFiles({ fs: view }, SKILLS_DIR, (name) => name === "SKILL.md").filter(
    (rel) => rel !== `${SKILLS_DIR}/SKILL.md`,
  );
  const agentFiles = findFiles({ fs: view }, AGENTS_DIR, (name) => name.endsWith(".md"));
  const skills = describeFiles(view, "skill", skillFiles, redact, warn);
  const subagents = describeFiles(view, "subagent", agentFiles, redact, warn);
  const fsWarnings = view.warnings().map((item) => ({ source: FS_SOURCE, path: shownPath(item.path), reason: item.reason }));

  return {
    userLayer: {
      root: SHOWN_ROOT,
      found: true,
      memory: memory.sort(byPath),
      settings: settings.item,
      skills,
      subagents,
      warnings: sortWarnings([...fsWarnings, ...warnings]),
      notes: [...NOTES],
    },
    permissions: settings.permissions,
  };
}

// The memory file of ~/.claude and the rules. A rule's load mode comes from its frontmatter, as the project's rules get it.
function readMemory(view) {
  const read = view.readText(MEMORY_FILE);
  if (!read.ok) return [];
  return [
    {
      path: shownPath(MEMORY_FILE),
      kind: "memory",
      loadMode: "always",
      loadReason: USER_MEMORY_REASON,
      bytes: read.bytes,
      ...countsOf(read.text),
    },
  ];
}

function readRules(view, warn) {
  const items = [];
  for (const rel of findRuleFiles(view)) {
    const read = view.readText(rel);
    if (!read.ok) continue;
    const mode = ruleModeOf(read.text);
    if (mode.loadReason === RULE_INVALID_REASON) warn(shownPath(rel), "invalid-frontmatter");
    items.push({ path: shownPath(rel), kind: "rule", ...mode, bytes: read.bytes, ...countsOf(read.text) });
  }
  return items;
}

// Every .md file under rules/, at any depth. Links to folders are not followed, and a link to a file counts when it points to
// a file. This is the walk of the project's rules (memory.mjs), which has no depth limit either.
function findRuleFiles(view) {
  const found = [];
  const visit = (dir) => {
    const listing = view.listDir(dir);
    if (!listing.ok) return;
    for (const entry of listing.entries) {
      const rel = `${dir}/${entry.name}`;
      if (entry.type === "dir") visit(rel);
      else if (entry.name.endsWith(".md") && isFileEntry(view, rel, entry.type)) found.push(rel);
    }
  };
  visit(RULES_DIR);
  return found.sort(compareText);
}

// A file, or a link that points to a file. The link is checked by the view, so one that leads out of ~/.claude is refused.
function isFileEntry(view, rel, type) {
  return type === "file" || (type === "symlink" && view.stat(rel).type === "file");
}

// settings.json: the permission lists, the defaultMode and the hooks. Other keys are not read. The rule texts are checked as the
// project's are: each one is matched with its raw text and shown with its redacted text (permissions.mjs writes only the shown
// text into a result). The defaultMode is recorded with applied false; the hooks are counted, never evaluated.
// The returned permissions are the lists for ctx.outside; item.permissions holds the same rules with their shown text only.
function readSettings(view, redact, warn) {
  const read = view.readText(SETTINGS_FILE);
  if (!read.ok) return { item: absentSettings(), permissions: emptyPermissions() };

  const data = parseObject(read.text, SETTINGS_SHOWN, warn) ?? {};
  const block = data.permissions === undefined ? {} : data.permissions;
  if (!isPlainObject(block)) warn(SETTINGS_SHOWN, "unexpected-shape", "permissions");
  const section = isPlainObject(block) ? block : {};
  const permissions = {};
  const shown = {};
  for (const list of ["allow", "ask", "deny"]) {
    const rules = stringsOf(section[list], SETTINGS_SHOWN, `permissions.${list}`, warn);
    permissions[list] = rules.map((rule) => ({ rule, shown: redact(rule), source: SETTINGS_SHOWN })).sort(byShown);
    shown[list] = permissions[list].map((entry) => ({ rule: entry.shown, source: entry.source }));
  }
  const defaultMode = scalarOf(section.defaultMode, SETTINGS_SHOWN, "permissions.defaultMode", { redact, warn });
  const hooks = hookEntriesOf(data.hooks, SETTINGS_SHOWN, warn);
  return {
    item: {
      path: SETTINGS_SHOWN,
      found: true,
      lines: countLines(read.text),
      permissions: shown,
      defaultMode: defaultMode === null ? null : { ...defaultMode, applied: false },
      hooks: { count: hooks.length, evaluated: false },
    },
    permissions,
  };
}

// The skills or subagents of one kind. Each file is described as the project's files are (describeMarkdown), and only its
// name and load mode are kept.
function describeFiles(view, kind, files, redact, warn) {
  const items = [];
  for (const rel of files) {
    const read = view.readText(rel);
    if (!read.ok) continue;
    const shown = shownPath(rel);
    const described = describeMarkdown(kind, shown, read.text, { redact, warn });
    items.push({ path: shown, name: described.name, loadMode: described.loadMode });
  }
  return items.sort(byPath);
}

// ---------------------------------------------------------------------------------------------------
// Shapes

// The path of a file of ~/.claude, as the output shows it.
function shownPath(rel) {
  return `${SHOWN_ROOT}/${rel}`;
}

// A warning of this measure. The path is already shown, and detail is present only when the warning has one.
function parseWarning(shown, reason, detail) {
  const item = { source: MEASURE_ID, path: shown, reason };
  return detail === undefined ? item : { ...item, detail };
}

// Removes duplicates (same source, path, reason and detail) and sorts by path, reason, source and detail.
function sortWarnings(items) {
  const unique = new Map();
  for (const item of items) {
    const key = JSON.stringify([item.source, item.path, item.reason, item.detail ?? null]);
    if (!unique.has(key)) unique.set(key, item);
  }
  return [...unique.values()].sort(
    (a, b) =>
      compareText(a.path, b.path) ||
      compareText(a.reason, b.reason) ||
      compareText(a.source, b.source) ||
      compareText(a.detail ?? "", b.detail ?? ""),
  );
}

function absentSettings() {
  return {
    path: SETTINGS_SHOWN,
    found: false,
    permissions: { allow: [], ask: [], deny: [] },
    defaultMode: null,
    hooks: { count: 0, evaluated: false },
  };
}

function emptyPermissions() {
  return { allow: [], ask: [], deny: [] };
}

// The layer when ~/.claude is not a folder. Nothing is read, and the notes do not apply.
function absentLayer() {
  return {
    root: SHOWN_ROOT,
    found: false,
    memory: [],
    settings: absentSettings(),
    skills: [],
    subagents: [],
    warnings: [],
    notes: [],
  };
}

const byPath = (a, b) => compareText(a.path, b.path);
const byShown = (a, b) => compareText(a.shown, b.shown) || compareText(a.source, b.source);

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
