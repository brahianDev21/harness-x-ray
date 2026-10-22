// The agent registry. data/agent-harness.json lists, for each coding agent and for conventions that no single agent owns
// (AGENTS.md and .agents/), the files it reads, what each file is, when it loads, and the official source that says so.
// This module checks that file's format and matches its globs. scripts/check-catalog.mjs runs the check. No consumer reads
// the registry yet.
//
// The format. The top level is an object with exactly two keys, agents and files, both non-empty lists. Any other key is
// an error.
//
// agents[] is { id, name, type } and no other key. id is kebab-case, name is a non-empty string, and type is "agent" (a
// coding agent) or "convention" (a shared convention that no single agent owns). Every agent has at least one entry in files.
//
// files[] is { id, agent, glob, kind, loadModel, sources, pathsField?, unless?, pending? } and no other key.
// - id is kebab-case and starts with its agent's id followed by "-". A longer agent id followed by "-" must not be its start
//   too: with agents claude and claude-code, claude-code-settings cannot belong to claude.
// - agent is the id of an entry of agents.
// - glob is a path glob relative to the repository root, matched exactly against a file path (POSIX, relative to the root).
//   Segments are separated by "/". "*" is any run of characters inside one segment (a leading dot included), and "**" is
//   allowed only as a whole segment and matches zero or more whole segments. Invalid: an empty glob, a glob longer than 512
//   characters or with more than 64 segments, a leading "/" or "./", a trailing "/", a backslash, a control character, an
//   empty, "." or ".." segment, the characters [ ] { } ! ? +, "**" mixed with other characters in a segment, and a glob made
//   only of "**" segments. The dialect is this small so that the same globs can later work in a CI path filter. A GitHub
//   path filter reads ? and + as zero or one, and one or more, of the preceding character, so both are forbidden.
//   Not verified: whether "*" matches a leading dot in a GitHub path filter. V02-24 must check it.
// - kind is instructions, settings (settings and permissions), hooks, skills, commands, subagents, mcp, or unknown.
// - loadModel is one of:
//   - always: read at the start of every session in the project;
//   - ancestors: read at session start when the file is in the working folder or a folder above it; nothing is claimed for
//     files below the working folder;
//   - folder: as ancestors, and a file in a folder below the working folder loads once the agent reads or edits a file in
//     that folder;
//   - glob: loads when the agent works with files that match the globs in the file's own frontmatter field named by
//     pathsField; a file without that field loads as always;
//   - invoked: the name and description are in context from the start, and the body loads when the file is invoked;
//   - unknown: not verified.
// - sources is a list, possibly empty, of distinct ids of entries of rules/sources.json whose type is official-docs.
// - pathsField is a non-empty string. It is required with loadModel glob and forbidden otherwise.
// - unless is a non-empty list of distinct ids of other entries of the same agent. It is allowed only with ancestors or
//   folder, and every listed entry must have a loadModel other than unknown. It means that the file loads only when no file
//   owned by the listed entries (see Ownership) exists in the working folder or a folder above it. That is the default: a
//   setting may change it, and the entry's pending says which setting.
// - pending is a non-empty string saying what remains to verify. It is required when sources is empty or loadModel is
//   unknown, and optional otherwise.
//
// Consistency: an empty sources list needs loadModel unknown, and so does kind unknown. Ids are unique across the whole file;
// the generic data check of check-catalog.mjs reports duplicates.
//
// Ownership: for one agent, a file belongs to the first entry of that agent, in file order, whose glob matches it. Entries
// of other agents never own it. So .claude/CLAUDE.md belongs to claude-code-dot-claude-claude-md, not to
// claude-code-claude-md.
//
// Order: because of ownership, specific entries come before general ones. The shadowing check reports an entry when each of
// its two witness paths (see witnessPaths) is owned by an earlier entry of the same agent. The witnesses are one with every
// "**" dropped (a trailing one stays as one folder) and one with every "**" as one folder. So a narrow entry before a
// general one passes, and a general entry before a narrow one is reported.

import { isPlainObject } from "./json-out.mjs";
import { wildcardMatches } from "./permissions.mjs";

/** The kinds a file entry can have. */
export const KINDS = Object.freeze(["instructions", "settings", "hooks", "skills", "commands", "subagents", "mcp", "unknown"]);
/** The load models a file entry can have. */
export const LOAD_MODELS = Object.freeze(["always", "ancestors", "folder", "glob", "invoked", "unknown"]);
/** The types an agent entry can have. */
export const AGENT_TYPES = Object.freeze(["agent", "convention"]);

const TOP_FIELDS = ["agents", "files"];
const AGENT_FIELDS = ["id", "name", "type"];
const FILE_FIELDS = ["id", "agent", "glob", "kind", "loadModel", "sources", "pathsField", "unless", "pending"];
const FILE_REQUIRED_FIELDS = ["id", "agent", "glob", "kind", "loadModel", "sources"];
// The same pattern as SOURCE_ID in scripts/check-catalog.mjs. That file imports this module, so it is not imported back.
const KEBAB_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const FORBIDDEN_GLOB_CHARS = /[[\]{}!]/;
// A GitHub path filter reads ? and + with other meanings (see the header), and no glob has a control character.
const NOT_PORTABLE_GLOB_CHARS = /[?+]/;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;
const MAX_GLOB_LENGTH = 512;
const MAX_GLOB_SEGMENTS = 64;

/**
 * Says why a glob is not valid, or returns null when it is valid (see the header for the dialect).
 * @param {unknown} glob
 * @returns {string | null} A short English message, or null.
 */
export function globProblem(glob) {
  if (typeof glob !== "string") return "must be a string";
  if (glob === "") return "must not be empty";
  if (glob.length > MAX_GLOB_LENGTH) return `must be at most ${MAX_GLOB_LENGTH} characters`;
  if (glob.startsWith("/")) return "must be relative to the repository root, so it must not start with /";
  if (glob.startsWith("./")) return "must not start with ./";
  if (glob.endsWith("/")) return "must not end with /";
  if (glob.includes("\\")) return "must not contain a backslash";
  if (FORBIDDEN_GLOB_CHARS.test(glob)) return "must not contain any of the characters [ ] { } or !";
  if (NOT_PORTABLE_GLOB_CHARS.test(glob)) return "must not contain ? or +; a GitHub path filter reads them differently";
  if (CONTROL_CHARS.test(glob)) return "must not contain a control character";
  const segments = glob.split("/");
  if (segments.length > MAX_GLOB_SEGMENTS) return `must have at most ${MAX_GLOB_SEGMENTS} segments`;
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    return 'must not contain an empty, "." or ".." segment';
  }
  if (segments.some((segment) => segment !== "**" && segment.includes("**"))) {
    return '"**" must be a whole segment, not mixed with other characters';
  }
  if (segments.every((segment) => segment === "**")) return 'must not be made only of "**" segments';
  return null;
}

/**
 * Tells whether a glob matches a file path exactly. A folder that matches does not cover the files under it.
 * @param {string} glob A valid glob (globProblem returns null for it). Any other glob throws a TypeError.
 * @param {string} path A POSIX path relative to the repository root. A path that is not clean (empty, absolute, or with an
 *   empty, "." or ".." segment) never matches.
 * @returns {boolean}
 */
export function matchHarnessGlob(glob, path) {
  const problem = globProblem(glob);
  if (problem !== null) throw new TypeError(`invalid glob ${JSON.stringify(glob)}: ${problem}`);
  if (typeof path !== "string") throw new TypeError("the path must be a string");
  const names = path.split("/");
  if (names.some((name) => name === "" || name === "." || name === "..")) return false;
  return segmentsMatch(glob.split("/"), names);
}

// reach[count] says whether the segments read so far match the first `count` names of the path. A "**" segment carries
// reach forward over any number of names, zero included; any other segment matches exactly one name, with wildcardMatches
// for its `*`. One row per segment means no backtracking: the time is the glob length times the path depth.
function segmentsMatch(segments, names) {
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
}

// The placeholder for one "*" and for one "**" segment in a witness path. No glob has a control character, so no literal
// text of a glob matches it, and a "*" matches it as a run of characters.
const PLACEHOLDER = "\u0000";

// Two paths that the glob matches, for the shadowing check. The first drops every "**" segment, but a trailing one becomes
// one placeholder segment; the second makes every "**" one placeholder segment. In both, each "*" becomes the placeholder.
// Each witness matches its own glob.
function witnessPaths(glob) {
  const segments = glob.split("/");
  const last = segments.length - 1;
  const toPlaceholders = (segment) => (segment === "**" ? PLACEHOLDER : segment.replaceAll("*", PLACEHOLDER));
  const fewest = segments.filter((segment, index) => segment !== "**" || index === last).map(toPlaceholders);
  const most = segments.map(toPlaceholders);
  return [fewest.join("/"), most.join("/")];
}

/**
 * Checks the parsed data/agent-harness.json. It reports every problem it finds and never throws on bad data.
 * @param {unknown} data The parsed file.
 * @param {{ sourceTypes: Map<string, string | null> | null }} options sourceTypes maps each source id of rules/sources.json
 *   to its type, or to null when the type is not valid. It is null when that file could not be read, which skips the two
 *   checks that need it: that a source exists, and that it is official-docs.
 * @returns {{ pointer: string, message: string }[]} pointer is a JSON pointer such as "/files/3/glob", and "" is the whole
 *   document. The list is in check order, not sorted.
 */
export function validateAgentHarness(data, { sourceTypes }) {
  const issues = [];
  const report = (pointer, message) => issues.push({ pointer, message });
  if (!isPlainObject(data)) {
    report("", `must be an object with the fields ${TOP_FIELDS.join(" and ")}`);
    return issues;
  }
  checkFieldNames(data, "", TOP_FIELDS, TOP_FIELDS, report);
  // A list that is null is missing or not a non-empty list. The checks that need it are then skipped, so one mistake is
  // reported once.
  const agents = readList(data, "agents", report);
  const filesList = readList(data, "files", report);
  const files = filesList ?? [];
  const agentIds = agents === null ? null : new Set(agents.filter(isPlainObject).map((agent) => agent.id).filter(isString));

  agents?.forEach((agent, index) => checkAgent(agent, index, report));
  const entryById = new Map();
  for (const entry of files) {
    if (isPlainObject(entry) && isString(entry.id) && !entryById.has(entry.id)) entryById.set(entry.id, entry);
  }
  files.forEach((entry, index) => checkFile(entry, index, { agentIds, entryById, sourceTypes, report }));
  if (agents !== null && filesList !== null) checkCoverage(agents, filesList, report);
  checkShadowing(files, report);
  return issues;
}

// Returns the list, or null after reporting it when it is not a non-empty list. A missing list is reported by the
// field check, so it gives null without a second report.
function readList(data, key, report) {
  const value = data[key];
  if (value === undefined) return null;
  if (!Array.isArray(value) || value.length === 0) {
    report(part(key), "must be a non-empty list");
    return null;
  }
  return value;
}

function checkAgent(agent, index, report) {
  const base = `/agents/${index}`;
  if (!isPlainObject(agent)) {
    report(base, "must be an object");
    return;
  }
  checkFieldNames(agent, base, AGENT_FIELDS, AGENT_FIELDS, report);
  const { id, name, type } = agent;
  if (id !== undefined && !isKebabId(id)) {
    report(`${base}/id`, `must be kebab-case (lowercase letters and digits joined by hyphens), found ${JSON.stringify(id)}`);
  }
  if (name !== undefined && !isNonEmptyString(name)) report(`${base}/name`, "must be a non-empty string");
  if (type !== undefined && !AGENT_TYPES.includes(type)) {
    report(`${base}/type`, `must be one of ${AGENT_TYPES.join(", ")}, found ${JSON.stringify(type)}`);
  }
}

// Checks one entry of files on its own. The cross-entry rules (unless, shadowing, agent coverage) are checked by the callers.
function checkFile(entry, index, { agentIds, entryById, sourceTypes, report }) {
  const base = `/files/${index}`;
  if (!isPlainObject(entry)) {
    report(base, "must be an object");
    return;
  }
  checkFieldNames(entry, base, FILE_FIELDS, FILE_REQUIRED_FIELDS, report);
  const { id, agent, glob, kind, loadModel, sources, pathsField, unless, pending } = entry;

  if (id !== undefined) {
    const longer = isKebabId(id) && isString(agent) && agentIds !== null ? longerAgentOf(id, agent, agentIds) : null;
    if (!isKebabId(id)) {
      report(`${base}/id`, `must be kebab-case (lowercase letters and digits joined by hyphens), found ${JSON.stringify(id)}`);
    } else if (isString(agent) && !id.startsWith(`${agent}-`)) {
      report(`${base}/id`, `must start with its agent id and a hyphen, "${agent}-", found ${JSON.stringify(id)}`);
    } else if (longer !== null) {
      report(
        `${base}/id`,
        `starts with "${longer}-", the id of agent "${longer}", so its agent must be "${longer}", not "${agent}"`,
      );
    }
  }
  // Skipped when agents is not a usable list, so an invalid agents list is not repeated for every file.
  if (agentIds !== null && agent !== undefined && !(isString(agent) && agentIds.has(agent))) {
    report(`${base}/agent`, `must be the id of an entry of agents, found ${JSON.stringify(agent)}`);
  }
  if (glob !== undefined) {
    const problem = globProblem(glob);
    if (problem !== null) report(`${base}/glob`, problem);
  }
  if (kind !== undefined && !KINDS.includes(kind)) {
    report(`${base}/kind`, `must be one of ${KINDS.join(", ")}, found ${JSON.stringify(kind)}`);
  }
  if (loadModel !== undefined && !LOAD_MODELS.includes(loadModel)) {
    report(`${base}/loadModel`, `must be one of ${LOAD_MODELS.join(", ")}, found ${JSON.stringify(loadModel)}`);
  }

  const sourcesEmpty = Array.isArray(sources) && sources.length === 0;
  checkSourceList(sources, base, sourceTypes, report);
  if (sourcesEmpty && loadModel !== undefined && loadModel !== "unknown") {
    report(`${base}/loadModel`, `must be unknown when sources is empty, found ${JSON.stringify(loadModel)}`);
  }
  if (kind === "unknown" && loadModel !== undefined && loadModel !== "unknown") {
    report(`${base}/loadModel`, `must be unknown when kind is unknown, found ${JSON.stringify(loadModel)}`);
  }

  if (loadModel === "glob") {
    if (pathsField === undefined) report(`${base}/pathsField`, "required when loadModel is glob");
    else if (!isNonEmptyString(pathsField)) report(`${base}/pathsField`, "must be a non-empty string");
  } else if (pathsField !== undefined) {
    report(`${base}/pathsField`, "allowed only when loadModel is glob");
  }

  if (unless !== undefined) checkUnless(unless, base, { id, agent, loadModel, entryById, report });

  if (pending !== undefined && !isNonEmptyString(pending)) report(`${base}/pending`, "must be a non-empty string");
  if (pending === undefined && (sourcesEmpty || loadModel === "unknown")) {
    report(`${base}/pending`, "required when sources is empty or loadModel is unknown; say what remains to verify");
  }
}

// The id of a longer agent that the id of an entry starts with, followed by a hyphen, or null. With agents claude and
// claude-code, the id claude-code-settings cannot belong to claude.
function longerAgentOf(id, agent, agentIds) {
  for (const other of agentIds) {
    if (other.length > agent.length && id.startsWith(`${other}-`)) return other;
  }
  return null;
}

// A list of distinct source ids. Each must exist in rules/sources.json with the type official-docs, unless the sources
// file could not be read (sourceTypes is null).
function checkSourceList(sources, base, sourceTypes, report) {
  if (sources === undefined) return;
  if (!Array.isArray(sources) || !sources.every(isString)) {
    report(`${base}/sources`, "must be a list of source ids (strings)");
    return;
  }
  sources.forEach((source, index) => {
    const field = `${base}/sources/${index}`;
    if (sources.indexOf(source) !== index) {
      report(field, `duplicate source id "${source}"`);
    } else if (sourceTypes !== null && !sourceTypes.has(source)) {
      report(field, `source id "${source}" does not exist in rules/sources.json`);
    } else if (sourceTypes !== null && sourceTypes.get(source) !== "official-docs") {
      report(field, `source "${source}" must have type official-docs, found ${JSON.stringify(sourceTypes.get(source))}`);
    }
  });
}

function checkUnless(unless, base, { id, agent, loadModel, entryById, report }) {
  if (loadModel !== undefined && loadModel !== "ancestors" && loadModel !== "folder") {
    report(`${base}/unless`, "allowed only when loadModel is ancestors or folder");
  }
  if (!Array.isArray(unless) || unless.length === 0 || !unless.every(isNonEmptyString)) {
    report(`${base}/unless`, "must be a non-empty list of entry ids");
    return;
  }
  unless.forEach((target, index) => {
    const field = `${base}/unless/${index}`;
    if (unless.indexOf(target) !== index) {
      report(field, `duplicate entry id "${target}"`);
    } else if (target === id) {
      report(field, "must not name the entry itself");
    } else if (!entryById.has(target)) {
      report(field, `"${target}" is not an entry in files`);
    } else if (entryById.get(target).agent !== agent) {
      report(field, `"${target}" is an entry of agent "${entryById.get(target).agent}", not of "${agent}"`);
    } else if (entryById.get(target).loadModel === "unknown") {
      report(field, `"${target}" has loadModel unknown; unless needs an entry whose loading is verified`);
    }
  });
}

// Every agent needs at least one entry in files.
function checkCoverage(agents, files, report) {
  agents.forEach((agent, index) => {
    if (!isPlainObject(agent) || !isString(agent.id)) return;
    if (!files.some((entry) => isPlainObject(entry) && entry.agent === agent.id)) {
      report(`/agents/${index}/id`, "has no entries in files; every agent needs at least one");
    }
  });
}

// An entry is shadowed when each of its witness paths (see witnessPaths) is owned by an earlier entry of the same agent, so
// the files it names already belong to earlier entries. Only entries with a valid glob and a string agent take part.
function checkShadowing(files, report) {
  const usable = [];
  files.forEach((entry, index) => {
    if (isPlainObject(entry) && isString(entry.agent) && globProblem(entry.glob) === null) usable.push({ entry, index });
  });
  for (const { entry, index } of usable) {
    // The owner of a witness is the first usable entry of the same agent whose glob matches it. The entry matches its own
    // witnesses, so each owner exists.
    const owners = witnessPaths(entry.glob).map((witness) =>
      usable.find((other) => other.entry.agent === entry.agent && matchHarnessGlob(other.entry.glob, witness)),
    );
    if (owners.every((owner) => owner.index < index)) {
      const first = owners[0];
      const label = isString(first.entry.id) ? first.entry.id : `/files/${first.index}`;
      report(`/files/${index}/glob`, `shadowed by ${label}; an earlier entry of the same agent owns the files it names`);
    }
  }
}

// Reports the fields that are not allowed and the ones that are required and missing.
function checkFieldNames(object, base, allowed, required, report) {
  for (const key of Object.keys(object)) {
    if (!allowed.includes(key)) report(base + part(key), `unknown field; the fields are ${allowed.join(", ")}`);
  }
  for (const key of required) {
    if (!Object.hasOwn(object, key)) report(base + part(key), "missing required field");
  }
}

// The JSON pointer part of one key or index. "~" and "/" are escaped as RFC 6901 says.
function part(key) {
  return `/${String(key).replaceAll("~", "~0").replaceAll("/", "~1")}`;
}

function isString(value) {
  return typeof value === "string";
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}

function isKebabId(value) {
  return typeof value === "string" && KEBAB_ID.test(value);
}
