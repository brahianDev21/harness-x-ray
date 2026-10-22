// Checks the rule catalog and the data files: node scripts/check-catalog.mjs [--root <dir>].
//
// The root defaults to this repository and must contain a rules/ folder. Exit codes: 0 when there
// are no errors (warnings are allowed), 1 when there are errors, 2 for a usage error.
//
// Output: one line per error, "<file>: <field>: <message>", then one line per warning with a
// "warning: " prefix, then a summary line. Files are POSIX paths relative to the root. Issues are
// sorted by file, field and message, so the output does not depend on the order in which the file
// system lists folders.
//
// What is checked:
// - rules/<ID>.md and rules/<ID>-<slug>.md. README.md and files that are not .md are not rules.
//   The file name, the frontmatter fields and their values, the id against the file name and the
//   axis, the body sections, and the evidence level against the sources. rules/README.md documents
//   the format.
// - rules/sources.json: its shape, unique kebab-case ids, https URLs, real dates and source types.
// - Every rule with kind "measured" and since "mvp" has an emitter (see below).
// - data/*.json, the contract for the teams that write these files:
//   - each file is valid JSON;
//   - every object at any depth that has an "id" key has an id that is unique within its file;
//   - every string under a key named "regex" or ending in "Regex" compiles with
//     new RegExp(value, flags). The value of such a key is a string or a list of strings, and flags
//     is the "flags" string next to the key, if there is one. Other keys (globs, plain patterns)
//     are not compiled. Files that are not .json are ignored.
// - data/agent-harness.json, the registry of the files that each agent reads: its format, the source ids and their
//   types, the globs, and the order of the entries. scripts/lib/agent-harness.mjs documents the format. The file is optional,
//   but anything else at its path must be a readable regular file.
// - data/layer-signals.json, the signals of the layer mapping: the manifest file names, the folder names of each hint and
//   the languages of each extension. scripts/lib/layer-signals.mjs (validateLayerSignals) documents the format and owns the checks.
//   The file is required: the layer mapping reads it, so a root without it has an error on the file.
// - data/injection-patterns.json, the patterns of text aimed at a coding agent: its categories, the fields of each pattern
//   and the unique ids. scripts/lib/injection-patterns.mjs (validateInjectionPatterns) documents the format and owns the
//   checks. The check treats the file as optional, as it treats data/agent-harness.json, but anything else at its path must be a
//   readable regular file. The scanner needs both files: a scan without them fails.
//
// Emitters: scripts/lib/measured-findings.mjs exports EMITTERS, the ids of the rules that produce a
// finding, as an array, a Set, a Map keyed by rule id, or a plain object keyed by rule id. The copy
// of that file is always read from this repository, never from --root. While the file does not
// exist, the emitter check is skipped with a warning.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { validateAgentHarness } from "./lib/agent-harness.mjs";
import { parseFrontmatter } from "./lib/frontmatter.mjs";
import { validateInjectionPatterns } from "./lib/injection-patterns.mjs";
import { isPlainObject } from "./lib/json-out.mjs";
import { validateLayerSignals } from "./lib/layer-signals.mjs";

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const USAGE = "usage: node scripts/check-catalog.mjs [--root <dir>]";
const EMITTERS_FILE = "scripts/lib/measured-findings.mjs";
const SOURCES_FILE = "rules/sources.json";
const AGENT_HARNESS_FILE = "data/agent-harness.json";
const LAYER_SIGNALS_FILE = "data/layer-signals.json";
const INJECTION_PATTERNS_FILE = "data/injection-patterns.json";

const AXIS_BY_PREFIX = new Map([
  ["RUL", "instructions"],
  ["CTX", "context"],
  ["SEC", "security"],
  ["VER", "verification"],
  ["STR", "structure"],
  ["COD", "code"],
]);
const AXES = [...AXIS_BY_PREFIX.values()];
const KINDS = ["measured", "judgment"];
const IMPACTS = ["high", "medium", "low"];
const SINCE = ["mvp", "v0.2", "v0.3"];
const STATUSES = ["draft", "validated"];
// Strongest first, so the index of a level is its strength.
const EVIDENCE = ["study", "benchmark", "official-docs", "industry-guidance", "atlas", "common-practice"];
const SOURCE_TYPES = EVIDENCE.filter((level) => level !== "common-practice");
const RULE_FIELDS = [
  "id", "title", "axis", "kind", "measuredSupport", "defaultImpact", "sources", "evidence", "since", "status",
];
const SOURCE_FIELDS = ["id", "title", "url", "type", "accessed", "note"];
const SECTIONS = [
  "What it checks", "Why it matters", "How it is detected", "Recommendation", "When not to apply", "Examples",
];

const RULE_ID = /^(?:RUL|CTX|SEC|VER|STR|COD)-\d{2}$/;
const RULE_FILE = /^([A-Z]{3}-\d{2})(?:-[a-z0-9]+(?:-[a-z0-9]+)*)?\.md$/;
const SOURCE_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const MEASURE_ID = /^M\d+$/;
const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const FENCE_OPEN = /^ {0,3}(`{3,}|~{3,})/;
const FENCE_CLOSE = /^ {0,3}(`{3,}|~{3,})[ \t]*$/;
const SECTION_HEADING = /^ {0,3}##[ \t]+(.*?)[ \t]*$/;

/** A usage error. The command line reports it with exit code 2. */
class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = "UsageError";
  }
}

/**
 * Checks the catalog under a root folder. Never writes anything.
 * @param {object} options
 * @param {string} options.root Folder that contains rules/ (and optionally data/).
 * @param {unknown[] | Set<string> | Map<string, unknown> | Record<string, unknown> | null} options.emitters
 *   The rule ids that have an emitter, in one of the four collection shapes, or null when the
 *   emitters are not available yet. A value of any other type throws a TypeError.
 * @returns {{ errors: Issue[], warnings: Issue[], counts: { rules: number, sources: number, dataFiles: number } }}
 *   Issue is { file, field, message }, sorted.
 * @throws {Error} If root has no rules/ folder.
 */
export function checkCatalog({ root, emitters }) {
  const emitterIds = collectionIds(emitters);
  const rulesDir = path.join(root, "rules");
  if (!isDirectory(rulesDir)) throw new Error(`no rules/ folder in ${root}`);

  const errors = [];
  const warnings = [];
  const sources = checkSources(root, errors);
  const sourceTypes = sources === null ? null : sources.types;
  checkAgentHarness(root, sourceTypes, errors);
  checkLayerSignals(root, errors);
  checkInjectionPatterns(root, errors);

  const names = listRuleFiles(rulesDir, warnings);
  const rules = [];
  const firstFileOfId = new Map();
  for (const name of names) {
    const file = `rules/${name}`;
    const text = readText(path.join(rulesDir, name));
    const rule = checkRuleFile(file, name, text, { errors, sourceTypes });
    if (rule.id !== null) {
      if (firstFileOfId.has(rule.id)) {
        errors.push(issue(file, "id", `duplicate id ${rule.id}; ${firstFileOfId.get(rule.id)} has it too`));
      } else {
        firstFileOfId.set(rule.id, file);
      }
    }
    rules.push({ file, ...rule });
  }

  checkEmitters(rules, emitterIds, errors, warnings);
  const dataFiles = checkDataFiles(root, errors);

  return {
    errors: sortIssues(errors),
    warnings: sortIssues(warnings),
    counts: { rules: names.length, sources: sources === null ? 0 : sources.count, dataFiles },
  };
}

/**
 * Reads the emitters of this harness. The file is looked up under harnessRoot, which is the
 * repository that contains this script (never the --root of a check). A missing file gives
 * emitters null and no error.
 * @param {string} harnessRoot
 * @returns {Promise<{ emitters: unknown, errors: Issue[] }>} emitters is null when there is no file
 *   or it cannot be used; in that case errors says why.
 */
export async function loadEmitters(harnessRoot) {
  const file = path.join(harnessRoot, EMITTERS_FILE);
  if (!fs.existsSync(file)) return { emitters: null, errors: [] };

  let loaded;
  try {
    loaded = await import(pathToFileURL(file).href);
  } catch (error) {
    return failedEmitters(issue(EMITTERS_FILE, "module", `cannot be imported: ${firstLine(error?.message ?? error)}`));
  }
  if (!("EMITTERS" in loaded)) return failedEmitters(issue(EMITTERS_FILE, "EMITTERS", "does not export EMITTERS"));
  if (!isCollection(loaded.EMITTERS)) {
    return failedEmitters(
      issue(EMITTERS_FILE, "EMITTERS", "must be an array, a Set, a Map or a plain object of rule ids"),
    );
  }
  return { emitters: loaded.EMITTERS, errors: [] };
}

function failedEmitters(problem) {
  return { emitters: null, errors: [problem] };
}

function issue(file, field, message) {
  return { file, field, message };
}

// Rule files -----------------------------------------------------------------------------------

// Returns the names of the rule files, sorted. Entries that look like rules but are not regular
// files are reported as warnings and not checked.
function listRuleFiles(rulesDir, warnings) {
  const names = [];
  for (const entry of fs.readdirSync(rulesDir, { withFileTypes: true })) {
    if (!entry.name.endsWith(".md") || entry.name === "README.md") continue;
    if (!entry.isFile()) {
      warnings.push(issue(`rules/${entry.name}`, "file", "is not a regular file, so it is not checked"));
      continue;
    }
    names.push(entry.name);
  }
  return names.sort(compareText);
}

// Checks one rule file. Returns the values the emitter check needs: id (null when it is not a
// valid rule id), kind and since (null when they are missing or invalid).
function checkRuleFile(file, name, text, context) {
  const nameMatch = RULE_FILE.exec(name);
  const fileId = nameMatch !== null && RULE_ID.test(nameMatch[1]) ? nameMatch[1] : null;
  if (fileId === null) {
    context.errors.push(issue(
      file,
      "file name",
      "must be <ID>.md or <ID>-<slug>.md, where <ID> is RUL, CTX, SEC, VER, STR or COD followed by a hyphen " +
        "and two digits, and <slug> is lowercase words joined by hyphens",
    ));
  }

  const parsed = parseFrontmatter(text);
  checkSections(file, parsed.body, context.errors);
  const none = { id: null, kind: null, since: null };
  if (parsed.error !== undefined) {
    context.errors.push(issue(file, "frontmatter", parsed.error));
    return none;
  }
  if (parsed.data === null) {
    context.errors.push(issue(file, "frontmatter", "missing; the file must start with a --- line"));
    return none;
  }
  return checkFields(file, parsed.data, fileId, context);
}

function checkFields(file, data, fileId, { errors, sourceTypes }) {
  const result = { id: null, kind: null, since: null };
  for (const key of Object.keys(data)) {
    if (!RULE_FIELDS.includes(key)) errors.push(issue(file, key, `unknown field; the fields are ${RULE_FIELDS.join(", ")}`));
  }
  const read = (key) => readField(file, data, key, errors);

  const id = read("id");
  if (id !== undefined) {
    if (typeof id !== "string" || !RULE_ID.test(id)) {
      errors.push(issue(file, "id", `must be a rule id such as RUL-01, found ${JSON.stringify(id)}`));
    } else {
      result.id = id;
      if (fileId !== null && id !== fileId) errors.push(issue(file, "id", `must match the file name prefix ${fileId}`));
    }
  }

  const title = read("title");
  if (title !== undefined && !isNonEmptyString(title)) errors.push(issue(file, "title", "must be a non-empty string"));

  const axis = checkEnum(file, "axis", read("axis"), AXES, errors);
  if (axis !== undefined && result.id !== null) {
    const expected = AXIS_BY_PREFIX.get(result.id.slice(0, 3));
    if (axis !== expected) errors.push(issue(file, "axis", `must be "${expected}" for ${result.id}, found "${axis}"`));
  }

  result.kind = checkEnum(file, "kind", read("kind"), KINDS, errors) ?? null;
  checkEnum(file, "defaultImpact", read("defaultImpact"), IMPACTS, errors);
  result.since = checkEnum(file, "since", read("since"), SINCE, errors) ?? null;
  checkEnum(file, "status", read("status"), STATUSES, errors);

  const measured = read("measuredSupport");
  if (measured !== undefined) {
    if (!Array.isArray(measured)) {
      errors.push(issue(file, "measuredSupport", `must be a list such as [] or [M11], found ${JSON.stringify(measured)}`));
    } else {
      const bad = measured.find((item) => typeof item !== "string" || !MEASURE_ID.test(item));
      if (bad !== undefined) {
        errors.push(issue(file, "measuredSupport", `items must look like M11, found ${JSON.stringify(bad)}`));
      }
    }
  }

  const sources = read("sources");
  let sourceList = null;
  if (sources !== undefined) {
    if (!Array.isArray(sources)) {
      errors.push(issue(
        file,
        "sources",
        `must be a list of source ids such as [] or [example-docs], found ${JSON.stringify(sources)}`,
      ));
    } else if (!sources.every(isString)) {
      errors.push(issue(file, "sources", "items must be source ids (strings)"));
    } else {
      sourceList = sources;
      if (sourceTypes !== null) {
        for (const sourceId of sources) {
          if (!sourceTypes.has(sourceId)) {
            errors.push(issue(file, "sources", `unknown source id "${sourceId}"; add it to rules/sources.json`));
          }
        }
      }
    }
  }

  const evidence = checkEnum(file, "evidence", read("evidence"), EVIDENCE, errors);
  if (evidence !== undefined && sourceList !== null) {
    if (sourceList.length === 0) {
      if (evidence !== "common-practice") {
        errors.push(issue(file, "evidence", `must be "common-practice" when sources is empty, found "${evidence}"`));
      }
    } else if (sourceTypes !== null && sourceList.every((sourceId) => typeof sourceTypes.get(sourceId) === "string")) {
      // Only checked when every cited source has a valid type; a missing or invalid one is already
      // reported in sources.json or above.
      const strongest = strongestLevel(sourceList.map((sourceId) => sourceTypes.get(sourceId)));
      if (evidence !== strongest) {
        errors.push(issue(file, "evidence", `must be "${strongest}", the strongest type among its sources, found "${evidence}"`));
      }
    }
  }
  return result;
}

// Returns the value of a required field, or undefined after reporting it missing or unreadable.
// The frontmatter reader stores a value it cannot read as { error } and keeps the other fields.
function readField(file, data, key, errors) {
  if (!Object.hasOwn(data, key)) {
    errors.push(issue(file, key, "missing required field"));
    return undefined;
  }
  const value = data[key];
  if (isPlainObject(value)) {
    errors.push(issue(file, key, typeof value.error === "string" ? value.error : "value is not supported"));
    return undefined;
  }
  return value;
}

// Returns the value when it is one of the allowed strings. Reports anything else. A value that is
// undefined was already reported by readField, so nothing more is said about it here.
function checkEnum(file, key, value, allowed, errors) {
  if (value === undefined) return undefined;
  if (typeof value === "string" && allowed.includes(value)) return value;
  errors.push(issue(file, key, `must be one of ${allowed.join(", ")}, found ${JSON.stringify(value)}`));
  return undefined;
}

function strongestLevel(levels) {
  return levels.reduce((best, level) => (EVIDENCE.indexOf(level) < EVIDENCE.indexOf(best) ? level : best));
}

// Body sections -------------------------------------------------------------------------------

// Checks the H2 sections of a rule body. Headings inside fenced code blocks are not sections.
// Every H2 must be one of SECTIONS, each at most once, in SECTIONS order, and none may be empty.
function checkSections(file, body, errors) {
  const seen = new Set();
  let last = -1;
  for (const section of readSections(body)) {
    const index = SECTIONS.indexOf(section.title);
    if (index === -1) {
      errors.push(issue(file, section.title, `unknown section; the sections are ${SECTIONS.join(", ")}`));
      continue;
    }
    if (seen.has(section.title)) {
      errors.push(issue(file, section.title, "section appears more than once"));
      continue;
    }
    seen.add(section.title);
    if (index < last) errors.push(issue(file, section.title, `section must come before "${SECTIONS[last]}"`));
    last = Math.max(last, index);
    if (section.text.trim() === "") errors.push(issue(file, section.title, "section is empty"));
  }
  for (const title of SECTIONS) {
    if (!seen.has(title)) errors.push(issue(file, title, "missing section"));
  }
}

// Splits the body at its H2 headings. text is the text under a heading, up to the next one.
function readSections(body) {
  const sections = [];
  let current = null;
  let fence = null;
  for (const line of body.split("\n")) {
    if (fence !== null) {
      const close = FENCE_CLOSE.exec(line);
      if (close !== null && close[1][0] === fence[0] && close[1].length >= fence.length) fence = null;
    } else {
      const open = FENCE_OPEN.exec(line);
      if (open !== null) {
        fence = open[1];
      } else {
        const heading = SECTION_HEADING.exec(line);
        if (heading !== null) {
          current = { title: heading[1].replace(/[ \t]+#+$/, ""), text: "" };
          sections.push(current);
          continue;
        }
      }
    }
    if (current !== null) current.text += `${line}\n`;
  }
  return sections;
}

// Sources -------------------------------------------------------------------------------------

// Checks rules/sources.json. Returns { types, count } where types maps each source id to its type,
// or to null when the type is not valid. It is null when the file is missing or its shape is broken,
// so the rules skip the source checks.
function checkSources(root, errors) {
  const full = path.join(root, SOURCES_FILE);
  if (!fs.existsSync(full)) {
    errors.push(issue(SOURCES_FILE, "sources", "file is missing; create it with an empty sources list"));
    return null;
  }
  let data;
  try {
    data = JSON.parse(readText(full));
  } catch (error) {
    errors.push(issue(SOURCES_FILE, "json", `not valid JSON: ${firstLine(error.message)}`));
    return null;
  }
  if (!isPlainObject(data)) {
    errors.push(issue(SOURCES_FILE, "json", 'the top level must be an object such as { "sources": [] }'));
    return null;
  }
  for (const key of Object.keys(data)) {
    if (key !== "sources") errors.push(issue(SOURCES_FILE, key, 'unknown field; the only field is "sources"'));
  }
  if (!Array.isArray(data.sources)) {
    errors.push(issue(SOURCES_FILE, "sources", "must be a list"));
    return null;
  }

  const types = new Map();
  const firstIndexOfId = new Map();
  data.sources.forEach((entry, index) => {
    checkSourceEntry(entry, index, { types, firstIndexOfId, errors });
  });
  return { types, count: data.sources.length };
}

function checkSourceEntry(entry, index, { types, firstIndexOfId, errors }) {
  const at = `sources[${index}]`;
  const field = (key) => `${at}.${key}`;
  if (!isPlainObject(entry)) {
    errors.push(issue(SOURCES_FILE, at, "must be an object"));
    return;
  }
  for (const key of Object.keys(entry)) {
    if (!SOURCE_FIELDS.includes(key)) {
      errors.push(issue(SOURCES_FILE, field(key), `unknown field; the fields are ${SOURCE_FIELDS.join(", ")}`));
    }
  }
  for (const key of SOURCE_FIELDS) {
    if (!Object.hasOwn(entry, key)) {
      errors.push(issue(SOURCES_FILE, field(key), "missing required field"));
    } else if (!isNonEmptyString(entry[key])) {
      errors.push(issue(SOURCES_FILE, field(key), "must be a non-empty string"));
    }
  }

  const { id, url, accessed, type } = entry;
  if (isNonEmptyString(id)) {
    if (!SOURCE_ID.test(id)) {
      errors.push(issue(
        SOURCES_FILE,
        field("id"),
        `must be kebab-case (lowercase letters and digits joined by hyphens), found ${JSON.stringify(id)}`,
      ));
    } else if (firstIndexOfId.has(id)) {
      errors.push(issue(SOURCES_FILE, field("id"), `duplicate id "${id}"; sources[${firstIndexOfId.get(id)}] has it too`));
    } else {
      firstIndexOfId.set(id, index);
      types.set(id, SOURCE_TYPES.includes(type) ? type : null);
    }
  }
  if (isNonEmptyString(url) && !isHttpsUrl(url)) {
    errors.push(issue(SOURCES_FILE, field("url"), `must be an https:// URL, found ${JSON.stringify(url)}`));
  }
  if (isNonEmptyString(accessed) && !isRealDate(accessed)) {
    errors.push(issue(
      SOURCES_FILE,
      field("accessed"),
      `must be a real date in YYYY-MM-DD form, found ${JSON.stringify(accessed)}`,
    ));
  }
  if (isNonEmptyString(type) && !SOURCE_TYPES.includes(type)) {
    errors.push(issue(SOURCES_FILE, field("type"), `must be one of ${SOURCE_TYPES.join(", ")}, found ${JSON.stringify(type)}`));
  }
}

function isHttpsUrl(value) {
  if (!value.startsWith("https://")) return false;
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

function isRealDate(value) {
  const match = ISO_DATE.exec(value);
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

// Emitters ------------------------------------------------------------------------------------

function checkEmitters(rules, emitterIds, errors, warnings) {
  if (emitterIds === null) {
    warnings.push(issue(
      EMITTERS_FILE,
      "EMITTERS",
      "EMITTERS is not available, so the check that every measured MVP rule has an emitter is skipped",
    ));
    return;
  }
  for (const rule of rules) {
    if (rule.id === null || rule.kind !== "measured" || rule.since !== "mvp") continue;
    if (!emitterIds.has(rule.id)) {
      errors.push(issue(rule.file, "kind", `measured rule with since "mvp" has no emitter in EMITTERS of ${EMITTERS_FILE}`));
    }
  }
}

// Returns the rule ids of a collection: items of an array or a Set, keys of a Map or a plain object.
function collectionIds(collection) {
  if (collection === null) return null;
  if (!isCollection(collection)) {
    throw new TypeError("emitters must be null, an array, a Set, a Map or a plain object");
  }
  if (Array.isArray(collection) || collection instanceof Set) return new Set(collection);
  if (collection instanceof Map) return new Set(collection.keys());
  return new Set(Object.keys(collection));
}

function isCollection(value) {
  return Array.isArray(value) || value instanceof Set || value instanceof Map || isPlainObject(value);
}

// Data files ----------------------------------------------------------------------------------

// Checks data/*.json. Returns the number of files.
function checkDataFiles(root, errors) {
  const dataDir = path.join(root, "data");
  if (!isDirectory(dataDir)) return 0;
  const names = fs
    .readdirSync(dataDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
    .map((entry) => entry.name)
    .sort(compareText);
  for (const name of names) {
    const file = `data/${name}`;
    let data;
    try {
      data = JSON.parse(readText(path.join(dataDir, name)));
    } catch (error) {
      errors.push(issue(file, "json", `not valid JSON: ${firstLine(error.message)}`));
      continue;
    }
    checkDataValue(file, data, "", { errors, firstPointerOfId: new Map() });
  }
  return names.length;
}

// Walks every value of a data file. pointer is the JSON pointer of the value, used as the field.
function checkDataValue(file, value, pointer, state) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => checkDataValue(file, item, `${pointer}/${index}`, state));
    return;
  }
  if (!isPlainObject(value)) return;

  if (Object.hasOwn(value, "id")) {
    const key = JSON.stringify(value.id);
    if (state.firstPointerOfId.has(key)) {
      state.errors.push(issue(file, `${pointer}/id`, `duplicate id ${key}; ${state.firstPointerOfId.get(key)} has it too`));
    } else {
      state.firstPointerOfId.set(key, `${pointer}/id`);
    }
  }
  checkRegexKeys(file, value, pointer, state.errors);
  for (const key of Object.keys(value)) {
    checkDataValue(file, value[key], `${pointer}/${escapePointer(key)}`, state);
  }
}

function checkRegexKeys(file, object, pointer, errors) {
  const keys = Object.keys(object).filter((key) => key === "regex" || key.endsWith("Regex"));
  if (keys.length === 0) return;
  const hasFlags = Object.hasOwn(object, "flags");
  if (hasFlags && typeof object.flags !== "string") {
    errors.push(issue(file, `${pointer}/flags`, "must be a string, since a regex is next to it"));
  }
  const flags = hasFlags && typeof object.flags === "string" ? object.flags : undefined;

  for (const key of keys) {
    const value = object[key];
    const base = `${pointer}/${escapePointer(key)}`;
    const candidates = Array.isArray(value)
      ? value.map((item, index) => [item, `${base}/${index}`])
      : [[value, base]];
    for (const [source, field] of candidates) {
      if (typeof source !== "string") continue;
      try {
        new RegExp(source, flags);
      } catch (error) {
        errors.push(issue(file, field, `not a valid regular expression: ${firstLine(error.message)}`));
      }
    }
  }
}

function escapePointer(key) {
  return String(key).replaceAll("~", "~0").replaceAll("/", "~1");
}

// Checks data/agent-harness.json with validateAgentHarness. The file is optional: a root without it is skipped. Anything
// else at its path must be a readable regular file, so a folder, a dangling symbolic link or a read error is an error on
// the file. A file that is not valid JSON is skipped here, because the data checks above report it. sourceTypes is null
// when rules/sources.json could not be read.
function checkAgentHarness(root, sourceTypes, errors) {
  const read = readDataFile(root, AGENT_HARNESS_FILE, errors);
  if (read === null) return;
  for (const item of validateAgentHarness(read.data, { sourceTypes })) {
    errors.push(issue(AGENT_HARNESS_FILE, item.pointer === "" ? "(root)" : item.pointer, item.message));
  }
}

// Checks data/layer-signals.json with validateLayerSignals. The file is required: scripts/map.mjs reads it through the layer
// mapping, so a root without it has an error on the file. A file that is not valid JSON is reported by the data checks.
function checkLayerSignals(root, errors) {
  if (!isPresent(path.join(root, LAYER_SIGNALS_FILE))) {
    errors.push(issue(LAYER_SIGNALS_FILE, "(file)", "is missing; the layer mapping reads it, so the file is required"));
    return;
  }
  const read = readDataFile(root, LAYER_SIGNALS_FILE, errors);
  if (read === null) return;
  for (const item of validateLayerSignals(read.data)) {
    errors.push(issue(LAYER_SIGNALS_FILE, item.pointer === "" ? "(root)" : item.pointer, item.message));
  }
}

// Checks data/injection-patterns.json with validateInjectionPatterns. A root without the file is skipped, as for
// data/agent-harness.json; the scanner itself needs it. A file that is not valid JSON is reported by the data checks.
function checkInjectionPatterns(root, errors) {
  const read = readDataFile(root, INJECTION_PATTERNS_FILE, errors);
  if (read === null) return;
  for (const item of validateInjectionPatterns(read.data)) {
    errors.push(issue(INJECTION_PATTERNS_FILE, item.pointer === "" ? "(root)" : item.pointer, item.message));
  }
}

// Reads one data file as JSON for a check of that file. Returns { data }, or null when nothing is at the path, when the path
// is not a readable regular file (the error is pushed), or when the file is not valid JSON.
function readDataFile(root, file, errors) {
  const full = path.join(root, file);
  if (!isPresent(full)) return null;
  let text;
  try {
    if (!fs.statSync(full).isFile()) {
      errors.push(issue(file, "(file)", "must be a regular file, not a folder or another kind of entry"));
      return null;
    }
    text = readText(full);
  } catch (error) {
    errors.push(issue(file, "(file)", `cannot be read: ${error.code ?? "unknown error"}`));
    return null;
  }
  try {
    return { data: JSON.parse(text) };
  } catch {
    return null;
  }
}

// Whether anything is at the path, a dangling symbolic link included. A path whose parent is not a folder is nothing there.
function isPresent(target) {
  try {
    fs.lstatSync(target);
    return true;
  } catch (error) {
    return error.code !== "ENOENT" && error.code !== "ENOTDIR";
  }
}

// Command line --------------------------------------------------------------------------------

function parseCommandLine(argv) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: false,
      strict: true,
      options: { root: { type: "string" } },
    });
  } catch (error) {
    throw new UsageError(error.message);
  }
  if (parsed.values.root === "") throw new UsageError("the --root folder must not be empty");
  return { root: parsed.values.root };
}

async function main(argv) {
  try {
    const { root: input } = parseCommandLine(argv);
    const root = path.resolve(input ?? HARNESS_ROOT);
    if (!isDirectory(path.join(root, "rules"))) throw new UsageError(`root must contain a rules/ folder: ${root}`);

    const loaded = await loadEmitters(HARNESS_ROOT);
    const result = checkCatalog({ root, emitters: loaded.emitters });
    const errors = sortIssues([...loaded.errors, ...result.errors]);
    for (const item of errors) console.log(formatIssue(item));
    for (const item of result.warnings) console.log(`warning: ${formatIssue(item)}`);
    console.log(summaryLine(result.counts, errors.length, result.warnings.length));
    return errors.length > 0 ? 1 : 0;
  } catch (error) {
    if (error instanceof UsageError) {
      console.error(`error: ${error.message}`);
      console.error(USAGE);
      return 2;
    }
    console.error(`error: ${firstLine(error?.message ?? error)}`);
    return 1;
  }
}

function formatIssue(item) {
  return `${item.file}: ${item.field}: ${item.message}`;
}

function summaryLine(counts, errorCount, warningCount) {
  const scanned = [
    plural(counts.rules, "rule"),
    plural(counts.sources, "source"),
    plural(counts.dataFiles, "data file"),
  ].join(", ");
  return `catalog: ${scanned}; ${plural(errorCount, "error")}, ${plural(warningCount, "warning")}`;
}

function plural(count, noun) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

// Helpers -------------------------------------------------------------------------------------

function sortIssues(items) {
  return [...items].sort(
    (a, b) => compareText(a.file, b.file) || compareText(a.field, b.field) || compareText(a.message, b.message),
  );
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

function isString(value) {
  return typeof value === "string";
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}

function isDirectory(target) {
  try {
    return fs.statSync(target).isDirectory();
  } catch {
    return false;
  }
}

// Reads a file as text with LF line endings: a leading BOM is dropped, and CRLF or a lone CR becomes
// LF, so the result does not depend on how git checked the file out.
function readText(target) {
  const text = fs.readFileSync(target, "utf8");
  const withoutBom = text.startsWith("\uFEFF") ? text.slice(1) : text;
  return withoutBom.replace(/\r\n?/g, "\n");
}

function firstLine(value) {
  return String(value).split("\n")[0];
}

// True when this file is the program that node runs. Importing the module (as the tests do) does
// not run the command line.
function isEntryPoint() {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return fs.realpathSync.native(entry) === fs.realpathSync.native(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  process.exitCode = await main(process.argv.slice(2));
}
