// Measure "verification": how the target checks its work, and how its tools are set up. It reads the root
// package.json as data, the memory texts that the memory measure left in ctx.memory, and the names of the
// files in the target. It never opens a lockfile or a tool config, and it runs nothing.
//
// Output:
// - verification.commands: the scripts of the root package.json that run a check (test, lint, typecheck,
//   format, verify, build), with their categories. The command text is not output: it may hold secrets.
// - verification.mentioned: the calls that the memory text makes to those scripts.
// - instructions.packageManager: the manager that the packageManager field names, the lockfiles at the
//   root, the managers that the memory text names, and whether those disagree (conflict).
// - structure.enforcementTools: the configs of tools that enforce rules, found by file name.
//
// The package.json warnings belong to the references measure, which reads the same file, so this measure
// adds none. Every text in the output is redacted.

import { markdownLines } from "./markdown.mjs";
import { packageScripts, readPackageJson } from "./package-json.mjs";
import { createRedactor } from "./redact.mjs";
import { scriptCallsInLine } from "./script-calls.mjs";

export const MEASURE_ID = "verification";

// Script names by category. "exact" matches the whole name, "prefix" the start (test: matches test:unit)
// and "suffix" the end (:test matches unit:test).
const NAME_RULES = [
  ["build", { exact: ["build"], prefix: ["build:"] }],
  ["format", { exact: ["format", "fmt"], prefix: ["format:"] }],
  ["lint", { exact: ["lint"], prefix: ["lint:"] }],
  ["test", { exact: ["test", "e2e"], prefix: ["test:"], suffix: [":test"] }],
  ["typecheck", { exact: ["typecheck", "type-check", "types", "check-types", "tsc"] }],
  ["verify", { exact: ["verify", "check", "ci", "validate"], prefix: ["verify:", "check:"] }],
];

// Words that a command contains, by category. They match as whole words and without regard to case, so
// "ava" does not match "java" or "avatars".
const COMMAND_RULES = [
  ["build", ["vite build", "astro build", "next build", "tsup", "esbuild", "rollup", "webpack"]],
  ["format", ["prettier", "biome format", "dprint"]],
  ["lint", ["eslint", "biome lint", "biome check", "oxlint", "stylelint"]],
  ["test", ["vitest", "jest", "mocha", "node --test", "playwright test", "ava", "cypress run"]],
  ["typecheck", ["vue-tsc", "svelte-check", "astro check"]],
];
// tsc type-checks only when --noEmit comes later in the same shell segment ("tsc -p . --noEmit"). A plain
// "tsc" builds, so it is not a typecheck.
const TSC_NO_EMIT = /(?<![\w.-])tsc(?![\w.-])[^&|;]*--noEmit(?![\w-])/i;
const COMMAND_PATTERNS = [
  ...COMMAND_RULES.map(([category, words]) => [
    category,
    new RegExp(`(?<![\\w.-])(?:${words.map(escapeRegExp).join("|")})(?![\\w.-])`, "i"),
  ]),
  ["typecheck", TSC_NO_EMIT],
];

const MANAGERS = new Set(["npm", "pnpm", "yarn", "bun"]);
// Lockfiles at the root, by name. They are never opened.
const LOCKFILE_MANAGERS = new Map([
  ["package-lock.json", "npm"],
  ["npm-shrinkwrap.json", "npm"],
  ["pnpm-lock.yaml", "pnpm"],
  ["yarn.lock", "yarn"],
  ["bun.lock", "bun"],
  ["bun.lockb", "bun"],
]);
// A manager name in memory text, as a whole word: a letter, digit, underscore, hyphen, slash or "@" on
// either side, or a dot before the name, makes it part of a longer name ("pnpmfile", "npm-run-all",
// "@pnpm/exe", "~/.npm"). A dot followed by a word character after the name makes it a file name
// ("yarn.lock", "bun.lockb", "npm.cmd"), so those are not mentions either. A dot that ends a sentence
// ("Install with npm.") is not followed by a word character, so it counts. Case matters: commands are lowercase.
const MANAGER_WORD = /(?<![\w.@/-])(npm|npx|pnpm|yarn|bunx?)(?![\w/-]|\.\w)/g;
const MANAGER_OF_WORD = new Map([
  ["npm", "npm"],
  ["npx", "npm"],
  ["pnpm", "pnpm"],
  ["yarn", "yarn"],
  ["bun", "bun"],
  ["bunx", "bun"],
]);

// Configs at the root, by file name. Each pattern matches one file name.
const ROOT_TOOLS = [
  ["biome", /^biome\.jsonc?$/],
  ["dependency-cruiser", /^\.dependency-cruiser\..+$/],
  ["editorconfig", /^\.editorconfig$/],
  ["eslint", /^(?:eslint\.config\..+|\.eslintrc.*)$/],
  ["gitleaks", /^\.?gitleaks\.toml$/],
  ["jscpd", /^\.jscpd\.json$/],
  ["lint-staged", /^(?:\.lintstagedrc.*|lint-staged\.config\..+)$/],
  ["prettier", /^(?:\.prettierrc.*|prettier\.config\..+)$/],
  ["secretlint", /^\.secretlintrc.*$/],
  ["typescript", /^tsconfig(?:\..+)?\.json$/],
];
// Workflows are the files directly inside .github/workflows.
const WORKFLOW = /^\.github\/workflows\/[^/]+\.ya?ml$/;
// Any file under this folder makes one husky entry, for the folder itself.
const HUSKY_FOLDER = ".husky";

export const verificationMeasure = Object.freeze({
  id: MEASURE_ID,
  collect: collectVerification,
});

function collectVerification(ctx) {
  const redact = createRedactor({ root: ctx.root });
  const read = readPackageJson(ctx);
  // An absent, unreadable or invalid package.json gives no scripts and no field. References reports it.
  const data = read.status === "ok" ? read.data : null;
  const listed = data === null ? null : packageScripts(data);
  const scripts = listed !== null && listed.ok ? listed.scripts : new Map();

  const classified = classifyScripts(scripts);
  const commands = classified
    .map(({ name, categories }) => ({ name: redact(name), categories }))
    .sort((a, b) => compareText(a.name, b.name));
  const listedNames = new Set(classified.map((item) => item.name));

  return {
    verification: {
      commands,
      mentioned: scriptMentions(ctx.memory, listedNames, redact),
    },
    instructions: {
      packageManager: packageManagerOf(ctx, data, redact),
    },
    structure: {
      enforcementTools: enforcementTools(ctx.files),
    },
  };
}

// The scripts that run a check, with their categories (sorted). A script with no category is left out.
function classifyScripts(scripts) {
  const classified = [];
  for (const [name, command] of scripts) {
    const categories = unique([...nameCategories(name), ...commandCategories(command)]).sort(compareText);
    if (categories.length > 0) classified.push({ name, categories });
  }
  return classified;
}

function nameCategories(name) {
  return NAME_RULES.filter(([, rule]) => matchesName(name, rule)).map(([category]) => category);
}

/**
 * The categories of a script name alone (test, lint, typecheck, verify, ...). The measured findings use it for a
 * script that a memory file names but the package.json does not define, so no command text is available.
 * @param {string} name Script name.
 * @returns {string[]} Sorted categories; empty when the name is not a check.
 */
export function categoriesOfScriptName(name) {
  return nameCategories(name).sort(compareText);
}

function matchesName(name, rule) {
  return (
    (rule.exact ?? []).includes(name) ||
    (rule.prefix ?? []).some((start) => name.startsWith(start)) ||
    (rule.suffix ?? []).some((end) => name.endsWith(end))
  );
}

function commandCategories(command) {
  return COMMAND_PATTERNS.filter(([, pattern]) => pattern.test(command)).map(([category]) => category);
}

// The calls of the memory text to a listed script. A call that repeats on the same line is one entry.
function scriptMentions(memory, listedNames, redact) {
  const found = new Map();
  for (const file of sortedFiles(memory)) {
    for (const line of markdownLines(memory.get(file).text)) {
      for (const call of scriptCallsInLine(line)) {
        if (!listedNames.has(call.script)) continue;
        const entry = { script: redact(call.script), file, line: line.number, text: redact(call.text) };
        found.set(JSON.stringify([entry.file, entry.line, entry.script, entry.text]), entry);
      }
    }
  }
  return [...found.values()].sort(
    (a, b) => compareText(a.file, b.file) || a.line - b.line || compareText(a.script, b.script),
  );
}

// The package manager as the target declares it, and as its lockfiles and memory text show it.
function packageManagerOf(ctx, data, redact) {
  const declared =
    data !== null && typeof data.packageManager === "string" && data.packageManager !== "" ? data.packageManager : null;
  // The field is "name@version". Only the four managers count; any other name gives null.
  const fieldManager = declared === null ? null : managerNamed(declared.split("@")[0]);
  const lockfiles = ctx.files
    .filter((entry) => LOCKFILE_MANAGERS.has(entry.path))
    .map((entry) => ({ path: entry.path, manager: LOCKFILE_MANAGERS.get(entry.path) }))
    .sort((a, b) => compareText(a.path, b.path));
  const mentions = managerMentions(ctx.memory);

  const named = new Set([...lockfiles, ...mentions].map((item) => item.manager));
  if (fieldManager !== null) named.add(fieldManager);
  return {
    field: declared === null ? null : redact(declared),
    fieldManager,
    lockfiles,
    mentions,
    conflict: named.size > 1,
  };
}

// The memory lines that name a package manager: one entry per manager, file and line.
function managerMentions(memory) {
  const found = [];
  for (const file of sortedFiles(memory)) {
    for (const line of markdownLines(memory.get(file).text)) {
      for (const manager of managersIn(line.text)) found.push({ manager, file, line: line.number });
    }
  }
  return found.sort(
    (a, b) => compareText(a.file, b.file) || a.line - b.line || compareText(a.manager, b.manager),
  );
}

function managersIn(text) {
  const found = new Set();
  for (const match of text.matchAll(MANAGER_WORD)) found.add(MANAGER_OF_WORD.get(match[1]));
  return [...found];
}

function managerNamed(name) {
  return MANAGERS.has(name) ? name : null;
}

// The config files of the tools that enforce rules. Only names are read: a file is listed, never opened.
function enforcementTools(files) {
  const found = new Map();
  const add = (tool, rel) => found.set(JSON.stringify([tool, rel]), { tool, path: rel });
  for (const { path: rel } of files) {
    if (WORKFLOW.test(rel)) add("github-actions", rel);
    if (rel.startsWith(`${HUSKY_FOLDER}/`)) add("husky", HUSKY_FOLDER);
    if (rel.includes("/")) continue;
    for (const [tool, pattern] of ROOT_TOOLS) {
      if (pattern.test(rel)) add(tool, rel);
    }
  }
  return [...found.values()].sort((a, b) => compareText(a.tool, b.tool) || compareText(a.path, b.path));
}

function sortedFiles(memory) {
  return [...memory.keys()].sort(compareText);
}

function unique(values) {
  return [...new Set(values)];
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
