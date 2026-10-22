// Measure "verification": how the target checks its work, and how its tools are set up. It reads the root
// package.json as data, the memory texts that the memory measure left in ctx.memory, and the names of the
// files in the target. It never opens a lockfile or a tool config, and it runs nothing.
//
// Output:
// - verification.commands: the scripts of the root package.json that run a check (test, lint, typecheck,
//   format, verify, build), with their categories. The command text is not output: it may hold secrets.
// - verification.mentioned: the calls that the memory text makes to those scripts.
// - verification.packages (only with a scope): the package.json files of the target other than the root one, each with
//   where it lies ("scope", "inherited" or "other"), its status ("ok", "unreadable" or "invalid") and its check scripts.
//   Sorted by where, then path. At most MAX_SCOPE_PACKAGES are kept, and the cut is one warning, scope-packages-cut.
//   Paths with a node_modules segment are skipped. Their check scripts are listed names for verification.mentioned.
// - instructions.packageManager: the manager that the packageManager field names, the lockfiles at the
//   root, the managers that the memory text names (mentions), the files that name a manager with the agents
//   that own them (byFile), and whether all of them disagree (conflict). The texts of the other agents' instruction
//   files (ctx.agentInstructions) count toward conflict and byFile, not toward mentions.
// - structure.enforcementTools: the configs of tools that enforce rules, found by file name, and the architecture tools that a
//   manifest names (MANIFEST_TOOLS): eslint-plugin-boundaries in a dependency list of a package.json, import-linter in a
//   pyproject.toml or setup.cfg section, and ArchUnit in a Maven or Gradle build file. A manifest is read as data (package.json
//   is parsed, the others are searched for a fixed marker), and a manifest that cannot be read names nothing. With a scope, the
//   configs and manifests directly inside each inherited folder, each scope folder and the folder of each package.json in
//   verification.packages count too, so a lint or typecheck config at the root of another layer counts.
//
// With a scope, verification.commands still reads only the root package.json: it lies outside the scope, and it still
// counts. The CI workflows and husky stay at the root, as without a scope. The package.json warnings belong to the
// references measure, which reads the same file, so this measure adds none, except scope-packages-cut. Every text in the
// output is redacted.

import path from "node:path";
import { instructionTextsOf } from "./agent-inventory.mjs";
import { markdownLines } from "./markdown.mjs";
import { isObject, packageScripts, readPackageJson } from "./package-json.mjs";
import { createRedactor } from "./redact.mjs";
import { scriptCallsInLine } from "./script-calls.mjs";

export const MEASURE_ID = "verification";

/** The most package.json files that verification.packages lists, with a scope. The rest are counted in one warning. */
export const MAX_SCOPE_PACKAGES = 100;
// The order of the where values in verification.packages.
const WHERE_ORDER = Object.freeze(["scope", "inherited", "other"]);

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
  ["import-linter", /^\.importlinter$/],
  ["jscpd", /^\.jscpd\.json$/],
  ["lint-staged", /^(?:\.lintstagedrc.*|lint-staged\.config\..+)$/],
  ["prettier", /^(?:\.prettierrc.*|prettier\.config\..+)$/],
  ["secretlint", /^\.secretlintrc.*$/],
  ["typescript", /^tsconfig(?:\..+)?\.json$/],
];
// Architecture tools that a manifest names. A package.json names a tool when one of DEPENDENCY_FIELDS lists the package; any
// other manifest names it when its text holds the marker. Markers are lower case and compared with the lower-case text.
const MANIFEST_TOOLS = [
  { tool: "eslint-plugin-boundaries", manifest: "package.json", dependency: "eslint-plugin-boundaries" },
  { tool: "import-linter", manifest: "pyproject.toml", marker: "[tool.importlinter" },
  { tool: "import-linter", manifest: "setup.cfg", marker: "[importlinter" },
  { tool: "archunit", manifest: "pom.xml", marker: "com.tngtech.archunit" },
  { tool: "archunit", manifest: "build.gradle", marker: "com.tngtech.archunit" },
  { tool: "archunit", manifest: "build.gradle.kts", marker: "com.tngtech.archunit" },
];
const DEPENDENCY_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
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
  // With a scope, the check scripts of the listed packages are listed names too (see verification.packages).
  const packages = ctx.scope ? scopePackages(ctx) : null;
  const packageChecks = packages === null ? [] : packages.entries.flatMap((entry) => entry.classified);
  const listedNames = new Set([...classified, ...packageChecks].map((item) => item.name));
  // The folders of the listed package.json files: their tool configs count too (enforcementTools).
  const packageFolders = packages === null ? [] : packages.entries.map((entry) => path.posix.dirname(entry.path));

  return {
    verification: {
      commands: commandsOf(classified, redact),
      mentioned: scriptMentions(ctx.memory, listedNames, redact),
      ...(packages === null ? {} : { packages: packages.entries.map((entry) => packageOutput(entry, redact)) }),
    },
    instructions: {
      packageManager: packageManagerOf(ctx, data, redact),
    },
    structure: {
      enforcementTools: enforcementTools(ctx, packageFolders),
    },
    warnings: packages === null ? [] : packages.warnings,
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

// The output form of the check scripts: names redacted, sorted by name.
function commandsOf(classified, redact) {
  return classified
    .map(({ name, categories }) => ({ name: redact(name), categories }))
    .sort((a, b) => compareText(a.name, b.name));
}

// The package.json files other than the root one, with a scope. Each is placed by its folder, read through readPackageJson,
// and kept with its raw script names (packageOutput redacts them). Only the first MAX_SCOPE_PACKAGES of the sorted list are
// kept. The entries are { path, where, status, classified }; warnings holds the one cut warning, when there is one.
function scopePackages(ctx) {
  const found = ctx.files
    .filter((file) => isOtherPackageFile(file.path))
    .map(({ path: rel }) => ({ path: rel, where: whereOf(ctx.scope, rel), ...scriptsOfPackage(readPackageJson(ctx, rel)) }))
    .sort((a, b) => WHERE_ORDER.indexOf(a.where) - WHERE_ORDER.indexOf(b.where) || compareText(a.path, b.path));
  const warnings =
    found.length > MAX_SCOPE_PACKAGES
      ? [{ path: ".", reason: "scope-packages-cut", detail: `count=${found.length - MAX_SCOPE_PACKAGES}` }]
      : [];
  return { entries: found.slice(0, MAX_SCOPE_PACKAGES), warnings };
}

// A package.json that is not the root one and does not lie under a node_modules folder.
function isOtherPackageFile(rel) {
  return rel !== "package.json" && path.posix.basename(rel) === "package.json" && !rel.split("/").includes("node_modules");
}

// The layer of a package.json by its folder: a scope folder or a folder inside one, an inherited folder, or any other.
function whereOf(scope, rel) {
  const folder = path.posix.dirname(rel);
  if (scope.contains(folder)) return "scope";
  return scope.isInherited(folder) ? "inherited" : "other";
}

// The status of one package.json and its check scripts. An absent file is reported as unreadable: it was listed, so it is
// not there when read. Only an ok status has check scripts.
function scriptsOfPackage(read) {
  if (read.status === "absent" || read.status === "unreadable") return { status: "unreadable", classified: [] };
  if (read.status === "invalid") return { status: "invalid", classified: [] };
  const listed = packageScripts(read.data);
  if (!listed.ok) return { status: "invalid", classified: [] };
  return { status: "ok", classified: classifyScripts(listed.scripts) };
}

function packageOutput({ path: rel, where, status, classified }, redact) {
  return { path: rel, where, status, commands: commandsOf(classified, redact) };
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
  // The lines of the memory texts and of the other agents' instruction texts that name a manager. Conflict counts all of them;
  // mentions keeps the memory lines only, as it always did.
  const allMentions = managerMentions(instructionTextsOf(ctx));

  const named = new Set([...lockfiles, ...allMentions].map((item) => item.manager));
  if (fieldManager !== null) named.add(fieldManager);
  return {
    field: declared === null ? null : redact(declared),
    fieldManager,
    lockfiles,
    mentions: allMentions.filter((item) => ctx.memory.has(item.file)),
    byFile: byFileOf(allMentions, ctx.agentOwners),
    conflict: named.size > 1,
  };
}

// The lines that name a package manager, for [file, text] pairs: one entry per manager, file and line.
function managerMentions(texts) {
  const found = [];
  for (const [file, text] of texts) {
    for (const line of markdownLines(text)) {
      for (const manager of managersIn(line.text)) found.push({ manager, file, line: line.number });
    }
  }
  return found.sort(
    (a, b) => compareText(a.file, b.file) || a.line - b.line || compareText(a.manager, b.manager),
  );
}

// The files that name a manager, sorted by file, with the managers each names (sorted) and the agents that own the file in the
// agent inventory (ctx.agentOwners; [] when none does). A file is listed only when it names at least one manager.
function byFileOf(mentions, owners) {
  const managersOf = new Map();
  for (const { manager, file } of mentions) {
    if (!managersOf.has(file)) managersOf.set(file, new Set());
    managersOf.get(file).add(manager);
  }
  return [...managersOf.keys()].sort(compareText).map((file) => ({
    file,
    managers: [...managersOf.get(file)].sort(compareText),
    agents: [...(owners.get(file) ?? [])],
  }));
}

function managersIn(text) {
  const found = new Set();
  for (const match of text.matchAll(MANAGER_WORD)) found.add(MANAGER_OF_WORD.get(match[1]));
  return [...found];
}

function managerNamed(name) {
  return MANAGERS.has(name) ? name : null;
}

// The config files of the tools that enforce rules, and the manifests that name an architecture tool. A config is found by
// name and never opened; a manifest of MANIFEST_TOOLS is read. A config or manifest counts when it lies directly in one of the
// config folders (configFolders). Workflows and husky are found at the root only.
function enforcementTools(ctx, packageFolders) {
  const folders = configFolders(ctx.scope, packageFolders);
  const found = new Map();
  const add = (tool, rel) => found.set(JSON.stringify([tool, rel]), { tool, path: rel });
  for (const { path: rel } of ctx.files) {
    if (WORKFLOW.test(rel)) add("github-actions", rel);
    if (rel.startsWith(`${HUSKY_FOLDER}/`)) add("husky", HUSKY_FOLDER);
    if (!folders.has(path.posix.dirname(rel))) continue;
    const name = path.posix.basename(rel);
    for (const [tool, pattern] of ROOT_TOOLS) {
      if (pattern.test(name)) add(tool, rel);
    }
    for (const entry of MANIFEST_TOOLS) {
      if (entry.manifest === name && manifestNames(ctx, rel, entry)) add(entry.tool, rel);
    }
  }
  return [...found.values()].sort((a, b) => compareText(a.tool, b.tool) || compareText(a.path, b.path));
}

// True when the manifest at rel names the tool of entry (see MANIFEST_TOOLS).
function manifestNames(ctx, rel, entry) {
  if (entry.dependency !== undefined) {
    const read = readPackageJson(ctx, rel);
    if (read.status !== "ok") return false;
    return DEPENDENCY_FIELDS.some((field) => isObject(read.data[field]) && Object.hasOwn(read.data[field], entry.dependency));
  }
  const read = ctx.readText(rel);
  return read.ok && read.text.toLowerCase().includes(entry.marker);
}

// The folders whose directly contained files are tool configs: the root, and with a scope also the inherited folders (the
// root included, once), the scope folders and the folders of the listed package.json files of the other layers.
function configFolders(scope, packageFolders) {
  return new Set(!scope ? ["."] : [".", ...scope.inherited, ...scope.folders, ...packageFolders]);
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
