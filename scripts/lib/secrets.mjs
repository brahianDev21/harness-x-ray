// Measure "secrets": the secret files of the target, the literal secrets of the harness, and the protection that the project gives
// to .env. The content of a secret file is never read: only its name is. A literal is read only from the harness: the memory
// files, the env of the two settings files, the env, headers and args of .mcp.json, and the text of skills, commands and
// subagents. Every value is masked before it is stored (see secret-patterns.mjs), and no measure of this file ever writes a
// raw value to a warning.
//
// Output: security.secrets = { fileListSource, files, literals, readProtection }. Nothing is run and no hook runs. The rules
// are read through loadClaudeConfig, and the parsed JSON through the same cache, so nothing is parsed twice.

import { loadClaudeConfig } from "./claude-config.mjs";
import { UNDETERMINABLE, coveredTools, hookRunState } from "./hook-matcher.mjs";
import { isPlainObject } from "./json-out.mjs";
import { USER_LAYER, decide, decisionRules } from "./permissions.mjs";
import { createRedactor } from "./redact.mjs";
import {
  findGenericSecrets,
  findSpecificSecrets,
  genericSecretOf,
  loadSecretPatterns,
  mask,
  overlaps,
  secretFileKind,
} from "./secret-patterns.mjs";

export const MEASURE_ID = "secrets";

// Memory files that Claude Code loads by name at any depth. Imports from them are not followed.
const MEMORY_NAMES = new Set(["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md"]);
// The memory files that may sit at the root of the target without being versioned.
const MEMORY_ROOT_FILES = ["CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md", "AGENTS.md"];
const RULES_DIR = ".claude/rules/";
const MCP_FILE = ".mcp.json";
// A flag with its value in one argument ("--token=VALUE"), and a flag alone ("--api-key").
const FLAG_WITH_VALUE = /^--?([A-Za-z0-9_.-]+)=(.+)$/;
const FLAG = /^--?([A-Za-z0-9_.-]+)$/;
// The read of .env at the root of the project, which the readProtection answers.
const ENV_AT_ROOT = Object.freeze({ tool: "Read", path: ".env" });

export const secretsMeasure = Object.freeze({ id: MEASURE_ID, collect: collectSecrets });

// Reads the target through ctx only. Returns the section that the scan core merges.
function collectSecrets(ctx) {
  const config = loadClaudeConfig(ctx);
  const rules = decisionRules(config.permissions, ctx.outside);
  const redact = createRedactor({ root: ctx.root });
  const literals = [];
  for (const { path, data } of config.parsedFiles.settings) literals.push(...settingsLiterals(ctx, path, data, redact));
  if (config.parsedFiles.mcp !== null) literals.push(...mcpLiterals(ctx, config.parsedFiles.mcp, redact));
  for (const rel of harnessTextPaths(ctx, config)) literals.push(...textLiterals(ctx, rel, redact));

  return {
    security: {
      secrets: {
        fileListSource: ctx.fileListSource,
        files: secretFiles(ctx, rules, redact),
        literals: sortLiterals(literals),
        readProtection: readProtectionOf(config, rules),
      },
    },
  };
}

// ---------------------------------------------------------------------------------------------------
// Secret files, by name only

// Every listed file whose base name is secret-shaped. Its content is not read: the list of the scan core is the only input.
function secretFiles(ctx, rules, redact) {
  const files = [];
  for (const { path } of ctx.files) {
    const kind = secretFileKind(path);
    if (kind === null) continue;
    files.push({ path: redact(path), kind, readDecision: verdictOf(decide(rules, { tool: "Read", path })) });
  }
  return files.sort((a, b) => compareText(a.path, b.path));
}

// ---------------------------------------------------------------------------------------------------
// Read protection

// Whether the project denies a Read of .env at the root, and which PreToolUse hooks cover the Read tool and whether each
// one runs for that read (docs: hooks, permissions).
function readProtectionOf(config, rules) {
  const hooks = config.hooks
    .filter((hook) => hook.event === "PreToolUse")
    .map((hook) => ({ hook, tools: coveredTools(hook.matcher, ["Read"]) }))
    .filter(({ tools }) => tools === UNDETERMINABLE || tools.length > 0);
  return {
    envAtRoot: verdictOf(decide(rules, ENV_AT_ROOT)),
    preToolUseReadHooks: hooks.map(({ hook, tools }) => ({
      source: hook.source,
      matcher: hook.matcher,
      if: hook.if,
      script: hook.script,
      failsOpen: hook.failsOpen,
      runsForEnv: hookRunState(hook, tools, ENV_AT_ROOT),
    })),
  };
}

// The four fields of a verdict that the output shows. The layer is kept only when the rule comes from the user's settings, so
// a project verdict has the same four fields as before.
function verdictOf(verdict) {
  const shown = { decision: verdict.decision, rule: verdict.rule, source: verdict.source, reason: verdict.reason };
  return verdict.layer === USER_LAYER ? { ...shown, layer: USER_LAYER } : shown;
}

// ---------------------------------------------------------------------------------------------------
// Literals in the settings, .mcp.json and the text files

// The env values of one settings file. Only the values are checked; the key names are shown as they are.
function settingsLiterals(ctx, rel, data, redact) {
  if (!isPlainObject(data.env) || secretFileKind(rel) !== null) return [];
  const where = { file: redact(rel), text: textOf(ctx, rel) };
  const items = [];
  for (const key of Object.keys(data.env).sort(compareText)) {
    const value = data.env[key];
    if (typeof value !== "string") continue;
    items.push(...valueLiterals(where, `env.${redact(key)}`, key, value));
  }
  return items;
}

// The env, headers and args of each server of .mcp.json.
function mcpLiterals(ctx, { path, data }, redact) {
  const servers = data.mcpServers;
  if (!isPlainObject(servers) || secretFileKind(path) !== null) return [];
  const where = { file: redact(path), text: textOf(ctx, path) };
  const items = [];
  for (const name of Object.keys(servers).sort(compareText)) {
    const server = servers[name];
    if (!isPlainObject(server)) continue;
    const base = `mcpServers.${redact(name)}`;
    for (const section of ["env", "headers"]) {
      const block = server[section];
      if (!isPlainObject(block)) continue;
      for (const key of Object.keys(block).sort(compareText)) {
        const value = block[key];
        if (typeof value !== "string") continue;
        items.push(...valueLiterals(where, `${base}.${section}.${redact(key)}`, key, value));
      }
    }
    if (Array.isArray(server.args)) items.push(...argLiterals(where, base, server.args));
  }
  return items;
}

// The args of one server, whose base is the already redacted name of the server. A specific token is found in any argument.
// A generic one is found in "--key=VALUE", and in a secret-named flag followed by its value (the next argument).
function argLiterals(where, base, args) {
  const items = [];
  args.forEach((arg, index) => {
    if (typeof arg !== "string") return;
    const location = `${base}.args[${index}]`;
    for (const found of findSpecificSecrets(arg)) items.push(literalOf(where, found.value, found.id, found.prefix, location));
    const withValue = FLAG_WITH_VALUE.exec(arg);
    if (withValue !== null) {
      items.push(...genericLiterals(where, location, withValue[1], withValue[2]));
      return;
    }
    const flag = FLAG.exec(arg);
    const next = args[index + 1];
    if (flag !== null && typeof next === "string" && !next.startsWith("-")) {
      items.push(...genericLiterals(where, `${base}.args[${index + 1}]`, flag[1], next));
    }
  });
  return items;
}

// Values of key-value places (env, headers): the specific tokens in the value, or else the generic assignment.
function valueLiterals(where, location, key, value) {
  const specific = findSpecificSecrets(value);
  if (specific.length > 0) return specific.map((found) => literalOf(where, found.value, found.id, found.prefix, location));
  return genericLiterals(where, location, key, value);
}

// The generic assignment of one key and value, unless the value holds a specific token (which is reported on its own).
function genericLiterals(where, location, key, value) {
  const secret = genericSecretOf(key, value);
  if (secret === null || findSpecificSecrets(value).length > 0) return [];
  return [literalOf(where, secret, loadSecretPatterns().generic.id, null, location)];
}

// The markdown files of the harness (memory and rules, skills, commands and subagents), one entry per path, sorted. A file
// with a secret-shaped name is not read: it is reported by name. A memory file that claudeMdExcludes matches is included on
// purpose: Claude's Read can open it, so a secret value in it is still reported here (the memory measure does not read it).
function harnessTextPaths(ctx, config) {
  const paths = new Set();
  for (const file of ctx.files) {
    if (isMemoryFile(file.path)) paths.add(file.path);
  }
  for (const rel of MEMORY_ROOT_FILES) {
    if (ctx.fs.exists(rel)) paths.add(rel);
  }
  for (const item of [...config.skills, ...config.commands, ...config.subagents]) paths.add(item.path);
  return [...paths].filter((rel) => secretFileKind(rel) === null).sort(compareText);
}

function isMemoryFile(rel) {
  const name = rel.split("/").pop();
  return MEMORY_NAMES.has(name) || (rel.startsWith(RULES_DIR) && rel.endsWith(".md"));
}

// The literals of one text file: the specific tokens, and the generic assignments that do not overlap one.
function textLiterals(ctx, rel, redact) {
  const read = ctx.readText(rel);
  if (!read.ok) return [];
  const file = redact(rel);
  const text = read.text;
  const specific = findSpecificSecrets(text);
  const items = specific.map((found) => ({
    file,
    line: lineAt(text, found.start),
    kind: found.id,
    masked: mask(found.value, found.prefix),
    location: "text",
  }));
  for (const found of findGenericSecrets(text)) {
    if (specific.some((other) => overlaps(found, other))) continue;
    items.push({ file, line: lineAt(text, found.start), kind: found.id, masked: mask(found.value, null), location: "text" });
  }
  return items;
}

// One literal. The line is where the value first appears in the file, for JSON files; null when it does not appear.
function literalOf(where, value, kind, prefix, location) {
  return { file: where.file, line: lineOfValue(where.text, value), kind, masked: mask(value, prefix), location };
}

// ---------------------------------------------------------------------------------------------------
// Helpers

// The text of a file as the scan core reads it, or null when it cannot be read.
function textOf(ctx, rel) {
  const read = ctx.readText(rel);
  return read.ok ? read.text : null;
}

// The 1-based line of an index in a text.
function lineAt(text, index) {
  return text.slice(0, index).split("\n").length;
}

// The 1-based line of the first occurrence of a value in a JSON file, where the value is written with JSON escapes. Null when
// the text is not available or the value does not occur.
function lineOfValue(text, value) {
  if (text === null) return null;
  const index = text.indexOf(JSON.stringify(value).slice(1, -1));
  return index === -1 ? null : lineAt(text, index);
}

// Sorted by file, then line (lines without a number last), kind, location and masked value.
function sortLiterals(items) {
  return items.sort(
    (a, b) =>
      compareText(a.file, b.file) ||
      compareLines(a.line, b.line) ||
      compareText(a.kind, b.kind) ||
      compareText(a.location, b.location) ||
      compareText(a.masked, b.masked),
  );
}

function compareLines(a, b) {
  if (a === null || b === null) return a === b ? 0 : a === null ? 1 : -1;
  return a - b;
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
