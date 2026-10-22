// Measure "claude-config": the Claude Code configuration of the target. It reads .claude/settings.json,
// .claude/settings.local.json, .mcp.json, and the skills, commands and subagents, through ctx only. It
// never runs, spawns or requires anything from the target.
//
// Output: claudeConfig (settings, hooks, skills, commands, subagents, mcpServers, claudeMdExcludes), security.permissions
// (reading only), one inventory item per file, and the always-loaded budget of skills, commands and
// subagents. The MCP servers and the context-injecting hooks go to context.alwaysLoaded.unknownStatic,
// because their size cannot be known without running them. Every string copied from the target goes
// through the redactor. Env and header values are never copied: only their key names. The parsed
// configuration is shared with other measures through loadClaudeConfig, which parses the files once per scan.
//
// With a scope (--scope, see scope.mjs), a nested skill whose path ctx.scope.keepsHarness rejects is left out: it is not read,
// not in the inventory and not in claudeConfig. The root skills, the commands, the subagents, .mcp.json, the settings and the
// hooks are global, so a scope does not change them.

import { parseFrontmatter } from "./frontmatter.mjs";
import { classifyScriptPath, findScriptWord, hookWords } from "./hook-command.mjs";
import { isPlainObject, toStableJson } from "./json-out.mjs";
import { matchPathGlob } from "./permissions.mjs";
import { createRedactor } from "./redact.mjs";
import { estimateTokens } from "./tokens.mjs";

export const MEASURE_ID = "claude-config";

// The shared settings file comes first and the local one second: the later file has the higher precedence.
const SETTINGS_FILES = [".claude/settings.json", ".claude/settings.local.json"];
const MCP_FILE = ".mcp.json";
const SKILLS_DIR = ".claude/skills";
const COMMANDS_DIR = ".claude/commands";
const AGENTS_DIR = ".claude/agents";
// Folders deeper than this, below the folder that is searched, are not searched.
export const MAX_WALK_DEPTH = 6;
// Claude Code truncates description and when_to_use in the skill listing at this many characters.
const MAX_DESCRIPTION_CHARS = 1536;
// Events whose plain-text stdout Claude Code adds to the context (docs: hooks).
const CONTEXT_EVENTS = new Set(["SessionStart", "UserPromptSubmit", "UserPromptExpansion", "PostModelSwitch"]);
// Permission modes that Claude Code ignores when a project settings file sets them (docs: permission-modes).
const IGNORED_MODES = new Set(["auto", "bypassPermissions"]);
// manual is the config value that the docs give as an alias of default.
const APPLIED_MODES = new Set(["default", "manual", "acceptEdits", "plan", "dontAsk"]);
// Frontmatter keys that this measure reads. An unsupported value in one of them makes the file's
// description unreadable. Other keys are not read, so an unsupported value in them does not matter.
const READ_KEYS = ["name", "description", "when_to_use", "disable-model-invocation", "tools", "disallowedTools", "permissionMode"];
const CONFIG_REASON = "configuration, not loaded into context";
const BODY_REASON = "the body loads when invoked";
const NAMELESS_REASON = "no name in the frontmatter, so Claude Code skips the file";
// A skill of a subfolder. NOT VERIFIED by a note: no note says that nested skills load on demand. This repository's
// CLAUDE.md says that skills inside test/fixtures load on demand, and this measure follows that. Nested commands and
// subagents are not inventoried: no note says that they load from a subfolder, so they are left out.
const NESTED_SKILL_REASON = "nested-skill";
const SCOPE_ROOT = "root";
const SCOPE_NESTED = "nested";
// The settings key that lists the memory files Claude Code does not load. Its syntax is not stated in any note.
const EXCLUDES_KEY = "claudeMdExcludes";

// The parsed configuration of each scan, keyed by its context. ctx.memory holds only memory file texts,
// which other measures iterate, so the parsed configuration is kept here instead.
const parsedByScan = new WeakMap();

export const claudeConfigMeasure = Object.freeze({ id: MEASURE_ID, collect: collectClaudeConfig });

/**
 * The parsed configuration of the target, read once per scan. Other measures use it instead of
 * parsing the files again. Only this measure emits the inventory and the warnings. The returned
 * object is shared: callers must not change it.
 * @param {object} ctx The scan context. One context is one scan, so it keys the parsed configuration.
 * @returns {{ settings: object[], hooks: object[], permissions: object, skills: object[], commands: object[],
 *   subagents: object[], mcpServers: object[], claudeMdExcludes: Array<{ pattern: string, shown: string, source: string }>,
 *   parsedFiles: { settings: Array<{ path: string, data: object }>, mcp: { path: string, data: object } | null },
 *   inventory: object[], warnings: object[] }}
 *   claudeMdExcludes lists the valid patterns of both settings files in file order: pattern is as written, for matching,
 *   and shown is the redacted form, for output. parsedFiles holds the parsed JSON objects of the settings and of
 *   .mcp.json, for measures that read values which the output does not copy (secrets). It is never written to the output.
 */
export function loadClaudeConfig(ctx) {
  if (!parsedByScan.has(ctx)) parsedByScan.set(ctx, parseClaudeConfig(ctx));
  return parsedByScan.get(ctx);
}

/**
 * Reads the Claude Code configuration of the target.
 * @param {object} ctx The scan context: root, fs (safe-fs view), readText and memory.
 * @returns {object} A partial measurements object, merged by the scan core.
 */
function collectClaudeConfig(ctx) {
  const config = loadClaudeConfig(ctx);

  const unknownStatic = [
    ...config.mcpServers.map((server) => ({ kind: "mcp-server", source: server.source, name: server.name })),
    ...config.hooks
      .filter((hook) => hook.injectsContext)
      .map((hook) => ({ kind: "hook-output", source: hook.source, event: hook.event, matcher: hook.matcher })),
  ];

  return {
    claudeConfig: {
      settings: config.settings,
      hooks: config.hooks,
      skills: config.skills,
      commands: config.commands,
      subagents: config.subagents,
      mcpServers: config.mcpServers,
      claudeMdExcludes: config.claudeMdExcludes.map(({ shown, source }) => ({ pattern: shown, source })).sort(byExclude),
    },
    security: { permissions: config.permissions },
    inventory: config.inventory,
    warnings: config.warnings,
    context: {
      alwaysLoaded: {
        byComponent: [
          budgetOf("skills", config.skills),
          budgetOf("commands", config.commands),
          budgetOf("subagents", config.subagents),
        ],
        unknownStatic,
      },
    },
  };
}

// Reads every file of the configuration once, and collects what it finds and what it could not read.
function parseClaudeConfig(ctx) {
  const redact = createRedactor({ root: ctx.root });
  const warnings = [];
  const inventory = [];
  const warn = (path, reason, detail) => {
    warnings.push(detail === undefined ? { path, reason } : { path, reason, detail });
  };
  const options = { redact, warn, inventory };

  const settings = readSettings(ctx, options);
  const mcp = readMcpServers(ctx, options);
  // A skill is a SKILL.md inside its own folder (docs: skills). A SKILL.md directly in the skills folder is not one.
  const skillFiles = findFiles(ctx, SKILLS_DIR, (name) => name === "SKILL.md").filter((rel) => rel !== `${SKILLS_DIR}/SKILL.md`);
  // Root skills come from the disk walk above. Nested skills come from ctx.files, which is the git-tracked list inside a git
  // repository and the disk walk otherwise. So inside git an untracked root skill is listed and an untracked nested skill is
  // not, and without git the disk walk also lists copies, such as .claude/worktrees/*/.claude/skills/*. A path that the root
  // walk already found is a root skill, so it is not listed again as nested (a skill inside another skill's folder).
  const rootSkillFiles = new Set(skillFiles);
  // With a scope (--scope), a nested skill outside it is left out before it is read: it is in neither the inventory nor skills.
  const scope = ctx.scope ?? null;
  const nestedSkillFiles = ctx.files
    .map((file) => file.path)
    .filter((rel) => isNestedSkill(rel) && !rootSkillFiles.has(rel) && (scope === null || scope.keepsHarness(rel)))
    .sort(compareText);
  // Root skills and nested skills share one list. Each item says its scope, and only the root items count in the budget.
  const skills = [
    ...readMarkdownFiles(ctx, "skill", skillFiles, options, SCOPE_ROOT),
    ...readMarkdownFiles(ctx, "skill", nestedSkillFiles, options, SCOPE_NESTED),
  ].sort(byPath);
  const commands = readMarkdownFiles(ctx, "command", findFiles(ctx, COMMANDS_DIR, isMarkdownName), options);
  const subagents = readMarkdownFiles(ctx, "subagent", findFiles(ctx, AGENTS_DIR, isMarkdownName), options);

  return {
    settings: settings.items,
    hooks: settings.hooks,
    permissions: settings.permissions,
    skills,
    commands,
    subagents,
    mcpServers: mcp.servers,
    claudeMdExcludes: settings.claudeMdExcludes,
    parsedFiles: { settings: settings.objects, mcp: mcp.document },
    inventory,
    warnings,
  };
}

// ---------------------------------------------------------------------------------------------------
// Settings files, permissions and hooks

// Reads both settings files and combines what they say about permissions. Lists add up across the
// two files; the scalar values (defaultMode, disableBypassPermissionsMode) come from the file with the
// higher precedence, which is the local file when it sets them.
function readSettings(ctx, { redact, warn, inventory }) {
  const items = [];
  const hooks = [];
  const objects = [];
  const claudeMdExcludes = [];
  const lists = { allow: [], ask: [], deny: [], additionalDirectories: [] };
  let defaultMode = null;
  let disableBypassPermissionsMode = null;

  for (const rel of SETTINGS_FILES) {
    const read = ctx.readText(rel);
    if (!read.ok) continue;
    inventory.push(configInventory(rel, "settings", read));
    const data = parseObject(read.text, rel, warn);
    if (data === null) {
      items.push({ path: rel, parsed: false, envKeys: [], enableAllProjectMcpServers: null, sandbox: emptySandbox() });
      continue;
    }
    objects.push({ path: rel, data });
    const summary = summarizeSettings(data, rel, { redact, warn });
    items.push(summary.item);
    for (const key of Object.keys(lists)) lists[key].push(...summary[key]);
    claudeMdExcludes.push(...summary.claudeMdExcludes);
    for (const entry of summary.hookEntries) hooks.push(hookItem(entry, rel, ctx, { redact, warn }));
    if (summary.defaultMode !== null) defaultMode = summary.defaultMode;
    if (summary.disableBypassPermissionsMode !== null) disableBypassPermissionsMode = summary.disableBypassPermissionsMode;
  }

  hooks.sort(byHook);
  const notes = [];
  if (lists.allow.length > 0) notes.push("allow-requires-folder-trust");
  if (lists.additionalDirectories.length > 0) notes.push("additional-directories-require-folder-trust");
  const permissions = {
    allow: lists.allow.sort(byRule),
    ask: lists.ask.sort(byRule),
    deny: lists.deny.sort(byRule),
    additionalDirectories: lists.additionalDirectories.sort(byPath),
    defaultMode: defaultMode === null ? null : { ...defaultMode, effect: effectOf(defaultMode.value) },
    disableBypassPermissionsMode,
    notes: notes.sort(compareText),
  };
  return { items: items.sort(byPath), hooks, permissions, objects, claudeMdExcludes };
}

// What one parsed settings file says. Unexpected shapes are warnings, and the values that are fine are
// still read.
function summarizeSettings(data, rel, { redact, warn }) {
  const summary = {
    item: {
      path: rel,
      parsed: true,
      envKeys: data.env === undefined ? [] : keyNames(data.env, rel, "env", { redact, warn }),
      enableAllProjectMcpServers: optionalBoolean(data.enableAllProjectMcpServers, rel, "enableAllProjectMcpServers", warn),
      sandbox: sandboxOf(data.sandbox, rel, { redact, warn }),
    },
    allow: [],
    ask: [],
    deny: [],
    additionalDirectories: [],
    defaultMode: null,
    disableBypassPermissionsMode: null,
    hookEntries: hookEntriesOf(data.hooks, rel, warn),
    claudeMdExcludes: excludesOf(data[EXCLUDES_KEY], rel, { redact, warn }),
  };
  const permissions = data.permissions;
  if (permissions === undefined) return summary;
  if (!isPlainObject(permissions)) {
    warn(rel, "unexpected-shape", "permissions");
    return summary;
  }
  for (const list of ["allow", "ask", "deny"]) {
    summary[list] = stringsOf(permissions[list], rel, `permissions.${list}`, warn).map((rule) => ({
      rule: redact(rule),
      source: rel,
    }));
  }
  summary.additionalDirectories = stringsOf(permissions.additionalDirectories, rel, "permissions.additionalDirectories", warn).map(
    (dir) => ({ path: redact(dir), source: rel }),
  );
  summary.defaultMode = scalarOf(permissions.defaultMode, rel, "permissions.defaultMode", { redact, warn });
  summary.disableBypassPermissionsMode = scalarOf(
    permissions.disableBypassPermissionsMode,
    rel,
    "permissions.disableBypassPermissionsMode",
    { redact, warn },
  );
  return summary;
}

function emptySandbox() {
  return { present: false, enabled: null, keys: [] };
}

function sandboxOf(value, rel, { redact, warn }) {
  if (value === undefined) return emptySandbox();
  if (!isPlainObject(value)) {
    warn(rel, "unexpected-shape", "sandbox");
    return { present: true, enabled: null, keys: [] };
  }
  return {
    present: true,
    enabled: optionalBoolean(value.enabled, rel, "sandbox.enabled", warn),
    keys: keyNames(value, rel, "sandbox", { redact, warn }),
  };
}

// The hook groups of a settings file, one entry per handler. A group or handler of the wrong shape is
// a warning and is skipped.
export function hookEntriesOf(hooks, rel, warn) {
  if (hooks === undefined) return [];
  if (!isPlainObject(hooks)) {
    warn(rel, "unexpected-shape", "hooks");
    return [];
  }
  const entries = [];
  for (const event of Object.keys(hooks)) {
    const groups = hooks[event];
    if (!Array.isArray(groups)) {
      warn(rel, "unexpected-shape", "hooks");
      continue;
    }
    for (const group of groups) {
      if (!isPlainObject(group) || !Array.isArray(group.hooks)) {
        warn(rel, "unexpected-shape", "hooks");
        continue;
      }
      const matcher = typeof group.matcher === "string" ? group.matcher : null;
      if (group.matcher !== undefined && matcher === null) warn(rel, "unexpected-shape", "hooks.matcher");
      for (const handler of group.hooks) {
        if (!isPlainObject(handler) || typeof handler.type !== "string") {
          warn(rel, "unexpected-shape", "hooks");
          continue;
        }
        entries.push({ event, matcher, handler });
      }
    }
  }
  return entries;
}

// One hook handler as the output shows it. The command is read, never run: the script it names is only
// checked for existence, and only when it lies inside the project.
function hookItem({ event, matcher, handler }, rel, ctx, { redact, warn }) {
  const command = commandOf(handler, rel, warn);
  const script = command === null ? null : scriptOf(command.words, ctx, redact);
  if (handler.timeout !== undefined && typeof handler.timeout !== "number") warn(rel, "unexpected-shape", "hooks.timeout");
  if (handler.onFailure !== undefined && typeof handler.onFailure !== "string") warn(rel, "unexpected-shape", "hooks.onFailure");
  if (handler.if !== undefined && typeof handler.if !== "string") warn(rel, "unexpected-shape", "hooks.if");
  return {
    source: rel,
    event: redact(event),
    matcher: matcher === null ? null : redact(matcher),
    // Docs (hooks): the rule that filters the calls the hook runs for. Only a string is kept.
    if: typeof handler.if === "string" ? redact(handler.if) : null,
    type: redact(handler.type),
    command: command === null ? null : redact(command.text),
    timeout: typeof handler.timeout === "number" && Number.isFinite(handler.timeout) ? handler.timeout : null,
    onFailure: typeof handler.onFailure === "string" ? redact(handler.onFailure) : null,
    script,
    injectsContext: CONTEXT_EVENTS.has(event),
    // Docs: a hook that fails or times out lets the action go on, unless onFailure is "block".
    failsOpen: handler.onFailure !== "block",
  };
}

// The command of a command hook as text (for display) and as words (for reading the script). An exec
// form hook (command plus args) is shown as its words joined by spaces.
function commandOf(handler, rel, warn) {
  if (handler.type !== "command") return null;
  if (typeof handler.command !== "string") {
    warn(rel, "unexpected-shape", "hooks.command");
    return null;
  }
  const execForm = Array.isArray(handler.args) && handler.args.every((arg) => typeof arg === "string");
  if (handler.args !== undefined && !execForm) warn(rel, "unexpected-shape", "hooks.args");
  if (execForm) {
    return { text: [handler.command, ...handler.args].join(" "), words: hookWords(handler.command, handler.args) };
  }
  return { text: handler.command, words: hookWords(handler.command, undefined) };
}

function scriptOf(words, ctx, redact) {
  const raw = findScriptWord(words);
  if (raw === null) return null;
  const place = classifyScriptPath(raw);
  if (place.external) return { path: redact(raw), external: true, exists: null };
  return { path: place.rel, external: false, exists: ctx.fs.exists(place.rel) };
}

// The effect that Claude Code gives a defaultMode value set in a project settings file (docs:
// permission-modes, settings). Both project files are covered by the same rule.
function effectOf(mode) {
  if (IGNORED_MODES.has(mode)) return "ignored-from-project";
  if (APPLIED_MODES.has(mode)) return "applies";
  return "unknown-value";
}

// The key names of an object, sorted, redacted. A value that is not an object is a warning.
function keyNames(value, rel, detail, { redact, warn }) {
  if (!isPlainObject(value)) {
    warn(rel, "unexpected-shape", detail);
    return [];
  }
  return Object.keys(value)
    .sort(compareText)
    .map((key) => redact(key));
}

function optionalBoolean(value, rel, detail, warn) {
  if (value === undefined) return null;
  if (typeof value === "boolean") return value;
  warn(rel, "unexpected-shape", detail);
  return null;
}

export function scalarOf(value, rel, detail, { redact, warn }) {
  if (value === undefined) return null;
  if (typeof value !== "string") {
    warn(rel, "unexpected-shape", detail);
    return null;
  }
  return { value: redact(value), source: rel };
}

// The strings of a list. A list that is not a list, or items that are not strings, are warnings, and
// the strings that are fine are kept.
export function stringsOf(value, rel, detail, warn) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    warn(rel, "unexpected-shape", detail);
    return [];
  }
  const strings = value.filter((item) => typeof item === "string");
  if (strings.length !== value.length) warn(rel, "unexpected-shape", detail);
  return strings;
}

// The valid patterns of claudeMdExcludes in one settings file, in file order. A value that is not a list, an entry that
// is not a string and a pattern that cannot be read are warnings, and the other patterns still apply. A pattern that
// starts with "/" or a drive letter, or that contains a backslash, is an unsupported-pattern: its meaning is not verified
// by a note, so it is not used (matchPathGlob also refuses the backslash and the brackets). An unsupported pattern is
// never copied, not even redacted. NOT VERIFIED: no note says which settings files accept claudeMdExcludes, so both project
// files are read, as the other lists are. The matching is case-sensitive, a trailing slash is dropped, AGENTS.md is treated
// as covered, and ancestors are not checked against the patterns (see memory.mjs); none of these is verified by a note.
function excludesOf(value, rel, { redact, warn }) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    warn(rel, "unexpected-shape", EXCLUDES_KEY);
    return [];
  }
  const patterns = [];
  for (const entry of value) {
    if (typeof entry !== "string") {
      warn(rel, "unexpected-shape", EXCLUDES_KEY);
      continue;
    }
    // Whether a pattern is supported does not depend on the path, so an empty path is enough to ask.
    if (isAbsoluteExclude(entry) || entry.includes("\\") || matchPathGlob(entry, "") === "unsupported") {
      warn(rel, "unsupported-pattern", EXCLUDES_KEY);
      continue;
    }
    patterns.push({ pattern: entry, shown: redact(entry), source: rel });
  }
  return patterns;
}

// A leading "/" or a drive letter. The meaning of such a claudeMdExcludes pattern is not verified by a note.
function isAbsoluteExclude(pattern) {
  return pattern.startsWith("/") || /^[A-Za-z]:/.test(pattern);
}

// Reads a JSON file whose top level must be an object. Returns null after a warning when it is not.
// The warning has no detail: the parser's message could quote the file.
export function parseObject(text, rel, warn) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    warn(rel, "invalid-json");
    return null;
  }
  if (!isPlainObject(data)) {
    warn(rel, "unexpected-shape");
    return null;
  }
  return data;
}

// ---------------------------------------------------------------------------------------------------
// MCP servers (.mcp.json)

// Lists the servers of .mcp.json by name, type and the key names of env and headers. The values, the
// command, the arguments and the URL are never copied. Returns the servers and the parsed file (null when it
// is missing or not a JSON object), which the secrets measure reads through loadClaudeConfig.
function readMcpServers(ctx, { redact, warn, inventory }) {
  const read = ctx.readText(MCP_FILE);
  if (!read.ok) return { servers: [], document: null };
  inventory.push(configInventory(MCP_FILE, "mcp", read));
  const data = parseObject(read.text, MCP_FILE, warn);
  if (data === null) return { servers: [], document: null };
  const document = { path: MCP_FILE, data };
  if (data.mcpServers === undefined) return { servers: [], document };
  if (!isPlainObject(data.mcpServers)) {
    warn(MCP_FILE, "unexpected-shape", "mcpServers");
    return { servers: [], document };
  }
  const servers = [];
  for (const name of Object.keys(data.mcpServers).sort(compareText)) {
    const server = data.mcpServers[name];
    if (!isPlainObject(server)) {
      warn(MCP_FILE, "unexpected-shape", "mcpServers");
      continue;
    }
    servers.push({
      source: MCP_FILE,
      name: redact(name),
      type: serverType(server, { redact, warn }),
      loadMode: "unknown-static",
      envKeys: server.env === undefined ? [] : keyNames(server.env, MCP_FILE, "mcpServers.env", { redact, warn }),
      headerKeys: server.headers === undefined ? [] : keyNames(server.headers, MCP_FILE, "mcpServers.headers", { redact, warn }),
    });
  }
  return { servers, document };
}

// Docs (mcp): an entry without "type" is read as stdio, but an entry with "url" and no "type" is a
// configuration error that Claude Code skips. That case is null here.
function serverType(server, { redact, warn }) {
  if (server.type === undefined) return "url" in server ? null : "stdio";
  if (typeof server.type === "string") return redact(server.type);
  warn(MCP_FILE, "unexpected-shape", "mcpServers.type");
  return null;
}

// ---------------------------------------------------------------------------------------------------
// Skills, commands and subagents

// Describes each markdown file of one kind, in the order given. The file is read only once; its
// inventory entry is recorded here. A skill has a scope: a root skill is in the budget when its description is
// (loadMode always); a nested skill is on demand and is never in the budget.
function readMarkdownFiles(ctx, kind, files, { redact, warn, inventory }, scope = SCOPE_ROOT) {
  const items = [];
  for (const rel of files) {
    const read = ctx.readText(rel);
    if (!read.ok) continue;
    const item = describeMarkdown(kind, rel, read.text, { redact, warn });
    const nested = kind === "skill" && scope === SCOPE_NESTED;
    if (kind === "skill") item.scope = scope;
    if (nested && item.loadMode === "always") item.loadMode = "on-demand";
    items.push(item);
    const notLoaded = kind === "subagent" && item.name === null;
    inventory.push({
      path: rel,
      kind,
      bytes: read.bytes,
      lines: countLines(read.text),
      estTokens: estimateTokens(read.text).estTokens,
      loadMode: notLoaded ? "not-loaded" : "on-demand",
      loadReason: notLoaded ? NAMELESS_REASON : nested ? NESTED_SKILL_REASON : BODY_REASON,
    });
  }
  return items;
}

// A nested skill: a SKILL.md inside a .claude/skills folder of a subfolder of the target, at any depth. The first
// ".claude" folder below the root must be followed by "skills", and at least one folder must lie between "skills" and
// SKILL.md, as at the root (a SKILL.md directly in the skills folder is not a skill).
function isNestedSkill(rel) {
  const parts = rel.split("/");
  const at = parts.indexOf(".claude", 1);
  return parts.at(-1) === "SKILL.md" && at !== -1 && parts[at + 1] === "skills" && parts.length - (at + 2) >= 2;
}

// What the listing of one skill, command or subagent costs. The description is what Claude Code keeps
// in context; the body loads only when the file is invoked.
export function describeMarkdown(kind, rel, text, { redact, warn }) {
  const parsed = parseFrontmatter(text);
  const broken = parsed.error !== undefined;
  const fields = broken ? {} : (parsed.data ?? {});
  const unsupported = !broken && READ_KEYS.some((key) => isUnsupported(fields[key]));
  const name = nameOf(kind, rel, fields, redact);
  if (broken || unsupported) {
    warn(rel, "frontmatter-unsupported");
    const item = {
      path: rel,
      name,
      descriptionChars: null,
      overLimit: null,
      disableModelInvocation: null,
      estTokens: null,
      loadMode: null,
      frontmatterError: broken ? "broken" : "unsupported-value",
    };
    if (kind === "subagent") Object.assign(item, { tools: null, disallowedTools: null, permissionMode: null });
    return item;
  }

  const description = descriptionOf(kind, fields.description, parsed.body);
  const whenToUse = fields.when_to_use === undefined || fields.when_to_use === null ? "" : String(fields.when_to_use);
  const listed = [description, whenToUse].filter((part) => part !== "").join("\n");
  const disableModelInvocation = fields["disable-model-invocation"] === true;
  const item = {
    path: rel,
    name,
    descriptionChars: listed.length,
    overLimit: listed.length > MAX_DESCRIPTION_CHARS,
    disableModelInvocation,
    estTokens: estimateTokens(listed).estTokens,
    loadMode: disableModelInvocation || (kind === "subagent" && name === null) ? "not-loaded" : "always",
    frontmatterError: null,
  };
  if (kind === "subagent") {
    item.tools = toolsOf(fields.tools, redact);
    item.disallowedTools = toolsOf(fields.disallowedTools, redact);
    item.permissionMode = typeof fields.permissionMode === "string" ? redact(fields.permissionMode) : null;
  }
  return item;
}

// Skills take their name from the frontmatter or from their folder (docs: skills). Commands take it
// from their path, with "/" shown as ":" (docs: commands). Subagents need a name in the frontmatter:
// without one Claude Code skips the file (docs: sub-agents).
function nameOf(kind, rel, fields, redact) {
  const hasName = typeof fields.name === "string" && fields.name !== "";
  if (kind === "subagent") return hasName ? redact(fields.name) : null;
  if (kind === "skill" && hasName) return redact(fields.name);
  if (kind === "skill") return redact(rel.split("/").at(-2));
  return redact(rel.slice(COMMANDS_DIR.length + 1, -".md".length).replaceAll("/", ":"));
}

// Docs (skills): without a description, Claude Code uses the first non-empty line of the content.
// Subagents have no such rule in the docs, so their description is empty when it is missing.
function descriptionOf(kind, value, body) {
  if (value !== undefined && value !== null) return String(value);
  if (kind === "subagent") return "";
  for (const line of body.split("\n")) {
    const trimmed = line.trim();
    if (trimmed !== "") return trimmed;
  }
  return "";
}

function toolsOf(value, redact) {
  if (typeof value === "string") return redact(value);
  if (Array.isArray(value)) return value.filter((item) => typeof item === "string").map((item) => redact(item));
  return null;
}

// An unsupported value from the frontmatter parser: { error: "line N: ..." }.
function isUnsupported(value) {
  return isPlainObject(value) && typeof value.error === "string";
}

// The always-loaded budget of one component: the items whose loadMode is "always".
function budgetOf(component, items) {
  const counted = items
    .filter((item) => item.loadMode === "always")
    .map((item) => ({ path: item.path, estTokens: item.estTokens }));
  return {
    component,
    estTokens: counted.reduce((sum, item) => sum + item.estTokens, 0),
    items: counted,
  };
}

// The files of a folder whose names pass accept, found by walking the folder. Symbolic links to
// folders are not followed; a link to a file counts when it points to a file.
export function findFiles(ctx, base, accept) {
  const found = [];
  const visit = (dir, depth) => {
    const listing = ctx.fs.listDir(dir);
    if (!listing.ok) return;
    for (const entry of listing.entries) {
      const rel = `${dir}/${entry.name}`;
      if (entry.type === "dir") {
        if (depth < MAX_WALK_DEPTH) visit(rel, depth + 1);
      } else if (accept(entry.name) && (entry.type === "file" || (entry.type === "symlink" && ctx.fs.stat(rel).type === "file"))) {
        found.push(rel);
      }
    }
  };
  visit(base, 0);
  return found.sort(compareText);
}

function isMarkdownName(name) {
  return name.endsWith(".md");
}

// ---------------------------------------------------------------------------------------------------
// Shared helpers

// The inventory entry of a configuration file. Its content is not loaded into context.
function configInventory(rel, kind, read) {
  return {
    path: rel,
    kind,
    bytes: read.bytes,
    lines: countLines(read.text),
    estTokens: estimateTokens(read.text).estTokens,
    loadMode: "not-loaded",
    loadReason: CONFIG_REASON,
  };
}

export function countLines(text) {
  if (text === "") return 0;
  const lines = text.split("\n").length;
  return text.endsWith("\n") ? lines - 1 : lines;
}

const byPath = (a, b) => compareText(a.path, b.path) || compareText(a.source ?? "", b.source ?? "");
const byRule = (a, b) => compareText(a.rule, b.rule) || compareText(a.source, b.source);
const byExclude = (a, b) => compareText(a.pattern, b.pattern) || compareText(a.source, b.source);

function byHook(a, b) {
  return (
    compareText(a.source, b.source) ||
    compareText(a.event, b.event) ||
    compareText(a.matcher ?? "", b.matcher ?? "") ||
    compareText(toStableJson(a), toStableJson(b))
  );
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
