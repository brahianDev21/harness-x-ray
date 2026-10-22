// Builds the remediation of one scan: the fragments of settings that a person can copy by hand, and the simulation of the
// harness with every simulated fragment applied. It reads measurements.json, and the agent's fragments once they are checked
// (checkAgentFragments). It never reads the target, runs nothing, and writes nothing: remediate.mjs writes the result.
//
// Measured fragments are permission rules only, because only the permission rules can be simulated (permissions.mjs):
// - SEC-01: for each broad shell allow (a bare one or a wildcard one) that lets destructive commands through by a rule, a
//   fragment with the rule of each such command (data coverRule). The rule asks, or denies when the command is critical in the
//   data. A command that SEC-01 covers is not repeated under SEC-02.
// - SEC-02: for each destructive command that passes today (its outcome, or a mode of its matrix, or a subagent run passes), a
//   fragment with its coverRule. The rule covers the sample command and the same prefix followed by any arguments. It does not
//   cover a reordered or respelled form, such as git push origin --force for git push --force, nor rm -fr for rm -rf. The data's
//   coverNote, when the entry has one, says what else the rule covers, and it is shown with the fragment.
// - SEC-03: for each secret file that the project does not already deny, a fragment with the deny rule Read(./<path>), and the
//   same for the .env at the root when the scan decides it and no secret file has that path. Literal secrets get no fragment:
//   they are listed as not simulated, by file and line only.
// Hooks are out of scope: they cannot be simulated without running them, so no fragment is a hook. No measured fragment has a
// hook, a text change or an allow rule.
//
// The simulation applies every simulated fragment together (the patch) to the project's rules, and reports for each destructive
// command and each secret read the outcome before and after the patch, for the measured value and for each mode of the matrix.
// The "before" is first simulated from the rules that measurements.json records. If it differs from the measured value (the scan
// read rules that the file does not record, such as the user layer's), that command or read is not simulated, with the reason,
// and its fragment is not applied. A command or read that passes before and not after is "moved"; one that still passes is
// "still-passes", never left out. A "classifier" result is a command that no mode passes and that auto mode would decide with a
// model: it is not a move.
//
// The outcomes in the modes of UNVERIFIED_MODES (auto and bypassPermissions) are NOT VERIFIED against the documentation. Each
// command row lists them in notVerified, so that a reader sees which results rest on them.
//
// Agent fragments are judgment proposals. Each is checked (checkAgentFragments): its rules parse, it holds no secret-shaped
// value, its rules name no folder of this machine, and its texts are redacted. A fragment is simulated when it has rules and each
// rule is one the simulation decides for every call (unmodelledReason); a fragment with no rule is listed with the reason
// no-rule, and any other fragment is listed as not simulated, with its reason.
//
// The lists of the remediation hold at most LIST_CAP items each. The items left out are counted in omitted. The fragments kept
// are the first ones, in order, and only they are simulated, so the file shows what the simulation applied.

import { loadDestructiveCommands } from "./destructive-commands.mjs";
import { BARE_SHELL_RULES, WILDCARD_SHELL_RULE } from "./measured-findings.mjs";
import { MATRIX_MODES, UNVERIFIED_MODES, decide, evaluate, evaluateInSessionMode, parseRule } from "./permissions.mjs";
import { createRedactor } from "./redact.mjs";
import { findGenericSecrets, findSpecificSecrets } from "./secret-patterns.mjs";
import { UsageError } from "./target.mjs";

export const SCHEMA_VERSION = 1;
// The most items of each list of remediation.json (fragments, commands, reads and literal secrets). The schema states it too.
export const LIST_CAP = 200;
// The largest size of agent-fragments.json and of remediation.json, in bytes. A larger file is an input error (exit 2), and a
// remediation that would be larger than its cap is not written.
export const AGENT_FRAGMENTS_MAX_BYTES = 256 * 1024;
export const REMEDIATION_MAX_BYTES = 256 * 1024;
// The limits of an agent's text after redaction: the schema's maxLength values of the fragment's title and text.
const TITLE_MAX = 120;
const TEXT_MAX = 1000;
// The decision of a Read that the fragment makes: a deny. A file that the project already denies is not given a fragment.
const DENY = "deny";

/**
 * Checks the agent's fragments once they pass their schema: the rule is a judgment rule of the catalog, the texts and the rules
 * hold no secret-shaped value, every rule parses, no rule names a folder of this machine, and the redacted texts fit their caps.
 * The texts are redacted. A problem is a usage error that names the fragment by its index only: the text of a rule is never
 * printed, since it may hold what was refused.
 * @param {Array<{ rule: string, title: string, text: string, settings?: object }>} items The fragments of agent-fragments.json.
 * @param {{ judgmentRules: Set<string>, redact: (value: unknown) => unknown }} options
 * @returns {Array<{ rule: string, title: string, text: string, settings: object | null }>}
 * @throws {UsageError} On the first fragment that breaks a check.
 */
export function checkAgentFragments(items, { judgmentRules, redact }) {
  return items.map((item, index) => {
    const where = `agent-fragments.json: fragment ${index}`;
    if (!judgmentRules.has(item.rule)) throw new UsageError(`${where}: the rule is not a judgment rule of the catalog`);
    const settings = item.settings === undefined ? null : item.settings;
    const rules = settings === null ? [] : [...settings.permissions.deny, ...settings.permissions.ask];
    for (const text of [item.title, item.text, ...rules]) {
      if (holdsSecretShape(text)) throw new UsageError(`${where}: holds a secret-shaped value; the value is not printed, remove it from the file`);
    }
    for (const rule of rules) {
      if (!parseRule(rule).ok) throw new UsageError(`${where}: a permission rule does not parse; its text is not printed`);
      if (redact(rule) !== rule) throw new UsageError(`${where}: a permission rule names a folder of this machine`);
    }
    const title = String(redact(item.title));
    const text = String(redact(item.text));
    if ([...title].length > TITLE_MAX || [...text].length > TEXT_MAX) {
      throw new UsageError(`${where}: the text is longer than its limit once the folders of this machine are redacted`);
    }
    return { rule: item.rule, title, text, settings };
  });
}

/**
 * Builds the remediation of one scan. The result is plain data: the rules, the outcomes, the fixed codes of the reasons, and the
 * agent's texts, which are redacted. It is the content of remediation.json (schemas/remediation.schema.json).
 * @param {object} options
 * @param {object} options.measurements The parsed measurements.json of the scan. It is not changed.
 * @param {ReturnType<typeof checkAgentFragments>} [options.agentFragments] The checked agent fragments, in their order.
 * @param {object[]} [options.destructiveCommands] The entries of data/destructive-commands.json, with coverRule. Defaults to the
 *   data file. A test may give its own list, for example with criticalPath true for a command.
 * @returns {object} The remediation: schemaVersion, scan, mode, fragments, commands, reads, notSimulated, omitted and summary.
 */
export function buildRemediation({ measurements, agentFragments = [], destructiveCommands = loadDestructiveCommands() }) {
  const { security } = measurements;
  const before = { allow: security.permissions.allow, ask: security.permissions.ask, deny: security.permissions.deny };
  const coverage = security.destructiveCoverage;
  const mode = coverage.mode === null ? null : coverage.mode.value;
  const measured = coverage.commands;
  const subagentPasses = new Set(
    (coverage.subagents ?? []).flatMap((agent) => (agent.results ?? []).filter((item) => item.outcome === "passes").map((item) => item.id)),
  );
  const data = new Map(destructiveCommands.map((command) => [command.id, command]));
  const passing = new Set(measured.filter((command) => passesToday(command, subagentPasses)).map((command) => command.id));
  const context = {
    data,
    mode,
    passing,
    findingIds: new Map(measurements.measuredFindings.map((item) => [item.rule, item.id])),
    comparable: new Map(measured.map((command) => [command.id, comparesWith(command, simulate(before, command, mode))])),
  };
  const reads = readTargets(security.secrets, before);

  const built = [];
  const covered = new Set();
  for (const entry of before.allow) {
    if (!BARE_SHELL_RULES.has(entry.rule) && !WILDCARD_SHELL_RULE.test(entry.rule)) continue;
    const ids = measured
      .filter((command) => !covered.has(command.id) && data.has(command.id) && passesThroughAllow(command, entry.rule))
      .map((command) => command.id);
    if (ids.length === 0) continue;
    for (const id of ids) covered.add(id);
    built.push(commandFragment("SEC-01", ids, context));
  }
  for (const command of measured) {
    if (covered.has(command.id) || !data.has(command.id) || !passesToday(command, subagentPasses)) continue;
    built.push(commandFragment("SEC-02", [command.id], context));
  }
  for (const target of reads) {
    const fragment = readFragment(target, context);
    if (fragment !== null) built.push(fragment);
  }
  for (const item of agentFragments) built.push(agentFragment(item));

  // The fragments the file keeps are the first ones; only they are applied, so the rows show the patch that the file lists.
  const fragments = capped(built);
  const applied = fragments.kept.filter((fragment) => fragment.simulated);
  const after = {
    allow: before.allow,
    ask: [...before.ask, ...applied.flatMap((fragment) => fragment.settings?.permissions.ask ?? [])],
    deny: [...before.deny, ...applied.flatMap((fragment) => fragment.settings?.permissions.deny ?? [])],
  };
  const commandRows = capped(measured.map((command) => commandRow(command, after, context)));
  const readRows = capped(reads.map((target) => readRow(target, after)));
  const literals = capped((security.secrets.literals ?? []).map((literal) => ({
    rule: "SEC-03",
    kind: "literal-secret",
    file: literal.file,
    line: literal.line,
    location: literal.location,
    secretKind: literal.kind,
    reason: "literal-secret",
  })));
  const numbered = fragments.kept.map((fragment, index) => ({ id: `fr-${index + 1}`, ...fragment }));

  return {
    schemaVersion: SCHEMA_VERSION,
    scan: { scannedAt: measurements.meta.scannedAt, target: measurements.target.name },
    mode,
    fragments: numbered,
    commands: commandRows.kept,
    reads: readRows.kept,
    notSimulated: literals.kept,
    omitted: {
      cap: LIST_CAP,
      fragments: fragments.omitted,
      commands: commandRows.omitted,
      reads: readRows.omitted,
      notSimulated: literals.omitted,
    },
    summary: summaryOf(numbered, commandRows.kept, readRows.kept, literals.kept, passing),
  };
}

/**
 * The redactor of the texts of one scan: the folders of this machine become <target> and ~, as for every text of the report.
 * @param {object} measurements The parsed measurements.json.
 * @returns {(value: unknown) => unknown}
 */
export function redactorFor(measurements) {
  return createRedactor({ root: measurements.meta.targetRoot });
}

/**
 * True when a text holds a secret-shaped value: a token of a specific pattern, or a generic assignment. The agent's texts must
 * pass it, and render-report applies it to every string of remediation.json.
 * @param {unknown} text
 * @returns {boolean}
 */
export function holdsSecretShape(text) {
  return findSpecificSecrets(text).length > 0 || findGenericSecrets(text).length > 0;
}

/**
 * True when some string of a parsed JSON value holds a secret-shaped value (see holdsSecretShape). The keys are not checked: the
 * schema fixes them before this is called.
 * @param {unknown} value
 * @returns {boolean}
 */
export function anyStringHoldsSecretShape(value) {
  if (typeof value === "string") return holdsSecretShape(value);
  if (Array.isArray(value)) return value.some(anyStringHoldsSecretShape);
  if (value !== null && typeof value === "object") return Object.values(value).some(anyStringHoldsSecretShape);
  return false;
}

/**
 * Whether a command passes before the patch, and what it does after it. A result is one of: unchanged (it did not pass before);
 * still-passes (a mode passes it after the patch); undeterminable (no mode passes it, and one of them cannot be settled);
 * classifier (no mode passes it, and auto mode would leave the decision to a model, which is not a move); moved (no mode passes it).
 * @param {boolean} passedBefore
 * @param {{ outcome: string, modes: Record<string, string> }} next The simulated outcome after the patch.
 * @returns {string}
 */
export function commandResult(passedBefore, next) {
  if (!passedBefore) return "unchanged";
  if (passesIn(next.outcome, next.modes)) return "still-passes";
  const outcomes = [next.outcome, ...Object.values(next.modes)];
  if (outcomes.includes("undeterminable")) return "undeterminable";
  if (outcomes.includes("classifier")) return "classifier";
  return "moved";
}

// ---------------------------------------------------------------------------------------------------
// Measured fragments

// The fragment of one finding for some destructive commands. Its settings hold the coverRule of each command: in deny when the
// command is critical in the data, and in ask otherwise. It is simulated when every command is simulated. No command of the data
// is critical today (criticalPath is false in every entry), so the deny branch is tested with data that marks one as critical.
function commandFragment(rule, ids, context) {
  const entries = ids.map((id) => context.data.get(id));
  const settings = settingsOf(
    unique(entries.filter((entry) => entry.criticalPath).map((entry) => entry.coverRule)),
    unique(entries.filter((entry) => !entry.criticalPath).map((entry) => entry.coverRule)),
  );
  const reason = ids.map((id) => context.comparable.get(id)).find((value) => value !== true) ?? null;
  return {
    origin: "measured",
    rule,
    measuredFindingId: context.findingIds.get(rule) ?? null,
    kind: "permissions",
    settings,
    title: null,
    text: null,
    coverNote: notesOf(entries),
    targets: ids.map((id) => ({ kind: "command", id })),
    simulated: reason === null,
    reason,
  };
}

// The coverNote texts of some entries, once each, in their order. Null when no entry has one.
function notesOf(entries) {
  const notes = unique(entries.map((entry) => entry.coverNote).filter((note) => typeof note === "string"));
  return notes.length === 0 ? null : notes.join(" ");
}

// The fragment of one secret read: a deny of Read(./<path>). Null when the project already denies the read.
function readFragment(target, context) {
  if (target.decision === DENY) return null;
  const base = {
    origin: "measured",
    rule: "SEC-03",
    measuredFindingId: context.findingIds.get("SEC-03") ?? null,
    kind: "permissions",
    title: null,
    text: null,
    coverNote: null,
    targets: [{ kind: "read", path: target.path }],
  };
  if (!safePath(target.path)) return { ...base, settings: null, simulated: false, reason: "unsupported-path" };
  const reason = target.comparable ? null : "simulation-mismatch";
  return { ...base, settings: settingsOf([`Read(./${target.path})`], []), simulated: reason === null, reason };
}

// A fragment that the agent proposed. Its settings are simulated when it has rules and every rule is one the simulation decides.
function agentFragment(item) {
  const base = {
    origin: "agent",
    rule: item.rule,
    measuredFindingId: null,
    title: item.title,
    text: item.text,
    coverNote: null,
    targets: [],
  };
  if (item.settings === null) return { ...base, kind: "other", settings: null, simulated: false, reason: "not-permission" };
  const { deny, ask } = item.settings.permissions;
  const rules = [...deny, ...ask];
  const reason = rules.length === 0 ? "no-rule" : (rules.map(unmodelledReason).find((code) => code !== null) ?? null);
  return { ...base, kind: "permissions", settings: item.settings, simulated: reason === null, reason };
}

// ---------------------------------------------------------------------------------------------------
// The simulation

// The outcome of one command under some rules, for the measured mode and for each mode of the matrix. The flags are the
// command's own (insideProject, criticalPath), as the measure gives them.
function simulate(rules, command, mode) {
  const call =
    command.parts === undefined
      ? { tool: command.tool, command: command.command }
      : { tool: command.tool, command: command.command, parts: command.parts };
  const flags = { insideProject: command.insideProject, criticalPath: command.criticalPath };
  return {
    outcome: evaluate(rules, call, { mode, ...flags }).outcome,
    modes: Object.fromEntries(
      MATRIX_MODES.map((name) => [name, evaluateInSessionMode(rules, call, { mode: name, ...flags }).outcome]),
    ),
  };
}

// True when the simulated value of a command is the measured one. Otherwise, the reason: no matrix in the scan, or a difference.
function comparesWith(command, simulated) {
  if (command.modes === undefined) return "no-matrix";
  const same =
    simulated.outcome === command.outcome && MATRIX_MODES.every((name) => simulated.modes[name] === command.modes[name]);
  return same ? true : "simulation-mismatch";
}

// The row of one command: its measured value, and its value after the patch. A command that is not simulated has no after. The
// notVerified list names the modes whose values are not verified (none when the scan has no matrix for the command).
function commandRow(command, after, context) {
  const hasMatrix = command.modes !== undefined && command.modes !== null;
  const base = {
    id: command.id,
    command: command.command,
    measured: { outcome: command.outcome, modes: command.modes ?? null },
    notVerified: hasMatrix ? [...UNVERIFIED_MODES] : [],
  };
  if (!context.data.has(command.id)) return { ...base, after: null, result: "not-simulated", reason: "not-in-data" };
  const comparable = context.comparable.get(command.id);
  if (comparable !== true) return { ...base, after: null, result: "not-simulated", reason: comparable };
  const next = simulate(after, command, context.mode);
  return { ...base, after: next, result: commandResult(context.passing.has(command.id), next), reason: null };
}

// The secret reads to simulate: each secret file of the scan, then the .env at the root when the scan decides it and no secret
// file has that path. Each read has its path, its measured decision, and whether the simulated before is that decision.
function readTargets(secrets, before) {
  const reads = (secrets.files ?? []).map((file) => readOf(file.path, file.readDecision, before));
  const env = secrets.readProtection?.envAtRoot;
  if (env !== undefined && env !== null && !reads.some((read) => read.path === ".env")) {
    reads.push(readOf(".env", env, before));
  }
  return reads;
}

function readOf(path, verdict, before) {
  const simulated = decide(before, { tool: "Read", path }).decision;
  return { path, decision: verdict.decision, comparable: simulated === verdict.decision };
}

// The row of one secret read: its measured decision, and the decision after the patch.
function readRow(target, after) {
  const base = { path: target.path, measured: target.decision };
  if (!safePath(target.path)) return { ...base, after: null, result: "not-simulated", reason: "unsupported-path" };
  if (!target.comparable) return { ...base, after: null, result: "not-simulated", reason: "simulation-mismatch" };
  const next = decide(after, { tool: "Read", path: target.path }).decision;
  return { ...base, after: next, result: readResult(target.decision, next), reason: null };
}

function readResult(measured, next) {
  if (measured === DENY) return "unchanged";
  if (next === DENY) return "moved";
  if (next === "undeterminable") return "undeterminable";
  return "still-readable";
}

// ---------------------------------------------------------------------------------------------------
// Helpers

// A broad allow lets a command through when the command's decision names that rule. A compound command names the rule of each
// part joined with " && ". A decision by a user rule is not an entry of the project's allow list, so it is not counted.
function passesThroughAllow(command, rule) {
  if (command.outcome !== "passes") return false;
  const decided = command.decidedBy;
  if (decided?.kind !== "rule" || decided.list !== "allow" || decided.layer === "user") return false;
  return String(decided.rule).split(" && ").includes(rule);
}

function passesToday(command, subagentPasses) {
  return passesIn(command.outcome, command.modes) || subagentPasses.has(command.id);
}

function passesIn(outcome, modes) {
  return outcome === "passes" || Object.values(modes ?? {}).includes("passes");
}

function settingsOf(deny, ask) {
  return { permissions: { deny, ask } };
}

// A path that a Read rule can state: see SAFE_PATH, and no absolute, home or empty, dot or dot-dot segment.
// The characters of a path that a Read rule can state without the rule syntax reading them as a pattern or as a part of the
// specifier: letters, digits, and . _ / @ + = , % and space. A path with any other character gets no rule.
const SAFE_PATH = /^[A-Za-z0-9._/@+=,% -]+$/;

function safePath(path) {
  if (typeof path !== "string" || !SAFE_PATH.test(path) || path.startsWith("/") || path.startsWith("~")) return false;
  return path.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

// Why a rule of an agent's fragment is not simulated, as a fixed code, or null when the simulation decides it for every call. Only
// Bash, PowerShell and Read rules are modelled. A Read rule is undecidable when permissions.mjs gives "unknown" for every path:
// a home path (~/), a negation (!), a bracket or a backslash, an absolute path other than //** and //**/<tail>, or an empty, "."
// or ".." segment. A parameter rule (run_in_background:) is undecidable too. An unknown in a deny or ask list makes every later
// decision undeterminable, so a fragment with such a rule is not applied.
function unmodelledReason(text) {
  const rule = parseRule(text);
  if (!rule.ok || rule.skipped === true) return "not-modelled-rule";
  if (rule.kind === "parameter") return "undecidable-rule";
  if (rule.kind === "bash" || rule.kind === "powershell") return null;
  if (rule.kind === "path" && rule.tool === "Read") return decidableReadSpecifier(rule.specifier) ? null : "undecidable-rule";
  return "not-modelled-rule";
}

// Whether permissions.mjs decides a Read specifier for some path (see pathRuleState and covered). A specifier that stays unknown
// for every path is not decidable.
function decidableReadSpecifier(specifier) {
  if (specifier === null) return true;
  if (specifier.startsWith("!") || specifier.startsWith("~/") || specifier.includes("[") || specifier.includes("\\")) return false;
  if (specifier.startsWith("//")) {
    const rest = specifier.slice(2);
    if (rest === "**") return true;
    return rest.startsWith("**/") && namesOnly(rest);
  }
  if (specifier.startsWith("/")) return namesOnly(specifier.slice(1));
  if (specifier.startsWith("./")) return namesOnly(specifier.slice(2));
  return namesOnly(specifier);
}

// A pattern whose segments are all names: an empty, "." or ".." segment makes permissions.mjs give "unknown". A trailing slash is
// not a segment. A loop, not a regular expression, as in permissions.mjs.
function namesOnly(body) {
  let end = body.length;
  while (end > 0 && body[end - 1] === "/") end -= 1;
  return body
    .slice(0, end)
    .split("/")
    .every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

// The first LIST_CAP items of a list, and how many were left out.
function capped(list) {
  const kept = list.slice(0, LIST_CAP);
  return { kept, omitted: list.length - kept.length };
}

function unique(values) {
  return [...new Set(values)];
}

function summaryOf(fragments, commandRows, readRows, notSimulated, passing) {
  const count = (list, predicate) => list.filter(predicate).length;
  return {
    fragments: fragments.length,
    measuredFragments: count(fragments, (fragment) => fragment.origin === "measured"),
    agentFragments: count(fragments, (fragment) => fragment.origin === "agent"),
    simulatedFragments: count(fragments, (fragment) => fragment.simulated),
    notSimulatedFragments: count(fragments, (fragment) => !fragment.simulated),
    commandsPassingToday: count(commandRows, (row) => passing.has(row.id)),
    commandsMoved: count(commandRows, (row) => row.result === "moved"),
    commandsStillPassing: count(commandRows, (row) => row.result === "still-passes"),
    commandsNotSimulated: count(commandRows, (row) => row.result === "not-simulated"),
    readsMoved: count(readRows, (row) => row.result === "moved"),
    readsNotSimulated: count(readRows, (row) => row.result === "not-simulated"),
    notSimulatedItems: notSimulated.length,
  };
}
