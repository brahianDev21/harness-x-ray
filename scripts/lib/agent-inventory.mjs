// Measure "agent-harness": the files that each coding agent reads, as the registry data/agent-harness.json says. The format and
// the load models are documented in lib/agent-harness.mjs. The target is read only through ctx.fs. Nothing from it is run,
// imported or parsed as code.
//
// Candidates. A file of the target is a candidate when a registry entry matches its path. The paths come from ctx.files and
// from a walk of the root-level names that the registry globs begin with (rootNamesOf), so an untracked file at the root is
// seen, as memory.mjs and claude-config.mjs see it. The walk goes at most MAX_WALK_DEPTH folders down, skips .git and
// node_modules, and never enters a symbolic link to a folder. Ownership: for each agent, a file belongs to the first entry of
// that agent, in file order, whose glob matches it. A file that no entry owns is not listed. A link is followed to its real
// location by ctx.fs.resolve, the same check that readText and stat make: a link that leaves the target is listed as
// outside-root and is never read, whatever it points to.
//
// Pairs. The inventory has one item per (file, agent) pair, so AGENTS.md has one for each agent that owns it. statusOf gives
// the status of a pair: what this scan can tell. Only the target is looked at. The files of the parent folders are not
// blockers and are not listed (V02-05).
//
// Scope (--scope, see scope.mjs). Without a scope nothing here changes. With one, a nested candidate (see isNested) whose path
// ctx.scope.keepsHarness rejects is dropped first: it is not listed, not in ctx.agentOwners and not a blocker. A kept nested file
// is read like a root file (see Reading). Re-rooting: for a kept path whose harness folder H (harnessFolderOf) is not the root,
// the registry is matched against the path relative to H, for each agent that does not own the path through the full-path match.
// The first entry of that agent, in file order, whose glob matches the relative path owns the pair. Such a pair has base H,
// is nested, and has status unknown, because the load models of the registry describe the root only. It is never a blocker and
// it is never blocked. The paths come from ctx.files and from a walk of the root names under each inherited folder other than
// the root and under each scope folder. NOT VERIFIED by a note: that an agent reads a file below a subfolder through the
// root-level glob of its registry entry, which re-rooting assumes.
//
// Listing. At most maxFiles files (MAX_FILES by default) are listed, in path order. The files beyond are left out of files and
// items, and one warning agent-files-cut counts them. The statuses are worked out from every candidate, so a blocker that is
// not listed still blocks: the cap changes what is shown, not what the shown pairs say.
//
// Reading. A listed file is read with ctx.fs.readText and the default file cap, in path order, while the bytes read in total stay
// within maxTotalBytes (MAX_TOTAL_BYTES by default, as duplication.mjs caps its reads). The size from the stat is checked before
// each read, and a file over the per-file cap is not charged, because readText refuses it without reading it. The read is not
// memoized, so the texts are not kept for the rest of the scan, except the texts that ctx.agentInstructions keeps (see below). A
// file is not read when its name or its link target is a secret name (secret-name), when its link leaves the target or cannot be
// resolved, when its claude-code pair matches claudeMdExcludes and no other agent owns it (claude-md-excludes: memory.mjs never
// reads an excluded file), when it is nested and no scope keeps it (nested), or when the total byte cap would be passed
// (bytes-cap). Without a scope a nested file is listed with its size and never read. With a scope, a kept nested file is read
// like a root file. Only the line count and, for a file of a context kind, the estimate are kept, and the text
// of an instruction file that ctx.agentInstructions keeps.
//
// Output. The section agentHarness. Two warnings can come from this measure: agent-files-cut counts the listed files left out
// by the file cap, and agent-bytes-cut counts the files not read for the byte cap. The failed reads also write the usual fs
// warnings. The shared budget (context.alwaysLoaded) is not changed here. Claude Code's budget is that shared one. The other
// agents are listed in agentHarness.unknownStatic, which is not part of the shared budget.
//
// Texts for the other measures. The text of a file that this measure reads, that has at least one pair of kind instructions
// and whose path is not in ctx.memory, is kept in ctx.agentInstructions: path -> { text, agents }, where agents are the sorted
// ids of the agents whose pair for the file is of kind instructions. A file already in ctx.memory is not kept twice. A nested
// file is never read, so it is never kept. ctx.agentOwners (path -> sorted agent ids of all pairs) is set for every candidate,
// before any read. The scanner core creates both channels empty; this measure is the only writer. The texts are not output:
// the measures that read them (references, verification) redact what they write.

import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadAgentHarness, matchHarnessGlob, validateAgentHarness } from "./agent-harness.mjs";
import { loadClaudeConfig, MAX_WALK_DEPTH } from "./claude-config.mjs";
import { MAX_FILES, MAX_TOTAL_BYTES } from "./duplication.mjs";
import { claudeMdExclusionOf, countsOf, EXCLUDED_REASON } from "./memory.mjs";
import { DEFAULT_MAX_BYTES } from "./safe-fs.mjs";
import { harnessFolderOf } from "./scope.mjs";
import { secretFileKind } from "./secret-patterns.mjs";

/** The id of the measure. Its section is agentHarness. */
export const MEASURE_ID = "agent-harness";

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const REGISTRY_PATH = "data/agent-harness.json";
const CLAUDE_CODE = "claude-code";
const UNVERIFIED_MODEL = "unknown";
const ALWAYS_MODEL = "always";
const FOLDER_MODEL = "folder";
const CONTEXT_KINDS = new Set(["instructions", "skills", "commands", "subagents"]);
const INSTRUCTIONS_KIND = "instructions";
// Folders that are never walked, at any depth.
const SKIPPED_NAMES = new Set([".git", "node_modules"]);
// Claude Code entries whose load model the registry does not verify, but which the budget that exists today counts: commands
// and subagents (claude-config.mjs), and the CLAUDE.md and AGENTS.md files of .claude/ (memory.mjs). They keep that treatment,
// marked as-before, so that CTX-01 does not change without evidence.
const COUNTED_AS_BEFORE = new Set([
  "claude-code-commands",
  "claude-code-subagents",
  "claude-code-dot-claude-claude-md",
  "claude-code-dot-claude-agents-md",
]);
const STATUS = Object.freeze({ loads: "loads", notLoaded: "not-loaded", excluded: "excluded", unknown: "unknown" });
const CONTEXT_BUDGET = "/context/alwaysLoaded";
const STATIC_BUDGET = "unknownStatic";
const AS_BEFORE = "as-before";
const NESTED_REASON = "nested";
const SECRET_REASON = "secret-name";
const BYTES_REASON = "bytes-cap";
const CUT_REASON = "agent-files-cut";
const BYTES_CUT_REASON = "agent-bytes-cut";

/**
 * Builds the agent-harness measure.
 * @param {object} [options]
 * @param {object} [options.registry] A registry as loadAgentHarness returns it. It is validated, and a TypeError is thrown when it
 *   is not valid. Default: the registry of this repository, which must be valid.
 * @param {number} [options.maxFiles] Files listed per scan, in path order. Default MAX_FILES.
 * @param {number} [options.maxTotalBytes] Bytes read per scan, in total. Default MAX_TOTAL_BYTES.
 * @returns {{ id: string, collect: (ctx: object) => object }}
 */
export function createAgentInventoryMeasure({ registry, maxFiles = MAX_FILES, maxTotalBytes = MAX_TOTAL_BYTES } = {}) {
  if (!Number.isSafeInteger(maxFiles) || maxFiles < 0) throw new TypeError("maxFiles must be a non-negative safe integer");
  if (!Number.isSafeInteger(maxTotalBytes) || maxTotalBytes < 0) {
    throw new TypeError("maxTotalBytes must be a non-negative safe integer");
  }
  let checked = registry;
  if (registry === undefined) {
    checked = loadAgentHarness(HARNESS_ROOT);
  } else {
    const [first] = validateAgentHarness(registry, { sourceTypes: null });
    if (first !== undefined) throw new TypeError(`the registry is not valid: ${first.pointer} ${first.message}`);
  }
  const model = modelOf(checked);
  return Object.freeze({
    id: MEASURE_ID,
    collect: (ctx) => collectAgentHarness(ctx, model, { maxFiles, maxTotalBytes }),
  });
}

function modelOf(registry) {
  return {
    agents: registry.agents,
    entries: registry.files,
    entriesById: new Map(registry.files.map((entry) => [entry.id, entry])),
    // The agents with at least one entry whose load model is verified. Today this is Claude Code only.
    verified: new Set(registry.files.filter((entry) => entry.loadModel !== UNVERIFIED_MODEL).map((entry) => entry.agent)),
  };
}

function collectAgentHarness(ctx, model, { maxFiles, maxTotalBytes }) {
  const candidates = findCandidates(ctx, model.entries);
  const excludes = loadClaudeConfig(ctx).claudeMdExcludes;
  for (const file of candidates) {
    file.claudeExclusion = agentsOfFile(file).includes(CLAUDE_CODE) ? claudeMdExclusionOf(excludes, file.path) : null;
  }
  // The statuses come from every candidate, so the cap below changes only what is listed.
  const env = { model, byPath: new Map(candidates.map((file) => [file.path, file])) };
  const pairs = buildPairs(candidates, env);
  for (const file of candidates) ctx.agentOwners.set(file.path, agentsOfFile(file));
  const listed = candidates.slice(0, maxFiles);
  const cut = candidates.length - listed.length;
  const listedPaths = new Set(listed.map((file) => file.path));
  const shownPairs = pairs.filter((pair) => listedPaths.has(pair.file.path));
  const instructionAgents = instructionAgentsOf(shownPairs);
  // Only a file with an instructions pair that the memory measure did not read is kept: ctx.memory already holds the others.
  const keepText = (rel) => instructionAgents.has(rel) && !ctx.memory.has(rel);
  const { outcomes, bytesCut } = readFiles(ctx, listed, maxTotalBytes, keepText);
  for (const file of listed) {
    const text = outcomes.get(file.path).text;
    if (text !== undefined) ctx.agentInstructions.set(file.path, { text, agents: instructionAgents.get(file.path) });
  }
  const pairsOf = groupByPath(shownPairs);
  const files = listed.map((file) => fileRecord(file, pairsOf.get(file.path), outcomes.get(file.path), model));
  const agents = agentsOf(model, shownPairs);
  const staticAgents = new Set(agents.filter((agent) => agent.budget === STATIC_BUDGET).map((agent) => agent.id));
  const warnings = [];
  if (cut > 0) warnings.push({ path: ".", reason: CUT_REASON, detail: `count=${cut}` });
  if (bytesCut > 0) warnings.push({ path: ".", reason: BYTES_CUT_REASON, detail: `count=${bytesCut}` });
  return {
    agentHarness: {
      registry: REGISTRY_PATH,
      agents,
      items: shownPairs.map(itemOf),
      files,
      unknownStatic: unknownStaticOf(shownPairs, outcomes, staticAgents),
    },
    warnings,
  };
}

// ---------------------------------------------------------------------------------------------------
// Candidates

// The files that some entry owns, sorted by path. Each has its owners (agent id to entry), the owners found by re-rooting
// (rerooted, see rerootedOf), and what is known before any read (see describe). A path that no entry owns is left out.
function findCandidates(ctx, entries) {
  const scope = scopeOf(ctx);
  const names = rootNamesOf(entries);
  const seen = new Set();
  const owned = new Map();
  const consider = (rel) => {
    if (seen.has(rel)) return;
    seen.add(rel);
    const ownership = ownershipOf(entries, rel, scope, names);
    if (ownership !== null) owned.set(rel, ownership);
  };
  for (const file of ctx.files) consider(file.path);
  walkRootNames(ctx, names, consider);
  // With a scope, the folders between the root and the scope, and the scope folders, are walked too, so that their harness
  // is seen.
  if (scope !== null) {
    for (const folder of [...scope.inherited, ...scope.folders]) {
      if (folder !== ".") walkRootNames(ctx, names, consider, folder);
    }
  }
  const found = [];
  for (const rel of [...owned.keys()].sort(compareText)) {
    const candidate = describe(ctx, rel, owned.get(rel));
    if (candidate !== null) found.push(candidate);
  }
  return found;
}

// The scope of the run (scope.mjs), or null when the whole target is scanned.
function scopeOf(ctx) {
  return ctx.scope ?? null;
}

// The owners of one path: the full-path owners (ownersOf) and, with a scope, the re-rooted owners (rerootedOf). Null when the
// path has no owner, or when the scope drops it. Without a scope the result is the one the scan has always had.
function ownershipOf(entries, rel, scope, names) {
  const owners = ownersOf(entries, rel);
  if (scope === null) return owners.size > 0 ? { owners, rerooted: null } : null;
  // A nested file outside the scope is dropped first: it is not listed, not in ctx.agentOwners and not a blocker.
  if (isNested(rel, owners) && !scope.keepsHarness(rel)) return null;
  const rerooted = rerootedOf(entries, rel, owners, scope, names);
  return owners.size > 0 || rerooted !== null ? { owners, rerooted } : null;
}

// The owners that a path gets below its harness folder H (harnessFolderOf), with a scope only. The path is matched against the
// registry relative to H, for each agent that does not own the path through the full-path match (owners): the first entry of
// that agent, in file order, whose glob matches the relative path owns it. Only a path whose H is not the root, that the scope
// keeps, and whose first segment below H is a registry root name is matched. Returns { base: H, owners } or null.
function rerootedOf(entries, rel, owners, scope, names) {
  const base = harnessFolderOf(rel);
  if (base === "." || !scope.keepsHarness(rel)) return null;
  const relative = rel.slice(base.length + 1);
  if (!names.has(relative.split("/")[0])) return null;
  const found = ownersOf(entries, relative, new Set(owners.keys()));
  return found.size > 0 ? { base, owners: found } : null;
}

// The ids of the agents that own a candidate, sorted: the full-path owners and the re-rooted ones.
function agentsOfFile(file) {
  const rerooted = file.rerooted === null ? [] : [...file.rerooted.owners.keys()];
  return [...file.owners.keys(), ...rerooted].sort(compareText);
}

// The registry entries that own a candidate: the full-path ones and the re-rooted ones.
function entriesOf(file) {
  const rerooted = file.rerooted === null ? [] : [...file.rerooted.owners.values()];
  return [...file.owners.values(), ...rerooted];
}

// What is known about one owned path before any read: its size, the real location that its links lead to, and the reason it
// cannot be read, when there is one. Null for a path that is not a file: a folder, or a link that does not resolve. A link that
// leaves the target keeps the outside-root reason and no size. A path with re-rooted owners is nested. scoped tells that a scope
// is given, which is what lets a kept nested file be read (see unreadableReasonOf).
function describe(ctx, rel, ownership) {
  const known = {
    path: rel,
    owners: ownership.owners,
    rerooted: ownership.rerooted,
    nested: isNested(rel, ownership.owners) || ownership.rerooted !== null,
    scoped: scopeOf(ctx) !== null,
    claudeExclusion: null,
  };
  const probe = ctx.fs.stat(rel);
  if (!probe.ok) {
    if (probe.reason !== "outside-root") return null;
    return { ...known, bytes: null, target: null, reason: "outside-root" };
  }
  if (probe.type !== "file") return null;
  const resolved = ctx.fs.resolve(rel);
  if (!resolved.ok) return { ...known, bytes: probe.bytes, target: null, reason: resolved.reason };
  return { ...known, bytes: probe.bytes, target: resolved.target, reason: null };
}

// The agent id to the first entry of that agent, in file order, whose glob matches rel. The agents in taken are left out.
function ownersOf(entries, rel, taken = new Set()) {
  const owners = new Map();
  for (const entry of entries) {
    if (!owners.has(entry.agent) && !taken.has(entry.agent) && matchHarnessGlob(entry.glob, rel)) owners.set(entry.agent, entry);
  }
  return owners;
}

// The names at the root that the walk starts from: the first segment of a glob with no "*" in it, and, for a glob of the form
// "**/NAME" with a literal NAME, that NAME. Both are walked at the root, so a root file that such a glob names is found even when
// it is untracked. A glob whose first segment has a "*" and that is not "**/NAME" is not walked on disk: the files it names are
// found only through ctx.files, so an untracked file reached only through such a glob is not found. Today only the nested-skills
// glob has that form ("*" first, then "**", ".claude/skills/*", "SKILL.md").
function rootNamesOf(entries) {
  const names = new Set();
  for (const entry of entries) {
    const segments = entry.glob.split("/");
    if (!segments[0].includes("*")) {
      names.add(segments[0]);
    } else if (segments[0] === "**" && segments.length === 2 && literalNameOf(segments[1]) !== null) {
      names.add(segments[1]);
    }
  }
  return names;
}

// Passes every path under the given names at the base folder (the root by default) to consider.
function walkRootNames(ctx, names, consider, base = ".") {
  const top = ctx.fs.listDir(base);
  if (!top.ok) return;
  for (const entry of top.entries) {
    if (!names.has(entry.name)) continue;
    const rel = base === "." ? entry.name : `${base}/${entry.name}`;
    if (entry.type === "dir") walkFolder(ctx, rel, 0, consider);
    else if (isFileEntry(ctx, rel, entry.type)) consider(rel);
  }
}

// The same walk as claude-config.mjs (findFiles): a folder is entered while the depth is below MAX_WALK_DEPTH. A symbolic link to
// a folder inside the target is not entered, because it is not a file.
function walkFolder(ctx, dir, depth, consider) {
  const listing = ctx.fs.listDir(dir);
  if (!listing.ok) return;
  for (const entry of listing.entries) {
    if (SKIPPED_NAMES.has(entry.name)) continue;
    const rel = `${dir}/${entry.name}`;
    if (entry.type === "dir") {
      if (depth < MAX_WALK_DEPTH) walkFolder(ctx, rel, depth + 1, consider);
    } else if (isFileEntry(ctx, rel, entry.type)) {
      consider(rel);
    }
  }
}

// A regular file, or a link to one. A link that leaves the target is kept, so that describe lists it as outside-root. A dangling
// link is not kept.
function isFileEntry(ctx, rel, type) {
  if (type === "file") return true;
  if (type !== "symlink") return false;
  const probe = ctx.fs.stat(rel);
  return probe.ok ? probe.type === "file" : probe.reason === "outside-root";
}

// A file is nested when it is in a subfolder and no owner has a literal first segment: then the registry does not fix its folder.
// The files that a glob such as ".agents/**" names are not nested, because that glob fixes the folder.
function isNested(rel, owners) {
  if (!rel.includes("/")) return false;
  return [...owners.values()].every((entry) => entry.glob.split("/")[0].includes("*"));
}

// The last segment of a glob when it is a literal name, or null when it has a "*".
function literalNameOf(segment) {
  const last = segment.slice(segment.lastIndexOf("/") + 1);
  return last.includes("*") ? null : last;
}

// ---------------------------------------------------------------------------------------------------
// Pairs and their status

// One pair per (file, agent), sorted by path and then by agent. Each carries its status and the fields that go with it.
function buildPairs(candidates, env) {
  const pairs = [];
  for (const file of candidates) {
    for (const [agent, entry] of file.owners) {
      pairs.push({ file, agent, entry, ...excludedFieldOf(agent, file), ...statusOf(file, agent, entry, env) });
    }
    // A re-rooted pair (see rerootedOf) has its base and always the status unknown: the registry's load models describe
    // the root.
    if (file.rerooted !== null) {
      for (const [agent, entry] of file.rerooted.owners) {
        pairs.push({
          file,
          agent,
          entry,
          base: file.rerooted.base,
          ...excludedFieldOf(agent, file),
          status: STATUS.unknown,
        });
      }
    }
  }
  return pairs.sort((a, b) => compareText(a.file.path, b.file.path) || compareText(a.agent, b.agent));
}

// What this scan can tell about one pair. The checks run in this order:
// - the load model is not verified: unknown;
// - Claude Code and claudeMdExcludes match the file: excluded (its excludedBy is set on every such pair, see excludedFieldOf);
// - a nested file whose model is neither always nor folder: unknown. The registry claims nothing for a file below the working
//   folder under ancestors. Under folder the registry says it loads once the agent works in its folder, so it keeps the claim;
// - an entry without unless: loads;
// - unless, with a verified blocker: not-loaded; with only an unverified blocker: unknown; with none: loads.
// Ancestors of the target are not considered (see the header).
function statusOf(file, agent, entry, env) {
  if (entry.loadModel === UNVERIFIED_MODEL) return { status: STATUS.unknown };
  if (exclusionFor(agent, file) !== null) return { status: STATUS.excluded };
  if (file.nested && entry.loadModel !== ALWAYS_MODEL && entry.loadModel !== FOLDER_MODEL) return { status: STATUS.unknown };
  if (entry.unless === undefined) return { status: STATUS.loads };
  const blockers = blockersOf(file, agent, entry, env);
  if (blockers.verified.length > 0) return { status: STATUS.notLoaded, blockedBy: blockers.verified };
  if (blockers.unverified.length > 0) return { status: STATUS.unknown, blockedBy: blockers.unverified };
  return { status: STATUS.loads };
}

// The files that block an entry with unless, looked for among the candidates of the same agent, in the file's folder or a
// folder above it inside the target. A verified blocker is owned by one of the unless entries and is not excluded: it stops
// the file from loading. An unverified blocker is either an unless file that claudeMdExcludes excludes, or a file that an entry
// with an unverified model owns (same agent and kind) under the name of an unless entry, in those folders or directly in
// a .claude/ folder of one of them. That is how .claude/CLAUDE.md counts, which the registry does not list in unless.
function blockersOf(file, agent, entry, env) {
  const unlessIds = new Set(entry.unless);
  const unlessEntries = entry.unless.map((id) => env.model.entriesById.get(id));
  const folders = foldersAbove(path.posix.dirname(file.path));
  const claudeFolders = folders.map(claudeFolderOf);
  const verified = [];
  const unverified = [];
  for (const other of env.byPath.values()) {
    if (other.path === file.path) continue;
    const owner = other.owners.get(agent);
    if (owner === undefined) continue;
    const folder = path.posix.dirname(other.path);
    if (unlessIds.has(owner.id)) {
      if (!folders.includes(folder)) continue;
      if (exclusionFor(agent, other) === null) verified.push(other.path);
      else unverified.push(other.path);
    } else if (isUnverifiedTwin(owner, unlessEntries, other.path) && (folders.includes(folder) || claudeFolders.includes(folder))) {
      unverified.push(other.path);
    }
  }
  return { verified: verified.sort(compareText), unverified: unverified.sort(compareText) };
}

// Whether an entry with an unverified model stands for an unless entry: the same kind, and the file name of an unless glob.
function isUnverifiedTwin(owner, unlessEntries, otherPath) {
  const name = path.posix.basename(otherPath);
  return (
    owner.loadModel === UNVERIFIED_MODEL &&
    unlessEntries.some((target) => target.kind === owner.kind && literalNameOf(target.glob) === name)
  );
}

// The folder and every folder above it inside the target, nearest first. The root is ".".
function foldersAbove(folder) {
  const folders = [];
  for (let current = folder; ; current = path.posix.dirname(current)) {
    folders.push(current);
    if (current === ".") return folders;
  }
}

// The .claude folder directly inside a folder of the target.
function claudeFolderOf(folder) {
  return folder === "." ? ".claude" : `${folder}/.claude`;
}

// The claudeMdExcludes entry that excludes a file for an agent, or null. Only Claude Code has that setting, and claudeExclusion
// is worked out for the candidates it owns.
function exclusionFor(agent, file) {
  return agent === CLAUDE_CODE ? file.claudeExclusion : null;
}

// The excludedBy field of a pair, whatever its status: it is set on every Claude Code pair whose file the setting matches.
function excludedFieldOf(agent, file) {
  const excluded = exclusionFor(agent, file);
  return excluded === null ? {} : { excludedBy: excluded.shown };
}

// A Claude Code entry that the existing budget counts although its load model is not verified.
function isCountedAsBefore(agent, entry) {
  return agent === CLAUDE_CODE && COUNTED_AS_BEFORE.has(entry.id);
}

function itemOf(pair) {
  const item = {
    path: pair.file.path,
    agent: pair.agent,
    entry: pair.entry.id,
    kind: pair.entry.kind,
    loadModel: pair.entry.loadModel,
    nested: pair.file.nested,
    status: pair.status,
  };
  if (pair.base !== undefined) item.base = pair.base;
  if (pair.blockedBy !== undefined) item.blockedBy = pair.blockedBy;
  if (pair.excludedBy !== undefined) item.excludedBy = pair.excludedBy;
  if (isCountedAsBefore(pair.agent, pair.entry)) item.budget = AS_BEFORE;
  return item;
}

// ---------------------------------------------------------------------------------------------------
// Reading

// The agents whose pair of each listed file is of kind instructions: path -> sorted agent ids. A file with no such pair is absent.
function instructionAgentsOf(pairs) {
  const agents = new Map();
  for (const pair of pairs) {
    if (pair.entry.kind !== INSTRUCTIONS_KIND) continue;
    if (!agents.has(pair.file.path)) agents.set(pair.file.path, []);
    agents.get(pair.file.path).push(pair.agent);
  }
  for (const list of agents.values()) list.sort(compareText);
  return agents;
}

// Reads the listed files in path order, while the bytes read in total stay within maxTotalBytes. A file is read through ctx.fs,
// not the memoized reader, so its text is not kept for the scan, unless keepText asks for it (see readOne). Only a file that will
// be read is charged: the size from the stat counts toward the total before the read, as duplication.mjs counts its reads. A file
// over DEFAULT_MAX_BYTES is refused by readText (too-large) without being read, so it is not charged, and it is still passed to
// readText, which keeps the fs warning. Each file gets an outcome: whether it was read, the reason when it was not, its counts,
// and its text when keepText asks for it.
function readFiles(ctx, listed, maxTotalBytes, keepText) {
  const outcomes = new Map();
  let bytesRead = 0;
  let bytesCut = 0;
  for (const file of listed) {
    const reason = unreadableReasonOf(file);
    const overFileCap = file.bytes > DEFAULT_MAX_BYTES;
    if (reason !== null) {
      outcomes.set(file.path, unread(reason));
    } else if (!overFileCap && bytesRead + file.bytes > maxTotalBytes) {
      bytesCut += 1;
      outcomes.set(file.path, unread(BYTES_REASON));
    } else {
      if (!overFileCap) bytesRead += file.bytes;
      outcomes.set(file.path, readOne(ctx, file, keepText(file.path)));
    }
  }
  return { outcomes, bytesCut };
}

// Why a file must not be read, decided before the read, or null when it may be read. The name of the file and the name of its
// link target are both checked for secret names, so a link cannot hide one.
function unreadableReasonOf(file) {
  const names = [file.path, file.target].filter((name) => name !== null);
  if (names.some((name) => secretFileKind(name) !== null)) return SECRET_REASON;
  if (file.reason !== null) return file.reason;
  // claudeMdExcludes is a Claude Code setting. A file that only Claude Code owns is not read when the setting matches it. A file
  // that another agent owns is still read for that agent; its claude-code pair keeps the status excluded and the excludedBy.
  if (file.claudeExclusion !== null && agentsOfFile(file).length === 1) return EXCLUDED_REASON;
  if (file.nested && !file.scoped) return NESTED_REASON;
  return null;
}

// Reads the real location that describe resolved, so the file that was checked is the one that is read. The text is put in the
// outcome only when keep is true, so the texts of the other files are not held after they are counted.
function readOne(ctx, file, keep) {
  const read = ctx.fs.readText(file.target);
  if (!read.ok) return unread(read.reason);
  const counts = countsOf(read.text);
  const context = entriesOf(file).some((entry) => CONTEXT_KINDS.has(entry.kind));
  const outcome = { read: true, notReadReason: null, lines: counts.lines, estTokens: context ? counts.estTokens : null };
  if (keep) outcome.text = read.text;
  return outcome;
}

function unread(reason) {
  return { read: false, notReadReason: reason, lines: null, estTokens: null };
}

// ---------------------------------------------------------------------------------------------------
// Output

function fileRecord(file, pairs, outcome, model) {
  const absent = [...model.verified].filter((agent) => !pairs.some((pair) => pair.agent === agent));
  return {
    path: file.path,
    nested: file.nested,
    read: outcome.read,
    notReadReason: outcome.notReadReason,
    bytes: file.bytes,
    lines: outcome.lines,
    estTokens: outcome.estTokens,
    loadedBy: agentsWith(pairs, STATUS.loads),
    notLoadedBy: [...agentsWith(pairs, STATUS.notLoaded), ...agentsWith(pairs, STATUS.excluded), ...absent].sort(compareText),
    unknownFor: agentsWith(pairs, STATUS.unknown),
  };
}

function agentsWith(pairs, status) {
  return pairs.filter((pair) => pair.status === status).map((pair) => pair.agent).sort(compareText);
}

// The agents with at least one pair, sorted by id. An agent is verified when the registry verifies one of its entries. Its budget
// is the shared one only for Claude Code: that is the only agent with a budget measure today. A verified agent of another id
// would also get unknownStatic, because no budget measure exists for it yet.
function agentsOf(model, pairs) {
  return model.agents
    .filter((agent) => pairs.some((pair) => pair.agent === agent.id))
    .sort((a, b) => compareText(a.id, b.id))
    .map((agent) => {
      const own = pairs.filter((pair) => pair.agent === agent.id);
      const verified = model.verified.has(agent.id);
      const countedAsBefore = own.filter((pair) => isCountedAsBefore(pair.agent, pair.entry));
      return {
        id: agent.id,
        name: agent.name,
        type: agent.type,
        verified,
        items: own.length,
        budget: verified && agent.id === CLAUDE_CODE ? CONTEXT_BUDGET : STATIC_BUDGET,
        unverifiedInBudget: [...new Set(countedAsBefore.map((pair) => pair.entry.id))].sort(compareText),
      };
    });
}

// The context files that an agent with its own budget loads and that were read, one per pair.
function unknownStaticOf(pairs, outcomes, staticAgents) {
  const items = [];
  for (const pair of pairs) {
    const outcome = outcomes.get(pair.file.path);
    if (!staticAgents.has(pair.agent) || !CONTEXT_KINDS.has(pair.entry.kind) || !outcome.read) continue;
    items.push({ agent: pair.agent, path: pair.file.path, kind: pair.entry.kind, estTokens: outcome.estTokens });
  }
  return items.sort((a, b) => compareText(a.agent, b.agent) || compareText(a.path, b.path));
}

function groupByPath(pairs) {
  const groups = new Map();
  for (const pair of pairs) {
    if (!groups.has(pair.file.path)) groups.set(pair.file.path, []);
    groups.get(pair.file.path).push(pair);
  }
  return groups;
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

/**
 * The [file, text] pairs of a scan's instruction texts: the memory texts (ctx.memory) and the texts of the other agents'
 * instruction files (ctx.agentInstructions), merged and sorted by file. The two maps never hold the same file.
 * @param {object} ctx The scan context. Both channels must exist; the scanner core creates them.
 * @returns {Array<[string, string]>}
 */
export function instructionTextsOf(ctx) {
  const texts = [
    ...[...ctx.memory].map(([file, node]) => [file, node.text]),
    ...[...ctx.agentInstructions].map(([file, entry]) => [file, entry.text]),
  ];
  return texts.sort(([a], [b]) => compareText(a, b));
}

/** The measure with the registry of this repository and the default caps. */
export const agentInventoryMeasure = createAgentInventoryMeasure();
