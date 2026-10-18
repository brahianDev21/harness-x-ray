import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { claudeConfigMeasure } from "../scripts/lib/claude-config.mjs";
import { destructiveCommandsMeasure } from "../scripts/lib/destructive-commands.mjs";
import { toStableJson } from "../scripts/lib/json-out.mjs";
import { scan } from "../scripts/lib/scanner.mjs";
import { findGenericSecrets, findSpecificSecrets, secretFileKind } from "../scripts/lib/secret-patterns.mjs";
import { secretsMeasure } from "../scripts/lib/secrets.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const SCHEMA_FILE = path.join(HARNESS_ROOT, "schemas", "measurements.schema.json");
const FIXTURES = path.join(TEST_DIR, "fixtures");
const SECRETS_FIXTURE = path.join(FIXTURES, "secrets");
const FIXED_NOW = new Date("2026-10-17T12:00:00.000Z");
const MEASURES = [claudeConfigMeasure, destructiveCommandsMeasure, secretsMeasure];

// Token-shaped values, built at run time so that this file holds no secret-shaped text (push protection would block it).
const GITHUB = ["gh", "p_"].join("") + ["A1b2C3d4E5", "f6G7h8I9j0", "K1l2M3n4O5", "p6Q7r8"].join("");
const ANTHROPIC = ["sk", "ant", "api03"].join("-") + "-Zx41Qw82Er63Ty74Ui85Op96As07Df18Gh29Jk30Lm41Nb52Vc63";
const AWS = "AKIA" + "Q3JX7LMN2PVR5TWZ";
const SLACK = ["xox", "b-1234567890-AbCdEfGhIj"].join("");
// Not token-shaped, but secret-named keys: the generic assignment must find them.
const GENERIC_ARG = "abcdefghijklmnop1234";
const GENERIC_PASSWORD = "hunter2hunter2hunter2";
const MARKER = "HXR-SECRETS-MARKER-5d1c8e";
const SEEDED = [GITHUB, ANTHROPIC, AWS, SLACK, GENERIC_ARG, GENERIC_PASSWORD, MARKER];

// What each seeded value looks like after masking (the prefix, an ellipsis and the last four characters).
const MASKED = {
  github: "ghp_…Q7r8",
  anthropic: "sk-ant-…Vc63",
  aws: "AKIA…5TWZ",
  slack: "xox…GhIj",
  generic: "ab…1234",
  password: "hu…ter2",
};

// Runs the command line through execFile (never a shell). Resolves with the exit code and both streams.
async function runScan(args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [SCAN_SCRIPT, ...args], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 120_000,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    if (typeof error.code !== "number") throw error; // The process did not start.
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

// A copy of a fixture in a temp folder, with files written on top of the copy. The scanner refuses a target inside this
// repository, so every test scans a copy.
function copyOf(t, name, files = {}, options = {}) {
  const fixture = makeFixture({ fromDir: path.join(FIXTURES, name), files, ...options });
  t.after(fixture.cleanup);
  return fixture;
}

// The secrets fixture, versioned in the copy, with token-shaped values written on top. The seeded values sit in every place
// that the measure reads: the memory of a skill, the env of the settings, the headers and args of .mcp.json, a hook command
// and a permission rule.
function seededFixture(t, overrides = {}) {
  const files = {
    ".env": `${MARKER}=1\n`,
    ".mcp.json": json({
      mcpServers: {
        docs: {
          type: "http",
          url: "https://docs.example.invalid/mcp",
          headers: { Authorization: `Bearer ${GITHUB}` },
        },
        local: {
          command: "node",
          args: ["./tools/server.mjs", "--aws-key-id", AWS, `--client-secret=${GENERIC_ARG}`, "--password", GENERIC_PASSWORD],
        },
      },
    }),
    ".claude/settings.json": json({
      env: { ANTHROPIC_API_KEY: ANTHROPIC, LOG_LEVEL: "info" },
      permissions: { allow: ["Bash(npm test)"], deny: [`Bash(curl -H ${SLACK} *)`] },
      hooks: {
        PreToolUse: [
          { matcher: "Bash", hooks: [{ type: "command", command: `node .claude/hooks/guard.mjs --token ${GITHUB}`, onFailure: "block" }] },
        ],
      },
    }),
    ".claude/skills/deploy-notes/SKILL.md": `---\nname: deploy-notes\ndescription: Deploys with the token ${SLACK}\n---\n\n# Deploy notes\n\nSet the credentials in the environment.\n`,
    ...overrides,
  };
  const fixture = makeFixture({ fromDir: SECRETS_FIXTURE, git: true, files });
  t.after(fixture.cleanup);
  return fixture;
}

function tempFolder(t) {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-secrets-out-"));
  t.after(() => fs.rmSync(folder, { recursive: true, force: true }));
  return folder;
}

function json(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

// The 1-based line of the first line that contains the text.
function lineOf(text, needle) {
  const index = text.split("\n").findIndex((line) => line.includes(needle));
  assert.notEqual(index, -1, `the text ${needle.slice(0, 8)} is in the file`);
  return index + 1;
}

async function scanSecrets(root) {
  return scan({ root, measures: MEASURES, now: FIXED_NOW });
}

// A measure context that refuses to read any secret-named path, with the paths that were asked for recorded.
function withoutSecretReads(ctx, reads) {
  const check = (rel) => {
    reads.push(rel);
    if (secretFileKind(rel) !== null) throw new Error(`the secret file ${rel} was read`);
  };
  return {
    ...ctx,
    readText(rel, options) {
      check(rel);
      return ctx.readText(rel, options);
    },
    fs: {
      ...ctx.fs,
      readText(rel, options) {
        check(rel);
        return ctx.fs.readText(rel, options);
      },
      stat(rel) {
        check(rel);
        return ctx.fs.stat(rel);
      },
      exists(rel) {
        check(rel);
        return ctx.fs.exists(rel);
      },
    },
  };
}

const ALL_FIXTURE_FILES = (folder) =>
  fs.readdirSync(folder, { recursive: true }).map((name) => path.join(folder, name)).filter((file) => fs.statSync(file).isFile());

test("secrets: no seeded raw value reaches measurements.json, the console, or the warnings", async (t) => {
  const fixture = seededFixture(t);
  const out = tempFolder(t);

  const cli = await runScan([fixture.root, "--out", out]);
  assert.equal(cli.code, 0);
  const raw = fs.readFileSync(path.join(out, "measurements.json"), "utf8");
  const result = await scanSecrets(fixture.root);

  for (const value of SEEDED) {
    assert.equal(raw.includes(value), false, `measurements.json holds ${value.slice(0, 6)}...`);
    assert.equal(cli.stdout.includes(value), false, "stdout holds a seeded value");
    assert.equal(cli.stderr.includes(value), false, "stderr holds a seeded value");
    assert.equal(toStableJson(result.warnings).includes(value), false, "a warning holds a seeded value");
  }
  for (const masked of [MASKED.github, MASKED.anthropic, MASKED.aws, MASKED.slack, MASKED.generic, MASKED.password]) {
    assert.ok(raw.includes(masked), `measurements.json shows ${masked}`);
  }
});

test("secrets: the hook command and the permission rule are masked in the configuration, not only the literals", async (t) => {
  const fixture = seededFixture(t);
  const result = await scanSecrets(fixture.root);

  assert.deepEqual(
    result.claudeConfig.hooks.map((hook) => hook.command),
    [`node .claude/hooks/guard.mjs --token ${MASKED.github}`],
  );
  assert.deepEqual(result.security.permissions.deny.map((entry) => entry.rule), [`Bash(curl -H ${MASKED.slack} *)`]);
});

test("secrets: a secret file is listed by name, and .env.example is not", async (t) => {
  const fixture = copyOf(t, "secrets", {}, { git: true });
  const result = await scanSecrets(fixture.root);

  assert.deepEqual(
    result.security.secrets.files.map((item) => [item.path, item.kind]),
    [
      [".env", "dotenv"],
      ["config/server.pem", "pem"],
    ],
  );
  assert.equal(result.security.secrets.files.some((item) => item.path === ".env.example"), false);
});

test("secrets: fileListSource says whether the list is versioned (git) or read from disk (walk)", async (t) => {
  const versioned = copyOf(t, "secrets", {}, { git: true });
  const onDisk = copyOf(t, "secrets");

  assert.equal((await scanSecrets(versioned.root)).security.secrets.fileListSource, "git");
  const walked = await scanSecrets(onDisk.root);
  assert.equal(walked.security.secrets.fileListSource, "walk");
  assert.deepEqual(
    walked.security.secrets.files.map((item) => item.path),
    [".env", "config/server.pem"],
    "a walk lists files that are not versioned",
  );
});

test("secrets: the content of a secret file is never read, only its name", async (t) => {
  const fixture = seededFixture(t);
  const reads = [];
  const guarded = {
    id: "guarded-secrets",
    collect: (ctx) => secretsMeasure.collect(withoutSecretReads(ctx, reads)),
  };

  const result = await scan({ root: fixture.root, measures: [guarded], now: FIXED_NOW });

  assert.ok(reads.includes(".claude/settings.json"), "the harness is read, so the check is active");
  assert.deepEqual(reads.filter((rel) => secretFileKind(rel) !== null), []);
  assert.deepEqual(result.security.secrets.files.map((item) => item.path), [".env", "config/server.pem"]);
});

test("secrets: the project's deny rule for .env at the root is reported, and its absence too", async (t) => {
  const guarded = await scanSecrets(copyOf(t, "guarded").root);
  assert.deepEqual(guarded.security.secrets.readProtection.envAtRoot, {
    decision: "deny",
    rule: "Read(**/.env)",
    source: ".claude/settings.json",
    reason: "deny-rule",
  });
  assert.deepEqual(guarded.security.secrets.readProtection.preToolUseReadHooks, [], "the guard hook covers Bash, not Read");

  const plain = await scanSecrets(copyOf(t, "secrets").root);
  assert.deepEqual(plain.security.secrets.readProtection.envAtRoot, {
    decision: "default",
    rule: null,
    source: null,
    reason: "no-rule-matched",
  });
});

test("secrets: each PreToolUse hook that covers Read is listed, with whether it runs for .env", async (t) => {
  const hook = (matcher, command, extra = {}) => ({ matcher, hooks: [{ type: "command", command, ...extra }] });
  const fixture = copyOf(t, "secrets", {
    ".claude/settings.json": json({
      hooks: {
        PreToolUse: [
          hook("Read", "node .claude/hooks/guard-env.mjs", { onFailure: "block" }),
          hook("Read|Grep", "node .claude/hooks/log-read.mjs"),
          hook("Read", "node .claude/hooks/docs-only.mjs", { if: "Read(./docs/**)" }),
          hook("Read(", "node .claude/hooks/broken.mjs"),
          hook("Edit", "node .claude/hooks/edit.mjs"),
          hook("Bash", "node .claude/hooks/bash.mjs"),
        ],
      },
    }),
  });
  const { preToolUseReadHooks } = (await scanSecrets(fixture.root)).security.secrets.readProtection;
  const byScript = new Map(preToolUseReadHooks.map((item) => [item.script.path, item]));

  assert.deepEqual(
    [...byScript.keys()].sort(),
    [".claude/hooks/broken.mjs", ".claude/hooks/docs-only.mjs", ".claude/hooks/guard-env.mjs", ".claude/hooks/log-read.mjs"],
    "Edit and Bash hooks do not cover Read",
  );
  assert.deepEqual(
    pick(byScript.get(".claude/hooks/guard-env.mjs")),
    { source: ".claude/settings.json", matcher: "Read", if: null, failsOpen: false, runsForEnv: "runs" },
  );
  assert.deepEqual(pick(byScript.get(".claude/hooks/log-read.mjs")), {
    source: ".claude/settings.json",
    matcher: "Read|Grep",
    if: null,
    failsOpen: true,
    runsForEnv: "runs",
  });
  assert.equal(byScript.get(".claude/hooks/docs-only.mjs").runsForEnv, "none", "its filter does not cover .env");
  assert.equal(byScript.get(".claude/hooks/broken.mjs").runsForEnv, "undeterminable", "a matcher that is not a regular expression");
});

function pick(item) {
  return { source: item.source, matcher: item.matcher, if: item.if, failsOpen: item.failsOpen, runsForEnv: item.runsForEnv };
}

test("secrets: literals give the file, the line, the kind and the location, with the value masked", async (t) => {
  const fixture = seededFixture(t);
  const { literals } = (await scanSecrets(fixture.root)).security.secrets;
  const settings = fs.readFileSync(path.join(fixture.root, ".claude", "settings.json"), "utf8");
  const mcp = fs.readFileSync(path.join(fixture.root, ".mcp.json"), "utf8");
  const skill = fs.readFileSync(path.join(fixture.root, ".claude", "skills", "deploy-notes", "SKILL.md"), "utf8");

  assert.deepEqual(literals, [
    { file: ".claude/settings.json", line: lineOf(settings, ANTHROPIC), kind: "anthropic-api-key", masked: MASKED.anthropic, location: "env.ANTHROPIC_API_KEY" },
    { file: ".claude/skills/deploy-notes/SKILL.md", line: lineOf(skill, SLACK), kind: "slack-token", masked: MASKED.slack, location: "text" },
    { file: ".mcp.json", line: lineOf(mcp, GITHUB), kind: "github-classic-token", masked: MASKED.github, location: "mcpServers.docs.headers.Authorization" },
    { file: ".mcp.json", line: lineOf(mcp, AWS), kind: "aws-access-key-id", masked: MASKED.aws, location: "mcpServers.local.args[2]" },
    { file: ".mcp.json", line: lineOf(mcp, GENERIC_ARG), kind: "generic-assignment", masked: MASKED.generic, location: "mcpServers.local.args[3]" },
    { file: ".mcp.json", line: lineOf(mcp, GENERIC_PASSWORD), kind: "generic-assignment", masked: MASKED.password, location: "mcpServers.local.args[5]" },
  ]);
});

test("secrets: references and placeholders are not reported, and the versioned fixture has no literal", async (t) => {
  const fixture = copyOf(t, "secrets", {}, { git: true });
  assert.deepEqual((await scanSecrets(fixture.root)).security.secrets.literals, []);
});

test("secrets: env of an MCP server and of the local settings file are read too", async (t) => {
  const fixture = copyOf(t, "secrets", {
    ".mcp.json": json({ mcpServers: { tools: { command: "node", env: { GITHUB_TOKEN: GITHUB, PLAIN: "info" } } } }),
    ".claude/settings.local.json": json({ env: { REPORT_SECRET: GENERIC_ARG } }),
  });
  const { literals } = (await scanSecrets(fixture.root)).security.secrets;

  assert.deepEqual(literals.map((item) => [item.file, item.location, item.kind, item.masked]), [
    [".claude/settings.local.json", "env.REPORT_SECRET", "generic-assignment", MASKED.generic],
    [".mcp.json", "mcpServers.tools.env.GITHUB_TOKEN", "github-classic-token", MASKED.github],
  ]);
});

test("secrets: memory files at any depth and the rules are read; other markdown is not", async (t) => {
  const fixture = copyOf(t, "secrets", {
    "CLAUDE.md": `# Notes\n\nDB_PASSWORD=${GENERIC_PASSWORD}\n`,
    "packages/app/AGENTS.md": `Use ${ANTHROPIC} for the model.\n`,
    ".claude/rules/security.md": `Slack: ${SLACK}\n`,
    "docs/notes.md": `Old token: ${GITHUB}\n`,
  });
  const { literals } = (await scanSecrets(fixture.root)).security.secrets;

  assert.deepEqual(
    literals.map((item) => [item.file, item.line, item.kind, item.masked]),
    [
      [".claude/rules/security.md", 1, "slack-token", MASKED.slack],
      ["CLAUDE.md", 3, "generic-assignment", MASKED.password],
      ["packages/app/AGENTS.md", 1, "anthropic-api-key", MASKED.anthropic],
    ],
  );
});

test("secrets: a placeholder in a memory file is not reported", async (t) => {
  const fixture = copyOf(t, "secrets", {
    "CLAUDE.md": "API_KEY=${API_KEY}\nexport TOKEN=<your-token-here>\npassword: changeme\n",
  });
  assert.deepEqual((await scanSecrets(fixture.root)).security.secrets.literals, []);
});

test("secrets: the output is the same on every scan", async (t) => {
  const fixture = seededFixture(t);
  const first = toStableJson((await scanSecrets(fixture.root)).security.secrets);
  const second = toStableJson((await scanSecrets(fixture.root)).security.secrets);
  assert.equal(first, second);
});

test("secrets: the versioned fixture holds no token-shaped text", () => {
  for (const file of ALL_FIXTURE_FILES(SECRETS_FIXTURE)) {
    const text = fs.readFileSync(file, "utf8");
    assert.deepEqual(findSpecificSecrets(text), [], `${path.relative(SECRETS_FIXTURE, file)} has a token-shaped value`);
    assert.deepEqual(findGenericSecrets(text), [], `${path.relative(SECRETS_FIXTURE, file)} has a generic secret`);
  }
});

test("secrets: the schema documents security.secrets and keeps the existing sections", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
  const security = schema.properties.security;
  assert.deepEqual(security.required, ["permissions", "destructiveCoverage", "secrets"]);
  assert.deepEqual(Object.keys(security.properties.secrets.properties).sort(), ["fileListSource", "files", "literals", "readProtection"]);
  assert.ok(schema.$defs.verdict, "the shared verdict definition exists");
});
