import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { createAgentInventoryMeasure } from "../scripts/lib/agent-inventory.mjs";
import { createMemoryMeasure } from "../scripts/lib/memory.mjs";
import { scan } from "../scripts/lib/scanner.mjs";
import { verificationMeasure } from "../scripts/lib/verification.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";
import { schemaProblems } from "./helpers/schema-check.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const FIXTURES = path.join(TEST_DIR, "fixtures");
const FIXED_NOW = new Date("2026-10-17T12:00:00.000Z");
// Text that only a lockfile holds. No output and no memory entry may include it.
const WITNESS = "witness-7c2a-lockfile-content";

// A copy of a versioned fixture in a temp folder, with extra files written on top of the copy.
function copyOf(t, name, files = {}) {
  const fixture = makeFixture({ fromDir: path.join(FIXTURES, name), files });
  t.after(fixture.cleanup);
  return fixture;
}

// A new fixture in a temp folder.
function freshFixture(t, description = {}) {
  const fixture = makeFixture(description);
  t.after(fixture.cleanup);
  return fixture;
}

// Runs the memory measure, then the verification measure. The ancestor walk stops at the fixture folder,
// so the real parent folders of the temp folder never count.
function verificationScan(fixture) {
  return scan({
    root: fixture.root,
    measures: [
      createMemoryMeasure({ ancestorLimit: fixture.base, home: path.join(fixture.base, "no-home") }),
      verificationMeasure,
    ],
    now: FIXED_NOW,
  });
}

// The text of a package.json with the given fields.
function packageJson(fields = {}) {
  return `${JSON.stringify({ name: "fixture", version: "1.0.0", private: true, ...fields }, null, 2)}\n`;
}

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

// The warnings that this measure adds. The fixtures are not git repositories, so the core adds its own
// git warning to every result; that one is not this measure's.
const verificationWarnings = (result) => result.warnings.filter((warning) => warning.source === "verification");

// Removes the meta block from the raw text. In the output, meta is a top-level key, so its block ends
// at the first line that is exactly "  },".
function withoutMetaText(raw) {
  const stripped = raw.replace(/^  "meta": \{\n[\s\S]*?^  \},\n/m, "");
  assert.notEqual(stripped, raw, "the meta block was not found");
  return stripped;
}

test("empty: no commands, no mentions, no package manager, and no tools", async (t) => {
  const fixture = copyOf(t, "empty");
  const result = await verificationScan(fixture);

  assert.deepEqual(result.verification, { commands: [], mentioned: [] });
  assert.deepEqual(result.instructions.packageManager, {
    field: null,
    fieldManager: null,
    lockfiles: [],
    mentions: [],
    byFile: [],
    conflict: false,
  });
  assert.deepEqual(result.structure, { enforcementTools: [] });
  assert.deepEqual(verificationWarnings(result), []);
});

test("minimal-good: test, lint, typecheck and format are classified, and the memory calls to them are found", async (t) => {
  const fixture = copyOf(t, "minimal-good");
  const result = await verificationScan(fixture);

  assert.deepEqual(result.verification.commands, [
    { name: "format", categories: ["format"] },
    { name: "lint", categories: ["lint"] },
    { name: "test", categories: ["test"] },
    { name: "typecheck", categories: ["typecheck"] },
  ]);
  assert.deepEqual(result.verification.mentioned, [
    { script: "test", file: "CLAUDE.md", line: 7, text: "npm test" },
    { script: "lint", file: "CLAUDE.md", line: 8, text: "npm run lint" },
    { script: "typecheck", file: "CLAUDE.md", line: 8, text: "npm run typecheck" },
    { script: "format", file: "CLAUDE.md", line: 9, text: "npm run format" },
    { script: "test", file: "CLAUDE.md", line: 12, text: "npm test" },
    { script: "lint", file: "CLAUDE.md", line: 13, text: "npm run lint" },
  ]);
  assert.deepEqual(result.instructions.packageManager, {
    field: null,
    fieldManager: null,
    lockfiles: [{ path: "package-lock.json", manager: "npm" }],
    mentions: [7, 8, 9, 12, 13].map((line) => ({ manager: "npm", file: "CLAUDE.md", line })),
    byFile: [{ file: "CLAUDE.md", managers: ["npm"], agents: [] }],
    conflict: false,
  });
  assert.deepEqual(result.structure, { enforcementTools: [] });
});

test("pm-conflict: the lockfile names pnpm, the memory names npm, and conflict is true", async (t) => {
  const fixture = copyOf(t, "pm-conflict");
  const result = await verificationScan(fixture);

  assert.deepEqual(result.instructions.packageManager, {
    field: null,
    fieldManager: null,
    lockfiles: [{ path: "pnpm-lock.yaml", manager: "pnpm" }],
    mentions: [{ manager: "npm", file: "CLAUDE.md", line: 3 }],
    byFile: [{ file: "CLAUDE.md", managers: ["npm"], agents: [] }],
    conflict: true,
  });
  assert.deepEqual(result.verification, { commands: [], mentioned: [] });
});

test("packageManager: the field is kept as written, its manager is the name before @, and it counts toward conflict", async (t) => {
  const pnpmField = freshFixture(t, {
    files: { "package.json": packageJson({ packageManager: "pnpm@9.0.0" }), "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" },
  });
  assert.deepEqual((await verificationScan(pnpmField)).instructions.packageManager, {
    field: "pnpm@9.0.0",
    fieldManager: "pnpm",
    lockfiles: [{ path: "pnpm-lock.yaml", manager: "pnpm" }],
    mentions: [],
    byFile: [],
    conflict: false,
  });

  const npmField = freshFixture(t, {
    files: { "package.json": packageJson({ packageManager: "npm@10.2.0" }), "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" },
  });
  assert.deepEqual((await verificationScan(npmField)).instructions.packageManager, {
    field: "npm@10.2.0",
    fieldManager: "npm",
    lockfiles: [{ path: "pnpm-lock.yaml", manager: "pnpm" }],
    mentions: [],
    byFile: [],
    conflict: true,
  });

  const otherField = freshFixture(t, { files: { "package.json": packageJson({ packageManager: "deno@1.40.0" }) } });
  assert.deepEqual((await verificationScan(otherField)).instructions.packageManager, {
    field: "deno@1.40.0",
    fieldManager: null,
    lockfiles: [],
    mentions: [],
    byFile: [],
    conflict: false,
  });
});

test("lockfiles: only the root counts, and each name gives its manager", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": packageJson(),
      "bun.lockb": "binary-looking text\n",
      "packages/app/yarn.lock": "# nested\n",
      "npm-shrinkwrap.json": "{}\n",
    },
  });
  const result = await verificationScan(fixture);

  assert.deepEqual(result.instructions.packageManager.lockfiles, [
    { path: "bun.lockb", manager: "bun" },
    { path: "npm-shrinkwrap.json", manager: "npm" },
  ]);
  assert.equal(result.instructions.packageManager.conflict, true);
});

test("classification: scripts are classified by name and by command, and a script with no category is left out", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": packageJson({
        scripts: {
          build: "vite build",
          check: "npm run lint && npm run typecheck",
          ci: "vitest run",
          dev: "vite",
          e2e: "playwright test",
          "format:check": "prettier --check .",
          format: "prettier --check .",
          lint: "eslint .",
          start: "node src/index.mjs",
          sync: "node scripts/sync-avatars.mjs",
          typecheck: "tsc --noEmit",
          types: "vue-tsc --noEmit",
          "unit:test": "node scripts/run-units.mjs",
        },
      }),
    },
  });
  const result = await verificationScan(fixture);

  assert.deepEqual(result.verification.commands, [
    { name: "build", categories: ["build"] },
    { name: "check", categories: ["verify"] },
    { name: "ci", categories: ["test", "verify"] },
    { name: "e2e", categories: ["test"] },
    { name: "format", categories: ["format"] },
    { name: "format:check", categories: ["format"] },
    { name: "lint", categories: ["lint"] },
    { name: "typecheck", categories: ["typecheck"] },
    { name: "types", categories: ["typecheck"] },
    { name: "unit:test", categories: ["test"] },
  ]);
  assert.equal(JSON.stringify(result.verification).includes("vitest run"), false, "the command text is not output");
});

test("verify names: verify:* and check:* are verify, and a name that only starts with check is not", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": packageJson({
        scripts: {
          "check:links": "node scripts/check-links.mjs",
          checkout: "node scripts/checkout.mjs",
          "verify:search": "node scripts/verify-search.mjs",
        },
      }),
    },
  });
  const result = await verificationScan(fixture);

  assert.deepEqual(result.verification.commands, [
    { name: "check:links", categories: ["verify"] },
    { name: "verify:search", categories: ["verify"] },
  ]);
});

test("typecheck commands: tsc needs --noEmit later in its segment, astro check and vue-tsc count, a plain tsc does not", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": packageJson({
        scripts: {
          "astro-check": "astro check",
          build: "tsc -p .",
          compile: "tsc -p .",
          emit: "tsc -p . && node scripts/write-report.mjs --noEmit",
          probe: "tsc -p . --noEmit",
          "probe:vue": "vue-tsc --noEmit",
        },
      }),
    },
  });
  const result = await verificationScan(fixture);

  // "compile" and "emit" have no category: a plain tsc is a build, and --noEmit in another segment is not
  // a flag of tsc.
  assert.deepEqual(result.verification.commands, [
    { name: "astro-check", categories: ["typecheck"] },
    { name: "build", categories: ["build"] },
    { name: "probe", categories: ["typecheck"] },
    { name: "probe:vue", categories: ["typecheck"] },
  ]);
});

test("mentions: calls to listed scripts are found in prose, inline code and fenced blocks; other calls are not", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": packageJson({ scripts: { ci: "vitest run", lint: "eslint .", "unit:test": "node scripts/run-units.mjs" } }),
      "CLAUDE.md": [
        "Run `npm run ci` before a commit.",
        "Use `pnpm unit:test` for units, and `yarn sync` only if needed.",
        "",
        "~~~sh",
        "npx vitest run",
        "npm run lint",
        "npm run missing",
        "~~~",
        "",
      ].join("\n"),
    },
  });
  const result = await verificationScan(fixture);

  assert.deepEqual(result.verification.mentioned, [
    { script: "ci", file: "CLAUDE.md", line: 1, text: "npm run ci" },
    { script: "unit:test", file: "CLAUDE.md", line: 2, text: "pnpm unit:test" },
    { script: "lint", file: "CLAUDE.md", line: 6, text: "npm run lint" },
  ]);
});

test("whole words: pnpmfile, npmrc, npm-run-all, scoped names and ~/.npm are not mentions; a sentence-end npm is", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": packageJson(),
      "CLAUDE.md": [
        "Hooks live in `pnpmfile.cjs` and `.npmrc`.",
        "Run `npm-run-all --parallel` only when needed. The cache is in ~/.npm.",
        "Packages such as @pnpm/exe are not managers in this text.",
        "Install with npm.",
        "",
      ].join("\n"),
    },
  });
  const result = await verificationScan(fixture);

  assert.deepEqual(result.instructions.packageManager.mentions, [{ manager: "npm", file: "CLAUDE.md", line: 4 }]);
  assert.equal(result.instructions.packageManager.conflict, false);
});

test("lockfile names: yarn.lock, bun.lockb and npm.cmd are not mentions; a sentence-final name is", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": packageJson(),
      "CLAUDE.md": [
        "Lockfiles such as `yarn.lock` and `bun.lockb` are generated.",
        "On Windows the shim is `npm.cmd`.",
        "Install with yarn.",
        "",
      ].join("\n"),
    },
  });
  const result = await verificationScan(fixture);

  assert.deepEqual(result.instructions.packageManager.mentions, [{ manager: "yarn", file: "CLAUDE.md", line: 3 }]);
  assert.equal(result.instructions.packageManager.conflict, false);
});

test("tools: root configs are listed by name; the same names in a subfolder are not; workflows and .husky are listed", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "eslint.config.mjs": "export default [];\n",
      "packages/app/eslint.config.mjs": "export default [];\n",
      ".prettierrc.json": "{}\n",
      "biome.jsonc": "{}\n",
      "tsconfig.json": "{}\n",
      "tsconfig.build.json": "{}\n",
      "apps/web/tsconfig.json": "{}\n",
      ".dependency-cruiser.cjs": "module.exports = {};\n",
      ".secretlintrc.json": "{}\n",
      ".gitleaks.toml": 'title = "example"\n',
      ".jscpd.json": "{}\n",
      ".lintstagedrc.json": "{}\n",
      ".editorconfig": "root = true\n",
      ".husky/pre-commit": "npx lint-staged\n",
      ".husky/_/husky.sh": "# helper\n",
      ".github/workflows/ci.yml": "name: ci\n",
      ".github/workflows/release.yaml": "name: release\n",
      ".github/workflows/nested/deep.yml": "name: deep\n",
      ".github/actions/setup/action.yml": "name: setup\n",
    },
  });
  const result = await verificationScan(fixture);

  assert.deepEqual(result.structure.enforcementTools, [
    { tool: "biome", path: "biome.jsonc" },
    { tool: "dependency-cruiser", path: ".dependency-cruiser.cjs" },
    { tool: "editorconfig", path: ".editorconfig" },
    { tool: "eslint", path: "eslint.config.mjs" },
    { tool: "github-actions", path: ".github/workflows/ci.yml" },
    { tool: "github-actions", path: ".github/workflows/release.yaml" },
    { tool: "gitleaks", path: ".gitleaks.toml" },
    { tool: "husky", path: ".husky" },
    { tool: "jscpd", path: ".jscpd.json" },
    { tool: "lint-staged", path: ".lintstagedrc.json" },
    { tool: "prettier", path: ".prettierrc.json" },
    { tool: "secretlint", path: ".secretlintrc.json" },
    { tool: "typescript", path: "tsconfig.build.json" },
    { tool: "typescript", path: "tsconfig.json" },
  ]);
});

test("tools: the architecture tools are found by config name or by the manifest that names them (positive controls next to each)", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      ".importlinter": "[importlinter]\nroot_package = app\n",
      "pyproject.toml": '[project]\nname = "app"\n\n[tool.importlinter]\nroot_package = "app"\n',
      "setup.cfg": "[metadata]\nname = app\n\n[importlinter]\nroot_package = app\n",
      "pom.xml": "<project><dependencies><dependency><groupId>com.tngtech.archunit</groupId></dependency></dependencies></project>\n",
      "build.gradle.kts": 'dependencies { testImplementation("com.tngtech.archunit:archunit-junit5:1.3.0") }\n',
      "package.json": packageJson({ devDependencies: { "eslint-plugin-boundaries": "^4.0.0", eslint: "^9.0.0" } }),
      // Not found: a manifest in a subfolder, and manifests that name no architecture tool.
      "services/api/pom.xml": "<project><groupId>com.tngtech.archunit</groupId></project>\n",
      "tools/build.gradle": 'dependencies { testImplementation "com.tngtech.archunit:archunit:1.3.0" }\n',
    },
  });
  const result = await verificationScan(fixture);
  assert.deepEqual(result.structure.enforcementTools, [
    { tool: "archunit", path: "build.gradle.kts" },
    { tool: "archunit", path: "pom.xml" },
    { tool: "eslint-plugin-boundaries", path: "package.json" },
    { tool: "import-linter", path: ".importlinter" },
    { tool: "import-linter", path: "pyproject.toml" },
    { tool: "import-linter", path: "setup.cfg" },
  ]);

  const plain = freshFixture(t, {
    files: {
      "pyproject.toml": '[project]\nname = "app"\n\n[tool.ruff]\nline-length = 100\n',
      "build.gradle": 'dependencies { testImplementation "org.junit.jupiter:junit-jupiter:5.10.0" }\n',
      "package.json": packageJson({ scripts: { lint: "eslint-plugin-boundaries is not a dependency here" } }),
    },
  });
  assert.deepEqual((await verificationScan(plain)).structure.enforcementTools, []);

  // The other manifest forms: dependencies (not only devDependencies), a root build.gradle, and a marker in a comment, which
  // counts too (the scan matches text; the rule asks the reviewer to open the config).
  const others = freshFixture(t, {
    files: {
      "package.json": packageJson({ dependencies: { "eslint-plugin-boundaries": "^4.0.0" } }),
      "build.gradle": 'dependencies { testImplementation "com.tngtech.archunit:archunit:1.3.0" }\n',
      "pyproject.toml": "# [tool.importlinter] is planned\n[project]\nname = 'app'\n",
    },
  });
  assert.deepEqual((await verificationScan(others)).structure.enforcementTools, [
    { tool: "archunit", path: "build.gradle" },
    { tool: "eslint-plugin-boundaries", path: "package.json" },
    { tool: "import-linter", path: "pyproject.toml" },
  ]);
  const schema = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "measurements.schema.json"), "utf8"));
  const tools = schema.properties.structure.properties.enforcementTools.items.properties.tool.enum;
  for (const tool of ["archunit", "eslint-plugin-boundaries", "import-linter"]) assert.ok(tools.includes(tool), tool);

  // A package.json that cannot be parsed names nothing, and adds no warning.
  const broken = freshFixture(t, { files: { "package.json": "{ not json" } });
  const brokenResult = await verificationScan(broken);
  assert.deepEqual(brokenResult.structure.enforcementTools, []);
  assert.deepEqual(brokenResult.warnings.filter((item) => item.source !== "git"), []);
});

test("a lockfile's content never reaches the output, and a package.json that cannot be parsed gives no commands and no warning", async (t) => {
  const lockfile = freshFixture(t, {
    files: {
      "package.json": packageJson({ scripts: { test: "node --test" } }),
      "yarn.lock": `# ${WITNESS}\n`,
      "CLAUDE.md": "Install with `yarn install`.\n",
    },
  });
  const withLock = await verificationScan(lockfile);
  assert.deepEqual(withLock.instructions.packageManager.lockfiles, [{ path: "yarn.lock", manager: "yarn" }]);
  assert.equal(JSON.stringify(withLock).includes(WITNESS), false, "the lockfile content is not read");

  const broken = freshFixture(t, {
    files: { "package.json": "{ not json", "CLAUDE.md": "Run `npm test`.\n" },
  });
  const result = await verificationScan(broken);
  assert.deepEqual(result.verification, { commands: [], mentioned: [] });
  assert.deepEqual(verificationWarnings(result), [], "the references measure reports package.json, not this one");
});

// Runs the memory measure, the agent-inventory measure and the verification measure.
function verificationWithAgents(fixture) {
  return scan({
    root: fixture.root,
    measures: [
      createMemoryMeasure({ ancestorLimit: fixture.base, home: path.join(fixture.base, "no-home") }),
      createAgentInventoryMeasure(),
      verificationMeasure,
    ],
    now: FIXED_NOW,
  });
}

test("byFile: AGENTS.md that says pnpm and .cursorrules that says npm give a conflict, with each file and the agents that own it", async (t) => {
  const fixture = freshFixture(t, { files: { "AGENTS.md": "Install with pnpm.\n", ".cursorrules": "Test with npm test.\n" } });
  const manager = (await verificationWithAgents(fixture)).instructions.packageManager;
  assert.equal(manager.conflict, true);
  assert.deepEqual(manager.byFile, [
    { file: ".cursorrules", managers: ["npm"], agents: ["cursor"] },
    { file: "AGENTS.md", managers: ["pnpm"], agents: ["agents-md", "claude-code"] },
  ]);
  assert.deepEqual(manager.mentions, [{ manager: "pnpm", file: "AGENTS.md", line: 1 }], "mentions keeps the memory lines only");
  // Without the agent-inventory measure the agent text is not read, so it does not count, and the memory file has no agent.
  const memoryOnly = (await verificationScan(fixture)).instructions.packageManager;
  assert.equal(memoryOnly.conflict, false);
  assert.deepEqual(memoryOnly.byFile, [{ file: "AGENTS.md", managers: ["pnpm"], agents: [] }]);
});

test("byFile: AGENTS.md and .cursorrules that both say pnpm give no conflict (positive control)", async (t) => {
  const fixture = freshFixture(t, { files: { "AGENTS.md": "Install with pnpm.\n", ".cursorrules": "Install with pnpm install.\n" } });
  const manager = (await verificationWithAgents(fixture)).instructions.packageManager;
  assert.equal(manager.conflict, false);
  assert.deepEqual(manager.byFile, [
    { file: ".cursorrules", managers: ["pnpm"], agents: ["cursor"] },
    { file: "AGENTS.md", managers: ["pnpm"], agents: ["agents-md", "claude-code"] },
  ]);
});

// Runs the memory measure, then the verification measure, with a scope. The ancestor walk stops at the fixture folder.
function scopedVerificationScan(fixture, scope) {
  return scan({
    root: fixture.root,
    measures: [
      createMemoryMeasure({ ancestorLimit: fixture.base, home: path.join(fixture.base, "no-home") }),
      verificationMeasure,
    ],
    now: FIXED_NOW,
    scope,
  });
}

// A monorepo whose only check is at the root: a test script, a CI workflow, and a root memory line that names the command.
// The web app has a package.json without scripts.
function monorepoWithRootCheck() {
  return {
    "package.json": packageJson({ scripts: { test: "node --test" } }),
    ".github/workflows/ci.yml": "name: ci\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
    "CLAUDE.md": "# Monorepo\n\nBefore reporting a change as done, run `npm test`.\n",
    "apps/web/package.json": packageJson({ name: "web" }),
    "apps/web/src/index.ts": "export {};\n",
  };
}

test("VER-01 acceptance: with the scope apps/web, the root test script, the root mention and the CI workflow still count", async (t) => {
  const fixture = freshFixture(t, { files: monorepoWithRootCheck() });
  const result = await scopedVerificationScan(fixture, ["apps/web"]);

  assert.deepEqual(result.verification.commands, [{ name: "test", categories: ["test"] }]);
  assert.deepEqual(result.verification.mentioned, [{ script: "test", file: "CLAUDE.md", line: 3, text: "npm test" }]);
  assert.deepEqual(result.structure.enforcementTools, [{ tool: "github-actions", path: ".github/workflows/ci.yml" }]);
  assert.deepEqual(result.verification.packages, [{ path: "apps/web/package.json", where: "scope", status: "ok", commands: [] }]);
  assert.deepEqual(verificationWarnings(result), []);
});

test("VER-01 acceptance: positive control, without a scope there is no packages list, and the same root checks are found", async (t) => {
  const fixture = freshFixture(t, { files: monorepoWithRootCheck() });
  const result = await verificationScan(fixture);

  assert.equal(Object.hasOwn(result.verification, "packages"), false);
  assert.deepEqual(result.verification.commands, [{ name: "test", categories: ["test"] }]);
  assert.deepEqual(result.structure.enforcementTools, [{ tool: "github-actions", path: ".github/workflows/ci.yml" }]);
  assert.deepEqual(verificationWarnings(result), []);
});

test("VER-01 acceptance: the only check lives in packages/testing, which is listed as other; its script name makes the root mention count", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": packageJson(),
      "CLAUDE.md": "# Monorepo\n\nRun `npm test` before you finish.\n",
      "apps/package.json": packageJson({ scripts: { lint: "eslint ." } }),
      "apps/web/package.json": packageJson({ name: "web" }),
      "packages/testing/package.json": packageJson({ scripts: { test: "vitest run" } }),
    },
  });
  const result = await scopedVerificationScan(fixture, ["apps/web"]);

  assert.deepEqual(result.verification.commands, []);
  assert.deepEqual(result.verification.packages, [
    { path: "apps/web/package.json", where: "scope", status: "ok", commands: [] },
    { path: "apps/package.json", where: "inherited", status: "ok", commands: [{ name: "lint", categories: ["lint"] }] },
    { path: "packages/testing/package.json", where: "other", status: "ok", commands: [{ name: "test", categories: ["test"] }] },
  ]);
  assert.deepEqual(result.verification.mentioned, [{ script: "test", file: "CLAUDE.md", line: 3, text: "npm test" }]);
});

test("VER-01 acceptance: positive control, without a scope the packages of other layers are not read, and the root mention is not a listed name", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": packageJson(),
      "CLAUDE.md": "# Monorepo\n\nRun `npm test` before you finish.\n",
      "packages/testing/package.json": packageJson({ scripts: { test: "vitest run" } }),
    },
  });
  const result = await verificationScan(fixture);

  assert.deepEqual(result.verification, { commands: [], mentioned: [] });
});

test("packages: a package.json that cannot be read or parsed is listed as such, one under node_modules is skipped, and the valid one is ok", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "apps/web/package.json": packageJson({ scripts: { test: "node --test" } }),
      "apps/web/bad/package.json": "{ not json",
      "apps/web/bin/package.json": Buffer.from('{"scripts":{"test":"x"}}\u0000'),
      "apps/web/node_modules/dep/package.json": packageJson({ scripts: { test: "node --test" } }),
    },
  });
  const result = await scopedVerificationScan(fixture, ["apps/web"]);

  assert.deepEqual(result.verification.packages, [
    { path: "apps/web/bad/package.json", where: "scope", status: "invalid", commands: [] },
    { path: "apps/web/bin/package.json", where: "scope", status: "unreadable", commands: [] },
    { path: "apps/web/package.json", where: "scope", status: "ok", commands: [{ name: "test", categories: ["test"] }] },
  ]);
  assert.deepEqual(verificationWarnings(result), []);
});

test("packages: more than 100 package.json files keep the first 100 and count the rest in one warning; 100 give none", async (t) => {
  const many = (count) =>
    Object.fromEntries(Array.from({ length: count }, (_, index) => [`apps/web/pkg-${index}/package.json`, packageJson()]));
  const over = freshFixture(t, { files: many(103) });
  const overResult = await scopedVerificationScan(over, ["apps/web"]);

  assert.equal(overResult.verification.packages.length, 100);
  assert.deepEqual(verificationWarnings(overResult), [
    { source: "verification", path: ".", reason: "scope-packages-cut", detail: "count=3" },
  ]);

  // Positive control: 99 extra files plus apps/web/package.json itself make exactly 100, which nothing cuts.
  const exact = freshFixture(t, { files: { ...many(99), "apps/web/package.json": packageJson() } });
  const exactResult = await scopedVerificationScan(exact, ["apps/web"]);
  assert.equal(exactResult.verification.packages.length, 100);
  assert.deepEqual(verificationWarnings(exactResult), []);
});

test("tools with a scope: the configs directly in an inherited folder and in the scope folder count; the ones deeper or outside do not", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "biome.json": "{}\n",
      ".github/workflows/ci.yml": "name: ci\n",
      "apps/.eslintrc.json": "{}\n",
      "apps/web/tsconfig.json": "{}\n",
      "apps/web/src/tsconfig.json": "{}\n",
      "apps/api/biome.json": "{}\n",
      "apps/web/.github/workflows/local.yml": "name: local\n",
    },
  });
  const result = await scopedVerificationScan(fixture, ["apps/web"]);

  assert.deepEqual(result.structure.enforcementTools, [
    { tool: "biome", path: "biome.json" },
    { tool: "eslint", path: "apps/.eslintrc.json" },
    { tool: "github-actions", path: ".github/workflows/ci.yml" },
    { tool: "typescript", path: "apps/web/tsconfig.json" },
  ]);
  // Positive control: without a scope, only the root configs and the root workflows count.
  const unscoped = await verificationScan(fixture);
  assert.deepEqual(unscoped.structure.enforcementTools, [
    { tool: "biome", path: "biome.json" },
    { tool: "github-actions", path: ".github/workflows/ci.yml" },
  ]);
});

test("verification: the measurements schema documents the verification, structure and packageManager fields", () => {
  const schema = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "measurements.schema.json"), "utf8"));
  assert.deepEqual(schema.properties.verification.required, ["commands", "mentioned"]);
  assert.deepEqual(schema.properties.structure.required, ["enforcementTools", "generatedFiles", "largeFiles", "mapCoverage", "tree"]);
  assert.ok(schema.properties.instructions.required.includes("packageManager"));
  const manager = schema.properties.instructions.properties.packageManager;
  assert.deepEqual(manager.required, ["field", "fieldManager", "lockfiles", "mentions", "byFile", "conflict"]);
  assert.deepEqual(manager.properties.fieldManager.enum, ["npm", "pnpm", "yarn", "bun", null]);
  assert.deepEqual(manager.properties.byFile.items.required, ["file", "managers", "agents"]);
  assert.deepEqual(schema.properties.verification.properties.commands.items.properties.categories.items.enum, [
    "build",
    "format",
    "lint",
    "test",
    "typecheck",
    "verify",
  ]);
});

test("a scoped result holds the values the schema describes: verification, with its packages, and the enforcement tools", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      ...monorepoWithRootCheck(),
      "apps/package.json": packageJson({ scripts: { lint: "eslint ." } }),
      "apps/web/bad/package.json": "{ not json",
    },
  });
  const result = await scopedVerificationScan(fixture, ["apps/web"]);
  const schema = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "measurements.schema.json"), "utf8"));

  assert.deepEqual(schemaProblems(schema.properties.verification, result.verification), []);
  assert.deepEqual(schemaProblems(schema.properties.structure.properties.enforcementTools, result.structure.enforcementTools), []);
});

test("the measurements schema documents verification.packages as optional, with the three where values and the three statuses", () => {
  const schema = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "measurements.schema.json"), "utf8"));
  const verification = schema.properties.verification;
  assert.deepEqual(verification.required, ["commands", "mentioned"], "packages is optional: it is present only with a scope");
  const packages = verification.properties.packages;
  assert.deepEqual([...packages.items.required].sort(), ["commands", "path", "status", "where"]);
  assert.deepEqual(packages.items.properties.where.enum, ["scope", "inherited", "other"]);
  assert.deepEqual(packages.items.properties.status.enum, ["ok", "unreadable", "invalid"]);
  assert.match(schema.properties.warnings.items.properties.reason.description, /scope-packages-cut/);
});

test("two CLI runs on a copy of pm-conflict give the same JSON, except meta", async (t) => {
  const fixture = copyOf(t, "pm-conflict");
  const first = path.join(fixture.base, "first");
  const second = path.join(fixture.base, "second");
  assert.equal((await runScan([fixture.root, "--out", first])).code, 0);
  assert.equal((await runScan([fixture.root, "--out", second])).code, 0);

  const rawFirst = fs.readFileSync(path.join(first, "measurements.json"), "utf8");
  const rawSecond = fs.readFileSync(path.join(second, "measurements.json"), "utf8");
  const dataFirst = JSON.parse(rawFirst);
  const dataSecond = JSON.parse(rawSecond);
  assert.equal(dataFirst.instructions.packageManager.conflict, true);
  assert.deepEqual(dataFirst.verification, { commands: [], mentioned: [] });
  delete dataFirst.meta;
  delete dataSecond.meta;
  assert.deepEqual(dataFirst, dataSecond);
  assert.equal(withoutMetaText(rawFirst), withoutMetaText(rawSecond));
  assert.equal(
    withoutMetaText(rawFirst).includes(JSON.stringify(fixture.root).slice(1, -1)),
    false,
    "no absolute path of this machine outside meta",
  );
});

test("tools with a scope: a config at the root of another layer counts when that layer has a package.json, and one without it does not", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "packages/api/package.json": packageJson({ name: "api" }),
      "packages/api/eslint.config.js": "export default [];\n",
      "packages/api/src/tsconfig.json": "{}\n",
      "packages/tools/eslint.config.js": "export default [];\n",
      "apps/web/package.json": packageJson({ name: "web" }),
      "apps/web/src/index.ts": "export {};\n",
    },
  });
  const result = await scopedVerificationScan(fixture, ["apps/web"]);

  assert.deepEqual(result.verification.packages, [
    { path: "apps/web/package.json", where: "scope", status: "ok", commands: [] },
    { path: "packages/api/package.json", where: "other", status: "ok", commands: [] },
  ]);
  assert.deepEqual(result.structure.enforcementTools, [{ tool: "eslint", path: "packages/api/eslint.config.js" }]);
  // Positive control: without a scope the other layers are not read, and their configs are not listed.
  const unscoped = await verificationScan(fixture);
  assert.deepEqual(unscoped.structure.enforcementTools, []);
});
