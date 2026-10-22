import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { makeFixture } from "./helpers/make-fixture.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const MAP_SCRIPT = path.join(HARNESS_ROOT, "scripts", "map.mjs");

// Runs the command line through execFile (never a shell). Resolves with the exit code and both streams.
async function runMap(args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [MAP_SCRIPT, ...args], {
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

// Every entry below a folder, as sorted relative paths with a trailing slash for folders. Links are not followed.
function snapshotOf(dir, prefix = "") {
  const entries = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = `${prefix}${entry.name}`;
    if (entry.isDirectory()) {
      entries.push(`${rel}/`, ...snapshotOf(path.join(dir, entry.name), `${rel}/`));
    } else {
      entries.push(rel);
    }
  }
  return entries.sort();
}

function freshTarget(t) {
  const fixture = makeFixture({
    files: {
      "package.json": JSON.stringify({ name: "demo", workspaces: ["packages/*"] }),
      "packages/a/package.json": '{"name":"a"}\n',
      "src/index.js": "export const x = 1;\n",
    },
  });
  t.after(fixture.cleanup);
  return fixture;
}

test("map: a copy of a fixture exits 0, writes only layers.json to --out, and leaves the target as it was", async (t) => {
  const fixture = freshTarget(t);
  const out = path.join(fixture.base, "out");
  const before = snapshotOf(fixture.root);

  const result = await runMap([fixture.root, "--out", out]);

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.equal(result.stdout, `layers: ${path.join(out, "layers.json")}\n`);
  assert.deepEqual(fs.readdirSync(out), ["layers.json"], "only layers.json is written");
  const layers = JSON.parse(fs.readFileSync(path.join(out, "layers.json"), "utf8"));
  assert.equal(layers.schemaVersion, 1);
  assert.equal(layers.meta.targetRoot, fs.realpathSync.native(fixture.root));
  assert.deepEqual(
    layers.units.map((unit) => unit.path),
    [".", "packages", "packages/a"],
  );
  assert.deepEqual(snapshotOf(fixture.root), before, "nothing is written into the target");
});

test("map: a target inside harness-x-ray is refused with exit 2", async (t) => {
  const fixture = freshTarget(t);
  const out = path.join(fixture.base, "out");

  const result = await runMap([path.join(HARNESS_ROOT, "scripts"), "--out", out]);

  assert.equal(result.code, 2);
  assert.match(result.stderr, /target is harness-x-ray or lies inside it/);
  assert.equal(fs.existsSync(out), false, "no output folder is created");
});

test("map: a target that does not exist is refused with exit 2", async (t) => {
  const fixture = freshTarget(t);
  const out = path.join(fixture.base, "out");

  const result = await runMap([path.join(fixture.base, "missing"), "--out", out]);

  assert.equal(result.code, 2);
  assert.match(result.stderr, /target does not exist/);
  assert.equal(fs.existsSync(out), false);
});

test("map: an output folder outside runs/ and the temp folder is refused with exit 2", async (t) => {
  const fixture = freshTarget(t);
  const out = path.join(HARNESS_ROOT, "docs", "map-test-output");

  const result = await runMap([fixture.root, "--out", out]);

  assert.equal(result.code, 2);
  assert.match(result.stderr, /folder must be inside runs\/ or the system temp folder/);
  assert.equal(fs.existsSync(out), false, "nothing is created in the repository");
});

test("map: an output folder inside the target is refused with exit 2, and nothing is written into the target", async (t) => {
  const fixture = freshTarget(t);
  const before = snapshotOf(fixture.root);
  const out = path.join(fixture.root, "layers-out");

  const result = await runMap([fixture.root, "--out", out]);

  assert.equal(result.code, 2);
  assert.match(result.stderr, /output folder is inside the target/);
  assert.equal(fs.existsSync(out), false, "no output folder is created in the target");
  assert.deepEqual(snapshotOf(fixture.root), before, "the target is unchanged");
});

test("map: missing target, extra positionals and an empty --out are usage errors with exit 2", async (t) => {
  const fixture = freshTarget(t);

  const none = await runMap([]);
  assert.equal(none.code, 2);
  assert.match(none.stderr, /missing the target folder/);

  const two = await runMap([fixture.root, fixture.root, "--out", path.join(fixture.base, "out")]);
  assert.equal(two.code, 2);
  assert.match(two.stderr, /expected one target folder/);

  const empty = await runMap([fixture.root, "--out", ""]);
  assert.equal(empty.code, 2);
  assert.match(empty.stderr, /must not be empty/);
});
