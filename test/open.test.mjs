import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import { main } from "../scripts/open.mjs";

// The command line of scripts/open.mjs, through main() with an injected opener: nothing here starts a command or a
// browser. The one spawned process runs with no argument, which is refused before anything could be executed, and it
// shows that the entry-point guard runs main. The .html file is in a unique subfolder of the real runs/ folder
// (git-ignored), removed afterwards together with runs/ when this file created it and it is then empty.
const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RUNS = path.join(HARNESS_ROOT, "runs");
const OPEN = path.join(HARNESS_ROOT, "scripts", "open.mjs");
const LINUX_GUI = { platform: "linux", env: { DISPLAY: ":0" } };

let createdRuns = false;
let folder;
let outsideDir;

before(() => {
  createdRuns = !fs.existsSync(RUNS);
  fs.mkdirSync(RUNS, { recursive: true });
  folder = fs.mkdtempSync(path.join(RUNS, "open-cli-test-"));
  outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-open-cli-"));
});

after(() => {
  fs.rmSync(folder, { recursive: true, force: true });
  fs.rmSync(outsideDir, { recursive: true, force: true });
  if (createdRuns && fs.readdirSync(RUNS).length === 0) fs.rmdirSync(RUNS);
});

// An injected opener that records each call and never runs anything.
function recorder() {
  const calls = [];
  const exec = async (file, args, options) => {
    calls.push({ file, args, options });
  };
  return { exec, calls };
}

// Collects what main prints, so that the test output stays clean.
function captureConsole(t) {
  const out = [];
  const err = [];
  t.mock.method(console, "log", (...parts) => out.push(parts.join(" ")));
  t.mock.method(console, "error", (...parts) => err.push(parts.join(" ")));
  return { out, err };
}

test("an .html file inside runs/ is opened through the injected opener: exit 0 and one recorded call", async (t) => {
  const { out } = captureConsole(t);
  const file = path.join(folder, "page.html");
  fs.writeFileSync(file, "<!doctype html>\n");
  const rec = recorder();

  const code = await main([file], { exec: rec.exec, ...LINUX_GUI });
  assert.equal(code, 0);
  assert.deepEqual(rec.calls.map((call) => [call.file, call.args]), [["xdg-open", [fs.realpathSync.native(file)]]]);
  assert.equal(rec.calls[0].options.shell, false);
  assert.equal(out.length, 1);
  assert.match(out[0], /^opened /);
});

test("the refused inputs exit 2 with a message, and the injected opener is never called", async (t) => {
  const { err } = captureConsole(t);
  const rec = recorder();
  const outsideFile = path.join(outsideDir, "outside.html");
  fs.writeFileSync(outsideFile, "<!doctype html>\n");
  const htm = path.join(folder, "old.htm");
  fs.writeFileSync(htm, "<!doctype html>\n");

  const refused = [
    [[], "expected exactly one file or URL"],
    [["a.html", "b.html"], "expected exactly one file or URL"],
    [["--bogus", "a.html"], "Unknown option"],
    [[outsideFile], "refused: file must be inside runs/"],
    [["https://example.com/"], "refused: not a local intake URL"],
    [[htm], "refused: not an .html file"],
  ];
  for (const [argv, text] of refused) {
    err.length = 0;
    const code = await main(argv, { exec: rec.exec, ...LINUX_GUI });
    assert.equal(code, 2, JSON.stringify(argv));
    assert.ok(err.join("\n").includes(text), `${JSON.stringify(argv)}: expected "${text}" in ${JSON.stringify(err)}`);
  }
  assert.equal(rec.calls.length, 0, "no refused input reaches the opener");
});

test("run as the entry point, the script reads its arguments: no argument exits 2 with the usage line", () => {
  const result = spawnSync(process.execPath, [OPEN], { encoding: "utf8", timeout: 30000 });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /usage: node scripts\/open\.mjs <file\|url>/);
  assert.equal(result.stdout, "");
});
