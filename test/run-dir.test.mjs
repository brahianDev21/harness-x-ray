import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { checkRunDir, checkRunFile, runRoots } from "../scripts/lib/run-dir.mjs";
import { symlinkSupport } from "./helpers/make-fixture.mjs";

const support = symlinkSupport();
const symlinkSkip = support.supported ? false : support.reason;
const REFUSED = { name: "UsageError", message: /folder must be inside runs\// };

// Injected roots, so that runs/ and the temp folder never overlap:
//   base/h   the harness folder, with base/h/runs inside it
//   base/t   the temp folder
//   base/o   a folder outside both
let base;
let harness;
let runs;
let tempRoot;
let outside;

before(() => {
  base = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-run-dir-"));
  harness = path.join(base, "h");
  runs = path.join(harness, "runs");
  tempRoot = path.join(base, "t");
  outside = path.join(base, "o");
  for (const dir of [runs, tempRoot, outside]) fs.mkdirSync(dir, { recursive: true });
});

after(() => fs.rmSync(base, { recursive: true, force: true }));

// The check with the injected roots. Every call of this file goes through it.
function check(dir, options = {}) {
  return checkRunDir(dir, harness, { tempRoot, ...options });
}

// The real path of the runs folder, which exists, so that the expected values can be built from it.
function realRuns() {
  return fs.realpathSync.native(runs);
}

test("run roots: runs is the real harness folder joined with runs, and temp is the real temp folder", () => {
  assert.deepEqual(runRoots(harness, { tempRoot }), {
    runs: path.join(fs.realpathSync.native(harness), "runs"),
    temp: fs.realpathSync.native(tempRoot),
  });
  assert.equal(runRoots(harness).temp, fs.realpathSync.native(os.tmpdir()), "the default temp folder is os.tmpdir()");
});

test("a folder inside runs/ is allowed, whether it exists or not, and so is a folder inside the temp folder", () => {
  fs.mkdirSync(path.join(runs, "existing"));
  assert.equal(check(path.join(runs, "existing")), path.join(realRuns(), "existing"));
  assert.equal(check(path.join(runs, "later")), path.join(realRuns(), "later"));
  assert.equal(check(path.join(runs, "later", "deeper", "still")), path.join(realRuns(), "later", "deeper", "still"));

  assert.equal(check(path.join(tempRoot, "later")), path.join(fs.realpathSync.native(tempRoot), "later"));
});

test("the runs folder and the temp folder themselves are refused, and a folder inside runs/ is still allowed", () => {
  assert.throws(() => check(runs), REFUSED);
  assert.throws(() => check(tempRoot), REFUSED);
  assert.equal(check(path.join(runs, "x")), path.join(realRuns(), "x"));
});

test("a folder outside both places is refused, and so is a folder of the harness that is not in runs/", () => {
  assert.throws(() => check(path.join(outside, "x")), REFUSED);
  assert.throws(() => check(path.join(harness, "x")), REFUSED);
  assert.equal(check(path.join(runs, "x")), path.join(realRuns(), "x"));
  assert.equal(check(path.join(tempRoot, "x")), path.join(fs.realpathSync.native(tempRoot), "x"));
});

test("a path that climbs out of runs/ with .. is refused", () => {
  const climbing = `${runs}${path.sep}..${path.sep}..${path.sep}o${path.sep}x`;
  assert.throws(() => check(climbing), REFUSED);
  assert.equal(check(path.join(runs, "x")), path.join(realRuns(), "x"));
});

test("a name that only starts with runs is refused, and a folder inside runs/ is allowed", () => {
  assert.throws(() => check(path.join(harness, "runs-evil", "x")), REFUSED);
  assert.equal(check(path.join(runs, "x")), path.join(realRuns(), "x"));
});

test("a link inside runs/ that points outside is refused, also with missing folders below it", { skip: symlinkSkip }, () => {
  fs.symlinkSync(outside, path.join(runs, "evil"), "dir");
  assert.throws(() => check(path.join(runs, "evil")), REFUSED);
  assert.throws(() => check(path.join(runs, "evil", "missing", "sub")), REFUSED);

  // Positive control: a link that stays inside runs/ is followed and allowed.
  fs.mkdirSync(path.join(runs, "ok"));
  fs.symlinkSync(path.join(runs, "ok"), path.join(runs, "inside-link"), "dir");
  assert.equal(check(path.join(runs, "inside-link")), path.join(realRuns(), "ok"));
  assert.equal(check(path.join(runs, "ok", "missing", "sub")), path.join(realRuns(), "ok", "missing", "sub"));
});

test("a broken link inside runs/ is refused, and so is a missing folder below it or a loop of links", { skip: symlinkSkip }, () => {
  fs.symlinkSync(path.join(outside, "missing"), path.join(runs, "broken"), "dir");
  const broken = { name: "UsageError", message: /broken symbolic link/ };
  assert.throws(() => check(path.join(runs, "broken")), broken);
  assert.throws(() => check(path.join(runs, "broken", "sub")), broken);

  fs.symlinkSync(path.join(runs, "loop-b"), path.join(runs, "loop-a"), "dir");
  fs.symlinkSync(path.join(runs, "loop-a"), path.join(runs, "loop-b"), "dir");
  assert.throws(() => check(path.join(runs, "loop-a")), broken);

  // Positive control: a normal folder next to them is allowed.
  assert.equal(check(path.join(runs, "ok")), path.join(realRuns(), "ok"));
});

test("a runs folder that is a link elsewhere is refused, and the real runs folder is allowed", { skip: symlinkSkip }, () => {
  const other = path.join(base, "h2");
  fs.mkdirSync(other);
  fs.symlinkSync(outside, path.join(other, "runs"), "dir");

  assert.throws(() => checkRunDir(path.join(other, "runs", "x"), other, { tempRoot }), REFUSED);
  assert.equal(check(path.join(runs, "x")), path.join(realRuns(), "x"));
});

test("with allowTemp false, the temp folder is refused, and runs/ is still allowed", () => {
  assert.throws(
    () => check(path.join(tempRoot, "x"), { allowTemp: false }),
    { name: "UsageError", message: /folder must be inside runs\/: / },
  );
  assert.equal(check(path.join(runs, "x"), { allowTemp: false }), path.join(realRuns(), "x"));
});

test("with allowTemp false, the temp folder is never resolved", (t) => {
  const resolved = [];
  const native = fs.realpathSync.native;
  t.mock.method(fs.realpathSync, "native", (target, ...rest) => {
    resolved.push(String(target));
    return native(target, ...rest);
  });
  const inTemp = (target) => target === tempRoot || target.startsWith(tempRoot + path.sep);

  check(path.join(runs, "x"), { allowTemp: false });
  assert.equal(resolved.some(inTemp), false, "the temp folder is not resolved when it is not allowed");

  // Positive control: the same spy sees the temp folder when it is allowed.
  check(path.join(tempRoot, "x"));
  assert.equal(resolved.some(inTemp), true);
});

test("a missing temp folder is no base: runs/ is still allowed, and a folder under the missing name is refused", () => {
  const missing = path.join(base, "missing-temp");
  assert.equal(runRoots(harness, { tempRoot: missing }).temp, null);
  assert.equal(check(path.join(runs, "x"), { tempRoot: missing }), path.join(realRuns(), "x"));
  assert.throws(() => check(path.join(missing, "x"), { tempRoot: missing }), REFUSED);
  assert.equal(fs.existsSync(missing), false, "the missing temp folder is not created");
});

test("a folder of the harness that is not in runs/ is refused, also when the temp folder contains the harness", () => {
  // base is the temp folder in these calls, so it contains the harness folder.
  const withBaseAsTemp = (dir) => checkRunDir(dir, harness, { tempRoot: base });
  for (const dir of [path.join(harness, "scripts", "x"), path.join(harness, ".claude", "x")]) {
    assert.throws(() => withBaseAsTemp(dir), REFUSED);
    assert.equal(fs.existsSync(dir), false, "a refused folder is not created");
  }

  // Positive controls: a folder below runs/, and a folder of the temp folder outside the harness.
  assert.equal(withBaseAsTemp(path.join(runs, "x")), path.join(realRuns(), "x"));
  assert.equal(withBaseAsTemp(path.join(base, "other", "x")), path.join(fs.realpathSync.native(base), "other", "x"));
});

test("a path that exists and is not a folder is refused as not a folder, and a folder is still allowed", () => {
  const file = path.join(runs, "plain-file");
  fs.writeFileSync(file, "keep\n");
  const notFolder = { name: "UsageError", message: /^not a folder: / };
  assert.throws(() => check(file), notFolder);
  assert.throws(() => check(path.join(file, "x")), notFolder);
  assert.equal(fs.readFileSync(file, "utf8"), "keep\n", "the file is left alone");

  // Positive control: a folder next to it is allowed.
  fs.mkdirSync(path.join(runs, "plain-folder"));
  assert.equal(check(path.join(runs, "plain-folder")), path.join(realRuns(), "plain-folder"));
});

test("checkRunFile accepts a missing file and a regular file", () => {
  const dir = path.join(runs, "files");
  fs.mkdirSync(dir);
  const file = path.join(dir, "report.md");
  assert.doesNotThrow(() => checkRunFile(file));
  fs.writeFileSync(file, "older\n");
  assert.doesNotThrow(() => checkRunFile(file));
});

test("checkRunFile refuses a link and a folder, and the file that the link points to is left alone", { skip: symlinkSkip }, () => {
  const dir = path.join(runs, "linked");
  fs.mkdirSync(dir);
  const target = path.join(outside, "keep.md");
  fs.writeFileSync(target, "keep\n");
  fs.symlinkSync(target, path.join(dir, "report.md"), "file");
  assert.throws(() => checkRunFile(path.join(dir, "report.md")), { name: "UsageError", message: /not a regular file/ });
  assert.equal(fs.readFileSync(target, "utf8"), "keep\n");

  const folder = path.join(runs, "folder-report");
  fs.mkdirSync(path.join(folder, "report.md"), { recursive: true });
  assert.throws(() => checkRunFile(path.join(folder, "report.md")), { name: "UsageError", message: /not a regular file/ });

  // Positive control: a regular file next to them is accepted.
  fs.writeFileSync(path.join(dir, "plain.md"), "plain\n");
  assert.doesNotThrow(() => checkRunFile(path.join(dir, "plain.md")));
});

test("checkRunFile refuses a hard link to a file outside, and that file is left alone", (t) => {
  const dir = path.join(tempRoot, "hard");
  fs.mkdirSync(dir, { recursive: true });
  const target = path.join(outside, "shared.md");
  fs.writeFileSync(target, "shared\n");
  const link = path.join(dir, "report.md");
  try {
    fs.linkSync(target, link);
  } catch (error) {
    t.skip(`hard links are not supported here: ${error.code}`);
    return;
  }
  assert.throws(() => checkRunFile(link), { name: "UsageError", message: /more than one hard link/ });
  assert.equal(fs.readFileSync(target, "utf8"), "shared\n");

  // Positive control: a regular file with one name, next to the hard link, is accepted.
  fs.writeFileSync(path.join(dir, "plain.md"), "plain\n");
  assert.doesNotThrow(() => checkRunFile(path.join(dir, "plain.md")));
});

test("checkRunFile with harnessRoot refuses a file outside the allowed places, and the temp folder when allowTemp is false", () => {
  const dir = path.join(runs, "location");
  fs.mkdirSync(dir);
  const inRuns = path.join(dir, "a.md");
  fs.writeFileSync(inRuns, "a\n");
  const outsideFile = path.join(outside, "b.md");
  fs.writeFileSync(outsideFile, "b\n");
  const tempFile = path.join(tempRoot, "c.md");
  fs.writeFileSync(tempFile, "c\n");
  const harnessFile = path.join(harness, "d.md");
  fs.writeFileSync(harnessFile, "d\n");
  const refused = { name: "UsageError", message: /file must be inside runs\/: / };
  const onlyRuns = { harnessRoot: harness, tempRoot, allowTemp: false };

  assert.throws(() => checkRunFile(outsideFile, onlyRuns), refused);
  assert.throws(() => checkRunFile(tempFile, onlyRuns), refused);
  assert.throws(() => checkRunFile(harnessFile, onlyRuns), refused);
  assert.throws(() => checkRunFile(path.join(outside, "missing.md"), onlyRuns), refused, "a missing file outside is refused too");

  // Positive controls: a file inside runs/ is accepted, the temp folder is accepted when allowTemp is true,
  // and without harnessRoot no location is checked, as before the option existed.
  assert.doesNotThrow(() => checkRunFile(inRuns, onlyRuns));
  assert.doesNotThrow(() => checkRunFile(tempFile, { harnessRoot: harness, tempRoot }));
  assert.doesNotThrow(() => checkRunFile(outsideFile));
  assert.equal(fs.readFileSync(outsideFile, "utf8"), "b\n", "the refused file is left alone");
});

test("checkRunFile with harnessRoot refuses a link inside runs/ that points outside, and keeps the link check", { skip: symlinkSkip }, () => {
  const dir = path.join(runs, "location-links");
  fs.mkdirSync(dir);
  const target = path.join(outside, "keep-linked.md");
  fs.writeFileSync(target, "keep\n");
  fs.symlinkSync(target, path.join(dir, "link.md"), "file");
  const onlyRuns = { harnessRoot: harness, tempRoot, allowTemp: false };
  assert.throws(() => checkRunFile(path.join(dir, "link.md"), onlyRuns), { name: "UsageError", message: /file must be inside runs\// });
  assert.equal(fs.readFileSync(target, "utf8"), "keep\n");

  // Positive control: a regular file inside runs/ next to the link is accepted.
  fs.writeFileSync(path.join(dir, "plain.md"), "plain\n");
  assert.doesNotThrow(() => checkRunFile(path.join(dir, "plain.md"), onlyRuns));
});
