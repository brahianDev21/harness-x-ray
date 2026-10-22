// Tests of lib/run-io.mjs: the reader of one JSON input of a run, the test of a name, and the writer of several output files as one
// step. Each test works in a temp fixture, which it removes.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { describe, test } from "node:test";
import { exists, readRunJson, writeRunFiles } from "../scripts/lib/run-io.mjs";
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";

const linkSupport = symlinkSupport();

// The files of a folder that are temporary names of this module, which must never be left behind.
function leftoverTemps(dir) {
  return fs.readdirSync(dir).filter((name) => name.endsWith(".tmp"));
}

describe("readRunJson", () => {
  test("reads a regular JSON file, and only that file's text is parsed (positive control)", (t) => {
    const fixture = makeFixture({ files: { "measurements.json": '{"meta": {"tool": "x"}}\n' } });
    t.after(fixture.cleanup);
    assert.deepEqual(readRunJson(path.join(fixture.root, "measurements.json")), { meta: { tool: "x" } });
  });

  test("a missing file, a file that is not JSON and a folder are usage errors, and the messages name the path only", (t) => {
    const fixture = makeFixture({ files: { "broken.json": "{ this is not json SECRET-LIKE-TEXT", "dir/x.txt": "x" } });
    t.after(fixture.cleanup);
    const missing = path.join(fixture.root, "missing.json");
    assert.throws(() => readRunJson(missing), (error) => error.message === `missing input file: ${missing}`);
    const broken = path.join(fixture.root, "broken.json");
    assert.throws(
      () => readRunJson(broken),
      (error) => error.message === `input file is not valid JSON: ${broken}` && !error.message.includes("SECRET-LIKE"),
    );
    assert.throws(() => readRunJson(path.join(fixture.root, "dir")), /is not a regular file/);
  });

  test("a symbolic link is refused, and so is a hard link", (t) => {
    const fixture = makeFixture({ files: { "real.json": "{}\n" } });
    t.after(fixture.cleanup);
    const real = path.join(fixture.root, "real.json");
    fs.linkSync(real, path.join(fixture.root, "second.json"));
    assert.throws(() => readRunJson(real), /more than one hard link/);
    if (!linkSupport.supported) return;
    fs.symlinkSync(real, path.join(fixture.root, "link.json"));
    assert.throws(() => readRunJson(path.join(fixture.root, "link.json")), /is not a regular file/);
  });

  test("a file larger than maxBytes is refused before it is read, and a file of exactly maxBytes is read (positive control)", (t) => {
    const fixture = makeFixture({ files: { "big.json": `{${" ".repeat(100)}}\n` } });
    t.after(fixture.cleanup);
    const file = path.join(fixture.root, "big.json");
    const size = fs.statSync(file).size;
    assert.throws(() => readRunJson(file, { maxBytes: size - 1 }), (error) => /larger than \d+ bytes/.test(error.message));
    assert.deepEqual(readRunJson(file, { maxBytes: size }), {});
    assert.deepEqual(readRunJson(file), {}, "without a cap, the file is read");
  });
});

describe("exists", () => {
  test("a name that exists is true, and a missing name is false (positive control)", (t) => {
    const fixture = makeFixture({ files: { "here.txt": "x\n", "dir/inside.txt": "y\n" } });
    t.after(fixture.cleanup);
    assert.equal(exists(path.join(fixture.root, "here.txt")), true);
    assert.equal(exists(path.join(fixture.root, "dir")), true);
    assert.equal(exists(path.join(fixture.root, "missing.txt")), false);
  });

  test("a dangling symbolic link exists as itself", (t) => {
    if (!linkSupport.supported) return t.skip(linkSupport.reason);
    const fixture = makeFixture({ files: { "placeholder.txt": "x\n" } });
    t.after(fixture.cleanup);
    fs.symlinkSync(path.join(fixture.root, "nowhere.json"), path.join(fixture.root, "dangling.json"));
    assert.equal(exists(path.join(fixture.root, "dangling.json")), true);
  });
});

describe("writeRunFiles", () => {
  test("writes every output, and leaves no temporary name behind (positive control)", (t) => {
    const fixture = makeFixture({ files: { "run/old.txt": "old\n" } });
    t.after(fixture.cleanup);
    const dir = path.join(fixture.root, "run");
    writeRunFiles(dir, [
      { name: "a.json", text: "{}\n" },
      { name: "b.md", text: "# b\n" },
    ]);
    assert.equal(fs.readFileSync(path.join(dir, "a.json"), "utf8"), "{}\n");
    assert.equal(fs.readFileSync(path.join(dir, "b.md"), "utf8"), "# b\n");
    assert.equal(fs.readFileSync(path.join(dir, "old.txt"), "utf8"), "old\n", "other files are not touched");
    assert.deepEqual(leftoverTemps(dir), []);
  });

  test("an existing output with the same name is replaced", (t) => {
    const fixture = makeFixture({ files: { "run/a.json": "old\n" } });
    t.after(fixture.cleanup);
    const dir = path.join(fixture.root, "run");
    writeRunFiles(dir, [{ name: "a.json", text: "new\n" }]);
    assert.equal(fs.readFileSync(path.join(dir, "a.json"), "utf8"), "new\n");
  });

  test("a failure while the temporary files are written removes them, and no final name is written", (t) => {
    const fixture = makeFixture({ files: { "run/keep.txt": "keep\n" } });
    t.after(fixture.cleanup);
    const dir = path.join(fixture.root, "run");
    // A name too long for a file name: the temporary name made from it is too long too, so its open fails after the first output.
    const tooLong = `${"x".repeat(300)}.json`;
    assert.throws(() =>
      writeRunFiles(dir, [
        { name: "ok.json", text: "{}\n" },
        { name: tooLong, text: "{}\n" },
      ]),
    );
    assert.deepEqual(fs.readdirSync(dir).sort(), ["keep.txt"], "no final name and no temporary name is left");
  });

  test("a name with a folder part, an empty name, or . or .. is a TypeError, and nothing is written", (t) => {
    const fixture = makeFixture({ files: { "run/keep.txt": "keep\n" } });
    t.after(fixture.cleanup);
    const dir = path.join(fixture.root, "run");
    for (const name of ["missing-folder/x.json", "a\\b.json", "", ".", ".."]) {
      assert.throws(
        () => writeRunFiles(dir, [{ name: "ok.json", text: "{}\n" }, { name, text: "{}\n" }]),
        (error) => error instanceof TypeError && /plain file name/.test(error.message),
        JSON.stringify(name),
      );
    }
    assert.deepEqual(fs.readdirSync(dir).sort(), ["keep.txt"], "the first output is not written when a later name is refused");
    writeRunFiles(dir, [{ name: "ok.json", text: "{}\n" }]);
    assert.equal(fs.readFileSync(path.join(dir, "ok.json"), "utf8"), "{}\n", "positive control: a plain name is written");
  });

  test("a failure during the renames removes the temporary files not yet renamed, and keeps the ones renamed", (t) => {
    const fixture = makeFixture({ files: { "run/blocked/inside.txt": "x\n" } });
    t.after(fixture.cleanup);
    const dir = path.join(fixture.root, "run");
    // A folder cannot be replaced by a file, so the second rename fails after the first one succeeded.
    assert.throws(() =>
      writeRunFiles(dir, [
        { name: "first.json", text: "{}\n" },
        { name: "blocked", text: "{}\n" },
      ]),
    );
    assert.equal(fs.readFileSync(path.join(dir, "first.json"), "utf8"), "{}\n", "the rename before the failure stays");
    assert.ok(fs.statSync(path.join(dir, "blocked")).isDirectory(), "the folder is untouched");
    assert.deepEqual(leftoverTemps(dir), []);
  });
});
