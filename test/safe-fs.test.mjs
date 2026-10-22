import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { DEFAULT_MAX_BYTES, createTargetFs, statOutside } from "../scripts/lib/safe-fs.mjs";
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";

const support = symlinkSupport();
const symlinkSkip = support.supported ? false : support.reason;
const isWindows = process.platform === "win32";

// Content of the file outside the root. No test may let it appear in a result or a warning.
const SECRET = "SECRET-VALUE outside the root\n";

/** Fixture with the secret in <base>/outside and the target opened over <base>/repo. */
function openFixture(t, description = {}) {
  const fixture = makeFixture({
    ...description,
    outside: { "secret.txt": SECRET, ...description.outside },
  });
  t.after(fixture.cleanup);
  return { fixture, target: createTargetFs(fixture.root) };
}

function assertNoSecret(...values) {
  assert.equal(JSON.stringify(values).includes("SECRET-VALUE"), false, "the outside secret leaked");
}

// Absolute folders of the fixture must not appear in results or warnings built from relative input.
function assertNoAbsolutePaths(fixture, value) {
  const dump = JSON.stringify(value);
  const folders = [fixture.base, fixture.root, fixture.outsideDir, fs.realpathSync.native(fixture.base)];
  for (const folder of folders) {
    assert.equal(dump.includes(JSON.stringify(folder).slice(1, -1)), false, "an absolute fixture path leaked");
  }
}

// A folder link inside the root must be refused by every method that could reach the outside folder.
function assertFolderLinkRefused(target, link) {
  assert.equal(target.readText(`${link}/secret.txt`).reason, "outside-root");
  assert.equal(target.stat(`${link}/secret.txt`).reason, "outside-root");
  assert.equal(target.listDir(link).reason, "outside-root");
  assert.equal(target.stat(link).reason, "outside-root");
  assert.equal(target.exists(`${link}/secret.txt`), false);
  assert.equal(target.exists(link), false);
}

test("hostile-symlink: a file symlink in the root that points outside is refused, and its content never appears", { skip: symlinkSkip }, (t) => {
  const { fixture, target } = openFixture(t, {
    symlinks: [{ path: "CLAUDE.md", target: "../outside/secret.txt" }],
  });

  const read = target.readText("CLAUDE.md");
  const stat = target.stat("CLAUDE.md");
  assert.deepEqual(read, { ok: false, path: "CLAUDE.md", reason: "outside-root" });
  assert.equal(stat.reason, "outside-root");
  assert.equal(target.exists("CLAUDE.md"), false);
  assert.deepEqual(target.warnings(), [{ path: "CLAUDE.md", reason: "outside-root" }]);
  assertNoSecret(read, stat, target.warnings());
  assertNoAbsolutePaths(fixture, target.warnings());
});

test("hostile-symlink: a folder symlink in the root cannot be used to read, list or stat outside", { skip: symlinkSkip }, (t) => {
  const { fixture, target } = openFixture(t, {
    files: { "notes/inside.txt": "inside\n" },
    symlinks: [{ path: "linked", target: "../outside", type: "dir" }],
  });

  assertFolderLinkRefused(target, "linked");
  // Listing the root does not follow the link: the entry is reported as a symlink.
  assert.deepEqual(target.listDir(".").entries, [
    { name: "linked", type: "symlink" },
    { name: "notes", type: "dir" },
  ]);
  assertNoSecret(target.warnings());
  assertNoAbsolutePaths(fixture, target.warnings());
});

test("hostile-symlink: a junction to a folder outside the root is refused (Windows, needs no privileges)", {
  skip: isWindows ? false : "junctions are a Windows feature; the folder symlink test covers other systems",
}, (t) => {
  const { fixture, target } = openFixture(t, {
    symlinks: [{ path: "linked-junction", target: "../outside", type: "junction" }],
  });

  assertFolderLinkRefused(target, "linked-junction");
  assert.deepEqual(target.listDir(".").entries, [{ name: "linked-junction", type: "symlink" }]);
  assertNoSecret(target.warnings());
  assertNoAbsolutePaths(fixture, target.warnings());
});

test("a link to a sibling folder whose name starts with the root's name is refused", { skip: symlinkSkip }, (t) => {
  const { fixture, target } = openFixture(t);
  // Root is <base>/repo; the sibling <base>/repo-evil shares its prefix.
  const sibling = path.join(fixture.base, "repo-evil");
  fs.mkdirSync(sibling);
  fs.writeFileSync(path.join(sibling, "secret.txt"), "SECRET-VALUE in a sibling folder\n");
  fs.symlinkSync(sibling, path.join(fixture.root, "evil-link"), "dir");

  assertFolderLinkRefused(target, "evil-link");
  assertNoSecret(target.warnings());
});

test("a symlink that stays inside the root is followed and read", { skip: symlinkSkip }, (t) => {
  const { target } = openFixture(t, {
    files: { "notes/real.txt": "real\n" },
    symlinks: [
      { path: "alias.txt", target: "notes/real.txt" },
      { path: "alias-dir", target: "notes", type: "dir" },
    ],
  });

  assert.deepEqual(target.readText("alias.txt"), { ok: true, path: "alias.txt", text: "real\n", bytes: 5 });
  assert.equal(target.readText("alias-dir/real.txt").text, "real\n");
  assert.equal(target.stat("alias.txt").type, "file");
  assert.equal(target.exists("alias-dir"), true);
  assert.deepEqual(target.warnings(), []);
});

test("resolve returns the real place of a link inside the root, and refuses a link that leaves it (positive control first)", { skip: symlinkSkip }, (t) => {
  const { target } = openFixture(t, {
    files: { "notes/real.txt": "real\n", "plain.txt": "plain\n" },
    symlinks: [
      { path: "alias.txt", target: "notes/real.txt" },
    ],
  });
  assert.deepEqual(target.resolve("plain.txt"), { ok: true, path: "plain.txt", target: "plain.txt" });
  assert.deepEqual(target.resolve("alias.txt"), { ok: true, path: "alias.txt", target: "notes/real.txt" });
  assert.equal(target.resolve("missing.txt").ok, false);
});

test("resolve refuses a link to a file outside the root with outside-root, and its content never appears", { skip: symlinkSkip }, (t) => {
  const { target } = openFixture(t, { symlinks: [{ path: "escape.txt", target: "../outside/secret.txt" }] });
  const resolved = target.resolve("escape.txt");
  assert.deepEqual(resolved, { ok: false, path: "escape.txt", reason: "outside-root" });
  assertNoSecret(resolved, target.warnings());
});

test("dangling and looping links are skipped without throwing", { skip: symlinkSkip }, (t) => {
  const { target } = openFixture(t, {
    symlinks: [
      { path: "dangling.txt", target: "missing.txt" },
      { path: "loop-a.txt", target: "loop-b.txt" },
      { path: "loop-b.txt", target: "loop-a.txt" },
    ],
  });

  const dangling = target.readText("dangling.txt");
  assert.deepEqual(dangling, { ok: false, path: "dangling.txt", reason: "not-found" });
  assert.equal(target.exists("dangling.txt"), false);

  const loop = target.readText("loop-a.txt");
  assert.equal(loop.ok, false);
  // The loop may be reported as not-found or read-error, depending on the operating system.
  assert.ok(["not-found", "read-error"].includes(loop.reason), `unexpected reason: ${loop.reason}`);
  assert.equal(target.exists("loop-a.txt"), false);
  assertNoSecret(dangling, loop, target.warnings());
});

test("a .. that follows a folder link is resolved lexically, so the read stays inside the root", { skip: symlinkSkip }, (t) => {
  const { target } = openFixture(t, {
    files: { "keep.txt": "keep\n" },
    symlinks: [{ path: "linked", target: "../outside", type: "dir" }],
  });

  const result = target.readText("linked/../keep.txt");
  assert.deepEqual(result, { ok: true, path: "keep.txt", text: "keep\n", bytes: 5 });
  assertNoSecret(result);
});

test("relative paths that leave the root are refused as outside-root", (t) => {
  const { fixture, target } = openFixture(t, { files: { "nested/keep.txt": "keep\n" } });
  const refused = [
    "../outside/secret.txt",
    "..\\outside\\secret.txt",
    "nested/../../outside/secret.txt",
    "nested\\..\\..\\outside\\secret.txt",
    "..",
    "../outside",
    ".. /outside/secret.txt", // Windows drops the trailing space, so this is the parent folder too.
    "C:secret.txt",
    "C:outside\\secret.txt",
    "C:/outside/secret.txt",
    "\\\\server\\share\\secret.txt",
    "//server/share/secret.txt",
    "\\\\?\\C:\\secret.txt",
    "\\\\.\\pipe\\secret",
    "\\rooted.txt",
    "/rooted.txt",
  ];

  for (const rel of refused) {
    assert.equal(target.readText(rel).reason, "outside-root", `readText(${JSON.stringify(rel)})`);
    assert.equal(target.stat(rel).reason, "outside-root", `stat(${JSON.stringify(rel)})`);
    assert.equal(target.exists(rel), false, `exists(${JSON.stringify(rel)})`);
  }
  for (const rel of ["..", "../outside"]) {
    assert.equal(target.listDir(rel).reason, "outside-root", `listDir(${JSON.stringify(rel)})`);
  }
  assertNoAbsolutePaths(fixture, target.warnings());
  assertNoSecret(target.warnings());
});

test("absolute paths to the outside file are refused in both separator forms", (t) => {
  const { fixture, target } = openFixture(t);
  const secret = path.join(fixture.outsideDir, "secret.txt");
  const forms = [secret, secret.replaceAll("\\", "/"), secret.replaceAll("/", "\\")];

  const results = forms.map((abs) => target.readText(abs));
  for (const [index, result] of results.entries()) {
    assert.equal(result.reason, "outside-root", forms[index]);
  }
  assert.equal(target.stat(forms[0]).reason, "outside-root");
  assert.equal(target.exists(forms[1]), false);
  assertNoSecret(results, target.warnings());
});

test("absolute paths are refused even when they point inside the root, because callers pass relative paths", (t) => {
  const { fixture, target } = openFixture(t, { files: { "nested/keep.txt": "keep\n" } });
  assert.equal(target.readText(path.join(fixture.root, "nested", "keep.txt")).reason, "outside-root");
});

test("paths are normalized, and a name that starts with two dots is not a parent folder", (t) => {
  const { target } = openFixture(t, { files: { "nested/keep.txt": "keep\n", "..notes.txt": "dots\n" } });

  for (const rel of ["./nested//keep.txt", "nested\\keep.txt", "nested/../nested/keep.txt"]) {
    assert.deepEqual(target.readText(rel), { ok: true, path: "nested/keep.txt", text: "keep\n", bytes: 5 }, rel);
  }
  assert.deepEqual(target.readText("..notes.txt"), { ok: true, path: "..notes.txt", text: "dots\n", bytes: 5 });
  assert.deepEqual(target.warnings(), []);
});

test("a root given through a symlink is resolved once and used as the containment base", { skip: symlinkSkip }, (t) => {
  const fixture = makeFixture({ files: { "inside.txt": "in\n" } });
  t.after(fixture.cleanup);
  const alias = path.join(fixture.base, "alias");
  fs.symlinkSync(fixture.root, alias, "dir");

  const target = createTargetFs(alias);
  assert.equal(target.readText("inside.txt").text, "in\n");
  assert.equal(target.readText("../repo/inside.txt").reason, "outside-root");
});

test("binary files are refused when a NUL byte is in the first 8 KB", (t) => {
  const { target } = openFixture(t, {
    files: {
      "nul-first.bin": Buffer.from([0x00, 0x41]),
      "nul-last-in-window.bin": Buffer.concat([Buffer.alloc(8191, 0x41), Buffer.from([0x00])]),
    },
  });

  assert.deepEqual(target.readText("nul-first.bin"), { ok: false, path: "nul-first.bin", reason: "binary" });
  assert.equal(target.readText("nul-last-in-window.bin").reason, "binary");
});

test("a NUL after the first 8 KB is not flagged as binary (the scan window is fixed at 8 KB)", (t) => {
  const content = Buffer.concat([Buffer.alloc(8192, 0x61), Buffer.from([0x00, 0x62, 0x0a])]);
  const { target } = openFixture(t, { files: { "late-nul.txt": content } });

  const result = target.readText("late-nul.txt");
  assert.equal(result.ok, true);
  assert.equal(result.bytes, 8192 + 3);
  assert.equal(result.text.includes("\0"), true);
});

test("files over maxBytes are too-large, and a file exactly at the cap is read", (t) => {
  const { target } = openFixture(t, {
    files: { "exact.txt": "x".repeat(16), "over.txt": "x".repeat(17), "empty.txt": "" },
  });

  assert.deepEqual(target.readText("exact.txt", { maxBytes: 16 }), {
    ok: true,
    path: "exact.txt",
    text: "x".repeat(16),
    bytes: 16,
  });
  const over = target.readText("over.txt", { maxBytes: 16 });
  assert.deepEqual(over, { ok: false, path: "over.txt", reason: "too-large" });
  assert.equal("text" in over, false, "a file over the cap must not be returned");
  assert.equal(target.readText("empty.txt", { maxBytes: 0 }).ok, true);
  assert.equal(target.readText("over.txt").ok, true, "the default cap is far above this file");
});

test("the default cap is 4 MiB: one byte over is too-large, and a file at the cap is read", (t) => {
  assert.equal(DEFAULT_MAX_BYTES, 4 * 1024 * 1024);
  const { target } = openFixture(t, {
    files: {
      "at-cap.txt": Buffer.alloc(DEFAULT_MAX_BYTES, 0x61),
      "over-cap.txt": Buffer.alloc(DEFAULT_MAX_BYTES + 1, 0x61),
    },
  });

  const atCap = target.readText("at-cap.txt");
  assert.equal(atCap.ok, true);
  assert.equal(atCap.bytes, DEFAULT_MAX_BYTES);
  assert.equal(target.readText("over-cap.txt").reason, "too-large");
});

test("a leading UTF-8 BOM is stripped and is not part of the text", (t) => {
  const { target } = openFixture(t, {
    files: { "bom.md": Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("# Title\n")]) },
  });

  assert.deepEqual(target.readText("bom.md"), { ok: true, path: "bom.md", text: "# Title\n", bytes: 11 });
});

test("CRLF, lone CR and mixed line endings give the line numbers an editor shows", (t) => {
  const { target } = openFixture(t, {
    files: {
      "crlf-windows/lines.md": "alpha\r\nbeta\r\ngamma\r\n",
      // Editor lines: one | two (lone CR) | three (LF) | four | blank | six (CR) | blank (CR) | seven.
      "mixed.md": "one\r\ntwo\rthree\nfour\r\n\r\nsix\r\rseven",
      // CR followed by CRLF is two line breaks: "p", a blank line, then "q".
      "cr-crlf.md": "p\r\r\nq",
    },
  });

  const crlf = target.readText("crlf-windows/lines.md");
  assert.equal(crlf.ok, true);
  assert.equal(crlf.bytes, Buffer.byteLength("alpha\r\nbeta\r\ngamma\r\n"));
  assert.equal(crlf.text.includes("\r"), false, "no CR may remain");
  assert.equal(crlf.text.split("\n")[2], "gamma", "line 3 is gamma, as in the editor");

  assert.deepEqual(target.readText("mixed.md").text.split("\n"), [
    "one", "two", "three", "four", "", "six", "", "seven",
  ]);
  assert.deepEqual(target.readText("cr-crlf.md").text.split("\n"), ["p", "", "q"]);
});

test("stat returns type and size without timestamps, and the root is a folder", (t) => {
  const { target } = openFixture(t, { files: { "notes/a.txt": "12345" } });

  assert.deepEqual(target.stat("notes/a.txt"), { ok: true, path: "notes/a.txt", type: "file", bytes: 5 });
  assert.deepEqual(target.stat("notes"), { ok: true, path: "notes", type: "dir", bytes: 0 });
  assert.deepEqual(target.stat(""), { ok: true, path: ".", type: "dir", bytes: 0 });
  assert.deepEqual(target.stat("."), { ok: true, path: ".", type: "dir", bytes: 0 });
  assert.deepEqual(target.stat("missing.txt"), { ok: false, path: "missing.txt", reason: "not-found" });
  assert.deepEqual(target.warnings(), [], "not-found is not recorded");
});

test("exists is true for files, folders and the root, and false for missing or refused entries", (t) => {
  const { target } = openFixture(t, { files: { "notes/a.txt": "a" } });

  assert.equal(target.exists("notes/a.txt"), true);
  assert.equal(target.exists("notes"), true);
  assert.equal(target.exists(""), true);
  assert.equal(target.exists("notes/missing.txt"), false);
  assert.equal(target.exists("notes/a.txt/child"), false);
});

test("listDir sorts by code unit order and reports types from lstat", (t) => {
  const { target } = openFixture(t, {
    // Names avoid case-only collisions, which Windows file systems would merge.
    files: { a: "", "B.txt": "", "Z.md": "", "a-b/inner.txt": "", "b.md": "", "é.md": "" },
  });

  assert.deepEqual(target.listDir(".").entries, [
    { name: "B.txt", type: "file" },
    { name: "Z.md", type: "file" },
    { name: "a", type: "file" },
    { name: "a-b", type: "dir" },
    { name: "b.md", type: "file" },
    { name: "é.md", type: "file" },
  ]);
  assert.deepEqual(target.listDir("a-b"), { ok: true, path: "a-b", entries: [{ name: "inner.txt", type: "file" }] });
  assert.deepEqual(target.listDir(""), target.listDir("."), "'' and '.' both mean the root");
  assert.deepEqual(target.warnings(), [], "successful listings record nothing");

  assert.equal(target.listDir("a").reason, "not-a-file", "listing a file is refused");
  assert.equal(target.listDir("missing").reason, "not-found");
  assert.deepEqual(target.warnings(), [{ path: "a", reason: "not-a-file" }], "not-found is not recorded");
});

test("named pipes are listed as other and refused by readText and stat, without being opened", {
  skip: isWindows ? "named pipes are a POSIX feature" : false,
}, (t) => {
  const { fixture, target } = openFixture(t);
  const pipe = path.join(fixture.root, "pipe");
  const outsidePipe = path.join(fixture.outsideDir, "pipe");
  for (const made of [pipe, outsidePipe]) {
    const result = spawnSync("mkfifo", [made]);
    if (result.error || result.status !== 0) {
      t.skip("mkfifo is not available on this system");
      return;
    }
  }

  // A read that opened the pipe would block forever, so these calls double as the check.
  assert.deepEqual(target.listDir(".").entries, [{ name: "pipe", type: "other" }]);
  assert.equal(target.readText("pipe").reason, "not-a-file");
  assert.equal(target.stat("pipe").reason, "not-a-file");
  assert.equal(target.exists("pipe"), true);
  assert.deepEqual(statOutside(outsidePipe), { exists: true, type: "other", bytes: 0 });
});

test("statOutside returns existence, type and size of an absolute path, and rejects relative input", (t) => {
  const fixture = makeFixture({ outside: { "secret.txt": SECRET, "sub/readme.md": "x\n" } });
  t.after(fixture.cleanup);

  assert.deepEqual(statOutside(path.join(fixture.outsideDir, "secret.txt")), {
    exists: true,
    type: "file",
    bytes: Buffer.byteLength(SECRET),
  });
  assert.deepEqual(statOutside(path.join(fixture.outsideDir, "sub")), { exists: true, type: "dir", bytes: 0 });
  assert.deepEqual(statOutside(path.join(fixture.outsideDir, "missing.md")), { exists: false });
  assert.throws(() => statOutside("secret.txt"), TypeError);
  assert.throws(() => statOutside("..\\outside\\secret.txt"), TypeError);
  assert.throws(() => statOutside(undefined), TypeError);
});

test("warnings are sorted, de-duplicated, free of absolute paths, and copies", (t) => {
  const { target } = openFixture(t, {
    files: { "z.bin": Buffer.from([0]), "a.bin": Buffer.from([0]), "big.txt": "xxxxx" },
  });

  target.readText("z.bin");
  target.readText("a.bin");
  target.readText("z.bin");
  target.readText("big.txt", { maxBytes: 2 });
  target.exists("missing.txt");
  target.readText("../outside/secret.txt");

  const warnings = target.warnings();
  assert.deepEqual(warnings, [
    { path: "../outside/secret.txt", reason: "outside-root" },
    { path: "a.bin", reason: "binary" },
    { path: "big.txt", reason: "too-large" },
    { path: "z.bin", reason: "binary" },
  ]);
  warnings.push({ path: "injected", reason: "read-error" });
  assert.equal(target.warnings().length, 4, "warnings() returns a copy");
  assertNoSecret(warnings);
});

test("createTargetFs refuses a missing root, a file as root, and a root that is not a string", (t) => {
  const fixture = makeFixture({ files: { "file.txt": "x\n" } });
  t.after(fixture.cleanup);

  assert.throws(() => createTargetFs(path.join(fixture.base, "missing")), /does not exist/);
  assert.throws(() => createTargetFs(path.join(fixture.root, "file.txt")), /not a folder/);
  assert.throws(() => createTargetFs(""), TypeError);
  assert.throws(() => createTargetFs(42), TypeError);
});

test("non-string paths and invalid maxBytes are programming errors and throw a TypeError", (t) => {
  const { target } = openFixture(t, { files: { "a.txt": "a" } });

  assert.throws(() => target.readText(undefined), TypeError);
  assert.throws(() => target.stat(42), TypeError);
  assert.throws(() => target.exists(null), TypeError);
  assert.throws(() => target.listDir({}), TypeError);
  assert.throws(() => target.readText("a.txt", { maxBytes: -1 }), TypeError);
  assert.throws(() => target.readText("a.txt", { maxBytes: 1.5 }), TypeError);
  assert.throws(() => target.readText("a.txt", { maxBytes: "16" }), TypeError);
});

test("a NUL byte in a path is not found and does not throw", (t) => {
  const { target } = openFixture(t, { files: { "a.txt": "a" } });

  assert.deepEqual(target.readText("a\0.txt"), { ok: false, path: "a\0.txt", reason: "not-found" });
  assert.equal(target.exists("a\0.txt"), false);
  assert.deepEqual(target.warnings(), []);
});
