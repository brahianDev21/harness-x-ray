import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import { openTarget } from "../scripts/lib/open-target.mjs";
import { symlinkSupport } from "./helpers/make-fixture.mjs";

// The opener is always injected: no test here starts a real command or a browser (the default spawn is never called).
// The .html fixtures are created in a unique subfolder of the real runs/ folder (git-ignored) and removed afterwards;
// runs/ itself is removed too when this file created it and it is then empty. The files outside runs/ are in a unique
// folder of the system temp folder.
const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RUNS = path.join(HARNESS_ROOT, "runs");
const support = symlinkSupport();
const symlinkSkip = support.supported ? false : support.reason;
const LINUX_GUI = { platform: "linux", env: { DISPLAY: ":0" } };
const WIN_ENV = { SystemRoot: "C:\\Windows" };

let createdRuns = false;
let folder;
let outsideDir;

before(() => {
  createdRuns = !fs.existsSync(RUNS);
  fs.mkdirSync(RUNS, { recursive: true });
  folder = fs.mkdtempSync(path.join(RUNS, "open-target-test-"));
  outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-open-target-"));
});

after(() => {
  fs.rmSync(folder, { recursive: true, force: true });
  fs.rmSync(outsideDir, { recursive: true, force: true });
  if (createdRuns && fs.readdirSync(RUNS).length === 0) fs.rmdirSync(RUNS);
});

// An injected executor that records each call. With a failure, it rejects with that error.
function recorder(failure) {
  const calls = [];
  const exec = async (file, args, options) => {
    calls.push({ file, args, options });
    if (failure) throw failure;
  };
  return { exec, calls };
}

function writeIn(dir, name, content = "<!doctype html>\n") {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content);
  return file;
}

function realOf(file) {
  return fs.realpathSync.native(file);
}

// Opens input on the given platform with the given environment, through the injected executor.
function launch(input, { platform, env, exec }) {
  return openTarget(input, { harnessRoot: HARNESS_ROOT, platform, env, exec });
}

test("an .html file inside runs/ is launched with xdg-open on Linux with DISPLAY set, by its real path and with no shell", async () => {
  const file = writeIn(folder, "report.html");
  const { exec, calls } = recorder();
  const result = await launch(file, { ...LINUX_GUI, exec });

  assert.equal(result.code, 0, result.message);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].file, "xdg-open");
  assert.deepEqual(calls[0].args, [realOf(file)]);
  assert.equal(calls[0].options.shell, false);
  assert.equal(calls[0].options.windowsHide, true);
  assert.equal(result.command, "xdg-open");
  assert.deepEqual(result.args, [realOf(file)]);
});

test("the same file is launched with open on macOS and with cmd.exe and start on Windows, without a graphical check", async () => {
  const file = writeIn(folder, "mac.html");
  const real = realOf(file);

  const mac = recorder();
  const macResult = await launch(file, { platform: "darwin", env: {}, exec: mac.exec });
  assert.equal(macResult.code, 0);
  assert.deepEqual(mac.calls.map((call) => [call.file, call.args]), [["open", [real]]]);
  assert.equal(mac.calls[0].options.shell, false);

  const win = recorder();
  const winResult = await launch(file, { platform: "win32", env: WIN_ENV, exec: win.exec });
  assert.equal(winResult.code, 0);
  assert.deepEqual(
    win.calls.map((call) => [call.file, call.args]),
    [["C:\\Windows\\System32\\cmd.exe", ["/d", "/s", "/c", "start", "", real]]],
  );
  assert.equal(win.calls[0].options.shell, false);
});

test("on Windows cmd.exe is started by its full path: ComSpec when it is an absolute cmd.exe, else SystemRoot, never a bare name", async () => {
  const file = writeIn(folder, "win-cmd.html");
  const cases = [
    [{ ComSpec: "C:\\Windows\\system32\\cmd.exe" }, "C:\\Windows\\system32\\cmd.exe"],
    [{ ComSpec: "C:\\WINDOWS\\SYSTEM32\\CMD.EXE" }, "C:\\WINDOWS\\SYSTEM32\\CMD.EXE"],
    [{ ComSpec: "C:\\Tools\\other.exe", SystemRoot: "C:\\Windows" }, "C:\\Windows\\System32\\cmd.exe"],
    [{ ComSpec: "cmd.exe", SystemRoot: "D:\\WinDir" }, "D:\\WinDir\\System32\\cmd.exe"],
    [{ SystemRoot: "C:\\Windows" }, "C:\\Windows\\System32\\cmd.exe"],
  ];
  for (const [env, command] of cases) {
    const { exec, calls } = recorder();
    const result = await launch(file, { platform: "win32", env, exec });
    assert.equal(result.code, 0, JSON.stringify(env));
    assert.equal(calls[0].file, command, JSON.stringify(env));
  }

  // Neither ComSpec nor SystemRoot gives a full path: exit 3, and nothing is started from the search path.
  const none = recorder();
  const missing = await launch(file, { platform: "win32", env: { ComSpec: "cmd.exe", SystemRoot: "relative" }, exec: none.exec });
  assert.equal(missing.code, 3);
  assert.match(missing.message, /cannot find cmd\.exe/);
  assert.equal(none.calls.length, 0);
});

test("a file name with spaces inside runs/ is launched, and a link inside runs/ is launched by the real path it points to", { skip: symlinkSkip }, async () => {
  const spaced = writeIn(folder, "my report.html");
  const { exec, calls } = recorder();
  assert.equal((await launch(spaced, { ...LINUX_GUI, exec })).code, 0);
  assert.deepEqual(calls[0].args, [realOf(spaced)]);

  // Positive control of the link rule: a link whose target stays inside runs/ is followed, and the target is passed.
  const link = path.join(folder, "alias.html");
  fs.symlinkSync(spaced, link, "file");
  const linked = recorder();
  assert.equal((await launch(link, { ...LINUX_GUI, exec: linked.exec })).code, 0);
  assert.deepEqual(linked.calls[0].args, [realOf(spaced)], "the realpath of the link, not the link");
});

test("a file that is not allowed is refused with exit 2 and the opener is never called", async () => {
  const ok = writeIn(folder, "ok.html");
  const { exec, calls } = recorder();
  // Positive control: the same run file is accepted with the same opener.
  assert.equal((await launch(ok, { ...LINUX_GUI, exec })).code, 0);
  assert.equal(calls.length, 1);

  const refused = [
    ["a file outside runs/", writeIn(outsideDir, "outside.html")],
    ["a .htm file", writeIn(folder, "old.htm")],
    ["a .HTML file", writeIn(folder, "UPPER.HTML")],
    ["a .html.txt file", writeIn(folder, "notes.html.txt")],
    ["a name with &", writeIn(folder, "a&b.html")],
    ["a name with a percent sign", writeIn(folder, "100%.html")],
    ["a folder named like a page", path.join(folder, "dir.html")],
    ["a missing file", path.join(folder, "missing.html")],
  ];
  fs.mkdirSync(path.join(folder, "dir.html"), { recursive: true });

  for (const [label, input] of refused) {
    const count = calls.length;
    const result = await launch(input, { ...LINUX_GUI, exec });
    assert.equal(result.code, 2, label);
    assert.equal(calls.length, count, `${label}: the opener must not be called`);
  }
});

test("a link inside runs/ that points outside is refused with exit 2, and the file it points to is left alone", { skip: symlinkSkip }, async () => {
  const target = writeIn(outsideDir, "linked-out.html", "keep\n");
  const link = path.join(folder, "escape.html");
  fs.symlinkSync(target, link, "file");
  const { exec, calls } = recorder();

  const result = await launch(link, { ...LINUX_GUI, exec });
  assert.equal(result.code, 2);
  assert.equal(calls.length, 0);
  assert.equal(fs.readFileSync(target, "utf8"), "keep\n");
});

test("on Windows a harness folder whose real path holds a cmd.exe metacharacter is refused, and off Windows it is accepted", async () => {
  // Positive control: a plain harness folder is accepted on win32 too. Each name below holds one character that cmd.exe
  // interprets, and a file of that harness outside runs/ is refused on Linux as well.
  const cases = [
    ["plain-harness", 0],
    ["h&x", 2],
    ["h%x", 2],
    ["h(1)", 2],
    ["h),x", 2],
    ["h;x", 2],
    ["h=x", 2],
  ];
  const linux = recorder();
  const win = recorder();
  for (const [name, winCode] of cases) {
    const harness = path.join(outsideDir, name);
    fs.mkdirSync(path.join(harness, "runs"), { recursive: true });
    const inRuns = writeIn(path.join(harness, "runs"), "run.html");
    const other = writeIn(harness, "other.html");

    const off = await openTarget(inRuns, { harnessRoot: harness, platform: "linux", env: { DISPLAY: ":0" }, exec: linux.exec });
    assert.equal(off.code, 0, name);
    assert.equal((await openTarget(other, { harnessRoot: harness, platform: "linux", env: { DISPLAY: ":0" }, exec: linux.exec })).code, 2, `${name}: outside runs/`);

    const on = await openTarget(inRuns, { harnessRoot: harness, platform: "win32", env: WIN_ENV, exec: win.exec });
    assert.equal(on.code, winCode, name);
  }
  assert.equal(linux.calls.length, cases.length, "one call per accepted harness on Linux, none for the files outside runs/");
  assert.equal(win.calls.length, 1, "only the plain harness reaches the opener on win32");
});

test("http://127.0.0.1 URLs with a port are launched, and every other URL is refused with exit 2", async () => {
  const { exec, calls } = recorder();
  const accepted = "http://127.0.0.1:5173/intake?t=abc";
  const control = await launch(accepted, { ...LINUX_GUI, exec });
  assert.equal(control.code, 0, control.message);
  assert.deepEqual(calls.map((call) => call.args), [[accepted]]);
  assert.equal(calls[0].options.shell, false);

  const refused = [
    "https://127.0.0.1:5173/intake",
    "http://localhost:5173/intake",
    "http://0.0.0.0:5173/",
    "http://127.0.0.2:5173/",
    "http://127.0.0.1/x",
    "http://127.0.0.1:0/",
    "http://127.0.0.1:70000/",
    "http://127.0.0.1:80@evil.com/",
    "http://127.0.0.1.evil.com:80/",
    "http://user:pw@127.0.0.1:80/",
    "http://127.0.0.1:5173/intake#frag",
    "http://127.0.0.1:5173/?a=1&b=2",
    "http://[::1]:5173/",
    "javascript:alert(1)",
    "file:///etc/hosts",
  ];
  for (const input of refused) {
    const count = calls.length;
    const result = await launch(input, { ...LINUX_GUI, exec });
    assert.equal(result.code, 2, input);
    assert.equal(calls.length, count, `${input}: the opener must not be called`);
  }
});

test("without a graphical environment on Linux the result is exit 3 and the opener is not called", async () => {
  const { exec, calls } = recorder();
  const url = await launch("http://127.0.0.1:5173/intake", { platform: "linux", env: {}, exec });
  assert.equal(url.code, 3);
  assert.match(url.message, /no graphical environment/);
  const file = writeIn(folder, "nogui.html");
  const page = await launch(file, { platform: "linux", env: {}, exec });
  assert.equal(page.code, 3);
  assert.equal(calls.length, 0, "nothing runs without DISPLAY or WAYLAND_DISPLAY");

  // Positive control: WAYLAND_DISPLAY alone is a graphical environment.
  assert.equal((await launch(file, { platform: "linux", env: { WAYLAND_DISPLAY: "wayland-0" }, exec })).code, 0);
  assert.equal(calls.length, 1);
});

test("an opener that is not installed (ENOENT) is exit 3, and any other failure of the opener is exit 1", async () => {
  const file = writeIn(folder, "failing.html");
  const missing = Object.assign(new Error("spawn xdg-open ENOENT"), { code: "ENOENT" });
  const notFound = await launch(file, { ...LINUX_GUI, exec: recorder(missing).exec });
  assert.equal(notFound.code, 3);
  assert.match(notFound.message, /opener not found: xdg-open/);

  const broken = Object.assign(new Error("spawn xdg-open EACCES\nsecond line"), { code: "EACCES" });
  const other = await launch(file, { ...LINUX_GUI, exec: recorder(broken).exec });
  assert.equal(other.code, 1);
  assert.equal(other.message.includes("\n"), false, "the message is one line");
});

test("an empty or missing input is refused with exit 2, without a call", async () => {
  const { exec, calls } = recorder();
  assert.equal((await launch("", { ...LINUX_GUI, exec })).code, 2);
  assert.equal((await launch(undefined, { ...LINUX_GUI, exec })).code, 2);
  assert.equal(calls.length, 0);
});
