import assert from "node:assert/strict";
import { test } from "node:test";
import { createRedactor } from "../scripts/lib/redact.mjs";

test("redact: on Windows the root becomes <target> and the home folder becomes ~, in every spelling", () => {
  const redact = createRedactor({ root: "C:\\Users\\dev\\repo", home: "C:\\Users\\dev", platform: "win32" });

  assert.equal(redact("C:\\Users\\dev\\repo\\scripts\\x.mjs"), "<target>\\scripts\\x.mjs");
  assert.equal(redact("C:/Users/dev/repo/scripts/x.mjs"), "<target>/scripts/x.mjs");
  assert.equal(redact("/c/Users/dev/repo/x.mjs"), "<target>/x.mjs");
  assert.equal(redact("//c/Users/dev/repo/x.mjs"), "<target>/x.mjs");
  assert.equal(redact("C:\\\\Users\\\\dev\\\\repo\\\\x"), "<target>\\\\x", "doubled backslashes");
  assert.equal(redact("C:\\Users\\dev\\tools\\y.mjs"), "~\\tools\\y.mjs");
  assert.equal(redact("/c/Users/dev/tools/y.mjs"), "~/tools/y.mjs");
});

test("redact: the match ignores letter case on Windows", () => {
  const redact = createRedactor({ root: "C:\\Users\\dev\\repo", home: "C:\\Users\\dev", platform: "win32" });

  assert.equal(redact("c:\\users\\DEV\\Repo\\x"), "<target>\\x");
  assert.equal(redact("/C/users/dev/REPO/x"), "<target>/x");
});

test("redact: a folder name that only starts with the folder is not replaced", () => {
  const redact = createRedactor({ root: "C:\\Users\\dev\\repo", home: "C:\\Users\\dev", platform: "win32" });

  assert.equal(redact("C:\\Users\\dev\\repo-evil\\x"), "~\\repo-evil\\x");
  assert.equal(redact("C:\\Users\\devx\\x"), "C:\\Users\\devx\\x");
});

test("redact: on POSIX the root and the home folder are replaced, and the text around them is kept", () => {
  const redact = createRedactor({ root: "/home/dev/repo", home: "/home/dev", platform: "linux" });

  assert.equal(redact("node /home/dev/repo/a.mjs --x"), "node <target>/a.mjs --x");
  assert.equal(redact("cat /home/dev/other"), "cat ~/other");
  assert.equal(redact("/home/devx/a"), "/home/devx/a");
  assert.equal(redact("x/home/dev/repo"), "x/home/dev/repo", "a match must start a path");
});

test("redact: a root that is a drive or a filesystem root is never replaced", () => {
  const redact = createRedactor({ root: "C:\\", home: "/", platform: "win32" });

  assert.equal(redact("C:\\Users\\x"), "C:\\Users\\x");
  assert.equal(redact("/c/Users/x"), "/c/Users/x");
});

test("redact: values that are not strings come back unchanged", () => {
  const redact = createRedactor({ root: "/tmp/repo", home: "/home/dev", platform: "linux" });

  assert.equal(redact(42), 42);
  assert.equal(redact(null), null);
  assert.deepEqual(redact(["/tmp/repo"]), ["/tmp/repo"]);
});

// Token-shaped values, built at run time so that this file holds no secret-shaped text (push protection would block it).
const GITHUB = ["gh", "p_"].join("") + ["A1b2C3d4E5", "f6G7h8I9j0", "K1l2M3n4O5", "p6Q7r8"].join("");
const ANTHROPIC = ["sk", "ant", "api03"].join("-") + "-Zx41Qw82Er63Ty74Ui85Op96As07Df18Gh29Jk30Lm41Nb52Vc63";

test("redact: a token inside a longer string is masked, and the text around it is kept", () => {
  const redact = createRedactor({ root: "/home/dev/repo", home: "/home/dev", platform: "linux" });

  assert.equal(
    redact(`curl -H "Authorization: Bearer ${GITHUB}" /home/dev/repo/x`),
    'curl -H "Authorization: Bearer ghp_\u2026Q7r8" <target>/x',
  );
  assert.equal(redact(`Bash(echo ${ANTHROPIC})`), "Bash(echo sk-ant-\u2026Vc63)");
  assert.equal(redact(`--token=${GITHUB}&next=1`), "--token=ghp_\u2026Q7r8&next=1");
});

test("redact: a key name and text without a token are kept as they are", () => {
  const redact = createRedactor({ root: "/home/dev/repo", home: "/home/dev", platform: "linux" });

  assert.equal(redact("API_KEY"), "API_KEY", "only token-shaped text is masked, not the name of a key");
  assert.equal(redact("node tools/risk-based-checks.mjs"), "node tools/risk-based-checks.mjs");
});
