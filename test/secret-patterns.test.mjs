import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  findGenericSecrets,
  findSpecificSecrets,
  genericSecretOf,
  loadSecretPatterns,
  mask,
  maskSpecificSecrets,
  secretFileKind,
  validateSecretData,
} from "../scripts/lib/secret-patterns.mjs";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const DATA_FILE = path.join(TEST_DIR, "..", "data", "secret-patterns.json");

// Token-shaped values, built at run time so that this file holds no secret-shaped text (push protection would block it).
const GITHUB = ["gh", "p_"].join("") + ["A1b2C3d4E5", "f6G7h8I9j0", "K1l2M3n4O5", "p6Q7r8"].join("");
const ANTHROPIC = ["sk", "ant", "api03"].join("-") + "-Zx41Qw82Er63Ty74Ui85Op96As07Df18Gh29Jk30Lm41Nb52Vc63";
const AWS = "AKIA" + "Q3JX7LMN2PVR5TWZ";
const SLACK = ["xox", "b-1234567890-AbCdEfGhIj"].join("");
const PRIVATE_KEY_HEADER = ["-----BEGIN ", "RSA ", "PRIVATE KEY-----"].join("");

test("secretFileKind: the secret names, at any depth, without the template names", () => {
  for (const name of [".env", ".env.local", "config/.env.production", "apps/web/.env.staging", ".ENV"]) {
    assert.equal(secretFileKind(name), "dotenv", name);
  }
  for (const name of [".env.example", ".env.sample", ".env.template", "config/.env.example", "x.env", "env", "env.local"]) {
    assert.equal(secretFileKind(name), null, name);
  }
  assert.equal(secretFileKind("config/server.pem"), "pem");
  assert.equal(secretFileKind("tls/client.key"), "key");
  assert.equal(secretFileKind("certs/store.p12"), "pkcs12");
  assert.equal(secretFileKind("certs/store.pfx"), "pfx");
  assert.equal(secretFileKind("Server.PEM"), "pem", "names ignore letter case");
  assert.equal(secretFileKind("home/id_rsa"), "ssh-rsa");
  assert.equal(secretFileKind("home/id_ed25519"), "ssh-ed25519");
  assert.equal(secretFileKind("id_rsa.pub"), null, "a public key is not a secret file");
  assert.equal(secretFileKind("app/credentials.json"), "credentials-json");
  assert.equal(secretFileKind("app/credentials.json.md"), null);
  assert.equal(secretFileKind("docs/keyboard.md"), null);
  assert.equal(secretFileKind("src\\config\\.env"), "dotenv", "Windows separators");
});

test("findSpecificSecrets: each token format is found once, under its own id and prefix", () => {
  const text = [
    `ANTHROPIC_API_KEY=${ANTHROPIC}`,
    `token ${GITHUB} and ${AWS}`,
    `slack ${SLACK}`,
    PRIVATE_KEY_HEADER,
  ].join("\n");
  const found = findSpecificSecrets(text);
  assert.deepEqual(
    found.map((item) => [item.id, item.prefix, item.value]),
    [
      ["anthropic-api-key", "sk-ant-", ANTHROPIC],
      ["github-classic-token", "ghp_", GITHUB],
      ["aws-access-key-id", "AKIA", AWS],
      ["slack-token", "xox", SLACK],
      ["private-key-header", "-----BEGIN", PRIVATE_KEY_HEADER],
    ],
  );
  assert.ok(found.every((item, index) => index === 0 || found[index - 1].start < item.start), "in order of position");
});

test("findSpecificSecrets: an sk- key is never reported a second time as a generic sk- key", () => {
  const found = findSpecificSecrets(`key=${ANTHROPIC}`);
  assert.equal(found.length, 1);
  assert.equal(found[0].id, "anthropic-api-key");
});

test("findSpecificSecrets: a word that contains a prefix is not a token", () => {
  const text = "a-task-manager-with-some-long-words-and-risk-based-checks, ghost_town_of_names_here, mask-the-value";
  assert.deepEqual(findSpecificSecrets(text), []);
});

test("findSpecificSecrets: the lengths that each format needs", () => {
  assert.deepEqual(findSpecificSecrets("AKIA" + "Q3JX7LMN2PVR5TWZA"), [], "AKIA with 17 characters is not a key id");
  assert.deepEqual(findSpecificSecrets("AKIA" + "Q3JX7LMN2PVR5TW"), [], "AKIA with 15 characters is not a key id");
  assert.deepEqual(findSpecificSecrets("sk-ant-short"), [], "a short sk-ant- value is not a key");
});

test("findGenericSecrets: a secret-named key with a long value, in text", () => {
  const found = findGenericSecrets("DB_PASSWORD=hunter2hunter2hunter2\nexport api_key: abcdefghijklmnop1234\n");
  assert.deepEqual(
    found.map((item) => [item.id, item.value]),
    [
      ["generic-assignment", "hunter2hunter2hunter2"],
      ["generic-assignment", "abcdefghijklmnop1234"],
    ],
  );
});

test("findGenericSecrets: an Authorization scheme is not part of the value", () => {
  const [found] = findGenericSecrets('Authorization: "Bearer abcdefghijklmnop1234"');
  assert.equal(found.value, "abcdefghijklmnop1234");
});

test("findGenericSecrets: references, placeholders, short and multi-word values are not secrets", () => {
  const text = [
    "api_key: ${API_KEY}",
    "token: <your-token-here>",
    "secret: your-secret-value-here",
    "password: changeme",
    "token: xxxxxxxxxxxxxxxxxxxxxxxx",
    "token: this is not one value at all",
    "password: short",
    "max_tokens: 4096",
    "description: the deploy script reads its credentials from the environment",
  ].join("\n");
  assert.deepEqual(findGenericSecrets(text), []);
});

test("genericSecretOf: a key that does not name a secret is never generic", () => {
  assert.equal(genericSecretOf("LOG_LEVEL", "abcdefghijklmnop1234"), null);
  assert.equal(genericSecretOf("API_KEY", "abcdefghijklmnop1234"), "abcdefghijklmnop1234");
  assert.equal(genericSecretOf("DB_PASSWORD", "abcdefghijklmnop1234"), "abcdefghijklmnop1234");
  assert.equal(genericSecretOf("Authorization", "Bearer abcdefghijklmnop1234"), "abcdefghijklmnop1234");
  assert.equal(genericSecretOf("API_KEY", "${API_KEY}"), null);
  assert.equal(genericSecretOf("API_KEY", 42), null, "values that are not strings");
});

test("mask: the literal prefix, an ellipsis and the last four characters", () => {
  assert.equal(mask(ANTHROPIC, "sk-ant-"), "sk-ant-…Vc63");
  assert.equal(mask(GITHUB, "ghp_"), "ghp_…Q7r8");
  assert.equal(mask(AWS, "AKIA"), "AKIA…5TWZ");
  assert.equal(mask(SLACK, "xox"), "xox…GhIj");
  assert.equal(mask("abcdefghijklmnop1234"), "ab…1234", "without a prefix, the first two characters");
});

test("mask: a prefix that the value does not start with is not used", () => {
  assert.equal(mask("xyz123456789", "sk-"), "xy…6789");
});

test("mask: a value too short to hide anything shows no tail", () => {
  assert.equal(mask("abc"), "ab…");
  assert.equal(mask("abcdefghi"), "ab…", "nine characters: the prefix plus eight is not reached");
  assert.equal(mask("abcdefghij"), "ab…ghij", "ten characters: the tail is shown");
  assert.equal(mask("ghp_abc", "ghp_"), "ghp_…", "a prefix longer than the hidden part");
});

test("mask: a masked form never contains the value", () => {
  assert.equal(mask("a"), "…");
  assert.equal(mask("sk-ant-", "sk-ant-"), "…", "the prefix is the whole value");
  for (let length = 1; length <= 40; length += 1) {
    const value = Array.from({ length }, (_, index) => String.fromCharCode(97 + ((index * 7) % 26))).join("");
    for (const prefix of [null, value.slice(0, 1), value.slice(0, 2), value.slice(0, 5)]) {
      assert.equal(mask(value, prefix).includes(value), false, `value of length ${length} with prefix ${prefix}`);
    }
  }
});

test("mask: rejects a value that is not a non-empty string", () => {
  assert.throws(() => mask(""), TypeError);
  assert.throws(() => mask(null), TypeError);
  assert.throws(() => mask(42), TypeError);
});

test("maskSpecificSecrets: a token inside a longer text is masked and the rest is kept", () => {
  const text = `curl -H "Authorization: Bearer ${GITHUB}" https://example.invalid`;
  assert.equal(maskSpecificSecrets(text), 'curl -H "Authorization: Bearer ghp_…Q7r8" https://example.invalid');
  assert.equal(maskSpecificSecrets("nothing secret here"), "nothing secret here");
});

test("the data file holds patterns and prefixes only: it has no token-shaped text", () => {
  const raw = fs.readFileSync(DATA_FILE, "utf8");
  assert.deepEqual(findSpecificSecrets(raw), []);
  assert.equal(validateSecretData(JSON.parse(raw)).contentPatterns.length, loadSecretPatterns().contentPatterns.length);
});

test("validateSecretData: names the first entry that is wrong", () => {
  const fresh = () => JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  const extra = fresh();
  extra.extra = [];
  assert.throws(() => validateSecretData(extra), /unknown field "extra"/);

  const duplicate = fresh();
  duplicate.contentPatterns[1].id = duplicate.contentPatterns[0].id;
  assert.throws(() => validateSecretData(duplicate), /duplicate id/);

  const broken = fresh();
  broken.fileNames[0].pattern = "(";
  assert.throws(() => validateSecretData(broken), /fileNames\[0\]\.pattern is not a valid regular expression/);

  const emptyPrefix = fresh();
  emptyPrefix.contentPatterns[0].prefix = "";
  assert.throws(() => validateSecretData(emptyPrefix), /prefix must be a non-empty string/);

  const noShow = fresh();
  noShow.genericAssignment.minValueLength = 0;
  assert.throws(() => validateSecretData(noShow), /minValueLength must be a positive integer/);

  const notKebab = fresh();
  notKebab.contentPatterns[0].id = "Not Kebab";
  assert.throws(() => validateSecretData(notKebab), /id must be kebab-case/);
});
