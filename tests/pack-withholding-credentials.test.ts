/**
 * The credential rules of the shared WITHHOLDING block (the name layer, the structure rule, the text rules the cloud tools had and
 * the CLD-05 shapes), run against the block taken from EVERY file that carries it, so that a carrier cannot drift. Every secret is a
 * random string made here from a fixed seed; nothing is read from a tool's output. The cases that must stay are written from the
 * shapes the rules name as their limits (a port flag, `curl -u` without a colon, `$2b` in prose, a next-page token).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const BEGIN = "# BEGIN SHARED WITHHOLDING";
const END = "# END SHARED WITHHOLDING";
const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const next = rng(20261103);
const secret = (n: number): string => Array.from({ length: n }, () => ALNUM[Math.floor(next() * ALNUM.length)]).join("");

async function carriers(): Promise<{ path: string; block: string }[]> {
  const out: { path: string; block: string }[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (e.name === "node_modules" || e.name === ".git") continue;
      if (e.isDirectory()) await walk(join(dir, e.name));
      else if (e.name === "run.py") {
        const text = await readFile(join(dir, e.name), "utf8");
        const s = text.indexOf(BEGIN);
        const e2 = text.indexOf(END);
        if (s >= 0 && e2 > s) out.push({ path: join(dir, e.name), block: text.slice(s, e2 + END.length) });
      }
    }
  };
  await walk(join(ROOT, "packs"));
  await walk(join(ROOT, "tool-library"));
  return out;
}

type Gone = [string, string, string]; // [label, the secret, the text it sits in]
const PW = "Hu" + secret(8) + "!7";
const PW2 = "Zq" + secret(9) + "#4";
const GONE: Gone[] = [
  ["a value assigned to a credential name", PW, `login failed password=${PW} retry`],
  ["a quoted value with spaces", "Correct Horse " + PW, `password="Correct Horse ${PW}"`],
  ["a short value", "a9!", "pwd=a9!"],
  ["a cookie header value", PW, `Cookie: theme=dark; sid=${PW}`],
  ["a Name/Value pair in text", PW, JSON.stringify([{ Name: "Password", Value: PW }])],
  ["a Name/Value pair with escaped quotes", PW, `{\\"Name\\":\\"Password\\",\\"Value\\":\\"${PW}\\"}`],
  ["a numeric Value (CLD-05)", "48151623", '{"Name":"pin","Value":48151623}'],
  ["an array Value (CLD-05)", PW2, `{"Name":"Password","Value":["${PW2}","x"]}`],
  ["the NewValue after an OldValue (CLD-05)", PW2, `{"Name":"Password","OldValue":"${PW}","NewValue":"${PW2}"}`],
  ["a Value over 4,096 characters (CLD-05)", "Q".repeat(5000), `{"Name":"Password","Value":"${"Q".repeat(5000)}"}`],
  ["the argument of ConvertTo-SecureString", PW, `$s = ConvertTo-SecureString '${PW}' -AsPlainText -Force`],
  ["a value given to a credential switch", PW, `New-LocalUser -Name x -Password '${PW}'`],
  ["mysql -u<user> -p<password> (CLD-05)", PW, `mysql -uroot -p${PW} appdb`],
  ["curl -u <user>:<password> (CLD-05)", PW, `curl -X POST -u admin:${PW} https://host.example/api`],
  ["curl --user with a quoted pair (CLD-05)", "pass word " + PW, `curl --user "admin:pass word ${PW}" https://host.example`],
  ["a bcrypt hash (CLD-05)", "$2b$12$" + "N9qo8uLOickgx2ZMRZoMye" + "IjZAgcfl7p92ldGxad68LJZdL17lhWy", "hash: $2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy end"],
  ["a connection string key", PW, `Server=db;Uid=sa;Pwd=${PW};`],
  ["a hash pair of an account database", "31d6cfe0d16ae931b73c59d7e0c089c0", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"],
  ["a private key block", "MIIEowIBAAKCAQEAxample" + "Body", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxampleBody\n-----END RSA PRIVATE KEY-----"],
];

/** Texts that must come back unchanged: they only look a little like a credential. */
const KEPT: string[] = [
  "ssh -p 22 user@host.example", "nc -p 8080 host.example", "mysql -p appdb", "mysql -h db.example -P 3306 appdb",
  "curl -u admin https://host.example", "curl -s https://host.example/path", "the price is $2b in prose", "see $2 and $2y for the rule",
  "pass: 3 attempts remain", "nextToken=AbCdEf123456", "design=final", "token ring network", "password policy was reviewed",
  JSON.stringify([{ Name: "Subject", Value: "hello world" }]), JSON.stringify([{ Name: "NextToken", Value: "page-two-marker" }]),
  '{"Name":"Password","Value":null}', '{"Name":"Password","Value":true}', "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-AbCdEf",
];

const CODE = `
import json, re, sys
data = json.load(sys.stdin)
ns = {"re": re}
exec(data["block"], ns)
print(json.dumps({"gone": [ns["scrub"](t) for t in data["gone"]], "kept": [ns["scrub"](t) for t in data["kept"]],
                  "spans": [[list(s) for s in ns["credential_spans"](t)] for t in data["gone"]]}))
`;

function runBlock(block: string, gone: string[], kept: string[]): { gone: string[]; kept: string[]; spans: [number, number, string][][] } {
  const r = spawnSync("python3", ["-I", "-c", CODE], { input: JSON.stringify({ block, gone, kept }), encoding: "utf8", timeout: 60_000 });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout);
}

test("every file that carries the block withholds the credential shapes and keeps the texts that only look like one", async () => {
  const all = await carriers();
  assert.ok(all.length >= 50, `${all.length} carriers`); // the exact number is held by tests/shared-blocks-census.test.ts
  const distinct = new Map<string, string>();
  for (const c of all) if (!distinct.has(c.block)) distinct.set(c.block, c.path);
  assert.equal(distinct.size, 1, `the carriers carry ${distinct.size} texts`);
  for (const c of all) {
    const got = runBlock(c.block, GONE.map((g) => g[2]), KEPT);
    GONE.forEach(([label, value], i) => {
      const shown = got.gone[i]!;
      const probe = value.length > 12 ? value.slice(0, 12) : value;
      assert.ok(!shown.includes(probe), `${c.path}: ${label} was printed: ${shown.slice(0, 80)}`);
      assert.match(shown, /withheld/, `${c.path}: ${label}`);
    });
    KEPT.forEach((text, i) => assert.equal(got.kept[i], text, `${c.path}: ${text}`));
  }
});

test("credential_spans returns ordered, disjoint spans inside the text, and says why", async () => {
  const [first] = await carriers();
  const got = runBlock(first!.block, GONE.map((g) => g[2]), []);
  got.spans.forEach((spans, i) => {
    assert.ok(spans.length >= 1, GONE[i]![0]);
    let end = 0;
    for (const [s, e, why] of spans) {
      assert.ok(s >= end && e > s && e <= GONE[i]![2].length && why.length > 0, `${GONE[i]![0]}: ${s}-${e}`);
      end = e;
    }
  });
});

test("a carrier that sets WITHHOLD_LIMIT keeps its own limit and the block's default stays 65,536", async () => {
  const [first] = await carriers();
  const code = `
import json, re, sys
block = sys.stdin.read()
a = {"re": re}; exec(block, a)
b = {"re": re, "WITHHOLD_LIMIT": 1 << 20}; exec(block, b)
big = "x" * 100000
print(json.dumps([a["TEXT_LIMIT"], b["TEXT_LIMIT"], a["scrub"](big).startswith("<over-long"), b["scrub"](big) == big]))`;
  const r = spawnSync("python3", ["-I", "-c", code], { input: first!.block, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), [65536, 1048576, true, true]);
});

test("a hook set by the carrier is called during a long scan and may end it; with none, nothing is called", async () => {
  const [first] = await carriers();
  const code = `
import json, re, sys
block = sys.stdin.read()
calls = []
class Stop(Exception): pass
def tick(units=1):
    calls.append(units)
    if len(calls) > 3: raise Stop()
ns = {"re": re, "WITHHOLD_TICK": tick}; exec(block, ns)
text = ("password=Abc123xyz " * 400)
try:
    ns["credential_spans"](text); stopped = False
except Stop:
    stopped = True
plain = {"re": re}; exec(block, plain)
print(json.dumps([stopped, len(calls) > 3, len(plain["credential_spans"](text)) > 0]))`;
  const r = spawnSync("python3", ["-I", "-c", code], { input: first!.block, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), [true, true, true]);
});

test("identifiers are not credentials: an access key id, a GUID, a SHA-256 and an ARN pass credential_spans untouched", async () => {
  const [first] = await carriers();
  const ids = ["AKIA" + "IOSFODNN7EXAMPLE", "11111111-2222-3333-4444-555555555555", "a".repeat(64), "arn:aws:iam::111122223333:role/service-role/AmazonSageMaker-ExecutionRole-20200101T000001", "i-0abc123def456789a"];
  const code = `
import json, re, sys
d = json.load(sys.stdin); ns = {"re": re}; exec(d["block"], ns)
print(json.dumps([ns["credential_spans"](t) for t in d["ids"]]))`;
  const r = spawnSync("python3", ["-I", "-c", code], { input: JSON.stringify({ block: first!.block, ids }), encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), ids.map(() => []));
});

test("the rules are linear: hostile texts of each rule's alphabet take well under a second at 64 KiB and a few seconds at 1 MiB", async () => {
  const [first] = await carriers();
  const code = `
import json, re, sys, time
block = sys.stdin.read()
shapes = {"password=": "password=", "quote": "password='", "pairs": '{"Name":"Password","Value":"', "arrays": '{"Name":"Password","Value":[', "mysql": "mysql ", "curl": "curl -u ", "bcrypt": "$2b$12$",
          "auth": "authorization:", "colons": ":", "angle": "<>", "b64": "Ab1+/", "backslashes": "\\\\", "eyJ": "eyJ", "cookie": "cookie:", "switch": "-password "}
out = {}
for size in (65536, 1 << 20):
    ns = {"re": re, "WITHHOLD_LIMIT": max(size, 65536)}; exec(block, ns)
    worst = 0.0
    for name, unit in shapes.items():
        text = (unit * (size // len(unit) + 1))[:size]
        start = time.process_time(); ns["scrub"](text); worst = max(worst, time.process_time() - start)
    out[size] = worst
print(json.dumps(out))`;
  const r = spawnSync("python3", ["-I", "-c", code], { input: first!.block, encoding: "utf8", timeout: 300_000 });
  assert.equal(r.status, 0, r.stderr);
  const worst = JSON.parse(r.stdout) as Record<string, number>;
  assert.ok(worst["65536"]! < 1, `64 KiB took ${worst["65536"]} s`);
  assert.ok(worst["1048576"]! < 8, `1 MiB took ${worst["1048576"]} s`);
});
