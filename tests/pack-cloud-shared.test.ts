/**
 * The cloud pack's three tools share one block of code (the lossless page, the secret-safe values file, the withholding of
 * credential-shaped text, timestamps, the bounded JSON reader), copied into each because a tool is standalone. This suite holds
 * the copies equal, holds the three to withholding the same strings, and holds each manifest to what its script does.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { execFileSync } from "node:child_process";
import { chmod, readFile, readdir, stat, symlink } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ALICE, SIGNIN, TOOLS, TRAIL, UAL, asJob, body, ct, everythingBut, exists, filesUnder, put, refused, rowsOf, spawnTool, tool, trail, withDir } from "./cloud-pack-harness.ts";
import type { Json } from "./cloud-pack-harness.ts";
import { CONTROLS, JWT, NAMED_CASES, TEXT_CASES, leaked } from "./cloud-pack-secrets.ts";

const NAMES = ["cloudtrail_parse", "signin_analyse", "ual_parse"] as const;
const SCRIPTS: Record<(typeof NAMES)[number], string> = { cloudtrail_parse: TRAIL, signin_analyse: SIGNIN, ual_parse: UAL };

const BEGIN = "# ---- BEGIN SHARED BLOCK";
const END = "# ---- END SHARED BLOCK";

async function sharedBlock(name: (typeof NAMES)[number]): Promise<string> {
  const text = await readFile(SCRIPTS[name], "utf8");
  const from = text.indexOf(BEGIN);
  const to = text.indexOf(END);
  assert.ok(from >= 0 && to > from, `${name} has the shared block`);
  return text.slice(from, text.indexOf("\n", to));
}

test("the shared block is identical in the three tools", async () => {
  const blocks = await Promise.all(NAMES.map(sharedBlock));
  assert.ok(blocks[0].length > 20000, "the block is the shared code, not a stub");
  assert.equal(blocks[1], blocks[0], "signin_analyse's copy equals cloudtrail_parse's");
  assert.equal(blocks[2], blocks[0], "ual_parse's copy equals cloudtrail_parse's");
});

// Names and values each tool must withhold alike. A name can be echoed in a path, in an error message, in a file name in a census.
const SHAPED: Array<[string, string]> = [
  ["a JSON Web Token", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"],
  ["a GitHub token", "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1eF3gH5"],
  // Built from parts: a literal that looks like a live token is refused by the host's push protection.
  ["a Slack token", "xox" + "b-" + "1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx"],
  ["a Google API key", "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"],
  ["a Google access token", "ya29." + "a0AfH6SMBxExampleExampleExampleExample123456"],
  ["an Azure client secret", "abc8Q~Zq9Xw7Vb6Nm5Lk4Jh3Gf2Dd1Sa0Pp9Oo8Ii"],
  ["a value assigned to a credential name", "password=Hunter2-correct-horse"],
  ["a value assigned to a credential name", "client_secret=Zq9Xw7Vb6Nm5Lk4Jh3Gf2"],
  ["a long unbroken base64-like run", "Zq9Xw7Vb6Nm5Lk4Jh3Gf2Dd1Sa0Pp9Oo8Ii7Uu6Yy5Tt4Rr3Ee2Ww1Qq0Aa9Ss8Dd7Ff6Gg5Hh4Jj3Kk2Ll1Mm0Nn9Bb8Vv7Cc6Xx5Zz4Zq9Xw7Vb6Nm5Lk4Jh3Gf2Dd1Sa0Pp9Oo8Ii"],
];

test("the three tools withhold the same strings from an error message that names them", async () => {
  await withDir(async (cwd) => {
    for (const script of Object.values(SCRIPTS)) {
      for (const [why, value] of SHAPED) {
        const out = refused(await tool(script, cwd, { path: `work/ev/${value}` }));
        const text = JSON.stringify(out);
        assert.ok(!text.includes(value), `${script.split("/").slice(-2)[0]} printed ${why}`);
        assert.match(text, /withheld/, `${script.split("/").slice(-2)[0]} said it withheld ${why}`);
      }
    }
  });
});

test("names that are not shaped like a credential are not withheld: a CloudTrail file name, a long path, an S3 key", async () => {
  await withDir(async (cwd) => {
    const names = [
      "111122223333_CloudTrail_us-east-1_20260214T0900Z_AbCdEf123456.json.gz",
      "arn:aws:iam::111122223333:role/service-role/AmazonSageMaker-ExecutionRole-20200101T000001",
      "backups/2026/02/14/" + "very-long-lowercase-object-key-name-".repeat(5) + "end",
    ];
    for (const name of names) {
      const out = refused(await tool(TRAIL, cwd, { path: `work/ev/${name}` }));
      assert.ok(JSON.stringify(out).includes(name), `${name} is printed as it is`);
    }
  });
});

test("the three tools carry the same typed refusals: a non-object argument, a pipe and a bad limit are JSON errors, never a traceback", async () => {
  await withDir(async (cwd) => {
    for (const script of Object.values(SCRIPTS)) {
      const nonObject = await tool(script, cwd, [1, 2, 3] as unknown as object);
      assert.notEqual(nonObject.code, 0);
      assert.doesNotMatch(nonObject.stderr, /Traceback/);
      assert.match(JSON.parse(nonObject.stdout).error, /arguments must be a JSON object/);
      await put(cwd, "work/ev/a.json", "{}");
      for (const bad of [{ limit: 0 }, { limit: "5" }, { limit: true }, { time_limit_seconds: 0 }, { time_limit_seconds: 9999 }, { write_values: "yes" }, { max_expanded_bytes: 5 }]) {
        const out = refused(await tool(script, cwd, { path: "work/ev/a.json", ...bad }));
        assert.equal(out.status, "failed");
        assert.match(out.error, /must be/);
      }
    }
  });
});

test("every manifest says what its tool reads, carries its script's sha256, declares every argument the script reads and says what is and is not measured", async () => {
  const read = /(?:want_str|want_bool|want_int|want_str_list|want_regex)\(\s*args,\s*"([a-z_]+)"|args\.get\("([a-z_]+)"/g;
  for (const name of NAMES) {
    const manifest = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
    const script = await readFile(SCRIPTS[name], "utf8");
    assert.equal(manifest.sha256, createHash("sha256").update(script).digest("hex"), `${name} sha256`);
    assert.ok(manifest.version >= 4, `${name} version raised`);
    assert.ok(manifest.timeout_seconds > 580, `${name}: the most time_limit_seconds allows (580) is under the tool's timeout, so the tool stops itself before it is killed`);
    assert.match(manifest.params.time_limit_seconds.description, /default 540, at most 580/);
    assert.ok(manifest.use?.names?.length > 0, `${name} says what it reads`);
    assert.equal(manifest.use.extensions, undefined, `${name}: a bare .json or .csv would hint it for every such file`);
    const keys = new Set([...script.matchAll(read)].map((m) => m[1] ?? m[2]));
    // ual_parse reads its two time bounds through a loop over their names.
    if (name === "ual_parse") for (const key of ["since", "until"]) keys.add(key);
    assert.ok(keys.size >= 10, `${name} reads its arguments`);
    for (const key of keys) assert.ok(key in manifest.params, `${name} reads ${key} and does not declare it`);
    for (const key of Object.keys(manifest.params)) assert.ok(keys.has(key), `${name} declares ${key} and does not read it`);
    assert.match(manifest.description, /`status` and `status_basis`/, `${name} says its answers carry status`);
    assert.match(manifest.description, /NOT measured/, `${name} says what it does not measure`);
    assert.match(manifest.description, /secret_output: true/, `${name} says it can reach secrets`);
    assert.match(manifest.description, /never replaces a smaller|never replaced by a smaller/i, `${name} says its output is never replaced`);
    assert.doesNotMatch(manifest.example, /work\/[a-z]+\.jsonl/, `${name}'s example does not write where a job cannot`);
    // The old claims are gone from the description.
    assert.doesNotMatch(manifest.description, /first hour|shape of enumeration|resolves an assumed role back to the session that issued it|unfamiliar addresses|without treating records of unknown outcome as successes/i, name);
  }
});

test("the tools run on the oldest and the newest Python the images and the runners carry: no syntax or stdlib call newer than 3.11", async () => {
  for (const name of NAMES) {
    const script = await readFile(SCRIPTS[name], "utf8");
    assert.doesNotMatch(script, /\bf"[^"]*\{[^}]*"[^"]*"[^}]*\}/, `${name}: no nested quotes in an f-string (3.12 only)`);
    assert.doesNotMatch(script, /\bitertools\.batched|\bexcept\*|^type \w+ =/m, `${name}: no 3.12 or 3.13 only construct`);
    assert.doesNotMatch(script, /zipfile\.is_zipfile/, `${name}: no stdlib validator for dispatch`);
    const out = refused(await tool(SCRIPTS[name], process.cwd(), { path: "/nonexistent-for-cloud-test" }));
    assert.equal(out.status, "failed");
  }
});

test("an answer is ASCII: a non-ASCII or non-UTF-8 name is escaped, so a lone surrogate cannot raise on the way out", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/ünïcode-名前.json", JSON.stringify({ Records: [{ eventName: "X", eventSource: "s3.amazonaws.com", eventTime: "2026-02-14T09:00:00Z", eventID: "u" }] }));
    const run = await tool(TRAIL, cwd, { path: "work/ev" });
    const out: Json = body(run);
    assert.equal(out.record_count, 1);
    // eslint-disable-next-line no-control-regex
    assert.match(run.stdout, /^[\x00-\x7f]*$/, "json.dumps escapes everything outside ASCII");
    assert.match(out.records[0].source_file, /n\u00ef|ünï/);
  });
});

test("a named pipe is never opened: as the path it is refused, and in a directory it is named and skipped", async (t) => {
  let fifo = true;
  await withDir(async (cwd) => {
    try {
      execFileSync("mkfifo", [join(cwd, "work", "pipe.json")]);
    } catch {
      fifo = false;
      return;
    }
    for (const script of Object.values(SCRIPTS)) {
      const out = refused(await tool(script, cwd, { path: "work/pipe.json" }));
      assert.equal(out.status, "failed");
      assert.match(out.error, /neither a regular file|regular file/);
    }
    await put(cwd, "work/ev/ok.json", JSON.stringify({ Records: [{ eventName: "X", eventSource: "s3.amazonaws.com", eventTime: "2026-02-14T09:00:00Z", eventID: "p" }] }));
    execFileSync("mkfifo", [join(cwd, "work", "ev", "pipe.json")]);
    await put(cwd, "work/ev/audit.json", JSON.stringify([{ Operation: "Send", Id: "1", UserId: "a@b.c", CreationTime: "2026-02-14T09:00:00Z" }]));
    for (const script of [TRAIL, UAL]) {
      const out: Json = JSON.parse((await tool(script, cwd, { path: "work/ev" })).stdout);
      assert.ok(out.skipped.some((s: Json) => /not a regular file: it is not opened/.test(s.reason)), `${script}: the pipe is named`);
      assert.equal(out.skipped_count, 1);
    }
    const trail: Json = body(await tool(TRAIL, cwd, { path: "work/ev" }));
    assert.equal(trail.status, "partial", "a file that was not read is not a complete read");
  });
  if (!fifo) t.skip("no mkfifo on this platform");
});

test("the tables say how many distinct values they could not count, and the sign-in analysis names the accounts it left out", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/ok.json", JSON.stringify({ Records: [{ eventName: "X", eventSource: "s3.amazonaws.com", eventTime: "2026-02-14T09:00:00Z", eventID: "p" }] }));
    const ct: Json = body(await tool(TRAIL, cwd, { path: "work/ev/ok.json" }));
    assert.deepEqual([ct.tables_uncounted.by_event, ct.tables_uncounted.by_identity, ct.tables_uncounted.by_address, ct.tables_uncounted.errors], [0, 0, 0, 0]);
    await put(cwd, "work/ev/ual.json", JSON.stringify([{ Operation: "Send", Id: "1", UserId: "a@b.c", CreationTime: "2026-02-14T09:00:00Z" }]));
    const ual: Json = body(await tool(UAL, cwd, { path: "work/ev/ual.json" }));
    assert.equal(ual.tables_uncounted.by_operation, 0);
    await put(cwd, "work/ev/s.json", JSON.stringify({ value: [{ id: "x", createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: "a@b.c", ipAddress: "1.2.3.4", status: { errorCode: 0 } }] }));
    const si: Json = body(await tool(SIGNIN, cwd, { path: "work/ev/s.json" }));
    assert.deepEqual([si.coverage.users_not_analysed_over_cap, si.coverage.users_not_analysed_named], [0, []]);
  });
});


// ---- what is withheld: one test for every credential format ------------------------------------------------------------------

/** One input per tool that carries `fields` where the tool prints free text and named fields (CloudTrail's request, the audit event's
 *  parameters, the sign-in's raw record). */
const carriers: Record<string, { script: string; file: string; text: (t: string) => string; named: (k: string, v: unknown) => string; args?: Json }> = {
  cloudtrail_parse: {
    script: TRAIL, file: "t.json", args: { link_sessions: false },
    text: (t) => trail(ct({ eventID: "s-1", eventSource: "ec2.amazonaws.com", eventName: "RunInstances", userIdentity: ALICE, userAgent: t, errorMessage: t, requestParameters: { description: t }, responseElements: { note: t } })),
    named: (k, v) => trail(ct({ eventID: "s-1", eventSource: "ec2.amazonaws.com", eventName: "RunInstances", userIdentity: ALICE, requestParameters: { [k]: v }, responseElements: { [k]: v }, additionalEventData: { [k]: v } })),
  },
  ual_parse: {
    script: UAL, file: "u.json",
    text: (t) => JSON.stringify([{ Id: "u-1", Operation: "Set-Mailbox", UserId: "alice@example.org", CreationTime: "2026-02-14T09:00:00Z", RecordType: 1, Workload: "Exchange", ClientInfoString: t, Parameters: [{ Name: "Note", Value: t }], ExtendedProperties: [{ Name: "Note", Value: t }] }]),
    named: (k, v) => JSON.stringify([{ Id: "u-1", Operation: "Set-Mailbox", UserId: "alice@example.org", CreationTime: "2026-02-14T09:00:00Z", RecordType: 1, Workload: "Exchange", [k]: v, Parameters: [{ Name: k, Value: v }] }]),
  },
  signin_analyse: {
    script: SIGNIN, file: "s.json",
    text: (t) => JSON.stringify({ value: [{ id: "g-1", createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: "alice@example.org", userId: "u-1", appDisplayName: "App", ipAddress: "198.51.100.1", userAgent: t, status: { errorCode: 50126, failureReason: t, additionalDetails: t } }] }),
    named: (k, v) => JSON.stringify({ value: [{ id: "g-1", createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: "alice@example.org", userId: "u-1", appDisplayName: "App", ipAddress: "198.51.100.1", status: { errorCode: 0 }, [k]: v }] }),
  },
};

async function leakIn(name: string, input: string, secrets: string[]): Promise<string | undefined> {
  const c = carriers[name];
  let found: string | undefined;
  await withDir(async (cwd) => {
    await put(cwd, `work/ev/${c.file}`, input);
    const run = await asJob(c.script, cwd, { path: `work/ev/${c.file}`, limit: 1, ...c.args });
    const parsed = body(run);
    const everything = await everythingBut(cwd, run.stdout + run.stderr, []);
    assert.ok(parsed.values_withheld.count >= 1, `${name}: something was withheld: ${JSON.stringify(parsed.values_withheld.by_reason)}`);
    for (const secret of secrets) {
      const hit = leaked(secret, everything);
      if (hit) found = `${name} printed ${hit} of ${secret.slice(0, 6)}...`;
    }
  });
  return found;
}

for (const [label, secret, text] of TEXT_CASES) {
  test(`a credential in free text is withheld from every channel by all three tools: ${label}`, async () => {
    for (const name of Object.keys(carriers)) assert.equal(await leakIn(name, carriers[name].text(text), [secret]), undefined);
  });
}

for (const [field, value] of NAMED_CASES) {
  test(`a field named ${field} is withheld whatever its value looks like`, async () => {
    const secret = String(value);
    for (const name of Object.keys(carriers)) {
      let marker = "";
      await withDir(async (cwd) => {
        const c = carriers[name];
        await put(cwd, `work/ev/${c.file}`, c.named(field, value));
        const run = await asJob(c.script, cwd, { path: `work/ev/${c.file}`, limit: 1, ...c.args });
        body(run);
        const everything = await everythingBut(cwd, run.stdout + run.stderr, []);
        marker = everything;
        if (typeof value === "string" && value.length >= 6) assert.equal(leaked(secret, everything), undefined, `${name} printed the value of ${field}`);
        else assert.doesNotMatch(everything, new RegExp(`"${field}": ${secret}[,}\\s]`), `${name} printed the value of ${field}`);
      });
      assert.match(marker, /credential-named field/, `${name} says it withheld ${field}`);
    }
  });
}

test("what is evidence and only looks a little like a secret is printed as it is: an access key id, an ARN that names a secret, a GUID, a hash, a client token", async () => {
  for (const name of Object.keys(carriers)) {
    await withDir(async (cwd) => {
      const c = carriers[name];
      const input = c.text("x");
      const note = CONTROLS.map(([, v]) => v);
      const filled =
        name === "cloudtrail_parse"
          ? trail(ct({ eventID: "k-1", eventSource: "ec2.amazonaws.com", eventName: "RunInstances", userIdentity: ALICE, requestParameters: { hints: note, clientToken: "a1b2c3d4-0000-1111-2222-333344445555", secretId: note[1] }, resources: [{ ARN: note[1] }] }))
          : name === "ual_parse"
            ? JSON.stringify([{ Id: "u-1", Operation: "Set-Mailbox", UserId: "alice@example.org", CreationTime: "2026-02-14T09:00:00Z", RecordType: 1, Parameters: [{ Name: "Hint", Value: note.join(" ") }] }])
            : JSON.stringify({ value: [{ id: "g-1", createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: "alice@example.org", userId: "u-1", appDisplayName: "App", ipAddress: "198.51.100.1", status: { errorCode: 0 }, userAgent: note.join(" ") }] });
      assert.ok(input.length > 0);
      await put(cwd, `work/ev/${c.file}`, filled);
      const out = body(await tool(c.script, cwd, { path: `work/ev/${c.file}`, ...c.args }));
      const text = JSON.stringify(out);
      for (const [label, value] of CONTROLS) assert.ok(text.includes(value), `${name} withheld ${label}`);
      if (name === "cloudtrail_parse") assert.ok(text.includes("a1b2c3d4-0000-1111-2222-333344445555"), "a client token that is an idempotency key is evidence");
    });
  }
});

// ---- a filter is not an oracle on a withheld value ---------------------------------------------------------------------------------

test("a filter is matched against the text as printed: the right prefix of a withheld value and a wrong one give the same answer", async () => {
  const token = JWT;
  await withDir(async (cwd) => {
    const trailText = trail(ct({ eventID: "o-1", eventSource: "s3.amazonaws.com", eventName: "GetObject", userIdentity: { type: "IAMUser", userName: token } }));
    await put(cwd, "work/ev/t.json", trailText);
    const right = body(await tool(TRAIL, cwd, { path: "work/ev/t.json", identity: "^" + token.slice(0, 8), link_sessions: false }));
    const wrong = body(await tool(TRAIL, cwd, { path: "work/ev/t.json", identity: "^zzzzzzzz", link_sessions: false }));
    assert.equal(right.record_count, wrong.record_count, "cloudtrail_parse: identity");
    assert.equal(right.record_count, 0);
    const marker = body(await tool(TRAIL, cwd, { path: "work/ev/t.json", identity: "withheld", link_sessions: false }));
    assert.equal(marker.record_count, 1, "the printed marker can be filtered on, which says nothing about the original");

    await put(cwd, "work/ev/u.json", JSON.stringify([{ Id: "u-1", Operation: "Send", UserId: token, CreationTime: "2026-02-14T09:00:00Z" }]));
    const uRight = body(await tool(UAL, cwd, { path: "work/ev/u.json", user: "^" + token.slice(0, 8) }));
    const uWrong = body(await tool(UAL, cwd, { path: "work/ev/u.json", user: "^zzzzzzzz" }));
    assert.equal(uRight.record_count, uWrong.record_count, "ual_parse: user");

    await put(cwd, "work/ev/s.json", JSON.stringify({ value: [{ id: "g-1", createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: token, appDisplayName: "App", ipAddress: "198.51.100.1", status: { errorCode: 0 } }] }));
    const sRight = body(await tool(SIGNIN, cwd, { path: "work/ev/s.json", user: "^" + token.slice(0, 8) }));
    const sWrong = body(await tool(SIGNIN, cwd, { path: "work/ev/s.json", user: "^zzzzzzzz" }));
    assert.equal(sRight.event_count, sWrong.event_count, "signin_analyse: user");
    assert.equal(sRight.coverage.events_filtered_out, 1);
  });
});

test("a filter pattern that can take exponential or very long time is refused or stopped, named, and the call returns", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/t.json", trail(ct({ eventID: "r-1", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::1:user/" + "a".repeat(41) } })));
    await put(cwd, "work/ev/u.json", JSON.stringify([{ Id: "u-1", Operation: "Send", UserId: "a".repeat(41), CreationTime: "2026-02-14T09:00:00Z" }]));
    await put(cwd, "work/ev/s.json", JSON.stringify({ value: [{ id: "g-1", createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: "a".repeat(41), status: { errorCode: 0 } }] }));
    const cases: Array<[string, string, string, string]> = [[TRAIL, "identity", "t.json", "link_sessions"], [UAL, "user", "u.json", ""], [SIGNIN, "user", "s.json", ""]];
    for (const [script, key, file] of cases.map((c) => [c[0], c[1], c[2]])) {
      for (const pattern of ["(a+)+$", "(a|aa)+$", "(a*)*b", "(.*)\\1", ".*.*.*.*.*.*x"]) {
        const started = Date.now();
        const out = refused(await tool(script, cwd, { path: `work/ev/${file}`, [key]: pattern, time_limit_seconds: 5 }));
        assert.equal(out.status, "failed");
        assert.match(out.error, /refused|took longer/, `${script.split("/").slice(-2)[0]} ${pattern}`);
        assert.ok(Date.now() - started < 20_000, `${pattern} returned in ${Date.now() - started} ms`);
      }
      // A pattern with a few repeats that does finish quickly is accepted.
      const ok = await tool(script, cwd, { path: `work/ev/${file}`, [key]: "^a.*$|arn:aws:iam::\\d+:user/.*" });
      assert.equal(ok.code, 0, ok.stdout);
    }
  });
});

test("an argument the tool does not take is refused, naming it and the ones it takes", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.json", "{}");
    for (const script of Object.values(SCRIPTS)) {
      const out = refused(await tool(script, cwd, { path: "work/ev/a.json", identiy: "alice", usr: "x" }));
      assert.equal(out.status, "failed");
      assert.match(out.error, /unknown argument\(s\): identiy, usr\. This tool takes: .*path/);
    }
  });
});

// ---- the process ends cleanly ---------------------------------------------------------------------------------------------------------

test("SIGTERM, which is what a job's timeout sends first, leaves no temporary result, no index and no half-written file behind", async (t) => {
  for (const [name, script, file, make] of [
    ["cloudtrail_parse", TRAIL, "big.json", (n: number) => JSON.stringify({ Records: Array.from({ length: n }, (_, i) => ct({ eventID: `g-${i}`, eventSource: "s3.amazonaws.com", eventName: "GetObject", userIdentity: ALICE })) })],
    ["ual_parse", UAL, "big.json", (n: number) => JSON.stringify(Array.from({ length: n }, (_, i) => ({ Id: `u-${i}`, Operation: "Send", UserId: "a@b.c", CreationTime: "2026-02-14T09:00:00Z" })))],
    ["signin_analyse", SIGNIN, "big.json", (n: number) => JSON.stringify({ value: Array.from({ length: n }, (_, i) => ({ id: `g-${i}`, createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: `u${i % 50}@example.org`, userId: `id-${i % 50}`, ipAddress: "198.51.100.1", status: { errorCode: 0 } })) })],
  ] as Array<[string, string, string, (n: number) => string]>) {
    let skipped: string | undefined;
    await withDir(async (cwd) => {
      await put(cwd, `work/ev/${file}`, make(300_000));
      await asJob(script, cwd, { path: "work/ev/missing" }); // makes the job output directory
      const { child, done } = spawnTool(script, cwd, { path: `work/ev/${file}`, out_file: "out/all.jsonl", time_limit_seconds: 300 }, { JOB_ID: "jterm", OUT: join(cwd, "out") });
      let temp: string | undefined;
      for (let i = 0; i < 400 && !temp; i++) {
        await new Promise((r) => setTimeout(r, 25));
        temp = (await readdir(join(cwd, "out"))).find((f) => f.startsWith(".") && f !== ".");
      }
      if (!temp) {
        skipped = `${name} finished before it could be signalled`;
        child.kill("SIGKILL");
        await done;
        return;
      }
      child.kill("SIGTERM");
      const run = await done;
      assert.equal(run.signal ?? null, null, `${name} exited by itself`);
      assert.equal(run.code, 143, `${name} exit code after SIGTERM: ${run.stderr}`);
      const left = (await filesUnder(join(cwd, "out"))).concat(await filesUnder(join(cwd, "work", "s1")));
      assert.deepEqual(left.filter((f) => !f.endsWith("/")), [], `${name} left files behind`);
      assert.equal(await exists(join(cwd, "out", "all.jsonl")), false, "the requested name only ever holds a finished result");
    });
    if (skipped) t.diagnostic(skipped);
  }
});

test("a job writes only under $OUT: with the run directory read-only, each tool still answers and leaves its files in $OUT", async (t) => {
  if (process.getuid?.() === 0) return t.skip("running as root: a read-only directory does not stop a write");
  const trees: Array<[string, string, string]> = [
    [TRAIL, "t.json", trail(ct({ eventID: "ro-1", eventSource: "sts.amazonaws.com", eventName: "AssumeRole" }), ct({ eventID: "ro-2", eventSource: "s3.amazonaws.com", eventName: "GetObject", userIdentity: ALICE }))],
    [UAL, "u.json", JSON.stringify([{ Id: "u-1", Operation: "Send", UserId: "a@b.c", CreationTime: "2026-02-14T09:00:00Z" }])],
    [SIGNIN, "s.json", JSON.stringify({ value: [{ id: "g-1", createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: "a@b.c", status: { errorCode: 0 } }] })],
  ];
  for (const [script, file, text] of trees) {
    await withDir(async (cwd) => {
      await put(cwd, `work/ev/${file}`, text);
      const outDir = join(cwd, "out");
      await asJob(script, cwd, { path: `work/ev/${file}` }, {}, "out", "jprime");
      const locked = [cwd, join(cwd, "work"), join(cwd, "work", "ev"), join(cwd, "work", "s1"), join(cwd, "inputs")];
      try {
        for (const d of locked) await chmod(d, 0o555);
        const run = await asJob(script, cwd, { path: `work/ev/${file}`, limit: 1, out_file: join(outDir, "all.jsonl") }, {}, "out", "jro");
        assert.equal(run.code, 0, run.stderr + run.stdout);
        const answer = JSON.parse(run.stdout);
        assert.equal(answer.status, "complete");
        assert.ok((await stat(outDir)).isDirectory());
      } finally {
        for (const d of locked) await chmod(d, 0o755);
      }
    });
  }
});

// ---- the code itself ---------------------------------------------------------------------------------------------------------------------

test("the shared block is the only place a shared name is bound: nothing after its end marker re-binds one of its names", async () => {
  for (const name of NAMES) {
    const text = await readFile(SCRIPTS[name], "utf8");
    const [shared, rest] = [text.slice(0, text.indexOf(END)), text.slice(text.indexOf(END))];
    const bound = new Set([...shared.matchAll(/^([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)/gm), ...shared.matchAll(/^(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)/gm)].map((m) => m[1]));
    const again = [...rest.matchAll(/^([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)/gm), ...rest.matchAll(/^(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)/gm)].map((m) => m[1]).filter((n) => bound.has(n));
    assert.deepEqual(again, [], `${name} re-binds a name of the shared block`);
  }
});

test("a source file holds no invisible or direction-changing character, and no non-ASCII character at all", async () => {
  for (const name of NAMES) {
    const text = await readFile(SCRIPTS[name], "utf8");
    // eslint-disable-next-line no-control-regex
    const bad = [...text.matchAll(/[^\x09\x0a\x20-\x7e]/g)].map((m) => `U+${m[0].codePointAt(0)!.toString(16).padStart(4, "0")} at ${m.index}`);
    assert.deepEqual(bad.slice(0, 5), [], `${name} has characters a reviewer cannot see`);
  }
});


test("a read that ended early publishes out_file as <name>.partial in all three tools", async () => {
  const bigs: Array<[string, string, string]> = [
    ["cloudtrail_parse", TRAIL, JSON.stringify({ Records: Array.from({ length: 3000 }, (_, i) => ct({ eventID: `p-${i}`, eventSource: "s3.amazonaws.com", eventName: "GetObject", requestParameters: { k: `v-${i}-${"y".repeat(30)}` } })) })],
    ["ual_parse", UAL, JSON.stringify(Array.from({ length: 3000 }, (_, i) => ({ Id: `u-${i}`, Operation: "Send", UserId: "a@b.c", CreationTime: "2026-02-14T09:00:00Z", Pad: `v-${i}-${"y".repeat(30)}` })))],
    ["signin_analyse", SIGNIN, JSON.stringify({ value: Array.from({ length: 3000 }, (_, i) => ({ id: `g-${i}`, createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: `u${i % 7}@example.org`, userId: `id-${i % 7}`, ipAddress: "198.51.100.1", status: { errorCode: 0 }, pad: `v-${i}-${"y".repeat(30)}` })) })],
  ];
  for (const [name, script, text] of bigs) {
    await withDir(async (cwd) => {
      const whole = gzipSync(Buffer.from(text));
      await put(cwd, "work/ev/cut.json.gz", whole.subarray(0, Math.floor(whole.length * 0.7)));
      const cut = body(await tool(script, cwd, { path: "work/ev/cut.json.gz", out_file: "work/s1/all.jsonl", limit: 5 }));
      assert.equal(cut.status, "partial", name);
      const where = cut.partial_records ?? cut.partial_events;
      assert.equal(cut.complete_records ?? cut.complete_events, undefined, `${name}: a partial result is not named complete`);
      assert.match(where, /all\.partial\.jsonl$/, name);
      assert.equal(await exists(join(cwd, "work/s1/all.jsonl")), false, `${name}: the requested name holds only a finished result`);
      assert.equal(await exists(join(cwd, "work/s1/all.partial.jsonl")), true, name);
      await put(cwd, "work/ev/whole.json.gz", whole);
      const full = body(await tool(script, cwd, { path: "work/ev/whole.json.gz", out_file: "work/s1/full.jsonl", limit: 5 }));
      assert.equal(full.status, "complete", name);
      assert.match(full.complete_records ?? full.complete_events, /full\.jsonl$/, name);
    });
  }
});


test("a file of nothing but white space is empty and not a complete read of nothing, a link that leads nowhere says so, and a NextPageUri is a next page", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/empty.json", "");
    await put(cwd, "work/ev/white.json", "  \n\n \t\n");
    await symlink("loop-b", join(cwd, "work", "ev", "loop-a"));
    await symlink("loop-a", join(cwd, "work", "ev", "loop-b"));
    for (const script of Object.values(SCRIPTS)) {
      for (const file of ["empty.json", "white.json"]) {
        const out = refused(await tool(script, cwd, { path: `work/ev/${file}` }));
        assert.equal(out.status, "failed", `${script.split("/").slice(-2)[0]} ${file}`);
      }
      assert.match(refused(await tool(script, cwd, { path: "work/ev/loop-a" })).error, /link that does not lead to a file/);
    }
    const page = (name: string, text: string): Promise<Json> => put(cwd, `work/ev/${name}`, text).then(() => ({}));
    await page("ct.json", JSON.stringify({ Records: [{ eventName: "X", eventSource: "s3.amazonaws.com", eventTime: "2026-02-14T09:00:00Z", eventID: "1" }], NextPageUri: "https://example.invalid/page2" }));
    await page("ual.json", JSON.stringify({ value: [{ Id: "1", Operation: "Send", UserId: "a@b.c", CreationTime: "2026-02-14T09:00:00Z" }], NextPageUri: "https://example.invalid/page2" }));
    await page("si.json", JSON.stringify({ value: [{ id: "1", createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: "a@b.c", status: { errorCode: 0 } }], NextPageUri: "https://example.invalid/page2" }));
    for (const [script, file] of [[TRAIL, "ct.json"], [UAL, "ual.json"], [SIGNIN, "si.json"]] as Array<[string, string]>) {
      const out = body(await tool(script, cwd, { path: `work/ev/${file}` }));
      assert.equal(out.status, "partial", file);
      assert.deepEqual(out.pagination_markers.flatMap((m: Json) => m.keys), ["NextPageUri"], file);
      assert.ok(!JSON.stringify(out).includes("example.invalid"), "a next-page link is never printed");
    }
  });
});


test("a value named a checksum or a digest is not taken for a key by its length: a base64 SHA-256 and SHA-512 stay, the same text in a field of another name is withheld", async () => {
  const sha256 = Buffer.from(createHash("sha256").update("a").digest()).toString("base64");
  const sha512 = Buffer.from(createHash("sha512").update("a").digest()).toString("base64");
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/t.json", trail(ct({ eventID: "c-1", eventSource: "s3.amazonaws.com", eventName: "PutObject", userIdentity: ALICE, requestParameters: { "x-amz-checksum-sha256": sha256, ChecksumSHA512: sha512, contentMD5: "1B2M2Y8AsgTpgAmY7PhCfg==", other: sha256 } })));
    const out = body(await tool(TRAIL, cwd, { path: "work/ev/t.json", link_sessions: false }));
    const request = out.records[0].request;
    assert.equal(request["x-amz-checksum-sha256"], sha256);
    assert.equal(request.ChecksumSHA512, sha512);
    assert.match(request.other, /withheld/);
  });
});

test("a long string of the shape of a token costs time in proportion to its length, and a scan that meets the deadline withholds what it did not scan", async () => {
  await withDir(async (cwd) => {
    const blob = "eyJ".repeat(100_000);
    const records = [1, 2].map((i) => ct({ eventID: `big-${i}`, eventSource: "s3.amazonaws.com", eventName: "PutObject", userIdentity: ALICE, requestParameters: { blob } }));
    await put(cwd, "work/ev/t.json", trail(...records));
    const started = Date.now();
    const out = body(await tool(TRAIL, cwd, { path: "work/ev/t.json", link_sessions: false, time_limit_seconds: 5 }));
    assert.ok(Date.now() - started < 15_000, `two 300 KB records took ${Date.now() - started} ms`);
    assert.equal(out.coverage.records_read, 2);
    // Behind a long deadline-less scan the other tools take the same text through the same rules.
    await put(cwd, "work/ev/u.json", JSON.stringify([{ Id: "1", Operation: "Send", UserId: "a@b.c", CreationTime: "2026-02-14T09:00:00Z", Pad: blob }]));
    const started2 = Date.now();
    body(await tool(UAL, cwd, { path: "work/ev/u.json" }));
    assert.ok(Date.now() - started2 < 15_000, `ual_parse took ${Date.now() - started2} ms`);
  });
});

test("SIGTERM flushes the values file: what the run withheld before the signal is in the file the job seals", async () => {
  const secret = "Hunter2-correct-horse-9";
  for (const [name, script, make] of [
    ["cloudtrail_parse", TRAIL, (n: number) => JSON.stringify({ Records: Array.from({ length: n }, (_, i) => ct({ eventID: `g-${i}`, eventSource: "s3.amazonaws.com", eventName: "GetObject", userIdentity: ALICE, requestParameters: i === 0 ? { password: secret } : {} })) })],
    ["ual_parse", UAL, (n: number) => JSON.stringify(Array.from({ length: n }, (_, i) => ({ Id: `u-${i}`, Operation: "Send", UserId: "a@b.c", CreationTime: "2026-02-14T09:00:00Z", ...(i === 0 ? { Password: secret } : {}) })))],
    ["signin_analyse", SIGNIN, (n: number) => JSON.stringify({ value: Array.from({ length: n }, (_, i) => ({ id: `g-${i}`, createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: `u${i % 50}@example.org`, userId: `id-${i % 50}`, status: { errorCode: 0 }, ...(i === 0 ? { password: secret } : {}) })) })],
  ] as Array<[string, string, (n: number) => string]>) {
    await withDir(async (cwd) => {
      await put(cwd, "work/ev/big.json", make(300_000));
      await asJob(script, cwd, { path: "work/ev/missing" });
      const { child, done } = spawnTool(script, cwd, { path: "work/ev/big.json", write_values: true, time_limit_seconds: 300, ...(name === "cloudtrail_parse" ? { link_sessions: false } : {}) }, { JOB_ID: "jflush", OUT: join(cwd, "out") });
      // The paged result is opened at the 501st row, so once a file is there the first record, which holds the secret, was withheld.
      let started = false;
      for (let i = 0; i < 1200 && !started; i++) {
        await new Promise((r) => setTimeout(r, 25));
        started = (await readdir(join(cwd, "out", "tool-output")).catch(() => [])).length > 0;
      }
      assert.ok(started, `${name}: the run reached its 501st row`);
      child.kill("SIGTERM");
      const run = await done;
      if (run.code === 0) return; // the run finished before the signal: nothing to show
      assert.equal(run.code, 143, name);
      const file = (await readdir(join(cwd, "out"))).find((f) => f.endsWith("-values.jsonl"));
      assert.ok(file, `${name}: the values file is kept`);
      assert.ok((await readFile(join(cwd, "out", file!), "utf8")).includes(secret), `${name}: the withheld original reached the file before the process ended`);
    });
  }
});
