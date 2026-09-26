/**
 * Custody after Fable's and Codex's reading of the recorded verdicts: every
 * check says its status, so an omitted or failed one never reads as a quiet
 * pass; the verdict seals each chain's length and head, and a re-check names
 * what was written after the seal; the operator's audit is chained and
 * matched to the trace; acquisition hashes are held to the evidence; a
 * read-only verify writes nothing; the verdict can be signed and timestamped,
 * and a reference clock's offset recorded.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { custodyAnchorPath, takeCustody, verdictOf, verifyCustody, type Custody } from "../scripts/custody.ts";
import { afterSeal, checksOf, parseAcquisitionHashes, readTimestampResponse, timestampRequest, verifySignature } from "../scripts/custody-checks.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const md5 = (s: string) => createHash("md5").update(s).digest("hex");

/** Trace lines chained as the collector writes them: each names the sha256 of the line before (the first, ""). */
function chained(objs: unknown[], after = ""): string {
  let prev = after;
  let out = "";
  for (const o of objs) {
    const line = JSON.stringify({ ...(o as Record<string, unknown>), prev });
    out += `${line}\n`;
    prev = sha(line);
  }
  return out;
}

async function appendChained(file: string, objs: unknown[]): Promise<void> {
  const last = (await readFile(file, "utf8")).trim().split("\n").at(-1) ?? "";
  await appendFile(file, chained(objs, last ? sha(last) : ""));
}

/** A run with two evidence files, a trace, and its runs directory holding the operator's audit. */
async function run(extra: { acquisition?: unknown; traceLines?: unknown[] } = {}): Promise<{ root: string; runs: string }> {
  const runs = await mkdtemp(join(tmpdir(), "custody-seal-runs-"));
  dirs.push(runs);
  const root = join(runs, "s1");
  await mkdir(join(root, "inputs"), { recursive: true });
  await writeFile(join(root, "inputs", "disk.E01"), "disk bytes\n");
  await writeFile(join(root, "inputs", "notes.txt"), "notes\n");
  await writeFile(
    join(root, "inputs.json"),
    JSON.stringify({
      source: "/evidence",
      bytes: 17,
      held: "bind",
      files: [
        { path: "inputs/disk.E01", bytes: 11, sha256: sha("disk bytes\n"), md5: md5("disk bytes\n") },
        { path: "inputs/notes.txt", bytes: 6, sha256: sha("notes\n") },
      ],
      ...(extra.acquisition ? { acquisition: extra.acquisition } : {}),
    }),
  );
  await mkdir(join(root, "traces"), { recursive: true });
  const lines = extra.traceLines ?? [{ ts: "2026-09-26T10:00:00Z", agent: "a0", tool: "bash", args: {}, result: { ok: true } }];
  await writeFile(join(root, "traces", "events.jsonl"), chained(lines));
  await writeFile(custodyAnchorPath(root), JSON.stringify({ run: "s1", started_at: "2026-09-26T10:00:00Z" }));
  return { root, runs };
}

/** Lines of the operator's audit, chained as swarm.sh writes them. */
async function audit(runs: string, lines: Array<Record<string, unknown>>): Promise<void> {
  let prev: string | null = null;
  let text = "";
  for (const l of lines) {
    const line = JSON.stringify({ ...l, prev });
    text += `${line}\n`;
    prev = sha(line);
  }
  await writeFile(join(runs, "operator-audit.jsonl"), text);
}

test("every check says its status, and the summary says the evidence is unchanged since the run began", async () => {
  const { root, runs } = await run();
  const c = await takeCustody(root, { runsDir: runs });
  const status = Object.fromEntries(c.checks.map((x) => [x.name, x.status]));
  assert.equal(status.evidence, "passed");
  assert.equal(status["acquisition hashes"], "not_applicable");
  assert.equal(status["store"], "not_applicable");
  assert.equal(status["operator audit"], "not_applicable");
  assert.match(c.summary, /evidence unchanged since the run began \(.*\); acquisition hashes not given \(--inputs-hashes\)/);
  assert.match(c.summary, /checks: \d+ passed, 0 failed, 0 incomplete, 0 unavailable/);
  assert.match(c.summary, /anchors are the operator's own files beside the run/);
  assert.ok(c.timing.total_ms >= 0 && "the evidence re-hash" in c.timing.phases, "the parts' durations are recorded");
  assert.equal(c.timing.evidence_bytes, 17);
  // A part that raised is unavailable, with why; never an absent part that reads as nothing wrong.
  const errored = checksOf({ ...c, store: null, not_reached: [] } as never, { store: "the journal could not be read (EIO)" });
  assert.deepEqual(errored.find((x) => x.name === "store"), { name: "store", status: "unavailable", reason: "the journal could not be read (EIO)" });
  const partial = verdictOf({ phase: "the trace", run: "s1", inputsDone: true, inputs: null, sessions: { files: [], digest: "d", not_files: [] } }, "ended");
  assert.equal(partial.checks.find((x) => x.name === "trace")?.status, "incomplete");
});

test("the acquisition hashes given at kickoff are held to the evidence as re-hashed, and a mismatch is said", async () => {
  const good = await run({ acquisition: { source: "imager.log", source_sha256: "a".repeat(64), entries: [{ path: "inputs/disk.E01", algo: "md5", digest: md5("disk bytes\n") }, { path: "inputs/notes.txt", algo: "sha256", digest: sha("notes\n") }] } });
  const c = await takeCustody(good.root, { runsDir: good.runs });
  assert.deepEqual(c.acquisition, { source: "imager.log", source_sha256: "a".repeat(64), given: 2, matched: 2, mismatched: [], not_compared: [] });
  assert.match(c.summary, /matches the acquisition hashes given \(2 of 2\)/);
  const bad = await run({ acquisition: { source: "imager.log", entries: [{ path: "inputs/disk.E01", algo: "md5", digest: "0".repeat(32) }, { path: "inputs/notes.txt", algo: "sha1", digest: "1".repeat(40) }] } });
  const b = await takeCustody(bad.root, { runsDir: bad.runs });
  assert.deepEqual(b.acquisition?.mismatched, ["inputs/disk.E01 (md5)"]);
  assert.deepEqual(b.acquisition?.not_compared, ["inputs/notes.txt (sha1)"], "a digest custody did not compute is not compared, and said");
  assert.equal(b.checks.find((x) => x.name === "acquisition hashes")?.status, "failed");
  assert.match(b.summary, /DOES NOT MATCH THE ACQUISITION HASHES GIVEN: inputs\/disk\.E01 \(md5\)/);
});

test("an imager's hash list is read in the shapes imagers write, matched to the inputs by path or unique name", () => {
  const inputs = ["inputs/disk.E01", "inputs/mem/memdump.mem", "inputs/a/x.bin", "inputs/b/x.bin"];
  const text = [
    "# acquired 2026-09-01",
    `${"a".repeat(32)}  disk.E01`,
    `SHA256 (mem/memdump.mem) = ${"b".repeat(64)}`,
    `memdump.mem ${"c".repeat(40)}`,
    `${"d".repeat(64)} *x.bin`,
    `${"e".repeat(64)}  other.E01`,
    "Case number: 42",
  ].join("\n");
  const r = parseAcquisitionHashes(text, inputs);
  assert.deepEqual(r.entries, [
    { path: "inputs/disk.E01", algo: "md5", digest: "a".repeat(32) },
    { path: "inputs/mem/memdump.mem", algo: "sha256", digest: "b".repeat(64) },
    { path: "inputs/mem/memdump.mem", algo: "sha1", digest: "c".repeat(40) },
  ]);
  assert.deepEqual(r.unmatched, ["*x.bin", "other.E01"], "an ambiguous name and one not among the inputs are named");
  assert.equal(r.ignored, 1);
});

test("the operator's audit is chained and each operator line on the trace is on it", async () => {
  const stopLine = { ts: "2026-09-26T10:05:00Z", recv_ts: "2026-09-26T10:05:00Z", agent: "system", tool: "operator_action", args: { command: "stop", argv: ["s1"] }, result: {}, agent_unverified: true };
  const { root, runs } = await run({ traceLines: [{ ts: "2026-09-26T10:00:00Z", agent: "a0", tool: "bash", args: {}, result: {} }, stopLine] });
  await audit(runs, [
    { at: "2026-09-26T10:00:00Z", command: "start", argv: ["--n", "1"], cwd: "/", os_user: "h", host: "m", via: "cli" },
    { at: "2026-09-26T10:05:01Z", command: "stop", argv: ["s1"], cwd: "/", os_user: "h", host: "m", via: "cli" },
  ]);
  const c = await takeCustody(root, { runsDir: runs });
  assert.equal(c.operator?.intact, true);
  assert.equal(c.operator?.matched, 1);
  assert.equal(c.checks.find((x) => x.name === "operator audit")?.status, "passed");
  assert.match(c.summary, /1 operator action from a shell outside the run, each on the operator audit/);
  // An audit line changed afterwards breaks its chain; a trace action it does not carry is named.
  const text = await readFile(join(runs, "operator-audit.jsonl"), "utf8");
  await writeFile(join(runs, "operator-audit.jsonl"), text.replace('"argv":["--n","1"]', '"argv":["--n","9"]'));
  await appendChained(join(root, "traces", "events.jsonl"), [{ ...stopLine, args: { command: "say", argv: ["s1", "hello"] } }]);
  const d = await takeCustody(root, { runsDir: runs });
  assert.equal(d.operator?.intact, false);
  assert.equal(d.operator?.unmatched.length, 1);
  assert.equal(d.checks.find((x) => x.name === "operator audit")?.status, "failed");
  assert.match(d.summary, /OPERATOR AUDIT CHAIN BROKEN/);
});

test("a read-only check writes nothing; verify holds the run to the sealed prefix and names the closing lines after it", async () => {
  const { root, runs } = await run();
  const anchorBefore = await readFile(custodyAnchorPath(root), "utf8");
  const ro = await takeCustody(root, { readOnly: true, runsDir: runs });
  assert.ok(ro.checks.length);
  assert.equal(existsSync(join(root, "custody.json")), false, "no verdict written");
  assert.equal(existsSync(join(root, "artifacts.json")), false, "no index written");
  assert.equal(await readFile(custodyAnchorPath(root), "utf8"), anchorBefore, "the anchor is untouched");
  const c = await takeCustody(root, { runsDir: runs });
  assert.equal(c.seal.trace.lines, 1);
  // The hub's own lines after custody, and the operator's stop: expected, and named.
  const closing = [
    { ts: "2026-09-26T10:06:00Z", agent: "system", tool: "custody", args: { via: "hub" }, result: { ok: true } },
    { ts: "2026-09-26T10:06:00Z", agent: "system", tool: "hub_clear_up", args: {}, result: { ok: true } },
    { ts: "2026-09-26T10:06:01Z", agent: "system", tool: "operator_action", args: { command: "stop", argv: ["s1", "--after-hub"] }, result: {}, agent_unverified: true },
  ];
  await appendChained(join(root, "traces", "events.jsonl"), closing);
  const v = await verifyCustody(root, { runsDir: runs });
  assert.equal(v.prefix.intact, true, v.prefix.detail);
  assert.deepEqual(v.after_seal, { lines: 3, tools: ["custody", "hub_clear_up", "operator_action:stop"], closure_only: true });
  assert.equal(v.verdict.anchor, "matches the verdict anchored outside the run");
  assert.equal(v.ok, true, JSON.stringify(v, null, 1));
  // A sealed line changed afterwards is found; so is a line after the seal that is not a closing one.
  const text = await readFile(join(root, "traces", "events.jsonl"), "utf8");
  await writeFile(join(root, "traces", "events.jsonl"), text.replace('"tool":"bash"', '"tool":"record"'));
  await appendChained(join(root, "traces", "events.jsonl"), [{ ts: "t", agent: "a0", tool: "record", args: {}, result: {} }]);
  const w = await verifyCustody(root, { runsDir: runs });
  assert.equal(w.prefix.intact, false);
  assert.match(w.prefix.detail, /THE SEALED PREFIX CHANGED/);
  assert.equal(w.after_seal.closure_only, false);
  assert.equal(w.ok, false);
  assert.deepEqual(afterSeal('{"tool":"custody"}\n{"tool":"bash"}\n', 1), { lines: 1, tools: ["bash"], closure_only: false });
});

test("the verdict is signed with an SSH key and timestamped by an RFC 3161 authority; a reference clock's offset is recorded; verify checks them", async () => {
  const { root, runs } = await run();
  const keyDir = await mkdtemp(join(tmpdir(), "custody-key-"));
  dirs.push(keyDir);
  const key = join(keyDir, "id");
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "examiner@lab", "-f", key]);
  // A stand-in authority: a granted response that carries the digest asked for and a time.
  const genTime = Buffer.from("20260926120000Z", "latin1");
  const server: Server = createServer((req, res) => {
    if (req.method === "HEAD") {
      res.writeHead(200, { date: new Date(Date.now() + 5_000).toUTCString() });
      res.end();
      return;
    }
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const at = body.indexOf(Buffer.from([0x04, 0x20]));
      const digest = body.subarray(at + 2, at + 34);
      const status = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]);
      const token = Buffer.concat([Buffer.from([0x04, 0x20]), digest, Buffer.from([0x18, genTime.length]), genTime]);
      const resp = Buffer.concat([Buffer.from([0x30, status.length + token.length]), status, token]);
      res.writeHead(200, { "content-type": "application/timestamp-reply" });
      res.end(resp);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/tsa`;
  try {
    const c = await takeCustody(root, { runsDir: runs, signKey: key, timestampUrl: url, timeReference: url });
    assert.ok(c.time_reference && c.time_reference.offset_ms !== null && c.time_reference.offset_ms >= 3000 && c.time_reference.offset_ms <= 7000, JSON.stringify(c.time_reference));
    assert.match(c.summary, /the host's clock behind http:\/\/127\.0\.0\.1:\d+\/tsa by \d+ ms/);
    assert.ok(existsSync(join(root, "custody.json.sig")));
    assert.ok(existsSync(join(root, "custody.json.tsr")));
    const anchor = JSON.parse(await readFile(custodyAnchorPath(root), "utf8")) as { custody: Array<{ signature?: { sha256?: string }; timestamp?: { gen_time?: string }; seal?: unknown }> };
    const last = anchor.custody.at(-1);
    assert.match(String(last?.signature?.sha256), /^[0-9a-f]{64}$/);
    assert.equal(last?.timestamp?.gen_time, "2026-09-26T12:00:00Z");
    assert.ok(last?.seal, "the seal is in the anchor too");
    const sig = await verifySignature(join(root, "custody.json"), join(root, "custody.json.sig"));
    assert.equal(sig.ok, true, sig.detail);
    const v = await verifyCustody(root, { runsDir: runs });
    assert.equal(v.signature.ok, true);
    assert.equal(v.timestamp.imprint, true);
    assert.equal(v.ok, true, JSON.stringify(v, null, 1));
    // An edited verdict: the signature no longer holds, nor does the anchor or the token.
    const text = await readFile(join(root, "custody.json"), "utf8");
    await writeFile(join(root, "custody.json"), text.replace('"run": "s1"', '"run": "s2"'));
    const edited = await verifyCustody(root, { runsDir: runs });
    assert.equal(edited.signature.ok, false);
    assert.equal(edited.timestamp.imprint, false);
    assert.equal(edited.ok, false);
  } finally {
    server.close();
  }
});

test("a timestamp request is DER for sha256, and a response is read for its status, digest and time", () => {
  const digest = sha("x");
  const req = timestampRequest(digest, Buffer.from([1, 2, 3, 4]));
  assert.equal(req[0], 0x30);
  assert.ok(req.includes(Buffer.from(digest, "hex")));
  assert.ok(req.includes(Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])), "the sha256 OID");
  const refused = Buffer.from([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02]);
  assert.deepEqual(readTimestampResponse(refused, digest), { granted: false, status: 2, imprint: false, gen_time: null });
});

test("custody's CLI exits 4 when a check does not pass, 0 when all do", async () => {
  const { root, runs } = await run();
  const cli = (r: string) => {
    try {
      execFileSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "..", "scripts", "custody.ts"), r, "--quiet", "--runs-dir", runs], { stdio: "pipe" });
      return 0;
    } catch (err) {
      return (err as { status: number }).status;
    }
  };
  assert.equal(cli(root), 0);
  await writeFile(join(root, "inputs", "notes.txt"), "changed\n");
  assert.equal(cli(root), 4, "the evidence changed: a verdict, and not a pass");
  const c = JSON.parse(await readFile(join(root, "custody.json"), "utf8")) as Custody;
  assert.equal(c.checks.find((x) => x.name === "evidence")?.status, "failed");
});
