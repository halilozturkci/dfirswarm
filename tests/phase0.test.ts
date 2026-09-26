// Two phase-0 promises no test held: a credential in a trace line is
// replaced before the line is written, and the console listens on this
// machine only unless told otherwise.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appendEvent, EVENTS_REL, initSandbox } from "../extensions/protocol.ts";

test("a trace line that carries the pane's trace token or the console's token keeps neither", async () => {
  const root = await mkdtemp(join(tmpdir(), "p0-redact-"));
  const saved = { t: process.env.SWARM_TRACE_TOKEN, u: process.env.SWARM_UI_TOKEN, s: process.env.SWARM_TRACE_SOCKET };
  try {
    await initSandbox(root, { swarmId: "s1", agentIds: ["a0"], capUsd: 1, wallClockMinutes: 5 });
    process.env.SWARM_TRACE_TOKEN = "trace-token-0123456789";
    process.env.SWARM_UI_TOKEN = "ui-token-abcdefghij";
    delete process.env.SWARM_TRACE_SOCKET;
    // An `env` a shell printed, whole, into a tool result.
    await appendEvent(root, { agent: "a0", tool: "bash", args: { command: "env" }, result: { output: "SWARM_TRACE_TOKEN=trace-token-0123456789\nSWARM_UI_TOKEN=ui-token-abcdefghij\n" } });
    const text = await readFile(join(root, EVENTS_REL), "utf8");
    assert.doesNotMatch(text, /trace-token-0123456789/);
    assert.doesNotMatch(text, /ui-token-abcdefghij/);
    assert.match(text, /\[secret SWARM_TRACE_TOKEN\]/);
    assert.match(text, /\[secret SWARM_UI_TOKEN\]/);
  } finally {
    for (const [k, v] of [["SWARM_TRACE_TOKEN", saved.t], ["SWARM_UI_TOKEN", saved.u], ["SWARM_TRACE_SOCKET", saved.s]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await rm(root, { recursive: true, force: true });
  }
});

test("the console listens on 127.0.0.1 unless it is told another address", async () => {
  const runs = await mkdtemp(join(tmpdir(), "p0-ui-"));
  const env: NodeJS.ProcessEnv = { ...process.env, SWARM_RUNS_DIR: runs };
  delete env.SWARM_UI_HOST;
  const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "..", "scripts", "ui-server.ts"), "--port", "0"], { env, stdio: ["ignore", "pipe", "pipe"] });
  try {
    let out = "";
    const url = await new Promise<string>((done, fail) => {
      const timer = setTimeout(() => fail(new Error(`the console printed no address: ${out}`)), 20_000);
      const onData = (d: Buffer) => {
        out += d.toString();
        const m = out.match(/https?:\/\/[^\s]+/);
        if (m) {
          clearTimeout(timer);
          done(m[0]);
        }
      };
      child.stdout.on("data", onData);
      child.stderr.on("data", onData);
    });
    assert.match(url, /^http:\/\/127\.0\.0\.1:\d+/, `the console's address: ${url}`);
  } finally {
    child.kill();
    await rm(runs, { recursive: true, force: true });
  }
});

test("the report says what was refused, or that it cannot know, and names where content went", async () => {
  const { egressRefusedLine, providersLine, custodyViolations, custodyOwnHostStops } = await import("../scripts/report.ts");
  assert.equal(egressRefusedLine([["evil.example", 3], ["x.test", 1]], true, null), "evil.example (3), x.test");
  assert.equal(egressRefusedLine([], true, null), "nothing was refused");
  assert.match(egressRefusedLine([], false, { netguard: false }), /not observable: no egress control was running/);
  assert.match(egressRefusedLine([], false, null), /not observable: no netguard log was kept/);
  const vm = { isolation: { mode: "microvm" } };
  assert.match(egressRefusedLine([], false, vm), /refusal leaves no log; msb stopped no credential placeholder/);
  assert.match(egressRefusedLine([], false, { ...vm, netguard_mode: "microvm-open" }), /network was open/);
  const stopped = custodyViolations({ vms: [{ agent: "a0", secret_violations: [{ env: "OPENAI_API_KEY", host: "evil.example", method: "POST", path: "/x" }] }] });
  assert.deepEqual(stopped, ["a0 OPENAI_API_KEY → evil.example POST /x"]);
  assert.match(egressRefusedLine([], false, vm, stopped), /msb stopped 1 credential placeholder aimed at a host not its own: a0 OPENAI_API_KEY → evil\.example/);
  // A stop on the credential's own host is a failed request, not a leak, and
  // is said as that (run se064eb had 52, all called "aimed at a host not its own").
  const custody = { vms: [{ agent: "a1", secret_violations: [{ env: "K", host: "api.openai.com", method: "POST", path: "/v1/responses", location: "body", own_host: true }] }] };
  assert.deepEqual(custodyViolations(custody), []);
  assert.deepEqual(custodyOwnHostStops(custody), ["a1 K → api.openai.com POST /v1/responses (body)"]);
  const line = egressRefusedLine([], false, vm, custodyViolations(custody), custodyOwnHostStops(custody));
  assert.match(line, /msb stopped no credential placeholder on its way to another host; msb also stopped 1 request to a credential's own host .*not a leak/);
  assert.equal(providersLine(null), "not recorded");
  assert.equal(
    providersLine({ providers: [{ model: "openai/gpt-5", hosts: ["api.openai.com"] }, { model: "ollama/q", local: true }, { model: "deepseek/d", hosts: ["api.deepseek.com"], role: "summary" }] }),
    "openai/gpt-5 → api.openai.com; ollama/q → this machine (local model); deepseek/d (the summary model self-compaction hands contexts to) → api.deepseek.com",
  );
});

test("the evidence check walks every file of a large set, not the first five thousand", async () => {
  const { mkdir, writeFile } = await import("node:fs/promises");
  const { createHash } = await import("node:crypto");
  const { verifyInputs } = await import("../extensions/protocol.ts");
  const root = await mkdtemp(join(tmpdir(), "dfs-inputs-"));
  try {
    await initSandbox(root, { swarmId: "big", agentIds: ["a0"], capUsd: 1, wallClockMinutes: 5 });
    const files: Array<{ path: string; bytes: number; sha256: string }> = [];
    for (let d = 0; d < 51; d++) {
      await mkdir(join(root, "inputs", `d${d}`), { recursive: true });
      for (let f = 0; f < 100; f++) {
        const text = `${d}/${f}\n`;
        await writeFile(join(root, "inputs", `d${d}`, `f${f}.txt`), text, { mode: 0o444 });
        files.push({ path: `inputs/d${d}/f${f}.txt`, bytes: text.length, sha256: createHash("sha256").update(text).digest("hex") });
      }
    }
    await writeFile(join(root, "inputs.json"), JSON.stringify({ source: "x", copied_at: "t", files, bytes: 0 }));
    const check = await verifyInputs(root);
    assert.equal(check?.checked, 5100);
    assert.equal(check?.content_ok, true, `${check?.missing.length} missing, ${check?.added.length} added, ${check?.modified.length} modified`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a seat in a VM that loses its hub is told after a minute, once, and stopped after four; the hub's return forgets it", async () => {
  const { hubLostStep, HUB_LOST_STEER_MS, HUB_LOST_STOP_MS } = await import("../extensions/agent-swarm.ts");
  let s = { since: 0, told: false };
  const t0 = 1_000_000;
  let step = hubLostStep(s, false, t0);
  assert.deepEqual([step.steer, step.stop], [false, false]);
  s = step.state;
  step = hubLostStep(s, false, t0 + HUB_LOST_STEER_MS);
  assert.deepEqual([step.steer, step.stop], [true, false], "told at a minute");
  s = step.state;
  step = hubLostStep(s, false, t0 + HUB_LOST_STEER_MS + 1000);
  assert.equal(step.steer, false, "told once");
  s = step.state;
  step = hubLostStep(s, false, t0 + HUB_LOST_STOP_MS);
  assert.equal(step.stop, true, "stopped at four minutes");
  step = hubLostStep(step.state, true, t0 + HUB_LOST_STOP_MS + 1);
  assert.deepEqual(step.state, { since: 0, told: false }, "the hub's return forgets the loss");
});

test("trace lines lost while two are written at once are told once, on one later line, and the count goes back to zero", async () => {
  const { logEvent, traceLinesLostCount } = await import("../extensions/agent-swarm.ts");
  const keep = { iso: process.env.SWARM_ISOLATION, agent: process.env.AGENT_ID, socket: process.env.SWARM_TRACE_SOCKET };
  process.env.SWARM_ISOLATION = "microvm";
  process.env.AGENT_ID = "a0";
  delete process.env.SWARM_TRACE_SOCKET;
  const root = await mkdtemp(join(tmpdir(), "phase0-lost-"));
  const stderr = process.stderr.write.bind(process.stderr);
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    // No spill directory yet: both lines are lost.
    await Promise.all([logEvent(root, "a0", "bash", {}, { ok: true }), logEvent(root, "a0", "read", {}, { ok: true })]);
    assert.equal(traceLinesLostCount(), 2);
    const { mkdir } = await import("node:fs/promises");
    await mkdir(join(root, "tool-output", "a0"), { recursive: true });
    await Promise.all([logEvent(root, "a0", "bash", {}, { ok: true }), logEvent(root, "a0", "read", {}, { ok: true })]);
    const lines = (await readFile(join(root, "tool-output", "a0", "trace-spill.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const told = lines.map((l) => l.args?.trace_lines_lost_before ?? 0);
    assert.deepEqual(told.sort(), [0, 2], "one line carries the two lost, the other nothing");
    assert.equal(traceLinesLostCount(), 0);
  } finally {
    process.stderr.write = stderr;
    for (const [k, v] of [["SWARM_ISOLATION", keep.iso], ["AGENT_ID", keep.agent], ["SWARM_TRACE_SOCKET", keep.socket]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await rm(root, { recursive: true, force: true });
  }
});

test("an event's time says its zone: a time without one is refused on every host, an offset is kept beside the UTC value", async () => {
  const { normalizeTs, recordEntry } = await import("../extensions/protocol.ts");
  const was = process.env.TZ;
  try {
    for (const tz of ["UTC", "Europe/Istanbul", "America/New_York"]) {
      process.env.TZ = tz;
      const naive = normalizeTs("2024-01-15T12:44:22");
      assert.equal(naive.ok, false, `refused under ${tz}`);
      assert.match((naive as { reason: string }).reason, /no zone/);
      assert.equal(normalizeTs("2024-01-15 12:44:22").ok, false);
      assert.deepEqual(normalizeTs("2024-01-15T12:44:22Z"), { ok: true, ts: "2024-01-15T12:44:22.000Z", raw: "2024-01-15T12:44:22Z" });
      assert.deepEqual(normalizeTs("2024-01-15T15:44:22+03:00"), { ok: true, ts: "2024-01-15T12:44:22.000Z", raw: "2024-01-15T15:44:22+03:00" });
      assert.equal((normalizeTs("2024-01-15T15:44:22+0300") as { ts?: string }).ts, "2024-01-15T12:44:22.000Z");
      assert.equal((normalizeTs("2024-01-15") as { ts?: string }).ts, "2024-01-15T00:00:00.000Z", "a date alone is that day, in UTC");
      assert.deepEqual(normalizeTs("2024-01-15T12:44:22.000Z"), { ok: true, ts: "2024-01-15T12:44:22.000Z" }, "no raw when it is already the value");
      assert.equal(normalizeTs("01/02/2024").ok, false, "a day and a month that read two ways are refused");
      assert.equal(normalizeTs("yesterday").ok, false);
    }
    process.env.TZ = "Europe/Istanbul";
    const root = await mkdtemp(join(tmpdir(), "phase0-ts-"));
    try {
      await initSandbox(root, { reset: true, agentIds: ["a0"] });
      const r = await recordEntry({ sandboxRoot: root, agentId: "a0" }, { kind: "event", value: "logon", ts: "2024-01-15T15:44:22+03:00", source: "Security.evtx", evidence: "EventID 4624 record 812" });
      assert.ok(r.ok);
      assert.equal((r as { entry: { ts?: string; ts_raw?: string } }).entry.ts, "2024-01-15T12:44:22.000Z");
      assert.equal((r as { entry: { ts_raw?: string } }).entry.ts_raw, "2024-01-15T15:44:22+03:00");
      assert.match(await readFile(join(root, "ledger", "ledger.md"), "utf8"), /2024-01-15T12:44:22\.000Z \(as written: 2024-01-15T15:44:22\+03:00\)/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  } finally {
    if (was === undefined) delete process.env.TZ;
    else process.env.TZ = was;
  }
});

test("the ledger chain: legacy entries before the chain pass, a version 1 entry appended after version 3 ones breaks it", async () => {
  const { ledgerHash, recordEntry, verifyLedgerChain } = await import("../extensions/protocol.ts");
  const root = await mkdtemp(join(tmpdir(), "phase0-chain-"));
  try {
    await initSandbox(root, { reset: true, agentIds: ["a0"] });
    const file = join(root, "ledger", "entries.jsonl");
    // A ledger begun before the chain: two legacy lines, then the harness's.
    const { mkdir, writeFile } = await import("node:fs/promises");
    await mkdir(join(root, "ledger"), { recursive: true });
    const legacy = [1, 2].map((seq) => JSON.stringify({ seq, kind: "ioc", value: `v${seq}`, by: "a0", authors: ["a0"], at: "2024-01-01T00:00:00.000Z" }));
    await writeFile(file, `${legacy.join("\n")}\n`);
    for (const value of ["evil.example.com", "10.0.0.9"]) {
      assert.ok((await recordEntry({ sandboxRoot: root, agentId: "a0" }, { kind: "ioc", value, source: "dns.log", evidence: "grep" })).ok);
    }
    const text = await readFile(file, "utf8");
    const good = verifyLedgerChain(text);
    assert.equal(good.ok, true, good.reason ?? "");
    assert.equal(good.chained, 2);
    // A pane appends a finding in the version 1 shape, correctly chained.
    const last = JSON.parse(text.trim().split("\n").at(-1) as string) as { hash: string; seq: number };
    const forged: Record<string, unknown> = { seq: last.seq + 1, kind: "finding", value: "the suspect is innocent", by: "a0", authors: ["a0"], at: new Date().toISOString(), prev: last.hash };
    forged.hash = ledgerHash(forged as never, last.hash);
    const bad = verifyLedgerChain(`${text}${JSON.stringify(forged)}\n`);
    assert.equal(bad.ok, false);
    assert.equal(bad.reason, "a version 1 entry after version 3 ones");
    assert.equal(bad.broken_at, 5);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the agents' evidence check compares names by their bytes: a name that is not UTF-8 is neither missing nor added", async (t) => {
  const { verifyInputs } = await import("../extensions/protocol.ts");
  const { mkdir, writeFile, symlink, chmod } = await import("node:fs/promises");
  const { createHash } = await import("node:crypto");
  const root = await mkdtemp(join(tmpdir(), "phase0-bytes-"));
  try {
    await initSandbox(root, { reset: true, agentIds: ["a0"] });
    const dir = join(root, "inputs");
    await mkdir(dir, { recursive: true });
    // "kay\xfdt.txt": a Windows-1254 name (ı is 0xfd there), as an archive leaves it.
    const name = Buffer.concat([Buffer.from("kay"), Buffer.from([0xfd]), Buffer.from("t.txt")]);
    const abs = Buffer.concat([Buffer.from(`${dir}/`), name]);
    try {
      await writeFile(abs, "evidence\n");
    } catch {
      t.skip("this filesystem keeps names as UTF-8 and refuses these bytes (APFS); the check runs on Linux");
      return;
    }
    const target = Buffer.concat([Buffer.from("kay"), Buffer.from([0xfd]), Buffer.from("t.txt")]);
    await symlink(target, Buffer.concat([Buffer.from(`${dir}/`), Buffer.from("alias")]));
    await chmod(abs, 0o444);
    const rel = Buffer.concat([Buffer.from("inputs/"), name]);
    const sha = createHash("sha256").update("evidence\n").digest("hex");
    const manifest = {
      source: "/evidence",
      copied_at: new Date().toISOString(),
      bytes: 9,
      enforce: "auto",
      guard: "none",
      files: [
        { path: "inputs/alias", path_b64: undefined, bytes: 0, sha256: createHash("sha256").update(Buffer.concat([Buffer.from("link:"), target])).digest("hex"), link: target.toString("utf8"), link_b64: target.toString("base64") },
        { path: rel.toString("utf8"), path_b64: rel.toString("base64"), bytes: 9, sha256: sha },
      ],
    };
    await writeFile(join(root, "inputs.json"), JSON.stringify(manifest));
    const check = await verifyInputs(root);
    assert.ok(check);
    assert.deepEqual({ missing: check.missing, added: check.added, modified: check.modified }, { missing: [], added: [], modified: [] });
    assert.equal(check.content_ok, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the agents' evidence check reads md5 and sha1 from the manifest and holds a re-read file to them; sha256 decides about the bytes", async () => {
  const { readInputsManifest, verifyInputs } = await import("../extensions/protocol.ts");
  const { mkdir, writeFile, chmod } = await import("node:fs/promises");
  const { createHash } = await import("node:crypto");
  const root = await mkdtemp(join(tmpdir(), "phase0-digests-"));
  try {
    await initSandbox(root, { reset: true, agentIds: ["a0"] });
    await mkdir(join(root, "inputs"), { recursive: true });
    const body = "disk image bytes\n";
    for (const n of ["a.bin", "b.bin"]) {
      await writeFile(join(root, "inputs", n), body);
      await chmod(join(root, "inputs", n), 0o444);
    }
    const d = (alg: string) => createHash(alg).update(body).digest("hex");
    // No stat recorded: the check reads each file again.
    const files = [
      { path: "inputs/a.bin", bytes: body.length, sha256: d("sha256"), md5: d("md5").toUpperCase(), sha1: d("sha1") },
      { path: "inputs/b.bin", bytes: body.length, sha256: d("sha256"), md5: "0".repeat(32), sha1: d("sha1") },
    ];
    await writeFile(join(root, "inputs.json"), JSON.stringify({ source: "/ev", copied_at: "", bytes: 0, enforce: "auto", guard: "none", files }));
    const manifest = await readInputsManifest(root);
    assert.equal(manifest?.files[0].md5, d("md5"), "md5 is read, lower-cased");
    assert.equal(manifest?.files[0].sha1, d("sha1"));
    const check = await verifyInputs(root);
    assert.ok(check);
    assert.equal(check.content_ok, true, "the bytes match their sha256");
    assert.deepEqual(check.digest_mismatch, ["inputs/b.bin"], "the manifest's md5 for b does not describe b's bytes");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a trace that is there and cannot be read is said so, by the event log and by the dossier, never taken for no trace", async () => {
  const { readEventLogChecked, eventLogProblem, readEventLog } = await import("../extensions/protocol.ts");
  const { buildDossier } = await import("../scripts/dossier.ts");
  const { mkdir, writeFile, symlink } = await import("node:fs/promises");
  const root = await mkdtemp(join(tmpdir(), "phase0-trace-"));
  try {
    await initSandbox(root, { reset: true, agentIds: ["a0"] });
    const trace = join(root, EVENTS_REL);
    await rm(trace, { force: true });
    // No trace at all: nothing to say.
    assert.deepEqual(await readEventLogChecked(root), { events: [], unreadable: null });
    let dossier = await buildDossier(root);
    assert.equal(dossier.files.find((f) => f.name === "trace.jsonl")?.reason, "not produced");
    // A trace that is a directory.
    await mkdir(trace);
    const dir = await readEventLogChecked(root);
    assert.equal(dir.unreadable, "not a regular file");
    assert.deepEqual([...(await readEventLog(root))], []);
    assert.equal(eventLogProblem(root), "not a regular file", "a caller of readEventLog can ask why");
    dossier = await buildDossier(root);
    const listed = dossier.files.find((f) => f.name === "trace.jsonl");
    assert.equal(listed?.present, false);
    assert.match(listed?.reason ?? "", /there, and could not be read: not a regular file/);
    await rm(trace, { recursive: true });
    // A trace that is a link to a file outside the run.
    const outside = join(root, "..", `outside-${Date.now()}.jsonl`);
    await writeFile(outside, `${JSON.stringify({ ts: "t", agent: "a0", tool: "bash", args: {}, result: {} })}\n`);
    await symlink(outside, trace);
    assert.equal((await readEventLogChecked(root)).unreadable, "a link, not the trace");
    assert.match((await buildDossier(root)).files.find((f) => f.name === "trace.jsonl")?.reason ?? "", /could not be read: a link/);
    await rm(outside, { force: true });
    await rm(trace, { force: true });
    // A readable trace again: read, and the problem is forgotten.
    await writeFile(trace, `${JSON.stringify({ ts: "t", agent: "a0", tool: "bash", args: {}, result: {} })}\n`);
    const ok = await readEventLogChecked(root);
    assert.equal(ok.unreadable, null);
    assert.equal(ok.events.length, 1);
    assert.equal(eventLogProblem(root), null);
    const good = (await buildDossier(root)).files.find((f) => f.name === "trace.jsonl");
    assert.equal(good?.present, true);
    assert.equal(good?.bytes, (await readFile(trace)).length);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a ledger entry is corrected by a later one that supersedes it: both stay, the chain holds, and the rules are said", async () => {
  const { ledgerCore, listLedger, readLedger, recordEntry, verifyLedgerChain } = await import("../extensions/protocol.ts");
  const root = await mkdtemp(join(tmpdir(), "phase0-supersedes-"));
  try {
    await initSandbox(root, { reset: true, agentIds: ["a0", "a1"] });
    const a0 = { sandboxRoot: root, agentId: "a0" };
    const a1 = { sandboxRoot: root, agentId: "a1" };
    const first = await recordEntry(a0, { kind: "finding", value: "The shell was uploaded through the contact form", source: "access.log", evidence: "POST /contact.php at 12:40" });
    assert.ok(first.ok);
    const before = ledgerCore((first as { entry: Parameters<typeof ledgerCore>[0] }).entry);
    assert.doesNotMatch(before, /supersedes/, "an entry that corrects nothing has the core it always had");
    // A peer corrects it; the seq may be written as #1.
    const fix = await recordEntry(a1, { kind: "finding", value: "The shell was uploaded through the file manager, not the contact form", source: "access.log", evidence: "POST /filemanager/upload.php at 12:39", supersedes: "#1" });
    assert.ok(fix.ok, (fix as { reason?: string }).reason);
    assert.equal((fix as { entry: { supersedes?: number } }).entry.supersedes, 1);
    assert.match(ledgerCore((fix as { entry: Parameters<typeof ledgerCore>[0] }).entry), /"supersedes":1/, "the correction is in the chained core");
    const entries = await readLedger(root);
    assert.equal(entries.length, 2, "nothing is deleted");
    assert.equal(entries[0].value, "The shell was uploaded through the contact form");
    const text = await readFile(join(root, "ledger", "entries.jsonl"), "utf8");
    assert.equal(verifyLedgerChain(text).ok, true);
    // A correction moved to another entry breaks the chain.
    const moved = text.replace('"supersedes":1', '"supersedes":2');
    assert.equal(verifyLedgerChain(moved).ok, false);
    const md = await readFile(join(root, "ledger", "ledger.md"), "utf8");
    assert.match(md, /\*\*#1\*\* The shell was uploaded through the contact form \*\*\(superseded by #2\)\*\*/);
    assert.match(md, /\*\*#2\*\* The shell was uploaded through the file manager, not the contact form \(corrects #1\)/);
    assert.match(md, /1 corrected by a later entry, which stands/);
    const listed = await listLedger(root, {});
    assert.equal((listed[0] as { superseded_by?: number }).superseded_by, 2);
    // What is refused, and why.
    const unknown = await recordEntry(a0, { kind: "finding", value: "x", source: "s", evidence: "e", supersedes: 9 });
    assert.equal(unknown.ok, false);
    assert.match((unknown as { reason: string }).reason, /no entry #9/);
    const self = await recordEntry(a0, { kind: "finding", value: "y", source: "s", evidence: "e", supersedes: 3 });
    assert.equal(self.ok, false, "the next seq is no entry yet: an entry cannot supersede itself");
    const twice = await recordEntry(a0, { kind: "finding", value: "z", source: "s", evidence: "e", supersedes: 1 });
    assert.equal(twice.ok, false);
    assert.match((twice as { reason: string }).reason, /already superseded by #2: correct #2 instead/);
    const same = await recordEntry(a0, { kind: "finding", value: "The shell was uploaded through the file manager, not the contact form", source: "access.log", evidence: "POST /filemanager/upload.php at 12:39", supersedes: 2 });
    assert.equal(same.ok, false);
    assert.match((same as { reason: string }).reason, /word for word/);
    // The same sentence with another confidence is a correction (18 of 33 refusals on the recorded runs were this).
    const surer = await recordEntry(a0, { kind: "finding", value: "The shell was uploaded through the file manager, not the contact form", source: "access.log", evidence: "POST /filemanager/upload.php at 12:39", confidence: "high", supersedes: 2, because: "the upload's own log line was found" });
    assert.equal(surer.ok, true, (surer as { reason?: string }).reason);
    assert.equal((surer as { entry: { because?: string } }).entry.because, "the upload's own log line was found");
    const bad = await recordEntry(a0, { kind: "finding", value: "w", source: "s", evidence: "e", supersedes: "first" });
    assert.equal(bad.ok, false);
    assert.match((bad as { reason: string }).reason, /whole number/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a search that found nothing is recorded as absence, with what, where and how far, and rendered as such", async () => {
  const { LEDGER_KINDS, recordEntry } = await import("../extensions/protocol.ts");
  assert.ok((LEDGER_KINDS as readonly string[]).includes("absence"));
  const root = await mkdtemp(join(tmpdir(), "phase0-absence-"));
  try {
    await initSandbox(root, { reset: true, agentIds: ["a0"] });
    const a0 = { sandboxRoot: root, agentId: "a0" };
    const noSource = await recordEntry(a0, { kind: "absence", value: "BitLocker recovery key", evidence: "grep -a 'BitLocker' (GNU grep 3.11), allocated files only" });
    assert.equal(noSource.ok, false);
    assert.match((noSource as { reason: string }).reason, /what was searched/);
    assert.match((noSource as { reason: string }).reason, /not found there/);
    const noEvidence = await recordEntry(a0, { kind: "absence", value: "BitLocker recovery key", source: "inputs/disk.E01" });
    assert.equal(noEvidence.ok, false);
    assert.match((noEvidence as { reason: string }).reason, /the query, the tool and its version, and the scope/);
    assert.match((noEvidence as { reason: string }).reason, /unallocated/);
    const noValue = await recordEntry(a0, { kind: "absence", value: " ", source: "inputs/disk.E01", evidence: "q" });
    assert.match((noValue as { reason: string }).reason, /what was looked for/);
    const ok = await recordEntry(a0, { kind: "absence", value: "BitLocker recovery key", source: "inputs/disk.E01, partition 2", evidence: "grep -a -i 'bitlocker' over icat of every allocated file (GNU grep 3.11, sleuthkit 4.12); unallocated and slack not searched" });
    assert.ok(ok.ok, (ok as { reason?: string }).reason);
    const md = await readFile(join(root, "ledger", "ledger.md"), "utf8");
    assert.match(md, /1 searches that found nothing/);
    assert.match(md, /## Searched, not found/);
    assert.match(md, /\| 1 \| BitLocker recovery key \| inputs\/disk\.E01, partition 2 \| grep -a -i 'bitlocker'.*unallocated and slack not searched \| a0 \|/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
