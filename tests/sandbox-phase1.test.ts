/**
 * Phase 1 of docs/sandbox-plan.md: the two structural holes.
 *
 * The write guard is a shell test (`tests/write-guard.test.sh`) because it is
 * a kernel profile. This is the other half: the trace's writer lives outside
 * the panes, and every line it writes names the line before it.
 */
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, mkdir, readFile, stat } from "node:fs/promises";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";
import { appendEvent, verifyEventChain, COLLECTOR_SOCKET_REL } from "../extensions/protocol.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const started: ChildProcess[] = [];

after(() => {
  for (const proc of started) proc.kill("SIGTERM");
});

async function collectorOn(root: string): Promise<string> {
  await mkdir(join(root, "traces"), { recursive: true });
  const proc = spawn("node", [join(ROOT, "scripts", "trace-collector.mjs"), root, "--quiet"], { stdio: "ignore" });
  started.push(proc);
  const socket = join(root, COLLECTOR_SOCKET_REL);
  for (let i = 0; i < 80; i += 1) {
    if (await stat(socket).then((s) => s.isSocket()).catch(() => false)) return socket;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error("the collector did not come up");
}

async function lines(root: string): Promise<string[]> {
  const text = await readFile(join(root, "traces", "events.jsonl"), "utf8").catch(() => "");
  return text.split("\n").filter(Boolean);
}

test("the collector writes the trace and chains every line to the one before it", async () => {
  const root = await mkdtemp(join(tmpdir(), "swarm-collector-"));
  const socket = await collectorOn(root);
  process.env.SWARM_TRACE_SOCKET = socket;
  try {
    for (let i = 0; i < 6; i += 1) {
      await appendEvent(root, { agent: `a${i % 3}`, tool: "bash", args: { n: i }, result: { ok: true } });
    }
    await new Promise((r) => setTimeout(r, 250));
    const written = await lines(root);
    assert.equal(written.length, 6);
    const text = `${written.join("\n")}\n`;
    const chain = verifyEventChain(text);
    assert.deepEqual({ ok: chain.ok, chained: chain.chained, total: chain.total }, { ok: true, chained: 6, total: 6 });
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

test("a line inserted after the fact breaks the chain and names where", async () => {
  const root = await mkdtemp(join(tmpdir(), "swarm-chain-"));
  const socket = await collectorOn(root);
  process.env.SWARM_TRACE_SOCKET = socket;
  try {
    for (let i = 0; i < 4; i += 1) await appendEvent(root, { agent: "a0", tool: "read", args: { n: i }, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 250));
    const written = await lines(root);
    // What an agent editing its own history would produce: a plausible line,
    // with a plausible parent hash, in the middle.
    const forged = JSON.stringify({ ts: "2026-01-01T00:00:00Z", agent: "a0", tool: "read", args: {}, result: { ok: true }, prev: "f".repeat(64) });
    const tampered = `${[...written.slice(0, 2), forged, ...written.slice(2)].join("\n")}\n`;
    const chain = verifyEventChain(tampered);
    assert.equal(chain.ok, false);
    assert.equal(chain.broken_at, 3);
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

test("a malformed message is refused rather than written", async () => {
  const root = await mkdtemp(join(tmpdir(), "swarm-malformed-"));
  const socket = await collectorOn(root);
  await new Promise<void>((resolve, reject) => {
    const s = connect(socket);
    s.on("error", reject);
    s.on("connect", () => s.end('this is not json\n{"ts":"t","agent":"a0","tool":"post","args":{},"result":{}}\n', () => resolve()));
  });
  await new Promise((r) => setTimeout(r, 250));
  const written = await lines(root);
  assert.equal(written.length, 1, "the good line lands and the bad one does not");
  assert.equal(JSON.parse(written[0]).tool, "post");
});

test("with no collector the harness still writes its own trace, and says it is unchained", async () => {
  const root = await mkdtemp(join(tmpdir(), "swarm-nocollector-"));
  delete process.env.SWARM_TRACE_SOCKET;
  await appendEvent(root, { agent: "a0", tool: "post", args: {}, result: { ok: true } });
  const written = await lines(root);
  assert.equal(written.length, 1);
  const chain = verifyEventChain(`${written.join("\n")}\n`);
  assert.equal(chain.ok, true, "an unchained file is not a broken one");
  assert.equal(chain.chained, 0, "and it does not claim a chain it does not have");
});

test("a socket that is not there falls back instead of losing the line", async () => {
  const root = await mkdtemp(join(tmpdir(), "swarm-deadsocket-"));
  process.env.SWARM_TRACE_SOCKET = join(root, "nothing-listening.sock");
  try {
    await appendEvent(root, { agent: "a0", tool: "wait", args: {}, result: { ok: true } });
    assert.equal((await lines(root)).length, 1);
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});


test("a pane that cannot reach the collector or the file spills rather than losing the line", async () => {
  // With a collector running, traces/ is read-only to the pane — the point of
  // the design — so a failed send has nowhere to write. Losing the line in
  // silence is the one outcome a record cannot have.
  const root = await mkdtemp(join(tmpdir(), "swarm-spill-"));
  await mkdir(join(root, "traces"), { recursive: true });
  await mkdir(join(root, "work"), { recursive: true });
  // A directory where the file should be: appendFile fails with EISDIR, which
  // stands in for "the kernel refuses this write".
  await mkdir(join(root, "traces", "events.jsonl"), { recursive: true });
  process.env.SWARM_TRACE_SOCKET = join(root, "nothing-listening.sock");
  try {
    await appendEvent(root, { agent: "a0", tool: "bash", args: { n: 1 }, result: { ok: true } }).catch(() => undefined);
    const spill = await readFile(join(root, "work", ".trace-spill.jsonl"), "utf8").catch(() => "");
    assert.equal(spill.split("\n").filter(Boolean).length, 1, "the line is in the spill, not gone");
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

test("the socket lives under traces/, which the write guard denies to the panes", () => {
  // A socket in the sandbox root is one an agent can unlink — and then bind
  // its own, becoming the writer of the record of what it did. Measured under
  // a real profile: unlink in the sandbox root succeeds, under traces/ it does
  // not.
  assert.equal(COLLECTOR_SOCKET_REL, "traces/.collector.sock");
});

test("the harness's own watchdogs record through the collector, so their lines are chained too", async () => {
  // idle-nudge.sh and reap.sh append the harness's own events. They used to
  // write the file directly — they run outside every pane, so the read-only
  // guard does not touch them — and their unchained line broke the *next*
  // collector line: with the watchdog on by default, a run reported its own
  // record as edited every three minutes. They send through the socket now,
  // which is also what lets an unchained line mean something.
  const root = await mkdtemp(join(tmpdir(), "swarm-external-"));
  const socket = await collectorOn(root);
  process.env.SWARM_TRACE_SOCKET = socket;
  try {
    await appendEvent(root, { agent: "a0", tool: "bash", args: {}, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 200));

    const emit = spawn("node", [join(ROOT, "scripts", "trace-emit.mjs"), root], { stdio: ["pipe", "ignore", "ignore"] });
    emit.stdin?.end(JSON.stringify({ ts: "t2", agent: "system", tool: "idle_nudge", args: {}, result: { ok: true } }));
    const code = await new Promise<number>((resolve) => emit.on("exit", (c) => resolve(c ?? 1)));
    assert.equal(code, 0, "trace-emit reports whether the collector took the line");

    await appendEvent(root, { agent: "a0", tool: "read", args: {}, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 250));

    const chain = verifyEventChain(`${(await lines(root)).join("\n")}\n`);
    assert.equal(chain.ok, true, "every line went through the one writer");
    assert.equal(chain.total, 3);
    assert.equal(chain.chained, 3, "including the watchdog's");
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

test("a direct append still cannot corrupt the lines that follow it", async () => {
  // Belt and braces: something that appends anyway — a future writer, a bug —
  // is caught by the verifier, and must not also break the next real line.
  const root = await mkdtemp(join(tmpdir(), "swarm-external2-"));
  const socket = await collectorOn(root);
  process.env.SWARM_TRACE_SOCKET = socket;
  try {
    await appendEvent(root, { agent: "a0", tool: "bash", args: {}, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 200));
    const { appendFile } = await import("node:fs/promises");
    await appendFile(join(root, "traces", "events.jsonl"), `${JSON.stringify({ ts: "t", agent: "system", tool: "reap", args: {}, result: {} })}\n`, "utf8");
    await appendEvent(root, { agent: "a0", tool: "read", args: {}, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 250));
    const all = await lines(root);
    const last = JSON.parse(all[2]) as { prev: string };
    const { createHash } = await import("node:crypto");
    assert.equal(last.prev, createHash("sha256").update(all[1]).digest("hex"), "the collector picked the chain up from the file");
  } finally {
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

test("a socket path past the kernel's limit still works", async () => {
  // ~/Library/CloudStorage/Dropbox/…/runs/<id>/traces/.collector.sock is 110
  // bytes, and a Unix socket path is limited to about 104. Binding and
  // connecting relative to the directory keeps what the kernel sees short —
  // without it the collector silently fails to start and every pane writes
  // its own unchained trace.
  const deep = join(await mkdtemp(join(tmpdir(), `swarm-${"d".repeat(60)}-`)), "runs", "s1234");
  await mkdir(join(deep, "traces"), { recursive: true });
  assert.ok(join(deep, COLLECTOR_SOCKET_REL).length > 104, "the fixture has to be past the limit to test it");
  const socket = await collectorOn(deep);
  const cwd = process.cwd();
  process.chdir(deep);
  process.env.SWARM_TRACE_SOCKET = socket;
  try {
    await appendEvent(deep, { agent: "a0", tool: "bash", args: {}, result: { ok: true } });
    await new Promise((r) => setTimeout(r, 250));
    assert.equal((await lines(deep)).length, 1);
    assert.equal(verifyEventChain(`${(await lines(deep)).join("\n")}\n`).chained, 1, "and it is chained");
  } finally {
    process.chdir(cwd);
    delete process.env.SWARM_TRACE_SOCKET;
  }
});

/** A collector with a token map and an anchor, the way the kickoff starts one. */
async function collectorWithTokens(root: string, map: Record<string, unknown>, anchor: string): Promise<string> {
  await mkdir(join(root, "traces"), { recursive: true });
  const proc = spawn(
    "node",
    [join(ROOT, "scripts", "trace-collector.mjs"), root, "--tokens", "--anchor", anchor, "--quiet"],
    { stdio: ["pipe", "ignore", "ignore"] },
  );
  started.push(proc);
  // The one line the kickoff writes: `{tokens, gate}`. A bare map here is a
  // token map with no gate; a map that already has the shape is passed as is.
  const line = typeof map.tokens === "object" && map.tokens !== null ? map : { tokens: map, gate: "" };
  proc.stdin?.end(JSON.stringify(line));
  const socket = join(root, COLLECTOR_SOCKET_REL);
  for (let i = 0; i < 80; i += 1) {
    if (await stat(socket).then((s) => s.isSocket()).catch(() => false)) return socket;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error("the collector did not come up");
}

function sendRaw(socket: string, payload: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const s = connect(socket);
    s.on("error", reject);
    s.on("connect", () => s.end(`${JSON.stringify(payload)}\n`, () => resolve()));
  });
}

test("a line is attributed by its token, not by what it claims", async () => {
  // Every pane shares one uid, so nothing in the body can be trusted to say
  // who wrote it. The token can: macOS does not let one process read
  // another's environment, and Herdr's API does not expose a pane's env.
  const root = await mkdtemp(join(tmpdir(), "swarm-token-"));
  const anchor = join(root, "anchor.json");
  const socket = await collectorWithTokens(root, { "tok-a0": "a0", "tok-a1": "a1" }, anchor);

  await sendRaw(socket, { ts: "t1", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "tok-a0" });
  // a1 trying to put an event on a0's name — the forgery the socket allows.
  await sendRaw(socket, { ts: "t2", agent: "a0", tool: "bash", args: { command: "rm -rf /evidence" }, result: { ok: true }, token: "tok-a1" });
  // and one with no token at all
  await sendRaw(socket, { ts: "t3", agent: "a0", tool: "read", args: {}, result: { ok: true } });
  await new Promise((r) => setTimeout(r, 300));

  const written = (await lines(root)).map((l) => JSON.parse(l) as Record<string, unknown>);
  assert.equal(written.length, 3);
  assert.equal(written[0].agent, "a0");
  assert.equal(written[0].token, undefined, "the token is a secret, never a field in the record");

  assert.equal(written[1].agent, "a1", "the sender, not the claim");
  assert.equal(written[1].claimed_agent, "a0", "and the attempt is on the record");

  assert.equal(written[2].agent_unverified, true, "a line with no token says so");

  const chain = verifyEventChain(`${(await lines(root)).join("\n")}\n`);
  assert.equal(chain.ok, true);
  assert.equal(chain.disputed, 1);
  assert.equal(chain.unverified, 1);
});


test("the collector decides the verdict, so a sender cannot stamp its own", async () => {
  // `agent_unverified` and `claimed_agent` are what the collector concluded
  // about a line. A sender that supplies them concludes for it: it can mark
  // its own work unattributable and repudiate it later, or spray the dispute
  // flag until a real forgery is one row among hundreds. They are stripped
  // on the way in, like `prev`.
  const root = await mkdtemp(join(tmpdir(), "swarm-verdict-"));
  const socket = await collectorWithTokens(root, { "tok-a0": "a0" }, join(root, "anchor.json"));

  await sendRaw(socket, {
    ts: "t1",
    agent: "a0",
    tool: "bash",
    args: {},
    result: { ok: true },
    token: "tok-a0",
    agent_unverified: true,
    claimed_agent: "someone-else",
    prev: "0".repeat(64),
  });
  await new Promise((r) => setTimeout(r, 300));

  const written = (await lines(root)).map((l) => JSON.parse(l) as Record<string, unknown>);
  assert.equal(written.length, 1);
  assert.equal(written[0].agent, "a0");
  assert.equal(written[0].agent_unverified, undefined, "a sender cannot mark its own line unattributed");
  assert.equal(written[0].claimed_agent, undefined, "nor invent a dispute");
  assert.notEqual(written[0].prev, "0".repeat(64), "nor choose its own parent");

  const chain = verifyEventChain(`${(await lines(root)).join("\n")}\n`);
  assert.equal(chain.unverified, 0);
  assert.equal(chain.disputed, 0);
});

test("with a gate in front, a token attributes only on a line the gate vouched for", async () => {
  // Linux: every pane of one uid can read a peer's environment, so the token
  // is not a secret there. scripts/trace-gate.py decides the sender from
  // SO_PEERCRED and marks each forwarded line with a key the panes never
  // see; the collector counts a token only beside that key.
  const root = await mkdtemp(join(tmpdir(), "swarm-gate-"));
  const anchor = join(root, "anchor.json");
  const socket = await collectorWithTokens(root, { tokens: { "tok-a0": "a0", "tok-a1": "a1" }, gate: "k-0123" }, anchor);

  // straight from a pane, with a token it read from /proc
  await sendRaw(socket, { ts: "t1", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "tok-a0" });
  // the same line as the gate forwards it
  await sendRaw(socket, { ts: "t2", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "tok-a1", gate: "k-0123" });
  // a guessed key
  await sendRaw(socket, { ts: "t3", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "tok-a0", gate: "k-9999" });
  await new Promise((r) => setTimeout(r, 150));

  const written = (await readFile(join(root, "traces", "events.jsonl"), "utf8"))
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));
  assert.equal(written.length, 3);
  assert.equal(written[0].agent_unverified, true, "a token without the gate's key does not attribute");
  assert.equal(written[1].agent, "a1", "the gate's token decides, whatever the body claims");
  assert.equal(written[1].claimed_agent, "a0");
  assert.equal(written[1].agent_unverified, undefined);
  assert.equal(written[2].agent_unverified, true, "a wrong key is no key");
  for (const w of written) {
    assert.equal(w.gate, undefined, "the key never reaches the record");
    assert.equal(w.token, undefined);
  }
});

test("the anchor only ever grows, so truncating the trace cannot reset it", async () => {
  // It used to re-read the line count from the file. Cutting the trace down
  // and letting the collector write one more line moved the anchor to the
  // shorter count, and the record then verified as intact — an anchor that
  // forgets is not an anchor.
  const root = await mkdtemp(join(tmpdir(), "swarm-anchor-"));
  const anchor = join(root, "anchor.json");
  const socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  for (let i = 1; i <= 4; i += 1) {
    await sendRaw(socket, { ts: `t${i}`, agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" });
  }
  await new Promise((r) => setTimeout(r, 400));
  assert.equal(JSON.parse(await readFile(anchor, "utf8")).lines, 4);

  const { writeFile } = await import("node:fs/promises");
  const kept = (await lines(root)).slice(0, 2);
  await writeFile(join(root, "traces", "events.jsonl"), `${kept.join("\n")}\n`, "utf8");
  await sendRaw(socket, { ts: "t5", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" });
  await new Promise((r) => setTimeout(r, 400));

  const after = JSON.parse(await readFile(anchor, "utf8"));
  assert.equal(after.lines, 5, "the anchor counts what was written, not what survived");
  const chain = verifyEventChain(`${(await lines(root)).join("\n")}\n`, {
    lines: after.lines,
    head: after.head,
    prev_head: after.prev_head,
  });
  assert.equal(chain.ok, false, "and the shortened record no longer matches it");
});

test("a line the collector refuses is reported as refused, not as written", async () => {
  // `trace-emit` used to exit 0 when the bytes reached the kernel. A line the
  // collector then threw away — over the size limit, missing a field — looked
  // recorded to its caller, whose fallback exists for exactly that case and
  // never ran. An event that disappears quietly is the one failure this file
  // cannot have.
  const root = await mkdtemp(join(tmpdir(), "swarm-refused-"));
  await collectorWithTokens(root, { t: "a0" }, join(root, "anchor.json"));
  const emit = (payload: unknown) =>
    new Promise<number>((resolve) => {
      const proc = spawn("node", [join(ROOT, "scripts", "trace-emit.mjs"), root], {
        stdio: ["pipe", "ignore", "ignore"],
      });
      proc.stdin?.end(JSON.stringify(payload));
      proc.on("exit", (code) => resolve(code ?? -1));
    });

  assert.equal(await emit({ ts: "t1", agent: "a0", tool: "bash", args: {}, result: { ok: true } }), 0);
  // No `tool`, so the collector refuses it.
  assert.equal(await emit({ ts: "t2", agent: "a0", args: {} }), 1, "a refused line must not report success");
  assert.equal((await lines(root)).length, 1, "and it is not in the record");
  // Past the old 1 MB line limit: recorded now. The trace keeps every result
  // whole, a 60,000-character bash output is ordinary, and the collector's
  // own ceiling is 64 MB a line. Only a malformed message is refused.
  assert.equal(await emit({ ts: "t3", agent: "a0", tool: "bash", args: {}, result: { ok: true, output: "x".repeat(1_100_000) } }), 0, "a 1.1 MB line is written whole");
  const recorded = await lines(root);
  assert.equal(recorded.length, 2);
  assert.equal(String((JSON.parse(recorded[1]!) as { result?: { output?: string } }).result?.output).length, 1_100_000, "and nothing of it was cut");
});

test("a line appended after the collector started breaks the chain", async () => {
  // The gap the hash chain did not close: an edit in the middle was caught,
  // an append at the end was not, because an unchained line was simply
  // skipped. Every legitimate writer goes through the collector now, so an
  // unchained line after the first chained one is something else's work.
  const root = await mkdtemp(join(tmpdir(), "swarm-append-"));
  const anchor = join(root, "anchor.json");
  const socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  await sendRaw(socket, { ts: "t1", agent: "a0", tool: "bash", args: {}, result: { ok: true }, token: "t" });
  await new Promise((r) => setTimeout(r, 250));
  const { appendFile } = await import("node:fs/promises");
  await appendFile(
    join(root, "traces", "events.jsonl"),
    `${JSON.stringify({ ts: "t2", agent: "a0", tool: "done", args: {}, result: { ok: true } })}\n`,
    "utf8",
  );
  const chain = verifyEventChain(`${(await lines(root)).join("\n")}\n`);
  assert.equal(chain.ok, false);
  assert.equal(chain.reason, "appended");
  assert.equal(chain.broken_at, 2);
});

test("a trace rewritten from the first line no longer matches the anchor", async () => {
  // A chain recomputed over a file somebody rewrote verifies against itself.
  // The anchor is what it cannot reproduce: it lives outside the sandbox,
  // where the write guard keeps a pane from reaching it.
  const root = await mkdtemp(join(tmpdir(), "swarm-anchor-"));
  const anchor = join(root, "..", `anchor-${Date.now()}.json`);
  const socket = await collectorWithTokens(root, { t: "a0" }, anchor);
  for (const n of [1, 2, 3]) {
    await sendRaw(socket, { ts: `t${n}`, agent: "a0", tool: "bash", args: { n }, result: { ok: true }, token: "t" });
  }
  await new Promise((r) => setTimeout(r, 350));
  const recorded = JSON.parse(await readFile(anchor, "utf8")) as { lines: number; head: string };
  assert.equal(recorded.lines, 3);

  const honest = `${(await lines(root)).join("\n")}\n`;
  assert.equal(verifyEventChain(honest, recorded).ok, true, "the real file matches its anchor");

  // What a rewrite looks like: two of the three lines, chained correctly.
  const { createHash } = await import("node:crypto");
  const kept = (await lines(root)).slice(0, 2);
  const rebuilt: string[] = [];
  let prev = "";
  for (const line of kept) {
    const record = { ...(JSON.parse(line) as Record<string, unknown>), prev };
    const rebuiltLine = JSON.stringify(record);
    rebuilt.push(rebuiltLine);
    prev = createHash("sha256").update(rebuiltLine).digest("hex");
  }
  const forged = `${rebuilt.join("\n")}\n`;
  assert.equal(verifyEventChain(forged).ok, true, "it verifies against itself, which is the problem");
  const caught = verifyEventChain(forged, recorded);
  assert.equal(caught.ok, false, "and against the anchor it does not");
  assert.equal(caught.reason, "shortened");
});

test("a message that is not an event is refused, whatever shape it has", async () => {
  const root = await mkdtemp(join(tmpdir(), "swarm-shape-"));
  const socket = await collectorWithTokens(root, { t: "a0" }, join(root, "anchor.json"));
  await sendRaw(socket, [1, 2, 3]);
  await sendRaw(socket, { totally: "unrelated", token: "t" });
  await sendRaw(socket, { ts: "t1", agent: "a0", tool: "post", args: {}, result: {}, token: "t" });
  await new Promise((r) => setTimeout(r, 300));
  const written = await lines(root);
  assert.equal(written.length, 1, "only the event lands");
  assert.equal((JSON.parse(written[0]) as { tool: string }).tool, "post");
});

test("a multibyte character split across two socket reads is written whole", async () => {
  // A large event arrives in several reads, and a read boundary can fall
  // inside a UTF-8 sequence. Decoding each read on its own turned both halves
  // into U+FFFD; the line still parsed, so the altered text was hashed into
  // the chain and the trace verified as intact while saying something else.
  const root = await mkdtemp(join(tmpdir(), "swarm-utf8-"));
  const socket = await collectorOn(root);
  const text = "İstanbul 東京 🔍 Москва";
  const bytes = Buffer.from(`${JSON.stringify({ ts: "t1", agent: "a0", tool: "bash", args: {}, result: { output: text } })}\n`, "utf8");
  // Cut inside the four-byte emoji.
  const cut = bytes.indexOf(Buffer.from("🔍", "utf8")) + 2;
  await new Promise<void>((resolve, reject) => {
    const s = connect(socket);
    s.on("error", reject);
    s.on("connect", () => {
      s.write(bytes.subarray(0, cut), () => {
        // Long enough that the collector reads the first half on its own.
        setTimeout(() => s.end(bytes.subarray(cut), () => resolve()), 150);
      });
    });
  });
  await new Promise((r) => setTimeout(r, 250));
  const written = await lines(root);
  assert.equal(written.length, 1);
  assert.equal((JSON.parse(written[0]!) as { result: { output: string } }).result.output, text);
});
