/**
 * The hub's live record of who reached a sensitive output:
 * every trace row of a seat passes the hub, and a row whose tool call names a
 * sensitive job's output gets a line of the hub's own after it, `sensitive_access`,
 * with the seat, the job, the part and path, how the harness came to see it
 * (`via`) and how sure it is (`certainty`). A page of a sensitive job's stdout
 * that a status call returns is noted the same way. Nothing is held, hidden or
 * changed for the seat. The job service here runs the local worker stand-in.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { connect, createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as board from "../extensions/board.ts";
import { initSandbox } from "../extensions/protocol.ts";
import { JobService } from "../scripts/job-service.ts";
import { sensitiveIndex } from "../scripts/output-hygiene.ts";
import { LOWER_BOUND_SENTENCE, accessRecord, classifyTraceRow, provenance, renderAccess, verifyAccess, type AccessIndex } from "../scripts/sensitive-access.ts";
import { Hub } from "../scripts/vm-hub.ts";
import { listInputs, localWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");
const cleanups: Array<() => Promise<unknown>> = [];
after(async () => {
  for (const c of cleanups.reverse()) await c().catch(() => undefined);
});

/** A value a job writes and the run treats as secret: a placeholder, never a real credential. */
const VALUE = "TOKEN-sample-7f3a91";

type Line = Record<string, any>;

async function until(cond: () => boolean, what: string, ms = 5000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error(`timed out waiting: ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

/** One raw line to a seat's socket, and the first line back. */
function exchange(socketPath: string, body: unknown): Promise<Line> {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    let answer = "";
    socket.setEncoding("utf8");
    socket.on("error", reject);
    socket.on("data", (chunk: string) => {
      answer += chunk;
      const cut = answer.indexOf("\n");
      if (cut >= 0) {
        socket.destroy();
        resolve(JSON.parse(answer.slice(0, cut)));
      }
    });
    socket.on("close", () => resolve(answer ? JSON.parse(answer.trim()) : {}));
    socket.on("connect", () => socket.write(`${JSON.stringify(body)}\n`));
  });
}

async function rig() {
  const agents = ["a1", "a2"];
  const base = await mkdtemp(join(tmpdir(), "dfs-access-"));
  const S = join(base, "runs", "t1");
  await mkdir(S, { recursive: true });
  await initSandbox(S, { swarmId: "t1", agentIds: agents, capUsd: 5, wallClockMinutes: 30 });
  for (const d of ["inputs", "tools", "catalog", "traces", "work/a1", "work/a2"]) await mkdir(join(S, d), { recursive: true });
  await writeFile(join(S, "work", "a1", "notes.txt"), "mine\n");
  listInputs(S);
  const dir = await mkdtemp(join(tmpdir(), "dfh-"));
  // The collector stand-in keeps what it takes, in memory and in the trace file a restarted hub reads.
  const lines: Line[] = [];
  const events = join(S, "traces", "events.jsonl");
  const colPath = join(dir, "col.sock");
  const collector: Server = createServer((socket) => {
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      let cut;
      while ((cut = buffer.indexOf("\n")) >= 0) {
        const text = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 1);
        const rec = JSON.parse(text);
        delete rec.token;
        lines.push(rec);
        appendFileSync(events, `${JSON.stringify(rec)}\n`);
        socket.write('{"ok":true}\n');
      }
    });
    socket.on("error", () => undefined);
  });
  await new Promise<void>((r) => collector.listen(colPath, () => r()));
  const tokens = Object.fromEntries([...agents.map((a) => [a, `token-${a}`]), ["system", "token-system"]]);
  const mk = () => new Hub({ sandbox: S, dir, agents, tokens, collector: colPath, backstop: false, quiet: true, settleMs: 0, herdrBin: "/usr/bin/false", forging: false });
  const hub = mk();
  await hub.start();
  const svc = new JobService({
    sandbox: S, run: "t1", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [join(ROOT, "packs", "computer-forensics-base")], forging: false, minFreeMb: 1,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async (a) => ({ name: a }),
  });
  await svc.start();
  hub.jobService = svc;
  cleanups.push(async () => {
    await svc.stop("over").catch(() => undefined);
    await hub.stop().catch(() => undefined);
    collector.close();
    spawnSync("chmod", ["-R", "u+w", base]);
    await rm(base, { recursive: true, force: true });
    await rm(dir, { recursive: true, force: true });
  });
  let seq = 0;
  const sid = "seat-sid-1";
  /** A seat's trace row, as the extension sends it. */
  const row = (tool: string, args: Record<string, unknown>, result: Record<string, unknown> = { ok: true }, at = ++seq) => ({ ts: new Date().toISOString(), agent: "a1", tool, args, result, sid, seq: at });
  const send = async (seat: string, r: Line) => {
    const answer = await exchange(hub.socketFor(seat), r);
    assert.equal(answer.ok, true, "the seat's trace line is taken as it always was");
  };
  const access = () => lines.filter((l) => l.agent === "system" && l.tool === "sensitive_access");
  const submit = async (who: string, spec: Record<string, unknown>) => {
    const r = await svc.submit(who, { kind: "command", timeout_seconds: 60, network: "off", inputs: [], ...spec } as never);
    assert.ok(r.ok, !r.ok ? r.reason : "");
    for (let i = 0; i < 1200; i += 1) {
      const j = svc.jobs.get(r.job.id);
      if (j && ["committed", "failed", "cancelled"].includes(j.state)) return j;
      await new Promise((res) => setTimeout(res, 50));
    }
    throw new Error(`${r.job.id} did not finish`);
  };
  return { S, hub, svc, lines, dir, agents, tokens, colPath, mk, row, send, access, submit };
}

/** A run with a secret job (a values file) and a plain job. */
async function withJobs() {
  const r = await rig();
  const secret = await r.submit("a1", { command: `echo done-with-it; printf '%s\\n' '${VALUE}' > "$OUT/values.jsonl"; echo '{"k":1}' > "$OUT/other.json"`, secret_output: true });
  const plain = await r.submit("a1", { command: `echo plain-output; echo hello > "$OUT/p.txt"` });
  assert.equal(secret.sensitive?.why, "secret_output");
  assert.equal(plain.sensitive, undefined);
  return { ...r, secret: secret.id, plain: plain.id };
}

test("a seat's read tool on a sensitive job's output is noted after its row: seat, job, part, path, via path, certainty path", async () => {
  const { hub, S, lines, row, send, access, secret } = await withJobs();
  void hub;
  const read = row("read", { path: `store/jobs/${secret}/out/values.jsonl` }, { ok: true, output: "(the value)" });
  await send("a1", read);
  await until(() => access().length === 1, "the access line");
  const [line] = access();
  assert.equal(line.agent, "system", "the harness's own line, not the seat's");
  assert.equal(line.args.seat, "a1");
  assert.equal(line.args.via, "path");
  assert.equal(line.args.certainty, "path");
  assert.equal(line.args.rules, 1);
  assert.deepEqual(line.args.on, { job: secret, part: "out", why: "secret_output", paths: [`store/jobs/${secret}/out/values.jsonl`] });
  assert.deepEqual([line.args.tool_row.agent, line.args.tool_row.sid, line.args.tool_row.seq, line.args.tool_row.tool], ["a1", read.sid, read.seq, "read"], "it points to the row it was made from");
  assert.ok(typeof line.ts === "string" && line.ts.length > 10, "and has its time");
  // The seat's row went through whole and first; the note follows it.
  const at = lines.findIndex((l) => l.tool === "read" && l.seq === read.seq);
  assert.ok(at >= 0 && lines.indexOf(line) > at, "the note follows its row");
  assert.equal(lines[at].result.output, "(the value)", "the row is forwarded as it came");
  // The same path, absolute (the VM sees the run at its host path), and through `..`, is the same job.
  await send("a1", row("read", { path: join(S, "store", "jobs", secret, "out", "values.jsonl") }));
  await send("a1", row("read", { file_path: `work/../store/jobs/${secret}/out/./other.json` }));
  await until(() => access().length === 3, "both");
  assert.deepEqual(access().slice(1).map((l) => l.args.on.paths), [[`store/jobs/${secret}/out/values.jsonl`], [`store/jobs/${secret}/out/other.json`]]);
});

test("grep, find and ls are noted; a job's own directory is read only by a search; its record and manifest say nothing of its content", async () => {
  const { row, send, access, secret } = await withJobs();
  await send("a1", row("grep", { pattern: "TOKEN", path: `store/jobs/${secret}/out` }));
  await send("a1", row("find", { pattern: "*.jsonl", path: `store/jobs/${secret}/out` }));
  await send("a1", row("ls", { path: `store/jobs/${secret}/out/` }));
  await send("a1", row("grep", { pattern: "TOKEN", path: `store/jobs/${secret}` }));
  await send("a1", row("read", { path: `store/jobs/${secret}/stdout.log` }));
  await until(() => access().length === 5, "five lines");
  assert.deepEqual(access().map((l) => [l.args.tool_row.tool, l.args.on.part, l.args.certainty]), [["grep", "out", "path"], ["find", "out", "path"], ["ls", "out", "path"], ["grep", "out", "path"], ["read", "log", "path"]]);
  // Names only, and the metadata files: no line.
  await send("a1", row("ls", { path: `store/jobs/${secret}` }));
  await send("a1", row("read", { path: `store/jobs/${secret}/manifest.json` }));
  await send("a1", row("read", { path: `store/jobs/${secret}/job.json` }));
  await send("a1", row("read", { path: "work/a1/notes.txt" }));
  // Settle: a row after them, which is noted.
  await send("a1", row("read", { path: `store/jobs/${secret}/out/other.json` }));
  await until(() => access().length === 6, "the settling line");
  assert.equal(access().length, 6, "nothing for a directory listing, the metadata files or a file of the seat's own");
});

test("a job that is not sensitive, a job id that only starts the same, and a path outside the run are not noted", async () => {
  const { row, send, access, secret, plain } = await withJobs();
  await send("a1", row("read", { path: `store/jobs/${plain}/out/p.txt` }));
  await send("a1", row("read", { path: `store/jobs/${secret}0/out/values.jsonl` }));
  await send("a1", row("read", { path: `/etc/store/jobs/${secret}/out/values.jsonl` }));
  await send("a1", row("bash", { command: `cat store/jobs/${plain}/out/p.txt && echo ${secret}0` }));
  await send("a1", row("read", { path: `store/jobs/${secret}/out/values.jsonl` }));
  await until(() => access().length >= 1, "the one that counts");
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(access().length, 1);
  assert.equal(access()[0].args.tool_row.seq, 5);
});

test("a shell command that names a sensitive output is noted with via text and certainty text; the id alone names the job", async () => {
  const { S, row, send, access, secret } = await withJobs();
  await send("a2", row("bash", { command: `cat store/jobs/${secret}/out/values.jsonl | head -3` }));
  await send("a2", row("bash", { command: `cd ${S}/store/jobs/${secret}/out && wc -c *` }));
  await send("a2", row("powershell", { command: `Get-Content store/jobs/${secret}/stderr.log` }));
  await send("a2", row("bash", { command: `echo "see ${secret} for the value"` }));
  await until(() => access().length === 4, "four lines");
  assert.deepEqual(access().map((l) => [l.args.seat, l.args.via, l.args.certainty, l.args.on.part, l.args.on.job]), [
    ["a2", "text", "text", "out", secret],
    ["a2", "text", "text", "out", secret],
    ["a2", "text", "text", "log", secret],
    ["a2", "text", "text", "run", secret],
  ]);
  assert.deepEqual(access()[0].args.on.paths, [`store/jobs/${secret}/out/values.jsonl`]);
});

test("a command that walks a root or globs over the jobs is a maybe, listing the sensitive jobs it could reach and not the plain ones", async () => {
  const { row, send, access, secret, plain } = await withJobs();
  await send("a1", row("bash", { command: "cat store/jobs/*/out/*" }));
  await send("a1", row("bash", { command: "grep -r TOKEN store/jobs" }));
  await send("a1", row("bash", { command: "find store -type f -name '*.jsonl'" }));
  await send("a1", row("grep", { pattern: "TOKEN", path: "store" }));
  await send("a1", row("grep", { pattern: "TOKEN" }));
  await send("a1", row("bash", { command: `cat store/jobs/${secret.slice(0, 5)}*/out/values.jsonl` }));
  // Not a reach: a listing of the jobs, and a word.
  await send("a1", row("bash", { command: "ls store/jobs" }));
  await send("a1", row("bash", { command: "echo store the result in a file" }));
  await send("a1", row("bash", { command: `cat store/jobs/${plain.slice(0, 5)}9*/out/x` }));
  await send("a1", row("bash", { command: `cat store/jobs/${secret}/out/values.jsonl` }));
  await until(() => access().length === 7, "seven lines");
  await new Promise((r) => setTimeout(r, 100));
  const maybes = access().filter((l) => l.args.certainty === "maybe");
  assert.equal(maybes.length, 6);
  for (const m of maybes) {
    assert.equal(m.args.on.job, null, "no one job");
    assert.deepEqual(m.args.on.candidates, [secret], "the sensitive job only; the plain one is not a candidate");
  }
  assert.deepEqual(maybes.map((l) => l.args.via), ["text", "text", "text", "path", "path", "text"]);
  assert.equal(access().at(-1)!.args.certainty, "text");
});

test("a blob is noted by its part, not by its digest: a digest of a weak secret is the secret", async () => {
  const { S, row, send, access, secret } = await withJobs();
  const ix = await sensitiveIndex(S);
  const sha = [...ix.content.entries()].find(([, id]) => id === secret)![0];
  await send("a1", row("bash", { command: `cat store/blobs/${sha}` }));
  await send("a1", row("read", { path: `store/blobs/${sha}` }));
  await until(() => access().length === 2, "two lines");
  for (const l of access()) {
    assert.equal(l.args.on.part, "blob");
    assert.equal(l.args.on.job, secret);
    assert.ok(!JSON.stringify(l).includes(sha), "no digest on the line");
  }
  assert.deepEqual(access().map((l) => l.args.via), ["text", "path"]);
});

test("a page of a sensitive job's stdout that job_status returns is certain, via api_page, and the page is returned whole", async () => {
  const { S, hub, access, secret, plain } = await withJobs();
  const status = (seat: string, id: string, extra: Record<string, unknown> = {}) => board.callBoard(hub.socketFor(seat), "jobStatus", [S, { job_id: id, ...extra }]) as Promise<Line>;
  const plainPage = await status("a2", plain);
  assert.equal(plainPage.stdout.text, "plain-output\n");
  const page = await status("a2", secret);
  assert.equal(page.ok, true);
  assert.equal(page.stdout.text, "done-with-it\n", "nothing is held back from the seat");
  await until(() => access().length === 1, "the page is noted");
  const [line] = access();
  assert.deepEqual([line.args.seat, line.args.via, line.args.certainty, line.args.on.job, line.args.on.part, line.args.on.why], ["a2", "api_page", "certain", secret, "stdout", "secret_output"]);
  assert.deepEqual(line.args.on.paths, [`store/jobs/${secret}/stdout.log`]);
  assert.deepEqual(line.args.api, { fn: "jobStatus", offset: 0, bytes: 13, total: 13 });
  assert.equal(line.args.tool_row, undefined, "it is made from an API answer, not from a trace row");
  // Another page is another line; the owner's own read is noted as well.
  await status("a1", secret, { offset: 5, limit: 4 });
  await until(() => access().length === 2, "the second page");
  assert.deepEqual([access()[1].args.seat, access()[1].args.api], ["a1", { fn: "jobStatus", offset: 5, bytes: 4, total: 13 }]);
});

test("the tail of a sensitive job's stderr in an answer is noted as a page of stderr", async () => {
  const r = await rig();
  const secret = await r.submit("a1", { command: `echo oops-detail >&2; printf '%s\\n' '${VALUE}' > "$OUT/values.jsonl"`, secret_output: true });
  const answer = (await board.callBoard(r.hub.socketFor("a2"), "jobStatus", [r.S, { job_id: secret.id }])) as Line;
  assert.equal(answer.job.stderr.tail, "oops-detail\n");
  await until(() => r.access().some((l) => l.args.on.part === "stderr"), "stderr noted");
  const line = r.access().find((l) => l.args.on.part === "stderr")!;
  assert.deepEqual([line.args.via, line.args.certainty, line.args.seat], ["api_page", "certain", "a2"]);
});

test("the seat is the socket's, whatever the row claims; a row sent twice is noted once", async () => {
  const { row, send, access, secret } = await withJobs();
  const r = row("read", { path: `store/jobs/${secret}/out/values.jsonl` });
  await send("a2", { ...r, agent: "a1" });
  await send("a2", { ...r, agent: "a1" });
  await send("a1", { ...r, agent: "a1" });
  await until(() => access().length === 2, "a2's line and a1's");
  await new Promise((res) => setTimeout(res, 100));
  assert.deepEqual(access().map((l) => l.args.seat), ["a2", "a1"], "a2's row twice is one line; a1's is its own");
});

test("a derived job's output is noted with why derived", async () => {
  const { svc, row, send, access, secret, submit } = await withJobs();
  const derived = await submit("a2", { command: `wc -c store/jobs/${secret}/out/values.jsonl > "$OUT/c.txt"`, inputs: ["all"] });
  assert.equal(derived.sensitive?.why, "derived");
  void svc;
  await send("a1", row("read", { path: `store/jobs/${derived.id}/out/c.txt` }));
  await until(() => access().length === 1, "the line");
  assert.equal(access()[0].args.on.why, "derived");
  assert.equal(access()[0].args.on.job, derived.id);
});

test("a read of a copy kept under tool-output/ is the same access, noted as a copy, by whoever reads it, also after a restart", async () => {
  const ctx = await withJobs();
  const { hub, row, send, access, secret, lines, mk } = ctx;
  const kept = "tool-output/a1/20261021T101500000-bash-ab12.out.log";
  const cat = row("bash", { command: `cat store/jobs/${secret}/out/values.jsonl` }, { ok: true, output: "(long)", full_output: { path: kept, bytes: 99999, lines: 3, sha256: "0".repeat(64) } });
  await send("a1", cat);
  await until(() => access().length === 1, "the cat");
  assert.equal(access()[0].result.kept_as, kept);
  await send("a2", row("read", { path: kept }));
  await send("a2", row("bash", { command: `grep -c TOKEN ${kept}` }));
  await until(() => access().length === 3, "the copy read twice");
  assert.deepEqual(access().slice(1).map((l) => [l.args.seat, l.args.via, l.args.on.part, l.args.on.job]), [["a2", "path", "copy", secret], ["a2", "text", "copy", secret]]);
  // A hub brought back after a crash: the same rows are not noted again, and the copy is still known.
  await hub.stop();
  const again = mk();
  await again.start();
  cleanups.push(async () => again.stop());
  again.jobService = ctx.svc;
  const before = access().length;
  assert.equal((await exchange(again.socketFor("a1"), cat)).ok, true);
  assert.equal((await exchange(again.socketFor("a2"), row("read", { path: `${kept}` }, { ok: true }, 900))).ok, true);
  await until(() => access().length === before + 1, "only the new read");
  await new Promise((res) => setTimeout(res, 100));
  assert.equal(access().length, before + 1, "the resent cat is not noted twice");
  assert.equal(access().at(-1)!.args.on.part, "copy", "the copy is still known to the new hub");
  void lines;
});

test("200 lines for a seat and a job, then one that says the rest are on the trace, then none", async () => {
  const { row, send, access, secret, lines } = await withJobs();
  for (let i = 0; i < 205; i += 1) await send("a1", row("read", { path: `store/jobs/${secret}/out/values.jsonl` }));
  await until(() => access().length === 201, "the lines and the burst line");
  await new Promise((res) => setTimeout(res, 100));
  assert.equal(access().length, 201);
  const last = access().at(-1)!;
  assert.equal(last.args.burst.after, 200);
  assert.match(last.args.burst.note, /on the trace as the rows they come from/);
  assert.equal(lines.filter((l) => l.agent === "a1" && l.tool === "read").length, 205, "every row is on the trace");
  // Another seat's count is its own.
  await send("a2", row("read", { path: `store/jobs/${secret}/out/values.jsonl` }));
  await until(() => access().length === 202, "a2's first");
});

test("with no sensitive output in the run, no row is noted and nothing changes for the seat", async () => {
  const r = await rig();
  const plain = await r.submit("a1", { command: `echo hi > "$OUT/p.txt"` });
  await r.send("a1", r.row("read", { path: `store/jobs/${plain.id}/out/p.txt` }));
  await r.send("a1", r.row("bash", { command: "cat store/jobs/*/out/*; find store -type f" }));
  await new Promise((res) => setTimeout(res, 100));
  assert.equal(r.access().length, 0);
  assert.equal(r.lines.filter((l) => l.agent === "a1").length, 2, "the seat's rows are on the trace as sent");
});

test("the matching, row by row", async () => {
  const sandbox = "/run/x";
  const ix = {
    jobs: new Map([["j000001", { id: "j000001", sensitivity: { why: "secret_output" as const, from: [], note: "" }, status: "ok", files: [], logs: [] }]]),
    content: new Map([["a".repeat(64), "j000001"]]),
    genJob: new Map([["g000002", "j000001"]]),
    aliasJob: new Map([["vault", "j000001"]]),
  } as unknown as AccessIndex;
  const hit = (tool: string, args: Record<string, unknown>) => classifyTraceRow({ tool, args }, ix, { sandbox });
  const one = (tool: string, args: Record<string, unknown>) => {
    const h = hit(tool, args);
    return h.length === 1 ? [h[0].job, h[0].via, h[0].certainty, h[0].part] : h;
  };
  assert.deepEqual(one("read", { path: "./store/jobs/j000001/out/a//b" }), ["j000001", "path", "path", "out"]);
  assert.deepEqual(one("read", { path: "/run/x/catalog/gen/g000002/members.tsv" }), ["j000001", "path", "path", "catalog"]);
  assert.deepEqual(one("read", { path: "catalog/vault/files.txt" }), ["j000001", "path", "path", "catalog"]);
  assert.deepEqual(hit("read", { path: "catalog/gen/g000009/x" }), []);
  assert.deepEqual(hit("read", { path: "../x/store/jobs/j000001/out/a" }), []);
  assert.deepEqual(hit("read", { path: "/other/store/jobs/j000001/out/a" }), []);
  assert.deepEqual(hit("read", { path: "store/jobs/j000001" }), [], "reading a directory holds no bytes");
  assert.deepEqual(hit("edit", { path: "store/jobs/j000001/out/a" }), [], "only the reading tools");
  assert.deepEqual(hit("bash", { command: 42 }), []);
  // A command: the paths it names, once per job, with every path that named it.
  const both = hit("bash", { command: "cp store/jobs/j000001/out/a work/a1/ && cat store/jobs/j000001/out/b" });
  assert.equal(both.length, 1);
  assert.deepEqual(both[0].paths, ["store/jobs/j000001/out/a", "store/jobs/j000001/out/b"]);
  assert.deepEqual(one("bash", { command: "cat $S/store/jobs/j000001/out/x" }), ["j000001", "text", "text", "out"]);
  assert.deepEqual(one("bash", { command: "cat '/run/x/store/jobs/j000001/out/x'" }), ["j000001", "text", "text", "out"]);
  assert.deepEqual(hit("bash", { command: "cat store/jobs/$J/out/x" }), [], "a path a shell computes is not seen");
  assert.deepEqual(hit("bash", { command: "echo j0000010 j00000" }), [], "an id is a whole word");
  // A glob over the job ids narrows to the jobs it matches.
  assert.deepEqual(hit("bash", { command: "cat store/jobs/j0000[0-9]1/out/x" }).map((h) => h.certainty), ["maybe"]);
  assert.deepEqual(hit("bash", { command: "cat store/jobs/j9*/out/x" }), []);
  assert.deepEqual(hit("bash", { command: "cat store/jobs/{j000001,j000002}/out/x" }).map((h) => [h.job, h.certainty]), [["j000001", "text"]], "a brace list that holds the id names it");
  assert.deepEqual(hit("bash", { command: "cat store/jobs/{j00000?,x}/out/x" }).map((h) => [h.job, h.certainty, h.candidates]), [[null, "maybe", ["j000001"]]]);
});

test("the reader (scripts/sensitive-access.ts) takes the hub's own lines: the record, the check against the trace and the chain of use", async () => {
  const { S, hub, row, send, access, secret, submit } = await withJobs();
  const derived = await submit("a2", { command: `wc -c store/jobs/${secret}/out/values.jsonl > "$OUT/c.txt"`, inputs: ["all"] });
  const kept = "tool-output/a1/20261021T101500000-bash-ab12.out.log";
  await send("a1", row("read", { path: `store/jobs/${secret}/out/values.jsonl` }));
  await send("a1", row("bash", { command: `cat store/jobs/${secret}/out/values.jsonl` }, { ok: true, full_output: { path: kept, bytes: 9, lines: 1, sha256: "0".repeat(64) } }));
  await send("a2", { ...row("read", { path: kept }), agent: "a2" });
  await send("a1", row("bash", { command: "cat store/jobs/*/out/*" }));
  await send("a1", row("read", { path: "work/a1/notes.txt" }));
  await board.callBoard(hub.socketFor("a2"), "jobStatus", [S, { job_id: secret }]);
  await until(() => access().length === 5, "five lines");
  await new Promise((r) => setTimeout(r, 100));
  const rec = await accessRecord(S);
  assert.deepEqual(rec.problems, []);
  const seen = rec.events.filter((e) => e.source === "trace");
  assert.equal(seen.length, 5);
  assert.ok(seen.every((e) => e.recorded && e.evidence === "harness_observed_read" && e.rules === 1));
  assert.deepEqual(seen.map((e) => [e.seat, e.via, e.certainty, e.job, e.part]).sort(), [
    ["a1", "path", "path", secret, "out"],
    ["a1", "text", "maybe", null, "run"],
    ["a1", "text", "text", secret, "out"],
    ["a2", "api_page", "certain", secret, "stdout"],
    ["a2", "path", "path", secret, "copy"],
  ]);
  assert.equal(seen.find((e) => e.part === "copy")?.tool_row?.agent, "a2");
  // The derived job is a verified link from the journal, under the same root.
  const link = rec.events.find((e) => e.evidence === "harness_verified_link");
  assert.deepEqual([link?.by_job, link?.job, link?.how], [derived.id, secret, "named_in_text"]);
  const prov = provenance(rec);
  assert.deepEqual(prov.roots.map((r) => r.job), [secret]);
  assert.equal(prov.roots[0].observed.length, 5);
  assert.deepEqual(prov.roots[0].used_by.map((c) => c.node.job), [derived.id]);
  // Every line points at a row the rules read as naming its job, and every such row has a line.
  const v = await verifyAccess(S);
  assert.deepEqual([v.ok, v.orphan.length, v.unrecorded.length, v.duplicate.length], [true, 0, 0, 0]);
  // Deriving from the trace alone adds nothing the hub did not record.
  const again = await accessRecord(S, { derive: true });
  assert.equal(again.events.filter((e) => !e.recorded).length, 0);
  assert.ok(renderAccess(rec).endsWith(`${LOWER_BOUND_SENTENCE}\n`));
});
