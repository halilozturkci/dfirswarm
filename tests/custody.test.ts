/**
 * The host's own custody check, taken after a run, and the report lines a
 * microVM run adds. The check is the harness's word, not an agent's: it
 * re-reads every byte, and a change anywhere has to be named.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, test } from "node:test";
import {
  confinedOutput,
  custodyAnchorPath,
  fsDecode,
  fsEncode,
  keptOutputRefs,
  markOwnHost,
  secretViolations,
  adverse,
  takeCustody,
  verdictAnchorState,
  verdictOf,
  type Custody,
} from "../scripts/custody.ts";
import { hashArtifacts } from "../scripts/artifacts.ts";
import { ACCESS_RULES, LOWER_BOUND_SENTENCE, SEAT_ROWS_SENTENCE } from "../scripts/sensitive-access.ts";
import { READ_HIT, T, fixtureFiles, hubLine, jl, traceRow, writeFiles, type Extra } from "./sensitive-access-fixture.ts";
import { ledgerHash, type LedgerEntry } from "../extensions/protocol.ts";
import {
  anchorGuarded,
  attributionLine,
  egressLine,
  evidenceArrival,
  evidenceFrom,
  herdrSocketLine,
  measuredGuardLine,
  vmRows,
  writeGuardLine,
} from "../scripts/report.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
/** The evidence part of a verdict, for a run whose manifest was readable. */
const evidence = (c: Custody) => c.inputs as Exclude<Custody["inputs"], null | { unverifiable: string }>;

async function sandbox(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "custody-"));
  dirs.push(root);
  await mkdir(join(root, "inputs", "mail"), { recursive: true });
  await writeFile(join(root, "inputs", "notes.txt"), "notes\n");
  await writeFile(join(root, "inputs", "mail", "a.bin"), "attachment");
  await writeFile(join(root, "inputs.json"), JSON.stringify({
    source: "/evidence",
    copied_at: "2026-09-24T00:00:00Z",
    bytes: 16,
    enforce: "auto",
    guard: "microvm",
    // A copy: inputs/ is the run's own directory (held in place, it would be a link to /evidence).
    held: "copy",
    files: [
      { path: "inputs/notes.txt", bytes: 6, sha256: sha("notes\n") },
      { path: "inputs/mail/a.bin", bytes: 10, sha256: sha("attachment") },
    ],
  }));
  await mkdir(join(root, ".pi-sessions", "a0"), { recursive: true });
  await writeFile(join(root, ".pi-sessions", "a0", "s.jsonl"), '{"type":"session"}\n');
  await mkdir(join(root, "tool-output", "a0"), { recursive: true });
  await writeFile(join(root, "tool-output", "a0", "x.out.log"), "whole output\n");
  await writeFile(join(root, "tool-output", "a0", "y.out.log"), "changed later\n");
  await mkdir(join(root, "traces"), { recursive: true });
  const lines = [
    { ts: "t", agent: "a0", tool: "bash", args: {}, result: { ok: true, full_output: { path: "tool-output/a0/x.out.log", bytes: 13, lines: 1, sha256: sha("whole output\n") } } },
    { ts: "t", agent: "a0", tool: "bash", args: {}, result: { ok: true, nested: [{ full_output: { path: "tool-output/a0/y.out.log", sha256: sha("as it was kept\n") } }] } },
    { ts: "t", agent: "a0", tool: "bash", args: {}, result: { ok: true, full_output: { path: "tool-output/a0/gone.log", sha256: sha("gone") } } },
  ];
  await writeFile(join(root, "traces", "events.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  return root;
}

test("every kept output the trace names is found, wherever in a line it sits", () => {
  const refs = keptOutputRefs({ a: { full_output: { path: "tool-output/a/1.log", sha256: "a".repeat(64) } }, b: [{ path: "tool-output/b/2.log", sha256: "b".repeat(64) }], c: { path: "work/x", sha256: "c".repeat(64) } });
  assert.deepEqual([...refs.keys()].sort(), ["tool-output/a/1.log", "tool-output/b/2.log"], "only the harness's kept outputs, not a work file");
});

test("custody names every kept output that is gone or no longer what the trace says", async () => {
  const root = await sandbox();
  const c = await takeCustody(root);
  assert.equal(evidence(c).unchanged, true);
  assert.equal(evidence(c).files, 2);
  assert.equal(evidence(c).manifest_anchored, null, "no anchor: said, not assumed");
  assert.equal(c.sessions.files.length, 1);
  assert.equal(c.sessions.files[0].sha256, sha('{"type":"session"}\n'));
  assert.equal(c.tool_outputs.referenced, 3);
  assert.equal(c.tool_outputs.verified, 1);
  assert.deepEqual(c.tool_outputs.missing, ["tool-output/a0/gone.log"]);
  assert.deepEqual(c.tool_outputs.mismatched, ["tool-output/a0/y.out.log"]);
  assert.match(c.summary, /KEPT OUTPUTS: 1\/3 verified, 1 missing, 1 not matching the trace/);
  const onDisk = JSON.parse(await readFile(join(root, "custody.json"), "utf8"));
  assert.equal(onDisk.summary, c.summary, "the verdict is written where the report reads it");
});

test("custody re-hashes the evidence in full and says what changed, went missing or appeared", async () => {
  const root = await sandbox();
  await writeFile(join(root, "inputs", "notes.txt"), "notes, edited\n");
  await rm(join(root, "inputs", "mail", "a.bin"));
  await writeFile(join(root, "inputs", "planted.txt"), "new");
  const c = await takeCustody(root);
  assert.equal(evidence(c).unchanged, false);
  assert.deepEqual(evidence(c).changed, ["inputs/notes.txt"]);
  assert.deepEqual(evidence(c).missing, ["inputs/mail/a.bin"]);
  assert.deepEqual(evidence(c).added, ["inputs/planted.txt"]);
  assert.match(c.summary, /^EVIDENCE CHANGED: 1 changed, 1 missing, 1 added/);
});

test("several sets held in place: custody re-hashes each through its link, finds what appeared in one, and walks no link the manifest does not name as a set", async () => {
  const root = await mkdtemp(join(tmpdir(), "custody-sets-"));
  const outside = await mkdtemp(join(tmpdir(), "custody-sets-ev-"));
  dirs.push(root, outside);
  await mkdir(join(outside, "laptop", "users"), { recursive: true });
  await mkdir(join(outside, "phone"), { recursive: true });
  await mkdir(join(outside, "other"), { recursive: true });
  await writeFile(join(outside, "laptop", "users", "ntuser.dat"), "hive");
  await writeFile(join(outside, "phone", "sms.db"), "sqlite");
  await symlink("users/ntuser.dat", join(outside, "laptop", "hive-link"));
  // inputs/ is the run's own directory with a link per set (swarm.sh bind_inputs).
  await mkdir(join(root, "inputs"));
  await symlink(join(outside, "laptop"), join(root, "inputs", "laptop"));
  await symlink(join(outside, "phone"), join(root, "inputs", "phone"));
  await writeFile(join(root, "inputs.json"), JSON.stringify({
    source: `${join(outside, "laptop")}, ${join(outside, "phone")}`,
    sets: [
      { name: "laptop", path: "inputs/laptop", source: join(outside, "laptop"), files: 2, bytes: 4 },
      { name: "phone", path: "inputs/phone", source: join(outside, "phone"), files: 1, bytes: 6 },
    ],
    copied_at: "2026-09-27T00:00:00Z",
    bytes: 10,
    enforce: "auto",
    guard: "microvm",
    held: "bind",
    files: [
      { path: "inputs/laptop/hive-link", bytes: 0, sha256: sha("link:users/ntuser.dat"), link: "users/ntuser.dat" },
      { path: "inputs/laptop/users/ntuser.dat", bytes: 4, sha256: sha("hive") },
      { path: "inputs/phone/sms.db", bytes: 6, sha256: sha("sqlite") },
    ],
  }));
  let c = await takeCustody(root);
  assert.equal(evidence(c).unchanged, true, c.summary);
  assert.deepEqual([evidence(c).checked?.files, evidence(c).checked?.links], [2, 1]);
  assert.deepEqual(evidence(c).added, [], "a set's link is where the set is, not a name added to the evidence");
  await writeFile(join(outside, "phone", "planted.db"), "new");
  await writeFile(join(outside, "laptop", "users", "ntuser.dat"), "HIVE");
  // A link at the top that the manifest does not name as a set is a name, and never walked.
  await symlink(join(outside, "other"), join(root, "inputs", "other"));
  c = await takeCustody(root);
  assert.deepEqual(evidence(c).changed, ["inputs/laptop/users/ntuser.dat"]);
  assert.deepEqual(evidence(c).added, ["inputs/other", "inputs/phone/planted.db"]);
});

test("the manifest is checked against the kickoff's anchor outside the run: a rewritten manifest is caught, a missing one is said", async () => {
  const root = await sandbox();
  const manifest = await readFile(join(root, "inputs.json"));
  await writeFile(custodyAnchorPath(root), JSON.stringify({ run: "t1", inputs_manifest_sha256: createHash("sha256").update(manifest).digest("hex") }));
  let c = await takeCustody(root);
  assert.equal(evidence(c).manifest_anchored, true);
  assert.match(c.summary, /manifest anchored/);
  assert.equal(c.run, "t1", "the run id comes from the anchor");
  // An agent that could write the manifest could make custody compare
  // against its own list; the anchor says which list the kickoff wrote.
  const forged = JSON.parse(manifest.toString()) as { files: Array<{ path: string; sha256: string }> };
  await writeFile(join(root, "inputs", "notes.txt"), "notes, edited\n");
  forged.files[0].sha256 = sha("notes, edited\n");
  await writeFile(join(root, "inputs.json"), JSON.stringify(forged));
  c = await takeCustody(root);
  assert.equal(evidence(c).manifest_anchored, false);
  assert.equal(evidence(c).unchanged, false, "a rewritten manifest is not an unchanged evidence set");
  assert.match(c.summary, /MANIFEST REWRITTEN/);
  await rm(join(root, "inputs.json"));
  c = await takeCustody(root);
  assert.ok(c.inputs && "unverifiable" in c.inputs, "evidence with no manifest is unverifiable, not unchanged");
  assert.match(c.summary, /EVIDENCE UNVERIFIABLE/);
});

test("custody takes no path an agent wrote at face value: a kept-output reference is a regular file under tool-output/ or it is refused", async () => {
  const root = await sandbox();
  for (const bad of ["tool-output/../../etc/passwd", "tool-output/a0/../../inputs.json", "tool-output/a0", "work/x.log"]) {
    const where = await confinedOutput(root, bad);
    assert.ok("why" in where, `${bad} is refused`);
  }
  const { symlink, mkdir: mk } = await import("node:fs/promises");
  await symlink("/etc/hosts", join(root, "tool-output", "a0", "link.log"));
  await mk(join(root, "tool-output", "a0", "dir.log"));
  assert.deepEqual(await confinedOutput(root, "tool-output/a0/link.log"), { why: "a link" });
  assert.deepEqual(await confinedOutput(root, "tool-output/a0/dir.log"), { why: "not a regular file" });
  const ok = await confinedOutput(root, "tool-output/a0/x.out.log");
  assert.ok("abs" in ok && ok.size === 13);
  // A trace line that names a link is a refusal in the verdict, and the stop goes on.
  await writeFile(join(root, "traces", "events.jsonl"), `${JSON.stringify({ ts: "t", agent: "a0", tool: "bash", args: {}, result: { full_output: { path: "tool-output/a0/link.log", sha256: "0".repeat(64) } } })}\n`);
  const c = await takeCustody(root, { timeoutSec: 60 });
  assert.deepEqual(c.tool_outputs.refused, ["tool-output/a0/link.log (a link)"]);
  assert.match(c.summary, /1 refused/);
});

test("custody has a deadline: past it the verdict says what was not finished instead of the stop hanging", async () => {
  const root = await sandbox();
  const c = await takeCustody(root, { timeoutSec: 0 });
  assert.ok(c.incomplete, "the deadline is on the record");
  assert.match(c.summary, /CUSTODY INCOMPLETE/);
});

test("the ledger's chain is verified: an entry rewritten after the fact breaks it", async () => {
  const root = await sandbox();
  await mkdir(join(root, "ledger"), { recursive: true });
  const e1: LedgerEntry = { seq: 1, kind: "event", ts: "2026-01-01T00:00:00Z", value: "first", source: "s", evidence: "e", by: "a0", authors: ["a0"], at: "2026-09-24T00:00:00Z" };
  e1.prev = "genesis";
  e1.hash = ledgerHash(e1, e1.prev);
  const e2: LedgerEntry = { seq: 2, kind: "finding", value: "second", source: "s", evidence: "e", by: "a1", authors: ["a1"], at: "2026-09-24T00:00:01Z" };
  e2.prev = e1.hash;
  e2.hash = ledgerHash(e2, e2.prev);
  await writeFile(join(root, "ledger", "entries.jsonl"), `${JSON.stringify(e1)}\n${JSON.stringify(e2)}\n`);
  let c = await takeCustody(root);
  assert.equal(c.ledger?.intact, true);
  assert.match(c.summary, /ledger 2 entries, all chained, chain intact/);
  await writeFile(join(root, "ledger", "entries.jsonl"), `${JSON.stringify({ ...e1, value: "first, reworded" })}\n${JSON.stringify(e2)}\n`);
  c = await takeCustody(root);
  assert.equal(c.ledger?.intact, false);
  assert.match(c.summary, /LEDGER CHAIN BROKEN/);
  // A line added after the chained ones without the chain is a line added
  // outside it, not an old unchained entry.
  const loose = { seq: 3, kind: "finding", value: "slipped in", source: "s", evidence: "e", by: "a1", authors: ["a1"], at: "2026-09-24T00:00:02Z" };
  await writeFile(join(root, "ledger", "entries.jsonl"), `${JSON.stringify(e1)}\n${JSON.stringify(e2)}\n${JSON.stringify(loose)}\n`);
  c = await takeCustody(root);
  assert.equal(c.ledger?.intact, false, "an unchained entry after chained ones breaks the chain");
  assert.match(c.summary, /LEDGER CHAIN BROKEN .*without the chain/);
});

test("the ledger's provenance is in its chain, and the ledger is held to the trace", async () => {
  const root = await sandbox();
  await mkdir(join(root, "ledger"), { recursive: true });
  // Entries written before the ledger was chained, then chained ones: the
  // first chained entry names the last old one, and the whole verifies.
  const old: LedgerEntry = { seq: 1, kind: "event", ts: "2026-01-01T00:00:00Z", value: "old", by: "a0", authors: ["a0"], at: "2026-09-24T00:00:00Z" };
  const e2: LedgerEntry = { v: 2, seq: 2, kind: "finding", value: "second", source: "s", evidence: "e", confidence: "high", by: "a1", authors: ["a1"], at: "2026-09-24T00:00:01Z" };
  e2.prev = ledgerHash(old, "genesis");
  e2.hash = ledgerHash(e2, e2.prev);
  const e3: LedgerEntry = { v: 2, seq: 3, kind: "ioc", value: "1.2.3.4", source: "fw.log", evidence: "line 9", by: "a0", authors: ["a0"], at: "2026-09-24T00:00:02Z" };
  e3.prev = e2.hash;
  e3.hash = ledgerHash(e3, e3.prev);
  const write = (entries: LedgerEntry[]) => writeFile(join(root, "ledger", "entries.jsonl"), entries.map((e) => JSON.stringify(e)).join("\n") + "\n");
  await write([old, e2, e3]);
  // The record tool's lines carry each new entry's hash.
  const traceLine = (e: LedgerEntry, n: number) => JSON.stringify({ ts: e.at, agent: e.by, tool: "record", args: {}, result: { ok: true, seq: e.seq, merged: false, total: n, hash: e.hash } });
  await writeFile(join(root, "traces", "events.jsonl"), `${traceLine(e2, 2)}\n${traceLine(e3, 3)}\n`);
  let c = await takeCustody(root);
  assert.equal(c.ledger?.intact, true, JSON.stringify(c.ledger));
  assert.match(c.summary, /ledger 3 entries, 2 of 3 chained, chain intact/);
  // Rewriting a version 2 entry's source breaks the chain: provenance is in the core.
  await write([old, e2, { ...e3, source: "somewhere else" }]);
  c = await takeCustody(root);
  assert.equal(c.ledger?.intact, false, "a rewritten source breaks the chain");
  // The last entry deleted: the chain the file still has is intact, and the
  // trace says an entry is gone.
  await write([old, e2]);
  c = await takeCustody(root);
  assert.deepEqual(c.ledger?.missing_from_ledger, [e3.hash]);
  assert.match(c.summary, /LEDGER DIFFERS FROM THE TRACE: 1 entry on the trace missing from the ledger/);
  // An entry written into the file without the tool: chained, never on the trace.
  const e4: LedgerEntry = { v: 2, seq: 4, kind: "finding", value: "forged", source: "x", evidence: "y", by: "a1", authors: ["a1"], at: "2026-09-24T00:00:03Z" };
  e4.prev = e3.hash;
  e4.hash = ledgerHash(e4, e4.prev);
  await write([old, e2, e3, e4]);
  c = await takeCustody(root);
  assert.deepEqual(c.ledger?.not_on_trace, [4]);
  assert.match(c.summary, /in the ledger never on the trace \(seq 4\)/);
});

test("custody checks a kept VM disk against its record, and counts lines the chain never took", async () => {
  const root = await sandbox();
  await mkdir(join(root, "vm"), { recursive: true });
  await mkdir(`${root}.vm-snapshots`, { recursive: true });
  dirs.push(`${root}.vm-snapshots`);
  const snap = join(`${root}.vm-snapshots`, "a0.msb");
  await writeFile(snap, "disk bytes");
  await writeFile(join(root, "vm", "a0.json"), JSON.stringify({ agent: "a0", image: { manifest_digest: "sha256:abc" }, snapshot: { path: snap, sha256: sha("disk bytes"), bytes: 10 } }));
  await writeFile(join(root, "vm", "a1.json"), JSON.stringify({ agent: "a1", image: { manifest_digest: "sha256:abc" }, snapshot: { path: snap, sha256: sha("other") } }));
  await writeFile(join(root, "tool-output", "a0", "trace-spill.jsonl"), '{"tool":"bash"}\n{"tool":"read"}\n');
  const c = await takeCustody(root);
  assert.deepEqual(c.vms?.map((v) => [v.agent, v.snapshot && "verified" in v.snapshot ? v.snapshot.verified : null]), [["a0", true], ["a1", false]]);
  assert.match(c.summary, /2 VMs, 1 of 2 snapshots verified against their record, .*2 NOT PUT AWAY/, "a VM never recorded as stopped is named");
  assert.deepEqual(c.trace.spilled, [{ path: "tool-output/a0/trace-spill.jsonl", lines: 2, agent: "a0", bad: 2, duplicates: 0 }], "spilled lines that do not say whose they are cannot be attributed");
  assert.match(c.summary, /2 trace lines outside the chain .* 2 NOT ATTRIBUTABLE/);
  await writeFile(join(root, "tool-output", "a0", "trace-spill.jsonl"), '{"tool":"bash","agent":"a0"}\n{"tool":"read","agent":"a1"}\n');
  const again = await takeCustody(root);
  assert.equal(again.trace.spilled[0].bad, 1, "a line in a0's spill that claims to be a1's is not attributable");
  // One image for the run: a VM that booted another digest than the one the
  // kickoff resolved is named.
  await writeFile(join(root, "vm", "a1.json"), JSON.stringify({ agent: "a1", image: { manifest_digest: "sha256:def", expected_digest: "sha256:abc" }, snapshot: { path: snap, sha256: sha("other") } }));
  const moved = await takeCustody(root);
  assert.match(moved.summary, /IMAGE DIGEST DIFFERS: a1 booted sha256:def, not sha256:abc/);
  // A package the VM's root installed outside the seat's toolchain is named.
  await writeFile(join(root, "vm", "a0.json"), JSON.stringify({ agent: "a0", image: { manifest_digest: "sha256:abc" }, snapshot: { path: snap, sha256: sha("disk bytes"), bytes: 10 }, installed_outside_image: { baseline: true, apt: { cowsay: "3.03" }, venv: { tabulate: "0.10.0" } } }));
  const installed = await takeCustody(root);
  assert.match(installed.summary, /INSTALLED OUTSIDE THE IMAGE AND THE TOOLCHAIN RECORD: a0 apt cowsay 3\.03, venv tabulate 0\.10\.0/);
  assert.equal(installed.vms?.find((v) => v.agent === "a1")?.installed_outside.note, "no inventory was taken (a VM put away before stop took one)");
  await writeFile(join(root, "vm", "a1.json"), JSON.stringify({ agent: "a1", image: { manifest_digest: "sha256:abc" }, snapshot: { path: snap, sha256: sha("other") }, runtime_changed: { from: "0.7.2", to: "0.7.3" } }));
  assert.match((await takeCustody(root)).summary, /MSB CHANGED DURING THE RUN: a1 0\.7\.2 → 0\.7\.3/);
  assert.doesNotMatch(again.summary, /IMAGE DIGEST DIFFERS/, "records with no resolved digest are not called different");
});

test("the report's custody lines know a microVM run", () => {
  assert.match(writeGuardLine("microvm"), /^enforced \(microVM/);
  assert.match(attributionLine("channel"), /^by channel/);
  assert.match(egressLine("microvm"), /^enforced \(microVM network policy/);
  assert.match(egressLine("microvm-open"), /^OPEN \(--no-netguard/, "a VM run with the network open says so, not \"none\"");
  assert.match(herdrSocketLine("unreachable"), /^out of reach/);
  assert.match(measuredGuardLine("microvm"), /probed at kickoff/);
  assert.equal(anchorGuarded("microvm", undefined), true, "the anchor is on the host, and the host is in no VM");
  assert.match(evidenceArrival({ source: "/ev", guard: "microvm", held: "bind" }), /mounted read-only/);
  assert.match(evidenceArrival({ source: "/ev", guard: "seatbelt", held: "bind" }), /linked to it/);
  assert.match(evidenceArrival({ source: "/ev", guard: "seatbelt" }), /^<p>Copied from/);
  // Several sets: each named at inputs/<name>/ with where it came from.
  const sets = [{ path: "inputs/laptop", source: "/ev/laptop", files: 3 }, { path: "inputs/phone", source: "/ev/phone", files: 1 }];
  assert.match(evidenceArrival({ source: "/ev/laptop, /ev/phone", guard: "microvm", held: "bind", sets }), /^<p>Used in place from 2 sets \(<code>\/ev\/laptop<\/code> as <code>inputs\/laptop\/<\/code>, 3 files; <code>\/ev\/phone<\/code> as <code>inputs\/phone\/<\/code>, 1 file\)/);
  assert.equal(evidenceFrom({ source: "/ev/laptop, /ev/phone", sets }), "in 2 sets: inputs/laptop/ from /ev/laptop (3 files); inputs/phone/ from /ev/phone (1 file)");
  assert.equal(evidenceFrom({ source: "/ev" }), "from /ev", "one set is said as it always was");
});

test("each agent's VM is a custody row: what it could write, reach and was given, and its disk", () => {
  const rows = vmRows([
    {
      agent: "a0",
      name: "dfs-r-a0",
      runtime: { name: "microsandbox", version: "0.7.2" },
      image: { ref: "ghcr.io/x/dfirswarm-memory@sha256:1", manifest_digest: "sha256:1" },
      cpus: 2,
      memory_mib: 2048,
      mounts: [{ host: "/r", guest: "/r", mode: "ro" }, { host: "/r/work", guest: "/r/work", mode: "rw" }, { host: "/r/work/quarantine", guest: "/r/work/quarantine", mode: "rw", noexec: true }],
      network: { default: "deny", allow_hosts: ["api.openai.com"], host_ports: [1234] },
      secrets: [{ name: "openai (API key)", hosts: ["api.openai.com"] }],
      snapshot: { path: "/r.vm-snapshots/a0.msb", sha256: "f".repeat(64) },
    },
  ]);
  assert.equal(rows[0][0], "Isolation");
  assert.match(rows[0][1], /microsandbox 0\.7\.2\), image ghcr\.io\/x\/dfirswarm-memory@sha256:1 \(sha256:1\)/);
  assert.equal(rows[1][0], "VM a0");
  assert.match(rows[1][1], /writable: \/r\/work, \/r\/work\/quarantine \(no-exec\)/);
  assert.match(rows[1][1], /could reach: api\.openai\.com:443, the host gateway :1234/);
  assert.match(rows[1][1], /openai \(API key\) → api\.openai\.com/);
  assert.match(rows[1][1], new RegExp(`kept, sha256 ${"f".repeat(64)}`));
  assert.deepEqual(vmRows([]), [], "a host run adds nothing");
});

test("the report says every VM booted the digest resolved at kickoff, or which did not, and what the image says it was built from", () => {
  const base = {
    runtime: { name: "microsandbox", version: "0.7.2" },
    network: { default: "deny", allow_hosts: ["msdl.microsoft.com:80", "api.x.com"] },
  };
  const description = { profile: "disk", pack_versions: { "windows-forensics": { version: "1.2.1" } }, redistributable: false, nonredistributable: ["fls", "vol"], downloads: { hayabusa: { version: "4.1.0" } } };
  const same = vmRows([
    { ...base, agent: "a0", image: { ref: "dfirswarm-disk:dev-arm64", manifest_digest: "sha256:aa", expected_digest: "sha256:aa", description } },
    { ...base, agent: "a1", image: { ref: "dfirswarm-disk:dev-arm64", manifest_digest: "sha256:aa", expected_digest: "sha256:aa", description } },
  ]);
  const digestRow = same.find(([k]) => k === "Image digest");
  assert.match(digestRow?.[1] ?? "", /^every VM booted sha256:aa, resolved once at kickoff$/);
  const record = same.find(([k]) => k === "Image record")?.[1] ?? "";
  assert.match(record, /profile disk; built from windows-forensics 1\.2\.1; pinned downloads hayabusa 4\.1\.0; NOT for redistribution \(2 programs/);
  assert.match(same.find(([k]) => k === "VM a0")?.[1] ?? "", /could reach: msdl\.microsoft\.com:80, api\.x\.com:443/, "a port given is not given another");
  const off = vmRows([
    { ...base, agent: "a0", image: { ref: "r", manifest_digest: "sha256:aa", expected_digest: "sha256:aa" } },
    { ...base, agent: "a1", image: { ref: "r", manifest_digest: "sha256:bb", expected_digest: "sha256:aa" } },
  ]);
  assert.match(off.find(([k]) => k === "Image digest")?.[1] ?? "", /^DIFFERS: a1 booted sha256:bb; the run resolved sha256:aa$/);
  const inv = vmRows([{ ...base, agent: "a0", installed_outside_image: { baseline: true, apt: { cowsay: "3.03" }, venv: {} } }]);
  assert.match(inv.find(([k]) => k === "VM a0")?.[1] ?? "", /installed at stop: INSTALLED OUTSIDE THE IMAGE: apt cowsay 3\.03/);
});

test("numbered trace lines: a line in both the chain and a spill is counted once as a duplicate, and a missing number is a lost line", async () => {
  const root = await sandbox();
  const chainLines = [1, 2, 4].map((seq) => ({ ts: "t", agent: "a0", tool: "bash", args: {}, result: {}, sid: "abc", seq }));
  await writeFile(join(root, "traces", "events.jsonl"), chainLines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  await writeFile(join(root, "tool-output", "a0", "trace-spill.jsonl"), [2, 5].map((seq) => JSON.stringify({ ts: "t", agent: "a0", tool: "read", args: {}, result: {}, sid: "abc", seq })).join("\n") + "\n");
  const c = await takeCustody(root);
  assert.equal(c.trace.spilled[0].duplicates, 1, "seq 2 reached the chain and the spill");
  assert.deepEqual(c.trace.gaps, [{ sid: "abc", agent: "a0", missing: 1 }], "seq 3 reached neither");
  assert.match(c.summary, /1 also in the chain/);
  assert.match(c.summary, /1 TRACE LINE LOST/);
});

test("a line whose own clock is far from the collector's is named, with how far", async () => {
  const root = await sandbox();
  const lines = [
    { ts: "2026-09-24T10:00:00.000Z", recv_ts: "2026-09-24T10:00:01.000Z", agent: "a0", tool: "bash", args: {}, result: {} },
    { ts: "2026-09-24T10:10:00.000Z", recv_ts: "2026-09-24T10:00:02.000Z", agent: "a1", tool: "bash", args: {}, result: {} },
    { ts: "2026-09-24T09:50:00.000Z", recv_ts: "2026-09-24T10:00:03.000Z", agent: "a1", tool: "read", args: {}, result: {} },
  ];
  await writeFile(join(root, "traces", "events.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  const c = await takeCustody(root);
  assert.deepEqual(c.trace.clock, [{ agent: "a1", lines: 2, max_skew_s: -603 }], "a0's one-second gap is not named; a1's ten minutes both ways are");
  assert.match(c.summary, /a1 2 lines \(up to -603 s\)/);
});

test("a placeholder msb stopped on its way to another host is read from the VM's runtime log", () => {
  const log = [
    "2026-09-24T07:03:09.080700Z  INFO microsandbox_runtime::runner::vm: sandbox starting sandbox=dfs-x",
    "2026-09-24T07:03:10.051819Z  WARN microsandbox_network::engine::secrets::handler: secret violation: placeholder detected for disallowed host action=block-and-log secret_env_var=K placeholder=dfirswarm-secret-probe-abc protocol=http/1.1 sni=api.openai.com host=api.openai.com method=GET path=/v1/models location=header match_form=raw guest_dst=172.66.0.243:443 http2_stream_id=",
  ].join("\n");
  assert.deepEqual(secretViolations(log), [{ at: "2026-09-24T07:03:10.051819Z", env: "K", host: "api.openai.com", method: "GET", path: "/v1/models", action: "block-and-log", location: "header", match_form: "raw" }]);
  assert.deepEqual(secretViolations("nothing here\n"), []);
});

test("a stop on the credential's own host is told from one aimed elsewhere", async () => {
  // Run se064eb: 52 stops, every one to api.openai.com, the host the
  // credential is bound to (msb 0.7.2 read a body starting with % as the
  // placeholder's location). The summary called them all "aimed at a host
  // not its own".
  const v = (env: string, host: string) => ({ at: "t", env, host, method: "POST", path: "/v1/responses", action: "block-and-log", location: "body" });
  const marked = markOwnHost(
    [v("DFIRSWARM_OPENAI_CREDENTIAL", "api.openai.com"), v("DFIRSWARM_OPENAI_CREDENTIAL", "api.deepseek.com"), v("VT_API_KEY", "www.virustotal.com"), v("NOBODY", "x.test"), v("DFIRSWARM_AZURE_CREDENTIAL", "r.openai.azure.com")],
    [
      { name: "openai (API key)", hosts: ["api.openai.com"] },
      { name: "VT_API_KEY", env: "VT_API_KEY", hosts: ["www.virustotal.com"] },
      { name: "azure-openai (API key)", env: "DFIRSWARM_AZURE_CREDENTIAL", hosts: ["r.openai.azure.com:8443"] },
    ],
  );
  assert.deepEqual(marked.map((x) => x.own_host), [true, false, true, null, true], "by the record's variable, the provider's name, a pack secret's name; a port does not matter; unknown is null");

  const root = await sandbox();
  await mkdir(join(root, "vm"), { recursive: true });
  const logs = join(`${root}.vm-snapshots`, "a0.logs");
  await mkdir(logs, { recursive: true });
  dirs.push(`${root}.vm-snapshots`);
  const warn = (host: string, location: string) =>
    `2026-09-24T23:01:03.397131Z  WARN microsandbox_network::engine::secrets::handler: secret violation: placeholder detected for disallowed host action=block-and-log secret_env_var=DFIRSWARM_OPENAI_CREDENTIAL placeholder=dfirswarm-secret-openai-x protocol=http/1.1 sni=${host} host=${host} method=POST path=/v1/responses location=${location} match_form=percent_decoded`;
  await writeFile(join(logs, "runtime.log"), [warn("api.openai.com", "body"), warn("api.deepseek.com", "header"), ""].join("\n"));
  await writeFile(join(root, "vm", "a0.json"), JSON.stringify({ agent: "a0", image: { manifest_digest: "sha256:abc" }, logs, secrets: [{ name: "openai (API key)", hosts: ["api.openai.com"] }] }));
  const c = await takeCustody(root);
  assert.deepEqual(c.vms?.[0].secret_violations.map((x) => [x.host, x.own_host, x.location]), [["api.openai.com", true, "body"], ["api.deepseek.com", false, "header"]]);
  assert.match(c.summary, /1 SECRET PLACEHOLDER AIMED AT A HOST NOT ITS OWN, stopped by msb: a0 DFIRSWARM_OPENAI_CREDENTIAL → api\.deepseek\.com POST \/v1\/responses \(header\)/);
  assert.match(c.summary, /msb stopped 1 request to a credential's own host on a placeholder it found outside the headers \(not a leak; each request failed\): a0 DFIRSWARM_OPENAI_CREDENTIAL → api\.openai\.com POST \/v1\/responses \(body\)/);
});

test("a trace with no chain is called unchained, never intact", async () => {
  const root = await sandbox();
  await writeFile(join(root, "traces", "events.jsonl"), [1, 2].map((i) => JSON.stringify({ ts: "t", agent: "a0", tool: "bash", args: { i }, result: {} })).join("\n") + "\n");
  const c = await takeCustody(root);
  assert.equal(c.trace.intact, false);
  assert.match(c.summary, /TRACE UNCHAINED \(2 lines\)/);
  assert.doesNotMatch(c.summary, /chain intact/);
});

test("custody indexes what the run produced and anchors the index and its own verdict outside the run", async () => {
  const root = await sandbox();
  await mkdir(join(root, "work", "a0"), { recursive: true });
  await writeFile(join(root, "work", "report.md"), "# findings\n");
  await writeFile(join(root, "work", "a0", "notes.txt"), "notes\n");
  const anchorFile = `${root}.custody-anchor.json`;
  await writeFile(anchorFile, JSON.stringify({ run: "t1", started_at: "2026-09-24T00:00:00Z" }));
  dirs.push(anchorFile);
  const c = await takeCustody(root);
  assert.equal(c.artifacts?.files, 2);
  const index = await readFile(join(root, "artifacts.json"), "utf8");
  assert.equal(c.artifacts?.index_sha256, sha(index));
  assert.match(c.summary, /2 work files indexed/);
  const anchor = JSON.parse(await readFile(anchorFile, "utf8")) as { run: string; custody: Array<{ sha256: string; artifacts_sha256: string }> };
  assert.equal(anchor.run, "t1", "the kickoff's fields stay");
  assert.equal(anchor.custody.at(-1)?.artifacts_sha256, sha(index));
  assert.equal(anchor.custody.at(-1)?.sha256, sha(await readFile(join(root, "custody.json"), "utf8")), "the verdict's own hash is anchored");
});

test("a line a sender says it could not write is counted, not lost in silence", async () => {
  const root = await sandbox();
  await writeFile(join(root, "traces", "events.jsonl"), `${JSON.stringify({ ts: "2026-09-24T00:00:00Z", agent: "a0", tool: "bash", args: { trace_lines_lost_before: 2 }, result: {} })}\n`);
  const c = await takeCustody(root);
  assert.deepEqual(c.trace.sender_lost, [{ agent: "a0", lines: 2 }]);
  assert.match(c.summary, /TRACE LINES THE SENDER COULD NOT WRITE: a0 2/);
});

/** An anchor outside the run, as the kickoff writes it, removed with the run. */
async function anchor(root: string, fields: Record<string, unknown>): Promise<void> {
  const file = custodyAnchorPath(root);
  dirs.push(file);
  await rm(file, { force: true });
  await writeFile(file, JSON.stringify({ run: "t1", started_at: "2026-09-24T00:00:00Z", ...fields }));
}

test("custody never reads or writes through a link planted where its outputs go, and keeps what it replaces", async () => {
  const root = await sandbox();
  const outside = await mkdtemp(join(tmpdir(), "custody-outside-"));
  dirs.push(outside);
  const secret = join(outside, "auth.json");
  const hook = join(outside, "settings.json");
  const planted = join(outside, "planted.json");
  await writeFile(secret, "SECRET-CREDENTIALS\n");
  await writeFile(hook, "{}\n");
  await writeFile(planted, "{}\n");
  // A pane links the verdict and the index to operator files.
  await symlink(secret, join(root, "custody.json"));
  await symlink(planted, join(root, "artifacts.json"));
  let c = await takeCustody(root);
  assert.equal(await readFile(secret, "utf8"), "SECRET-CREDENTIALS\n", "the verdict was written through the link");
  assert.equal(await readFile(planted, "utf8"), "{}\n", "the index was written through the link");
  for (const name of ["custody.json", "artifacts.json"]) {
    const st = await lstat(join(root, name));
    assert.ok(st.isFile() && !st.isSymbolicLink(), `${name} is a file of custody's own`);
  }
  assert.match(c.previous ?? "", /custody\.json was a link; removed, not read/);
  for (const name of await readdir(root)) {
    const st = await lstat(join(root, name));
    if (st.isFile()) assert.doesNotMatch(await readFile(join(root, name), "utf8"), /SECRET-CREDENTIALS/, `${name} holds the link target's bytes`);
  }
  // A previous verdict whose `at` names a file the pane linked: not a date,
  // so it is kept under custody's own name, and the link is left alone.
  await writeFile(join(root, "custody.json"), JSON.stringify({ at: "pwn", summary: "a pane's verdict" }));
  await symlink(hook, join(root, "custody.pwn.json"));
  c = await takeCustody(root);
  assert.equal(await readFile(hook, "utf8"), "{}\n");
  assert.match(c.previous ?? "", /^custody\.previous-\d+T\d+Z\.json$/);
  // A real date whose dated name is a link: the rename replaces the link, never writes through it.
  await writeFile(join(root, "custody.json"), JSON.stringify({ at: "2026-01-01T00:00:00.000Z", summary: "the old verdict" }));
  await symlink(hook, join(root, "custody.20260101T000000000Z.json"));
  c = await takeCustody(root);
  assert.equal(c.previous, "custody.20260101T000000000Z.json");
  assert.equal(await readFile(hook, "utf8"), "{}\n");
  assert.ok(!(await lstat(join(root, "custody.20260101T000000000Z.json"))).isSymbolicLink());
  assert.match(await readFile(join(root, "custody.20260101T000000000Z.json"), "utf8"), /the old verdict/);
});

test("a directory of more than 125,000 evidence files gets a verdict", { skip: process.env.DFIRSWARM_SLOW_TESTS !== "1" && "slow (about 40 s): set DFIRSWARM_SLOW_TESTS=1" }, async () => {
  // One push of a spread array this long overflowed the stack, and custody wrote no verdict at all.
  const root = await mkdtemp(join(tmpdir(), "custody-many-"));
  dirs.push(root);
  await mkdir(join(root, "inputs", "big"), { recursive: true });
  const files: Array<{ path: string; bytes: number; sha256: string }> = [];
  for (let i = 0; i < 130_000; i++) {
    await writeFile(join(root, "inputs", "big", `f${i}`), "");
    files.push({ path: `inputs/big/f${i}`, bytes: 0, sha256: sha("") });
  }
  await writeFile(join(root, "inputs.json"), JSON.stringify({ source: "/x", copied_at: "t", files, bytes: 0, enforce: "auto", guard: "none" }));
  const c = await takeCustody(root, { timeoutSec: 600 });
  assert.equal(evidence(c).unchanged, true, c.summary);
  assert.equal(evidence(c).files, 130_000);
});

test("the manifest is read as a stream: chunk boundaries, escapes and braces inside names, and its bytes are what is anchored", async () => {
  const root = await sandbox();
  await writeFile(join(root, "inputs", 'odd "name" {x} [y].txt'), "odd\n");
  const manifest = JSON.parse(await readFile(join(root, "inputs.json"), "utf8")) as { files: Array<Record<string, unknown>> };
  manifest.files.push({ path: 'inputs/odd "name" {x} [y].txt', bytes: 4, sha256: sha("odd\n") });
  // Padding past one read chunk, so names and escapes straddle a boundary.
  const text = JSON.stringify({ padding: " ".repeat(1_500_000), ...manifest }, null, 2);
  await writeFile(join(root, "inputs.json"), text);
  await anchor(root, { inputs_manifest_sha256: sha(text) });
  const c = await takeCustody(root);
  assert.equal(evidence(c).files, 3);
  assert.equal(evidence(c).unchanged, true, c.summary);
  assert.equal(evidence(c).manifest_anchored, true);
  await writeFile(join(root, "inputs.json"), '{"files": [ {"path": "inputs/notes.txt"');
  assert.match((await takeCustody(root)).summary, /EVIDENCE UNVERIFIABLE/, "a manifest cut short is no manifest");
});

test("md5 and sha1 are compared beside sha256 when the manifest carries them, in the one read", async () => {
  const root = await sandbox();
  const md5 = (t: string) => createHash("md5").update(t).digest("hex");
  const sha1 = (t: string) => createHash("sha1").update(t).digest("hex");
  const m = JSON.parse(await readFile(join(root, "inputs.json"), "utf8")) as { files: Array<Record<string, unknown>> };
  m.files[0] = { ...m.files[0], md5: md5("notes\n"), sha1: sha1("notes\n") };
  await writeFile(join(root, "inputs.json"), JSON.stringify(m));
  let c = await takeCustody(root);
  assert.equal(evidence(c).unchanged, true, c.summary);
  assert.deepEqual(evidence(c).digests_compared, { sha256: 2, md5: 1, sha1: 1 });
  assert.match(c.summary, /md5 on 1 and sha1 on 1 compared too/);
  m.files[0] = { ...m.files[0], md5: md5("something else") };
  await writeFile(join(root, "inputs.json"), JSON.stringify(m));
  c = await takeCustody(root);
  assert.deepEqual(evidence(c).changed, ["inputs/notes.txt"], "an md5 that does not match is a change");
});

test("a name that is not UTF-8 is the same name in the manifest and on disk", async () => {
  // Python writes such a name with surrogateescape: each byte that is not
  // UTF-8 as a lone surrogate. Read back as bytes, it is the name on disk.
  const raw = Buffer.from([0x62, 0x61, 0x64, 0xff, 0x2e, 0x74, 0x78, 0x74]); // bad\xff.txt
  const asPython = "bad\udcff.txt";
  assert.deepEqual(fsEncode(asPython), raw);
  assert.equal(fsDecode(raw), asPython);
  assert.deepEqual(fsEncode("İstanbul ğüşıö 日本"), Buffer.from("İstanbul ğüşıö 日本", "utf8"), "a UTF-8 name is its UTF-8 bytes");
  if (process.platform !== "linux") return; // APFS refuses a name that is not UTF-8
  const root = await sandbox();
  const dir = Buffer.from(join(root, "inputs"));
  await writeFile(Buffer.concat([dir, Buffer.from("/"), raw]), "legacy\n");
  const m = JSON.parse(await readFile(join(root, "inputs.json"), "utf8")) as { files: Array<Record<string, unknown>> };
  m.files.push({ path: `inputs/${asPython}`, bytes: 7, sha256: sha("legacy\n") });
  await writeFile(join(root, "inputs.json"), JSON.stringify(m));
  let c = await takeCustody(root);
  assert.equal(evidence(c).unchanged, true, c.summary);
  // And with the bytes recorded outright.
  m.files[2] = { path: "inputs/bad?.txt", path_b64: Buffer.concat([Buffer.from("inputs/"), raw]).toString("base64"), bytes: 7, sha256: sha("legacy\n") };
  await writeFile(join(root, "inputs.json"), JSON.stringify(m));
  c = await takeCustody(root);
  assert.equal(evidence(c).unchanged, true, c.summary);
});

test("a link where a file was, a file where a link was, and a file the host cannot read are each said for what they are", async () => {
  const root = await sandbox();
  await symlink("notes.txt", join(root, "inputs", "alias"));
  const m = JSON.parse(await readFile(join(root, "inputs.json"), "utf8")) as { files: Array<Record<string, unknown>> };
  m.files.push({ path: "inputs/alias", bytes: 0, sha256: sha("link:notes.txt"), link: "notes.txt" });
  await writeFile(join(root, "inputs.json"), JSON.stringify(m));
  assert.equal(evidence(await takeCustody(root)).unchanged, true);
  await rm(join(root, "inputs", "alias"));
  await writeFile(join(root, "inputs", "alias"), "a file now");
  let c = await takeCustody(root);
  assert.deepEqual(evidence(c).changed, ["inputs/alias"], "a regular file where the link was is a change, not an absence");
  assert.deepEqual(evidence(c).missing, []);
  if (process.getuid?.() === 0) return; // root reads a file whatever its mode
  await rm(join(root, "inputs", "alias"));
  await symlink("notes.txt", join(root, "inputs", "alias"));
  await chmod(join(root, "inputs", "mail", "a.bin"), 0o000);
  try {
    c = await takeCustody(root);
  } finally {
    await chmod(join(root, "inputs", "mail", "a.bin"), 0o644);
  }
  assert.equal(evidence(c).unchanged, false);
  assert.deepEqual(evidence(c).missing, [], "a file that is there is not missing");
  assert.match(evidence(c).unreadable[0] ?? "", /^inputs\/mail\/a\.bin \(unreadable \(EACCES\)\)$/);
  assert.match(c.summary, /EVIDENCE NOT FULLY RE-HASHED: 2 of 3 checked unchanged, 1 unreadable by the host/);
});

test("custody opens no FIFO and follows no link: a trace, a ledger, spills and evidence that are not files", async () => {
  const root = await sandbox();
  const fifo = (p: string) => execFileSync("mkfifo", [p]);
  await rm(join(root, "traces", "events.jsonl"));
  fifo(join(root, "traces", "events.jsonl"));
  await mkdir(join(root, "ledger"), { recursive: true });
  fifo(join(root, "ledger", "entries.jsonl"));
  fifo(join(root, "tool-output", "a0", "trace-spill.jsonl"));
  await mkdir(join(root, "work"), { recursive: true });
  await symlink("/dev/stdin", join(root, "work", ".trace-spill.jsonl"));
  fifo(join(root, "inputs", "pipe"));
  const m = JSON.parse(await readFile(join(root, "inputs.json"), "utf8")) as { files: Array<Record<string, unknown>> };
  m.files.push({ path: "inputs/pipe", bytes: 0, sha256: sha("special:fifo"), special: "fifo" });
  await writeFile(join(root, "inputs.json"), JSON.stringify(m));
  const started = Date.now();
  const c = await takeCustody(root, { timeoutSec: 60 });
  assert.ok(Date.now() - started < 30_000, "custody waited on something");
  assert.equal(evidence(c).unchanged, true, "a FIFO recorded as one is checked by its kind, never opened");
  assert.equal(evidence(c).checked.special, 1);
  assert.match(c.summary, /TRACE UNREADABLE: not a regular file/);
  assert.match(c.summary, /SPILL NOT READ: .*tool-output\/a0\/trace-spill\.jsonl is not a regular file/);
  assert.match(c.summary, /SPILL NOT READ: .*work\/\.trace-spill\.jsonl is a link/);
  assert.match(c.summary, /LEDGER CHAIN BROKEN \(the ledger is not a regular file\)/);
});

test("the ledger is held to the trace whatever the trace carries: a forged ledger, and an old-shaped entry after new ones, are not on it", async () => {
  const root = await sandbox();
  await mkdir(join(root, "ledger"), { recursive: true });
  // Chained version 2 entries, and a trace (it has lines) with no record line at all.
  const e1: LedgerEntry = { v: 2, seq: 1, kind: "finding", value: "forged", source: "s", evidence: "e", by: "a0", authors: ["a0"], at: "2026-09-24T00:00:00Z" };
  e1.prev = "genesis";
  e1.hash = ledgerHash(e1, e1.prev);
  await writeFile(join(root, "ledger", "entries.jsonl"), `${JSON.stringify(e1)}\n`);
  let c = await takeCustody(root);
  assert.deepEqual(c.ledger?.not_on_trace, [1], "a whole ledger written without the tool is not on the trace");
  assert.equal(c.ledger?.intact, false);
  // The tool's line carries its hash; then an entry in the old shape, chained on, is appended by hand.
  await writeFile(join(root, "traces", "events.jsonl"), `${JSON.stringify({ ts: "t", agent: "a0", tool: "record", args: {}, result: { ok: true, seq: 1, merged: false, total: 1, hash: e1.hash } })}\n`);
  const old: LedgerEntry = { seq: 2, kind: "finding", value: "slipped in", by: "a0", authors: ["a0"], at: "2026-09-24T00:00:01Z" };
  old.prev = e1.hash;
  old.hash = ledgerHash(old, old.prev);
  await writeFile(join(root, "ledger", "entries.jsonl"), `${JSON.stringify(e1)}\n${JSON.stringify(old)}\n`);
  c = await takeCustody(root);
  assert.equal(c.ledger?.intact, false, "an old-shaped entry after the first version 2 one was not written by the tool");
  assert.ok(c.ledger?.not_on_trace.includes(2), JSON.stringify(c.ledger));
});

test("a version 3 ledger is held to the trace too: an entry the trace never carried is named, however well it is chained", async () => {
  const root = await sandbox();
  await anchor(root, { isolation: "microvm" });
  await mkdir(join(root, "ledger"), { recursive: true });
  const v3 = (seq: number, value: string, prev: string): LedgerEntry => {
    const e: LedgerEntry = { v: 3, seq, kind: "finding", value, source: "inputs/notes.txt", evidence: "line 1", confidence: "high", refs: ["input:inputs/notes.txt"], by: "a0", authors: ["a0"], at: `2026-09-27T00:00:0${seq}Z` };
    e.prev = prev;
    e.hash = ledgerHash(e, prev);
    return e;
  };
  const e1 = v3(1, "recorded through the hub", "genesis");
  const e2 = v3(2, "written into the file by hand", e1.hash as string);
  await writeFile(join(root, "ledger", "entries.jsonl"), `${JSON.stringify(e1)}\n${JSON.stringify(e2)}\n`);
  // The hub logged e1 only.
  await writeFile(join(root, "traces", "events.jsonl"), `${JSON.stringify({ ts: "t", agent: "system", tool: "hub_call", args: { fn: "recordEntry", seat: "a0" }, result: { ok: true, hash: e1.hash }, sid: "hub", seq: 1 })}\n`);
  const c = await takeCustody(root);
  assert.equal(c.ledger?.detail, "2 of 2 entries chained", "its own chain holds");
  assert.deepEqual(c.ledger?.not_on_trace, [2], JSON.stringify(c.ledger));
  assert.equal(c.ledger?.intact, false);
  assert.equal(c.checks.find((x) => x.name === "ledger")?.status, "failed");
  assert.equal(c.checks.find((x) => x.name === "ledger")?.reason, "1 in the ledger and never on the trace (seq 2)", "the check says why, not only that the chain holds");
  assert.match(c.summary, /in the ledger never on the trace \(seq 2\)/);
});

test("in a microVM run the ledger is held to the hub's lines, and a seat's lines and spill speak for that seat only", async () => {
  const root = await sandbox();
  await anchor(root, { isolation: "microvm" });
  await mkdir(join(root, "ledger"), { recursive: true });
  const e1: LedgerEntry = { v: 2, seq: 1, kind: "ioc", value: "1.2.3.4", source: "s", evidence: "e", by: "a0", authors: ["a0"], at: "2026-09-24T00:00:00Z" };
  e1.prev = "genesis";
  e1.hash = ledgerHash(e1, e1.prev);
  await writeFile(join(root, "ledger", "entries.jsonl"), `${JSON.stringify(e1)}\n`);
  const lines = [
    // The hub's line for the record, which no guest writes.
    { ts: "t", agent: "system", tool: "hub_call", args: { fn: "recordEntry", seat: "a0" }, result: { ok: true, hash: e1.hash }, sid: "hub", seq: 1 },
    // A seat's own line claiming a record the hub never made: a false tamper alarm, if believed.
    { ts: "t", agent: "a0", tool: "record", args: {}, result: { ok: true, hash: "f".repeat(64) }, sid: "s0", seq: 1 },
    // a1's lines 1 and 3: its line 2 was lost.
    { ts: "t", agent: "a1", tool: "bash", args: {}, result: {}, sid: "s1", seq: 1 },
    { ts: "t", agent: "a1", tool: "bash", args: {}, result: {}, sid: "s1", seq: 3 },
  ];
  await writeFile(join(root, "traces", "events.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  // a0's spill fills a1's gap and adds losses in a1's name; neither is a0's to say.
  await writeFile(
    join(root, "tool-output", "a0", "trace-spill.jsonl"),
    `${JSON.stringify({ ts: "t", agent: "a1", tool: "bash", args: { trace_lines_lost_before: 5 }, result: {}, sid: "s1", seq: 2 })}\n`,
  );
  // And the shared spill on work/, which no VM run writes.
  await mkdir(join(root, "work"), { recursive: true });
  await writeFile(join(root, "work", ".trace-spill.jsonl"), `${JSON.stringify({ ts: "t", agent: "a1", tool: "bash", args: {}, result: {}, sid: "s1", seq: 2 })}\n`);
  const c = await takeCustody(root);
  assert.equal(c.isolation, "microvm");
  assert.equal(c.ledger?.intact, true, JSON.stringify(c.ledger));
  assert.equal(c.ledger?.held_to, "the hub's lines");
  assert.deepEqual(c.ledger?.missing_from_ledger, [], "a seat's own line is not the hub's");
  assert.deepEqual(c.ledger?.claimed_by_seat, ["f".repeat(64)]);
  assert.deepEqual(c.trace.gaps, [{ sid: "s1", agent: "a1", missing: 1 }], "a1's lost line stays lost");
  assert.deepEqual(c.trace.sender_lost, [], "a0 cannot report losses for a1");
  assert.equal(c.trace.spilled.find((x) => x.path === "tool-output/a0/trace-spill.jsonl")?.bad, 1);
  assert.equal(c.trace.spilled.find((x) => x.path === "work/.trace-spill.jsonl")?.bad, 1, "the shared spill is nobody's in a VM run");
});

test("a kept output is checked against the hash it was kept under, and only its own agent names it", async () => {
  const root = await sandbox();
  const kept = sha("whole output\n");
  await writeFile(join(root, "tool-output", "a0", "x.out.log"), "rewritten\n");
  const lines = [
    { ts: "t", agent: "a0", tool: "bash", args: {}, result: { full_output: { path: "tool-output/a0/x.out.log", sha256: kept } } },
    // The seat names it again with the rewritten file's hash.
    { ts: "t", agent: "a0", tool: "bash", args: {}, result: { full_output: { path: "tool-output/a0/x.out.log", sha256: sha("rewritten\n") } } },
    // Another seat names a0's output with a hash of its own choosing.
    { ts: "t", agent: "a1", tool: "bash", args: {}, result: { full_output: { path: "tool-output/a0/y.out.log", sha256: "0".repeat(64) } } },
  ];
  await writeFile(join(root, "traces", "events.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  const c = await takeCustody(root);
  assert.deepEqual(c.tool_outputs.mismatched, ["tool-output/a0/x.out.log"], "naming it again did not launder it");
  assert.deepEqual(c.tool_outputs.rereferenced, ["tool-output/a0/x.out.log"]);
  assert.deepEqual(c.tool_outputs.foreign, ["tool-output/a0/y.out.log (named by a1)"]);
  assert.equal(c.tool_outputs.referenced, 1);
  assert.match(c.summary, /KEPT OUTPUT NAMED AGAIN WITH ANOTHER HASH/);
});

test("VM records: one that cannot be read and an agent with none are named; a host run's vm/ is not read", async () => {
  const root = await sandbox();
  await anchor(root, { isolation: "microvm" });
  await writeFile(join(root, "team.json"), JSON.stringify({ swarm_id: "t1", n: 3, agents: [{ id: "a0" }, { id: "a1" }, { id: "a2" }] }));
  await mkdir(join(root, "vm"), { recursive: true });
  await mkdir(`${root}.vm-snapshots`, { recursive: true });
  dirs.push(`${root}.vm-snapshots`);
  const snap = join(`${root}.vm-snapshots`, "a0.msb");
  await writeFile(snap, "disk bytes");
  await writeFile(join(root, "vm", "a0.json"), JSON.stringify({ agent: "a0", stopped_at: "t", snapshot: { path: snap, sha256: sha("other bytes") } }));
  await writeFile(join(root, "vm", "a1.json"), '{"agent": "a1", "snap');
  let c = await takeCustody(root);
  assert.deepEqual(c.vm_records?.unreadable, ["a1.json (not valid JSON)"]);
  assert.deepEqual(c.vm_records?.no_record, ["a1", "a2"]);
  assert.match(c.summary, /VM RECORD UNREADABLE: a1\.json/);
  assert.match(c.summary, /NO VM RECORD FOR: a1, a2/);
  assert.match(c.summary, /SNAPSHOT DOES NOT MATCH ITS RECORD \(a0\)/, "a disk that changed after stop is named");
  // A host run: vm/ is the panes' to write, and nothing in it reaches the verdict.
  await anchor(root, { isolation: "host" });
  await writeFile(join(root, "vm", "a1.json"), JSON.stringify({ agent: "INJECTED TEXT", installed_outside_image: { apt: { "rm -rf": "1" } } }));
  c = await takeCustody(root);
  assert.equal(c.vms, null);
  assert.match(c.summary, /VM RECORDS NOT READ: a vm\/ directory in a host run/);
  assert.doesNotMatch(c.summary, /INJECTED TEXT/);
});

test("a snapshot msb could not load is not a disk that failed msb's check", async () => {
  const root = await sandbox();
  await anchor(root, { isolation: "microvm" });
  await mkdir(join(root, "vm"), { recursive: true });
  await mkdir(`${root}.vm-snapshots`, { recursive: true });
  dirs.push(`${root}.vm-snapshots`);
  const snap = join(`${root}.vm-snapshots`, "a0.msb");
  await writeFile(snap, "disk bytes");
  await writeFile(join(root, "vm", "a0.json"), JSON.stringify({ agent: "a0", stopped_at: "t", snapshot: { path: snap, sha256: sha("disk bytes") } }));
  const bin = join(await mkdtemp(join(tmpdir(), "msb-stand-in-")), "msb");
  dirs.push(dirname(bin));
  await writeFile(bin, '#!/bin/sh\necho "error: no space left on device" >&2\nexit 1\n', { mode: 0o755 });
  const was = process.env.SWARM_MSB_BIN;
  process.env.SWARM_MSB_BIN = bin;
  let c: Custody;
  try {
    c = await takeCustody(root);
  } finally {
    if (was === undefined) delete process.env.SWARM_MSB_BIN;
    else process.env.SWARM_MSB_BIN = was;
  }
  const s = c.vms?.[0].snapshot as { verified: boolean; msb_verified: boolean | null; msb_note?: string };
  assert.equal(s.verified, true);
  assert.equal(s.msb_verified, null, "msb never checked it");
  assert.match(s.msb_note ?? "", /could not load the snapshot: error: no space left on device/);
  assert.doesNotMatch(c.summary, /FAILED MSB'S CHECK/);
  assert.match(c.summary, /1 not checked by msb \(a0: msb could not load the snapshot/);
  assert.deepEqual((await readdir(`${root}.vm-snapshots`)).filter((n) => n.startsWith(".verify-")), [], "the load directory is gone");
});

test("the verdict in the run is held to the one anchored outside it", async () => {
  const root = await sandbox();
  await anchor(root, {});
  assert.deepEqual(await verdictAnchorState(root), { state: "no verdict" });
  const c = await takeCustody(root);
  assert.deepEqual(await verdictAnchorState(root), { state: "matches", at: c.at });
  const text = await readFile(join(root, "custody.json"), "utf8");
  await writeFile(join(root, "custody.json"), text.replace(c.summary, "evidence unchanged (all fine)"));
  const edited = await verdictAnchorState(root);
  assert.equal(edited.state, "differs");
  assert.match(edited.state === "differs" ? edited.note : "", /changed after custody wrote it/);
});

test("a verdict written when custody is ended early names what it never reached", () => {
  const c = verdictOf(
    {
      phase: "the trace",
      run: "t1",
      inputsDone: true,
      inputs: { unverifiable: "x" },
      sessions: { files: [], digest: "d", not_files: [] },
    },
    "still running 120 s past its 60 s deadline, during the trace; ended",
  );
  assert.deepEqual(c.not_reached, ["the trace", "the kept outputs", "the ledger", "the VMs", "the artifact index"]);
  assert.match(c.summary, /NOT CHECKED BEFORE CUSTODY ENDED: the trace, the kept outputs, the ledger, the VMs, the artifact index/);
  assert.match(c.summary, /CUSTODY INCOMPLETE: still running/);
  assert.doesNotMatch(c.summary, /NO TRACE|kept outputs verified/, "a part never reached is not reported as empty");
});

test("the artifact index stops at the deadline and names what it did not hash", async () => {
  const root = await sandbox();
  await mkdir(join(root, "work"), { recursive: true });
  await writeFile(join(root, "work", "a.txt"), "a");
  const index = await hashArtifacts(root, { expiry: { over: true } });
  assert.deepEqual(index.files, []);
  assert.deepEqual(index.skipped, [{ path: "work/a.txt", reason: "not hashed: the deadline passed" }]);
});

test("operator actions from another shell are the operator's, not unverified lines; a removed VM whose database was not cleared is named", async () => {
  const root = await sandbox();
  await anchor(root, { isolation: "microvm" });
  await writeFile(
    join(root, "traces", "events.jsonl"),
    [
      { ts: "t", agent: "system", tool: "operator_action", args: { command: "stop" }, result: {}, agent_unverified: true },
      { ts: "t", agent: "a0", tool: "bash", args: {}, result: {}, agent_unverified: true },
    ].map((l) => JSON.stringify(l)).join("\n") + "\n",
  );
  await mkdir(join(root, "vm"), { recursive: true });
  await writeFile(join(root, "vm", "a0.json"), JSON.stringify({ agent: "a0", stopped_at: "t", msb_db: "busy" }));
  await writeFile(join(root, "vm", "a1.json"), JSON.stringify({ agent: "a1", stopped_at: "t", msb_db: "scrubbed" }));
  const c = await takeCustody(root);
  assert.equal(c.trace.unverified, 1);
  assert.equal(c.trace.operator_actions, 1);
  assert.equal(c.vms?.find((v) => v.agent === "a0")?.msb_db, "busy");
  assert.match(c.summary, /MSB'S DATABASE NOT CLEARED after removing a0 \(busy\): a secret's value may remain in msb's database/);
  assert.doesNotMatch(c.summary, /a1 \(scrubbed\)/);
});

test("the model gateway's log: its chain is checked, its hash anchored with the verdict, and one in a host run or behind a link is not read", async () => {
  const root = await sandbox();
  await anchor(root, { isolation: "microvm" });
  // No gateway: nothing about one in the verdict.
  let c = await takeCustody(root);
  assert.equal(c.model_gateway, null);
  assert.doesNotMatch(c.summary, /gateway/i);
  // The log as the gateway writes it: each line's prev the sha256 of the line before, the first null.
  const lines: string[] = [];
  let prev: string | null = null;
  for (const rec of [
    { at: "2026-09-24T00:00:01Z", seat: "a0", model: "gpt-5.4", status: 200, input: 10, output: 5, usd: 0.001 },
    { at: "2026-09-24T00:00:02Z", seat: "a1", refused: "seat_cap", status: 429 },
    { at: "2026-09-24T00:00:03Z", seat: "a0", model: "gpt-5.4", status: 200, input: 12, output: 7, usd: 0.0012 },
  ]) {
    const line = JSON.stringify({ ...rec, prev });
    lines.push(line);
    prev = sha(line);
  }
  const log = join(root, "traces", "model-gateway.jsonl");
  await writeFile(log, `${lines.join("\n")}\n`);
  c = await takeCustody(root);
  assert.deepEqual(c.model_gateway, { lines: 3, intact: true, detail: "3 lines, chain intact", sha256: sha(`${lines.join("\n")}\n`) });
  assert.match(c.summary, /model gateway log 3 lines, chain intact/);
  const anchored = JSON.parse(await readFile(custodyAnchorPath(root), "utf8")) as { custody: Array<{ model_gateway?: unknown }> };
  assert.deepEqual(anchored.custody.at(-1)?.model_gateway, { sha256: sha(`${lines.join("\n")}\n`), lines: 3, intact: true });
  // A line rewritten after it was chained: the next line no longer names it.
  await writeFile(log, `${[lines[0], lines[1].replace("seat_cap", "none"), lines[2]].join("\n")}\n`);
  c = await takeCustody(root);
  assert.equal(c.model_gateway?.intact, false);
  assert.match(c.summary, /MODEL GATEWAY LOG CHAIN BROKEN \(chain broken at line 3 \(prev does not name the line before it\)\)/);
  // A line deleted from the top: the first line names a line before it.
  await writeFile(log, `${lines.slice(1).join("\n")}\n`);
  assert.match((await takeCustody(root)).model_gateway?.detail ?? "", /chain broken at line 1 \(the first line names a line before it\)/);
  // A link in its place is not followed.
  const outside = await mkdtemp(join(tmpdir(), "gw-outside-"));
  dirs.push(outside);
  await writeFile(join(outside, "real.jsonl"), `${lines.join("\n")}\n`);
  await rm(log);
  await symlink(join(outside, "real.jsonl"), log);
  c = await takeCustody(root);
  assert.equal(c.model_gateway?.refused, "a link");
  assert.match(c.summary, /MODEL GATEWAY LOG NOT READ: it is a link/);
  // A host run runs no gateway: a file there is not the harness's.
  await rm(log);
  await writeFile(log, `${lines.join("\n")}\n`);
  await anchor(root, { isolation: "host" });
  c = await takeCustody(root);
  assert.equal(c.model_gateway?.refused, "in a host run");
  assert.equal(c.model_gateway?.intact, false);
  // Not reached before custody ended: named as such.
  const partial = verdictOf({ phase: "the ledger", sandbox: root, inputsDone: true, ledgerDone: true, vmsDone: true, artifactsDone: true }, "the deadline passed");
  assert.ok(partial.not_reached.includes("the model gateway log"));
});

test("a trace record that holds raw U+2028 and U+2029 verifies intact in custody, and a record edited to end in CRLF is reported edited", async () => {
  const root = await sandbox();
  const chain = (records: Array<Record<string, unknown>>): string[] => {
    const lines: string[] = [];
    let prev = "";
    for (const r of records) {
      const line = JSON.stringify({ ...r, prev });
      lines.push(line);
      prev = createHash("sha256").update(line).digest("hex");
    }
    return lines;
  };
  const lines = chain([
    { ts: "t", agent: "a0", tool: "bash", args: { text: "before after" }, result: { ok: true } },
    { ts: "t", agent: "a0", tool: "read", args: { text: "x y" }, result: { ok: true } },
    { ts: "t", agent: "a0", tool: "bash", args: {}, result: { ok: true } },
  ]);
  assert.ok(lines[0]!.includes(" ") && lines[1]!.includes(" "), "JSON.stringify writes both raw");
  await writeFile(join(root, "traces", "events.jsonl"), `${lines.join("\n")}\n`);
  const intact = await takeCustody(root);
  assert.equal(intact.trace.intact, true, intact.trace.detail);
  assert.equal(intact.trace.lines, 3, "three records, not five pieces");
  // The same records with the first line edited to end in CRLF: the CR is part of the record, so the chain breaks there.
  await writeFile(join(root, "traces", "events.jsonl"), `${lines[0]}\r\n${lines.slice(1).join("\n")}\n`);
  const edited = await takeCustody(root);
  assert.equal(edited.trace.intact, false, "an added CR is an edit");
});

// --- the access record in the verdict (PKG-ACC-01) ---------------------------------------------------------------

async function accessRun(extra: Extra = {}, edit?: (files: Record<string, string>) => void): Promise<string> {
  const base = await mkdtemp(join(tmpdir(), "custody-access-"));
  dirs.push(base);
  const files = fixtureFiles(extra);
  edit?.(files);
  return writeFiles(base, files);
}

const accessCheck = (c: Custody) => c.checks.find((x) => x.name === "sensitive access");
const READ_ROW = traceRow("agent-2", 1, "read", { path: "store/jobs/j000001/out/values.jsonl" }, T(10));
const READ_LINE = hubLine(T(10, 1), "agent-2", READ_HIT, { sid: "sid-agent-2", seq: 1, tool: "read" });

test("custody holds the access record to the trace: an agreeing record passes, and the summary ends with the fixed sentences", async () => {
  const S = await accessRun({ trace: [READ_ROW, READ_LINE] });
  const c = await takeCustody(S);
  assert.deepEqual([accessCheck(c)?.status, accessCheck(c)?.reason], ["passed", undefined]);
  assert.equal(c.access_record?.sensitive_jobs, 4);
  assert.ok(c.summary.endsWith(` ${SEAT_ROWS_SENTENCE} ${LOWER_BOUND_SENTENCE}`), "the summary ends with the two sentences, the lower bound last");
  assert.match(c.summary, /access to sensitive outputs: 4 sensitive jobs, every recorded line agrees/);
});

test("custody: a recorded line with no trace row behind it is a FAIL, a recorded way the scope manifest does not bear out is a FAIL", async () => {
  const orphan = await takeCustody(await accessRun({ trace: [READ_LINE] }));
  assert.equal(accessCheck(orphan)?.status, "failed");
  assert.match(accessCheck(orphan)?.reason ?? "", /1 recorded access line\(s\) point at a trace row that is not there/);
  assert.match(orphan.summary, /1 RECORDED ACCESS LINE WITH NO TRACE ROW BEHIND IT \(FAIL\)/);
  const bad = await takeCustody(await accessRun({ trace: [READ_ROW, READ_LINE] }, (f) => (f["run1/store/jobs/j000034/scope.1.json"] += " ")));
  assert.equal(accessCheck(bad)?.status, "failed");
  assert.match(accessCheck(bad)?.reason ?? "", /1 recorded way\(s\) .* disagree with the scope manifest of its job_started \(j000034: declared from j000001 \(manifest_unverified\)\)/);
  assert.match(bad.summary, /1 RECORDED WAY\(S\) NOT AGREEING WITH THE SCOPE MANIFEST OF THEIR JOB \(FAIL\)/);
  assert.ok(adverse(bad).some((x) => x.name === "sensitive access"));
});

test("custody: a seat row no line records and a row recorded twice are a WARN, never a FAIL; none at the burst limit", async () => {
  const missing = await takeCustody(await accessRun({ trace: [READ_ROW] }));
  assert.equal(accessCheck(missing)?.status, "passed", "a WARN does not fail the verdict");
  assert.match(accessCheck(missing)?.reason ?? "", /^WARN: 1 seat row\(s\) the rules read as an access have no line \(trace:L1\)$/);
  assert.match(missing.summary, /WARN: 1 seat row the rules read as an access with no line/);
  assert.ok(!adverse(missing).some((x) => x.name === "sensitive access"));
  const twice = await takeCustody(await accessRun({ trace: [READ_ROW, READ_LINE, { ...READ_LINE, ts: T(10, 2) }] }));
  assert.equal(accessCheck(twice)?.status, "passed");
  assert.match(accessCheck(twice)?.reason ?? "", /WARN: 1 line\(s\) repeat a row/);
  const burst = { ...hubLine(T(10, 2), "agent-2", READ_HIT, undefined), args: { rules: ACCESS_RULES, seat: "agent-2", via: "path", certainty: "path", on: { job: "j000001", part: "out" }, burst: { after: 200, note: "the rest are on the trace" } } };
  const limited = await takeCustody(await accessRun({ trace: [READ_ROW, burst] }));
  assert.deepEqual([accessCheck(limited)?.status, accessCheck(limited)?.reason], ["passed", undefined], "no false WARN at the burst limit");
});

test("custody: lines written under other rules are a note, never a FAIL", async () => {
  const c = await takeCustody(await accessRun({ trace: [READ_ROW, hubLine(T(10, 1), "agent-2", READ_HIT, { sid: "sid-agent-2", seq: 1, tool: "read" }, { rules: 0 })] }));
  assert.equal(accessCheck(c)?.status, "passed");
  assert.equal(accessCheck(c)?.reason, "note: the lines were written under rules 0; the lines and the rows are not compared");
});

test("custody: a run with no sensitive output, or no store, has nothing to hold: not applicable, and no access sentences in the summary", async () => {
  const none = await accessRun({}, (f) => {
    f["run1/store/journal.jsonl"] = jl({ v: 1, seq: 0, at: T(0), type: "job_accepted", job: "j000010", spec: { kind: "command" }, requester: { agent: "agent-2" } });
    f["run1/traces/events.jsonl"] = jl(READ_ROW);
  });
  const c = await takeCustody(none);
  assert.deepEqual([accessCheck(c)?.status, accessCheck(c)?.reason], ["not_applicable", "the run has no sensitive output"]);
  assert.ok(!c.summary.includes(LOWER_BOUND_SENTENCE));
  const noStore = await takeCustody(await accessRun({ skip: ["journal"] }));
  assert.equal(accessCheck(noStore)?.status, "not_applicable");
  assert.equal(noStore.access_record, null);
});

test("custody: the access check is charged to custody's own deadline, and a verdict ended before it names it as not reached", async () => {
  const S = await accessRun({ trace: [READ_ROW, READ_LINE] });
  const late = await takeCustody(S, { timeoutSec: 0 });
  assert.ok(late.incomplete, "the deadline had passed");
  assert.notEqual(accessCheck(late)?.status, "passed", "a check that did not run is never a pass");
  const ended = verdictOf({ phase: "the store", sandbox: S, storeDone: true }, "ended");
  assert.ok(ended.not_reached.includes("the access record"));
  assert.equal(ended.checks.find((x) => x.name === "sensitive access")?.status, "incomplete");
});
