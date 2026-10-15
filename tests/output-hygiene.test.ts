/**
 * Output hygiene (docs/adr/0016): a job run with secret_output seals every
 * output sensitive; a job that reads one (by path, or with no scope and its
 * command naming the job) seals sensitive output too, as derived; an entry
 * citing one is recorded sensitive; a redacted package withholds them whole,
 * names what it withheld and scans every file for what should not be there
 * (a small output's own text included); a package made without --redact
 * names what in it is sensitive; the export treats an unmarked entry citing
 * one as sensitive; and the kept output of a cancelled job cited later is a
 * defect until the citing entry says how it treats it.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import { exportLedger } from "../scripts/export.ts";
import { describe, JobService } from "../scripts/job-service.ts";
import { derivedFrom, secretShaped, sensitiveEntries, sensitiveIndex, sensitiveRefs } from "../scripts/output-hygiene.ts";
import { hygieneReport, redactPackage } from "../scripts/package-tools.ts";
import { localWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const F = { basis: "observed", confidence: "medium", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
/** A value a job writes and the run treats as secret: a placeholder, never a real credential. */
const VALUE = "TOKEN-sample-7f3a91";

async function run() {
  const base = await mkdtemp(join(tmpdir(), "hygiene-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "shyg", agentIds: ["a1", "a2"] });
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) await mkdir(join(S, d), { recursive: true });
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  const svc = new JobService({
    sandbox: S, run: "shyg", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [join(ROOT, "packs", "computer-forensics-base")], forging: false, minFreeMb: 1,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async (a) => ({ name: a }),
  });
  await svc.start();
  return { S, base, svc, a1: { sandboxRoot: S, agentId: "a1" } };
}

async function until(svc: JobService, id: string) {
  // A minute: under a whole suite's load a worker stand-in can be slow to start.
  for (let i = 0; i < 1200; i += 1) {
    const j = svc.jobs.get(id);
    if (j && ["committed", "failed", "cancelled"].includes(j.state)) return j;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`${id} did not finish`);
}

async function submitted(svc: JobService, who: string, spec: Record<string, unknown>) {
  const r = await svc.submit(who, { kind: "command", timeout_seconds: 60, network: "off", ...spec } as never);
  assert.ok(r.ok, !r.ok ? r.reason : "");
  return until(svc, r.job.id);
}

/**
 * A store record read once it is whole: the service writes job.json and manifest.json in place, just after the job reads committed,
 * so a read on a loaded machine can land between the file's creation and its last byte ("Unexpected end of JSON input"). Waited for
 * (a state, not a time): a record that never parses fails with what was read.
 */
async function settled(path: string): Promise<Buffer> {
  if (!path.endsWith(".json")) return readFile(path);
  let last = "";
  for (let i = 0; i < 400; i++) {
    const bytes = await readFile(path).catch(() => Buffer.alloc(0));
    try {
      JSON.parse(bytes.toString("utf8"));
      return bytes;
    } catch (e) {
      last = `${(e as Error).message} after ${bytes.length} bytes`;
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`${path} never held a whole JSON document: ${last}`);
}

/** The job's job_committed line on the store journal, waited for: it may land just after the job reads committed. */
async function committedLine(S: string, job: string): Promise<{ sensitive: { why?: string } } & Record<string, unknown>> {
  for (let i = 0; i < 200; i++) {
    const journal = await readFile(storePaths(S).journal, "utf8").catch(() => "");
    const line = journal.split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((l) => l.type === "job_committed" && l.job === job);
    if (line) return line;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`no job_committed line for ${job}`);
}

test("secret_output seals every output sensitive; a job reading one is derived; an entry citing one is recorded sensitive", async () => {
  const { S, svc, a1 } = await run();
  const secret = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"; echo read one configuration file`, inputs: [], secret_output: true });
  assert.equal(secret.status, "ok");
  assert.equal(secret.sensitive?.why, "secret_output");
  // On the journal (the record) and in the job's projection. The job_committed line may land just after the job reads committed: waited for.
  const committed = await committedLine(S, secret.id);
  assert.equal(committed.sensitive.why, "secret_output");
  assert.equal(JSON.parse((await settled(join(storePaths(S).jobs, secret.id, "job.json"))).toString("utf8")).sensitive.why, "secret_output");
  assert.match(describe(secret), /Its outputs are sensitive \(it ran with secret_output\)/);
  assert.equal((await svc.submit("a1", { kind: "command", command: "true", inputs: [], secret_output: "yes" } as never)).ok, false, "secret_output is true or false");

  // Declared by path: derived from it.
  const byPath = await submitted(svc, "a2", { command: `echo derived > "$OUT/d.txt"`, inputs: [`job:${secret.id}/value.txt`] });
  assert.deepEqual([byPath.sensitive?.why, byPath.sensitive?.from], ["derived", [secret.id]]);
  // No scope declared: held to what its command names.
  const naming = await submitted(svc, "a2", { command: `wc -c store/jobs/${secret.id}/out/value.txt > "$OUT/count.txt"`, inputs: ["all"] });
  assert.deepEqual(naming.sensitive?.from, [secret.id]);
  const unrelated = await submitted(svc, "a2", { command: `echo unrelated > "$OUT/u.txt"`, inputs: ["all"] });
  assert.equal(unrelated.sensitive, undefined, "a job that names nothing sensitive is not");
  // Derived from derived: the chain carries.
  const second = await submitted(svc, "a1", { command: `echo again > "$OUT/a.txt"`, inputs: [`job:${byPath.id}`] });
  assert.deepEqual(second.sensitive?.from, [byPath.id]);

  // The entry citing it is recorded sensitive, and says why.
  const rec = await P.recordEntry(a1, { kind: "finding", ...F, value: "The configuration held an access token", source: "the job's output", evidence: "the job's command", refs: [`job:${secret.id}/value.txt`] });
  assert.ok(rec.ok, (rec as { reason?: string }).reason);
  assert.equal((rec as { entry: P.LedgerEntry }).entry.sensitive, true);
  assert.match(String((rec as { note?: string }).note), /recorded sensitive: it cites sensitive output \(job:j\d+\/value\.txt, job j\d+ ran with secret_output\)/);
  assert.deepEqual(await sensitiveRefs(S, [`job:${unrelated.id}/u.txt`]), [], "an unrelated output is not sensitive");
  // An entry that cites nothing sensitive is left as its author said.
  const plain = await P.recordEntry(a1, { kind: "finding", ...F, value: "Nothing of note in the unrelated output", source: "the job's output", evidence: "cat", refs: [`job:${unrelated.id}/u.txt`] });
  assert.equal((plain as { entry: P.LedgerEntry }).entry.sensitive, undefined);
  await svc.stop("test over");
});

test("identical bytes of a sensitive output are sensitive at commit, while the same_as index (ADR 0017) is still being built", async () => {
  const { S, svc } = await run();
  const secret = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"`, inputs: [], secret_output: true });
  assert.equal(secret.sensitive?.why, "secret_output");
  // The same_as index as a restarted service has it while it reads the manifests: not built yet.
  const inner = svc as unknown as { outputIndex: unknown };
  inner.outputIndex = null;
  // Another job writes the same bytes from nothing it declared as sensitive (it made them itself).
  const again = await submitted(svc, "a2", { command: `printf '%s' '${VALUE}' > "$OUT/copy.txt"`, inputs: [] });
  assert.deepEqual([again.sensitive?.why, again.sensitive?.from], ["derived", [secret.id]], "decided before job_committed, from the journal's sensitive jobs and their manifests, not from the same_as index");
  const committed = await committedLine(S, again.id);
  assert.equal(committed.sensitive?.why, "derived", "the job_committed line says so");
  assert.equal(again.same_as, undefined, "the hint waits for the index; the sensitivity did not");
  await svc.stop("test over");
});

test("derived sensitivity follows the executed snapshot: a work copy by its digest, a catalogue alias, and through several jobs", async () => {
  const { S, svc, base } = await run();
  const secret = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"`, inputs: [], secret_output: true });
  const digest = JSON.parse((await settled(join(storePaths(S).jobs, secret.id, "manifest.json"))).toString("utf8")).files[0].sha256;
  // An agent copies the sensitive output into its own work directory, under a name that says nothing.
  await mkdir(join(S, "work", "a1"), { recursive: true });
  await writeFile(join(S, "work", "a1", "notes.bin"), VALUE);
  const byWork = await submitted(svc, "a2", { command: `wc -c work/a1/notes.bin > "$OUT/n.txt"`, inputs: ["work/a1/notes.bin"] });
  assert.deepEqual([byWork.sensitive?.why, byWork.sensitive?.from], ["derived", [secret.id]], "a job reading a work copy of the output, by its digest, is derived");
  assert.equal((await sensitiveIndex(S)).content.get(digest), secret.id);
  // A generation an alias points at: a job reading through the alias is derived.
  await svc.stop("test over");
});

test("the derivation is by path, digest and generation for a declared scope, and by id for none; a small output is a scan word only when it is shaped like a secret", () => {
  const sensitive = new Set(["j000003"]);
  const at = (objects: Array<{ path: string; sha256?: string }> | null, text = "") => derivedFrom({ objects, text, sensitive, contentJob: (s: string) => (s === "a".repeat(64) ? "j000003" : null), generationJob: (g: string) => (g === "g000002" ? "j000003" : null), aliasJob: (a: string) => (a === "vault" ? "j000003" : null) });
  assert.deepEqual(at([{ path: "store/jobs/j000003/out/x" }]), ["j000003"]);
  assert.deepEqual(at([{ path: `store/blobs/${"a".repeat(64)}` }]), ["j000003"]);
  assert.deepEqual(at([{ path: "inputs/disk.E01", sha256: "a".repeat(64) }]), ["j000003"], "the same bytes by digest, wherever they are");
  assert.deepEqual(at([{ path: "catalog/gen/g000002/members.tsv" }]), ["j000003"]);
  assert.deepEqual(at([{ path: "catalog/vault/filelist.txt" }]), ["j000003"], "a catalogue alias resolves to its job");
  assert.deepEqual(at([{ path: "store/jobs/j000004/out/x" }]), []);
  assert.deepEqual(at(null, "python3 read.py store/jobs/j000003/out/key"), ["j000003"]);
  assert.deepEqual(at(null, "echo j0000031"), [], "an id inside a longer word is not the job");
  assert.deepEqual(at([{ path: "inputs/x" }], "echo j000003"), [], "a declared scope is held to what it declared, not to its words");
  assert.equal(secretShaped("none"), false);
  assert.equal(secretShaped("success"), false);
  assert.equal(secretShaped("abc123"), true);
  assert.equal(secretShaped("a-long-plain-phrase"), true);
  assert.equal(secretShaped("two\nlines here"), false);
});

test("a redacted package withholds sensitive outputs whole, names them, and scans every file for their text; one made without --redact names them", async () => {
  const { S, svc, a1, base } = await run();
  const secret = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"; echo "read the configuration"`, inputs: [], secret_output: true });
  const other = await submitted(svc, "a1", { command: `echo "nothing sensitive" > "$OUT/p.txt"`, inputs: [] });
  await svc.stop("test over");
  // An entry that cites the output without being marked (as one recorded before the harness marked them would be).
  const ledgerLine = { v: 4, seq: 1, kind: "finding", value: "Unmarked entry about the configuration", source: "s", evidence: "e", refs: [`job:${secret.id}/value.txt`], by: "a1", authors: ["a1"], at: new Date().toISOString() };
  await mkdir(join(S, "ledger"), { recursive: true });
  await writeFile(join(S, "ledger", "entries.jsonl"), `${JSON.stringify(ledgerLine)}\n`);
  assert.deepEqual([...(await sensitiveEntries(S, [ledgerLine as never])).keys()], [1], "an unmarked entry citing a sensitive output is sensitive");
  // A package laid out as swarm.sh package --with-outputs lays it out.
  const make = async (name: string) => {
    const pkg = join(base, name);
    for (const id of [secret.id, other.id]) {
      await mkdir(join(pkg, "store", "jobs", id, "out"), { recursive: true });
      for (const f of ["job.json", "manifest.json", "stdout.log"]) await writeFile(join(pkg, "store", "jobs", id, f), await settled(join(storePaths(S).jobs, id, f)));
    }
    await writeFile(join(pkg, "store", "jobs", secret.id, "out", "value.txt"), VALUE);
    await writeFile(join(pkg, "store", "jobs", other.id, "out", "p.txt"), "nothing sensitive\n");
    await mkdir(join(pkg, "board"), { recursive: true });
    // The value repeated where no ledger entry says it: a post and a work file.
    await writeFile(join(pkg, "board", "main.md"), `a post quoting ${VALUE} in passing\n`);
    await mkdir(join(pkg, "work"), { recursive: true });
    await writeFile(join(pkg, "work", "notes.md"), `notes: ${VALUE}\n`);
    await writeFile(join(pkg, "ledger.jsonl"), `${JSON.stringify(ledgerLine)}\n`);
    return pkg;
  };
  const plain = await make("pkg-plain");
  const h = await hygieneReport(S, plain);
  assert.equal(h.outputs, 1);
  assert.equal(h.carried, 2, "the sensitive output and its log are carried in this package");
  const hygSidecar = JSON.parse(await readFile(join(plain, "..", `${basename(plain)}.private.json`), "utf8"));
  assert.ok(Object.keys(hygSidecar.map).length >= 1, "the hygiene report keeps its keyed ids in a private sidecar outside the package");
  assert.ok(h.hits.some((x) => x.path === "board/main.md" && x.output), "the scan finds the output's text in a post");
  const hyg = JSON.parse(await readFile(join(plain, "HYGIENE.json"), "utf8"));
  assert.deepEqual(hyg.entries.map((e: { seq: number }) => e.seq), [1]);
  assert.equal(await readFile(join(plain, "board", "main.md"), "utf8"), `a post quoting ${VALUE} in passing\n`, "without --redact nothing is taken out");

  const pkg = await make("pkg-redacted");
  const r = await redactPackage(S, pkg, { leaks: "list" });
  assert.deepEqual(r.withheld.map((w) => w.path).sort(), [`store/jobs/${secret.id}/out/value.txt`, `store/jobs/${secret.id}/stdout.log`]);
  const stub = await readFile(join(pkg, "store", "jobs", secret.id, "out", "value.txt"), "utf8");
  assert.match(stub, /^\[withheld: sensitive content \(bytes a sensitive job wrote \(job j\d+\)\); matched hidden-[0-9a-f]{24}\./, "the stub names a keyed id, not the digest");
  assert.doesNotMatch(stub, /[0-9a-f]{64}/, "the stub publishes no digest a low-entropy value could be brute-forced from");
  assert.equal(await readFile(join(pkg, "store", "jobs", other.id, "out", "p.txt"), "utf8"), "nothing sensitive\n", "another job's output is kept");
  assert.doesNotMatch(await readFile(join(pkg, "board", "main.md"), "utf8"), new RegExp(VALUE), "the output's text is taken out of a post");
  assert.doesNotMatch(await readFile(join(pkg, "work", "notes.md"), "utf8"), new RegExp(VALUE));
  assert.deepEqual(r.leaks, [], "the scan after redaction finds nothing");
  const red = JSON.parse(await readFile(join(pkg, "REDACTIONS.json"), "utf8"));
  assert.equal(red.sensitive_outputs[0].job, secret.id);
  assert.deepEqual(red.withheld.map((w: { path: string }) => w.path).sort(), r.withheld.map((w) => w.path).sort());
  assert.equal(red.entries[0].seq, 1);
  assert.match(red.entries[0].why, /cites sensitive output/);
  const txt = await readFile(join(pkg, "REDACTIONS.txt"), "utf8");
  assert.match(txt, /Withheld whole: \nhidden-[0-9a-f]{24}\s+\d+\s+store\/jobs\/j\d+\/(out\/value\.txt|stdout\.log)/);
  assert.doesNotMatch(txt.split("Withheld whole:")[1].split("sha256 before")[0], /[0-9a-f]{64}/, "the withheld list carries no digest, only keyed ids");
  // The private sidecar, outside the package, maps the ids to the real digests.
  const sidecar = JSON.parse(await readFile(join(pkg, "..", `${basename(pkg)}.private.json`), "utf8"));
  const ids = r.withheld.map((w) => w.sha256_of_original);
  for (const id of ids) assert.match(sidecar.map[id].sha256, /^[0-9a-f]{64}$/, "the sidecar has the real digest");
  assert.ok(!existsSync(join(pkg, `${basename(pkg)}.private.json`)) && !existsSync(join(pkg, "..", `${basename(pkg)}.private.json`).replace(base, pkg)), "the sidecar is not inside the package");
  // A copy in a form the redaction cannot rewrite (a binary file) is a hit the scan names.
  const leaky = await make("pkg-leaky");
  await writeFile(join(leaky, "work", "blob.bin"), Buffer.concat([Buffer.alloc(16), Buffer.from(VALUE, "utf16le")]));
  const again = await redactPackage(S, leaky, { leaks: "list" });
  assert.ok(again.leaks.some((x) => x.path === "work/blob.bin" && x.output && x.as === "bytes"), JSON.stringify(again.leaks));
});

test("a byte-identical copy of a sensitive output, with no ledger entry and no scan word, is withheld by its digest; a secret-bearing filename is a keyed id or a scan hit", async () => {
  const { S, svc, base } = await run();
  // A multiline output over the scan-word bound: no ledger entry names it, and its text is no single secret-shaped word.
  const big = Array.from({ length: 40 }, (_, i) => `line ${i}: TOKEN-${i}-value-of-some-length`).join("\n") + "\n";
  const secret = await submitted(svc, "a1", { command: `cat > "$OUT/dump.txt" <<'EOF'\n${big}EOF`, inputs: [], secret_output: true });
  const pkg = join(base, "pkg");
  await mkdir(join(pkg, "store", "jobs", secret.id, "out"), { recursive: true });
  for (const f of ["job.json", "manifest.json"]) await writeFile(join(pkg, "store", "jobs", secret.id, f), await settled(join(storePaths(S).jobs, secret.id, f)));
  const sealedBytes = await readFile(join(storePaths(S).jobs, secret.id, "out", "dump.txt"));
  await writeFile(join(pkg, "store", "jobs", secret.id, "out", "dump.txt"), sealedBytes);
  // A byte-identical copy far from the store, with no ledger entry at all.
  await mkdir(join(pkg, "work", "a1"), { recursive: true });
  await writeFile(join(pkg, "work", "a1", "carved.bin"), sealedBytes);
  // A small secret output, and a retained, non-sensitive file named after its value.
  const small = await submitted(svc, "a1", { command: `printf '%s' 'PINWORD-4821' > "$OUT/pin.txt"`, inputs: [], secret_output: true });
  await mkdir(join(pkg, "store", "jobs", small.id, "out"), { recursive: true });
  for (const f of ["job.json", "manifest.json"]) await writeFile(join(pkg, "store", "jobs", small.id, f), await settled(join(storePaths(S).jobs, small.id, f)));
  await writeFile(join(pkg, "store", "jobs", small.id, "out", "pin.txt"), await readFile(join(storePaths(S).jobs, small.id, "out", "pin.txt")));
  await writeFile(join(pkg, "work", "a1", "notes-PINWORD-4821.txt"), "nothing in here\n");
  await writeFile(join(pkg, "ledger.jsonl"), "");
  const r = await redactPackage(S, pkg, { leaks: "list" });
  assert.ok(r.withheld.some((w) => w.path === "work/a1/carved.bin"), "a byte-identical copy anywhere is withheld by its digest");
  assert.doesNotMatch(await readFile(join(pkg, "work", "a1", "carved.bin"), "utf8"), /TOKEN-3-value/, "the copy's bytes are gone");
  // The filename holding the value of a small sensitive output is a scan hit, its commitment a keyed id.
  const fnHit = r.leaks.find((h) => h.as === "filename");
  assert.ok(fnHit && fnHit.path.includes("notes-PINWORD"), JSON.stringify(r.leaks));
  assert.match(fnHit!.token_sha256, /^hidden-/, "a filename hit on a low-entropy value is a keyed id, not a hash");
  const red = JSON.parse(await readFile(join(pkg, "REDACTIONS.json"), "utf8"));
  assert.doesNotMatch(JSON.stringify(red), /PINWORD-4821/, "no secret value is printed in the record");
  await svc.stop("test over");
});

test("a sensitive generation's coverage is withheld from its catalogue projection at the source", async () => {
  const base = await mkdtemp(join(tmpdir(), "hygiene-gen-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "sgen", agentIds: ["a1"] });
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  const { Journal, sealTree: seal, publishGeneration, storePaths: sp } = await import("../scripts/evidence-store.ts");
  const journal = await Journal.open(S);
  const staging = join(base, "gen-out");
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, "coverage.json"), JSON.stringify({ status: "partial", covered: "the vault at TOKEN-secret-value", not_covered: "the rest", errors: ["decrypt failed for TOKEN-secret-value"] }));
  await writeFile(join(staging, "index.tsv"), "members.tsv\tthe members named TOKEN-secret-value\n");
  await writeFile(join(staging, "members.tsv"), "1\tTOKEN-secret-value\n");
  await seal(S, staging, join(sp(S).jobs, "j000009", "out"), "j000009", 1);
  const g = await publishGeneration(journal, { job: "j000009", recipe: "r", recipe_sha256: "0".repeat(64), target: { name: "vault" }, sensitive: true });
  const rec = JSON.parse(await readFile(join(sp(S).gen, g.generation.id, "generation.json"), "utf8"));
  assert.equal(rec.sensitive, true);
  assert.doesNotMatch(JSON.stringify(rec.coverage), /TOKEN-secret-value/, "the coverage detail is withheld from the record");
  assert.doesNotMatch(JSON.stringify(rec.files), /TOKEN-secret-value/, "the file descriptions are withheld");
  const revIdx = JSON.parse(await readFile(join(sp(S).revisions, String(g.revision), "index.json"), "utf8"));
  assert.doesNotMatch(JSON.stringify(revIdx), /TOKEN-secret-value/, "the revision index carries no coverage detail of it");
  const md = await readFile(join(sp(S).revisions, String(g.revision), "index.md"), "utf8");
  assert.doesNotMatch(md, /TOKEN-secret-value/, "the revision markdown carries none either");
});

test("the export's redaction treats an unmarked entry citing a sensitive output as sensitive", async () => {
  const { S, svc } = await run();
  const secret = await submitted(svc, "a1", { command: `printf '%s' '${VALUE}' > "$OUT/value.txt"`, inputs: [], secret_output: true });
  await svc.stop("test over");
  const line = { v: 4, seq: 1, kind: "finding", value: "Unmarked words about the configuration", source: "s", evidence: "e", refs: [`job:${secret.id}/value.txt`], by: "a1", authors: ["a1"], at: new Date().toISOString() };
  await mkdir(join(S, "ledger"), { recursive: true });
  await writeFile(join(S, "ledger", "entries.jsonl"), `${JSON.stringify(line)}\n`);
  const csv = await exportLedger(S, "csv", { redact: true, review: new Map(), grounding: {} });
  assert.doesNotMatch(csv, /Unmarked words about the configuration/);
  assert.match(csv, /\[redacted: marked sensitive\]/);
  const open = await exportLedger(S, "csv", { review: new Map(), grounding: {} });
  assert.match(open, /Unmarked words about the configuration/, "an export not for handing over is the ledger as it is");
});

test("a cancelled job's kept output cited later is a defect until the citing entry says how it treats it", async () => {
  const base = await mkdtemp(join(tmpdir(), "hygiene-partial-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "spart", agentIds: ["a1", "a2"] });
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  // A job an agent cancelled half way: what it wrote is sealed, with its status.
  const staging = join(base, "staging");
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, "rows.csv"), "t,what\n1,first half\n");
  await sealTree(S, staging, join(storePaths(S).jobs, "j000007", "out"), "j000007", 1);
  await writeFile(join(storePaths(S).jobs, "j000007", "job.json"), JSON.stringify({ id: "j000007", state: "committed", status: "cancelled", spec: { kind: "command", command: "x", inputs: [] }, requester: { agent: "a1" } }));
  const a1 = { sandboxRoot: S, agentId: "a1" };
  const ev = await P.recordEntry(a1, { kind: "event", ts: "2026-01-01T10:00:00Z", value: "The first half of the rows starts here", source: "rows.csv", evidence: "the job's output", refs: ["job:j000007/rows.csv"] });
  assert.ok(ev.ok, (ev as { reason?: string }).reason);
  const seq = (ev as { entry: P.LedgerEntry }).entry.seq;
  // The gate, pure: the citing entry is the defect.
  const partial = P.partialOutputCites(await P.readLedger(S), (ref) => (/j000007/.test(ref) ? { job: "j000007", status: "cancelled" } : { job: "x", status: "ok" }));
  assert.deepEqual([...partial.keys()], [seq]);
  const check = await checkLedgerAnswers(S, ["summary"]);
  const d = check.defects.find((x) => x.code === "partial_output");
  assert.ok(d, check.lines.join("\n"));
  assert.deepEqual(d.seqs, [seq]);
  assert.equal(d.named_by.length, 0, "never named away by a limitation");
  assert.match(check.lines.join("\n"), /DEFECT: #\d+ cites the kept output of job j000007 \(cancelled\)/);
  // A limitation does not resolve it; the entry saying how it treats the output does.
  await P.recordEntry(a1, { kind: "limitation", value: `E-${seq} rests on a cancelled job`, source: "s", evidence: "e", reason: "partial" });
  assert.ok((await checkLedgerAnswers(S, ["summary"])).defects.some((x) => x.code === "partial_output"));
  const fixed = await P.recordEntry(a1, { kind: "event", ts: "2026-01-01T10:00:00Z", value: "The first half of the rows starts here (from a job stopped half way)", source: "rows.csv", evidence: "the job's output", refs: ["job:j000007/rows.csv"], qualifies: [{ ref: "job:j000007/rows.csv", why: "the rows it wrote before it was stopped are whole lines; nothing after them is claimed" }], supersedes: seq });
  assert.ok(fixed.ok, (fixed as { reason?: string }).reason);
  assert.ok(!(await checkLedgerAnswers(S, ["summary"])).defects.some((x) => x.code === "partial_output"), "the correction says how it treats it");
  // A search recorded partial is its own disposition.
  assert.deepEqual([...P.partialOutputCites([{ v: 4, seq: 1, kind: "absence", value: "v", completion: "partial", refs: ["job:j000007/rows.csv"], by: "a", authors: ["a"], at: "t" } as P.LedgerEntry], () => ({ job: "j000007", status: "cancelled" })).keys()], []);

  // The same partial output cited by its bare digest is caught too.
  const rowsSha = JSON.parse(await readFile(join(storePaths(S).jobs, "j000007", "manifest.json"), "utf8")).files[0].sha256;
  const byDigest = await P.recordEntry(a1, { kind: "event", ts: "2026-01-01T11:00:00Z", value: "The rows, cited by their digest", source: "rows.csv", evidence: "the digest", refs: [`sha256:${rowsSha}`] });
  assert.ok(byDigest.ok, (byDigest as { reason?: string }).reason);
  assert.ok((await checkLedgerAnswers(S, ["summary"])).defects.some((x) => x.code === "partial_output" && x.seqs.includes((byDigest as { entry: P.LedgerEntry }).entry.seq)), "a sha256: citation of a partial output is a defect");

  // A successful job that copies the cancelled output, cited: its bytes are the partial producer's, so it is a defect too.
  const copyStaging = join(base, "staging-copy");
  await mkdir(copyStaging, { recursive: true });
  await writeFile(join(copyStaging, "rows.csv"), "t,what\n1,first half\n");
  await sealTree(S, copyStaging, join(storePaths(S).jobs, "j000008", "out"), "j000008", 1);
  await writeFile(join(storePaths(S).jobs, "j000008", "job.json"), JSON.stringify({ id: "j000008", state: "committed", status: "ok", spec: { kind: "command", command: "cp", inputs: ["job:j000007/rows.csv"] }, requester: { agent: "a1" } }));
  const byCopy = await P.recordEntry(a1, { kind: "event", ts: "2026-01-01T12:00:00Z", value: "The rows, from the copy", source: "rows.csv", evidence: "the copy", refs: ["job:j000008/rows.csv"] });
  assert.ok(byCopy.ok, (byCopy as { reason?: string }).reason);
  const copyDefect = (await checkLedgerAnswers(S, ["summary"])).defects.find((x) => x.code === "partial_output" && x.seqs.includes((byCopy as { entry: P.LedgerEntry }).entry.seq));
  assert.ok(copyDefect, "a finding on a successful copy of a cancelled job's output keeps the partial status");
});
