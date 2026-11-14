/**
 * Every hash-chained register a run writes under its sandbox is sealed by
 * custody, bound in a release, packaged and verified (scripts/chained-
 * registers.ts keeps the list). A .jsonl name the harness uses that is in
 * neither of that module's lists fails here: a new chain is covered, or
 * said to be something else, with why.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CHAINED_REGISTERS, coveredNames, OTHER_JSONL, sealedOf, type ChainedRegister } from "../scripts/chained-registers.ts";
import { chainLines } from "./chain-lines.ts";
import { custodyAnchorPath, takeCustody, verifyCustody } from "../scripts/custody.ts";
import { PACKAGE_COMPONENTS, verifyPackage } from "../scripts/package-tools.ts";
import { packageLayout, runLayout } from "../scripts/release-record.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");

/** The first line's content changed with its own hash fields kept: a rewritten record. */
function rewriteFirst(lines: string[]): string[] {
  const o = JSON.parse(lines[0]!) as Record<string, unknown>;
  const k = ["note", "value", "how", "why", "tokens", "args", "state"].find((x) => x in o)!;
  o[k] = k === "tokens" ? 999 : k === "args" ? { n: 999 } : k === "state" ? "hits" : "rewritten";
  return [JSON.stringify(o), ...lines.slice(1)];
}

/** A run with two evidence files and a trace, custody's anchor beside it (tests/custody-seal.test.ts's shape). */
async function stoppedRun(): Promise<{ root: string; runs: string }> {
  const runs = await mkdtemp(join(tmpdir(), "chains-runs-"));
  dirs.push(runs);
  const root = join(runs, "s1");
  await mkdir(join(root, "inputs"), { recursive: true });
  await writeFile(join(root, "inputs", "disk.E01"), "disk bytes\n");
  await writeFile(join(root, "inputs.json"), JSON.stringify({ source: "/evidence", bytes: 11, held: "copy", files: [{ path: "inputs/disk.E01", bytes: 11, sha256: sha("disk bytes\n") }] }));
  await mkdir(join(root, "traces"), { recursive: true });
  await writeFile(join(root, "traces", "events.jsonl"), `${chainLines("trace", 1).join("\n")}\n`);
  // A microVM run: the model gateway's log is read only there.
  await mkdir(join(root, "vm"), { recursive: true });
  await writeFile(custodyAnchorPath(root), JSON.stringify({ run: "s1", started_at: "2026-09-29T10:00:00Z" }));
  return { root, runs };
}

const write = async (file: string, lines: string[]) => {
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, `${lines.join("\n")}\n`);
};

/** What the seal holds for a register: its length, and its head as the register's code says. */
function expectedSeal(r: ChainedRegister, lines: string[]): unknown {
  const last = lines.at(-1)!;
  switch (r.code) {
    case "trace":
      return { lines: lines.length, bytes: Buffer.byteLength(`${lines.join("\n")}\n`), last_line_sha256: sha(last) };
    case "gateway":
      return { lines: lines.length, sha256: sha(`${lines.join("\n")}\n`) };
    case "journal":
      return { lines: lines.length, head: sha(last) };
    case "ledger":
      return { entries: lines.length, head: (JSON.parse(last) as { hash: string }).hash };
    default:
      return { lines: lines.length, head: (JSON.parse(last) as { hash: string }).hash };
  }
}

test("every .jsonl name the harness uses is a chained register in the list, or said to be something else", () => {
  const files = spawnSync("git", ["ls-files", "extensions", "scripts"], { cwd: ROOT, encoding: "utf8" }).stdout.split("\n").filter((f) => /\.(ts|sh|mjs|py)$/.test(f));
  const covered = coveredNames();
  const unknown = new Map<string, string>();
  for (const f of files) {
    for (const m of readFileSync(join(ROOT, f), "utf8").matchAll(/[A-Za-z0-9_.-]*\.jsonl\b/g)) {
      if (!covered.has(m[0]) && !unknown.has(m[0])) unknown.set(m[0], f);
    }
  }
  assert.deepEqual(
    [...unknown].map(([name, f]) => `${name} (${f})`),
    [],
    "a .jsonl the harness names is in neither list of scripts/chained-registers.ts: a hash-chained register of the run goes into CHAINED_REGISTERS and is sealed, bound, packaged and verified; anything else goes into OTHER_JSONL, with why",
  );
  for (const [name, why] of Object.entries(OTHER_JSONL)) assert.ok(why.length > 20, `${name} says why it is not a register`);
});

test("custody seals every chained register by its length and head, and custody-verify names one rewritten", async () => {
  for (const r of CHAINED_REGISTERS) {
    const { root, runs } = await stoppedRun();
    const lines = r.code === "trace" ? chainLines("trace", 2) : chainLines(r.code, 2);
    await write(join(root, r.rel), lines);
    const c = await takeCustody(root, { runsDir: runs });
    assert.deepEqual(sealedOf(c.seal as unknown as Record<string, unknown>, r.seal), expectedSeal(r, lines), `${r.rel}: the verdict seals it at ${r.seal}`);
    const intact = await verifyCustody(root, { runsDir: runs });
    assert.deepEqual(intact.seal_drift, [], `${r.rel}: nothing drifted yet`);
    await write(join(root, r.rel), rewriteFirst(lines));
    const bad = await verifyCustody(root, { runsDir: runs });
    assert.equal(bad.ok, false, `${r.rel}: a rewritten line fails custody-verify`);
  }
});

test("an earlier seal still verifies as a prefix after the run went on, and not once a sealed line was rewritten", async () => {
  for (const r of CHAINED_REGISTERS.filter((x) => x.code !== "trace")) {
    const { root, runs } = await stoppedRun();
    const lines = chainLines(r.code, 2);
    await write(join(root, r.rel), lines);
    await takeCustody(root, { runsDir: runs });
    // The run resumed and went on: the register grew, and custody was taken again.
    const grown = chainLines(r.code, 1, lines);
    await write(join(root, r.rel), grown);
    await takeCustody(root, { runsDir: runs });
    const v = await verifyCustody(root, { runsDir: runs });
    assert.equal(v.earlier.length, 1);
    assert.equal(v.earlier[0].ok, true, `${r.rel}: ${v.earlier[0].broken.join("; ")}`);
    await write(join(root, r.rel), rewriteFirst(grown));
    const w = await verifyCustody(root, { runsDir: runs });
    assert.equal(w.earlier[0].ok && w.ok, false, `${r.rel}: a rewritten sealed line breaks the earlier seal or the current one`);
  }
});

test("every chained register is packaged and verified in the package against the seal", async () => {
  const swarm = readFileSync(join(ROOT, "scripts", "swarm.sh"), "utf8");
  for (const r of CHAINED_REGISTERS) {
    // The package names it (COMPONENTS.json), and swarm.sh copies it there.
    assert.ok(PACKAGE_COMPONENTS.some((c) => c.source === r.rel && c.path === r.package), `${r.rel} is a package component at ${r.package}`);
    const [dir, base] = [dirname(r.rel), r.rel.split("/").at(-1)!];
    const direct = swarm.includes(`pkg_copy "$sandbox/${r.rel}" "$out/${r.package}"`);
    const looped = new RegExp(`for f in [^;]*\\b${base.replace(/\./g, "\\.")}\\b[^;]*; do pkg_copy "\\$sandbox/${dir}/\\$f" "\\$out/${dirname(r.package)}/\\$f"`).test(swarm);
    assert.ok(direct || looped, `swarm.sh package copies ${r.rel} to ${r.package}`);
    // verifyPackage holds it to the verdict's seal, and names one rewritten.
    const { root, runs } = await stoppedRun();
    const lines = r.code === "trace" ? chainLines("trace", 2) : chainLines(r.code, 2);
    await write(join(root, r.rel), lines);
    await takeCustody(root, { runsDir: runs });
    const pkg = await mkdtemp(join(tmpdir(), "chains-pkg-"));
    dirs.push(pkg);
    await cp(join(root, "custody.json"), join(pkg, "custody.json"));
    await write(join(pkg, r.package), lines);
    const bad = /BROKEN|NOT THE|HEAD NOT|NOT AS SEALED/;
    const good = verifyPackage(pkg);
    assert.ok(!good.lines.some((l) => bad.test(l)), `${r.package} as sealed: ${good.lines.join("\n")}`);
    await write(join(pkg, r.package), rewriteFirst(lines));
    const rewritten = verifyPackage(pkg);
    assert.equal(rewritten.ok, false, `${r.package} rewritten fails the package's verify`);
    assert.ok(rewritten.lines.some((l) => bad.test(l)), `${r.package} rewritten is named: ${rewritten.lines.join("\n")}`);
  }
});

test("every chained register is bound by a release: in its own chains, or through the verdict it binds", () => {
  const run = runLayout("/run", null, null) as unknown as Record<string, unknown>;
  const pkg = packageLayout("/nonexistent-package") as unknown as Record<string, unknown>;
  for (const r of CHAINED_REGISTERS) {
    assert.equal(run[r.layout], r.rel, `the release's run layout names ${r.rel}`);
    assert.equal(pkg[r.layout], r.package, `the release's package layout names ${r.package}`);
  }
  const src = readFileSync(join(ROOT, "scripts", "release-record.ts"), "utf8");
  for (const r of CHAINED_REGISTERS.filter((x) => x.release === "verdict")) assert.ok(src.includes(`layout.${r.layout}`), `verifyReleases holds ${r.rel} to the verdict it binds`);
  for (const r of CHAINED_REGISTERS.filter((x) => x.release === "chains")) assert.match(src, new RegExp(`\\b${r.layout}\\??: `), `a release's chains name ${r.rel}`);
});

test("a release binds the store sweeps in its chains, and the finish register and the model gateway's log through the verdict: rewritten, each is named; grown after a resume, each is a prefix", async () => {
  const { stoppedRun: releaseRun, cleanUp } = await import("./release-fixture.ts");
  const { draftRelease, runContext } = await import("../scripts/release.ts");
  const { verifyReleases } = await import("../scripts/release-record.ts");
  const { anchorResume } = await import("../scripts/custody.ts");
  after(cleanUp);
  const sweeps = chainLines("sweep", 2);
  const finish = chainLines("lead", 2);
  const gateway = chainLines("gateway", 2);
  const r = await releaseRun({
    before: async (root) => {
      await write(join(root, "ledger", "sweeps.jsonl"), sweeps);
      await write(join(root, "leads", "finish.jsonl"), finish);
      await write(join(root, "traces", "model-gateway.jsonl"), gateway);
      await mkdir(join(root, "vm"), { recursive: true });
    },
  });
  const ctx = runContext(r.root, { run: r.id, runsDir: r.runs });
  const made = await draftRelease(ctx, { home: r.home, say: () => undefined });
  assert.ok(made.written);
  const record = JSON.parse(await readFile(join(r.root, "release", "v0", "release.json"), "utf8")) as { chains: { sweeps?: { lines: number; head: string } } };
  assert.deepEqual(record.chains.sweeps, { lines: 2, head: (JSON.parse(sweeps[1]!) as { hash: string }).hash }, "the release binds the sweeps in its own chains");
  const layout = runLayout(r.root, null, custodyAnchorPath(r.root));
  const ok = await verifyReleases(layout);
  assert.equal(ok.ok, true, ok.lines.join("\n"));
  // Rewritten: named.
  for (const [rel, lines, what] of [["ledger/sweeps.jsonl", sweeps, /the store sweeps/], ["leads/finish.jsonl", finish, /the finish register/], ["traces/model-gateway.jsonl", gateway, /the model gateway log/]] as const) {
    await write(join(r.root, rel), rewriteFirst([...lines]));
    const bad = await verifyReleases(layout);
    assert.equal(bad.ok, false, `${rel} rewritten`);
    assert.match(bad.lines.join("\n"), what);
    await write(join(r.root, rel), [...lines]);
  }
  // The run resumed after the release and went on: each register grew; what the release binds is a prefix.
  const entries = (await readFile(join(r.root, "ledger", "entries.jsonl"), "utf8")).trim().split("\n");
  const head = (l: string) => (JSON.parse(l) as { hash: string }).hash;
  anchorResume(r.root, { at: new Date(Date.now() + 60_000).toISOString(), by: "operator", segment: 1, heads: { ledger: { lines: entries.length, head: head(entries.at(-1)!) }, sweeps: { lines: 2, head: head(sweeps[1]!) } } });
  await write(join(r.root, "ledger", "sweeps.jsonl"), chainLines("sweep", 1, [...sweeps]));
  await write(join(r.root, "leads", "finish.jsonl"), chainLines("lead", 1, [...finish]));
  await write(join(r.root, "traces", "model-gateway.jsonl"), chainLines("gateway", 1, [...gateway]));
  const grown = await verifyReleases(layout);
  assert.equal(grown.ok, true, grown.lines.join("\n"));
  assert.match(grown.lines.join("\n"), /the store sweeps it binds is a prefix of the store sweeps here \(2 of 3\)/);
  assert.match(grown.lines.join("\n"), /the finish register it binds \(2 events\) is a prefix of the finish register here \(3\)/);
  assert.match(grown.lines.join("\n"), /the model gateway log it binds \(2 lines\) is a prefix of the log here \(3\)/);
});

test("--redact treats a sweep's looked_for strings and hits like other sensitive text: the sweep of a sensitive coverage record, and one that says a sensitive entry's words, keep only what chains them", async () => {
  const SW = await import("../extensions/store-sweep.ts");
  const { redactPackage } = await import("../scripts/package-tools.ts");
  const { coverage, rec, run } = await import("./negative-bar-fixture.ts");
  const { S, a0 } = await run();
  const SECRET = "Vault-Key-7731-XQ";
  // A sensitive entry whose words the second sweep repeats, and a sensitive coverage record whose strings are the secret itself.
  const ioc = await rec(a0, { kind: "ioc", value: `the vault key ${SECRET}`, source: "notes", evidence: "row 11", sensitive: true });
  assert.ok(ioc.ok, (ioc as { reason?: string }).reason);
  const abs = await rec(a0, { kind: "absence", value: "a key", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] });
  assert.ok(abs.ok);
  const seqAbs = (abs as { entry: { seq: number } }).entry.seq;
  const sensitiveCov = await rec(a0, { ...coverage("2", ["input:disk.E01"], [`E-${seqAbs}`], { looked_for: ["Other-Secret-5521"] }), sensitive: true });
  assert.ok(sensitiveCov.ok, (sensitiveCov as { reason?: string }).reason);
  const plainCov = await rec(a0, coverage("2", ["input:logs/a.log"], [`E-${seqAbs}`], { looked_for: [SECRET] }));
  assert.ok(plainCov.ok, (plainCov as { reason?: string }).reason);
  await SW.awaitSweeps(S);
  const sweepsText = await readFile(join(S, SW.LEDGER_SWEEPS), "utf8");
  assert.equal(sweepsText.trim().split("\n").length, 2);
  // The package: the ledger and the sweeps as swarm.sh copies them.
  const pkg = await mkdtemp(join(tmpdir(), "chains-redact-"));
  dirs.push(pkg);
  await cp(join(S, "ledger", "entries.jsonl"), join(pkg, "ledger.jsonl"));
  await cp(join(S, SW.LEDGER_SWEEPS), join(pkg, "ledger-sweeps.jsonl"));
  const r = await redactPackage(S, pkg, { leaks: "list" });
  assert.deepEqual(r.leaks, [], "nothing of either secret is left");
  const after_ = await readFile(join(pkg, "ledger-sweeps.jsonl"), "utf8");
  for (const s of [SECRET, "Other-Secret-5521"]) assert.doesNotMatch(after_, new RegExp(s), `the sweeps hold no ${s}`);
  const lines = after_.trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
  assert.deepEqual(lines.map((l) => l.redacted), [true, true]);
  assert.deepEqual(Object.keys(lines[0]!).sort(), ["hash", "line_sha256", "prev", "redacted", "seq", "state", "target", "v"]);
  const v = verifyPackage(pkg);
  assert.match(v.lines.join("\n"), /Sweeps:       2 lines, chain intact, 2 redacted \(their hashes kept\)/);
});
