/**
 * What redaction replaced, and what it missed (scripts/package-tools.ts):
 * every change recorded with the sha256 of what it replaced, why and which
 * sensitive entry's words it held (REDACTIONS.json, under the manifest); a
 * JSON file redacted field by field, keeping its shape; a short value (a
 * PIN) taken out wherever it stands, a letter touching it included, and
 * its digits left only inside a longer number, a hash, a keyed id or an
 * encoded blob, by the redaction and the scan alike; an agent's dispute of
 * a sensitive entry redacted keeping its chain; a release's PDF withheld
 * and its signed record left as it was;
 * and a scan of every packaged file for each sensitive entry's words,
 * normalised (case, path separators, JSON escapes, UTF-16), which names a
 * hit by file, entry and the word's sha256, never the word.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { disputeEntry, initSandbox, recordEntry, readLedger } from "../extensions/protocol.ts";
import { leakScan, redactPackage, sensitiveTokens, verifyPackage, writeComponents } from "../scripts/package-tools.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const KEY = "5f3c9a17e2b84d06a1c7f9e3b2d58a40";
const PIN = "4821";
/** A record without its hashes and keyed ids: the PIN's four digits inside one are chance, not the PIN (package-tools.ts holds a short word to that rule). */
const withoutHex = (s: string) => s.replace(/[0-9a-fA-F]{16,}/g, "");
const PATH = "C:\\Users\\mira\\Documents\\vault.kdbx";

/** A run with a key, a PIN and a path marked sensitive, a dispute of one, and a package laid out as swarm.sh package lays it. */
async function run(): Promise<{ root: string; pkg: string }> {
  const root = await mkdtemp(join(tmpdir(), "redaction-"));
  dirs.push(root);
  await initSandbox(root, { reset: true, agentIds: ["a0", "a1"] });
  const a0 = { sandboxRoot: root, agentId: "a0" };
  await recordEntry(a0, { kind: "finding", value: "The laptop was imaged on 2024-04-05", source: "E01 header", evidence: "ewfinfo", basis: "observed", confidence: "high", indicates: "The acquisition is dated.", confidence_why: "The E01 header records it." });
  await recordEntry(a0, { kind: "ioc", value: `Vault key ${KEY}`, source: "memory", evidence: "strings over the dump", sensitive: true });
  await recordEntry(a0, { kind: "ioc", value: PIN, source: "sticky note photo", evidence: "IMG_0042", sensitive: true });
  await recordEntry(a0, { kind: "ioc", value: PATH, source: "MFT", evidence: "fls row 88", sensitive: true });
  const key = (await readLedger(root, { raw: true })).find((e) => e.value.includes(KEY));
  const d = await disputeEntry({ sandboxRoot: root, agentId: "a1" }, { seq: key?.seq, why: `the key ${KEY} is the backup's, not the vault's` });
  assert.equal(d.ok, true, JSON.stringify(d));
  const pkg = join(root, "package");
  for (const d2 of ["trace", "board", "work/a0", "store/jobs/j000001", "release/v1"]) await mkdir(join(pkg, d2), { recursive: true });
  await writeFile(join(pkg, "ledger.jsonl"), await readFile(join(root, "ledger", "entries.jsonl")));
  await writeFile(join(pkg, "ledger-disputes.jsonl"), await readFile(join(root, "ledger", "disputes.jsonl")));
  await writeFile(join(pkg, "board", "main.md"), `a0: the PIN is ${PIN}, the key ${KEY}\n`);
  await writeFile(join(pkg, "store", "jobs", "j000001", "job.json"), `${JSON.stringify({ id: "j000001", spec: { kind: "command", command: `keepass2john ${PATH}`, inputs: ["all"] }, status: "ok" }, null, 2)}\n`);
  await writeFile(join(pkg, "release", "v1", "report.pdf"), Buffer.concat([Buffer.from("%PDF-1.4\n"), Buffer.from([0, 1, 2]), Buffer.from(`stream ${KEY}`)]));
  await writeFile(join(pkg, "release", "v1", "report.html"), `<p>The key is ${KEY}.</p>\n`);
  await writeFile(join(pkg, "release", "v1", "release.json"), `${JSON.stringify({ kind: "dfirswarm-release", version: 1, adoption: { dispositions: [] } }, null, 2)}\n`);
  await writeFile(join(pkg, "custody.json"), JSON.stringify({ seal: {} }));
  writeComponents(root, pkg);
  return { root, pkg };
}

test("a sensitive entry's words: each text field whole, and each identifier-like run in it, with the entry it came from; a four-character PIN included", async () => {
  const { root } = await run();
  const t = sensitiveTokens(await readLedger(root, { raw: true }));
  const words = t.map((x) => x.token);
  assert.ok(words.includes(`Vault key ${KEY}`) && words.includes(KEY) && words.includes(PIN) && words.includes(PATH));
  assert.ok(!words.includes("strings over the dump") || t.find((x) => x.token === "strings over the dump")?.seq === 2, "a field of a sensitive entry is its words");
  assert.ok(!words.some((w) => w.includes("imaged on")), "an entry not marked sensitive gives none");
  assert.equal(t.find((x) => x.token === PIN)?.seq, 3);
});

test("every redaction is recorded with the sha256 of what it replaced, why, and which entry; a JSON file keeps its shape; a dispute keeps its chain; a PDF is withheld and a signed record left", async () => {
  const { root, pkg } = await run();
  // The signed record says what an examiner wrote: sealed as it is, so the scan must find it (listed, not refused).
  await writeFile(join(pkg, "release", "v1", "release.json"), `${JSON.stringify({ kind: "dfirswarm-release", version: 1, adoption: { dispositions: [{ note: `the PIN ${PIN} was confirmed` }] } }, null, 2)}\n`);
  const releaseBefore = await readFile(join(pkg, "release", "v1", "release.json"));
  const r = await redactPackage(root, pkg, { leaks: "list" });
  assert.equal(r.entries, 3);
  const rec = JSON.parse(await readFile(join(pkg, "REDACTIONS.json"), "utf8")) as { entries: Array<{ seq: number }>; changes: Array<{ path: string; before_sha256: string; after_sha256: string; replaced: Array<{ what: string; entry: number | null; sha256_of_original: string; pointer?: string; count?: number }> }>; leak_scan: { mode: string; hits: Array<{ path: string; entry: number; token_sha256: string }> } };
  assert.deepEqual(rec.entries.map((e) => e.seq), [2, 3, 4]);
  const byPath = new Map(rec.changes.map((c) => [c.path, c]));
  // The ledger: each sensitive entry's line, by the sha256 of the line it replaced.
  const ledgerChange = byPath.get("ledger.jsonl");
  assert.deepEqual(ledgerChange?.replaced.map((x) => [x.what, x.entry]), [["entry", 2], ["entry", 3], ["entry", 4]]);
  const originalLines = (await readFile(join(root, "ledger", "entries.jsonl"), "utf8")).split("\n").filter(Boolean);
  assert.equal(ledgerChange?.replaced[0].sha256_of_original, sha(originalLines[1]));
  // The dispute of the key: redacted, its chain kept, and verify walks it.
  assert.deepEqual(byPath.get("ledger-disputes.jsonl")?.replaced.map((x) => x.what), ["line"]);
  const disp = JSON.parse((await readFile(join(pkg, "ledger-disputes.jsonl"), "utf8")).trim()) as Record<string, unknown>;
  assert.equal(disp.redacted, true);
  assert.equal(disp.act, "dispute");
  assert.match(String(disp.hash), /^[0-9a-f]{64}$/);
  // A JSON file, field by field: the command replaced whole, the shape kept.
  const job = JSON.parse(await readFile(join(pkg, "store", "jobs", "j000001", "job.json"), "utf8")) as { spec: { command: string; kind: string } };
  assert.equal(job.spec.command, "[redacted: marked sensitive]");
  assert.equal(job.spec.kind, "command");
  const field = byPath.get("store/jobs/j000001/job.json")?.replaced[0];
  assert.deepEqual([field?.what, field?.pointer, field?.entry], ["field", "/spec/command", 4]);
  assert.match(String(field?.sha256_of_original), /^hidden-[0-9a-f]{24}$/, "a field's commitment is a keyed id, not a hash of a low-entropy value");
  // Text, word by word, each word recorded by its sha256 and how often.
  const board = byPath.get("board/main.md");
  assert.ok(board?.replaced.some((x) => x.what === "text" && /^hidden-[0-9a-f]{24}$/.test(x.sha256_of_original) && x.count === 1), "a low-entropy word's commitment is a keyed id");
  assert.doesNotMatch(await readFile(join(pkg, "board", "main.md"), "utf8"), new RegExp(`${PIN}|${KEY}`));
  // A release's PDF cannot be redacted word by word: withheld. Its signed record is left as it was, and the scan names what it holds.
  assert.match(await readFile(join(pkg, "release", "v1", "report.pdf"), "utf8"), /^\[withheld: sensitive content \(a release's PDF[^)]*\); matched hidden-[0-9a-f]{24}\./);
  assert.doesNotMatch(await readFile(join(pkg, "release", "v1", "report.html"), "utf8"), new RegExp(KEY));
  assert.deepEqual(await readFile(join(pkg, "release", "v1", "release.json")), releaseBefore);
  assert.equal(rec.leak_scan.mode, "list");
  assert.deepEqual(rec.leak_scan.hits.map((h) => [h.path, h.entry]), [["release/v1/release.json", 3]]);
  assert.match(rec.leak_scan.hits[0].token_sha256, /^hidden-[0-9a-f]{24}$/, "a scan hit on a low-entropy value is a keyed id, not its hash");
  assert.doesNotMatch(JSON.stringify(rec), new RegExp(`${KEY}|vault\\.kdbx`), "the record names keyed ids, never the words");
  assert.doesNotMatch(withoutHex(JSON.stringify(rec)), new RegExp(PIN), "the record names keyed ids, never the words");
  // The private sidecar, outside the package, carries the map and never a value.
  const side = JSON.parse(await readFile(join(pkg, "..", `${pkg.slice(pkg.lastIndexOf("/") + 1)}.private.json`), "utf8"));
  assert.ok(Object.keys(side.map).length >= 1);
  assert.doesNotMatch(JSON.stringify(side), new RegExp(KEY), "the sidecar maps ids to a description, not to the value");
  assert.doesNotMatch(withoutHex(JSON.stringify(side)), new RegExp(PIN), "the sidecar maps ids to a description, not to the value");
  // Verify: the chains walk, the lineage and the scan are said.
  const v = verifyPackage(pkg);
  assert.match(v.lines.join("\n"), /Disputes:     1 lines, chain intact, 1 redacted \(their hashes kept\)/);
  assert.match(v.lines.join("\n"), /the leak scan after it FOUND 1 HIT\(S\), LISTED: release\/v1\/release\.json \(entry 3\)/);
});

test("a short sensitive value is caught wherever it stands, a letter touching it included; its digits inside a longer number, a sha256, a keyed id or a base64 blob are not it", async () => {
  const { root, pkg } = await run();
  const hash = `9f0e${PIN}ab`.padEnd(64, "c");
  const id = `hidden-c${PIN}d7e4078e6518613b415`;
  const stamp = `2026-09-29T03:33:12.${PIN}45Z`;
  const blob = `YSBibG9iIG9m${PIN}IGVuY29kZWQgYnl0ZXM=`;
  const chance = `sha256 ${hash}\nid ${id}\nat ${stamp}\nbody ${blob}\n`;
  await writeFile(join(pkg, "work", "a0", "chance.md"), chance);
  await writeFile(join(pkg, "work", "a0", "row.json"), `${JSON.stringify({ sha256: hash, at: stamp, body: blob, note: `PIN${PIN}` })}\n`);
  // A path's run is long, but holds no digits of its own beyond the PIN: not an encoding.
  await writeFile(join(pkg, "work", "a0", "pin.md"), `pin=${PIN}\nPIN${PIN}\npin=${PIN}x\narchive/userfolders/Pin${PIN}/notes\n`);
  const r = await redactPackage(root, pkg, { leaks: "list" });
  // Redaction: left inside a longer run, taken out wherever else it stands.
  assert.equal(await readFile(join(pkg, "work", "a0", "chance.md"), "utf8"), chance);
  const row = JSON.parse(await readFile(join(pkg, "work", "a0", "row.json"), "utf8"));
  assert.deepEqual([row.sha256, row.at, row.body, row.note], [hash, stamp, blob, "[redacted: marked sensitive]"]);
  assert.equal(await readFile(join(pkg, "work", "a0", "pin.md"), "utf8"), "pin=[redacted: marked sensitive]\nPIN[redacted: marked sensitive]\npin=[redacted: marked sensitive]x\narchive/userfolders/Pin[redacted: marked sensitive]/notes\n");
  assert.deepEqual(r.leaks.filter((h) => h.path.startsWith("work/")), []);
  // The scan alone, as text, UTF-8 and UTF-16LE bytes, and file names.
  const tokens = sensitiveTokens(await readLedger(root, { raw: true }));
  const d = await mkdtemp(join(tmpdir(), "redaction-short-"));
  dirs.push(d);
  const utf16 = (t: string) => Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(t, "utf16le")]);
  await writeFile(join(d, "chance.txt"), chance);
  await writeFile(join(d, "chance16.bin"), utf16(chance));
  await writeFile(join(d, "chance8.bin"), Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from(chance)]));
  await writeFile(join(d, `${hash}.bin`), "nothing\n");
  assert.deepEqual(leakScan(d, tokens, { filenames: true }).hits, []);
  await writeFile(join(d, "glued.txt"), `PIN${PIN}\n`);
  await writeFile(join(d, "glued16.bin"), utf16(`PIN${PIN}\n`));
  await writeFile(join(d, "glued8.bin"), Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from(`PIN${PIN}\n`)]));
  await writeFile(join(d, `pin${PIN}.txt`), "nothing\n");
  const hits = leakScan(d, tokens, { filenames: true }).hits.map((h) => [h.path, h.entry, h.as]).sort((a, b) => String(a[0]).localeCompare(String(b[0])));
  assert.deepEqual(hits, [["glued.txt", 3, "text"], ["glued16.bin", 3, "bytes"], ["glued8.bin", 3, "bytes"], [`pin${PIN}.txt`, 3, "filename"]]);
});

test("the scan after redaction finds what word replacement cannot: UTF-16 text, another case, the other path separator, bytes in a binary", async () => {
  const { root, pkg } = await run();
  await writeFile(join(pkg, "work", "a0", "notes-utf16.txt"), Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`key: ${KEY}\n`, "utf16le")]));
  await writeFile(join(pkg, "work", "a0", "upper.md"), `KEY ${KEY.toUpperCase()}\n`);
  await writeFile(join(pkg, "work", "a0", "path.md"), `opened ${PATH.replace(/\\/g, "/")}\n`);
  await writeFile(join(pkg, "work", "a0", "blob.bin"), Buffer.concat([Buffer.from([0, 0, 1]), Buffer.from(KEY)]));
  const r = await redactPackage(root, pkg);
  const hit = (path: string) => r.leaks.find((h) => h.path === path);
  assert.equal(hit("work/a0/notes-utf16.txt")?.as, "bytes");
  assert.equal(hit("work/a0/upper.md")?.as, "text");
  assert.equal(hit("work/a0/path.md")?.entry, 4);
  assert.equal(hit("work/a0/blob.bin")?.as, "bytes");
  assert.equal(JSON.parse(await readFile(join(pkg, "REDACTIONS.json"), "utf8")).leak_scan.mode, "fail", "the default: a hit refuses the package (swarm.sh package exits on it)");
  // The scan alone, on a clean tree: nothing.
  const clean = await mkdtemp(join(tmpdir(), "redaction-clean-"));
  dirs.push(clean);
  await writeFile(join(clean, "a.txt"), "nothing sensitive\n");
  assert.deepEqual(leakScan(clean, sensitiveTokens(await readLedger(root, { raw: true }))).hits, []);
});

test("a file a recipe's coverage marks secret_bearing is withheld whole in a redacted package, its digest kept in the sidecar; an unmarked sibling stays; a count under the same key is no mark", async () => {
  const { root, pkg } = await run();
  const out = join(pkg, "store", "jobs", "j000002", "out");
  await mkdir(join(out, "sub"), { recursive: true });
  const rows = "1\t10.0.0.5\t/login?user=mira&token=Zq7kP2mR9xWd\n";
  await writeFile(join(out, "http.tsv"), rows);
  await writeFile(join(out, "dns.tsv"), "1\texample.org\n");
  await writeFile(join(out, "sub", "tls.tsv"), "1\tsubject\n");
  await writeFile(join(out, "outside.txt"), "not named by the mark\n");
  // the mark, by its shape: a name beside the JSON and a reason; an escaping name, an absolute one and a non-string reason are no marks
  await writeFile(join(out, "coverage.json"), JSON.stringify({ recipe: "any-recipe", secret_bearing: { "http.tsv": "URL query values", "sub/tls.tsv": "subject names", "../../../ledger.jsonl": "x", "/etc/hostname": "x", "dns.tsv": 3 } }));
  // an answer field that counts, under the same key, marks nothing
  await mkdir(join(pkg, "store", "jobs", "j000003", "out"), { recursive: true });
  await writeFile(join(pkg, "store", "jobs", "j000003", "out", "answer.json"), JSON.stringify({ secret_bearing: { passwords: 2, tokens: 1 } }));
  await writeFile(join(pkg, "store", "jobs", "j000003", "out", "passwords"), "kept\n");
  const r = await redactPackage(root, pkg, { leaks: "list" });
  assert.match(await readFile(join(out, "http.tsv"), "utf8"), /^\[withheld: sensitive content \(marked secret_bearing by store\/jobs\/j000002\/out\/coverage\.json: URL query values\); matched hidden-[0-9a-f]{24}\./);
  assert.match(await readFile(join(out, "sub", "tls.tsv"), "utf8"), /^\[withheld: sensitive content \(marked secret_bearing by [^)]*subject names\)/);
  assert.equal(await readFile(join(out, "dns.tsv"), "utf8"), "1\texample.org\n", "a sibling the mark gives a number for is not withheld");
  assert.equal(await readFile(join(out, "outside.txt"), "utf8"), "not named by the mark\n", "an unmarked sibling stays");
  assert.equal(await readFile(join(pkg, "store", "jobs", "j000003", "out", "passwords"), "utf8"), "kept\n", "a count under secret_bearing is an answer field, not a mark");
  assert.ok(r.withheld.some((w) => w.path.endsWith("http.tsv") && /secret_bearing/.test(w.why) && /^hidden-[0-9a-f]{24}$/.test(w.sha256_of_original) && w.bytes === rows.length));
  const rec = JSON.parse(await readFile(join(pkg, "REDACTIONS.json"), "utf8")) as { changes: Array<{ path: string; before_sha256: string }> };
  assert.equal(rec.changes.find((c) => c.path === "store/jobs/j000002/out/http.tsv")?.before_sha256, sha(rows), "the record keeps the sha256 of the withheld file");
  assert.doesNotMatch(JSON.stringify(rec), /Zq7kP2mR9xWd/, "and never its text");
  const side = JSON.parse(await readFile(join(pkg, "..", `${pkg.slice(pkg.lastIndexOf("/") + 1)}.private.json`), "utf8")) as { map: Record<string, { sha256?: string; path?: string }> };
  assert.ok(Object.values(side.map).some((m) => m.sha256 === sha(rows) && m.path === "store/jobs/j000002/out/http.tsv"), "the sidecar keeps the digest and the path of the withheld file");
});
