/**
 * ransomware-response: recovery_validate. A decryptor-output tree with good, corrupt, truncated, still-encrypted and wrong-key files; format
 * validators fed hostile structures (a zip bomb is not unpacked); a known-original hash list with a mismatch; provenance that looks like exit
 * zero beside bad output; the four verdict words and no other; the SQLite check on a copy; stop signals; identifier-shaped names. Data is
 * synthetic and made here from the formats' specifications.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { deflateRawSync } from "node:zlib";
import { buildZip } from "./pack-re-harness.ts";
import { withCwd } from "./tool-library-harness.ts";
import { PACK, exists, filesUnder, tool } from "./ransomware-pack-harness.ts";

const VALIDATE = join(PACK, "recovery_validate", "run.py");
const MANIFEST = join(PACK, "recovery_validate", "manifest.json");
const WORDS = ["matches_known_original", "structurally_valid", "unrecovered", "inconclusive"];

type Row = {
  file: string; status: string; reason?: string; bytes?: number; sha256?: string | null; sha256_withheld?: string; verdict: string; verdict_basis: string;
  format_check?: Record<string, unknown> & { structure_ok: boolean | null; format?: string };
  known_original?: { supplied: boolean; matches: boolean | null; source: string | null };
  ciphertext?: { size_equal?: boolean };
  unrecovered?: { equal_to_ciphertext_bytes: number; all_zero_bytes: number; bytes: number; ranges_total: number; ranges: Array<{ offset: number; length: number; kind: string }> };
};
type Answer = {
  status: string; status_basis: string; partial_reasons: string[]; verdicts: Record<string, number>; items: Row[]; coverage: Record<string, unknown>;
  decryptor_provenance: Record<string, unknown> | null; profile: { file: string; rows: number } | null; pages: { items: { matched: number; all_results?: string } };
  error?: string; interrupted?: boolean;
};

async function run(cwd: string, args: unknown, env: Record<string, string> = {}): Promise<{ answer: Answer; stdout: string; stderr: string }> {
  const out = await tool(VALIDATE, cwd, args, env);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return { answer: JSON.parse(out.stdout) as Answer, stdout: out.stdout, stderr: out.stderr };
}

const sha = (b: Buffer): string => createHash("sha256").update(b).digest("hex");
function plain(n: number): Buffer {
  const line = Buffer.from("The recovered quarterly report was reviewed and approved. ");
  return Buffer.concat(Array.from({ length: Math.ceil(n / line.length) }, () => line)).subarray(0, n);
}
async function put(cwd: string, dir: string, name: string, data: Buffer): Promise<string> {
  const path = join("work", dir, name);
  await mkdir(join(cwd, "work", dir), { recursive: true });
  await writeFile(join(cwd, path), data);
  return path;
}
const by = (a: Answer, name: string): Row => a.items.find((r) => r.file.endsWith(name))!;

test("a decryptor-output tree: good, corrupt, truncated, still-encrypted and wrong-key files each get the verdict the evidence supports", async () => {
  await withCwd(async (cwd) => {
    const good = buildZip([{ name: "word/document.xml", data: plain(20000) }]);
    const cipher = randomBytes(20000);
    await put(cwd, "rec", "good.docx", good);
    await put(cwd, "rec", "truncated.docx", good.subarray(0, good.length - 40));
    const corrupt = Buffer.from(good);
    corrupt.fill(0x41, good.length - 80, good.length - 30);       // the central directory is overwritten
    await put(cwd, "rec", "corrupt.docx", corrupt);
    await put(cwd, "rec", "still.docx", cipher);
    await put(cwd, "cip", "still.docx", cipher);
    await put(cwd, "rec", "wrongkey.docx", randomBytes(20000));
    await put(cwd, "rec", "note.txt", plain(30000));
    await put(cwd, "rec", "zeros.bin", Buffer.alloc(20000));
    const { answer } = await run(cwd, { recovered_root: "work/rec", ciphertext_root: "work/cip", provenance: { name: "a decryptor", exit_code: 0, obtained: true, verified: true } });
    assert.equal(answer.status, "complete", answer.status_basis);
    assert.equal(by(answer, "good.docx").verdict, "structurally_valid");
    assert.equal(by(answer, "note.txt").verdict, "structurally_valid");
    assert.equal(by(answer, "truncated.docx").verdict, "inconclusive");
    assert.equal(by(answer, "corrupt.docx").verdict, "inconclusive");
    assert.equal(by(answer, "wrongkey.docx").verdict, "inconclusive");
    assert.equal(by(answer, "still.docx").verdict, "unrecovered");
    assert.equal(by(answer, "zeros.bin").verdict, "unrecovered");
    assert.equal(by(answer, "still.docx").unrecovered!.equal_to_ciphertext_bytes, 20000);
    assert.deepEqual(answer.verdicts, { matches_known_original: 0, structurally_valid: 2, unrecovered: 2, inconclusive: 3 });
    // provenance that looks like success is recorded and moves nothing: the wrong-key output has exit_code 0 beside it
    assert.equal(answer.decryptor_provenance!.exit_code, 0);
    assert.match(String(answer.decryptor_provenance!.recorded), /not verified and not used for any verdict/);
    assert.doesNotMatch(JSON.stringify(answer.items), /"recovered"/);
  });
});

test("unrecovered ranges are exact, in whole granules, and the file is inconclusive, not valid, while any remain", async () => {
  await withCwd(async (cwd) => {
    const cipher = randomBytes(8192 * 6);
    const data = Buffer.from(randomBytes(8192 * 6));
    cipher.copy(data, 8192, 8192, 16384);        // granules 2..3 (of 4096) are still ciphertext
    data.fill(0, 8192 * 4, 8192 * 5);            // two zero granules after a gap
    await put(cwd, "rec", "part.bin", data);
    await put(cwd, "cip", "part.bin", cipher);
    const { answer } = await run(cwd, { items: [{ recovered: "work/rec/part.bin", ciphertext: "work/cip/part.bin" }] });
    const r = by(answer, "part.bin");
    assert.equal(r.verdict, "inconclusive");
    assert.deepEqual(r.unrecovered!.ranges.map((x) => [x.kind, x.offset, x.length]), [["equal_to_ciphertext", 8192, 8192], ["all_zero", 32768, 8192]]);
    assert.equal(r.unrecovered!.bytes, 16384);
    const rows = (await readFile(join(cwd, answer.profile!.file), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    assert.equal(rows.filter((x) => x.record === "unrecovered_range").length, 2);
    assert.equal(rows[rows.length - 1]!.record, "receipt");
  });
});

test("a known-original hash list: a match, a mismatch, and a list entry by name", async () => {
  await withCwd(async (cwd) => {
    const data = plain(5000);
    await put(cwd, "rec", "a.txt", data);
    await put(cwd, "rec", "b.txt", plain(6000));
    await writeFile(join(cwd, "known.sha256"), `${sha(data)}  a.txt\n${"0".repeat(64)} *b.txt\nnot a line\n`);
    const { answer } = await run(cwd, { recovered_root: "work/rec", known_originals: "known.sha256" });
    assert.equal(by(answer, "a.txt").verdict, "matches_known_original");
    assert.equal(by(answer, "a.txt").known_original!.source, "list");
    const b = by(answer, "b.txt");
    assert.equal(b.verdict, "inconclusive", "a known original was given and differs: a valid structure does not stand in for it");
    assert.match(b.verdict_basis, /hash differs/);
    const item = await run(cwd, { items: [{ recovered: "work/rec/a.txt", known_sha256: sha(data).toUpperCase() }, { recovered: "work/rec/a.txt", known_sha256: "1".repeat(64) }] });
    assert.deepEqual(item.answer.items.map((r) => r.verdict), ["matches_known_original", "inconclusive"]);
    const bad = await tool(VALIDATE, cwd, { items: [{ recovered: "work/rec/a.txt", known_sha256: "xyz" }] });
    assert.notEqual(bad.code, 0);
  });
});

test("a zip bomb is not unpacked: only the directory is read, its declared sizes are reported as claims, and the bounds hold", async () => {
  await withCwd(async (cwd) => {
    // 40 MiB of zeros deflated is about 40 KiB: a real bomb in miniature
    const zeros = Buffer.alloc(40 * 1024 * 1024);
    const bomb = buildZip([{ name: "zeros.bin", data: zeros, compressed: deflateRawSync(zeros) }]);
    assert.ok(bomb.length < 200000);
    await put(cwd, "rec", "bomb.zip", bomb);
    // a directory that claims more than 64 MiB: not walked
    const big = Buffer.from(buildZip([{ name: "a", data: plain(100) }]));
    const eocd = big.length - 22;
    big.writeUInt32LE(100 * 1024 * 1024, eocd + 12);
    await put(cwd, "rec", "bigdir.zip", big);
    // a directory entry whose lengths run past the directory
    const lies = Buffer.from(buildZip([{ name: "a", data: plain(100) }]));
    const cdAt = lies.length - 22 - 46 - 1;
    lies.writeUInt16LE(60000, cdAt + 28);
    await put(cwd, "rec", "lies.zip", lies);
    const began = Date.now();
    const { answer } = await run(cwd, { recovered_root: "work/rec" });
    assert.ok(Date.now() - began < 20000);
    const b = by(answer, "bomb.zip");
    assert.equal(b.format_check!.unpacked, false);
    assert.equal(b.format_check!.possible_zip_bomb, true);
    assert.equal(b.format_check!.declared_uncompressed_bytes, 40 * 1024 * 1024);
    assert.equal(b.format_check!.structure_ok, true, "the directory is valid; that is all that is said");
    assert.equal(by(answer, "bigdir.zip").format_check!.directory_error, "directory_larger_than_the_bound_or_the_file");
    assert.notEqual(by(answer, "lies.zip").verdict, "structurally_valid");
    assert.equal(answer.status, "complete");
  });
});

test("png, jpeg, pdf and sqlite: damaged ones are not valid, and the SQLite check runs on a copy that is gone afterwards, never on the input", async () => {
  await withCwd(async (cwd) => {
    const png = Buffer.concat([Buffer.from("89504e470d0a1a0a", "hex"), Buffer.from("0000000d", "hex"), Buffer.from("IHDR"), Buffer.alloc(13), Buffer.alloc(4), Buffer.from("0000000049454e44ae426082", "hex")]);
    const jpeg = Buffer.concat([Buffer.from("ffd8ffe000104a46494600010100000100010000", "hex"), Buffer.from("ffda000c03010002110311003f00", "hex"), randomBytes(50), Buffer.from("ffd9", "hex")]);
    const pdf = Buffer.from("%PDF-1.4\n1 0 obj\n<<>>\nendobj\nxref\n0 1\n0000000000 65535 f \ntrailer\n<<>>\nstartxref\n29\n%%EOF\n");
    await put(cwd, "rec", "ok.png", png);
    await put(cwd, "rec", "cut.png", png.subarray(0, png.length - 20));
    await put(cwd, "rec", "ok.jpg", jpeg);
    await put(cwd, "rec", "cut.jpg", jpeg.subarray(0, jpeg.length - 10));
    await put(cwd, "rec", "ok.pdf", pdf);
    await put(cwd, "rec", "cut.pdf", pdf.subarray(0, pdf.length - 10));
    // an SQLite database made by SQLite
    const made = spawnSync("python3", ["-c", "import sqlite3,sys\nd=sqlite3.connect(sys.argv[1])\nd.execute('create table t(a text)')\nd.executemany('insert into t values(?)',[('row %d'%i*30,) for i in range(2000)])\nd.commit()\nd.close()", join(cwd, "work", "rec", "ok.db")]);
    assert.equal(made.status, 0, made.stderr.toString());
    const db = await readFile(join(cwd, "work", "rec", "ok.db"));
    const damaged = Buffer.from(db);
    randomBytes(4096).copy(damaged, 4096 * 2);
    await put(cwd, "rec", "damaged.db", damaged);
    const before = await stat(join(cwd, "work", "rec", "ok.db"));
    const { answer } = await run(cwd, { recovered_root: "work/rec" });
    for (const n of ["ok.png", "ok.jpg", "ok.pdf", "ok.db"]) assert.equal(by(answer, n).verdict, "structurally_valid", n);
    for (const n of ["cut.png", "cut.jpg", "cut.pdf", "damaged.db"]) assert.notEqual(by(answer, n).verdict, "structurally_valid", n);
    assert.equal(by(answer, "ok.db").format_check!.integrity_check, "ok");
    assert.equal(by(answer, "damaged.db").format_check!.integrity_check, "failed");
    const after = await stat(join(cwd, "work", "rec", "ok.db"));
    assert.equal(after.mtimeMs, before.mtimeMs, "the input is untouched");
    assert.deepEqual((await readdir(join(cwd, "work", "rec"))).filter((n) => n.includes("journal") || n.includes("wal") || n.startsWith(".")), []);
    const left = Object.keys(await filesUnder(join(cwd, "work", "s1"))).filter((n) => n.split("/").pop()!.startsWith("."));
    assert.deepEqual(left, [], "the copy is gone");
    const off = await run(cwd, { items: ["work/rec/ok.db"], check_sqlite: false });
    assert.equal(off.answer.items[0]!.format_check!.integrity_check, "disabled");
  });
});

test("no verdict outside the four words can be printed, in the answer, the table or the profile, and the source holds the set", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "rec", "a.txt", plain(3000));
    await put(cwd, "rec", "b.bin", randomBytes(3000));
    await put(cwd, "rec", "c.zip", Buffer.alloc(100));
    const { answer, stdout } = await run(cwd, { recovered_root: "work/rec", items: ["work/rec/none.bin"] });
    const verdicts = new Set([...answer.items.map((r) => r.verdict), ...Object.keys(answer.verdicts)]);
    for (const v of verdicts) assert.ok(WORDS.includes(v), v);
    assert.deepEqual(Object.keys(answer.verdicts), WORDS);
    const all = await readFile(join(cwd, answer.pages.items.all_results ?? answer.profile!.file), "utf8");
    for (const m of (stdout + all).matchAll(/"verdict": "([^"]*)"/g)) assert.ok(WORDS.includes(m[1]!), m[1]);
    const source = await readFile(VALIDATE, "utf8");
    assert.match(source, /VERDICTS = \("matches_known_original", "structurally_valid", "unrecovered", "inconclusive"\)/);
    const decide = source.slice(source.indexOf("def decide("), source.indexOf("def walk_tree("));
    const literals = [...decide.matchAll(/return "([a-z_]+)", /g)].map((m) => m[1]!);
    assert.ok(literals.length >= 8);
    for (const w of literals) assert.ok(WORDS.includes(w), w);
    assert.doesNotMatch(stdout, /"verdict": "recovered"/);
  });
});

test("identifier-shaped names and plaintext bytes are on no channel, and the hash of a credential file is not printed", async () => {
  await withCwd(async (cwd) => {
    const dirId = "9F8E7D6C5B4A3210";
    const noteId = "7A6B5C4D3E2F1019";
    const marker = "UNIQUERECOVEREDMARKERQQ";
    await put(cwd, `rec/${dirId}`, "a.txt", Buffer.from(`${marker} ${"x".repeat(500)}`));
    await put(cwd, "rec", `README_${noteId}.txt`, Buffer.from(`${marker} note`));
    const key = Buffer.from("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1yc2EAAAADAQABAAABAQ\n-----END OPENSSH PRIVATE KEY-----\n");
    await put(cwd, "rec", "id_rsa", key);
    await put(cwd, "rec", "notes.txt", Buffer.from(`${key.toString()}`));
    const { answer, stdout, stderr } = await run(cwd, { recovered_root: "work/rec" });
    const files = await filesUnder(join(cwd, "work", "s1"));
    for (const text of [stdout, stderr, ...Object.values(files)]) {
      assert.ok(!text.includes(dirId) && !text.includes(noteId), "no identifier on any channel");
      assert.ok(!text.includes(marker), "no byte of a file");
      assert.ok(!text.includes(sha(key)), "the hash of a credential file is printed nowhere");
    }
    assert.equal(by(answer, "id_rsa").sha256, null);
    assert.match(by(answer, "id_rsa").sha256_withheld!, /credential file/);
    assert.equal(by(answer, "notes.txt").sha256, null, "a private-key header in the first bytes is enough");
    assert.match(by(answer, "a.txt").sha256!, /^[0-9a-f]{64}$/);
  });
});

test("a link, a named pipe and an unreadable path are inconclusive with a reason and the tool does not hang; the answer is partial", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "rec", "real.txt", plain(2000));
    spawnSync("ln", ["-s", join(cwd, "work", "rec", "real.txt"), join(cwd, "work", "rec", "link.txt")]);
    assert.equal(spawnSync("mkfifo", [join(cwd, "work", "rec", "pipe.txt")]).status, 0);
    const { answer } = await run(cwd, { recovered_root: "work/rec", items: ["work/rec/missing.txt", "work/rec/bad\u0000name"] });
    assert.equal(by(answer, "link.txt").reason, "link_not_followed");
    assert.equal(by(answer, "pipe.txt").reason, "not_a_regular_file");
    assert.equal(by(answer, "missing.txt").reason, "read_failed");
    assert.equal(answer.items.filter((r) => r.reason === "path_invalid").length, 1);
    assert.equal(answer.status, "partial");
    assert.ok(answer.items.filter((r) => r.status === "not_checked").every((r) => r.verdict === "inconclusive"));
  });
});

test("the read budget and the clock end a large file as partial, with the verdict inconclusive", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "rec", "big.bin", randomBytes(4 << 20));
    const { answer } = await run(cwd, { items: ["work/rec/big.bin"], read_budget_bytes: 1 << 20 });
    const r = answer.items[0]!;
    assert.equal(r.status, "partial");
    assert.equal(r.reason, "read_budget_spent");
    assert.equal(r.verdict, "inconclusive");
    assert.equal(r.sha256, null, "a hash of a part is not the file's hash");
    assert.equal(answer.status, "partial");
  });
});

const SLOW = String.raw`
import os, runpy, sys, time
_real = os.pread
def slow(fd, n, off):
    time.sleep(float(os.environ["SLOW_PREAD"]))
    return _real(fd, n, off)
os.pread = slow
script = sys.argv[1]
sys.argv = [script]
runpy.run_path(script, run_name="__main__")
`;

for (const [signal, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
  test(`${signal} while a file is being read: one JSON answer, exit code ${code}, no temporary file left`, async () => {
    await withCwd(async (cwd) => {
      await put(cwd, "rec", "big.bin", randomBytes(20 << 20));
      const child = spawn("python3", ["-c", SLOW, VALIDATE], { cwd, env: { ...process.env, AGENT_ID: "s1", SLOW_PREAD: "0.2" } });
      const out: Buffer[] = [];
      const err: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => out.push(c));
      child.stderr.on("data", (c: Buffer) => err.push(c));
      const closed = new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
      child.stdin.end(JSON.stringify({ items: ["work/rec/big.bin"] }));
      const place = join(cwd, "work", "s1", "tool-output");
      const deadline = Date.now() + 20000;
      while (!((await exists(place)) && (await readdir(place)).length > 0) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
      await new Promise((r) => setTimeout(r, 400));
      child.kill(signal);
      assert.equal(await closed, code, Buffer.concat(err).toString());
      const answer = JSON.parse(Buffer.concat(out).toString()) as Answer;
      assert.equal(answer.status, "failed");
      assert.equal(answer.interrupted, true);
      assert.deepEqual(await readdir(place), []);
    });
  });
}

test("hostile parameters give a JSON refusal and never a traceback", async () => {
  await withCwd(async (cwd) => {
    const deep = (n: number): string => "[".repeat(n) + "]".repeat(n);
    const cases: Array<[string, string]> = [
      ["not json", "{"], ["deep nesting", `{"items": ${deep(100000)}}`], ["a huge integer", `{"items": ["x"], "granule": ${"9".repeat(5000)}}`],
      ["wrong types", `{"items": "x"}`], ["numbers", `{"items": [1]}`], ["an array", `[]`], ["no input", `{}`], ["a granule past the bound", `{"items": ["x"], "granule": 2000000}`],
      ["ciphertext_root alone", `{"ciphertext_root": "x"}`], ["a provenance key", `{"items": ["x"], "provenance": {"password": "x"}}`],
      ["a long provenance value", `{"items": ["x"], "provenance": {"name": "${"a".repeat(600)}"}}`], ["an unknown item key", `{"items": [{"recovered": "x", "run": true}]}`],
    ];
    for (const [label, input] of cases) {
      const child = spawnSync("python3", [VALIDATE], { cwd, input, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" }, timeout: 60000 });
      assert.doesNotMatch(child.stderr, /Traceback/, label);
      const answer = JSON.parse(child.stdout) as { status: string };
      assert.equal(answer.status, "failed", `${label}: ${child.stdout}`);
      assert.equal(child.status, 1, label);
    }
  });
});

test("the manifest's claims hold, the tool runs nothing from the evidence, and the shared blocks are the survey's", async () => {
  const manifest = JSON.parse(await readFile(MANIFEST, "utf8")) as { timeout_seconds: number; description: string; params: Record<string, { description: string }>; example: string };
  const source = await readFile(VALIDATE, "utf8");
  const max = /DEFAULT_SECONDS, MAX_SECONDS = (\d+), (\d+)/.exec(source)!;
  assert.ok(Number(max[2]) <= manifest.timeout_seconds - 60);
  assert.match(manifest.params.max_seconds!.description, new RegExp(`default ${max[1]}, at most ${max[2]}`));
  assert.match(manifest.description, /The tool never says `recovered`/);
  for (const w of WORDS) assert.ok(manifest.description.includes(`\`${w}\``), w);
  for (const name of ["items", "recovered_root", "ciphertext_root", "known_originals", "provenance", "granule", "check_sqlite", "limit", "read_budget_bytes", "max_seconds"]) assert.ok(manifest.params[name], name);
  JSON.parse(manifest.example);
  // nothing from the evidence is run, imported, loaded or unpacked
  const code = source.replace(/"""[\s\S]*?"""/g, "").replace(/^\s*#.*$/gm, "");
  assert.doesNotMatch(code, /subprocess|os\.system|os\.exec|os\.spawn|zipfile|tarfile|importlib|__import__|pickle|marshal|\beval\(|\bexec\(/);
  assert.doesNotMatch(code, /start_new_session|setsid|process_group/);
  const survey = await readFile(join(PACK, "encrypted_survey", "run.py"), "utf8");
  const block = (text: string, name: string): string => new RegExp(`^# BEGIN SHARED ${name}\\n[\\s\\S]*?^# END SHARED ${name}$`, "m").exec(text)![0];
  for (const name of ["PLACE", "PAGE", "STOP", "WITHHOLDING", "NAMES", "BACKSTOP"]) assert.equal(block(source, name), block(survey, name), name);
  assert.equal(((await stat(VALIDATE)).mode & 0o111) !== 0, true);
  assert.match(manifest.description, /25 MB resident/);
  // the leaf that names the tool lists it, and so is no longer method only
  const leaf = await readFile(join(PACK, "..", "skills", "recovery", "routes-and-decryptors.md"), "utf8");
  assert.match(leaf, /^tools: \[file_carver, recovery_validate\]$/m);
  for (const w of WORDS) assert.ok(leaf.includes(`\`${w}\``), `the leaf names ${w}`);
  const pack = JSON.parse(await readFile(join(PACK, "..", "pack.json"), "utf8")) as { method_only: Array<{ path: string }>; tools: string[] };
  assert.ok(!pack.method_only.some((m) => m.path === "skills/recovery/routes-and-decryptors.md"));
  assert.ok(pack.tools.includes("recovery_validate"));
});
