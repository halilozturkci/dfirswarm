/**
 * The shared withholding block reads a text of repeated `eyJ` in linear time, and no call of `scrub` or `token_spans` can run long
 * on a text a file chose. The JWT alternative of the block's prefixed-token expression was tried at every `eyJ` and ran to the end of
 * the run of name characters each time, so a text made of `eyJ` cost the square of its length: 63,000 characters took 1.5 s, a
 * docx whose external target was 1.8 million characters of it (2,324 bytes on disk) kept doc_probe busy past its manifest's 120 s,
 * and a 300 KB RTF object class took 37 s. The block now reads the JWT from the runs of name characters in one pass and withholds a
 * text over 64 KiB whole, by its length.
 *
 * Every input is built here from the shapes the rules name or from draws with a fixed seed. Each test fails on the code before.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { join } from "node:path";
import { DOC_PROBE, DOC_STRUCTURE, PE_DIRECTORIES, RE, body, buildZip, put, rels, tool, withCwd } from "./pack-re-harness.ts";
import { ROOT } from "./tool-library-harness.ts";

const PACKS = join(ROOT, "packs");
/** One tool of each family that carries the block (the copies are held byte-equal by the other suites). */
const FAMILIES: Record<string, string> = {
  network: join(PACKS, "network-forensics", "tools", "pcap_summary", "run.py"),
  base: join(PACKS, "computer-forensics-base", "tools", "sqlite_query", "run.py"),
  virtualization: join(PACKS, "virtualization-backup-forensics", "tools", "virtualization_inventory", "run.py"),
  memory: join(PACKS, "memory-forensics", "tools", "mem_fs", "run.py"),
  "encrypted-containers": join(PACKS, "encrypted-containers", "tools", "crypto_id", "run.py"),
  ransomware: join(PACKS, "ransomware-response", "tools", "ransom_note_scan", "run.py"),
  "reverse-engineering": DOC_PROBE,
  "tool-library": join(ROOT, "tool-library", "sqlite_query", "run.py"),
};
const CAPA_FLOSS = join(RE, "recipes", "capa-floss", "run.py");

const LOAD = [
  "import importlib.util, json, random, re, sys, time",
  "spec = importlib.util.spec_from_file_location('tool_under_test', sys.argv[1])",
  "m = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(m)",
].join("\n");

function py(path: string, code: string, argv: string[] = [], timeout = 120_000): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("python3", ["-I", "-c", `${LOAD}\n${code}`, path, ...argv], { encoding: "utf8", timeout, maxBuffer: 1 << 26, env: { ...process.env, AGENT_ID: "s1" } });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

test("scrub and token_spans read a text of 600,000 `eyJ` in under a second, in every family that carries the block; before, 63,000 characters took 1.5 s and this took half an hour", () => {
  for (const [family, path] of Object.entries(FAMILIES)) {
    const r = py(path, [
      "def took(fn, *a):",
      "    start = time.process_time()",
      "    out = fn(*a)",
      "    return out, time.process_time() - start",
      "whole = 'eyJ' * 600000",
      "gated, t1 = took(m.scrub, whole)",
      "url, t2 = took(m.redact_url, 'http://h/' + whole)",
      "spans, t3 = took(m.token_spans, whole)",
      // under the limit: the rules themselves, not the length gate, bound the time
      "under = 'eyJ' * (m.TEXT_LIMIT // 3)",
      "_, t4 = took(m.scrub, under)",
      "m.TEXT_LIMIT = 10 ** 9",
      "lifted, t5 = took(m.scrub, whole)",
      "print(json.dumps([gated, url, spans, [t1, t2, t3, t4, t5], lifted]))",
    ].join("\n"));
    assert.equal(r.status, 0, `${family}: ${r.stderr}`);
    const [gated, url, spans, times, lifted] = JSON.parse(r.stdout) as [string, string, number[][], number[], string];
    assert.equal(gated, "<over-long text withheld 1800000 characters>", family);
    assert.match(url, /^http:\/\/h\/?<over-long text withheld \d+ characters>$/, family);
    assert.deepEqual(spans, [[0, 1800000]], family);
    assert.equal(lifted, "<token-shaped text withheld 1800000 characters>", `${family}: with the length gate lifted the rules still read it whole`);
    times.forEach((t, i) => assert.ok(t < 1, `${family}: call ${i + 1} took ${t.toFixed(2)} s of CPU`));
  }
});

test("the prefixed secrets are found as the expression with the JWT alternative found them, 1,000 generated texts in each family (JWTs glued to other tokens, in the middle of a run, with padding, non-ASCII text and line breaks)", () => {
  const drive = [
    "OLD = re.compile(r'(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]*|(?i:basic|bearer)\\s+[A-Za-z0-9+/=._~-]{8,}')",
    "GLUED = re.compile(r'(?:%s)[A-Za-z0-9_+%%-]*' % OLD.pattern)",
    "TAIL = re.compile(r'[A-Za-z0-9_+%-]*')",
    "atoms = ['/', '=', '==', '\\n', '.', '..', ':', '@', '//', ' ', 'aB3d', 'Word', 'ghp_Ab3dEf5hIj7lMn9pQr1tUv3x', 'AKIAIOSFODNN7EXAMPLE', 'a9b2c7', '_', '-', '+', '%', 'é', '日本',",
    "         'eyJ', 'eyJ', 'eyJ', 'eyJhbGciOi', '.eyJzdWIiOiIxMjM0NTY3ODkw.', 'eyJhbGciOi.eyJzdWIiOi.sig', 'eyJhbGciOiJI.eyJzdWIiOiIx.SflKxwRJSMeKKF2QT4', 'eyJabcdefgh.abcdefg.zzzzzzzz',",
    "         'bearer abcdefgh123', 'Bearer eyJhbGciOiJI.eyJzdWIiOiIx.sig', 'basic ', 'sk-abcdefghijklmnopqrstuv', 'xoxb-1234567890-abc', 'github_pat_abcdefghijklmnopqrstuvwxyz', 'eyJ_', 'e.yJ']",
    "chars = 'aZ09/=_-\\n.eyJ+%é '",
    "rnd = random.Random(int(sys.argv[2]))",
    "bad = []",
    "for i in range(1000):",
    "    p = rnd.choice((0.3, 0.6, 0.9))",
    "    s = ''.join(rnd.choice(atoms) if rnd.random() < p else rnd.choice(chars) for _ in range(rnd.randint(0, 400 if i % 20 == 0 else 40)))",
    "    if [x.span() for x in OLD.finditer(s)] != m._prefixed_spans(s):",
    "        bad.append(s)",
    "    elif i % 3 == 0 and [x.span() for x in GLUED.finditer(s)] != m._prefixed_spans(s, TAIL):",
    "        bad.append(s)",
    "print(json.dumps(bad[:3]))",
  ].join("\n");
  Object.entries(FAMILIES).forEach(([family, path], i) => {
    const r = py(path, drive, [String(700 + i)]);
    assert.equal(r.status, 0, `${family}: ${r.stderr}`);
    assert.equal(r.stdout.trim(), "[]", family);
  });
});

test("a text over 64 KiB is withheld whole, by its length, and one of exactly 64 KiB is examined, in every family", () => {
  for (const [family, path] of Object.entries(FAMILIES)) {
    const r = py(path, "print(json.dumps([m.TEXT_LIMIT, m.scrub('x' * (m.TEXT_LIMIT + 1)), m.scrub('x' * m.TEXT_LIMIT) == 'x' * m.TEXT_LIMIT]))");
    assert.equal(r.status, 0, `${family}: ${r.stderr}`);
    const [limit, over, at] = JSON.parse(r.stdout) as [number, string, boolean];
    assert.equal(limit, 65536, family);
    assert.equal(over, "<over-long text withheld 65537 characters>", family);
    assert.ok(at, family);
  }
});

test("the reverse-engineering tools and the capa-floss recipe find a prefixed secret glued to its run in linear time, and as the expression did", () => {
  [DOC_STRUCTURE, PE_DIRECTORIES, CAPA_FLOSS].forEach((path, i) => {
    const r = py(path, [
      "start = time.process_time()",
      "spans = m._glued_spans('eyJ' * 600000)",
      "joined = m._glued_spans('eyJ' * 600000 + '.abcdefgh.sig')",
      "took = time.process_time() - start",
      "tail = m._glued_spans('Bearer eyJhbGciOiJI.eyJzdWIiOiIx.sig+x%y/z AKIAIOSFODNN7EXAMPLEabc_def')",
      "print(json.dumps([spans, took, tail, joined]))",
    ].join("\n"));
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    const [spans, took, tail, joined] = JSON.parse(r.stdout) as [number[][], number, number[][], number[][]];
    assert.deepEqual(spans, [], `${path}: no dot, no JWT`);
    assert.deepEqual(joined, [[0, 1800013]], path);
    assert.ok(took < 1, `${path} (${i}): ${took.toFixed(2)} s`);
    assert.deepEqual(tail, [[0, 40], [43, 70]], path);
  });
});

test("doc_probe: a .docx of 2,324 bytes whose external target is 1.8 million characters of `eyJ` is answered in seconds, the target given by its length; before, no answer past the manifest's 120 s", { timeout: 60_000 }, async () => {
  await withCwd(async (cwd) => {
    const target = "http://h/" + "eyJ".repeat(600_000);
    const ct = Buffer.from('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>');
    const zip = buildZip([{ name: "[Content_Types].xml", data: ct }, { name: "word/_rels/document.xml.rels", data: Buffer.from(rels([{ id: "rId1", type: "hyperlink", target, mode: "External" }])) }]);
    assert.ok(zip.length < 4096, `${zip.length} bytes on disk`);
    await put(cwd, "work/eyj.docx", zip);
    const started = Date.now();
    const r = await tool(DOC_PROBE, cwd, { path: "work/eyj.docx", max_seconds: 20 });
    const seconds = (Date.now() - started) / 1000;
    const a = body(r);
    assert.ok(seconds < 10, `${seconds.toFixed(1)} s`);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.external_targets[0].target_length, target.length);
    assert.doesNotMatch(r.stdout, /eyJeyJeyJ/);
  });
});

test("doc_probe: an RTF object class of 300 KB of `eyJ` is answered in seconds, partly by its length; before, 37 s", { timeout: 60_000 }, async () => {
  await withCwd(async (cwd) => {
    const rtf = `{\\rtf1\\ansi {\\object\\objemb{\\*\\objclass ${"eyJ".repeat(100_000)}}{\\*\\objdata 0105000002000000}}}`;
    await put(cwd, "work/eyj.rtf", rtf);
    const started = Date.now();
    const r = await tool(DOC_PROBE, cwd, { path: "work/eyj.rtf", max_seconds: 20 });
    const seconds = (Date.now() - started) / 1000;
    const a = body(r);
    assert.ok(seconds < 10, `${seconds.toFixed(1)} s`);
    assert.equal(a.container, "RTF");
    assert.doesNotMatch(r.stdout, /eyJeyJeyJ/);
  });
});

test("doc_probe: an external target of 21,000 `eyJ` (under the limit, so the rules read it) is withheld as token-shaped text in under 5 s", { timeout: 60_000 }, async () => {
  await withCwd(async (cwd) => {
    const target = "http://h/" + "eyJ".repeat(21_000);
    const ct = Buffer.from('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>');
    await put(cwd, "work/under.docx", buildZip([{ name: "[Content_Types].xml", data: ct }, { name: "word/_rels/document.xml.rels", data: Buffer.from(rels([{ id: "rId1", type: "hyperlink", target, mode: "External" }])) }]));
    const started = Date.now();
    const r = await tool(DOC_PROBE, cwd, { path: "work/under.docx" });
    assert.ok((Date.now() - started) / 1000 < 5);
    const a = body(r);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.match(r.stdout, /<token-shaped text withheld 63000 characters>/);
  });
});
