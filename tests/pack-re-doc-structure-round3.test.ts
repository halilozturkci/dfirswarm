/**
 * doc_structure, the findings of the third review, each case named after its finding: direct PDF actions known by their place (never
 * by a Python object's identity), the parser's memory held to a budget of what it keeps, duplicate names in a compound file's storage,
 * the scan-mode trailer search with a budget of its own, and the smaller items. Every file is written here from the format's own rules
 * (ISO 32000-1 objects, cross-reference tables, object streams and the Flate filter; [MS-CFB] directory entries and their name rule;
 * [MS-OVBA] dir streams; the PKWARE APPNOTE local and central headers), never from the tool's output.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { deflateSync } from "node:zlib";
import { test } from "node:test";
import { DOC_STRUCTURE, body, buildZip, put, tool, u16, withCwd } from "./pack-re-harness.ts";
import type { Json, Run } from "./pack-re-harness.ts";
import { buildCfb, buildPdf, ovbaCompress, vbaDirStream } from "./pack-re-doc-fixtures.ts";
import type { PdfObj } from "./pack-re-doc-fixtures.ts";

/** The tool with a hard wall limit and the child's peak RSS (and, with `rlimitMb`, an address-space limit it cannot pass). */
export function bounded(cwd: string, args: Record<string, unknown>, killAfterMs: number, rlimitMb = 0): { run: Run; seconds: number; rssMb: number } {
  const wrapper = [
    "import json, resource, subprocess, sys, time",
    "limit = int(sys.argv[3])",
    "def pre():",
    "    if limit:",
    "        resource.setrlimit(resource.RLIMIT_AS, (limit << 20, limit << 20))",
    "t = time.monotonic()",
    "try:",
    "    p = subprocess.run([sys.executable, sys.argv[1]], input=sys.stdin.buffer.read(), capture_output=True, timeout=float(sys.argv[2]), preexec_fn=pre if limit and sys.platform != 'darwin' else None)",
    "    code, out, err = p.returncode, p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace')",
    "except subprocess.TimeoutExpired as exc:",
    "    code, out, err = None, (exc.stdout or b'').decode('utf-8', 'replace'), 'killed at the case limit'",
    "r = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss",
    "print(json.dumps({'code': code, 'stdout': out, 'stderr': err, 'seconds': time.monotonic() - t, 'rss_mb': r / (1 << 20) if sys.platform == 'darwin' else r / 1024}))",
  ].join("\n");
  const r = spawnSync("python3", ["-c", wrapper, DOC_STRUCTURE, String(killAfterMs / 1000), String(rlimitMb)], { cwd, input: JSON.stringify(args), encoding: "utf8", maxBuffer: 1 << 28, env: { ...process.env, AGENT_ID: "s1" } });
  assert.equal(r.status, 0, r.stderr);
  const o = JSON.parse(r.stdout);
  return { run: { code: o.code, stdout: o.stdout, stderr: o.stderr }, seconds: o.seconds, rssMb: o.rss_mb };
}

// --- P1-2: direct actions are known by their place ------------------------------------------------------------------------------

/** 200 pages, each with 20 Link annotations of their own, each with its own direct URI action: 4,202 objects, past the object cache. */
function linkHeavy(pages = 200, perPage = 20): Buffer {
  const objs: PdfObj[] = [{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>" }];
  const kids: string[] = [];
  let num = 3;
  for (let p = 0; p < pages; p++) {
    const page = num++;
    kids.push(`${page} 0 R`);
    const annots: string[] = [];
    for (let a = 0; a < perPage; a++) {
      const an = num++;
      annots.push(`${an} 0 R`);
      objs.push({ num: an, body: `<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /URI /URI (http://h.example/p${p}/a${a}) >> >>` });
    }
    objs.push({ num: page, body: `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Annots [ ${annots.join(" ")} ] >>` });
  }
  objs.push({ num: 2, body: `<< /Type /Pages /Kids [ ${kids.join(" ")} ] /Count ${pages} >>` });
  return buildPdf(objs.sort((x, y) => x.num - y.num), "/Root 1 0 R").file;
}

test("P1-2 4,000 Link annotations each with its own direct action, past the object cache: 4,000 actions, complete, the same on five runs", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/links.pdf", linkHeavy());
    const counts: number[] = [];
    for (let i = 0; i < 5; i++) {
      const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/links.pdf" }));
      assert.equal(a.status, "complete", JSON.stringify([a.problems, a.limits_hit]));
      counts.push(a.actions.count);
      assert.equal(a.tables.pdf_actions.matched, 4000);
      assert.equal(a.annotation_subtypes.Link, 4000);
    }
    assert.deepEqual(counts, [4000, 4000, 4000, 4000, 4000]);
  });
});

test("P1-2 a /Next chain that two links reach is 'reached by two /Next links', a chain that returns is a cycle; a direct /Next is a row of its own", async () => {
  await withCwd(async (cwd) => {
    const objs: PdfObj[] = [
      { num: 1, body: "<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R /AA << /WC 7 0 R >> >>" },
      { num: 2, body: "<< /Type /Pages /Kids [] /Count 0 >>" },
      // 4 -> [5, 6]; 5 -> 6: object 6 is reached twice, not a cycle
      { num: 4, body: "<< /S /URI /URI (http://a.example/) /Next [ 5 0 R 6 0 R ] >>" },
      { num: 5, body: "<< /S /URI /URI (http://b.example/) /Next 6 0 R >>" },
      { num: 6, body: "<< /S /URI /URI (http://c.example/) /Next << /S /URI /URI (http://direct.example/) >> >>" },
      // 7 -> 8 -> 7: a cycle
      { num: 7, body: "<< /S /URI /URI (http://d.example/) /Next 8 0 R >>" },
      { num: 8, body: "<< /S /URI /URI (http://e.example/) /Next 7 0 R >>" },
    ];
    await put(cwd, "work/next.pdf", buildPdf(objs, "/Root 1 0 R").file);
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/next.pdf" }));
    assert.ok(a.problems.some((p: string) => /reached from Catalog\/OpenAction reaches object 6 by two \/Next links: it is listed once/.test(p)), JSON.stringify(a.problems));
    assert.ok(a.problems.some((p: string) => /reached from Catalog\/AA\/WC returns to object 7: a cycle, followed once/.test(p)), JSON.stringify(a.problems));
    assert.ok(!a.problems.some((p: string) => /object 6: a cycle/.test(p)), JSON.stringify(a.problems));
    // 4, 5, 6, the direct one after 6 (reached once: the second way to 6 is not followed again), 7, 8
    assert.equal(a.actions.count, 6, JSON.stringify(a.tables.pdf_actions.rows));
  });
});

test("P3 a chain of more than eight references in a row is a problem, not a silent stop", async () => {
  await withCwd(async (cwd) => {
    const objs: PdfObj[] = [{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R /OpenAction 10 0 R >>" }, { num: 2, body: "<< /Type /Pages /Kids [] /Count 0 >>" }];
    for (let i = 10; i < 20; i++) objs.push({ num: i, body: `${i + 1} 0 R` });
    objs.push({ num: 20, body: "<< /S /JavaScript /JS (app.alert(1)) >>" });
    await put(cwd, "work/hops.pdf", buildPdf(objs, "/Root 1 0 R").file);
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/hops.pdf" }));
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /object 10 leads through more than 8 references in a row/.test(p)), JSON.stringify(a.problems));
  });
});

// --- P1-3: what the parser keeps is bounded by its size --------------------------------------------------------------------------

/** A PDF whose objects are in Flate object streams (ISO 32000-1 7.5.7) and whose index is a cross-reference stream (7.5.8). */
function objstmPdf(direct: Map<number, string>, streams: Map<number, [number, Buffer][]>): Buffer {
  const parts: Buffer[] = [Buffer.from("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", "latin1")];
  let at = parts[0]!.length;
  const ent = new Map<number, [number, number, number]>();
  const push = (b: Buffer): void => { parts.push(b); at += b.length; };
  for (const [n, body] of [...direct].sort((x, y) => x[0] - y[0])) {
    ent.set(n, [1, at, 0]);
    push(Buffer.from(`${n} 0 obj\n${body}\nendobj\n`, "latin1"));
  }
  for (const [stm, members] of streams) {
    let hdr = "";
    const bodies: Buffer[] = [];
    let off = 0;
    members.forEach(([num, b], i) => { hdr += `${num} ${off} `; bodies.push(b, Buffer.from("\n")); off += b.length + 1; ent.set(num, [2, stm, i]); });
    const raw = deflateSync(Buffer.concat([Buffer.from(hdr, "latin1"), ...bodies]));
    ent.set(stm, [1, at, 0]);
    push(Buffer.concat([Buffer.from(`${stm} 0 obj\n<< /Type /ObjStm /N ${members.length} /First ${hdr.length} /Filter /FlateDecode /Length ${raw.length} >>\nstream\n`, "latin1"), raw, Buffer.from("\nendstream\nendobj\n")]));
  }
  const xn = Math.max(...ent.keys()) + 1;
  ent.set(xn, [1, at, 0]);
  const size = xn + 1;
  const rows = Buffer.alloc(size * 7);
  for (let n = 0; n < size; n++) {
    const [t, a, b] = ent.get(n) ?? [0, 0, n === 0 ? 65535 : 0];
    rows[n * 7] = t;
    rows.writeUInt32BE(a, n * 7 + 1);
    rows.writeUInt16BE(b, n * 7 + 5);
  }
  const x = at;
  push(Buffer.concat([Buffer.from(`${xn} 0 obj\n<< /Type /XRef /Size ${size} /W [1 4 2] /Root 1 0 R /Length ${rows.length} >>\nstream\n`, "latin1"), rows, Buffer.from(`\nendstream\nendobj\nstartxref\n${x}\n%%EOF\n`, "latin1")]));
  return Buffer.concat(parts);
}

const BASE = new Map<number, string>([[1, "<< /Type /Catalog /Pages 2 0 R >>"], [2, "<< /Type /Pages /Kids [] /Count 0 >>"]]);
const names = (n: number): Buffer => Buffer.from("[" + "/a".repeat(n) + "]", "latin1");

test("P1-3 a 118 KB file of four object streams, seven members each of 999,000 names: under 400 MB, partial, the bound named (3 GB, complete, before)", async () => {
  await withCwd(async (cwd) => {
    const streams = new Map<number, [number, Buffer][]>();
    for (let s = 0; s < 4; s++) streams.set(100 + s, Array.from({ length: 7 }, (_x, k): [number, Buffer] => [200 + s * 10 + k, names(999_000)]));
    await put(cwd, "work/mem.pdf", objstmPdf(BASE, streams));
    // the members compress well past max_ratio's 1,000: the ratio is lifted so that the parser, not the decoder, meets them
    const { run, seconds, rssMb } = bounded(cwd, { path: "work/mem.pdf", max_ratio: 1_000_000 }, 120_000);
    const a = JSON.parse(run.stdout) as Json;
    assert.ok(rssMb < 400, `${rssMb.toFixed(0)} MB`);
    assert.ok(seconds < 60, `${seconds.toFixed(1)} s`);
    assert.equal(a.status, "partial");
    assert.ok(a.limits_hit.some((l: string) => /more than 250000 values in one parse/.test(l)), JSON.stringify(a.limits_hit));
    assert.equal(a.census.objects_not_read_at_a_limit, 28);
  });
});

test("P1-3 objects under the per-parse bound, many of them, in object streams and outside: every one read, complete, under 400 MB (the cache is held to its size)", async () => {
  await withCwd(async (cwd) => {
    const streams = new Map<number, [number, Buffer][]>();
    for (let s = 0; s < 4; s++) streams.set(100 + s, Array.from({ length: 7 }, (_x, k): [number, Buffer] => [200 + s * 10 + k, names(240_000)]));
    const direct = new Map(BASE);
    for (let k = 0; k < 5; k++) direct.set(300 + k, "[" + "/a".repeat(240_000) + "]");
    await put(cwd, "work/many.pdf", objstmPdf(direct, streams));
    const { run, rssMb } = bounded(cwd, { path: "work/many.pdf", max_ratio: 1_000_000 }, 120_000);
    const a = JSON.parse(run.stdout) as Json;
    assert.ok(rssMb < 400, `${rssMb.toFixed(0)} MB`);
    assert.equal(a.status, "complete", JSON.stringify([a.problems, a.limits_hit]));
    assert.equal(a.census.objects_listed, 2 + 4 + 28 + 5 + 1);
    assert.equal(a.census.objects_not_read_at_a_limit, 0);
  });
});

test("P3 object streams whose members interleave are decoded again when they leave the cache, and counted against max_total_bytes once: complete", async () => {
  await withCwd(async (cwd) => {
    const streams = new Map<number, [number, Buffer][]>();
    const pad = Buffer.from("(" + "x".repeat(2000) + ")", "latin1");
    for (let s = 0; s < 8; s++) streams.set(100 + s, []);
    for (let k = 0; k < 400; k++) streams.get(100 + (k % 8))!.push([1000 + k, pad]);
    await put(cwd, "work/il.pdf", objstmPdf(BASE, streams));
    // eight streams of about 100 KB decoded: 800 KB read once; a cache of six re-read every one of them before, past 1 MB
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/il.pdf", max_total_bytes: 1 << 20 }));
    assert.equal(a.status, "complete", JSON.stringify([a.problems, a.limits_hit]));
    assert.equal(a.census.objects_not_read_at_a_limit, 0);
    assert.ok(a.budgets.stream_bytes_read < 1 << 20);
  });
});

test("P3 more than 100 distinct filter chains: the first 100 are counted by chain, the rest are counted and the limit is named", async () => {
  await withCwd(async (cwd) => {
    const objs: PdfObj[] = [{ num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>" }, { num: 2, body: "<< /Type /Pages /Kids [] /Count 0 >>" }];
    for (let i = 0; i < 120; i++) objs.push({ num: 10 + i, body: `<< /Filter /F${i} >>`, stream: Buffer.from("x") });
    await put(cwd, "work/f.pdf", buildPdf(objs, "/Root 1 0 R").file);
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/f.pdf" }));
    assert.equal(a.streams.count, 120);
    assert.equal(Object.values(a.streams.by_filter_chain as Record<string, number>).reduce((x, y) => x + y, 0), 100);
    assert.equal(a.streams.in_chains_past_the_first_100, 20);
    assert.ok(a.limits_hit.some((l: string) => /more than 100 distinct filter chains/.test(l)), JSON.stringify(a.limits_hit));
  });
});

// --- P1-4: two entries of one name in a compound file's storage -------------------------------------------------------------------

function twoDirs(secondDirName: string): Buffer {
  const a = { name: "ThisDocument", source: "Sub Document_Open()\r\nEnd Sub\r\n" };
  const evil = { name: "Evil", source: "Sub AutoOpen()\r\nShell \"x\"\r\nEnd Sub\r\n" };
  const cache = Buffer.alloc(24, 0xab);
  const vba = {
    name: "VBA",
    children: [
      { name: "dir", data: ovbaCompress(vbaDirStream([a], [24])) },
      { name: secondDirName, data: ovbaCompress(vbaDirStream([evil], [24])) },
      { name: "_VBA_PROJECT", data: Buffer.concat([u16(0x61cc), u16(0xffff), Buffer.from([0]), u16(0), Buffer.alloc(40, 0x11)]) },
      { name: "ThisDocument", data: Buffer.concat([cache, ovbaCompress(Buffer.from(a.source, "latin1"))]) },
      { name: "Evil", data: Buffer.concat([cache, ovbaCompress(Buffer.from(evil.source, "latin1"))]) },
    ],
  };
  return buildCfb([{ name: "Macros", children: [vba, { name: "PROJECT", data: Buffer.from('ID="{00000000-0000-0000-0000-000000000000}"\r\nModule=ThisDocument\r\n', "latin1") }] },
    { name: "WordDocument", data: Buffer.alloc(4200) }]);
}

for (const [label, second] of [["the same name", "dir"], ["names that differ only in case ([MS-CFB] 2.6.4 compares in upper case)", "DIR"]] as const) {
  test(`P1-4 a VBA storage with two dir streams of ${label}: both are listed and read, the module only the second names is in vba_projects, partial`, async () => {
    await withCwd(async (cwd) => {
      await put(cwd, "work/dup.doc", twoDirs(second));
      const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/dup.doc" }));
      assert.equal(a.status, "partial");
      assert.ok(a.problems.some((p: string) => /share the name Macros\/VBA\/dir in one storage \(\[MS-CFB\] 2\.6\.4/i.test(p)), JSON.stringify(a.problems));
      const projects = a.vba_projects as Json[];
      assert.equal(projects.length, 2, JSON.stringify(projects));
      const modules = projects.flatMap((p) => p.modules.map((m: Json) => m.name)).sort();
      assert.deepEqual(modules, ["Evil", "ThisDocument"]);
      assert.ok(projects.every((p) => p.dir_copy && p.dir_copy.of === 2));
      const evil = projects.flatMap((p) => p.modules).find((m: Json) => m.name === "Evil");
      assert.equal(evil.source, "decompressed");
      const rows = (a.tables.ole_directory.rows as Json[]).filter((r) => /^Macros\/VBA\/dir$/i.test(r.path));
      assert.equal(rows.length, 2);
      assert.ok(rows.every((r) => r.duplicate_name_in_storage === true));
    });
  });
}

test("P1-4 a stream in a VBA storage that no dir names is said; a project with every stream named is complete", async () => {
  await withCwd(async (cwd) => {
    const a0 = { name: "Module1", source: "Sub A()\r\nEnd Sub\r\n" };
    const cache = Buffer.alloc(24, 0xab);
    const vba = (extra: { name: string; data: Buffer }[]) => ({
      name: "VBA",
      children: [{ name: "dir", data: ovbaCompress(vbaDirStream([a0], [24])) }, { name: "_VBA_PROJECT", data: Buffer.concat([u16(0x61cc), u16(0xffff), Buffer.from([0]), u16(0), Buffer.alloc(40, 0x11)]) },
        { name: "__SRP_0", data: Buffer.from("cache") }, { name: "Module1", data: Buffer.concat([cache, ovbaCompress(Buffer.from(a0.source, "latin1"))]) }, ...extra],
    });
    const project = { name: "PROJECT", data: Buffer.from('ID="{00000000-0000-0000-0000-000000000000}"\r\nModule=Module1\r\n', "latin1") };
    await put(cwd, "work/ok.bin", buildCfb([vba([]), project]));
    const ok = body(await tool(DOC_STRUCTURE, cwd, { path: "work/ok.bin" }));
    assert.equal(ok.status, "complete", JSON.stringify(ok.problems));
    await put(cwd, "work/hidden.bin", buildCfb([vba([{ name: "Hidden", data: Buffer.concat([cache, ovbaCompress(Buffer.from("Sub AutoOpen()\r\nEnd Sub\r\n"))]) }]), project]));
    const h = body(await tool(DOC_STRUCTURE, cwd, { path: "work/hidden.bin" }));
    assert.equal(h.status, "partial");
    assert.ok(h.problems.some((p: string) => /VBA: the stream Hidden in the VBA storage is named by no module of the dir stream read/.test(p)), JSON.stringify(h.problems));
  });
});

// --- P2: the scan for trailers has a share of its own ----------------------------------------------------------------------------

test("P2 a file with no startxref and a 16 MB tail of 'trailer' keywords: the census, the catalog and the JavaScript action are still read, and the limit says what it stopped", async () => {
  await withCwd(async (cwd) => {
    const head = Buffer.from("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n" +
      "3 0 obj\n<< /S /JavaScript /JS 4 0 R >>\nendobj\n4 0 obj\n<< /Length 11 >>\nstream\napp.alert()\nendstream\nendobj\n", "latin1");
    const junk: Buffer[] = [];
    for (let i = 0; i < 40; i++) junk.push(Buffer.from("trailer<</A(", "latin1"), Buffer.alloc(400_000, 0x20));
    await put(cwd, "work/tail.pdf", Buffer.concat([head, ...junk]));
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/tail.pdf" }));
    assert.equal(a.structure_source, "scan of the file for object headers");
    assert.ok(a.census, JSON.stringify(Object.keys(a)));
    assert.equal(a.catalog.object, 1);
    assert.equal(a.actions.count, 1);
    assert.equal(a.actions.by_type.JavaScript, 1);
    assert.ok(a.limits_hit.every((l: string) => !/its budget for one call/.test(l)), JSON.stringify(a.limits_hit));
    // each keyword begins a dictionary longer than 1 MiB, and the search's own share ends it before the last few: both said
    assert.ok(a.limits_hit.some((l: string) => /^\d+ 'trailer' keyword\(s\) found by the scan begin a dictionary of more than 1 MiB/.test(l)), JSON.stringify(a.limits_hit));
    assert.ok(a.limits_hit.some((l: string) => /the scan for trailers spent its share of the parser's budget/.test(l)), JSON.stringify(a.limits_hit));
  });
});

// --- P3: smaller items ----------------------------------------------------------------------------------------------------------

test("P3 a ZIP member whose local header names another part, or another method, than the central directory: each row says so, and it is a problem", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip([{ name: "[Content_Types].xml", data: Buffer.from("<Types/>"), method: 0 }, { name: "word/document.xml", data: Buffer.from("<a/>"), method: 0 },
      { name: "word/other.xml", data: Buffer.from("<b/>"), method: 0 }]);
    const doc = zip.indexOf(Buffer.from("word/document.xml"));
    zip.write("word/documenX.xml", doc, "latin1");            // the first occurrence is the local header's name
    const other = zip.indexOf(Buffer.from("PK\x03\x04", "latin1"), zip.indexOf(Buffer.from("word/other.xml")) - 30);
    zip.writeUInt16LE(8, other + 8);                          // the local header says deflated, the central directory stored
    await put(cwd, "work/l.docx", zip);
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/l.docx" }));
    assert.equal(a.status, "partial");
    assert.equal(a.local_headers_that_differ, 2);
    const rows = a.tables.parts.rows as Json[];
    assert.deepEqual(rows.find((r) => r.name === "word/document.xml").local_header_differs, ["name"]);
    assert.deepEqual(rows.find((r) => r.name === "word/other.xml").local_header_differs, ["method"]);
    assert.ok(a.problems.some((p: string) => /^2 member\(s\) have a local header that disagrees with the central directory/.test(p)), JSON.stringify(a.problems));
    await put(cwd, "work/ok.docx", buildZip([{ name: "[Content_Types].xml", data: Buffer.from("<Types/>") }, { name: "word/document.xml", data: Buffer.from("<a/>") }]));
    const ok = body(await tool(DOC_STRUCTURE, cwd, { path: "work/ok.docx" }));
    assert.equal(ok.local_headers_that_differ, undefined);
  });
});

test("P3 compound file entries: a type [MS-CFB] does not define, an unallocated entry a tree reaches, a name without its NUL, and a root entry size the mini stream does not match are each said", async () => {
  await withCwd(async (cwd) => {
    const base = buildCfb([{ name: "Alpha", data: Buffer.from("a".repeat(100)) }, { name: "Beta", data: Buffer.from("b".repeat(100)) }]);
    const dirAt = (sid: number): number => 512 + 512 * base.readUInt32LE(48) + sid * 128;
    const entry = (b: Buffer, name: string): number => {
      for (let sid = 1; sid < 4; sid++) if (b.subarray(dirAt(sid), dirAt(sid) + 64).toString("utf16le").startsWith(name)) return dirAt(sid);
      throw new Error(name);
    };
    const t3 = Buffer.from(base);
    t3[entry(t3, "Alpha") + 66] = 3;                          // type 3: not a type [MS-CFB] 2.6.1 defines
    const t0 = Buffer.from(base);
    t0[entry(t0, "Beta") + 66] = 0;                           // unallocated, and still linked from the root's tree
    const nul = Buffer.from(base);
    const at = entry(nul, "Alpha");
    nul.writeUInt16LE(Buffer.from("Alpha", "utf16le").length, at + 64);   // the length leaves out the terminator ...
    const root = Buffer.from(base);
    root.writeUInt32LE(64, dirAt(0) + 120);                   // the mini stream holds 256 bytes; the root entry says 64
    const short = Buffer.from(base);
    short.writeUInt32LE(227, dirAt(0) + 120);                  // Beta's last byte is the mini stream's 228th: one byte past the size declared
    const cases: [string, Buffer, RegExp][] = [
      ["root-1", short, /stream Beta: a mini sector lies beyond the mini stream \(the root entry declares 227 bytes\)/],
      ["t3", t3, /1 directory entry is of a type \[MS-CFB\] 2\.6\.1 does not define \(0x03\)/],
      ["t0", t0, /1 unallocated directory entry is reached from a storage's tree/],
      ["nul", nul, /1 directory entry has a name length that does not fit the name field/],
      ["root", root, /a mini sector lies beyond the mini stream \(the root entry declares 64 bytes\)/],
    ];
    for (const [name, data, re] of cases) {
      await put(cwd, `work/${name}.doc`, data);
      const a = body(await tool(DOC_STRUCTURE, cwd, { path: `work/${name}.doc` }));
      assert.equal(a.status, "partial", name);
      assert.ok(a.problems.some((p: string) => re.test(p)), `${name}: ${JSON.stringify(a.problems)}`);
    }
    await put(cwd, "work/ok.doc", base);
    assert.equal(body(await tool(DOC_STRUCTURE, cwd, { path: "work/ok.doc" })).status, "complete");
  });
});

test("P3 a tool-output directory that is a symbolic link is refused: nothing is written through it, in a job or not, and the answer says so", async () => {
  await withCwd(async (cwd) => {
    const { mkdir, readdir, symlink } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const zip = buildZip([{ name: "[Content_Types].xml", data: Buffer.from("<Types/>") }, ...Array.from({ length: 5 }, (_x, i) => ({ name: `word/AKIAIOSFODNN7EXAMPL${i}.xml`, data: Buffer.from("<a/>") }))]);
    await put(cwd, "work/in/z.docx", zip);
    await mkdir(join(cwd, "elsewhere"), { recursive: true });
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    await symlink(join(cwd, "elsewhere"), join(cwd, "work", "s1", "tool-output"));
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/in/z.docx", limit: 1 }));
    assert.deepEqual(await readdir(join(cwd, "elsewhere")), []);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /is a symbolic link: refused, nothing written through it/.test(p)), JSON.stringify(a.problems));
    assert.equal(a.withheld_names_file, undefined);
    await mkdir(join(cwd, "out"), { recursive: true });
    await symlink(join(cwd, "elsewhere"), join(cwd, "out", "tool-output"));
    const { asJob } = await import("./pack-re-harness.ts");
    const j = body(await asJob(DOC_STRUCTURE, cwd, { path: "work/in/z.docx", limit: 1 }));
    assert.deepEqual(await readdir(join(cwd, "elsewhere")), []);
    assert.ok(j.problems.some((p: string) => /is a symbolic link: refused/.test(p)), JSON.stringify(j.problems));
  });
});

test("P3 under a Python older than 3.11 (no possessive quantifiers) the call is refused as JSON, by name, without a traceback", (t) => {
  const old = ["/usr/bin/python3", "python3.10", "python3.9", "python3.8"].find((bin) => {
    const v = spawnSync(bin, ["-c", "import sys; print(sys.version_info[0] * 100 + sys.version_info[1])"], { encoding: "utf8" });
    return v.status === 0 && Number(v.stdout.trim()) < 311;
  });
  if (!old) {
    t.skip("no Python older than 3.11 on this machine");
    return;
  }
  const r = spawnSync(old, ["-I", DOC_STRUCTURE], { input: JSON.stringify({ path: "nothing.pdf" }), encoding: "utf8" });
  assert.doesNotMatch(r.stderr, /Traceback/);
  const a = JSON.parse(r.stdout);
  assert.equal(a.status, "failed");
  assert.match(a.error, /^doc_structure needs Python 3\.11 or later .*: this is Python 3\.\d+; nothing was read$/);
});

test("a member name the directory marks UTF-8 that is not UTF-8 is read as CP437 and said: the other members are listed, the archive is not lost", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip([{ name: "[Content_Types].xml", data: Buffer.from("<Types/>") }, { name: "Xord/document.xml", data: Buffer.from("<a/>") }, { name: "word/b.xml", data: Buffer.from("<b/>") }]);
    for (let at = zip.indexOf(Buffer.from("Xord/")); at >= 0; at = zip.indexOf(Buffer.from("Xord/"), at + 1)) zip[at] = 0xa0;   // local and central name
    await put(cwd, "work/u.docx", zip);
    const a = body(await tool(DOC_STRUCTURE, cwd, { path: "work/u.docx" }));
    assert.equal(a.status, "partial");
    assert.equal(a.members.listed, 3);
    assert.ok(a.problems.some((p: string) => /^1 member name marked UTF-8 \(general purpose flag bit 11\) is not UTF-8: read as CP437/.test(p)), JSON.stringify(a.problems));
    assert.ok(!a.problems.some((p: string) => /local header that disagrees/.test(p)), JSON.stringify(a.problems));
  });
});

// --- P1-1: the reviewers' spill case --------------------------------------------------------------------------------------------

test("P1-1 three hundred case spellings of word/<AWS secret>.xml (part names compare without case): every spelling is withheld, in the answer, the spill file and the parts table", async () => {
  await withCwd(async (cwd) => {
    const { readFile } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const { filesUnder } = await import("./pack-re-harness.ts");
    const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const base = `word/${secret}.xml`;
    const seen = new Set<string>();
    for (let i = 0; i < 300; i++) seen.add([...base].map((ch, k) => ((i >> (k % 9)) & 1 && /[a-z]/i.test(ch) ? ch.toUpperCase() : ch)).join(""));
    await put(cwd, "work/s.docx", buildZip([{ name: "[Content_Types].xml", data: Buffer.from("<Types/>") }, ...[...seen].map((n) => ({ name: n, data: Buffer.from("x") }))]));
    for (const limit of [1, 1000]) {
      const r = await tool(DOC_STRUCTURE, cwd, { path: "work/s.docx", limit });
      const windows = Array.from({ length: secret.length - 8 }, (_x, i) => secret.slice(i, i + 9));
      const texts = [r.stdout];
      for (const f of await filesUnder(join(cwd, "work"))) if (!/withheld-names|s\.docx$/.test(f)) texts.push(await readFile(join(cwd, "work", f), "latin1"));
      for (const t of texts) for (const w of windows) assert.ok(!t.includes(w), `limit ${limit}: '${w}'`);
      assert.equal(JSON.parse(r.stdout).withheld_by_final_check, undefined);
    }
  });
});
