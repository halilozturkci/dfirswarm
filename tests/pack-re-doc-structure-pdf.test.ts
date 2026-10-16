/**
 * doc_structure on PDF, against files written by hand to ISO 32000-1 (tests/pack-re-doc-fixtures.ts): classic cross-reference
 * tables, cross-reference streams with a PNG predictor and an object stream, hybrid files, incremental updates, encryption
 * dictionaries with planted verifiers. What these cases hold: the structure is read, not searched for (a keyword inside an
 * object stream is found, a name written with # escapes is the name it spells, a page count is two numbers named for what they
 * are); the encryption dictionary comes from the CURRENT trailer, with verifiers by length only; an action is reported with the
 * key that reaches it and with a mark when nothing reaches it; every stream is read under budgets; and a hostile file (a loop,
 * a nest, a lying length, a bomb, a table of four billion entries) is a limit or a problem in the answer, never a hang or a trace.
 */
import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { deflateSync } from "node:zlib";
import { DOC_STRUCTURE, asJob, body, filesUnder, put, refused, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { buildPdf, buildPdfWithStreams, pdfObject } from "./pack-re-doc-fixtures.ts";
import type { PdfObj } from "./pack-re-doc-fixtures.ts";

async function run(cwd: string, name: string, data: Buffer | string, args: Record<string, unknown> = {}): Promise<{ a: Json; text: string }> {
  await put(cwd, `work/${name}`, data);
  const r = await tool(DOC_STRUCTURE, cwd, { path: `work/${name}`, ...args });
  return { a: body(r), text: r.stdout };
}

const CATALOG = (extra = ""): PdfObj => ({ num: 1, body: `<< /Type /Catalog /Pages 2 0 R ${extra} >>` });
const PAGES: PdfObj = { num: 2, body: "<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>" };
const PAGE = (extra = ""): PdfObj => ({ num: 3, body: `<< /Type /Page /Parent 2 0 R ${extra} >>` });
const actionsOf = (a: Json): Json[] => a.tables.pdf_actions.rows;

test("a classic file: the cross-reference table, the trailer, the revision and the object census are read, not searched for", async () => {
  await withCwd(async (cwd) => {
    const pdf = buildPdf([CATALOG(), PAGES, PAGE()], "/Root 1 0 R");
    const { a } = await run(cwd, "a.pdf", pdf.file);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.structure_source, "cross-reference chain");
    assert.equal(a.pdf_header.version, "1.7");
    assert.equal(a.startxref, pdf.xrefAt);
    assert.equal(a.revisions.length, 1);
    assert.deepEqual({ kind: a.revisions[0].kind, entries: a.revisions[0].entries, size: a.revisions[0].size }, { kind: "table", entries: 4, size: 4 });
    assert.equal(a.census.objects_listed, 3);
    assert.deepEqual(a.object_types, { Catalog: 1, Pages: 1, Page: 1 });
    assert.equal(a.trailer.root, true);
    assert.equal(a.catalog.object, 1);
    assert.equal(a.encryption_summary.found, false);
    assert.match(a.encryption_summary.limit, /bounded to the cross-reference chain/);
    assert.equal(a.tables.objects.rows.find((r: Json) => r.object === 3).offset, pdf.offsets.get(3));
  });
});

test("a page count is two numbers named for what they are: the root node's declared /Count and the leaves reached; a /Type /Pages and a /Type /Page are not two pages", async () => {
  await withCwd(async (cwd) => {
    const fragment = buildPdf([CATALOG(), { num: 2, body: "<< /Type /Pages /Kids [ 3 0 R ] /Count 7 >>" }, PAGE()], "/Root 1 0 R");
    const { a } = await run(cwd, "pages.pdf", fragment.file);
    assert.equal(a.pages.declared_count_in_root_pages_node, 7);
    assert.equal(a.pages.leaf_nodes_traversed, 1);
    assert.match(a.pages.note, /Neither is a verified page count/);
    assert.equal("page_count" in a, false);
    assert.equal("pages" in a.pages, false);
  });
});

test("the encryption dictionary is read through the current trailer; the owner and user verifiers are reported by length and are in no answer", async () => {
  await withCwd(async (cwd) => {
    const o = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";
    const u = "ff00ee11dd22cc33bb44aa5599668877ff00ee11dd22cc33bb44aa5599668877";
    const pdf = buildPdf([CATALOG(), PAGES, PAGE(), { num: 6, body: `<< /Filter /Standard /V 4 /R 4 /Length 128 /P -3904 /O <${o}> /U <${u}> /EncryptMetadata false /CF << /StdCF << /CFM /AESV2 /Length 16 /AuthEvent /DocOpen >> >> /StmF /StdCF /StrF /StdCF >>` }], "/Root 1 0 R /Encrypt 6 0 R");
    const { a, text } = await run(cwd, "enc.pdf", pdf.file);
    assert.equal(a.encryption_summary.found, true);
    const d = a.encryption.dictionary;
    assert.deepEqual({ filter: d.filter, v: d.v, r: d.r, length_bits: d.length_bits, encrypt_metadata: d.encrypt_metadata, stm_f: d.stm_f }, { filter: "Standard", v: 4, r: 4, length_bits: 128, encrypt_metadata: false, stm_f: "StdCF" });
    assert.deepEqual(d.crypt_filters, { StdCF: { cfm: "AESV2", length: 16, auth_event: "DocOpen" } });
    assert.equal(d.permissions.signed, -3904);
    assert.equal(d.permissions.hex, "0xFFFFF0C0");
    assert.deepEqual(d.verifier_fields_present, [{ name: "O", length: 32 }, { name: "U", length: 32 }]);
    for (const secret of [o, u, o.slice(0, 16), u.slice(0, 16), Buffer.from(o, "hex").toString("latin1")]) assert.ok(!text.includes(secret), "a verifier is in the answer");
    assert.match(d.not_determined, /no password, empty or otherwise, was tried/);
  });
});

test("a trailer that names an encryption dictionary only in an EARLIER revision is not 'encrypted' and not 'not encrypted': it is not determined, and said", async () => {
  await withCwd(async (cwd) => {
    const first = buildPdf([CATALOG(), PAGES, PAGE(), { num: 6, body: "<< /Filter /Standard /V 1 /R 2 /O <00> /U <00> /P -4 >>" }], "/Root 1 0 R /Encrypt 6 0 R");
    // An incremental update: the changed page object, a new table, and a trailer with /Prev and no /Encrypt.
    const at = first.file.length;
    const page = pdfObject({ num: 3, body: "<< /Type /Page /Parent 2 0 R /Rotate 90 >>" });
    const xref = `xref\n3 1\n${String(at).padStart(10, "0")} 00000 n \ntrailer\n<< /Size 7 /Root 1 0 R /Prev ${first.xrefAt} >>\nstartxref\n${at + page.length}\n%%EOF\n`;
    const { a } = await run(cwd, "inc.pdf", Buffer.concat([first.file, page, Buffer.from(xref)]));
    assert.equal(a.revisions.length, 2);
    assert.equal(a.revisions[0].prev, first.xrefAt);
    assert.equal(a.encryption_summary.found, null);
    assert.match(a.encryption_summary.basis, /earlier revision/);
    assert.equal(a.objects_scan.numbers_defined_more_than_once, 1, "object 3 is defined twice");
  });
});

test("an incremental update's newest definition wins; a /Prev loop is a problem, not an endless walk", async () => {
  await withCwd(async (cwd) => {
    const first = buildPdf([CATALOG("/OpenAction 4 0 R"), PAGES, PAGE(), { num: 4, body: "<< /S /URI /URI (http://old.example.test/) >>" }], "/Root 1 0 R");
    const at = first.file.length;
    const obj = pdfObject({ num: 4, body: "<< /S /URI /URI (http://new.example.test/) >>" });
    const xrefAt = at + obj.length;
    const xref = `xref\n4 1\n${String(at).padStart(10, "0")} 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R /Prev ${first.xrefAt} >>\nstartxref\n${xrefAt}\n%%EOF\n`;
    const { a } = await run(cwd, "upd.pdf", Buffer.concat([first.file, obj, Buffer.from(xref)]));
    assert.equal(actionsOf(a)[0].target, "http://new.example.test/");
    // The table's own /Prev is pointed back at the table.
    const looping = buildPdf([CATALOG(), PAGES, PAGE()], "/Root 1 0 R /Prev 0");
    const text = looping.file.toString("latin1").replace("/Prev 0", `/Prev ${looping.xrefAt}`);
    const r = await run(cwd, "loop.pdf", Buffer.from(text.replace(/startxref\n\d+/, `startxref\n${looping.xrefAt}`), "latin1"));
    assert.equal(r.a.status, "partial");
    assert.ok(r.a.problems.some((p: string) => /returns to offset|loop/.test(p)), JSON.stringify(r.a.problems));
  });
});

test("a hybrid file: an object listed only in the /XRefStm stream is found", async () => {
  await withCwd(async (cwd) => {
    const parts: Buffer[] = [Buffer.from("%PDF-1.5\n", "latin1")];
    let at = parts[0]!.length;
    const offs = new Map<number, number>();
    for (const o of [CATALOG("/OpenAction 4 0 R"), PAGES, PAGE(), { num: 4, body: "<< /S /Launch /F (cmd.txt) >>" }]) {
      offs.set(o.num, at);
      const b = pdfObject(o);
      parts.push(b);
      at += b.length;
    }
    // Object 4 is free in the table and in use in the cross-reference stream (W [1 2 1], Index [4 1], no filter).
    const stmAt = at;
    const entry = Buffer.from([1, (offs.get(4)! >> 8) & 0xff, offs.get(4)! & 0xff, 0]);
    const stm = pdfObject({ num: 5, body: "<< /Type /XRef /Size 6 /W [1 2 1] /Index [4 1] >>", stream: entry });
    parts.push(stm);
    at += stm.length;
    const xrefAt = at;
    let table = "xref\n0 4\n0000000000 65535 f \n";
    for (const n of [1, 2, 3]) table += `${String(offs.get(n)).padStart(10, "0")} 00000 n \n`;
    table += `4 1\n0000000000 00000 f \ntrailer\n<< /Size 6 /Root 1 0 R /XRefStm ${stmAt} >>\nstartxref\n${xrefAt}\n%%EOF\n`;
    const { a } = await run(cwd, "hybrid.pdf", Buffer.concat([...parts, Buffer.from(table)]));
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.revisions[0].hybrid_xrefstm, stmAt);
    assert.equal(actionsOf(a)[0].action, "Launch");
  });
});

test("a startxref that points at nothing, and a file cut before its table, are rebuilt by scanning for object headers, and said", async () => {
  await withCwd(async (cwd) => {
    const pdf = buildPdf([CATALOG("/OpenAction 4 0 R"), PAGES, PAGE(), { num: 4, body: "<< /S /URI /URI (http://x.example.test/) >>" }], "/Root 1 0 R");
    const wrong = Buffer.from(pdf.file.toString("latin1").replace(/startxref\n\d+/, "startxref\n12"), "latin1");
    const a = (await run(cwd, "wrong.pdf", wrong)).a;
    assert.equal(a.structure_source, "scan of the file for object headers");
    assert.equal(a.status, "partial");
    assert.equal(actionsOf(a)[0].action, "URI");
    assert.ok(a.anomalies.some((x: string) => /could not be used/.test(x)));
    const cut = (await run(cwd, "cut.pdf", pdf.file.subarray(0, pdf.xrefAt - 20))).a;
    assert.equal(cut.structure_source, "scan of the file for object headers");
    assert.ok(cut.problems.some((p: string) => /no startxref/.test(p)));
    assert.equal(cut.catalog.object, 1, "the catalog is found by its type when no trailer says where it is");
    assert.equal(cut.encryption_summary.found, null, "with no trailer the answer to encryption is not determined");
  });
});

test("bytes before the header and after the last %%EOF are observations; offsets relative to the header are followed", async () => {
  await withCwd(async (cwd) => {
    const pdf = buildPdf([CATALOG(), PAGES, PAGE()], "/Root 1 0 R");
    const prefix = Buffer.from("GARBAGEGARBAGE\n", "latin1");
    const a = (await run(cwd, "shift.pdf", Buffer.concat([prefix, pdf.file, Buffer.from("trailing junk after eof")]))).a;
    assert.equal(a.pdf_header.offset, prefix.length);
    assert.ok(a.anomalies.some((x: string) => /byte\(s\) before the %PDF- header/.test(x)), JSON.stringify(a.anomalies));
    assert.ok(a.anomalies.some((x: string) => /after the last %%EOF/.test(x)), JSON.stringify(a.anomalies));
    assert.equal(a.structure_source, "cross-reference chain", "header-relative offsets are followed");
    assert.equal(a.census.objects_listed, 3);
  });
});

// --- actions -------------------------------------------------------------------------------------------------------------------

test("every action is reported with the key that reaches it; what a byte search cannot see (a #-escaped name, a script in a stream, an action in an additional-actions dictionary) is found", async () => {
  await withCwd(async (cwd) => {
    const js = Buffer.from("app.alert('PlantedScriptMarker9')", "latin1");
    const pdf = buildPdf(
      [
        CATALOG("/OpenAction 4 0 R /AA << /WC 5 0 R >>"),
        PAGES,
        PAGE("/AA << /O 6 0 R >> /Annots [ 7 0 R 8 0 R ]"),
        { num: 4, body: "<< /S /Java#53cript /JS 9 0 R /Next 10 0 R >>" },
        { num: 5, body: "<< /S /Launch /F (calc.exe) /Win << /F (calc.exe) /P (--planted-parameter-text) >> >>" },
        { num: 6, body: "<< /S /JavaScript /JS (this.print\\(\\);) >>" },
        { num: 7, body: "<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A << /S /URI /URI (https://user:hunter2@host.example.test/p?k=abcDEF123456) >> >>" },
        { num: 8, body: "<< /Type /Annot /Subtype /Widget /AA << /E << /S /GoToR /F (other.pdf) /D [0 /Fit] >> >> >>" },
        { num: 9, body: "<< /Filter /FlateDecode >>", stream: deflateSync(js) },
        { num: 10, body: "<< /S /Named /N /Print >>" },
        { num: 11, body: "<< /S /URI /URI (http://unreached.example.test/) >>" },
      ],
      "/Root 1 0 R",
    );
    const { a, text } = await run(cwd, "act.pdf", pdf.file);
    const rows = actionsOf(a);
    const by = (t: string): Json => rows.find((r) => r.trigger === t);
    assert.equal(by("Catalog/OpenAction").action, "JavaScript", "/Java#53cript is /JavaScript");
    assert.deepEqual(by("Catalog/OpenAction").script, { form: "stream", object: 9, stream_bytes: deflateSync(js).length });
    assert.equal(by("Catalog/OpenAction/Next").action, "Named");
    assert.equal(by("Catalog/OpenAction/Next").name, "Print");
    assert.equal(by("Catalog/AA/WC").action, "Launch");
    assert.deepEqual(by("Catalog/AA/WC").windows_launch, { F: 8, P: 24 });
    assert.equal(by("Page/AA/O").action, "JavaScript");
    assert.deepEqual(by("Page/AA/O").script, { form: "string", bytes: "this.print();".length });
    assert.equal(by("Page/Annot[Link]/A").action, "URI");
    assert.equal(by("Page/Annot[Widget]/AA/E").action, "GoToR");
    assert.equal(by("Page/Annot[Widget]/AA/E").target, "other.pdf");
    const unreached = rows.find((r) => r.object === 11);
    assert.deepEqual({ reached: unreached.reached_from_catalog, trigger: unreached.trigger }, { reached: false, trigger: null });
    assert.equal(a.actions.unreached_from_catalog, 1);
    assert.deepEqual(a.actions.by_type, { JavaScript: 2, Named: 1, Launch: 1, URI: 2, GoToR: 1 });
    // The URI's user-info and token-shaped query value are withheld; the length stays.
    assert.ok(!text.includes("hunter2") && !text.includes("abcDEF123456"));
    assert.match(by("Page/Annot[Link]/A").target, /^https:\/\/<userinfo withheld \d+ characters>@host\.example\.test\/p\?k=<withheld 12 characters>$/);
    // Neither the script nor the Launch parameter text is in the answer.
    for (const planted of ["PlantedScriptMarker9", "planted-parameter-text", "this.print"]) assert.ok(!text.includes(planted), planted);
    assert.match(a.actions.note, /whether it runs depends on the reader/);
  });
});

test("an OpenAction that is a destination is a destination, not an action", async () => {
  await withCwd(async (cwd) => {
    const { a } = await run(cwd, "dest.pdf", buildPdf([CATALOG("/OpenAction [ 3 0 R /Fit ]"), PAGES, PAGE()], "/Root 1 0 R").file);
    assert.equal(a.actions.count, 0);
    assert.equal(a.destinations_seen, 1);
  });
});

test("write_values puts the whole target in the sealed values file, in a job only; extract javascript writes each script exactly", async () => {
  await withCwd(async (cwd) => {
    const url = "https://user:hunter2@host.example.test/p?k=abcDEF123456";
    const js = Buffer.from("app.alert('streamed')", "latin1");
    const pdf = buildPdf(
      [
        CATALOG("/OpenAction 4 0 R"),
        PAGES,
        PAGE("/Annots [ 5 0 R ]"),
        { num: 4, body: "<< /S /JavaScript /JS 6 0 R >>" },
        { num: 5, body: `<< /Type /Annot /Subtype /Link /A << /S /URI /URI (${url}) >> /AA << /E << /S /JavaScript /JS (inline\\(\\)) >> >> >>` },
        { num: 6, body: "<< /Filter /FlateDecode >>", stream: deflateSync(js) },
      ],
      "/Root 1 0 R",
    );
    await put(cwd, "work/v.pdf", pdf.file);
    const job = body(await asJob(DOC_STRUCTURE, cwd, { path: "work/v.pdf", write_values: true, extract_to: "out/js", extract: ["javascript"] }));
    // the target, and the digest of each of the two scripts written (in the values file, never in the answer)
    assert.equal(job.secret_values.written, 3);
    const values = (await readFile(join(cwd, "out", "doc-structure-values.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(values[0].value, url);
    assert.equal(values.filter((v: Json) => v.kind === "extracted_object_sha256").length, 2);
    assert.equal(values[0].finding_id, job.tables.pdf_actions.rows.find((r: Json) => r.action === "URI").finding_id);
    const scripts = await Promise.all(job.extracted.map(async (r: Json) => (await readFile(join(cwd, r.file))).toString("latin1")));
    assert.deepEqual(scripts.sort(), ["app.alert('streamed')", "inline()"]);
    const no = refused(await tool(DOC_STRUCTURE, cwd, { path: "work/v.pdf", write_values: true }));
    assert.match(no.error, /refused outside a job/);
  });
});

test("embedded files: the file specification's name is withheld when token-shaped, the stream is located, and pdf:<n> and pdf-raw:<n> give the decoded and the encoded bytes exactly", async () => {
  await withCwd(async (cwd) => {
    const payload = Buffer.from("MZ planted embedded payload bytes ".repeat(40), "latin1");
    const packed = deflateSync(payload);
    const token = "Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK.exe";
    const pdf = buildPdf(
      [
        CATALOG("/Names << /EmbeddedFiles << /Names [ (a) 4 0 R ] >> >>"),
        PAGES,
        PAGE(),
        { num: 4, body: `<< /Type /Filespec /UF (${token}) /EF << /F 5 0 R >> >>` },
        { num: 5, body: "<< /Type /EmbeddedFile /Subtype /application#2Foctet-stream /Filter /FlateDecode >>", stream: packed },
      ],
      "/Root 1 0 R",
    );
    await put(cwd, "work/emb.pdf", pdf.file);
    const r = await asJob(DOC_STRUCTURE, cwd, { path: "work/emb.pdf", extract_to: "out/e", extract: ["pdf:5", "pdf-raw:5"] });
    const a = body(r);
    assert.equal(a.embedded_files.length, 1);
    assert.equal(a.embedded_files[0].stream_object, 5);
    assert.equal(a.embedded_files[0].stream_bytes, packed.length);
    assert.deepEqual(a.embedded_files[0].filters, ["FlateDecode"]);
    assert.ok(!r.stdout.includes(token), "a token-shaped file name is withheld");
    assert.ok(a.withheld.names >= 1);
    const bytes = await Promise.all(a.extracted.map(async (x: Json) => readFile(join(cwd, x.file))));
    assert.equal(bytes.length, 2);
    assert.ok(bytes.some((b) => b.equals(payload)), "the decoded stream is the payload");
    assert.ok(bytes.some((b) => b.equals(packed)), "the raw stream is the encoded bytes");
  });
});

// --- object streams, filters, lengths -------------------------------------------------------------------------------------------

test("a cross-reference stream with a PNG predictor and an object stream: an action inside the object stream is found, which a byte search cannot do", async () => {
  await withCwd(async (cwd) => {
    const f = buildPdfWithStreams();
    const { a } = await run(cwd, "streams.pdf", f.file);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.revisions[0].kind, "stream");
    assert.equal(a.revisions[0].entries, 8);
    assert.equal(a.census.compressed_objects_indexed, 2);
    const rows = a.tables.objects.rows;
    assert.deepEqual(rows.filter((r: Json) => r.in_object_stream).map((r: Json) => [r.object, r.in_object_stream, r.index_in_stream]), [[5, 4, 0], [6, 4, 1]]);
    assert.equal(actionsOf(a)[0].action, "URI");
    assert.equal(actionsOf(a)[0].target, "http://example.test/x");
    assert.equal(a.streams.by_filter_chain.FlateDecode, 2);
  });
});

test("a stream whose /Length lies is measured by its endstream and said; an unsupported filter is named, not skipped", async () => {
  await withCwd(async (cwd) => {
    const data = Buffer.from("0123456789".repeat(4));
    const pdf = buildPdf([CATALOG(), PAGES, PAGE(), { num: 4, body: "<< /Length 5 >>", stream: data }, { num: 5, body: "<< /Filter [ /ASCII85Decode /LZWDecode ] >>", stream: Buffer.from("abc") }], "/Root 1 0 R");
    const { a } = await run(cwd, "len.pdf", pdf.file);
    const row = a.tables.objects.rows.find((r: Json) => r.object === 4);
    assert.deepEqual({ declared: row.stream.declared_length, measured: row.stream.measured_length, ok: row.stream.length_consistent }, { declared: 5, measured: 40, ok: false });
    assert.equal(a.streams.length_inconsistent, 1);
    assert.equal(a.streams.undecodable_filter, 1);
    assert.deepEqual(a.tables.objects.rows.find((r: Json) => r.object === 5).stream.filters, ["ASCII85Decode", "LZWDecode"]);
  });
});

test("a Flate bomb is stopped by the stream budget and the ratio, whether it is extracted or is an object stream; nothing is written", async () => {
  await withCwd(async (cwd) => {
    const zeros = deflateSync(Buffer.alloc(40 << 20));
    assert.ok(zeros.length < 100_000, "the fixture is small on disk");
    const pdf = buildPdf([CATALOG(), PAGES, PAGE(), { num: 4, body: "<< /Filter /FlateDecode >>", stream: zeros }], "/Root 1 0 R");
    const a = (await run(cwd, "bomb.pdf", pdf.file, { extract_to: "work/s1/e", extract: ["pdf:4"], max_stream_bytes: 8 << 20 })).a;
    assert.equal(a.status, "partial");
    assert.ok(a.limits_hit.some((l: string) => /pdf:4|expanded past/.test(l) && /max_stream_bytes|max_ratio/.test(l)), JSON.stringify(a.limits_hit));
    assert.deepEqual(await filesUnder(join(cwd, "work", "s1", "e")), []);
    // The same kind of bytes inside an object stream that holds an action: the action is not found, and the answer says why.
    const bombStm = buildPdfWithStreams({ objstmExtra: Buffer.alloc(40 << 20) });
    const b = (await run(cwd, "bomb2.pdf", bombStm.file, { max_stream_bytes: 8 << 20 })).a;
    assert.equal(b.status, "partial");
    assert.ok(b.limits_hit.some((l: string) => /max_stream_bytes|max_ratio/.test(l)), JSON.stringify(b.limits_hit));
    assert.equal(b.actions.count, 0);
  });
});

test("encrypted object streams cannot be read without a key, and no key is tried: the objects inside are counted unreadable and the answer says so", async () => {
  await withCwd(async (cwd) => {
    const f = buildPdfWithStreams();
    // Make the object stream's data not inflate, as an encrypted stream would not.
    const text = f.file.toString("latin1");
    const at = text.indexOf("stream\n", text.indexOf("/ObjStm")) + 7;
    const bytes = Buffer.from(f.file);
    for (let i = 0; i < 12; i++) bytes[at + i] = 0x55;
    const { a } = await run(cwd, "encstm.pdf", bytes);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /object stream 4/.test(p)), JSON.stringify(a.problems));
    assert.equal(a.census.objects_unreadable, 2);
    assert.equal(a.actions.count, 0, "an action inside an unreadable object stream is not found; the answer says the stream was unreadable");
  });
});

// --- hostile files ----------------------------------------------------------------------------------------------------------------

test("a page tree that returns to itself ends, and says so", async () => {
  await withCwd(async (cwd) => {
    const pdf = buildPdf([CATALOG(), { num: 2, body: "<< /Type /Pages /Kids [ 3 0 R 2 0 R ] /Count 2 >>" }, PAGE()], "/Root 1 0 R");
    const { a } = await run(cwd, "cycle.pdf", pdf.file);
    assert.ok(a.problems.some((p: string) => /page tree returns to object 2/.test(p)), JSON.stringify(a.problems));
    assert.equal(a.pages.leaf_nodes_traversed, 1);
  });
});

test("an object nested 5,000 arrays deep is an unreadable object, named; no recursion error, no trace", async () => {
  await withCwd(async (cwd) => {
    const deep = "[".repeat(5000) + "]".repeat(5000);
    const pdf = buildPdf([CATALOG(), PAGES, PAGE(), { num: 4, body: deep }], "/Root 1 0 R");
    await put(cwd, "work/deep.pdf", pdf.file);
    const r = await tool(DOC_STRUCTURE, cwd, { path: "work/deep.pdf" });
    assert.doesNotMatch(r.stderr, /Traceback|RecursionError/);
    const a = body(r);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /object 4 could not be read: objects nest deeper/.test(p)), JSON.stringify(a.problems));
    assert.equal(a.census.objects_unreadable, 1);
  });
});

test("a cross-reference subsection that declares four billion entries is refused for what the file can hold", async () => {
  await withCwd(async (cwd) => {
    const pdf = buildPdf([CATALOG(), PAGES, PAGE()], "/Root 1 0 R");
    const text = pdf.file.toString("latin1").replace("xref\n0 4\n", "xref\n0 4000000000\n");
    const { a } = await run(cwd, "huge.pdf", Buffer.from(text, "latin1"));
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /declares 4000000000 entries and the file cannot hold them/.test(p)), JSON.stringify(a.problems));
    assert.equal(a.structure_source, "scan of the file for object headers");
  });
});

test("max_objects bounds the index: objects past it are named as a limit, not dropped quietly", async () => {
  await withCwd(async (cwd) => {
    const objs: PdfObj[] = [CATALOG(), PAGES, PAGE(), ...Array.from({ length: 20 }, (_, i) => ({ num: 4 + i, body: "<< /Type /Font >>" }))];
    const { a } = await run(cwd, "many.pdf", buildPdf(objs, "/Root 1 0 R").file, { max_objects: 8 });
    assert.equal(a.status, "partial");
    assert.ok(a.limits_hit.some((l: string) => /more than max_objects \(8\)/.test(l)), JSON.stringify(a.limits_hit));
    assert.ok(a.census.objects_listed <= 8);
  });
});

test("a large honest file is read in bounded time and the table keeps every row in a file", async () => {
  await withCwd(async (cwd) => {
    const objs: PdfObj[] = [CATALOG(), PAGES, PAGE(), ...Array.from({ length: 6000 }, (_, i) => ({ num: 4 + i, body: `<< /Type /Annot /Subtype /Text /Contents (note ${i}) >>` }))];
    const t0 = Date.now();
    const { a } = await run(cwd, "big.pdf", buildPdf(objs, "/Root 1 0 R").file, { limit: 100 });
    assert.ok(Date.now() - t0 < 30000);
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.census.objects_listed, 6003);
    assert.equal(a.tables.objects.returned, 100);
    const lines = (await readFile(join(cwd, a.tables.objects.all_results), "utf8")).trim().split("\n");
    assert.equal(lines.length, 6003);
    assert.equal(((await stat(join(cwd, a.tables.objects.all_results))).mode & 0o777), 0o600);
  });
});

test("the old doc_probe fragment: one /Pages and one /Page returns no page count, no execution verdict and no encryption verdict from a keyword", async () => {
  await withCwd(async (cwd) => {
    const { a } = await run(cwd, "frag.pdf", "%PDF-1.4\n1 0 obj << /Type /Pages /Count 9 >> endobj\n2 0 obj << /Type /Page >> endobj\ntrailer << /Root 1 0 R /Note (/Encrypt /JavaScript) >>\n%%EOF\n");
    assert.equal(a.status, "partial");
    assert.equal(a.actions.count, 0, "a keyword inside a string is not an action");
    assert.notEqual(a.encryption_summary.found, true, "the word /Encrypt inside a string is not an encryption dictionary");
  });
});
