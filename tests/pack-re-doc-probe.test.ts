/**
 * doc_probe against fixtures built from the formats' own layouts: ZIP archives written to the PKWARE APPNOTE
 * (tests/pack-re-harness.ts), OPC relationship parts (ECMA-376 Part 2: the Relationships element in the
 * package-relationships namespace, with Id, Type, Target and TargetMode attributes), and the literal tokens of
 * ISO 32000 (PDF) and the RTF specification.
 *
 * What these cases hold: decompression is bounded by explicit budgets and says so; a relationship is read by an
 * XML parser (any attribute quoting, any namespace prefix), never by a regular expression over text; a DOCTYPE
 * is refused rather than expanded; a member that cannot be read is counted, not skipped; PDF keywords are
 * markers with offsets, not a page count or an execution verdict; an extension that disagrees with the parts is
 * said as a disagreement, not as a rename; and what a URL or a name can hold (a credential, a token) is withheld
 * from the answer and kept whole only in a sealed job file.
 */
import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { deflateRawSync } from "node:zlib";
import { DOC_PROBE, REL_NS, asJob, body, buildZip, exists, filesUnder, put, refused, rels, tool, withCwd } from "./pack-re-harness.ts";
import type { Json, ZipEntry } from "./pack-re-harness.ts";

async function probe(cwd: string, name: string, data: Buffer | string, args: Record<string, unknown> = {}, env: Record<string, string> = {}): Promise<Json> {
  await put(cwd, `work/${name}`, data);
  return body(await tool(DOC_PROBE, cwd, { path: `work/${name}`, ...args }, env));
}

const CONTENT_TYPES: ZipEntry = { name: "[Content_Types].xml", data: Buffer.from('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>') };
const DOC: ZipEntry = { name: "word/document.xml", data: Buffer.from("<w:document/>") };
const PROJECT = Buffer.from("vba project bytes");

// --- budgets -----------------------------------------------------------------------------------------------------

test("a member that inflates past the per-member budget stops there: partial, named, and nothing extracted", async () => {
  await withCwd(async (cwd) => {
    // 8 MiB of zeros deflates to about 8 KiB: a high-ratio member, the shape of a decompression bomb.
    const zeros = Buffer.alloc(8 << 20);
    const zip = buildZip([CONTENT_TYPES, DOC, { name: "word/vbaProject.bin", data: zeros }]);
    assert.ok(zip.length < 20_000, "the fixture is small on disk");
    const out = await probe(cwd, "bomb.docx", zip, { extract_to: "work/s1/parts", max_member_bytes: 1 << 20 });
    assert.equal(out.status, "partial", JSON.stringify(out));
    assert.equal(out.members.over_budget, 1);
    assert.ok(out.limits_hit.some((l: string) => /vbaProject/.test(l) || /budget/i.test(l)), JSON.stringify(out.limits_hit));
    const written = await filesUnder(join(cwd, "work", "s1", "parts"));
    assert.deepEqual(written, [], "a member over its budget is not extracted: a cut copy would pass for the part");
    assert.ok(out.members.read >= 0);
  });
});

test("the default budgets stop a member of sixty MiB of zeros by its expansion ratio, before it is read", async () => {
  await withCwd(async (cwd) => {
    // Under the 64 MiB per-member budget, and about 1,030 bytes out for each byte in: over the default ratio of 1,000.
    const zip = buildZip([CONTENT_TYPES, DOC, { name: "word/vbaProject.bin", data: Buffer.alloc(60 << 20) }]);
    const out = await probe(cwd, "bomb2.docx", zip, { extract_to: "work/s1/parts" });
    assert.equal(out.status, "partial");
    assert.equal(out.members.over_budget, 1);
    assert.ok(out.limits_hit.some((l: string) => /ratio/.test(l)), JSON.stringify(out.limits_hit));
    assert.deepEqual(await filesUnder(join(cwd, "work", "s1", "parts")), []);
  });
});

test("the total expanded bytes are budgeted across members, and the members not attempted are counted", async () => {
  await withCwd(async (cwd) => {
    const part = (n: string): ZipEntry => ({ name: n, data: Buffer.from(Array.from({ length: 400_000 }, (_, i) => (i * 7919) & 0xff)), method: 0 });
    const zip = buildZip([CONTENT_TYPES, part("word/vbaProject.bin"), part("xl/vbaProject.bin")]);
    const out = await probe(cwd, "two.docx", zip, { extract_to: "work/s1/parts", max_total_bytes: 500_000 });
    assert.equal(out.status, "partial");
    assert.equal(out.members.read, 1);
    assert.equal(out.members.not_attempted, 1);
    assert.equal((await filesUnder(join(cwd, "work", "s1", "parts"))).length, 1);
  });
});

test("more members than max_members are listed up to the limit, and the rest are counted as not listed", async () => {
  await withCwd(async (cwd) => {
    const entries: ZipEntry[] = Array.from({ length: 5 }, (_, i) => ({ name: `word/part${i}.xml`, data: Buffer.from("<x/>") }));
    const out = await probe(cwd, "many.docx", buildZip(entries), { max_members: 3 });
    assert.equal(out.status, "partial");
    assert.equal(out.members.declared, 5);
    assert.equal(out.members.listed, 3);
    assert.equal(out.parts.length, 3);
  });
});

test("a member that cannot be read is counted: encrypted, corrupt and unsupported members are not silently skipped", async () => {
  await withCwd(async (cwd) => {
    const good = rels([{ id: "rId1", type: "hyperlink", target: "https://example.org/a", mode: "External" }]);
    const zip = buildZip([
      CONTENT_TYPES,
      { name: "_rels/.rels", data: Buffer.from(good) },
      // flag bit 0: encrypted. The bytes are not a deflate stream and are never decoded.
      { name: "word/_rels/document.xml.rels", data: Buffer.from("x"), flags: 1, compressed: Buffer.from("garbage-not-a-stream"), method: 8 },
      // a deflate stream cut off: the member is corrupt
      { name: "xl/_rels/workbook.xml.rels", data: Buffer.from("<Relationships/>".repeat(20)), compressed: deflateRawSync(Buffer.from("<Relationships/>".repeat(20))).subarray(0, 5), method: 8 },
    ]);
    const out = await probe(cwd, "bad.docx", zip);
    assert.equal(out.status, "partial");
    assert.equal(out.members.encrypted, 1);
    assert.equal(out.members.failed, 1);
    assert.equal(out.external_targets.length, 1, "the readable relationship part still yields its target");
  });
});

// --- relationships -------------------------------------------------------------------------------------------------

test("relationships are read by an XML parser: single-quoted attributes and a prefixed element are found", async () => {
  await withCwd(async (cwd) => {
    const single = rels([{ id: "rId7", type: "attachedTemplate", target: "http://example.org/t.dotm", mode: "External" }], "'");
    const prefixed =
      `<?xml version="1.0"?><r:Relationships xmlns:r="${REL_NS}">` +
      `<r:Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" ` +
      `TargetMode="External" Target="file:///\\\\server\\share\\x.bin"/></r:Relationships>`;
    const zip = buildZip([CONTENT_TYPES, { name: "word/_rels/document.xml.rels", data: Buffer.from(single) }, { name: "xl/_rels/workbook.xml.rels", data: Buffer.from(prefixed) }, DOC]);
    const out = await probe(cwd, "rels.docx", zip);
    const byId = Object.fromEntries(out.external_targets.map((t: Json) => [t.relationship_id, t]));
    assert.equal(byId["rId7"].type, "attachedTemplate");
    assert.match(byId["rId7"].target, /^http:\/\/example\.org\/t\.dotm$/);
    assert.equal(byId["rId9"].type, "oleObject");
    assert.equal(byId["rId9"].part, "xl/_rels/workbook.xml.rels");
    assert.equal(out.status, "complete", JSON.stringify(out.problems));
  });
});

test("a relationship that is not External is not an external target, and the case of the attribute value matters", async () => {
  await withCwd(async (cwd) => {
    const text =
      `<Relationships xmlns="${REL_NS}">` +
      `<Relationship Id="a" Type="x/y" Target="media/image1.png"/>` +
      `<Relationship Id="b" Type="x/y" Target="https://example.org/b" TargetMode="Internal"/>` +
      `<Relationship Id="c" Type="x/y" Target="https://example.org/c" TargetMode="external"/>` +
      `</Relationships>`;
    const out = await probe(cwd, "m.docx", buildZip([CONTENT_TYPES, { name: "_rels/.rels", data: Buffer.from(text) }]));
    assert.deepEqual(out.external_targets.map((t: Json) => t.relationship_id), []);
    assert.ok(out.problems.some((p: string) => /TargetMode/.test(p)), "a TargetMode that is neither Internal nor External is said");
  });
});

test("a DOCTYPE in a relationships part is refused and not expanded", async () => {
  await withCwd(async (cwd) => {
    const bomb =
      `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>` +
      `<Relationships xmlns="${REL_NS}"><Relationship Id="x" Type="t/hyperlink" Target="&b;" TargetMode="External"/></Relationships>`;
    const out = await probe(cwd, "dtd.docx", buildZip([CONTENT_TYPES, { name: "_rels/.rels", data: Buffer.from(bomb) }]));
    assert.equal(out.status, "partial");
    assert.deepEqual(out.external_targets, []);
    assert.ok(out.problems.some((p: string) => /DOCTYPE/i.test(p)), JSON.stringify(out.problems));
  });
});

test("a relationships part that is not well-formed keeps the relationships read before the error, and says so", async () => {
  await withCwd(async (cwd) => {
    const text =
      `<Relationships xmlns="${REL_NS}">` +
      `<Relationship Id="a" Type="x/hyperlink" Target="https://example.org/first" TargetMode="External"/>` +
      `<Relationship Id="b" Type="x/hyperlink" Target="https://example.org/second" TargetMode="External"` + // cut off: never closed
      ``;
    const out = await probe(cwd, "cut.docx", buildZip([CONTENT_TYPES, { name: "_rels/.rels", data: Buffer.from(text) }]));
    assert.equal(out.status, "partial");
    assert.deepEqual(out.external_targets.map((t: Json) => t.relationship_id), ["a"]);
    assert.ok(out.problems.some((p: string) => /not well-formed/.test(p)), JSON.stringify(out.problems));
    assert.equal(out.members.failed, 1);
  });
});

test("only relationships parts are read for relationships, and the coverage says so", async () => {
  await withCwd(async (cwd) => {
    const out = await probe(cwd, "c.docx", buildZip([CONTENT_TYPES, DOC]));
    assert.ok(out.coverage.structures_read.some((s: string) => /\.rels/.test(s)));
    assert.ok(out.coverage.structures_not_read.some((s: string) => /embedded/i.test(s)));
    assert.ok(out.coverage.structures_not_read.some((s: string) => /encrypt/i.test(s)));
  });
});

// --- what the answer may hold -----------------------------------------------------------------------------------------

const SECRET_USER = "alice";
const SECRET_PASS = "hunter2-correct-horse";
const SECRET_SIG = "sv=2022-11-02&sig=Zk3pQ9x7LmN2vB8dTrYw5uHc1aEfGj6oKsIq4XyP0Vt%3D";
const TOKEN = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5";
const SECRET_TARGET = `https://${SECRET_USER}:${SECRET_PASS}@files.example.org/share/t.dotm?${SECRET_SIG}#frag`;

function secretDoc(): Buffer {
  return buildZip([
    CONTENT_TYPES,
    { name: "word/_rels/document.xml.rels", data: Buffer.from(rels([{ id: "rId1", type: "attachedTemplate", target: SECRET_TARGET, mode: "External" }])) },
    { name: `word/embeddings/${TOKEN}.bin`, data: Buffer.from("object") },
    DOC,
  ]);
}

test("an external target's credentials and query values are not in the answer, and its length and host are", async () => {
  await withCwd(async (cwd) => {
    const out = await probe(cwd, "s.docx", secretDoc());
    const text = JSON.stringify(out);
    for (const secret of [SECRET_PASS, SECRET_USER + ":", "Zk3pQ9x7LmN2vB8dTrYw5uHc1aEfGj6oKsIq4XyP0Vt", "#frag"]) assert.ok(!text.includes(secret), `${secret} is in the answer`);
    const t = out.external_targets[0];
    assert.match(t.target, /^https:\/\/<userinfo withheld \d+ characters>@files\.example\.org\/share\/t\.dotm\?/);
    assert.equal(t.target_length, SECRET_TARGET.length);
    assert.equal(out.secret_values.requested, false);
    assert.ok(out.withheld.urls >= 1);
  });
});

test("a part named like a token is not printed", async () => {
  await withCwd(async (cwd) => {
    const out = await probe(cwd, "s2.docx", secretDoc());
    assert.ok(!JSON.stringify(out).includes(TOKEN));
    assert.ok(out.parts.some((p: Json) => p.name_withheld === true));
  });
});

test("write_values puts the whole target in a sealed job file: refused outside a job, 0600, and never overwritten", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/s.docx", secretDoc());
    const outside = refused(await tool(DOC_PROBE, cwd, { path: "work/s.docx", write_values: true }));
    assert.match(outside.error, /outside a job/);
    assert.deepEqual(await filesUnder(join(cwd, "work")), ["s.docx"]);

    const first = body(await asJob(DOC_PROBE, cwd, { path: "work/s.docx", write_values: true }));
    assert.equal(first.secret_values.written, 1);
    assert.equal(first.secret_values.contains_secret_values, true);
    const file = join(cwd, "out", "doc-probe-values.jsonl");
    const rows = (await readFile(file, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(rows[0].value, SECRET_TARGET);
    assert.equal(rows[0].finding_id, first.external_targets[0].finding_id);
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const all = JSON.stringify(first);
    assert.ok(!all.includes(SECRET_PASS), "the answer still holds no value");

    const second = refused(await asJob(DOC_PROBE, cwd, { path: "work/s.docx", write_values: true }));
    assert.match(second.error, /already exists/);
    assert.equal((await readFile(file, "utf8")).trim().split("\n").length, 1, "the earlier file was not touched");
  });
});

test("write_values with nothing to write leaves an empty 0600 file and says written: 0", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/c.docx", buildZip([CONTENT_TYPES, DOC]));
    const out = body(await asJob(DOC_PROBE, cwd, { path: "work/c.docx", write_values: true }));
    assert.equal(out.secret_values.written, 0);
    assert.equal(out.secret_values.contains_secret_values, false);
    const file = join(cwd, "out", "doc-probe-values.jsonl");
    assert.equal((await stat(file)).size, 0);
    assert.equal((await stat(file)).mode & 0o777, 0o600);
  });
});

// --- extraction ---------------------------------------------------------------------------------------------------------

test("only the parts whose names match the code-related patterns are extracted, and the output says that", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip([CONTENT_TYPES, DOC, { name: "word/vbaProject.bin", data: PROJECT }, { name: "word/embeddings/oleObject1.bin", data: Buffer.from("ole") }]);
    const out = await probe(cwd, "x.docm", zip, { extract_to: "work/s1/parts" });
    assert.deepEqual(out.code_related_parts, ["word/vbaProject.bin"]);
    const files = await filesUnder(join(cwd, "work", "s1", "parts"));
    assert.equal(files.length, 1);
    assert.equal((await readFile(join(cwd, "work", "s1", "parts", files[0]!))).toString(), PROJECT.toString());
    assert.match(out.extraction_note, /name/i);
    assert.equal(out.extracted_parts_may_contain_secrets, true);
  });
});

test("a second extraction into the same directory leaves the first files alone", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip([CONTENT_TYPES, { name: "word/vbaProject.bin", data: PROJECT }]);
    await put(cwd, "work/x.docm", zip);
    body(await tool(DOC_PROBE, cwd, { path: "work/x.docm", extract_to: "work/s1/parts" }));
    body(await tool(DOC_PROBE, cwd, { path: "work/x.docm", extract_to: "work/s1/parts" }));
    assert.equal((await filesUnder(join(cwd, "work", "s1", "parts"))).length, 2);
  });
});

test("in a job extract_to must be under $OUT: anything else is a JSON error, not a traceback", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/x.docm", buildZip([CONTENT_TYPES, { name: "word/vbaProject.bin", data: PROJECT }]));
    const out = refused(await asJob(DOC_PROBE, cwd, { path: "work/x.docm", extract_to: "work/elsewhere" }));
    assert.match(out.error, /\$OUT/);
    const ok = body(await asJob(DOC_PROBE, cwd, { path: "work/x.docm", extract_to: "out/parts" }));
    assert.equal(ok.members.read, 1);
    assert.ok(await exists(join(cwd, "out", "parts")));
  });
});

// --- what the tool says about the file --------------------------------------------------------------------------------------

test("an extension that disagrees with the parts is a disagreement, not a rename, and nothing says it was fetched or will run", async () => {
  await withCwd(async (cwd) => {
    const rel = rels([{ id: "rId1", type: "attachedTemplate", target: "http://example.org/t.dotm", mode: "External" }]);
    const out = await probe(cwd, "invoice.docx", buildZip([CONTENT_TYPES, DOC, { name: "_rels/.rels", data: Buffer.from(rel) }, { name: "word/vbaProject.bin", data: PROJECT }]));
    const text = JSON.stringify(out);
    assert.doesNotMatch(text, /has been renamed|It has been renamed|which cannot carry a macro/);
    assert.doesNotMatch(text, /fetches when the document opens|runs automatically|run on open|needs a user to click/);
    assert.match(out.extension_content_disagreement.text, /renaming history, application acceptance and execution are not established/);
    assert.equal(out.extension_content_disagreement.extension, "docx");
    assert.match(out.note, /Static container triage only/);
  });
});

test("an Office file with no disagreement says none", async () => {
  await withCwd(async (cwd) => {
    const out = await probe(cwd, "plain.docx", buildZip([CONTENT_TYPES, DOC]));
    assert.equal(out.extension_content_disagreement, null);
    assert.equal(out.kind, "Word");
    assert.equal(out.opc_markers["[Content_Types].xml"], true);
  });
});

test("a zip64 archive is listed from its zip64 end record, and one whose zip64 record is missing fails with the reason", async () => {
  await withCwd(async (cwd) => {
    const rel = rels([{ id: "rId1", type: "hyperlink", target: "https://example.org/a", mode: "External" }]);
    const entries: ZipEntry[] = [CONTENT_TYPES, { name: "_rels/.rels", data: Buffer.from(rel) }, DOC];
    const out = await probe(cwd, "z64.docx", buildZip(entries, { zip64: true }));
    assert.equal(out.members.declared, 3);
    assert.equal(out.members.listed, 3);
    assert.equal(out.external_targets.length, 1);
    assert.equal(out.status, "complete", JSON.stringify(out.problems));
    // The same archive with its zip64 locator wiped: the end record holds sentinels and nothing says where the real values are.
    const broken = buildZip(entries, { zip64: true });
    broken.fill(0, broken.length - 22 - 20, broken.length - 22);
    await put(cwd, "work/broken.docx", broken);
    const bad = refused(await tool(DOC_PROBE, cwd, { path: "work/broken.docx" }));
    assert.equal(bad.status, "failed");
    assert.match(bad.error, /zip64/i);
  });
});

test("a ZIP with no end-of-central-directory record fails loudly, with the reason", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/t.docx", Buffer.concat([Buffer.from("PK\x03\x04"), Buffer.alloc(200, 1)]));
    const out = refused(await tool(DOC_PROBE, cwd, { path: "work/t.docx" }));
    assert.equal(out.status, "failed");
    assert.match(out.error, /end of central directory/i);
  });
});

test("a central directory that lies outside the file is a failure that names it, the same on every Python", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip([CONTENT_TYPES, DOC]);
    // The end record says the directory is a million bytes long.
    zip.writeUInt32LE(1_000_000, zip.length - 22 + 12);
    await put(cwd, "work/t.docx", zip);
    const out = refused(await tool(DOC_PROBE, cwd, { path: "work/t.docx" }));
    assert.equal(out.status, "failed");
    assert.match(out.error, /central directory/i);
  });
});

// --- PDF, RTF, OLE --------------------------------------------------------------------------------------------------------

const PDF = [
  "%PDF-1.4",
  "1 0 obj\n<< /Type /Pages /Kids [2 0 R] /Count 1 >>\nendobj",
  "2 0 obj\n<< /Type /Page /Parent 1 0 R >>\nendobj",
  "3 0 obj\n<< /OpenAction 5 0 R /AA << /O 5 0 R >> /JS (x) /JSON 1 /Launch << /F (a) >> /LaunchX 2 /Encrypt 9 0 R >>\nendobj",
  "trailer\n<< /Root 3 0 R >>",
  "%%EOF",
].join("\n");

test("a PDF is a set of marker observations with offsets: no page count, no encryption verdict, no execution meaning", async () => {
  await withCwd(async (cwd) => {
    const out = await probe(cwd, "a.pdf", PDF);
    assert.ok(!("pages" in out), "a lexical count of /Type /Page tokens is not a page count");
    assert.ok(!("encrypted" in out));
    assert.equal(out.encrypt_marker_present, true);
    const marker = Object.fromEntries(out.markers.map((m: Json) => [m.keyword, m]));
    assert.equal(marker["/OpenAction"].count, 1);
    assert.equal(marker["/OpenAction"].first_offsets[0], PDF.indexOf("/OpenAction"));
    assert.equal(marker["/AA"].count, 1);
    assert.equal(marker["/JS"].count, 1, "/JSON is another name");
    assert.equal(marker["/Launch"].count, 1, "/LaunchX is another name");
    assert.doesNotMatch(JSON.stringify(out), /runs when the document opens|launches an external program|execution route/i);
    assert.match(out.note, /compressed|object stream|not an absence/i);
  });
});

test("a PDF without the Encrypt marker is not said to be unencrypted", async () => {
  await withCwd(async (cwd) => {
    const out = await probe(cwd, "b.pdf", "%PDF-1.7\n1 0 obj\n<< >>\nendobj\n%%EOF\n");
    assert.equal(out.encrypt_marker_present, false);
    assert.ok(!("encrypted" in out));
    assert.ok(out.coverage.structures_not_read.some((s: string) => /encrypt/i.test(s)));
  });
});

test("RTF object markers are control words with offsets, and a longer control word is not one of them", async () => {
  await withCwd(async (cwd) => {
    const rtf = "{\\rtf1{\\object{\\*\\objclass Word.Document.8}{\\*\\objdata 0105000002000000}}{\\objdatafoo 1}}";
    const out = await probe(cwd, "a.rtf", rtf);
    assert.equal(out.objdata_markers, 1);
    assert.deepEqual(out.classes, ["Word.Document.8"]);
    assert.equal(out.object_offsets[0], rtf.indexOf("\\objdata "));
  });
});

test("an OLE compound file reports byte markers by encoding, and does not claim a macro project", async () => {
  await withCwd(async (cwd) => {
    const magic = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    const ole = Buffer.concat([magic, Buffer.alloc(512 - 8), Buffer.from("_\0V\0B\0A\0_\0P\0R\0O\0J\0E\0C\0T\0", "latin1"), Buffer.alloc(100)]);
    const out = await probe(cwd, "a.doc", ole);
    assert.ok(!("has_macro_marker" in out));
    const m = Object.fromEntries(out.markers.map((x: Json) => [`${x.marker}|${x.encoding}`, x]));
    assert.equal(m["_VBA_PROJECT|UTF-16LE"].found, true);
    assert.equal(m["_VBA_PROJECT|UTF-16LE"].first_offset, 512);
    assert.equal(m["VBA|ASCII"].found, false);
    assert.match(out.note, /directory|byte search|marker/i);
    assert.ok(out.coverage.structures_not_read.some((s: string) => /OLE directory|streams/i.test(s)));
  });
});

test("a file that is none of the containers is unsupported, with its first bytes, and exit 1", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/x.bin", "plain text, no container");
    const out = refused(await tool(DOC_PROBE, cwd, { path: "work/x.bin" }));
    assert.equal(out.status, "unsupported");
    assert.equal(out.head_hex, Buffer.from("plain te").toString("hex"));
  });
});

test("budget arguments are typed", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/c.docx", buildZip([CONTENT_TYPES, DOC]));
    for (const key of ["max_member_bytes", "max_total_bytes", "max_members", "max_ratio"]) {
      const out = refused(await tool(DOC_PROBE, cwd, { path: "work/c.docx", [key]: 0 }));
      assert.match(out.error, new RegExp(key));
    }
  });
});
