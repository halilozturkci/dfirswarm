/**
 * archive_probe reads a doc_structure result by reference (the remaining half of the hand-off). `structure` names a result file of the
 * run; archive_probe reads it for a PDF or an OLE file, only after it has checked that the file lies inside the run with no link on the
 * way, is a regular file of bounded size, has doc_structure's shape, and describes a file of this one's size and name (a sha256, where
 * the result records one, must match). A result that fails any check is rejected with the reason and none of its content is shown. The
 * byte search stays a heuristic with status partial whatever the result says, and no reference declared means no new field.
 */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import { type Json, asJob, body, refused, withCwd } from "./pack-network-harness.ts";
import { ROOT } from "./tool-library-harness.ts";

const SCRIPT = join(ROOT, "packs", "encrypted-containers", "tools", "archive_probe", "run.py");

const PDF_PLAIN = Buffer.from("%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R /Size 2 >>\nstartxref\n0\n%%EOF\n");
const PDF_ENC = Buffer.from("%PDF-1.6\n1 0 obj << /Type /Catalog >> endobj\n2 0 obj << /Filter /Standard /V 4 /R 4 /P -3904 >> endobj\ntrailer << /Root 1 0 R /Encrypt 2 0 R /Size 3 >>\nstartxref\n0\n%%EOF\n");
const OLE = Buffer.concat([Buffer.from("d0cf11e0a1b11ae1", "hex"), Buffer.alloc(2048)]);

type Opts = Partial<{ tool: string; parser: string; status: string; bytes: number; path: string; found: unknown; basis: unknown; items: unknown; sha256: unknown; summary: unknown }>;
function result(file: string, size: number, o: Opts = {}): string {
  const doc: Json = {
    tool: o.tool ?? "doc_structure", parser: o.parser ?? "doc_structure/1", path: o.path ?? file, bytes: o.bytes ?? size, status: o.status ?? "complete",
    encryption_summary: o.summary !== undefined ? o.summary : { found: o.found === undefined ? true : o.found, basis: o.basis ?? "the newest trailer names an encryption dictionary, which was read",
      items: o.items ?? [{ where: "PDF trailer", handler: "Standard", revision: 4 }] },
  };
  if (o.sha256 !== undefined) doc.sha256 = o.sha256;
  return JSON.stringify(doc);
}

const call = async (cwd: string, args: Json): Promise<Json> => body(await asJob(SCRIPT, cwd, args));

test("a matching doc_structure result is read for a PDF, with its source named, beside the heuristic byte search", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "doc.pdf"), PDF_ENC);
    await mkdir(join(cwd, "store"), { recursive: true });
    await writeFile(join(cwd, "store", "structure.json"), result("doc.pdf", PDF_ENC.length));
    const a = await call(cwd, { path: "doc.pdf", structure: "store/structure.json" });
    assert.equal(a.structure_reading.accepted, true, JSON.stringify(a.structure_reading));
    assert.equal(a.structure_reading.encryption_found, true);
    assert.equal(a.structure_reading.matched_by, "size and name");
    assert.equal(a.structure_reading.item_summaries[0].handler, "Standard");
    assert.equal(a.structure_reading.declared, "store/structure.json");
    assert.equal(a.protected, null, "the byte search's own finding is still undetermined");
    assert.equal(a.status, "partial");
    assert.match(a.protection, /^heuristic/);
    assert.match(a.structure_reading.note, /no marker is not 'not encrypted'/);
    // the same for an OLE file, with found false
    await writeFile(join(cwd, "doc.doc"), OLE);
    await writeFile(join(cwd, "ole.json"), result("doc.doc", OLE.length, { found: false, basis: "none of the encryption structures this tool reads was found", items: [] }));
    const b = await call(cwd, { path: "doc.doc", structure: "ole.json" });
    assert.equal(b.structure_reading.accepted, true);
    assert.equal(b.structure_reading.encryption_found, false);
    assert.equal(b.protected, null);
  });
});

test("none declared: no structure_reading field, and the answer is the one it was", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "doc.pdf"), PDF_PLAIN);
    const a = await call(cwd, { path: "doc.pdf" });
    assert.equal("structure_reading" in a, false);
    assert.equal(a.status, "partial");
  });
});

test("a result for another file, a forged result and a result that is not doc_structure's are rejected with the reason and none of their content shown", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "doc.pdf"), PDF_ENC);
    const canary = "Zq" + randomBytes(12).toString("hex");
    const cases: Array<[string, string, RegExp]> = [
      ["other size", result("doc.pdf", PDF_ENC.length, { bytes: PDF_ENC.length + 1, basis: canary }), /another size/],
      ["other name", result("elsewhere.pdf", PDF_ENC.length, { basis: canary }), /another name/],
      ["wrong tool", result("doc.pdf", PDF_ENC.length, { tool: "doc_probe", basis: canary }), /not a doc_structure result/],
      ["wrong parser", result("doc.pdf", PDF_ENC.length, { parser: "other/1", basis: canary }), /not a doc_structure result/],
      ["failed", result("doc.pdf", PDF_ENC.length, { status: "failed", basis: canary }), /status is not complete or partial/],
      ["found as a number", result("doc.pdf", PDF_ENC.length, { found: 1, basis: canary }), /no usable encryption_summary/],
      ["found as text", result("doc.pdf", PDF_ENC.length, { found: "yes", basis: canary }), /no usable encryption_summary/],
      ["no summary", result("doc.pdf", PDF_ENC.length, { summary: "x" + canary }), /no usable encryption_summary/],
      ["bytes as text", result("doc.pdf", PDF_ENC.length, { bytes: String(PDF_ENC.length) as unknown as number, basis: canary }), /another size/],
      ["sha256 of another file", result("doc.pdf", PDF_ENC.length, { sha256: createHash("sha256").update("other").digest("hex"), basis: canary }), /sha256 is not this file's/],
      ["sha256 not hex", result("doc.pdf", PDF_ENC.length, { sha256: "zz", basis: canary }), /not a sha256/],
      ["not JSON", "this is not json " + canary, /could not be read as JSON/],
      ["a list", "[1,2]", /not a doc_structure result/],
      ["huge integer", '{"bytes": ' + "9".repeat(6000) + "}", /could not be read as JSON/],
      ["deep nesting", "[".repeat(200000), /could not be read as JSON/],
      ["lone surrogate", '{"tool":"\\ud800"}', /not a doc_structure result/],
    ];
    for (const [label, text, why] of cases) {
      await writeFile(join(cwd, "r.json"), text);
      const run = await asJob(SCRIPT, cwd, { path: "doc.pdf", structure: "r.json" });
      const a = body(run);
      assert.equal(a.structure_reading.accepted, false, label);
      assert.match(a.structure_reading.rejected, why, label);
      assert.ok(!run.stdout.includes(canary), `${label}: the content of a rejected result is shown`);
      assert.equal(a.status, "partial", label);
    }
  });
});

test("a result that records the file's sha256 is accepted only when it is this file's", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "doc.pdf"), PDF_ENC);
    await writeFile(join(cwd, "r.json"), result("doc.pdf", PDF_ENC.length, { sha256: createHash("sha256").update(PDF_ENC).digest("hex").toUpperCase() }));
    const a = await call(cwd, { path: "doc.pdf", structure: "r.json" });
    assert.equal(a.structure_reading.accepted, true);
    assert.equal(a.structure_reading.matched_by, "size and name and sha256");
  });
});

test("a result outside the run, behind a link, a directory, a FIFO or a missing file is rejected, and a FIFO does not hold the tool", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "doc.pdf"), PDF_ENC);
    await mkdir(join(cwd, "sub"), { recursive: true });
    await writeFile(join(cwd, "good.json"), result("doc.pdf", PDF_ENC.length));
    await symlink(join(cwd, "good.json"), join(cwd, "link.json"));
    await symlink(join(cwd, "sub"), join(cwd, "linked-dir"));
    await writeFile(join(cwd, "sub", "r.json"), result("doc.pdf", PDF_ENC.length));
    assert.equal(spawnSync("mkfifo", [join(cwd, "pipe.json")]).status, 0);
    for (const [label, spec, why] of [
      ["parent directory", "../outside.json", /not a file inside the run/],
      ["absolute outside", "/etc/passwd", /not a file inside the run/],
      ["a link", "link.json", /link is on the way/],
      ["a link in the path", "linked-dir/r.json", /link is on the way/],
      ["a directory", "sub", /not a regular file/],
      ["missing", "nothing.json", /could not be read as JSON/],
      ["a FIFO", "pipe.json", /not a regular file/],
    ] as Array<[string, string, RegExp]>) {
      const started = Date.now();
      const a = await call(cwd, { path: "doc.pdf", structure: spec });
      assert.equal(a.structure_reading.accepted, false, label);
      assert.match(a.structure_reading.rejected, why, label);
      assert.ok(Date.now() - started < 15_000, label);
    }
  });
});

test("a result for a container that is not a PDF or an OLE file is not used", async () => {
  await withCwd(async (cwd) => {
    const zip = Buffer.concat([Buffer.from("504b0506", "hex"), Buffer.alloc(18)]);
    await writeFile(join(cwd, "a.zip"), zip);
    await writeFile(join(cwd, "r.json"), result("a.zip", zip.length));
    const a = await call(cwd, { path: "a.zip", structure: "r.json" });
    assert.equal(a.structure_reading.accepted, false);
    assert.match(a.structure_reading.rejected, /PDF or an OLE compound file only/);
  });
});

test("hostile values of structure are JSON refusals", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "doc.pdf"), PDF_ENC);
    for (const structure of [5, "", "a\u0000b", "x".repeat(5000), ["a"], {}, true]) {
      const a = refused(await asJob(SCRIPT, cwd, { path: "doc.pdf", structure }));
      assert.equal(a.status, "failed", JSON.stringify(structure));
    }
    await writeFile(join(cwd, "r.json"), "{}");
    const lone = body(await asJob(SCRIPT, cwd, { path: "doc.pdf", structure: "\ud800.json" }));
    assert.equal(lone.structure_reading.accepted, false);
  });
});
