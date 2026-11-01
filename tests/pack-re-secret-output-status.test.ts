/**
 * doc_probe, doc_structure and pe_directories (reverse-engineering): the values mode (`write_values`) is declared as secret output in the manifest and
 * checked by the tool, and every refusal is one JSON answer with the status pair.
 *
 *  - the manifest carries `secret_output: { when_args: ["write_values"] }`, a form the harness accepts (parseSecretDeclaration), and the description says SENSITIVE;
 *  - in a job that is not run as secret output (JOB_ID and OUT set, SECRET_OUTPUT not 1) the values mode is refused as JSON, before anything is created in
 *    $OUT, and so it is outside a job; in a job run as secret output (SECRET_OUTPUT=1) doc_probe writes its values file, mode 0600;
 *  - given nothing, a path that is not there and a path of the wrong type, each tool answers `status` failed and a `status_basis`, exit 1.
 */
import assert from "node:assert/strict";
import { crc32 } from "node:zlib";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { parseSecretDeclaration } from "../scripts/output-hygiene.ts";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";

const TOOLS = ["doc_probe", "doc_structure", "pe_directories"];
const script = (tool: string): string => join(ROOT, "packs", "reverse-engineering", "tools", tool, "run.py");

/** A ZIP of stored members (APPNOTE 4.3): local headers, the central directory and the end record. */
function zip(members: Record<string, string>): Buffer {
  const local: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const [name, text] of Object.entries(members)) {
    const data = Buffer.from(text, "utf8");
    const nameBytes = Buffer.from(name, "utf8");
    const crc = crc32(data);
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0);
    head.writeUInt16LE(20, 4);
    head.writeUInt32LE(crc, 14);
    head.writeUInt32LE(data.length, 18);
    head.writeUInt32LE(data.length, 22);
    head.writeUInt16LE(nameBytes.length, 26);
    local.push(head, nameBytes, data);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameBytes.length, 28);
    cd.writeUInt32LE(offset, 42);
    central.push(cd, nameBytes);
    offset += head.length + nameBytes.length + data.length;
  }
  const dir = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(members).length, 8);
  end.writeUInt16LE(Object.keys(members).length, 10);
  end.writeUInt32LE(dir.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, dir, end]);
}

const RELS = '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
  + '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="http://files.example.org/template.dotm" TargetMode="External"/>'
  + "</Relationships>";

test("the three manifests declare secret_output for write_values, in a form the harness accepts, and say SENSITIVE", async () => {
  for (const tool of TOOLS) {
    const m = JSON.parse(await readFile(join(ROOT, "packs", "reverse-engineering", "tools", tool, "manifest.json"), "utf8")) as { secret_output: unknown; params: Record<string, { type: string }>; description: string };
    assert.deepEqual(m.secret_output, { when_args: ["write_values"] }, tool);
    assert.equal(parseSecretDeclaration(m.secret_output, m.params, true).ok, true, tool);
    assert.equal(m.params.write_values.type, "boolean", tool);
    assert.match(m.description, /SENSITIVE/, tool);
  }
});

for (const tool of TOOLS) {
  test(`${tool}: write_values is refused as JSON, before anything is created, in a job not run as secret output and outside a job`, async () => {
    await withCwd(async (cwd) => {
      await mkdir(join(cwd, "work"), { recursive: true });
      await mkdir(join(cwd, "out"), { recursive: true });
      await writeFile(join(cwd, "work", "doc.docx"), zip({ "word/_rels/document.xml.rels": RELS }));
      for (const [label, env] of [
        ["a job not run as secret output", { JOB_ID: "j000001", OUT: join(cwd, "out") }],
        ["no job", {}],
      ] as [string, Record<string, string>][]) {
        const r = await runPy(script(tool), cwd, { path: "work/doc.docx", write_values: true }, undefined, { AGENT_ID: "s1", ...env });
        const where = `${tool} in ${label}: exit ${r.code}, stdout ${r.stdout.slice(0, 200)}, stderr ${r.stderr.slice(-120)}`;
        assert.doesNotMatch(r.stderr, /Traceback/, where);
        const doc = JSON.parse(r.stdout) as { status?: string; error?: string; status_basis?: string };
        assert.equal(doc.status, "failed", where);
        assert.equal(r.code, 1, where);
        assert.match(String(doc.error), /write_values is refused outside a job/, where);
        assert.deepEqual(await readdir(join(cwd, "out")), [], `${where}: nothing is created in $OUT`);
      }
    });
  });

  test(`${tool}: given nothing, a missing path and a path of the wrong type it answers failed with a status_basis`, async () => {
    await withCwd(async (cwd) => {
      for (const [label, args] of [["{}", {}], ["a missing path", { path: "work/does-not-exist" }], ["a path of the wrong type", { path: 5 }]] as [string, unknown][]) {
        const r = await runPy(script(tool), cwd, args, undefined, { AGENT_ID: "s1" });
        const where = `${tool} given ${label}: exit ${r.code}, stdout ${r.stdout.slice(0, 200)}, stderr ${r.stderr.slice(-120)}`;
        assert.doesNotMatch(r.stderr, /Traceback/, where);
        const doc = JSON.parse(r.stdout) as { status?: string; status_basis?: string };
        assert.equal(doc.status, "failed", where);
        assert.equal(r.code, 1, where);
        assert.ok(typeof doc.status_basis === "string" && doc.status_basis.length > 0 &&!doc.status_basis.includes("\n"), where);
      }
    });
  });
}

test("doc_probe: in a job run as secret output (SECRET_OUTPUT=1) the values file is written, mode 0600", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work"), { recursive: true });
    await mkdir(join(cwd, "out"), { recursive: true });
    await writeFile(join(cwd, "work", "doc.docx"), zip({ "word/_rels/document.xml.rels": RELS }));
    const r = await runPy(script("doc_probe"), cwd, { path: "work/doc.docx", write_values: true }, undefined, { AGENT_ID: "s1", JOB_ID: "j000001", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    const doc = JSON.parse(r.stdout) as { status: string };
    assert.ok(["complete", "partial"].includes(doc.status), r.stdout.slice(0, 200));
    const file = join(cwd, "out", "doc-probe-values.jsonl");
    assert.equal(((await stat(file)).mode & 0o777).toString(8), "600");
  });
});
