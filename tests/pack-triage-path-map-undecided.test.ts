/**
 * triage-collection: collection_path_map no longer labels a delivered file `hypothesis_only` ("no record names it") when the per-file record
 * below whose directory it lies was not read whole: an unread row may name it. verify and coverage already counted that case apart
 * (delivered_files_not_decided_the_record_was_not_read_whole); path_map now gives the row its own status,
 * `undecided_record_not_read_whole`, counted in by_status, said in by_status_basis and listed in the manifest.
 * A record that is not read whole here is a copy log written in UTF-16 (a documented cause: the readers refuse a file that is not UTF-8 text)
 * and a Velociraptor uploads.json in UTF-16.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { KAPE_COPY_HEADER, TOOLS, body, kapeCopyRow, put, tool, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";
import { createHash } from "node:crypto";

const PATH_MAP = join(TOOLS, "collection_path_map", "run.py");
const utf16 = (text: string) => Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]);
const status = (out: Json, rel: string) => (out.mappings as Json[]).find((r) => r.delivered === rel)?.status;

test("a file below a copy log that was not read whole is undecided, not hypothesis_only; below one read whole it is hypothesis_only", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "cut/C/a.txt", "aaaa");
    await put(cwd, "cut/C/stray.txt", "stray");
    await put(cwd, "cut/r_CopyLog.csv", utf16(`${KAPE_COPY_HEADER}\n`));
    const cut = body(await tool(PATH_MAP, cwd, { root: "cut" }));
    assert.equal(cut.status, "partial", "the answer is partial where a record is not read whole");
    assert.equal(status(cut, "C/a.txt"), "undecided_record_not_read_whole", JSON.stringify(cut.by_status));
    assert.equal(status(cut, "C/stray.txt"), "undecided_record_not_read_whole");
    assert.equal(cut.by_status.undecided_record_not_read_whole, 2, "counted in by_status");
    assert.equal(cut.by_status.hypothesis_only, undefined, "no file is called one that no record names");
    assert.match(cut.by_status_basis, /undecided_record_not_read_whole: no row that was read names it/);
    assert.equal(status(cut, "r_CopyLog.csv"), "collector_record", "the record itself is still a collector record");

    // the same tree with the copy log read whole: a.txt is named, stray.txt is named by no record
    const sha1 = createHash("sha1").update("aaaa").digest("hex").toUpperCase();
    const row = kapeCopyRow("C:\\a.txt", "D:\\o\\C\\a.txt", 4).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", sha1);
    await put(cwd, "whole/C/a.txt", "aaaa");
    await put(cwd, "whole/C/stray.txt", "stray");
    await put(cwd, "whole/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${row}\n`);
    const whole = body(await tool(PATH_MAP, cwd, { root: "whole" }));
    assert.equal(status(whole, "C/a.txt"), "observed");
    assert.equal(status(whole, "C/stray.txt"), "hypothesis_only");
    assert.equal(whole.by_status.undecided_record_not_read_whole, undefined);
  });
});

test("a file below a Velociraptor uploads.json that was not read whole is undecided, and one outside the uploads directory is not", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "v/uploads.json", utf16("{}\n"));
    await put(cwd, "v/uploads/auto/x.txt", "x");
    await put(cwd, "v/notes.txt", "outside the uploads directory");
    const out = body(await tool(PATH_MAP, cwd, { root: "v" }));
    assert.equal(status(out, "v/uploads/auto/x.txt".replace(/^v\//, "")), "undecided_record_not_read_whole", JSON.stringify(out.mappings));
    assert.equal(status(out, "notes.txt"), "hypothesis_only", "the per-file record does not cover a file outside its directory");
  });
});

test("every row status the code can give is in the manifest, and in the status text of the answer", async () => {
  const code = await readFile(join(TOOLS, "collection_path_map", "run.py"), "utf8");
  const manifest = (JSON.parse(await readFile(join(TOOLS, "collection_path_map", "manifest.json"), "utf8")) as Json).description as string;
  const statuses = new Set([...code.matchAll(/^\s+status = "([a-z_]+)"$/gm)].map((m) => m[1]));
  assert.ok(statuses.has("undecided_record_not_read_whole") && statuses.has("hypothesis_only") && statuses.size >= 6, [...statuses].join(","));
  await withCwd(async (cwd) => {
    await put(cwd, "e/a.txt", "x");
    const basis = body(await tool(PATH_MAP, cwd, { root: "e" })).by_status_basis as string;
    for (const s of statuses) {
      assert.match(manifest, new RegExp(s), `the manifest lists ${s}`);
      assert.match(basis, new RegExp(s), `the status text says ${s}`);
    }
  });
});
