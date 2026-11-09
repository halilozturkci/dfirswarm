/**
 * triage-collection: the census of the four record tools. It grows only while the process holds less than 60% of the memory it may hold
 * (COLLECTION_MEMORY_BYTES, else the cgroup or address-space limit), as the recipe's pass does: past that it stops, partial, with JSON and
 * the reason, and no record is called missing. A name is joined NFC-normalised and then case-folded, so a name a macOS host wrote in
 * decomposed form is the file its precomposed record names. A link or a special file below a per-file record is listed with its kind.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { KAPE_COPY_HEADER, TOOLS, asJob, body, kapeCopyRow, link, put, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const PARSE = join(TOOLS, "collection_manifest_parse", "run.py");
const VERIFY = join(TOOLS, "collection_manifest_verify", "run.py");
const PATH_MAP = join(TOOLS, "collection_path_map", "run.py");
const COVERAGE = join(TOOLS, "collection_coverage", "run.py");
const sha1 = (data: string) => createHash("sha1").update(data).digest("hex").toUpperCase();

/** A copy log with one row (notes.txt, 5 bytes, "hello") at the root of the delivery, and the file it names. */
async function kape(cwd: string, root: string, extra: Array<[string, string]> = []): Promise<void> {
  const row = kapeCopyRow("C:\\Users\\a\\notes.txt", "D:\\o\\C\\Users\\a\\notes.txt", 5).replace("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", sha1("hello")).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", sha1("hello"));
  await put(cwd, `${root}/2026_run_CopyLog.csv`, `${KAPE_COPY_HEADER}\n${row}\n`);
  await put(cwd, `${root}/C/Users/a/notes.txt`, "hello");
  for (const [rel, data] of extra) await put(cwd, `${root}/${rel}`, data);
}

test("under a low memory bound each of the four tools ends partial, with JSON and the memory reason", async () => {
  await withCwd(async (cwd) => {
    await kape(cwd, "ev");
    // more entries than one memory check apart, in a directory the walk reaches after the root's own files
    await mkdir(join(cwd, "ev", "many"), { recursive: true });
    for (let i = 0; i < 1500; i++) await put(cwd, `ev/many/f${i}.txt`, "x");
    const calls: Array<[string, Json]> = [
      [PARSE, { root: "ev" }],
      [VERIFY, { root: "ev" }],
      [PATH_MAP, { root: "ev", paths: ["C:\\Users\\a\\notes.txt"] }],
      [COVERAGE, { root: "ev", questions: [{ id: "q1", source_paths: ["C:\\Users\\a\\notes.txt"] }] }],
    ];
    for (const [script, args] of calls) {
      const name = script.split("/").slice(-2)[0];
      const whole = body(await asJob(script, cwd, args, {}, `whole-${name}`));
      assert.doesNotMatch(String(whole.status_basis), /memory bound/, `${name}: no stop without a bound`);
      const out = body(await asJob(script, cwd, args, { COLLECTION_MEMORY_BYTES: "1" }, `low-${name}`));
      assert.equal(out.status, "partial", `${name}: ${out.status_basis}`);
      assert.match(String(out.status_basis), /memory bound/, `${name}: the reason is named`);
      assert.equal(out.census.complete, false, `${name}: the census says it is not complete`);
      assert.match(String(out.census.stopped?.reason), /memory bound/, `${name}: the census names the stop`);
    }
    // a record is not called missing because the census stopped
    const verify = body(await asJob(VERIFY, cwd, { root: "ev" }, { COLLECTION_MEMORY_BYTES: "1" }, "low-verify-2"));
    assert.equal(verify.by_status.missing, 0, "no record is called missing from a census that stopped");
    // a bound that is not a positive whole number is no bound
    for (const bad of ["0", "-5", "many", "9".repeat(400)]) {
      const out = body(await asJob(PARSE, cwd, { root: "ev" }, { COLLECTION_MEMORY_BYTES: bad }, "bad-bound"));
      assert.doesNotMatch(String(out.status_basis), /memory bound/, `a bound of ${bad.slice(0, 12)} is ignored`);
    }
  });
});

test("an NFC record paired with an NFD-named delivered file is matched, and the other way round too", async (t) => {
  await withCwd(async (cwd) => {
    const nfc = "\u00e9.txt";
    const nfd = "e\u0301.txt";
    await mkdir(join(cwd, "probe"), { recursive: true });
    await put(cwd, `probe/${nfd}`, "x");
    if (!(await readdir(join(cwd, "probe"))).includes(nfd)) return t.skip("this file system normalises names: an NFD name cannot be created here");
    for (const [recorded, delivered] of [[nfc, nfd], [nfd, nfc]]) {
      const root = `ev-${recorded === nfc ? "nfc" : "nfd"}`;
      const row = kapeCopyRow(`C:\\Users\\a\\${recorded}`, `D:\\o\\C\\Users\\a\\${recorded}`, 5).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", sha1("hello"));
      await put(cwd, `${root}/2026_run_CopyLog.csv`, `${KAPE_COPY_HEADER}\n${row}\n`);
      await put(cwd, `${root}/C/Users/a/${delivered}`, "hello");
      const out = body(await asJob(VERIFY, cwd, { root }, {}, `nfc-${root}`));
      assert.equal(out.by_status.matched, 1, JSON.stringify(out.by_status));
      assert.equal(out.by_status.missing, 0);
      assert.equal(out.by_status.unexpected, 0);
      assert.equal(out.status, "complete", out.status_basis);
      // the path map joins the supplied path the same way
      const map = body(await asJob(PATH_MAP, cwd, { root, paths: [`C:\\Users\\a\\${recorded}`] }, {}, `map-${root}`));
      assert.ok(!/missing/.test(JSON.stringify(map.by_status)) || map.by_status.missing === 0 || map.by_status.missing === undefined, JSON.stringify(map.by_status));
    }
  });
});

test("a symlink and a FIFO below a per-file record are listed with their kind, never followed, and counted", async () => {
  await withCwd(async (cwd) => {
    await kape(cwd, "ev");
    await link(join(cwd, "ev"), "C/Users/a/shortcut", "notes.txt");
    execFileSync("mkfifo", [join(cwd, "ev", "C", "Users", "a", "pipe")]);
    const out = body(await asJob(VERIFY, cwd, { root: "ev" }, {}, "links"));
    const rows = out.links_and_special_files as Json[];
    const kinds = Object.fromEntries(rows.map((r) => [String(r.delivered).split("/").pop(), r.kind]));
    assert.equal(kinds.shortcut, "link", JSON.stringify(rows));
    assert.equal(kinds.pipe, "special file", JSON.stringify(rows));
    assert.equal(rows.length, 2);
    assert.equal(out.denominators.links_and_special_files_in_scope_of_a_per_file_record, 2);
    assert.equal(out.by_status.unexpected, 0, "a link and a pipe are not delivered files");
    assert.equal(out.denominators.delivered_files_in_scope_of_a_per_file_record, 1, "notes.txt");
    assert.equal(out.by_status.matched, 1, "the file the record names is still matched, and nothing was followed or opened");
  });
});
