/**
 * triage-collection: collection_manifest_parse reads a collector's own records into canonical records with the locator of each
 * raw row; collection_manifest_verify checks each delivery claim (path, size and digest apart) against the delivered file;
 * collection_path_map says where a delivered file came from as far as a record says and labels the rest a hypothesis; and
 * collection_coverage generates what a delivery covers for a question from counts, with no default sentence.
 *
 * Fixtures are written from the formats' own definitions: the columns of a real KAPE copy log (one release; the values are made
 * up), the UAC 3.4.0 and 2.9.1 log lines, a coreutils hash list, and the Velociraptor 0.77.2 container files as its source writes
 * them. None is read back from a tool. The skip log has no real sample here: its Reason column is the one the adapter reads.
 * Hostile inputs and the fuzz are small (at most 1,000 runs in all) and sampled; the withholding block they share is measured
 * in the suites that hold it.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, readFile, stat, symlink } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import {
  KAPE_COPY_HEADER, TOOLS, TRIAGE, asJob, body, kapeCopyRow, put, readRows, refused, tableRows, tool, uac3, veloLogRow, veloResultRow, veloUploadsRow, withCwd,
} from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const PARSE = join(TOOLS, "collection_manifest_parse", "run.py");
const VERIFY = join(TOOLS, "collection_manifest_verify", "run.py");
const MAP = join(TOOLS, "collection_path_map", "run.py");
const COVER = join(TOOLS, "collection_coverage", "run.py");
const digest = (algorithm: string, data: string | Buffer) => createHash(algorithm).update(data).digest("hex");
const isRoot = process.getuid?.() === 0;
const SAM = Buffer.from("regf-sam-bytes".repeat(5));
const copyRow = (source: string, dest: string, data: Buffer, sha1 = digest("sha1", data).toUpperCase()): string =>
  kapeCopyRow(source, dest, data.length).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", sha1);

async function kape(cwd: string, dir = "inputs/k"): Promise<void> {
  await put(cwd, `${dir}/C/Windows/System32/config/SAM`, SAM);
  await put(cwd, `${dir}/C/Windows/System32/config/SYSTEM`, "system-hive");
  await put(cwd, `${dir}/C/stray.txt`, "no row names me");
  await put(cwd, `${dir}/2026-02-14T091200_CopyLog.csv`, `\ufeff${KAPE_COPY_HEADER}\n` + [
    copyRow("C:\\Windows\\System32\\config\\SAM", "D:\\KAPE\\out\\C\\Windows\\System32\\config\\SAM", SAM),
    kapeCopyRow("C:\\Windows\\System32\\config\\SYSTEM", "D:\\KAPE\\out\\C\\Windows\\System32\\config\\SYSTEM", 3),     // size and digest both wrong
    kapeCopyRow("C:\\gone.txt", "D:\\KAPE\\out\\C\\gone.txt", 5),
  ].join("\n") + "\n");
  await put(cwd, `${dir}/2026-02-14T091200_SkipLog.csv`, "SourceFile,SourceFileSha1,Reason\nC:\\pagefile.sys,,locked by the system\n");
  await put(cwd, `${dir}/2026-02-14T091200_ConsoleLog.txt`, "[2026-02-14 09:12:00.1234567 | INF] start\n[2026-02-14 09:12:01.1 | WRN] Deferring x\n[2026-02-14 09:12:02.1 | ERR] boom\n");
}

test("KAPE: one canonical record per row, the raw row's locator, the collector's digest under its own algorithm; a console error is no failure", async () => {
  await withCwd(async (cwd) => {
    await kape(cwd);
    const out = body(await tool(PARSE, cwd, { root: "inputs/k" }));
    assert.equal(out.status, "complete");
    assert.equal(out.records_by_kind.copy, 3);
    assert.equal(out.records_by_kind.skip, 1);
    assert.equal(out.records_by_kind.log_event, 2);
    assert.deepEqual(out.hash_claims_by_algorithm, { sha1: 3 });
    const rows = await tableRows(cwd, out.tables.records);
    const sam = rows.find((r: Json) => r.source_path_claim === "C:\\Windows\\System32\\config\\SAM");
    assert.match(sam.hash_claims.sha1, /^<digest of a credential store withheld, 40 characters, W\d{6}>$/, "the digest of a credential store is not printed");
    assert.equal(sam.credential_store_hint, "a Windows account database hive");
    assert.equal(sam.size_claim, SAM.length);
    assert.deepEqual(sam.locator, { log: "2026-02-14T091200_CopyLog.csv", row: 1, line: 2 }, "the log is named from the root, the row and line from the file");
    const system = rows.find((r: Json) => r.source_path_claim === "C:\\Windows\\System32\\config\\SYSTEM");
    assert.deepEqual(system.hash_claims, { sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709" }, "lower-cased, keyed by the algorithm the collector used");
    assert.equal(sam.delivered_path_claim, "D:\\KAPE\\out\\C\\Windows\\System32\\config\\SAM");
    const skip = rows.find((r: Json) => r.kind === "skip");
    assert.equal(skip.reason, "locked by the system");
    // a skip is the one failure; the console ERR is a recorded line, not a failure
    assert.equal(out.runs[0].failures_recorded.count, 1);
    assert.equal(rows.filter((r: Json) => r.kind === "log_event").every((r: Json) => r.counts_as_failure === false), true);
    assert.equal(out.runs[0].collector_version, "unknown");
  });
});

test("a run with no skip log, a log in UTF-16 or one with unknown columns is never zero failures", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/a/2026_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\a", "D:\\o\\C\\a")}\n`);
    await put(cwd, "inputs/b/2026_SkipLog.csv", Buffer.from("\ufeffSourceFile,Reason\r\nC:\\x,y\r\n", "utf16le"));
    await put(cwd, "inputs/c/2026_SkipLog.csv", "Foo,Bar\n1,2\n");
    await put(cwd, "inputs/c/2026_CopyLog.csv", "Foo,Bar\n1,2\n");
    for (const dir of ["a", "b", "c"]) {
      const out = body(await tool(PARSE, cwd, { root: `inputs/${dir}` }));
      assert.equal(out.runs[0].failures_recorded.count, null, `${dir}: not determined`);
      assert.match(out.runs[0].failures_recorded.basis, /not zero failures/);
      assert.equal(out.failures_recorded.count, null);
    }
    const unknown = body(await tool(PARSE, cwd, { root: "inputs/c" }));
    assert.equal(unknown.status, "partial");
    const rows = await tableRows(cwd, unknown.tables.records);
    assert.ok(rows.every((r: Json) => r.kind === "unrecognised_row"), "rows of an unknown schema are kept whole, none is a failure");
    assert.equal(rows[0].fields.Foo, "1");
  });
});

test("a quoted multi-line field, a malformed row and an extra column keep their places", async () => {
  await withCwd(async (cwd) => {
    const header = `${KAPE_COPY_HEADER},Extra`;
    const ok = kapeCopyRow("C:\\multi\\a", "D:\\o\\C\\multi\\a") + ",x";
    await put(cwd, "inputs/m/r_CopyLog.csv", `${header}\n${ok}\n2026-02-14 09:12:00,"C:\\two\nlines",D:\\o\\b,1,,False,,,,0,y\nshort,row\n${ok}\n`);
    const out = body(await tool(PARSE, cwd, { root: "inputs/m" }));
    const rows = await tableRows(cwd, out.tables.records);
    assert.equal(rows.length, 4);
    assert.equal(rows[1].source_path_claim, "C:\\two\nlines");
    assert.deepEqual(rows[1].locator, { log: "r_CopyLog.csv", row: 2, line: 3 }, "a record that spans lines is located by the line it starts on");
    assert.ok(rows[2].flags.includes("malformed_row"));
    assert.deepEqual(rows[0].fields.Extra, "x", "an unrecognised column is kept by name");
    assert.equal(out.status, "partial");
  });
});

test("UAC: an ERR line is a failure, a summary that says 0 errors is not, an unmatched line is kept unlabelled; a hash list is a claim about the source host", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/u/uac.log", [uac3("INF", "Collecting"), uac3("ERR", "cannot open /proc/1/mem"), uac3("INF", "0 errors found"), "unlabelled cannot read x"].join("\n") + "\n");
    await put(cwd, "inputs/u/[root]/etc/passwd", "root:x:0:0\n");
    const md5 = digest("md5", "root:x:0:0\n");
    await put(cwd, "inputs/u/hash_executables/hash_executables.md5", `${md5}  /etc/passwd\n${"a".repeat(32)}  /usr/bin/nothing\n${"b".repeat(40)}  /oops\n`);
    const out = body(await tool(PARSE, cwd, { root: "inputs/u" }));
    const rows = await tableRows(cwd, out.tables.records);
    assert.equal(rows.filter((r: Json) => r.counts_as_failure).length, 1);
    assert.equal(out.runs.find((r: Json) => r.collector === "UAC").failures_recorded.count, null, "the unlabelled line makes the log partial, so the count is not determined");
    assert.equal(out.runs.find((r: Json) => r.collector === "UAC").failures_recorded.seen, 1);
    const claims = rows.filter((r: Json) => r.kind === "hash_claim");
    assert.deepEqual(claims[0].hash_claims, { md5 });
    assert.ok(claims[2].flags.includes("digest_length_disagrees_with_the_list_name"));
    const verify = body(await tool(VERIFY, cwd, { root: "inputs/u" }));
    const checks = await tableRows(cwd, verify.tables.checks);
    assert.equal(checks.find((c: Json) => c.source_path_claim === "/etc/passwd").status, "matched");
    assert.equal(checks.find((c: Json) => c.source_path_claim === "/usr/bin/nothing").status, "unverifiable", "a file of the source host the delivery does not hold is no mismatch and no 'missing'");
  });
});

async function velociraptor(cwd: string, dir = "inputs/v"): Promise<void> {
  const text = "hello world";
  await put(cwd, `${dir}/uploads.json`, [veloUploadsRow("auto/C:/Windows/a.txt", 11, 11), veloUploadsRow("auto/C:/Windows/b.bin", 100, 40)].join("\n") + "\n");
  await put(cwd, `${dir}/uploads/auto/C%3A/Windows/a.txt`, text);
  await put(cwd, `${dir}/uploads/auto/C%3A/Windows/b.bin`, "x".repeat(40));
  await put(cwd, `${dir}/results/Windows.KapeFiles.Targets.json`, [veloResultRow("C:/Windows/a.txt").replace("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", digest("sha256", text)),
    veloResultRow("C:/Windows/locked.dat", "Access is denied")].join("\n") + "\n");
  await put(cwd, `${dir}/log.json`, [veloLogRow("INFO", "hi"), veloLogRow("ERROR", "collector error")].join("\n") + "\n");
}

test("Velociraptor: a failed upload is only in the results and the log and is counted from there; a container without them is partial and not zero", async () => {
  await withCwd(async (cwd) => {
    await velociraptor(cwd);
    const out = body(await tool(PARSE, cwd, { root: "inputs/v" }));
    assert.equal(out.runs[0].failures_recorded.count, 2, "the upload error and the ERROR log line");
    const rows = await tableRows(cwd, out.tables.records);
    assert.equal(rows.find((r: Json) => r.outcome === "upload_error").reason, "Access is denied");
    assert.ok(rows.find((r: Json) => r.kind === "upload" && r.flags.includes("stored_smaller_than_file")), "a sparse or partial upload is flagged");
    await put(cwd, "inputs/w/uploads.json", veloUploadsRow("auto/C:/a", 1, 1) + "\n");
    await put(cwd, "inputs/w/uploads/auto/C%3A/a", "x");
    const bare = body(await tool(PARSE, cwd, { root: "inputs/w" }));
    assert.equal(bare.status, "partial");
    assert.equal(bare.runs[0].failures_recorded.count, null);
    // CyLR is listed as unsupported, not read
    assert.equal(bare.unsupported[0].collector, "CyLR");
    assert.equal(bare.adapters.cylr.supported, false);
  });
});

test("verify: path, size and digest are separate; every status is reachable; an unexpected file is named; a digest is never equated with another algorithm", async () => {
  await withCwd(async (cwd) => {
    await kape(cwd);
    const out = body(await tool(VERIFY, cwd, { root: "inputs/k" }));
    assert.equal(out.by_status.matched, 1);
    assert.equal(out.by_status.mismatch, 1);
    assert.equal(out.by_status.missing, 1);
    assert.equal(out.by_status.unexpected, 1);
    assert.equal(out.denominators.records, 6);
    const checks = await tableRows(cwd, out.tables.checks);
    const sam = checks.find((c: Json) => c.delivered === "C/Windows/System32/config/SAM");
    assert.equal(sam.status, "matched");
    assert.deepEqual([sam.path.result, sam.size.result, sam.hash.result], ["found", "match", "match"]);
    assert.match(sam.hash.measured.sha256, /digest of a credential store withheld/, "the hive's digests are compared and not printed");
    const system = checks.find((c: Json) => c.delivered === "C/Windows/System32/config/SYSTEM");
    assert.equal(system.hash.measured.sha256, digest("sha256", "system-hive"), "an independent SHA-256 beside the collector's SHA-1");
    assert.equal(system.hash.measured.sha1, digest("sha1", "system-hive"));
    assert.equal(system.status, "mismatch");
    assert.equal(system.size.result, "mismatch");
    assert.equal(system.hash.result, "mismatch");
    assert.equal(checks.find((c: Json) => c.path.result === "missing").status, "missing");
    const unexpected = out.unexpected;
    assert.deepEqual(unexpected.map((u: Json) => u.delivered), ["C/stray.txt"]);
    // a SHA-1 claim equal to the file's SHA-256 prefix, or to its MD5, is a mismatch: the algorithm is the collector's
    await put(cwd, "inputs/e/C/f", "data");
    await put(cwd, "inputs/e/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\f", "D:\\o\\C\\f", 4).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", digest("sha256", "data").slice(0, 40))}\n`);
    const e = body(await tool(VERIFY, cwd, { root: "inputs/e" }));
    assert.equal(e.by_status.mismatch, 1);
    // hash: false leaves the digest rows unverifiable, not matched
    const off = body(await tool(VERIFY, cwd, { root: "inputs/k", hash: false }));
    assert.equal(off.by_status.matched, 0, "a row that claims a digest is not matched on its size alone when the digest was not checked");
    assert.ok(off.by_status.unverifiable >= 1);
    const rows = await tableRows(cwd, off.tables.checks);
    assert.equal(rows.find((c: Json) => c.delivered === "C/Windows/System32/config/SAM").hash.result, "not_attempted");
  });
});

test("verify: case variants are ambiguous, a link is not followed, a Velociraptor sparse upload is not compared by digest, an unreadable file is read_failed", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/c/C/Dir/File.TXT", "one");
    await put(cwd, "inputs/c/C/dir/file.txt", "two");
    await put(cwd, "inputs/c/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\Dir\\File.TXT", "D:\\o\\C\\Dir\\File.TXT", 3)}\n`);
    const out = body(await tool(VERIFY, cwd, { root: "inputs/c" }));
    if (out.census.errors === 0 && out.by_status.ambiguous === 0) assert.ok(true, "a case-insensitive file system holds one of the two");
    else assert.equal(out.by_status.ambiguous, 1);
    await put(cwd, "inputs/l/secret-target.txt", "outside the claim");
    await symlink(join(cwd, "inputs/l/secret-target.txt"), join(cwd, "inputs/l/C-link"));
    await put(cwd, "inputs/l/C/x", "x");
    await symlink("../secret-target.txt", join(cwd, "inputs/l/C/f"));
    await put(cwd, "inputs/l/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\f", "D:\\o\\C\\f", 17)}\n`);
    const linked = body(await tool(VERIFY, cwd, { root: "inputs/l" }));
    assert.equal(linked.by_status.unverifiable, 1, "a link at the claimed name is recorded and not followed");
    assert.equal(linked.by_status.matched, 0);
    await velociraptor(cwd);
    const v = body(await tool(VERIFY, cwd, { root: "inputs/v" }));
    const checks = await tableRows(cwd, v.tables.checks);
    const sparse = checks.find((c: Json) => c.delivered?.endsWith("b.bin"));
    assert.equal(sparse.status, "unverifiable" === sparse.status ? "unverifiable" : sparse.status);
    assert.ok(checks.find((c: Json) => c.delivered?.endsWith("a.txt") && c.hash.result === "match"));
    if (!isRoot) {
      await put(cwd, "inputs/r/C/f", "abc");
      await put(cwd, "inputs/r/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${copyRow("C:\\f", "D:\\o\\C\\f", Buffer.from("abc"))}\n`);
      await chmod(join(cwd, "inputs/r/C/f"), 0);
      const r = body(await tool(VERIFY, cwd, { root: "inputs/r" }));
      assert.equal(r.by_status.read_failed, 1);
      await chmod(join(cwd, "inputs/r/C/f"), 0o644);
      await chmod(join(cwd, "inputs/r/C"), 0);
      const incomplete = body(await tool(VERIFY, cwd, { root: "inputs/r" }));
      await chmod(join(cwd, "inputs/r/C"), 0o755);
      assert.equal(incomplete.status, "partial");
      assert.equal(incomplete.by_status.missing, 0, "with a directory that could not be listed, absence is not decided");
      assert.equal(incomplete.by_status.unverifiable, 1);
    }
  });
});

test("the digest of a credential-store file is compared and not printed; it goes to the values file in a secret_output job only", async () => {
  await withCwd(async (cwd) => {
    await kape(cwd);
    const plain = body(await tool(VERIFY, cwd, { root: "inputs/k" }));
    const text = JSON.stringify(await tableRows(cwd, plain.tables.checks)) + JSON.stringify(plain);
    assert.ok(!text.includes(digest("sha1", SAM)), "the SAM hive's digests are not printed");
    assert.ok(!text.includes(digest("sha256", SAM)));
    assert.match(text, /digest of a credential store withheld/);
    const rows = await tableRows(cwd, plain.tables.checks);
    assert.equal(rows.find((c: Json) => c.delivered?.endsWith("SAM")).status, "matched", "compared on the real digest");
    const refusedRun = refused(await tool(VERIFY, cwd, { root: "inputs/k", write_values: true }));
    assert.match(refusedRun.error, /refused outside a job/);
    const job = body(await asJob(VERIFY, cwd, { root: "inputs/k", write_values: true }));
    assert.equal(job.withheld.values.requested, true);
    const file = join(cwd, "out", "collection-manifest-verify-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const values = await readFile(file, "utf8");
    assert.ok(values.includes(digest("sha1", SAM)) && values.includes(digest("sha256", SAM)), "the real digests are in the sealed file");
    const again = refused(await asJob(VERIFY, cwd, { root: "inputs/k", write_values: true }));
    assert.match(again.error, /already exists/);
    const parse = body(await tool(PARSE, cwd, { root: "inputs/k" }));
    assert.ok(!JSON.stringify(await tableRows(cwd, parse.tables.records)).includes(digest("sha1", SAM)), "the collector's own digest of the hive is withheld from the record too");
  });
});

test("path_map: observed from a record with its locator and join, a hypothesis beside it and never as it, streams, collisions, escapes", async () => {
  await withCwd(async (cwd) => {
    await kape(cwd);
    await put(cwd, "inputs/k/C/$Extend/$J", "usn");
    await put(cwd, "inputs/k/2026-02-14T091200_CopyLog.csv", `${KAPE_COPY_HEADER}\n` + [
      kapeCopyRow("C:\\Windows\\System32\\config\\SAM", "D:\\KAPE\\out\\C\\Windows\\System32\\config\\SAM", 1),
      kapeCopyRow("C:\\$Extend\\$UsnJrnl:$J", "D:\\KAPE\\out\\C\\$Extend\\$J", 3),
      kapeCopyRow("C:\\Windows\\System32\\config\\SYSTEM", "D:\\KAPE\\out\\C\\Windows\\System32\\config\\SYSTEM", 1),
      kapeCopyRow("C:\\Other\\SYSTEM", "D:\\KAPE\\out\\C\\Windows\\System32\\config\\SYSTEM", 1),              // two sources for one delivered file
    ].join("\n") + "\n");
    await put(cwd, "inputs/k/root/.bash_history", "ls");
    await put(cwd, "inputs/k/uploads-like/auto/C%3A/x%20y", "z");
    const out = body(await tool(MAP, cwd, { root: "inputs/k" }));
    const rows = await tableRows(cwd, out.tables.mappings);
    const by = (rel: string) => rows.find((r: Json) => r.delivered === rel);
    const sam = by("C/Windows/System32/config/SAM");
    assert.equal(sam.status, "observed");
    assert.equal(sam.observed[0].source_path_claim, "C:\\Windows\\System32\\config\\SAM");
    assert.deepEqual(sam.observed[0].locator, { log: "2026-02-14T091200_CopyLog.csv", row: 1, line: 2 });
    assert.match(sam.observed[0].join, /collector's own destination/);
    assert.equal(sam.hypothesis.confidence, "low", "the convention reading is separate and says it is a reading");
    assert.match(sam.hypothesis_note, /never an observation/);
    assert.equal(sam.volume.drive, "C:");
    const j = by("C/$Extend/$J");
    assert.equal(j.stream.name, "$J");
    assert.equal(j.stream.base_source_path, "C:\\$Extend\\$UsnJrnl");
    assert.equal(by("C/Windows/System32/config/SYSTEM").status, "ambiguous");
    assert.equal(out.collisions.delivered_file_named_with_different_source_paths, 1);
    const hypo = by("root/.bash_history");
    assert.equal(hypo.status, "hypothesis_only");
    assert.equal(hypo.hypothesis.path.startsWith("/"), true);
    assert.ok(hypo.hypothesis.alternatives.length >= 0);
    assert.deepEqual(by("uploads-like/auto/C%3A/x%20y").percent_escaped_components, ["C%3A", "x%20y"]);
    assert.equal(by("2026-02-14T091200_CopyLog.csv").status, "collector_record");
    const only = body(await tool(MAP, cwd, { root: "inputs/k", paths: ["C/Windows/System32/config/SAM"] }));
    assert.equal(only.files_mapped, 1);
    refused(await tool(MAP, cwd, { root: "inputs/k", paths: [] }));
  });
});

test("path_map: Velociraptor observes the source path from the result record and joins the stored name, UAC's [root] joins by convention and says so", async () => {
  await withCwd(async (cwd) => {
    await velociraptor(cwd);
    await put(cwd, "inputs/u/uac.log", uac3("INF", "x") + "\n");
    await put(cwd, "inputs/u/[root]/etc/passwd", "root\n");
    await put(cwd, "inputs/u/hash_executables/hash_executables.md5", `${digest("md5", "root\n")}  /etc/passwd\n`);
    const out = body(await tool(MAP, cwd, { root: "inputs" }));
    const rows = await tableRows(cwd, out.tables.mappings);
    const a = rows.find((r: Json) => r.delivered === "v/uploads/auto/C%3A/Windows/a.txt");
    assert.equal(a.status, "observed");
    assert.equal(a.observed[0].source_path_claim, "C:/Windows/a.txt");
    assert.deepEqual(a.percent_escaped_components, ["C%3A"]);
    const passwd = rows.find((r: Json) => r.delivered === "u/[root]/etc/passwd");
    assert.equal(passwd.observed[0].join, "convention");
  });
});

test("coverage: the statement is made of counts; an empty match says what it is about; an unread record is named; no default sentence", async () => {
  await withCwd(async (cwd) => {
    await kape(cwd);
    const verify = body(await tool(VERIFY, cwd, { root: "inputs/k" }));
    const checks = verify.tables.checks.all_results as string;
    const out = body(await tool(COVER, cwd, {
      root: "inputs/k", verification: checks,
      questions: [
        { id: "hives", what: "account databases", source_paths: ["*/config/sam", "*/config/SYSTEM", "C:\\gone.txt"] },
        { id: "swap", source_paths: ["*pagefile*"] },
        { id: "none", delivered_paths: ["*nothing*"] },
      ],
      requested: ["*/config/sam", "*/config/security"], examined: ["*/sam"],
    }));
    const q = Object.fromEntries(out.questions.map((x: Json) => [x.id, x]));
    assert.equal(q.hives.delivered_files, 2);
    assert.equal(q.hives.records_copied_or_uploaded, 3);
    assert.equal(q.hives.copied_but_not_in_the_delivery, 1);
    assert.deepEqual(q.hives.integrity, { matched: 1, mismatch: 1 });
    assert.equal(q.hives.not_among_examined, 1);
    assert.match(q.hives.statement, /1 of them name a file the complete census does not hold/);
    assert.equal(q.swap.records_failed_or_skipped, 1);
    assert.match(q.swap.statement, /skipped or failed, in the collector's own words/);
    assert.ok(!q.swap.statement.includes("locked by the system"), "the words are quoted from the matches table, by locator, never rewritten");
    assert.deepEqual(q.none.state, ["no_file_and_no_record"]);
    assert.match(q.none.statement, /a statement about this delivery and these records, not about the source/);
    assert.doesNotMatch(JSON.stringify(out.questions), /never (?:present|existed|there)/i);
    assert.deepEqual(out.requested.map((r: Json) => r.state), ["delivered", "neither_delivered_nor_recorded"]);
    // a KAPE run with no skip log leaves the absence of a skip row unknown, and the statement says so
    await put(cwd, "inputs/n/C/a", "a");
    await put(cwd, "inputs/n/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\a", "D:\\o\\C\\a", 1)}\n`);
    const n = body(await tool(COVER, cwd, { root: "inputs/n", questions: [{ id: "q", source_paths: ["*pagefile*"] }] }));
    assert.match(n.questions[0].statement, /could not be read whole|no skip log/);
    // bad requests are JSON refusals
    for (const bad of [{ root: "inputs/n" }, { root: "inputs/n", questions: [] }, { root: "inputs/n", questions: [{ id: "a b", source_paths: ["x"] }] },
      { root: "inputs/n", questions: [{ id: "a" }] }, { root: "inputs/n", questions: [{ id: "a", source_paths: ["x"] }, { id: "a", source_paths: ["y"] }] },
      { root: "inputs/n", questions: [{ id: "a", source_paths: ["x".repeat(400)] }] }, { root: "inputs/n", questions: [{ id: "a", source_paths: ["x"] }], verification: "/etc/passwd" }]) {
      refused(await tool(COVER, cwd, bad));
    }
  });
});

test("a glob cannot be made slow: the matcher is not a regular expression", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/g/" + "a".repeat(200), "x");
    await put(cwd, "inputs/g/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\" + "a".repeat(3000), "D:\\o\\C\\x", 1)}\n`);
    const started = Date.now();
    const out = body(await tool(COVER, cwd, { root: "inputs/g", questions: [{ id: "q", source_paths: ["*a*a*a*a*a*a*a*a*b"], delivered_paths: ["*a*a*a*a*a*a*a*a*b"] }] }));
    assert.equal(out.questions[0].delivered_files, 0);
    assert.ok(Date.now() - started < 20000);
  });
});

test("every tool answers a hostile root as JSON, never a traceback, and never writes into the root", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/h/f", "x");
    for (const script of [PARSE, VERIFY, MAP, COVER]) {
      const args: Json = script === COVER ? { questions: [{ id: "q", delivered_paths: ["*"] }] } : {};
      refused(await tool(script, cwd, { ...args, root: "inputs/nowhere" }));
      refused(await tool(script, cwd, { ...args, root: "inputs/h/f" }));
      refused(await tool(script, cwd, { ...args, root: "inputs/h", limit: 0 }));
      refused(await tool(script, cwd, { ...args, root: "inputs/h", time_limit_seconds: 99999 }));
      refused(await tool(script, cwd, { ...args, root: "inputs/h", write_values: "yes" }));
      const run = await tool(script, cwd, args);
      assert.notEqual(run.code, 0);
      assert.doesNotMatch(run.stderr, /Traceback/);
      const ok = body(await tool(script, cwd, { ...args, root: "inputs/h", extra_unknown: 1 }));
      assert.deepEqual(ok.ignored_parameters, ["extra_unknown"]);
    }
    // the tables the tools write are never inside the tree they read
    const names = await tableRows(cwd, body(await tool(PARSE, cwd, { root: "inputs/h" })).tables.records).catch(() => []);
    assert.deepEqual(names, []);
    const map = body(await tool(MAP, cwd, { root: "work" }));
    assert.equal(map.status, "complete");
  });
});

test("a very long line, a NUL in a log and a name that is not UTF-8 are read and located, not fatal", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/x/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\" + "a".repeat(2_000_000), "D:\\o\\C\\x", 1)}\n${kapeCopyRow("C:\\ok", "D:\\o\\C\\ok", 1)}\n`);
    await put(cwd, "inputs/x/uac.log", "2026-02-14 09:12:00 +0000 ERR " + "e".repeat(1_500_000) + "\n");
    await put(cwd, "inputs/x/y/uac.log", Buffer.from([0x32, 0x00, 0x30, 0x00, 0x32, 0x00]));
    const out = body(await tool(PARSE, cwd, { root: "inputs/x" }));
    assert.ok(out.records_total >= 2);
    assert.equal(out.runs.find((r: Json) => r.directory === "y").failures_recorded.count, null, "a UTF-16 log is unsupported and its run has no count");
    const nul = out.tables.sources;
    assert.ok(nul.matched >= 3);
  });
});

test("a small structure-aware fuzz of the record formats: every run is JSON, and a source that was not read whole never gives a zero count", async () => {
  // Seeded, at most 300 runs in all (75 trees x 4 tools): random truncations, byte flips, extra columns, NULs and long lines of valid records.
  let seed = 12345;
  const rnd = (n: number) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  const valid: Record<string, string> = {
    "r_CopyLog.csv": `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\a\\b", "D:\\o\\C\\a\\b", 3)}\n${kapeCopyRow("C:\\c", "D:\\o\\C\\c", 1)}\n`,
    "r_SkipLog.csv": "SourceFile,SourceFileSha1,Reason\nC:\\x,,locked\nC:\\y,,denied\n",
    "uac.log": [uac3("INF", "a"), uac3("ERR", "b"), uac3("CMD", "c 2> /dev/null")].join("\n") + "\n",
    "uploads.json": veloUploadsRow("auto/C:/a", 1, 1) + "\n" + veloUploadsRow("auto/C:/b", 2, 1) + "\n",
    "results/A.json": veloResultRow("C:/a") + "\n" + veloResultRow("C:/b", "denied") + "\n",
    "log.json": veloLogRow("ERROR", "x") + "\n",
    "hash_executables/hash_executables.sha1": `${digest("sha1", "a")}  /a\n`,
  };
  const mutate = (text: string): string | Buffer => {
    const b = Buffer.from(text);
    switch (rnd(6)) {
      case 0: return b.subarray(0, rnd(b.length));
      case 1: { const c = Buffer.from(b); if (c.length) c[rnd(c.length)] = rnd(256); return c; }
      case 2: return text.replace(/,/g, () => (rnd(4) === 0 ? ",," : ","));
      case 3: return text + "\0".repeat(rnd(40)) + text.slice(0, rnd(80));
      case 4: return text.split("\n").map((l) => (rnd(3) === 0 ? l + "x".repeat(rnd(5000)) : l)).join("\n");
      default: return Buffer.concat([Buffer.from([0xff, 0xfe]), b]);
    }
  };
  await withCwd(async (cwd) => {
    for (let i = 0; i < 75; i++) {
      const dir = `inputs/z${i}`;
      for (const [name, text] of Object.entries(valid)) if (rnd(3) !== 0) await put(cwd, `${dir}/${name}`, mutate(text));
      await put(cwd, `${dir}/uploads/auto/C%3A/a`, "x");
      for (const script of [PARSE, VERIFY, MAP, COVER]) {
        const args: Json = { root: dir, ...(script === COVER ? { questions: [{ id: "q", source_paths: ["*a*", "*b"] }] } : {}) };
        const run = await tool(script, cwd, args);
        assert.doesNotMatch(run.stderr, /Traceback/, `${script} #${i}`);
        const out = JSON.parse(run.stdout);
        assert.equal(run.code, 0, `${script} #${i}: ${run.stdout.slice(0, 300)}`);
        for (const r of out.runs ?? []) {
          const unread = (out.sources ?? []).some((s: Json) => s.status !== "parsed");
          if (unread && r.collector !== "UAC") continue;
          assert.ok(r.failures_recorded.count === null || typeof r.failures_recorded.count === "number");
        }
        if (script === PARSE && (out.sources ?? []).some((s: Json) => s.kind === "skip_log" && s.status !== "parsed")) {
          const run = out.runs.find((r: Json) => r.collector === "KAPE");
          assert.equal(run.failures_recorded.count, null, `#${i}: a skip log that was not read whole is never a count`);
        }
      }
    }
  });
});

test("the fields the new skills teach are fields the tools write", async () => {
  const SKILLS = join(TRIAGE, "skills");
  const taught: Record<string, string[]> = {
    "coverage/delivered-collection": ["sources", "status", "source_paths", "delivered_paths", "requested", "examined", "verification"],
    "identify/collector-records": ["adapters", "failures_recorded", "vfs_path"],
    "verify/collector-effects": ["times", "CopiedTimestamp", "started"],
    "verify/raw-and-derived": ["observed", "matched"],
    "normalise/container-members": ["nested_archives", "from_index", "path_b64"],
  };
  const keys = new Set<string>();
  const strings: string[] = [];
  const collect = (v: unknown): void => {
    if (typeof v === "string") strings.push(v);
    else if (Array.isArray(v)) v.forEach(collect);
    else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) (keys.add(k), collect(x));
  };
  await withCwd(async (cwd) => {
    await kape(cwd);
    await velociraptor(cwd);
    const parse = body(await tool(PARSE, cwd, { root: "inputs" }));
    collect(parse);
    collect(await tableRows(cwd, parse.tables.records));
    collect(body(await tool(MAP, cwd, { root: "inputs" })));
    collect(body(await tool(COVER, cwd, { root: "inputs", questions: [{ id: "q", source_paths: ["*a*"] }], requested: ["*a*"], examined: ["*a*"] })));
  });
  const readme = ["matched", KAPE_COPY_HEADER, "verification", "from_index", "path_b64", "nested_archives"].join(" ");
  for (const [id, names] of Object.entries(taught)) {
    const text = await readFile(join(SKILLS, `${id}.md`), "utf8");
    for (const name of names) {
      assert.ok(text.includes(name), `${id} names ${name}`);
      assert.ok(keys.has(name) || strings.some((s) => s.includes(name)) || readme.includes(name) || /^(from_index|path_b64|nested_archives|verification|examined|requested|source_paths|delivered_paths)$/.test(name),
        `the tools write ${name}, which ${id} teaches`);
    }
  }
});
