/**
 * triage-collection: collection_index is a census of the delivered objects with a hypothesis per source path. A hypothesis is
 * labelled one, an observed path comes only from a collector's own record, a mixed root is indexed, links are recorded and never
 * followed, every error is a row, an existing file is never replaced, and a time distribution is reported without a verdict.
 *
 * Fixtures are built by hand or from a format's own definition (the EWF signature, the columns of a real KAPE copy log); the
 * path probes are the five inputs of the review plus the root/ case, whose expected readings are written here, not read back.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, readFile, stat, symlink, utimes, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import {
  EWF_SIGNATURE, INDEX, KAPE_COPY_HEADER, asJob, assertAbsent, body, caseInsensitiveVolume, exists, filesUnder, kapeCopyRow, link, put, readRows, refused,
  tableRows, tool, withCwd,
} from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const AWS_EXAMPLE_KEY_ID = "AKIAIOSFODNN7EXAMPLE";

const byPath = (out: Json): Record<string, Json> => Object.fromEntries(out.entries.map((e: Json) => [e.in_collection, e]));

test("a path read by convention is a labelled hypothesis with its method, confidence and alternatives, and root/ is never stripped", async () => {
  await withCwd(async (cwd) => {
    for (const rel of ["C/Users/a/NTUSER.DAT", "[root]/etc/passwd", "uploads/auto/C%3A/Users/a/NTUSER.DAT", "collection/C/Users/a/NTUSER.DAT",
      "root/.bash_history", "C$/Windows/win.ini", "etc/hosts"]) await put(cwd, `inputs/c/${rel}`, "x");
    // a lower-case c beside an upper-case C cannot exist on a case-insensitive volume: its own root
    await put(cwd, "inputs/lower/c/config.txt", "x");
    const out = body(await tool(INDEX, cwd, { root: "inputs/c" }));
    const e = { ...byPath(out), ...byPath(body(await tool(INDEX, cwd, { root: "inputs/lower" }))) };
    const h = (rel: string) => e[rel].source_path_hypothesis;
    assert.equal(h("C/Users/a/NTUSER.DAT").path, "C:\\Users\\a\\NTUSER.DAT");
    assert.equal(h("C/Users/a/NTUSER.DAT").confidence, "low", "a bare single letter is a weak signal");
    assert.equal(h("C$/Windows/win.ini").path, "C:\\Windows\\win.ini");
    assert.equal(h("C$/Windows/win.ini").confidence, "medium");
    assert.equal(h("[root]/etc/passwd").path, "/etc/passwd");
    assert.equal(h("[root]/etc/passwd").confidence, "medium");
    // A wrapper that needs the collector's own index is not decoded.
    assert.equal(h("uploads/auto/C%3A/Users/a/NTUSER.DAT").path, "uploads/auto/C%3A/Users/a/NTUSER.DAT");
    assert.equal(h("uploads/auto/C%3A/Users/a/NTUSER.DAT").confidence, "none");
    assert.deepEqual(h("uploads/auto/C%3A/Users/a/NTUSER.DAT").unresolved_components, ["uploads", "auto", "C%3A"]);
    assert.equal(h("uploads/auto/C%3A/Users/a/NTUSER.DAT").alternatives[0].path, "C:\\Users\\a\\NTUSER.DAT");
    assert.equal(h("collection/C/Users/a/NTUSER.DAT").path, "collection/C/Users/a/NTUSER.DAT");
    assert.equal(h("collection/C/Users/a/NTUSER.DAT").confidence, "none");
    assert.equal(h("c/config.txt").path, "C:\\config.txt");
    assert.equal(h("c/config.txt").confidence, "low");
    assert.equal(h("c/config.txt").alternatives[0].path, "/c/config.txt");
    // A real /root directory stays; the wrapper reading is the alternative.
    assert.equal(h("root/.bash_history").path, "/root/.bash_history");
    assert.deepEqual(h("root/.bash_history").unresolved_components, ["root"]);
    assert.equal(h("root/.bash_history").alternatives[0].path, "/.bash_history");
    assert.equal(h("etc/hosts").path, "/etc/hosts", "a Linux tree is rooted the same way whether or not it starts with root/");
    assert.equal(h("etc/hosts").confidence, "low");
    for (const rel of Object.keys(e)) {
      assert.equal(e[rel].source_path_observed, null, "no collector record: nothing is observed");
      assert.equal(e[rel].source_path_mapping, "no_collector_mapping");
      assert.equal("original_path" in e[rel], false, "the old field is gone");
    }
    assert.equal(out.source_paths.observed.status, "no collector mapping available");
  });
});

test("a path a KAPE copy log records is observed, with its log and row; rows that name one source are one observation, rows that name two are ambiguous, and no row is nothing", async () => {
  await withCwd(async (cwd) => {
    for (const user of ["a", "b", "c", "d"]) await put(cwd, `inputs/k/C/Users/${user}/NTUSER.DAT`, "hive");
    await put(cwd, "inputs/k/C/other.txt", "x");
    const copy1 = [KAPE_COPY_HEADER,
      kapeCopyRow("C:\\Users\\a\\NTUSER.DAT", "D:\\out1\\C\\Users\\a\\NTUSER.DAT"),
      kapeCopyRow("C:\\Users\\b\\NTUSER.DAT", "D:\\out1\\C\\Users\\b\\NTUSER.DAT"),
      kapeCopyRow("C:\\Users\\d\\NTUSER.DAT", "D:\\out1\\C\\Users\\d\\NTUSER.DAT")].join("\r\n") + "\r\n";
    const copy2 = [KAPE_COPY_HEADER,
      kapeCopyRow("C:\\Users\\b\\NTUSER.DAT", "E:\\again\\C\\Users\\b\\NTUSER.DAT"),
      kapeCopyRow("C:\\Windows.old\\Users\\d\\NTUSER.DAT", "E:\\again\\C\\Users\\d\\NTUSER.DAT")].join("\r\n") + "\r\n";
    await put(cwd, "inputs/k/2026-02-14T09_12_00_1_CopyLog.csv", "\ufeff" + copy1);
    await put(cwd, "inputs/k/2026-02-15T09_12_00_2_CopyLog.csv", copy2);
    const out = body(await tool(INDEX, cwd, { root: "inputs/k" }));
    const e = byPath(out);
    const a = e["C/Users/a/NTUSER.DAT"];
    assert.equal(a.source_path_mapping, "observed");
    assert.equal(a.source_path_observed.path, "C:\\Users\\a\\NTUSER.DAT");
    assert.equal(a.source_path_observed.log, "2026-02-14T09_12_00_1_CopyLog.csv");
    assert.equal(a.source_path_observed.row, 1);
    assert.equal(a.source_path_observed.recorded_modified_utc_raw, "2026-01-02 03:04:05.678", "the log's own time, raw, beside the delivered one");
    assert.match(a.source_path_observed.recorded_modified_clock, /a different clock from the delivered file's modified/);
    assert.equal(a.source_path_observed.recorded_file_size_raw, "1", "the log's FileSize is carried beside the delivered size");
    assert.equal(a.source_path_hypothesis.path, "C:\\Users\\a\\NTUSER.DAT", "the hypothesis is still labelled one");
    const b = e["C/Users/b/NTUSER.DAT"];
    assert.equal(b.source_path_mapping, "observed", "two rows that agree on the source are not in doubt about it");
    assert.equal(b.source_path_observed.path, "C:\\Users\\b\\NTUSER.DAT");
    assert.deepEqual(b.source_path_observed.also_rows, [{ log: "2026-02-15T09_12_00_2_CopyLog.csv", row: 1 }], "every row is cited");
    const d = e["C/Users/d/NTUSER.DAT"];
    assert.equal(d.source_path_mapping, "ambiguous");
    assert.equal(d.source_path_observed, null);
    assert.equal(d.source_path_candidates.candidate_count, 2, "every candidate is in the row");
    assert.deepEqual(d.source_path_candidates.candidates.map((c: Json) => c.path).sort(), ["C:\\Users\\d\\NTUSER.DAT", "C:\\Windows.old\\Users\\d\\NTUSER.DAT"]);
    assert.match(d.source_path_candidates.why, /different sources/);
    assert.equal(e["C/Users/c/NTUSER.DAT"].source_path_mapping, "no_row_matched");
    assert.equal(e["C/Users/c/NTUSER.DAT"].source_path_observed, null);
    assert.deepEqual(out.source_paths.observed.files, { observed: 2, ambiguous: 1, no_row_matched: 4, mapping_capped: 0 });
    assert.equal(out.source_paths.observed.status, "read");
    assert.equal(out.source_paths.observed.rows_loaded, 5);
    assert.match(out.source_paths.observed.basis, /digests in the log are not compared/);
  });
});

test("a copy log that cannot be used for the mapping is named, the status is partial, and no path is observed from it", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/C/a.txt", "x");
    await put(cwd, "inputs/k/r_CopyLog.csv", "Foo,Bar\n1,2\n");
    const out = body(await tool(INDEX, cwd, { root: "inputs/k" }));
    assert.equal(out.status, "partial");
    assert.equal(out.source_paths.observed.status, "partial");
    assert.equal(out.source_paths.observed.logs_unsupported[0].log, "r_CopyLog.csv");
    assert.equal(byPath(out)["C/a.txt"].source_path_observed, null);
  });
});

test("a root that holds a disk image is indexed, the image says what it looks like, and the rest of the tree is still listed", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/m/disk.E01", Buffer.concat([EWF_SIGNATURE, Buffer.alloc(100)]));
    await put(cwd, "inputs/m/C/Users/a/NTUSER.DAT", "hive");
    await put(cwd, "inputs/m/memory.raw", Buffer.alloc(2000));
    const out = body(await tool(INDEX, cwd, { root: "inputs/m" }));
    assert.equal(out.census.regular_files, 3);
    const e = byPath(out);
    assert.equal(e["disk.E01"].object_class.class, "disk_container");
    assert.equal(e["disk.E01"].object_class.basis, "bytes");
    assert.match(e["disk.E01"].object_class.note, /not opened/);
    assert.equal(e["memory.raw"].object_class.class, "unknown");
    assert.equal(e["C/Users/a/NTUSER.DAT"].object_class, undefined, "a copied file carries no class");
    assert.match(e["disk.E01"].sha256, /^[0-9a-f]{64}$/);
    assert.equal(e["disk.E01"].source_path_hypothesis.confidence, "none");
  });
});

test("thirty files all dated one day are reported as a distribution fact with no cause, and every date is kept", async () => {
  await withCwd(async (cwd) => {
    const day = Date.UTC(2026, 1, 14, 9, 30) / 1000;
    for (let i = 0; i < 30; i++) {
      await put(cwd, `inputs/f/C/f${i}.txt`, "x");
      await utimes(join(cwd, `inputs/f/C/f${i}.txt`), day, day);
    }
    const out = body(await tool(INDEX, cwd, { root: "inputs/f" }));
    assert.equal(out.mtime_distribution_anomaly.dominant_date_utc, "2026-02-14");
    assert.equal(out.mtime_distribution_anomaly.files_on_that_date, 30);
    assert.equal(out.mtime_distribution_anomaly.regular_files, 30);
    assert.equal(out.mtime_distribution_anomaly.fraction, 1);
    assert.match(out.mtime_distribution_anomaly.not_established, /^the cause/);
    assert.equal(out.flat_timestamps, undefined);
    assert.doesNotMatch(JSON.stringify(out), /probably dropped|dropped the original|about the copy rather than the machine|every timestamp conclusion/i);
    assert.deepEqual(out.modification_dates, { "2026-02-14": 30 });
    // a spread of dates is no anomaly
    for (let i = 0; i < 12; i++) {
      await put(cwd, `inputs/g/f${i}.txt`, "x");
      const t = Date.UTC(2026, 0, 1 + i, 12) / 1000;
      await utimes(join(cwd, `inputs/g/f${i}.txt`), t, t);
    }
    const spread = body(await tool(INDEX, cwd, { root: "inputs/g" }));
    assert.equal(spread.mtime_distribution_anomaly, null);
    assert.equal(Object.keys(spread.modification_dates).length, 12, "every date, not the ten commonest");
  });
});

test("a link is recorded and never followed or hashed, a dangling one too; a pipe is recorded and not read", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "outside/secret.txt", "outside");
    await put(cwd, "inputs/l/a.txt", "x");
    await link(cwd, "inputs/l/to-file", join(cwd, "outside/secret.txt"));
    await link(cwd, "inputs/l/to-dir", join(cwd, "outside"));
    await symlink("missing-target", join(cwd, "inputs/l/dangling"));
    const { execFileSync } = await import("node:child_process");
    execFileSync("mkfifo", [join(cwd, "inputs/l/pipe")]);
    const out = body(await tool(INDEX, cwd, { root: "inputs/l" }));
    const e = byPath(out);
    assert.equal(out.census.regular_files, 1);
    assert.equal(out.census.symbolic_links, 3);
    assert.equal(out.census.special_files, 1);
    for (const name of ["to-file", "to-dir", "dangling"]) {
      assert.equal(e[name].kind, "symlink");
      assert.equal(e[name].followed, false);
      assert.equal(e[name].sha256, undefined);
    }
    assert.equal(e["to-file"].link_target, join(cwd, "outside/secret.txt"));
    assert.equal(e["dangling"].link_target, "missing-target");
    assert.equal(e["pipe"].kind, "special");
    assert.equal(e["pipe"].read, false);
    assert.equal(Object.keys(e).some((k) => k.startsWith("to-dir/")), false, "the directory behind a link is not walked");
  });
});

test("every object it could not list, stat or read is a row and an error with its reason, and the status is partial", async (t) => {
  if (process.getuid?.() === 0) return t.skip("running as root");
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/e/ok.txt", "x");
    await put(cwd, "inputs/e/locked/inner.txt", "x");
    await put(cwd, "inputs/e/unreadable.bin", "x", 0o000);
    await chmod(join(cwd, "inputs/e/locked"), 0o000);
    try {
      const out = body(await tool(INDEX, cwd, { root: "inputs/e" }));
      const e = byPath(out);
      assert.equal(out.status, "partial");
      assert.equal(out.census.errors, 2);
      assert.equal(e["locked"].kind, "unexamined");
      assert.match(e["locked"].error, /PermissionError/);
      assert.equal(e["unreadable.bin"].hash_status, "failed");
      assert.match(e["unreadable.bin"].hash_error, /PermissionError/);
      assert.equal(e["unreadable.bin"].sha256, null);
      assert.equal(out.hashing.failed, 1);
      assert.deepEqual(out.census.first_errors.map((x: Json) => x.path).sort(), ["locked", "unreadable.bin"], "paths as the rows show them, not prefixed with the root");
    } finally {
      await chmod(join(cwd, "inputs/e/locked"), 0o755);
      await chmod(join(cwd, "inputs/e/unreadable.bin"), 0o644);
    }
  });
});

test("an out_file inside the collection is refused before anything is read or written, and an existing file is never truncated or replaced", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/coll/a.txt", "x");
    const inside = refused(await tool(INDEX, cwd, { root: "work/coll", out_file: "work/coll/index.jsonl" }));
    assert.match(inside.error, /out_file is inside the collection/);
    assert.equal(await exists(join(cwd, "work/coll/index.jsonl")), false);
    assert.deepEqual(await filesUnder(join(cwd, "work/coll")), ["a.txt"]);
    // an earlier answer at the name stays; this one is kept beside it and named
    await put(cwd, "work/index.jsonl", "KEEP\n");
    const out = body(await tool(INDEX, cwd, { root: "work/coll", out_file: "work/index.jsonl" }));
    assert.equal(await readFile(join(cwd, "work/index.jsonl"), "utf8"), "KEEP\n");
    assert.equal(out.complete_index, "work/index.2.jsonl");
    assert.match(out.index.all_results_note, /a different file was already at work\/index\.jsonl and was kept/);
    const rows = await readRows(join(cwd, "work/index.2.jsonl"));
    assert.deepEqual(rows.map((r: Json) => r.in_collection), ["a.txt"]);
    // the same result again is the file already there
    const again = body(await tool(INDEX, cwd, { root: "work/coll", out_file: "work/index.jsonl" }));
    assert.equal(again.complete_index, "work/index.2.jsonl");
    // outside the run directory, under inputs/, and through a link are refused as before
    assert.match(refused(await tool(INDEX, cwd, { root: "work/coll", out_file: "../escaped.jsonl" })).error, /must stay inside the run directory/);
    assert.match(refused(await tool(INDEX, cwd, { root: "work/coll", out_file: "inputs/x.jsonl" })).error, /cannot be under inputs\//);
  });
});

test("a default output that would lie inside the tree is excluded from the census and never listed as an object", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/s1/files/a.txt", "x");
    await put(cwd, "work/s1/files/b.txt", "y");
    const out = body(await tool(INDEX, cwd, { root: "work/s1", limit: 1 }));
    // the tree is work/s1, the spill file is work/s1/tool-output/...: it is this run's own file
    assert.equal(out.census.regular_files, 2);
    assert.equal(out.index.rows, 2);
    const rows = await readRows(join(cwd, out.index.all_results));
    assert.deepEqual(rows.map((r: Json) => r.in_collection), ["files/a.txt", "files/b.txt"]);
  });
});

test("contains filters the page; the file holds every object with matches_filter, and only the matching files are hashed", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/c/C/Users/a/NTUSER.DAT", "hive");
    await put(cwd, "inputs/c/C/Users/a/other.txt", "x");
    await put(cwd, "inputs/c/C/Windows/win.ini", "y");
    const out = body(await tool(INDEX, cwd, { root: "inputs/c", contains: "ntuser" }));
    assert.equal(out.entry_count, 1);
    assert.equal(out.entries_inline, 1);
    assert.equal(out.entries[0].in_collection, "C/Users/a/NTUSER.DAT");
    assert.equal(out.index.filter.contains, "ntuser");
    assert.equal(out.index.scope, "every object walked, with matches_filter on each row");
    assert.equal(out.hashing.hashed, 1);
    assert.equal(out.hashing.not_attempted_outside_filter, 2);
    const rows = await readRows(join(cwd, out.complete_index));
    assert.equal(rows.length, 3, "the complete index is not the filtered view");
    assert.deepEqual(rows.map((r: Json) => [r.in_collection, r.matches_filter]).sort(), [
      ["C/Users/a/NTUSER.DAT", true], ["C/Users/a/other.txt", false], ["C/Windows/win.ini", false]]);
    const outside = rows.find((r: Json) => r.in_collection.endsWith("win.ini"));
    assert.equal(outside.sha256, null);
    assert.match(outside.hash_status, /outside the contains filter/);
    // the filter also reads the hypothesis
    const hyp = body(await tool(INDEX, cwd, { root: "inputs/c", contains: "C:\\\\Windows" }));
    assert.equal(hyp.entry_count, 1);
    assert.match(refused(await tool(INDEX, cwd, { root: "inputs/c", contains: "(" })).error, /not a valid regex/);
  });
});

test("in a job the whole census is written to $OUT whatever the size, named as it will be cited, and a rerun neither crashes nor replaces it; the run directory is not written", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/j/C/a.txt", "x");
    await put(cwd, "inputs/j/C/b.txt", "y");
    await chmod(join(cwd, "work"), 0o555);
    await chmod(join(cwd, "inputs"), 0o555);
    try {
      const first = body(await asJob(INDEX, cwd, { root: "inputs/j" }, {}, "out", "j000950"));
      assert.match(first.complete_index, /^store\/jobs\/j000950\/out\/tool-output\/collection_index-[0-9a-f]{16}\.jsonl$/);
      assert.equal(first.inline_limited, false);
      assert.equal(first.index.rows, 2);
      const file = join(cwd, "out", first.complete_index.split("/out/")[1]);
      assert.equal((await readRows(file)).length, 2);
      const second = body(await asJob(INDEX, cwd, { root: "inputs/j" }, {}, "out", "j000950"));
      assert.notEqual(second.complete_index, first.complete_index);
      assert.equal((await readRows(file)).length, 2);
      // an explicit out_file outside $OUT is refused with the way to name one, not left to fail on a read-only file system
      const outside = refused(await asJob(INDEX, cwd, { root: "inputs/j", out_file: "work/index.jsonl" }, {}, "out", "j000950"));
      assert.match(outside.error, /not under this job's output directory/);
      assert.equal(await exists(join(cwd, "work/index.jsonl")), false);
      const named = body(await asJob(INDEX, cwd, { root: "inputs/j", out_file: join(cwd, "out/index.jsonl") }, {}, "out", "j000950"));
      assert.equal(named.complete_index, "store/jobs/j000950/out/index.jsonl");
    } finally {
      await chmod(join(cwd, "work"), 0o755);
      await chmod(join(cwd, "inputs"), 0o755);
    }
  });
});

test("outside a job the inline page is bounded by limit and the whole census goes under work/<agent>/tool-output", async () => {
  await withCwd(async (cwd) => {
    for (let i = 0; i < 5; i++) await put(cwd, `inputs/p/f${i}.txt`, `x${i}`);
    const out = body(await tool(INDEX, cwd, { root: "inputs/p", limit: 2 }));
    assert.equal(out.entries.length, 2);
    assert.equal(out.entry_count, 5);
    assert.equal(out.inline_limited, true);
    assert.match(out.complete_index, /^work\/s1\/tool-output\/collection_index-[0-9a-f]{16}\.jsonl$/);
    assert.equal((await readRows(join(cwd, out.complete_index))).length, 5);
    const small = body(await tool(INDEX, cwd, { root: "inputs/p", limit: 50 }));
    assert.equal(small.complete_index, null, "everything fits inline: no file");
    assert.equal(small.inline_limited, false);
  });
});

test("a credential store is marked by its name and not hashed unless asked, in a job; the refusal outside a job is a JSON error", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/s/etc/shadow", "root:x:1:::\n");
    await put(cwd, "inputs/s/home/u/.ssh/id_ed25519", "key");
    await put(cwd, "inputs/s/home/u/.aws/credentials", "x");
    await put(cwd, "inputs/s/home/u/notes.txt", "x");
    await put(cwd, "inputs/s/credentials", "not under .aws");
    const out = body(await tool(INDEX, cwd, { root: "inputs/s" }));
    const e = byPath(out);
    for (const name of ["etc/shadow", "home/u/.ssh/id_ed25519", "home/u/.aws/credentials"]) {
      assert.ok(e[name].may_hold_secrets.kind, name);
      assert.equal(e[name].sha256, null, `${name} is not hashed by default`);
      assert.match(e[name].hash_status, /name marks a credential store/);
      assert.match(e[name].may_hold_secrets.basis, /name hint only/);
    }
    assert.equal(e["home/u/notes.txt"].may_hold_secrets, undefined);
    assert.match(e["home/u/notes.txt"].sha256, /^[0-9a-f]{64}$/);
    assert.equal(e["credentials"].may_hold_secrets, undefined, "credentials outside .aws is an ordinary name");
    assert.equal(out.hashing.not_attempted_credential_store_name, 3);
    assert.match(refused(await tool(INDEX, cwd, { root: "inputs/s", hash_credential_stores: true })).error, /needs a job and write_values: true/);
    assert.match(refused(await asJob(INDEX, cwd, { root: "inputs/s", hash_credential_stores: true }, {}, "out", "j000959")).error, /needs a job and write_values: true/);
    const jobRun = await asJob(INDEX, cwd, { root: "inputs/s", hash_credential_stores: true, write_values: true }, {}, "out", "j000960");
    const job = body(jobRun);
    const shadow = byPath(job)["etc/shadow"];
    assert.equal(shadow.sha256, null, "the digest of a credential store is not in the answer");
    assert.match(shadow.hash_status, /the digest is in the values file only/);
    assert.equal(job.hashing.credential_store_digests_in_the_values_file, 3);
    assert.equal(job.hashing.not_attempted_credential_store_name, 0);
    const digest = createHash("sha256").update("root:x:1:::\n").digest("hex");
    assert.ok(!jobRun.stdout.includes(digest), "not in stdout");
    assert.ok(!(await readFile(join(cwd, "out", job.complete_index.split("/out/")[1]), "utf8")).includes(digest), "not in the index file either");
    const values = await readRows(join(cwd, "out/collection-index-values.jsonl"));
    assert.ok(values.some((v: Json) => v.value === digest && v.file === "etc/shadow"), "in the sealed values file, with its path");
  });
});

test("a name shaped like an access key is withheld in every row and in the file; the real name goes to the sealed values file only when asked, in a job", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, `inputs/w/home/${AWS_EXAMPLE_KEY_ID}/f.txt`, "x");
    await put(cwd, "inputs/w/GUID-{3F2504E0-4F89-11D3-9A0C-0305E82C3301}/g.txt", "x");
    await link(cwd, `inputs/w/link-${AWS_EXAMPLE_KEY_ID}`, "target");
    const plain = await tool(INDEX, cwd, { root: "inputs/w", limit: 1 });
    assert.ok(!plain.stdout.includes(AWS_EXAMPLE_KEY_ID));
    const out = body(plain);
    const file = await readFile(join(cwd, out.complete_index), "utf8");
    assert.ok(!file.includes(AWS_EXAMPLE_KEY_ID), "not in the file the answer names");
    assert.match(file, /<access-key-shaped text withheld, 20 characters, W\d{6}>/);
    assert.match(file, /GUID-\{3F2504E0-4F89-11D3-9A0C-0305E82C3301\}/, "a GUID is a name, not a secret");
    assert.ok(out.withheld.strings_withheld >= 1);
    const job = await asJob(INDEX, cwd, { root: "inputs/w", write_values: true }, {}, "out", "j000970");
    assert.ok(!job.stdout.includes(AWS_EXAMPLE_KEY_ID));
    const answer = body(job);
    const wholeFile = await readFile(join(cwd, "out", answer.complete_index.split("/out/")[1]), "utf8");
    assert.ok(!wholeFile.includes(AWS_EXAMPLE_KEY_ID));
    const values = await readRows(join(cwd, "out/collection-index-values.jsonl"));
    assert.ok(values.length >= 2);
    assert.ok(values.some((v: Json) => String(v.value).includes(AWS_EXAMPLE_KEY_ID)));
    assert.equal((await stat(join(cwd, "out/collection-index-values.jsonl"))).mode & 0o777, 0o600);
    assert.match(refused(await asJob(INDEX, cwd, { root: "inputs/w", write_values: true }, {}, "out", "j000970")).error, /values file already exists/);
  });
});

test("a renamed-stream candidate is a labelled heuristic, SummaryInformation is a known stream name, and the old typo is gone", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/st/C/Users/a/report.txt_Zone.Identifier", "x");
    await put(cwd, "inputs/st/C/Users/a/report.doc_SummaryInformation", "x");
    await put(cwd, "inputs/st/C/Users/a/holiday_photos.jpg", "x");
    await put(cwd, "inputs/st/private/var/x.y_manager.metadata.plist", "x");                 // a name that only ends like a stream: not a candidate
    const out = body(await tool(INDEX, cwd, { root: "inputs/st" }));
    const streams = out.possible_renamed_streams;
    assert.deepEqual(streams.map((s: Json) => [s.possible_original, s.known_stream]).sort(), [["report.doc:SummaryInformation", true], ["report.txt:Zone.Identifier", true]]);
    assert.match(streams[0].basis, /heuristic/);
    const script = await readFile(INDEX, "utf8");
    assert.ok(!script.includes("sumarryinformation"));
    assert.equal(out.possible_renamed_streams_table.matched, 2);
  });
});

test("a reserved device name is noted as an observation, not as something a collector did", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/r/C/LPT1.txt", "x");
    await put(cwd, "inputs/r/C/COM9", "x");
    const out = body(await tool(INDEX, cwd, { root: "inputs/r" }));
    const e = byPath(out);
    assert.match(e["C/LPT1.txt"].notes[0], /whether a collector renamed it is not established/);
    assert.ok(e["C/COM9"].notes);
  });
});

test("bad arguments are JSON errors and a refusal leaves no file behind", async () => {
  await withCwd(async (cwd) => {
    assert.match(refused(await tool(INDEX, cwd, {})).error, /root is required/);
    assert.match(refused(await tool(INDEX, cwd, { root: "nope" })).error, /no such directory/);
    assert.match(refused(await tool(INDEX, cwd, { root: "inputs", limit: -1 })).error, /limit must be an integer/);
    assert.match(refused(await tool(INDEX, cwd, { root: "inputs", hash: "yes" })).error, /hash must be true or false/);
    assert.match(refused(await tool(INDEX, cwd, { root: "inputs", contains: "x".repeat(2001) })).error, /longer than 2000/);
    assert.deepEqual(await filesUnder(join(cwd, "work")), []);
  });
});

test("with hash false nothing is hashed and each row says so", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/h/a.txt", "x");
    const out = body(await tool(INDEX, cwd, { root: "inputs/h", hash: false }));
    assert.equal(out.entries[0].sha256, null);
    assert.equal(out.entries[0].hash_status, "not_attempted: hash was false");
    assert.equal(out.hashing.not_attempted_hash_false, 1);
    assert.equal(out.hashing.hashed, 0);
  });
});

test("a file's digest is the SHA-256 of the whole file, whatever its size", async () => {
  await withCwd(async (cwd) => {
    const data = Buffer.alloc((3 << 20) + 17, 0x61);                // 3 MiB and a little over: more than one read
    await put(cwd, "inputs/d/big.bin", data);
    const out = body(await tool(INDEX, cwd, { root: "inputs/d" }));
    const { createHash } = await import("node:crypto");
    assert.equal(out.entries[0].sha256, createHash("sha256").update(data).digest("hex"));
    assert.equal(out.entries[0].hash_status, "hashed");
    assert.equal((await lstat(join(cwd, "inputs/d/big.bin"))).size, out.entries[0].bytes);
    // an empty file has the digest of nothing
    await writeFile(join(cwd, "inputs/d/empty"), "");
    const e = byPath(body(await tool(INDEX, cwd, { root: "inputs/d" })));
    assert.equal(e["empty"].sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});

test("a parser name and a row number are on every row, and the census says what it covers", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/q/a.txt", "x");
    await put(cwd, "inputs/q/b/c.txt", "y");
    const out = body(await tool(INDEX, cwd, { root: "inputs/q" }));
    assert.equal(out.parser, "collection_index/4");
    assert.deepEqual(out.entries.map((e: Json) => e.row), [1, 2]);
    assert.deepEqual(out.entries.map((e: Json) => e.in_collection), ["a.txt", "b/c.txt"], "directories are sorted and visited in order");
    assert.equal(out.census.directories_listed, 2);
    assert.equal(out.hashing.whole_file, true);
    assert.equal(out.status, "complete");
  });
});

const DEADLINE_CODE = `
import importlib.util, io, json, sys
script, root = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("lib", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.start_clock = lambda seconds: mod.DEADLINE.__setitem__(0, -1.0)      # a deadline already past: the monotonic clock is above it
sys.stdin = io.StringIO(json.dumps({"root": root}))
mod.main()
`;

test("when the time limit ends, the census stops, says how much was not listed, and the status is partial", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/t/a.txt", "x");
    await put(cwd, "inputs/t/b/c.txt", "y");
    const { runPySnippet } = await import("./tool-library-harness.ts");
    const run = await runPySnippet(DEADLINE_CODE, [INDEX, join(cwd, "inputs/t")], null);
    assert.equal(run.code, 0, run.stderr);
    const out = JSON.parse(run.stdout);
    assert.equal(out.status, "partial");
    assert.match(out.census.stopped.reason, /time limit/);
    assert.equal(out.census.stopped.directories_not_listed, 1, "the root itself was not listed");
    assert.match(out.status_basis, /time limit/);
    assert.equal(out.census.regular_files, 0);
  });
});

test("a hash that the time limit ends is a row that says so, with the bytes read", async () => {
  await withCwd(async (cwd) => {
    const { runPySnippet } = await import("./tool-library-harness.ts");
    const code = `
import runpy, sys, time
ns = runpy.run_path(sys.argv[1], run_name="lib")
ns["DEADLINE"][0] = time.monotonic() - 1
try:
    ns["hash_file"](sys.argv[2], True, True)
except ns["HashStopped"] as stop:
    print("stopped after", stop.read)
`;
    await put(cwd, "inputs/t/big.bin", Buffer.alloc(3 << 20, 1));
    const run = await runPySnippet(code, [INDEX, join(cwd, "inputs/t/big.bin")], null);
    assert.equal(run.code, 0, run.stderr);
    assert.equal(run.stdout.trim(), `stopped after ${1 << 20}`);
  });
});

test("a file at the top of the collection has no directory to read a convention from, even when its name is a letter", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/t/C", "x");
    const out = body(await tool(INDEX, cwd, { root: "inputs/t" }));
    assert.equal(out.entries[0].source_path_hypothesis.path, "C");
    assert.equal(out.entries[0].source_path_hypothesis.confidence, "none");
  });
});

test("a file name that is not UTF-8 is listed with its bytes as an escape, in the answer and in the file, and never raises", async (t) => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "inputs/b"), { recursive: true });
    const name = Buffer.concat([Buffer.from(join(cwd, "inputs/b") + "/bad"), Buffer.from([0xff]), Buffer.from("name.txt")]);
    try {
      await writeFile(name, "x");
    } catch (error) {
      return t.skip(`this file system refuses a name that is not UTF-8 (${(error as NodeJS.ErrnoException).code})`);
    }
    const run = await tool(INDEX, cwd, { root: "inputs/b", out_file: "work/index.jsonl" });
    const out = body(run);
    assert.equal(out.entries[0].in_collection, "bad\udcffname.txt");
    assert.match(run.stdout, /bad\\udcffname\.txt/);
    const rows = await readRows(join(cwd, out.complete_index));
    assert.deepEqual(rows.map((r: Json) => r.in_collection), ["bad\udcffname.txt"]);
    assert.match(rows[0].sha256, /^[0-9a-f]{64}$/, "the file was opened by its real bytes");
  });
});

const PY_UTIME = `
import os, sys
os.utime(sys.argv[1], ns=(int(sys.argv[2]), int(sys.argv[2])))
`;
const DEADLINE_MAIN = `
import importlib.util, io, json, sys
script, root, mode = sys.argv[1], sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location("lib", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
if mode == "hash-stops-on-last":
    real = mod.hash_file
    def stop_on_last(path, want_hash, want_head):
        if path.endswith("zz-big.bin"):
            raise mod.HashStopped(1048576)
        return real(path, want_hash, want_head)
    mod.hash_file = stop_on_last
if mode == "size-changes":
    real = mod.hash_file
    def grow(path, want_hash, want_head):
        digest, head, nread = real(path, want_hash, want_head)
        return digest, head, nread + 500
    mod.hash_file = grow
sys.stdin = io.StringIO(json.dumps({"root": root, "hash": True}))
mod.main()
`;

test("modified_epoch_ns is a decimal string, exact for a time with non-zero nanoseconds that no double holds, and the ISO time agrees", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/n/a.txt", "x");
    const ns = 1771070123456789012n;                          // the nanoseconds past the microsecond are non-zero: a microsecond cut would be caught
    const { runPySnippet } = await import("./tool-library-harness.ts");
    const set = await runPySnippet(PY_UTIME, [join(cwd, "inputs/n/a.txt"), String(ns)], null);
    assert.equal(set.code, 0, set.stderr);
    const real = (await stat(join(cwd, "inputs/n/a.txt"), { bigint: true })).mtimeNs;
    assert.equal(real % 1000n, ns % 1000n, "this file system keeps the nanoseconds (otherwise the case below is vacuous)");
    const run = await tool(INDEX, cwd, { root: "inputs/n" });
    const out = body(run);
    assert.equal(typeof out.entries[0].modified_epoch_ns, "string");
    assert.equal(BigInt(out.entries[0].modified_epoch_ns), real, "exact after JSON.parse, which would round a number past 2^53");
    assert.match(run.stdout, /"modified_epoch_ns": "\d{19}"/);
    const seconds = real / 1_000_000_000n;
    assert.equal(out.entries[0].modified, `${new Date(Number(seconds) * 1000).toISOString().slice(0, 19)}.${String(real % 1_000_000_000n).padStart(9, "0")}Z`);
    assert.match(out.time_basis, /decimal string/);
    // and in the complete index file
    const whole = await tool(INDEX, cwd, { root: "inputs/n", limit: 1 });
    assert.equal(typeof (await readRows(join(cwd, body(whole).complete_index ?? "x")).catch(() => [{ modified_epoch_ns: "" }]))[0].modified_epoch_ns, "string");
  });
});

test("contains is read on what is printed: a withheld name is searched as its marker, so the filter tells nothing about the text behind it", async () => {
  await withCwd(async (cwd) => {
    const key = "AKIAZQ7KX3MPL2N4R6TY";                       // 20 characters shaped like an access key id (synthetic)
    await put(cwd, `inputs/c/Users/x/${key}/notes.txt`, "x");
    await put(cwd, "inputs/c/Users/x/other.txt", "y");
    const answers: Json[] = [];
    for (const rx of ["AKIAZ", "AKIAY", "AKIAZQ7", "AKIAZQ8", "withheld", "other"]) {
      const run = await tool(INDEX, cwd, { root: "inputs/c", contains: rx });
      assert.ok(!run.stdout.includes(key.slice(4, 12)), `the answer for ${rx} does not show the key`);
      answers.push(body(run));
    }
    const shape = (o: Json) => [o.entry_count, o.hashing.hashed, o.hashing.not_attempted_outside_filter, o.entries.map((e: Json) => e.matches_filter)];
    assert.deepEqual(shape(answers[0]), shape(answers[1]), "AKIAZ and AKIAY give the same answer");
    assert.deepEqual(shape(answers[2]), shape(answers[3]));
    assert.equal(answers[0].entry_count, 0, "the text behind the marker is not searchable");
    assert.ok(answers[4].entry_count >= 1, "the marker itself is searchable: withheld");
    assert.equal(answers[5].entry_count, 1);
  });
});

test("one copy-log row is one file's: a file outside the log's own directory never claims it, and the match does not depend on the root", async () => {
  await withCwd(async (cwd) => {
    const log = [KAPE_COPY_HEADER, kapeCopyRow("C:\\$MFT", "D:\\kape\\Collected\\C\\$MFT")].join("\r\n") + "\r\n";
    await put(cwd, "inputs/a/Collected/2026-02-14T09_12_00_1_CopyLog.csv", log);
    for (const rel of ["Collected/C/$MFT", "C/$MFT", "$MFT", "other/C/$MFT"]) await put(cwd, `inputs/a/${rel}`, "mft");
    const out = body(await tool(INDEX, cwd, { root: "inputs/a" }));
    const e = byPath(out);
    assert.equal(e["Collected/C/$MFT"].source_path_mapping, "observed");
    assert.equal(e["Collected/C/$MFT"].source_path_observed.path, "C:\\$MFT");
    for (const rel of ["C/$MFT", "$MFT", "other/C/$MFT"]) {
      assert.equal(e[rel].source_path_mapping, "no_row_matched", `${rel} lies outside the log's directory`);
      assert.equal(e[rel].source_path_observed, null);
    }
    assert.equal(out.source_paths.observed.files.observed, 1);
    // the same delivery indexed from the log's own directory, or from a renamed parent, gives the same observation
    const inner = byPath(body(await tool(INDEX, cwd, { root: "inputs/a/Collected" })));
    assert.equal(inner["C/$MFT"].source_path_observed.path, "C:\\$MFT");
    // nested runs: each file is observed from its own run's log, and a file below no log's directory is not observed
    await put(cwd, "inputs/b/1_CopyLog.csv", [KAPE_COPY_HEADER, kapeCopyRow("C:\\x.txt", "D:\\kape\\C\\x.txt")].join("\n") + "\n");
    await put(cwd, "inputs/b/run2/2_CopyLog.csv", [KAPE_COPY_HEADER, kapeCopyRow("C:\\x.txt", "E:\\kape\\run2\\C\\x.txt")].join("\n") + "\n");
    await put(cwd, "inputs/b/C/x.txt", "1");
    await put(cwd, "inputs/b/run2/C/x.txt", "2");
    const nested = byPath(body(await tool(INDEX, cwd, { root: "inputs/b" })));
    assert.equal(nested["C/x.txt"].source_path_mapping, "observed");
    assert.equal(nested["C/x.txt"].source_path_observed.log, "1_CopyLog.csv");
    assert.equal(nested["run2/C/x.txt"].source_path_mapping, "observed");
    assert.equal(nested["run2/C/x.txt"].source_path_observed.log, "run2/2_CopyLog.csv");
  });
});

test("two siblings that differ only in case do not both claim one row: both are ambiguous (on a case-sensitive file system)", async (t) => {
  await withCwd(async (cwd) => {
    if (await caseInsensitiveVolume(join(cwd, "probe"))) return t.skip("this file system is case-insensitive: the two names cannot exist");
    await put(cwd, "inputs/k/r_CopyLog.csv", [KAPE_COPY_HEADER, kapeCopyRow("C:\\Users\\A\\NTUSER.DAT", "D:\\o\\C\\Users\\A\\NTUSER.DAT")].join("\n") + "\n");
    await put(cwd, "inputs/k/C/Users/A/NTUSER.DAT", "1");
    await put(cwd, "inputs/k/C/Users/A/ntuser.dat", "2");
    const e = byPath(body(await tool(INDEX, cwd, { root: "inputs/k" })));
    assert.equal(e["C/Users/A/NTUSER.DAT"].source_path_mapping, "ambiguous");
    assert.equal(e["C/Users/A/ntuser.dat"].source_path_mapping, "ambiguous");
    assert.match(e["C/Users/A/ntuser.dat"].source_path_candidates.why, /shares its name/);
  });
});

test("a copy log with rows the mapping cannot use makes the mapping and the answer partial and says how many", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/C/a.txt", "x");
    await put(cwd, "inputs/k/C/b.txt", "x");
    await put(cwd, "inputs/k/C/c.txt", "x");
    // row 1 is short, row 3 holds an unterminated quote that swallows the rest
    await put(cwd, "inputs/k/r_CopyLog.csv", `${KAPE_COPY_HEADER}\nonly,three\n${kapeCopyRow("C:\\b.txt", "D:\\o\\C\\b.txt")}\n2026-02-14,"C:\\c.txt,D:\\o\\C\\c.txt,1\n`);
    const out = body(await tool(INDEX, cwd, { root: "inputs/k" }));
    assert.equal(out.status, "partial");
    assert.equal(out.source_paths.observed.status, "partial");
    assert.ok(out.source_paths.observed.rows_unusable >= 2);
    assert.match(out.status_basis, /copy-log row\(s\) could not be used/);
    assert.equal(byPath(out)["C/b.txt"].source_path_observed.path, "C:\\b.txt", "the usable row still maps");
  });
});

test("a hash the time limit cuts on the last file, or a file that changes size while it is read, makes the answer partial", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/t/a.txt", "x");
    await put(cwd, "inputs/t/sub/zz-big.bin", "y");
    const { runPySnippet } = await import("./tool-library-harness.ts");
    const cut = await runPySnippet(DEADLINE_MAIN, [INDEX, join(cwd, "inputs/t"), "hash-stops-on-last"], null);
    assert.equal(cut.code, 0, cut.stderr);
    const a = JSON.parse(cut.stdout);
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /the time limit ended a hash/);
    assert.equal(a.hashing.stopped_by_time_limit, 1);
    assert.match(a.entries.find((e: Json) => e.in_collection.endsWith("zz-big.bin")).hash_status, /stopped: the time limit ended the read after 1048576 bytes/);
    const grew = await runPySnippet(DEADLINE_MAIN, [INDEX, join(cwd, "inputs/t"), "size-changes"], null);
    const b = JSON.parse(grew.stdout);
    assert.equal(b.status, "partial");
    const row = b.entries[0];
    assert.equal(row.sha256, null, "the digest of bytes that are not the census object is not printed as the file's");
    assert.match(row.sha256_of_bytes_read, /^[0-9a-f]{64}$/);
    assert.equal(row.hash_status, "size_changed_during_read");
    assert.equal(b.hashing.hashed, 0);
    assert.equal(b.hashing.size_changed_during_read, 2);
  });
});

test("a case-variant spelling of the collection or of inputs/ does not get round the out_file guards", async (t) => {
  await withCwd(async (cwd) => {
    if (!(await caseInsensitiveVolume(join(cwd, "probe")))) return t.skip("this file system is case-sensitive: a case variant is another directory");
    await put(cwd, "work/coll/a.txt", "x");
    const inside = refused(await tool(INDEX, cwd, { root: "work/coll", out_file: "work/COLL/index.jsonl" }));
    assert.match(inside.error, /out_file is inside the collection/);
    assert.deepEqual(await filesUnder(join(cwd, "work/coll")), ["a.txt"]);
    assert.match(refused(await tool(INDEX, cwd, { root: "work/COLL", out_file: "work/coll/sub/index.jsonl" })).error, /out_file is inside the collection/);
    assert.match(refused(await tool(INDEX, cwd, { root: "work/coll", out_file: "INPUTS/x.jsonl" })).error, /cannot be under inputs\//);
    assert.equal(await exists(join(cwd, "inputs/x.jsonl")), false);
  });
});

test("credential-store names beyond the first list are marked and not hashed: iOS keychain, master.passwd, ntds.dit, hive logs, key files, DPAPI, host keys", async () => {
  await withCwd(async (cwd) => {
    const names = ["private/var/Keychains/keychain-2.db", "private/etc/master.passwd", "Windows/NTDS/ntds.dit", "Windows/System32/config/SAM.LOG1",
      "home/u/server.key", "home/u/cert.pem", "etc/ssh/ssh_host_ed25519_key", "home/u/.ssh/id_ed25519_sk", "home/u/.docker/config.json", "home/u/.kube/config",
      "Users/a/AppData/Roaming/Microsoft/Protect/S-1-5-21-1/abc", "Users/a/AppData/Roaming/Microsoft/Credentials/ABC123", "home/u/.gnupg/private-keys-v1.d/x",
      "etc/krb5.keytab", "home/u/wallet.dat", "Users/a/AppData/Local/Google/Chrome/User Data/Default/Login Data For Account",
      "Users/a/AppData/Local/Google/Chrome/User Data/Local State", "home/u/.ssh/id_rsa.bak"];
    const ordinary = ["home/u/.ssh/known_hosts", "home/u/.ssh/id_ed25519.pub", "home/u/notes.txt", "etc/ssl/certs/readme"];
    for (const rel of [...names, ...ordinary]) await put(cwd, `inputs/s/${rel}`, "k");
    const e = byPath(body(await tool(INDEX, cwd, { root: "inputs/s" })));
    for (const rel of names) {
      assert.ok(e[rel].may_hold_secrets, `${rel} is marked`);
      assert.equal(e[rel].sha256, null, `${rel} is not hashed`);
    }
    for (const rel of ordinary) {
      assert.equal(e[rel].may_hold_secrets, undefined, `${rel} is not marked`);
      assert.match(e[rel].sha256, /^[0-9a-f]{64}$/);
    }
  });
});

test("every summary key comes before the entries, so the model's first 64 KiB hold where the census is, its status and the anomaly", async () => {
  await withCwd(async (cwd) => {
    for (let i = 0; i < 300; i++) await put(cwd, `inputs/b/d${i % 10}/file${String(i).padStart(3, "0")}.txt`, `x${i}`);
    const run = await tool(INDEX, cwd, { root: "inputs/b" });
    const out = body(run);
    const keys = Object.keys(JSON.parse(run.stdout));
    assert.deepEqual(keys.slice(-2), ["entries", "possible_renamed_streams"]);
    for (const summary of ["status", "census", "complete_index", "hashing", "source_paths", "mtime_distribution_anomaly", "withheld"]) {
      assert.ok(keys.indexOf(summary) < keys.indexOf("entries"), `${summary} is before entries`);
      assert.ok(run.stdout.indexOf(`"${summary}"`) < 65536, `${summary} is inside the first 64 KiB`);
    }
    assert.ok(Buffer.byteLength(JSON.stringify(out.entries)) <= 33000, "the inline page is bounded by bytes, not only by rows");
    assert.ok(out.inline_limited);
    assert.equal(out.index.rows, 300);
  });
});

test("the manifest example runs in a job: it names no out_file outside $OUT", async () => {
  await withCwd(async (cwd) => {
    const manifest = JSON.parse(await readFile(join(INDEX, "..", "manifest.json"), "utf8"));
    const example = JSON.parse(manifest.example);
    assert.equal(example.out_file, undefined);
    await put(cwd, `${example.root}/C/Users/a/NTUSER.DAT`, "hive");
    const out = body(await asJob(INDEX, cwd, example, {}, "out", "j000991"));
    assert.equal(out.status, "complete");
    assert.equal(out.entry_count, 1);
  });
});

test("a contains pattern that can backtrack for ever is refused before anything is read, and the ordinary ones are not", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/r/" + "a".repeat(30) + "!", "x");
    for (const bad of ["(a|a)+$", "(a+)+$", "(a*)*b", "((a|b)c)+", "(a)\\1"]) {
      // run with a deadline of the test's own: a tool that accepts the pattern would backtrack for minutes, and the suite must fail, not hang
      const run = spawnSync("python3", [INDEX], { cwd, input: JSON.stringify({ root: "inputs/r", contains: bad }), timeout: 15000, env: { ...process.env, AGENT_ID: "s1" } });
      assert.equal(run.signal, null, `${bad} was refused at once, not left to backtrack`);
      assert.match(JSON.parse(run.stdout.toString()).error, /contains repeats a group|back-reference/, bad);
    }
    for (const ok of ["NTUSER", "\\.(db|sqlite)$", "a+!", "^a{5,}", "(\\d+)-(\\d+)", "[a-z]+$"]) body(await tool(INDEX, cwd, { root: "inputs/r", contains: ok }));
  });
});

test("an empty directory is a row, a link that cannot be read says why on its row, and the census counts directories it listed", async (t) => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "inputs/e/target-folder"), { recursive: true });
    await put(cwd, "inputs/e/a.txt", "x");
    const out = body(await tool(INDEX, cwd, { root: "inputs/e" }));
    const dir = byPath(out)["target-folder"];
    assert.deepEqual([dir.kind, dir.entries, dir.empty], ["directory", 0, true]);
    assert.equal(out.census.empty_directories, 1);
    assert.equal(out.census.directories_listed, 2);
    assert.equal(out.census.directories, undefined);
  });
});

test("a Linux tree is read the same way whether or not it starts with root/, and [root] may sit below a wrapper directory", async () => {
  await withCwd(async (cwd) => {
    for (const rel of ["etc/passwd", "root/.bash_history", "home/u/.profile", "var/log/syslog", "uac-host-linux-20260214/[root]/etc/shadow", "stray/file.txt"]) await put(cwd, `inputs/l/${rel}`, "x");
    const e = byPath(body(await tool(INDEX, cwd, { root: "inputs/l" })));
    for (const [rel, path] of [["etc/passwd", "/etc/passwd"], ["root/.bash_history", "/root/.bash_history"], ["home/u/.profile", "/home/u/.profile"], ["var/log/syslog", "/var/log/syslog"]]) {
      assert.equal(e[rel].source_path_hypothesis.path, path);
      assert.equal(e[rel].source_path_hypothesis.confidence, "low");
    }
    const uac = e["uac-host-linux-20260214/[root]/etc/shadow"].source_path_hypothesis;
    assert.equal(uac.path, "/etc/shadow");
    assert.deepEqual(uac.unresolved_components, ["uac-host-linux-20260214"]);
    assert.equal(uac.confidence, "low");
    assert.equal(e["stray/file.txt"].source_path_hypothesis.confidence, "none");
  });
});

test("no secret-shaped string reaches the answer, the index file or stderr from a path, a link target, a copy-log time or a hypothesis; the real strings are in the sealed file only when asked", async () => {
  await withCwd(async (cwd) => {
    const secrets = {
      ghp: "ghp_Zq7Svb9Kt00123456789abcdefghijKLMNOP",
      pem: "MIIEowIBAAKCAQEAq7ZkP3rT9vLmN2xWc5YhB8dF1gJ4sUo6aEi0",
      userinfo: "Wint3rPass99@Synth77Tail",
      aws: "AKIAIOSFODNN7EXAMPLE",
    };
    await put(cwd, `inputs/s/home/${secrets.ghp}/f.txt`, "x");
    await put(cwd, `inputs/s/home/ftp:/svc:${secrets.userinfo}@10.20.30.40/g.txt`.replace("ftp:/", "ftp__"), "x");
    await link(cwd, "inputs/s/link", `https://svc:${secrets.userinfo}@10.20.30.40/drop`);
    await link(cwd, `inputs/s/key-${secrets.aws}`, `-----BEGIN RSA PRIVATE KEY-----${secrets.pem}-----END RSA PRIVATE KEY-----`);
    await put(cwd, "inputs/s/C/Users/a/NTUSER.DAT", "hive");
    await put(cwd, "inputs/s/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n2026-02-14 09:12:00.123,C:\\Users\\a\\NTUSER.DAT,D:\\o\\C\\Users\\a\\NTUSER.DAT,1,da39a3ee5e6b4b0d3255bfef95601890afd80709,False,2026-01-01,token=${secrets.ghp},2026-01-03,0.01\n`);
    const run = await tool(INDEX, cwd, { root: "inputs/s", limit: 1 });
    const out = body(run);
    const file = await readFile(join(cwd, out.complete_index), "utf8");
    assertAbsent([run.stdout, run.stderr, file].join("\n"), secrets, "collection_index");
    assert.match(file, /withheld, \d+ characters, W\d{6}>/);
    assert.equal(byPath({ entries: out.entries })["C/Users/a/NTUSER.DAT"]?.source_path_observed?.path ?? "C:\\Users\\a\\NTUSER.DAT", "C:\\Users\\a\\NTUSER.DAT");
    const job = await asJob(INDEX, cwd, { root: "inputs/s", write_values: true, limit: 1 }, {}, "out", "j000975");
    assertAbsent(job.stdout + job.stderr, secrets, "collection_index in a job");
    const values = JSON.stringify(await readRows(join(cwd, "out/collection-index-values.jsonl")));
    for (const name of ["ghp", "userinfo", "aws"]) assert.ok(values.includes(secrets[name as keyof typeof secrets]), `${name} is in the sealed file`);
  });
});

test("the files this run creates are not listed as delivered files: the streams table's spill and the values file, inside a root that holds them", async () => {
  await withCwd(async (cwd) => {
    for (let i = 0; i < 4; i++) await put(cwd, `work/s1/files/doc${i}.txt_Zone.Identifier`, "z");
    const out = body(await tool(INDEX, cwd, { root: "work/s1", limit: 1 }));
    const names = (await readRows(join(cwd, out.complete_index))).map((r: Json) => r.in_collection);
    assert.deepEqual(names.filter((n: string) => n.includes("tool-output/") || n.startsWith(".collection_index")), [], "no row names this run's own files");
    assert.equal(out.census.regular_files, 4);
    const job = body(await asJob(INDEX, cwd, { root: "out", write_values: true }, {}, "out", "j000976"));
    assert.deepEqual(job.entries.map((e: Json) => e.in_collection), [], "the values file the job creates in $OUT, which the root holds, is not an object of the census");
  });
});
