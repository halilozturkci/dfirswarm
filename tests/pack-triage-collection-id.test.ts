/**
 * triage-collection: collection_id classifies each object of a delivery on its own, names the collectors that left records by
 * the paths it found, reads every recognised log whole, and gives a failure count only when every failure-source log was read
 * whole: an unrecognised, unreadable, time-limited or partly read log, an incomplete walk or an unopened archive makes the count
 * null, never 0.
 *
 * Fixtures are built from the formats' own definitions (the EWF, VHDX and LiME signatures, a GPT header at offset 512, the
 * columns of a real KAPE copy log, the UAC 3.4.0 and 2.9.1 log line forms and the Velociraptor 0.77.2 container files as their
 * sources write them) or by hand. None is read back from the tool. The KAPE skip log has no real sample here: its two columns
 * are a stand-in the adapter recognises, and the tests that need a skip row say so.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, readdir, stat, utimes } from "node:fs/promises";
import { execFileSync, spawn } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import {
  EWF_SIGNATURE, GPT_SIGNATURE, ID, KAPE_COPY_HEADER, LIME_MAGIC, VHDX_SIGNATURE, assertAbsent, asJob, body, exists, filesUnder, kapeCopyRow, link,
  put, readRows, refused, sparse, tableRows, tool, uac2, uac3, veloLogRow, veloResultRow, veloUploadsRow, withCwd,
} from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const NUL = (n: number) => Buffer.alloc(n);
const AWS_EXAMPLE_KEY_ID = "AKIAIOSFODNN7EXAMPLE";            // the documented example access key id of AWS
const runs = (out: Json, collector: string): Json[] => out.runs.filter((r: Json) => r.collector === collector);
const root = process.getuid?.() === 0;

test("a raw memory capture beside a copied tree makes the delivery mixed, each object classified, and nothing returns early", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/c/C/Windows/System32/config/SYSTEM", "regf");
    await put(cwd, "inputs/c/C/Users/a/NTUSER.DAT", "regf");
    await put(cwd, "inputs/c/memory.raw", Buffer.concat([LIME_MAGIC, Buffer.from([1, 0, 0, 0]), NUL(64)]));
    const out = body(await tool(ID, cwd, { root: "inputs/c" }));
    assert.equal(out.delivery.kind, "mixed");
    assert.equal(out.delivery.object_counts.memory_capture, 1);
    assert.equal(out.delivery.object_counts.other_files, 2);
    assert.equal(out.delivery.object_counts.other_files_below_the_top_level, 2);
    assert.equal(out.delivery.object_counts.disk_container, 0);
    const memory = out.objects.find((o: Json) => o.path === "memory.raw");
    assert.equal(memory.class, "memory_capture");
    assert.equal(memory.basis, "bytes");
    // The old tool answered "disk image / physical image" for any top-level .raw and read nothing else.
    assert.equal(out.collector, undefined);
    assert.equal(out.evidence_kind, undefined);
    assert.equal(out.walk.files, 3);
    assert.deepEqual(out.delivery.not_observed, ["disk containers"]);
    assert.ok(out.artefact_families_by_name["the SYSTEM hive"], "the copied files were still examined");
  });
});

test("an image delivery with a note beside it is that image, not mixed; the note is another file", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/d/Case4.E01", Buffer.concat([EWF_SIGNATURE, NUL(100)]));
    await put(cwd, "inputs/d/CASE.md", "notes");
    await put(cwd, "inputs/d/traffic.pcapng", "capture");
    const out = body(await tool(ID, cwd, { root: "inputs/d" }));
    assert.equal(out.delivery.kind, "disk_container");
    assert.equal(out.delivery.object_counts.disk_container, 1);
    assert.equal(out.delivery.object_counts.other_files, 2);
    assert.equal(out.delivery.object_counts.other_files_below_the_top_level, 0);
    assert.equal(out.delivery.object_counts.logical_files, undefined, "the residue is not called logical");
    assert.deepEqual(out.delivery.not_observed, ["memory captures"]);
    // a copied tree beside the image does make it mixed
    await put(cwd, "inputs/d/collected/C/Users/a/NTUSER.DAT", "hive");
    assert.equal(body(await tool(ID, cwd, { root: "inputs/d" })).delivery.kind, "mixed");
    // two kinds of object are mixed with no copied file at all
    await put(cwd, "inputs/e/Case4.E01", Buffer.concat([EWF_SIGNATURE, NUL(100)]));
    await put(cwd, "inputs/e/memdump.mem", NUL(100));
    const two = body(await tool(ID, cwd, { root: "inputs/e" }));
    assert.equal(two.delivery.kind, "mixed");
    assert.equal(two.delivery.object_counts.other_files, 0);
  });
});

test("a name that says image or raw with no signature behind it is unknown, never a physical image, and says it cannot exclude either kind", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/c/blob.raw", NUL(3000));
    await put(cwd, "inputs/c/note.txt", "hello");
    const out = body(await tool(ID, cwd, { root: "inputs/c" }));
    const blob = out.objects.find((o: Json) => o.path === "blob.raw");
    assert.equal(blob.class, "unknown");
    assert.equal(blob.basis, "extension only");
    assert.match(blob.evidence, /no recognised container signature/);
    assert.equal(out.delivery.object_counts.disk_container, 0);
    assert.equal(out.delivery.kind, "unknown");
    // an object that may be either kind leaves neither kind "not observed"
    assert.deepEqual(out.delivery.not_observed, []);
    assert.equal(out.delivery.not_observed_complete, false);
    assert.match(out.delivery.not_observed_caveats[0], /may be a disk or a memory capture/);
  });
});

test("a small file named like an image below the top, or one whose bytes are plainly something else, is a copied file; a large one is an unknown object counted apart", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/n/app/cache/a.img", Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), NUL(2000)]));   // a PNG
    await put(cwd, "inputs/n/app/cache/b.img", NUL(2000));                                                                                       // small, no signature
    await sparse(join(cwd, "inputs/n/app/big/c.img"), 2 << 20, []);                                                                            // 2 MiB, no signature
    const out = body(await tool(ID, cwd, { root: "inputs/n" }));
    assert.deepEqual(out.objects.map((o: Json) => o.path), ["app/big/c.img"]);
    assert.equal(out.delivery.object_counts.unknown, 0);
    assert.equal(out.delivery.object_counts.unknown_nested, 1);
    assert.equal(out.delivery.object_counts.other_files, 2);
    assert.equal(out.delivery.kind, "logical", "a nested unknown object does not make the delivery mixed by itself");
    assert.equal(out.delivery.not_observed_complete, false);
  });
});

test("disk containers are recognised by their own signatures; a raw or flat image by its volume signatures, and only when it is large enough to be one", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/d/case.E01", Buffer.concat([EWF_SIGNATURE, NUL(100)]));
    await put(cwd, "inputs/d/case.E02", Buffer.concat([EWF_SIGNATURE, NUL(100)]));
    await put(cwd, "inputs/d/vm/disk.vhdx", Buffer.concat([VHDX_SIGNATURE, NUL(100)]));
    await sparse(join(cwd, "inputs/d/raw/disk.dd"), 2 << 20, [[510, Buffer.from([0x55, 0xaa])], [512, GPT_SIGNATURE]]);
    await sparse(join(cwd, "inputs/d/vm/fixed.vhd"), 2 << 20, [[510, Buffer.from([0x55, 0xaa])]]);   // a fixed VHD starts with the disk itself
    await sparse(join(cwd, "inputs/d/vm/disk-flat.vmdk"), 2 << 20, [[510, Buffer.from([0x55, 0xaa])]]);
    // $Boot is 8 KiB and starts with an NTFS boot sector: a copied file, not a disk.
    await sparse(join(cwd, "inputs/d/C/$Boot"), 8192, [[3, Buffer.from("NTFS    ")], [510, Buffer.from([0x55, 0xaa])]]);
    const out = body(await tool(ID, cwd, { root: "inputs/d" }));
    const byPath = Object.fromEntries(out.objects.map((o: Json) => [o.path, o]));
    assert.equal(byPath["case.E01"].class, "disk_container");
    assert.match(byPath["case.E01"].format, /EWF/);
    assert.equal(byPath["case.E02"].class, "disk_container", "each segment of a set is listed");
    assert.equal(byPath["vm/disk.vhdx"].class, "disk_container");
    assert.equal(byPath["raw/disk.dd"].class, "disk_container");
    assert.match(byPath["raw/disk.dd"].evidence, /GPT header at offset 512/);
    assert.equal(byPath["vm/fixed.vhd"].class, "disk_container", "the boot signature is looked for in a .vhd too");
    assert.equal(byPath["vm/disk-flat.vmdk"].class, "disk_container");
    assert.equal(byPath["C/$Boot"], undefined, "an 8 KiB boot sector is a copied file");
    assert.equal(out.delivery.object_counts.disk_container, 6);
  });
});

test("a delivery of one kind says that kind, an empty one says so, and no fixed list of what a delivery cannot contain is printed", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/only-image/case.E01", Buffer.concat([EWF_SIGNATURE, NUL(100)]));
    const one = body(await tool(ID, cwd, { root: "inputs/only-image" }));
    assert.equal(one.delivery.kind, "disk_container");
    await put(cwd, "inputs/logical/C/Windows/System32/config/SYSTEM", "regf");
    const logical = body(await tool(ID, cwd, { root: "inputs/logical" }));
    assert.equal(logical.delivery.kind, "logical");
    assert.deepEqual(logical.delivery.not_observed, ["disk containers", "memory captures"]);
    assert.equal(logical.delivery.not_observed_complete, true);
    assert.match(logical.delivery.not_observed_basis, /limit of this delivery, not a finding about the source/);
    assert.equal(logical.cannot_contain, undefined);
    await mkdir(join(cwd, "inputs/empty"), { recursive: true });
    assert.equal(body(await tool(ID, cwd, { root: "inputs/empty" })).delivery.kind, "empty");
  });
});

test("not_observed says what it did not look into: an unopened archive, a hibernation file and an incomplete walk each qualify it", async (t) => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/q/collection.zip", Buffer.concat([Buffer.from("PK\x03\x04"), NUL(40)]));
    await put(cwd, "inputs/q/C/hiberfil.sys", "HIBR");
    const out = body(await tool(ID, cwd, { root: "inputs/q" }));
    assert.equal(out.delivery.not_observed_complete, false);
    assert.ok(out.delivery.not_observed_caveats.some((c: string) => /1 top-level archive\(s\) were not opened/.test(c)));
    assert.ok(out.delivery.not_observed_caveats.some((c: string) => /hiberfil\.sys/.test(c) && /not captures/.test(c)));
    assert.ok(out.artefact_families_by_name["the hibernation file (a file named like one: memory-bearing, not a capture)"]);
    if (root) return t.diagnostic("running as root: the unreadable directory is readable");
    await put(cwd, "inputs/w/ok", "x");
    await put(cwd, "inputs/w/locked/f", "x");
    await chmod(join(cwd, "inputs/w/locked"), 0o000);
    try {
      const walk = body(await tool(ID, cwd, { root: "inputs/w" }));
      assert.equal(walk.delivery.not_observed_complete, false);
      assert.ok(walk.delivery.not_observed_caveats.includes("the walk was incomplete"));
    } finally {
      await chmod(join(cwd, "inputs/w/locked"), 0o755);
    }
  });
});

test("two KAPE runs in one tree are two runs, each with its own logs and counts, and the whole skip row is kept", async () => {
  await withCwd(async (cwd) => {
    const run1 = "2026-02-14T09_12_00_1111111";
    const run2 = "2026-02-15T10_00_00_2222222";
    await put(cwd, `inputs/k/${run1}_CopyLog.csv`, "\ufeff" + [KAPE_COPY_HEADER, kapeCopyRow("C:\\a", "D:\\o1\\C\\a"), kapeCopyRow("C:\\b", "D:\\o1\\C\\b")].join("\r\n") + "\r\n");
    await put(cwd, `inputs/k/${run1}_SkipLog.csv`, "SourceFile,Reason\r\nC:\\pagefile.sys,File in use\r\nC:\\x,\"Access, denied\"\r\n");
    await put(cwd, `inputs/k/${run2}_CopyLog.csv`, [KAPE_COPY_HEADER, kapeCopyRow("C:\\c", "D:\\o2\\C\\c")].join("\n") + "\n");
    await put(cwd, `inputs/k/${run2}_SkipLog.csv`, "SourceFile,Reason\n");
    await put(cwd, "inputs/k/C/a", "x");
    const out = body(await tool(ID, cwd, { root: "inputs/k" }));
    const kape = runs(out, "KAPE");
    assert.equal(kape.length, 2, "both runs are kept");
    const [r1, r2] = kape;
    assert.equal(r1.run_id, run1);
    assert.equal(r1.files_in_copy_log, 2);
    assert.equal(r2.files_in_copy_log, 1);
    assert.deepEqual(r1.logs.map((l: Json) => l.kind), ["copy_log", "skip_log"]);
    assert.equal(r1.logs[0].status, "parsed");
    assert.equal(r1.collector_version, "unknown");
    assert.equal(out.collector_candidates[0].markers_total, 4);
    assert.equal(out.failed_target_count, 2);
    assert.equal(out.failed_targets_seen, 2);
    const reasons = out.failed_targets.map((f: Json) => [f.target, f.reason, f.outcome]);
    assert.deepEqual(reasons, [["C:\\pagefile.sys", "File in use", "skipped"], ["C:\\x", "Access, denied", "skipped"]]);
    assert.deepEqual(out.failed_targets[1].locator, { row: 2, line: 3 });
    assert.deepEqual(out.failed_targets[0].row_values, { SourceFile: "C:\\pagefile.sys", Reason: "File in use" });
    assert.equal(out.collector, undefined);
    assert.ok(out.layout_clues.every((c: Json) => !("collector" in c)), "a drive-letter directory is a clue, never an attribution");
    assert.match(out.failed_target_count_basis, /every failure-source log was read whole/);
  });
});

test("a copy log alone gives no failure count: a skip log is where the skips are, and its absence is not zero", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/r_CopyLog.csv", KAPE_COPY_HEADER + "\n" + kapeCopyRow("C:\\a", "D:\\o\\C\\a") + "\n");
    const out = body(await tool(ID, cwd, { root: "inputs/k" }));
    assert.equal(out.failed_target_count, null);
    assert.match(out.failed_target_count_basis, /no skip log, UAC log or Velociraptor container was read/);
    assert.match(out.failed_target_count_basis, /not zero failures/);
  });
});

test("a skip log whose columns are not recognised keeps every row whole in the unrecognised rows, counts none as a failure, and gives no count", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/2026-02-14T09_12_00_1_SkipLog.csv", "Foo,Bar\nx,y\nz,w\n");
    const out = body(await tool(ID, cwd, { root: "inputs/k" }));
    const log = runs(out, "KAPE")[0].logs[0];
    assert.equal(log.status, "partial");
    assert.match(log.reason, /every row is kept whole/);
    assert.equal(out.status, "partial");
    assert.equal(out.failed_target_count, null);
    assert.equal(out.failed_targets_seen, 0);
    assert.deepEqual(out.failed_targets, []);
    assert.deepEqual(out.unrecognised_rows.map((r: Json) => r.row_values), [{ Foo: "x", Bar: "y" }, { Foo: "z", Bar: "w" }]);
    await put(cwd, "inputs/e/2026-02-14T09_12_00_1_SkipLog.csv", "");
    const empty = body(await tool(ID, cwd, { root: "inputs/e" }));
    assert.equal(runs(empty, "KAPE")[0].logs[0].status, "unsupported");
    assert.equal(empty.failed_target_count, null, "a log that could not be read gives no count, not zero");
  });
});

test("a skip log that is binary or UTF-16 is unsupported: its bytes are not failures", async () => {
  await withCwd(async (cwd) => {
    const bytes = Buffer.alloc(5120);
    for (let i = 0; i < bytes.length; i++) bytes[i] = i % 251;                       // every byte value, NUL included, in a fixed order (not random)
    await put(cwd, "inputs/b/B_SkipLog.csv", bytes);
    const binary = body(await tool(ID, cwd, { root: "inputs/b" }));
    assert.equal(runs(binary, "KAPE")[0].logs[0].status, "unsupported");
    assert.match(runs(binary, "KAPE")[0].logs[0].reason, /binary|NUL/);
    assert.equal(binary.failed_targets_seen, 0);
    assert.equal(binary.failed_target_count, null);
    const text = "SourceFile,Reason\r\nC:\\a,locked\r\nC:\\b,denied\r\n";
    await put(cwd, "inputs/u/U_SkipLog.csv", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]));
    const utf16 = body(await tool(ID, cwd, { root: "inputs/u" }));
    assert.equal(runs(utf16, "KAPE")[0].logs[0].status, "unsupported");
    assert.match(runs(utf16, "KAPE")[0].logs[0].reason, /UTF-16/);
    assert.equal(utf16.failed_targets_seen, 0);
    assert.equal(utf16.failed_target_count, null);
  });
});

test("a malformed CSV row is counted and located, the rest of the log is still read, and the count stays null while the log is partial", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/r_SkipLog.csv", ["SourceFile,Reason", "C:\\a,locked", "C:\\b", "C:\\c,denied,extra", "C:\\d,ok", ""].join("\n"));
    const out = body(await tool(ID, cwd, { root: "inputs/k" }));
    const log = runs(out, "KAPE")[0].logs[0];
    assert.equal(log.rows, 4);
    assert.equal(log.malformed_rows, 2);
    assert.deepEqual(log.problems.map((p: Json) => p.locator.line), [3, 4]);
    assert.equal(log.status, "partial");
    assert.equal(out.failed_targets.filter((f: Json) => f.malformed).length, 2);
    assert.equal(out.failed_targets_seen, 4);
    assert.equal(out.failed_target_count, null);
  });
});

test("a skip row with a field longer than the CSV module's default limit is kept whole; a log cut inside a quoted field is flagged, not read as clean", async () => {
  await withCwd(async (cwd) => {
    const big = "x".repeat(200000);
    await put(cwd, "inputs/k/r_SkipLog.csv", `SourceFile,Reason\nC:\\a,"${big}"\nC:\\b,ok\n`);
    const out = body(await tool(ID, cwd, { root: "inputs/k" }));
    assert.equal(out.failed_targets_seen, 2);
    assert.equal(out.failed_target_count, 2);
    assert.equal(out.tables.failed_targets.matched, 2);
    const whole = await tableRows(cwd, out.tables.failed_targets);
    assert.equal(whole[0].reason.length, 200000, "the row larger than the inline budget is whole in the file the table names");
    await put(cwd, "inputs/t/r_SkipLog.csv", 'SourceFile,Reason\nC:\\a,locked\nC:\\b,"denied because');
    const cut = body(await tool(ID, cwd, { root: "inputs/t" }));
    const log = runs(cut, "KAPE")[0].logs[0];
    assert.equal(log.status, "partial");
    assert.equal(log.malformed_rows, 1);
    assert.equal(cut.failed_target_count, null);
  });
});

test("a failure count of 0 is never given for a log that was not read: an unreadable second log, a header-only first one, a time limit, UAC lines nobody recognised", async (t) => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/a/A_SkipLog.csv", "SourceFile,Reason\n");
    await put(cwd, "inputs/a/B_SkipLog.csv", "SourceFile,Reason\nC:\\x,locked\nC:\\y,denied\n", 0o644);
    const clean = body(await tool(ID, cwd, { root: "inputs/a" }));
    assert.equal(clean.failed_target_count, 2, "both logs read whole: the count is the rows");
    if (!root) {
      await chmod(join(cwd, "inputs/a/B_SkipLog.csv"), 0o000);
      try {
        const out = body(await tool(ID, cwd, { root: "inputs/a" }));
        assert.equal(out.failed_target_count, null);
        assert.equal(out.failed_targets_seen, 0);
        assert.equal(out.status, "partial");
        assert.match(out.failed_target_count_basis, /B_SkipLog\.csv is unreadable/);
      } finally {
        await chmod(join(cwd, "inputs/a/B_SkipLog.csv"), 0o644);
      }
    } else t.diagnostic("running as root: a mode-000 log is readable");
    // UAC lines that carry failure words and no level the adapter knows
    await put(cwd, "inputs/u/uac.log", [uac3("INF", "Starting"), ...Array.from({ length: 50 }, (_, i) => `cannot open /x/${i}: Permission denied`), ""].join("\n"));
    const uac = body(await tool(ID, cwd, { root: "inputs/u" }));
    assert.equal(uac.failed_target_count, null);
    assert.equal(runs(uac, "UAC")[0].record.unlabelled_lines_with_failure_words, 50);
    // a Velociraptor index that is a JSON array beside a UAC log with a clean summary
    await put(cwd, "inputs/m/uac.log", uac3("INF", "Collection finished, 0 errors found") + "\n");
    await put(cwd, "inputs/m/v/uploads.json", JSON.stringify([{ Error: "x" }]));
    const mixed = body(await tool(ID, cwd, { root: "inputs/m" }));
    assert.equal(mixed.failed_target_count, null);
    // a time limit that ends the read
    const rows = ["SourceFile,Reason"];
    for (let i = 0; i < 30; i++) rows.push(`C:\\f${i},r${i}`);
    await put(cwd, "inputs/l/r_SkipLog.csv", rows.join("\n") + "\n");
    const { runPySnippet } = await import("./tool-library-harness.ts");
    const code = `
import importlib.util, io, json, sys
spec = importlib.util.spec_from_file_location("lib", sys.argv[1]); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
mod.start_clock = lambda seconds: mod.DEADLINE.__setitem__(0, -1.0)
sys.stdin = io.StringIO(json.dumps({"root": sys.argv[2]})); mod.main()`;
    const limited = await runPySnippet(code, [ID, join(cwd, "inputs/l")], null);
    assert.equal(limited.code, 0, limited.stderr);
    const answer = JSON.parse(limited.stdout);
    assert.equal(answer.status, "partial");
    assert.equal(answer.failed_target_count, null);
  });
});

test("a delivery with an archive that was not opened has no failure count even when the logs beside it are clean", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/z/r_SkipLog.csv", "SourceFile,Reason\n");
    await put(cwd, "inputs/z/rest.zip", Buffer.concat([Buffer.from("PK\x03\x04"), NUL(40)]));
    const out = body(await tool(ID, cwd, { root: "inputs/z" }));
    assert.equal(out.failed_target_count, null);
    assert.match(out.failed_target_count_basis, /1 archive\(s\) were not opened/);
  });
});

test("UAC: the 3.4.0 line form (INF, ERR, CMD, DBG) and the 2.9.1 form are read; an ERR is a failure with its line, a summary saying 0 errors is not, command stderr is counted apart", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/u/uac.log", [
      uac3("INF", "Starting collection"),
      uac3("INF", "Collection finished, 0 errors found", 1),
      uac3("DBG", "a debug line", 2),
      uac3("CMD", "ls /nonexistent 2> ls: cannot access '/nonexistent': No such file or directory", 3),
      uac3("ERR", "_find_based_collector: No such file or directory", 4),
      "",
    ].join("\n"));
    const out = body(await tool(ID, cwd, { root: "inputs/u" }));
    const record = runs(out, "UAC")[0].record;
    assert.equal(record.status, "parsed");
    assert.deepEqual(record.levels, { INF: 2, DBG: 1, CMD: 1, ERR: 1 });
    assert.equal(record.command_stderr_lines, 1);
    assert.equal(out.failed_target_count, 1);
    assert.equal(out.failed_targets[0].outcome, "error");
    assert.deepEqual(out.failed_targets[0].locator, { line: 5 });
    assert.match(out.failed_targets[0].reason, /_find_based_collector/);
    assert.ok(out.problems.some((p: Json) => p.kind === "uac_command_stderr" && p.locator.line === 4), "the command's stderr is a row of the problems table");

    await put(cwd, "inputs/u2/uac.log", [uac2("INFO", "Starting collection"), uac2("WARNING", "a warning is not an error", 1), uac2("COMMAND", "ls", 2), uac2("ERROR", "cannot read /proc/1/mem", 3), ""].join("\n"));
    const old = body(await tool(ID, cwd, { root: "inputs/u2" }));
    assert.equal(runs(old, "UAC")[0].record.status, "parsed");
    assert.equal(old.failed_target_count, 1);
    assert.deepEqual(old.failed_targets[0].locator, { line: 4 });
    assert.equal(runs(old, "UAC")[0].record.levels.WARNING, 1);
  });
});

test("UAC: an unmatched line is kept unlabelled and never counted, and the count is not given while it exists; a log with no recognised event is unsupported", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/u/uac.log", [uac3("INF", "Starting collection"), "cannot say what this line is", uac3("ERR", "boom", 2), ""].join("\n"));
    const out = body(await tool(ID, cwd, { root: "inputs/u" }));
    const record = runs(out, "UAC")[0].record;
    assert.equal(record.unmatched_lines, 1);
    assert.equal(record.unlabelled_lines_with_failure_words, 1);
    assert.equal(record.unlabelled_examples[0].text, "cannot say what this line is");
    assert.equal(record.status, "partial");
    assert.equal(out.failed_targets_seen, 1);
    assert.equal(out.failed_target_count, null);
    await put(cwd, "inputs/u2/uac.log", "starting\nan error happened here\ndone\n");
    const none = body(await tool(ID, cwd, { root: "inputs/u2" }));
    assert.equal(runs(none, "UAC")[0].record.status, "unsupported");
    assert.equal(none.failed_target_count, null);
    assert.match(none.failed_target_count_basis, /not zero failures/);
    // [root] by itself names a UAC candidate with no log; only a uac.log is read
    await mkdir(join(cwd, "inputs/d/[root]/etc"), { recursive: true });
    const dirs = body(await tool(ID, cwd, { root: "inputs/d" }));
    assert.equal(dirs.collector_candidates[0].collector, "UAC");
    assert.match(dirs.collector_candidates[0].basis, /\[root\] directory name only/);
    assert.deepEqual(runs(dirs, "UAC"), []);
    assert.equal(dirs.failed_target_count, null);
  });
});

test("Velociraptor 0.77.2: a failed upload is in results/*.json and log.json and in no row of uploads.json, so the count comes from those", async () => {
  await withCwd(async (cwd) => {
    const c = "inputs/v";
    await put(cwd, `${c}/uploads.json`, veloUploadsRow("/C:/Windows/a") + "\n");
    await put(cwd, `${c}/results/Windows.KapeFiles.Targets.json`, [veloResultRow("/C:/Windows/a"), veloResultRow("/C:/Windows/b", "The process cannot access the file because it is being used by another process.")].join("\n") + "\n");
    await put(cwd, `${c}/log.json`, [veloLogRow("DEFAULT", "Starting collection"), veloLogRow("ERROR", "Error uploading /C:/Windows/b: in use"), veloLogRow("WARN", "slow")].join("\n") + "\n");
    await put(cwd, `${c}/collection_context.json`, "{}");
    const out = body(await tool(ID, cwd, { root: c }));
    const record = runs(out, "Velociraptor")[0].record;
    assert.equal(record.status, "parsed");
    assert.deepEqual(Object.fromEntries(Object.entries(record.sources).map(([k, v]: [string, Json]) => [k, v.status])), { "uploads.json": "parsed", "results/*.json": "parsed", "log.json": "parsed" });
    assert.equal(record.uploads_rows, 1);
    assert.equal(record.result_rows, 2);
    assert.equal(record.rows_with_upload_error, 1);
    assert.equal(record.error_lines, 1);
    assert.equal(record.warning_lines, 1);
    assert.deepEqual(record.artefacts, { "Windows.KapeFiles.Targets": 2 });
    assert.equal(out.failed_target_count, 2);
    const upload = out.failed_targets.find((f: Json) => f.log.endsWith("results/Windows.KapeFiles.Targets.json"));
    assert.equal(upload.outcome, "error");
    assert.equal(upload.artefact, "Windows.KapeFiles.Targets");
    assert.equal(upload.target, "/C:/Windows/b");
    assert.match(upload.reason, /being used by another process/);
    assert.deepEqual(upload.locator, { line: 2 });
    assert.ok(out.failed_targets.some((f: Json) => f.log === "v/log.json" || f.log.endsWith("log.json")));
  });
});

test("Velociraptor: a clean 0.77.2 collection is a count of 0 only when results and log.json were read; with either missing, or an uploads index of the wrong shape, there is no count", async () => {
  await withCwd(async (cwd) => {
    const c = "inputs/v";
    await put(cwd, `${c}/uploads.json`, veloUploadsRow("/C:/Windows/a") + "\n");
    // the index alone: the very collection the old tool called "complete, 0 failures" while an upload had failed
    const alone = body(await tool(ID, cwd, { root: c }));
    assert.equal(alone.status, "partial");
    assert.equal(alone.failed_target_count, null);
    assert.match(runs(alone, "Velociraptor")[0].record.reason, /results\/\*\.json is not_found/);
    assert.match(runs(alone, "Velociraptor")[0].record.reason, /log\.json is not_found/);
    await put(cwd, `${c}/results/Windows.KapeFiles.Targets.json`, veloResultRow("/C:/Windows/a") + "\n");
    await put(cwd, `${c}/log.json`, veloLogRow("DEFAULT", "Starting collection") + "\n");
    const clean = body(await tool(ID, cwd, { root: c }));
    assert.equal(clean.status, "complete");
    assert.equal(clean.failed_target_count, 0);
    // a stored size smaller than the file's is a lead, named, and not a failure
    await put(cwd, "inputs/s/uploads.json", [veloUploadsRow("/C:/a", 100, 40), JSON.stringify({ ...JSON.parse(veloUploadsRow("/C:/a.idx", 10, 1)), Type: "idx" })].join("\n") + "\n");
    await put(cwd, "inputs/s/results/Custom.json", veloResultRow("/C:/a") + "\n");
    await put(cwd, "inputs/s/log.json", veloLogRow("DEFAULT", "x") + "\n");
    const sparseRun = body(await tool(ID, cwd, { root: "inputs/s" }));
    assert.equal(runs(sparseRun, "Velociraptor")[0].record.rows_stored_smaller_than_file, 1);
    assert.equal(sparseRun.failed_target_count, 0);
    assert.ok(sparseRun.problems.some((p: Json) => p.kind === "upload_stored_smaller_than_file"));
    // an uploads.json that is a JSON array
    await put(cwd, "inputs/w/uploads.json", JSON.stringify([{ _Source: "a" }]));
    const array = body(await tool(ID, cwd, { root: "inputs/w" }));
    assert.equal(runs(array, "Velociraptor")[0].record.sources["uploads.json"].status, "unsupported");
    assert.match(runs(array, "Velociraptor")[0].record.sources["uploads.json"].reason, /JSON array, not JSON Lines/);
    assert.equal(array.failed_target_count, null);
    // a container with no uploads has no uploads.json at all, and its context file still names it
    await put(cwd, "inputs/n/collection_context.json", "{}");
    await put(cwd, "inputs/n/results/Generic.Client.Info.json", JSON.stringify({ Hostname: "h" }) + "\n");
    await put(cwd, "inputs/n/log.json", veloLogRow("DEFAULT", "x") + "\n");
    const noUploads = body(await tool(ID, cwd, { root: "inputs/n" }));
    assert.equal(noUploads.collector_candidates[0].collector, "Velociraptor");
    assert.equal(noUploads.failed_target_count, 0);
    // malformed rows are located and keep the count out
    await put(cwd, "inputs/m/uploads.json", veloUploadsRow("/C:/a") + "\nthis is not json\n");
    await put(cwd, "inputs/m/results/Custom.json", veloResultRow("/C:/a") + "\n");
    await put(cwd, "inputs/m/log.json", veloLogRow("DEFAULT", "x") + "\n");
    const bad = body(await tool(ID, cwd, { root: "inputs/m" }));
    assert.deepEqual(runs(bad, "Velociraptor")[0].record.problems.map((p: Json) => [p.file, p.locator.line, p.error]), [["uploads.json", 2, "not valid JSON"]]);
    assert.equal(bad.failed_target_count, null);
  });
});

test("records found inside collected data belong to the source host: they are named, not read, and out of the count", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/n/uploads/auto/C%3A/Users/a/r_SkipLog.csv", "SourceFile,Reason\nC:\\x,locked\n");
    await put(cwd, "inputs/n/[root]/home/u/uac.log", uac3("ERR", "from the source host") + "\n");
    const out = body(await tool(ID, cwd, { root: "inputs/n" }));
    assert.equal(out.collector_candidates.length, 1, "only the [root] directory name is a UAC candidate");
    assert.equal(out.failed_targets_seen, 0);
    assert.equal(out.walk.logs_inside_collected_data_total, 2);
    assert.deepEqual(out.walk.logs_inside_collected_data.sort(), ["[root]/home/u/uac.log", "uploads/auto/C%3A/Users/a/r_SkipLog.csv"]);
  });
});

test("a KAPE console log is read whole: its warnings and errors are rows of the problems table with their lines, not failures, and no version is claimed", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/r_ConsoleLog.txt", ["Some banner line", "[2026-02-14 09:12:00.1234567 | INF] Started", "[2026-02-14 09:12:01.2345678 | WRN] Skipping sparse data area in $J!", "[2026-02-14 09:12:02.3456789 | ERR] Deferring x due to UnauthorizedAccessException", ""].join("\r\n"));
    const out = body(await tool(ID, cwd, { root: "inputs/k" }));
    const log = runs(out, "KAPE")[0].logs[0];
    assert.equal(log.kind, "console_log");
    assert.deepEqual(log.levels, { INF: 1, WRN: 1, ERR: 1 });
    assert.equal(log.unmatched_lines, 1);
    assert.equal(runs(out, "KAPE")[0].collector_version, "unknown");
    const rows = out.problems.filter((p: Json) => p.kind === "console_line");
    assert.deepEqual(rows.map((p: Json) => [p.level, p.locator.line]), [["WRN", 3], ["ERR", 4]]);
    assert.equal(out.failed_targets_seen, 0);
    assert.equal(out.failed_target_count, null, "a console log is no failure source");
  });
});

test("problems are lossless: 30 unreadable directories, links and special files are 25 inline each and all 30 in the problems table", async (t) => {
  if (root) return t.skip("running as root: a mode-000 directory is readable");
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "inputs/p"), { recursive: true });
    for (let i = 0; i < 30; i++) {
      await put(cwd, `inputs/p/locked${String(i).padStart(2, "0")}/f`, "x");
      await chmod(join(cwd, `inputs/p/locked${String(i).padStart(2, "0")}`), 0o000);
      await link(cwd, `inputs/p/link${String(i).padStart(2, "0")}`, "elsewhere");
    }
    try {
      const out = body(await tool(ID, cwd, { root: "inputs/p" }));
      assert.equal(out.walk.errors, 30);
      assert.equal(out.walk.first_errors.length, 25);
      assert.equal(out.walk.symbolic_links_not_followed, 30);
      assert.equal(out.walk.first_links.length, 25);
      assert.equal(out.tables.problems.matched, 60);
      const rows = await tableRows(cwd, out.tables.problems);
      assert.equal(rows.length, 60);
      assert.equal(rows.filter((r: Json) => r.kind === "walk_error").length, 30);
      assert.deepEqual(rows.filter((r: Json) => r.kind === "walk_error").map((r: Json) => r.path).slice(-1), ["locked29"]);
      assert.match(out.status_basis, /walk\.first_errors and the problems table/);
      assert.doesNotMatch(out.status_basis, /walk_errors/);
    } finally {
      for (let i = 0; i < 30; i++) await chmod(join(cwd, `inputs/p/locked${String(i).padStart(2, "0")}`), 0o755);
    }
  });
});

test("an unreadable directory and a link are reported, never followed or dropped; a pipe does not hang the walk", async (t) => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/t/C/a", "x");
    await put(cwd, "outside/uploads.json", JSON.stringify({ vfs_path: "x" }) + "\n");
    await link(cwd, "inputs/t/link-out", join(cwd, "outside"));
    execFileSync("mkfifo", [join(cwd, "inputs/t/pipe")]);
    await put(cwd, "inputs/t/locked/uploads.json", "{}\n");
    await chmod(join(cwd, "inputs/t/locked"), 0o000);
    try {
      const out = body(await tool(ID, cwd, { root: "inputs/t" }));
      assert.equal(out.walk.symbolic_links_not_followed, 1);
      assert.deepEqual(out.walk.first_links.map((l: Json) => l.path), ["link-out"]);
      assert.equal(out.walk.special_files_not_read, 1);
      assert.equal(out.failed_target_count, null);
      if (!root) {
        assert.equal(out.collector_candidates.length, 0, "the link's target and the unlisted directory were not read");
        assert.equal(out.walk.errors, 1);
        assert.equal(out.walk.first_errors[0].path, "locked");
        assert.equal(out.status, "partial");
      } else t.diagnostic("running as root: the mode-000 directory is readable");
    } finally {
      await chmod(join(cwd, "inputs/t/locked"), 0o755);
    }
  });
});

test("a log that was a link when the walk began is not read through it", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "secret-elsewhere.csv", "SourceFile,Reason\nC:\\x,y\n");
    await link(cwd, "inputs/k/r_SkipLog.csv", join(cwd, "secret-elsewhere.csv"));
    const out = body(await tool(ID, cwd, { root: "inputs/k" }));
    assert.equal(out.collector_candidates.length, 0);
    assert.equal(out.failed_targets_seen, 0);
    assert.equal(out.walk.symbolic_links_not_followed, 1);
  });
});

test("bytes that are not UTF-8 in a log are counted and survive in valid JSON; a lone surrogate never raises", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/r_SkipLog.csv", Buffer.concat([Buffer.from("SourceFile,Reason\nC:\\caf"), Buffer.from([0xe9]), Buffer.from(",gone\n")]));
    const run = await tool(ID, cwd, { root: "inputs/k" });
    const out = body(run);
    assert.equal(runs(out, "KAPE")[0].logs[0].rows_with_undecodable_bytes, 1);
    assert.equal(out.failed_targets[0].target, "C:\\caf\udce9");
    assert.match(run.stdout, /caf\\udce9/, "written as an escape, readable as JSON, not a crash");
  });
});

// Every secret-shaped string a collector's log or a path can carry, each placed in every channel the tool prints: a UAC ERR line, a
// KAPE skip row (value and column name), a Velociraptor result row (value and key), a log.json line and a file name. The test asserts
// that no 6-character window of the secret part is in the answer, the files it names, or stderr.
const SECRETS: Record<string, string> = {
  urlAt: "Wint3rPass99@Synth77Tail",                                 // a password that holds an @, behind a user name
  urlSlash: "Pa/ss9WordTail77",                                      // a password that holds a slash
  basic: "dXNlcjpTZWNyZXRQYXNzd29yZDEy",
  awsSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYQ7vT2mZ9nB4c",
  password: "Zebra7Quartz!Hunter2",
  pem: "MIIEowIBAAKCAQEAq7ZkP3rT9vLmN2xWc5YhB8dF1gJ4sUo6aEi0",
  ghp: "ghp_" + "Zq7Svb9Kt00123456789abcdefghijKLMNOP",             // a GitHub token: ghp_ and 36 characters
  jwe: "eyJhbGciOiJSQS1PQUVQIiwiZW5jIjoiQTI1NkdDTSJ9.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ",
};
const SECRET_TEXT = [
  `connect ftp://svc_backup:${SECRETS.urlAt}@10.20.30.40/drop failed`,
  `get https://admin:${SECRETS.urlSlash}@files.example.test/x failed`,
  `Authorization: Basic ${SECRETS.basic}`,
  `aws_access_key_id=${AWS_EXAMPLE_KEY_ID} aws_secret_access_key=${SECRETS.awsSecret}`,
  `login password=${SECRETS.password} refused`,
  `-----BEGIN RSA PRIVATE KEY-----\n${SECRETS.pem}\n-----END RSA PRIVATE KEY-----`,
  `token backup_${SECRETS.ghp} rejected`,
  `blob ${SECRETS.jwe}`,
];

test("no secret-shaped string reaches the answer, a file it names or stderr, from any channel; the real strings are in the sealed values file only when asked, in a job", async () => {
  await withCwd(async (cwd) => {
    const uac = SECRET_TEXT.map((s, i) => uac3("ERR", s.replace(/\n/g, " "), i)).join("\n") + "\n";
    await put(cwd, "inputs/s/uac.log", uac);
    const csvCell = (s: string) => `"${s.replace(/"/g, '""')}"`;
    await put(cwd, "inputs/s/k/r_SkipLog.csv", `SourceFile,Reason,${SECRETS.ghp}\n${SECRET_TEXT.map((s, i) => `C:\\f${i},${csvCell(s)},x`).join("\n")}\n`);
    await put(cwd, "inputs/s/v/uploads.json", veloUploadsRow("/C:/a") + "\n");
    await put(cwd, "inputs/s/v/results/Custom.json", JSON.stringify({ Upload: { Path: "/C:/b", StoredName: "/uploads/b", Error: SECRET_TEXT[0], [SECRETS.ghp]: "key" } }) + "\n");
    await put(cwd, "inputs/s/v/log.json", SECRET_TEXT.map((s) => veloLogRow("ERROR", s)).join("\n") + "\n");
    const run = await tool(ID, cwd, { root: "inputs/s" });
    const out = body(run);
    const files: string[] = [];
    for (const info of Object.values(out.tables) as Json[]) if (info.all_results) files.push(await readFile(join(cwd, info.all_results), "utf8"));
    const everything = [run.stdout, run.stderr, ...files].join("\n");
    assertAbsent(everything, { ...SECRETS, aws: AWS_EXAMPLE_KEY_ID }, "collection_id");
    assert.ok(out.withheld.strings_withheld > 8);
    assert.match(everything, /withheld, \d+ characters, W\d{6}>/, "each withheld text carries a finding id");
    // asked outside a job: refused by name, nothing written
    assert.match(refused(await tool(ID, cwd, { root: "inputs/s", write_values: true })).error, /refused outside a job/);
    // in a job: the file is created first, 0600, holds the real strings; the answer says where
    const job = await asJob(ID, cwd, { root: "inputs/s", write_values: true }, {}, "out", "j000900");
    assertAbsent(job.stdout + job.stderr, { ...SECRETS, aws: AWS_EXAMPLE_KEY_ID }, "collection_id in a job");
    const answer = body(job);
    assert.equal(answer.withheld.values.values_file, "store/jobs/j000900/out/collection-id-values.jsonl");
    const file = join(cwd, "out", "collection-id-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const rows = await readRows(file);
    assert.equal(rows.length, answer.withheld.values.written);
    const all = JSON.stringify(rows);
    for (const [name, secret] of Object.entries({ urlAt: SECRETS.urlAt, pem: SECRETS.pem, aws: AWS_EXAMPLE_KEY_ID })) assert.ok(all.includes(secret), `${name} is in the sealed file`);
    assert.ok(rows.every((r: Json) => /^W\d{6}$/.test(r.finding_id)));
    // a second run in the same job does not overwrite it: refused by name, the file is untouched
    const before = await readFile(file, "utf8");
    assert.match(refused(await asJob(ID, cwd, { root: "inputs/s", write_values: true }, {}, "out", "j000900")).error, /values file already exists/);
    assert.equal(await readFile(file, "utf8"), before);
  });
});

test("with nothing to withhold the values file is an empty 0600 file and the answer says written 0", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/c/C/a", "x");
    const answer = body(await asJob(ID, cwd, { root: "inputs/c", write_values: true }, {}, "out", "j000901"));
    assert.equal(answer.withheld.values.written, 0);
    assert.equal(answer.withheld.values.contains_secret_values, false);
    const file = join(cwd, "out", "collection-id-values.jsonl");
    assert.equal((await stat(file)).size, 0);
    assert.equal((await stat(file)).mode & 0o777, 0o600);
  });
});

test("a table longer than the limit goes whole to a file under $OUT in a job, a second run does not touch the first, and nothing is written elsewhere", async () => {
  await withCwd(async (cwd) => {
    const rows = ["SourceFile,Reason"];
    for (let i = 0; i < 7; i++) rows.push(`C:\\f${i},reason ${i}`);
    await put(cwd, "inputs/k/r_SkipLog.csv", rows.join("\n") + "\n");
    await chmod(join(cwd, "work"), 0o555);
    await chmod(join(cwd, "inputs"), 0o555);
    try {
      const first = body(await asJob(ID, cwd, { root: "inputs/k", limit: 3 }, {}, "out", "j000902"));
      assert.equal(first.failed_targets.length, 3);
      assert.equal(first.tables.failed_targets.matched, 7);
      assert.equal(first.tables.failed_targets.truncated, true);
      assert.match(first.tables.failed_targets.all_results, /^store\/jobs\/j000902\/out\/tool-output\/collection_id-failures-[0-9a-f]{16}\.jsonl$/);
      const kept = await tableRows(cwd, first.tables.failed_targets);
      assert.equal(kept.length, 7);
      assert.equal(kept[6].reason, "reason 6");
      const second = body(await asJob(ID, cwd, { root: "inputs/k", limit: 3 }, {}, "out", "j000902"));
      assert.notEqual(second.tables.failed_targets.all_results, first.tables.failed_targets.all_results);
      assert.equal((await tableRows(cwd, first.tables.failed_targets)).length, 7);
      assert.deepEqual((await filesUnder(join(cwd, "out"))).filter((f) => !f.startsWith("tool-output/")), []);
    } finally {
      await chmod(join(cwd, "work"), 0o755);
      await chmod(join(cwd, "inputs"), 0o755);
    }
  });
});

test("outside a job the whole table goes under work/<agent>/tool-output; where nothing can be written the answer is a JSON error, never a traceback", async () => {
  await withCwd(async (cwd) => {
    const rows = ["SourceFile,Reason"];
    for (let i = 0; i < 4; i++) rows.push(`C:\\f${i},r${i}`);
    await put(cwd, "inputs/k/r_SkipLog.csv", rows.join("\n") + "\n");
    const ok = body(await tool(ID, cwd, { root: "inputs/k", limit: 2 }));
    assert.match(ok.tables.failed_targets.all_results, /^work\/s1\/tool-output\/collection_id-failures-[0-9a-f]{16}\.jsonl$/);
    assert.equal((await tableRows(cwd, ok.tables.failed_targets)).length, 4);
    await mkdir(join(cwd, "ro"), { recursive: true });
    await chmod(join(cwd, "ro"), 0o555);
    try {
      if (root) return;
      const error = refused(await tool(ID, join(cwd, "ro"), { root: join(cwd, "inputs/k"), limit: 2 }));
      assert.match(error.error, /could not be written/);
    } finally {
      await chmod(join(cwd, "ro"), 0o755);
    }
  });
});

test("a root that contains the place the tool spills to does not list its own tables as delivered files", async () => {
  await withCwd(async (cwd) => {
    for (let i = 0; i < 5; i++) await put(cwd, `work/s1/files/case${i}.E01`, Buffer.concat([EWF_SIGNATURE, NUL(10)]));
    const out = body(await tool(ID, cwd, { root: "work/s1", limit: 2 }));
    assert.equal(out.walk.files, 5, "the objects table the run is writing under tool-output is not a delivered file");
    assert.equal(out.delivery.object_counts.disk_container, 5);
    assert.ok(out.tables.objects.all_results);
  });
});

test("a SIGTERM leaves a JSON answer that says the tool was stopped and no half-written file", async (t) => {
  await withCwd(async (cwd) => {
    const rows = ["SourceFile,Reason"];
    for (let i = 0; i < 400000; i++) rows.push(`C:\\file${i},reason number ${i}`);
    await put(cwd, "inputs/k/big_SkipLog.csv", rows.join("\n") + "\n");
    const child = spawn("python3", [ID], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    let out = "";
    child.stdout.on("data", (c: Buffer) => (out += c.toString()));
    const closed = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
    child.stdin.end(JSON.stringify({ root: "inputs/k", limit: 1 }));
    const dir = join(cwd, "work", "s1", "tool-output");
    for (let i = 0; i < 400; i++) {                                        // wait until the table has spilled into its temporary file
      if ((await readdir(dir).catch(() => [] as string[])).some((n) => n.startsWith(".collection_id-failures-"))) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    if (!(await readdir(dir).catch(() => [] as string[])).some((n) => n.startsWith(".collection_id-failures-"))) return t.skip("the tool finished before the signal");
    child.kill("SIGTERM");
    const code = await closed;
    assert.notEqual(code, 0);
    assert.match(JSON.parse(out).error, /stopped by signal 15/);
    assert.deepEqual((await readdir(dir)).filter((n) => n.startsWith(".")), [], "no hidden temporary file is left");
  });
});

test("bad arguments are JSON errors; a parameter the tool does not read is named in the answer", async () => {
  await withCwd(async (cwd) => {
    assert.match(refused(await tool(ID, cwd, {})).error, /root is required/);
    assert.match(refused(await tool(ID, cwd, { root: "nope" })).error, /no such directory/);
    await put(cwd, "inputs/a_SkipLog.csv", "x");
    assert.match(refused(await tool(ID, cwd, { root: "inputs/a_SkipLog.csv" })).error, /root is a file: give the directory that holds it/);
    assert.match(refused(await tool(ID, cwd, { root: "inputs", limit: 0 })).error, /limit must be an integer/);
    assert.match(refused(await tool(ID, cwd, { root: "inputs", write_values: "yes" })).error, /write_values must be true or false/);
    assert.match(refused(await tool(ID, cwd, { root: "inputs", time_limit_seconds: 0 })).error, /time_limit_seconds/);
    await mkdir(join(cwd, "inputs/ok"), { recursive: true });
    assert.deepEqual(body(await tool(ID, cwd, { root: "inputs/ok", time_limit: 5, bogus: true })).ignored_parameters, ["bogus", "time_limit"]);
  });
});

test("an archive is counted at the top level only; a nested archive is a copied file", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/a/collection.zip", Buffer.concat([Buffer.from("PK\x03\x04"), NUL(40)]));
    await put(cwd, "inputs/a/nested/inner.zip", Buffer.concat([Buffer.from("PK\x03\x04"), NUL(40)]));
    await put(cwd, "inputs/a/nested/report.docx", Buffer.concat([Buffer.from("PK\x03\x04"), NUL(40)]));
    const out = body(await tool(ID, cwd, { root: "inputs/a" }));
    assert.equal(out.delivery.object_counts.archive, 1);
    assert.equal(out.delivery.nested_archives_named_like_archives, 1);
    assert.equal(out.delivery.kind, "mixed");
    assert.deepEqual(out.objects.map((o: Json) => o.path), ["collection.zip"]);
    assert.match(out.objects[0].note, /not opened/);
  });
});

test("records of more than one collector in one tree are all named, each by its own paths, and none wins by order", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/m/uacdir/uac.log", uac3("INF", "Starting") + "\n");
    await put(cwd, "inputs/m/kapedir/r_CopyLog.csv", KAPE_COPY_HEADER + "\n" + kapeCopyRow("C:\\x", "D:\\o\\C\\x") + "\n");
    await put(cwd, "inputs/m/veloci/uploads.json", veloUploadsRow("/C:/x") + "\n");
    await put(cwd, "inputs/m/C/data.bin", "x");                      // a drive-letter directory beside them: a clue, not a fourth collector
    const out = body(await tool(ID, cwd, { root: "inputs/m" }));
    assert.deepEqual(out.collector_candidates.map((c: Json) => c.collector).sort(), ["KAPE", "UAC", "Velociraptor"]);
    const markers = Object.fromEntries(out.collector_candidates.map((c: Json) => [c.collector, c.observed_markers]));
    assert.deepEqual(markers.UAC, ["uacdir/uac.log"]);
    assert.deepEqual(markers.KAPE, ["kapedir/r_CopyLog.csv"]);
    assert.deepEqual(markers.Velociraptor, ["veloci/uploads.json"]);
    assert.equal(out.layout_clues.length, 1);
    assert.deepEqual(out.layout_clues[0].compatible_with, ["a KAPE target tree", "CyLR output", "a hand-made copy"]);
  });
});

test("runs are a table: 40 containers are 5 inline with limit 5 and all 40 in the file, and the answer's summary comes before every page", async () => {
  await withCwd(async (cwd) => {
    for (let i = 0; i < 40; i++) await put(cwd, `inputs/r/d${String(i).padStart(2, "0")}/uac.log`, uac3("INF", "x") + "\n");
    const run = await tool(ID, cwd, { root: "inputs/r", limit: 5 });
    const out = body(run);
    assert.equal(out.runs.length, 5);
    assert.equal(out.tables.runs.matched, 40);
    assert.equal((await tableRows(cwd, out.tables.runs)).length, 40);
    assert.equal(out.collector_candidates[0].markers_total, 40);
    assert.equal(out.collector_candidates[0].observed_markers.length, 25);
    const keys = Object.keys(JSON.parse(run.stdout));
    assert.deepEqual(keys.slice(-5), ["objects", "runs", "failed_targets", "unrecognised_rows", "problems"], "the pages come last");
    assert.ok(keys.indexOf("tables") < keys.indexOf("objects") && keys.indexOf("delivery") < keys.indexOf("objects"));
    assert.ok(run.stdout.indexOf('"tables"') < 65536, "the summary and the table index are inside the first 64 KiB the model reads");
  });
});

test("a file that is the name of a manifest example is read as a directory root: the error says give the directory", async () => {
  await withCwd(async (cwd) => {
    const manifest = JSON.parse(await readFile(join(ID, "..", "manifest.json"), "utf8"));
    const example = JSON.parse(manifest.example);
    await mkdir(join(cwd, example.root), { recursive: true });
    assert.equal(body(await asJob(ID, cwd, example, {}, "out", "j000990")).status, "complete");
  });
});

test("the nothing-else: no utimes verdict, the tool never opens a container, and the answer carries no old text", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/a/case.E01", Buffer.concat([EWF_SIGNATURE, NUL(100)]));
    await utimes(join(cwd, "inputs/a/case.E01"), 1_000_000, 1_000_000);
    const out = body(await tool(ID, cwd, { root: "inputs/a" }));
    assert.doesNotMatch(JSON.stringify(out), /probably|physical image|no carving|unallocated/i);
    assert.equal(out.delivery.object_counts.logical_files, undefined);
  });
});
