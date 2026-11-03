/**
 * lnk_jumplist and JLECmd: the optional second reader of a Jump List's DestList. Each DestList entry's `integrity.jlecmd` says `agree`,
 * `disagree` or `not_run`; a disagreement turns the status to partial, and a JLECmd that is absent, fails, runs out of time or writes too much is
 * `not_run` with the reason, never `agree`.
 *
 * The stand-in `JLECmd` writes the CSV the pinned build writes for `-f <file> --csv <dir>`: `<timestamp>_AutomaticDestinations.csv`, one row per
 * DestList entry, with the columns the build's metadata names (SourceFile, AppId, EntryNumber, CreationTime, LastModified, Hostname, Path,
 * PinStatus, ...). The values come from the fixture's own numbers (tests/windows-t1-fixtures.ts), never from the tool's output. The option names
 * (-f, --csv, --dt, -q) are the ones the pinned JLECmd 2026.10.6 build lists in its help strings; the build was not run for this test (see the
 * gated real-run case, which is skipped where dotnet or the dll is missing).
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN, body, everyFileUnder, stub, tool } from "./windows-pack-harness.ts";
import { FILETIME_A, cfb, destList, lnk, pathWithOnlyPython } from "./windows-t1-fixtures.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const APP = "1b4dd67f29cb1962";
const NAME = `${APP}.automaticDestinations-ms`;
const LOCAL = lnk({ local: { path: "C:\\case\\report.txt", serial: 0x1a2b3c4d, label: "SYSTEM" }, name: "Report" });
const entryPath = (n: number): string => `C:\\case\\f${n}.txt`;
/** A jump list of two links and a DestList of two entries: entry 1 unpinned, entry 2 pinned, each accessed one second after the one before. */
const AUTO = (paths: Record<number, string> = {}): Buffer =>
  cfb([
    { name: "1", data: LOCAL },
    { name: "2", data: LOCAL },
    { name: "DestList", data: destList(4, [1, 2].map((n) => ({ number: n, host: "WKS", filetime: FILETIME_A + BigInt(n) * 10_000_000n, pin: n === 2 ? 0 : -1, path: paths[n] ?? entryPath(n) }))) },
  ]);

type Csv = { n: number; path: string; time: string; pin: "Pinned" | "Unpinned"; app?: string };
const GOOD: Csv[] = [
  { n: 1, path: entryPath(1), time: "2023-11-13 00:53:21.1234567", pin: "Unpinned" },
  { n: 2, path: entryPath(2), time: "2023-11-13 00:53:22.1234567", pin: "Pinned" },
];
const field = (v: string): string => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
const HEAD = "SourceFile,SourceCreated,SourceModified,SourceAccessed,AppId,AppIdDescription,DestListVersion,LastUsedEntryNumber,MRU,EntryNumber,CreationTime,LastModified,Hostname,MacAddress,Path,PinStatus,FileBirthDroid,FileDroid,VolumeBirthDroid,VolumeDroid,TargetCreated,TargetModified,TargetAccessed,FileSize,RelativePath,WorkingDirectory,FileAttributes,HeaderFlags,DriveType,VolumeSerialNumber,VolumeLabel,LocalPath,CommonPath,TargetIDAbsolutePath,TargetMFTEntryNumber,TargetMFTSequenceNumber,MachineID,MachineMACAddress,TrackerCreatedOn,ExtraBlocksPresent,Arguments,InteractionCount";
function csvText(rows: Csv[], head = HEAD): string {
  const cols = head.split(",");
  const lines = rows.map((r, i) => {
    const values: Record<string, string> = { SourceFile: `/x/${NAME}`, AppId: r.app ?? APP, AppIdDescription: "Test", DestListVersion: "4", MRU: String(i), EntryNumber: String(r.n), CreationTime: "2023-11-13 00:00:00.0000000", LastModified: r.time, Hostname: "WKS", Path: r.path, PinStatus: r.pin };
    return cols.map((c) => field(values[c] ?? "")).join(",");
  });
  return [head, ...lines].join("\n") + "\n";
}
/** A JLECmd stand-in: records its arguments, then writes the CSV where `--csv` says. `after` runs after the CSV is written. */
const jlecmd = (csv: string, argsFile: string, extra = ""): string => `printf '%s\\n' "$@" > "${argsFile}"
f=""; d=""
while [ $# -gt 0 ]; do case "$1" in -f) f="$2"; shift;; --csv) d="$2"; shift;; esac; shift; done
cat > "$d/20261103000000_AutomaticDestinations.csv" <<'CSV'
${csv}CSV
${extra}`;

const rowsOf = async (cwd: string, out: Answer): Promise<Row[]> => (await readFile(join(cwd, out.rows_file ?? ""), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Row);
const entriesOf = (rows: Row[]): Row[] => rows.filter((r) => r.row === "destlist_entry");
const results = (rows: Row[]): string[] => entriesOf(rows).map((r) => r.integrity.jlecmd.result);
const leftovers = async (cwd: string): Promise<string[]> => (await everyFileUnder(cwd)).filter((f) => /\.jlecmd-/.test(f));
async function pidsOf(file: string, n: number): Promise<number[]> {
  for (let i = 0; i < 100; i++) {
    const ids = (await readFile(file, "utf8").catch(() => "")).trim().split("\n").filter(Boolean).map(Number);
    if (ids.length >= n) return ids;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`the stand-in never wrote ${n} process id(s) to ${file}`);
}
const gone = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return false;
  } catch {
    return true;
  }
};

test("JLECmd agrees: every entry says agree, the receipt counts it, the status is complete and the call is the one the build documents", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", NAME), AUTO());
    await stub(bin, "JLECmd", jlecmd(csvText(GOOD), join(cwd, "args.txt")));
    const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}` }, {}, bin));
    assert.equal(out.status, "complete", out.status_basis);
    assert.match(out.status_basis, /and with JLECmd where JLECmd was run/);
    assert.deepEqual([out.jlecmd.checked, out.jlecmd.agreed, out.jlecmd.disagreed, out.jlecmd.not_run, out.jlecmd.entries_agreed], [1, 1, 0, 0, 2]);
    const rows = await rowsOf(cwd, out);
    assert.deepEqual(results(rows), ["agree", "agree"]);
    assert.deepEqual(entriesOf(rows)[0].integrity.jlecmd.compared, ["entry_count", "path", "access_time", "pin_state", "application_id"]);
    const list = rows.find((r) => r.row === "destlist")!;
    assert.equal(list.integrity.jlecmd.result, "agree");
    assert.deepEqual([list.integrity.jlecmd.jlecmd_entries, list.integrity.jlecmd.destlist_entries], [2, 2]);
    // The arguments: the file, a CSV directory, a nanosecond date format, quiet. The directory is the tool's own, under its output, and is gone.
    const args = (await readFile(join(cwd, "args.txt"), "utf8")).trim().split("\n");
    assert.deepEqual([args[0], args[1].endsWith(NAME), args[2], args[4], args[5], args[6]], ["-f", true, "--csv", "--dt", "yyyy-MM-dd HH:mm:ss.fffffff", "-q"]);
    assert.match(args[3], /lnk_jumplist-[0-9a-f]{12}\/\.jlecmd-/);
    assert.deepEqual(await leftovers(cwd), []);
  });
});

test("a quoted path with a comma in JLECmd's CSV is one field, and a UTF-8 byte order mark before the first column does not hide that column", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", NAME), AUTO({ 1: "C:\\case\\a,b \"c\".txt" }));
    // EntryNumber is the first header, so a byte order mark kept in the name would make the column missing and the result not_run.
    const head = "EntryNumber,Path,LastModified,PinStatus,AppId";
    await stub(bin, "JLECmd", jlecmd("\uFEFF" + csvText([{ ...GOOD[0], path: "C:\\case\\a,b \"c\".txt" }, GOOD[1]], head), join(cwd, "args.txt")));
    const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}` }, {}, bin));
    assert.deepEqual(results(await rowsOf(cwd, out)), ["agree", "agree"], JSON.stringify(out.jlecmd));
  });
});

test("JLECmd disagrees: a path, a time, a pin state, an entry it lacks, an entry only it lists, another application id and another count are each said, and the status is partial", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", NAME), AUTO());
    const run = async (csv: Csv[]): Promise<{ out: Answer; rows: Row[] }> => {
      await stub(bin, "JLECmd", jlecmd(csvText(csv), join(cwd, "args.txt")));
      const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}` }, {}, bin));
      return { out, rows: await rowsOf(cwd, out) };
    };
    const fields = (rows: Row[], i: number): string[] => (entriesOf(rows)[i].integrity.jlecmd.differences ?? []).map((d: Row) => d.field);
    let r = await run([{ ...GOOD[0], path: "C:\\case\\other.txt" }, GOOD[1]]);
    assert.equal(r.out.status, "partial");
    assert.match(r.out.status_basis, /JLECmd disagrees with the DestList read on 1 jump list/);
    assert.deepEqual(results(r.rows), ["disagree", "agree"]);
    assert.deepEqual(fields(r.rows, 0), ["path"]);
    assert.equal(r.out.jlecmd.disagreed, 1);
    assert.equal(r.out.jlecmd.entries_disagreed, 1);
    r = await run([{ ...GOOD[0], time: "2023-11-13 00:53:21.1234568" }, GOOD[1]]);
    assert.deepEqual(fields(r.rows, 0), ["access_time"]);
    assert.equal(r.out.status, "partial");
    r = await run([GOOD[0], { ...GOOD[1], pin: "Unpinned" }]);
    assert.deepEqual(fields(r.rows, 1), ["pin_state"]);
    assert.equal(r.out.status, "partial");
    r = await run([GOOD[0]]);
    assert.deepEqual(fields(r.rows, 1), ["entry"]);
    assert.deepEqual(r.rows.find((x) => x.row === "destlist")!.integrity.jlecmd.differences, [{ field: "entry_count", destlist: 2, jlecmd: 1 }]);
    r = await run([...GOOD, { n: 9, path: "C:\\x", time: "2023-11-13 00:53:22.1234567", pin: "Unpinned" }]);
    assert.equal(r.out.status, "partial");
    assert.deepEqual(r.rows.find((x) => x.row === "destlist")!.integrity.jlecmd.differences.map((d: Row) => d.field), ["entry_count", "entries"]);
    r = await run([{ ...GOOD[0], app: "ffffffffffffffff" }, { ...GOOD[1], app: "ffffffffffffffff" }]);
    assert.equal(r.out.status, "partial");
    assert.deepEqual(r.rows.find((x) => x.row === "destlist")!.integrity.jlecmd.differences, [{ field: "application_id", file_name: APP, jlecmd: ["ffffffffffffffff"] }]);
    assert.deepEqual(results(r.rows), ["agree", "agree"], "the application id is a property of the file: the entries themselves agree, and the file's row and the status say it");
  });
});

test("a JLECmd that is absent, fails, writes nothing, writes an odd CSV or is not understood is not_run with the reason, the status says so, and nothing is called agree", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", NAME), AUTO());
    const why = async (script: string | null): Promise<Answer> => {
      if (script !== null) await stub(bin, "JLECmd", script);
      const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}` }, {}, bin));
      assert.equal(out.status, "complete", out.status_basis);
      assert.deepEqual([out.jlecmd.checked, out.jlecmd.agreed, out.jlecmd.not_run], [0, 0, 1]);
      assert.deepEqual(results(await rowsOf(cwd, out)), ["not_run", "not_run"]);
      assert.match(out.status_basis, /JLECmd, the second reader of a DestList, was not run for 1 jump list/);
      assert.deepEqual(await leftovers(cwd), []);
      return out;
    };
    const absent = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}` }, { PATH: await pathWithOnlyPython(cwd) }));
    assert.equal(absent.jlecmd.not_run, 1);
    assert.equal(absent.jlecmd.failed, 0, "an absent program is not a failed run");
    assert.match(JSON.stringify(absent.jlecmd.why_not_run), /JLECmd is not in this image/);
    assert.equal(absent.status, "complete");
    let out = await why("exit 3");
    assert.equal(out.jlecmd.failed, 1);
    assert.match(JSON.stringify(out.jlecmd.why_not_run), /JLECmd exited 3/);
    assert.match(out.status_basis, /gave no result for 1 of them/);
    out = await why("exit 0");
    assert.match(JSON.stringify(out.jlecmd.why_not_run), /wrote 0 automatic-destinations CSV/);
    out = await why(jlecmd(csvText(GOOD, "SourceFile,AppId,EntryNumber,Path,PinStatus"), join(cwd, "args.txt")));
    assert.match(JSON.stringify(out.jlecmd.why_not_run), /no column LastModified/);
    out = await why(jlecmd(csvText([{ ...GOOD[0], time: "11/13/2023 00:53:21" }, GOOD[1]]), join(cwd, "args.txt")));
    assert.match(JSON.stringify(out.jlecmd.why_not_run), /not a date to 100 nanoseconds/);
    out = await why(jlecmd(csvText([{ ...GOOD[0], pin: "Maybe" as "Pinned" }, GOOD[1]]), join(cwd, "args.txt")));
    assert.match(JSON.stringify(out.jlecmd.why_not_run), /PinStatus/);
    out = await why(jlecmd(csvText([{ ...GOOD[0], n: "0x1" as unknown as number }, GOOD[1]]), join(cwd, "args.txt")));
    assert.match(JSON.stringify(out.jlecmd.why_not_run), /EntryNumber/);
  });
});

test("JLECmd's output cap: a CSV or a stream of output past the cap ends the run, nothing is read from it, and its directory is removed", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", NAME), AUTO());
    // 40 MiB on standard output.
    await stub(bin, "JLECmd", "head -c 41943040 /dev/zero | tr '\\0' 'x'; exit 0");
    let out = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}`, max_seconds: 60 }, {}, bin));
    assert.equal(out.jlecmd.not_run, 1);
    assert.match(JSON.stringify(out.jlecmd.why_not_run), /cap/);
    assert.deepEqual(results(await rowsOf(cwd, out)), ["not_run", "not_run"]);
    // 40 MiB in the CSV itself, rows that would otherwise agree: the cap stops the writer, and the file that reached it is not read.
    await stub(bin, "JLECmd", jlecmd(csvText(GOOD), join(cwd, "args.txt"), 'head -c 41943040 /dev/zero | tr "\\0" "x" >> "$d/20261103000000_AutomaticDestinations.csv"; exit 0'));
    out = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}`, max_seconds: 60 }, {}, bin));
    assert.equal(out.jlecmd.agreed, 0);
    assert.equal(out.jlecmd.not_run, 1);
    assert.match(JSON.stringify(out.jlecmd.why_not_run), /cap/);
    assert.deepEqual(await leftovers(cwd), []);
  });
});

test("JLECmd runs under the tool's own clock: it is ended before max_seconds, a clock too short does not start it, and no child survives", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", NAME), AUTO());
    const pidFile = join(cwd, "jlecmd.pid");
    await stub(bin, "JLECmd", `echo $$ >> "${pidFile}"; exec sleep 60`);
    const began = Date.now();
    const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}`, max_seconds: 12 }, {}, bin));
    const took = Date.now() - began;
    assert.ok(took < 12_000, `the answer came in ${took} ms, inside max_seconds`);
    assert.match(JSON.stringify(out.jlecmd.why_not_run), /did not answer in \d+ seconds/);
    assert.equal(out.jlecmd.failed, 1);
    assert.equal(out.status, "complete");
    assert.deepEqual(results(await rowsOf(cwd, out)), ["not_run", "not_run"]);
    const [pid] = await pidsOf(pidFile, 1);
    await new Promise((r) => setTimeout(r, 300));
    assert.ok(gone(pid), "JLECmd is gone");
    assert.deepEqual(await leftovers(cwd), []);
    // A clock of 5 seconds leaves no room (the tool keeps 6 back for ending a run and for the answer): JLECmd is not started.
    const short = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}`, max_seconds: 5 }, {}, bin));
    assert.match(JSON.stringify(short.jlecmd.why_not_run), /clock/);
    assert.equal((await readFile(pidFile, "utf8")).trim().split("\n").length, 1, "it was not started again");
  });
});

test("SIGTERM while JLECmd runs: no child is left, no directory of JLECmd's is left, and the tool answers interrupted with exit 143", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", NAME), AUTO());
    const pidFile = join(cwd, "jlecmd.pid");
    await stub(bin, "JLECmd", `echo $$ >> "${pidFile}"; (sleep 60 & echo $! >> "${pidFile}"; wait) & wait`);
    const child = spawn("python3", [join(WIN, "lnk_jumplist", "run.py")], { cwd, env: { ...process.env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}` }, stdio: ["pipe", "pipe", "pipe"] });
    const chunks: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => chunks.push(c));
    child.stdin.end(JSON.stringify({ path: `work/${NAME}`, max_seconds: 100 }));
    const pids = await pidsOf(pidFile, 2);
    child.kill("SIGTERM");
    const code = await new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
    assert.equal(code, 143);
    assert.equal((JSON.parse(Buffer.concat(chunks).toString("utf8")) as Answer).status, "interrupted");
    await new Promise((r) => setTimeout(r, 300));
    for (const pid of pids) assert.ok(gone(pid), `process ${pid} is gone with the tool`);
    assert.deepEqual(await leftovers(cwd), []);
  });
});

test("a jump list whose DestList cannot be compared (cut, empty) or that has none is not given to JLECmd, and a custom destinations file and a lone link are not either", async () => {
  await withCwd(async (cwd, bin) => {
    const marker = join(cwd, "called.txt");
    await stub(bin, "JLECmd", `echo called >> "${marker}"; exit 1`);
    await writeFile(join(cwd, "work", "lone.lnk"), LOCAL);
    await writeFile(join(cwd, "work", `${APP}.customDestinations-ms`), Buffer.concat([LOCAL, Buffer.alloc(16, 1)]));
    await writeFile(join(cwd, "work", "0000000000000001.automaticDestinations-ms"), cfb([{ name: "DestList", data: destList(4, []) }]));
    const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work" }, {}, bin));
    assert.equal(out.jlecmd.checked + out.jlecmd.failed, 0);
    assert.match(JSON.stringify(out.jlecmd.why_not_run), /no entries read/);
    assert.equal(await readFile(marker, "utf8").catch(() => ""), "");
  });
});

// ---- the real program, where it is installed -----------------------------------------------------------------------------------------

const hasReal = spawnSync("sh", ["-c", "command -v dotnet >/dev/null && command -v JLECmd >/dev/null"]).status === 0;
test("the real JLECmd (through dotnet) reads the fixture's DestList and agrees with it", { skip: hasReal ? false : "dotnet or JLECmd (the pinned JLECmd.dll behind a wrapper) is not on PATH on this host" }, async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", NAME), AUTO());
    const version = spawnSync("sh", ["-c", "JLECmd --help 2>&1 | head -n 3"], { encoding: "utf8" }).stdout.trim();
    const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}` }));
    console.log(`# real JLECmd: ${version.replace(/\n/g, " | ")}`);
    assert.equal(out.jlecmd.checked, 1, JSON.stringify(out.jlecmd));
    assert.deepEqual(results(await rowsOf(cwd, out)), ["agree", "agree"], JSON.stringify(out.jlecmd));
  });
});

// ---- the time of an entry, the guards, the budget ------------------------------------------------------------------------------------

const AUTO_TIMES = (first: bigint): Buffer =>
  cfb([
    { name: "1", data: LOCAL },
    { name: "2", data: LOCAL },
    { name: "DestList", data: destList(4, [{ number: 1, host: "WKS", filetime: first, pin: -1, path: entryPath(1) }, { number: 2, host: "WKS", filetime: FILETIME_A + 20_000_000n, pin: 0, path: entryPath(2) }]) },
  ]);

test("an entry whose DestList FILETIME has no date is compared, not skipped: 0 must be JLECmd's 1601 instant, a value past year 9999 is not_compared and not listed as compared", async () => {
  await withCwd(async (cwd, bin) => {
    const run = async (first: bigint, theirs: string): Promise<{ out: Answer; rows: Row[] }> => {
      await writeFile(join(cwd, "work", NAME), AUTO_TIMES(first));
      await stub(bin, "JLECmd", jlecmd(csvText([{ ...GOOD[0], time: theirs }, GOOD[1]]), join(cwd, "args.txt")));
      const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}` }, {}, bin));
      return { out, rows: await rowsOf(cwd, out) };
    };
    // FILETIME 0 and JLECmd printing a 2023 date: a disagreement, not an agreement that skipped the field.
    let r = await run(0n, "2023-11-13 00:53:21.1234567");
    assert.equal(r.out.status, "partial");
    assert.deepEqual(results(r.rows), ["disagree", "agree"]);
    assert.deepEqual(entriesOf(r.rows)[0].integrity.jlecmd.differences, [{ field: "access_time", destlist: "1601-01-01T00:00:00.0000000Z", jlecmd: "2023-11-13T00:53:21.1234567Z" }]);
    // FILETIME 0 and JLECmd printing the same instant: agreement, with access_time compared.
    r = await run(0n, "1601-01-01 00:00:00.0000000");
    assert.equal(r.out.status, "complete", r.out.status_basis);
    assert.deepEqual(results(r.rows), ["agree", "agree"]);
    assert.ok(entriesOf(r.rows)[0].integrity.jlecmd.compared.includes("access_time"));
    // A FILETIME past year 9999: nothing to compare, said in the entry, and access_time is not among its compared fields.
    r = await run(0xffffffffffffffffn, "2023-11-13 00:53:21.1234567");
    const one = entriesOf(r.rows)[0].integrity.jlecmd;
    assert.equal(one.result, "agree");
    assert.ok(!one.compared.includes("access_time"), JSON.stringify(one));
    assert.equal(one.not_compared[0].field, "access_time");
    assert.ok(entriesOf(r.rows)[1].integrity.jlecmd.compared.includes("access_time"));
  });
});

test("guards: a CSV that lists an entry twice, two CSV files, and a DestList read only to its first 50,000 entries are each disagree or not_run, never agree", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", NAME), AUTO());
    await stub(bin, "JLECmd", jlecmd(csvText([...GOOD, GOOD[1]]), join(cwd, "args.txt")));
    let out = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}` }, {}, bin));
    assert.equal(out.status, "partial");
    assert.match(JSON.stringify((await rowsOf(cwd, out)).find((r) => r.row === "destlist")!.integrity.jlecmd.differences), /jlecmd_lists_twice/);
    await stub(bin, "JLECmd", jlecmd(csvText(GOOD), join(cwd, "args.txt"), 'cp "$d/20261103000000_AutomaticDestinations.csv" "$d/20261103000001_AutomaticDestinations.csv"'));
    out = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}` }, {}, bin));
    assert.equal(out.jlecmd.agreed, 0);
    assert.match(JSON.stringify(out.jlecmd.why_not_run), /wrote 2 automatic-destinations CSV/);
    const marker = join(cwd, "called.txt");
    await stub(bin, "JLECmd", `echo called >> "${marker}"; exit 1`);
    const many = Array.from({ length: 50_001 }, (_, i) => ({ number: i + 1, host: "W", filetime: FILETIME_A, pin: -1, path: "a" }));
    await writeFile(join(cwd, "work", NAME), cfb([{ name: "1", data: LOCAL }, { name: "DestList", data: destList(4, many) }]));
    out = body<Answer>(await tool("lnk_jumplist", cwd, { path: `work/${NAME}`, max_seconds: 100 }, {}, bin));
    assert.match(JSON.stringify(out.jlecmd.why_not_run), /DestList cut/);
    assert.equal(await readFile(marker, "utf8").catch(() => ""), "");
  });
});

test("the budget: after 200 jump lists were given to JLECmd the rest are not_run, said, and not started", async () => {
  await withCwd(async (cwd, bin) => {
    const calls = join(cwd, "calls.txt");
    await stub(bin, "JLECmd", `echo x >> "${calls}"; exit 1`);
    for (let i = 0; i < 203; i++) await writeFile(join(cwd, "work", `${i.toString(16).padStart(16, "0")}.automaticDestinations-ms`), AUTO());
    const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work", max_seconds: 100 }, {}, bin));
    assert.equal(out.jlecmd.failed, 200);
    assert.equal(out.jlecmd.why_not_run.budget, 3);
    assert.equal((await readFile(calls, "utf8")).trim().split("\n").length, 200);
    assert.equal(out.jlecmd.agreed, 0);
  });
});
