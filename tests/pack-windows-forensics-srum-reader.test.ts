/**
 * srum_reader: SRUDB.dat through SrumECmd and dissect.target, with the backend named on every row.
 *
 * Neither backend is installed where this suite was written (no dotnet, no Windows, no dissect.target), so the backends here are stand-ins that write
 * the shapes the pinned SrumECmd 2026.10.1 documents in its help strings and metadata: `-f <SRUDB.dat> [-r <SOFTWARE>] --csv <dir> --temp <dir>
 * --dt <format>`, a CSV per table named `<timestamp>_SrumECmd_<table>_Output.csv`, and the console lines `Found SRUM database file ... (State: ...)`.
 * The same build refuses to run off Windows ("Non-Windows platforms not supported ...", read from its strings), and one case holds the tool to that.
 * The dissect.target stand-in prints JSON lines for `target-query -f srum --json <dir>`. None of these shapes comes from a real run of the programs.
 * The ESE header the tool reads itself is built here from libyal's documented layout (signature EF CD AB 89 at offset 4, the database state at 52).
 * The ESE test databases libyal publishes could not be fetched in this work (no network), so no real SRUDB.dat is read by the suite; the gated
 * case at the end runs the real programs where they are on PATH and says so.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN, body, everyFileUnder, failed, stub, tool } from "./windows-pack-harness.ts";
import { SHAPES, leaked, plant } from "./windows-canary.ts";
import { pathWithOnlyPython } from "./windows-t1-fixtures.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** The 4 KiB head of an ESE database: checksum, signature at 4, format version at 8, file type at 12, database state at 52 (libyal's layout). */
function ese(state: number, pad = 4096): Buffer {
  const b = Buffer.alloc(pad);
  Buffer.from("efcdab89", "hex").copy(b, 4);
  b.writeUInt32LE(0x620, 8);
  b.writeUInt32LE(0, 12);
  b.writeUInt32LE(state, 52);
  return b;
}

const NET_HEAD = "Id,Timestamp,ExeInfo,ExeInfoDescription,ExeTimestamp,SidType,Sid,UserName,UserId,AppId,BytesSent,BytesReceived,InterfaceLuid,InterfaceType,L2ProfileId,ProfileName";
type Net = { id: number; time: string; app?: string; sid?: string; user?: string; sent?: number; recv?: number; profile?: string; profileId?: number };
const net = (r: Net): string =>
  [r.id, r.time, r.app ?? "", "", "2026-01-01 00:00:00", "User", r.sid ?? "", r.user ?? "", 5, 7 + r.id, r.sent ?? 100 * r.id, r.recv ?? 200 * r.id, "1689399632855040", "Ethernet", r.profileId ?? 11, r.profile ?? ""]
    .map((v) => (/[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v)))
    .join(",");
const NET_GOOD: Net[] = [
  { id: 1, time: "2026-10-12 08:00:00", app: "C:\\Windows\\System32\\svchost.exe", sid: "S-1-5-18", user: "SYSTEM", profile: "HomeNet" },
  { id: 2, time: "2026-10-12 09:00:00", app: "C:\\Program Files\\Chrome\\chrome.exe", sid: "S-1-5-21-111-222-333-1001", user: "alice" },
  { id: 3, time: "2026-10-12 11:30:00", app: "", sid: "", user: "" },
];
const CONSOLE_CLEAN = "Found SRUM database file 'x' (State: Clean Shutdown, Format Version: 1568, Engine Version: 6.2)";

/** A SrumECmd stand-in: records its arguments, writes the CSV named by --csv, prints `console`, exits `code`. */
function srumecmd(csvs: Record<string, string>, argsFile: string, opts: { console?: string; code?: number; before?: string; after?: string } = {}): string {
  const writes = Object.entries(csvs)
    .map(([name, text]) => `cat > "$d/${name}" <<'CSV'\n${text}CSV`)
    .join("\n");
  return `printf '%s\\n' "$@" > "${argsFile}"
d=""
while [ $# -gt 0 ]; do case "$1" in --csv) d="$2"; shift;; esac; shift; done
${opts.before ?? ""}
${writes}
${opts.console ? `echo "${opts.console}"` : ""}
${opts.after ?? ""}
exit ${opts.code ?? 0}`;
}
const NET_CSV = (rows: Net[] = NET_GOOD): Record<string, string> => ({ "20261104000000_SrumECmd_NetworkUsages_Output.csv": [NET_HEAD, ...rows.map(net)].join("\n") + "\n" });

/** A target-query stand-in: `--help` lists --json; any other call prints `lines` as JSON records. */
const targetQuery = (lines: object[], extra = ""): string => `case "$*" in *--help*) echo "usage: target-query [--json] [-f FUNCTION] target"; exit 0;; esac
${extra}
cat <<'JSONL'
${lines.map((l) => JSON.stringify(l)).join("\n")}
JSONL`;
const dissectRecords = (table: string, n: number): object[] =>
  Array.from({ length: n }, (_, i) => ({ _recorddescriptor: [`windows/srum/${table}`, []], ts: `2026-10-12T0${8 + i}:00:00.000000+00:00`, app: `a${i}`, bytes_sent: 100 * (i + 1) }));

async function layout(cwd: string, state = 3, logs: string[] = [], hive = true): Promise<{ db: string; root: string; hive: string }> {
  const root = join(cwd, "work", "ev");
  const sru = join(root, "Windows", "System32", "sru");
  const cfg = join(root, "Windows", "System32", "config");
  await mkdir(sru, { recursive: true });
  await mkdir(cfg, { recursive: true });
  await writeFile(join(sru, "SRUDB.dat"), ese(state));
  for (const l of logs) await writeFile(join(sru, l), Buffer.alloc(4096));
  if (hive) await writeFile(join(cfg, "SOFTWARE"), Buffer.from("regf" + "\0".repeat(100)));
  return { db: join(sru, "SRUDB.dat"), root, hive: join(cfg, "SOFTWARE") };
}
const rowsOf = async (cwd: string, out: Answer): Promise<Row[]> => (await readFile(join(cwd, out.rows_file ?? ""), "utf8")).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as Row);
const leftovers = async (cwd: string): Promise<string[]> => (await everyFileUnder(cwd)).filter((f) => /\.(srumecmd|dissect)-/.test(f));
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
const byBackend = (out: Answer, backend: string): Answer[] => out.tables.filter((t: Answer) => t.backend === backend);

test("SrumECmd alone: rows carry their backend, ids are resolved or kept and counted, units come from the column names, the call is the one the help strings document", async () => {
  await withCwd(async (cwd, bin) => {
    const { db, hive } = await layout(cwd);
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(), join(cwd, "args.txt"), { console: CONSOLE_CLEAN }));
    const out = body<Answer>(await tool("srum_reader", cwd, { path: db, software: hive }, {}, bin));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.database.state, "clean shutdown");
    assert.equal(out.database.format_version, "0x620");
    assert.equal(out.backends.srumecmd.state, "ran");
    assert.equal(out.backends.srumecmd.facts.console_database_state, "Clean Shutdown");
    assert.equal(out.backends.dissect.state, "not_installed");
    assert.equal(out.comparison.state, "not_run");
    assert.equal(out.rows_total, 3);
    const rows = await rowsOf(cwd, out);
    assert.deepEqual(rows.map((r) => r.backend), ["srumecmd", "srumecmd", "srumecmd"]);
    assert.deepEqual(rows.map((r) => r.table), ["NetworkUsages", "NetworkUsages", "NetworkUsages"]);
    assert.deepEqual(rows.map((r) => r.source_row), [1, 2, 3]);
    assert.equal(rows[0].time, "2026-10-12T08:00:00Z");
    assert.equal(rows[0].time_raw, "2026-10-12 08:00:00");
    assert.deepEqual(rows[0].counters, { BytesSent: { value: 100, unit: "bytes" }, BytesReceived: { value: 200, unit: "bytes" } });
    assert.equal(rows[0].app_path, "C:\\Windows\\System32\\svchost.exe");
    assert.equal(rows[0].user_sid, "S-1-5-18");
    assert.equal(rows[0].profile_name, "HomeNet");
    assert.equal(rows[0].profile_resolved, true);
    // The distance to the previous distinct row time of the table, not the length of an interval.
    assert.deepEqual(rows.map((r) => r.interval_seconds_since_previous_row_time), [null, 3600, 9000]);
    // Unresolved ids are kept in their rows, flagged and counted.
    assert.equal(rows[1].profile_resolved, false);
    assert.match(rows[1].profile_unresolved_because, /a SOFTWARE hive was given but SrumECmd printed no name/);
    assert.deepEqual([rows[2].app_resolved, rows[2].user_resolved, rows[2].app_path, rows[2].user_sid], [false, false, null, null]);
    assert.deepEqual(out.unresolved_ids_total, { app: 1, user: 1, profile: 2 });
    const t = byBackend(out, "srumecmd")[0];
    assert.deepEqual(t.retained_interval, { earliest: "2026-10-12T08:00:00Z", latest: "2026-10-12T11:30:00Z" });
    assert.deepEqual(t.unresolved_ids, { app: 1, user: 1, profile: 2 });
    assert.equal(t.canonical_table, "network_usage");
    assert.equal(out.rows.length, 3);
    // The arguments: the file, the hive, a CSV directory and a temp directory of the tool's own, a fixed date format.
    const args = (await readFile(join(cwd, "args.txt"), "utf8")).trim().split("\n");
    assert.deepEqual([args[0], args[1], args[2], args[3], args[4], args[6], args[8], args[9]], ["-f", db, "-r", hive, "--csv", "--temp", "--dt", "yyyy-MM-dd HH:mm:ss"]);
    assert.match(args[5], /srum_reader-[0-9a-f]{12}\/\.srumecmd-[^/]+\/csv$/);
    assert.deepEqual(await leftovers(cwd), []);
  });
});

test("without the SOFTWARE hive a profile id is unresolved and the row says why; a directory gives the one SRUDB.dat and the one config/SOFTWARE under it", async () => {
  await withCwd(async (cwd, bin) => {
    const { db, root, hive } = await layout(cwd);
    // (the stand-in prints a profile name only when it is given a hive, as the help string says the hive is for)
    const unnamed = NET_GOOD.map((r) => ({ ...r, profile: "" }));
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(unnamed), join(cwd, "args.txt"), { console: CONSOLE_CLEAN }));
    let out = body<Answer>(await tool("srum_reader", cwd, { path: db }, {}, bin));
    let rows = await rowsOf(cwd, out);
    assert.equal(rows[0].profile_resolved, false);
    assert.equal(rows[0].profile_unresolved_because, "no SOFTWARE hive was given");
    assert.equal(out.software_hive.path, null);
    assert.ok(!(await readFile(join(cwd, "args.txt"), "utf8")).includes("\n-r\n"));
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(), join(cwd, "args.txt"), { console: CONSOLE_CLEAN }));
    out = body<Answer>(await tool("srum_reader", cwd, { path: root }, {}, bin));
    assert.equal(out.database.path, db);
    assert.equal(out.software_hive.path, hive);
    assert.match(out.software_hive.found_by, /config\/SOFTWARE/);
    assert.ok((await readFile(join(cwd, "args.txt"), "utf8")).includes(`
-r
${hive}
`), "the hive found under the directory is given with -r");
    rows = await rowsOf(cwd, out);
    assert.equal(rows[0].profile_resolved, true);
    // Two databases under a directory: refused, naming them, nothing run.
    const other = join(root, "Other", "SRUDB.dat");
    await mkdir(join(root, "Other"), { recursive: true });
    await writeFile(other, ese(3));
    const e = failed(await tool("srum_reader", cwd, { path: root }, {}, bin));
    assert.match(e.error, /2 file\(s\) named SRUDB\.dat, not one/);
    assert.equal(e.found_count, 2);
  });
});

test("SrumECmd on a non-Windows host says unsupported_platform: no rows, the status is failed, and the run is never read as an empty database", async () => {
  await withCwd(async (cwd, bin) => {
    const { db } = await layout(cwd);
    await stub(bin, "SrumECmd", `echo "Non-Windows platforms not supported due to the need to load ESE specific Windows libraries! Exiting..."; exit 0`);
    const run = await tool("srum_reader", cwd, { path: db }, {}, bin);
    const out = failed(run) as Answer;
    assert.equal(out.status, "failed");
    assert.equal(out.backends.srumecmd.state, "unsupported_platform");
    assert.match(out.backends.srumecmd.why, /refuses to run on a non-Windows host/);
    assert.match(out.status_basis, /no backend produced rows/);
    assert.equal(out.rows_total, 0);
    assert.deepEqual(await leftovers(cwd), []);
    // The same with the backend asked for by name.
    const named = failed(await tool("srum_reader", cwd, { path: db, backend: "srumecmd" }, {}, bin)) as Answer;
    assert.equal(named.status, "failed");
    // With dissect.target also present, its rows are the answer and the unsupported backend is said, not hidden.
    const { root } = await layout(cwd);
    await stub(bin, "target-query", targetQuery(dissectRecords("network_usage", 2)));
    const both = body<Answer>(await tool("srum_reader", cwd, { path: root }, {}, bin));
    assert.equal(both.backends.srumecmd.state, "unsupported_platform");
    assert.equal(both.backends.dissect.state, "ran");
    assert.equal(both.comparison.state, "not_run");
    assert.deepEqual((await rowsOf(cwd, both)).map((r) => r.backend), ["dissect", "dissect"]);
  });
});

test("both backends: agreeing row counts say agree, differing counts say disagree and make the status partial, an unmatched table is not_compared and never agree", async () => {
  await withCwd(async (cwd, bin) => {
    const { root } = await layout(cwd);
    const two = NET_GOOD.slice(0, 2);
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(two), join(cwd, "args.txt"), { console: CONSOLE_CLEAN }));
    await stub(bin, "target-query", targetQuery(dissectRecords("network_usage", 2)));
    let out = body<Answer>(await tool("srum_reader", cwd, { path: root }, {}, bin));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.comparison.state, "agree");
    assert.deepEqual(out.comparison.tables.network_usage, { srumecmd: 2, dissect: 2, result: "agree" });
    assert.match(out.status_basis, /the two backends agree on every table's row count/);
    let rows = await rowsOf(cwd, out);
    assert.deepEqual(rows.map((r) => r.backend), ["srumecmd", "srumecmd", "dissect", "dissect"]);
    assert.equal(rows[2].counters && Object.keys(rows[2].counters).length, 0, "dissect's fields are kept, not interpreted");
    assert.equal(rows[2].other.bytes_sent, 100);
    // Disagree: dissect finds three.
    await stub(bin, "target-query", targetQuery(dissectRecords("network_usage", 3)));
    out = body<Answer>(await tool("srum_reader", cwd, { path: root }, {}, bin));
    assert.equal(out.status, "partial");
    assert.equal(out.comparison.state, "disagree");
    assert.deepEqual(out.comparison.tables.network_usage, { srumecmd: 2, dissect: 3, result: "disagree" });
    assert.match(out.status_basis, /disagree on the row count of 1 table/);
    // A table dissect names in a way this tool cannot match: not compared, partial, never agree.
    await stub(bin, "target-query", targetQuery(dissectRecords("zzz_unknown", 2)));
    out = body<Answer>(await tool("srum_reader", cwd, { path: root }, {}, bin));
    assert.notEqual(out.comparison.state, "agree");
    assert.equal(out.status, "partial");
    assert.ok(out.comparison.not_compared_count >= 1);
    // A table only one backend has is a disagreement.
    await stub(bin, "target-query", targetQuery(dissectRecords("push_notifications", 1)));
    out = body<Answer>(await tool("srum_reader", cwd, { path: root }, {}, bin));
    assert.equal(out.comparison.state, "disagree");
    assert.equal(out.comparison.tables.network_usage.result, "disagree");
    assert.match(out.comparison.tables.network_usage.why, /only srumecmd names this table/);
    rows = await rowsOf(cwd, out);
    assert.ok(rows.some((r) => r.backend === "dissect" && r.table === "push_notifications"));
  });
});

test("a backend that is absent, fails, times out, writes nothing, or writes an odd shape is not_run or reported, never agree; the other backend's rows stand with the state said", async () => {
  await withCwd(async (cwd, bin) => {
    const { root } = await layout(cwd);
    await stub(bin, "target-query", targetQuery(dissectRecords("network_usage", 2)));
    const run = async (script: string | null): Promise<Answer> => {
      if (script !== null) await stub(bin, "SrumECmd", script);
      const out = body<Answer>(await tool("srum_reader", cwd, { path: root, max_seconds: 20 }, {}, bin));
      assert.notEqual(out.comparison.state, "agree");
      assert.equal(out.comparison.state, "not_run");
      assert.equal(out.backends.dissect.state, "ran");
      assert.deepEqual(await leftovers(cwd), []);
      return out;
    };
    let out = await run("exit 3");
    assert.equal(out.backends.srumecmd.state, "failed");
    assert.match(out.backends.srumecmd.why, /SrumECmd exited 3/);
    out = await run("exit 0");
    assert.equal(out.backends.srumecmd.state, "failed");
    assert.match(out.backends.srumecmd.why, /wrote no table CSV/);
    out = await run("kill -9 $$");
    assert.match(out.backends.srumecmd.why, /ended by signal 9/);
    out = await run("sleep 60");
    assert.equal(out.backends.srumecmd.state, "timed_out");
    assert.match(out.backends.srumecmd.why, /did not finish in \d+ seconds/);
    // A table CSV with no header: the problem is named and the status is partial; both backends ran, so the counts are compared (2 against 0).
    await stub(bin, "SrumECmd", srumecmd({ "x_SrumECmd_NetworkUsages_Output.csv": "" }, join(cwd, "a.txt")));
    const empty = body<Answer>(await tool("srum_reader", cwd, { path: root, max_seconds: 20 }, {}, bin));
    assert.equal(empty.status, "partial");
    assert.match(empty.backends.srumecmd.problems.join(" "), /no header row/);
    assert.equal(empty.comparison.state, "disagree");
    const absent = failed(await tool("srum_reader", cwd, { path: root }, { PATH: await pathWithOnlyPython(cwd) })) as Answer;
    assert.equal(absent.backends.srumecmd.state, "not_installed");
    assert.equal(absent.backends.dissect.state, "not_installed");
    assert.equal(absent.status, "failed");
  });
});

test("a malformed CSV is named, not swallowed: a ragged row, a time that is not a date, bytes that are not UTF-8 and an over-wide header each make the status partial or the table unread", async () => {
  await withCwd(async (cwd, bin) => {
    const { db } = await layout(cwd);
    const run = async (text: string, name = "x_SrumECmd_NetworkUsages_Output.csv"): Promise<Answer> => {
      await stub(bin, "SrumECmd", srumecmd({ [name]: text }, join(cwd, "a.txt"), { console: CONSOLE_CLEAN }));
      return body<Answer>(await tool("srum_reader", cwd, { path: db, backend: "srumecmd" }, {}, bin));
    };
    let out = await run(`${NET_HEAD}\n${net(NET_GOOD[0])},extra1,extra2\n${net(NET_GOOD[1])}\n`);
    assert.equal(out.status, "partial");
    assert.match(out.backends.srumecmd.problems.join(" "), /row 1 has 2 cell\(s\) more than the header/);
    const rows = await rowsOf(cwd, out);
    assert.equal(rows.length, 2, "the ragged row is kept");
    assert.equal(rows[0].other._extra_cells, "extra1,extra2");
    out = await run(`${NET_HEAD}\n${net({ ...NET_GOOD[0], time: "12/10/2026 8am" })}\n`);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /1 row\(s\) have a time this tool could not read/);
    const bad = (await rowsOf(cwd, out))[0];
    assert.deepEqual([bad.time, bad.time_raw], [null, "12/10/2026 8am"]);
    out = await run(`${NET_HEAD}\n${net({ ...NET_GOOD[0], user: "caf\u00e9" })}\n`.replace("caf\u00e9", "caf\ufffd"));
    assert.equal(out.rows_total, 1);
    const wide = Array.from({ length: 600 }, (_, i) => `c${i}`).join(",");
    await stub(bin, "SrumECmd", srumecmd({ "x_SrumECmd_NetworkUsages_Output.csv": `${wide}\n${wide}\n` }, join(cwd, "a.txt"), { console: CONSOLE_CLEAN }));
    out = failed(await tool("srum_reader", cwd, { path: db, backend: "srumecmd" }, {}, bin)) as Answer;
    assert.equal(out.status, "failed", "a table that was not read gives no row");
    assert.match(out.backends.srumecmd.problems.join(" "), /600 columns/);
    // A table that is not one the tool knows is kept under its own name and says so.
    out = await run(`${NET_HEAD}\n${net(NET_GOOD[0])}\n`, "x_SrumECmd_Mystery_Output.csv");
    assert.match(byBackend(out, "srumecmd")[0].time_semantics, /not known to this tool/);
  });
});

test("the database state: a dirty one with no log beside it is partial, one with logs that no backend says it replayed is partial, one SrumECmd says it replayed is complete; a file that is not ESE is refused", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(), join(cwd, "args.txt"), { console: CONSOLE_CLEAN }));
    let { db } = await layout(cwd, 2);
    let out = body<Answer>(await tool("srum_reader", cwd, { path: db }, {}, bin));
    assert.equal(out.database.state, "dirty shutdown");
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /state 'dirty shutdown' \(not a clean shutdown\) and no log or checkpoint file is beside it/);
    ({ db } = await layout(cwd, 2, ["SRU.log", "SRU.chk", "SRUtmp.log", "notes.txt"]));
    out = await tool("srum_reader", cwd, { path: db }, {}, bin).then((r) => body<Answer>(r));
    assert.deepEqual(out.database.logs_beside.map((l: Row) => l.name), ["SRU.chk", "SRU.log", "SRUtmp.log"]);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /log files are beside it, but no backend said it replayed them/);
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(), join(cwd, "args.txt"), { console: "Transaction logs in 'x' replayed into the copies" }));
    out = body<Answer>(await tool("srum_reader", cwd, { path: db }, {}, bin));
    assert.equal(out.backends.srumecmd.facts.logs_replayed, true);
    assert.equal(out.status, "complete", out.status_basis);
    assert.match(out.database.state, /dirty shutdown/, "the header still says what the file says: the tool replays nothing");
    // The other states are not a clean shutdown either.
    for (const [code, name] of [[1, "just created"], [4, "being converted"], [5, "force detach"], [9, "unknown (9)"]] as const) {
      ({ db } = await layout(cwd, code));
      out = body<Answer>(await tool("srum_reader", cwd, { path: db }, {}, bin));
      assert.equal(out.database.state, name);
      assert.equal(out.status, "partial", `state ${code}`);
    }
    // Not an ESE file, a file too short, a missing file, a FIFO.
    await writeFile(join(cwd, "work", "notese.dat"), Buffer.alloc(4096, 1));
    assert.match(failed(await tool("srum_reader", cwd, { path: "work/notese.dat" }, {}, bin)).error, /not an ESE file/);
    await writeFile(join(cwd, "work", "short.dat"), Buffer.alloc(10));
    assert.match(failed(await tool("srum_reader", cwd, { path: "work/short.dat" }, {}, bin)).error, /not an ESE file/);
    assert.match(failed(await tool("srum_reader", cwd, { path: "work/missing.dat" }, {}, bin)).error, /could not be read/);
    spawnSync("mkfifo", [join(cwd, "work", "pipe.dat")]);
    assert.match(failed(await tool("srum_reader", cwd, { path: "work/pipe.dat" }, {}, bin)).error, /neither a regular file nor a directory/);
    await mkdir(join(cwd, "work", "soft"), { recursive: true });
    spawnSync("mkfifo", [join(cwd, "work", "soft", "hive")]);
    ({ db } = await layout(cwd));
    assert.match(failed(await tool("srum_reader", cwd, { path: db, software: "work/soft/hive" }, {}, bin)).error, /software is not a regular file/);
  });
});

test("what SrumECmd says about its own run is not lost: a table it could not export, a read problem, an error on the file, a repaired copy and an unreadable hive each make the status partial", async () => {
  await withCwd(async (cwd, bin) => {
    const { db, hive } = await layout(cwd);
    const say = async (line: string): Promise<Answer> => {
      await stub(bin, "SrumECmd", srumecmd(NET_CSV(), join(cwd, "args.txt"), { console: `${CONSOLE_CLEAN}\n${line}` }));
      return body<Answer>(await tool("srum_reader", cwd, { path: db, software: hive }, {}, bin));
    };
    let out = await say("Error exporting 'NetworkUsages' data! Error: boom");
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /reported 1 table\(s\) it could not export/);
    out = await say("3 problem(s) found while reading the database (everything else was exported):");
    assert.match(out.status_basis, /reported 3 problem\(s\) while reading the database/);
    out = await say("Error processing file! Message: x.");
    assert.match(out.status_basis, /an error processing the file/);
    out = await say("the copy was repaired with esentutl /p (what only the missing logs had is lost)");
    assert.match(out.status_basis, /repaired its copy of the database/);
    out = await say("Unable to read SOFTWARE hive 'x': user and network profile names are missing (see above)");
    assert.match(out.status_basis, /could not read the SOFTWARE hive/);
    assert.match((await rowsOf(cwd, out))[1].profile_unresolved_because, /could not read the SOFTWARE hive/);
    for (const r of [out]) assert.equal(r.status, "partial");
  });
});

test("a backend that ran and gave nothing usable is never complete: no output, a header-only CSV, error lines on stderr, and records of an unknown shape", async () => {
  await withCwd(async (cwd, bin) => {
    const { db, root } = await layout(cwd);
    const headerOnly = { "x_SrumECmd_NetworkUsages_Output.csv": `${NET_HEAD}\n` };
    // dissect prints nothing (exit 0), SrumECmd is absent: no backend produced a row.
    await stub(bin, "target-query", `case "$*" in *--help*) echo "--json"; exit 0;; esac\nexit 0`);
    let out = failed(await tool("srum_reader", cwd, { path: root, backend: "dissect" }, {}, bin)) as Answer;
    assert.equal(out.status, "failed");
    assert.equal(out.rows_total, 0);
    assert.match(out.status_basis, /no backend produced rows/);
    // a SrumECmd whose CSV is only a header: failed, not complete with 0 rows.
    await stub(bin, "SrumECmd", srumecmd(headerOnly, join(cwd, "a.txt"), { console: CONSOLE_CLEAN }));
    out = failed(await tool("srum_reader", cwd, { path: db, backend: "srumecmd" }, {}, bin)) as Answer;
    assert.equal(out.status, "failed");
    // with both: SrumECmd has rows and dissect nothing => partial, and the empty one is named.
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(), join(cwd, "a.txt"), { console: CONSOLE_CLEAN }));
    const both = body<Answer>(await tool("srum_reader", cwd, { path: root }, {}, bin));
    assert.equal(both.status, "partial");
    assert.match(both.status_basis, /dissect ran and exited 0 but produced no row/);
    // dissect stderr says error although it exits 0: partial, with the first line shown.
    await stub(bin, "target-query", targetQuery(dissectRecords("network_usage", 3), `echo "ERROR: failed to parse table" >&2`));
    const err = body<Answer>(await tool("srum_reader", cwd, { path: root }, {}, bin));
    assert.equal(err.status, "partial");
    assert.match(err.status_basis, /dissect printed 1 line\(s\) that say error/);
    assert.match(err.backends.dissect.facts.first_error_line, /failed to parse table/);
    // records of an unknown shape: no descriptor, no ts, a ts that is not a string.
    for (const odd of [{ foo: 1 }, { _recorddescriptor: ["windows/srum/network_usage", []] }, { _recorddescriptor: ["windows/srum/network_usage", []], ts: 5 }]) {
      await stub(bin, "target-query", targetQuery([odd]));
      const o = body<Answer>(await tool("srum_reader", cwd, { path: root, backend: "dissect" }, {}, bin));
      assert.equal(o.status, "partial", JSON.stringify(odd));
      assert.match(o.backends.dissect.problems.join(" "), /no _recorddescriptor|no readable ts/);
    }
  });
});

test("the status basis names the real database state: a dirty database whose logs SrumECmd replayed is complete and says dirty, not clean", async () => {
  await withCwd(async (cwd, bin) => {
    const { db } = await layout(cwd, 2, ["edb.log"]);
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(), join(cwd, "a.txt"), { console: "Transaction logs in 'x' replayed into the copies" }));
    const out = body<Answer>(await tool("srum_reader", cwd, { path: db }, {}, bin));
    assert.equal(out.status, "complete", out.status_basis);
    assert.match(out.status_basis, /database state is 'dirty shutdown', with log files beside it that a backend said it replayed/);
    assert.doesNotMatch(out.status_basis, /clean-shutdown/);
    const clean = await layout(cwd, 3);
    const c = body<Answer>(await tool("srum_reader", cwd, { path: clean.db }, {}, bin));
    assert.match(c.status_basis, /database state is 'clean shutdown'/);
  });
});

test("a backend that was run and failed or timed out while the other gave rows makes the status partial, said in the basis", async () => {
  await withCwd(async (cwd, bin) => {
    const { root } = await layout(cwd);
    await stub(bin, "target-query", targetQuery(dissectRecords("network_usage", 2)));
    await stub(bin, "SrumECmd", "exit 3");
    let out = body<Answer>(await tool("srum_reader", cwd, { path: root, max_seconds: 20 }, {}, bin));
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /srumecmd was run and failed .*its rows are missing and nothing was compared/);
    await stub(bin, "SrumECmd", "sleep 60");
    out = body<Answer>(await tool("srum_reader", cwd, { path: root, max_seconds: 10 }, {}, bin));
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /srumecmd was run and timed_out/);
    // unsupported_platform stays as designed: complete, said in backends and comparison.
    await stub(bin, "SrumECmd", `echo "Non-Windows platforms not supported due to the need to load ESE specific Windows libraries! Exiting..."`);
    out = body<Answer>(await tool("srum_reader", cwd, { path: root }, {}, bin));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.backends.srumecmd.state, "unsupported_platform");
  });
});

test("an interrupted run leaves no empty output directory", async () => {
  await withCwd(async (cwd, bin) => {
    const { db } = await layout(cwd);
    const pidFile = join(cwd, "srum.pid");
    await stub(bin, "SrumECmd", `echo $$ >> "${pidFile}"; exec sleep 60`);
    const child = spawn("python3", [join(WIN, "srum_reader", "run.py")], { cwd, env: { ...process.env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}` }, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify({ path: db, max_seconds: 100 }));
    await pidsOf(pidFile, 1);
    child.kill("SIGTERM");
    await new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
    const left = (await readdir(join(cwd, "work", "s1")).catch(() => [] as string[])).filter((n) => n.startsWith("srum_reader-"));
    assert.deepEqual(left, []);
  });
});

test("the arguments are checked before anything runs", async () => {
  await withCwd(async (cwd, bin) => {
    const { db } = await layout(cwd);
    for (const [args, re] of [
      [{}, /path is required/],
      [{ path: db, backend: "both" }, /backend is all, srumecmd or dissect/],
      [{ path: db, limit: 0 }, /limit must be a whole number/],
      [{ path: db, limit: 10001 }, /limit must be a whole number/],
      [{ path: db, limit: true }, /limit must be a whole number/],
      [{ path: db, max_seconds: 241 }, /max_seconds must be a number from 1 to 240/],
      [{ path: db, max_seconds: 0 }, /max_seconds must be a number/],
      [{ path: db, software: 7 }, /software, when given/],
      [[], /one JSON object/],
    ] as const) assert.match(failed(await tool("srum_reader", cwd, args, {}, bin)).error, re);
    const bad = await tool("srum_reader", cwd, "not json", {}, bin);
    assert.equal(bad.code, 1);
    assert.doesNotMatch(bad.stderr, /Traceback/);
    assert.equal(await readdir(join(cwd, "work")).then((l) => l.includes("s1")), false, "nothing was made for a refused call");
  });
});

test("the clock: a backend is ended well before max_seconds, a backend that cannot be given time is not started, and no child or work directory survives", async () => {
  await withCwd(async (cwd, bin) => {
    const { db } = await layout(cwd);
    const pidFile = join(cwd, "srum.pid");
    await stub(bin, "SrumECmd", `echo $$ >> "${pidFile}"; exec sleep 60`);
    const began = Date.now();
    const run = await tool("srum_reader", cwd, { path: db, max_seconds: 10 }, {}, bin);
    const took = Date.now() - began;
    const out = failed(run) as Answer;
    assert.ok(took < 10_000, `the answer came in ${took} ms, inside max_seconds`);
    assert.equal(out.backends.srumecmd.state, "timed_out");
    const [pid] = await pidsOf(pidFile, 1);
    await new Promise((r) => setTimeout(r, 300));
    assert.ok(gone(pid), "SrumECmd is gone");
    assert.deepEqual(await leftovers(cwd), []);
    // A clock of 2 seconds leaves nothing for a run (a run needs 2 seconds after the part kept back).
    const short = failed(await tool("srum_reader", cwd, { path: db, max_seconds: 2 }, {}, bin)) as Answer;
    assert.equal(short.backends.srumecmd.state, "not_attempted");
    assert.equal((await readFile(pidFile, "utf8")).trim().split("\n").length, 1, "it was not started again");
  });
});

test("four runs at once, each with a backend that never ends, all answer before the manifest's timeout and leave no child", async () => {
  await withCwd(async (cwd, bin) => {
    const { db } = await layout(cwd);
    const pidFile = join(cwd, "srum.pid");
    await stub(bin, "SrumECmd", `echo $$ >> "${pidFile}"; (sleep 60 & echo $! >> "${pidFile}"; wait) & wait`);
    const began = Date.now();
    const runs = await Promise.all([8, 9, 10, 11].map((s) => tool("srum_reader", cwd, { path: db, max_seconds: s }, { AGENT_ID: `p${s}` }, bin)));
    const took = Date.now() - began;
    for (const r of runs) assert.equal((failed(r) as Answer).backends.srumecmd.state, "timed_out");
    assert.ok(took < 30_000, `four runs took ${took} ms`);
    await new Promise((r) => setTimeout(r, 400));
    const pids = await pidsOf(pidFile, 8);
    for (const pid of pids) assert.ok(gone(pid), `process ${pid} is gone`);
    assert.deepEqual(await leftovers(cwd), []);
  });
});

test("SIGTERM, SIGINT and SIGHUP while a backend runs: no child, no work directory, an interrupted document, exit 128 plus the signal", async () => {
  for (const [name, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
    await withCwd(async (cwd, bin) => {
      const { db } = await layout(cwd);
      const pidFile = join(cwd, "srum.pid");
      await stub(bin, "SrumECmd", `echo $$ >> "${pidFile}"; (sleep 60 & echo $! >> "${pidFile}"; wait) & wait`);
      const child = spawn("python3", [join(WIN, "srum_reader", "run.py")], { cwd, env: { ...process.env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}` }, stdio: ["pipe", "pipe", "pipe"] });
      const chunks: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => chunks.push(c));
      child.stdin.end(JSON.stringify({ path: db, max_seconds: 100 }));
      const pids = await pidsOf(pidFile, 2);
      child.kill(name);
      const exit = await new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
      assert.equal(exit, code, name);
      const out = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Answer;
      assert.equal(out.status, "interrupted");
      assert.equal(out.signal, code - 128);
      await new Promise((r) => setTimeout(r, 300));
      for (const pid of pids) assert.ok(gone(pid), `${name}: process ${pid} is gone with the tool`);
      assert.deepEqual(await leftovers(cwd), [], name);
    });
  }
});

test("canaries in application paths, user names and profile names are not printed whole, in the answer, the rows file or on stderr", async () => {
  await withCwd(async (cwd, bin) => {
    const { db, hive } = await layout(cwd);
    const picked = SHAPES.filter((s) => s.fileOk && ["ghp", "akia", "glpat", "sk_live", "aiza"].includes(s.name));
    assert.ok(picked.length >= 4);
    const canaries = picked.flatMap((s) => plant(s, 2, 7));
    const rows: Net[] = canaries.map((c, i) => ({
      id: i + 1, time: `2026-10-12 0${i % 9}:00:00`, app: `C:\\Users\\${c.text}\\AppData\\run.exe`, sid: "S-1-5-21-1-2-3-1001", user: i % 2 ? `user ${c.text}` : "alice", profile: i % 3 === 0 ? `wifi ${c.text}` : "Home",
    }));
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(rows), join(cwd, "args.txt"), { console: CONSOLE_CLEAN }));
    const run = await tool("srum_reader", cwd, { path: db, software: hive, limit: 3 }, {}, bin);
    const out = body<Answer>(run);
    const file = await readFile(join(cwd, out.rows_file), "utf8");
    assert.equal(file.trim().split("\n").length, canaries.length);
    assert.equal(leaked(canaries, [run.stdout, run.stderr, file]), 0, "no canary core is printed whole");
    assert.ok(out.boundary.strings_withheld > 0, "the boundary withheld something");
    assert.match(file, /<withheld \d+ characters/);
    // A name that holds no secret is shown whole.
    assert.match(file, /"C:\\\\Windows\\\\System32\\\\svchost.exe"|alice|Home/);
  });
});

test("hostile input: a 3 MiB cell, 5,000 rows and a CSV whose rows carry control characters are read in bounded time and the answer is JSON", async () => {
  await withCwd(async (cwd, bin) => {
    const { db } = await layout(cwd);
    const big = Array.from({ length: 5000 }, (_, i) => ({ id: i + 1, time: `2026-10-${String(1 + (i % 28)).padStart(2, "0")} 08:${String(i % 60).padStart(2, "0")}:00`, app: `C:\\p${i}\\a.exe`, sid: "S-1-5-18", user: "u" }));
    big[10].app = "x".repeat(3 << 20);
    big[20].user = "a\u0007b\u001bc\u0000d";
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(big), join(cwd, "args.txt"), { console: CONSOLE_CLEAN }));
    const began = Date.now();
    const run = await tool("srum_reader", cwd, { path: db, limit: 5, max_seconds: 120 }, {}, bin);
    const out = body<Answer>(run);
    assert.ok(Date.now() - began < 120_000);
    assert.equal(out.rows_total, 5000);
    assert.ok(["complete", "partial"].includes(out.status));
    if (out.status === "complete") assert.equal(out.boundary.strings_withheld_by_the_stop ?? 0, 0);
    assert.equal(out.rows.length, 5);
    assert.equal(out.rows_inline_truncated, true);
  });
});

test("a dissect.target that lists no --json, fails, or is unsupported is reported and not read", async () => {
  await withCwd(async (cwd, bin) => {
    const { root } = await layout(cwd);
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(), join(cwd, "args.txt"), { console: CONSOLE_CLEAN }));
    const dissect = async (script: string, seconds = 100): Promise<Answer> => {
      await stub(bin, "target-query", script);
      const out = body<Answer>(await tool("srum_reader", cwd, { path: root, max_seconds: seconds }, {}, bin));
      assert.equal(out.comparison.state, "not_run");
      assert.deepEqual((await rowsOf(cwd, out)).map((r) => r.backend), ["srumecmd", "srumecmd", "srumecmd"]);
      return out;
    };
    let out = await dissect(`echo "usage: target-query target"`);
    assert.equal(out.backends.dissect.state, "unsupported_shape");
    out = await dissect(`case "$*" in *--help*) echo "--json"; exit 0;; esac; echo "no such plugin: srum" >&2; exit 2`);
    assert.equal(out.backends.dissect.state, "unsupported");
    out = await dissect(`case "$*" in *--help*) echo "--json"; exit 0;; esac; echo boom >&2; exit 1`);
    assert.equal(out.backends.dissect.state, "failed");
    out = await dissect(`case "$*" in *--help*) echo "--json"; exit 0;; esac; sleep 60`, 10);
    assert.equal(out.backends.dissect.state, "timed_out");
    assert.deepEqual(await leftovers(cwd), []);
    // Records that are not JSON, not objects, or longer than a line may be: counted as problems, the rest are read.
    await stub(bin, "target-query", `case "$*" in *--help*) echo "--json"; exit 0;; esac
echo 'not json'
echo '[1,2]'
echo '{"_recorddescriptor":["windows/srum/network_usage",[]],"ts":"2026-10-12T08:00:00+00:00"}'`);
    const odd = body<Answer>(await tool("srum_reader", cwd, { path: root, backend: "dissect" }, {}, bin));
    assert.equal(odd.status, "partial");
    assert.match(odd.backends.dissect.problems.join(" "), /record 1 is not JSON/);
    assert.equal(odd.rows_total, 1);
  });
});

test("a table with more than 250,000 distinct times is not given its distance to the previous one, and the table says so; the same rows keep their order and times", async () => {
  await withCwd(async (cwd, bin) => {
    const { db } = await layout(cwd);
    const rows: Net[] = [{ id: 1, time: "2026-10-12 08:00:00", app: "a", sid: "S-1-5-18", user: "u" }, { id: 2, time: "2026-10-12 08:00:00", app: "b", sid: "S-1-5-18", user: "u" }, { id: 3, time: "2026-10-12 07:00:00", app: "c", sid: "S-1-5-18", user: "u" }];
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(rows), join(cwd, "args.txt"), { console: CONSOLE_CLEAN }));
    const out = body<Answer>(await tool("srum_reader", cwd, { path: db }, {}, bin));
    const got = await rowsOf(cwd, out);
    // Rows out of file order and two with one time: the distance is to the previous distinct time, whatever the order in the file.
    assert.deepEqual(got.map((r) => r.interval_seconds_since_previous_row_time), [3600, 3600, null]);
    assert.deepEqual(byBackend(out, "srumecmd")[0].retained_interval, { earliest: "2026-10-12T07:00:00Z", latest: "2026-10-12T08:00:00Z" });
  });
});

test("a rerun does not replace a larger rows file with a smaller one, and the rows file is private to the output directory", async () => {
  await withCwd(async (cwd, bin) => {
    const { db } = await layout(cwd);
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(), join(cwd, "args.txt"), { console: CONSOLE_CLEAN }));
    const first = body<Answer>(await tool("srum_reader", cwd, { path: db }, {}, bin));
    const before = await readFile(join(cwd, first.rows_file), "utf8");
    const second = body<Answer>(await tool("srum_reader", cwd, { path: db, limit: 1 }, {}, bin));
    assert.equal(second.rows.length, 1);
    assert.equal(second.rows_total, 3);
    assert.equal(second.rows_file, first.rows_file, "the same rows are the same file");
    assert.equal(await readFile(join(cwd, second.rows_file), "utf8"), before);
    assert.match(first.rows_file, /^work\/s1\/srum_reader-[0-9a-f]{12}\/rows\.jsonl$/);
    const files = (await everyFileUnder(join(cwd, "work", "s1"))).filter((f) => !f.endsWith("rows.jsonl"));
    assert.deepEqual(files, [], "nothing else is left in the output directory");
  });
});

test("a clock that runs out while the rows are read is said: the status is partial, the answer comes back inside max_seconds, and what was cut is never reported complete", async () => {
  await withCwd(async (cwd, bin) => {
    const { db } = await layout(cwd);
    // 200,000 rows written by the stand-in itself (python3 is on the PATH of the suite): more than the boundary can judge in 12 seconds.
    await stub(bin, "SrumECmd", `d=""
while [ $# -gt 0 ]; do case "$1" in --csv) d="$2"; shift;; esac; shift; done
python3 - "$d" <<'PY'
import sys
with open(sys.argv[1] + "/x_SrumECmd_NetworkUsages_Output.csv", "w") as f:
    f.write("${NET_HEAD}\\n")
    for i in range(200000):
        f.write("%d,2026-10-12 08:%02d:%02d,C:\\\\p\\\\a%d.exe,,2026-01-01 00:00:00,User,S-1-5-18,u,5,7,1,2,1689399632855040,Ethernet,11,Home\\n" % (i, (i // 60) % 60, i % 60, i))
PY
echo "${CONSOLE_CLEAN}"`);
    const began = Date.now();
    const out = body<Answer>(await tool("srum_reader", cwd, { path: db, max_seconds: 12 }, {}, bin));
    assert.ok(Date.now() - began < 20_000, `the answer came in ${Date.now() - began} ms`);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /ran out while srumecmd's output was being read/);
    assert.ok(out.rows_total > 0 && out.rows_total < 200000, `rows_total ${out.rows_total}`);
    assert.equal((await rowsOf(cwd, out)).length, out.rows_total, "every row that was read is in the file");
    assert.deepEqual(await leftovers(cwd), []);
  });
});

test("the inline rows are held to a byte budget as well as to limit: a row past it is in the file only, and a repeated column name is a named problem", async () => {
  await withCwd(async (cwd, bin) => {
    const { db } = await layout(cwd);
    const rows: Net[] = [{ id: 1, time: "2026-10-12 08:00:00", app: "y".repeat(400_000), sid: "S-1-5-18", user: "u" }, ...NET_GOOD];
    await stub(bin, "SrumECmd", srumecmd(NET_CSV(rows), join(cwd, "args.txt"), { console: CONSOLE_CLEAN }));
    const out = body<Answer>(await tool("srum_reader", cwd, { path: db, limit: 1000 }, {}, bin));
    assert.equal(out.rows_total, 4);
    assert.equal(out.rows.length, 0, "the first row alone is past 256 KiB");
    assert.equal(out.rows_inline_truncated, true);
    assert.equal((await rowsOf(cwd, out)).length, 4);
    assert.ok(JSON.stringify(out).length < 200_000, "the answer stays small");
    await stub(bin, "SrumECmd", srumecmd({ "x_SrumECmd_NetworkUsages_Output.csv": `${NET_HEAD},Id\n${net(NET_GOOD[0])},9\n` }, join(cwd, "args.txt"), { console: CONSOLE_CLEAN }));
    const dup = body<Answer>(await tool("srum_reader", cwd, { path: db }, {}, bin));
    assert.equal(dup.status, "partial");
    assert.match(dup.backends.srumecmd.problems.join(" "), /names a column twice/);
  });
});

test("the manifest and the docs say what the tool is: the programs it runs are declared, and the unverified shapes are said", async () => {
  const manifest = JSON.parse(await readFile(join(WIN, "srum_reader", "manifest.json"), "utf8")) as { requires: string[]; description: string; version: number; timeout_seconds: number; params: Record<string, unknown> };
  assert.deepEqual(manifest.requires, ["SrumECmd", "dotnet", "target-query"]);
  assert.equal(manifest.version, 2);
  assert.deepEqual(Object.keys(manifest.params), ["path", "software", "backend", "limit", "max_seconds"]);
  assert.match(manifest.description, /EXPECTED NOT TO RUN ON A NON-WINDOWS HOST/);
  assert.match(manifest.description, /FROM HELP STRINGS AND METADATA, NOT FROM A REAL RUN/);
  assert.match(manifest.description, /never agree/);
  const host = JSON.parse(await readFile(join(WIN, "..", "requires", "host.json"), "utf8")) as { binaries: Array<{ name: string; optional?: boolean; licence: string; install: { download?: { version: string; run: string; amd64: { url: string; sha256: string; bin: string } } } }> };
  const pin = host.binaries.find((b) => b.name === "SrumECmd")!;
  assert.equal(pin.optional, true);
  assert.equal(pin.licence, "MIT");
  assert.equal(pin.install.download?.run, "dotnet");
  assert.equal(pin.install.download?.amd64.bin, "SrumECmd.dll");
  assert.match(pin.install.download?.amd64.url ?? "", /^https:\/\/download\.ericzimmermanstools\.com\/net\/SrumECmd\.zip$/);
  assert.match(pin.install.download?.amd64.sha256 ?? "", /^[0-9a-f]{64}$/);
});

// ---- the real programs, where they are installed ------------------------------------------------------------------------------------

const hasReal = spawnSync("sh", ["-c", "command -v dotnet >/dev/null && command -v SrumECmd >/dev/null && test -n \"$SRUM_REAL_DB\""]).status === 0;
test("the real SrumECmd reads a real SRUDB.dat (SRUM_REAL_DB) and the tool's rows say so", { skip: hasReal ? false : "dotnet, SrumECmd (the pinned dll behind a wrapper) or SRUM_REAL_DB is not available on this host; the pinned build also refuses to run off Windows" }, async () => {
  await withCwd(async (cwd) => {
    const out = body<Answer>(await tool("srum_reader", cwd, { path: process.env.SRUM_REAL_DB, backend: "srumecmd" }));
    console.log(`# real SrumECmd: ${out.backends.srumecmd.state} ${out.rows_total} row(s)`);
    assert.equal(out.backends.srumecmd.state, "ran", JSON.stringify(out.backends.srumecmd));
  });
});
