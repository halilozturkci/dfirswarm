/**
 * lnk_jumplist: shell links and Jump Lists as rows, against links written from MS-SHLLINK and compound files written from MS-CFB
 * (tests/windows-t1-fixtures.ts), never from a tool's output.
 *
 * What the cases hold:
 *   - the values a link was built with come back: the three FILETIMEs raw and as UTC with seven fractional digits, the VolumeID (drive
 *     type, serial as eight hex digits, label), the local path or the network share, the tracker's machine;
 *   - every offset is right: the bytes of the file at a row's extents are the bytes the fixture wrote, for a lone link, for a link in a
 *     compound file's mini stream and for a carved customDestinations-ms;
 *   - the container checks name what is wrong (a chain that loops or points at itself, a file cut short, a stream no DestList entry
 *     names, a DestList entry with no stream) and the status is partial;
 *   - lnkinfo is the independent reader: agreement, disagreement (partial) and absence are each said;
 *   - the arguments of a link are not in the answer, in a path, on stderr or in a file, and are written whole only in a job run as secret output;
 *   - hostile files (every prefix of a link, a random file, a FIFO, a symlink loop) end in JSON, never a traceback.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { body, everyFileUnder, failed, stub, tool } from "./windows-pack-harness.ts";
import { SHAPES, leaked, plant, prng } from "./windows-canary.ts";
import { FILETIME_A, cfb, destList, lnk, pathWithOnlyPython } from "./windows-t1-fixtures.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const LOCAL = lnk({ local: { path: "C:\\case\\report.txt", serial: 0x1a2b3c4d, label: "SYSTEM" }, name: "Report", args: "--flag", workDir: "C:\\case", tracker: { machine: "WORKSTATION" } });
const NETWORK = lnk({ network: { net: "\\\\srv\\share", device: "Z:" }, relative: "..\\x.doc" });
const AUTO = (links: Array<[string, Buffer]> = [["1", LOCAL], ["2", NETWORK]], entries = [1, 2], extra: Array<{ name: string; data: Buffer }> = []): Buffer =>
  cfb([...links.map(([name, data]) => ({ name, data })), ...extra, { name: "DestList", data: destList(4, entries.map((n) => ({ number: n, host: "WKS", filetime: FILETIME_A + BigInt(n) * 10_000_000n, pin: n === 2 ? 0 : -1, path: `C:\\case\\f${n}.txt` }))) }]);

const rowsOf = async (cwd: string, out: Answer): Promise<Row[]> => (await readFile(join(cwd, out.rows_file ?? ""), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Row);
const sha = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

/** The bytes of a file at a row's extents, joined. */
async function bytesAt(path: string, extents: Array<{ file_offset: number; bytes: number }>): Promise<Buffer> {
  const whole = await readFile(path);
  return Buffer.concat(extents.map((e) => whole.subarray(e.file_offset, e.file_offset + e.bytes)));
}
/** The process ids a stand-in wrote to its file, once there are at least `n` of them (the stand-in is started by the tool, so it is waited for). */
async function pidsOf(file: string, n: number): Promise<string[]> {
  for (let i = 0; i < 100; i++) {
    const text = await readFile(file, "utf8").catch(() => "");
    const ids = text.trim().split("\n").filter(Boolean);
    if (ids.length >= n) return ids;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`the stand-in never wrote ${n} process id(s) to ${file}`);
}
const job = async (cwd: string, n = 1): Promise<Record<string, string>> => {
  await mkdir(join(cwd, "out"), { recursive: true });
  return { JOB_ID: `j00000${n}`, OUT: join(cwd, "out") };
};

test("a link comes back with what it was built with: times raw and in UTC, VolumeID, target, tracker", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "a.lnk"), LOCAL);
    const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/a.lnk", limit: 10 }));
    assert.equal(out.status, "complete");
    assert.deepEqual(out.counts, { files: 1, containers: 0, streams: 0, destlist_entries: 0, links: 1 });
    const link = (await rowsOf(cwd, out)).find((r) => r.row === "link")!;
    assert.equal(link.header.created_filetime, String(FILETIME_A));
    assert.equal(link.header.accessed_filetime, String(FILETIME_A + 10_000_000n));
    assert.equal(link.header.written_filetime, String(FILETIME_A + 20_000_000n));
    assert.equal(link.header.created, "2023-11-13T00:53:20.1234567Z");
    assert.equal(link.header.written, "2023-11-13T00:53:22.1234567Z");
    assert.equal(link.header.file_length, 4321);
    assert.equal(link.target.kind, "local");
    assert.equal(link.target.path, "C:\\case\\report.txt");
    assert.deepEqual([link.target.volume.serial_number, link.target.volume.label, link.target.volume.drive_type, link.target.volume.drive_type_name], ["1A2B3C4D", "SYSTEM", 3, "fixed"]);
    assert.equal(link.tracker[0].machine, "WORKSTATION");
    assert.equal(link.integrity.structure_complete, true);
    assert.equal(link.file_offset, 0);
    assert.equal(link.sha256, sha(LOCAL));
    // A link and a share: the network target, with the share, the device and the provider.
    await writeFile(join(cwd, "work", "n.lnk"), NETWORK);
    const net = (await rowsOf(cwd, body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/n.lnk" })))).find((r) => r.row === "link")!;
    assert.equal(net.target.kind, "network");
    assert.equal(net.target.network.net_name, "\\\\srv\\share");
    assert.equal(net.target.network.device_name, "Z:");
    assert.equal(net.target.volume, null);
  });
});

test("an automaticDestinations-ms: the container, the DestList, and the offset of every stream and link are right", async () => {
  await withCwd(async (cwd) => {
    const file = join(cwd, "work", "1b4dd67f29cb1962.automaticDestinations-ms");
    const container = AUTO();
    await writeFile(file, container);
    const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/1b4dd67f29cb1962.automaticDestinations-ms", limit: 3 }));
    assert.equal(out.status, "complete", out.status_basis);
    assert.deepEqual(out.counts, { files: 1, containers: 1, streams: 3, destlist_entries: 2, links: 2 });
    assert.ok(out.rows.length <= 3, "the page is the inline size");
    assert.ok(out.rows_total > 3 && out.rows_file, "the whole is in the file");
    const rows = await rowsOf(cwd, out);
    assert.equal(rows.length, out.rows_total);
    assert.equal(rows.find((r) => r.row === "file")!.application_id, "1b4dd67f29cb1962");
    const box = rows.find((r) => r.row === "container")!;
    assert.deepEqual([box.major_version, box.sector_size, box.mini_sector_size, box.consistent, box.problems], [3, 512, 64, true, []]);
    // Every stream row and link row: the file's bytes at the extents are the stream's bytes (the fixture's), whatever the tool decoded.
    const expected: Record<string, Buffer> = { "1": LOCAL, "2": NETWORK };
    for (const row of rows.filter((r) => r.row === "stream" && expected[r.name])) {
      assert.deepEqual(await bytesAt(file, row.extents), expected[row.name], `stream ${row.name} is where the row says`);
      assert.equal(row.extents[0].file_offset, row.file_offset);
      assert.equal(row.storage, "mini stream");
      assert.equal(row.in_destlist, true);
    }
    for (const row of rows.filter((r) => r.row === "link")) {
      assert.deepEqual(await bytesAt(file, row.extents), expected[row.stream], `link in stream ${row.stream}`);
      assert.equal(row.sha256, sha(expected[row.stream]));
      assert.equal(row.container, "automaticDestinations-ms");
    }
    // The DestList entries name their streams, with the times they were built with (raw FILETIME and UTC).
    const entries = rows.filter((r) => r.row === "destlist_entry");
    assert.deepEqual(entries.map((e) => [e.entry_number, e.stream, e.stream_present, e.pinned]), [[1, "1", true, false], [2, "2", true, true]]);
    assert.equal(entries[0].last_access_filetime, String(FILETIME_A + 10_000_000n));
    assert.equal(entries[0].last_access, "2023-11-13T00:53:21.1234567Z");
    assert.equal(entries[1].path, "C:\\case\\f2.txt");
    assert.match(JSON.stringify(rows.find((r) => r.row === "destlist")!.not_decoded), /counters/);
    // A link's row cites the DestList entry that names it.
    assert.equal(rows.find((r) => r.row === "link" && r.stream === "2")!.destlist_entry, 2);
  });
});

test("a stream no entry names, an entry with no stream, and a DestList of a version the pack does not read are each named (the last two make the status partial)", async () => {
  await withCwd(async (cwd) => {
    const orphan = AUTO([["1", LOCAL], ["2", NETWORK], ["7", LOCAL]], [1, 2]);
    await writeFile(join(cwd, "work", "a.automaticDestinations-ms"), orphan);
    const a = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/a.automaticDestinations-ms" }));
    const rows = await rowsOf(cwd, a);
    const orphanRow = rows.find((r) => r.row === "stream" && r.name === "7")!;
    assert.equal(orphanRow.in_destlist, false);
    assert.match(orphanRow.orphan, /no entry/);
    assert.equal(a.status, "complete", "a stream the DestList does not name is a finding in its row, not damage to the container");
    await writeFile(join(cwd, "work", "b.automaticDestinations-ms"), AUTO([["1", LOCAL]], [1, 2]));
    const b = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/b.automaticDestinations-ms" }));
    const entry = (await rowsOf(cwd, b)).filter((r) => r.row === "destlist_entry").find((e) => e.entry_number === 2)!;
    assert.equal(entry.stream_present, false);
    assert.equal(b.status, "partial");
    // Version 2 of the DestList is none the pack has a layout for.
    const odd = cfb([{ name: "1", data: LOCAL }, { name: "DestList", data: Buffer.concat([Buffer.from([2, 0, 0, 0, 1, 0, 0, 0]), Buffer.alloc(24), Buffer.alloc(200)]) }]);
    await writeFile(join(cwd, "work", "c.automaticDestinations-ms"), odd);
    const c = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/c.automaticDestinations-ms" }));
    assert.equal(c.status, "partial");
    assert.match(JSON.stringify(await rowsOf(cwd, c)), /version 2 is not one this parser reads/);
  });
});

test("a damaged container is named: a chain that loops, a chain that points at itself, a file cut short, a DIFAT that loops", async () => {
  await withCwd(async (cwd) => {
    const big = lnk({ local: { path: "C:\\" + "x".repeat(7000), serial: 1, label: "L" } });
    assert.ok(big.length > 4096, "the stream is past the mini stream cutoff");
    const cases: Array<[string, Buffer, RegExp]> = [
      ["a stream chain that loops", cfb([{ name: "1", data: big }, { name: "DestList", data: destList(4, [{ number: 1, host: "H", filetime: FILETIME_A, pin: -1, path: "p" }]) }], { loopFirstStream: true }), /loops/],
      ["a stream chain that points at itself", cfb([{ name: "1", data: big }, { name: "DestList", data: destList(4, [{ number: 1, host: "H", filetime: FILETIME_A, pin: -1, path: "p" }]) }], { swapFatLinks: true }), /loops|chain/],
      ["a file cut in a sector", AUTO().subarray(0, AUTO().length - 100), /whole number|outside|cut|short|leaves/i],
      ["a file cut before its directory", AUTO().subarray(0, 700), /outside|leaves|short|whole/i],
    ];
    for (const [label, data, why] of cases) {
      await writeFile(join(cwd, "work", "x.automaticDestinations-ms"), data);
      const run = await tool("lnk_jumplist", cwd, { path: "work/x.automaticDestinations-ms" });
      assert.doesNotMatch(run.stderr, /Traceback/, label);
      const out = JSON.parse(run.stdout) as Answer;
      assert.notEqual(out.status, "complete", label);
      const text = JSON.stringify(out.rows_file ? await rowsOf(cwd, out) : out.rows);
      assert.match(text, why, label);
    }
    // A compound file whose DIFAT chain loops.
    const looped = Buffer.from(AUTO());
    looped.writeUInt32LE(110, 0x2c); // more FAT sectors than the header holds (109), so the DIFAT chain is read
    looped.writeUInt32LE(1, 0x44); // its first sector is sector 1 (a directory sector), and the header says there is one
    looped.writeUInt32LE(1, 0x48);
    await writeFile(join(cwd, "work", "d.automaticDestinations-ms"), looped);
    const run = await tool("lnk_jumplist", cwd, { path: "work/d.automaticDestinations-ms" });
    assert.doesNotMatch(run.stderr, /Traceback/);
    assert.notEqual((JSON.parse(run.stdout) as Answer).status, "complete");
  });
});

test("a customDestinations-ms is carved at every link header, each marked carved, and its container is not parsed", async () => {
  await withCwd(async (cwd) => {
    const file = join(cwd, "work", "c.customDestinations-ms");
    const data = Buffer.concat([Buffer.alloc(8, 9), LOCAL, Buffer.alloc(4), NETWORK, Buffer.alloc(16, 1)]);
    await writeFile(file, data);
    const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/c.customDestinations-ms" }));
    const rows = await rowsOf(cwd, out);
    const links = rows.filter((r) => r.row === "link");
    assert.equal(links.length, 2);
    assert.ok(links.every((l) => l.carved === true && l.container === "customDestinations-ms"));
    assert.deepEqual(links.map((l) => l.file_offset), [8, 8 + LOCAL.length + 4]);
    // A carve runs to the next header (or the end of the file): the bytes between two links belong to the first, and are not interpreted.
    assert.deepEqual(await bytesAt(file, links[0].extents), Buffer.concat([LOCAL, Buffer.alloc(4)]));
    assert.deepEqual(await bytesAt(file, links[1].extents), Buffer.concat([NETWORK, Buffer.alloc(16, 1)]));
    assert.match(rows.find((r) => r.row === "file")!.method, /not parsed/);
  });
});

test("lnkinfo is the independent reader: agreement, a disagreement (partial) and absence are each said, and what it prints for the arguments is not copied", async () => {
  const stubInfo = (o: { serial?: string; created?: string; args?: string } = {}): string => `cat <<'EOF'
lnkinfo 20240423

Windows Shortcut information:

Link information:
\tCreation time\t\t\t: ${o.created ?? "Nov 13, 2023 00:53:20.123456700 UTC"}
\tModification time\t\t: Nov 13, 2023 00:53:22.123456700 UTC
\tAccess time\t\t\t: Nov 13, 2023 00:53:21.123456700 UTC
\tFile size\t\t\t: 4321 bytes
\tDrive type\t\t\t: Fixed (3)
\tDrive serial number\t\t: ${o.serial ?? "0x1a2b3c4d"}
\tVolume label\t\t\t: SYSTEM
\tLocal path\t\t\t: C:\\case\\report.txt
\tCommand line arguments\t\t: ${o.args ?? "--flag"}
EOF`;
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "a.lnk"), LOCAL);
    await stub(bin, "lnkinfo", stubInfo());
    const agree = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/a.lnk" }, {}, bin));
    assert.equal(agree.lnkinfo.checked, 1);
    assert.equal(agree.lnkinfo.agreed, 1);
    assert.equal(agree.status, "complete");
    const link = (await rowsOf(cwd, agree)).find((r) => r.row === "link")!;
    assert.deepEqual(link.integrity.lnkinfo.compared.sort(), ["accessed", "created", "file_length", "target", "volume.drive_type", "volume.label", "volume.serial_number", "written"]);
    await stub(bin, "lnkinfo", stubInfo({ serial: "0x1a2b3c4e" }));
    const differ = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/a.lnk" }, {}, bin));
    assert.equal(differ.lnkinfo.disagreed, 1);
    assert.equal(differ.integrity.disagrees, 1);
    assert.equal(differ.status, "partial");
    assert.match(differ.status_basis, /lnkinfo disagrees/);
    assert.match(JSON.stringify((await rowsOf(cwd, differ)).find((r) => r.row === "link")!.integrity), /volume\.serial_number/);
    await stub(bin, "lnkinfo", stubInfo({ created: "Nov 13, 2023 00:53:21.123456700 UTC" }));
    const time = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/a.lnk" }, {}, bin));
    assert.equal(time.status, "partial");
    // A lnkinfo that fails is a link it could not read: not run, said, and the status does not turn on it.
    await stub(bin, "lnkinfo", "exit 1");
    const failedRead = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/a.lnk" }, {}, bin));
    assert.equal(failedRead.lnkinfo.not_run, 1);
    assert.equal(failedRead.status, "complete");
    assert.match(failedRead.status_basis, /lnkinfo, the independent reader, was not run/);
  });
  // Absent: said by name.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "a.lnk"), LOCAL);
    const onlyPython = await pathWithOnlyPython(cwd);
    const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/a.lnk" }, { PATH: onlyPython }));
    assert.equal(out.lnkinfo.not_run, 1);
    assert.match(JSON.stringify(out.lnkinfo.why_not_run), /not in this image|lnkinfo/);
  });
  // The real program, where it is installed: it agrees with the fixture's own values.
  if (spawnSync("sh", ["-c", "command -v lnkinfo"]).status === 0) {
    await withCwd(async (cwd) => {
      await writeFile(join(cwd, "work", "a.lnk"), LOCAL);
      await writeFile(join(cwd, "work", "n.lnk"), NETWORK);
      const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work" }));
      assert.equal(out.lnkinfo.checked, 2, JSON.stringify(out.lnkinfo));
      assert.equal(out.lnkinfo.disagreed, 0, JSON.stringify((await rowsOf(cwd, out)).map((r) => r.integrity?.lnkinfo)));
    });
  }
});

// ---- the boundary -----------------------------------------------------------------------------------------------------------

test("the arguments of a link are in no answer, no path, no stderr and no file; write_values-style output is refused outside a job and is a 0600 file in a job run as secret output", async () => {
  const canaries = plant(SHAPES.find((s) => s.name === "ghp")!, 8, 4).concat(plant(SHAPES.find((s) => s.name === "b64_20")!, 8, 4), plant(SHAPES.find((s) => s.name === "random_base62_40")!, 8, 4));
  await withCwd(async (cwd, bin) => {
    // lnkinfo prints the arguments too: a stand-in that does, to show its text is not copied either.
    await stub(bin, "lnkinfo", `echo "\\tCommand line arguments\\t\\t: $(cat "$1" | tr -c '[:print:]' '.' | head -c 400)"`);
    for (const [i, c] of canaries.entries()) {
      await writeFile(join(cwd, "work", `l${i}.lnk`), lnk({ local: { path: "C:\\a\\b.exe", serial: 7, label: "V" }, args: `-k ${c.text}`, workDir: "C:\\a" }));
    }
    const run = await tool("lnk_jumplist", cwd, { path: "work", limit: 5 }, {}, bin);
    const out = body<Answer>(run);
    const files = await everyFileUnder(cwd);
    const texts = [run.stdout, run.stderr, ...files.filter((f) => !f.endsWith(".lnk")), ...(await Promise.all(files.filter((f) => !f.endsWith(".lnk")).map(async (f) => (await readFile(f)).toString("latin1"))))];
    assert.equal(leaked(canaries, texts), 0, "no canary core is printed whole");
    assert.equal(out.counts.links, canaries.length);
    const rows = await rowsOf(cwd, out);
    assert.ok(rows.filter((r) => r.row === "link").every((r) => r.strings.arguments_present === true && typeof r.strings.arguments_chars === "number"));
    // The text goes only where the flag and the job allow.
    const before = new Set(files);
    const refused = failed(await tool("lnk_jumplist", cwd, { path: "work", write_strings: true }, {}, bin));
    assert.match(refused.error, /write_strings is refused/);
    assert.deepEqual(new Set(await everyFileUnder(cwd)), before, "nothing was made");
    const env = await job(cwd);
    assert.match(failed(await tool("lnk_jumplist", cwd, { path: "work", write_strings: true }, env, bin)).error, /refused/);
    const secret = await tool("lnk_jumplist", cwd, { path: "work", write_strings: true, limit: 5 }, { ...env, SECRET_OUTPUT: "1" }, bin);
    const answer = body<Answer>(secret);
    const written = (await everyFileUnder(join(cwd, "out"))).filter((f) => /strings-values/.test(f));
    assert.equal(written.length, 1);
    assert.equal((await stat(written[0])).mode & 0o777, 0o600);
    const whole = await readFile(written[0], "utf8");
    for (const c of canaries.slice(0, 5)) assert.ok(whole.includes(c.cores[0]), "the argument is in the file, whole");
    const others = [secret.stdout, secret.stderr, ...(await Promise.all((await everyFileUnder(cwd)).filter((f) => f !== written[0] && !f.endsWith(".lnk")).map(async (f) => (await readFile(f)).toString("latin1"))))];
    assert.equal(leaked(canaries, others), 0, "and in nothing else");
    assert.equal(answer.secret_values.contains_secret_values ?? answer.secret_values.written > 0, true);
    // A second run in the same job keeps the first file.
    body<Answer>(await tool("lnk_jumplist", cwd, { path: "work", write_strings: true }, { ...env, SECRET_OUTPUT: "1" }, bin));
    assert.equal((await everyFileUnder(join(cwd, "out"))).filter((f) => /strings-values/.test(f)).length, 2);
    assert.equal(await readFile(written[0], "utf8"), whole);
  });
});

// ---- hostile inputs ---------------------------------------------------------------------------------------------------------

test("hostile inputs end in JSON, never a traceback: every prefix of a link, random files, a FIFO, a symlink loop, a directory of them", async () => {
  await withCwd(async (cwd) => {
    const r = prng(5);
    const random = (n: number): Buffer => Buffer.from(Array.from({ length: n }, () => Math.floor(r() * 256)));
    let n = 0;
    const check = async (label: string, args: unknown): Promise<Answer> => {
      const run = await tool("lnk_jumplist", cwd, args);
      assert.doesNotMatch(run.stderr, /Traceback/, label);
      assert.ok(run.code === 0 || run.code === 1, `${label}: exit ${run.code}`);
      const parsed = JSON.parse(run.stdout) as Answer;
      n++;
      return parsed;
    };
    for (let cut = 0; cut <= 300; cut += 7) {
      await writeFile(join(cwd, "work", "p.lnk"), LOCAL.subarray(0, cut));
      const out = await check(`prefix ${cut}`, { path: "work/p.lnk" });
      if (cut < LOCAL.length) assert.notEqual(out.status, "complete", `prefix ${cut} is not a whole link`);
    }
    await writeFile(join(cwd, "work", "r1.lnk"), random(3000));
    await check("random .lnk", { path: "work/r1.lnk" });
    await writeFile(join(cwd, "work", "r2.automaticDestinations-ms"), random(9000));
    await check("random jump list", { path: "work/r2.automaticDestinations-ms" });
    await writeFile(join(cwd, "work", "z.lnk"), Buffer.alloc(0));
    await check("empty", { path: "work/z.lnk" });
    await check("missing", { path: "work/none.lnk" });
    const huge = Buffer.from(LOCAL);
    huge.writeUInt32LE(0xffffffff, 0x4c); // an ID list size past the file
    await writeFile(join(cwd, "work", "huge.lnk"), huge);
    await check("an ID list size past the file", { path: "work/huge.lnk" });
    await mkdir(join(cwd, "dir", "sub"), { recursive: true });
    await writeFile(join(cwd, "dir", "a.lnk"), LOCAL);
    await writeFile(join(cwd, "dir", "sub", "notes.txt"), "text");
    await symlink("..", join(cwd, "dir", "sub", "up"));
    await symlink("a.lnk", join(cwd, "dir", "alias.lnk"));
    const dir = await check("a directory with a link to its parent", { path: "dir" });
    assert.equal(dir.counts.links, 1, "a link is not followed, a file of another kind is not read");
    assert.ok(dir.skipped >= 1 || dir.status === "complete");
    const fifo = join(cwd, "dir", "pipe.lnk");
    if (spawnSync("mkfifo", [fifo]).status === 0) {
      const withFifo = await check("a FIFO among the files", { path: "dir", max_seconds: 20 });
      assert.equal(withFifo.status, "partial", "a FIFO is never opened and the status says it was not read");
      assert.match(withFifo.status_basis, /not opened/);
      assert.match(JSON.stringify(withFifo.skipped_first), /pipe\.lnk/);
    }
    await writeFile(join(cwd, "work", "mode0.lnk"), LOCAL);
    await chmod(join(cwd, "work", "mode0.lnk"), 0);
    if (process.getuid?.() !== 0) await check("no permission", { path: "work/mode0.lnk" });
    for (const args of [{}, { path: 5 }, { path: "" }, { path: "work", limit: 0 }, { path: "work", limit: "5" }, { path: "work", max_seconds: 0 }, { path: "work", max_files: 0 }, { path: "work", write_strings: 1 }, []]) {
      const run = await tool("lnk_jumplist", cwd, args);
      assert.notEqual(run.code, 0, JSON.stringify(args));
      assert.doesNotMatch(run.stderr, /Traceback/);
      assert.ok(JSON.parse(run.stdout).error);
      n++;
    }
    assert.ok(n >= 40);
  });
});

test("a link or a jump list past the sizes the tool reads whole is named and not read, in a bounded time and as JSON", async () => {
  await withCwd(async (cwd) => {
    const { truncate } = await import("node:fs/promises");
    await writeFile(join(cwd, "work", "huge.lnk"), LOCAL.subarray(0, 20));
    await truncate(join(cwd, "work", "huge.lnk"), 200 * 2 ** 20);
    await writeFile(join(cwd, "work", "huge.automaticDestinations-ms"), Buffer.from("d0cf11e0a1b11ae1", "hex"));
    await truncate(join(cwd, "work", "huge.automaticDestinations-ms"), 300 * 2 ** 20);
    for (const name of ["huge.lnk", "huge.automaticDestinations-ms"]) {
      const run = await tool("lnk_jumplist", cwd, { path: `work/${name}`, limit: 2 });
      assert.doesNotMatch(run.stderr, /Traceback/, name);
      const out = JSON.parse(run.stdout) as Answer;
      assert.equal(out.status, "partial", name);
      assert.match(out.status_basis, /could not be read whole/, name);
    }
  });
});

test("names with a quote, a bracket, a newline or 300 characters are answered in JSON", async () => {
  await withCwd(async (cwd) => {
    for (const name of ["a\"b'c.lnk", "a[1]{2}.lnk", "line\nbreak.lnk", "x".repeat(200) + ".lnk"]) {
      await writeFile(join(cwd, "work", name), LOCAL);
      const run = await tool("lnk_jumplist", cwd, { path: `work/${name}` });
      assert.doesNotMatch(run.stderr, /Traceback/, name);
      assert.equal((JSON.parse(run.stdout) as Answer).status, "complete", name);
    }
  });
});

// ---- time, signals, processes -----------------------------------------------------------------------------------------------

test("lnkinfo stays in the tool's group: the tool's clock and SIGTERM end it, and the tool answers in JSON", async () => {
  const { spawn } = await import("node:child_process");
  await withCwd(async (cwd, bin) => {
    const pidFile = join(cwd, "lnkinfo.pid");
    await stub(bin, "lnkinfo", `echo $$ >> "${pidFile}"; exec sleep 60`);
    await writeFile(join(cwd, "work", "a.lnk"), LOCAL);
    const began = Date.now();
    const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/a.lnk", max_seconds: 3 }, {}, bin));
    assert.ok(Date.now() - began < 20_000, `returned in ${Date.now() - began} ms`);
    assert.ok(["complete", "partial"].includes(out.status));
    const first = (await pidsOf(pidFile, 1)).map(Number);
    await new Promise((r) => setTimeout(r, 300));
    for (const pid of first) assert.throws(() => process.kill(pid, 0), "lnkinfo is gone");
    // SIGTERM while lnkinfo sleeps.
    const child = spawn("python3", [join(process.cwd(), "packs/windows-forensics/tools/lnk_jumplist/run.py")], { cwd, env: { ...process.env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}` }, stdio: ["pipe", "pipe", "pipe"] });
    const chunks: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => chunks.push(c));
    child.stdin.end(JSON.stringify({ path: "work/a.lnk", max_seconds: 100 }));
    const count = first.length;
    const all = (await pidsOf(pidFile, count + 1)).map(Number);
    child.kill("SIGTERM");
    const code = await new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
    assert.equal(code, 143);
    assert.equal((JSON.parse(Buffer.concat(chunks).toString("utf8")) as Answer).status, "interrupted");
    await new Promise((r) => setTimeout(r, 300));
    assert.throws(() => process.kill(all[all.length - 1], 0), "the program is gone with the tool");
  });
});

test("the tool starts nothing in a session of its own, and a second run in the same job keeps the first run's files", async () => {
  const text = (await readFile(join(process.cwd(), "packs/windows-forensics/tools/lnk_jumplist/run.py"), "utf8")).replace(/"""[\s\S]*?"""/g, "");
  const outside = text.replace(/# BEGIN SHARED PROCESS[\s\S]*?# END SHARED PROCESS/, "").replace(/^\s*#.*$/gm, "");
  assert.doesNotMatch(outside, /start_new_session|\bsetsid\b|preexec_fn|os\.setpgid|os\.setpgrp|killpg/);
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "a.lnk"), LOCAL);
    const env = await job(cwd);
    const first = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/a.lnk", limit: 1 }, env));
    const files = await everyFileUnder(join(cwd, "out"));
    const sizes = new Map(await Promise.all(files.map(async (f) => [f, (await stat(f)).size] as const)));
    const second = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/a.lnk", limit: 1 }, env));
    assert.equal(second.status, first.status);
    for (const [f, size] of sizes) assert.equal((await stat(f)).size, size, `${f} is kept as it was`);
  });
});

// ---- fuzz -------------------------------------------------------------------------------------------------------------------

test("structure-aware mutations of a link and of a Jump List (400 cases): JSON every time, never a traceback, never a complete status for a damaged link", async () => {
  const r = prng(99);
  const pick = (n: number): number => Math.floor(r() * n);
  const bases: Array<[string, Buffer]> = [["lnk", LOCAL], ["lnk", NETWORK], ["automaticDestinations-ms", AUTO()]];
  await withCwd(async (cwd) => {
    for (let i = 0; i < 400; i++) {
      const [ext, base] = bases[i % bases.length];
      const m = Buffer.from(base);
      const kind = pick(4);
      if (kind === 0) m[pick(m.length)] ^= 1 << pick(8);
      else if (kind === 1) for (let k = 0; k < 4; k++) m[pick(m.length)] = pick(256);
      else if (kind === 2) m.writeUInt32LE(pick(2) ? 0xffffffff : pick(70000), pick(m.length - 4));
      const data = kind === 3 ? m.subarray(0, pick(m.length)) : m;
      const name = `f.${ext}`;
      await writeFile(join(cwd, "work", name), data);
      const run = await tool("lnk_jumplist", cwd, { path: `work/${name}`, limit: 2 });
      assert.doesNotMatch(run.stderr, /Traceback/, `case ${i}`);
      assert.ok(run.code === 0 || run.code === 1, `case ${i}: exit ${run.code}`);
      const out = JSON.parse(run.stdout) as Answer;
      assert.ok(["complete", "partial", "failed"].includes(out.status), `case ${i}: ${run.stdout.slice(0, 200)}`);
      if (kind === 3 && ext === "lnk") assert.notEqual(out.status, "complete", `case ${i}: a cut link is not complete`);
    }
  });
});
