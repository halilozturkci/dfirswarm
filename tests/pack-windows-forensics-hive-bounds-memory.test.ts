/**
 * The HIVE BOUNDS block's open, memory and late-list bounds (round 4), and the tool-level fixes that came with them. Every hive is written
 * from the regf layout (tests/windows-hive.ts) and every log from tests/windows-t1-fixtures.ts; memory is the tool's own peak resident size,
 * read by tests/fixtures/peak_rss.py, with bounds far above what the fixed tool needs and far below what the unfixed one took.
 *
 *   - open: regipy takes the first allocated cell of the first bin for the root key, reading 4 bytes at a time with no clock (a free first
 *     cell in a 16 MiB hive is about 13 s; 40 MB was 57.6 s in a 2 GB box). The block checks the base block and the root cell first.
 *   - subkeys: an "ri" index naming one list of 1,000 keys 65,535 times in a hive padded to 40 MiB held up to size // 76 key records
 *     (about 550,000, 1.2 KB each) before de-duplicating; a list now keeps only distinct keys and stops after a run of repeats.
 *   - values: a value list naming one 18 MiB string eight times held four decoded copies at once; a value over 16 MiB is now said with
 *     its length and not read.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { REGIPY, WIN, body, tool } from "./windows-pack-harness.ts";
import { runPy } from "./tool-library-harness.ts";
import { hive } from "./windows-hive.ts";
import type { HiveKey } from "./windows-hive.ts";
import { peakRssPrelude } from "./peak-rss.ts";
import { BASE_BLOCK, differingPages, hvleLog, withSequences } from "./windows-t1-fixtures.ts";
import { VARIANTS, type Node } from "./windows-stub-regipy.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const MiB = 1 << 20;
const keys = (n: number, prefix = "K"): HiveKey[] => Array.from({ length: n }, (_, i) => ({ name: prefix + String(i).padStart(5, "0") }));

function dual(name: string, fn: (v: (typeof VARIANTS)[number]) => Promise<void>): void {
  for (const v of VARIANTS) test(`${name} [${v.label}]`, { skip: v.skip }, () => fn(v));
}

type Peak = { code: number; out: Answer | null; stdout: string; stderr: string; peak: number; wall: number };

/** Run a tool of the pack under run_peak: its answer, its own peak resident size in bytes and its wall time in ms. */
async function peakTool(name: string, cwd: string, args: unknown, env: Record<string, string> = {}, seconds = 150): Promise<Peak> {
  const wrapper = peakRssPrelude() + String.raw`
import json
cp, peak = run_peak([sys.executable, sys.argv[1]], input=sys.stdin.buffer.read(), capture_output=True, timeout=float(sys.argv[2]))
sys.stdout.write(json.dumps({"code": cp.returncode, "stdout": cp.stdout.decode("utf-8", "replace"), "stderr": cp.stderr.decode("utf-8", "replace")[-4000:], "peak": peak}))
`;
  const started = Date.now();
  const raw: string = await new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", wrapper, join(WIN, name, "run.py"), String(seconds)], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve(Buffer.concat(out).toString("utf8")) : reject(new Error(`the wrapper ended ${code}: ${Buffer.concat(err).toString("utf8")}`))));
    child.stdin.end(JSON.stringify(args));
  });
  const wall = Date.now() - started;
  const r = JSON.parse(raw) as { code: number; stdout: string; stderr: string; peak: number };
  let out: Answer | null = null;
  try {
    out = JSON.parse(r.stdout) as Answer;
  } catch {
    out = null;
  }
  return { ...r, out, wall };
}

const problemsText = (out: Answer): string => JSON.stringify(out.problems ?? out.records?.problems ?? []);

// --- the open -----------------------------------------------------------------------------------------------------------------------

/** A hive whose first bin is declared as the whole file and holds nothing but zeros after its header, padded with `pad` bytes of zeros: its
 * root cell (the first cell) is free, and regipy reads the bin 4 bytes at a time to the end of the file looking for an allocated cell. */
function freeRoot(pad: number): Buffer {
  const buf = Buffer.concat([hive({ name: "ROOT", children: [{ name: "K" }] }), Buffer.alloc(pad)]);
  buf.fill(0, BASE_BLOCK + 0x20);
  buf.writeUInt32LE(buf.length - BASE_BLOCK, BASE_BLOCK + 8);
  return buf;
}

test("a hive whose root cell is free is refused at once by every carrier, with what was found, not scanned word by word", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "free.dat"), freeRoot(16 * MiB));
    const calls: Array<[string, Answer]> = [
      ["regkv", { hive: "work/free.dat", key: "" }],
      ["shellbags", { hive: "work/free.dat" }],
      ["amcache_apps", { hive: "work/free.dat" }],
      ["userassist_bam_shimcache", { hive: "work/free.dat" }],
      ["persistence_normalise", { system: "work/free.dat" }],
      ["registry_recover", { hive: "work/free.dat" }],
    ];
    for (const [name, args] of calls) {
      const started = Date.now();
      const run = await tool(name, cwd, args);
      const took = Date.now() - started;
      assert.doesNotMatch(run.stderr, /Traceback/, name);
      const out = JSON.parse(run.stdout) as Answer;
      assert.ok(took < 8000, `${name} took ${took} ms`);
      const said = JSON.stringify(out);
      assert.match(said, /root key's cell \(offset 32\) is free/, `${name}: ${said.slice(0, 600)}`);
      if (name === "registry_recover") {
        assert.equal(out.records.status, "failed", said.slice(0, 600));
        assert.notEqual(out.status, "complete");
      } else {
        assert.equal(out.status, "failed", `${name}: ${said.slice(0, 400)}`);
      }
    }
  });
});

test("a hive with no bin at 4096, or a first bin of size 0, is refused with what was found", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const good = hive({ name: "ROOT", children: [{ name: "K" }] });
    const noBin = Buffer.from(good);
    noBin.write("xxxx", BASE_BLOCK, "latin1");
    const zeroBin = Buffer.from(good);
    zeroBin.writeUInt32LE(0, BASE_BLOCK + 8);
    await writeFile(join(cwd, "work", "nobin.dat"), noBin);
    await writeFile(join(cwd, "work", "zerobin.dat"), zeroBin);
    const a = JSON.parse((await tool("regkv", cwd, { hive: "work/nobin.dat", key: "" })).stdout) as Answer;
    assert.equal(a.status, "failed");
    assert.match(String(a.reason), /no hive bin at offset 4096/);
    const b = JSON.parse((await tool("regkv", cwd, { hive: "work/zerobin.dat", key: "" })).stdout) as Answer;
    assert.equal(b.status, "failed");
    assert.match(String(b.reason), /size of 0 bytes, which is not a positive multiple of 4096/);
    // and a hive as Windows writes it still opens
    await writeFile(join(cwd, "work", "good.dat"), good);
    const c = body<Answer>(await tool("regkv", cwd, { hive: "work/good.dat", key: "" }));
    assert.equal(c.status, "complete");
    assert.deepEqual(c.subkeys.map((s: Answer) => s.name), ["K"]);
  });
});

// --- a repeating index: distinct keys only, and a run of repeats ends the list -------------------------------------------------------

/** 1,000 keys under `place`, their leaf named 65,535 times by an "ri" index, in a hive padded to 40 MiB (so that size // 76 is 550,000). */
function repeating(place: string[]): Buffer {
  let node: HiveKey = { name: place[place.length - 1], children: keys(1000), indexRepeats: 65535 };
  for (let i = place.length - 2; i >= 0; i--) node = { name: place[i], children: [node] };
  return Buffer.concat([hive({ name: "ROOT", children: [node] }), Buffer.alloc(40 * MiB)]);
}

test("an index that names one list 65,535 times holds the distinct keys only: four carriers stay small and say where they stopped", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "big.dat"), repeating(["Big"]));
    await writeFile(join(cwd, "work", "Amcache.hve"), repeating(["Root", "InventoryApplicationFile"]));
    const calls: Array<[string, Answer]> = [
      ["regkv", { hive: "work/big.dat", key: "Big" }],
      ["shellbags", { hive: "work/big.dat", key: "Big", limit: 5 }],
      ["registry_recover", { hive: "work/big.dat", limit: 5 }],
      ["amcache_apps", { hive: "work/Amcache.hve", limit: 5 }],
    ];
    for (const [name, args] of calls) {
      const r = await peakTool(name, cwd, args);
      assert.ok(r.out, `${name}: no JSON (${r.code}) ${r.stderr.slice(-600)}`);
      assert.doesNotMatch(r.stderr, /Traceback/, name);
      // The hive alone is 40 MiB, held twice by the library; 550,000 key records were over 600 MiB.
      assert.ok(r.peak < 260 * MiB, `${name}: peak ${Math.round(r.peak / MiB)} MiB`);
      assert.ok(r.wall < 20_000, `${name}: ${r.wall} ms`);
      assert.equal(r.out.status, "partial", name);
      assert.match(problemsText(r.out), /named keys it had already named 4096 times in a row/, `${name}: ${problemsText(r.out).slice(0, 600)}`);
    }
  });
});

// --- a value over the per-value cap -------------------------------------------------------------------------------------------------

test("a value list naming one 18 MiB string eight times reads none of it: each is said with its length, and memory stays small", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const text = "\u4141".repeat(9 * MiB);           // 18 MiB of UTF-16, decoded at two bytes a character
    await writeFile(join(cwd, "work", "h.dat"), hive({ name: "ROOT", children: [{ name: "K", values: [{ name: "big", type: "sz", value: text }], valueListRepeats: 8 }] }));
    for (const [name, args] of [["regkv", { hive: "work/h.dat", key: "K" }], ["registry_recover", { hive: "work/h.dat", limit: 5 }]] as Array<[string, Answer]>) {
      const r = await peakTool(name, cwd, args);
      assert.ok(r.out, `${name}: no JSON ${r.stderr.slice(-600)}`);
      // The hive is 18 MiB; four decoded copies of the string (and the answer holding them) were 239 MiB for regkv.
      assert.ok(r.peak < 150 * MiB, `${name}: peak ${Math.round(r.peak / MiB)} MiB`);
      assert.equal(r.out.status, "partial", name);
      const said = problemsText(r.out);
      assert.equal((said.match(/declares 18874370 bytes of data, more than the 16 MiB this tool reads of one value/g) ?? []).length, 8, `${name}: ${said.slice(0, 800)}`);
      if (name === "regkv") assert.deepEqual(r.out.values, {}, "no value of the key is in the answer");
    }
  });
});

// --- registry_recover: hash-1 ends a log; a sequence number wraps; a stop removes the files placed --------------------------------------

function generation(n: number): Buffer {
  return hive({ name: "ROOT", children: [{ name: "Software", children: [{ name: "Run", values: [{ name: "App", type: "sz", value: `C:\\gen${n}.exe` }] }] }] }, { primarySeq: 10, secondarySeq: 10 });
}
const G = [0, 1, 2, 3].map(generation);
const BINS = G[0].length - BASE_BLOCK;

test("registry_recover uses a log's entries up to the first wrong pages hash: an entry after it is not applied, whatever its number", async () => {
  await withCwd(async (cwd) => {
    // log1: 10 (good), 11 (pages hash wrong), 12 (good); log2: 11 (good). The other log bridges 11, and log1's 12 is past its bad entry.
    const log1 = hvleLog(G[3], [
      { sequence: 10, hiveBinsDataSize: BINS, pages: differingPages(G[0], G[1]) },
      { sequence: 11, hiveBinsDataSize: BINS, pages: differingPages(G[1], G[2]), corrupt: "hash1" },
      { sequence: 12, hiveBinsDataSize: BINS, pages: differingPages(G[2], G[3]) },
    ], { primary: 10 });
    const log2 = hvleLog(G[2], [{ sequence: 11, hiveBinsDataSize: BINS, pages: differingPages(G[1], G[2]) }], { primary: 11 });
    await writeFile(join(cwd, "work", "h.dat"), withSequences(G[0], 13, 10));
    await writeFile(join(cwd, "work", "h.log1"), log1);
    await writeFile(join(cwd, "work", "h.log2"), log2);
    const out = body<Answer>(await tool("registry_recover", cwd, { hive: "work/h.dat", log1: "work/h.log1", log2: "work/h.log2", export: false }));
    assert.equal(out.entries_applied, 2, JSON.stringify(out).slice(0, 800));
    assert.deepEqual(out.sequence_after, [12, 12]);
    assert.equal(out.status, "partial");
    const receipt = JSON.parse(await readFile(join(cwd, out.receipt), "utf8")) as Answer;
    assert.deepEqual(receipt.replay.order.map((o: Answer) => [o.log, o.sequence]), [["log1", 10], ["log2", 11]]);
    const entries = receipt.logs.find((l: Answer) => l.role === "log1").entries as Answer[];
    assert.equal(entries.length, 2, "the scan of log1 ends at its bad entry");
    assert.match(entries[1].reason, /pages hash \(hash-1\) is wrong/);
  });
});

test("registry_recover follows sequence 0xFFFFFFFF with 0 and writes the numbers after it", async () => {
  await withCwd(async (cwd) => {
    const log1 = hvleLog(G[2], [
      { sequence: 0xffffffff, hiveBinsDataSize: BINS, pages: differingPages(G[0], G[1]) },
      { sequence: 0, hiveBinsDataSize: BINS, pages: differingPages(G[1], G[2]) },
    ], { primary: 0xffffffff });
    await writeFile(join(cwd, "work", "h.dat"), withSequences(G[0], 0, 0xffffffff));
    await writeFile(join(cwd, "work", "h.log1"), log1);
    const run = await tool("registry_recover", cwd, { hive: "work/h.dat", log1: "work/h.log1", export: false });
    assert.doesNotMatch(run.stderr, /Traceback|struct\.error/);
    const out = body<Answer>(run);
    assert.equal(out.entries_applied, 2);
    assert.deepEqual(out.sequence_after, [1, 1]);
    assert.equal(out.status, "complete", out.status_basis);
    assert.match(out.status_basis, /up to sequence 0\b/);
  });
});

test("registry_recover stopped while regfexport counts removes keys.jsonl and the other files it placed, as its answer says", { skip: REGIPY }, async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "h.dat"), G[0]);
    // A regfexport that does not finish: the stop arrives while the tool waits for it, after keys.jsonl is placed and before the receipt.
    await writeFile(join(bin, "regfexport"), "#!/bin/sh\nsleep 60\n");
    await chmod(join(bin, "regfexport"), 0o755);
    await mkdir(join(cwd, "out"), { recursive: true });
    const env = { ...process.env, AGENT_ID: "s1", JOB_ID: "j000001", OUT: join(cwd, "out"), PATH: `${bin}:${process.env.PATH ?? ""}` };
    const child = spawn("python3", [join(WIN, "registry_recover", "run.py")], { cwd, env });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", () => undefined);
    const ended = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
    child.stdin.end(JSON.stringify({ hive: "work/h.dat", limit: 5 }));
    const placed = async (): Promise<string[]> => {
      const found: string[] = [];
      for (const d of await readdir(join(cwd, "out"), { withFileTypes: true }).catch(() => [])) {
        if (d.isDirectory()) for (const f of await readdir(join(cwd, "out", d.name)).catch(() => [])) found.push(join(d.name, f));
      }
      return found;
    };
    let seen: string[] = [];
    for (let i = 0; i < 200; i++) {
      seen = await placed();
      if (seen.some((f) => f.endsWith("keys.jsonl"))) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.ok(seen.some((f) => f.endsWith("keys.jsonl")), `keys.jsonl was never placed: ${seen.join(", ")}`);
    assert.ok(!seen.some((f) => f.endsWith("receipt.json")), "the receipt is not there yet");
    await new Promise((r) => setTimeout(r, 300));
    child.kill("SIGTERM");
    await ended;
    const answer = JSON.parse(Buffer.concat(out).toString("utf8")) as Answer;
    assert.equal(answer.status, "failed");
    assert.equal(answer.interrupted, true);
    const left = (await placed()).filter((f) => !f.split("/").pop()!.startsWith("."));
    assert.deepEqual(left, [], `files left after the stop: ${left.join(", ")}`);
    assert.match(answer.status_basis, /file\(s\) it had placed/);
  });
});

// --- amcache_apps: two values read as one field ---------------------------------------------------------------------------------------

dual("amcache_apps keeps both values a legacy entry reads as one field, says so, and is partial", async (v) => {
  await withCwd(async (cwd) => {
    const root: Node = { name: "ROOT", children: [{ name: "Root", children: [{ name: "File", children: [{ name: "{vol}", children: [{ name: "0001", values: [
      { name: "15", type: "sz", value: "C:\\real\\evil.exe" },
      { name: "full_path", type: "sz", value: "C:\\Windows\\notepad.exe" },
    ] }] }] }] }] };
    const env = await v.write(cwd, "work/Amcache.hve", root);
    const out = body<Answer>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }, env));
    assert.equal(out.status, "partial", out.status_basis);
    const row = out.entries[0] as Answer;
    const shown = [row.full_path, row["value:full_path"], row["value:15"]].filter(Boolean).sort();
    assert.deepEqual(shown, ["C:\\Windows\\notepad.exe", "C:\\real\\evil.exe"], JSON.stringify(row));
    assert.ok(out.problems.some((p: string) => /two of its values are read as the field 'full_path'/.test(p)), JSON.stringify(out.problems));
  });
});

// --- shellbags: a value name twice, and a long MRUListEx ------------------------------------------------------------------------------

const VOLUME_ITEM = Buffer.concat([Buffer.from([0x19, 0x00, 0x2f]), Buffer.from("E:\\\0", "latin1"), Buffer.alloc(19)]);
const ROOT_ITEM = Buffer.concat([Buffer.from([0x14, 0x00, 0x1f, 0x50]), Buffer.from("e04fd020ea3a6910a2d808002b30309d", "hex"), Buffer.alloc(2)]);

dual("shellbags keeps a later value of a slot's name, lists it as a value without a subkey, and is partial", async (v) => {
  await withCwd(async (cwd) => {
    const mru = Buffer.alloc(8);
    mru.writeInt32LE(0, 0);
    mru.writeInt32LE(-1, 4);
    const env = await v.write(cwd, "work/UsrClass.dat", { name: "ROOT", children: [{ name: "Bag", values: [
      { name: "0", type: "binary", value: VOLUME_ITEM },
      { name: "0", type: "binary", value: ROOT_ITEM },
      { name: "MRUListEx", type: "binary", value: mru },
    ], children: [{ name: "0" }] }] });
    const out = body<Answer>(await tool("shellbags", cwd, { hive: "work/UsrClass.dat", key: "Bag" }, env));
    assert.equal(out.status, "partial", out.status_basis);
    assert.equal(out.entry_count, 2, JSON.stringify(out.entries));
    const slot = out.entries.find((e: Answer) => !e.no_subkey) as Answer;
    assert.equal(slot.item.type, "volume", "the first value of the name is the slot's");
    assert.equal(slot.mru_position, 0);
    assert.ok(out.problems.some((p: Answer) => /1 of its values have a name that an earlier value of the key has/.test(p.why)), JSON.stringify(out.problems));
  });
});

test("shellbags reads a 15 MB MRUListEx under 6,000 subkeys in seconds: positions come from a map, and only as many entries as there are slots", { skip: REGIPY }, async () => {
  // 3.9 million entries that all name slot 0: every other slot was looked for through the whole list (in, then index), 6,000 times.
  await withCwd(async (cwd) => {
    const ints = 3_900_000;
    const mru = Buffer.alloc(4 * ints + 4);
    mru.writeInt32LE(-1, 4 * ints);
    await writeFile(join(cwd, "work", "UsrClass.dat"), hive({ name: "ROOT", children: [{ name: "Bag", values: [{ name: "MRUListEx", type: "binary", value: mru }],
      children: Array.from({ length: 6000 }, (_, i) => ({ name: String(i) })) }] }));
    const started = Date.now();
    const out = body<Answer>(await tool("shellbags", cwd, { hive: "work/UsrClass.dat", key: "Bag", limit: 3 }));
    assert.ok(Date.now() - started < 30_000, `took ${Date.now() - started} ms`);
    assert.equal(out.entry_count, 6000);
    assert.equal(out.walk_stopped_by_time_limit, false);
  });
});

// --- persistence_normalise: a name twice; tasks past the cap; a line nested too deep ---------------------------------------------------

dual("persistence_normalise reads the first ImagePath of a service, as Windows does, keeps the later one and is partial", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SYSTEM", { name: "ROOT", children: [{ name: "ControlSet001", children: [{ name: "Services", children: [{ name: "Svc1", values: [
      { name: "ImagePath", type: "expand_sz", value: "C:\\Windows\\System32\\first.exe" },
      { name: "imagepath", type: "expand_sz", value: "C:\\Windows\\System32\\later.exe" },
      { name: "Start", type: "dword", value: 2 },
    ] }] }] }] });
    const out = body<Answer>(await tool("persistence_normalise", cwd, { system: "work/SYSTEM" }, env));
    assert.equal(out.status, "partial", out.status_basis);
    const svc = out.items.find((i: Answer) => i.mechanism === "service") as Answer;
    assert.equal(svc.image_path, "C:\\Windows\\System32\\first.exe");
    assert.equal(svc.image_path_value, "C:\\Windows\\System32\\later.exe");
    assert.ok(out.problems.some((p: string) => /1 of its values have a name that an earlier value of the key has/.test(p)), JSON.stringify(out.problems));
  });
});

test("persistence_normalise holds at most 100,000 tasks from an evtx result file, counts the rest, and reads past a line nested too deep", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const lines: string[] = ["[".repeat(200_000) + "]".repeat(200_000)];
    for (let i = 0; i < 120_000; i++) lines.push(JSON.stringify({ channel: "Microsoft-Windows-TaskScheduler/Operational", event_id: 106, record_id: i, data: { TaskName: `\\T${i}` } }));
    await writeFile(join(cwd, "work", "ev.jsonl"), lines.join("\n") + "\n");
    // contains matches nothing: the tasks are held and counted, and none is written (writing is not what is tested)
    await mkdir(join(cwd, "work", "Tasks"), { recursive: true });
    const out = body<Answer>(await tool("persistence_normalise", cwd, { tasks_dir: "work/Tasks", evtx_results: "work/ev.jsonl", contains: "no-such-needle" }));
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /20000 task\(s\) were met after the 100000 this tool holds at once/);
    assert.match(out.status_basis, /1 line\(s\) of the evtx result file could not be read/);
  });
});

// --- userassist_bam_shimcache: what is left at the time limit is counted, not decoded ---------------------------------------------------

test("userassist_bam_shimcache counts the ShimCache entries left at its time limit from the header, without decoding them", { skip: REGIPY }, async () => {
  // A Windows 7 (64-bit) blob of 300,000 entries that each name one 64 KiB path: past the deadline the decoder was run to the end to count
  // them (1.5 million entries took the run 15 s past its limit). The tool's deadline is set to 3 s in a copy, so the tail is most of it.
  await withCwd(async (cwd) => {
    const n = 300_000;
    const plen = 65534;
    const head = Buffer.alloc(128);
    head.writeUInt32LE(0xbadc0fee, 0);
    head.writeUInt32LE(n, 4);
    const entry = Buffer.alloc(48);
    entry.writeUInt16LE(plen, 0);
    entry.writeUInt16LE(plen, 2);
    entry.writeBigUInt64LE(BigInt(128 + n * 48), 8);
    entry.writeBigUInt64LE(132_000_000_000_000_000n, 16);
    const blob = Buffer.concat([head, Buffer.concat(Array.from({ length: n }, () => entry)), Buffer.from("A\0".repeat(plen / 2), "latin1")]);
    await writeFile(join(cwd, "work", "SYSTEM"), hive({ name: "ROOT", children: [{ name: "ControlSet001", children: [{ name: "Control", children: [{ name: "Session Manager",
      children: [{ name: "AppCompatCache", values: [{ name: "AppCompatCache", type: "binary", value: blob }] }] }] }] }] }));
    const src = await readFile(join(WIN, "userassist_bam_shimcache", "run.py"), "utf8");
    const patched = src.replace("DEADLINE_SECONDS = 84 ", "DEADLINE_SECONDS = 3 ");
    assert.notEqual(patched, src, "the deadline was patched");
    await mkdir(join(cwd, "copy"), { recursive: true });
    await writeFile(join(cwd, "copy", "run.py"), patched);
    const started = Date.now();
    const out = body<Answer>(await runPy(join(cwd, "copy", "run.py"), cwd, { hive: "work/SYSTEM", source: "shimcache", limit: 1 }, undefined, { AGENT_ID: "s1" }));
    const took = Date.now() - started;
    assert.ok(took < 6_000, `took ${took} ms with a 3 s deadline`);      // decoding the tail to count it took 8 s here
    assert.equal(out.status, "partial");
    const m = /(\d+) ShimCache entr\(ies\) were not read/.exec(out.status_basis);
    assert.ok(m, out.status_basis);
    assert.ok(Number(m[1]) > n - 50_000 && Number(m[1]) <= n, out.status_basis);
  });
});

test("userassist_bam_shimcache says an AppCompatCache value over the size cap is not read, and does not say the source is absent", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const blob = Buffer.alloc(17 * MiB);
    blob.writeUInt32LE(0xbadc0fee, 0);
    await writeFile(join(cwd, "work", "SYSTEM"), hive({ name: "ROOT", children: [{ name: "ControlSet001", children: [{ name: "Control", children: [{ name: "Session Manager",
      children: [{ name: "AppCompatCache", values: [{ name: "AppCompatCache", type: "binary", value: blob }] }] }] }] }] }));
    const out = body<Answer>(await tool("userassist_bam_shimcache", cwd, { hive: "work/SYSTEM", source: "shimcache" }));
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: string) => /declares 17825792 bytes of data, more than the 16 MiB/.test(p)), JSON.stringify(out.problems));
  });
});
