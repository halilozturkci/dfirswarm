/**
 * Follow-ups to the windows-forensics withholding work, each pinned by a deterministic test:
 *
 *  1. regkv reads its clock for every subkey of the key it is listing (one key can hold hundreds of thousands), and counts the rest;
 *  2. shellbags names and lists at most MAX_UNOPENED_LISTED keys and entries past its time limit, and counts the rest;
 *  3. the last-row memo of row_object keeps 1, True and 1.0 apart;
 *  4. tree_complete is false when the walk stopped at its time limit;
 *  5. amcache_apps names the layout it stopped in with fixed words, so its status basis stays readable past the judging time;
 *  6. the seal stop sits 3.5 seconds before the manifest's time limit and after the tool's own clock;
 *  7. past the judging time a short plain string in a typed field (a SID, a GUID, a digest) must still fit the grammar of its type.
 *
 * The clock of a tool is replaced by a counter (or by a clock that starts at its first reading) in a copy of the tool, so that no case depends on how
 * fast the machine is.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { runPy, withCwd } from "./tool-library-harness.ts";
import { AGENT, WIN } from "./windows-pack-harness.ts";
import { VARIANTS, type Node, type Val } from "./windows-stub-regipy.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const PLACEHOLDER = /^<withheld \d+ (?:characters|bytes)/;
const BEGIN = "# BEGIN SHARED BOUNDARY";
const END = "# END SHARED BOUNDARY";
const OUT_OF_TIME: [string, string] = ["SEAL_BUDGET = 10.0", "SEAL_BUDGET = -1.0"];
const CLOCK_LINE = '    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]';

/** `out_of_time()` that is true from its `after`th reading on. */
const afterReadings = (after: number): [string, string] => [
  `def out_of_time():\n${CLOCK_LINE}`,
  `_READINGS = [0]\n\n\ndef out_of_time():\n    _READINGS[0] += 1\n    return _READINGS[0] > ${after}`,
];

/** A copy of a tool with some of its text changed (an edit marked optional may be absent), run on `args`. */
async function runPatched(name: string, cwd: string, edits: Array<[string, string] | [string, string, "optional"]>, args: unknown, env: Record<string, string>): Promise<{ answer: Answer; stdout: string }> {
  let text = await readFile(join(WIN, name, "run.py"), "utf8");
  for (const [from, to, optional] of edits) {
    if (optional && !text.includes(from)) continue;
    assert.ok(text.includes(from), `${name}: ${from}`);
    text = text.replace(from, to);
  }
  const file = join(cwd, "patched", `${name}.py`);
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, text, "utf8");
  const run = await runPy(file, cwd, args, undefined, { ...AGENT, ...env });
  assert.equal(run.code, 0, run.stderr + run.stdout);
  assert.doesNotMatch(run.stderr, /Traceback/);
  return { answer: JSON.parse(run.stdout) as Answer, stdout: run.stdout };
}

const item = (text: string): Buffer => {
  const content = Buffer.concat([Buffer.from([0x4e, 0x00]), Buffer.from(text, "latin1"), Buffer.from([0])]);
  const size = Buffer.alloc(2);
  size.writeUInt16LE(content.length + 2);
  return Buffer.concat([size, content]);
};
const underShell = (bag: Node): Node => ({
  name: "HIVE",
  children: [{ name: "Local Settings", children: [{ name: "Software", children: [{ name: "Microsoft", children: [{ name: "Windows", children: [{ name: "Shell", children: [bag] }] }] }] }] }],
});

for (const V of VARIANTS) {
  const skip = V.skip || false;

  // 1 and 4

  test(`regkv: the clock is read for every subkey of the key being listed, the rest is counted and not listed, and tree_complete is false [${V.label}]`, { skip }, async () => {
    await withCwd(async (cwd) => {
      const children = Array.from({ length: 60 }, (_, i) => ({ name: `child${String(i).padStart(3, "0")}` }));
      const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [{ name: "Wide", children }] });
      // reading 1 is the walk's own check at the key; readings 2 to 20 are children 0 to 18
      const { answer } = await runPatched("regkv", cwd, [afterReadings(20)], { hive: "work/SOFTWARE", key: "Wide", recurse: true, depth: 3, limit: 5 }, env);
      assert.equal(answer.walk_stopped_by_time_limit, true);
      assert.equal(answer.nodes_listed, 19, "the children after the time limit are not listed");
      assert.equal(answer.subkeys_not_listed_for_time, 41, "and are counted");
      assert.equal(answer.tree_complete, false, "a walk the time limit stopped is not a complete tree, whatever the inline list holds");
      assert.equal(answer.status, "partial");
      assert.match(answer.status_basis, /branch\(es\) were not entered|problem\(s\) are named/);
      assert.equal(answer.node_count, 19, "the file of nodes holds the 19 listed");
      assert.equal(answer.stopped_branches.length, 1, "the key that was being listed is named once");
      assert.equal(answer.stopped_branches[0].subkeys, 41);
      assert.ok(answer.problems.some((p: Answer) => /41 subkey\(s\) of the key being listed were not listed/.test(JSON.stringify(p))), "the walk's problem line says so");
    });
  });

  test(`regkv: a key with thousands of children is cut by the real clock inside the loop (a clock that starts at its first reading) [${V.label}]`, { skip }, async () => {
    await withCwd(async (cwd) => {
      const total = 4000;
      const children = Array.from({ length: total }, (_, i) => ({ name: `k${String(i).padStart(5, "0")}` }));
      const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [{ name: "Wide", children }] });
      const clock: [string, string] = [
        `def out_of_time():\n${CLOCK_LINE}`,
        // (the clock starts at the second reading, the first child's: the first, at the key, comes before the names are sorted)
        `_T0 = []\n_N = [0]\n\n\ndef out_of_time():\n    _N[0] += 1\n    if _N[0] == 2:\n        _T0.append(time.monotonic())\n    return bool(_T0) and time.monotonic() - _T0[0] > 0.003`,
      ];
      const { answer } = await runPatched("regkv", cwd, [clock], { hive: "work/SOFTWARE", key: "Wide", recurse: true, depth: 3, limit: 5 }, env);
      assert.ok(answer.nodes_listed > 0 && answer.nodes_listed < total, `${answer.nodes_listed} of ${total} listed`);
      assert.equal(answer.nodes_listed + answer.subkeys_not_listed_for_time, total, "every child is listed or counted");
      assert.equal(answer.tree_complete, false);
      assert.equal(answer.walk_stopped_by_time_limit, true);
    });
  });

  test(`regkv: a walk that was not stopped is complete, and a walk with more than the inline list holds says partial but not that the time limit was reached [${V.label}]`, { skip }, async () => {
    await withCwd(async (cwd) => {
      const children = Array.from({ length: 2100 }, (_, i) => ({ name: `k${String(i).padStart(4, "0")}` }));
      const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [{ name: "Big", children }, { name: "Small", children: [{ name: "a" }] }] });
      const big = JSON.parse((await runPy(join(WIN, "regkv", "run.py"), cwd, { hive: "work/SOFTWARE", key: "Big" }, undefined, { ...AGENT, ...env })).stdout) as Answer;
      assert.equal(big.tree_complete, false);
      assert.equal(big.walk_stopped_by_time_limit, false);
      assert.equal(big.subkeys_not_listed_for_time, undefined);
      assert.match(big.status_basis, /the inline listing holds the first 2000 keys/);
      const small = JSON.parse((await runPy(join(WIN, "regkv", "run.py"), cwd, { hive: "work/SOFTWARE", key: "Small" }, undefined, { ...AGENT, ...env })).stdout) as Answer;
      assert.equal(small.tree_complete, true);
      assert.equal(small.status, "complete");
    });
  });

  // 2

  test(`shellbags: past the time limit the first MAX_UNOPENED_LISTED siblings are named and listed and the rest are counted, not judged [${V.label}]`, { skip }, async () => {
    await withCwd(async (cwd) => {
      const names = Array.from({ length: 12 }, (_, i) => `folder${i}`);
      const values: Val[] = names.map((t, i) => ({ name: String(i), type: "binary" as const, value: item(t) }));
      const bag: Node = { name: "BagMRU", values, children: names.map((_, i) => ({ name: String(i) })) };
      const env = await V.write(cwd, "work/UsrClass.dat", underShell(bag));
      // reading 1 is the check at the root; every later reading is past the time limit
      const { answer } = await runPatched("shellbags", cwd, [afterReadings(1), ["MAX_UNOPENED_LISTED = 1000 ", "MAX_UNOPENED_LISTED = 3 ", "optional"]], { hive: "work/UsrClass.dat", limit: 50 }, env);
      assert.equal(answer.walk_stopped_by_time_limit, true);
      assert.equal(answer.not_walked_count, 3, "three keys are named");
      assert.equal(answer.not_walked_not_named, 9, "nine are only counted");
      assert.equal(answer.entries_not_listed_for_time, 9, "and their entries are not listed");
      assert.equal(answer.entry_count, 3);
      assert.equal(answer.status, "partial");
      assert.match(answer.status_basis, /9 key\(s\) met after the time limit were counted and not named/);
    });
  });

  test(`shellbags: numbered values that no key holds are bounded the same way past the time limit [${V.label}]`, { skip }, async () => {
    await withCwd(async (cwd) => {
      const values: Val[] = Array.from({ length: 10 }, (_, i) => ({ name: String(i), type: "binary" as const, value: item(`orphan${i}`) }));
      const env = await V.write(cwd, "work/UsrClass.dat", underShell({ name: "BagMRU", values }));
      const second = await runPatched("shellbags", cwd, [afterReadings(1), ["MAX_UNOPENED_LISTED = 1000 ", "MAX_UNOPENED_LISTED = 3 ", "optional"]], { hive: "work/UsrClass.dat", limit: 50 }, env);
      assert.equal(second.answer.entry_count, 3, "three are listed");
      assert.equal(second.answer.values_without_subkey_count, 3, "three are in the orphan file");
      assert.equal(second.answer.entries_not_listed_for_time, 7, "seven are counted");
      assert.equal(second.answer.walk_stopped_by_time_limit, true);
    });
  });

  // 5

  test(`amcache_apps: the layout the walk stopped in is named with fixed words, so the status basis is readable past the judging time and holds no name of the hive [${V.label}]`, { skip }, async () => {
    await withCwd(async (cwd) => {
      const volume = "VolumeWithAVeryLongNameOfTheHive0123456789";
      const rows: Node[] = Array.from({ length: 4 }, (_, i) => ({ name: `file${i}`, values: [{ name: "15", type: "sz" as const, value: `c:\\program files\\tool ${i}\\tool.exe` }] }));
      const env = await V.write(cwd, "work/Amcache.hve", { name: "HIVE", children: [{ name: "Root", children: [{ name: "File", children: [{ name: volume, children: rows }] }] }] });
      for (const late of [false, true]) {
        // readings: 1 the volume, 2 the first row, 3 the second (late)
        const { answer, stdout } = await runPatched("amcache_apps", cwd, [afterReadings(2), ...(late ? [OUT_OF_TIME] : [])], { hive: "work/Amcache.hve", limit: 10 }, env);
        assert.equal(answer.walk_stopped_by_time_limit, true);
        assert.equal(answer.status, "partial");
        assert.doesNotMatch(answer.status_basis, PLACEHOLDER, `the reason the answer is partial is readable (late path: ${late})`);
        assert.match(answer.status_basis, /time limit \(84 seconds\) was reached in the older layout \(File\), inside a volume/);
        assert.ok(!answer.status_basis.includes(volume), "no name of the hive in the status basis");
        assert.ok(!answer.problems.some((p: unknown) => String(p).includes(volume) && /time limit/.test(String(p))), "nor in the line that says the time limit was reached");
        void stdout;
      }
    });
  });

  test(`amcache_apps: the newer layout is named by a fixed label as well [${V.label}]`, { skip }, async () => {
    await withCwd(async (cwd) => {
      const rows: Node[] = [0, 1, 2].map((i) => ({ name: `${i}`, values: [{ name: "LowerCaseLongPath", type: "sz" as const, value: `c:\\program files\\tool ${i}\\tool.exe` }] }));
      const env = await V.write(cwd, "work/Amcache.hve", { name: "HIVE", children: [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: rows }] }] });
      const { answer } = await runPatched("amcache_apps", cwd, [afterReadings(1), OUT_OF_TIME], { hive: "work/Amcache.hve", limit: 10 }, env);
      assert.doesNotMatch(answer.status_basis, PLACEHOLDER);
      assert.match(answer.status_basis, /reached in the newer layout \(InventoryApplicationFile\)/);
    });
  });
}

// 6

test("the seal stop of each of the six tools is 3.5 seconds or more before its manifest's time limit, and after the tool's own clock", async () => {
  const six = ["regkv", "shellbags", "amcache_apps", "evtx_query", "evtx_carve", "esedb_query"];
  for (const name of six) {
    const text = await readFile(join(WIN, name, "run.py"), "utf8");
    const manifest = JSON.parse(await readFile(join(WIN, name, "manifest.json"), "utf8")) as { timeout_seconds: number };
    const stop = Number(/seal_stop_after\(([0-9.]+)\)\s+#/.exec(text)?.[1]);
    const own = Number(/^DEADLINE_SECONDS = ([0-9]+)\s/m.exec(text)?.[1]);
    assert.ok(Number.isFinite(stop) && Number.isFinite(own), `${name}: both constants are found`);
    assert.ok(manifest.timeout_seconds - stop >= 3.5, `${name}: the seal stop ${stop} s is ${manifest.timeout_seconds - stop} s before the limit of ${manifest.timeout_seconds} s`);
    assert.ok(own + 1.5 <= stop, `${name}: the tool's own clock (${own} s) runs out before the seal stop (${stop} s)`);
    assert.ok(/3\.5 seconds before its time limit/.test(JSON.stringify(manifest)) || (await readFile(join(WIN, name, "manifest.json"), "utf8")).includes("3.5 seconds before its time limit"), `${name}: the manifest says where the seal stop is`);
  }
});

// 3 and 7: the shared block of every tool that carries it, driven in-process

const DRIVE = String.raw`
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("block", sys.argv[1])
blk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(blk)
case = sys.argv[2]
if case == "row_memo":
    rows = [{"a": 1}, {"a": True}, {"a": 1.0}, {"a": 0}, {"a": False}, {"a": 0.0}, {"a": -0.0}, {"a": 1}, {"a": 1}]
    print(json.dumps([repr(blk.row_object(r)) for r in rows]))
elif case == "row_memo_hits":
    calls = [0]
    real = blk._seal
    def counting(*a, **k):
        calls[0] += 1
        return real(*a, **k)
    blk._seal = counting
    row = {"name": "plain", "n": 1, "ok": True, "f": 0.5}
    first = blk.row_object(row)
    after_first = calls[0]
    second = blk.row_object(dict(row))
    print(json.dumps({"first": after_first, "calls": calls[0], "same": first == second, "row": second}))
elif case == "typed_late":
    blk.SEAL_BUDGET = -1.0
    blk.OWN_NAMES.add("ownword")
    cases = [["sid", "hello"], ["digest", "deadbeefcafe"], ["guid", "hello"], ["guid", "abcdef0123"], ["number", "12345"], ["number", "twelve"], ["version", "1.2.3"],
             ["version", "plainword"], ["text", "hello"], ["name", "hello"], ["sid", "S15"], ["sid", "ownword"], ["mac", "hello"], ["ip", "hello"], ["time", "hello"]]
    print(json.dumps([[k, t, blk.seal(t, k)] for k, t in cases]))
elif case == "typed_normal":
    cases = [["sid", "hello"], ["guid", "hello"], ["guid", "abcdef0123"], ["number", "12345"]]
    print(json.dumps([[k, t, blk.seal(t, k)] for k, t in cases]))
`;

const blocks = new Map<string, string>();
async function blockFile(name: string): Promise<string> {
  let file = blocks.get(name);
  if (!file) {
    const text = await readFile(join(WIN, name, "run.py"), "utf8");
    const dir = await mkdtemp(join(tmpdir(), "win-followups-"));
    file = join(dir, "block.py");
    await writeFile(file, "import re, json, os, sys\nfrom pathlib import Path\n" + text.slice(text.indexOf(BEGIN), text.indexOf(END) + END.length) + "\n");
    await writeFile(join(dir, "drive.py"), DRIVE);
    blocks.set(name, file);
  }
  return file;
}

async function drive(name: string, kase: string): Promise<any> { // eslint-disable-line @typescript-eslint/no-explicit-any
  const file = await blockFile(name);
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [join(dirname(file), "drive.py"), file, kase]);
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve(JSON.parse(Buffer.concat(out).toString("utf8"))) : reject(new Error(`${name} ${kase}: ${Buffer.concat(err).toString("utf8")}`))));
  });
}

const carriers = async (): Promise<string[]> => {
  const names: string[] = [];
  for (const name of (await readdir(WIN)).sort()) if ((await readFile(join(WIN, name, "run.py"), "utf8").catch(() => "")).includes(BEGIN)) names.push(name);
  return names;
};

for (const name of ["regkv", "shellbags", "amcache_apps", "evtx_query", "evtx_carve", "esedb_query"]) {
  test(`${name}: the last-row memo keeps 1, True and 1.0 apart (and 0, False, 0.0 and -0.0), and still serves an identical row once`, async () => {
    const got = await drive(name, "row_memo");
    assert.deepEqual(got, ["{'a': 1}", "{'a': True}", "{'a': 1.0}", "{'a': 0}", "{'a': False}", "{'a': 0.0}", "{'a': -0.0}", "{'a': 1}", "{'a': 1}"]);
    const hits = await drive(name, "row_memo_hits");
    assert.ok(hits.first >= 1);
    assert.equal(hits.calls, hits.first, "the second identical row is the first's result: nothing is judged again");
    assert.equal(hits.same, true);
  });

  test(`${name}: past the judging time a short plain string in a typed field must fit the grammar of its type`, async () => {
    const got = (await drive(name, "typed_late")) as Array<[string, string, string]>;
    const shown = (kind: string, text: string): string => got.find((g) => g[0] === kind && g[1] === text)![2];
    for (const [kind, text] of [["sid", "hello"], ["digest", "deadbeefcafe"], ["guid", "hello"], ["number", "twelve"], ["version", "plainword"], ["mac", "hello"], ["ip", "hello"], ["time", "hello"]]) {
      assert.match(shown(kind, text), PLACEHOLDER, `${kind} ${text} is withheld`);
    }
    for (const [kind, text] of [["guid", "abcdef0123"], ["number", "12345"], ["version", "1.2.3"], ["text", "hello"], ["name", "hello"], ["sid", "S15"], ["sid", "ownword"]]) {
      assert.equal(shown(kind, text), text, `${kind} ${text} is still shown`);
    }
  });
}

test("the block is the same in every tool that carries it, and six tools carry it", async () => {
  const names = await carriers();
  assert.ok(names.length >= 6, names.join(", "));
  const seen = new Set<string>();
  for (const name of names) {
    const text = await readFile(join(WIN, name, "run.py"), "utf8");
    seen.add(text.slice(text.indexOf(BEGIN), text.indexOf(END) + END.length));
  }
  assert.equal(seen.size, 1, "one block, byte for byte");
});
