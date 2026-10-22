/**
 * regkv, shellbags and amcache_apps read hives that were made to cost: an index that names one list many times, thousands of values of
 * one name, a value the library cannot decode. Each case is built from the regf layout (tests/windows-hive.ts) and, for the stand-in
 * regipy, from the same description; the real library runs where it is installed.
 *
 * Layout facts used: an nk cell is at least 76 bytes and a vk cell at least 20, so a hive of N bytes holds at most N / 76 keys and
 * N / 20 values; an "ri" index root is a list of offsets of leaf lists (signature, element count, offsets).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";
import { WIN, body, failed, py, tool } from "./windows-pack-harness.ts";
import { VARIANTS, type Node, type Variant } from "./windows-stub-regipy.ts";

function dual(name: string, fn: (v: Variant) => Promise<void>): void {
  for (const v of VARIANTS) test(`${name} [${v.label}]`, { skip: v.skip }, () => fn(v));
}

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const keys = (n: number, prefix = "K"): Node[] => Array.from({ length: n }, (_, i) => ({ name: prefix + String(i).padStart(5, "0") }));

/** Every file a tool wrote for the agent (work/s1/...), with its size. */
async function written(cwd: string): Promise<Array<{ file: string; bytes: number }>> {
  const out: Array<{ file: string; bytes: number }> = [];
  async function walk(dir: string): Promise<void> {
    for (const entry of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      else out.push({ file: full, bytes: (await stat(full)).size });
    }
  }
  await walk(join(cwd, "work", "s1"));
  return out;
}

// --- an index that repeats a list -----------------------------------------------

dual("regkv reads a subkey index that repeats one list for what a hive of that size can hold, not for what the index claims", async (v) => {
  // An "ri" index naming a leaf list of 500 keys 300 times is read as 150,000 keys by the library: a 53 KB hive listed them all
  // (2,000 repeats: a million keys, 1.2 GB and two 157 MB files).
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/h.dat", { name: "ROOT", children: [{ name: "Big", children: keys(500), indexRepeats: 300 }] });
    const hiveBytes = (await stat(join(cwd, "work", "h.dat"))).size;
    const out = body<Answer>(await tool("regkv", cwd, { hive: "work/h.dat", key: "Big" }, env));
    assert.ok(out.nodes_listed <= Math.floor(hiveBytes / 76), `${out.nodes_listed} keys listed from a ${hiveBytes}-byte hive`);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /problem/);
    assert.ok(out.problems.some((p: Answer) => /more keys than a \d+-byte hive can hold/.test(p.error)), JSON.stringify(out.problems));
    assert.ok(out.problems.some((p: Answer) => /more than once; each is listed once/.test(p.error)), "the repeated elements are said");
    assert.equal(new Set(out.subkeys.map((s: Answer) => s.name)).size, out.subkeys.length, "a key is listed once");
    assert.equal(out.subkeys.length, 500, "every distinct key is listed");
    assert.ok((await written(cwd)).every((f) => f.bytes < 2_000_000), "no large file is written");
  });
});

dual("shellbags reads a BagMRU index that repeats one list for what a hive of that size can hold", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/UsrClass.dat", { name: "ROOT", children: [{ name: "Big", children: keys(500), indexRepeats: 300 }] });
    const hiveBytes = (await stat(join(cwd, "work", "UsrClass.dat"))).size;
    const out = body<Answer>(await tool("shellbags", cwd, { hive: "work/UsrClass.dat", key: "Big", limit: 20 }, env));
    assert.ok(out.keys_walked <= Math.floor(hiveBytes / 76) + 1, `${out.keys_walked} keys walked`);
    assert.ok(out.entry_count <= 500 + 1);
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: Answer) => /more keys than a \d+-byte hive can hold/.test(p.why)), JSON.stringify(out.problems));
    assert.ok((await written(cwd)).every((f) => f.bytes < 2_000_000));
  });
});

dual("amcache_apps reads an inventory index that repeats one list for what a hive of that size can hold", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/Amcache.hve", {
      name: "ROOT",
      children: [{ name: "Root", children: [{
        name: "InventoryApplicationFile",
        children: keys(500).map((k) => ({ ...k, values: [{ name: "FileId", type: "sz" as const, value: "0000" + "ab".repeat(20) }] })),
        indexRepeats: 300,
      }] }],
    });
    const hiveBytes = (await stat(join(cwd, "work", "Amcache.hve"))).size;
    const out = body<Answer>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve", limit: 20 }, env));
    assert.ok(out.entry_count <= Math.floor(hiveBytes / 76), `${out.entry_count} rows from a ${hiveBytes}-byte hive`);
    assert.equal(out.entry_count, 500, "every distinct key is a row, once");
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: string) => /more keys than a \d+-byte hive can hold/.test(p)), JSON.stringify(out.problems));
    assert.ok((await written(cwd)).every((f) => f.bytes < 2_000_000));
  });
});

// --- values -----------------------------------------------------------------------

test("regkv names 16,000 values of one name in linear time, and a value really called 'a (2)' keeps its place", { skip: VARIANTS[1].skip }, async () => {
  // The numbering loop started again at 2 for every duplicate: 8,000 duplicates took nine seconds, 16,000 forty (the tool's own
  // limit is thirty).
  await withCwd(async (cwd) => {
    const dupes = Array.from({ length: 16_000 }, (_, i) => ({ name: "a", type: "dword" as const, value: i }));
    const env = await VARIANTS[1].write(cwd, "work/h.dat", { name: "ROOT", children: [{ name: "Many", values: dupes }] });
    const started = Date.now();
    const out = body<Answer>(await tool("regkv", cwd, { hive: "work/h.dat", key: "Many" }, env));
    assert.ok(Date.now() - started < 15_000, `took ${Date.now() - started} ms`);
    assert.equal(Object.keys(out.values).length, 16_000);
    assert.equal(out.values.a, 0);
    assert.equal(out.values["a (2)"], 1);
    assert.equal(out.values["a (16000)"], 15_999);
    assert.ok(out.problems.some((p: Answer) => /more than one value named 'a'; the 15999 later one/.test(p.error)));
  });
});

dual("regkv gives every value its own name when a value is really called like the number of another", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/h.dat", { name: "ROOT", children: [{ name: "K", values: [
      { name: "a", type: "dword", value: 1 }, { name: "a", type: "dword", value: 2 }, { name: "a (2)", type: "dword", value: 3 },
      { name: "a", type: "dword", value: 4 }, { name: "a (2)", type: "dword", value: 5 },
    ] }] });
    const out = body<Answer>(await tool("regkv", cwd, { hive: "work/h.dat", key: "K" }, env));
    assert.equal(Object.keys(out.values).length, 5, JSON.stringify(out.values));
    assert.deepEqual(Object.values(out.values).sort(), [1, 2, 3, 4, 5], "no value replaced another");
  });
});

test("regkv reads at most the values a hive of that size can hold from a value list that repeats one record", { skip: VARIANTS[1].skip }, async () => {
  await withCwd(async (cwd) => {
    const env = await VARIANTS[1].write(cwd, "work/h.dat", { name: "ROOT", children: [{ name: "K", values: [{ name: "a", type: "dword", value: 7 }], valueListRepeats: 40_000 }] });
    const hiveBytes = (await stat(join(cwd, "work", "h.dat"))).size;
    const out = body<Answer>(await tool("regkv", cwd, { hive: "work/h.dat", key: "K" }, env));
    assert.ok(Object.keys(out.values).length <= Math.floor(hiveBytes / 20), `${Object.keys(out.values).length} values from ${hiveBytes} bytes`);
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: Answer) => /more values than a \d+-byte hive can hold/.test(p.error)), JSON.stringify(out.problems).slice(0, 400));
  });
});

test("regkv reads a value list that names one big record again and again for the data the hive can hold, not once per element", { skip: VARIANTS[1].skip }, async () => {
  // 3,000 elements naming one 60 KB value read 180 MB from a 70 KB hive (the value cap alone, hive size / 20, allowed all of them).
  await withCwd(async (cwd) => {
    const env = await VARIANTS[1].write(cwd, "work/h.dat", { name: "ROOT", children: [{ name: "K", values: [{ name: "big", type: "binary", value: Buffer.alloc(60_000, 7) }], valueListRepeats: 3_000 }] });
    const hiveBytes = (await stat(join(cwd, "work", "h.dat"))).size;
    const out = body<Answer>(await tool("regkv", cwd, { hive: "work/h.dat", key: "K" }, env));
    assert.ok(Object.keys(out.values).length * 60_000 <= 4 * hiveBytes + 60_000, `${Object.keys(out.values).length} values of 60 KB from a ${hiveBytes}-byte hive`);
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: Answer) => /hold more data than a \d+-byte hive can/.test(p.error)), JSON.stringify(out.problems).slice(0, 300));
  });
});

dual("regkv says a big-endian DWORD is not in the answer, instead of returning an empty value as complete", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/h.dat", { name: "ROOT", children: [{ name: "K", values: [{ name: "Be", type: 5, value: Buffer.from([0x11, 0x22, 0x33, 0x44]) }] }] });
    const out = body<Answer>(await tool("regkv", cwd, { hive: "work/h.dat", key: "K" }, env));
    assert.equal(out.value_types.Be, "REG_DWORD_BIG_ENDIAN");
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: Answer) => /REG_DWORD_BIG_ENDIAN, for which regipy returns no data/.test(p.error)), JSON.stringify(out.problems));
  });
});

// --- the library's own messages ---------------------------------------------------

dual("regkv and amcache_apps print no byte of a value the library could not decode, on stderr or anywhere", async (v) => {
  // regipy logs "can't decode byte 0xd1 in position 4" for a text value that is neither UTF-16 nor UTF-8: a byte of a value the
  // tool withholds, on stderr (21% of 16-byte and 63% of 64-byte random values of that kind).
  await withCwd(async (cwd) => {
    const bad = Buffer.from([0xd1, 0xff, 0xc3, 0x28, 0xa0, 0xa1, 0xe2, 0x28, 0xa1, 0xf0, 0x28, 0x8c, 0xbc, 0xfe, 0xfd]); // odd length, invalid in both
    const env = await v.write(cwd, "work/SECURITY", { name: "ROOT", children: [{ name: "Policy", children: [{ name: "Secrets", children: [{ name: "X", children: [{ name: "CurrVal", values: [{ name: "", type: 1, value: bad }] }] }] }] }] });
    const run = await tool("regkv", cwd, { hive: "work/SECURITY", key: "Policy\\Secrets\\X\\CurrVal" }, env);
    assert.equal(run.stderr, "", "nothing on stderr");
    for (const piece of ["0xd1", "can't decode", "position", "formating", bad.toString("hex"), "d1ffc328"]) assert.equal(run.stdout.includes(piece), false, piece);
    const out = JSON.parse(run.stdout) as Answer;
    assert.ok(out.library_messages_withheld >= 1, "the message is counted");
    assert.ok(out.problems.some((p: Answer) => /regipy logged \d+ message/.test(p.error)));
    assert.match(String(out.values["(default)"] ?? out.values[""] ?? Object.values(out.values)[0]), /^\[withheld/);
    // the same value in an Amcache layout
    const amcacheEnv = await v.write(cwd, "work/Amcache.hve", { name: "ROOT", children: [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: [{ name: "K1", values: [{ name: "Path", type: 1, value: bad }] }] }] }] });
    const am = await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }, amcacheEnv);
    assert.equal(am.stderr, "");
    assert.equal(am.stdout.includes("0xd1"), false);
    assert.equal(am.stdout.includes("can't decode"), false);
    assert.ok(JSON.parse(am.stdout).library_messages_withheld >= 1);
  });
});

// --- result files -----------------------------------------------------------------

dual("shellbags names its result files from what was asked about, never from the needle, and a digest of a guess does not match", async (v) => {
  // The name held sha256 of [hive, roots, contains, max_depth]: hashing a guessed needle into the same list reproduced the printed name.
  await withCwd(async (cwd) => {
    const folders = ["a1", "a2", "a3", "b1", "b2", "b3"].map((name) => ({ name }));
    const env = await v.write(cwd, "work/UsrClass.dat", { name: "ROOT", children: [{ name: "Root", children: folders }] });
    const run = (needle: string) => tool("shellbags", cwd, { hive: "work/UsrClass.dat", key: "Root", contains: needle, limit: 1 }, env);
    const a = body<Answer>(await run("a"));
    const b = body<Answer>(await run("b"));
    assert.ok(a.all_results && b.all_results, "three entries match each needle, more than the page holds");
    for (const needle of ["a", "b", "A", "a1"]) {
      const guessed = py(
        "import hashlib, json, sys\nprint('shellbags-' + hashlib.sha256(json.dumps(['work/UsrClass.dat', ['Root'], sys.argv[1], 24], sort_keys=True, default=str).encode()).hexdigest()[:16] + '.jsonl')",
        needle,
      ).trim();
      for (const out of [a, b]) assert.ok(!String(out.all_results).includes(guessed), `${out.all_results} is the name of a digest of ${needle}`);
    }
    assert.notEqual(a.all_results, b.all_results, "another needle is another result");
    assert.match(String(b.all_results), /-2\.jsonl$/);
    assert.equal(String(a.all_results), String(b.all_results).replace(/-2\.jsonl$/, ".jsonl"), "the two names differ by an ordinal only");
    const again = body<Answer>(await run("a"));
    assert.equal(again.all_results, a.all_results, "the same result is named again, not copied");
  });
});

dual("regkv and shellbags never replace a result file that is there: the same result is named again, another takes the next name", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/h.dat", { name: "ROOT", children: [{ name: "Big", children: keys(40) }] });
    const args = { hive: "work/h.dat", key: "Big", recurse: true, depth: 1, limit: 5 };
    const first = body<Answer>(await tool("regkv", cwd, args, env));
    assert.ok(first.all_nodes);
    const again = body<Answer>(await tool("regkv", cwd, args, env));
    assert.equal(again.all_nodes, first.all_nodes, "the same result keeps its name");
    // A larger file under that name: a rerun with a lower node limit used to put a smaller result over a larger one.
    const file = join(cwd, first.all_nodes);
    const bigger = (await readFile(file, "utf8")) + JSON.stringify({ path: "Big\\kept" }) + "\n";
    await writeFile(file, bigger);
    const third = body<Answer>(await tool("regkv", cwd, args, env));
    assert.notEqual(third.all_nodes, first.all_nodes);
    assert.match(third.all_nodes, /-2\.jsonl$/);
    assert.equal(await readFile(file, "utf8"), bigger, "the file that was there is as it was");
    // max_nodes is part of what was asked: a rerun with it set is another result
    const limited = body<Answer>(await tool("regkv", cwd, { ...args, max_nodes: 10 }, env));
    assert.notEqual(limited.all_nodes, first.all_nodes);
    assert.equal(await readFile(file, "utf8"), bigger);
  });
});

dual("regkv pages its problems: the first 50 are inline, all are in a file the answer names", async (v) => {
  await withCwd(async (cwd) => {
    const children: Node[] = Array.from({ length: 60 }, (_, i) => ({ name: "P" + String(i).padStart(3, "0"), children: keys(1, "c"), indexRepeats: 2 }));
    const env = await v.write(cwd, "work/h.dat", { name: "ROOT", children: [{ name: "Top", children }] });
    const out = body<Answer>(await tool("regkv", cwd, { hive: "work/h.dat", key: "Top", recurse: true, depth: 1 }, env));
    assert.equal(out.problem_count, 60, "each of the 60 keys lists a name more than once");
    assert.equal(out.problems.length, 50);
    assert.ok(out.all_problems, "the whole list is in a file");
    const rows = (await readFile(join(cwd, out.all_problems), "utf8")).trim().split("\n");
    assert.equal(rows.length, 60);
  });
});

dual("regkv names a missing key with at most 200 of the names that are there, and counts them", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/h.dat", { name: "ROOT", children: [{ name: "Wide", children: keys(300) }] });
    const err = failed(await tool("regkv", cwd, { hive: "work/h.dat", key: "Wide\\Nope" }, env));
    assert.equal(err.error, "key not found");
    assert.equal((err.subkeys_there as string[]).length, 200);
    assert.equal(err.subkeys_there_count, 300);
    assert.equal(err.status, "failed");
    assert.ok(typeof err.status_basis === "string" && String(err.status_basis).length > 10);
  });
});

dual("amcache_apps keeps a value called layout (or key, volume, sha1_raw) apart from the row's own fields", async (v) => {
  // A raw value NAME overwrote the tool's field: `layout` changed the row's layout and rows_by_layout, `key_last_modified` the time.
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/Amcache.hve", { name: "ROOT", children: [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: [{
      name: "K1",
      values: [{ name: "layout", type: "sz", value: "Spoofed" }, { name: "key_last_modified", type: "sz", value: "1999-01-01" }, { name: "Path", type: "sz", value: "C:\\a.exe" }],
    }] }] }] });
    const out = body<Answer>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }, env));
    assert.equal(out.entries[0].layout, "InventoryApplicationFile");
    assert.deepEqual(out.rows_by_layout, { InventoryApplicationFile: 1 });
    assert.equal(out.entries[0]["value:layout"], "Spoofed");
    assert.equal(out.entries[0]["value:key_last_modified"], "1999-01-01");
    assert.notEqual(out.entries[0].key_last_modified, "1999-01-01");
    assert.equal(out.entries[0].Path, "C:\\a.exe");
  });
});

dual("amcache_apps pages its problems: none is cut at 20 without a file", async (v) => {
  await withCwd(async (cwd) => {
    const volumes: Node[] = Array.from({ length: 45 }, (_, i) => ({ name: "vol" + i, children: keys(1), indexRepeats: 2 }));
    const env = await v.write(cwd, "work/Amcache.hve", { name: "ROOT", children: [{ name: "Root", children: [{ name: "File", children: volumes }] }] });
    const out = body<Answer>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve", limit: 500 }, env));
    assert.equal(out.problem_count, 45, JSON.stringify(out.problems.slice(-3)));
    assert.equal(out.problems.length, 40);
    assert.equal(out.problems_not_listed, 5);
    assert.ok(out.all_problems, "the whole list is in a file");
    assert.equal((await readFile(join(cwd, out.all_problems), "utf8")).trim().split("\n").length, 45);
    assert.equal(out.status, "partial");
  });
});

dual("amcache_apps says a complete read is complete, and why", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/Amcache.hve", { name: "ROOT", children: [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: keys(3) }] }] });
    const out = body<Answer>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }, env));
    assert.equal(out.status, "complete");
    assert.match(out.status_basis, /every row of both inventories was read/);
  });
});

// --- the tool's own clock and the signals ---------------------------------------------

test("regkv, shellbags and amcache_apps stop at their own time limit, say partial, and name what was not opened", async () => {
  await withCwd(async (cwd) => {
    const v = VARIANTS[0];
    const tree: Node[] = [{ name: "Root", children: [{ name: "A", children: keys(5) }, { name: "B", children: keys(5) }, { name: "InventoryApplicationFile", children: keys(5) }] }];
    const env = await v.write(cwd, "work/h.dat", { name: "HIVE", children: tree });
    for (const [name, args, check] of [
      ["regkv", { hive: "work/h.dat", key: "Root", recurse: true, depth: 3 }, (o: Answer) => assert.ok(o.walk_stopped_by_time_limit && o.stopped_branch_count >= 1)],
      ["shellbags", { hive: "work/h.dat", key: "Root" }, (o: Answer) => assert.ok(o.walk_stopped_by_time_limit && o.not_walked_count >= 1)],
      ["amcache_apps", { hive: "work/h.dat" }, (o: Answer) => assert.ok(o.walk_stopped_by_time_limit)],
    ] as Array<[string, Record<string, unknown>, (o: Answer) => void]>) {
      const src = (await readFile(join(WIN, name, "run.py"), "utf8")).replace(/DEADLINE_SECONDS = \d+ /, "DEADLINE_SECONDS = 0 ");
      assert.ok(src.includes("DEADLINE_SECONDS = 0 "), name);
      await mkdir(join(cwd, "copy", name), { recursive: true });
      await writeFile(join(cwd, "copy", name, "run.py"), src);
      const run = await runPy(join(cwd, "copy", name, "run.py"), cwd, args, undefined, { AGENT_ID: "s1", ...env });
      assert.equal(run.code, 0, run.stdout + run.stderr);
      const out = JSON.parse(run.stdout) as Answer;
      assert.equal(out.status, "partial", name);
      assert.match(out.status_basis, /time limit|not walked|not entered|problem/, name);
      check(out);
    }
  });
});

function startHeld(name: string, cwd: string, args: unknown, env: Record<string, string>) {
  const child = spawn("python3", [join(WIN, name, "run.py")], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
  let stdout = "";
  child.stdout.on("data", (c: Buffer) => (stdout += c.toString()));
  const closed = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
  child.stdin.end(JSON.stringify(args));
  return { child, closed, out: () => stdout };
}

for (const variant of VARIANTS) {
  test(`regkv, shellbags and amcache_apps stopped by SIGTERM answer JSON, exit 143 and leave no temporary file [${variant.label}]`, { skip: variant.skip }, async () => {
    await withCwd(async (cwd) => {
      const big: Node[] = [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: keys(25_000).map((k) => ({ ...k, children: [{ name: "c" }] })) }] }];
      const env = await variant.write(cwd, "work/h.dat", { name: "HIVE", children: big });
      for (const [name, args, prefix] of [
        ["regkv", { hive: "work/h.dat", key: "Root\\InventoryApplicationFile", recurse: true, depth: 2, limit: 1 }, ".regkv"],
        ["shellbags", { hive: "work/h.dat", key: "Root\\InventoryApplicationFile", limit: 1 }, ".shellbags"],
        ["amcache_apps", { hive: "work/h.dat", limit: 1 }, ".amcache_apps"],
      ] as Array<[string, Record<string, unknown>, string]>) {
        const run = startHeld(name, cwd, args, env);
        const dir = join(cwd, "work", "s1", "tool-output");
        let seen = false;
        for (let waited = 0; waited < 30_000 && !seen; waited += 25) {
          seen = (await readdir(dir).catch(() => [] as string[])).some((n) => n.startsWith(prefix));
          if (!seen) await new Promise((r) => setTimeout(r, 25));
        }
        assert.ok(seen, `${name} never opened a temporary file`);
        // Stopped where it is, so that the signal cannot arrive after the answer; the handler runs when it goes on.
        run.child.kill("SIGSTOP");
        run.child.kill("SIGTERM");
        run.child.kill("SIGCONT");
        assert.equal(await run.closed, 143, name);
        const out = JSON.parse(run.out()) as Answer;
        assert.equal(out.status, "interrupted", name);
        assert.equal(out.signal, 15);
        assert.deepEqual((await readdir(dir)).filter((n) => n.startsWith(".")), [], `${name} left a temporary file`);
      }
    });
  });
}

// --- twins, shared blocks -----------------------------------------------------------

test("regkv's and amcache_apps' tool-library twins are byte-equal to the pack's tools", async () => {
  for (const name of ["regkv", "amcache_apps"]) {
    for (const file of ["run.py", "manifest.json"]) {
      assert.ok((await readFile(join(WIN, name, file))).equals(await readFile(join(ROOT, "tool-library", name, file))), `${name}/${file} differs from the tool-library copy`);
    }
  }
});

test("the windows-forensics tools that carry a shared block (place, page, stop, hive bounds) carry it identically", async () => {
  for (const [begin, end, expect] of [
    ["# BEGIN SHARED PLACE", "# END SHARED PLACE", ["regkv", "shellbags", "amcache_apps", "registry_recover", "lnk_jumplist"]],
    ["# BEGIN SHARED PAGE", "# END SHARED PAGE", ["regkv", "shellbags", "amcache_apps", "registry_recover", "lnk_jumplist"]],
    ["# BEGIN SHARED STOP", "# END SHARED STOP", ["regkv", "shellbags", "amcache_apps"]],
    ["# BEGIN SHARED HIVE BOUNDS", "# END SHARED HIVE BOUNDS", ["regkv", "shellbags", "amcache_apps", "registry_recover"]],
  ] as Array<[string, string, string[]]>) {
    const found: Record<string, string> = {};
    for (const name of await readdir(WIN)) {
      const text = await readFile(join(WIN, name, "run.py"), "utf8").catch(() => "");
      if (text.includes(begin)) found[name] = text.slice(text.indexOf(begin), text.indexOf(end) + end.length);
    }
    for (const name of expect) assert.ok(found[name], `${name} lacks ${begin}`);
    const digests = new Set(Object.values(found).map((b) => createHash("sha256").update(b).digest("hex")));
    assert.equal(digests.size, 1, `${begin} differs between ${Object.keys(found).join(", ")}`);
  }
});
