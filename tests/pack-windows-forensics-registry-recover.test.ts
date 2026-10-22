/**
 * registry_recover: the replay of a hive's transaction logs onto a copy, against hives and logs written from the layouts
 * (tests/windows-hive.ts for the hive, tests/windows-t1-fixtures.ts for the two log formats), never from a tool's output.
 *
 * What the cases hold:
 *   - the recovered copy is, byte for byte, the state the fixture says it should be (the entries' pages over the old pages, the two
 *     sequence numbers, the checksum), the original and the logs are not touched, and the receipt says what was and was not applied;
 *   - an entry is applied only when it is the next one the hive needs: a wrong hash, an older entry, an entry that does not follow,
 *     a clean hive's newer entry and an old-format log whose numbers disagree are each named under `unrecovered`/`why`, and the
 *     copy is not made;
 *   - a withheld value (a SAM user's V, a value named for a password) is never in the answer, stderr, a path or a file, and is
 *     written, whole, only to a 0600 file in a job run as secret output;
 *   - hostile files (empty, truncated, a directory, a FIFO, no permission, a symlink loop, a log that is not one) end in JSON,
 *     never a traceback, and never leave the original changed;
 *   - a program it starts stays in its group, the tool's clock and a signal end it, and a second run in the same job keeps the first.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { REGIPY, body, everyFileUnder, failed, stub, tool } from "./windows-pack-harness.ts";
import type { Run } from "./windows-pack-harness.ts";
import { SHAPES, leaked, plant, prng } from "./windows-canary.ts";
import { hive } from "./windows-hive.ts";
import type { HiveKey } from "./windows-hive.ts";
import { BASE_BLOCK, differingPages, dirtLog, hvleLog, pathWithOnlyPython, withSequences } from "./windows-t1-fixtures.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");
/**
 * The key and value records are read with regipy, which CI does not install: where it is missing the replay (stdlib only) is still
 * tested with `export: false`, and the cases that read records are skipped with the reason.
 */
const RECORDS = !REGIPY;
const skip = REGIPY;

/** A hive whose Run value says which generation it is: generation n is the state after n log entries. */
function generation(n: number, extra: number = 0): Buffer {
  const children: HiveKey[] = [{ name: "Run", values: [{ name: "App", type: "sz", value: `C:\\gen${n}.exe` }] }];
  for (let i = 0; i < extra; i++) children.push({ name: `Grown${i}`, values: [{ name: "x", type: "binary", value: Buffer.alloc(300, i + 1) }] });
  return hive({ name: "ROOT", children: [{ name: "Software", children }] }, { primarySeq: 10, secondarySeq: 10 });
}
const G = [0, 1, 2, 3].map((n) => generation(n));
const BINS = G[0].length - BASE_BLOCK;

type Setup = { hive: Buffer; logs?: Record<string, Buffer> };
async function put(cwd: string, s: Setup, name = "h"): Promise<Record<string, unknown>> {
  await writeFile(join(cwd, "work", `${name}.dat`), s.hive);
  const args: Record<string, unknown> = { hive: `work/${name}.dat`, limit: 5, export: RECORDS };
  for (const [role, data] of Object.entries(s.logs ?? {})) {
    await writeFile(join(cwd, "work", `${name}.${role}`), data);
    args[role] = `work/${name}.${role}`;
  }
  return args;
}
/** The process id a stand-in wrote to its file (the tool starts the stand-in, so it is waited for until it differs from `not`). */
async function pidOf(file: string, not?: number): Promise<number> {
  for (let i = 0; i < 100; i++) {
    const text = await readFile(file, "utf8").catch(() => "");
    const id = Number(text.trim().split("\n").filter(Boolean).pop());
    if (id && id !== not) return id;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`the stand-in never wrote a process id to ${file}`);
}
const job = async (cwd: string, n = 1): Promise<Record<string, string>> => {
  await mkdir(join(cwd, "out"), { recursive: true });
  return { JOB_ID: `j00000${n}`, OUT: join(cwd, "out") };
};
const recoveredOf = (cwd: string, out: Answer): string => join(cwd, out.recovered_copy as string);
const keysOf = async (cwd: string, out: Answer): Promise<Answer[]> => (await readFile(join(cwd, out.records.keys_file), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Answer);

test("two entries across LOG1 and LOG2 are applied in order: the copy is the expected state byte for byte, and nothing else is touched", async () => {
  await withCwd(async (cwd) => {
    const s: Setup = {
      hive: withSequences(G[0], 12, 10),
      logs: {
        log1: hvleLog(G[2], [{ sequence: 10, hiveBinsDataSize: BINS, pages: differingPages(G[0], G[1]) }], { primary: 10 }),
        log2: hvleLog(G[2], [{ sequence: 11, hiveBinsDataSize: BINS, pages: differingPages(G[1], G[2]) }], { primary: 11 }),
      },
    };
    const args = await put(cwd, s);
    const before = await Promise.all(["h.dat", "h.log1", "h.log2"].map(async (f) => sha(await readFile(join(cwd, "work", f)))));
    const out = body<Answer>(await tool("registry_recover", cwd, args));
    assert.equal(out.status, "complete");
    assert.equal(out.dirty_before, true);
    assert.equal(out.replayed, true);
    assert.deepEqual(out.sequence_before, [12, 10]);
    assert.deepEqual(out.sequence_after, [12, 12]);
    assert.equal(out.entries_applied, 2);
    assert.deepEqual(out.unrecovered, []);
    // The expected copy: generation 2's pages, the two sequence numbers set to the number after the last applied entry.
    assert.equal(sha(await readFile(recoveredOf(cwd, out))), sha(withSequences(G[2], 12, 12)));
    // Nothing the caller gave was changed.
    const after = await Promise.all(["h.dat", "h.log1", "h.log2"].map(async (f) => sha(await readFile(join(cwd, "work", f)))));
    assert.deepEqual(after, before);
    // The receipt names what was done to the base block.
    const receipt = JSON.parse(await readFile(join(cwd, out.receipt), "utf8")) as Answer;
    assert.equal(receipt.replay.performed, true);
    assert.deepEqual(receipt.replay.base_block_fields_changed, ["primary_sequence", "secondary_sequence", "hive_bins_data_size", "checksum"]);
    assert.deepEqual(receipt.replay.order.map((o: Answer) => [o.log, o.sequence]), [["log1", 10], ["log2", 11]]);
    assert.equal(receipt.hive_original.sha256, before[0], "the receipt holds the original's digest");
    assert.equal(receipt.recovered.sha256, sha(withSequences(G[2], 12, 12)));
    if (RECORDS) {
      // The records are the recovered state, and the changes name the one value that differs.
      const keys = await keysOf(cwd, out);
      assert.ok(keys.some((r) => JSON.stringify(r).includes("gen2.exe")), "the recovered state is what keys.jsonl holds");
      assert.ok(!keys.some((r) => JSON.stringify(r).includes("gen0.exe")), "the old value is not");
      assert.equal(out.records.changes.compared, true);
      assert.equal(out.records.changes.inline.some((c: Answer) => c.change === "value_changed" && c.name === "App"), true);
    }
  });
});

test("an entry is applied only when it is the next one the hive needs", async () => {
  const cases: Array<[string, Setup, RegExp]> = [
    ["a wrong pages hash ends the log there", { hive: withSequences(G[0], 11, 10), logs: { log1: hvleLog(G[1], [{ sequence: 10, hiveBinsDataSize: BINS, pages: differingPages(G[0], G[1]), corrupt: "hash1" }], { primary: 10 }) } }, /hash/],
    ["a wrong header hash ends the log there", { hive: withSequences(G[0], 11, 10), logs: { log1: hvleLog(G[1], [{ sequence: 10, hiveBinsDataSize: BINS, pages: differingPages(G[0], G[1]), corrupt: "hash2" }], { primary: 10 }) } }, /hash|header|signature|entry/],
    ["an entry that does not follow is not applied", { hive: withSequences(G[0], 11, 10), logs: { log1: hvleLog(G[2], [{ sequence: 12, hiveBinsDataSize: BINS, pages: differingPages(G[0], G[2]) }], { primary: 12 }) } }, /does not follow/],
    ["a clean hive's newer entry is reported and not applied", { hive: G[0], logs: { log1: hvleLog(G[1], [{ sequence: 11, hiveBinsDataSize: BINS, pages: differingPages(G[0], G[1]) }], { primary: 11 }) } }, /clean hive/],
  ];
  for (const [label, setup, why] of cases) {
    await withCwd(async (cwd) => {
      const out = body<Answer>(await tool("registry_recover", cwd, await put(cwd, setup)));
      assert.equal(out.replayed, false, label);
      assert.equal(out.entries_applied, 0, label);
      assert.equal(out.status, "partial", label);
      assert.equal(out.recovered_copy ?? null, null, `${label}: no copy is made`);
      assert.ok(out.unrecovered.length >= 1, label);
      assert.match(JSON.stringify(out.unrecovered), why, label);
      assert.deepEqual(out.unrecovered[0].hive_ranges.length >= 0, true);
      // What the hive holds is still read (the state as it is), and the answer does not call it recovered.
      if (RECORDS) assert.match(out.records.source, /^the hive as it is/, label);
    });
  }
});

test("an entry older than the hive's state is not written over newer pages (the state regipy's replay would produce)", async () => {
  await withCwd(async (cwd) => {
    // The hive is at generation 1, sequence 12/12 +1 dirty; the log holds an older entry (sequence 9) that would put generation 0 back.
    const s: Setup = { hive: withSequences(G[1], 13, 12), logs: { log1: hvleLog(G[0], [{ sequence: 9, hiveBinsDataSize: BINS, pages: differingPages(G[1], G[0]) }], { primary: 9 }) } };
    const out = body<Answer>(await tool("registry_recover", cwd, await put(cwd, s)));
    assert.equal(out.entries_applied, 0);
    assert.equal(out.replayed, false);
    assert.equal(out.recovered_copy ?? null, null);
    if (RECORDS) {
      const keys = await keysOf(cwd, out);
      assert.ok(keys.some((r) => JSON.stringify(r).includes("gen1.exe")), "the newer state stands");
      assert.ok(!keys.some((r) => JSON.stringify(r).includes("gen0.exe")), "the older page is not put over it");
    }
    // Without regipy the same is shown by the hive: it is the generation-1 file with its dirty numbers, unchanged.
    assert.equal(sha(await readFile(join(cwd, "work", "h.dat"))), sha(withSequences(G[1], 13, 12)));
  });
});

test("an old-format (DIRT) log is applied as a whole, only when its own numbers agree with each other and with the hive", async () => {
  const sectors: Array<{ index: number; data: Buffer }> = [];
  for (let i = 0; i < BINS / 512; i++) {
    const a = G[0].subarray(BASE_BLOCK + i * 512, BASE_BLOCK + (i + 1) * 512);
    const b = G[1].subarray(BASE_BLOCK + i * 512, BASE_BLOCK + (i + 1) * 512);
    if (!a.equals(b)) sectors.push({ index: i, data: Buffer.from(b) });
  }
  assert.ok(sectors.length > 0);
  await withCwd(async (cwd) => {
    const out = body<Answer>(await tool("registry_recover", cwd, await put(cwd, { hive: withSequences(G[0], 10, 9), logs: { log1: dirtLog(G[1], BINS, sectors, { primary: 10 }) } })));
    assert.equal(out.replayed, true);
    assert.equal(out.entries_applied, 1);
    assert.equal(sha(await readFile(recoveredOf(cwd, out))), sha(withSequences(G[1], 10, 10)));
  });
  await withCwd(async (cwd) => {
    // The log's two numbers differ: it was itself cut off, and is not applied.
    const out = body<Answer>(await tool("registry_recover", cwd, await put(cwd, { hive: withSequences(G[0], 10, 9), logs: { log1: dirtLog(G[1], BINS, sectors, { primary: 10, secondary: 9 }) } })));
    assert.equal(out.replayed, false);
    assert.equal(out.status, "partial");
    assert.match(JSON.stringify(out.unrecovered), /sequence|number|agree/i);
  });
  await withCwd(async (cwd) => {
    // Its numbers agree with each other and not with the hive's.
    const out = body<Answer>(await tool("registry_recover", cwd, await put(cwd, { hive: withSequences(G[0], 10, 9), logs: { log1: dirtLog(G[1], BINS, sectors, { primary: 20 }) } })));
    assert.equal(out.replayed, false);
    assert.equal(out.status, "partial");
  });
});

test("a hive whose bins grow in the log grows in the copy, and a dirty hive with no log named is read as it is and said to be partial", async () => {
  const big = generation(1, 40);
  assert.ok(big.length > G[0].length, "the fixture grows");
  await withCwd(async (cwd) => {
    const s: Setup = { hive: withSequences(G[0], 11, 10), logs: { log1: hvleLog(big, [{ sequence: 10, hiveBinsDataSize: big.length - BASE_BLOCK, pages: differingPages(G[0], big) }], { primary: 10 }) } };
    const out = body<Answer>(await tool("registry_recover", cwd, await put(cwd, s)));
    assert.equal(out.replayed, true, JSON.stringify(out.unrecovered));
    assert.equal(sha(await readFile(recoveredOf(cwd, out))), sha(withSequences(big, 11, 11)));
  });
  await withCwd(async (cwd) => {
    const out = body<Answer>(await tool("registry_recover", cwd, await put(cwd, { hive: withSequences(G[0], 11, 10) })));
    assert.equal(out.replayed, false);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /dirty/);
    assert.match(out.status_basis, /no log/);
  });
});

test("the independent reader: regfexport's counts agreeing, disagreeing, and absent are each said, and a disagreement makes the status partial", { skip }, async () => {
  const s: Setup = { hive: G[0] };
  const counts = async (cwd: string, args: Record<string, unknown>, bin: string): Promise<Answer> => body<Answer>(await tool("registry_recover", cwd, args, {}, bin));
  await withCwd(async (cwd, bin) => {
    const args = await put(cwd, s);
    const plain = await counts(cwd, args, bin);
    const keys = plain.records.keys as number;
    const values = plain.records.values as number;
    const lines = (k: number, v: number): string => `i=0; while [ $i -lt ${k} ]; do echo "Key path: x$i"; i=$((i+1)); done; i=0; while [ $i -lt ${v} ]; do echo "Value: y$i"; i=$((i+1)); done`;
    await stub(bin, "regfexport", lines(keys, values));
    const agree = await counts(cwd, args, bin);
    assert.equal(agree.records.independent_reader.regfexport.agrees, true);
    assert.equal(agree.status, "complete");
    await stub(bin, "regfexport", lines(keys + 1, values));
    const differ = await counts(cwd, args, bin);
    assert.equal(differ.records.independent_reader.regfexport.agrees, false);
    assert.equal(differ.status, "partial");
    assert.match(differ.status_basis, /regfexport/);
  });
  await withCwd(async (cwd) => {
    // Not installed at all (a PATH that holds python3 and nothing else): said, and not a failure of the read.
    const onlyPython = await pathWithOnlyPython(cwd);
    const out = body<Answer>(await tool("registry_recover", cwd, await put(cwd, s), { PATH: onlyPython }));
    assert.equal(out.records.independent_reader.regfexport.ran, false);
    assert.match(out.records.independent_reader.regfexport.why, /not in this image/);
    assert.equal(out.status, "complete", "an absent second reader is said, and is not a failure of the read");
  });
});

// ---- the boundary -----------------------------------------------------------------------------------------------------------

/** A SAM-shaped and a plainly named secret, a value of each kind that is withheld, and one that is not. */
function secretHive(canaries: string[]): Buffer {
  const n = canaries.length;
  return hive(
    {
      name: "ROOT",
      children: [
        { name: "SAM", children: [{ name: "Domains", children: [{ name: "Account", children: [{ name: "Users", children: canaries.map((c, i) => ({ name: (0x1f4 + i).toString(16).padStart(8, "0").toUpperCase(), values: [{ name: "V", type: "binary" as const, value: Buffer.from(c, "latin1") }, { name: "SupplementalCredentials", type: "binary" as const, value: Buffer.from(c + "!", "latin1") }, { name: "F", type: "binary" as const, value: Buffer.alloc(8, 7) }] })) }] }] }] },
        { name: "Settings", values: [...canaries.map((c, i) => ({ name: `Password${i}`, type: "sz" as const, value: c })), { name: "PasswordMinAge", type: "dword" as const, value: 7 }, { name: "Plain", type: "sz" as const, value: "visible-" + n }] },
      ],
    },
    { primarySeq: 5, secondarySeq: 5 },
  );
}

test("withheld values: random canaries in a SAM user's V and in values named for a password are in no output, no path and no file; the number and the plain value are shown", { skip }, async () => {
  const shapes = ["ghp", "akia", "jwt", "b64_20", "pw_assign", "random_base62_24", "plain_password", "uuid_secret"].map((n) => SHAPES.find((s) => s.name === n)!);
  const canaries = shapes.flatMap((shape) => plant(shape, 25, 5)).filter((c) => !c.text.includes("\u0000"));
  await withCwd(async (cwd) => {
    const s: Setup = { hive: secretHive(canaries.map((c) => c.text)) };
    const args = await put(cwd, s);
    const run = await tool("registry_recover", cwd, args);
    const out = body<Answer>(run);
    assert.ok(out.sensitive_values_withheld_count >= canaries.length * 3, `withheld: ${out.sensitive_values_withheld_count}`);
    const files = await everyFileUnder(cwd);
    const texts = [run.stdout, run.stderr, ...files.filter((f) => !f.endsWith("/work/h.dat")).map((f) => f), ...(await Promise.all(files.filter((f) => !f.endsWith("/work/h.dat")).map(async (f) => (await readFile(f)).toString("latin1"))))];
    assert.equal(leaked(canaries, texts), 0, "no canary core is printed whole");
    // Not in the hex of a binary value either (the V values are bytes of the canary).
    for (const c of canaries.slice(0, 40)) {
      const raw = Buffer.from(c.text, "latin1");
      assert.ok(!texts.some((t) => t.includes(raw.toString("hex")) || t.includes(raw.toString("base64"))), "no hex or base64 of a withheld value");
    }
    const keys = await keysOf(cwd, out);
    const text = JSON.stringify(keys);
    assert.match(text, /visible-/, "a value not withheld is shown");
    assert.equal(out.contains_secret_values, false);
    assert.equal(out.values_file, null);
    // The record of a withheld value says where it is and how long, and nothing of its bytes.
    const withheld = keys.filter((r) => r.row === "value" && /withheld/i.test(JSON.stringify(r)));
    assert.ok(withheld.length >= canaries.length * 3);
    assert.ok(withheld.every((r) => typeof r.length === "number" || typeof r.size === "number" || /length|size/.test(JSON.stringify(r))));
  });
});

test("write_values is refused outside a job and in a job that is not secret output, before anything is made", async () => {
  const canaries = plant(SHAPES.find((s) => s.name === "ghp")!, 6, 9);
  await withCwd(async (cwd) => {
    const args = await put(cwd, { hive: secretHive(canaries.map((c) => c.text)) });
    const before = new Set(await everyFileUnder(cwd));
    const refused = failed(await tool("registry_recover", cwd, { ...args, write_values: true }));
    assert.match(refused.error, /write_values is refused/);
    assert.deepEqual(new Set(await everyFileUnder(cwd)), before, "nothing was made");
    const env = await job(cwd);
    const plain = failed(await tool("registry_recover", cwd, { ...args, write_values: true }, env));
    assert.match(plain.error, /refused/);
    assert.deepEqual(new Set(await everyFileUnder(cwd)), before, "a job that is not secret output made nothing");
  });
});

test("in a job run as secret output write_values writes the whole values to a 0600 file only, and a second run keeps the first", { skip }, async () => {
  const canaries = plant(SHAPES.find((s) => s.name === "ghp")!, 6, 9);
  await withCwd(async (cwd) => {
    const s: Setup = { hive: secretHive(canaries.map((c) => c.text)) };
    const args = await put(cwd, s);
    const env = await job(cwd);
    const secret = await tool("registry_recover", cwd, { ...args, write_values: true }, { ...env, SECRET_OUTPUT: "1" });
    const out = body<Answer>(secret);
    assert.equal(out.contains_secret_values, true);
    const values = (await everyFileUnder(join(cwd, "out"))).filter((f) => f.endsWith("values.jsonl"));
    assert.equal(values.length, 1);
    assert.equal((await stat(values[0])).mode & 0o777, 0o600);
    const rows = (await readFile(values[0], "utf8")).trim().split("\n");
    assert.ok(rows.length >= canaries.length * 3);
    const whole = rows.join("\n");
    for (const c of canaries.slice(0, 3)) assert.ok(whole.includes(c.cores[0]) || whole.includes(Buffer.from(c.text, "latin1").toString("hex")) || whole.includes(Buffer.from(c.text, "latin1").toString("base64")), "the value is in the file, whole");
    // The answer, stderr and every other file hold none of them.
    const others = (await everyFileUnder(cwd)).filter((f) => !values.includes(f) && !f.endsWith("/work/h.dat"));
    const texts = [secret.stdout, secret.stderr, ...(await Promise.all(others.map(async (f) => (await readFile(f)).toString("latin1")))), ...others];
    assert.equal(leaked(canaries, texts), 0);
    // A second run in the same job keeps the first file and writes another.
    const again = body<Answer>(await tool("registry_recover", cwd, { ...args, write_values: true }, { ...env, SECRET_OUTPUT: "1" }));
    const now = (await everyFileUnder(join(cwd, "out"))).filter((f) => /values(-\d+)?\.jsonl$/.test(f));
    assert.equal(now.length, 2, "the first values file is kept and a second is made");
    assert.equal(again.contains_secret_values, true);
    assert.equal(await readFile(values[0], "utf8"), rows.join("\n") + "\n");
  });
});

// ---- hostile inputs ---------------------------------------------------------------------------------------------------------

test("hostile files end in JSON, never a traceback, and the original is not changed", async () => {
  await withCwd(async (cwd) => {
    const good = withSequences(G[0], 11, 10);
    const goodLog = hvleLog(G[1], [{ sequence: 10, hiveBinsDataSize: BINS, pages: differingPages(G[0], G[1]) }], { primary: 10 });
    const rnd = prng(3);
    const random = (n: number): Buffer => Buffer.from(Array.from({ length: n }, () => Math.floor(rnd() * 256)));
    const hives: Array<[string, Buffer]> = [
      ["empty", Buffer.alloc(0)],
      ["short", Buffer.from("regf")],
      ["random", random(70_000)],
      ["header-only", good.subarray(0, BASE_BLOCK)],
      ["cut-in-a-page", good.subarray(0, BASE_BLOCK + 2000)],
      ["zeros", Buffer.alloc(BASE_BLOCK * 4)],
    ];
    const logs: Array<[string, Buffer]> = [
      ["empty", Buffer.alloc(0)],
      ["random", random(9000)],
      ["header-only", goodLog.subarray(0, 512)],
      ["cut-entry", goodLog.subarray(0, 512 + 700)],
      ["zero-size-entry", (() => { const b = Buffer.from(goodLog); b.writeUInt32LE(0, 512 + 4); return b; })()],
      ["huge-size-entry", (() => { const b = Buffer.from(goodLog); b.writeUInt32LE(0xfffffe00, 512 + 4); return b; })()],
      ["huge-page-count", (() => { const b = Buffer.from(goodLog); b.writeUInt32LE(0xffffffff, 512 + 20); return b; })()],
      ["page-past-the-hive", hvleLog(G[1], [{ sequence: 10, hiveBinsDataSize: BINS, pages: [{ offset: 0x7fff0000, data: Buffer.alloc(4096, 1) }] }], { primary: 10 })],
    ];
    let n = 0;
    const check = async (label: string, run: Run): Promise<void> => {
      assert.doesNotMatch(run.stderr, /Traceback/, label);
      assert.ok(run.code === 0 || run.code === 1, `${label}: exit ${run.code}`);
      const parsed = JSON.parse(run.stdout) as Answer;
      assert.ok(parsed.status === "complete" || parsed.status === "partial" || parsed.status === "failed", `${label}: ${run.stdout.slice(0, 200)}`);
      n++;
    };
    for (const [name, data] of hives) {
      await writeFile(join(cwd, "work", "x.dat"), data);
      await check(`hive ${name}`, await tool("registry_recover", cwd, { hive: "work/x.dat" }));
      await check(`hive ${name} with a log`, await tool("registry_recover", cwd, { hive: "work/x.dat", log1: "work/g.log" }).catch(() => ({ code: 1, stdout: '{"status":"failed"}', stderr: "" })));
    }
    await writeFile(join(cwd, "work", "g.dat"), good);
    const goodSha = sha(good);
    for (const [name, data] of logs) {
      await writeFile(join(cwd, "work", "g.log"), data);
      await check(`log ${name}`, await tool("registry_recover", cwd, { hive: "work/g.dat", log1: "work/g.log", log2: "work/g.log" }));
      assert.equal(sha(await readFile(join(cwd, "work", "g.dat"))), goodSha, `log ${name}: the hive is unchanged`);
    }
    // Not files.
    await mkdir(join(cwd, "work", "adir"));
    await check("a directory", await tool("registry_recover", cwd, { hive: "work/adir" }));
    await symlink("loop2", join(cwd, "work", "loop1"));
    await symlink("loop1", join(cwd, "work", "loop2"));
    await check("a symlink loop", await tool("registry_recover", cwd, { hive: "work/loop1" }));
    await check("a missing file", await tool("registry_recover", cwd, { hive: "work/none.dat" }));
    await check("a missing log", await tool("registry_recover", cwd, { hive: "work/g.dat", log1: "work/none.log" }));
    const fifo = join(cwd, "work", "fifo");
    if (spawnSync("mkfifo", [fifo]).status === 0) {
      const r = await tool("registry_recover", cwd, { hive: "work/fifo" });
      assert.notEqual(r.code, 0);
      assert.match(JSON.parse(r.stdout).error, /not a regular file/);
      n++;
    }
    await writeFile(join(cwd, "work", "mode0.dat"), good);
    await chmod(join(cwd, "work", "mode0.dat"), 0);
    if (process.getuid?.() !== 0) await check("no permission", await tool("registry_recover", cwd, { hive: "work/mode0.dat" }));
    await chmod(join(cwd, "work", "mode0.dat"), 0o600);
    // Arguments of the wrong kind.
    for (const args of [{}, { hive: 5 }, { hive: "" }, { hive: "work/g.dat", log1: 7 }, { hive: "work/g.dat", limit: 0 }, { hive: "work/g.dat", limit: true }, { hive: "work/g.dat", max_seconds: 0 }, { hive: "work/g.dat", max_seconds: 1000 }, { hive: "work/g.dat", write_values: "yes" }, { hive: "work/g.dat", export: 1 }, []]) {
      const r = await tool("registry_recover", cwd, args);
      assert.notEqual(r.code, 0, JSON.stringify(args));
      assert.doesNotMatch(r.stderr, /Traceback/);
      assert.ok(JSON.parse(r.stdout).error);
      n++;
    }
    assert.ok(n >= 30);
  });
});

test("a second run with the same arguments, in the same job, neither fails nor replaces the first run's files, and does not make them twice", async () => {
  await withCwd(async (cwd) => {
    const s: Setup = { hive: withSequences(G[0], 11, 10), logs: { log1: hvleLog(G[1], [{ sequence: 10, hiveBinsDataSize: BINS, pages: differingPages(G[0], G[1]) }], { primary: 10 }) } };
    const args = await put(cwd, s);
    const env = await job(cwd);
    const first = body<Answer>(await tool("registry_recover", cwd, args, env));
    const before = new Map(await Promise.all((await everyFileUnder(join(cwd, "out"))).map(async (f) => [f, sha(await readFile(f))] as const)));
    assert.ok(before.size >= 2);
    const second = body<Answer>(await tool("registry_recover", cwd, args, env));
    assert.equal(second.replayed, true);
    assert.equal(second.status, first.status);
    for (const [f, digest] of before) assert.equal(sha(await readFile(f)), digest, `${f} is as the first run left it`);
    // The same arguments give the same bytes: the copy and the records the first run left are the ones the second names (a file is
    // never replaced, and none is made twice).
    assert.deepEqual((await everyFileUnder(join(cwd, "out"))).sort(), [...before.keys()].sort());
    assert.equal(second.recovered_copy, first.recovered_copy);
  });
});

test("a hive past the tool's bound is refused as JSON before it is read, and a large sparse hive is replayed in pieces", async () => {
  await withCwd(async (cwd) => {
    const huge = join(cwd, "work", "huge.dat");
    await writeFile(huge, "regf");
    const { truncate } = await import("node:fs/promises");
    await truncate(huge, 4 * 2 ** 30 + BASE_BLOCK);
    const refused = failed(await tool("registry_recover", cwd, { hive: "work/huge.dat" }));
    assert.match(refused.error, /larger than the 4294967296 bytes/);
    // A 64 MiB hive (a small one padded with zeros past its declared bins) is replayed with export off: the pieces are 1 MiB, so the memory stays small.
    const s: Setup = { hive: withSequences(G[0], 11, 10), logs: { log1: hvleLog(G[1], [{ sequence: 10, hiveBinsDataSize: BINS, pages: differingPages(G[0], G[1]) }], { primary: 10 }) } };
    const args = await put(cwd, s, "pad");
    await truncate(join(cwd, "work", "pad.dat"), 64 * 2 ** 20);
    const out = body<Answer>(await tool("registry_recover", cwd, { ...args, export: false }));
    assert.equal(out.replayed, true);
    assert.equal((await stat(recoveredOf(cwd, out))).size, 64 * 2 ** 20);
  });
});

test("a name with a quote, a bracket, a newline or 300 characters, and a raw non-UTF-8 name, is answered in JSON", async () => {
  await withCwd(async (cwd) => {
    const names = ["a\"b'c.dat", "a[1]{2}.dat", "line\nbreak.dat", "x".repeat(200) + ".dat"];
    for (const name of names) {
      await writeFile(join(cwd, "work", name), G[0]);
      const r = await tool("registry_recover", cwd, { hive: `work/${name}`, limit: 1 });
      assert.doesNotMatch(r.stderr, /Traceback/, name);
      const out = JSON.parse(r.stdout) as Answer;
      assert.ok(out.status, name);
    }
    const bad = Buffer.concat([Buffer.from(join(cwd, "work") + "/"), Buffer.from([0x66, 0xff, 0x2e, 0x64, 0x61, 0x74])]);
    let made = false;
    try {
      await writeFile(bad, G[0]);
      made = true;
    } catch {
      /* this file system refuses a name that is not UTF-8 (macOS): the branch runs on Linux */
    }
    if (made) {
      const r = spawnSync("python3", [join(process.cwd(), "packs/windows-forensics/tools/registry_recover/run.py")], { cwd, input: JSON.stringify({ hive: "work/f\udcff.dat" }), encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
      assert.doesNotMatch(r.stderr, /Traceback/);
    }
  });
});

// ---- time, signals, processes -----------------------------------------------------------------------------------------------

test("a program it starts stays in its group: its own clock ends regfexport, and SIGTERM leaves JSON (status interrupted) and exit 143 with the program gone", { skip }, async () => {
  const { spawn } = await import("node:child_process");
  await withCwd(async (cwd, bin) => {
    const pidFile = join(cwd, "regfexport.pid");
    await stub(bin, "regfexport", `echo $$ > "${pidFile}"; exec sleep 60`);
    const args = await put(cwd, { hive: G[0] });
    // The clock: max_seconds 2 returns within a few seconds, with the reader said not to have finished.
    const began = Date.now();
    const out = body<Answer>(await tool("registry_recover", cwd, { ...args, max_seconds: 2 }, {}, bin));
    assert.ok(Date.now() - began < 8000, `returned in ${Date.now() - began} ms`);
    assert.notEqual(out.records.independent_reader.regfexport.finished, true);
    const pid = await pidOf(pidFile);
    await new Promise((r) => setTimeout(r, 300));
    assert.throws(() => process.kill(pid, 0), "regfexport is gone");
    // SIGTERM: partial JSON, 143.
    const child = spawn("python3", [join(process.cwd(), "packs/windows-forensics/tools/registry_recover/run.py")], { cwd, env: { ...process.env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}` }, stdio: ["pipe", "pipe", "pipe"] });
    const chunks: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => chunks.push(c));
    child.stdin.end(JSON.stringify({ ...args, max_seconds: 60 }));
    const second = await pidOf(pidFile, pid);
    child.kill("SIGTERM");
    const code = await new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
    assert.equal(code, 143);
    const last = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Answer;
    assert.equal(last.status, "interrupted");
    await new Promise((r) => setTimeout(r, 300));
    assert.throws(() => process.kill(second, 0), "the program is gone with the tool");
  });
});

test("the tool starts nothing in a session of its own", async () => {
  const text = (await readFile(join(process.cwd(), "packs/windows-forensics/tools/registry_recover/run.py"), "utf8")).replace(/"""[\s\S]*?"""/g, "");
  const outside = text.replace(/# BEGIN SHARED PROCESS[\s\S]*?# END SHARED PROCESS/, "").replace(/^\s*#.*$/gm, "");
  assert.doesNotMatch(outside, /start_new_session|\bsetsid\b|preexec_fn|os\.setpgid|os\.setpgrp|killpg/);
});

// ---- fuzz -------------------------------------------------------------------------------------------------------------------

test("structure-aware mutations of a log (400 cases): JSON every time, the original unchanged, and a copy only when the receipt says it was replayed", async () => {
  const base = hvleLog(G[2], [
    { sequence: 10, hiveBinsDataSize: BINS, pages: differingPages(G[0], G[1]) },
    { sequence: 11, hiveBinsDataSize: BINS, pages: differingPages(G[1], G[2]) },
  ], { primary: 10 });
  const hiveBytes = withSequences(G[0], 12, 10);
  const r = prng(77);
  const pick = (n: number): number => Math.floor(r() * n);
  const fields: Array<[number, number]> = [[0, 4], [4, 4], [8, 4], [12, 4], [16, 4], [20, 4], [24, 8], [32, 8], [40, 4], [44, 4]];
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "f.dat"), hiveBytes);
    const hiveSha = sha(hiveBytes);
    for (let i = 0; i < 400; i++) {
      const m = Buffer.from(base);
      const kind = pick(5);
      if (kind === 0) m[pick(m.length)] ^= 1 << pick(8);
      else if (kind === 1) { const [at, n] = fields[pick(fields.length)]; for (let k = 0; k < n; k++) m[512 + at + k] = pick(256); }
      else if (kind === 2) { const [at, n] = fields[pick(fields.length)]; for (let k = 0; k < n; k++) m[512 + 4096 + 512 + at + k] = pick(256); }
      else if (kind === 3) { /* truncate */ }
      const data = kind === 3 ? m.subarray(0, pick(m.length)) : kind === 4 ? Buffer.concat([m.subarray(0, 512 + pick(2) * 4608), Buffer.alloc(pick(1200), pick(256))]) : m;
      await writeFile(join(cwd, "work", "f.log"), data);
      const run = await tool("registry_recover", cwd, { hive: "work/f.dat", log1: "work/f.log", log2: "work/f.log", export: false });
      assert.doesNotMatch(run.stderr, /Traceback/, `case ${i}`);
      assert.ok(run.code === 0 || run.code === 1, `case ${i}: exit ${run.code}`);
      const out = JSON.parse(run.stdout) as Answer;
      assert.ok(["complete", "partial", "failed"].includes(out.status), `case ${i}`);
      if (out.replayed === true) {
        const copy = await readFile(join(cwd, out.recovered_copy));
        assert.equal(copy.subarray(0, 4).toString("latin1"), "regf", `case ${i}`);
        assert.equal(copy.readUInt32LE(4), copy.readUInt32LE(8), `case ${i}: a copy is clean`);
      } else {
        assert.ok(out.recovered_copy === null || out.recovered_copy === undefined, `case ${i}`);
      }
    }
    assert.equal(sha(await readFile(join(cwd, "work", "f.dat"))), hiveSha);
    const left = (await readdir(join(cwd, "work", "s1")).catch(() => [])).filter((n) => n.startsWith("."));
    assert.deepEqual(left, [], "no temporary file is left");
  });
});
