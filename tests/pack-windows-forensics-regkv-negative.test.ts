/**
 * regkv: a negative the tool established is an answer, and a dirty hive is never plainly complete.
 *
 *   A key that is not in a hive the tool read came back as `ok: false, error: "key not found"` with exit 1, so the job that
 *   established the absence was a failed job and a finding could not cite it. It is `ok: true, found: false`, exit 0, and the
 *   status says what was read: how far the path matched, and whether the lists on the way were read whole.
 *
 *   A dirty hive (the two sequence numbers of the base block differ) whose logs were not beside it was answered `complete`.
 *   regkv replays no log, so every answer from a dirty hive is partial and the basis names the log files it looked for.
 *
 * The hives are the ones tests/windows-hive.ts writes from the regf layout (base block, hbin, nk/vk/li cells) and the
 * stand-in of tests/windows-stub-regipy.ts: each case is read twice, by the stand-in and, where it is installed, by regipy.
 */
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { body, failed, tool } from "./windows-pack-harness.ts";
import { VARIANTS, type Node, type Variant } from "./windows-stub-regipy.ts";

function dual(name: string, fn: (v: Variant) => Promise<void>): void {
  for (const v of VARIANTS) test(`${name} [${v.label}]`, { skip: v.skip }, () => fn(v));
}

type Negative = {
  ok: boolean;
  found: boolean;
  error?: string;
  parser: string;
  hive: string;
  key: string;
  status: string;
  status_basis: string;
  deepest_found: string;
  missing: string;
  path_parts_matched: number;
  path_parts_asked: number;
  subkeys_there: string[];
  subkeys_there_count: number;
  problems: Array<{ where: string; what: string; error: string }>;
  problem_count: number;
  hive_dirty: boolean;
  hive_sequence_numbers: number[];
  transaction_logs_looked_for: string[];
  transaction_logs_beside_hive: string[];
  transaction_logs_replayed: boolean;
};

type Found = { found: boolean; status: string; status_basis: string; values: Record<string, unknown>; hive_dirty: boolean; transaction_logs_looked_for: string[]; transaction_logs_beside_hive: string[] };

const SOFTWARE: Node = {
  name: "ROOT",
  children: [{ name: "Microsoft", children: [{ name: "Windows", children: [{ name: "CurrentVersion", children: [{ name: "Run", values: [{ name: "App", type: "sz", value: "C:\\Tools\\app.exe" }] }] }] }] }],
};

dual("regkv answers a key that is not in a clean hive it read: ok, found false, exit 0, complete, and how far the path matched", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", SOFTWARE);
    const out = body<Negative>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Microsoft\\Windows\\CurrentVersion\\RunOnce\\Setup" }, env));
    assert.equal(out.ok, true);
    assert.equal(out.found, false);
    assert.equal(out.error, undefined, "an absence is not an error");
    assert.equal(out.status, "complete");
    assert.equal(out.hive, "work/SOFTWARE");
    assert.equal(out.key, "Microsoft\\Windows\\CurrentVersion\\RunOnce\\Setup");
    assert.equal(out.deepest_found, "\\Microsoft\\Windows\\CurrentVersion");
    assert.equal(out.missing, "RunOnce");
    assert.deepEqual([out.path_parts_matched, out.path_parts_asked], [3, 5]);
    assert.deepEqual(out.subkeys_there, ["Run"]);
    assert.equal(out.problem_count, 0);
    assert.equal(out.hive_dirty, false);
    assert.match(out.status_basis, /3 of the 5 part\(s\) of the key asked for were matched/);
    assert.match(out.status_basis, /read to its end without a problem, and the hive is not dirty/);
    assert.match(out.parser, /^regkv\/\d+$/);
  });
});

dual("regkv says found: true for a key that is there, and stays complete on a clean hive", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", SOFTWARE);
    const out = body<Found>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Microsoft\\Windows\\CurrentVersion\\Run" }, env));
    assert.equal(out.found, true);
    assert.equal(out.status, "complete");
    assert.equal(out.values.App, "C:\\Tools\\app.exe");
  });
});

dual("regkv does not call a key absent when the list it looked in was not read whole: the negative is partial and names the problem", async (v) => {
  await withCwd(async (cwd) => {
    // The index of Top names its one list twice (an ri element repeated): the names are listed once and the repeat is a problem.
    const root: Node = { name: "ROOT", children: [{ name: "Top", children: [{ name: "Alpha" }, { name: "Beta" }], indexRepeats: 2 }] };
    const env = await v.write(cwd, "work/h.dat", root);
    const out = body<Negative>(await tool("regkv", cwd, { hive: "work/h.dat", key: "Top\\Gamma" }, env));
    assert.equal(out.found, false);
    assert.equal(out.status, "partial");
    assert.equal(out.problem_count, 1);
    assert.match(out.problems[0]!.error, /more than once/);
    assert.match(out.status_basis, /the key is not shown absent: 1 problem\(s\) are named under problems/);
  });
});

dual("regkv keeps a real error a failure: a hive that is not there, a file that is not a hive, arguments that are wrong", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", SOFTWARE);
    const gone = failed(await tool("regkv", cwd, { hive: "work/NOPE", key: "Microsoft" }, env));
    assert.equal(gone.error, "no such hive");
    assert.equal(gone.status, "failed");
    assert.equal(gone.ok, false);
    assert.equal(gone.found, undefined, "a hive that was not read says nothing about a key");
    await writeFile(join(cwd, "work", "notes.txt"), "this is not a registry hive\n".repeat(200));
    const bad = failed(await tool("regkv", cwd, { hive: "work/notes.txt", key: "Microsoft" }, env));
    assert.equal(bad.error, "could not read the hive");
    assert.equal(bad.ok, false);
    assert.equal(failed(await tool("regkv", cwd, { hive: "work/SOFTWARE" }, env)).error, "hive and key are required, both text");
    assert.match(failed(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Microsoft", depth: -1 }, env)).error, /depth must be a whole number/);
  });
});

dual("regkv on a dirty hive with no log beside it is partial, for a key found and for a key missing, and names the logs it looked for", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", SOFTWARE, { primarySeq: 12, secondarySeq: 11 });
    const looked = ["work/SOFTWARE.LOG1", "work/SOFTWARE.LOG2", "work/SOFTWARE.LOG"];
    const out = body<Found>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Microsoft\\Windows\\CurrentVersion\\Run" }, env));
    assert.equal(out.found, true);
    assert.equal(out.hive_dirty, true);
    assert.equal(out.status, "partial", "the logs were not replayed: the value may not be the live registry's");
    assert.deepEqual(out.transaction_logs_looked_for, looked);
    assert.deepEqual(out.transaction_logs_beside_hive, []);
    assert.match(out.status_basis, /the hive is dirty \(its sequence numbers 12 and 11 differ\) and no transaction log was replayed/);
    assert.match(out.status_basis, /looked for \.LOG1, \.LOG2 and \.LOG beside the hive \(transaction_logs_looked_for\) and found none/);
    assert.match(out.status_basis, /may differ from the live registry/);
    assert.equal(out.values.App, "C:\\Tools\\app.exe", "what the hive file holds is still read");

    const miss = body<Negative>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Microsoft\\Windows\\CurrentVersion\\RunOnce" }, env));
    assert.equal(miss.found, false);
    assert.equal(miss.status, "partial", "a key the logs may add is not shown absent");
    assert.deepEqual(miss.transaction_logs_looked_for, looked);
    assert.equal(miss.transaction_logs_replayed, false);
    assert.match(miss.status_basis, /the key is not shown absent: the hive is dirty/);
  });
});

dual("regkv on a dirty hive with its logs beside it is still partial: it replays none, and says how many it found", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", SOFTWARE, { primarySeq: 12, secondarySeq: 11 });
    await mkdir(join(cwd, "work"), { recursive: true });
    await writeFile(join(cwd, "work", "SOFTWARE.LOG1"), Buffer.alloc(512));
    const out = body<Found>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Microsoft" }, env));
    assert.equal(out.status, "partial");
    assert.deepEqual(out.transaction_logs_beside_hive, ["work/SOFTWARE.LOG1"]);
    assert.match(out.status_basis, /found 1 \(transaction_logs_beside_hive\), and it replays none/);
    assert.match(out.status_basis, /registry_recover/);
  });
});
