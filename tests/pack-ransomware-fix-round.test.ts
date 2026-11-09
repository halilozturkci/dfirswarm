/**
 * ransomware-response, fix round for the three new tools: a line that never ends is read under the clock; byte sums that would overflow the
 * index are capped and said so; the timeline index keeps a bounded number of distinct kinds; an unread counterpart or ciphertext makes the
 * answer partial; time_limit.reached is true when the clock ended a file; a zip that declares data in no bytes is a possible bomb.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { buildZip } from "./pack-re-harness.ts";
import { withCwd } from "./tool-library-harness.ts";
import { PACK, tool } from "./ransomware-pack-harness.ts";

const REPORT = join(PACK, "ransomware_scope_report", "run.py");
const EXTENT = join(PACK, "encryption_extent", "run.py");
const VALIDATE = join(PACK, "recovery_validate", "run.py");

type J = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
async function run(script: string, cwd: string, args: unknown): Promise<J> {
  const out = await tool(script, cwd, args);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as J;
}
async function put(cwd: string, name: string, data: Buffer | string): Promise<string> {
  await mkdir(join(cwd, "work"), { recursive: true });
  await writeFile(join(cwd, "work", name), data);
  return `work/${name}`;
}

const SLOW = String.raw`
import os, runpy, sys, time
_real = os.pread
def slow(fd, n, off):
    time.sleep(0.05)
    return _real(fd, n, off)
os.pread = slow
script = sys.argv[1]
sys.argv = [script]
runpy.run_path(script, run_name="__main__")
`;
function runSlow(cwd: string, script: string, args: unknown): Promise<J> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", SLOW, script], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.on("error", reject);
    child.on("close", () => resolve(JSON.parse(Buffer.concat(out).toString()) as J));
    child.stdin.end(JSON.stringify(args));
  });
}

for (const kind of ["censuses", "timelines"] as const) {
  test(`ransomware_scope_report: a ${kind} input that is a huge sparse file with no newline ends at max_seconds, not when the file does`, async () => {
    await withCwd(async (cwd) => {
      await mkdir(join(cwd, "work"), { recursive: true });
      const big = join(cwd, "work", "nonl.jsonl");
      await writeFile(big, "");
      try {
        await truncate(big, 300 * 1000 ** 3);
      } catch {
        return;
      }
      const began = Date.now();
      const answer = await run(REPORT, cwd, { [kind]: [{ host: "h", file: "work/nonl.jsonl" }], max_seconds: 3 });
      assert.ok((Date.now() - began) / 1000 < 20, `took ${(Date.now() - began) / 1000} s`);
      assert.equal(answer.status, "partial");
      assert.equal(answer.time_limit.reached, true);
      assert.ok(answer.partial_reasons.some((r: string) => /time limit/.test(r)));
    });
  });
}

test("encryption_extent: a census that is a huge sparse file with no newline ends at max_seconds", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work"), { recursive: true });
    const big = join(cwd, "work", "nonl.jsonl");
    await writeFile(big, "");
    try {
      await truncate(big, 300 * 1000 ** 3);
    } catch {
      return;
    }
    const began = Date.now();
    const answer = await run(EXTENT, cwd, { policy: "full", census: "work/nonl.jsonl", max_seconds: 3 });
    assert.ok((Date.now() - began) / 1000 < 20);
    assert.equal(answer.status, "partial");
    assert.equal(answer.time_limit.reached, true);
  });
});

test("ransomware_scope_report: byte sums past the cap are held at the cap and the answer says so, with no overflow", async () => {
  await withCwd(async (cwd) => {
    const rows = Array.from({ length: 12 }, () => JSON.stringify({ record: "file", file: "x", bytes: 2 ** 61, status: "candidate" })).join("\n");
    await put(cwd, "c.jsonl", rows + "\n" + JSON.stringify({ record: "receipt", parser: "encrypted_survey/3", status: "complete" }) + "\n");
    await put(cwd, "e.jsonl", Array.from({ length: 12 }, () => JSON.stringify({ record: "file", bytes: 2 ** 61, bytes_inspected: 2 ** 61, status: "inspected", high_entropy_runs: 1 })).join("\n") + "\n" + JSON.stringify({ record: "receipt", parser: "encryption_extent/1", status: "complete" }) + "\n");
    const answer = await run(REPORT, cwd, { censuses: [{ host: "h", file: "work/c.jsonl" }], extents: [{ host: "h", file: "work/e.jsonl" }] });
    assert.notEqual(answer.status, "failed", JSON.stringify(answer).slice(0, 300));
    assert.equal(answer.status, "partial");
    assert.ok(answer.partial_reasons.some((r: string) => /reached the cap of 2\^50 \(1 PiB\)/.test(r)));
    assert.equal(answer.hosts[0].denominators.bytes, 1125899906842624);
    assert.equal(answer.sum_cap.bytes_and_runs_per_key, 1125899906842624);
  });
});

test("ransomware_scope_report: distinct timeline kinds are bounded, the events of later kinds are counted under one kind, and the answer says so", async () => {
  await withCwd(async (cwd) => {
    const lines: string[] = [];
    for (let i = 0; i < 100500; i++) lines.push(JSON.stringify({ host: "h", time: "2026-10-01T10:00:00Z", kind: `k${i}` }));
    await put(cwd, "t.jsonl", lines.join("\n") + "\n");
    const answer = await run(REPORT, cwd, { timelines: [{ file: "work/t.jsonl" }], limit: 5 });
    assert.equal(answer.status, "partial");
    assert.ok(answer.partial_reasons.some((r: string) => /500 timeline events had a kind past the first 100000/.test(r)));
    assert.equal(answer.hosts[0].timeline.kinds, 100001);
    assert.equal(answer.hosts[0].timeline.events, 100500);
  });
});

test("encryption_extent: a counterpart that is missing, a pipe or of another size makes the answer partial and is named", async () => {
  await withCwd(async (cwd) => {
    const f = await put(cwd, "a.bin", randomBytes(8192));
    const short = await put(cwd, "short.bin", randomBytes(100));
    const ok = await run(EXTENT, cwd, { policy: "full", files: [{ path: f, counterpart: f }] });
    assert.equal(ok.status, "complete", ok.status_basis);
    for (const [label, counterpart, reason] of [["missing", "work/none.bin", "read_failed"], ["another size", short, "size_differs"]] as const) {
      const a = await run(EXTENT, cwd, { policy: "full", files: [{ path: f, counterpart }] });
      assert.equal(a.status, "partial", label);
      assert.match(a.status_basis, new RegExp(`1 counterparts could not be compared \\(${reason} 1\\)`), label);
    }
  });
});

test("recovery_validate: a ciphertext that is missing or of another size makes the answer partial and is named", async () => {
  await withCwd(async (cwd) => {
    const f = await put(cwd, "r.bin", randomBytes(8192));
    const short = await put(cwd, "c.bin", randomBytes(100));
    for (const [label, ciphertext, reason] of [["missing", "work/none.bin", "read_failed"], ["another size", short, "size_differs"]] as const) {
      const a = await run(VALIDATE, cwd, { items: [{ recovered: f, ciphertext }] });
      assert.equal(a.status, "partial", label);
      assert.match(a.status_basis, new RegExp(`1 ciphertexts could not be compared \\(${reason} 1\\)`), label);
    }
  });
});

test("time_limit.reached is true when the clock ended a file, in encryption_extent and in recovery_validate", async () => {
  await withCwd(async (cwd) => {
    const f = await put(cwd, "big.bin", randomBytes(4096 * 400));
    const a = await runSlow(cwd, EXTENT, { policy: "full", files: [f], max_seconds: 1 });
    assert.equal(a.status, "partial");
    assert.equal(a.files[0].reason, "time_limit");
    assert.equal(a.time_limit.reached, true);
    const big = await put(cwd, "big2.bin", randomBytes(40 << 20));
    const b = await runSlow(cwd, VALIDATE, { items: [big], max_seconds: 1 });
    assert.equal(b.status, "partial");
    assert.equal(b.items[0].reason, "time_limit");
    assert.equal(b.time_limit.reached, true);
  });
});

test("recovery_validate: a zip that declares data in no compressed bytes is a possible zip bomb", async () => {
  await withCwd(async (cwd) => {
    const z = buildZip([{ name: "a", data: Buffer.alloc(1000), method: 0, compressed: Buffer.alloc(0) }]);
    await put(cwd, "z.zip", z);
    const a = await run(VALIDATE, cwd, { items: ["work/z.zip"] });
    assert.equal(a.items[0].format_check.declared_compressed_bytes, 0);
    assert.equal(a.items[0].format_check.possible_zip_bomb, true);
  });
});
