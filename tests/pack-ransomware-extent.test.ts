/**
 * ransomware-response: encryption_extent. Files of known entropy structure (zero, text, random, zip, gzip, random blocks at known offsets,
 * an intermittent 16-byte pattern), a plaintext counterpart, a 100 GB sparse file, a link, a named pipe and an unreadable file, a rerun
 * with a smaller clock, stop signals, identifier-shaped names on every channel, the entropy function held equal to the survey's, a census
 * by reference, hostile parameters and the manifest's own claims. Data is synthetic and made here from the formats' specifications.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, readdir, stat, symlink, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { test } from "node:test";
import { buildZip } from "./pack-re-harness.ts";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { PACK, SURVEY, allRows, exists, filesUnder, tool } from "./ransomware-pack-harness.ts";

const EXTENT = join(PACK, "encryption_extent", "run.py");
const MANIFEST = join(PACK, "encryption_extent", "manifest.json");

type Range = { offset: number; length: number };
type FileRow = {
  file: string; file_id: number; status: string; reason?: string; bytes?: number; bytes_inspected?: number; bytes_uninspected?: number;
  uninspected_ranges_total?: number; uninspected_ranges?: Range[]; high_entropy_fraction?: number | null; high_entropy_windows?: number;
  high_entropy_runs_total?: number; high_entropy_runs?: Range[]; block_pattern?: { observed: boolean; run_bytes?: number; period_bytes?: number; runs: number };
  structure?: { expected_format: string | null; magic_present: boolean | null; footer_present: boolean | null; container_parses: boolean | null; checked: boolean; reason?: string; expected_from?: string | null };
  counterpart?: { compared: boolean; reason?: string; windows_compared?: number; windows_equal?: number; windows_differ?: number; first_differing_offset?: number | null; last_differing_offset?: number | null };
  layout?: { findings: Array<{ rule: number; result: string }> };
  entropy_histogram?: Record<string, number>; alternative_explanation?: string; uncertainty?: string[];
};
type Answer = {
  status: string; complete: string; status_basis: string; partial_reasons: string[]; files: FileRow[]; coverage: Record<string, unknown> & { not_inspected_by_reason: Record<string, number> };
  profile: { file: string; rows: number } | null; pages: { files: { matched: number; returned: number; truncated: boolean; all_results?: string } }; time_limit: { reached: boolean };
  threshold: { value: number; reachable_by_random_data: boolean }; paths_withheld: number; error?: string; interrupted?: boolean; boundary?: unknown;
};

async function run(cwd: string, args: unknown, env: Record<string, string> = {}): Promise<{ answer: Answer; stdout: string; stderr: string; code: number | null }> {
  const out = await tool(EXTENT, cwd, args, env);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return { answer: JSON.parse(out.stdout) as Answer, stdout: out.stdout, stderr: out.stderr, code: out.code };
}

const profileRows = async (cwd: string, answer: Answer): Promise<Array<Record<string, unknown>>> =>
  (await readFile(join(cwd, answer.profile!.file), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);

function plain(n: number): Buffer {
  const line = Buffer.from("The quarterly figures were reviewed and approved by the committee on Tuesday. ");
  return Buffer.concat(Array.from({ length: Math.ceil(n / line.length) }, () => line)).subarray(0, n);
}

async function put(cwd: string, name: string, data: Buffer): Promise<string> {
  const path = join("work", "ev", name);
  await mkdir(join(cwd, "work", "ev"), { recursive: true });
  await writeFile(join(cwd, path), data);
  return path;
}

test("zero, text, random, zip, gzip: the fraction, the runs and the structure each file has", async () => {
  await withCwd(async (cwd) => {
    const zero = await put(cwd, "zero.bin", Buffer.alloc(40960));
    const text = await put(cwd, "plain.txt", plain(40960));
    const rnd = await put(cwd, "random.bin", randomBytes(40960));
    const zip = await put(cwd, "archive.zip", buildZip([{ name: "a.bin", data: randomBytes(30000), method: 0 }]));
    const gz = await put(cwd, "packed.gz", gzipSync(randomBytes(30000)));
    const { answer } = await run(cwd, { policy: "full", files: [zero, text, rnd, zip, gz] });
    const by = Object.fromEntries(answer.files.map((f) => [f.file.split("/").pop()!, f]));
    assert.equal(answer.status, "complete", answer.status_basis);
    assert.equal(by["zero.bin"]!.high_entropy_fraction, 0);
    assert.equal(by["plain.txt"]!.high_entropy_fraction, 0);
    assert.equal(by["plain.txt"]!.structure!.container_parses, true);
    assert.equal(by["random.bin"]!.high_entropy_fraction, 1);
    assert.deepEqual(by["random.bin"]!.high_entropy_runs, [{ offset: 0, length: 40960 }]);
    // a zip of stored random bytes is high entropy and a valid zip: both facts are given, and neither is called encryption
    assert.ok(by["archive.zip"]!.high_entropy_fraction! > 0.9);
    assert.deepEqual([by["archive.zip"]!.structure!.magic_present, by["archive.zip"]!.structure!.footer_present, by["archive.zip"]!.structure!.container_parses], [true, true, true]);
    assert.match(by["archive.zip"]!.alternative_explanation!, /normally compressed/);
    assert.equal(by["packed.gz"]!.structure!.magic_present, true);
    assert.ok(by["packed.gz"]!.high_entropy_fraction! > 0.9);
    assert.doesNotMatch(JSON.stringify(answer), /"percent(age)?_encrypted"|"recovered"/);
    assert.equal(answer.threshold.value, 7.5);
    assert.equal(answer.threshold.reachable_by_random_data, true);
  });
});

test("random blocks at known offsets are found as runs at those offsets, with the file's structure damaged and the uninspected ranges empty under full", async () => {
  await withCwd(async (cwd) => {
    const data = Buffer.from(plain(65536 * 2));
    for (const at of [8192, 40960]) randomBytes(4096).copy(data, at);
    const path = await put(cwd, "doc.txt.locked", data);
    const { answer } = await run(cwd, { policy: "full", files: [path] });
    const f = answer.files[0]!;
    assert.deepEqual(f.high_entropy_runs, [{ offset: 8192, length: 4096 }, { offset: 40960, length: 4096 }]);
    assert.equal(f.high_entropy_fraction, 8192 / 131072);
    assert.equal(f.bytes_uninspected, 0);
    assert.equal(f.uninspected_ranges_total, 0);
    assert.equal(f.block_pattern!.observed, false, "two runs are no pattern");
    assert.equal(answer.status, "complete");
  });
});

test("runs of the same length at the same spacing are an observed block pattern, named as windows and never as a family", async () => {
  await withCwd(async (cwd) => {
    const data = Buffer.from(plain(4096 * 40));
    for (let at = 4096; at < data.length; at += 4096 * 5) randomBytes(4096).copy(data, at);
    const path = await put(cwd, "pattern.bin", data);
    const { answer } = await run(cwd, { policy: "full", files: [path] });
    const f = answer.files[0]!;
    assert.deepEqual(f.block_pattern, { observed: true, runs: 8, run_bytes: 4096, period_bytes: 4096 * 5, basis: f.block_pattern && (f.block_pattern as unknown as { basis: string }).basis });
    assert.match((f.block_pattern as unknown as { basis: string }).basis, /names no family/);
    assert.doesNotMatch(JSON.stringify(answer), /ransomware family|"family"/i);
  });
});

test("an intermittent pattern of 16 bytes every 256 is not called encryption: the fraction is 0, the histogram shifts, and the answer says a pattern finer than the window is not located", async () => {
  await withCwd(async (cwd) => {
    const data = Buffer.from(plain(65536));
    for (let at = 0; at + 16 <= data.length; at += 256) randomBytes(16).copy(data, at);
    const path = await put(cwd, "intermittent.dat", data);
    const { answer, stdout } = await run(cwd, { policy: "full", files: [path] });
    const f = answer.files[0]!;
    assert.equal(f.high_entropy_fraction, 0);
    assert.equal(f.high_entropy_runs_total, 0);
    const meanOf = async (a: Answer): Promise<number> => {
      const rows = (await profileRows(cwd, a)).filter((r) => r.record === "window").map((r) => r.entropy as number);
      return rows.reduce((n, x) => n + x, 0) / rows.length;
    };
    const plainRun = (await run(cwd, { policy: "full", files: [await put(cwd, "plain.dat", plain(65536))] })).answer;
    assert.ok((await meanOf(answer)) > (await meanOf(plainRun)) + 0.3, "the windows read higher than plain text does, and stay under the threshold");
    assert.match(stdout, /A pattern finer than the window is not located/);
  });
});

test("a window of 64 bytes is said to seldom reach the threshold, and the answer states what a random window reads", async () => {
  await withCwd(async (cwd) => {
    const path = await put(cwd, "r.bin", randomBytes(4096));
    const { answer } = await run(cwd, { policy: "full", window: 64, files: [path] });
    assert.equal(answer.threshold.reachable_by_random_data, false);
    assert.equal(answer.files[0]!.high_entropy_fraction, 0);
    assert.match(answer.files[0]!.uncertainty!.join(" "), /seldom reaches it/);
  });
});

test("a plaintext counterpart: windows that match, windows that differ and where; a counterpart of another size is not compared", async () => {
  await withCwd(async (cwd) => {
    const original = plain(4096 * 10);
    const changed = Buffer.from(original);
    randomBytes(4096).copy(changed, 4096 * 3);
    randomBytes(4096).copy(changed, 4096 * 7);
    const enc = await put(cwd, "doc.txt.locked", changed);
    const orig = await put(cwd, "original.txt", original);
    const short = await put(cwd, "short.txt", original.subarray(0, 4096));
    const { answer } = await run(cwd, { policy: "full", files: [{ path: enc, counterpart: orig, counterpart_authenticated: true }, { path: enc, counterpart: short }, { path: enc, counterpart: "work/ev/missing.txt" }] });
    const [a, b, c] = answer.files;
    assert.deepEqual([a!.counterpart!.compared, a!.counterpart!.windows_compared, a!.counterpart!.windows_equal, a!.counterpart!.windows_differ], [true, 10, 8, 2]);
    assert.deepEqual([a!.counterpart!.first_differing_offset, a!.counterpart!.last_differing_offset], [4096 * 3, 4096 * 7]);
    assert.match(JSON.stringify(a!.counterpart), /recorded as the caller gave it; the tool does not verify it/);
    assert.deepEqual([b!.counterpart!.compared, b!.counterpart!.reason], [false, "size_differs"]);
    assert.deepEqual([c!.counterpart!.compared, c!.counterpart!.reason], [false, "read_failed"]);
    const rows = await profileRows(cwd, answer);
    assert.equal(rows.filter((r) => r.record === "window" && r.equal_to_counterpart === false).length, 2);
  });
});

test("a 100 GB sparse file: a bounded read, the uninspected ranges named, and the answer partial", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    const big = join(cwd, "work", "ev", "huge.vmdk.locked");
    await writeFile(big, "");
    try {
      await truncate(big, 100 * 1000 ** 3);
    } catch {
      return; // a file system without large sparse files: nothing to measure
    }
    const started = Date.now();
    const sampled = await run(cwd, { policy: "sampling", sample_windows: 20, files: ["work/ev/huge.vmdk.locked"] });
    assert.ok(Date.now() - started < 30000);
    const f = sampled.answer.files[0]!;
    assert.equal(f.bytes, 100 * 1000 ** 3);
    assert.equal(f.bytes_inspected, 20 * 4096);
    assert.equal(f.uninspected_ranges_total, 19, "the first window starts at byte 0 and the last ends at the last byte: 19 gaps between 20 windows");
    assert.equal(f.uninspected_ranges!.length, 16, "the row shows 16 ranges; the profile has every one");
    assert.equal(f.bytes_uninspected, 100 * 1000 ** 3 - 20 * 4096);
    assert.equal(sampled.answer.status, "partial");
    assert.match(sampled.answer.status_basis, /policy sampling: 1 files have bytes outside the sampled windows/);
    const ranges = (await profileRows(cwd, sampled.answer)).filter((r) => r.record === "uninspected");
    assert.equal(ranges.length, 19);
    assert.equal(ranges.reduce((n, r) => n + (r.length as number), 0), f.bytes_uninspected);
    // a full scan under a small read budget stops at the budget and names the rest as one range
    const budgeted = await run(cwd, { policy: "full", read_budget_bytes: 1 << 20, files: ["work/ev/huge.vmdk.locked"] });
    const g = budgeted.answer.files[0]!;
    assert.equal(g.reason, "read_budget_spent");
    assert.equal(g.bytes_inspected, 1 << 20);
    assert.deepEqual(g.uninspected_ranges, [{ offset: 1 << 20, length: 100 * 1000 ** 3 - (1 << 20) }]);
    assert.equal(budgeted.answer.status, "partial");
  });
});

test("a link, a named pipe, a directory, an unreadable file and an invalid path are each not_inspected with a reason, and a named pipe does not hang the tool", async () => {
  await withCwd(async (cwd) => {
    const real = await put(cwd, "real.bin", randomBytes(8192));
    await symlink(join(cwd, real), join(cwd, "work", "ev", "link.bin"));
    assert.equal(spawnSync("mkfifo", [join(cwd, "work", "ev", "pipe.bin")]).status, 0);
    await mkdir(join(cwd, "work", "ev", "dir.bin"));
    const locked = await put(cwd, "locked.bin", randomBytes(8192));
    await chmod(join(cwd, locked), 0);
    const { answer } = await run(cwd, { policy: "full", files: [real, "work/ev/link.bin", "work/ev/pipe.bin", "work/ev/dir.bin", locked, "work/ev/bad\u0000name", "work/ev/lone\ud800.bin", "work/ev/none.bin"] });
    const status = (n: string): string => `${answer.files.find((f) => f.file.endsWith(n))!.status}:${answer.files.find((f) => f.file.endsWith(n))!.reason}`;
    assert.equal(status("real.bin"), "inspected:undefined");
    assert.equal(status("link.bin"), "not_inspected:link_not_followed");
    assert.equal(status("pipe.bin"), "not_inspected:not_a_regular_file");
    assert.equal(status("dir.bin"), "not_inspected:not_a_regular_file");
    // root can read a mode-000 file: either answer is honest, a crash or a hang is not
    assert.match(status("locked.bin"), /^(inspected:undefined|not_inspected:read_failed)$/);
    assert.equal(answer.files.filter((f) => f.reason === "path_invalid").length, 2);
    assert.equal(status("none.bin"), "not_inspected:read_failed");
    assert.equal(answer.status, "partial");
    assert.match(answer.status_basis, /files were not inspected/);
    assert.ok(answer.coverage.not_inspected_by_reason.link_not_followed === 1);
  });
});

const SLOW = String.raw`
import os, runpy, sys, time
_real = os.pread
def slow(fd, n, off):
    time.sleep(float(os.environ["SLOW_PREAD"]))
    return _real(fd, n, off)
os.pread = slow
script = sys.argv[1]
sys.argv = [script]
runpy.run_path(script, run_name="__main__")
`;

type Ended = { code: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string };

async function runSlow(cwd: string, args: unknown, signal: NodeJS.Signals | null, env: Record<string, string> = {}): Promise<Ended> {
  const child = spawn("python3", ["-c", SLOW, EXTENT], { cwd, env: { ...process.env, AGENT_ID: "s1", SLOW_PREAD: "0.01", ...env } });
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => out.push(c));
  child.stderr.on("data", (c: Buffer) => err.push(c));
  const ended = new Promise<Ended>((resolve) => child.on("close", (code, sig) => resolve({ code, signal: sig, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") })));
  child.stdin.end(JSON.stringify(args));
  if (signal) {
    const place = join(cwd, "work", "s1", "tool-output");
    const deadline = Date.now() + 20000;
    while (!((await exists(place)) && (await readdir(place)).length > 0) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    await new Promise((r) => setTimeout(r, 300));
    child.kill(signal);
  }
  return ended;
}

for (const [signal, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
  test(`${signal} while windows are being read: one JSON answer, exit code ${code}, no traceback, no temporary file left`, async () => {
    await withCwd(async (cwd) => {
      const path = await put(cwd, "big.bin", randomBytes(4096 * 400));
      const ended = await runSlow(cwd, { policy: "full", files: [path] }, signal);
      assert.equal(ended.code, code, ended.stderr);
      assert.doesNotMatch(ended.stderr, /Traceback/);
      const answer = JSON.parse(ended.stdout) as Answer;
      assert.equal(answer.status, "failed");
      assert.equal(answer.interrupted, true);
      const left = Object.keys(await filesUnder(join(cwd, "work", "s1"))).filter((n) => n.split("/").pop()!.startsWith("."));
      assert.deepEqual(left, [], "no hidden temporary file");
      assert.deepEqual(await readdir(join(cwd, "work", "s1", "tool-output")), [], "no profile file with the name of a finished one");
    });
  });
}

test("a second signal while the stop answer is written still gives one document", async () => {
  await withCwd(async (cwd) => {
    const path = await put(cwd, "big.bin", randomBytes(4096 * 400));
    const child = spawn("python3", ["-c", SLOW, EXTENT], { cwd, env: { ...process.env, AGENT_ID: "s1", SLOW_PREAD: "0.01" } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    const closed = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
    child.stdin.end(JSON.stringify({ policy: "full", files: [path] }));
    await new Promise((r) => setTimeout(r, 1500));
    child.kill("SIGTERM");
    child.kill("SIGHUP");
    child.kill("SIGINT");
    await closed;
    const text = Buffer.concat(out).toString("utf8");
    assert.equal(text.trim().split("\n").length, 1);
    assert.equal((JSON.parse(text) as Answer).status, "failed");
  });
});

test("a rerun with a smaller clock keeps the larger earlier profile and names its own file", async () => {
  await withCwd(async (cwd) => {
    const path = await put(cwd, "set.bin", randomBytes(4096 * 120));
    const first = await run(cwd, { policy: "full", files: [path] });
    assert.equal(first.answer.status, "complete");
    const bigName = first.answer.profile!.file;
    const bigBytes = (await stat(join(cwd, bigName))).size;
    const ended = await runSlow(cwd, { policy: "full", files: [path], max_seconds: 1 }, null);
    assert.equal(ended.code, 0, ended.stderr);
    const second = JSON.parse(ended.stdout) as Answer;
    assert.equal(second.status, "partial");
    assert.equal(second.time_limit.reached === false, true, "the per-file clock is in the file row, not the walk");
    assert.equal(second.files[0]!.reason, "time_limit");
    assert.notEqual(second.profile!.file, bigName);
    assert.match(second.profile!.file, /-2\.jsonl$/);
    assert.equal((await stat(join(cwd, bigName))).size, bigBytes, "the earlier profile is intact");
    assert.ok((await stat(join(cwd, second.profile!.file))).size < bigBytes);
  });
});

test("max_seconds is honoured to within 2 s, also for a large window", async () => {
  await withCwd(async (cwd) => {
    const path = await put(cwd, "w.bin", randomBytes(1 << 22));
    const began = Date.now();
    const ended = await runSlow(cwd, { policy: "full", window: 64, files: [path], max_seconds: 2 }, null, { SLOW_PREAD: "0.001" });
    const took = (Date.now() - began) / 1000;
    assert.equal(ended.code, 0, ended.stderr);
    const answer = JSON.parse(ended.stdout) as Answer;
    assert.equal(answer.status, "partial");
    assert.equal(answer.files[0]!.reason, "time_limit");
    assert.ok(took < 2 + 2 + 1, `took ${took} s (startup included)`);
  });
});

test("identifier-shaped path components are withheld on every channel, and a note-named file's name too; no byte of a file is printed", async () => {
  await withCwd(async (cwd) => {
    const dirId = "9F8E7D6C5B4A3210";
    const noteId = "7A6B5C4D3E2F1019";
    const marker = "UNIQUEPLAINTEXTMARKERQQ";
    await mkdir(join(cwd, "work", "ev", dirId), { recursive: true });
    await writeFile(join(cwd, "work", "ev", dirId, "a.docx.locked"), Buffer.concat([Buffer.from(marker), randomBytes(8192)]));
    await writeFile(join(cwd, "work", "ev", `README_${noteId}.txt`), Buffer.from(`${marker} Your files are encrypted`));
    await writeFile(join(cwd, "work", "ev", `cp_${dirId}.txt`), plain(5000));
    const { answer, stdout, stderr } = await run(cwd, {
      policy: "full",
      files: [`work/ev/${dirId}/a.docx.locked`, `work/ev/README_${noteId}.txt`, { path: `work/ev/${dirId}/a.docx.locked`, counterpart: `work/ev/${dirId}/a.docx.locked` }],
    });
    const files = await filesUnder(join(cwd, "work", "s1"));
    const channels = [stdout, stderr, ...Object.values(files)];
    assert.ok(channels.length >= 3);
    for (const text of channels) {
      assert.ok(!text.includes(dirId), "the directory identifier is on no channel");
      assert.ok(!text.includes(noteId), "the note-named file's identifier is on no channel");
      assert.ok(!text.includes(marker), "no byte of a file is printed");
      assert.ok(!text.includes(Buffer.from(marker).toString("hex")), "no byte of a file is printed in hex");
    }
    assert.ok(answer.paths_withheld >= 2);
    assert.ok(answer.files.every((f) => f.file.length > 0));
  });
});

test("the entropy function is the survey's: the two sources are the same function", () => {
  const code = [
    "import ast, sys",
    "def fn(path):",
    "    t = ast.parse(open(path, encoding='utf-8').read())",
    "    f = [n for n in ast.walk(t) if isinstance(n, ast.FunctionDef) and n.name == 'entropy_exact']",
    "    assert len(f) == 1, path",
    "    return ast.dump(f[0]), ast.unparse(f[0])",
    "a, b = fn(sys.argv[1]), fn(sys.argv[2])",
    "print('EQUAL' if a == b and 'Counter' in a[1] else 'DIFFERENT')",
  ].join("\n");
  const r = spawnSync("python3", ["-I", "-c", code, SURVEY, EXTENT], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), "EQUAL");
});

async function survey(cwd: string): Promise<string> {
  const out = await tool(SURVEY, cwd, { root: "work/ev" });
  const ans = JSON.parse(out.stdout) as { census: { file: string } };
  return ans.census.file;
}

test("a census by reference: its candidate rows are measured, an unknown parser is refused by name, no receipt is partial, and no candidate is not complete", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "a.docx.locked", randomBytes(9000));
    await put(cwd, "b.txt", plain(9000));
    const census = await survey(cwd);
    const { answer } = await run(cwd, { policy: "full", census });
    assert.deepEqual(answer.files.map((f) => f.file.split("/").pop()), ["a.docx.locked"]);
    assert.equal(answer.status, "complete", answer.status_basis);
    const all = await run(cwd, { policy: "full", census, census_statuses: ["candidate", "noncandidate"] });
    assert.equal(all.answer.files.length, 2);
    // an unknown parser
    const text = await readFile(join(cwd, census), "utf8");
    const lines = text.trimEnd().split("\n");
    const receipt = JSON.parse(lines[lines.length - 1]!) as Record<string, unknown>;
    await writeFile(join(cwd, "other.jsonl"), [...lines.slice(0, -1), JSON.stringify({ ...receipt, parser: "encrypted_survey/9" })].join("\n") + "\n");
    const refused = await tool(EXTENT, cwd, { policy: "full", census: "other.jsonl" });
    assert.notEqual(refused.code, 0);
    const refusal = JSON.parse(refused.stdout) as { error: string; status: string };
    assert.equal(refusal.status, "failed");
    assert.match(refusal.error, /encrypted_survey\/9/);
    // no receipt: read, and partial
    await writeFile(join(cwd, "norec.jsonl"), lines.slice(0, -1).join("\n") + "\n");
    const partial = (await run(cwd, { policy: "full", census: "norec.jsonl" })).answer;
    assert.equal(partial.status, "partial");
    assert.match(partial.status_basis, /no receipt/);
    assert.equal(partial.files.length, 1);
    // a census with no row of the selected statuses: nothing was measured, so it is not complete
    const none = (await run(cwd, { policy: "full", census, census_statuses: ["read_failed"] })).answer;
    assert.equal(none.status, "partial");
    assert.match(none.status_basis, /no file was measured/);
    // a census that is a named pipe is refused without hanging
    spawnSync("mkfifo", [join(cwd, "census.fifo")]);
    const pipe = await tool(EXTENT, cwd, { policy: "full", census: "census.fifo" });
    assert.notEqual(pipe.code, 0);
    assert.equal((JSON.parse(pipe.stdout) as { status: string }).status, "failed");
  });
});

test("structure: magic, footer and container are separate facts, and a damaged zip, pdf, png and sqlite each show which one failed", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip([{ name: "a.txt", data: plain(2000) }]);
    const png = Buffer.concat([Buffer.from("89504e470d0a1a0a", "hex"), Buffer.from("0000000d", "hex"), Buffer.from("IHDR"), Buffer.alloc(13), Buffer.alloc(4), Buffer.from("0000000049454e44ae426082", "hex")]);
    const pdf = Buffer.from("%PDF-1.4\n1 0 obj\n<<>>\nendobj\nxref\n0 1\n0000000000 65535 f \ntrailer\n<<>>\nstartxref\n29\n%%EOF\n");
    const sqlite = Buffer.concat([Buffer.from("SQLite format 3\0"), Buffer.from([0x10, 0x00]), Buffer.alloc(4096 - 18)]);
    const files = { "ok.zip": zip, "cut.zip": zip.subarray(0, zip.length - 30), "rand.zip": randomBytes(zip.length), "ok.png": png, "rand.png": randomBytes(png.length), "ok.pdf": pdf, "rand.pdf": randomBytes(pdf.length), "ok.db": sqlite, "odd.db": sqlite.subarray(0, 4000) };
    const names: string[] = [];
    for (const [n, d] of Object.entries(files)) names.push(await put(cwd, n, d));
    const { answer } = await run(cwd, { policy: "full", files: names });
    const s = (n: string) => answer.files.find((f) => f.file.endsWith(n))!.structure!;
    for (const n of ["ok.zip", "ok.png", "ok.pdf", "ok.db"]) {
      assert.equal(s(n).magic_present, true, n);
      assert.equal(s(n).container_parses, true, n);
    }
    assert.equal(s("ok.pdf").footer_present, true);
    assert.equal(s("ok.png").footer_present, true);
    assert.deepEqual([s("cut.zip").magic_present, s("cut.zip").footer_present, s("cut.zip").container_parses], [true, false, false]);
    for (const n of ["rand.zip", "rand.png", "rand.pdf"]) assert.equal(s(n).magic_present, false, n);
    assert.equal(s("odd.db").container_parses, false);
    // the format can be named by the caller when the name says nothing
    const named = await run(cwd, { policy: "full", files: [{ path: names[0]!.replace("ok.zip", "ok.zip"), format: "zip" }], check_structure: true });
    assert.equal(named.answer.files[0]!.structure!.expected_from, "caller");
    const skipped = (await run(cwd, { policy: "full", files: [names[0]!], check_structure: false })).answer.files[0]!;
    assert.equal(skipped.structure, undefined);
  });
});

test("a layout is judged only when supplied, rule by rule, and names no family", async () => {
  await withCwd(async (cwd) => {
    const data = Buffer.from(plain(65536));
    randomBytes(8192).copy(data, 0);
    const path = await put(cwd, "doc.bin", data);
    const none = (await run(cwd, { policy: "full", files: [path] })).answer.files[0]!;
    assert.equal(none.layout, undefined);
    const layout = { name: "supplied layout", validated: false, rules: [
      { from: "start", offset: 0, length: 4096, expect: "high_entropy" },
      { from: "end", offset: 0, length: 4096, expect: "high_entropy" },
      { from: "start", offset: 65000, length: 4096, expect: "not_high_entropy" },
    ] };
    const { answer, stdout } = await run(cwd, { policy: "full", files: [path], layout });
    assert.deepEqual(answer.files[0]!.layout!.findings.map((f) => f.result), ["consistent", "inconsistent", "outside_file"]);
    assert.match(stdout, /identify no family/);
    for (const bad of [{ ...layout, rules: [] }, { ...layout, rules: [{ from: "middle", offset: 0, length: 1, expect: "high_entropy" }] }, { ...layout, validated: "yes" }, "layout"]) {
      const out = await tool(EXTENT, cwd, { policy: "full", files: [path], layout: bad });
      assert.notEqual(out.code, 0);
      assert.equal((JSON.parse(out.stdout) as { status: string }).status, "failed");
    }
  });
});

test("hostile parameters give a JSON refusal and never a traceback", async () => {
  await withCwd(async (cwd) => {
    const deep = (n: number): string => "[".repeat(n) + "]".repeat(n);
    const cases: Array<[string, string]> = [
      ["not json", "{"],
      ["deep nesting", `{"policy": "full", "files": ${deep(100000)}}`],
      ["a huge integer", `{"policy": "full", "files": ["x"], "window": ${"9".repeat(5000)}}`],
      ["a huge exponent", `{"policy": "full", "files": ["x"], "max_seconds": 1e999}`],
      ["NaN", `{"policy": "full", "files": ["x"], "threshold": NaN}`],
      ["wrong types", `{"policy": 5, "files": "x"}`],
      ["a list of numbers", `{"policy": "full", "files": [1, 2]}`],
      ["a boolean window", `{"policy": "full", "files": ["x"], "window": true}`],
      ["an array", `[]`],
      ["no policy", `{"files": ["x"]}`],
      ["a window past the bound", `{"policy": "full", "files": ["x"], "window": 67108865}`],
      ["no input", `{"policy": "full"}`],
      ["unknown file key", `{"policy": "full", "files": [{"path": "x", "mode": "w"}]}`],
      ["a lone surrogate in a key", `{"policy": "full", "files": ["x"], "\\ud800": 1}`],
    ];
    for (const [label, input] of cases) {
      const child = spawnSync("python3", [EXTENT], { cwd, input, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" }, timeout: 60000 });
      assert.doesNotMatch(child.stderr, /Traceback/, label);
      if (label === "a lone surrogate in a key") {
        assert.ok([0, 1].includes(child.status ?? -1), label);
        JSON.parse(child.stdout);
        continue;
      }
      if (label === "a huge exponent") {
        // 1e999 is a float (infinity) for the integer parameter: refused
        assert.notEqual(child.status, 0, label);
      }
      const answer = JSON.parse(child.stdout) as { status: string };
      assert.equal(answer.status, "failed", `${label}: ${child.stdout}`);
      assert.equal(child.status, 1, label);
    }
  });
});

test("the manifest's own claims hold: the clock, the rationale for the threshold, the parser, no family field, and the example parses", async () => {
  const manifest = JSON.parse(await readFile(MANIFEST, "utf8")) as { timeout_seconds: number; description: string; params: Record<string, { description: string }>; example: string; entry: string };
  const source = await readFile(EXTENT, "utf8");
  const max = /DEFAULT_SECONDS, MAX_SECONDS = (\d+), (\d+)/.exec(source)!;
  assert.ok(Number(max[2]) <= manifest.timeout_seconds - 60, "the tool's own clock is at least 60 s below the manifest's");
  assert.match(manifest.params.max_seconds!.description, new RegExp(`default ${max[1]}, at most ${max[2]}`));
  assert.match(manifest.description, /the reverse-engineering pack's entropy_map uses 7\.2/);
  assert.match(manifest.description, /not a percentage of the file that was encrypted/);
  assert.match(source, /PARSER = "encryption_extent\/1"/);
  assert.doesNotMatch(source.replace(/"""[\s\S]*?"""/, "").replace(/^\s*#.*$/gm, ""), /affiliate|actor_name|"family"\s*:/i);
  assert.doesNotMatch(source, /start_new_session|setsid|process_group/);
  for (const name of ["policy", "files", "census", "census_statuses", "window", "threshold", "sample_windows", "layout", "check_structure", "limit", "read_budget_bytes", "max_seconds"]) assert.ok(manifest.params[name], `${name} is documented`);
  assert.deepEqual(JSON.parse(manifest.example), { policy: "sampling", files: ["work/extracted/report.docx.locked"] });
  assert.match(source, /DEFAULT_WINDOW, MIN_WINDOW, MAX_WINDOW = 4096, 64, 67108864/);
  assert.match(manifest.description, /fewer than about 1000 bytes/);
  // the claims about measured numbers are the ones written in the description
  assert.match(manifest.description, /1,048,576 windows/);
  assert.match(manifest.description, /106,687,821 bytes/);
});

test("the shared blocks are the survey's, byte for byte, and the pack-local LosslessPage is the same class", async () => {
  const survey = await readFile(SURVEY, "utf8");
  const extent = await readFile(EXTENT, "utf8");
  const block = (text: string, name: string): string => {
    const m = new RegExp(`^# BEGIN SHARED ${name}\\n[\\s\\S]*?^# END SHARED ${name}$`, "m").exec(text);
    assert.ok(m, `the ${name} block is there`);
    return m[0];
  };
  for (const name of ["PLACE", "PAGE", "STOP", "WITHHOLDING", "NAMES", "BACKSTOP"]) assert.equal(block(extent, name), block(survey, name), name);
  const cls = (text: string): string => /^class LosslessPage:[\s\S]*?(?=^# BEGIN SHARED PLACE)/m.exec(text)![0];
  assert.equal(cls(extent), cls(survey));
  assert.ok(await exists(EXTENT));
  assert.equal(((await stat(EXTENT)).mode & 0o111) !== 0, true, "run.py is executable");
});

test("the rows shown inline are cut by size and the whole table is in a file that is named", async () => {
  await withCwd(async (cwd) => {
    const names: string[] = [];
    for (let i = 0; i < 30; i++) names.push(await put(cwd, `f${String(i).padStart(2, "0")}.dat`, randomBytes(5000)));
    const { answer } = await run(cwd, { policy: "full", files: names, limit: 5 });
    assert.equal(answer.files.length, 5);
    assert.equal(answer.pages.files.matched, 30);
    const rows = await allRows<FileRow>(cwd, answer.pages.files);
    assert.equal(rows.length, 30);
  });
});
