/**
 * ransomware-response: what the two answers say about themselves. Every answer carries status (complete, partial or failed) and a
 * status_basis, the partial ones say why, a threshold compares the unrounded reading, and ransom_note_scan writes values only in a job
 * that is run as secret output, as recovery_key_scan does.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPySnippet, withCwd } from "./tool-library-harness.ts";
import { NOTES, SURVEY, body, exists, refused, tool } from "./ransomware-pack-harness.ts";

type Answer = { status: string; status_basis: string; complete: string; partial_reasons: string[] };
const NOTE = "Your files are encrypted. To decrypt your files, pay in bitcoin and restore your files.\n";

for (const [name, script] of [["encrypted_survey", SURVEY], ["ransom_note_scan", NOTES]] as const) {
  test(`${name}: a whole answer is complete with a basis, and every failure is failed with a basis`, async () => {
    await withCwd(async (cwd) => {
      await mkdir(join(cwd, "work", "ev"), { recursive: true });
      await writeFile(join(cwd, "work", "ev", "README.txt"), NOTE);
      const whole = body<Answer>(await tool(script, cwd, { root: "work/ev" }));
      assert.deepEqual([whole.status, whole.complete, whole.partial_reasons], ["complete", "complete", []]);
      assert.ok(whole.status_basis.length > 40);
      for (const args of [{}, { root: "work/nothing" }, { root: "work/ev", limit: 0 }, { root: "work/ev", max_seconds: "x" }]) {
        const failed = refused(await tool(script, cwd, args)) as unknown as Answer & { error: string };
        assert.equal(failed.status, "failed", JSON.stringify(args));
        assert.ok(failed.status_basis.length > 20);
      }
    });
  });

  test(`${name}: input that is not JSON, and a root that is a file, are failed answers and not tracebacks`, async () => {
    await withCwd(async (cwd) => {
      await writeFile(join(cwd, "work", "file.txt"), "x");
      const direct = await runPySnippet("import runpy,sys; sys.argv=[sys.argv[1]]; runpy.run_path(sys.argv[0], run_name='__main__')", [script], undefined);
      assert.notEqual(direct.code, 0);
      assert.doesNotMatch(direct.stderr, /Traceback/);
      assert.equal((JSON.parse(direct.stdout) as Answer).status, "failed");
      const file = refused(await tool(script, cwd, { root: "work/file.txt" })) as unknown as Answer;
      assert.equal(file.status, "failed");
    });
  });
}

// --- ransom_note_scan: secret output --------------------------------------------------

const VICTIM = "Zq" + "7Km".repeat(4) + "Pw";

test("ransom_note_scan writes no values in a job that was not run as secret output, as recovery_key_scan does not, and writes them in one that was", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    await writeFile(join(ev, "README.txt"), `${NOTE}your personal id: ${VICTIM}\n`);
    const out = join(cwd, "out");
    await mkdir(out);
    const plain = refused(await tool(NOTES, cwd, { root: "work/ev", write_values: true }, { JOB_ID: "j000001", OUT: out })) as unknown as { error: string; write_values: string; written: boolean };
    assert.equal(plain.write_values, "refused");
    assert.equal(plain.written, false);
    assert.match(plain.error, /not run as secret output/);
    assert.match(plain.error, /job_run tool=ransom_note_scan/);
    assert.equal(await exists(join(out, "ransom-note-values.jsonl")), false, "nothing was written");
    // the ordinary mode needs no flag and carries no value
    const ordinary = await tool(NOTES, cwd, { root: "work/ev" }, { JOB_ID: "j000001", OUT: out });
    assert.ok(!ordinary.stdout.includes(VICTIM));
    assert.equal(await exists(join(out, "ransom-note-values.jsonl")), false);
    const secret = body<{ secret_values: { written: number } }>(await tool(NOTES, cwd, { root: "work/ev", write_values: true }, { JOB_ID: "j000001", OUT: out, SECRET_OUTPUT: "1" }));
    assert.ok(secret.secret_values.written >= 2);
    assert.match(await readFile(join(out, "ransom-note-values.jsonl"), "utf8"), new RegExp(VICTIM));
    for (const other of ["0", "", "true"]) {
      const o2 = join(cwd, "out" + other.length + other);
      await mkdir(o2);
      const r = refused(await tool(NOTES, cwd, { root: "work/ev", write_values: true }, { JOB_ID: "j000002", OUT: o2, SECRET_OUTPUT: other })) as unknown as { error: string };
      assert.match(r.error, /not run as secret output/, `SECRET_OUTPUT=${other}`);
    }
  });
});

test("ransom_note_scan declares that a job which sets write_values is secret output, like recovery_key_scan", async () => {
  const manifest = JSON.parse(await readFile(join(ROOT, "packs", "ransomware-response", "tools", "ransom_note_scan", "manifest.json"), "utf8")) as {
    secret_output: unknown;
    params: { write_values: { type: string; default?: unknown } };
    version: number;
  };
  assert.deepEqual(manifest.secret_output, { when_args: ["write_values"] });
  assert.equal(manifest.params.write_values.type, "boolean");
  assert.ok(manifest.params.write_values.default === undefined || manifest.params.write_values.default === false);
  const encrypted = JSON.parse(await readFile(join(ROOT, "packs", "encrypted-containers", "tools", "recovery_key_scan", "manifest.json"), "utf8")) as { secret_output: unknown };
  assert.deepEqual(manifest.secret_output, encrypted.secret_output);
  assert.ok(manifest.version >= 3);
});

// --- encrypted_survey: what is partial -------------------------------------------------

test("encrypted_survey: candidates left unprofiled by the sample limit make the answer partial, and say how many", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    for (let i = 0; i < 8; i++) await writeFile(join(ev, `f${i}.doc.locked`), randomBytes(9000));
    const some = body<Answer & { sampling: { profiled: number; candidates_not_profiled: Record<string, number> } }>(await tool(SURVEY, cwd, { root: "work/ev", sample: 3 }));
    assert.deepEqual([some.status, some.complete], ["partial", "partial"]);
    assert.equal(some.sampling.profiled, 3);
    assert.equal(some.sampling.candidates_not_profiled.sample_limit, 5);
    assert.match(some.status_basis, /5 candidates were not profiled: the sample \(3\) was reached/);
    const all = body<Answer>(await tool(SURVEY, cwd, { root: "work/ev", sample: 8 }));
    assert.equal(all.status, "complete");
  });
});

const CAPPED = String.raw`
import contextlib, importlib.util, io, json, os, sys
spec = importlib.util.spec_from_file_location("survey", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.HOUR_CAP = 2
os.chdir(sys.argv[2]); os.environ["AGENT_ID"] = "s1"
sys.stdin = io.StringIO(json.dumps(json.loads(sys.argv[3])))
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    m.main()
print(buf.getvalue())`;

test("encrypted_survey: a capped hour table makes the answer partial, and with census false it does not say the census has every file", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    const { utimes } = await import("node:fs/promises");
    const t0 = Date.UTC(2026, 3, 12, 0, 10, 0) / 1000;
    for (let i = 0; i < 5; i++) {
      await writeFile(join(ev, `b${i}.txt`), "The quarterly figures were reviewed on Monday and approved without change. ".repeat(100));
      await utimes(join(ev, `b${i}.txt`), t0 + i * 3600, t0 + i * 3600);
    }
    for (const census of [true, false]) {
      const run = await runPySnippet(CAPPED, [SURVEY, cwd, JSON.stringify({ root: "work/ev", census })], null);
      assert.equal(run.code, 0, run.stderr);
      const answer = JSON.parse(run.stdout) as Answer & { histogram_tables: { all_files: string } };
      assert.equal(answer.status, "partial", `census ${census}`);
      assert.match(answer.status_basis, /all files hour table is capped at 2 distinct hours: 3 files are not counted in it/);
      if (census) assert.match(answer.histogram_tables.all_files, /the census has every one/);
      else {
        assert.doesNotMatch(answer.histogram_tables.all_files, /the census has every one/);
        assert.match(answer.histogram_tables.all_files, /does not list files that matched nothing/);
      }
    }
  });
});

// --- encrypted_survey: a head that reads 7.4996 is not at 7.5 -----------------------------

/** A 65,536-byte block whose entropy is between 7.4995 and 7.5 (so that it prints as 7.5): symbol counts found by search. */
function blockNearThreshold(): Buffer {
  const total = 65536;
  const entropy = (counts: number[]): number => -counts.reduce((s, c) => (c ? s + (c / total) * Math.log2(c / total) : s), 0);
  for (let small = 1; small < 600; small++) {
    for (let wide = 170; wide <= 200; wide++) {
      const rest = total - small;
      const each = Math.floor(rest / wide);
      const counts = Array.from({ length: wide }, () => each);
      counts[0] += rest - each * wide;
      counts.push(small);
      const e = entropy(counts);
      if (e > 7.4996 && e < 7.49995 && counts.length <= 256) {
        const bytes = Buffer.alloc(total);
        let at = 0;
        counts.forEach((c, symbol) => {
          bytes.fill(symbol, at, at + c);
          at += c;
        });
        // shuffle (a fixed multiplicative walk; the entropy does not depend on the order)
        const out = Buffer.alloc(total);
        for (let i = 0; i < total; i++) out[(i * 40503) % total] = bytes[i];
        return out;
      }
    }
  }
  throw new Error("no block found");
}

test("encrypted_survey compares the unrounded entropy: a head that prints as 7.5 but reads 7.4997 is not a candidate", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    await writeFile(join(ev, "data.bin"), blockNearThreshold());
    await writeFile(join(ev, "over.bin"), randomBytes(65536));
    const answer = body<Answer & { candidates: { file: string; head_entropy: number }[]; coverage: { noncandidate_files: number }; census: { file: string } }>(await tool(SURVEY, cwd, { root: "work/ev" }));
    assert.deepEqual(answer.candidates.map((c) => c.file.split("/").pop()), ["over.bin"]);
    assert.equal(answer.coverage.noncandidate_files, 1);
    const census = (await readFile(join(cwd, answer.census.file), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { file?: string; head_entropy?: number });
    const near = census.find((r) => r.file?.endsWith("data.bin"));
    assert.equal(near?.head_entropy, 7.5, "it prints as 7.5");
  });
});
