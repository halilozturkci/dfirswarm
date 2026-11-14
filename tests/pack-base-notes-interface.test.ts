/**
 * computer-forensics-base: two notes held to the interface they describe (Batman III runs, findings I-19 and I-20).
 *
 * evidence/ad1 told the seat to "declare every segment in the job's inputs" after the job scope began to take the
 * segment set from the first segment, and its only example call was the locator form of `members`, with the sentence
 * that `members` also takes the item number left for the prose: a seat shown the note's card wrote `ad1:item=<n>`
 * 24 seconds later. Each form the note shows is run here against ad1_extract, on the same item, and the form it
 * warns against is shown to be refused or to name nothing.
 *
 * data/sqlite-secrets gave an export of `logins` as its example while the Windows pack's browser/strings was read as
 * forbidding sqlite_query on Login Data. The base note now says which call is allowed and under which secret-output
 * conditions; the conditions are run here against sqlite_query.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ad1Image } from "./ad1-fixture.ts";
import { PYTHON3 } from "./host-gates.ts";
import { runPy } from "./tool-library-harness.ts";

const ROOT = join(import.meta.dirname, "..");
const CFB = process.env.PACK_DIR || join(ROOT, "packs", "computer-forensics-base");
const AD1_ITEMS = join(CFB, "recipes", "ad1-items", "run.py");
const AD1_EXTRACT = join(CFB, "tools", "ad1_extract", "run.py");
const SQLITE_QUERY = join(CFB, "tools", "sqlite_query", "run.py");

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

async function note(id: string): Promise<{ front: string; body: string }> {
  const text = await readFile(join(CFB, "skills", `${id}.md`), "utf8");
  const m = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text);
  assert.ok(m, `${id} has front matter`);
  return { front: m[1], body: m[2] };
}

async function withRun(fn: (run: string) => Promise<void>): Promise<void> {
  const run = await realpath(await mkdtemp(join(process.platform === "darwin" ? "/tmp" : tmpdir(), "notes-if-")));
  try {
    for (const d of ["inputs", "work/s1", "store/jobs/j000001/out"]) await mkdir(join(run, d), { recursive: true });
    await fn(run);
  } finally {
    await rm(run, { recursive: true, force: true });
  }
}

/** The args={...} object of each example call of a tool in a note's indented blocks, with the note's placeholders filled in. */
function examples(body: string, tool: string, fill: (text: string) => string): Answer[] {
  return body.split("\n").filter((l) => /^ {4}\S/.test(l) && l.includes(tool)).map((l) => {
    const m = /args[=:] ?(\{.*\})(?: inputs=|\)$)/.exec(l.trim());
    assert.ok(m, `the example carries its arguments: ${l}`);
    return JSON.parse(fill(m[1])) as Answer;
  });
}

test("evidence/ad1 says to list first, then shows members by locator and by number, one example of each, and both take the same item", async () => {
  const { front, body } = await note("evidence/ad1");
  const flat = body.replace(/\s+/g, " ");
  // The rule, in the prose and in the card a seat is shown with a call it makes without holding the note.
  assert.match(flat, /`members` takes a locator \(the text `ad1:item=<address>`, the `locator` column\) OR the item's number `n` \(a number, the `n` column\); never `ad1:item=<n>`/);
  const card = /^card: (.+)$/m.exec(front)?.[1] ?? "";
  assert.match(card, /"ad1:item=<address>"/);
  assert.match(card, /OR item numbers as numbers/);
  assert.match(card, /never ad1:item=<n>/);
  assert.ok(card.length <= 700, "the card is shown whole");
  // The segments: the first one names the set. The old sentence is gone.
  assert.doesNotMatch(flat, /Declare every segment/);
  assert.match(flat, /Name the first segment only, in `image` and in `inputs`: the job is given the image's whole segment set from it\./);
  const lines = body.split("\n").filter((l) => /^ {4}job_run tool=ad1_extract /.test(l));
  assert.equal(lines.length, 3, "the list first, then one example of each form of members");
  assert.ok(lines.every((l) => l.endsWith('inputs=["input:case.ad1"]')), "each declares the first segment and no other");
  assert.match(lines[0], /"list": true/);
  assert.match(lines[1], /"members": \["ad1:item=<address>"\]/);
  assert.match(lines[2], /"members": \[<n>\]/);
  // List first, then targeted members; the whole tree only on purpose (the Batman III runs: six seats each walked the whole image).
  assert.match(card, /List first \(\{"list": true\}: no file written; rows n, locator, type, size, path\), then name what you need/);
  assert.match(card, /The whole tree only with whole: true\./);
  assert.match(flat, /Naming nothing writes a small image out and answers for a large one with the list: `whole: true` writes the whole tree/);
  assert.match(flat, /A `members` call for files stops once they are written: `selection` answers for them, and `image_status: not_checked` says the image-wide checks did not run\. A folder, whole or `paths` call walks to the end/);

  await withRun(async (run) => {
    const tree = [{ name: "C:", folder: true, children: [{ name: "a.txt", content: Buffer.from("first") }, { name: "wanted.txt", content: Buffer.from("the one asked for") }] }];
    await writeFile(join(run, "inputs", "case.ad1"), ad1Image(tree));
    // The catalogue's member list, as the recipe writes it: n and locator are two columns, and they differ.
    const made = spawnSync(PYTHON3, [AD1_ITEMS, "run", "--target", JSON.stringify({ paths: ["inputs/case.ad1"] }), "--out", "store/jobs/j000001/out"], { cwd: run, encoding: "utf8" });
    assert.equal(made.status, 0, made.stdout + made.stderr);
    const rows = (await readFile(join(run, "store/jobs/j000001/out/members.tsv"), "utf8")).trim().split("\n").map((l) => l.split("\t"));
    const col = (name: string) => rows[0].indexOf(name);
    const wanted = rows.find((r) => r[col("path")] === "C:/wanted.txt")!;
    const n = wanted[col("n")];
    const locator = wanted[col("locator")];
    assert.match(locator, /^ad1:item=\d+$/);
    assert.notEqual(locator, `ad1:item=${n}`, "an item's number is not its address");

    const all = examples(body, "ad1_extract", (t) => t.replace("ad1:item=<address>", locator).replace("<n>", n));
    // The list the note says to take first: no file of the image, and the two columns the other forms are written from.
    assert.deepEqual(all[0], { image: "inputs/case.ad1", list: true });
    const listed = await runPy(AD1_EXTRACT, run, { ...all[0], out_dir: "work/s1/listed" }, undefined, { AGENT_ID: "s1" });
    assert.equal(listed.code, 0, listed.stdout + listed.stderr);
    const l = JSON.parse(listed.stdout) as Answer;
    assert.deepEqual([l.mode, l.rows_total, l.columns], ["list", 3, ["n", "locator", "type", "size", "path"]]);
    assert.deepEqual(l.rows.find((r: Answer) => r.path === "C:/wanted.txt"), { n: Number(n), locator, type: "file", size: 17, path: "C:/wanted.txt" }, "the list and the catalogue name the item alike");
    await assert.rejects(readFile(join(run, "work", "s1", "listed", "C:", "wanted.txt")), "a list writes no file of the image out");
    const calls = all.slice(1);
    assert.deepEqual(calls.map((c) => c.members), [[locator], [Number(n)]]);
    for (const [i, args] of calls.entries()) {
      const r = await runPy(AD1_EXTRACT, run, { ...args, out_dir: `work/s1/form-${i}` }, undefined, { AGENT_ID: "s1" });
      assert.equal(r.code, 0, r.stdout + r.stderr);
      const a = JSON.parse(r.stdout) as Answer;
      assert.equal(a.files, 1, JSON.stringify(args));
      assert.equal(await readFile(join(run, "work", "s1", `form-${i}`, "C:", "wanted.txt"), "utf8"), "the one asked for");
    }
    // The form the note warns against: the number written as a locator names no item of the image here, and the answer says so.
    const wrong = await runPy(AD1_EXTRACT, run, { image: "inputs/case.ad1", members: [`ad1:item=${n}`], out_dir: "work/s1/wrong" }, undefined, { AGENT_ID: "s1" });
    const w = JSON.parse(wrong.stdout) as Answer;
    assert.notEqual(wrong.code, 0);
    assert.match(JSON.stringify(w), new RegExp(`no item at ad1:item=${n} in this read of the image`));
  });
});

test("data/sqlite-secrets says which read of a secret table is allowed and under which secret-output conditions, and sqlite_query holds each", async () => {
  const { body } = await note("data/sqlite-secrets");
  const flat = body.replace(/\s+/g, " ");
  assert.match(flat, /\*\*Allowed: in a job, the values to a file\.\*\* The one way to read such a table \(a browser's `Login Data`, `Cookies`, `key4\.db` too\): a job with `secret_output: true`, `table` .* and `write_values: true`; refused outside a job or without secret output\./);
  assert.match(flat, /\*\*Not allowed:\*\* `sql` over the values, anywhere/);
  assert.match(flat, /A browser's stored passwords stay encrypted there\./);
  // The Windows pack's note sends a reader of Login Data to this one, with the same call: the two say one thing.
  const windows = (await readFile(join(ROOT, "packs", "windows-forensics", "skills", "browser", "strings.md"), "utf8")).replace(/\s+/g, " ");
  assert.match(windows, /`Login Data`, `Cookies`, `Web Data`, `cookies\.sqlite` and `key4\.db` are read as secret output: a job with `secret_output: true`, `table` and `write_values: true`, never an inline `sql` over the values \(the base pack's `data\/sqlite-secrets`\)/);

  const [args] = examples(body, "sqlite_query", (t) => t.replace("<snapshot or database>", "work/s1/Login Data"));
  assert.deepEqual(args, { db_path: "work/s1/Login Data", table: "logins", write_values: true });
  await withRun(async (run) => {
    const made = spawnSync(PYTHON3, ["-c", [
      "import sqlite3, sys",
      "c = sqlite3.connect(sys.argv[1])",
      "c.execute('create table logins (origin_url text, username_value text, password_value blob)')",
      "c.execute('insert into logins values (?, ?, ?)', ('https://example.test/', 'user@example.test', b'v10' + bytes(range(40))))",
      "c.commit()",
    ].join("\n"), join(run, "work", "s1", "Login Data")], { encoding: "utf8" });
    assert.equal(made.status, 0, made.stderr);
    const out = join(run, "store", "jobs", "j000001", "out");
    // Outside a job: refused, nothing written.
    let r = await runPy(SQLITE_QUERY, run, args, undefined, { AGENT_ID: "s1" });
    let a = JSON.parse(r.stdout) as Answer;
    assert.notEqual(r.code, 0);
    assert.match(JSON.stringify(a), /outside a job/);
    // In a job that is not secret output: refused.
    r = await runPy(SQLITE_QUERY, run, args, undefined, { JOB_ID: "j000001", OUT: out, SECRET_OUTPUT: "0" });
    a = JSON.parse(r.stdout) as Answer;
    assert.notEqual(r.code, 0);
    assert.match(JSON.stringify(a), /secret output/);
    // With sql beside the mode: refused (no query over the values).
    r = await runPy(SQLITE_QUERY, run, { ...args, sql: "select * from logins where username_value like 'u%'" }, undefined, { JOB_ID: "j000001", OUT: out, SECRET_OUTPUT: "1" });
    assert.notEqual(r.code, 0);
    // The allowed call: the values go to the file, and the answer holds none of them.
    r = await runPy(SQLITE_QUERY, run, args, undefined, { JOB_ID: "j000001", OUT: out, SECRET_OUTPUT: "1" });
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.doesNotMatch(r.stdout, /user@example\.test/);
    const kept = await readFile(join(out, "sqlite-query-values.jsonl"), "utf8");
    assert.match(kept, /user@example\.test/);
  });
});
