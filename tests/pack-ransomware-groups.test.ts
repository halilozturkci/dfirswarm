/**
 * ransom_note_scan: template-similarity groups. Notes of one template with different victim ids are one group; a note that differs only in its
 * id is not split off; the groups are the same whatever the ids are (canaries in the ids change no membership, count or order and are on no
 * channel); a template change right at the threshold falls on the side the threshold says; 10,000 notes are grouped within bounds; stop signals
 * end the tool cleanly. The notes are synthetic.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { NOTES, allRows, exists, filesUnder, tool } from "./ransomware-pack-harness.ts";

type Group = { group_id: string; copies: number; member_note_ids: string[]; directories: string[]; directories_total: number; earliest_mtime_ns: number; latest_mtime_ns: number; basis: string };
type Member = { group_id: string; note_id: string; directory: string; mtime_ns: number };
type Note = { note_id: string; file: string };
type Answer = {
  parser: string; status: string; status_basis: string; partial_reasons: string[]; template_groups: Group[]; template_group_members: Member[];
  template_grouping: { threshold: number; notes_grouped: number; groups: number; notes_not_grouped: Record<string, number>; binary_notes_are_not_grouped: number };
  pages: Record<string, { matched: number; all_results?: string }>; notes: Note[]; error?: string; interrupted?: boolean;
};

async function scan(cwd: string, args: Record<string, unknown> = {}, env: Record<string, string> = {}): Promise<{ answer: Answer; stdout: string; stderr: string }> {
  const out = await tool(NOTES, cwd, { root: "work/ev", limit: 100000, ...args }, env);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return { answer: JSON.parse(out.stdout) as Answer, stdout: out.stdout, stderr: out.stderr };
}

/** The words of a template: distinct, so that every shingle is its own. */
const words = (n: number, tag = "w"): string[] => Array.from({ length: n }, (_, i) => `${tag}${String.fromCharCode(97 + (i % 26))}${String.fromCharCode(97 + Math.floor(i / 26))}word`);
const hex = (n: number): string => randomBytes(n).toString("hex").toUpperCase();

function note(template: string[], id: string, onion: string): string {
  return `${template.join(" ")}\nYour personal ID: ${id}\nOpen http://${onion}.onion/ and write to support@${onion.slice(0, 8)}.example\n`;
}
const onionOf = (): string => Array.from({ length: 56 }, () => "abcdefghijklmnopqrstuvwxyz234567"[Math.floor(Math.random() * 32)]).join("");

async function put(cwd: string, name: string, text: string | Buffer): Promise<void> {
  await mkdir(join(cwd, "work", "ev"), { recursive: true });
  await writeFile(join(cwd, "work", "ev", name), text);
}

/** The groups as sets of the notes' file names, which are short and plain so that they print and sort the same in every run. */
async function structure(cwd: string, a: Answer): Promise<string[][]> {
  const whole = async <T>(page: { all_results?: string }, inline: T[]): Promise<T[]> => (page.all_results ? allRows<T>(cwd, page as { matched: number; returned: number; truncated: boolean; all_results: string }) : inline);
  const notes = await whole<Note>(a.pages.notes!, a.notes);
  const nameOf = new Map(notes.map((n) => [n.note_id, n.file.split("/").pop()!]));
  const members = await whole<Member>(a.pages.template_group_members!, a.template_group_members);
  const byGroup = new Map<string, string[]>();
  for (const m of members) byGroup.set(m.group_id, [...(byGroup.get(m.group_id) ?? []), nameOf.get(m.note_id)!]);
  return [...byGroup.values()].map((v) => v.sort()).sort((x, y) => y.length - x.length || x[0]!.localeCompare(y[0]!));
}

test("two notes of one template with different victim ids, addresses and wallets fall into one group; a different template is another", async () => {
  await withCwd(async (cwd) => {
    const t = words(60);
    await put(cwd, "README_a.txt", note(t, hex(8), onionOf()));
    await put(cwd, "README_b.txt", note(t, hex(8), onionOf()));
    await put(cwd, "README_c.txt", note(words(60, "other"), hex(8), onionOf()));
    const { answer } = await scan(cwd);
    assert.equal(answer.parser, "ransom_note_scan/4");
    assert.equal(answer.template_grouping.notes_grouped, 3);
    assert.equal(answer.template_grouping.groups, 2);
    assert.deepEqual(answer.template_groups.map((g) => g.copies), [2, 1]);
    assert.deepEqual(await structure(cwd, answer), [["README_a.txt", "README_b.txt"], ["README_c.txt"]]);
    assert.equal(answer.status, "complete", answer.status_basis);
  });
});

test("a note that differs only in its id is not split off, whatever the id is", async () => {
  await withCwd(async (cwd) => {
    const t = words(80);
    for (let i = 0; i < 12; i++) await put(cwd, `README_${String(i).padStart(2, "0")}.txt`, note(t, i % 2 ? hex(8) : `Z9${hex(7)}`, onionOf()));
    const { answer } = await scan(cwd);
    assert.equal(answer.template_grouping.groups, 1);
    assert.equal(answer.template_groups[0]!.copies, 12);
  });
});

test("canaries in the ids change no membership, count or order, and are on no channel", async () => {
  const shapes: Array<() => string> = [() => hex(8), () => hex(16), () => `${hex(4)}-${hex(4)}`, () => randomBytes(12).toString("base64").replace(/[^A-Za-z0-9]/g, "Q")];
  const runs: string[][][] = [];
  const canaries: string[] = [];
  for (let round = 0; round < 3; round++) {
    await withCwd(async (cwd) => {
      const a = words(70, "alpha");
      const b = words(70, "beta");
      for (let i = 0; i < 9; i++) {
        const id = shapes[(i + round) % shapes.length]!();
        canaries.push(id);
        const onion = onionOf();
        canaries.push(onion);
        await put(cwd, `README_${String(i).padStart(2, "0")}.txt`, note(i % 3 === 0 ? b : a, id, onion));
      }
      const { answer, stdout, stderr } = await scan(cwd);
      const files = await filesUnder(join(cwd, "work", "s1"));
      for (const text of [stdout, stderr, ...Object.values(files)]) for (const c of canaries) assert.ok(!text.includes(c), "a canary is on a channel");
      assert.match(JSON.stringify(answer.template_groups), /"basis"/);
      runs.push(await structure(cwd, answer));
    });
  }
  assert.deepEqual(runs[1], runs[0]);
  assert.deepEqual(runs[2], runs[0]);
  assert.deepEqual(runs[0]!.map((g) => g.length), [6, 3]);
});

test("a template change right at the threshold falls on the side the threshold says: 0.8 joins, a second changed word does not, and the threshold moves the line", async () => {
  await withCwd(async (cwd) => {
    // 29 distinct words make 27 shingles; one changed word in the middle changes 3 of them: similarity 24 / 30 = 0.8 exactly
    const base = words(29);
    const one = [...base];
    one[14] = "changedone";
    const two = [...one];
    two[5] = "changedtwo";                      // a second, separate change: 6 shingles differ, similarity 21 / 33
    await put(cwd, "README_0.txt", base.join(" ") + "\n");
    await put(cwd, "README_1.txt", one.join(" ") + "\n");
    await put(cwd, "README_2.txt", two.join(" ") + "\n");
    const at = (await scan(cwd, { template_threshold: 0.8 })).answer;
    assert.deepEqual(await structure(cwd, at), [["README_0.txt", "README_1.txt", "README_2.txt"]], "0.8 joins the first two, and the third joins the second (0.8 to it) so the group is connected");
    const strict = (await scan(cwd, { template_threshold: 0.81 })).answer;
    assert.deepEqual(await structure(cwd, strict), [["README_0.txt"], ["README_1.txt"], ["README_2.txt"]], "0.81 is above 0.8: nothing joins");
    const loose = (await scan(cwd, { template_threshold: 0.5 })).answer;
    assert.equal(loose.template_grouping.groups, 1);
    // base against two (21 / 33) alone
    await put(cwd, "README_1.txt", "unrelated text with different words altogether " + words(30, "zz").join(" ") + "\n");
    const apart = (await scan(cwd, { template_threshold: 0.8 })).answer;
    assert.equal(apart.template_grouping.groups, 3, "similarity below the threshold does not join");
  });
});

test("10,000 notes are grouped within bounds: 5 templates, 2,000 notes each, ids all different", async () => {
  await withCwd(async (cwd) => {
    const templates = [1, 2, 3, 4, 5].map((n) => words(120, `t${n}`));
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    for (let d = 0; d < 100; d++) {
      const dir = join(cwd, "work", "ev", `d${String(d).padStart(3, "0")}`);
      await mkdir(dir, { recursive: true });
      for (let i = 0; i < 100; i++) {
        const k = (d * 100 + i) % 5;
        await writeFile(join(dir, "README.txt".replace("README", `README_${i}`)), note(templates[k]!, hex(8), "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"));
      }
    }
    const began = Date.now();
    const child = spawnSync("python3", ["-c", "import resource,subprocess,sys,json\nr=subprocess.run([sys.executable,sys.argv[1]],input=sys.argv[2].encode(),capture_output=True)\nprint(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)\nsys.stdout.flush()\nsys.stdout.buffer.write(r.stdout)", NOTES, JSON.stringify({ root: "work/ev", limit: 200 })], { cwd, encoding: "utf8", maxBuffer: 1 << 28, timeout: 600_000, env: { ...process.env, AGENT_ID: "s1" } });
    const [rss, ...rest] = child.stdout.split("\n");
    const answer = JSON.parse(rest.join("\n")) as Answer;
    assert.ok((Date.now() - began) / 1000 < 400);
    assert.equal(answer.status, "complete", answer.status_basis);
    assert.equal(answer.template_grouping.notes_grouped, 10000);
    assert.equal(answer.template_grouping.groups, 5);
    assert.deepEqual(answer.template_groups.map((g) => g.copies), [2000, 2000, 2000, 2000, 2000]);
    assert.equal(answer.template_groups[0]!.member_note_ids.length, 20, "the row shows 20 members and the page holds every one");
    assert.equal(answer.pages.template_group_members!.matched, 10000);
    assert.equal(answer.template_groups[0]!.directories.length, 20);
    assert.ok(answer.template_groups[0]!.directories_total >= 20);
    const rssKb = process.platform === "darwin" ? Number(rss) / 1024 : Number(rss);   // ru_maxrss is in bytes on macOS, in KB on Linux
    assert.ok(rssKb < 500_000, `the tool's resident size was ${rssKb} KB`);
  });
});

test("a binary note, a note with no words, and a partly scanned note are not grouped and are counted", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "README_bin.txt", Buffer.concat([Buffer.from("data"), Buffer.alloc(100), randomBytes(200)]));
    await put(cwd, "README_empty_words.txt", "!!! ??? ...\n");
    await put(cwd, "README_ok.txt", note(words(40), hex(8), onionOf()));
    const { answer } = await scan(cwd);
    assert.equal(answer.template_grouping.binary_notes_are_not_grouped, 1);
    assert.equal(answer.template_grouping.notes_not_grouped.no_text, 1);
    assert.equal(answer.template_grouping.notes_grouped, 1);
  });
});

test("a directory named like a value of its note, or holding an identifier, is withheld in the group rows too, and swapping the raw names changes no row", async () => {
  const rows: Array<{ copies: number; total: number; shown: string[] }> = [];
  for (const dirs of [["9F8E7D6C5B4A3210", "1A2B3C4D5E6F7081", "plain"], ["AAAAAAAA11112222", "BBBBBBBB33334444", "plain"]]) {
    await withCwd(async (cwd) => {
      const t = words(50);
      for (const [i, d] of dirs.entries()) {
        await mkdir(join(cwd, "work", "ev", d), { recursive: true });
        // the first note holds the name of its own directory as its personal id: the value rule withholds the name
        await writeFile(join(cwd, "work", "ev", d, "README.txt"), note(t, i === 0 ? dirs[0]! : hex(8), onionOf()));
      }
      const { answer, stdout, stderr } = await scan(cwd);
      const files = await filesUnder(join(cwd, "work", "s1"));
      for (const text of [stdout, stderr, ...Object.values(files)]) for (const d of dirs.filter((x) => x !== "plain")) assert.ok(!text.includes(d), `${d} is on a channel`);
      const group = answer.template_groups[0]!;
      assert.equal(group.directories_total, 3);
      assert.equal(group.directories.filter((d) => d.includes("withheld")).length, 2);
      rows.push({ copies: group.copies, total: group.directories_total, shown: [...group.directories].sort() });
    });
  }
  assert.deepEqual(rows[1], rows[0]);
});

test("template_threshold: hostile values give a JSON refusal and never a traceback", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "README_a.txt", "x\n");
    for (const bad of ["0.2", "1.5", "\"0.8\"", "true", "null", "[0.8]", "NaN", "Infinity", "1e999"]) {
      const child = spawnSync("python3", [NOTES], { cwd, input: `{"root": "work/ev", "template_threshold": ${bad}}`, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
      assert.doesNotMatch(child.stderr, /Traceback/, bad);
      assert.equal((JSON.parse(child.stdout) as { status: string }).status, "failed", bad);
      assert.equal(child.status, 1, bad);
    }
  });
});

const SLOW = String.raw`
import os, runpy, sys, time
_real = os.scandir
def slow(path="."):
    time.sleep(float(os.environ["SLOW_SCANDIR"]))
    return _real(path)
os.scandir = slow
script = sys.argv[1]
sys.argv = [script]
runpy.run_path(script, run_name="__main__")
`;

for (const [signal, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
  test(`${signal} while notes are being grouped: one JSON answer, exit code ${code}, no temporary file left`, async () => {
    await withCwd(async (cwd) => {
      const t = words(50);
      for (let d = 0; d < 40; d++) {
        await mkdir(join(cwd, "work", "ev", `d${d}`), { recursive: true });
        await writeFile(join(cwd, "work", "ev", `d${d}`, "README.txt"), note(t, hex(8), onionOf()));
      }
      const child = spawn("python3", ["-c", SLOW, NOTES], { cwd, env: { ...process.env, AGENT_ID: "s1", SLOW_SCANDIR: "0.15" } });
      const out: Buffer[] = [];
      const err: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => out.push(c));
      child.stderr.on("data", (c: Buffer) => err.push(c));
      const closed = new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
      child.stdin.end(JSON.stringify({ root: "work/ev", limit: 1 }));
      const place = join(cwd, "work", "s1", "tool-output");
      const deadline = Date.now() + 20000;
      while (!((await exists(place)) && (await readdir(place)).length > 0) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
      await new Promise((r) => setTimeout(r, 300));
      child.kill(signal);
      assert.equal(await closed, code, Buffer.concat(err).toString());
      const doc = JSON.parse(Buffer.concat(out).toString()) as Answer;
      assert.equal(doc.status, "failed");
      assert.equal(doc.interrupted, true);
      const left = Object.keys(await filesUnder(join(cwd, "work", "s1"))).filter((n) => n.split("/").pop()!.startsWith("."));
      assert.deepEqual(left, []);
    });
  });
}

test("the manifest states the method, the bounds and the parser, and the source holds them", async () => {
  const manifest = JSON.parse(await readFile(join(NOTES, "..", "manifest.json"), "utf8")) as { description: string; params: Record<string, { description: string }>; version: number };
  const source = await readFile(NOTES, "utf8");
  for (const text of ["ransom_note_scan/4", "3-token shingles", "128 smallest shingle hashes", "65,536 characters", "50,000 notes", "standard error near 0.035", "template_threshold", "after every located indicator span"]) {
    assert.ok(manifest.description.includes(text), text);
  }
  assert.match(source, /PARSER = "ransom_note_scan\/4"/);
  assert.match(source, /TEMPLATE_SKETCH = 128/);
  assert.match(source, /TEMPLATE_CHARS = 65536/);
  assert.match(source, /TEMPLATE_MAX_NOTES = 50000/);
  assert.match(source, /DEFAULT_TEMPLATE_THRESHOLD = 0.8/);
  assert.ok(manifest.params.template_threshold);
  assert.ok(manifest.version >= 10);
  assert.doesNotMatch(source.replace(/"""[\s\S]*?"""/g, "").replace(/^\s*#.*$/gm, ""), /^\s*import (numpy|scipy|sklearn|datasketch)/m);
});
