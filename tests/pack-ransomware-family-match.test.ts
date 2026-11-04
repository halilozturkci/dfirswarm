/**
 * ransomware-response: ransomware_family_match. The fixtures are written from what the cited public pages say about each family (the
 * extension and the note name), not from a run of the tool; the notes and values files are synthetic, with canaries in them.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { PACK, filesUnder, tool } from "./ransomware-pack-harness.ts";

const DIR = join(PACK, "ransomware_family_match");
const MATCH = join(DIR, "run.py");
const MANIFEST = join(DIR, "manifest.json");

type J = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

async function run(cwd: string, args: unknown, env: Record<string, string> = {}, script = MATCH): Promise<{ a: J; stdout: string; stderr: string; code: number | null }> {
  const out = await tool(script, cwd, args, env);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return { a: JSON.parse(out.stdout) as J, stdout: out.stdout, stderr: out.stderr, code: out.code };
}

/** A values file of ransom_note_scan, written from its documented row shape: one note_preview row per note, then indicator rows. */
async function values(cwd: string, notes: Array<{ id: string; file: string }>, name = "vals.jsonl"): Promise<string> {
  const rows: J[] = [];
  let f = 1;
  for (const n of notes) {
    rows.push({ finding_id: n.id, note_id: n.id, file: n.file, offset: 0, kind: "note_preview", encoding: "utf-8", validation: null, value: "preview CANARY-PREVIEW-77aa" });
    rows.push({ finding_id: `F${String(f++).padStart(6, "0")}`, note_id: n.id, file: n.file, offset: 10, kind: "onion", encoding: "utf-8", validation: null, value: "canaryxyzcanaryxyzcanaryxyz.onion" });
  }
  await writeFile(join(cwd, name), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  return name;
}

const ids = (a: J): string[] => (a.candidates as J[]).map((c) => `${c.entry}/${c.variant}`);
const families = (a: J): string[] => [...new Set((a.candidates as J[]).map((c) => c.entry as string))].sort();

// What the cited pages say (extension, note name) for each family: the fixtures of the shipped entries.
const SHIPPED: Array<{ family: string; ext: string; note: string; support?: string }> = [
  { family: "akira", ext: ".akira", note: "akira_readme.txt" },
  { family: "lockbit", ext: ".lockbit3", note: "Restore-My-Files.txt" },
  { family: "blackcat", ext: ".abc1234", note: "RECOVER-abc1234-FILES.txt" },
  { family: "black-basta", ext: ".basta", note: "readme.txt", support: "single_feature" },
  { family: "rhysida", ext: ".rhysida", note: "CriticalBreachDetected.pdf" },
  { family: "phobos", ext: ".phobos", note: "info.hta" },
  { family: "play", ext: ".PLAY", note: "PLAY_README.txt" },
];

test("each shipped family is a candidate for its extension and note name, and unidentified for neither", async () => {
  await withCwd(async (cwd) => {
    for (const s of SHIPPED) {
      const { a } = await run(cwd, { extensions: [s.ext], note_names: [s.note] });
      assert.equal(a.status, "complete", a.status_basis);
      assert.ok(families(a).includes(s.family), `${s.family}: ${JSON.stringify(ids(a))}`);
      const mine = (a.candidates as J[]).find((c) => c.entry === s.family)!;
      assert.equal(mine.support, s.support ?? "corroborated", s.family);
      assert.ok(mine.features.length >= 2 && mine.sources.length >= 1);
      assert.match(a.statement, /No match here does not mean that an unknown family is absent/);
      assert.equal(a.affiliate_or_actor, "this tool has no such field: a family match never names an affiliate or an actor");
    }
    const none = (await run(cwd, { extensions: [".docx"], note_names: ["notes.txt"] })).a;
    assert.equal(none.outcome, "unidentified");
    assert.deepEqual(none.candidates, []);
    assert.match(none.statement, /does not mean that an unknown family is absent/);
  });
});

test("a note name two families share is reported as ambiguous, and so are two families supported alike", async () => {
  await withCwd(async (cwd) => {
    const weak = (await run(cwd, { note_names: ["ReadMe.TXT"] })).a;
    assert.equal(weak.outcome, "ambiguous");
    assert.deepEqual(weak.tied_families, ["black-basta", "play"]);
    for (const c of weak.candidates as J[]) assert.equal(c.support, "weak_lead");
    const alike = (await run(cwd, { extensions: [".akira", ".rhysida"] })).a;
    assert.equal(alike.outcome, "ambiguous");
    assert.deepEqual(alike.tied_families, ["akira", "rhysida"]);
    assert.ok(alike.contradictions.length === 0, "two extensions of two families are two observations, not a contradiction between kinds");
    const lead = (await run(cwd, { extensions: [".akira"], note_names: ["akira_readme.txt", "readme.txt"] })).a;
    assert.equal(lead.outcome, "leading_candidate");
    assert.equal(lead.candidates[0].entry, "akira");
    assert.ok(families(lead).includes("black-basta"), "the family that is not the leader is listed, not dropped");
  });
});

test("an extension of one variant with a note of another, and of one family with a note of another, are contradictions", async () => {
  await withCwd(async (cwd) => {
    const variants = (await run(cwd, { extensions: [".akira"], note_names: ["akiranew.txt"] })).a;
    assert.ok(variants.contradictions.some((c: J) => c.kind === "features_support_different_variants" && c.between.join() === "extension,note_name"));
    assert.ok(variants.variant_ambiguity.some((v: J) => v.entry === "akira"), "the two variants are supported alike");
    const fam = (await run(cwd, { extensions: [".akira"], note_names: ["PLAY_README.txt"] })).a;
    assert.ok(fam.contradictions.some((c: J) => c.kind === "features_support_different_families"));
    assert.equal(fam.outcome, "leading_candidate", "a strong extension outweighs a note name of one source, and the other family is still listed");
    assert.deepEqual(families(fam), ["akira", "play"]);
    const agree = (await run(cwd, { extensions: [".abc1234"], note_names: ["RECOVER-abc1234-FILES.txt"] })).a;
    assert.equal(agree.outcome, "candidate");
    assert.deepEqual(agree.contradictions, []);
    const other = (await run(cwd, { extensions: [".abc1234"], note_names: ["RECOVER-zzz9999-FILES.txt"] })).a;
    assert.ok(other.contradictions.some((c: J) => c.kind === "note_name_embeds_another_extension"));
    assert.equal(other.candidates[0].support, "single_feature", "the shape alone does not corroborate a note that embeds other text");
    const shapeOnly = (await run(cwd, { extensions: [".abc1234"] })).a;
    assert.equal(shapeOnly.candidates[0].support, "weak_lead");
  });
});

test("observed_on is compared with the dates of the cited sources: before, within, after, and not stated", async () => {
  await withCwd(async (cwd) => {
    const at = async (when: string): Promise<J> => ((await run(cwd, { extensions: [".rhysida"], observed_on: when })).a.candidates as J[])[0].period_check;
    assert.equal((await at("2021-03")).status, "before_cited_sources");
    assert.equal((await at("2024-01-15")).status, "within_cited_sources");
    assert.equal((await at("2026-10")).status, "after_cited_sources");
    const p = await at("2024-01");
    assert.equal(p.cited_sources_dated_from, "2023-05-23");
    assert.equal(p.cited_sources_dated_to, "2025-09-17");
    assert.match(p.note, /not a contradiction/);
    const undated = ((await run(cwd, { extensions: [".abc1234"], observed_on: "2024-01" })).a.candidates as J[])[0].period_check;
    assert.equal(undated.status, "not_stated");
    assert.equal((await run(cwd, { extensions: [".rhysida"], observed_on: "next week" })).code, 1);
  });
});

test("a set or an entry past its freshness date is reported as stale and the answer is partial; a fresh date is complete", async () => {
  await withCwd(async (cwd) => {
    const fresh = (await run(cwd, { extensions: [".akira"], as_of: "2027-05-03" })).a;
    assert.equal(fresh.status, "complete");
    assert.equal(fresh.candidates[0].stale, false);
    const old = (await run(cwd, { extensions: [".akira"], as_of: "2027-05-04" })).a;
    assert.equal(old.status, "partial");
    assert.equal(old.reference_set.stale, true);
    assert.equal(old.candidates[0].stale, true);
    assert.match(old.status_basis, /past its freshness date/);
    // one entry earlier than the set: only a matched stale entry makes the answer partial
    const copy = await copyTool(cwd);
    try {
      await editReference(copy, (doc) => {
        doc.entries.find((e: J) => e.id === "akira").fresh_until = "2026-12-01";
      });
      const stale = (await run(cwd, { extensions: [".akira", ".rhysida"], as_of: "2027-01-10" }, {}, join(copy, "run.py"))).a;
      assert.equal(stale.reference_set.stale, false);
      assert.equal(stale.status, "partial");
      assert.match(stale.status_basis, /matched entries past their freshness date: akira/);
      const byEntry = Object.fromEntries((stale.candidates as J[]).map((c) => [c.entry, c.stale]));
      assert.equal(byEntry.akira, true);
      assert.equal(byEntry.rhysida, false);
      const clean = (await run(cwd, { extensions: [".rhysida"], as_of: "2027-01-10" }, {}, join(copy, "run.py"))).a;
      assert.equal(clean.status, "complete", clean.status_basis);
    } finally {
      await rm(join(copy, ".."), { recursive: true, force: true });
    }
  });
});

async function copyTool(cwd: string): Promise<string> {
  const target = join(await mkdtemp(join(tmpdir(), "match-tool-")), "ransomware_family_match");
  await cp(DIR, target, { recursive: true });
  return target;
}

/** Edit entries.json of a copy and write a manifest that matches it, as a maintainer's regeneration would. */
async function editReference(copy: string, change: (doc: J) => void): Promise<void> {
  const path = join(copy, "reference", "entries.json");
  const doc = JSON.parse(await readFile(path, "utf8")) as J;
  change(doc);
  const text = JSON.stringify(doc, null, 2) + "\n";
  await writeFile(path, text);
  const mpath = join(copy, "reference", "reference-manifest.json");
  const manifest = JSON.parse(await readFile(mpath, "utf8")) as J;
  manifest.files["entries.json"] = sha(text);
  await writeFile(mpath, JSON.stringify(manifest, null, 2) + "\n");
}

test("a tampered reference file, an unlisted file and a missing file are refused, and nothing is matched", async () => {
  await withCwd(async (cwd) => {
    const intact = (await run(cwd, { extensions: [".akira"] })).a;
    assert.equal(intact.status, "complete");
    assert.ok(intact.reference_set.files_checked_against_manifest.every((f: J) => f.sha256_matches_manifest === true));
    for (const [name, change] of [
      ["entries", async (d: string) => writeFile(join(d, "reference", "entries.json"), (await readFile(join(d, "reference", "entries.json"), "utf8")).replace('"akira"', '"akirb"'))],
      ["rules", async (d: string) => writeFile(join(d, "reference", "rules.yar"), (await readFile(join(d, "reference", "rules.yar"), "utf8")) + "\n")],
      ["unlisted", async (d: string) => writeFile(join(d, "reference", "extra.yar"), "rule x { condition: true }\n")],
      ["missing", async (d: string) => rm(join(d, "reference", "rules.yar"))],
      ["manifest", async (d: string) => writeFile(join(d, "reference", "reference-manifest.json"), "{}")],
    ] as Array<[string, (d: string) => Promise<void>]>) {
      const copy = await copyTool(cwd);
      try {
        await change(copy);
        const out = await run(cwd, { extensions: [".akira"] }, {}, join(copy, "run.py"));
        assert.equal(out.code, 1, name);
        assert.equal(out.a.status, "failed", name);
        assert.deepEqual(out.a.candidates, undefined, name);
        assert.match(out.a.error, /reference|manifest/, name);
        assert.equal(out.a.reference_set_used, false, name);
      } finally {
        await rm(join(copy, ".."), { recursive: true, force: true });
      }
    }
    // a set whose entries and manifest agree but whose rule version disagrees with rules.yar is malformed
    const copy = await copyTool(cwd);
    try {
      await editReference(copy, (d) => {
        d.entries.find((e: J) => e.id === "phobos").variants[0].features.find((f: J) => f.match === "yara").rule_version = 2;
      });
      const out = await run(cwd, { extensions: [".phobos"] }, {}, join(copy, "run.py"));
      assert.equal(out.a.status, "failed");
      assert.match(out.a.error, /rule version/);
    } finally {
      await rm(join(copy, ".."), { recursive: true, force: true });
    }
  });
});

test("the shipped reference set is dated, sourced and reviewed, and has no field for an affiliate or an actor", async () => {
  const doc = JSON.parse(await readFile(join(DIR, "reference", "entries.json"), "utf8")) as J;
  const manifest = JSON.parse(await readFile(join(DIR, "reference", "reference-manifest.json"), "utf8")) as J;
  assert.equal(doc.set.licence, "AGPL-3.0-or-later");
  assert.match(doc.set.snapshot_date, /^\d{4}-\d{2}-\d{2}$/);
  assert.ok(doc.set.fresh_until > doc.set.snapshot_date);
  assert.equal(manifest.files["entries.json"], sha(await readFile(join(DIR, "reference", "entries.json"))));
  assert.equal(manifest.files["rules.yar"], sha(await readFile(join(DIR, "reference", "rules.yar"))));
  assert.ok(doc.entries.length >= 5 && doc.entries.length <= 10);
  for (const [sid, s] of Object.entries(doc.sources) as Array<[string, J]>) {
    assert.match(s.url, /^https:\/\//, sid);
    assert.match(s.retrieved, /^2026-\d{2}-\d{2}$/, sid);
    assert.ok(s.title && s.publisher && s.page_dates, sid);
  }
  for (const e of doc.entries as J[]) {
    assert.match(e.reviewed_on, /^\d{4}-\d{2}-\d{2}$/);
    assert.ok(e.fresh_until > e.reviewed_on);
    assert.ok(["weak", "moderate", "strong"].includes(e.evidence_strength));
    for (const v of e.variants as J[]) {
      assert.ok(v.valid_for.length > 10, `${e.id}: valid_for`);
      for (const f of v.features as J[]) assert.ok(f.sources.length >= 1 && f.sources.every((s: string) => s in doc.sources));
    }
  }
  const text = JSON.stringify(doc).toLowerCase();
  for (const key of ["affiliate", "actor", "threat_actor", "group", "attribution"]) {
    const keys = new Set<string>();
    JSON.stringify(doc, (k, v) => (keys.add(k.toLowerCase()), v));
    assert.ok(!keys.has(key), `no field named ${key}`);
  }
  assert.ok(!text.includes("affiliate") && !text.includes("threat actor"), "the set says nothing about who runs a family");
});

test("a canary in a note, in a note name, in an extension and in the values file is printed nowhere, and a text rule's offset is found", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "ev", "dir-c4n4ryV1ctimId99"), { recursive: true });
    const noteA = join(cwd, "ev", "info.txt");
    const noteB = join(cwd, "ev", "dir-c4n4ryV1ctimId99", "READ-ME-c4n4ry1234567890abcd.txt");
    const head = "!!! ";
    await writeFile(noteA, `${head}All of your files are encrypted !!!\nvictim id: c4n4ryV1ctimId99ZZ wallet bc1qcanarycanarycanarycanarycanarycana key 5Kcanarycanarycanarycanary onion canaryxyzcanaryxyzcanaryxyz.onion\n`);
    await writeFile(noteB, "your network has been encrypted\ncontact canary-mail@canary.example\n");
    const v = await values(cwd, [{ id: "N000001", file: noteA }, { id: "N000002", file: noteB }]);
    const ext = ".id[c4n4ryV1ctimId99ZZ].[canary-mail@canary.example].phobos";
    const { a, stdout } = await run(cwd, { values_file: v, extensions: [ext, ".c4n4ry9"], note_names: ["READ-ME-c4n4ry1234567890abcd.txt"] });
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal(a.engine.available, true);
    const phobos = (a.candidates as J[]).find((c) => c.entry === "phobos")!;
    const text = phobos.features.find((f: J) => f.kind === "note_text");
    assert.equal(text.rule, "rm_phobos_note_phrase_1");
    assert.equal(text.rule_version, 1);
    assert.deepEqual(text.note_hits, [{ note_id: "N000001", offsets: [head.length] }]);
    assert.ok(phobos.features.some((f: J) => f.kind === "extension" && f.match === "regex"), "the compound suffix is matched by shape");
    const play = (a.candidates as J[]).find((c) => c.entry === "play")!;
    assert.deepEqual(play.features.find((f: J) => f.kind === "note_text").note_hits, [{ note_id: "N000002", offsets: [0] }]);
    assert.deepEqual(a.note_text_hits.map((h: J) => [h.rule, h.note_id, h.offsets]).sort(), [["rm_phobos_note_phrase_1", "N000001", [4]], ["rm_play_note_phrase_1", "N000002", [0]]]);
    const canaries = ["c4n4ry", "canary", "CANARY", "V1ctim", "bc1q", "5Kcanary", ".onion", "@", "READ-ME", "info.txt", ev(cwd)];
    for (const [where, body] of [["stdout", stdout]]) {
      for (const c of canaries) assert.ok(!(body as string).includes(c), `${c} is in ${where}`);
    }
    assert.equal(a.observations.notes_in_values_file, 2);
    assert.equal(a.observations.notes_given_to_yara, 2);
    assert.equal(a.paths_withheld, 0);
    assert.equal(a.truncated, false);
    // the same, with the rows in the paging file
    const paged = await run(cwd, { values_file: v, extensions: [ext, ".c4n4ry9"], note_names: ["READ-ME-c4n4ry1234567890abcd.txt"], limit: 1 });
    assert.equal(paged.a.truncated, true, "limit 1 puts the rest in the paging file");
    assert.ok(paged.a.pages.candidates.all_results);
    const written = await filesUnder(join(cwd, "work"));
    assert.ok(Object.keys(written).length >= 1);
    for (const [where, body] of [["stdout", paged.stdout], ...Object.entries(written)]) {
      for (const c of canaries) assert.ok(!(body as string).includes(c), `${c} is in ${where}`);
    }
  });
});
const ev = (cwd: string): string => join(cwd, "ev");

test("filters work on the shown text of the reference only: a hidden value as the filter finds nothing and shows no count of it", async () => {
  await withCwd(async (cwd) => {
    const only = (await run(cwd, { extensions: [".akira", ".play", ".rhysida"], filter: "play" })).a;
    assert.deepEqual(families(only), ["play"]);
    assert.equal(only.outcome, "candidate");
    const byLabel = (await run(cwd, { extensions: [".akira", ".play"], filter: "Rust" })).a;
    assert.equal(byLabel.outcome, "unidentified", "a word of no entry's shown text selects nothing");
    const hidden = (await run(cwd, { extensions: [".c4n4ry9", ".akira"], note_names: ["c4n4ry-note.txt"], filter: "c4n4ry" })).a;
    const none = (await run(cwd, { extensions: [".zzz", ".akira"], note_names: ["zzz-note.txt"], filter: "c4n4ry" })).a;
    assert.equal(hidden.outcome, "unidentified");
    assert.deepEqual({ ...hidden, observations: null, reference_set: null }, { ...none, observations: null, reference_set: null }, "the hidden value changes nothing but the observation counts");
    assert.equal((await run(cwd, { extensions: [".akira"], filter: "   " })).code, 1);
  });
});

test("with yara absent the extension and name matching run, the text rules do not, and the answer is partial and says so", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "pathbin"), { recursive: true });
    const { execFileSync } = await import("node:child_process");
    const py = execFileSync("which", ["python3"]).toString().trim();
    await symlink(py, join(cwd, "pathbin", "python3"));
    const note = join(cwd, "info.txt");
    await writeFile(note, "!!! All of your files are encrypted !!!\n");
    const v = await values(cwd, [{ id: "N000001", file: note }]);
    const { a } = await run(cwd, { values_file: v, extensions: [".phobos"] }, { PATH: join(cwd, "pathbin") });
    assert.equal(a.status, "partial");
    assert.equal(a.engine.available, false);
    assert.match(a.status_basis, /yara is not installed/);
    const phobos = (a.candidates as J[])[0];
    assert.equal(phobos.entry, "phobos");
    assert.ok(!phobos.features.some((f: J) => f.kind === "note_text"));
    // nothing for yara to read: no values file, so the answer does not depend on it
    const noNotes = (await run(cwd, { extensions: [".phobos"] }, { PATH: join(cwd, "pathbin") })).a;
    assert.equal(noNotes.status, "complete");
  });
});

test("a yara that hangs is ended at max_seconds with its tree, the answer is partial, and no process is left", async () => {
  await withCwd(async (cwd, bin) => {
    const pidFile = join(cwd, "yara.pid");
    await writeFile(join(bin, "yara"), `#!/bin/sh\nif [ "$1" = "--version" ]; then echo 4.5.0; exit 0; fi\necho $$ > ${pidFile}\nsleep 120 &\necho $! >> ${pidFile}\nwait\n`, { mode: 0o755 });
    const note = join(cwd, "info.txt");
    await writeFile(note, "x\n");
    const v = await values(cwd, [{ id: "N000001", file: note }]);
    const start = Date.now();
    const out = await tool(MATCH, cwd, { values_file: v, extensions: [".phobos"], max_seconds: 3 }, { PATH: `${bin}:${process.env.PATH}` });
    const took = Date.now() - start;
    assert.ok(took < 9000, `took ${took} ms`);
    const a = JSON.parse(out.stdout) as J;
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /time limit|timed out/);
    const pids = (await readFile(pidFile, "utf8")).trim().split("\n").map(Number);
    assert.equal(pids.length, 2);
    for (const pid of pids) {
      let alive = true;
      try {
        process.kill(pid, 0);
      } catch {
        alive = false;
      }
      assert.equal(alive, false, `pid ${pid} is still running`);
    }
  });
});

test("a stop signal ends the tool with one JSON answer, exit 128 + the signal, and kills yara and what it started", async () => {
  await withCwd(async (cwd, bin) => {
    const pidFile = join(cwd, "yara.pid");
    await writeFile(join(bin, "yara"), `#!/bin/sh\nif [ "$1" = "--version" ]; then echo 4.5.0; exit 0; fi\necho $$ > ${pidFile}\nsleep 120 &\necho $! >> ${pidFile}\nwait\n`, { mode: 0o755 });
    const note = join(cwd, "info.txt");
    await writeFile(note, "x\n");
    const v = await values(cwd, [{ id: "N000001", file: note }]);
    const child = spawn("python3", [MATCH], { cwd, env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, AGENT_ID: "s1" }, detached: false });
    const stdout: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdout.push(c));
    child.stdin.end(JSON.stringify({ values_file: v, extensions: [".phobos"], max_seconds: 60 }));
    for (let i = 0; i < 100; i++) {
      try {
        if ((await readFile(pidFile, "utf8")).trim().split("\n").length === 2) break;
      } catch {
        /* not yet */
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    const pids = (await readFile(pidFile, "utf8")).trim().split("\n").map(Number);
    child.kill("SIGTERM");
    const code = await new Promise<number | null>((r) => child.on("close", (c) => r(c)));
    assert.equal(code, 143);
    const a = JSON.parse(Buffer.concat(stdout).toString()) as J;
    assert.equal(a.status, "failed");
    assert.equal(a.interrupted, true);
    await new Promise((r) => setTimeout(r, 300));
    for (const pid of pids) {
      let alive = true;
      try {
        process.kill(pid, 0);
      } catch {
        alive = false;
      }
      assert.equal(alive, false, `pid ${pid} is still running`);
    }
  });
});

test("a hostile values file is read without a crash: bad rows, a very long row, a link as the file, a note that is too large, a note that is a link", async () => {
  await withCwd(async (cwd) => {
    const note = join(cwd, "akira_readme.txt");
    await writeFile(note, "x\n");
    const big = join(cwd, "big.txt");
    await writeFile(big, "!!! All of your files are encrypted !!!\n" + "y".repeat(3000));
    const link = join(cwd, "linknote.txt");
    await symlink(note, link);
    const good = JSON.stringify({ note_id: "N000001", file: note, kind: "note_preview", value: "v" });
    const rows = [
      "not json", "[1,2]", JSON.stringify({ kind: "note_preview", file: 7 }), good,
      JSON.stringify({ note_id: "N000002", file: big, kind: "note_preview", value: "v" }),
      JSON.stringify({ note_id: "N000003", file: link, kind: "note_preview", value: "v" }),
      JSON.stringify({ note_id: "not an id ! ", file: join(cwd, "missing.txt"), kind: "note_preview", value: "v" }),
    ];
    await writeFile(join(cwd, "h.jsonl"), rows.join("\n") + "\n");
    const { a } = await run(cwd, { values_file: "h.jsonl", max_note_bytes: 1000 });
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /3 rows|2 rows|rows of the values file could not be read/);
    assert.match(a.status_basis, /larger than max_note_bytes/);
    assert.match(a.status_basis, /link_not_followed|read_failed/);
    assert.ok(families(a).includes("black-basta") === false);
    assert.equal(a.candidates[0].entry, "akira", "the note name still matches");
    await symlink(join(cwd, "h.jsonl"), join(cwd, "l.jsonl"));
    const linked = await run(cwd, { values_file: "l.jsonl" });
    assert.equal(linked.code, 1);
    assert.match(linked.a.error, /values file could not be read/);
    const dir = await run(cwd, { values_file: cwd });
    assert.equal(dir.code, 1);
    const empty = await run(cwd, {});
    assert.equal(empty.code, 1);
    assert.match(empty.a.error, /name what was observed/);
    const huge = await run(cwd, { extensions: [".x"], max_seconds: 271 });
    assert.equal(huge.code, 1);
    assert.match(huge.a.error, /at most 270/);
  });
});

test("max_notes hands the rest to a name match only and says so; nothing is silently skipped", async () => {
  await withCwd(async (cwd) => {
    const notes = [];
    for (let i = 1; i <= 5; i++) {
      const f = join(cwd, `n${i}.txt`);
      await writeFile(f, "!!! All of your files are encrypted !!!\n");
      notes.push({ id: `N00000${i}`, file: f });
    }
    const v = await values(cwd, notes);
    const { a } = await run(cwd, { values_file: v, max_notes: 2 });
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /3 notes past max_notes \(2\)/);
    const feature = (a.candidates as J[])[0].features.find((f: J) => f.kind === "note_text");
    assert.equal(feature.notes_matched, 2);
    const all = (await run(cwd, { values_file: v })).a;
    assert.equal(all.status, "complete");
    assert.equal(all.candidates[0].features.find((f: J) => f.kind === "note_text").notes_matched, 5);
  });
});

test("the tool fetches nothing and names no network call, and runs nothing but yara", async () => {
  const src = await readFile(MATCH, "utf8");
  assert.doesNotMatch(src, /^\s*(import|from)\s+(socket|urllib|http|requests|ftplib|smtplib|ssl|xmlrpc)/m);
  assert.ok(!src.includes("urlopen") && !src.includes("create_connection"));
  const own = src.split("# END SHARED BACKSTOP")[1];
  const calls = [...own.matchAll(/(?:preflight|run_to_files|spawn)\(\[?([^,\])]+)/g)].map((m) => m[1].trim());
  assert.deepEqual([...new Set(calls)].sort(), ["argv", "binary"]);
  const out = await tool(MATCH, tmpdir(), { extensions: [".akira"] }, { http_proxy: "http://127.0.0.1:9", https_proxy: "http://127.0.0.1:9" });
  assert.equal(JSON.parse(out.stdout).status, "complete");
});

test("the manifest declares secret output required, a clock below its timeout, the stop window and the snapshot statement", async () => {
  const m = JSON.parse(await readFile(MANIFEST, "utf8")) as J;
  assert.equal(m.secret_output, "required");
  assert.equal(m.timeout_seconds, 300);
  assert.match(m.params.max_seconds.description, /default 240, at most 270; the manifest's timeout is 300/);
  assert.match(m.description, /SNAPSHOT/);
  assert.match(m.description, /no match does not mean that an unknown family is absent/);
  assert.match(m.description, /NEVER names an affiliate or an actor/);
  assert.match(m.description, /a stop signal in that window can end the tool with no JSON answer at all/);
  assert.match(m.description, /SIGKILL cannot be caught/);
  assert.match(m.description, /not passed to the tool/);
  assert.match(m.description, /fetches nothing/);
  assert.equal(m.sha256, sha(await readFile(MATCH)));
  JSON.parse(m.example);
  const src = await readFile(MATCH, "utf8");
  assert.match(src, /DEFAULT_SECONDS, MAX_SECONDS = 240, 270/);
});

test("a rerun with a smaller, different table keeps the earlier larger file and names the new one", async () => {
  await withCwd(async (cwd) => {
    const big = (await run(cwd, { extensions: [".akira", ".basta", ".play", ".rhysida"], limit: 1 })).a;
    const first = big.pages.candidates.all_results as string;
    assert.ok(first);
    const before = await readFile(join(cwd, first), "utf8");
    const small = (await run(cwd, { extensions: [".akira", ".basta"], limit: 1 })).a;
    const second = small.pages.candidates.all_results as string;
    assert.ok(second);
    assert.notEqual(second, first);
    assert.equal(await readFile(join(cwd, first), "utf8"), before);
    assert.equal(before.trimEnd().split("\n").length, 5);
    assert.equal((await readFile(join(cwd, second), "utf8")).trimEnd().split("\n").length, 2);
  });
});
