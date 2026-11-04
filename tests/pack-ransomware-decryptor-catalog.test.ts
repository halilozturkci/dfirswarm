/**
 * ransomware-response: decryptor_catalog. The expected facts are written from what the cited public pages say about each decryptor
 * (its publisher, its prerequisite, its date), not from a run of the tool.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { PACK, filesUnder, tool } from "./ransomware-pack-harness.ts";

const DIR = join(PACK, "decryptor_catalog");
const CATALOG = join(DIR, "run.py");
const MANIFEST = join(DIR, "manifest.json");

type J = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

async function run(cwd: string, args: unknown, env: Record<string, string> = {}, script = CATALOG): Promise<{ a: J; stdout: string; stderr: string; code: number | null }> {
  const out = await tool(script, cwd, args, env);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return { a: JSON.parse(out.stdout) as J, stdout: out.stdout, stderr: out.stderr, code: out.code };
}

async function copyTool(): Promise<string> {
  const target = join(await mkdtemp(join(tmpdir(), "catalog-tool-")), "decryptor_catalog");
  await cp(DIR, target, { recursive: true });
  return target;
}

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

const rowsOf = (a: J): J[] => a.entries as J[];
const entryIds = (a: J): string[] => rowsOf(a).map((r) => r.entry as string);

test("a lookup by family gives the entry of that family, with its publisher, date and sources; names and aliases match in any case", async () => {
  await withCwd(async (cwd) => {
    const expected: Array<[string, string, string, string]> = [
      ["akira", "akira-avast", "Avast (Gen Digital)", "2023-06-29"],
      ["Rhysida", "rhysida-avast", "Avast (Gen Digital)", "2024-02-13"],
      ["PHOBOS", "phobos-8base-npa", "Japan National Police Agency", "2025-07-18"],
      ["8Base", "phobos-8base-npa", "Japan National Police Agency", "2025-07-18"],
      ["black basta", "black-basta-srlabs", "Security Research Labs", "2023-12-30"],
      ["LockBit 3.0", "lockbit-three-japan-police", "", ""],
    ];
    for (const [name, id, publisher, date] of expected) {
      const { a } = await run(cwd, { hypotheses: [name] });
      assert.equal(a.status, "complete", a.status_basis);
      assert.equal(a.result, "entries_found", name);
      assert.deepEqual(entryIds(a), [id], name);
      const row = rowsOf(a)[0];
      assert.ok(row.publisher.startsWith(publisher), name);
      if (date) assert.equal(row.publication.date, date, name);
      assert.ok(row.sources.length >= 1 && row.acquisition.redistributed_here === false);
      assert.equal(row.checked_on, "2026-11-04");
      assert.ok(a.sources.length >= 1 && a.sources.every((s: J) => s.retrieved === "2026-11-04" && s.title));
    }
  });
});

test("a lookup by variant says whether the sources state the tool for that variant", async () => {
  await withCwd(async (cwd) => {
    const status = async (family: string, variant?: string): Promise<string> => rowsOf((await run(cwd, { hypotheses: [variant ? { family, variant } : family] })).a)[0].variant_status;
    assert.equal(await status("akira", "akira-original"), "stated_for_this_variant");
    assert.equal(await status("akira", "akira-v2-akiranew"), "not_stated_for_this_variant");
    assert.equal(await status("akira"), "variant_not_given");
    assert.equal(await status("phobos", "phobos-8base"), "stated_for_this_variant");
    assert.equal(await status("phobos", "phobos-core"), "stated_for_this_variant");
    assert.equal(await status("rhysida", "rhysida-2023"), "source_names_no_versions");
    assert.equal(await status("black-basta", "black-basta-basta-extension"), "source_names_no_versions");
    const two = (await run(cwd, { hypotheses: [{ family: "akira", variant: "akira-original" }, { family: "akira", variant: "akira-v2-akiranew" }] })).a;
    assert.deepEqual(rowsOf(two).map((r) => [r.hypothesis_position, r.variant_status]), [[0, "stated_for_this_variant"], [1, "not_stated_for_this_variant"]]);
  });
});

test("an entry whose prerequisites are not met says so, one that is met says so, and the rest is unknown", async () => {
  await withCwd(async (cwd) => {
    const akira = async (extra: J): Promise<J> => rowsOf((await run(cwd, { hypotheses: ["akira"], ...extra })).a)[0];
    const none = await akira({});
    assert.equal(none.prerequisites_status, "unknown");
    assert.deepEqual(none.prerequisites.map((p: J) => [p.kind, p.status]), [["original_and_encrypted_pair", "unknown"], ["memory_for_password_cracking", "unknown"]]);
    const lacking = await akira({ lack: ["original_and_encrypted_pair"], have: ["memory_for_password_cracking"] });
    assert.equal(lacking.prerequisites_status, "not_met");
    assert.deepEqual(lacking.prerequisites.map((p: J) => p.status), ["not_met", "met"]);
    const met = await akira({ have: ["original_and_encrypted_pair", "memory_for_password_cracking"] });
    assert.equal(met.prerequisites_status, "all_met");
    const partial = await akira({ have: ["original_and_encrypted_pair"] });
    assert.equal(partial.prerequisites_status, "unknown");
    const basta = rowsOf((await run(cwd, { hypotheses: ["black-basta"], lack: ["known_plaintext_64_bytes"] })).a)[0];
    assert.equal(basta.prerequisites_status, "not_met");
    assert.equal(basta.prerequisites[0].kind, "known_plaintext_64_bytes");
    assert.equal((await run(cwd, { hypotheses: ["akira"], have: ["a_kind_nobody_listed"] })).code, 1);
    assert.equal((await run(cwd, { hypotheses: ["akira"], have: ["original_and_encrypted_pair"], lack: ["original_and_encrypted_pair"] })).code, 1);
  });
});

test("an unknown family answers no_entry_in_snapshot in the manifest's wording, and the name is not printed", async () => {
  await withCwd(async (cwd) => {
    const manifest = JSON.parse(await readFile(MANIFEST, "utf8")) as J;
    const quoted = /`(No entry in this snapshot is not "no decryptor exists"\.)`/.exec(manifest.description);
    assert.ok(quoted, "the manifest fixes the wording between backticks");
    const { a, stdout } = await run(cwd, { hypotheses: ["C4N4RY-family-ab12cd34ef56", { family: "akira", variant: "C4N4RY-variant" }, "unknownlocker"] });
    assert.equal(a.result, "entries_found");
    assert.deepEqual(a.no_entry.map((n: J) => [n.hypothesis_position, n.result, n.statement]), [[0, "no_entry_in_snapshot", quoted[1]], [2, "no_entry_in_snapshot", quoted[1]]]);
    assert.ok(a.statement.startsWith(quoted[1]));
    assert.equal(a.hypotheses.without_entry, 2);
    assert.ok(!stdout.includes("C4N4RY") && !stdout.includes("unknownlocker"));
    const only = (await run(cwd, { hypotheses: ["unknownlocker"] })).a;
    assert.equal(only.result, "no_entry_in_snapshot");
    assert.deepEqual(only.entries, []);
    assert.equal(only.status, "complete");
    assert.match(only.statement, /not "no decryptor exists"/);
  });
});

test("a snapshot or an entry past its freshness date is stale and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    assert.equal((await run(cwd, { hypotheses: ["akira"], as_of: "2027-05-03" })).a.status, "complete");
    const old = (await run(cwd, { hypotheses: ["akira"], as_of: "2027-05-04" })).a;
    assert.equal(old.status, "partial");
    assert.equal(old.reference_set.stale, true);
    assert.equal(rowsOf(old)[0].stale, true);
    const copy = await copyTool();
    try {
      await editReference(copy, (doc) => {
        doc.entries.find((e: J) => e.id === "akira-avast").fresh_until = "2026-12-01";
      });
      const out = (await run(cwd, { hypotheses: ["akira", "rhysida"], as_of: "2027-01-10" }, {}, join(copy, "run.py"))).a;
      assert.equal(out.reference_set.stale, false);
      assert.equal(out.status, "partial");
      assert.match(out.status_basis, /entries past their freshness date: akira-avast/);
      assert.deepEqual(Object.fromEntries(rowsOf(out).map((r) => [r.entry, r.stale])), { "akira-avast": true, "rhysida-avast": false });
      assert.equal((await run(cwd, { hypotheses: ["rhysida"], as_of: "2027-01-10" }, {}, join(copy, "run.py"))).a.status, "complete");
    } finally {
      await rm(copy, { recursive: true, force: true });
    }
    assert.equal((await run(cwd, { hypotheses: ["akira"], as_of: "tomorrow" })).code, 1);
  });
});

test("a tampered snapshot, an unlisted file, a missing file and a changed manifest are refused", async () => {
  await withCwd(async (cwd) => {
    const intact = (await run(cwd, { hypotheses: ["akira"] })).a;
    assert.ok(intact.reference_set.files_checked_against_manifest.every((f: J) => f.sha256_matches_manifest === true));
    for (const [name, change] of [
      ["entries", async (d: string) => writeFile(join(d, "reference", "entries.json"), (await readFile(join(d, "reference", "entries.json"), "utf8")).replace("2023-06-29", "2023-06-30"))],
      ["unlisted", async (d: string) => writeFile(join(d, "reference", "extra.json"), "{}")],
      ["missing", async (d: string) => rm(join(d, "reference", "entries.json"))],
      ["manifest", async (d: string) => writeFile(join(d, "reference", "reference-manifest.json"), "{}")],
    ] as Array<[string, (d: string) => Promise<void>]>) {
      const copy = await copyTool();
      try {
        await change(copy);
        const out = await run(cwd, { hypotheses: ["akira"] }, {}, join(copy, "run.py"));
        assert.equal(out.code, 1, name);
        assert.equal(out.a.status, "failed", name);
        assert.equal(out.a.entries, undefined, name);
        assert.equal(out.a.reference_set_used, false, name);
        assert.match(out.a.error, /reference|manifest/, name);
      } finally {
        await rm(copy, { recursive: true, force: true });
      }
    }
    // a set that redistributes, and one whose entry cites a source that is not listed, are malformed even when the manifest agrees
    for (const change of [
      (d: J) => { d.entries[0].acquisition.redistributed_here = true; },
      (d: J) => { d.entries[0].sources.push("S99"); },
    ]) {
      const copy = await copyTool();
      try {
        await editReference(copy, change);
        const out = await run(cwd, { hypotheses: ["akira"] }, {}, join(copy, "run.py"));
        assert.equal(out.a.status, "failed");
        assert.match(out.a.error, /malformed/);
      } finally {
        await rm(copy, { recursive: true, force: true });
      }
    }
  });
});

test("obtained_and_verified is the caller's: null unless it set it, copied as given, and an unknown entry is refused", async () => {
  await withCwd(async (cwd) => {
    assert.equal(rowsOf((await run(cwd, { hypotheses: ["akira"] })).a)[0].obtained_and_verified, null);
    const set = rowsOf((await run(cwd, { hypotheses: ["akira", "rhysida"], obtained_and_verified: { "akira-avast": true, "rhysida-avast": false } })).a);
    assert.deepEqual(set.map((r) => r.obtained_and_verified), [true, false]);
    assert.equal((await run(cwd, { hypotheses: ["akira"], obtained_and_verified: { "no-such-entry": true } })).code, 1);
    assert.equal((await run(cwd, { hypotheses: ["akira"], obtained_and_verified: { "akira-avast": "yes" } })).code, 1);
    const src = await readFile(CATALOG, "utf8");
    assert.ok(!/obtained_and_verified"?\]?\s*[:=]\s*True/.test(src), "the source never sets the flag true");
  });
});

test("it answers with networking unavailable, fetches nothing, executes nothing and uploads nothing", async () => {
  await withCwd(async (cwd) => {
    const src = await readFile(CATALOG, "utf8");
    assert.doesNotMatch(src, /^\s*(import|from)\s+(socket|urllib|http|requests|ftplib|smtplib|ssl|xmlrpc|subprocess)/m);
    for (const word of ["urlopen", "create_connection", "Popen", "os.system", "os.exec", "preflight", "run_to_files"]) assert.ok(!src.includes(word), word);
    const probe = spawnSync("unshare", ["-rn", "python3", "-c", "import socket,sys\ns=socket.socket()\ns.settimeout(2)\ntry:\n    s.connect(('192.0.2.1',80)); sys.exit(1)\nexcept OSError:\n    sys.exit(0)"]);
    if (probe.status === 0) {
      const out = spawnSync("unshare", ["-rn", "python3", CATALOG], { cwd, input: JSON.stringify({ hypotheses: ["akira", "zzz"] }), env: { ...process.env, AGENT_ID: "s1" } });
      assert.equal(out.status, 0, out.stderr.toString());
      const a = JSON.parse(out.stdout.toString()) as J;
      assert.equal(a.status, "complete");
      assert.equal(a.result, "entries_found");
    }
    const proxied = await run(cwd, { hypotheses: ["akira"] }, { http_proxy: "http://127.0.0.1:9", https_proxy: "http://127.0.0.1:9" });
    assert.equal(proxied.a.status, "complete");
  });
});

test("the shipped snapshot is dated, sourced and reviewed, ships no executable, and links to pages, not to files", async () => {
  const doc = JSON.parse(await readFile(join(DIR, "reference", "entries.json"), "utf8")) as J;
  const manifest = JSON.parse(await readFile(join(DIR, "reference", "reference-manifest.json"), "utf8")) as J;
  assert.equal(manifest.files["entries.json"], sha(await readFile(join(DIR, "reference", "entries.json"))));
  assert.deepEqual(await readdir(join(DIR, "reference")), ["entries.json", "reference-manifest.json"]);
  assert.equal(doc.set.licence, "AGPL-3.0-or-later");
  assert.ok(doc.set.fresh_until > doc.set.snapshot_date);
  for (const [sid, s] of Object.entries(doc.sources) as Array<[string, J]>) {
    assert.match(s.url, /^https:\/\//, sid);
    assert.doesNotMatch(s.url, /\.(exe|zip|msi|pdf|7z|tar|gz|dll|py)$/i, `${sid} is a page, not a file`);
    assert.match(s.retrieved, /^2026-\d{2}-\d{2}$/, sid);
  }
  assert.ok(doc.entries.length >= 3);
  for (const e of doc.entries as J[]) {
    assert.match(e.reviewed_on, /^\d{4}-\d{2}-\d{2}$/);
    assert.ok(e.fresh_until > e.reviewed_on);
    assert.ok(e.sources.length >= 1 && e.sources.every((s: string) => s in doc.sources));
    assert.equal(e.acquisition.redistributed_here, false);
    assert.ok(e.prerequisites.length >= 1 && e.limitations.length >= 1 && e.publisher && e.tool_name);
    assert.ok(["weak", "moderate", "strong"].includes(e.evidence_strength));
    for (const p of e.prerequisites as J[]) assert.ok(p.kind in doc.prerequisite_kinds);
  }
  const text = JSON.stringify(doc);
  assert.doesNotMatch(text, /https?:\/\/[^"]*\.(exe|zip|msi)/i);
});

test("a hostile request is refused with JSON: wrong types, too many hypotheses, too long a name, a clock beyond the manifest's", async () => {
  await withCwd(async (cwd) => {
    for (const args of [{}, { hypotheses: [] }, { hypotheses: "akira" }, { hypotheses: [7] }, { hypotheses: [{ family: "akira", other: 1 }] }, { hypotheses: ["x".repeat(201)] },
      { hypotheses: Array.from({ length: 1001 }, () => "akira") }, { hypotheses: ["akira"], max_seconds: 101 }, { hypotheses: ["akira"], limit: 0 }, { hypotheses: ["akira"], have: "x" }]) {
      const out = await run(cwd, args);
      assert.equal(out.code, 1, JSON.stringify(args).slice(0, 80));
      assert.equal(out.a.status, "failed");
    }
    const bad = await tool(CATALOG, cwd, "not an object");
    assert.equal(JSON.parse(bad.stdout).status, "failed");
    const extra = (await run(cwd, { hypotheses: ["akira"], mystery: 1 })).a;
    assert.deepEqual(extra.unrecognised_parameters, ["mystery"]);
  });
});

test("tables longer than limit are written whole, and a rerun with a smaller table keeps the earlier larger file", async () => {
  await withCwd(async (cwd) => {
    const all = ["akira", "rhysida", "phobos", "lockbit", "black-basta"];
    const big = (await run(cwd, { hypotheses: all, limit: 2 })).a;
    assert.equal(big.truncated, true);
    assert.equal(big.entries.length, 2);
    const first = big.pages.entries.all_results as string;
    const rows = (await readFile(join(cwd, first), "utf8")).trimEnd().split("\n");
    assert.equal(rows.length, 5);
    const before = await readFile(join(cwd, first), "utf8");
    const small = (await run(cwd, { hypotheses: ["akira", "rhysida", "phobos"], limit: 2 })).a;
    const second = small.pages.entries.all_results as string;
    assert.notEqual(second, first);
    assert.equal(await readFile(join(cwd, first), "utf8"), before);
    assert.equal((await readFile(join(cwd, second), "utf8")).trimEnd().split("\n").length, 3);
    const names = await filesUnder(join(cwd, "work"));
    assert.ok(Object.keys(names).length >= 2);
  });
});

test("a stop signal ends the tool with one JSON answer and exit 128 + the signal", async () => {
  await withCwd(async (cwd) => {
    // the tool waits for the rest of its input; the signal arrives after its handlers are in
    const child = spawn("python3", [CATALOG], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stdin.write('{"hypotheses": [');
    await new Promise((r) => setTimeout(r, 1500));
    child.kill("SIGTERM");
    const code = await new Promise<number | null>((r) => child.on("close", (c) => r(c)));
    assert.equal(code, 143);
    const a = JSON.parse(Buffer.concat(out).toString()) as J;
    assert.equal(a.status, "failed");
    assert.equal(a.interrupted, true);
  });
});

test("the manifest declares the clock below its timeout, the wording, the stop window and no secret output", async () => {
  const m = JSON.parse(await readFile(MANIFEST, "utf8")) as J;
  assert.equal(m.timeout_seconds, 120);
  assert.equal(m.secret_output, undefined, "it reads no note and no value");
  assert.match(m.params.max_seconds.description, /default 60, at most 100; the manifest's timeout is 120/);
  assert.match(m.description, /never fetches/);
  assert.match(m.description, /never sets it true/);
  assert.match(m.description, /a stop signal in that window can end the tool with no JSON answer at all/);
  assert.match(m.description, /SIGKILL cannot be caught/);
  assert.equal(m.sha256, sha(await readFile(CATALOG)));
  JSON.parse(m.example);
  assert.match(await readFile(CATALOG, "utf8"), /DEFAULT_SECONDS, MAX_SECONDS = 60, 100/);
});
