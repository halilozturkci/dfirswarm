/**
 * triage-collection: the findings of the post-merge review of the manifest tools and the collection-intake recipe, one test per
 * finding. Every test here fails on the code it replaced (TRIAGE_TOOLS names another copy of the tools and TRIAGE_RECIPE another copy
 * of the recipe, to show it):
 *   - a plain tar cut where a member header should start, or inside a header, was read as a finished archive (status complete, and
 *     the members after the cut were "missing");
 *   - `requested` called a target "recorded_not_delivered" from an incomplete census, and a question's statement said "the delivery
 *     holds nothing under these patterns" over a census that could not list a directory;
 *   - collection_manifest_parse and the recipe printed the sha256, md5 and sha1 that a Velociraptor upload record keeps in `fields`
 *     for a credential store;
 *   - verify called a file an ambiguous record may name "unexpected" while path_map called it "no record names it";
 *   - the recipe said complete with an archive inside the archive that it did not open, had no clock inside a member of a tar, and
 *     kept every marked record on disk with no total bound.
 * Every digest here is of a made-up byte string; nothing is read back from a tool to build a fixture.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet } from "./tool-library-harness.ts";
import { KAPE_COPY_HEADER, TOOLS, TRIAGE, asJob, body, caseInsensitiveVolume, filesUnder, kapeCopyRow, put, tableRows, tool, uac3, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const RECIPE = process.env.TRIAGE_RECIPE ?? join(TRIAGE, "recipes", "collection-intake", "run.py");
const PARSE = join(TOOLS, "collection_manifest_parse", "run.py");
const VERIFY = join(TOOLS, "collection_manifest_verify", "run.py");
const MAP = join(TOOLS, "collection_path_map", "run.py");
const COVER = join(TOOLS, "collection_coverage", "run.py");
const isRoot = process.getuid?.() === 0;
const digest = (algorithm: string, data: string | Buffer) => createHash(algorithm).update(data).digest("hex");

async function recipe(args: string[], cwd: string, env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [RECIPE, ...args], { cwd, env: { ...process.env, ...env } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => out.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8") }));
  });
}

const target = (p: string) => JSON.stringify({ paths: [p] });
const cov = async (cwd: string, out: string): Promise<Json> => JSON.parse(await readFile(join(cwd, out, "coverage.json"), "utf8"));
const jsonl = async (path: string): Promise<Json[]> => (await readFile(path, "utf8")).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));

const BUILD = `
import sys, json, io, tarfile, zipfile, gzip
spec = json.load(sys.stdin)
def plain(members, end_blocks):
    # members laid out by hand: a header block and the data padded to 512, then end_blocks zero blocks
    out = b""
    for name, data in members:
        ti = tarfile.TarInfo(name); ti.size = len(data.encode())
        out += ti.tobuf(tarfile.USTAR_FORMAT) + data.encode() + b"\\0" * (-len(data.encode()) % 512)
    return out + b"\\0" * (512 * end_blocks)
kind, path = spec["kind"], spec["path"]
members = spec.get("members", [])
if kind == "tar":
    data = plain(members, spec.get("end_blocks", 2))
    if "cut" in spec: data = data[: spec["cut"]]
    if "cut_after_members" in spec:
        full = plain(members[: spec["cut_after_members"]], 0)
        data = full + (plain(members[spec["cut_after_members"]:], 0)[: spec.get("into_header", 0)])
    if "append" in spec: data += plain(spec["append"], 2)
    open(path, "wb").write(data)
elif kind == "tgz":
    open(path, "wb").write(gzip.compress(plain(members, 2)))
elif kind == "tbz2":
    import bz2
    open(path, "wb").write(bz2.compress(plain(members, 2)))
elif kind == "txz":
    import lzma
    open(path, "wb").write(lzma.compress(plain(members, 2)))
elif kind == "tgz2":
    # two gzip members: the second holds a second tar that a reader which stops after the first never sees
    open(path, "wb").write(gzip.compress(plain(members, 2)) + gzip.compress(plain(spec["append"], 2)))
elif kind == "zip":
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members: z.writestr(name, data)
elif kind == "bigtgz":
    # one member of spec["bytes"] zero bytes, written as a stream
    ti = tarfile.TarInfo("zeros.bin"); ti.size = spec["bytes"]
    with gzip.open(path, "wb", compresslevel=1) as g:
        g.write(ti.tobuf(tarfile.PAX_FORMAT))
        chunk = bytes(1 << 22); left = spec["bytes"]
        while left > 0:
            n = min(left, len(chunk)); g.write(chunk[:n]); left -= n
        g.write(bytes(-spec["bytes"] % 512 + 1024))
`;

async function build(spec: Json): Promise<void> {
  const run = await runPySnippet(BUILD, [], spec);
  assert.equal(run.code, 0, run.stderr);
}

const COPY_LOG = `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\a.txt", "D:\\o\\C\\a.txt", 4).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", digest("sha1", "aaaa"))}\n` +
  `${kapeCopyRow("C:\\b.txt", "D:\\o\\C\\b.txt", 4).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", digest("sha1", "bbbb"))}\n`;
const KAPE_MEMBERS: Array<[string, string]> = [["K/2026_CopyLog.csv", COPY_LOG], ["K/C/a.txt", "aaaa"], ["K/C/b.txt", "bbbb"]];

// ---- T-P1-1: a truncated plain tar --------------------------------------------------------------------------------------------

test("recipe: a plain tar cut where a header should start, or inside a header, is partial and its missing members are not 'missing'", async () => {
  await withCwd(async (cwd) => {
    const cases: Array<[string, Json, RegExp]> = [
      ["boundary", { cut_after_members: 2 }, /no end-of-archive marker/],
      ["mid_header", { cut_after_members: 2, into_header: 100 }, /100 byte\(s\) into a member header/],
      ["one_byte", { cut_after_members: 2, into_header: 1 }, /1 byte\(s\) into a member header/],
      ["only_the_log", { cut_after_members: 1 }, /no end-of-archive marker/],
    ];
    for (const [name, extra, why] of cases) {
      const path = join(cwd, `${name}.tar`);
      await build({ kind: "tar", path, members: KAPE_MEMBERS, ...extra });
      const detect = await recipe(["detect", "--target", target(path)], cwd);
      assert.equal(detect.code, 0, `${name}: ${detect.stdout}`);
      assert.match(JSON.parse(detect.stdout).listing_note, why, `${name}: detect says the tar is cut`);
      const run = await recipe(["run", "--target", target(path), "--out", `o_${name}`], cwd);
      assert.equal(run.code, 0, `${name}: ${run.stdout}`);
      const c = await cov(cwd, `o_${name}`);
      assert.equal(c.status, "partial", `${name}: ${JSON.stringify(c.status_basis)}`);
      assert.match(c.status_basis, why, name);
      const checks = await jsonl(join(cwd, `o_${name}`, "verification.jsonl"));
      assert.ok(!checks.some((r: Json) => r.status === "missing"), `${name}: a member after the cut is not called missing`);
      assert.ok(checks.every((r: Json) => r.status === "matched" || r.status === "unverifiable"), name);
    }
  });
});

test("recipe: a finished tar is complete with one end block, two, or the usual padding; data after the end marker makes it partial", async () => {
  await withCwd(async (cwd) => {
    for (const blocks of [1, 2, 20]) {
      const path = join(cwd, `end${blocks}.tar`);
      await build({ kind: "tar", path, members: KAPE_MEMBERS, end_blocks: blocks });
      const run = await recipe(["run", "--target", target(path), "--out", `o_end${blocks}`], cwd);
      assert.equal(run.code, 0, run.stdout);
      const c = await cov(cwd, `o_end${blocks}`);
      assert.equal(c.status, "complete", `${blocks} end block(s): ${c.status_basis}`);
      assert.deepEqual(c.verification, { matched: 2 });
    }
    const joined = join(cwd, "joined.tar");
    await build({ kind: "tar", path: joined, members: KAPE_MEMBERS, append: [["K2/2027_CopyLog.csv", COPY_LOG]] });
    const run = await recipe(["run", "--target", target(joined), "--out", "o_joined"], cwd);
    assert.equal(run.code, 0, run.stdout);
    const c = await cov(cwd, "o_joined");
    assert.equal(c.status, "partial");
    assert.match(c.status_basis, /follow the tar's end-of-archive marker/);
    // a gzip tar, whole, is complete; cut anywhere it is still not complete
    const tgz = join(cwd, "whole.tgz");
    await build({ kind: "tgz", path: tgz, members: KAPE_MEMBERS });
    assert.equal((await recipe(["run", "--target", target(tgz), "--out", "o_tgz"], cwd)).code, 0);
    assert.equal((await cov(cwd, "o_tgz")).status, "complete");
    // a stream cut in its trailer, or with a second member after it, holds a whole tar inside a stream that is not finished
    for (const kind of ["tgz", "tbz2", "txz"]) {
      const ok = join(cwd, `whole.${kind}`);
      await build({ kind, path: ok, members: KAPE_MEMBERS });
      assert.equal((await recipe(["run", "--target", target(ok), "--out", `o_ok_${kind}`], cwd)).code, 0);
      assert.equal((await cov(cwd, `o_ok_${kind}`)).status, "complete", kind);
      const bytes = await readFile(ok);
      for (const lose of [1, 3, 5, 9]) {
        await put(cwd, `tail${lose}.${kind}`, bytes.subarray(0, bytes.length - lose));
        const dt = await recipe(["detect", "--target", target(join(cwd, `tail${lose}.${kind}`))], cwd);
        assert.equal(dt.code, 0, dt.stdout);
        await recipe(["run", "--target", target(join(cwd, `tail${lose}.${kind}`)), "--out", `o_tail_${kind}${lose}`], cwd);
        const c = await cov(cwd, `o_tail_${kind}${lose}`);
        assert.notEqual(c.status, "complete", `${kind} without its last ${lose} byte(s): ${c.status_basis}`);
        assert.match(c.status_basis, /stream|trailer|end/, `${kind} ${lose}`);
      }
    }
    const two = join(cwd, "two.tgz2");
    await build({ kind: "tgz2", path: two, members: KAPE_MEMBERS, append: [["K2/2027_CopyLog.csv", COPY_LOG]] });
    await recipe(["run", "--target", target(two), "--out", "o_two"], cwd);
    const t2 = await cov(cwd, "o_two");
    assert.equal(t2.status, "partial");
    assert.match(t2.status_basis, /follow the gzip trailer/);
    const whole = await readFile(tgz);
    for (const keep of [0.3, 0.6, 0.9]) {
      const cut = join(cwd, `cut${keep}.tgz`);
      await put(cwd, `cut${keep}.tgz`, whole.subarray(0, Math.floor(whole.length * keep)));
      await recipe(["run", "--target", target(cut), "--out", `o_cut${keep}`], cwd);
      assert.notEqual((await cov(cwd, `o_cut${keep}`)).status, "complete", `a gzip tar cut at ${keep}`);
    }
  });
});

// ---- T-P1-2, T-P1-3: an incomplete census says what it did not examine ---------------------------------------------------------

async function kapeWithHiddenDirectory(cwd: string): Promise<void> {
  await put(cwd, "inputs/c/C/Windows/a.txt", "aaaa");
  await put(cwd, "inputs/c/C/Hidden/h1.txt", "h1");
  await put(cwd, "inputs/c/C/Hidden/h2.dat", "h2");
  await put(cwd, "inputs/c/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n` + [
    kapeCopyRow("C:\\Windows\\a.txt", "D:\\o\\C\\Windows\\a.txt", 4).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", digest("sha1", "aaaa")),
    kapeCopyRow("C:\\Hidden\\h1.txt", "D:\\o\\C\\Hidden\\h1.txt", 2),
    kapeCopyRow("C:\\Hidden\\h2.dat", "D:\\o\\C\\Hidden\\h2.dat", 2),
  ].join("\n") + "\n");
  await put(cwd, "inputs/c/r_SkipLog.csv", "SourceFile,Reason\n");
}

test("coverage: with a directory the census could not list, `requested` and the statement claim no absence", async (t) => {
  if (isRoot) return t.skip("root can list a directory of mode 000");
  await withCwd(async (cwd) => {
    await kapeWithHiddenDirectory(cwd);
    await chmod(join(cwd, "inputs/c/C/Hidden"), 0);
    try {
      const out = body(await tool(COVER, cwd, {
        root: "inputs/c",
        questions: [{ id: "hid", what: "hidden files", source_paths: ["c:/hidden/*"] }, { id: "hid2", delivered_paths: ["c/hidden/*"] }, { id: "none", source_paths: ["*nothing*"] },
          { id: "win", delivered_paths: ["c/windows/*"] }],
        requested: ["c:/hidden/*", "c:/windows/*", "c:/never/*"],
      }));
      assert.equal(out.status, "partial");
      assert.equal(out.census.complete, false);
      const states = out.requested.map((r: Json) => `${r.pattern}=${r.state}`);
      assert.deepEqual(states, ["c:/hidden/*=recorded_delivery_not_decided", "c:/windows/*=delivered", "c:/never/*=unknown_census_incomplete"]);
      const q = Object.fromEntries(out.questions.map((x: Json) => [x.id, x]));
      for (const id of ["hid", "hid2", "none"]) {
        assert.ok(!q[id].state.includes("no_file_and_no_record"), `${id}: no absence is stated`);
        assert.ok(q[id].state.includes("census_incomplete"), id);
        assert.doesNotMatch(q[id].statement, /The delivery holds nothing under these patterns/, id);
        assert.match(q[id].statement, /census of the delivery is incomplete \(1 directory or entry could not be listed or examined\)/, id);
        assert.match(q[id].statement, /not a statement that the delivery holds nothing/, id);
      }
      assert.match(q.hid.statement, /^Question hid \(hidden files\): no listed delivered file matches; 2 record\(s\) of KAPE say a matching file was copied or uploaded\./);
      assert.ok(!q.hid.state.includes("recorded_as_copied_but_not_in_the_delivery"), "the census could not decide the copies absent");
      assert.equal(q.win.delivered_files, 1);
      assert.ok(q.win.state.includes("delivered"));
      // the same questions over a complete census keep their negatives
      await chmod(join(cwd, "inputs/c/C/Hidden"), 0o755);
      const whole = body(await tool(COVER, cwd, { root: "inputs/c", questions: [{ id: "none", source_paths: ["*nothing*"] }], requested: ["c:/never/*"] }));
      assert.deepEqual(whole.questions[0].state, ["no_file_and_no_record"]);
      assert.match(whole.questions[0].statement, /The delivery holds nothing under these patterns/);
      assert.equal(whole.requested[0].state, "neither_delivered_nor_recorded");
    } finally {
      await chmod(join(cwd, "inputs/c/C/Hidden"), 0o755);
    }
  });
});

test("coverage: a complete census still says a record's file is absent, and a record that cannot be read leaves `requested` undecided", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/C/a.txt", "a");
    await put(cwd, "inputs/k/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\a.txt", "D:\\o\\C\\a.txt", 1)}\n${kapeCopyRow("C:\\gone\\x.txt", "D:\\o\\C\\gone\\x.txt", 1)}\n`);
    await put(cwd, "inputs/k/r_SkipLog.csv", "SourceFile,Reason\n");
    const out = body(await tool(COVER, cwd, { root: "inputs/k", questions: [{ id: "g", source_paths: ["c:/gone/*"] }], requested: ["c:/gone/*", "c:/a.txt", "c:/zzz/*"] }));
    assert.deepEqual(out.requested.map((r: Json) => r.state), ["recorded_not_delivered", "delivered", "neither_delivered_nor_recorded"]);
    assert.ok(out.questions[0].state.includes("recorded_as_copied_but_not_in_the_delivery"));
    await put(cwd, "inputs/u/C/a.txt", "a");
    await put(cwd, "inputs/u/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\a.txt", "D:\\o\\C\\a.txt", 1)}\n`);
    const noSkip = body(await tool(COVER, cwd, { root: "inputs/u", questions: [{ id: "q", source_paths: ["*zzz*"] }], requested: ["c:/zzz/*"] }));
    assert.equal(noSkip.requested[0].state, "unknown_records_unread", "a KAPE run with no skip log: a skip row may be missing");
  });
});

// ---- T-P2-1: digests of a credential store in `fields` -------------------------------------------------------------------------

const SAM_BYTES = "regf-sam-hive-of-the-source-host";
const OTHER_BYTES = "ordinary notes file";
const SAM_DIGESTS = { sha256: digest("sha256", SAM_BYTES), md5: digest("md5", SAM_BYTES), sha1: digest("sha1", SAM_BYTES) };
const OTHER_SHA256 = digest("sha256", OTHER_BYTES);

function upload(path: string, stored: string, data: string, extra: Json = {}): string {
  return JSON.stringify({
    _Source: "Windows.KapeFiles.Targets",
    Upload: {
      Path: path, Size: data.length, StoredSize: data.length, StoredName: stored, Accessor: "auto", Components: stored.split("/"),
      sha256: digest("sha256", data), md5: digest("md5", data), Sha1: digest("sha1", data), Hashes: { SHA256: digest("sha256", data) }, ...extra,
    },
  });
}

async function velociraptorTree(cwd: string, root: string): Promise<void> {
  await put(cwd, `${root}/collection_context.json`, "{}");
  await put(cwd, `${root}/uploads/auto/C%3A/Windows/System32/config/SAM`, SAM_BYTES);
  await put(cwd, `${root}/uploads/auto/C%3A/Users/a/notes.txt`, OTHER_BYTES);
  await put(cwd, `${root}/uploads.json`, [
    JSON.stringify({ vfs_path: "auto/C%3A/Windows/System32/config/SAM", file_size: SAM_BYTES.length, uploaded_size: SAM_BYTES.length }),
    JSON.stringify({ vfs_path: "auto/C%3A/Users/a/notes.txt", file_size: OTHER_BYTES.length, uploaded_size: OTHER_BYTES.length }),
  ].join("\n") + "\n");
  await put(cwd, `${root}/results/Windows.KapeFiles.Targets.json`, [
    upload("C:\\Windows\\System32\\config\\SAM", "auto/C%3A/Windows/System32/config/SAM", SAM_BYTES),
    upload("C:\\Users\\a\\notes.txt", "auto/C%3A/Users/a/notes.txt", OTHER_BYTES),
  ].join("\n") + "\n");
  await put(cwd, `${root}/log.json`, JSON.stringify({ level: "INFO", message: "done" }) + "\n");
}

test("parse: the digests a Velociraptor upload record keeps in `fields` for a credential store are withheld, in every output; another file's stay", async () => {
  await withCwd(async (cwd) => {
    await velociraptorTree(cwd, "inputs/v");
    const run = await asJob(PARSE, cwd, { root: "inputs/v", write_values: true });
    const out = body(run);
    const text = [run.stdout, ...(await Promise.all((await filesUnder(cwd)).filter((f) => !f.startsWith("inputs/") && !f.endsWith("-values.jsonl")).map((f) => readFile(join(cwd, f), "utf8").catch(() => ""))))].join("\n");
    for (const [algorithm, value] of Object.entries(SAM_DIGESTS)) assert.ok(!text.includes(value), `the ${algorithm} of the SAM hive is in an output`);
    const rows = await tableRows(cwd, out.tables.records);
    const sam = rows.filter((r: Json) => JSON.stringify(r).includes("SAM"));
    assert.ok(sam.length >= 2, "the SAM rows are there");
    const result = sam.find((r: Json) => r.kind === "upload_result");
    assert.equal(result.fields.sha256.startsWith("<digest of a credential store withheld, 64 characters, W"), true);
    assert.match(result.fields.md5, /withheld, 32 characters/);
    assert.match(result.fields.Sha1, /withheld, 40 characters/);
    assert.match(result.fields.Hashes.SHA256, /withheld, 64 characters/, "a digest nested in the record");
    assert.equal(result.fields.StoredSize, SAM_BYTES.length, "the rest of the record is as the collector wrote it");
    assert.ok(result.flags.includes("digest_withheld_credential_store"));
    assert.equal(result.credential_store_hint, "a Windows account database hive");
    const notes = rows.find((r: Json) => r.kind === "upload_result" && String(r.source_path_claim).endsWith("notes.txt"));
    assert.equal(notes.fields.sha256, OTHER_SHA256, "a file that is not a credential store keeps its digests whole");
    assert.equal(notes.hash_claims.sha256, OTHER_SHA256);
    // the withheld values are for the agent that needs them: they are in the values file of a job run for secrets
    const values = await readFile(join(cwd, "out", "collection-manifest-parse-values.jsonl"), "utf8");
    for (const value of Object.values(SAM_DIGESTS)) assert.ok(values.includes(value), "the value is in the values file");
  });
});

test("verify, path_map and coverage print no digest of a credential store either; the recipe's records.jsonl and inventory carry none", async () => {
  await withCwd(async (cwd) => {
    await velociraptorTree(cwd, "inputs/v");
    for (const [script, args] of [[VERIFY, { root: "inputs/v" }], [MAP, { root: "inputs/v" }], [COVER, { root: "inputs/v", questions: [{ id: "q", source_paths: ["*SAM*"] }] }]] as Array<[string, Json]>) {
      const run = await tool(script, cwd, args);
      body(run);
      const files = (await filesUnder(cwd)).filter((f) => !f.startsWith("inputs/") && !f.startsWith("o/"));
      const text = [run.stdout, ...(await Promise.all(files.map((f) => readFile(join(cwd, f), "utf8").catch(() => ""))))].join("\n");
      for (const value of Object.values(SAM_DIGESTS)) assert.ok(!text.includes(value), `${script}: a digest of the SAM hive is in an output`);
    }
    const members: Array<[string, string]> = [
      ["v/collection_context.json", "{}"],
      ["v/uploads/auto/C%3A/Windows/System32/config/SAM", SAM_BYTES],
      ["v/uploads/auto/C%3A/Users/a/notes.txt", OTHER_BYTES],
      ["v/uploads.json", (await readFile(join(cwd, "inputs/v/uploads.json"), "utf8"))],
      ["v/results/Windows.KapeFiles.Targets.json", await readFile(join(cwd, "inputs/v/results/Windows.KapeFiles.Targets.json"), "utf8")],
      ["v/log.json", JSON.stringify({ level: "INFO", message: "done" }) + "\n"],
    ];
    await build({ kind: "zip", path: join(cwd, "v.zip"), members });
    const run = await recipe(["run", "--target", target(join(cwd, "v.zip")), "--out", "o"], cwd);
    assert.equal(run.code, 0, run.stdout);
    const everything = (await Promise.all((await readdir(join(cwd, "o"))).map((f) => readFile(join(cwd, "o", f), "utf8")))).join("\n");
    for (const value of Object.values(SAM_DIGESTS)) assert.ok(!everything.includes(value), "a digest of the SAM hive is in the recipe's outputs");
    assert.ok(everything.includes(OTHER_SHA256), "the other file's digest is");
    const records = await jsonl(join(cwd, "o", "records.jsonl"));
    assert.match(records.find((r: Json) => r.kind === "upload_result" && String(r.source_path_claim).endsWith("SAM")).fields.md5, /withheld, 32 characters/);
    const checks = await jsonl(join(cwd, "o", "verification.jsonl"));
    assert.ok(checks.every((r: Json) => r.status === "matched"), JSON.stringify(checks.map((r: Json) => r.status)));
  });
});

// ---- T-P2-2: verify, path_map and coverage agree on a file an ambiguous record may name ---------------------------------------

test("verify, path_map and coverage: a file an ambiguous record may name is not 'unexpected', not 'named by no record', not 'hypothesis only'", async () => {
  await withCwd(async (cwd) => {
    // the destination's tail is found only by its file name, at the top of the log's directory: the record cannot be told from this file
    await put(cwd, "inputs/k/x.txt", "xx");
    await put(cwd, "inputs/k/C/other.txt", "o");
    await put(cwd, "inputs/k/stray.txt", "stray");
    await put(cwd, "inputs/k/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\Users\\a\\x.txt", "D:\\o\\C\\Users\\a\\x.txt", 2)}\n${kapeCopyRow("C:\\other.txt", "D:\\o\\C\\other.txt", 1)}\n`);
    const verify = body(await tool(VERIFY, cwd, { root: "inputs/k" }));
    assert.equal(verify.by_status.ambiguous, 1);
    assert.deepEqual(verify.unexpected.map((u: Json) => u.delivered), ["stray.txt"], "only the file no record can name");
    assert.equal(verify.by_status.unexpected, 1);
    assert.equal(verify.denominators.delivered_files_an_ambiguous_record_may_name, 1);
    const map = body(await tool(MAP, cwd, { root: "inputs/k" }));
    const rows = await tableRows(cwd, map.tables.mappings);
    const x = rows.find((r: Json) => r.delivered === "x.txt");
    assert.equal(x.status, "candidate_of_ambiguous_record");
    assert.deepEqual(x.may_be_named_by_records, [1]);
    assert.equal(rows.find((r: Json) => r.delivered === "stray.txt").status, "hypothesis_only");
    const cover = body(await tool(COVER, cwd, { root: "inputs/k", questions: [{ id: "q", delivered_paths: ["*.txt"] }] }));
    const q = cover.questions[0];
    assert.equal(q.delivered_without_a_record, 1, "stray.txt only");
    const matches = await tableRows(cwd, cover.tables.matches);
    assert.equal(matches.find((m: Json) => m.delivered === "x.txt" && m.match === "delivered_file").may_be_named_by_an_ambiguous_record, true);
  });
});

test("verify and path_map: case twins an ambiguous record names are neither 'unexpected' nor 'hypothesis only' (where the file system tells them apart)", async (t) => {
  await withCwd(async (cwd) => {
    if (await caseInsensitiveVolume(join(cwd, "probe"))) return t.skip("this file system folds case");
    await put(cwd, "inputs/c/C/Docs/Dup.txt", "1");
    await put(cwd, "inputs/c/C/Docs/dup.txt", "2");
    await put(cwd, "inputs/c/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\Docs\\Dup.txt", "D:\\o\\C\\Docs\\Dup.txt", 1)}\n`);
    const verify = body(await tool(VERIFY, cwd, { root: "inputs/c" }));
    assert.equal(verify.by_status.ambiguous, 1);
    assert.equal(verify.by_status.unexpected, 0);
    const map = body(await tool(MAP, cwd, { root: "inputs/c" }));
    const rows = await tableRows(cwd, map.tables.mappings);
    assert.deepEqual(rows.filter((r: Json) => r.delivered.startsWith("C/Docs/")).map((r: Json) => r.status), ["candidate_of_ambiguous_record", "candidate_of_ambiguous_record"]);
  });
});

// ---- T-P2-3: an archive inside the archive ---------------------------------------------------------------------------------------

test("recipe: an archive inside the archive that may hold records makes the run partial and is named; a collected file that is an archive does not", async () => {
  await withCwd(async (cwd) => {
    await build({ kind: "zip", path: join(cwd, "inner.zip"), members: [["K/2026_CopyLog.csv", COPY_LOG]] });
    const inner = await readFile(join(cwd, "inner.zip"));
    // 1. a skip log beside an inner zip: the records are only in the inner archive
    await runPySnippet(`import zipfile,sys
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("outer/2026_SkipLog.csv", "SourceFile,Reason\\r\\n")
    z.writestr("outer/inner.zip", open(sys.argv[2], "rb").read())`, [join(cwd, "nested.zip"), join(cwd, "inner.zip")], null);
    const nested = await recipe(["run", "--target", target(join(cwd, "nested.zip")), "--out", "o_nested"], cwd);
    assert.equal(nested.code, 0, nested.stdout);
    const c = await cov(cwd, "o_nested");
    assert.equal(c.status, "partial");
    assert.match(c.status_basis, /1 archive\(s\) inside the archive were not opened and may hold records: outer\/inner\.zip/);
    assert.equal(c.nested_archives_not_opened_and_not_collected_files_total, 1);
    assert.equal(c.nested_archives_not_opened_and_not_collected_files[0].name, "outer/inner.zip");
    // 2. archives that are the source host's own files: below [root], and named by a record as a delivered file
    const log = `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\Users\\a\\data.zip", "D:\\o\\C\\Users\\a\\data.zip", inner.length).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", digest("sha1", inner))}\n`;
    await runPySnippet(`import zipfile,sys
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("K/2026_CopyLog.csv", sys.argv[2]); z.writestr("K/C/Users/a/data.zip", open(sys.argv[3], "rb").read())
    z.writestr("U/uac.log", sys.argv[4]); z.writestr("U/[root]/var/log/syslog.1.gz", b"\\x1f\\x8b")`, [join(cwd, "collected.zip"), log, join(cwd, "inner.zip"), `${uac3("INF", "start")}\n`], null);
    const collected = await recipe(["run", "--target", target(join(cwd, "collected.zip")), "--out", "o_collected"], cwd);
    assert.equal(collected.code, 0, collected.stdout);
    const d = await cov(cwd, "o_collected");
    assert.equal(d.status, "complete", d.status_basis);
    assert.equal(d.nested_archives_total, 2, "both are still named");
    assert.equal(d.nested_archives_not_opened_and_not_collected_files_total, 0);
    assert.match(d.status_basis, /2 archive\(s\) inside the archive are files the collector copied from the source host/);
  });
});

// ---- T-P2-4: a clock inside a member -----------------------------------------------------------------------------------------------

test("recipe detect: a member that takes longer to read than the detect clock ends the listing as 'could not tell'", async () => {
  await withCwd(async (cwd) => {
    const path = join(cwd, "big.tgz");
    await build({ kind: "bigtgz", path, bytes: 600 * 1024 * 1024 });
    const started = Date.now();
    const detect = await recipe(["detect", "--target", target(path)], cwd, { COLLECTION_INTAKE_DETECT_SECONDS: "0.05" });
    const seconds = (Date.now() - started) / 1000;
    assert.equal(detect.code, 2, detect.stdout);
    assert.match(JSON.parse(detect.stdout).why, /the listing stopped \(the detect time limit\): could not tell/);
    assert.ok(seconds < 30, `the listing stopped on the clock (${seconds}s)`);
  });
});

// ---- T-P2-5: the records kept at once are bounded ------------------------------------------------------------------------------------

test("recipe: the records kept on disk at once have a total bound; a record that would pass it is named, not parsed, and the run is partial", async () => {
  await withCwd(async (cwd) => {
    const line = `${uac3("INF", "x".repeat(60))}\n`;
    const log = line.repeat(Math.ceil(300000 / line.length));       // about 300 KB
    const members: Array<[string, string]> = [];
    for (const n of [1, 2, 3, 4, 5, 6]) members.push([`r${n}/uac.log`, log]);
    await build({ kind: "zip", path: join(cwd, "many.zip"), members });
    const run = await recipe(["run", "--target", target(join(cwd, "many.zip")), "--out", "o"], cwd, { COLLECTION_INTAKE_KEPT_TOTAL_BYTES: String(800 * 1000) });
    assert.equal(run.code, 0, run.stdout);
    const c = await cov(cwd, "o");
    assert.equal(c.status, "partial");
    assert.ok(c.records_kept_bytes <= 800 * 1000, `kept ${c.records_kept_bytes}`);
    assert.equal(c.records_kept_bytes, 2 * Buffer.byteLength(log), "whole records only: two fit, none is cut");
    assert.deepEqual(c.records_not_kept_total_cap.map((x: Json) => x.name), ["r3/uac.log", "r4/uac.log", "r5/uac.log", "r6/uac.log"]);
    assert.match(c.status_basis, /4 collector record\(s\) were not kept or parsed because the records kept at once would have passed 800000 bytes: r3\/uac\.log, r4\/uac\.log/);
    const units = JSON.parse(await readFile(join(cwd, "o", "units.json"), "utf8"));
    const statuses = units.units.flatMap((u: Json) => u.sources.map((s: Json) => `${s.log}=${s.status}`));
    assert.equal(statuses.filter((s: string) => s.endsWith("=parsed")).length, 2, JSON.stringify(statuses));
    assert.ok(statuses.some((s: string) => s.startsWith("r3/uac.log=unreadable")));
    const inventory = await readFile(join(cwd, "o", "inventory.tsv"), "utf8");
    assert.equal(inventory.trim().split("\n").length, 7, "every member is in the inventory with its digest, kept or not");
    assert.deepEqual((await readdir(join(cwd, "o"))).filter((f) => f.startsWith(".")), [], "nothing is left behind");
  });
});

test("recipe: a record the readers would refuse as binary is not kept on disk, and is still reported unsupported for the same reason", async () => {
  await withCwd(async (cwd) => {
    const members: Array<[string, string]> = [];
    for (const n of [1, 2, 3]) members.push([`r${n}/uac.log`, `${uac3("INF", "x")}\n`.repeat(150) + "\u0000".repeat(5000)]);
    members.push(["r4/uac.log", "\u0000".repeat(300000)]);
    await build({ kind: "zip", path: join(cwd, "bin.zip"), members });
    const run = await recipe(["run", "--target", target(join(cwd, "bin.zip")), "--out", "o"], cwd);
    assert.equal(run.code, 0, run.stdout);
    const c = await cov(cwd, "o");
    assert.equal(c.status, "partial");
    assert.equal(c.records_kept_bytes, 3 * (`${uac3("INF", "x")}\n`.length * 150 + 5000), "only the three that have no NUL in their first 4 KiB are kept");
    const units = JSON.parse(await readFile(join(cwd, "o", "units.json"), "utf8"));
    const sources = units.units.flatMap((u: Json) => u.sources.map((s: Json) => s));
    const r4 = sources.find((s: Json) => s.log === "r4/uac.log");
    assert.equal(r4.status, "unsupported");
    assert.match(r4.reason, /NUL bytes in its first 4 KiB/);
  });
});

// ---- T-P2-6: the skill says what the tool does ----------------------------------------------------------------------------------------

test("the coverage skill states the three-way split the tool makes, and that a negative needs a complete census", async () => {
  const skill = await readFile(join(TRIAGE, "skills", "coverage", "delivered-collection.md"), "utf8");
  assert.match(skill, /census_incomplete/);
  assert.match(skill, /recorded_delivery_not_decided/);
  assert.match(skill, /unknown_census_incomplete/);
  assert.doesNotMatch(skill, /\*neither delivered nor recorded\*\./, "the old unconditional list item");
});
