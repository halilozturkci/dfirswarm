/**
 * backup_materialise (mobile-forensics): a derivative layout of an iOS backup, every file tied to its Manifest row.
 *
 * The fixtures are built from the backup format and never from the tool's output: Manifest.db's Files table (fileID, domain,
 * relativePath, flags, file), the keyed archive Apple's NSKeyedArchiver writes in `file` ($archiver, $version, $top with a root UID,
 * $objects), the three plists, and the blobs in `<xx>/<fileID>`. Real iOS 17, 18 and 26 backups are owner-only (OD-17): these
 * fixtures are built from the specification, which the batch's pull request says.
 *
 * To see that a test fails on the code it was written against, point BACKUP_MATERIALISE at a script that is not the tool (the tool is
 * new in this change, so on the base every test fails because the script does not exist).
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, runPySnippet, withCwd } from "./tool-library-harness.ts";

const TOOL = process.env.BACKUP_MATERIALISE ?? join(ROOT, "packs", "mobile-forensics", "tools", "backup_materialise", "run.py");
const AGENT = { AGENT_ID: "s1" };

type Run = { code: number | null; stdout: string; stderr: string };
type Row = {
  file_id: string; file_id_valid: boolean; domain: string; relative_path: string; domain_b64: string | null; path_b64: string | null;
  name_withheld: boolean; selected_by: string; manifest_rowid: number | null; manifest_size: number | null; state: string; blob?: string;
  blob_bytes?: number; sha256?: string; derivative_path?: string; derivative_bytes?: number; reason?: string; size_matches_manifest?: boolean;
  name_collision?: { kind: string }[];
};
type Answer = {
  status: string; status_basis: string; copy_content: boolean; error?: string; interrupted?: string; observations: string[];
  derivative: { root?: string; values_file?: string; values_written?: number; written?: boolean };
  counts: { rows_read: number; rows_selected: number; states: Record<string, number>; copied_files: number; copied_bytes: number; rejected_paths: number;
    name_collisions: number; names_withheld: number; selected_not_kept_max_files: number; companions_found: number };
  entries: Row[]; entry_count: number; collisions: { file_id: string; derivative_path: string }[]; collision_count: number;
  pages: { entries: { rows: number; all_results: string; truncated: boolean } }; stopped_at_row: number | null; paths_withheld: number;
};

const sha256 = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");

/** A backup directory from a spec on stdin. Each entry: id, path, domain, size or data, blob (sharded, flat, none, dir, symlink:<target>), flags, msize. */
const BACKUP = String.raw`
import json, os, plistlib, sqlite3, sys
dest = sys.argv[1]
spec = json.load(sys.stdin)
os.makedirs(dest, exist_ok=True)
def archive(size, mode):
    return plistlib.dumps({"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"root": plistlib.UID(1)},
        "$objects": ["$null", {"Size": size, "Mode": mode, "$class": plistlib.UID(2)}, {"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]}]}, fmt=plistlib.FMT_BINARY)
if spec.get("manifest_plist", True):
    with open(os.path.join(dest, "Manifest.plist"), "wb") as fh:
        body = {"Version": "10.0"}
        if "encrypted" in spec: body["IsEncrypted"] = spec["encrypted"]
        elif not spec.get("no_flag"): body["IsEncrypted"] = False
        plistlib.dump(body, fh)
with open(os.path.join(dest, "Info.plist"), "wb") as fh:
    plistlib.dump({"Device Name": "Fixture Phone"}, fh)
with open(os.path.join(dest, "Status.plist"), "wb") as fh:
    plistlib.dump({"SnapshotState": spec.get("snapshot", "finished")}, fh)
con = sqlite3.connect(os.path.join(dest, "Manifest.db"))
con.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
for e in spec["entries"]:
    data = e["data"].encode() if "data" in e else (b"x" * e.get("size", 10))
    if "fill" in e: data = bytes((i * 7 + e["fill"]) % 256 for i in range(e.get("size", 10)))
    path = e["path"]
    if e.get("path_hex"):
        con.execute("INSERT INTO Files VALUES (?,?,CAST(? AS TEXT),?,?)", (e["id"], e.get("domain", "HomeDomain"), bytes.fromhex(e["path_hex"]), e.get("flags", 1), archive(e.get("msize", len(data)), 0o100644)))
    else:
        con.execute("INSERT INTO Files VALUES (?,?,?,?,?)", (e["id"], e.get("domain", "HomeDomain"), path, e.get("flags", 1), archive(e.get("msize", len(data)), 0o100644)))
    blob = e.get("blob", "sharded")
    if blob == "sharded":
        os.makedirs(os.path.join(dest, e["id"][:2]), exist_ok=True)
        with open(os.path.join(dest, e["id"][:2], e["id"]), "wb") as fh: fh.write(data)
    elif blob == "flat":
        with open(os.path.join(dest, e["id"]), "wb") as fh: fh.write(data)
    elif blob == "dir":
        os.makedirs(os.path.join(dest, e["id"][:2], e["id"]), exist_ok=True)
    elif blob == "fifo":
        os.makedirs(os.path.join(dest, e["id"][:2]), exist_ok=True)
        os.mkfifo(os.path.join(dest, e["id"][:2], e["id"]))
    elif blob.startswith("symlink:"):
        os.makedirs(os.path.join(dest, e["id"][:2]), exist_ok=True)
        os.symlink(blob[8:], os.path.join(dest, e["id"][:2], e["id"]))
con.commit()
con.close()
`;

function fid(n: number, shard = "aa"): string {
  return shard + n.toString(16).padStart(38, "0");
}

async function backup(cwd: string, name: string, spec: Record<string, unknown>): Promise<string> {
  const dir = join(cwd, "work", name);
  const out = await runPySnippet(BACKUP, [dir], spec);
  assert.equal(out.code, 0, out.stderr);
  return dir;
}

function run(cwd: string, args: unknown, env: Record<string, string> = {}): Promise<Run> {
  return runPy(TOOL, cwd, args, undefined, { ...AGENT, ...env });
}

async function asJob(cwd: string, args: unknown, name = "out", job = "j-1", secret = true): Promise<Run> {
  await mkdir(join(cwd, name), { recursive: true });
  return run(cwd, args, { JOB_ID: job, OUT: join(cwd, name), ...(secret ? { SECRET_OUTPUT: "1" } : {}) });
}

function body(out: Run): Answer {
  assert.doesNotMatch(out.stderr, /Traceback/);
  assert.ok(out.code === 0, out.stderr + out.stdout);
  return JSON.parse(out.stdout) as Answer;
}

function failed(out: Run): Answer {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as Answer;
}

async function walk(dir: string): Promise<string[]> {
  const out: string[] = [];
  const names = await readdir(dir, { withFileTypes: true }).catch(() => []);
  for (const e of names) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walk(p)));
    else out.push(p);
  }
  return out.sort();
}

async function jsonl(path: string): Promise<Row[]> {
  const text = await readFile(path, "utf8");
  return text.split("\n").filter(Boolean).map((l) => JSON.parse(l) as Row);
}

/** The path the answer cites, as a file under the job's directory (`store/jobs/<job>/out/...`) or the work directory. */
function cited(cwd: string, name: string, shown: string): string {
  return shown.startsWith("store/jobs/") ? join(cwd, name, shown.split("/out/")[1]) : join(cwd, shown);
}

test("it lays out the files under the domain and path the phone knew, every one tied to its Manifest row, with the hash of the blob", async () => {
  await withCwd(async (cwd) => {
    const data = [Buffer.from("sms body"), Buffer.from("notes body ".repeat(500)), Buffer.alloc(3 * 1024 * 1024 + 17, 0x78)];
    const dir = await backup(cwd, "plain", { entries: [
      { id: fid(1), path: "Library/SMS/sms.db", data: data[0].toString() },
      { id: fid(2, "bb"), domain: "AppDomain-com.example.notes", path: "Documents/notes.sqlite", data: data[1].toString() },
      { id: fid(3, "cc"), path: "Library/Big/big.bin", blob: "flat", size: data[2].length },
    ] });
    const answer = body(await asJob(cwd, { path: dir, all: true, copy_content: true }));
    assert.equal(answer.status, "complete", answer.status_basis);
    assert.equal(answer.counts.copied_files, 3);
    const byId = Object.fromEntries(answer.entries.map((r) => [r.file_id, r]));
    const sms = byId[fid(1)];
    assert.equal(sms.domain, "HomeDomain");
    assert.equal(sms.relative_path, "Library/SMS/sms.db");
    assert.equal(Buffer.from(sms.domain_b64!, "base64").toString(), "HomeDomain");
    assert.equal(Buffer.from(sms.path_b64!, "base64").toString(), "Library/SMS/sms.db");
    assert.equal(sms.state, "copied");
    assert.equal(sms.sha256, sha256(data[0]));
    assert.equal(sms.derivative_path, "files/HomeDomain/Library/SMS/sms.db");
    assert.equal(sms.manifest_size, data[0].length);
    assert.equal(sms.size_matches_manifest, true);
    assert.ok(sms.manifest_rowid! >= 1);
    // The bytes on disk are the blob's bytes, under the name the Manifest gave.
    const root = cited(cwd, "out", answer.derivative.root!);
    assert.deepEqual(await readFile(join(root, sms.derivative_path!)), data[0]);
    assert.deepEqual(await readFile(join(root, byId[fid(2, "bb")].derivative_path!)), data[1]);
    assert.equal(byId[fid(2, "bb")].derivative_path, "files/AppDomain-com.example.notes/Documents/notes.sqlite");
    assert.equal(byId[fid(3, "cc")].sha256, sha256(data[2]));
    // The banner says what the derivative is.
    const banner = JSON.parse(await readFile(join(root, "derivative.json"), "utf8")) as { kind: string; is_not: string };
    assert.equal(banner.kind, "ios-backup-derivative");
    assert.match(banner.is_not, /phone/);
    // The whole account is the file the answer names, and its count is the lines it holds.
    const all = await jsonl(cited(cwd, "out", answer.pages.entries.all_results));
    assert.equal(all.length, answer.entry_count);
    assert.equal(all.length, 3);
    // Everything written is under $OUT: the work directory of the run holds nothing.
    assert.deepEqual(await readdir(join(cwd, "work")), ["plain"]);
  });
});

test("without copy_content it is a plan: the map and the state of each blob, no content, no digest, no derivative", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "plan", { entries: [{ id: fid(1), path: "Library/a.db", size: 33 }, { id: fid(2), path: "Library/b.db", blob: "none" }] });
    const r = await run(cwd, { path: dir, domains: ["HomeDomain"] });
    const answer = body(r);
    assert.equal(answer.copy_content, false);
    assert.equal(answer.derivative.written, false);
    const states = Object.fromEntries(answer.entries.map((e) => [e.relative_path, e.state]));
    assert.deepEqual(states, { "Library/a.db": "planned", "Library/b.db": "missing" });
    for (const e of answer.entries) assert.equal(e.sha256, undefined, "no digest of a blob is computed in a plan");
    assert.equal(answer.status, "partial");
    assert.match(answer.status_basis, /missing 1/);
    const written = (await walk(join(cwd, "work", "s1"))).map((p) => relative(join(cwd, "work", "s1"), p));
    assert.equal(written.length, 1, written.join(", "));
    assert.match(written[0], /^tool-output\/backup_materialise-[0-9a-f]{16}\.jsonl$/);
    // A plan of present blobs only is complete and says it is a plan.
    const dir2 = await backup(cwd, "plan2", { entries: [{ id: fid(1), path: "Library/a.db" }] });
    const ok = body(await run(cwd, { path: dir2, all: true }));
    assert.equal(ok.status, "complete");
    assert.match(ok.status_basis, /plan/);
  });
});

test("copy_content is refused as JSON, before anything is made, outside a job and in a job that is not secret output", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "refuse", { entries: [{ id: fid(1), path: "Library/a.db" }] });
    const outside = failed(await run(cwd, { path: dir, all: true, copy_content: true }));
    assert.match(outside.error!, /copy_content is refused outside a job/);
    assert.deepEqual(await readdir(join(cwd, "work")), ["refuse"]);
    const notSecret = failed(await asJob(cwd, { path: dir, all: true, copy_content: true }, "out", "j-2", false));
    assert.match(notSecret.error!, /SECRET_OUTPUT is not 1/);
    assert.deepEqual(await readdir(join(cwd, "out")), [], "nothing is created in the output directory");
    // Other argument mistakes are refused too: no default of the whole map, no unknown argument, no password anywhere.
    assert.match(failed(await run(cwd, { path: dir })).error!, /name what to lay out/);
    assert.match(failed(await run(cwd, { path: dir, all: true, domains: ["HomeDomain"] })).error!, /do not give domains or paths/);
    assert.match(failed(await run(cwd, { path: dir, all: true, password: "x" })).error!, /no such argument/);
    assert.match(failed(await run(cwd, { path: dir, all: true, copy_content: "yes" })).error!, /true or false/);
  });
});

test("an encrypted backup is refused, an unknown encryption state is said and partial, and a Manifest.db that is not SQLite is refused", async () => {
  await withCwd(async (cwd) => {
    const enc = await backup(cwd, "enc", { encrypted: true, entries: [{ id: fid(1), path: "Library/a.db" }] });
    const refused = failed(await run(cwd, { path: enc, all: true }));
    assert.match(refused.error!, /encrypted/);
    assert.equal(refused.status, "failed");
    const unknown = await backup(cwd, "unk", { no_flag: true, entries: [{ id: fid(1), path: "Library/a.db" }] });
    const a = body(await run(cwd, { path: unknown, all: true }));
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /encryption state is unknown/);
    const junk = join(cwd, "work", "junk");
    await mkdir(junk, { recursive: true });
    await writeFile(join(junk, "Manifest.db"), Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 131 + 7) % 256)));
    assert.match(failed(await run(cwd, { path: junk, all: true })).error!, /not a plaintext SQLite database/);
    const unfinished = await backup(cwd, "unfinished", { snapshot: "new", entries: [{ id: fid(1), path: "Library/a.db" }] });
    assert.match(body(await run(cwd, { path: unfinished, all: true })).status_basis, /did not finish/);
  });
});

test("a missing blob, a directory, a link, a FIFO and a bad file id are refused and counted, and the file a link points at is untouched", async () => {
  await withCwd(async (cwd) => {
    const outside = join(cwd, "outside.txt");
    await writeFile(outside, "outside the backup");
    const before = await readFile(outside);
    const dir = await backup(cwd, "states", { entries: [
      { id: fid(1), path: "Library/ok.db", size: 12 },
      { id: fid(2), path: "Library/missing.db", blob: "none" },
      { id: fid(3), path: "Library/dir.db", blob: "dir" },
      { id: fid(4), path: "Library/link.db", blob: `symlink:${outside}` },
      { id: fid(5), path: "Library/fifo.db", blob: "fifo" },
      { id: "not-a-file-id", path: "Library/bad.db", blob: "none" },
      { id: fid(6), path: "Library/dirflag", flags: 2, blob: "none" },
    ] });
    const r = await Promise.race([asJob(cwd, { path: dir, all: true, copy_content: true }), new Promise<never>((_, rej) => setTimeout(() => rej(new Error("the tool hung on a FIFO")), 20000))]);
    const answer = body(r);
    const states = Object.fromEntries(answer.entries.map((e) => [e.relative_path, e.state]));
    assert.deepEqual(states, {
      "Library/ok.db": "copied", "Library/missing.db": "missing", "Library/dir.db": "directory", "Library/link.db": "symlink",
      "Library/fifo.db": "special", "Library/bad.db": "refused_id", "Library/dirflag": "not_applicable",
    });
    assert.equal(answer.status, "partial");
    assert.deepEqual(await readFile(outside), before);
    const files = await walk(join(cwd, "out", "derivative", "files"));
    assert.deepEqual(files.map((p) => relative(join(cwd, "out", "derivative", "files"), p)), ["HomeDomain/Library/ok.db"]);
    assert.ok(!(await lstat(join(cwd, "out", "derivative", "files", "HomeDomain", "Library")).then((s) => s.isSymbolicLink())));
    // A link as the shard directory is not followed either.
    const shardLink = await backup(cwd, "shardlink", { entries: [{ id: fid(1, "ee"), path: "Library/a.db", blob: "none" }] });
    await mkdir(join(cwd, "elsewhere"), { recursive: true });
    await writeFile(join(cwd, "elsewhere", fid(1, "ee")), "elsewhere");
    await symlink(join(cwd, "elsewhere"), join(shardLink, "ee"));
    const s = body(await run(cwd, { path: shardLink, all: true }));
    assert.equal(s.entries[0].state, "shard_not_a_directory");
  });
});

test("a hostile relativePath is rejected and listed, and nothing is written outside the output directory", async () => {
  await withCwd(async (cwd) => {
    const longComponent = "c".repeat(300);
    const longPath = Array.from({ length: 70 }, (_, i) => `d${i}`).join("/");
    const dir = await backup(cwd, "hostile", { entries: [
      { id: fid(1), path: "../escape.txt" },
      { id: fid(2), path: "Library/../../escape2.txt" },
      { id: fid(3), path: "/etc/absolute.txt" },
      { id: fid(4), path: "Library/with\0nul.txt", path_hex: Buffer.from("Library/with\0nul.txt").toString("hex") },
      { id: fid(5), path: `Library/${longComponent}` },
      { id: fid(6), path: `${"p/".repeat(1500)}x` },
      { id: fid(7), path: longPath },
      { id: fid(8), path: "Library/./dot.txt" },
      { id: fid(9), path: "Library//empty.txt" },
      { id: fid(10), path: "Library/fine.txt" },
      { id: fid(11), domain: "../Home", path: "Library/x" },
      { id: fid(12), domain: "A/B", path: "Library/x" },
    ] });
    const before = await walk(cwd);
    const answer = body(await asJob(cwd, { path: dir, all: true, copy_content: true }));
    const states = answer.entries.map((e) => `${e.manifest_rowid}:${e.state}`);
    assert.equal(answer.counts.states.rejected_path, 11, states.join(" "));
    assert.equal(answer.counts.rejected_paths, 11);
    assert.equal(answer.counts.copied_files, 1);
    assert.equal(answer.status, "partial");
    for (const e of answer.entries.filter((r) => r.state === "rejected_path")) assert.ok(e.reason, "a rejected row says why");
    const after = (await walk(cwd)).filter((p) => !before.includes(p));
    for (const p of after) assert.ok(p.startsWith(join(cwd, "out")), `written outside $OUT: ${p}`);
    assert.equal((await stat(join(cwd, "out", "derivative", "files", "HomeDomain", "Library", "fine.txt"))).isFile(), true);
    assert.equal(await stat(join(cwd, "escape.txt")).then(() => true, () => false), false);
    assert.equal(await stat(join(cwd, "work", "escape.txt")).then(() => true, () => false), false);
  });
});

test("duplicate paths and paths that differ only in case or in Unicode form each get their own name, and the collisions are listed", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "collide", { entries: [
      { id: fid(1), path: "Library/Note.txt", data: "first" },
      { id: fid(2), path: "Library/Note.txt", data: "duplicate" },
      { id: fid(3), path: "Library/NOTE.TXT", data: "upper" },
      { id: fid(4), path: "library/note.txt", data: "lower dir" },
      { id: fid(5), path: "Library/café.txt", data: "nfc" },
      { id: fid(6), path: "Library/café.txt", data: "nfd" },
      { id: fid(7), path: "Library/thing", data: "a file" },
      { id: fid(8), path: "Library/thing/inside.txt", data: "below a file" },
    ] });
    const answer = body(await asJob(cwd, { path: dir, all: true, copy_content: true }));
    assert.equal(answer.status, "complete", answer.status_basis);
    const paths = answer.entries.map((e) => e.derivative_path!);
    assert.equal(new Set(paths.map((p) => p.normalize("NFC").toLowerCase())).size, paths.length, `names fold to distinct names: ${paths.join(", ")}`);
    const files = await walk(join(cwd, "out", "derivative", "files"));
    assert.equal(files.length, 8, "all eight blobs are in the layout");
    const contents = await Promise.all(files.map((f) => readFile(f, "utf8")));
    assert.deepEqual([...contents].sort(), ["a file", "below a file", "duplicate", "first", "lower dir", "nfc", "nfd", "upper"]);
    assert.ok(answer.counts.name_collisions >= 5, String(answer.counts.name_collisions));
    assert.equal(answer.collision_count, answer.collisions.length);
    const kinds = new Set(answer.entries.flatMap((e) => (e.name_collision ?? []).map((c) => c.kind)));
    assert.ok(kinds.has("duplicate_path") && kinds.has("case_fold") && kinds.has("file_vs_directory"), [...kinds].join(","));
    // The first of two is the one with the plain name.
    assert.equal(answer.entries[0].derivative_path, "files/HomeDomain/Library/Note.txt");
  });
});

test("a hostile run of one name resolves in linear time", async () => {
  await withCwd(async (cwd) => {
    const entries = Array.from({ length: 20000 }, (_, i) => ({ id: fid(i + 1, "ab"), path: "Library/same.txt", blob: "none" }));
    const dir = await backup(cwd, "many-same", { entries });
    const began = Date.now();
    const answer = body(await run(cwd, { path: dir, all: true, max_seconds: 100 }));
    assert.equal(answer.entry_count, 20000);
    assert.ok(Date.now() - began < 60000, `${Date.now() - began} ms`);
    assert.equal(new Set((await jsonl(join(cwd, answer.pages.entries.all_results))).map((r) => r.derivative_path)).size, 20000);
  });
});

test("the -wal, -shm and -journal of a selected file are laid out beside it, found through the Manifest, and are absent when the Manifest has none", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "companions", { entries: [
      { id: fid(1), path: "Library/SMS/sms.db", data: "main" },
      { id: fid(2), path: "Library/SMS/sms.db-wal", data: "wal" },
      { id: fid(3), path: "Library/SMS/sms.db-shm", data: "shm" },
      { id: fid(4), domain: "OtherDomain", path: "Library/SMS/sms.db-journal", data: "other domain's journal" },
      { id: fid(5), path: "Library/Notes/notes.db", data: "alone" },
    ] });
    const answer = body(await asJob(cwd, { path: dir, paths: ["Library/SMS/sms.db"], copy_content: true }));
    const by = Object.fromEntries(answer.entries.map((e) => [e.relative_path, e]));
    assert.equal(by["Library/SMS/sms.db"].selected_by, "selection");
    assert.equal(by["Library/SMS/sms.db-wal"].selected_by, `companion_of:${fid(1)}`);
    assert.equal(by["Library/SMS/sms.db-shm"].selected_by, `companion_of:${fid(1)}`);
    assert.equal(answer.entries.length, 3, "the journal of another domain is not this file's, and notes.db is not selected");
    assert.equal(answer.counts.companions_found, 2);
    assert.equal(await readFile(join(cwd, "out", "derivative", "files", "HomeDomain", "Library", "SMS", "sms.db-wal"), "utf8"), "wal");
    const alone = body(await run(cwd, { path: dir, paths: ["Library/Notes/notes.db"] }));
    assert.equal(alone.entries.length, 1);
    assert.equal(alone.counts.companions_found, 0);
    // A prefix selects everything below it; a domain selects its rows.
    assert.equal(body(await run(cwd, { path: dir, paths: ["Library/"] })).entries.length, 5, "a prefix selects every domain's rows below it");
    assert.equal(body(await run(cwd, { path: dir, domains: ["HomeDomain"], paths: ["Library/"] })).entries.length, 4);
    assert.equal(body(await run(cwd, { path: dir, domains: ["OtherDomain"] })).entries.length, 1);
  });
});

test("max_files, max_bytes and max_seconds each give partial and say which limit and what was left", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "limits", { entries: Array.from({ length: 6 }, (_, i) => ({ id: fid(i + 1), path: `Library/f${i}.bin`, size: 1000 })) });
    const files = body(await asJob(cwd, { path: dir, all: true, copy_content: true, max_files: 4 }, "o1"));
    assert.equal(files.status, "partial");
    assert.equal(files.counts.selected_not_kept_max_files, 2);
    assert.equal(files.counts.copied_files, 4);
    assert.match(files.status_basis, /max_files/);
    const bytes = body(await asJob(cwd, { path: dir, all: true, copy_content: true, max_bytes: 2500 }, "o2"));
    assert.equal(bytes.status, "partial");
    assert.equal(bytes.counts.copied_files, 2);
    assert.equal(bytes.counts.states.not_copied_max_bytes, 4);
    assert.match(bytes.status_basis, /max_bytes/);
    assert.ok(bytes.counts.copied_bytes <= 2500);
    // A time limit that ends the read of Manifest.db.
    const big = await backup(cwd, "bigmap", { entries: [{ id: fid(1), path: "Library/a.db" }] });
    const grow = String.raw`
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.executemany("INSERT INTO Files VALUES (?,?,?,?,NULL)", (("%040x" % (i + 100), "HomeDomain", "Library/x%d" % i, 1) for i in range(400000)))
con.commit()
`;
    assert.equal((await runPySnippet(grow, [join(big, "Manifest.db")], null)).code, 0);
    const timed = body(await run(cwd, { path: big, all: true, max_seconds: 0.4, max_files: 500000 }));
    assert.equal(timed.status, "partial");
    assert.notEqual(timed.stopped_at_row, null);
    assert.match(timed.status_basis, /time limit stopped the read/);
  });
});

/** The tool with every read of a copy chunk delayed, so that a copy takes as long as the test needs. */
const SLOW = String.raw`
import os, runpy, sys, time
delay = float(sys.argv[1])
real = os.read
def slow(fd, n):
    if n == 1 << 20:
        time.sleep(delay)
    return real(fd, n)
os.read = slow
sys.argv = [sys.argv[2]]
runpy.run_path(sys.argv[0], run_name="__main__")
`;

function slowTool(cwd: string, args: unknown, delay: number, env: Record<string, string>): { child: ReturnType<typeof spawn>; done: Promise<Run> } {
  const child = spawn("python3", ["-c", SLOW, String(delay), TOOL], { cwd, env: { ...process.env, ...AGENT, ...env } });
  const out: Buffer[] = [], err: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => out.push(c));
  child.stderr.on("data", (c: Buffer) => err.push(c));
  child.stdin.on("error", () => {});
  child.stdin.end(JSON.stringify(args));
  const done = new Promise<Run>((resolve) => child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") })));
  return { child, done };
}

test("max_seconds ends the copying: the files not reached are listed as not attempted, and no file is half written", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "clock", { entries: Array.from({ length: 40 }, (_, i) => ({ id: fid(i + 1), path: `Library/f${i}.bin`, size: 500 })) });
    await mkdir(join(cwd, "out"), { recursive: true });
    const { done } = slowTool(cwd, { path: dir, all: true, copy_content: true, max_seconds: 2 }, 0.1, { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" });
    const answer = body(await done);
    assert.equal(answer.status, "partial");
    assert.ok(answer.counts.states.not_attempted_max_seconds >= 1, JSON.stringify(answer.counts.states));
    assert.ok(answer.counts.copied_files >= 1 && answer.counts.copied_files < 40, String(answer.counts.copied_files));
    assert.equal(answer.entry_count, 40, "every row has its line, the ones not reached too");
    const files = await walk(join(cwd, "out", "derivative", "files"));
    assert.equal(files.length, answer.counts.copied_files);
    for (const f of files) assert.equal((await readFile(f)).length, 500);
    assert.deepEqual((await walk(join(cwd, "out"))).filter((p) => /\.bm-|\.tmp$/.test(p)), []);
  });
});

test("SIGTERM in the middle of a copy ends with JSON and exit 143, leaves no temporary file and no half file under a final name", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "term", { entries: Array.from({ length: 6 }, (_, i) => ({ id: fid(i + 1), path: `Library/f${i}.bin`, fill: i, size: 3 * 1024 * 1024 })) });
    await mkdir(join(cwd, "out"), { recursive: true });
    const { child, done } = slowTool(cwd, { path: dir, all: true, copy_content: true, max_seconds: 120 }, 0.5, { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" });
    // Wait until a hidden temporary exists, which is the middle of a copy.
    const until = Date.now() + 20000;
    let seen = false;
    while (Date.now() < until && !seen) {
      seen = (await walk(join(cwd, "out"))).some((p) => /\/\.bm-[^/]*\.tmp$/.test(p));
      if (!seen) await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(seen, "a copy was in progress");
    child.kill("SIGTERM");
    const r = await done;
    assert.equal(r.code, 143, r.stderr + r.stdout);
    const answer = JSON.parse(r.stdout) as Answer;
    assert.equal(answer.interrupted, "SIGTERM");
    assert.doesNotMatch(r.stderr, /Traceback/);
    const left = await walk(join(cwd, "out"));
    assert.deepEqual(left.filter((p) => /\.bm-|\.tmp$|\/\.backup_materialise-/.test(p)), []);
    for (const f of left.filter((p) => p.includes(`${join(cwd, "out", "derivative", "files")}/`))) assert.equal((await readFile(f)).length, 3 * 1024 * 1024, "a file under a final name is whole");
  });
});

test("a second run in the same $OUT names again what is identical and never replaces a file with another: a changed blob takes -2", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "again", { entries: [{ id: fid(1), path: "Library/a.db", data: "version one, the longer text" }, { id: fid(2), path: "Library/b.db", data: "same" }] });
    const first = body(await asJob(cwd, { path: dir, all: true, copy_content: true }));
    const filesDir = join(cwd, "out", "derivative", "files", "HomeDomain", "Library");
    assert.equal(first.derivative.values_file!.endsWith("backup-materialise-values.jsonl"), true);
    const second = body(await asJob(cwd, { path: dir, all: true, copy_content: true }));
    assert.deepEqual((await readdir(filesDir)).sort(), ["a.db", "b.db"], "identical content is named again, not copied twice");
    // The blob changes to a shorter text: the earlier, larger file is kept and the new one takes -2.
    await writeFile(join(dir, "aa", fid(1)), "v2");
    const third = body(await asJob(cwd, { path: dir, all: true, copy_content: true }));
    assert.deepEqual((await readdir(filesDir)).sort(), ["a-2.db", "a.db", "b.db"]);
    assert.equal(await readFile(join(filesDir, "a.db"), "utf8"), "version one, the longer text");
    assert.equal(await readFile(join(filesDir, "a-2.db"), "utf8"), "v2");
    assert.equal(third.entries.find((e) => e.file_id === fid(1))!.derivative_path, "files/HomeDomain/Library/a-2.db");
    assert.ok(third.entries.find((e) => e.file_id === fid(1))!.name_collision!.some((c) => c.kind === "name_taken_on_disk"));
    // The result files and the values files are three, none replacing another.
    const outNames = await readdir(join(cwd, "out"));
    assert.equal(outNames.filter((n) => n.startsWith("backup-materialise-values")).length, 3);
    assert.equal((await readdir(join(cwd, "out", "tool-output"))).filter((n) => n.endsWith(".jsonl")).length, 3);
    assert.notEqual(first.pages.entries.all_results, second.pages.entries.all_results);
  });
});

test("a path component shaped like a recovery password is withheld on every channel; its real name is only in the 0600 values file", async () => {
  // 300 canaries from a seeded generator, as eight groups of six digits: with none found on any channel, the rate of a leak is under 1 % at 95 %
  // confidence (the Wilson upper bound for 0 of 300 is 1.26 %).
  await withCwd(async (cwd) => {
    let x = 20260203 >>> 0;
    const next = (): number => { x = (Math.imul(x, 1664525) + 1013904223) >>> 0; return x; };
    const keys = Array.from({ length: 300 }, () => Array.from({ length: 8 }, () => String(next() % 1000000).padStart(6, "0")).join("-"));
    const entries = keys.map((k, i) => (i % 3 === 0
      ? { id: fid(i + 1), path: `Documents/${k}/note.txt`, data: `n${i}` }
      : i % 3 === 1 ? { id: fid(i + 1), domain: `AppDomain-${k}`, path: "Library/n.txt", data: `n${i}` }
      : { id: fid(i + 1), path: `Documents/${k}.txt`, data: `n${i}` }));
    const dir = await backup(cwd, "keys", { entries });
    const r = await asJob(cwd, { path: dir, all: true, copy_content: true });
    const answer = body(r);
    assert.equal(answer.status, "complete", answer.status_basis);
    assert.equal(answer.counts.names_withheld, 300);
    const values = cited(cwd, "out", answer.derivative.values_file!);
    const names = (await walk(join(cwd, "out"))).filter((p) => p !== values);
    const channels = [r.stdout, r.stderr, ...names.map((n) => n), ...(await Promise.all(names.filter((n) => /\.(jsonl|json)$/.test(n)).map((n) => readFile(n, "utf8"))))];
    const hay = channels.join("\n");
    for (const k of keys) {
      for (const probe of [k, k.replaceAll("-", ""), k.split("-").slice(0, 3).join("-")]) assert.ok(!hay.includes(probe), `a canary reached a channel: ${probe.slice(0, 8)}...`);
    }
    // The values file holds the real names, 0600, and each row says where it is.
    assert.equal((await stat(values)).mode & 0o777, 0o600);
    const vrows = (await readFile(values, "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as { finding_id: string; value: { domain: string; relative_path: string } });
    assert.equal(vrows.length, 300);
    const text = vrows.map((v) => v.value.domain + "|" + v.value.relative_path).join("\n");
    for (const k of keys) assert.ok(text.includes(k));
    // The names under the layout carry the placeholder, and several rows of one placeholder are told apart.
    const rows = await jsonl(cited(cwd, "out", answer.pages.entries.all_results));
    assert.ok(rows.every((e) => e.name_withheld && e.path_b64 === null && e.domain_b64 === null));
    assert.equal(new Set(rows.map((e) => e.derivative_path)).size, 300);
    // contains-style oracle: selecting by a guessed name matches nothing, and the placeholder matches every withheld row alike.
    const guess = body(await run(cwd, { path: dir, paths: [`Documents/${keys[0]}/note.txt`] }));
    assert.equal(guess.entries.length, 0);
    assert.equal(guess.status, "partial");
    assert.match(guess.status_basis, /matched no row/);
  });
});

test("a plan reads a key-shaped name too: the placeholder is in the result file and the real name is nowhere", async () => {
  await withCwd(async (cwd) => {
    const key = "123456-654321-111111-222222-333333-444444-555555-666666";
    const dir = await backup(cwd, "plankey", { entries: [{ id: fid(1), path: `Documents/${key}/n.txt` }] });
    const r = await run(cwd, { path: dir, all: true });
    const answer = body(r);
    const all = (await Promise.all((await walk(join(cwd, "work", "s1")).then((l) => l)).map((f) => readFile(f, "utf8")))).join("\n");
    assert.ok(!(r.stdout + all).includes("123456"));
    assert.equal(answer.entries[0].relative_path, "Documents/<recovery-password-shaped name withheld>/n.txt");
    assert.equal(answer.paths_withheld >= 1, true);
  });
});

/** A Manifest.db whose table b-tree is a graph: 19 interior pages of 4 cells that all point at the next page, ending in one leaf (4^18 leaf visits). */
const DAG_DB = String.raw`
import os, sqlite3, struct, sys
dest, fan, levels, ps = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), 512
def varint(n):
    out = [n & 0x7f]
    n >>= 7
    while n:
        out.append((n & 0x7f) | 0x80)
        n >>= 7
    return bytes(reversed(out))
os.makedirs(dest, exist_ok=True)
path = os.path.join(dest, "Manifest.db")
con = sqlite3.connect(path)
con.execute("PRAGMA page_size = %d" % ps)
con.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
con.execute("INSERT INTO Files VALUES ('0123456789abcdef0123456789abcdef01234567', 'HomeDomain', 'Library/x', 1, NULL)")
con.commit()
con.close()
data = bytearray(open(path, "rb").read())
leaf = bytearray(data[ps:2 * ps])
leaf_no = levels + 2
pages = []
for i in range(levels):
    child = 2 + i + 1 if i < levels - 1 else leaf_no
    page = bytearray(ps)
    page[0] = 5
    content, pointers = ps, []
    for j in range(fan):
        cell = struct.pack(">I", child) + varint(j + 1)
        content -= len(cell)
        page[content:content + len(cell)] = cell
        pointers.append(content)
    struct.pack_into(">H", page, 3, fan)
    struct.pack_into(">H", page, 5, content)
    struct.pack_into(">I", page, 8, child)
    for j, pointer in enumerate(pointers):
        struct.pack_into(">H", page, 12 + 2 * j, pointer)
    pages.append(page)
out = bytearray(data[:ps])
for page in pages:
    out += page
out += leaf
struct.pack_into(">I", out, 28, leaf_no)
struct.pack_into(">I", out, 24, struct.unpack_from(">I", out, 92)[0])
open(path, "wb").write(out)
`;

function guarded(cwd: string, args: unknown, killMs: number, signal?: { name: NodeJS.Signals; after: number }): Promise<Run & { killed: boolean; ms: number }> {
  return new Promise((resolve, reject) => {
    const began = Date.now();
    const child = spawn("python3", [TOOL], { cwd, env: { ...process.env, ...AGENT } });
    const out: Buffer[] = [], err: Buffer[] = [];
    let killed = false;
    const guard = setTimeout(() => { killed = true; child.kill("SIGKILL"); }, killMs);
    if (signal) setTimeout(() => child.kill(signal.name), signal.after);
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(guard);
      resolve({ code, killed, ms: Date.now() - began, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") });
    });
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(args));
  });
}

test("a Manifest.db whose table b-tree points at itself ends at max_seconds and on a stop signal", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "dag");
    const made = await runPySnippet(DAG_DB, [dir, "4", "19"], null);
    assert.equal(made.code, 0, made.stderr);
    for (const [name, content] of [["Manifest.plist", ""], ["Status.plist", ""]]) await writeFile(join(dir, name), content);
    const r = await guarded(cwd, { path: dir, all: true, max_seconds: 2 }, 40000);
    assert.equal(r.killed, false, "the tool had to be killed after 40 s");
    assert.equal(r.code, 0, r.stderr + r.stdout);
    const answer = JSON.parse(r.stdout) as Answer;
    assert.equal(answer.status, "partial");
    assert.notEqual(answer.stopped_at_row, null);
    assert.ok(r.ms < 20000, `${r.ms} ms`);
    const s = await guarded(cwd, { path: dir, all: true, max_seconds: 120 }, 40000, { name: "SIGTERM", after: 1500 });
    assert.equal(s.killed, false, "SIGTERM was not answered");
    assert.equal(s.code, 143, s.stderr + s.stdout);
    assert.equal((JSON.parse(s.stdout) as Answer).interrupted, "SIGTERM");
  });
});

test("a -wal of Manifest.db is applied in a working copy and never in place, and the copy is removed", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "walcopy", { entries: [{ id: fid(1), path: "Library/a.db" }] });
    // The second row is committed only in the WAL.
    const make = String.raw`
import os, shutil, sqlite3, sys
db = sys.argv[1]
con = sqlite3.connect(db)
con.execute("PRAGMA journal_mode = WAL")
con.execute("PRAGMA wal_autocheckpoint = 0")
con.execute("INSERT INTO Files VALUES (?,?,?,?,NULL)", (sys.argv[2], "HomeDomain", "Library/from-wal.db", 1))
con.commit()
shutil.copy(db, db + ".main"); shutil.copy(db + "-wal", db + ".walcopy")
con.close()
for s in ("", "-wal", "-shm"):
    if os.path.exists(db + s): os.remove(db + s)
os.rename(db + ".main", db); os.rename(db + ".walcopy", db + "-wal")
`;
    assert.equal((await runPySnippet(make, [join(dir, "Manifest.db"), fid(2)], null)).code, 0);
    const walBefore = await readFile(join(dir, "Manifest.db-wal"));
    const dbBefore = await readFile(join(dir, "Manifest.db"));
    const answer = body(await run(cwd, { path: dir, all: true }));
    assert.deepEqual(answer.entries.map((e) => e.relative_path).sort(), ["Library/a.db", "Library/from-wal.db"]);
    assert.deepEqual(await readFile(join(dir, "Manifest.db-wal")), walBefore);
    assert.deepEqual(await readFile(join(dir, "Manifest.db")), dbBefore);
    assert.deepEqual((await readdir(join(cwd, "work", "s1", "tool-output"))).filter((n) => n.includes("working-copy")), []);
  });
});

test("a read-only output directory and a full file system are said, not reported as facts about the backup", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "ro", { entries: [{ id: fid(1), path: "Library/a.db", size: 9000 }, { id: fid(2), path: "Library/b.db", size: 9000 }] });
    await mkdir(join(cwd, "out"), { recursive: true });
    await chmod(join(cwd, "out"), 0o500);
    const r = await run(cwd, { path: dir, all: true, copy_content: true }, { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" });
    await chmod(join(cwd, "out"), 0o700);
    const answer = JSON.parse(r.stdout) as Answer;
    assert.notEqual(r.code, 0);
    assert.equal(answer.status, "failed");
    assert.doesNotMatch(r.stderr, /Traceback/);
    // A file size limit stands in for a full disk (ENOSPC/EFBIG on the first write): the rows say write_failed, the run does not say complete.
    const limited = await new Promise<Run>((resolve) => {
      const child = spawn("bash", ["-c", `ulimit -f 6; exec python3 -c 'import signal; signal.signal(signal.SIGXFSZ, signal.SIG_IGN); import runpy, sys; sys.argv=[sys.argv[1]]; runpy.run_path(sys.argv[0], run_name="__main__")' "${TOOL}"`],
        { cwd, env: { ...process.env, ...AGENT, JOB_ID: "j-2", OUT: join(cwd, "out2"), SECRET_OUTPUT: "1" } });
      const out: Buffer[] = [], err: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => out.push(c));
      child.stderr.on("data", (c: Buffer) => err.push(c));
      child.stdin.on("error", () => {});
      child.stdin.end(JSON.stringify({ path: dir, all: true, copy_content: true }));
      child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    });
    const parsed = JSON.parse(limited.stdout) as Answer;
    assert.equal(parsed.status, "partial", limited.stdout.slice(0, 500));
    assert.ok(parsed.counts.states.write_failed >= 1, JSON.stringify(parsed.counts.states));
    assert.match(parsed.status_basis, /write_failed/);
    for (const row of parsed.entries.filter((e) => e.state === "write_failed")) assert.ok(row.reason, "the refused write says what refused it");
    assert.doesNotMatch(limited.stderr, /Traceback/);
    assert.deepEqual((await walk(join(cwd, "out2"))).filter((p) => /\.bm-|\.tmp$/.test(p)), [], "the temporary of the refused write is removed");
  });
});

test("a fuzz of 400 hostile Manifest rows never writes outside $OUT and never gives a traceback", async () => {
  // At most 1,000 cases per tool: 400 rows with random names from a seeded generator (separators, dots, NULs, long and non-UTF-8 names).
  await withCwd(async (cwd) => {
    let x = 7;
    const next = (): number => { x = (Math.imul(x, 1103515245) + 12345) >>> 0; return x; };
    const alphabet = ["a", "B", ".", "..", "/", "//", "é", "é", " ", "-2", "x".repeat(40), "\\", "~", "CON", "%2e%2e"];
    const entries = Array.from({ length: 400 }, (_, i) => {
      const n = 1 + (next() % 6);
      const path = Array.from({ length: n }, () => alphabet[next() % alphabet.length]).join(next() % 2 ? "/" : "");
      return { id: fid(i + 1, "cd"), path, data: `d${i}` };
    });
    const dir = await backup(cwd, "fuzz", { entries });
    const before = await walk(cwd);
    const r = await asJob(cwd, { path: dir, all: true, copy_content: true });
    const answer = body(r);
    assert.equal(answer.entry_count, 400);
    const stray = (await walk(cwd)).filter((p) => !before.includes(p) && !p.startsWith(join(cwd, "out")));
    assert.deepEqual(stray, []);
    const files = await walk(join(cwd, "out", "derivative", "files"));
    assert.equal(files.length, answer.counts.copied_files);
    for (const f of files) assert.ok(f.startsWith(join(cwd, "out", "derivative", "files") + "/"));
  });
});

// --- fix round 1: a Manifest companion that is not a file, and a link planted in the output directory ---------------------------------------

test("a Manifest.db-wal or -journal that is a FIFO or a directory is said in the answer and makes it partial, as a link does", async () => {
  await withCwd(async (cwd) => {
    const entries = [{ id: fid(1), path: "Library/SMS/sms.db", data: "main" }];
    const control = await backup(cwd, "plain", { entries });
    assert.equal(body(await run(cwd, { path: control, all: true })).status, "complete");
    for (const [name, make] of [["fifo", (p: string) => execFileSync("mkfifo", [p])], ["dir", (p: string) => execFileSync("mkdir", [p])]] as const) {
      const dir = await backup(cwd, name, { entries });
      make(join(dir, "Manifest.db-wal"));
      const answer = body(await run(cwd, { path: dir, all: true }));
      assert.equal(answer.status, "partial", `${name}: ${answer.status_basis}`);
      assert.ok(answer.observations.some((o) => /Manifest\.db-wal is not a regular file/.test(o)), JSON.stringify(answer.observations));
    }
  });
});

test("a tool-output directory that is a link planted in the output directory is refused as JSON, and nothing is written through it", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "planted", { entries: [{ id: fid(1), path: "Library/SMS/sms.db", data: "main" }] });
    await mkdir(join(cwd, "out"), { recursive: true });
    await mkdir(join(cwd, "elsewhere"), { recursive: true });
    await symlink(join(cwd, "elsewhere"), join(cwd, "out", "tool-output"));
    const answer = failed(await run(cwd, { path: dir, all: true }, { JOB_ID: "j-1", OUT: join(cwd, "out") }));
    assert.match(answer.error ?? "", /tool-output/);
    assert.deepEqual(await readdir(join(cwd, "elsewhere")), []);
  });
});
