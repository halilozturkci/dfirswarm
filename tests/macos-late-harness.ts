/**
 * Helpers for the suites of the late macOS tools (macos_tcc, macos_login_items, safari_history, segb_read, apfs_inventory): builders for the
 * formats they read, written from the formats' documented layouts and never from a tool's output (SQLite itself builds the databases, plistlib
 * the keyed archives, Buffer the SEGB files), a runner that can signal a tool, and a reader of every file a run left behind.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";
import { MAC, body, filesUnder, ok, plainJob, reachable, secretJob, tool } from "./macos-pack-harness.ts";
import type { Json, Run } from "./macos-pack-harness.ts";
import { ROOT, runPySnippet } from "./tool-library-harness.ts";

export { MAC, ROOT, body, filesUnder, ok, plainJob, reachable, secretJob, tool };
export type { Json, Run };
export const TCC = join(MAC, "macos_tcc", "run.py");
export const BTM = join(MAC, "macos_login_items", "run.py");
export const SAFARI = join(MAC, "safari_history", "run.py");
export const SEGB = join(MAC, "segb_read", "run.py");
export const APFS = join(MAC, "apfs_inventory", "run.py");
export const LATE = { macos_tcc: TCC, macos_login_items: BTM, safari_history: SAFARI, segb_read: SEGB, apfs_inventory: APFS } as const;

/** Run a tool as the harness starts one: leading its own process group (the shared process block ends what holds a pipe only when the tool leads its group). */
export function leader(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return new Promise((resolve, reject) => {
    const e = { ...process.env, AGENT_ID: "s1", ...env };
    if (bin) e.PATH = `${bin}:${e.PATH ?? ""}`;
    const child = spawn("python3", [script], { cwd, env: e, detached: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    child.stdin.end(JSON.stringify(args));
  });
}

/** Run a tool, send it `signal` after `afterMs`, and return how it ended. */
export function signalled(script: string, cwd: string, args: unknown, signal: NodeJS.Signals, afterMs: number, env: Record<string, string> = {}, bin?: string): Promise<Run & { signal: string | null }> {
  return new Promise((resolve, reject) => {
    const e = { ...process.env, AGENT_ID: "s1", ...env };
    if (bin) e.PATH = `${bin}:${e.PATH ?? ""}`;
    const child = spawn("python3", [script], { cwd, env: e });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code, sig) => resolve({ code, signal: sig, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    child.stdin.end(JSON.stringify(args));
    setTimeout(() => child.kill(signal), afterMs);
  });
}

// ---- TCC ------------------------------------------------------------------------------------------------------------------------------------

/**
 * The `access` table of each macOS version, from the documented column lists (the version is in the fixture's name; 26 and 27 are not built: their
 * schema is not verified here). argv: path, version, mode (plain | wal); stdin: {rows: [{...column values}]}.
 */
export const TCC_BUILD = `
import json, os, shutil, sqlite3, sys
path, version, mode = sys.argv[1], sys.argv[2], sys.argv[3]
spec = json.load(sys.stdin)
COLUMNS = {
  "10.15": "service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, allowed INTEGER NOT NULL, prompt_count INTEGER NOT NULL, csreq BLOB, policy_id INTEGER, indirect_object_identifier_type INTEGER, indirect_object_identifier TEXT, indirect_object_code_identity BLOB, flags INTEGER, last_modified INTEGER NOT NULL",
  "11": "service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL, csreq BLOB, policy_id INTEGER, indirect_object_identifier_type INTEGER, indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', indirect_object_code_identity BLOB, flags INTEGER, last_modified INTEGER NOT NULL",
  "12": "service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL, csreq BLOB, policy_id INTEGER, indirect_object_identifier_type INTEGER, indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', indirect_object_code_identity BLOB, flags INTEGER, last_modified INTEGER NOT NULL, pid INTEGER, pid_version INTEGER, boot_uuid TEXT NOT NULL DEFAULT 'UNUSED', last_reminder INTEGER",
  "13": "service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL, csreq BLOB, policy_id INTEGER, indirect_object_identifier_type INTEGER, indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', indirect_object_code_identity BLOB, flags INTEGER, last_modified INTEGER NOT NULL, pid INTEGER, pid_version INTEGER, boot_uuid TEXT NOT NULL DEFAULT 'UNUSED', last_reminder INTEGER",
  "14": "service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL, csreq BLOB, policy_id INTEGER, indirect_object_identifier_type INTEGER, indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', indirect_object_code_identity BLOB, flags INTEGER, last_modified INTEGER NOT NULL, pid INTEGER, pid_version INTEGER, boot_uuid TEXT NOT NULL DEFAULT 'UNUSED', last_reminder INTEGER",
  "15": "service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL, csreq BLOB, policy_id INTEGER, indirect_object_identifier_type INTEGER, indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', indirect_object_code_identity BLOB, flags INTEGER, last_modified INTEGER NOT NULL, pid INTEGER, pid_version INTEGER, boot_uuid TEXT NOT NULL DEFAULT 'UNUSED', last_reminder INTEGER, expired_at INTEGER",
}
tmp = path + ".build"
os.makedirs(tmp, exist_ok=True)
c = sqlite3.connect(tmp + "/TCC.db")
if mode == "wal":
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA wal_autocheckpoint=0")
c.execute("CREATE TABLE admin (key TEXT PRIMARY KEY NOT NULL, value INTEGER NOT NULL)")
c.execute("INSERT INTO admin VALUES ('version', ?)", (spec.get("admin", 15),))
c.execute("CREATE TABLE access (" + COLUMNS[version] + ")")
if "policy" in spec:
    c.execute("CREATE TABLE policies (id INTEGER NOT NULL PRIMARY KEY, bundle_id TEXT NOT NULL, uuid TEXT NOT NULL, display TEXT NOT NULL)")
    c.execute("INSERT INTO policies VALUES (7, 'com.example.mdm', 'u', 'd')")
c.commit()
if mode == "wal":
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
for row in spec["rows"]:
    names = list(row)
    c.execute("INSERT INTO access (" + ",".join(names) + ") VALUES (" + ",".join("?" * len(names)) + ")", [bytes.fromhex(row[n][4:]) if isinstance(row[n], str) and row[n].startswith("hex:") else row[n] for n in names])
c.commit()
os.makedirs(os.path.dirname(path), exist_ok=True)
for suffix, name in (("", "TCC.db"), ("-wal", "TCC.db-wal"), ("-shm", "TCC.db-shm")):
    if os.path.exists(tmp + "/" + name):
        shutil.copy(tmp + "/" + name, path + suffix)
c.close()
shutil.rmtree(tmp)
`;

export async function tccDb(cwd: string, name: string, version: string, rows: Array<Record<string, unknown>>, mode: "plain" | "wal" = "plain", extra: Json = {}): Promise<string> {
  const path = join(cwd, "work", name);
  const out = await runPySnippet(TCC_BUILD, [path, version, mode], { rows, ...extra });
  assert.equal(out.code, 0, out.stderr);
  return `work/${name}`;
}

// ---- Safari ---------------------------------------------------------------------------------------------------------------------------------

/** History.db with the tables of Safari (history_items, history_visits) from their documented columns. argv: path, mode; stdin: {items, visits}. */
export const SAFARI_BUILD = `
import json, os, shutil, sqlite3, sys
path, mode = sys.argv[1], sys.argv[2]
spec = json.load(sys.stdin)
tmp = path + ".build"
os.makedirs(tmp, exist_ok=True)
c = sqlite3.connect(tmp + "/History.db")
if mode == "wal":
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA wal_autocheckpoint=0")
c.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, domain_expansion TEXT, visit_count INTEGER NOT NULL, daily_visit_counts BLOB NOT NULL, weekly_visit_counts BLOB, autocomplete_triggers BLOB, should_recompute_derived_visit_counts INTEGER NOT NULL, visit_count_score INTEGER NOT NULL, status_code INTEGER NOT NULL DEFAULT 0)")
c.execute("CREATE TABLE history_visits (id INTEGER PRIMARY KEY AUTOINCREMENT, history_item INTEGER NOT NULL REFERENCES history_items(id), visit_time REAL NOT NULL, title TEXT, load_successful BOOLEAN NOT NULL DEFAULT 1, http_non_get BOOLEAN NOT NULL DEFAULT 0, synthesized BOOLEAN NOT NULL DEFAULT 0, redirect_source INTEGER, redirect_destination INTEGER, origin INTEGER NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 0, attributes INTEGER NOT NULL DEFAULT 0, score INTEGER NOT NULL DEFAULT 0)")
c.commit()
if mode == "wal":
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
for url in spec["items"]:
    c.execute("INSERT INTO history_items (url, domain_expansion, visit_count, daily_visit_counts, should_recompute_derived_visit_counts, visit_count_score) VALUES (?, 'example', 1, x'00', 0, 100)", (url,))
for item, t, title in spec["visits"]:
    c.execute("INSERT INTO history_visits (history_item, visit_time, title) VALUES (?, ?, ?)", (item, t, title))
c.commit()
os.makedirs(os.path.dirname(path), exist_ok=True)
for suffix, name in (("", "History.db"), ("-wal", "History.db-wal"), ("-shm", "History.db-shm")):
    if os.path.exists(tmp + "/" + name):
        shutil.copy(tmp + "/" + name, path + suffix)
c.close()
shutil.rmtree(tmp)
`;

export async function safariDb(cwd: string, name: string, items: string[], visits: Array<[number, number, string]>, mode: "plain" | "wal" = "plain"): Promise<string> {
  const path = join(cwd, "work", name);
  const out = await runPySnippet(SAFARI_BUILD, [path, mode], { items, visits });
  assert.equal(out.code, 0, out.stderr);
  return `work/${name}`;
}

// ---- keyed archives -------------------------------------------------------------------------------------------------------------------------

/** A binary NSKeyedArchiver plist built with plistlib from a JSON description: {objects: [...], top: {...}}; {"uid": n} is a reference, {"bytes": hex} data. */
export const BTM_BUILD = `
import json, plistlib, sys
U = plistlib.UID
def conv(v):
    if isinstance(v, dict):
        if set(v) == {"uid"}: return U(v["uid"])
        if set(v) == {"bytes"}: return bytes.fromhex(v["bytes"])
        return {k: conv(x) for k, x in v.items()}
    if isinstance(v, list): return [conv(x) for x in v]
    return v
spec = json.load(sys.stdin)
doc = {"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": conv(spec["top"]), "$objects": conv(spec["objects"])}
if spec.get("plain"): doc = conv(spec["plain"])
open(sys.argv[1], "wb").write(plistlib.dumps(doc, fmt=plistlib.FMT_XML if spec.get("xml") else plistlib.FMT_BINARY))
`;

export async function btmFile(cwd: string, name: string, spec: Json): Promise<string> {
  const path = join(cwd, "work", name);
  await mkdir(join(path, ".."), { recursive: true });
  const out = await runPySnippet(BTM_BUILD, [path], spec);
  assert.equal(out.code, 0, out.stderr);
  return `work/${name}`;
}

const cls = (name: string) => ({ $classname: name, $classes: [name, "NSObject"] });
const uid = (n: number) => ({ uid: n });

/**
 * A versioned store as the system writes one, from the NSKeyedArchiver encoding rules: a root NSDictionary whose NS.keys/NS.objects hold the user
 * identifier and an NSArray of items; each item an object of class `Item` whose properties are references (or numbers). Returns the spec.
 */
export function storeSpec(items: Array<Record<string, unknown>>, userKey = "itemsByUserIdentifier"): Json {
  const objects: unknown[] = ["$null"];
  const add = (o: unknown): number => (objects.push(o), objects.length - 1);
  const rootIndex = add(null);
  const dictClass = add(cls("NSDictionary"));
  const arrClass = add(cls("NSArray"));
  const itemClass = add(cls("Item"));
  const key = add(userKey);
  const refs: number[] = [];
  for (const item of items) {
    const props: Record<string, unknown> = { $class: uid(itemClass) };
    for (const [k, v] of Object.entries(item)) props[k] = typeof v === "string" ? uid(add(v)) : v;
    refs.push(add(props));
  }
  const arr = add({ $class: uid(arrClass), "NS.objects": refs.map(uid) });
  objects[rootIndex] = { $class: uid(dictClass), "NS.keys": [uid(key)], "NS.objects": [uid(arr)] };
  return { objects, top: { root: uid(rootIndex) } };
}

// ---- SEGB -----------------------------------------------------------------------------------------------------------------------------------

export function varint(n: number): Buffer {
  const out: number[] = [];
  let v = n;
  for (;;) {
    const b = v & 0x7f;
    v = Math.floor(v / 128);
    if (v) out.push(b | 0x80);
    else {
      out.push(b);
      return Buffer.from(out);
    }
  }
}
export const tag = (field: number, wire: number, rest: Buffer = Buffer.alloc(0)): Buffer => Buffer.concat([varint(field * 8 + wire), rest]);
const pad8 = (n: number): number => (8 - (n % 8)) % 8;

/** A SEGB1 file: the 56-byte header (end-of-data offset, 48 bytes, the magic), frames of a 32-byte header and a payload padded to 8. */
export function segb1(frames: Array<{ payload: Buffer; state: number; t1: number; t2: number }>, trailing: Buffer = Buffer.alloc(0), lengthOverride?: number): Buffer {
  const body: Buffer[] = [];
  for (const f of frames) {
    const h = Buffer.alloc(32);
    h.writeInt32LE(lengthOverride ?? f.payload.length, 0);
    h.writeInt32LE(f.state, 4);
    h.writeDoubleLE(f.t1, 8);
    h.writeDoubleLE(f.t2, 16);
    body.push(h, f.payload, Buffer.alloc(pad8(32 + f.payload.length)));
  }
  const data = Buffer.concat(body);
  const head = Buffer.alloc(56);
  head.writeUInt32LE(56 + data.length, 0);
  head.write("SEGB", 52, "latin1");
  return Buffer.concat([head, data, trailing]);
}

/** A SEGB2 file: the 32-byte header (magic, count, creation time), a table of 16-byte entries (end offset, state, time), then the payloads. */
export function segb2(frames: Array<{ payload: Buffer; state: number; t: number }>, endOverride?: (i: number, end: number) => number, countOverride?: number): Buffer {
  const entries: Buffer[] = [];
  const parts: Buffer[] = [];
  let end = 0;
  frames.forEach((f, i) => {
    const start = (end + 7) & ~7;
    if (i) parts.push(Buffer.alloc(start - end));
    parts.push(f.payload);
    end = start + f.payload.length;
    const e = Buffer.alloc(16);
    e.writeInt32LE(endOverride ? endOverride(i, end) : end, 0);
    e.writeInt32LE(f.state, 4);
    e.writeDoubleLE(f.t, 8);
    entries.push(e);
  });
  const head = Buffer.alloc(32);
  head.write("SEGB", 0, "latin1");
  head.writeInt32LE(countOverride ?? frames.length, 4);
  head.writeDoubleLE(700000199, 8);
  const table = Buffer.concat([head, ...entries]);
  return Buffer.concat([table, Buffer.alloc(pad8(table.length)), ...parts]);
}

// ---- fsapfsinfo -----------------------------------------------------------------------------------------------------------------------------

/** A stand-in `fsapfsinfo` on a PATH directory: `body` is Python run with the program's arguments in `argv` after the version call has been answered. */
export async function fsapfsStub(bin: string, script: string, version = "fsapfsinfo 20231209"): Promise<void> {
  await mkdir(bin, { recursive: true });
  const file = join(bin, "fsapfsinfo");
  await writeFile(file, `#!/usr/bin/env python3\nimport os, signal, sys, time\nargv = sys.argv[1:]\nif argv == ["-V"]:\n    print(${JSON.stringify(version)})\n    sys.exit(0)\n${script}\n`);
  await chmod(file, 0o755);
}

export const FSAPFS_OK = `
print("fsapfsinfo 20231209")
print()
print("Container information:")
print("\\tNumber of volumes\\t: 2")
print("\\tBlock size\\t\\t: 4096 bytes")
print()
print("Volume: 1:")
print("\\tIdentifier\\t\\t: 11111111-2222-3333-4444-555555555555")
print("\\tName\\t\\t\\t: Macintosh HD")
print("\\tIs encrypted\\t\\t: no")
print()
print("Volume: 2:")
print("\\tIdentifier\\t\\t: 66666666-7777-8888-9999-aaaaaaaaaaaa")
print("\\tName\\t\\t\\t: Data")
print("\\tIs encrypted\\t\\t: yes")
print("\\tIs locked\\t\\t: yes")
`;

/** Every JSON string and key in a document. */
export function strings(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const v of value) strings(v, out);
  else if (value && typeof value === "object") for (const [k, v] of Object.entries(value)) (out.push(k), strings(v, out));
  return out;
}

export async function everything(cwd: string, answer: string): Promise<string> {
  return [answer, ...(await reachable(cwd, (p) => p.includes("/evidence/")))].join("\n");
}

export { readFile };
