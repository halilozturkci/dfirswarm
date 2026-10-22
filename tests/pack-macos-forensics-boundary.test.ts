/**
 * fsevents_parse, knowledgec_query and unified_log print paths, stream names, column names, values and log messages from evidence. They carry the
 * shared boundary block of the windows-forensics pack byte for byte (an allow-list per field type, a deny-list for free text, an independent
 * backstop), and this suite holds: the copies equal; the values modes declared in the manifests and refused unless the harness runs the job as
 * secret output; random canaries of 23 shapes planted in the slots each tool prints, the share printed whole asserted per family, the shapes the
 * boundary does not claim asserted to be printed; a `contains` that reads what is printed; hostile strings of 4,096 and 32,768 characters judged in
 * bounded CPU time; real strings left as they are. The stop block is held equal across the four tools.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { parseSecretDeclaration } from "../scripts/output-hygiene.ts";
import { CREATED, FS, KC, MAC, PLIST, UL, body, filesUnder, fsDir, fsPage, fsRecord, gz, kcDb, measured, ok, plainJob, reachable, secretJob, tool, ul, ulStandin, logarchive } from "./macos-pack-harness.ts";
import type { Json } from "./macos-pack-harness.ts";
import { SHAPES, fragmentLeaked, leaked, plant, type Canary, type Shape } from "./windows-canary.ts";

// ---- the blocks are copies ------------------------------------------------------------------------------------------------------------------

async function block(path: string, begin: string, end: string): Promise<string> {
  const text = await readFile(path, "utf8");
  const start = text.indexOf(begin);
  const stop = text.indexOf(end);
  assert.ok(start >= 0 && stop > start, `${path} carries ${begin}`);
  assert.equal(text.indexOf(begin, start + 1), -1, "once");
  return text.slice(start, stop + end.length);
}

const TOOLS = ["plist_read", "fsevents_parse", "knowledgec_query", "unified_log"];
const BOUNDARY = ["fsevents_parse", "knowledgec_query", "unified_log"];

test("the four tools carry the same stop block, byte for byte", async () => {
  const blocks = await Promise.all(TOOLS.map((t) => block(join(MAC, t, "run.py"), "# BEGIN SHARED STOP", "# END SHARED STOP")));
  for (const other of blocks.slice(1)) assert.equal(other, blocks[0]);
  assert.ok(blocks[0].length > 2000);
});

test("the three tools that print evidence carry the windows-forensics boundary block, byte for byte, as shipped there", async () => {
  const reference = await block(join(ROOT, "packs", "windows-forensics", "tools", "regkv", "run.py"), "# BEGIN SHARED BOUNDARY", "# END SHARED BOUNDARY");
  assert.ok(reference.length > 60_000);
  for (const t of BOUNDARY) assert.equal(await block(join(MAC, t, "run.py"), "# BEGIN SHARED BOUNDARY", "# END SHARED BOUNDARY"), reference, t);
});

// ---- the values modes are declared, and refused unless the job is secret output ----------------------------------------------------------------

const manifest = async (t: string): Promise<Json> => JSON.parse(await readFile(join(MAC, t, "manifest.json"), "utf8")) as Json;

test("the manifests of the tools that write values declare secret_output for exactly those arguments, in a form the harness accepts", async () => {
  const wanted: Record<string, string[]> = { plist_read: ["write_values"], fsevents_parse: ["write_values"], knowledgec_query: ["write_values", "export_oversize"] };
  for (const [name, args] of Object.entries(wanted)) {
    const m = await manifest(name);
    assert.deepEqual(m.secret_output, { when_args: args }, name);
    const parsed = parseSecretDeclaration(m.secret_output, m.params, true);
    assert.equal(parsed.ok, true, `${name}: ${JSON.stringify(parsed)}`);
    for (const a of args) assert.equal(m.params[a].type, "boolean", `${name}.${a}`);
    assert.match(m.description, /SENSITIVE/, name);
  }
  assert.equal((await manifest("unified_log")).secret_output, undefined, "unified_log writes no value of its own: the reader's output is a file of the job");
  assert.match((await manifest("unified_log")).description, /SENSITIVE/);
});

test("write_values and export_oversize are refused as JSON, before anything is made, outside a job and in a job that is not secret output", async () => {
  await withCwd(async (cwd) => {
    const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(fsPage("2SLD", [fsRecord("a/b", 1n, CREATED, 1n)])) });
    const db = await kcDb(cwd, "k.db", 20);
    await writeFile(join(cwd, "work", "p.plist"), '<?xml version="1.0"?><plist version="1.0"><dict><key>a</key><string>b</string></dict></plist>');
    const cases: Array<[string, string, Json]> = [
      ["plist_read", PLIST, { path: "work/p.plist", write_values: true }],
      ["fsevents_parse", FS, { path: dir, write_values: true }],
      ["knowledgec_query", KC, { db, write_values: true }],
      ["knowledgec_query", KC, { db, export_oversize: true }],
    ];
    for (const [name, script, args] of cases) {
      for (const run of [await tool(script, cwd, args), await plainJob(script, cwd, args)]) {
        assert.equal(run.code, 1, `${name} ${JSON.stringify(args)}: ${run.stderr}`);
        const answer = body(run);
        assert.equal(answer.status, "failed");
        assert.match(answer.error, /secret output|outside a job/);
        assert.equal(typeof answer.status_basis, "string");
      }
    }
    assert.deepEqual((await filesUnder(join(cwd, "out"))).filter((f) => !f.endsWith(".gitkeep")), [], "nothing was written in the job's output");
    // In a job the harness runs as secret output the same requests are accepted.
    ok(await secretJob(FS, cwd, { path: dir, write_values: true }));
    ok(await secretJob(KC, cwd, { db, export_oversize: true }));
  });
});

// ---- random canaries in the slots each tool prints ---------------------------------------------------------------------------------------------

const N = Number(process.env.MACOS_CANARY_N ?? 300);
const BOUND: Record<string, number> = {
  "token prefix families": 1, JWT: 1, "PEM private key": 1, "named secrets and user-info": 1, "invisible splits": 1,
  "AWS-shaped and base64 keys": 6, "generic random token": 3,
};
const NAMES = ["ghp", "github_pat", "akia", "glpat", "sk_live", "sendgrid", "aiza", "npm", "jwt", "aws_secret40", "b64_16", "b64_20", "b64_32", "pem", "pw_assign", "pw_colon", "userinfo_at", "nul_split", "zw_split", "random_base62_24", "random_base62_40", "plain_password", "passphrase", "uuid_secret"];
const shapes = NAMES.map((n) => SHAPES.find((s) => s.name === n)!);
const clean = (cs: Canary[]): Canary[] => cs.map((c) => ({ ...c, text: c.text.replace(/\u0000/g, "") }));
const rate = (cs: Canary[], outputs: string[]): number => (100 * leaked(cs, outputs)) / cs.length;

function check(shape: Shape, r: number, where: string): void {
  if (shape.residual) assert.ok(r >= 90, `${shape.name}: a shape the boundary does not claim is printed in ${where} (${r.toFixed(1)}%)`);
  else assert.ok(r <= BOUND[shape.family], `${shape.name}: ${r.toFixed(1)}% printed whole in ${where}, bound ${BOUND[shape.family]}%`);
}

const outputsOf = async (cwd: string, run: { stdout: string; stderr: string }, skip: (f: string) => boolean): Promise<string[]> => [run.stdout, run.stderr, ...(await reachable(cwd, skip))];

for (const shape of shapes) {
  test(`fsevents_parse: ${shape.name} in the path of a record is withheld at the shown rate, in the answer and in every file`, async () => {
    const canaries = clean(plant(shape, N, 41));
    await withCwd(async (cwd) => {
      const pages: Buffer[] = [];
      for (let i = 0; i < canaries.length; i += 100) pages.push(fsPage("2SLD", canaries.slice(i, i + 100).map((c, k) => fsRecord(`Users/alice/${c.text}`, BigInt(i + k + 1), CREATED, BigInt(i + k + 1)))));
      const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(Buffer.concat(pages)) });
      const run = await tool(FS, cwd, { path: dir, limit: 20 });
      const answer = body(run);
      assert.ok(answer.boundary, "the answer says what the boundary did");
      check(shape, rate(canaries, await outputsOf(cwd, run, (f) => f.includes("/ev/"))), "the answer or a file");
    });
  });

  test(`knowledgec_query: ${shape.name} as a value, in another column, in a BLOB's head and as a column name is withheld at the shown rate`, async () => {
    const canaries = clean(plant(shape, N, 43));
    await withCwd(async (cwd) => {
      const over: Record<string, Record<string, unknown>> = {};
      canaries.forEach((c, i) => {
        const bytes = Buffer.concat([Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]), Buffer.from(c.text, "utf8"), Buffer.from([9, 8, 7])]);
        over[String(i + 1)] = { ZVALUESTRING: c.text, ZX0: c.text, ZX1: { hex: bytes.toString("hex") } };
      });
      const db = await kcDb(cwd, "k.db", canaries.length, ["ZX0", "ZX1"], over);
      const run = await tool(KC, cwd, { db, limit: 20, out_file: "work/o.jsonl" });
      const answer = body(run);
      assert.ok(answer.boundary);
      check(shape, rate(canaries, await outputsOf(cwd, run, (f) => f.endsWith("/k.db"))), "a value, a column or a BLOB head");
      // as the name of a column (a schema is printed: the columns of ZOBJECT, the joins, the SQL of an error)
      const named = await kcDb(cwd, "n.db", 5, canaries.map((c, i) => `${c.text.slice(0, 120)}~${i}`));
      const byName = await tool(KC, cwd, { db: named, limit: 5 });
      body(byName);
      check(shape, rate(canaries, await outputsOf(cwd, byName, (f) => f.endsWith("/k.db") || f.endsWith("/n.db"))), "the name of a column");
    });
  });

  test(`unified_log: ${shape.name} in a message, a process path and a subsystem of the preview is withheld at the shown rate`, async () => {
    const canaries = clean(plant(shape, N, 47)).filter((c) => !/[\r\n]/.test(c.text));
    await withCwd(async (cwd) => {
      await writeFile(join(cwd, "work", "canaries.json"), JSON.stringify(canaries.map((c) => c.text)));
      const bin = await ulStandin(cwd, `
texts = json.load(open("work/canaries.json"))
with open(out, "w") as f:
    for t in texts:
        f.write(json.dumps({"timestamp": "2026-02-14T09:30:00.000000+0000", "eventMessage": "login " + t, "processImagePath": "/usr/bin/" + t, "subsystem": "com.apple." + t, "process": "sudo"}) + "\\n")
`);
      const run = await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u", limit: canaries.length });
      const answer = body(run);
      assert.ok(answer.boundary);
      assert.equal(answer.entry_count, canaries.length);
      // the reader's own output file is the reader's: it is not read here
      check(shape, rate(canaries, await outputsOf(cwd, run, (f) => f.endsWith("unifiedlogs.jsonl") || f.endsWith("canaries.json") || f.endsWith("unifiedlogs.ndjson"))), "the preview");
    });
  });
}

test("a canary planted in all four slots is searched with the same oracle: 12-character pieces of the whole are not printed either", async () => {
  const shape = SHAPES.find((s) => s.name === "ghp")!;
  const canaries = clean(plant(shape, 100, 53));
  await withCwd(async (cwd) => {
    const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(fsPage("2SLD", canaries.map((c, i) => fsRecord(`Users/alice/${c.text}`, BigInt(i + 1), CREATED, BigInt(i + 1))))) });
    const run = await tool(FS, cwd, { path: dir, out_file: "work/o.jsonl" });
    body(run);
    assert.equal(fragmentLeaked(canaries, await outputsOf(cwd, run, (f) => f.includes("/ev/"))), 0);
  });
});

// ---- write_values: the originals of what was withheld, in one file, in a secret job ------------------------------------------------------------

test("write_values puts the originals of the withheld strings in one 0600 file of a secret job and nowhere else; the answer carries none", async () => {
  const canaries = clean(plant(SHAPES.find((s) => s.name === "glpat")!, 40, 59));
  await withCwd(async (cwd) => {
    const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(fsPage("2SLD", canaries.map((c, i) => fsRecord(`Users/alice/${c.text}`, BigInt(i + 1), CREATED, BigInt(i + 1))))) });
    const db = await kcDb(cwd, "k.db", canaries.length, ["ZX0"], Object.fromEntries(canaries.map((c, i) => [String(i + 1), { ZVALUESTRING: c.text }])));
    for (const [name, script, args, file] of [["fsevents_parse", FS, { path: dir, out_file: "work/o1.jsonl", write_values: true }, "fsevents_parse-values.jsonl"], ["knowledgec_query", KC, { db, out_file: "work/o2.jsonl", write_values: true }, "knowledgec_query-values.jsonl"]] as const) {
      const run = await secretJob(script, cwd, args);
      const answer = ok(run);
      const target = join(cwd, "out", file);
      assert.equal((await stat(target)).mode & 0o777, 0o600, name);
      const originals = await readFile(target, "utf8");
      assert.equal(leaked(canaries, [originals]) >= canaries.length * 0.9, true, `${name}: the values file holds the originals`);
      assert.equal(answer.boundary.values.written > 0, true, name);
      assert.equal(answer.boundary.values.values_file, `store/jobs/j-1/out/${file}`);
      const elsewhere = await outputsOf(cwd, run, (f) => f.endsWith("-values.jsonl") || f.endsWith("/k.db") || f.includes("/ev/"));
      assert.equal(leaked(canaries, elsewhere), 0, `${name}: no original outside the values file`);
    }
  });
});

// ---- a contains that reads what the answer prints ----------------------------------------------------------------------------------------------

test("fsevents_parse: contains is looked for in the path as printed, so a piece of a withheld path matches nothing, and the blind count is the same for any needle", async () => {
  await withCwd(async (cwd) => {
    const secret = "ghp_" + "Zq7Svb9Kt0Lm4Pw8Yd2Xc5Rf1Bn6Hj3Ae0Qs";
    const dir = await fsDir(cwd, "ev", {
      "0000000000000001": gz(fsPage("2SLD", [fsRecord(`Users/alice/${secret}`, 1n, CREATED, 1n), fsRecord("Users/alice/Documents/report.docx", 2n, CREATED, 2n)])),
    });
    const hit = ok(await tool(FS, cwd, { path: dir, contains: secret.slice(0, 20) }));
    assert.equal(hit.record_count, 0, "a needle that is part of a withheld path matches nothing");
    assert.equal(hit.filters.contains_blind_records, 1, "the record whose path is withheld is counted");
    assert.equal(hit.status, "partial");
    const other = ok(await tool(FS, cwd, { path: dir, contains: "no-such-needle-anywhere" }));
    assert.equal(other.filters.contains_blind_records, hit.filters.contains_blind_records, "the same count for another needle: it is no way to test a guess");
    assert.equal(other.record_count, 0);
    const shown = ok(await tool(FS, cwd, { path: dir, contains: "report\\.docx" }));
    assert.equal(shown.record_count, 1);
    assert.equal(shown.filters.contains_blind_records, 1, "the other record is still counted: its path has text withheld in it");
    const nothingHidden = await fsDir(cwd, "ev2", { "0000000000000001": gz(fsPage("2SLD", [fsRecord("Users/alice/Documents/report.docx", 1n, CREATED, 1n)])) });
    const absent = ok(await tool(FS, cwd, { path: nothingHidden, contains: "zzz-not-there" }));
    assert.equal(absent.record_count, 0);
    assert.equal(absent.filters.contains_blind_records, 0);
    assert.equal(absent.status, "complete", "nothing is withheld, so none is none");
  });
});

// ---- hostile strings of 4,096 and 32,768 characters -------------------------------------------------------------------------------------------

const TOKEN = "ghp_" + "Zq7Svb9Kt0Lm4Pw8Yd2Xc5Rf1Bn6Hj3Ae0Qs";
const ATOMS: Array<[string, string]> = [
  ["backslashes", "\\"], ["eyJ", "eyJ"], ["password=", "password="], ["pem", "-----BEGIN PRIVATE KEY-----"], ["a-a-", "a-a-"], ["AKIA", "AKIA"], ["x", "x"],
  ["userinfo", "https://u:"], ["hex", "0123456789abcdef"], ["equals", "="], ["=A", "=A"], ["digits", "1234567890123456789"], ["slashes", "a/b/"], ["at", "a@"],
];
const hostile = (n: number): string[] => ATOMS.map(([, atom]) => TOKEN + " " + atom.repeat(Math.ceil(n / atom.length)).slice(0, n));

for (const size of [4096, 32768]) {
  test(`the three tools judge ${ATOMS.length} hostile shapes of ${size} characters in bounded CPU time and print the token that led them in none`, async () => {
    const strings = hostile(size);
    await withCwd(async (cwd) => {
      const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(fsPage("2SLD", strings.map((s, i) => fsRecord(`Users/alice/${s}`, BigInt(i + 1), CREATED, BigInt(i + 1))))) });
      const fsRun = await measured(FS, cwd, { path: dir, out_file: "work/o.jsonl" });
      assert.equal(fsRun.code, 0, fsRun.stderr);
      assert.ok(fsRun.cpu < 30, `fsevents_parse ${fsRun.cpu.toFixed(1)} s of CPU`);
      const db = await kcDb(cwd, "k.db", strings.length, ["ZX0"], Object.fromEntries(strings.map((s, i) => [String(i + 1), { ZVALUESTRING: s, ZX0: s }])));
      const kcRun = await measured(KC, cwd, { db, out_file: "work/ok.jsonl" });
      assert.equal(kcRun.code, 0, kcRun.stderr);
      assert.ok(kcRun.cpu < 30, `knowledgec_query ${kcRun.cpu.toFixed(1)} s of CPU`);
      await writeFile(join(cwd, "work", "canaries.json"), JSON.stringify(strings));
      const bin = await ulStandin(cwd, `
texts = json.load(open("work/canaries.json"))
with open(out, "w") as f:
    for t in texts:
        f.write(json.dumps({"timestamp": "2026-02-14T09:30:00.000000+0000", "eventMessage": t, "process": "sudo", "subsystem": "s"}) + "\\n")
`);
      const ulRun = await measured(UL, cwd, { path: await logarchive(cwd), out_dir: "work/u", limit: 100 }, { PATH: bin });
      assert.equal(ulRun.code, 0, ulRun.stderr);
      assert.ok(ulRun.cpu < 30, `unified_log ${ulRun.cpu.toFixed(1)} s of CPU`);
      for (const [name, printed] of [["fsevents_parse", fsRun.stdout], ["knowledgec_query", kcRun.stdout], ["unified_log", ulRun.stdout]] as const) {
        assert.ok(!printed.includes(TOKEN), `${name} printed the token that led the string`);
      }
      const files = (await reachable(cwd, (f) => f.endsWith("/k.db") || f.includes("/ev/") || f.endsWith("canaries.json") || f.endsWith("unifiedlogs.jsonl") || f.endsWith("unifiedlogs.ndjson"))).join("\n");
      assert.ok(!files.includes(TOKEN), "a result file holds the token");
    });
  });
}

// ---- real strings come out as they went in ------------------------------------------------------------------------------------------------------

const REAL_PATHS = [
  "Users/alice/Documents/Quarterly report (final).docx", "Applications/Safari.app/Contents/MacOS/Safari", "private/var/db/dslocal/nodes/Default/users/alice.plist",
  "Library/Preferences/com.apple.loginwindow.plist", "Users/alice/Library/Application Support/Google/Chrome/Default/History", "System/Library/CoreServices/Finder.app",
  "private/etc/sudoers.d/admin", "Users/alice/Downloads/Setup-1.2.3.pkg", "Users/alice/.zsh_history", "Library/LaunchDaemons/com.example.helper.plist",
  "Users/alice/Library/Mobile Documents/com~apple~CloudDocs/notes.txt", "Volumes/Backup/Time Machine/2026-02-14-093000.previous", "usr/local/bin/brew",
  "Users/alice/Pictures/Photos Library.photoslibrary/database/Photos.sqlite", "private/var/log/system.log", "Users/alice/Desktop/Screenshot 2026-02-14 at 9.30.00 AM.png",
];
const REAL_MESSAGES = ["Reached target multi-user", "Unable to find a password for com.apple.mail", "launchd: service exited with abnormal code: 78", "com.apple.xpc.launchd", "sudo: alice : TTY=ttys001 ; USER=root ; COMMAND=/usr/bin/id"];
/** A cost the block has and the manifests state: sudo's `PWD=` is taken for a password's name, and its value is withheld. */
const SUDO_PWD = "sudo: alice : TTY=ttys001 ; PWD=/Users/alice ; USER=root ; COMMAND=/usr/bin/id";

test("real paths, stream names, column names and messages are printed as they are", async () => {
  await withCwd(async (cwd) => {
    const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(fsPage("2SLD", REAL_PATHS.map((p, i) => fsRecord(p, BigInt(i + 1), CREATED, BigInt(i + 1))))) });
    const fs = ok(await tool(FS, cwd, { path: dir }));
    assert.deepEqual(fs.records.map((r: Json) => r.path), REAL_PATHS);
    assert.equal(fs.status, "complete");
    assert.equal(fs.boundary.strings_withheld, 0);
    const db = await kcDb(cwd, "k.db", 10);
    const kc = ok(await tool(KC, cwd, { db }));
    assert.equal(kc.status, "complete");
    assert.deepEqual(kc.entries.slice(0, 5).map((e: Json) => e.stream), ["/app/usage", "/display/isBacklit", "/device/isLocked", "/safari/history", "/app/inFocus"]);
    assert.equal(kc.entries[0].metadata.Z_DKSAFARIHISTORYMETADATAKEY__URL, "https://example.com/page2");
    assert.equal(kc.boundary.strings_withheld, 0);
    await writeFile(join(cwd, "work", "canaries.json"), JSON.stringify(REAL_MESSAGES));
    const bin = await ulStandin(cwd, `
texts = json.load(open("work/canaries.json"))
with open(out, "w") as f:
    for t in texts:
        f.write(json.dumps({"timestamp": "2026-02-14T09:30:00.000000+0000", "eventMessage": t, "processImagePath": "/usr/libexec/xpcproxy", "subsystem": "com.apple.xpc.launchd"}) + "\\n")
`);
    const log = ok(await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u" }));
    assert.deepEqual(log.entries.map((e: Json) => e.eventMessage), REAL_MESSAGES);        // (the stand-in's own path is a random temp directory: that one is withheld, as it should be)
    await writeFile(join(cwd, "work", "canaries.json"), JSON.stringify([SUDO_PWD]));
    const sudo = ok(await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u2" }));
    assert.equal(sudo.entries[0].eventMessage, "sudo: alice : TTY=ttys001 ; PWD=<withheld 12 characters: secret value> ; USER=root ; COMMAND=/usr/bin/id", "the cost of the named-secret rule: PWD= is taken for a password");
  });
});

test("a BLOB's head is printed as hexadecimal, and a BLOB that holds a secret-shaped text is withheld", async () => {
  await withCwd(async (cwd) => {
    const secret = "ghp_" + "Zq7Svb9Kt0Lm4Pw8Yd2Xc5Rf1Bn6Hj3Ae0Qs";
    const plain = Buffer.from([0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 1, 2, 3, 4]);
    const holding = Buffer.concat([Buffer.from([1, 2, 3]), Buffer.from(secret), Buffer.from([4])]);
    const db = await kcDb(cwd, "k.db", 2, ["ZX0"], { "1": { ZX0: { hex: plain.toString("hex") } }, "2": { ZX0: { hex: holding.toString("hex") } } });
    const answer = ok(await tool(KC, cwd, { db }));
    const [a, b] = [answer.entries[0], answer.entries[1]].sort((x: Json, y: Json) => x.z_pk - y.z_pk);
    assert.deepEqual(a.zobject_other.ZX0, { _blob_bytes: 12, _hex: plain.toString("hex"), _truncated: false });
    assert.match(b.zobject_other.ZX0._hex, /^<withheld \d+ characters: binary data holding a secret-shaped text>$/);
    assert.ok(!answer.entries.some((e: Json) => JSON.stringify(e).includes(secret)));
    assert.ok(!JSON.stringify(answer).includes(Buffer.from(secret).toString("hex")));
  });
});
