/**
 * Expressions and loops of the windows, macos, linux and triage packs that were tried at every offset of a text a file chose, and
 * cost the square of its length (or the cube): a shell link's strings, vshadowinfo's lines, a PAM line in auth.log, a web token in a
 * collector's text, a plist key's name. Each of them is read in time linear in the text now, and each answers what the expression
 * answered (1,000 generated texts per tool against the expression written out here). The timings were taken in Docker (node:22,
 * Python 3.11, --cpus=1); a test here fails on the code before, either by the answer or by the clock.
 *
 *   lnk_parse     a link's 65,535-character name of repeated `eyJ` (or any long run of name characters) took 25 s in the expression that
 *                 reads a URL with a password; five such strings took past the manifest's 30 s.
 *   vss_stores    a line of 4,096 spaces in vshadowinfo's output took 37 s (the cube of the length).
 *   auth_log      a 65,000-byte line of `ruser=` and spaces took a minute.
 *   triage        a text of repeated `eyJ` took 0.5 s per 8,192-character window, 6 s at 64 KiB.
 *   plist_read    a key name of 8 MiB held the secret-name pattern for 3 s (0.4 microseconds a character).
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";

const PACKS = join(ROOT, "packs");
const LNK_PARSE = join(PACKS, "windows-forensics", "tools", "lnk_parse", "run.py");
const VSS_STORES = join(PACKS, "windows-forensics", "tools", "vss_stores", "run.py");
const AUTH_LOG = join(PACKS, "linux-forensics", "tools", "auth_log", "run.py");
const PLIST_READ = join(PACKS, "macos-forensics", "tools", "plist_read", "run.py");
const TRIAGE_TOOLS = ["collection_coverage", "collection_id", "collection_index", "collection_manifest_parse", "collection_manifest_verify", "collection_path_map"];

const LOAD = [
  "import importlib.util, json, random, re, sys, time",
  "spec = importlib.util.spec_from_file_location('tool_under_test', sys.argv[1])",
  "m = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(m)",
  "def took(fn, *a):",
  "    start = time.process_time()",
  "    out = fn(*a)",
  "    return out, time.process_time() - start",
].join("\n");

/** Python code run against one tool's module, its answer a JSON line on stdout. */
function py(path: string, code: string, timeout = 120_000): unknown {
  const r = spawnSync("python3", ["-I", "-c", `${LOAD}\n${code}`, path], { encoding: "utf8", timeout, maxBuffer: 1 << 26, env: { ...process.env, AGENT_ID: "s1" } });
  assert.equal(r.status, 0, `${r.stderr}${r.error ?? ""}`);
  return JSON.parse(r.stdout);
}

/** A tool run with a deadline: past it the process is killed and the test says so, where the code before would have run for minutes. */
function run(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string, seconds = 20): Promise<{ code: number | null; stdout: string; stderr: string; killed: boolean; seconds: number }> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const child = spawn("python3", [script], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env, ...(bin ? { PATH: `${bin}:${process.env.PATH ?? ""}` } : {}) } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let killed = false;
    const timer = setTimeout(() => { killed = true; child.kill("SIGKILL"); }, seconds * 1000);
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), killed, seconds: (Date.now() - started) / 1000 });
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(JSON.stringify(args));
  });
}

// --- lnk_parse ----------------------------------------------------------------------------------------------------------------

/** MS-SHLLINK: the 76-byte header, StringData in order (name, relative path, working directory, arguments, icon location), the terminal block. */
function lnk(strings: string[]): Buffer {
  const header = Buffer.alloc(0x4c);
  header.writeUInt32LE(0x4c, 0);
  Buffer.from("0114020000000000c000000000000046", "hex").copy(header, 4);
  let flags = 0x80;
  const parts: Buffer[] = [];
  strings.forEach((text, i) => {
    flags |= [0x04, 0x08, 0x10, 0x20, 0x40][i];
    const count = Buffer.alloc(2);
    count.writeUInt16LE(text.length, 0);
    parts.push(count, Buffer.from(text, "utf16le"));
  });
  header.writeUInt32LE(flags, 0x14);
  return Buffer.concat([header, ...parts, Buffer.alloc(4)]);
}

test("lnk_parse reads a link's strings for the shape of a secret in linear time, and as the one expression did (1,000 generated texts)", () => {
  const [differences, shaped, times] = py(LNK_PARSE, [
    "OLD = re.compile(",
    "    r'(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[-_]?key|access[-_]?key|client[-_]?secret|credential|private[-_]?key|bearer|authorization)s?\\s*[=:]\\s*\\S'",
    "    r'|[a-z][a-z0-9+.-]*://[^/\\s:@]+:[^/\\s@]+@'",
    "    r'|\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}'",
    "    r'|\\bAKIA[0-9A-Z]{16}\\b|\\bgh[pousr]_[A-Za-z0-9]{20,}|\\bxox[abprs]-[A-Za-z0-9-]{10,}'",
    "    r'|-----BEGIN [A-Z ]*PRIVATE KEY'",
    "    r'|(?:^|\\s)--?(?:p|pw|pass|passw|password|passwd|pwd|token|secret|apikey|api-key)\\s+\\S')",
    "atoms = ['eyJ', 'eyJhbGciOiJI', 'EYJ', 'eyJ-', '-eyJ', '_eyJ', 'é', 'ſ', '\\u212a', '.', '..', 'a', ':', '://', '//', '@', 'a://', 'x://u:p@h', 'http://u:p@h',",
    "         'u:p@', 'ftp', '1', '+', '-', '_', ' ', '\\t', '\\n', '/', '=', 'password', 'token=', 'Bearer ', '-p ', '--password ', 'AKIAIOSFODNN7EXAMPLE',",
    "         'ghp_abcdefghijklmnopqrstuvwx', '-----BEGIN RSA PRIVATE KEY', 'abcdefghij', 'abcdefghijk', 'eyJabcdefghij.abcdefghij', 'eyJabcdefghi.abcdefghij']",
    "rnd = random.Random(11)",
    "differences, shaped = [], 0",
    "for _ in range(1000):",
    "    text = ''.join(rnd.choice(atoms) for _ in range(rnd.randint(1, 9)))",
    "    old = OLD.search(text) is not None",
    "    shaped += old",
    "    if old != m.secret_shaped(text):",
    "        differences.append(text)",
    "times = {}",
    "for unit in ['eyJ', 'eyJ-', '-eyJ', 'a', 'a.', 'a://', '://', 'x://u:', 'eyJhbGciOiJIUzI1NiJ9.', 'password ', '-p ', 'AKIA', '=']:",
    "    text = unit * (65535 // len(unit))",
    "    times[unit] = took(m.secret_shaped, text)[1]",
    "print(json.dumps([differences, shaped, times]))",
  ].join("\n")) as [string[], number, Record<string, number>];
  assert.deepEqual(differences, []);
  assert.ok(shaped > 100 && shaped < 900, `both outcomes are drawn (${shaped} of 1000 were shaped like a secret)`);
  for (const [unit, seconds] of Object.entries(times)) assert.ok(seconds < 1, `${JSON.stringify(unit)} x 65,535 characters took ${seconds.toFixed(2)} s of CPU`);
});

test("lnk_parse ends a link of five 65,535-character strings of repeated eyJ inside its manifest's 30 s (before, one such string took 25 s)", async () => {
  await withCwd(async (cwd) => {
    const name = "eyJ".repeat(21845);
    await writeFile(join(cwd, "work", "big.lnk"), lnk([name, name, name, name, name]));
    const r = await run(LNK_PARSE, cwd, { path: "work/big.lnk", size: 800_000 }, {}, undefined, 20);
    assert.equal(r.killed, false, `still running after ${r.seconds} s`);
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.ok(r.seconds < 10, `${r.seconds} s`);
    assert.equal((JSON.parse(r.stdout) as { ok: boolean }).ok, true);
  });
});

test("lnk_parse withholds a string over 262,144 characters whole, by its length, and says it was not read", () => {
  const [limit, kept, marker, rows, stored] = py(LNK_PARSE, [
    "class Values:",
    "    enabled = False",
    "    rows = []",
    "    def add(self, finding, locator, value):",
    "        Values.rows.append(finding)",
    "held, sink = m.Held(Values()), []",
    "long = 'a' * (m.SCAN_LIMIT + 1)",
    "shown = m.guard(held, sink, {'link_offset': 0, 'field': 'local_base_path_unicode'}, long)",
    "same = m.guard(held, sink, {'link_offset': 0, 'field': 'name'}, 'a' * m.SCAN_LIMIT)",
    "print(json.dumps([m.SCAN_LIMIT, same == 'a' * m.SCAN_LIMIT, shown, sink, len(Values.rows)]))",
  ].join("\n")) as [number, boolean, string, Array<Record<string, unknown>>, number];
  assert.equal(limit, 262144);
  assert.equal(kept, true, "a string at the limit is read, and printed when it holds no secret");
  assert.equal(marker, "[withheld: 262145 characters]");
  assert.equal(rows.length, 1);
  assert.equal(rows[0].field, "local_base_path_unicode");
  assert.equal(rows[0].chars, 262145);
  assert.match(String(rows[0].not_scanned), /longer than 262144 characters: withheld whole, not read for the shape of a secret/);
  assert.equal(stored, 1);
});

// --- vss_stores ---------------------------------------------------------------------------------------------------------------

test("vss_stores reads a `key : value` line of vshadowinfo's output in linear time, as the expression did (1,000 generated lines)", () => {
  const [differences, matched, times] = py(VSS_STORES, [
    "FIELD = re.compile(r'^\\s+(.+?)\\s*:\\s*(.*\\S)\\s*$')",
    "atoms = [' ', '  ', '\\t', ':', ' : ', 'a', 'Identifier', '{b7a6d1e0-0000-0000-0000-000000000000}', '\\u00a0', 'é', 'x y', ': ']",
    "rnd = random.Random(5)",
    "differences, matched = [], 0",
    "for _ in range(1000):",
    "    line = ''.join(rnd.choice(atoms) for _ in range(rnd.randint(0, 7)))",
    "    old = FIELD.match(line)",
    "    old = None if old is None else [old.group(1), old.group(2)]",
    "    matched += old is not None",
    "    new = m.parse_field(line)",
    "    if old != (None if new is None else list(new)):",
    "        differences.append([line, old, new])",
    "times = {}",
    "for name, line in [('spaces', ' ' * 65536), ('spaces then colon', ' ' * 65536 + ':'), ('spaces, colon, x', ' ' * 65536 + ':x'), ('colons', ' ' + ':' * 65535), ('space colon pairs', ' :' * 32768), ('key then spaces', '  key' + ' ' * 65536 + ': v')]:",
    "    times[name] = took(m.parse_field, line)[1]",
    "print(json.dumps([differences, matched, times]))",
  ].join("\n")) as [unknown[], number, Record<string, number>];
  assert.deepEqual(differences, []);
  assert.ok(matched > 100 && matched < 900, `both outcomes are drawn (${matched} of 1000 matched)`);
  for (const [name, seconds] of Object.entries(times)) assert.ok(seconds < 1, `${name}: ${seconds.toFixed(2)} s of CPU`);
});

test("vss_stores finishes when vshadowinfo prints a line of 4,096 spaces (before, 37 s) and still reads the fields around it", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "disk.raw"), Buffer.alloc(4096));
    await mkdir(bin, { recursive: true });
    const report = [
      "vshadowinfo 20240101", "", "Volume Shadow Snapshot information:", "\tNumber of stores:\t1", "", "Store: 1", " ".repeat(4096), "\tIdentifier\t\t: {b7a6d1e0-0000-0000-0000-000000000000}",
      "\tVolume size\t\t: 104857600 bytes",
    ].join("\n");
    await writeFile(join(cwd, "report.txt"), report + "\n");
    await writeFile(join(bin, "vshadowinfo"), `#!/bin/sh\ncat '${join(cwd, "report.txt")}'\n`, { mode: 0o755 });
    const r = await run(VSS_STORES, cwd, { image: "work/disk.raw" }, {}, bin, 15);
    assert.equal(r.killed, false, `still running after ${r.seconds} s`);
    assert.equal(r.code, 0, r.stderr + r.stdout);
    const answer = JSON.parse(r.stdout) as { stores?: Array<Record<string, unknown>> };
    assert.equal(answer.stores?.length, 1);
    assert.equal(answer.stores?.[0].identifier, "{b7a6d1e0-0000-0000-0000-000000000000}");
    assert.equal(answer.stores?.[0].volume_size, "104857600 bytes");
  });
});

// --- auth_log -----------------------------------------------------------------------------------------------------------------

test("auth_log finds the rhost that ends a PAM failure's text in one pass from the end, as the expression did (1,000 generated texts)", () => {
  const [differences, matched, times] = py(AUTH_LOG, [
    "OLD = re.compile(r'\\s*(?:^|\\s)rhost=(\\S*)\\s*$')",
    "atoms = ['rhost=', 'rhost=192.0.2.5', ' ', '  ', '\\t', '\\n', '\\r\\n', '\\x1c', '\\u00a0', '\\u2003', 'a', 'b c', 'ruser=', 'user=', '=', 'xrhost=', 'rhost', 'rhost =', 'é', '192.0.2.5', 'rhost=a rhost=b', ':', '']",
    "rnd = random.Random(3)",
    "differences, matched = [], 0",
    "for _ in range(1000):",
    "    text = ''.join(rnd.choice(atoms) for _ in range(rnd.randint(0, 8)))",
    "    old = OLD.search(text)",
    "    old = None if old is None else [old.start(), old.group(1)]",
    "    matched += old is not None",
    "    new = m.pam_rhost_last(text)",
    "    if old != (None if new is None else list(new)):",
    "        differences.append([text, old, new])",
    "times = {}",
    "for name, text in [('spaces', ' ' * 65000 + 'b'), ('spaces, rhost', ' ' * 65000 + ' rhost=x'), ('rhost, spaces', 'rhost=x' + ' ' * 65000), ('rhosts', 'rhost= ' * 9000), ('tabs', '\\t' * 65000)]:",
    "    times[name] = took(m.pam_rhost_last, text)[1]",
    "print(json.dumps([differences, matched, times]))",
  ].join("\n")) as [unknown[], number, Record<string, number>];
  assert.deepEqual(differences, []);
  assert.ok(matched > 50 && matched < 900, `both outcomes are drawn (${matched} of 1000 matched)`);
  for (const [name, seconds] of Object.entries(times)) assert.ok(seconds < 1, `${name}: ${seconds.toFixed(2)} s of CPU`);
});

test("auth_log reads a 65,000-byte PAM failure line of spaces in under a second (before, a minute), and still takes the rhost and ruser of an ordinary one", async () => {
  await withCwd(async (cwd) => {
    const head = "Feb 14 09:30:02 web01 sshd[2201]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser=";
    const long = `${head}a${" ".repeat(65000 - head.length - 2)}b`;
    const ordinary = `${head}bob rhost=192.0.2.5  user=alice`;
    await mkdir(join(cwd, "work", "log"), { recursive: true });
    await writeFile(join(cwd, "work", "log", "auth.log"), `${long}\n${ordinary}\n`);
    const r = await run(AUTH_LOG, cwd, { path: "work/log" }, {}, undefined, 20);
    assert.equal(r.killed, false, `still running after ${r.seconds} s`);
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.ok(r.seconds < 5, `${r.seconds} s`);
    const answer = JSON.parse(r.stdout) as { records: Array<Record<string, unknown>> };
    const failures = answer.records.filter((row) => row.kind === "auth_failure");
    assert.equal(failures.length, 2);
    assert.equal(failures[1].source, "192.0.2.5");
    assert.equal(failures[1].ruser_bytes, 3, "the name after ruser= is withheld, its length is kept");
    assert.equal(failures[0].source, undefined, "no rhost ends the long line");
    assert.equal(failures[0].ruser_bytes, 65000 - head.length, "the whole long name after ruser= is the ruser");
  });
});

// --- triage-collection --------------------------------------------------------------------------------------------------------

test("every triage tool finds a web token in a text in linear time, as the expression did (1,000 generated texts per tool)", () => {
  for (const name of TRIAGE_TOOLS) {
    const [differences, found, times] = py(join(PACKS, "triage-collection", "tools", name, "run.py"), [
      "OLD = re.compile(r'eyJ[A-Za-z0-9_=-]{8,}(?:\\.[A-Za-z0-9_=-]*){2,4}')",
      "atoms = ['eyJ', 'eyJ', 'eyJhbGciOiJI', 'eyJabcdefgh', 'eyJabcdefg', '.', '..', '...', 'a', 'abcdefgh', '=', '==', '-', '_', 'é', ' ', '\\n', 'x.y.z',",
      "         'eyJhbGciOiJI.eyJzdWIiOiIx.SflKxwRJ', '.eyJ', 'eyJ.', '/', '%', 'Bearer ', 'eyj', '.a.b.c.d.e.f']",
      "rnd = random.Random(7)",
      "differences, found = [], 0",
      "for _ in range(1000):",
      "    text = ''.join(rnd.choice(atoms) for _ in range(rnd.randint(0, 10)))",
      "    old = [x.span() for x in OLD.finditer(text)]",
      "    found += bool(old)",
      "    new = m._web_token_spans(text)",
      "    if old != new:",
      "        differences.append([text, old, new])",
      "times = {}",
      "for unit in ['eyJ', 'eyJ.', 'eyJ..', 'eyJ-', 'eyJ=', 'a.eyJ', 'eyJabcdefgh.', 'eyJabcdefgh.a.']:",
      "    text = unit * (65535 // len(unit))",
      "    times[unit] = took(m._web_token_spans, text)[1]",
      "    times['scrub ' + unit] = took(m.scrub, text)[1]",
      "print(json.dumps([differences, found, times]))",
    ].join("\n")) as [unknown[], number, Record<string, number>];
    assert.deepEqual(differences, [], name);
    assert.ok(found > 100 && found < 900, `${name}: both outcomes are drawn (${found} of 1000 held a token)`);
    for (const [unit, seconds] of Object.entries(times)) assert.ok(seconds < 1, `${name}: ${JSON.stringify(unit)} x 65,535 characters took ${seconds.toFixed(2)} s of CPU`);
  }
});

test("every triage tool still withholds a web token by its shape (two to four parts), and reads the text around it", () => {
  for (const name of TRIAGE_TOOLS) {
    const [whole, three, five, bare, short] = py(join(PACKS, "triage-collection", "tools", name, "run.py"), [
      "jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk'",
      "print(json.dumps([m.scrub('Authorization seen in ' + jwt + ' for host'), m.scrub('x eyJabcdefgh.a.b y'), m.scrub('x eyJabcdefgh.a.b.c.d.e y'),",
      "                  m.scrub('see ' + 'eyJ' * 3 + ' here'), m.scrub('eyJabcdefg.a.b is short')]))",
    ].join("\n")) as [string, string, string, string, string];
    assert.match(whole, /^Authorization seen in <[a-z -]+ withheld, 91 characters, W000001> for host$/, name);
    assert.equal(three, "x <web-token-shaped text withheld, 15 characters, W000002> y", `three parts: ${name}`);
    assert.equal(five, "x <web-token-shaped text withheld, 19 characters, W000003>.e y", "a token takes at most four parts: " + name);
    assert.equal(bare, "see eyJeyJeyJ here", name);
    assert.equal(short, "eyJabcdefg.a.b is short", "seven characters after the head are not a token: " + name);
  }
});

// --- plist_read ---------------------------------------------------------------------------------------------------------------

test("plist_read does not read a key name of over 65,536 characters for a secret's name: the value is withheld, with that reason (before, 8 MiB of name took 3 s)", async () => {
  const [seconds, withheld, reason, plain, atLimit] = py(PLIST_READ, [
    "class Ids:",
    "    n = 0",
    "    def __call__(self):",
    "        self.n += 1",
    "        return 'L%06d' % self.n",
    "walk = m.Walk(Ids(), 1000, 100, 4096, True)",
    "big = {'a' * (8 << 20): 'value'}",
    "out, seconds = took(walk.convert, big, [], 0)",
    "again = m.Walk(Ids(), 1000, 100, 4096, True)",
    "ordinary = again.convert({'a' * 65536: 'kept', 'b' * 65537: 'held', 'Password': 'held too'}, [], 0)",
    "print(json.dumps([seconds, out['a' * (8 << 20)], walk.found[0][1]['reason'], ordinary['a' * 65536], ordinary['b' * 65537]]))",
  ].join("\n")) as [number, Record<string, unknown>, string, string, Record<string, unknown>];
  assert.ok(seconds < 1, `${seconds.toFixed(2)} s of CPU`);
  assert.match(String(withheld._withheld), /^the key's name is over 65536 characters and was not read for a secret's name$/);
  assert.match(reason, /^key name over 65536 characters: not read for a secret's name, so withheld$/);
  assert.equal(plain, "kept", "a name of exactly the limit is read as before");
  assert.match(String(atLimit._withheld), /over 65536 characters/);
});

test("plist_read answers a file whose key name is over the limit with a locator, not the value", async () => {
  await withCwd(async (cwd) => {
    const make = [
      "import plistlib, sys",
      "plistlib.dump({'k' * 70000: 'the value', 'ordinary': 'shown'}, open(sys.argv[1], 'wb'), fmt=plistlib.FMT_XML)",
    ].join("\n");
    assert.equal(spawnSync("python3", ["-c", make, join(cwd, "work", "long.plist")]).status, 0);
    const r = await run(PLIST_READ, cwd, { path: "work/long.plist" }, {}, undefined, 20);
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.doesNotMatch(r.stdout, /the value/);
    assert.match(r.stdout, /over 65536 characters/);
    assert.match(r.stdout, /shown/);
  });
});
