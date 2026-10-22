/**
 * encrypted-containers, second round: a name or a header string that takes the withholding rule a long time, a clock that is read too
 * rarely, an End record inside a ZIP comment, a read that never returns, and the smaller findings that came with them. Every test here
 * fails on the tools as they were before this round; fixtures are built from the formats and canaries from pieces.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, runPySnippet, withCwd } from "./tool-library-harness.ts";

const ENC = join(ROOT, "packs", "encrypted-containers", "tools");
const SCAN = join(ENC, "recovery_key_scan", "run.py");
const PROBE = join(ENC, "archive_probe", "run.py");
const ID = join(ENC, "crypto_id", "run.py");
const AGENT = { AGENT_ID: "s1" };
const FULLWIDTH_SOLIDUS = "／";
const LONG_TEXT = "<text too long to judge withheld>";

type Run = { code: number | null; stdout: string; stderr: string };
type Json = Record<string, any>;

async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
}

/** The answer of a run that ended as the tool meant (one JSON document, no traceback). */
function answer(out: Run, code = 0): Json {
  assert.equal(out.code, code, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as Json;
}

/** A run of a tool as a child of a Python driver, which reports the child's CPU seconds (immune to a loaded host) and wall seconds. */
const TIMED = String.raw`
import json, os, resource, subprocess, sys, time
call = json.load(sys.stdin)
t0 = time.time()
p = subprocess.run(["python3", sys.argv[1]], input=json.dumps(call["args"]).encode(), capture_output=True, cwd=sys.argv[2], env={**os.environ, "AGENT_ID": "s1", **call.get("env", {})})
u = resource.getrusage(resource.RUSAGE_CHILDREN)
try:
    out = json.loads(p.stdout)
except ValueError:
    out = None
print(json.dumps({"code": p.returncode, "cpu": u.ru_utime + u.ru_stime, "wall": time.time() - t0, "out": out, "err": p.stderr.decode()[-400:]}))
`;

async function timed(script: string, cwd: string, args: unknown, env: Record<string, string> = {}): Promise<{ code: number; cpu: number; wall: number; out: Json; err: string }> {
  const run = await runPySnippet(TIMED, [script, cwd], { args, env });
  assert.equal(run.code, 0, run.stderr);
  return JSON.parse(run.stdout);
}

// --- scaffolding that stands in for a slow clock, a read that never returns, a missing 7z --------------------------------------------

/** A sitecustomize, switched by the environment: FAST_CLOCK (time.monotonic advances half a second a call), HIDE_7Z, STUCK_SUFFIX (a read of a
 * file with that ending never returns; STUCK_MASK also blocks the signals that could end it), PREAD_STUCK (os.pread never returns), SCALE_STOP
 * (the hard stop runs that many times faster), BOOM (os.path.realpath raises with that text). */
const SITE = String.raw`
import builtins, os, signal, time
if os.environ.get("FAST_CLOCK"):
    _t = [0.0]
    def _monotonic():
        _t[0] += 0.5
        return _t[0]
    time.monotonic = _monotonic
if os.environ.get("SCALE_STOP"):
    _k = float(os.environ["SCALE_STOP"])
    _pc = time.perf_counter
    time.perf_counter = lambda: _pc() * _k
    _set = signal.setitimer
    signal.setitimer = lambda which, seconds, interval=0.0: _set(which, seconds / _k, interval)
if os.environ.get("HIDE_7Z"):
    import shutil
    _which = shutil.which
    shutil.which = lambda c, *a, **k: None if str(c) in ("7z", "7zz", "7za") else _which(c, *a, **k)
def _block():
    if os.environ.get("STUCK_MASK"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM, signal.SIGTERM})
    r, _w = os.pipe()
    os.read(r, 1)
if os.environ.get("STUCK_SUFFIX"):
    _open = builtins.open
    class Stuck:
        def __init__(self, fh): self._fh = fh
        def read(self, n=-1): _block()
        def __enter__(self): return self
        def __exit__(self, *a): self._fh.close()
        def __getattr__(self, name): return getattr(self._fh, name)
    def _stuck_open(file, mode="r", *a, **k):
        fh = _open(file, mode, *a, **k)
        return Stuck(fh) if "b" in mode and str(file).endswith(os.environ["STUCK_SUFFIX"]) else fh
    builtins.open = _stuck_open
if os.environ.get("PREAD_STUCK"):
    os.pread = lambda fd, n, off: _block()
if os.environ.get("BOOM"):
    def _boom(*a, **k): raise RuntimeError(os.environ["BOOM"])
    os.path.realpath = _boom
`;

async function site(cwd: string): Promise<string> {
  const dir = join(cwd, "site");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "sitecustomize.py"), SITE);
  return dir;
}

// --- fixtures --------------------------------------------------------------------------------------------------------------------

let seed = 20261021;
function rnd(): number {
  seed = (seed * 1664525 + 1013904223) >>> 0;
  return seed / 2 ** 32;
}
const pick = (alphabet: string, n: number) => Array.from({ length: n }, () => alphabet[Math.floor(rnd() * alphabet.length)]).join("");
const DIGITS = "0123456789";
/** A vendor access key id built from pieces: a flagged span for the token rule, never a literal. */
const flagged = () => ["AK", "IA", pick("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)].join("");
const recoveryKey = () => Array.from({ length: 8 }, () => String(Math.floor(rnd() * 65536) * 11).padStart(6, "0")).join("-");

type Member = { name?: string; nameBytes?: Buffer; flags?: number; data?: Buffer };

/** A ZIP from the APPNOTE's record layouts: local headers, the central directory, an End record with a comment, and bytes after it. */
function zipOf(members: Member[], opts: { comment?: Buffer; tail?: Buffer; declared?: number } = {}): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let at = 0;
  for (const m of members) {
    const name = m.nameBytes ?? Buffer.from(m.name ?? "a", "utf8");
    const flags = m.flags ?? 0x0800;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt32LE(1, 18);
    local.writeUInt32LE(1, 22);
    local.writeUInt16LE(name.length, 26);
    const record = Buffer.concat([local, name, m.data ?? Buffer.from("x")]);
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE(20, 4);
    c.writeUInt16LE(20, 6);
    c.writeUInt16LE(flags, 8);
    c.writeUInt32LE(1, 20);
    c.writeUInt32LE(1, 24);
    c.writeUInt16LE(name.length, 28);
    c.writeUInt32LE(at, 42);
    central.push(Buffer.concat([c, name]));
    parts.push(record);
    at += record.length;
  }
  const cd = Buffer.concat(central);
  return Buffer.concat([...parts, cd, endRecord(opts.declared ?? members.length, cd.length, at, opts.comment), opts.tail ?? Buffer.alloc(0)]);
}

function endRecord(entries: number, cdBytes: number, cdOffset: number, comment: Buffer = Buffer.alloc(0), declaredComment?: number): Buffer {
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries, 8);
  end.writeUInt16LE(entries, 10);
  end.writeUInt32LE(cdBytes, 12);
  end.writeUInt32LE(cdOffset, 16);
  end.writeUInt16LE(declaredComment ?? comment.length, 20);
  return Buffer.concat([end, comment]);
}

/** Six members, five of them encrypted. */
const SIX: Member[] = Array.from({ length: 6 }, (_, i) => ({ name: `m${i}.txt`, flags: 0x0800 | (i === 0 ? 0 : 1) }));

/** A 7z whose header is plain and holds `text` as one printable run, so that 7z, where there is one, has to refuse it and the hint path runs. */
function sevenZip(text: Buffer): Buffer {
  const header = Buffer.concat([Buffer.from([0x01]), text, Buffer.from([0])]);
  const start = Buffer.alloc(32);
  Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]).copy(start, 0);
  start.writeBigUInt64LE(BigInt(header.length), 20);
  return Buffer.concat([start, header]);
}

// --- the withholding rule is given bounded text ---------------------------------------------------------------------------

test("archive_probe judges a ZIP member name in bounded time: a long run of name characters and flagged spans after a full-width solidus", async () => {
  // The token rule of the shared block re-reads everything in front of a `/` once for each flagged span behind it, and NFKC turns the
  // full-width solidus of a name into one: a ZIP of 100 KB with one entry kept the tool busy for 290 CPU seconds.
  await withCwd(async (cwd) => {
    const span = `${flagged()}!${FULLWIDTH_SOLIDUS}`;
    const names = [
      `${"a".repeat(30000)}!${FULLWIDTH_SOLIDUS}${span.repeat(20)}`,
      `${("ab12" + FULLWIDTH_SOLIDUS).repeat(9000)}${flagged()}`,
      `${"a".repeat(240)}!${FULLWIDTH_SOLIDUS}${span.repeat(120)}`.slice(0, 4000),
    ];
    for (const [i, name] of names.entries()) {
      await writeFile(join(cwd, "work", `q${i}.zip`), zipOf([{ name }]));
      const run = await timed(PROBE, cwd, { path: `work/q${i}.zip`, max_seconds: 100 });
      assert.equal(run.code, 0, run.err);
      assert.ok(run.cpu < 2 && run.wall < 6, `family ${i}: ${run.cpu.toFixed(1)} CPU s, ${run.wall.toFixed(1)} s`);
      assert.equal(run.out.entry_count, 1);
      assert.equal(run.out.status, "complete");
      const shown = run.out.entries[0].name as string;
      assert.ok(shown === LONG_TEXT || /withheld/.test(shown), `family ${i}: ${shown.slice(0, 60)}`);
      assert.doesNotMatch(JSON.stringify(run.out), /AKIA/);
    }
    // A name with many components is judged piece by piece, and a name of a few such pieces is not a name.
    await writeFile(join(cwd, "work", "deep.zip"), zipOf([{ name: "d/".repeat(5000) + "f.txt" }]));
    const deep = await timed(PROBE, cwd, { path: "work/deep.zip" });
    assert.ok(deep.cpu < 2);
    assert.equal(deep.out.entries[0].name, LONG_TEXT);
  });
});

test("archive_probe reads its clock for every entry of a ZIP, so a directory of names that each take a moment is cut at max_seconds", async () => {
  await withCwd(async (cwd) => {
    const members = Array.from({ length: 60 }, (_, i) => ({ name: `n${i}/doc${i}.txt` }));
    await writeFile(join(cwd, "work", "many.zip"), zipOf(members));
    const out = answer(await tool(PROBE, cwd, { path: "work/many.zip", max_seconds: 3 }, { FAST_CLOCK: "1", PYTHONPATH: await site(cwd) }));
    assert.equal(out.listing, "partial");
    assert.match(out.listing_problem, /time limit \(max_seconds 3\) was reached after \d+ entries/);
    assert.ok(out.entry_count >= 1 && out.entry_count < 20, `${out.entry_count} entries were listed`);
    assert.deepEqual([out.status, out.partial], ["partial", true]);
  });
});

test("archive_probe reads its clock for every header string of a 7z, and a string that is one huge run is judged in bounded time", async () => {
  await withCwd(async (cwd, bin) => {
    const env = { HIDE_7Z: "1", PYTHONPATH: await site(cwd) };
    // 200 strings: the clock was read once in a thousand.
    const strings = Array.from({ length: 200 }, (_, i) => `entry ${i} name`).join("\u0000");
    await writeFile(join(cwd, "work", "many.7z"), sevenZip(Buffer.from(strings, "latin1")));
    const cut = answer(await tool(PROBE, cwd, { path: "work/many.7z", max_seconds: 3 }, { ...env, FAST_CLOCK: "1" }));
    assert.match(cut.header_strings_cut, /time limit \(max_seconds 3\) was reached: the strings after the \d+ listed were not read/);
    assert.ok(cut.header_strings_hint_count < 20, `${cut.header_strings_hint_count} strings`);
    // One string of 40,000 characters that holds a `/` and a flagged span after each: 226 CPU seconds.
    const huge = `${"a".repeat(40000)}!/${`${flagged()}!/`.repeat(60)}`;
    await writeFile(join(cwd, "work", "huge.7z"), sevenZip(Buffer.from(huge, "latin1")));
    const run = await timed(PROBE, cwd, { path: "work/huge.7z", max_seconds: 100 }, env);
    assert.ok(run.cpu < 2 && run.wall < 6, `${run.cpu.toFixed(1)} CPU s`);
    assert.equal(run.out.header_strings_hint_count, 1);
    assert.equal(run.out.header_strings_hint[0], LONG_TEXT);
    // The same text as a member name and as a diagnostic of a 7z that lists.
    await writeFile(join(cwd, "listing.txt"), `Path = x.7z\nType = 7z\n\n----------\nPath = ${huge}\nSize = 3\nEncrypted = -\n\n`);
    await writeFile(join(cwd, "diag.txt"), `WARNING: ${huge}\n`);
    await writeFile(join(bin, "7z"), `#!/bin/sh\ncat "${join(cwd, "listing.txt")}" "${join(cwd, "diag.txt")}"\nexit 1\n`);
    await chmod(join(bin, "7z"), 0o755);
    const listed = await timed(PROBE, cwd, { path: "work/huge.7z" }, { PATH: `${bin}:${process.env.PATH}` });
    assert.ok(listed.cpu < 2 && listed.wall < 6, `${listed.cpu.toFixed(1)} CPU s`);
    assert.equal(listed.out.members[0].name, LONG_TEXT);
    assert.doesNotMatch(JSON.stringify(listed.out), /AKIA/);
  });
});

// --- an End record inside the comment ----------------------------------------------------------------------------------------

test("archive_probe does not take the End record a ZIP comment holds for the archive's own", async () => {
  // A comment may hold anything. The last signature in the file was read, whatever its comment length said: a 22-byte record of 0 entries
  // in the comment made an archive of six members, five of them encrypted, "complete, not protected, 0 entries" (7-Zip lists the six).
  await withCwd(async (cwd) => {
    const fake = endRecord(0, 0, 0);
    const listed = async (file: string, zip: Buffer) => {
      await writeFile(join(cwd, "work", file), zip);
      return answer(await tool(PROBE, cwd, { path: `work/${file}` }));
    };
    // The decoy is the end of the comment: two End records end the file and disagree.
    for (const [file, comment] of [["end.zip", Buffer.concat([Buffer.from("zz"), fake])], ["only.zip", fake]] as const) {
      const out = await listed(file, zipOf(SIX, { comment }));
      assert.deepEqual([out.status, out.entry_count, out.encrypted_entries, out.protected], ["partial", 6, 5, true], file);
      assert.equal(out.end_records_disagree.others.length, 1);
      assert.equal(out.end_records_disagree.others[0].entries, 0);
      assert.match(out.status_basis, /other End record with a different directory/);
      assert.match(out.not_determined[0], /which End record is the archive's/);
    }
    // Bytes follow the decoy: it does not end the file, and the archive's own record does.
    const behind = await listed("behind.zip", zipOf(SIX, { comment: Buffer.concat([Buffer.from("zz"), fake, Buffer.from("yy")]) }));
    assert.deepEqual([behind.status, behind.entry_count, behind.encrypted_entries, behind.protected], ["complete", 6, 5, true]);
    // A record appended after the archive (7-Zip lists the six): the archive is read and the two are named.
    const appended = await listed("appended.zip", Buffer.concat([zipOf(SIX), fake]));
    assert.deepEqual([appended.status, appended.entry_count, appended.encrypted_entries], ["partial", 6, 5]);
    assert.equal(appended.end_records_disagree.others.length, 1);
    // An honest empty archive, and an ordinary comment, stay complete.
    const empty = await listed("empty.zip", endRecord(0, 0, 0));
    assert.deepEqual([empty.status, empty.entry_count, empty.protected], ["complete", 0, false]);
    assert.equal((await listed("comment.zip", zipOf(SIX, { comment: Buffer.from("made by a tool") }))).status, "complete");
  });
});

test("archive_probe names a sound archive that lies wholly before the one that ends the file (a second archive appended)", async () => {
  // Archive A (six members, five encrypted) followed by archive B (one plain member): 7-Zip lists A with a "data after the end of archive"
  // warning, `zipfile` lists B. The tool answered `complete`, 1 entry, 0 encrypted, not protected, and named nothing.
  await withCwd(async (cwd) => {
    const listed = async (file: string, zip: Buffer) => {
      await writeFile(join(cwd, "work", file), zip);
      return answer(await tool(PROBE, cwd, { path: `work/${file}` }));
    };
    const a = zipOf(SIX);
    const b = zipOf([{ name: "plain.txt", flags: 0x0800 }]);
    const both = await listed("a-then-b.zip", Buffer.concat([a, b]));
    assert.equal(both.status, "partial");
    assert.notEqual(both.protected, false, "not protected is not said of a file that holds an encrypted archive");
    assert.equal(both.end_records_disagree.read.entries, 1);
    assert.deepEqual(both.end_records_disagree.others.map((o: Json) => o.entries), [6]);
    assert.equal(both.end_records_disagree.others[0].offset, a.length - 22);
    assert.match(both.status_basis, /other End record with a different directory/);
    assert.match(both.not_determined[0], /which End record is the archive's/);
    // The other way round (the larger archive last) and three archives: every earlier archive is named.
    const rev = await listed("b-then-a.zip", Buffer.concat([b, a]));
    assert.deepEqual([rev.status, rev.entry_count, rev.encrypted_entries, rev.end_records_disagree.others.length], ["partial", 6, 5, 1]);
    const three = await listed("three.zip", Buffer.concat([a, zipOf([{ name: "x" }, { name: "y" }]), b]));
    assert.equal(three.status, "partial");
    assert.deepEqual(three.end_records_disagree.others.map((o: Json) => o.entries).sort(), [2, 6]);
    // Two archives of one shape (one member each, a name of one length) that differ only in the flag: named all the same.
    const same = await listed("same-shape.zip", Buffer.concat([zipOf([{ name: "a", flags: 0x0801 }]), zipOf([{ name: "b", flags: 0x0800 }])]));
    assert.deepEqual([same.status, same.entry_count, same.encrypted_entries, same.end_records_disagree.others.length], ["partial", 1, 0, 1]);
    assert.notEqual(same.protected, false);
    // A stored ZIP inside a member is not another archive: a jar that holds one, even as the last member, stays complete, and so does
    // an archive behind a stub (offsets are relative to the archive).
    const inner = zipOf(SIX);
    const jar = await listed("jar.zip", zipOf([{ name: "a.class" }, { name: "inner.zip", data: inner }]));
    assert.deepEqual([jar.status, jar.entry_count, jar.protected, jar.end_records_disagree], ["complete", 2, false, undefined]);
    const stub = await listed("stub.zip", Buffer.concat([Buffer.from("#!/bin/sh\nexit 0\n"), zipOf([{ name: "inner.zip", data: inner }, { name: "z" }])]));
    assert.deepEqual([stub.status, stub.entry_count, stub.end_records_disagree], ["complete", 2, undefined]);
    const sfx = await listed("sfx.zip", Buffer.concat([Buffer.from("MZ stub".repeat(40)), zipOf(SIX)]));
    assert.deepEqual([sfx.status, sfx.entry_count, sfx.encrypted_entries, sfx.protected], ["complete", 6, 5, true]);
  });
});

test("archive_probe says so when no End record ends the file, and does not call such a list complete", async () => {
  await withCwd(async (cwd) => {
    const listed = async (file: string, zip: Buffer) => {
      await writeFile(join(cwd, "work", file), zip);
      return answer(await tool(PROBE, cwd, { path: `work/${file}` }));
    };
    const zeros = await listed("zeros.zip", zipOf(SIX, { tail: Buffer.alloc(40) }));
    assert.deepEqual([zeros.status, zeros.trailing_zero_bytes], ["complete", 40]);
    const junk = await listed("junk.zip", zipOf(SIX, { tail: Buffer.from("junk-junk") }));
    assert.deepEqual([junk.status, junk.entry_count, junk.trailing_bytes_after_comment], ["partial", 6, 9]);
    assert.match(junk.status_basis, /9 bytes that are not zeros follow the End record's comment/);
    const plain = await listed("plain.zip", zipOf([{ name: "a.txt", flags: 0x0800 }, { name: "b.txt", flags: 0x0800 }], { tail: Buffer.from("junk") }));
    assert.deepEqual([plain.status, plain.protected], ["partial", null], "not protected is not said of a list nothing vouches for");
    const short = zipOf(SIX);
    const overrun = await listed("overrun.zip", Buffer.concat([short.subarray(0, short.length - 2), Buffer.from([50, 0]), Buffer.from("short")]));
    assert.deepEqual([overrun.status, overrun.entry_count, overrun.end_record_comment_overruns_by], ["partial", 6, 45]);
  });
});

test("archive_probe does not say a list is not protected when its count differs from the End record's", async () => {
  await withCwd(async (cwd) => {
    for (const [file, declared] of [["more.zip", 8], ["fewer.zip", 1]] as const) {
      await writeFile(join(cwd, "work", file), zipOf([{ name: "a.txt", flags: 0x0800 }, { name: "b.txt", flags: 0x0800 }], { declared }));
      const out = answer(await tool(PROBE, cwd, { path: `work/${file}` }));
      assert.deepEqual([out.status, out.entry_count, out.protected, out.entry_count_matches_declared], ["partial", 2, null, false], file);
    }
  });
});

test("archive_probe does not read an archive's members as a header message because one is named like it", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "x.7z"), sevenZip(Buffer.from("abcdefg", "latin1")));
    await writeFile(join(bin, "7z"), "#!/bin/sh\nprintf 'Path = x.7z\\nType = 7z\\n\\n----------\\nPath = Wrong password.txt\\nSize = 3\\nEncrypted = -\\n\\n'\nexit 2\n");
    await chmod(join(bin, "7z"), 0o755);
    const out = answer(await tool(PROBE, cwd, { path: "work/x.7z" }, {}, bin));
    assert.equal(out.listing.status, "failed");
    assert.notEqual(out.header_encrypted, true);
    assert.equal(out.status, "partial");
  });
});

// --- PDF and OLE are searched in windows ------------------------------------------------------------------------------------

test("archive_probe finds a PDF's markers across the edges of its search windows, and the first /V, /R and /P wherever they are", async () => {
  await withCwd(async (cwd) => {
    const window = 8 << 20;
    const body = Buffer.alloc(window + (3 << 20), 0x20);
    Buffer.from("%PDF-1.7\n").copy(body, 0);
    for (const at of [window - 4, window + 1000, body.length - 100]) Buffer.from("/Encrypt").copy(body, at);
    Buffer.from("/V 4 /R 4 /P -3904").copy(body, window + 5000);
    await writeFile(join(cwd, "work", "big.pdf"), body);
    const out = answer(await tool(PROBE, cwd, { path: "work/big.pdf" }));
    assert.deepEqual(out.encrypt_marker.first_offsets, [window - 4, window + 1000, body.length - 100]);
    assert.deepEqual([out.encrypt_marker.count, out.search_complete, out.bytes_searched], [3, true, body.length]);
    assert.deepEqual([out.unresolved_hints.v, out.unresolved_hints.r, out.unresolved_hints.p], [4, 4, -3904]);
  });
});

// --- a read that never returns ---------------------------------------------------------------------------------------------

/** One JSON document, status partial, the hard stop named, and the wall time within the limit and its grace (plus the host's slack). */
function hardStopped(run: { code: number | null; stdout: string; stderr: string }, wall: number, limit: number): Json {
  assert.equal(run.code, 0, run.stderr + run.stdout);
  assert.doesNotMatch(run.stderr, /Traceback/);
  const out = JSON.parse(run.stdout) as Json; // two documents would not parse
  assert.deepEqual([out.status, out.partial, out.interrupted, out.hard_stopped], ["partial", true, true, true]);
  assert.match(out.stopped_by, new RegExp(`${limit} seconds`));
  assert.ok(wall < limit + 5 + 8, `the answer came after ${wall.toFixed(1)} s`);
  return out;
}

for (const [mask, how] of [["", "SIGALRM ends a read a signal can interrupt"], ["1", "the watchdog thread ends a read no signal can interrupt"]] as const) {
  test(`archive_probe, recovery_key_scan and crypto_id answer once and end when a read never returns: ${how}`, async () => {
    await withCwd(async (cwd) => {
      const base = { PYTHONPATH: await site(cwd), ...(mask ? { STUCK_MASK: mask } : {}) };
      await writeFile(join(cwd, "work", "s.zip"), zipOf([{ name: "a.txt" }]));
      await mkdir(join(cwd, "work", "ev"), { recursive: true });
      await writeFile(join(cwd, "work", "ev", "f.bin"), `row ${recoveryKey()}\n`);
      await writeFile(join(cwd, "work", "k.bin"), Buffer.alloc(4096, 7));
      // The three at once: each is a process of its own, and each has to answer within its limit and the grace.
      const started = Date.now();
      const [probe, scan, crypto] = await Promise.all([
        tool(PROBE, cwd, { path: "work/s.zip", max_seconds: 3 }, { ...base, STUCK_SUFFIX: ".zip" }),
        tool(SCAN, cwd, { path: "work/ev", max_seconds: 3 }, { ...base, STUCK_SUFFIX: ".bin" }),
        // crypto_id has a time limit of its own (100 s); here the hard stop runs thirty times faster.
        tool(ID, cwd, { path: "work/k.bin" }, { ...base, STUCK_SUFFIX: ".bin", SCALE_STOP: "30" }),
      ]);
      const wall = (Date.now() - started) / 1000;
      assert.match(hardStopped(probe, wall, 3).path, /s\.zip$/);
      assert.equal(hardStopped(scan, wall, 3).written_values, 0);
      hardStopped(crypto, wall, 100);
    });
  });
}

/** The watchdog's moment, placed by hand: the hard stop is due, the thread has read its due time and not yet taken the lock, and the main
 * thread prints an error answer through the tool's own `fail`. Whatever the thread prints after that is a second document. */
const FAIL_RACE = String.raw`
import json, os, re, signal, sys, threading, time
text = open(sys.argv[1], encoding="utf-8").read()
ns = {"re": re, "json": json, "os": os, "sys": sys}
for name in ("WITHHOLDING", "NAMES", "STOP"):
    b, e = "# BEGIN SHARED " + name, "# END SHARED " + name
    exec(text[text.index(b):text.index(e)], ns)
start = text.index("def fail(")
exec(text[start:text.index("\n\n\n", start)], ns)
STOP = ns["STOP"]
ns["install_stop"](last_word=lambda signum: ns["interrupted_answer"](signum))
STOP["limit"] = 1
STOP["hard_due"] = time.perf_counter() - 1          # due already
read, go = threading.Event(), threading.Event()
def watchdog():
    due = STOP["hard_due"]                           # what the real watchdog does first ...
    assert due is not None and time.perf_counter() >= due
    read.set()
    go.wait(5)                                       # ... then the lock is taken some instructions later
    ns["hard_stop"](STOP["signal"])
t = threading.Thread(target=watchdog, daemon=True)
t.start()
read.wait(5)
try:
    ns["fail"]("the file cannot be read")
except SystemExit as exc:
    sys.stdout.flush()
    go.set()
    t.join(5)
    sys.stderr.write("main ended, code %s\n" % exc.code)
    sys.stderr.flush()
    os._exit(exc.code)
`;

test("fail() claims the stop as emit() does: a watchdog that has read its due time prints no second document", async () => {
  for (const path of [PROBE, SCAN, ID]) {
    const run = await runPySnippet(FAIL_RACE, [path], null);
    const docs = run.stdout.split("\n").filter((l) => l.trim().startsWith("{"));
    assert.equal(docs.length, 1, `${docs.length} documents from ${path}: ${run.stdout}${run.stderr}`);
    const got = JSON.parse(docs[0]) as Json;
    assert.deepEqual([got.status, got.error], ["failed", "the file cannot be read"]);
    assert.equal(run.code, 1, run.stderr);
    assert.match(run.stderr, /main ended, code 1/);
  }
});

test("archive_probe reads a mapped 7z header through the descriptor first, so that a stalled page is a stalled read the watchdog ends", async () => {
  // A page fault in a mapped file stops the interpreter, signal handlers and threads with it: a 9.8 GB archive that was kept on a cloud
  // volume blocked the tool for more than 200 s with max_seconds 100. os.pread stands in for the page that does not come.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "s.7z"), sevenZip(Buffer.from("abcdefg", "latin1")));
    const started = Date.now();
    const out = hardStopped(await tool(PROBE, cwd, { path: "work/s.7z", max_seconds: 3 }, { PYTHONPATH: await site(cwd), PREAD_STUCK: "1" }), (Date.now() - started) / 1000, 3);
    assert.match(out.path, /s\.7z$/);
  });
});

const DISARM = String.raw`
import json, os, signal, sys, time
text = open(sys.argv[1], encoding="utf-8").read()
ns = {"os": os, "sys": sys, "json": json, "seal": lambda v, key=None: v}
exec(text[text.index("# BEGIN SHARED STOP"):text.index("# END SHARED STOP")], ns)
ns["GRACE_SECONDS"] = 1
ns["set_deadline"](1)
armed = signal.getitimer(signal.ITIMER_REAL)[0]
if sys.argv[2] == "emit":
    ns["emit"]({"answer": 1})
else:
    ns["disarm_stop"]()
print(json.dumps({"armed": armed, "after": signal.getitimer(signal.ITIMER_REAL)[0]}), flush=True)
time.sleep(2.6)      # past the deadline and its grace: a timer still armed would end this process with SIGALRM
print("alive", flush=True)
`;

test("the hard stop is disarmed when the answer goes out or the tool fails, and is armed only by a deadline", async () => {
  for (const path of [SCAN, PROBE, ID]) {
    for (const how of ["emit", "disarm"]) {
      const run = spawnSync("python3", ["-c", DISARM, path, how], { encoding: "utf8" });
      assert.equal(run.status, 0, `${how} in ${path}: ${run.stderr}`);
      const lines = run.stdout.trim().split("\n").filter((l) => l !== "");
      const state = JSON.parse(lines[lines.length - 2]) as { armed: number; after: number };
      assert.ok(state.armed > 1 && state.armed <= 2, `the timer was not armed by the deadline (${state.armed})`);
      assert.equal(state.after, 0);
      assert.equal(lines[lines.length - 1], "alive");
      if (how === "emit") assert.match(run.stdout, /"answer": 1/);
    }
  }
});

// --- recovery_key_scan -----------------------------------------------------------------------------------------------------

test("recovery_key_scan reads its clock for every finding: a window of findings is cut at max_seconds, and what was not worked through is named unread", async () => {
  await withCwd(async (cwd) => {
    const lines = Array.from({ length: 3000 }, () => `${recoveryKey()}\n`);
    assert.equal(lines[0].length, 56);
    await writeFile(join(cwd, "work", "dense.txt"), lines.join(""));
    const out = answer(await tool(SCAN, cwd, { path: "work/dense.txt", max_seconds: 3, limit: 5 }, { FAST_CLOCK: "1", PYTHONPATH: await site(cwd) }));
    assert.deepEqual([out.status, out.interrupted], ["partial", true]);
    assert.match(out.stopped_by, /time limit \(max_seconds 3\)/);
    const worked = out.finding_count as number;
    assert.ok(worked >= 1 && worked < 100, `${worked} findings were worked through`);
    // The file counts as read up to the first finding that was not worked through: no byte is called read that was not.
    assert.equal(out.coverage.files_stopped, 1);
    const row = out.exceptions.find((e: Json) => e.status === "partial");
    assert.deepEqual([row.bytes_read, row.bytes_unread], [56 * worked, 56 * 3000 - 56 * worked]);
  });
});

test("recovery_key_scan withholds the text of an unexpected failure, as the other two tools do", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "a.txt"), "nothing here\n");
    const number = pick(DIGITS, 12);
    const run = await tool(SCAN, cwd, { path: "work/ev" }, { PYTHONPATH: await site(cwd), BOOM: `cannot resolve ${number}` });
    assert.equal(run.code, 1, run.stdout);
    const out = JSON.parse(run.stdout) as Json;
    assert.equal(out.status, "failed");
    assert.match(out.error, /^unexpected failure: RuntimeError: cannot resolve <identifier-shaped text withheld>$/);
    assert.ok(!run.stdout.includes(number));
  });
});

test("a result that cannot be written is an error answer with status_basis, in archive_probe and recovery_key_scan", async (t) => {
  if (process.getuid?.() === 0) return t.skip("root writes anywhere");
  await withCwd(async (cwd) => {
    const out = join(cwd, "locked");
    await mkdir(out);
    await chmod(out, 0o500);
    try {
      await writeFile(join(cwd, "work", "three.zip"), zipOf([{ name: "a" }, { name: "b" }, { name: "c" }]));
      await mkdir(join(cwd, "work", "ev"), { recursive: true });
      for (const n of [1, 2, 3]) await writeFile(join(cwd, "work", "ev", `k${n}.txt`), `${recoveryKey()}\n`);
      for (const [script, args] of [[PROBE, { path: "work/three.zip", limit: 1 }], [SCAN, { path: "work/ev", limit: 1 }]] as const) {
        const run = await tool(script, cwd, args, { JOB_ID: "j000001", OUT: out });
        assert.equal(run.code, 1, run.stdout + run.stderr);
        const got = JSON.parse(run.stdout) as Json;
        assert.equal(got.status, "failed");
        assert.match(got.status_basis, /could not be written/);
      }
    } finally {
      await chmod(out, 0o700);
    }
  });
});

test("the manifests carry the limits of the withholding rule as they are measured", async () => {
  for (const tool of ["archive_probe", "crypto_id", "recovery_key_scan"]) {
    const manifest = JSON.parse(await readFile(join(ENC, tool, "manifest.json"), "utf8")) as { description: string };
    const text = manifest.description;
    for (const needle of [
      "uniform draws of letters and digits",
      "all-capital letters-only run of any length",
      "three groups of four or five capitals and digits",
      "a number of 9 digits or fewer",
      "with the rule removed",
      "is bounded",
      "with one decimal digit glued to the first or last group",
      "with a letter in it or glued to it",
      "anything but a hyphen, underscore, dot, space or nothing",
      "of 24 at most 0.1% and of 40 none",
    ]) assert.ok(text.includes(needle), `${tool}: the manifest does not say "${needle}"`);
    assert.match(text, /stop is the clock's, not the work's/i, `${tool}: the hard stop is the clock's`);
    if (tool === "archive_probe") assert.ok(text.includes("a second archive appended"), "the second archive");
    assert.doesNotMatch(text, /random mixed-case letters and digits of 8, 12 or 40 characters 0 draws, of 9 about 1\.4%/, `${tool}: the old table`);
  }
});
