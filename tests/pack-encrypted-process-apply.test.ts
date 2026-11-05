/**
 * PKG-P5 (the encrypted-containers tools of the process sweep). The shared PROCESS block ends what a program leaves behind (settle()); the tools of this pack that run a program and
 * report a file that program wrote call process_apply, so that a program that exits 0 and leaves a writer behind, or a host where the absence of one cannot be proven, never answers
 * `complete` over a file the program wrote. Stand-ins only, with real abandoned children (a child in the tool's group that keeps its descriptors, setsid, a double fork, one that
 * truncates and rewrites, a periodic writer, and holders of the output pipe or of standard input):
 *   - password_recover (the *2john helper's hash file, john's pot, log and show output), crypto_metadata (the reader's output file), crypto_selftest (each reader's output file, the
 *     version probes) and materialise_decrypted (the decrypted image, written through a descriptor the reader child's own children inherit) answer `partial`, say what was ended
 *     (`program_group.left_behind`), and the files they describe are the files now and 2.4 seconds later; where the absence of a leftover cannot be proven (sys.platform patched to
 *     darwin, or ctypes.CDLL replaced by a library whose prctl fails) a clean run is `partial` and says why; a clean run is `complete`;
 *   - tcrypt_header, archive_metadata and archive_probe report only what a program printed on a pipe: a host that cannot adopt orphans does not make them less than complete, a process
 *     that settle() ended makes them `partial`, and a process that holds the pipe (silently, or writing without end) is let go one second after the program ended, with the listing
 *     marked `listed_with_warnings` (it was held to the tool's own clock when the writer never stopped);
 *   - no recovered value, key or password reaches an answer, standard output or standard error in any of these cases.
 * The cases that fail on the batch head (before the tools called process_apply) are the abandoned-child ones: the answer was `complete` over a file the program's child could have
 * changed, and archive_metadata / archive_probe waited for a continuous writer until their own deadline; run with ENCRYPTED_PACK_TOOLS naming the head's tools to see it.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Host = "linux" | "darwin" | "refused";
const LINUX = process.platform === "linux";
const TOOLS = process.env.ENCRYPTED_PACK_TOOLS ?? join(ROOT, "packs", "encrypted-containers", "tools");
const script = (tool: string): string => join(TOOLS, tool, "run.py");
const sha = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const CANARY = "Tr0ub4dor&3-canary-9f2c-p5";
const REAL_7Z = spawnSync("sh", ["-c", "command -v 7z"], { encoding: "utf8" }).stdout.trim();

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
async function pidsOf(file: string): Promise<number[]> {
  return (await readFile(file, "utf8").catch(() => "")).split(/\s+/).filter(Boolean).map(Number);
}
async function reap(file: string): Promise<void> {
  for (const pid of await pidsOf(file)) if (alive(pid)) process.kill(pid, "SIGKILL");
}
async function allGone(file: string, waitMs = 3000): Promise<number[]> {
  const until = Date.now() + waitMs;
  for (;;) {
    const left = (await pidsOf(file)).filter(alive);
    if (!left.length || Date.now() > until) return left;
    await sleep(50);
  }
}

// ---- how a tool is run: the way the harness starts a secret_output job (the leader of a process group of its own), on a patched host when asked ----------------------------

const DARWIN = `
import sys, os, subprocess, selectors, ctypes, json, re, time, hashlib, shutil, signal, stat, errno, functools, runpy, select, struct, resource, tempfile, threading
script = sys.argv[1]
sys.argv = sys.argv[1:]
sys.platform = "darwin"
runpy.run_path(script, run_name="__main__")
`;
const REFUSED = `
import sys, os, subprocess, selectors, ctypes, json, re, time, hashlib, shutil, signal, stat, errno, functools, runpy, select, struct, resource, tempfile, threading
script = sys.argv[1]
sys.argv = sys.argv[1:]
class Refusing(object):
    def prctl(self, *a):
        return -1
ctypes.CDLL = lambda *a, **k: Refusing()
runpy.run_path(script, run_name="__main__")
`;
const WRAPPERS: Record<Host, string | undefined> = { linux: undefined, darwin: DARWIN, refused: REFUSED };
type Run = { code: number | null; stdout: string; stderr: string; ms: number };

let jobs = 0;
async function exec(tool: string, cwd: string, env: Record<string, string>, args: unknown, host: Host = "linux"): Promise<Run> {
  await mkdir(join(cwd, "out"), { recursive: true });
  jobs += 1;
  const wrapper = WRAPPERS[host];
  const file = script(tool);
  const argv = wrapper ? ["-c", wrapper, file] : [file];
  const full = { ...process.env, AGENT_ID: "s1", JOB_ID: `p5j${String(jobs).padStart(5, "0")}`, OUT: join(cwd, "out"), SECRET_OUTPUT: "1", ...env };
  return new Promise((resolveRun, reject) => {
    const began = Date.now();
    const child = spawn("python3", argv, { cwd, env: full, detached: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolveRun({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), ms: Date.now() - began }));
    child.stdin.on("error", () => undefined);
    child.stdin.end(JSON.stringify(args));
  });
}

// ---- the leftover: one Python function, used by every stand-in ---------------------------------------------------------------------------------------------------------

/**
 * Python that forks a child which writes to `paths` (by name) LEAVE_DELAY seconds after the program is gone, the way LEAVE_VARIANT says. inherit keeps every descriptor of the
 * program (the output pipe or file included) and stays in its group; setsid and double close them all and leave the group; rewrite truncates the file; periodic never stops;
 * hold keeps standard output open and says nothing; chatty keeps it open and writes a line every 20 ms; flood keeps it open and writes as fast as it can for 30 s; stdin keeps only standard input.
 */
const LEAVE = String.raw`
import os, sys, time, json
CFG = json.load(open(LEAVE_CFG)) if os.path.exists(LEAVE_CFG) else {}


def leave(*paths):
    variant = CFG.get("variant")
    if not variant:
        return
    delay = float(CFG.get("delay", "2.5"))
    if os.fork() != 0:
        return
    if variant == "double":
        if os.fork() != 0:
            os._exit(0)
    if variant in ("setsid", "double", "rewrite", "periodic", "hold", "chatty", "stdin", "flood"):
        os.setsid()
    open(CFG["pids"], "a").write("%d\n" % os.getpid())
    if variant != "inherit":
        keep = (1,) if variant in ("hold", "chatty", "flood") else (0,) if variant == "stdin" else ()
        for fd in range(0, 256):
            if fd not in keep:
                try:
                    os.close(fd)
                except OSError:
                    pass
    if variant in ("hold", "stdin"):
        time.sleep(40)
        os._exit(0)
    if variant == "flood":
        junk = b"junk line from a leftover\n" * 2000
        end = time.time() + 30
        while time.time() < end:
            try:
                os.write(1, junk)
            except OSError:
                break
        os._exit(0)
    if variant == "chatty":
        for _ in range(2000):
            try:
                os.write(1, b"junk line from a leftover\n")
            except OSError:
                break
            time.sleep(0.02)
        os._exit(0)
    if variant == "periodic":
        while True:
            time.sleep(0.2)
            for p in paths:
                open(p, "a").write("late\n")
    time.sleep(delay)
    for p in paths:
        if variant == "rewrite":
            open(p, "w").write("REWRITTEN BY A LATE WRITER\n")
        else:
            open(p, "a").write("late\n")
    os._exit(0)
`;
const PY = "#!/usr/bin/env python3\n";
/** The stand-ins read what to leave from a file next to them (the tools give a program a clean environment, so an environment variable does not reach it). */
const cfgPath = (bin: string): string => join(bin, "leave.json");
async function pystub(bin: string, name: string, code: string): Promise<void> {
  await mkdir(bin, { recursive: true });
  const path = join(bin, name);
  await writeFile(path, PY + `LEAVE_CFG = ${JSON.stringify(cfgPath(bin))}
` + LEAVE + code, "utf8");
  await chmod(path, 0o755);
}

// ---- the cases ---------------------------------------------------------------------------------------------------------------------------------------------------------

type Setup = { args: unknown; env?: Record<string, string> };
type Case = {
  name: string;
  tool: string;
  install: (cwd: string, bin: string) => Promise<Setup>;
  /** The files the answer describes (absolute), read when the answer is in and again later. */
  watched: (answer: Answer, cwd: string) => Promise<string[]>;
  /** What the answer says about those files, checked against them. */
  claims?: (answer: Answer, files: Buffer[], paths: string[]) => void;
  /** The program that leaves the process (LEAVE_PROGRAM). */
  program: string;
};

type Outcome = { answer: Answer; run: Run; cwd: string; pids: string; files: Buffer[]; paths: string[] };

async function inCase(c: Case, variant: string | null, host: Host, check: (o: Outcome) => Promise<void>): Promise<void> {
  await withCwd(async (cwd, bin) => {
    const pids = join(cwd, "leftover.pids");
    try {
      const s = await c.install(cwd, bin);
      const { LEAVE_DELAY: delay, ...rest } = s.env ?? {};
      await writeFile(cfgPath(bin), JSON.stringify({ variant, program: c.program, pids, delay: delay ?? "2.5" }));
      const env: Record<string, string> = { PATH: `${bin}:${process.env.PATH ?? ""}`, ...rest };
      const run = await exec(c.tool, cwd, env, s.args, host);
      assert.doesNotMatch(run.stderr, /Traceback/, run.stderr);
      assert.ok(!run.stdout.includes(CANARY) && !run.stderr.includes(CANARY), "the recovered value is in no output channel");
      const answer = JSON.parse(run.stdout) as Answer;
      const paths = await c.watched(answer, cwd).catch(() => [] as string[]);
      const files = await Promise.all(paths.map((p) => readFile(p).catch(() => Buffer.alloc(0))));
      await check({ answer, run, cwd, pids, files, paths });
    } finally {
      await reap(pids);
    }
  });
}

const NOW = "work/input.bin";
const listing = async (dir: string): Promise<string[]> => (await readdir(dir).catch(() => [] as string[])).sort().map((n) => join(dir, n));

// ---- password_recover: the helper's hash file and john's pot -----------------------------------------------------------------------------------------------------------

const ZIP2JOHN = `
if "--version" in sys.argv[1:]:
    sys.exit(0)
print("x.zip:$pkzip$1*fakehash*")
sys.stdout.flush()
if CFG.get("program") == "zip2john":
    leave(os.readlink("/proc/self/fd/1"))
`;
const JOHN = `
a = sys.argv[1:]
if "--version" in a:
    print("John the Ripper 1.9.0-jumbo-1")
    sys.stdout.flush()
    if CFG.get("program") == "john-version":
        leave()
    sys.exit(0)
if "--show" in a:
    print("1 password hash cracked, 0 left")
    sys.stdout.flush()
    if CFG.get("program") == "john-show":
        leave(os.readlink("/proc/self/fd/1"))
    sys.exit(0)
pot = [x.split("=", 1)[1] for x in a if x.startswith("--pot=")][0]
open(pot, "a").write("hash0:" + os.environ["CANARY"] + "\\n")
print("Loaded 1 password hash")
sys.stdout.flush()
if CFG.get("program") == "john":
    leave(pot, os.readlink("/proc/self/fd/1"))
`;
const recover = (program: "john" | "zip2john" | "john-show" | "john-version"): Case => ({
  name: `password_recover (${program})`,
  tool: "password_recover",
  program,
  install: async (cwd, bin) => {
    await writeFile(join(cwd, "work", "x.zip"), "PK stand-in\n");
    await writeFile(join(cwd, "work", "cand.txt"), "one\ntwo\n");
    await pystub(bin, "zip2john", ZIP2JOHN);
    await pystub(bin, "john", JOHN);
    return { args: { source: "work/x.zip", format: "zip", candidates: "work/cand.txt", max_seconds: 30 }, env: { CANARY } };
  },
  watched: async (_a, cwd) => (await listing(join(cwd, "out"))).filter((p) => /password_recover-(hash\.txt|john\.pot|john-.*)$/.test(p) && !p.endsWith("-session") && !p.endsWith(".rec")),
  claims: (a, files, paths) => {
    assert.equal(a.recovered, 1);
    const pot = paths.findIndex((p) => p.endsWith("password_recover-john.pot"));
    assert.ok(pot >= 0, "the pot file is there");
    assert.equal(files[pot].toString(), `hash0:${CANARY}\n`, "the pot holds what john wrote and nothing else");
    const hash = paths.findIndex((p) => p.endsWith("password_recover-hash.txt"));
    assert.equal(files[hash].toString(), "x.zip:$pkzip$1*fakehash*\n", "the hash file holds what the helper wrote and nothing else");
  },
});

// ---- crypto_metadata: the reader's output file ------------------------------------------------------------------------------------------------------------------------

const BDEINFO = `
a = sys.argv[1:]
if a[:1] == ["-V"]:
    print("bdeinfo 20221031")
    sys.stdout.flush()
    if CFG.get("program") == "bdeinfo-probe":
        leave()
    sys.exit(0)
print("bdeinfo 20221031\\n\\nBitLocker Drive Encryption information:\\n\\tEncryption method\\t\\t: AES-XTS 128-bit\\n\\tNumber of key protectors\\t: 1\\n\\nKey protector 0:\\n\\tType\\t\\t\\t\\t: TPM\\n")
sys.stdout.flush()
if CFG.get("program") == "bdeinfo":
    leave(os.readlink("/proc/self/fd/1"))
`;
function bitlockerVolume(): Buffer {
  const offsets = [4096, 8192, 12288];
  const b = Buffer.alloc(16384 + 512);
  b.write("-FVE-FS-", 3, "ascii");
  b.writeUInt16LE(512, 11);
  offsets.forEach((o, i) => {
    b.writeBigUInt64LE(BigInt(o), 176 + 8 * i);
    b.write("-FVE-FS-", o, "ascii");
    b.writeUInt16LE(64, o + 8);
    b.writeUInt16LE(2, o + 10);
  });
  return b;
}
const metadataFor = (program: string): Case => ({
  name: "crypto_metadata",
  tool: "crypto_metadata",
  program,
  install: async (cwd, bin) => {
    await writeFile(join(cwd, "work", "disk.img"), bitlockerVolume());
    await pystub(bin, "bdeinfo", BDEINFO);
    return { args: { path: "work/disk.img", max_seconds: 30 } };
  },
  watched: async () => [],
  claims: (a) => {
    assert.equal(a.scheme, "BitLocker");
    assert.equal(a.reader.exit_code, 0);
  },
});
const metadata = metadataFor("bdeinfo");

// ---- crypto_selftest: each reader's output file, the version probes -------------------------------------------------------------------------------------------------

const SELFTEST_BDE = `
a = sys.argv[1:]
if a[:1] == ["-V"]:
    print("bdeinfo 20221031")
    if CFG.get("program") == "bdeinfo-version":
        leave(os.readlink("/proc/self/fd/1"))
    sys.exit(0)
print("Key protector 0:")
sys.stdout.flush()
if CFG.get("program") == "bdeinfo":
    leave(os.readlink("/proc/self/fd/1"))
`;
const selftest = (program: "bdeinfo" | "bdeinfo-version"): Case => ({
  name: `crypto_selftest (${program})`,
  tool: "crypto_selftest",
  program,
  install: async (_cwd, bin) => {
    await pystub(bin, "bdeinfo", SELFTEST_BDE);
    return { args: { max_seconds: 60 }, env: { PATH: `${bin}:/usr/bin:/bin` } };
  },
  watched: async (_a, cwd) => {
    const dir = join(cwd, "out", "tool-output", "crypto_selftest-samples");
    return listing(dir);
  },
  claims: (a) => {
    const pair = a.records.find((r: Answer) => r.kind === "pair" && r.program === "bdeinfo");
    assert.equal(pair.result, "parsed");
  },
});

// ---- materialise_decrypted: the decrypted image, through a descriptor the reader child's own children inherit ---------------------------------------------------------

const PLAIN = Buffer.alloc(5000, 0x41);
const xor = (b: Buffer): Buffer => Buffer.from(b.map((x) => x ^ 0x5a));
function aesContainer(plain: Buffer): Buffer {
  const padded = Buffer.concat([plain, Buffer.alloc((16 - (plain.length % 16)) % 16)]);
  return Buffer.concat([Buffer.from("AES\x02\x00", "latin1"), Buffer.from([0, 0]), Buffer.alloc(16, 1), Buffer.alloc(48, 2), Buffer.alloc(32, 3), xor(padded), Buffer.from([plain.length % 16]), Buffer.alloc(32, 4)]);
}
const PYAES = `
import glob
def get_version(): return "6.1.1"
def decryptStream(fin, fout, passw, bufferSize, inputLength):
    if passw != open(os.environ["STANDIN_EXPECT_FILE"]).read().strip(): raise ValueError("Wrong password")
    data = fin.read()
    body = data[5 + 2 + 16 + 48 + 32: len(data) - 33]
    m = data[-33]
    if m: body = body[:len(body) - (16 - m)]
    fout.write(bytes(b ^ 0x5a for b in body))
    fout.flush()
    leave(*glob.glob(os.path.join(os.environ["OUT"], "materialised", "*.partial")))
`;
const materialise: Case = {
  name: "materialise_decrypted",
  tool: "materialise_decrypted",
  program: "reader",
  install: async (cwd, bin) => {
    const mods = join(cwd, "mods");
    await mkdir(mods, { recursive: true });
    await writeFile(join(mods, "pyAesCrypt.py"), `LEAVE_CFG = ${JSON.stringify(cfgPath(bin))}
` + LEAVE + PYAES);
    await writeFile(join(cwd, "box.aes"), aesContainer(PLAIN));
    await writeFile(join(cwd, "key.txt"), CANARY + "\n", { mode: 0o600 });
    await chmod(join(cwd, "key.txt"), 0o600);
    await writeFile(join(cwd, "expect.txt"), CANARY, { mode: 0o600 });
    return { args: { operation: "aescrypt_decrypt", source: "box.aes", key_ref: "key.txt", max_seconds: 60 }, env: { PYTHONPATH: mods, STANDIN_EXPECT_FILE: join(cwd, "expect.txt") } };
  },
  watched: async (_a, cwd) => listing(join(cwd, "out", "materialised")),
  claims: (a, files, paths) => {
    assert.equal(a.output.bytes, PLAIN.length);
    const image = paths.findIndex((p) => /decrypted-aescrypt-decrypt\.bin(\.partial)?$/.test(p));
    assert.ok(image >= 0, "the image is there");
    if (a.status === "complete") assert.equal(sha(files[image]), sha(PLAIN), "a complete answer names the file as it is");
    else assert.equal(a.output.verified, false);
  },
};

/** The same case with a leftover that would write 3 s after the program, longer than the one second a held pipe is given. */
const slow = (c: Case): Case => ({ ...c, install: async (cwd, bin) => {
  const s = await c.install(cwd, bin);
  return { ...s, env: { LEAVE_DELAY: "3", ...(s.env ?? {}) } };
} });

const HELD: Case[] = [recover("john"), recover("john-show"), recover("zip2john"), metadata, selftest("bdeinfo"), selftest("bdeinfo-version"), materialise];

// ---- the runner ---------------------------------------------------------------------------------------------------------------------------------------------------------

const VARIANTS = ["inherit", "setsid", "double", "rewrite", "periodic"];
for (const c of HELD) {
  for (const variant of VARIANTS) {
    test(`${c.name}: a child of the program (${variant}) that writes after the program exited 0 is ended: partial, and the files the answer describes do not change afterwards`, { skip: !LINUX }, async () => {
      await inCase(c, variant, "linux", async (o) => {
        assert.equal(o.answer.status, "partial", o.run.stdout.slice(0, 1500));
        const group = o.answer.program_group;
        assert.ok(group, "the answer carries program_group");
        assert.ok(group.left_behind >= 1, `program_group.left_behind is ${group.left_behind}`);
        assert.equal(group.subreaper, true);
        assert.match(JSON.stringify(o.answer).replace(/\\"/g, '"'), /left \d+ process|process\(es\)/, "the answer says a process was left and ended");
        assert.deepEqual(await allGone(o.pids), [], "the leftover is gone");
        await sleep(2400);
        const later = await Promise.all(o.paths.map((p) => readFile(p).catch(() => Buffer.alloc(0))));
        o.paths.forEach((p, i) => {
          assert.equal(sha(later[i]), sha(o.files[i]), `${p} is the file the answer describes, and does not change after it`);
          assert.doesNotMatch(later[i].toString("latin1"), /late\n|REWRITTEN/, `${p} holds nothing a leftover wrote`);
        });
      });
    });
  }

  test(`${c.name}: a clean run is complete, with nothing left behind and nothing unproven`, { skip: !LINUX }, async () => {
    await inCase(c, null, "linux", async (o) => {
      assert.equal(o.answer.status, "complete", JSON.stringify(o.answer.status_basis ?? o.run.stdout.slice(0, 800)));
      const group = o.answer.program_group;
      assert.ok(group, "the answer carries program_group");
      assert.equal(group.left_behind, 0);
      assert.deepEqual(group.unproven, []);
      assert.equal(group.subreaper, true);
      c.claims?.(o.answer, o.files, o.paths);
    });
  });

  for (const host of ["darwin", "refused"] as const) {
    test(`${c.name}: where the absence of a leftover cannot be proven (${host === "darwin" ? "the host is not Linux" : "the kernel refuses PR_SET_CHILD_SUBREAPER"}), a clean run is at most partial and says why`, { skip: !LINUX }, async () => {
      await inCase(c, null, host, async (o) => {
        assert.equal(o.answer.status, "partial", JSON.stringify(o.answer.status_basis ?? o.run.stdout.slice(0, 800)));
        const group = o.answer.program_group;
        assert.equal(group.subreaper, false);
        assert.ok(group.unproven.length >= 1, "program_group.unproven names the reason");
        assert.match(JSON.stringify(o.answer), /cannot be shown to be final|cannot adopt|refused PR_SET_CHILD_SUBREAPER|cannot prove|no process behind|left no process|cannot be proven/);
        c.claims?.(o.answer, o.files, o.paths);
      });
    });
  }
}

// ---- password_recover: the pot file is sealed and the recovered value is withheld even when a process was left ---------------------------------------------------------

test("password_recover: with a leftover the pot file is still 0600, still the only place the recovered value is, and the answer carries no value, hash or length", { skip: !LINUX }, async () => {
  await inCase(recover("john"), "setsid", "linux", async (o) => {
    const pot = o.paths.find((p) => p.endsWith("password_recover-john.pot")) as string;
    assert.equal((await stat(pot)).mode & 0o777, 0o600);
    assert.equal(o.answer.recovered, 1);
    assert.ok(!o.run.stdout.includes("fakehash"), "no hash in the answer");
    assert.ok(!o.run.stdout.includes(CANARY));
    assert.match(String(o.answer.pot_file), /password_recover-john\.pot$/);
  });
});

test("materialise_decrypted: a leftover that held the reader's descriptors leaves a .partial file the answer calls unverified, no digest of it is claimed, and its size is the file's", { skip: !LINUX }, async () => {
  await inCase(materialise, "inherit", "linux", async (o) => {
    assert.equal(o.answer.status, "partial");
    assert.equal(o.answer.output.verified, false);
    assert.match(o.answer.output.path, /\.partial$/);
    const image = o.paths.findIndex((p) => p.endsWith(".partial"));
    assert.equal(o.answer.output.bytes, o.files[image].length, "the size is the file's");
    const prov = o.paths.find((p) => p.includes("provenance")) as string;
    const doc = JSON.parse(await readFile(prov, "utf8")) as Answer;
    assert.equal(doc.output.complete, false);
    assert.equal(doc.output.sha256, null);
    assert.match(doc.output.sha256_note, /may have changed the file/);
  });
});

// ---- the programs that print on a pipe: tcrypt_header ------------------------------------------------------------------------------------------------------------------

const TCRYPT = `
a = sys.argv[1:]
if "--version" in a:
    print("cryptsetup 2.6.1")
    sys.exit(0)
sys.stdin.read()
print("TCRYPT header information for /dev/stub\\nVersion:       5\\nDriver req.:   0\\nFlags:         0\\nSector size:   512\\nMK offset:     0\\nVolume size:   10485760\\nPBKDF:         PBKDF2\\nPBKDF2 hash:   sha512\\nCipher chain:  aes-twofish-serpent\\nCipher mode:   xts-plain64\\nMK bits:       192")
sys.stdout.flush()
if CFG.get("program") == "cryptsetup":
    leave()
`;
const tcrypt: Case = {
  name: "tcrypt_header",
  tool: "tcrypt_header",
  program: "cryptsetup",
  install: async (cwd, bin) => {
    await writeFile(join(cwd, "work", "real.img"), "volume bytes");
    await writeFile(join(cwd, "work", "password.txt"), CANARY + "\n", { mode: 0o600 });
    await chmod(join(cwd, "work", "password.txt"), 0o600);
    await pystub(bin, "cryptsetup", TCRYPT);
    return { args: { source: "work/real.img", password_file: "work/password.txt", max_seconds: 30 }, env: { LEAVE_DELAY: "3" } };
  },
  watched: async () => [],
};

for (const variant of ["setsid", "double", "inherit", "hold", "chatty", "stdin", "flood"]) {
  test(`tcrypt_header: cryptsetup leaves a process (${variant}): the answer comes within seconds, the process is gone, and a status that rests on a pipe a process held is partial`, { skip: !LINUX }, async () => {
    await inCase(tcrypt, variant, "linux", async (o) => {
      assert.ok(o.run.ms < 15_000, `answered in ${o.run.ms} ms`);
      assert.equal(o.answer.decrypted, true);
      assert.equal(o.answer.status, "partial", o.run.stdout.slice(0, 800));
      assert.ok(o.answer.program_group.left_behind >= 1);
      assert.match(o.answer.status_basis, /left \d+ process/);
      assert.deepEqual(await allGone(o.pids), [], "the leftover is gone");
    });
  });
}

test("tcrypt_header: a clean run is complete with nothing left behind; a host that cannot adopt orphans does not make an answer built from a pipe less than complete, and says so in program_group", { skip: !LINUX }, async () => {
  await inCase(tcrypt, null, "linux", async (o) => {
    assert.equal(o.answer.status, "complete", o.answer.status_basis);
    assert.equal(o.answer.program_group.left_behind, 0);
    assert.deepEqual(o.answer.program_group.unproven, []);
  });
  for (const host of ["darwin", "refused"] as const) {
    await inCase(tcrypt, null, host, async (o) => {
      assert.equal(o.answer.status, "complete", `${host}: ${o.answer.status_basis}`);
      assert.equal(o.answer.program_group.subreaper, false);
      assert.ok(o.answer.program_group.unproven.length + o.answer.program_group.notes.length >= 1);
    });
  }
});

// ---- archive_metadata and archive_probe: 7z's listing on a pipe ---------------------------------------------------------------------------------------------------------

const SEVENZ = `
import subprocess
r = subprocess.run([os.environ["REAL_7Z"]] + sys.argv[1:])
sys.stdout.flush()
if CFG.get("program") == "7z":
    leave()
sys.exit(r.returncode)
`;
const archive = (tool: string): Case => ({
  name: tool,
  tool,
  program: "7z",
  install: async (cwd, bin) => {
    await writeFile(join(cwd, "work", "a.txt"), "hello\n");
    const made = spawnSync(REAL_7Z, ["a", "-bso0", "-bsp0", join(cwd, "work", "x.7z"), join(cwd, "work", "a.txt")]);
    assert.equal(made.status, 0);
    await pystub(bin, "7z", SEVENZ);
    return { args: { path: "work/x.7z", max_seconds: 20 }, env: { REAL_7Z, LEAVE_DELAY: "3" } };
  },
  watched: async () => [],
});

for (const tool of ["archive_metadata", "archive_probe"]) {
  const c = archive(tool);
  const skip = !LINUX || !REAL_7Z;
  test(`${tool}: a clean listing is complete with nothing left behind; a host that cannot adopt orphans does not make a listing read from a pipe less than complete`, { skip }, async () => {
    await inCase(c, null, "linux", async (o) => {
      assert.equal(o.answer.status, "complete", o.answer.status_basis);
      assert.equal(o.answer.program_group.left_behind, 0);
      assert.deepEqual(o.answer.program_group.unproven, []);
    });
    for (const host of ["darwin", "refused"] as const) {
      await inCase(c, null, host, async (o) => {
        assert.equal(o.answer.status, "complete", `${host}: ${o.answer.status_basis}`);
        assert.equal(o.answer.program_group.subreaper, false);
        assert.ok(o.answer.program_group.unproven.length + o.answer.program_group.notes.length >= 1);
      });
    }
  });

  for (const variant of ["setsid", "double", "stdin"]) {
    test(`${tool}: a process 7z left behind that holds no descriptor of the tool's (${variant}) is ended and the answer says so (partial)`, { skip }, async () => {
      await inCase(c, variant, "linux", async (o) => {
        assert.equal(o.answer.status, "partial", o.run.stdout.slice(0, 800));
        assert.ok(o.answer.program_group.left_behind >= 1);
        assert.match(o.answer.status_basis, /left \d+ process/);
        assert.deepEqual(await allGone(o.pids), [], "the leftover is gone");
      });
    });
  }

  for (const variant of ["inherit", "hold", "chatty", "flood"]) {
    test(`${tool}: a process that holds 7z's output pipe after 7z ended (${variant}) is let go one second later even if it never stops writing, the listing is marked, and the answer is partial`, { skip }, async () => {
      await inCase(c, variant, "linux", async (o) => {
        assert.ok(o.run.ms < 8000, `answered in ${o.run.ms} ms (the tool's own deadline is 20 s)`);
        assert.equal(o.answer.status, "partial", o.run.stdout.slice(0, 800));
        const lister = o.answer.lister ?? o.answer.listing;
        if (variant !== "inherit") {
          assert.equal(lister.pipe_held, true);
          assert.equal(lister.status, "listed_with_warnings");
        }
        assert.ok(o.answer.program_group.left_behind >= 1);
        assert.deepEqual(await allGone(o.pids), [], "the leftover is gone");
      });
    });
  }
}

// ---- the readers that wait for a pipe, with a stand-in that exits leaving a holder: each answers within its clock with a truthful status ------------------------------------

for (const variant of ["hold", "chatty", "stdin", "inherit", "flood"]) {
  test(`crypto_selftest: a version probe that leaves a process holding its pipe (${variant}) does not hold the tool: it answers within seconds, partial, and the process is gone`, { skip: !LINUX }, async () => {
    await inCase(slow(selftest("bdeinfo-version")), variant, "linux", async (o) => {
      assert.ok(o.run.ms < 60_000, `answered in ${o.run.ms} ms`);
      assert.equal(o.answer.status, "partial", o.run.stdout.slice(0, 800));
      assert.ok(o.answer.program_group.left_behind >= 1);
      assert.deepEqual(await allGone(o.pids), [], "the leftover is gone");
    });
  });
  test(`materialise_decrypted: a process the reader child leaves behind (${variant}; inherit keeps the result pipe) does not hold the tool: partial, the file kept unverified, the process gone`, { skip: !LINUX }, async () => {
    await inCase(slow(materialise), variant, "linux", async (o) => {
      assert.ok(o.run.ms < 20_000, `answered in ${o.run.ms} ms`);
      assert.equal(o.answer.status, "partial", o.run.stdout.slice(0, 800));
      assert.ok(o.answer.program_group.left_behind >= 1);
      assert.equal(o.answer.output.verified, false);
      assert.deepEqual(await allGone(o.pids), [], "the leftover is gone");
    });
  });
}

// ---- the version probes of password_recover and crypto_metadata, and a flood after the program ended ------------------------------------------------------------------------

for (const [c, name] of [[recover("john-version"), "john --version"], [metadataFor("bdeinfo-probe"), "bdeinfo -V"]] as Array<[Case, string]>) {
  for (const variant of ["hold", "chatty", "stdin", "flood"]) {
    test(`${c.name}: ${name} leaves a process holding its pipe (${variant}): the answer comes within seconds, partial, the process is gone`, { skip: !LINUX }, async () => {
      await inCase(slow(c), variant, "linux", async (o) => {
        assert.ok(o.run.ms < 12_000, `answered in ${o.run.ms} ms`);
        assert.equal(o.answer.status, "partial", o.run.stdout.slice(0, 800));
        assert.ok(o.answer.program_group.left_behind >= 1);
        assert.deepEqual(await allGone(o.pids), [], "the leftover is gone");
      });
    });
  }
}
