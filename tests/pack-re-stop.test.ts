/**
 * Every reverse-engineering tool and recipe answers once, with exit 128 + the signal, on SIGTERM, SIGINT and SIGHUP at any moment after its
 * stop handlers are installed, and the handlers are installed at module level, not when main() starts:
 *   - doc_probe, entropy_map and pe_info take the windows-lineage shared STOP block (tests/pack-shared-stop.test.ts pins its text);
 *   - fuzzy_hash, unpack_safe, authenticode_verify, the capa-floss recipe and the static-binary recipe install their shared PROCESS block's handlers right after the block, with a
 *     minimal last word that main() replaces;
 *   - doc_structure and pe_directories install their own handlers (and not their SIGALRM hard limit, which only a deadline arms) at module level.
 *
 * Two shapes of case for each carrier and each of the three signals:
 *   - early: the source is run up to the line that says the handlers are in, a signal is sent to itself, and the process must answer once and
 *     exit 128 + the signal (the part before that line, the start of the interpreter and the compiling of the file, cannot be closed from inside
 *     the file and is not claimed);
 *   - mid-work: the real tool on a workload that takes seconds, signalled at a random moment of a seeded set: one JSON document on stdout and
 *     either exit 128 + the signal or, when the tool had finished first, exit 0; no hidden temporary file left; and at least one of the runs of
 *     each carrier was stopped, so that the case is not one that only ever finishes.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_PROBE, DOC_STRUCTURE, ELF_DIRECTORIES, ENTROPY, FUZZY, MACHO_DIRECTORIES, PE_DIRECTORIES, PE_INFO, RE, RECIPE, TOOLS, buildElf, buildPe, buildZip, put, stub, withCwd } from "./pack-re-harness.ts";
import type { Json, ZipEntry } from "./pack-re-harness.ts";
import { buildPeDirs } from "./pack-re-doc-fixtures.ts";

const CAPA_FLOSS = join(RE, "recipes", "capa-floss", "run.py");
const UNPACK_SAFE = join(TOOLS, "unpack_safe", "run.py");
const AUTHENTICODE_VERIFY = join(TOOLS, "authenticode_verify", "run.py");
const CLR_INSPECT = join(TOOLS, "clr_inspect", "run.py");
const SIGNALS = ["SIGTERM", "SIGINT", "SIGHUP"] as const;
const NUMBER = { SIGTERM: 15, SIGINT: 2, SIGHUP: 1 } as const;

type Carrier = {
  name: string;
  script: string;
  /** The line after which the handlers are in: the source up to and including it is what the early case runs. */
  marker: string;
  /** Builds the workload in `cwd` and returns the argv and stdin of the real run (`bin` is a directory on PATH for stand-in programs). */
  work: (cwd: string, bin: string) => Promise<{ argv: string[]; stdin: string }>;
};

const STOP = "# END SHARED STOP";
const MODULE_LEVEL = "# the stop handlers are installed here, at module level";

const CARRIERS: Carrier[] = [
  {
    name: "doc_probe", script: DOC_PROBE, marker: STOP,
    work: async (cwd) => {
      const type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink";
      const rows: string[] = [];
      for (let i = 0; i < 300_000; i++) rows.push(`<Relationship Id="rId${i}" Type="${type}" Target="http://h.example/${i}" TargetMode="External"/>`);
      const part = Buffer.from(`<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${rows.join("")}</Relationships>`);
      await put(cwd, "inputs/many.docx", buildZip([{ name: "[Content_Types].xml", data: Buffer.from("<Types/>") }, { name: "word/_rels/document.xml.rels", data: part }]));
      return { argv: [], stdin: JSON.stringify({ path: "inputs/many.docx", max_seconds: 100 }) };
    },
  },
  {
    name: "entropy_map", script: ENTROPY, marker: STOP,
    work: async (cwd) => {
      const path = await put(cwd, "inputs/big.bin", Buffer.alloc(16));
      await truncate(path, 4 * 2 ** 30);
      return { argv: [], stdin: JSON.stringify({ path: "inputs/big.bin" }) };
    },
  },
  {
    name: "pe_info", script: PE_INFO, marker: STOP,
    work: async (cwd) => {
      const name = "a/" + Array.from({ length: 150 }, (_, i) => `Ab3${String(i).padStart(4, "0")}xYz9QwErTy1u`).join("/") + "?x=1";
      await put(cwd, "inputs/needed.elf", buildElf({ cls: 64, needed: Array.from({ length: 4096 }, () => name) }));
      return { argv: [], stdin: JSON.stringify({ path: "inputs/needed.elf" }) };
    },
  },
  {
    name: "fuzzy_hash", script: FUZZY, marker: MODULE_LEVEL,
    work: async (cwd, bin) => {
      await stub(bin, "ssdeep", `if [ "$1" = "-V" ]; then echo 2.14.1; exit 0; fi\nsleep 30`);
      await stub(bin, "tlsh", `if [ "$1" = "-version" ]; then echo 4.12.0; exit 0; fi\nsleep 30`);
      await put(cwd, "inputs/sample.bin", "x".repeat(2000));
      return { argv: [], stdin: JSON.stringify({ path: "inputs/sample.bin" }) };
    },
  },
  {
    name: "unpack_safe", script: UNPACK_SAFE, marker: MODULE_LEVEL,
    work: async (cwd, bin) => {
      await stub(bin, "upx", `if [ "$1" = "--version" ]; then echo upx 5.2.1; exit 0; fi
if [ "$1" = "-t" ]; then exit 0; fi
if [ "$1" = "-l" ]; then exit 0; fi
sleep 60`);
      await put(cwd, "inputs/sample.bin", "x".repeat(2000));
      return { argv: [], stdin: JSON.stringify({ path: "inputs/sample.bin" }) };
    },
  },
  {
    name: "authenticode_verify", script: AUTHENTICODE_VERIFY, marker: MODULE_LEVEL,
    work: async (cwd, bin) => {
      await stub(bin, "osslsigncode", `if [ "$1" = "--version" ]; then echo "osslsigncode 2.5, using:"; exit 0; fi
sleep 60`);
      await put(cwd, "inputs/s.exe", buildPe({}).file);
      await put(cwd, "inputs/ca.pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
      return { argv: [], stdin: JSON.stringify({ path: "inputs/s.exe", trust_ca: "inputs/ca.pem" }) };
    },
  },
  {
    name: "clr_inspect", script: CLR_INSPECT, marker: MODULE_LEVEL,
    work: async (cwd) => {
      const path = await put(cwd, "inputs/big.dll", buildPeDirs({ clr: {} }).file);
      await truncate(path, 2 ** 30);
      return { argv: [], stdin: JSON.stringify({ path: "inputs/big.dll" }) };
    },
  },
  {
    name: "capa-floss", script: CAPA_FLOSS, marker: MODULE_LEVEL,
    work: async (cwd, bin) => {
      await stub(bin, "capa", `if [ "$1" = "--version" ]; then echo v; exit 0; fi\nsleep 60`);
      await stub(bin, "floss", `if [ "$1" = "--version" ]; then echo v; exit 0; fi\nsleep 60`);
      await put(cwd, "inputs/s.exe", buildPe({}).file);
      return { argv: ["run", "--target", JSON.stringify({ paths: ["inputs/s.exe"] }), "--out", "catalog"], stdin: "" };
    },
  },
  {
    name: "static-binary", script: RECIPE, marker: MODULE_LEVEL,
    work: async (cwd) => {
      const path = await put(cwd, "inputs/big.exe", buildPe({}).file);
      await truncate(path, 2 ** 30);
      return { argv: ["run", "--target", JSON.stringify({ paths: ["inputs/big.exe"] }), "--out", "catalog"], stdin: "" };
    },
  },
  {
    name: "doc_structure", script: DOC_STRUCTURE, marker: MODULE_LEVEL,
    work: async (cwd) => {
      const entries: ZipEntry[] = [{ name: "[Content_Types].xml", data: Buffer.from("<Types/>") }];
      for (let i = 0; i < 100_001; i++) entries.push({ name: `m${String(i).padStart(6, "0")}.bin`, data: Buffer.from("x"), method: 0 });
      await put(cwd, "inputs/many.docx", buildZip(entries, { zip64: true }));
      return { argv: [], stdin: JSON.stringify({ path: "inputs/many.docx", max_seconds: 80 }) };
    },
  },
  {
    name: "elf_directories", script: ELF_DIRECTORIES, marker: MODULE_LEVEL,
    work: async (cwd) => {
      await put(cwd, "inputs/syms.so", buildElf({ cls: 64, needed: Array.from({ length: 150_000 }, (_, i) => `lib${i}Name${i * 7}.so`) }));
      return { argv: [], stdin: JSON.stringify({ path: "inputs/syms.so" }) };
    },
  },
  {
    name: "macho_directories", script: MACHO_DIRECTORIES, marker: MODULE_LEVEL,
    work: async (cwd) => {
      const names = Array.from({ length: 150_000 }, (_, i) => `_symbol${i}Name${i * 7}`);
      const table = Buffer.concat(names.map((n, i) => { const b = Buffer.alloc(16); b.writeUInt32LE(1 + i * 24, 0); b[4] = 0x0f; b[5] = 1; return b; }));
      const strings = Buffer.concat([Buffer.from([0]), ...names.map((n) => Buffer.from(n + "\0"))]);
      const header = Buffer.alloc(32 + 24);
      header.set([0xcf, 0xfa, 0xed, 0xfe], 0);
      header.writeUInt32LE(0x01000007, 4);
      header.writeUInt32LE(2, 12);
      header.writeUInt32LE(1, 16);
      header.writeUInt32LE(24, 20);
      header.writeUInt32LE(2, 32);
      header.writeUInt32LE(24, 36);
      header.writeUInt32LE(4096, 40);
      header.writeUInt32LE(names.length, 44);
      header.writeUInt32LE(4096 + table.length, 48);
      header.writeUInt32LE(strings.length, 52);
      await put(cwd, "inputs/syms.macho", Buffer.concat([header, Buffer.alloc(4096 - header.length), table, strings]));
      return { argv: [], stdin: JSON.stringify({ path: "inputs/syms.macho" }) };
    },
  },
  {
    name: "pe_directories", script: PE_DIRECTORIES, marker: MODULE_LEVEL,
    work: async (cwd) => {
      await put(cwd, "inputs/exports.dll", buildPeDirs({ exports: { imageName: "a.dll", functions: Array.from({ length: 65_000 }, (_, i) => ({ name: `Export${i}Name${i * 7}` })) } }).file);
      return { argv: [], stdin: JSON.stringify({ path: "inputs/exports.dll" }) };
    },
  },
  {
    // the two tools added in this pack carry the same handling from their first line
    name: "go_buildinfo", script: join(TOOLS, "go_buildinfo", "run.py"), marker: STOP,
    work: async (cwd) => {
      const sentinelStart = Buffer.from("3077af0c9274080241e1c107e6d618e6", "hex");
      const sentinelEnd = Buffer.from("f932433186182072008242104116d8f2", "hex");
      const text = Buffer.from(["path\tex.org/main", ...Array.from({ length: 600_000 }, (_, i) => `dep\tex.org/m${i}\tv1.0.0\t`)].join("\n") + "\n", "latin1");
      const mod = Buffer.concat([sentinelStart, text, sentinelEnd]);
      const lead = (n: number): Buffer => { const out: number[] = []; let v = n; while (v >= 0x80) { out.push((v & 0x7f) | 0x80); v = Math.floor(v / 128); } out.push(v); return Buffer.from(out); };
      const head = Buffer.alloc(32);
      Buffer.from([0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a]).copy(head);
      head[14] = 8;
      head[15] = 2;
      await put(cwd, "inputs/go.bin", Buffer.concat([Buffer.from("\x7fELF\x02\x01\x01", "latin1"), Buffer.alloc(9), Buffer.alloc(0x100 - 16), head, lead(8), Buffer.from("go1.22.5"), lead(mod.length), mod]));
      return { argv: [], stdin: JSON.stringify({ path: "inputs/go.bin" }) };
    },
  },
  {
    name: "marshal_inspect", script: join(TOOLS, "marshal_inspect", "run.py"), marker: STOP,
    work: async (cwd) => {
      const n = 1_900_000;
      const count = Buffer.alloc(4);
      count.writeInt32LE(n);
      await put(cwd, "inputs/ints.bin", Buffer.concat([Buffer.from("("), count, Buffer.concat(Array.from({ length: n }, () => Buffer.from([0x69, 1, 0, 0, 0])))]));
      return { argv: [], stdin: JSON.stringify({ path: "inputs/ints.bin", max_seconds: 50 }) };
    },
  },
];

/** The files directly in `dir` whose names begin with a dot: a hidden temporary file a stopped tool left. */
async function hidden(dir: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (d: string): Promise<void> => {
    for (const e of await readdir(d, { withFileTypes: true }).catch(() => [])) {
      if (e.name.startsWith(".") && e.name !== ".keep") out.push(join(d, e.name));
      if (e.isDirectory() && e.name !== "inputs") await walk(join(d, e.name));
    }
  };
  await walk(dir);
  return out;
}

function oneDocument(stdout: string, where: string): Json {
  const text = stdout.trim();
  assert.ok(text.length > 0, `${where}: no answer`);
  let parsed: Json;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    assert.fail(`${where}: stdout is not one JSON document (${(error as Error).message}): ${text.slice(0, 300)}`);
  }
  return parsed;
}

// --- early: a signal right after the handlers are installed ----------------------------------------------------------------------------

test("the handlers are in at module level: a signal sent right after the line that installs them gives one JSON answer and exit 128 + the signal, for each carrier and each signal", async () => {
  for (const c of CARRIERS) {
    const source = await readFile(c.script, "utf8");
    const at = source.indexOf(c.marker);
    assert.ok(at >= 0, `${c.name}: no line "${c.marker}"`);
    const prefix = source.slice(0, source.indexOf("\n", at) + 1);
    for (const signal of SIGNALS) {
      const dir = await mkdtemp(join(tmpdir(), "re-stop-early-"));
      try {
        const script = join(dir, "prefix.py");
        await writeFile(script, `${prefix}\nimport os as _os, signal as _signal, time as _time\n_os.kill(_os.getpid(), _signal.${signal})\n_time.sleep(30)\nprint("survived")\n`);
        const ran = spawnSync("python3", [script], { cwd: dir, encoding: "utf8", timeout: 60_000, input: "", env: { ...process.env, AGENT_ID: "s1" } });
        assert.equal(ran.status, 128 + NUMBER[signal], `${c.name} ${signal}: exit ${ran.status}; ${ran.stderr.slice(0, 300)}`);
        assert.doesNotMatch(ran.stderr, /Traceback/, `${c.name} ${signal}`);
        const answer = oneDocument(ran.stdout, `${c.name} ${signal}`);
        assert.ok(answer.status === "interrupted" || answer.status === "failed", `${c.name} ${signal}: ${ran.stdout}`);
        assert.ok(!ran.stdout.includes("survived"));
        assert.deepEqual(await hidden(dir), [], `${c.name} ${signal}: a hidden file was left`);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    }
  }
});

// --- mid-work: the real tool, signalled at seeded random moments ----------------------------------------------------------------------------

function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Waits until the process has SIGHUP, SIGINT and SIGTERM handlers (the kernel's own account, SigCgt in /proc/<pid>/status), so that the moment of
 * the signal is counted from the handlers and not from the start of the interpreter, which takes a fifth of a second to a second for the larger
 * files, and longer on a loaded runner. Without /proc a fixed two seconds stand in. Gives up after 8 s (a tool that never installs them is signalled anyway, and the case fails on its own).
 */
async function handlersIn(pid: number): Promise<void> {
  const want = 0x1n | 0x2n | 0x4000n;
  const until = Date.now() + 8_000;
  while (Date.now() < until) {
    try {
      const status = await readFile(`/proc/${pid}/status`, "utf8");
      const m = /SigCgt:\s+([0-9a-f]+)/.exec(status);
      if (m && (BigInt(`0x${m[1]}`) & want) === want) return;
    } catch {
      if (process.platform !== "linux") {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        return;
      }
      return;                                 // the process is gone already
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

async function runSignalled(c: Carrier, cwd: string, bin: string, spec: { argv: string[]; stdin: string }, signal: (typeof SIGNALS)[number], delayMs: number): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const child = spawn("python3", [c.script, ...spec.argv], { cwd, env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, AGENT_ID: "s1" }, detached: true, stdio: ["pipe", "pipe", "pipe"] });
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  child.stdout.on("data", (b: Buffer) => out.push(b));
  child.stderr.on("data", (b: Buffer) => err.push(b));
  child.stdin.on("error", () => undefined);
  child.stdin.end(spec.stdin);
  const closed = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
  await handlersIn(child.pid as number);
  await new Promise((resolve) => setTimeout(resolve, delayMs));
  try {
    child.kill(signal);
  } catch {
    /* already gone */
  }
  const code = await Promise.race([closed, new Promise<number | null>((resolve) => setTimeout(() => { try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* gone */ } resolve(-999); }, 60_000))]);
  try {
    process.kill(-(child.pid as number), "SIGKILL");     // what the tool started and left, if anything (the case is not about that)
  } catch {
    /* none */
  }
  return { code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") };
}

for (const c of CARRIERS) {
  test(`${c.name}: signalled at seeded random moments of a real run, each of the three signals: one JSON document, exit 128 + the signal (or 0 if it had finished), no hidden file`, async (t) => {
    await withCwd(async (cwd, bin) => {
      const spec = await c.work(cwd, bin);
      const random = rng(c.name.length * 7919 + 13);
      let stopped = 0;
      for (const signal of SIGNALS) {
        for (let k = 0; k < 2; k++) {
          const delay = 50 + Math.floor(random() * 1500);        // counted from the moment the handlers are in
          const ran = await runSignalled(c, cwd, bin, spec, signal, delay);
          const where = `${c.name} ${signal} at ${delay} ms`;
          assert.notEqual(ran.code, -999, `${where}: the tool did not end`);
          assert.doesNotMatch(ran.stderr, /Traceback/, `${where}: ${ran.stderr.slice(0, 400)}`);
          const answer = oneDocument(ran.stdout, where);
          if (ran.code === 128 + NUMBER[signal]) {
            stopped += 1;
            assert.ok(answer.status === "interrupted" || answer.status === "failed", `${where}: ${ran.stdout.slice(0, 300)}`);
          } else {
            assert.ok(ran.code === 0 || ran.code === 1, `${where}: exit ${ran.code}`);       // it had finished (or refused) before the signal
          }
          assert.deepEqual(await hidden(cwd), [], `${where}: a hidden file was left`);
          await rm(join(cwd, "catalog"), { recursive: true, force: true });
        }
      }
      // (a host that reads the workload faster than the first signal can arrive, as a Mac does with a sparse file of a gigabyte, has no stopped run to look at: the case says so and does not pass for it)
      if (stopped === 0 && process.platform !== "linux") return t.skip(`${c.name}: the workload ends before the first signal on this host`);
      assert.ok(stopped >= 1, `${c.name}: no run was stopped by its signal: the workload is too short`);
      await mkdir(join(cwd, "work"), { recursive: true });
    });
  });
}
