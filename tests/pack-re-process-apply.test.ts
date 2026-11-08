/**
 * PKG-P7 (reverse-engineering, ransomware-response and virtualization-backup-forensics in the process sweep). The shared PROCESS block ends what a program leaves
 * behind (settle()); the tools that run a program and report a file that program wrote call process_apply (or carry the verdict into their own status), so that
 * a program that exits 0 and leaves a writer behind, or a host where the absence of one cannot be proven, never answers `complete` over a file the program wrote.
 * Stand-ins only, with real abandoned children:
 *   plain    a child in the tool's group that writes to the file by name a second after the program exited 0
 *   stdout   a child that holds the program's stdout (a file the tool keeps, or the pipe it reads) and writes to it after the exit
 *   setsid   the same writer in a session of its own, with no descriptor open
 *   double   a double fork (the parent of the writer is gone at once)
 *   rewrite  a session of its own that truncates the file and writes it again
 *   periodic a session of its own that appends every 100 ms until it is killed
 * The tools that report a file a program wrote (clr_inspect decompile, unpack_safe, fuzzy_hash, the capa-floss recipe): the answer is `partial`, says what was
 * ended (program_group.left_behind, a line under problems or errors), every leftover is gone, and nothing under the working directory changed between the answer and
 * 1.6 seconds later. A clean run is still `complete` (left_behind 0, nothing unproven). Where the absence cannot be proven (the host is not Linux, or the kernel
 * refuses PR_SET_CHILD_SUBREAPER: the tool is run with sys.platform patched, or with ctypes.CDLL replaced by a library whose prctl fails) a clean run of such a tool is
 * `partial` and says why. The tools that report only what a program printed on a pipe (authenticode_verify, doc_structure's second reading, ransomware_family_match,
 * snapshot_chain_check's qemu-img reading) carry program_group, are `partial` for a process settle() ended, and are not held to an unproven host. The static-binary
 * recipe runs two tools of this pack that start no program: it carries the verdict, is `partial` for a process settle() ended and is not held to an unproven host.
 * The cases that fail on the batch head (before the tools called process_apply) are the ones that expect program_group, or `partial` for a host that cannot adopt.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { VARIANTS, alive, exec, pids, reap, sh, sleep, snapshot, stubDir } from "./network-process-harness.ts";
import type { Host, Run } from "./network-process-harness.ts";
import { RE, TOOLS, buildPe, put, stub, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { buildPdf, buildPeDirs } from "./pack-re-doc-fixtures.ts";
import type { PdfObj } from "./pack-re-doc-fixtures.ts";
import { qcow2 } from "./pack-virtualization-harness.ts";
import { ROOT } from "./tool-library-harness.ts";
import { NO_ADOPTION } from "./host-gates.ts";

const CLR = join(TOOLS, "clr_inspect", "run.py");
const UNPACK = join(TOOLS, "unpack_safe", "run.py");
const FUZZY = join(TOOLS, "fuzzy_hash", "run.py");
const AUTH = join(TOOLS, "authenticode_verify", "run.py");
const DOC = join(TOOLS, "doc_structure", "run.py");
const CAPA_FLOSS = join(RE, "recipes", "capa-floss", "run.py");
const STATIC = join(RE, "recipes", "static-binary", "run.py");
const MATCH = join(ROOT, "packs", "ransomware-response", "tools", "ransomware_family_match", "run.py");
const CHAIN = join(ROOT, "packs", "virtualization-backup-forensics", "tools", "snapshot_chain_check", "run.py");

type Case = {
  name: string;
  /** Stage the stand-ins and run the tool; the answer (the first JSON document on stdout, or the recipe's coverage.json) and the run. */
  invoke: (cwd: string, bin: string, left: string | undefined, host: Host) => Promise<{ answer: Json; run: Run }>;
  variants: string[];
  /** False for a tool that reports only what a program printed on a pipe (or runs no program of its own). */
  holdsFiles: boolean;
  /** The program_group of the answer, where it is not the answer's own program_group. */
  group?: (answer: Json) => Json;
};
const text = (a: Json): string => JSON.stringify(a);
const groupOf = (c: Case, a: Json): Json => (c.group ? c.group(a) : a.program_group);

async function expectLeft(c: Case, variant: string): Promise<void> {
  await withCwd(async (cwd, bin) => {
    try {
      const { answer } = await c.invoke(cwd, bin, variant, "linux");
      assert.equal(answer.status, "partial", `${c.name} ${variant}: ${answer.status_basis}`);
      if ("ok" in answer) assert.equal(answer.ok, false, `${c.name} ${variant}`);
      const group = groupOf(c, answer);
      assert.ok(group, "the answer carries program_group");
      assert.ok(group.left_behind >= 1, `${c.name} ${variant}: ${JSON.stringify(group)}`);
      assert.equal(group.subreaper, true);
      assert.match(text(answer), /left \d+ process\(es\) running after it ended/, `${c.name} ${variant}: the leftover is named`);
      const left = await pids(cwd);
      assert.ok(left.length >= 1, `${c.name} ${variant}: the stand-in left a process`);
      for (const pid of left) assert.equal(alive(pid), false, `${c.name} ${variant}: leftover ${pid} is gone`);
      const now = await snapshot(cwd);
      await sleep(1600);
      assert.deepEqual(await snapshot(cwd), now, `${c.name} ${variant}: nothing changed after the answer`);
    } finally {
      await reap(cwd);
    }
  });
}

async function expectClean(c: Case): Promise<void> {
  await withCwd(async (cwd, bin) => {
    const { answer } = await c.invoke(cwd, bin, undefined, "linux");
    assert.equal(answer.status, "complete", `${c.name}: ${answer.status_basis}`);
    const group = groupOf(c, answer);
    assert.ok(group, "program_group is in a clean answer too");
    assert.equal(group.left_behind, 0);
    assert.deepEqual(group.unproven, []);
    assert.equal(group.subreaper, true);
  });
}

async function expectUnproven(c: Case, host: Host): Promise<void> {
  await withCwd(async (cwd, bin) => {
    const { answer } = await c.invoke(cwd, bin, undefined, host);
    const group = groupOf(c, answer);
    assert.ok(group, `${c.name} ${host}: program_group`);
    assert.equal(group.subreaper, false);
    assert.ok(group.unproven.length >= 1, `${c.name} ${host}: ${JSON.stringify(group)}`);
    if (c.holdsFiles) {
      assert.equal(answer.status, "partial", `${c.name} ${host}: ${answer.status_basis}`);
      assert.match(text(answer), /cannot be shown to be final/, `${c.name} ${host}: says why`);
      if ("ok" in answer) assert.equal(answer.ok, false);
    } else {
      assert.equal(answer.status, "complete", `${c.name} ${host}: a tool that reports only what a program printed is not held: ${answer.status_basis}`);
    }
  });
}

function register(c: Case): void {
  for (const variant of c.variants) test(`${c.name}: a ${variant} leftover is ended, the answer is partial and the files do not change after it`, { skip: NO_ADOPTION }, () => expectLeft(c, variant));
  test(`${c.name}: a clean run is complete, nothing left, nothing unproven`, { skip: NO_ADOPTION }, () => expectClean(c));
  for (const host of ["darwin", "refused"] as const) {
    test(`${c.name}: where the absence of a leftover cannot be proven (${host}) a clean run is ${c.holdsFiles ? "partial and says why" : "still complete, with the reason in program_group"}`, () => expectUnproven(c, host));
  }
}

/**
 * The leftovers for the tools that read a pipe. A program that leaves a process holding its pipe is read for one second (PIPE_GRACE) and the pipe is let go, so
 * the leftover must outlive that second:
 *   hold    a process in the tool's group that holds the program's pipes and says nothing
 *   tick    one that writes a line to the pipe every 100 ms
 *   setsid  one in a session of its own that holds no pipe at all
 */
const PIPE_LEAVE_SH = `
leave() {
  [ -n "$STUB_LEFT" ] || return 0
  n0=$(cat "$STUB_DIR/left.pids" 2>/dev/null | wc -l)
  case "$STUB_LEFT" in
    hold)   sh -c 'echo $$ >> "$STUB_DIR/left.pids"; exec sleep 30' & ;;
    tick)   sh -c 'echo $$ >> "$STUB_DIR/left.pids"; while :; do echo tick; sleep 0.1; done' & ;;
    setsid) setsid sh -c 'echo $$ >> "$STUB_DIR/left.pids"; exec sleep 30' </dev/null >/dev/null 2>&1 & ;;
  esac
  i=0
  while [ "$i" -lt 100 ]; do
    [ "$(cat "$STUB_DIR/left.pids" 2>/dev/null | wc -l)" -gt "$n0" ] && break
    sleep 0.02; i=$((i + 1))
  done
}
`;
const PIPE_VARIANTS = ["hold", "tick", "setsid"];
const pipeSh = (body: string): string => `#!/bin/sh
${PIPE_LEAVE_SH}
${body}`;

const env = (dir: string, left: string | undefined, more: Record<string, string> = {}): Record<string, string> => ({ STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}), ...more });
const json = (run: Run): Json => {
  assert.doesNotMatch(run.stderr, /Traceback/);
  return JSON.parse(run.stdout);
};

// ---- clr_inspect (decompile) -------------------------------------------------------------------------------------------------------------------------

register({
  name: "clr_inspect decompile",
  variants: VARIANTS,
  holdsFiles: true,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    // the tool gives the decompiler an environment of its own (PATH and a few fixed variables), so the stand-in carries what the others take from the environment
    await stub(bin, "ilspycmd", sh(`STUB_DIR="${dir}"; STUB_LEFT="${left ?? ""}"; export STUB_DIR STUB_LEFT
case "$1" in --version) echo "ilspycmd: 11.2.0.10050"; exit 0;; esac
echo "namespace Demo { }"
leave "$(readlink /proc/$$/fd/1 2>/dev/null || lsof -a -p $$ -d 1 -Fn 2>/dev/null | sed -n 's/^n//p')"
exit 0
`));
    await put(cwd, "work/a.dll", buildPeDirs({ clr: {} }).file);
    await mkdir(join(cwd, "out"), { recursive: true });
    const run = await exec(CLR, [], { path: "work/a.dll", decompile: true }, cwd, bin, env(dir, left, { JOB_ID: "j000001", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }), host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: json(run), run };
  },
});

// ---- unpack_safe -------------------------------------------------------------------------------------------------------------------------------------

const UPX = sh(`case "$1" in
--version) echo "upx 5.2.1"; exit 0;;
-t) echo "[OK] $3"; exit 0;;
-l) printf '   3000 <-   100   40.00%%   linux/amd64   x\\n'; exit 0;;
-d) out="$3"; head -c 3000 /dev/zero | tr '\\0' 'A' > "$out"; leave "$out"; exit 0;;
esac
exit 2
`);
register({
  name: "unpack_safe",
  variants: VARIANTS,
  holdsFiles: true,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "upx", UPX);
    await put(cwd, "work/sample.exe", "UPXOK expand=3000 ");
    const run = await exec(UNPACK, [], { path: "work/sample.exe" }, cwd, bin, env(dir, left), host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: json(run), run };
  },
});

// ---- fuzzy_hash --------------------------------------------------------------------------------------------------------------------------------------

const TLSH_DIGEST = "T1" + "A1B2C3D4E5".repeat(7);
const SSDEEP_DIGEST = "96:aBcDeF0123456789+/aBcDeF0123456789+/:XyZ0123456789+/";
register({
  name: "fuzzy_hash",
  variants: VARIANTS,
  holdsFiles: true,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "ssdeep", sh(`if [ "$1" = "-V" ]; then echo "2.14.1"; exit 0; fi
echo 'ssdeep,1.1--blocksize:hash:hash,filename'
echo "${SSDEEP_DIGEST},\\"$(basename "$3")\\""
leave "$(readlink /proc/$$/fd/1 2>/dev/null || lsof -a -p $$ -d 1 -Fn 2>/dev/null | sed -n 's/^n//p')"
exit 0
`));
    await stub(bin, "tlsh", sh(`if [ "$1" = "-version" ]; then echo "tlsh 4.12.0"; exit 0; fi
printf '${TLSH_DIGEST}\\t%s\\n' "$2"
exit 0
`));
    await put(cwd, "work/sample.bin", "some bytes ".repeat(500));
    const run = await exec(FUZZY, [], { path: "work/sample.bin" }, cwd, bin, env(dir, left), host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: json(run), run };
  },
});

// ---- the capa-floss recipe ---------------------------------------------------------------------------------------------------------------------------

const CAPA_JSON = JSON.stringify({ meta: { version: "stand-in", analysis: { format: "pe" } }, rules: { "create mutex": { meta: { namespace: "host-interaction/mutex" }, matches: [[4096, {}]] } } });
const FLOSS_JSON = JSON.stringify({ analysis: { enable_static_strings: true }, strings: { static_strings: ["one"], stack_strings: [], decoded_strings: [] } });
async function recipeRun(script: string, args: string[], cwd: string, bin: string, environment: Record<string, string>, host: Host): Promise<{ answer: Json; run: Run }> {
  const out = join(cwd, "catalog");
  const run = await exec(script, ["run", "--target", JSON.stringify({ paths: [join(cwd, "inputs/s.exe")] }), "--out", out, ...args], undefined, cwd, bin, environment, host);
  assert.equal(run.code, 0, run.stderr + run.stdout);
  assert.doesNotMatch(run.stderr, /Traceback/);
  return { answer: JSON.parse(await readFile(join(out, "coverage.json"), "utf8")), run };
}
register({
  name: "capa-floss recipe",
  variants: VARIANTS,
  holdsFiles: true,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await writeFile(join(dir, "capa.json"), CAPA_JSON);
    await writeFile(join(dir, "floss.json"), FLOSS_JSON);
    await stub(bin, "capa", sh(`if [ "$1" = "--version" ]; then echo "stand-in 0.0"; exit 0; fi
cat "$STUB_DIR/capa.json"
leave "$(readlink /proc/$$/fd/1 2>/dev/null || lsof -a -p $$ -d 1 -Fn 2>/dev/null | sed -n 's/^n//p')"
exit 0
`));
    await stub(bin, "floss", sh(`if [ "$1" = "--version" ]; then echo "stand-in 0.0"; exit 0; fi
cat "$STUB_DIR/floss.json"
exit 0
`));
    await put(cwd, "inputs/s.exe", buildPe({}).file);
    return recipeRun(CAPA_FLOSS, [], cwd, bin, env(dir, left), host);
  },
});

// ---- the static-binary recipe: two tools of this pack, which start no program ---------------------------------------------------------------------------
// A leftover is made by a sitecustomize on the child's PYTHONPATH (a real abandoned child, a session of its own, that appends to the tool's output a second after
// pe_info has ended).

const SITE = `import os, sys, time
if os.environ.get("RE_LEFT") and sys.argv and sys.argv[0].endswith("pe_info/run.py"):
    pid = os.fork()
    if pid == 0:
        os.setsid()
        for fd in range(3, 256):
            try:
                os.close(fd)
            except OSError:
                pass
        time.sleep(1.0)
        open(os.environ["RE_LEFT"], "ab").write(b"late\\n")
        os._exit(0)
    open(os.path.join(os.environ["STUB_DIR"], "left.pids"), "a").write("%d\\n" % pid)
`;
register({
  name: "static-binary recipe",
  variants: ["setsid"],
  holdsFiles: false,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await mkdir(join(cwd, "site"), { recursive: true });
    await writeFile(join(cwd, "site", "sitecustomize.py"), SITE);
    await put(cwd, "inputs/s.exe", buildPe({}).file);
    return recipeRun(STATIC, [], cwd, bin, env(dir, left, { PYTHONPATH: join(cwd, "site"), ...(left ? { RE_LEFT: join(cwd, "catalog", "binary.json") } : {}) }), host);
  },
});

// ---- authenticode_verify (osslsigncode's words on a pipe) --------------------------------------------------------------------------------------------

register({
  name: "authenticode_verify",
  variants: PIPE_VARIANTS,
  holdsFiles: false,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "osslsigncode", pipeSh(`case "$1" in
--version) printf 'osslsigncode 2.5, using:\\n\\tOpenSSL 3.0.7 1 Nov 2022\\n'; exit 0;;
verify) printf 'Current PE checksum   : 00000000\\nCalculated PE checksum: 00007FBE\\n\\nNo signature found\\n\\nFailed\\n'; leave "$STUB_DIR/verify.target"; exit 1;;
esac
exit 2
`));
    await put(cwd, "work/a.exe", buildPe({}).file);
    const run = await exec(AUTH, [], { path: "work/a.exe" }, cwd, bin, env(dir, left), host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: json(run), run };
  },
});

// ---- doc_structure's second reading (qpdf's words on a pipe) -----------------------------------------------------------------------------------------

const CATALOG: PdfObj = { num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>" };
const PAGES: PdfObj = { num: 2, body: "<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>" };
const PAGE: PdfObj = { num: 3, body: "<< /Type /Page /Parent 2 0 R >>" };
const UNSUPPORTED_PDF = buildPdf([CATALOG, PAGES, PAGE, { num: 6, body: "<< /Filter /Acme#20Security /V 4 /R 4 /Length 128 /P -3904 /O <00> /U <00> >>" }], "/Root 1 0 R /Encrypt 6 0 R").file;
register({
  name: "doc_structure second reading",
  variants: PIPE_VARIANTS,
  holdsFiles: false,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "qpdf", pipeSh(`if [ "$1" = "--version" ]; then echo "qpdf version 11.3.0"; exit 0; fi
printf 'R = 6\\nP = -3904\\nextract for accessibility: allowed\\nstream encryption method: AESv3\\nstring encryption method: AESv3\\nfile encryption method: AESv3\\n'
leave "$STUB_DIR/qpdf.target"
exit 0
`));
    await put(cwd, "work/a.pdf", UNSUPPORTED_PDF);
    const run = await exec(DOC, [], { path: "work/a.pdf", second_reading: true }, cwd, bin, env(dir, left), host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: json(run), run };
  },
});

// ---- ransomware_family_match (yara's hits on a pipe) -------------------------------------------------------------------------------------------------

register({
  name: "ransomware_family_match",
  variants: PIPE_VARIANTS,
  holdsFiles: false,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "yara", pipeSh(`if [ "$1" = "--version" ]; then echo 4.5.0; exit 0; fi
cat > /dev/null
leave "$STUB_DIR/yara.target"
exit 0
`));
    const note = join(cwd, "ev", "info.txt");
    await mkdir(join(cwd, "ev"), { recursive: true });
    await writeFile(note, "!!! All of your files are encrypted !!!\n");
    const rows = [{ finding_id: "N000001", note_id: "N000001", file: note, offset: 0, kind: "note_preview", encoding: "utf-8", validation: null, value: "preview" }];
    await writeFile(join(cwd, "vals.jsonl"), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
    const run = await exec(MATCH, [], { values_file: "vals.jsonl", extensions: [".phobos"] }, cwd, bin, env(dir, left), host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: json(run), run };
  },
});

// ---- snapshot_chain_check (qemu-img's words on a pipe) -----------------------------------------------------------------------------------------------

register({
  name: "snapshot_chain_check qemu-img",
  variants: PIPE_VARIANTS,
  holdsFiles: false,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "qemu-img", pipeSh(`printf '{"virtual-size": 1073741824, "filename": "x", "format": "qcow2", "actual-size": 4096, "dirty-flag": false}\\n'
leave "$STUB_DIR/qemu.target"
exit 0
`));
    await put(cwd, "inputs/q/base.qcow2", qcow2({ size: 1073741824n }));
    const run = await exec(CHAIN, [], { root: "inputs/q", qemu_img: "auto" }, cwd, bin, env(dir, left), host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: json(run), run };
  },
});
