/**
 * PKG-P6 (the memory-forensics pack in the process sweep). The shared PROCESS block ends what a program leaves behind (settle()); the memory tools that run Volatility or
 * dwarf2json put a line under the status basis and carry program_group, so that a program that exits 0 and leaves a writer behind never answers `complete` over what it
 * wrote or printed. Stand-ins only, with real abandoned children (network-process-harness.ts and process-apply-cases.ts describe them):
 *   vol_views (dump)      the plugin exports files into the job's directory the tool lists and hashes: held to the non-Linux rule as well
 *   vol_views (rows)      the plugin's rows come on a pipe: partial for a process settle() ended, not for a host that cannot adopt orphans
 *   vol_readiness, isf_intake, mem_registry   the same, for the help listing, the banners, the converter's table, hivelist
 * mem_fs is not in this file: it carries no PROCESS block, copies bytes it reads from a FUSE mount and has its own holder search (pack-memory-pipe-holders.test.ts probes it).
 * The cases that fail on the batch head (before the tools called process_apply) are the ones that expect `partial` and program_group: the answer was `complete`.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { FEW, HOLDERS, VARIANTS, exec, sh, stubDir } from "./network-process-harness.ts";
import { register } from "./process-apply-cases.ts";
import type { Case } from "./process-apply-cases.ts";

const MEM = process.env.MEM_TOOLS_DIR ?? join(ROOT, "packs", "memory-forensics", "tools");
const VIEWS = join(MEM, "vol_views", "run.py");
const READY = join(MEM, "vol_readiness", "run.py");
const ISF = join(MEM, "isf_intake", "run.py");
const REGISTRY = join(MEM, "mem_registry", "run.py");

async function stub(bin: string, name: string, script: string): Promise<void> {
  await mkdir(bin, { recursive: true });
  await writeFile(join(bin, name), script, { mode: 0o755 });
  await chmod(join(bin, name), 0o755);
}
const pre = (dir: string, left: string | undefined): string => `export STUB_DIR="${dir}" STUB_LEFT="${left ?? ""}" STUB_LSLEEP=3\n`;

// Volatility 3's help (one listing in the form each tool reads: the brace list, and one dotted name per line under "Plugins:")
const HELP = `usage: vol [-h] ... PLUGIN ...

Plugins:
  {banners.Banners,windows.pslist.PsList,windows.info.Info,windows.registry.hivelist.HiveList,windows.registry.printkey.PrintKey}
  PLUGIN
    banners.Banners     Attempts to identify banners
    windows.info.Info   Show OS and kernel details
    windows.pslist.PsList  Lists the processes
    windows.registry.hivelist.HiveList  Lists the registry hives
    windows.registry.printkey.PrintKey  Lists the registry keys
`;
const HEADER = "PID\\tPPID\\tImageFileName\\tOffset(V)\\tThreads\\tHandles\\tCreateTime";
const ROW = "4\\t0\\tSystem\\t0xfa8000a00004\\t12\\t300\\t2024-01-02 10:00:00.000000 UTC";

/** A stand-in `vol`: the help listings, the plugin's rows, an export file with -o, hivelist and the banners; `at` names the call that leaves a process and `target` what it writes. */
function vol(dir: string, left: string | undefined, at: "help" | "run", target: (shell: string) => string): string {
  return sh(`${pre(dir, left)}export LC_ALL=C
case "$*" in
  *"--offline --help"*) echo "Volatility 3 Framework 2.28.2" >&2
cat <<'HELP'
${HELP}HELP
    ${at === "help" ? 'leave "$STUB_DIR/late.txt"' : ":"}
    exit 0;;
  *"PsList --help"*) echo "usage: vol windows.pslist.PsList [-h] [--pid [PID ...]] [--dump]"; exit 0;;
  *banners.Banners*) printf 'Offset\\tBanner\\n0x1000\\tb%s\\n' "'Linux version 5.15.0-91-generic (buildd@lcy02) (gcc 11.4.0) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\\\\n'"
    ${at === "run" ? 'leave "$STUB_DIR/late.txt"' : ":"}
    exit 0;;
  *hivelist*) printf 'Offset\\tFileFullPath\\n0xf8a000a0\\t\\\\SystemRoot\\\\System32\\\\Config\\\\SOFTWARE\\n'
    ${at === "run" ? 'leave "$STUB_DIR/late.txt"' : ":"}
    exit 0;;
esac
# a plugin run: the rows on stdout, and with -o a file in the export directory
prev=""; outdir=""
for a in "$@"; do [ "$prev" = "-o" ] && outdir="$a"; prev="$a"; done
printf '${HEADER}\\n${ROW}\\n'
[ -n "$outdir" ] && printf 'exported bytes\\n' > "$outdir/pid.4.dmp"
${at === "run" ? target("run") : ":"}
exit 0
`);
}
// the leftover of a run writes to a file the stand-in names: the export (held) or a file beside the tool (pipe only)
const toExport = (): string => '[ -n "$outdir" ] && leave "$outdir/pid.4.dmp" || leave "$STUB_DIR/late.txt"';
const toLate = (): string => 'leave "$STUB_DIR/late.txt"';

async function job(cwd: string): Promise<{ out: string; env: Record<string, string> }> {
  const out = join(cwd, "job-out");
  await mkdir(out, { recursive: true });
  return { out, env: { JOB_ID: "job1", OUT: out, SECRET_OUTPUT: "1" } };
}
async function prepare(cwd: string, bin: string, left: string | undefined, at: "help" | "run", target: () => string): Promise<string> {
  const dir = await stubDir(cwd);
  await writeFile(join(dir, "late.txt"), "");
  await stub(bin, "vol", vol(dir, left, at, target));
  await writeFile(join(cwd, "inputs", "mem.raw"), Buffer.alloc(8192));
  await writeFile(join(cwd, "inputs", "ready.json"), JSON.stringify({ parser: "vol_readiness/1", verdict: "ready", views_requested: ["plugins", "symbols"], inputs: { path: "inputs/mem.raw" }, volatility: { version: "2.28.2" } }));
  return dir;
}

// ---- vol_views --------------------------------------------------------------------------------------------------------------------------------------

function views(dump: boolean): Case {
  return {
    name: `vol_views (${dump ? "dump" : "rows"})`,
    variants: dump ? VARIANTS : FEW.concat(["plain"]),
    holdsFiles: dump,
  holders: HOLDERS,
    invoke: async (cwd, bin, left, host) => {
      const dir = await prepare(cwd, bin, left, "run", dump ? toExport : toLate);
      const j = await job(cwd);
      const run = await exec(VIEWS, [], { path: "inputs/mem.raw", question: "windows.pslist", readiness: "inputs/ready.json", ...(dump ? { dump: true, write_values: true } : {}) }, cwd, bin,
        { STUB_DIR: dir, ...j.env, ...(left ? { STUB_LEFT: left } : {}) }, host);
      assert.equal(run.code, 0, run.stderr + run.stdout);
      return { answer: JSON.parse(run.stdout), run };
    },
  };
}
register(views(true));
register(views(false));

// ---- vol_readiness ----------------------------------------------------------------------------------------------------------------------------------

const readiness: Case = {
  name: "vol_readiness",
  variants: FEW.concat(["plain"]),
  holdsFiles: false,
  holders: HOLDERS,
  invoke: async (cwd, bin, left, host) => {
    const dir = await prepare(cwd, bin, left, "help", toLate);
    const run = await exec(READY, [], { views: ["plugins"], plugins: ["windows.pslist"] }, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout), run };
  },
};
register(readiness);

// ---- mem_registry -----------------------------------------------------------------------------------------------------------------------------------

const registry: Case = {
  name: "mem_registry",
  variants: FEW.concat(["plain"]),
  holdsFiles: false,
  holders: HOLDERS,
  invoke: async (cwd, bin, left, host) => {
    const dir = await prepare(cwd, bin, left, "run", toLate);
    const run = await exec(REGISTRY, [], { path: "inputs/mem.raw", mode: "hivelist" }, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout), run };
  },
};
register(registry);

// ---- isf_intake -------------------------------------------------------------------------------------------------------------------------------------

const BANNER = "Linux version 5.15.0-91-generic (buildd@lcy02) (gcc 11.4.0) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023";
const B64 = Buffer.from(BANNER).toString("base64");

const isf: Case = {
  name: "isf_intake",
  variants: FEW.concat(["plain"]),
  holdsFiles: false,
  holders: HOLDERS,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await writeFile(join(dir, "late.txt"), "");
    await stub(bin, "vol", sh(`${pre(dir, left)}printf 'Offset\\tBanner\\n0x1000\\tb%s\\n' "'${BANNER}\\\\n'"\nexit 0\n`));
    await stub(bin, "dwarf2json", sh(`${pre(dir, left)}case "$1" in --version) echo "dwarf2json 0.9.0"; exit 0;; esac
printf '{"metadata": {"producer": {"name": "stub"}}, "symbols": {"last": {"address": 1}, "linux_banner": {"type": {"kind": "array", "count": 80, "subtype": {"kind": "base", "name": "char"}}, "address": 4096, "constant_data": "${B64}"}}}\\n'
leave "$STUB_DIR/late.txt"
exit 0
`));
    await writeFile(join(cwd, "inputs", "mem.lime"), Buffer.alloc(8192));
    await writeFile(join(cwd, "inputs", "vmlinux"), Buffer.from("not really elf"));
    const run = await exec(ISF, [], { path: "inputs/mem.lime", debug: "inputs/vmlinux", kind: "elf", build_identity: "5.15.0-91-generic", symbols_out: "work/s1/symbols" }, cwd, bin,
      { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout), run };
  },
};
register(isf);

// A converter that left a process is not trusted: its table is a pipe a leftover could have written into, so no table is kept and nothing is ready.
test("isf_intake: a table whose converter left a process behind is not kept, and the verdict is unknown", { timeout: 120000 }, async () => {
  await withCwd(async (cwd, bin) => {
    const { answer } = await isf.invoke(cwd, bin, "setsid", "linux");
    assert.equal(answer.status, "partial");
    assert.equal(answer.verdict, "unknown");
    assert.equal(answer.table, undefined, "no table is described as kept");
    const kept = await readdir(join(cwd, "work", "s1", "symbols")).catch(() => []);
    assert.deepEqual(kept, [], "nothing is left in the symbols directory");
  });
});
