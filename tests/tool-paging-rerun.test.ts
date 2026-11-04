/**
 * One driver reruns the paging tools in one job-shaped $OUT (JOB_ID and OUT set). Run 1 asks for a large page, run 2 for a small one, in the same $OUT.
 * The rule (docs/packs.md, section 8): a rerun never replaces a larger output file with a smaller one. So after run 2:
 *
 *  - every file run 1 left in $OUT is still there with the same bytes (the larger file survived);
 *  - run 2 left its own file under another name, or its answer says it kept the earlier one;
 *  - run 2's answer names run 1's paging file(s) and its own.
 *
 * A tool is covered when it has a builder in CASES (an input that gives more rows than the small limit, and the two argument sets). The paging tools
 * with no builder yet are listed in tests/tool-paging-rerun-allowed.json under "uncovered", and every tool that fails is listed under "failing", each
 * with the item or package that removes it. The lists may only shrink: a tool that fails or is uncovered with no entry fails the test, and so does an
 * entry that no longer applies. The per-pack rerun tests stay: this driver adds one uniform check.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod } from "node:fs/promises";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const LIMIT_MS = 30_000;

type Args = Record<string, unknown>;
type Case = {
  tool: string; // pack/tool
  /** Writes the input under `dir` and returns the arguments both runs share. */
  build: (dir: string) => Promise<Args>;
  large: Args;
  small: Args;
  /** Extra environment for both runs (a stand-in program on PATH, say), made under `dir`. */
  env?: (dir: string) => Promise<Record<string, string>>;
};
type Entry = { tool: string; item: string; why: string };

// ---- the fixtures: small inputs that hold more rows than the small limit ----------------------------------------------------------------------

const lines = (n: number, line: (i: number) => string): string => Array.from({ length: n }, (_, i) => line(i)).join("\n") + "\n";

/** A shell link: the 76-byte header, then StringData (MS-SHLLINK): a name, a relative path, a working directory. */
function lnk(i: number): Buffer {
  const header = Buffer.alloc(0x4c);
  header.writeUInt32LE(0x4c, 0);
  Buffer.from("0114020000000000c000000000000046", "hex").copy(header, 4);
  header.writeUInt32LE(0x04 | 0x08 | 0x10 | 0x80, 0x14);
  const parts: Buffer[] = [];
  for (const text of [`item ${i}`, `..\\docs\\file${i}.txt`, `C:\\Users\\user${i}`]) {
    const count = Buffer.alloc(2);
    count.writeUInt16LE(text.length, 0);
    parts.push(count, Buffer.from(text, "utf16le"));
  }
  return Buffer.concat([header, ...parts, Buffer.alloc(4)]);
}

async function put(dir: string, rel: string, data: string | Buffer): Promise<void> {
  await mkdir(dirname(join(dir, rel)), { recursive: true });
  await writeFile(join(dir, rel), data);
}

/** A stand-in `vol` under dir/bin: its listing and its plugin output are the strings given; the image and the readiness receipt are written beside it. */
async function standInVol(dir: string, help: string, plugin: string): Promise<Record<string, string>> {
  const py = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).stdout.trim();
  const script = [
    `#!${py}`,
    "import sys",
    "a = sys.argv[1:]",
    "if a[-1:] == ['--help'] and len(a) == 2:",
    "    sys.stderr.write('Volatility 3 Framework 2.28.2\\n'); sys.stdout.write(" + JSON.stringify(JSON.stringify(help)).slice(0, 0) + "HELP)",
    "elif a[-1:] == ['--help']:",
    "    sys.stdout.write('usage: vol plugin [--pid PID]\\n')",
    "else:",
    "    sys.stdout.write(PLUGIN)",
    "",
  ].join("\n").replace("HELP", JSON.stringify(help)).replace("PLUGIN", JSON.stringify(plugin));
  await put(dir, "bin/vol", script);
  await chmod(join(dir, "bin", "vol"), 0o755);
  await put(dir, "mem.raw", Buffer.alloc(8192));
  await put(dir, "ready.json", JSON.stringify({ parser: "vol_readiness/1", verdict: "ready", views_requested: ["plugins", "symbols"], inputs: { path: "mem.raw" }, volatility: { version: "2.28.2" } }));
  return { PATH: `${join(dir, "bin")}:${process.env.PATH ?? ""}` };
}

const names300 = Array.from({ length: 300 }, (_, i) => `mod${i}.Plugin${i}`).join(",");
const hives40 = Array.from({ length: 40 }, (_, i) => `0x${(0xf8a000010010 + i * 0x1000).toString(16)}\t\\REGISTRY\\USER\\u${i}\tDisabled\n`).join("");
const procs60 = Array.from({ length: 60 }, (_, i) => `${100 + i}\t4\tp${i}.exe\n`).join("");

const CASES: Case[] = [
  {
    tool: "memory-forensics/vol_readiness",
    build: async () => ({ views: ["plugins"] }),
    env: (dir) => standInVol(dir, `Plugins:\n  {${names300}}\n`, ""),
    large: { limit: 100 },
    small: { limit: 5 },
  },
  {
    tool: "memory-forensics/mem_registry",
    build: async () => ({ path: "mem.raw", mode: "hivelist" }),
    env: (dir) => standInVol(dir, "Plugins:\n  {windows.registry.hivelist.HiveList,windows.registry.printkey.PrintKey}\n", `Offset\tFileFullPath\tFile output\n${hives40}`),
    large: { limit: 20 },
    small: { limit: 1 },
  },
  {
    tool: "memory-forensics/vol_views",
    build: async () => ({ path: "mem.raw", question: "windows.pslist", readiness: "ready.json" }),
    env: (dir) => standInVol(dir, "Plugins:\n  {windows.pslist.PsList}\n", `PID\tPPID\tImageFileName\n${procs60}`),
    large: { limit: 20 },
    small: { limit: 1 },
  },
  {
    tool: "windows-forensics/lnk_parse",
    build: async (dir) => {
      await put(dir, "blob.bin", Buffer.concat(Array.from({ length: 6 }, (_, i) => Buffer.concat([lnk(i), Buffer.alloc(16)]))));
      return { path: "blob.bin", scan: true };
    },
    large: { limit: 4 },
    small: { limit: 1 },
  },
  {
    tool: "computer-forensics-base/sig_carve",
    build: async (dir) => {
      await put(dir, "blob.bin", Buffer.concat(Array.from({ length: 40 }, () => Buffer.concat([Buffer.from("PK\x03\x04", "latin1"), Buffer.alloc(60)]))));
      return { path: "blob.bin" };
    },
    large: { max_hits: 20 },
    small: { max_hits: 2 },
  },
  {
    tool: "linux-forensics/auth_log",
    build: async (dir) => {
      await put(dir, "auth.log", lines(40, (i) => `Nov  1 10:00:${String(i % 60).padStart(2, "0")} host sshd[${100 + i}]: Failed password for invalid user u${i} from 10.0.0.${i + 1} port 22 ssh2`));
      return { path: "auth.log", year: 2026 };
    },
    large: { limit: 20 },
    small: { limit: 1 },
  },
  {
    tool: "linux-forensics/shell_history",
    build: async (dir) => {
      await put(dir, "root/home/alice/.bash_history", lines(40, (i) => `echo command ${i}`));
      await put(dir, "root/etc/passwd", "alice:x:1000:1000::/home/alice:/bin/bash\n");
      return { root: "root", root_is_file_system_root: true };
    },
    large: { limit: 20 },
    small: { limit: 1 },
  },
  {
    tool: "linux-forensics/cron_dump",
    build: async (dir) => {
      await put(dir, "root/etc/crontab", lines(40, (i) => `${i % 60} * * * * root /usr/bin/job${i}`));
      return { root: "root" };
    },
    large: { limit: 20 },
    small: { limit: 1 },
  },
  {
    tool: "linux-forensics/audit_events",
    build: async (dir) => {
      await put(dir, "audit.log", lines(40, (i) => `type=SYSCALL msg=audit(1700000000.${String(i).padStart(3, "0")}:${100 + i}): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 a3=4 items=0 ppid=1 pid=${200 + i} auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="x" exe="/bin/x" key=(null)`));
      return { paths: ["audit.log"] };
    },
    large: { limit: 20 },
    small: { limit: 1 },
  },
  {
    tool: "linux-forensics/linux_persistence",
    build: async (dir) => {
      for (let i = 0; i < 40; i++) await put(dir, `root/etc/systemd/system/job${i}.service`, `[Unit]\nDescription=job ${i}\n[Service]\nType=simple\nExecStart=/usr/bin/job${i}\n[Install]\nWantedBy=multi-user.target\n`);
      return { root: "root" };
    },
    large: { limit: 20 },
    small: { limit: 1 },
  },
  {
    tool: "linux-forensics/container_inventory",
    build: async (dir) => {
      for (let i = 0; i < 40; i++) {
        const id = i.toString(16).padStart(64, "a");
        await put(dir, `root/var/lib/docker/containers/${id}/config.v2.json`, JSON.stringify({ ID: id, Name: `/c${i}`, Created: "2026-01-01T00:00:00Z", Path: "/bin/sh", Args: [], Image: `sha256:${"b".repeat(64)}`, State: { Running: false }, Config: { Image: "x" } }));
        await put(dir, `root/var/lib/docker/containers/${id}/hostconfig.json`, JSON.stringify({ Privileged: false }));
      }
      return { root: "root" };
    },
    large: { limit: 20 },
    small: { limit: 1 },
  },
  {
    tool: "linux-forensics/container_layers",
    build: async (dir) => {
      for (let i = 0; i < 40; i++) await put(dir, `layer/etc/file${i}`, `row ${i}\n`);
      return { layers: ["layer"] };
    },
    large: { limit: 20 },
    small: { limit: 1 },
  },
  {
    tool: "linux-forensics/package_verify",
    build: async (dir) => {
      await put(dir, "root/var/lib/dpkg/status", "Package: a\nStatus: install ok installed\n");
      await put(dir, "root/var/lib/dpkg/info/a.md5sums", "d41d8cd98f00b204e9800998ecf8427e  usr/bin/a\n");
      await put(dir, "bin/debsums", `#!/bin/bash\ncase "$1" in --version) echo "debsums version 9.9.9"; exit 0;; esac\nfor i in $(seq 1 40); do echo "/usr/bin/f$i      FAILED"; done\nexit 2\n`);
      await chmod(join(dir, "bin", "debsums"), 0o755);
      return { root: "root", family: "debian" };
    },
    env: async (dir) => ({ PATH: `${join(dir, "bin")}:${process.env.PATH ?? ""}` }),
    large: { limit: 20 },
    small: { limit: 1 },
  },
  {
    tool: "ransomware-response/ransom_note_scan",
    build: async (dir) => {
      for (let i = 0; i < 12; i++) await put(dir, `share/d${i}/README_DECRYPT.txt`, "Your files are encrypted. Contact us at recover@example.org to get the decryptor.\n");
      return { root: "share" };
    },
    large: { limit: 6 },
    small: { limit: 1 },
  },
  {
    tool: "ransomware-response/encrypted_survey",
    build: async (dir) => {
      for (let i = 0; i < 12; i++) await put(dir, `share/f${i}.docx.locked`, Buffer.from(Array.from({ length: 4096 }, (_, k) => (k * 131 + i * 17 + (k >> 3) * 29) & 0xff)));
      return { root: "share" };
    },
    large: { limit: 6 },
    small: { limit: 1 },
  },
  {
    tool: "ransomware-response/encryption_extent",
    build: async (dir) => {
      const files: string[] = [];
      for (let i = 0; i < 12; i++) {
        await put(dir, `share/f${i}.docx.locked`, Buffer.from(Array.from({ length: 4096 }, (_, k) => (k * 131 + i * 17 + (k >> 3) * 29) & 0xff)));
        files.push(`share/f${i}.docx.locked`);
      }
      return { policy: "full", files };
    },
    large: { limit: 6 },
    small: { limit: 1 },
  },
  {
    // Run 2 asks for less than run 1 asks for (one object of two), so its table is a different, smaller one under the same name: a tool that
    // replaces the file named by its arguments fails here, which a rerun that writes the same table twice could not show.
    tool: "ransomware-response/backup_destruction_correlate",
    build: async (dir) => {
      const row = (i: number, image: string, cmd: string) => ({ timestamp: "2026-10-01T10:00:00Z", event_id: 4688, channel: "Security", record_id: i, data: { NewProcessName: image, CommandLine: cmd, SubjectUserName: "u", NewProcessId: `0x${i + 1}` } });
      const rows = [
        ...Array.from({ length: 6 }, (_, i) => row(i, "C:\\Windows\\System32\\vssadmin.exe", "vssadmin delete shadows /all")),
        ...Array.from({ length: 4 }, (_, i) => row(10 + i, "C:\\Windows\\System32\\wbadmin.exe", "wbadmin delete catalog")),
      ];
      await put(dir, "answer.json", JSON.stringify({ parser: "evtx_query/4", status: "complete", events: [] }));
      await put(dir, "rows.jsonl", rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
      return { events: [{ host: "h1", file: "answer.json", result_file: "rows.jsonl" }] };
    },
    large: { limit: 6 },
    small: { limit: 1, only_objects: ["backup_catalog"] },
  },
  {
    // Run 2 considers fewer reference entries (the filter), so its candidates table is a different, smaller one under the same name.
    tool: "ransomware-response/ransomware_family_match",
    build: async () => ({ extensions: [".akira", ".basta", ".play", ".rhysida"] }),
    large: { limit: 1 },
    small: { limit: 1, filter: "black" },
  },
  {
    tool: "ransomware-response/recovery_validate",
    build: async (dir) => {
      const files: string[] = [];
      for (let i = 0; i < 12; i++) {
        await put(dir, `rec/f${i}.txt`, Buffer.from(`recovered text number ${i}\n`.repeat(20)));
        files.push(`rec/f${i}.txt`);
      }
      return { items: files };
    },
    large: { limit: 6 },
    small: { limit: 1 },
  },
  {
    tool: "ransomware-response/ransomware_scope_report",
    build: async (dir) => {
      const censuses: Array<{ host: string; file: string }> = [];
      for (let i = 0; i < 12; i++) {
        const rows = [JSON.stringify({ record: "file", file: "x", bytes: 10 + i, status: "candidate" }), JSON.stringify({ record: "receipt", parser: "encrypted_survey/3", status: "complete" })];
        await put(dir, `c${i}.jsonl`, Buffer.from(rows.join("\n") + "\n"));
        censuses.push({ host: `host${i}`, file: `c${i}.jsonl` });
      }
      return { censuses };
    },
    large: { limit: 6 },
    small: { limit: 1 },
  },
  {
    tool: "encrypted-containers/recovery_key_scan",
    build: async (dir) => {
      const key = (i: number) => Array.from({ length: 8 }, (_, g) => String(((i + 1) * 11 * (g + 3) * 7) % 11 * 0 + 111111 + ((i * 7 + g * 13) % 888888)).slice(0, 6).padEnd(6, "1")).join("-");
      await put(dir, "keys.txt", lines(20, (i) => `Recovery key ${i}: ${key(i)}`));
      return { path: "keys.txt" };
    },
    large: { limit: 10 },
    small: { limit: 1 },
  },
  {
    tool: "cloud-forensics/cloudtrail_parse",
    build: async (dir) => {
      const records = Array.from({ length: 30 }, (_, i) => ({
        eventVersion: "1.08", eventTime: `2026-10-0${1 + (i % 9)}T10:00:00Z`, eventSource: "iam.amazonaws.com", eventName: "CreateUser",
        awsRegion: "us-east-1", sourceIPAddress: `203.0.113.${i + 1}`, userAgent: "aws-cli/2.0", eventID: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
        userIdentity: { type: "IAMUser", userName: `u${i}`, arn: `arn:aws:iam::123456789012:user/u${i}`, accountId: "123456789012" },
        requestParameters: { userName: `new${i}` },
      }));
      await put(dir, "trail.json", JSON.stringify({ Records: records }));
      return { path: "trail.json" };
    },
    large: { limit: 15 },
    small: { limit: 1 },
  },
  {
    tool: "windows-forensics/utf16_urls",
    build: async (dir) => {
      await put(dir, "mem.bin", Buffer.concat(Array.from({ length: 20 }, (_, i) => Buffer.concat([Buffer.alloc(8), Buffer.from(`http://host${i}.example.org/path/${i}`, "utf16le")]))));
      return { path: "mem.bin" };
    },
    large: { limit: 10 },
    small: { limit: 1 },
  },
  {
    tool: "windows-forensics/recyclebin_i",
    build: async (dir) => {
      for (let i = 0; i < 8; i++) {
        const name = Buffer.from(`C:\\Users\\u\\Desktop\\gone${i}.txt\0`, "utf16le");
        const head = Buffer.alloc(24);
        head.writeBigUInt64LE(2n, 0); // version 2 (Windows 10)
        head.writeBigUInt64LE(1234n, 8);
        head.writeBigUInt64LE(133000000000000000n, 16);
        const len = Buffer.alloc(4);
        len.writeUInt32LE(name.length / 2, 0);
        await put(dir, `bin/$I${String(i).padStart(6, "A")}.txt`, Buffer.concat([head, len, name]));
      }
      return { path: "bin" };
    },
    large: { limit: 4 },
    small: { limit: 1 },
  },
];

// ---- the driver ------------------------------------------------------------------------------------------------------------------------------

type Run = { code: number | null; stdout: string; stderr: string };

function run(script: string, cwd: string, env: Record<string, string>, args: Args): Promise<Run> {
  return new Promise((resolve) => {
    const child = spawn("python3", [script], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    const timer = setTimeout(() => child.kill("SIGKILL"), LIMIT_MS);
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", () => undefined);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") });
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(JSON.stringify(args));
  });
}

/** Every file under `dir`: path relative to it -> sha256 of its bytes. */
async function snapshot(dir: string): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  for (const e of await readdir(dir, { withFileTypes: true, recursive: true }).catch(() => [])) {
    if (!e.isFile()) continue;
    const full = join(e.parentPath, e.name);
    out.set(full.slice(dir.length + 1), createHash("sha256").update(await readFile(full).catch(() => "")).digest("hex"));
  }
  return out;
}

/** Why the rerun of a tool is not safe, or null. `first` and `second` are the answers; `before` and `after` the $OUT after each run. */
export function rerunFailure(first: Run, second: Run, before: Map<string, string>, after: Map<string, string>): string | null {
  if (first.code === null || second.code === null) return "a run was killed";
  if (!before.size) return `run 1 left no file in $OUT (exit ${first.code}): ${first.stdout.slice(0, 120).replace(/\s+/g, " ")}`;
  for (const [file, digest] of before) {
    if (!after.has(file)) return `run 2 removed ${file}`;
    if (after.get(file) !== digest) return `run 2 replaced ${file}, a file of run 1, with other bytes`;
  }
  // run 2 names the page it points at: the earlier file it kept (the same name, the same bytes) or a file of its own, and a name it gives is a file that is there
  const present = new Set([...after.keys()].map((f) => f.split("/").pop() as string));
  const named = [...new Set(second.stdout.match(/[A-Za-z0-9_.-]+\.jsonl/g) ?? [])];
  if (!named.length) return "run 2's answer names no paging file";
  const dangling = named.filter((n) => !present.has(n));
  if (dangling.length) return `run 2's answer names ${dangling[0]}, which is not in $OUT`;
  return null;
}

/** Runs a tool twice in one job-shaped $OUT (a large page, then a small one) and says why the rerun is unsafe, or null. */
async function exercise(script: string, dir: string, first: Args, second: Args, extra: Record<string, string> = {}): Promise<string | null> {
  await mkdir(join(dir, "out"), { recursive: true });
  const env = { ...extra, JOB_ID: "j000001", OUT: join(dir, "out") };
  const one = await run(script, dir, env, first);
  const before = await snapshot(join(dir, "out"));
  const two = await run(script, dir, env, second);
  const after = await snapshot(join(dir, "out"));
  if (process.env.PAGING_RERUN_DEBUG) await writeFile(join(process.env.PAGING_RERUN_DEBUG, `${script.split("/").slice(-2, -1)[0]}.json`), `${one.stdout}\n${two.stdout}\n${[...before.keys()].join(" ")} | ${[...after.keys()].join(" ")}\n`);
  return rerunFailure(one, two, before, after);
}

async function allowed(): Promise<{ uncovered: Entry[]; failing: Entry[] }> {
  const all = JSON.parse(await readFile(join(ROOT, "tests", "tool-paging-rerun-allowed.json"), "utf8")) as { uncovered: Entry[]; failing: Entry[] };
  for (const e of [...all.uncovered, ...all.failing]) assert.ok(e.tool && e.item && e.why && !/\n/.test(e.why), `an entry needs tool, item and a one-line why: ${JSON.stringify(e)}`);
  return all;
}

/** The tools whose source writes or names a paging file. */
async function pagingTools(): Promise<string[]> {
  const out: string[] = [];
  const packs = join(ROOT, "packs");
  for (const pack of (await readdir(packs)).sort()) {
    for (const name of await readdir(join(packs, pack, "tools")).catch(() => [] as string[])) {
      const src = await readFile(join(packs, pack, "tools", name, "run.py"), "utf8").catch(() => "");
      if (/paging_files|results_to|NoReplacePage|LosslessPage/.test(src)) out.push(`${pack}/${name}`);
    }
  }
  return out;
}

test("every paging tool is rerun in one $OUT with a smaller limit, or is listed as uncovered", { timeout: 600_000 }, async () => {
  const list = await allowed();
  const paging = await pagingTools();
  assert.ok(paging.length >= 40, `${paging.length} paging tools found`);
  const covered = new Set(CASES.map((c) => c.tool));
  for (const c of CASES) assert.ok(paging.includes(c.tool), `${c.tool} is not a paging tool`);
  const uncovered = paging.filter((t) => !covered.has(t));
  const known = new Set(list.uncovered.map((e) => e.tool));
  const fresh = uncovered.filter((t) => !known.has(t));
  assert.equal(fresh.length, 0, `${fresh.length} paging tool(s) have no builder in tests/tool-paging-rerun.test.ts and no "uncovered" entry:\n  ${fresh.join("\n  ")}`);
  const stale = list.uncovered.filter((e) => covered.has(e.tool) || !paging.includes(e.tool)).map((e) => e.tool);
  assert.equal(stale.length, 0, `"uncovered" entries that are covered now or are not paging tools, remove them: ${stale.join(", ")}`);

  const failures = new Map<string, string>();
  for (const c of CASES) {
    const dir = await mkdtemp(join(tmpdir(), "paging-rerun-"));
    try {
      const shared = await c.build(dir);
      const extra = c.env ? await c.env(dir) : {};
      const [pack, name] = c.tool.split("/");
      const why = await exercise(join(ROOT, "packs", pack, "tools", name, "run.py"), dir, { ...shared, ...c.large }, { ...shared, ...c.small }, extra);
      if (why) failures.set(c.tool, why);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
  const failing = new Set(list.failing.map((e) => e.tool));
  const unexpected = [...failures].filter(([t]) => !failing.has(t)).map(([t, why]) => `  ${t}: ${why}`);
  assert.equal(unexpected.length, 0, `${unexpected.length} tool(s) fail the rerun with no entry in tests/tool-paging-rerun-allowed.json:\n${unexpected.join("\n")}`);
  const gone = list.failing.filter((e) => !failures.has(e.tool)).map((e) => `  ${e.tool} (${e.item})`);
  assert.equal(gone.length, 0, `entries of tests/tool-paging-rerun-allowed.json that no longer fail, remove them:\n${gone.join("\n")}`);
});


// ---- the driver can fail: stub tools that page the way a good tool and a bad one do -------------------------------------------------------------

/** A stub paging tool. `replace` is the old way (the file named by the arguments, replaced at the end); otherwise a file that is there is kept. */
const stub = (replace: boolean): string => `
import json, os, sys, hashlib
args = json.load(sys.stdin)
rows = ["row %d" % i for i in range(args["rows"])]
name = "stub-" + hashlib.sha256(args["path"].encode()).hexdigest()[:8] + ".jsonl"
path = os.path.join(os.environ["OUT"], "tool-output", name)
os.makedirs(os.path.dirname(path), exist_ok=True)
if ${replace ? "True" : "False"} or not os.path.exists(path):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        for r in rows:
            f.write(json.dumps({"r": r}) + "\\n")
    os.replace(tmp, path)
print(json.dumps({"status": "complete", "status_basis": "stub", "pages": {"all_results": "store/jobs/j000001/out/tool-output/" + name}}))
`;

test("the driver fails a tool that replaces its larger file with a smaller one, and passes one that keeps it", async () => {
  const dir = await mkdtemp(join(tmpdir(), "paging-stub-"));
  try {
    await writeFile(join(dir, "replacing.py"), stub(true));
    await writeFile(join(dir, "keeping.py"), stub(false));
    await mkdir(join(dir, "bad"), { recursive: true });
    await mkdir(join(dir, "good"), { recursive: true });
    const bad = await exercise(join(dir, "replacing.py"), join(dir, "bad"), { path: "p", rows: 10 }, { path: "p", rows: 2 });
    assert.match(bad ?? "", /run 2 replaced tool-output\/stub-[0-9a-f]{8}\.jsonl, a file of run 1, with other bytes/);
    assert.equal(await exercise(join(dir, "keeping.py"), join(dir, "good"), { path: "p", rows: 10 }, { path: "p", rows: 2 }), null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the rerun check finds a replaced file, a removed file, a dangling name, no name, and takes a safe rerun", () => {
  const ok: Run = { code: 0, stdout: "", stderr: "" };
  const sha = (s: string) => createHash("sha256").update(s).digest("hex");
  const first = new Map([["tool-output/a.jsonl", sha("big")]]);
  const own = new Map([...first, ["tool-output/b.jsonl", sha("small")]]);
  const names = (...n: string[]): Run => ({ ...ok, stdout: JSON.stringify({ pages: { all_results: n.map((x) => `out/tool-output/${x}`) } }) });
  assert.equal(rerunFailure(ok, names("b.jsonl"), first, own), null, "a file of its own");
  assert.equal(rerunFailure(ok, names("a.jsonl"), first, first), null, "the earlier file, kept, named again");
  assert.match(rerunFailure(ok, names("a.jsonl"), first, new Map([["tool-output/a.jsonl", sha("small")]])) ?? "", /replaced tool-output\/a.jsonl/);
  assert.match(rerunFailure(ok, names("a.jsonl"), first, new Map()) ?? "", /removed/);
  assert.match(rerunFailure(ok, names("c.jsonl"), first, own) ?? "", /c.jsonl, which is not in \$OUT/);
  assert.match(rerunFailure(ok, ok, first, first) ?? "", /names no paging file/);
  assert.match(rerunFailure(ok, ok, new Map(), new Map()) ?? "", /left no file in \$OUT/);
});
