#!/usr/bin/env node
/**
 * Seed a fixture runs directory for the web app: no model, no Herdr, no keys.
 * Uses the same protocol.ts primitives the live extension uses, so every file
 * shape matches a real run. Used by tests/ui-server.test.ts and by
 * `npm run ui:fixture` for local browsing / screenshots.
 *
 *   node --experimental-strip-types scripts/seed-fixture.ts [runs-dir]
 */
import { createHash } from "node:crypto";
import { chmod, mkdir, readdir, readFile, rm, symlink, utimes, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  appendEvent,
  CURSORS_REL,
  applySessionUsage,
  claimFile,
  createContext,
  inboxLogResult,
  initSandbox,
  markDone,
  postMessage,
  reapStalledAgents,
  recordFileVersion,
  releaseFile,
  type AgentBudget,
  forgeTool,
  recordEntry,
  systemContext,
} from "../extensions/protocol.ts";
import { checkStore, Journal, sealTree, sha256File, storePaths, type StoreCheck } from "./evidence-store.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

type RunSpec = {
  id: string;
  label: string;
  state: "running" | "prepared" | "stopped" | "finished";
  n: number;
  model: string;
  cap_usd: number;
  wall: number;
  goal: string;
  started_min_ago: number;
  workspace_id: string;
};

const RUNS: RunSpec[] = [
  {
    id: "s7a1c",
    label: "compromised-web-server",
    state: "running",
    n: 6,
    model: "deepseek/deepseek-v4-pro",
    cap_usd: 3,
    wall: 15,
    goal: "Establish how the web server in inputs/ was compromised. Record every dated event in the ledger, draw the path in work/attack-path.svg, and leave work/notes.md with what is proven and what is not. A peer reviews the timeline before anyone calls done.",
    started_min_ago: 23,
    workspace_id: "w7",
  },
  {
    id: "s3f09",
    label: "usb-policy",
    state: "running",
    n: 2,
    model: "deepseek/deepseek-v4-flash",
    cap_usd: 0.5,
    wall: 8,
    goal: "Two peers share the sandbox. List every USB mass-storage device the SYSTEM hive has seen into work/usb-devices.txt, one per line with its first and last connection, claiming the file in turn.",
    started_min_ago: 41,
    workspace_id: "w9",
  },
  {
    id: "sbe12",
    label: "ransomware-triage",
    state: "running",
    n: 10,
    model: "google/gemini-3.7-flash",
    cap_usd: 3,
    wall: 15,
    goal: "Triage the ransomware on this host: encryption start, the note, the persistence, the account used. Deliver work/report.html as one self-contained file and work/summary.md with one line per agent.",
    started_min_ago: 9,
    workspace_id: "wF",
  },
  {
    id: "s1e77",
    label: "single-hive-triage",
    state: "running",
    n: 1,
    model: "deepseek/deepseek-v4-flash",
    cap_usd: 0.1,
    wall: 5,
    goal: "Single agent. Post what you are taking on threads/main, list the Run keys of the SOFTWARE hive into work/triage.txt, call done.",
    started_min_ago: 70,
    workspace_id: "w1",
  },
  {
    id: "s0d4e",
    label: "unallocated-carve",
    state: "stopped",
    n: 3,
    model: "openai/gpt-5.4-mini",
    cap_usd: 1,
    wall: 8,
    goal: "Carve deleted executables out of unallocated space with work/carve.py and record every hit with its offset.",
    started_min_ago: 95,
    workspace_id: "w3",
  },
  {
    // A microVM run the hub finished: VM records, the hub's own trace lines,
    // custody, the operator's record and an examiner's review, so every VM
    // screen of the console is exercised against the fixture.
    id: "svm1d",
    label: "web-server-vm",
    state: "finished",
    n: 3,
    model: "openai/gpt-5.4-mini",
    cap_usd: 2,
    wall: 20,
    goal: "In microVMs: establish how the web server in inputs/ was compromised, record every dated event, and deliver work/report.md.",
    started_min_ago: 130,
    workspace_id: "w5",
  },
];

const CALLSIGNS = ["Scout", "Stitch", "Doubter", "Pixel", "Referee", "Anvil", "Comet", "Ledger", "Quill", "Vesper"];

function ids(spec: RunSpec): string[] {
  return Array.from({ length: spec.n }, (_, i) => `${spec.id}${String(i).padStart(2, "0")}`);
}

function usage(spent: number, tokens: number, calls: number): AgentBudget {
  return {
    spent_usd: spent,
    tokens,
    calls,
    input: Math.round(tokens * 0.7),
    output: Math.round(tokens * 0.2),
    cache_read: Math.round(tokens * 0.1),
    cache_write: 0,
  };
}

/** What swarm.sh --inputs leaves behind: the copy, the pristine clone, no write bits, inputs.json. */
async function seedInputs(root: string, files: Record<string, string>, guard: string): Promise<void> {
  const manifest: Array<{ path: string; bytes: number; sha256: string }> = [];
  let total = 0;
  for (const dir of ["inputs", ".inputs-pristine"]) {
    for (const [rel, text] of Object.entries(files)) {
      const abs = join(root, dir, rel);
      await mkdir(dirname(abs), { recursive: true });
      await writeFile(abs, text, "utf8");
      await chmod(abs, 0o444);
    }
    for (const rel of Object.keys(files)) {
      const parts = rel.split("/").slice(0, -1);
      for (let i = parts.length; i >= 1; i--) await chmod(join(root, dir, ...parts.slice(0, i)), 0o555);
    }
    await chmod(join(root, dir), 0o555);
  }
  for (const [rel, text] of Object.entries(files)) {
    const bytes = Buffer.byteLength(text);
    total += bytes;
    manifest.push({ path: `inputs/${rel}`, bytes, sha256: createHash("sha256").update(text).digest("hex") });
  }
  manifest.sort((a, b) => a.path.localeCompare(b.path));
  await writeFile(
    join(root, "inputs.json"),
    `${JSON.stringify({ source: "/srv/evidence/webserver-2026-02", copied_at: iso(23), files: manifest, bytes: total, enforce: "auto", guard }, null, 2)}\n`,
    "utf8",
  );
}

async function backdate(path: string, minutesAgo: number): Promise<void> {
  const t = new Date(Date.now() - minutesAgo * 60_000);
  await utimes(path, t, t);
}

function iso(minutesAgo: number, plusSec = 0): string {
  return new Date(Date.now() - minutesAgo * 60_000 + plusSec * 1000).toISOString();
}

async function event(root: string, agent: string, tool: string, args: Record<string, unknown>, result: unknown, minutesAgo: number, plusSec = 0) {
  await appendEvent(root, { ts: iso(minutesAgo, plusSec), agent, tool, args, result });
}

const ATTACK_PATH_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 520 200" width="520" height="200">
  <rect width="520" height="200" fill="#f7f5f0"/>
  <g font-family="ui-sans-serif, system-ui" font-size="12" fill="#1c1b1a">
    <rect x="16" y="70" width="112" height="46" rx="6" fill="#ffffff" stroke="#3e5c76" stroke-width="2"/>
    <text x="30" y="90">203.0.113.24</text><text x="30" y="106">first request</text>
    <rect x="176" y="70" width="112" height="46" rx="6" fill="#ffffff" stroke="#b23a48" stroke-width="2"/>
    <text x="190" y="90">upload.aspx</text><text x="190" y="106">web shell</text>
    <rect x="336" y="70" width="112" height="46" rx="6" fill="#ffffff" stroke="#e09f3e" stroke-width="2"/>
    <text x="350" y="90">svchost.exe</text><text x="350" y="106">persistence</text>
    <path d="M128 93 L176 93 M288 93 L336 93" stroke="#1c1b1a" stroke-width="2" marker-end="url(#a)"/>
  </g>
  <defs><marker id="a" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
    <path d="M0 0 L8 4 L0 8 Z" fill="#1c1b1a"/></marker></defs>
</svg>
`;

const TRIAGE_REPORT_HTML = `<!doctype html>
<meta charset="utf-8">
<title>Ransomware triage</title>
<style>
  body{font:14px/1.6 ui-sans-serif,system-ui;margin:0;background:#f7f5f0;color:#1c1b1a}
  main{max-width:46rem;margin:0 auto;padding:2rem 1.25rem}
  h1{font-family:ui-serif,Georgia,serif;font-size:1.75rem;margin:0 0 .25rem}
  .sub{color:#6b6862;margin:0 0 1.5rem}
  table{border-collapse:collapse;width:100%;margin:1rem 0}
  th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #e3ded3}
  th{font-size:.75rem;letter-spacing:.06em;text-transform:uppercase;color:#6b6862}
  code{font-family:ui-monospace,monospace;font-size:.85em}
</style>
<main>
  <h1>Ransomware triage</h1>
  <p class="sub">Encryption started 2026-02-11 03:14 UTC. Four exhibits below.</p>
  <table>
    <thead><tr><th>Exhibit</th><th>When</th><th>What</th><th>Evidence</th></tr></thead>
    <tbody>
      <tr><td>E-1</td><td>03:02</td><td>Scheduled task created</td><td><code>inode 21188-128-4</code></td></tr>
      <tr><td>E-2</td><td>03:14</td><td>First file renamed <code>.lokd</code></td><td><code>$UsnJrnl seq 4471</code></td></tr>
      <tr><td>E-3</td><td>03:14</td><td>Ransom note written</td><td><code>work/extracted/READ_ME.txt</code></td></tr>
      <tr><td>E-4</td><td>03:51</td><td>Volume shadow copies deleted</td><td><code>Security.evtx 4688</code></td></tr>
    </tbody>
  </table>
  <p>The account used was <code>SVC-BACKUP</code>, whose password had not changed since 2023.</p>
</main>
`;

const PREFETCH_CSV = `ts,executable,run_count,source
2026-02-11T03:02:11Z,SCHTASKS.EXE,3,Prefetch/SCHTASKS.EXE-9A1C77B2.pf
2026-02-11T03:14:02Z,LOKD.EXE,1,Prefetch/LOKD.EXE-44C1E019.pf
2026-02-11T03:51:40Z,VSSADMIN.EXE,2,Prefetch/VSSADMIN.EXE-1B7E3300.pf
`;

const USB_FIRST = `Kingston DataTraveler 3.0  serial 60A44C3F9C21  first 2026-02-03T09:12:41Z  last 2026-02-09T17:04:02Z
`;

const USB_SECOND = `SanDisk Cruzer Blade  serial 4C530001180216119213  first 2026-02-10T22:48:07Z  last 2026-02-11T03:59:55Z
`;

const RUN_KEYS = `SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
  SecurityHealth   %windir%\\system32\\SecurityHealthSystray.exe
  OneDriveSetup    C:\\Windows\\SysWOW64\\OneDriveSetup.exe /thfirstsetup
  svchost          C:\\Users\\Public\\svchost.exe        <- not a system path
`;

const CARVE_PY = `import struct, sys

MZ = b"MZ"

def carve(path, start=0, end=None):
    """Walk unallocated space for PE headers and report each offset."""
    with open(path, "rb") as fh:
        fh.seek(start)
        offset = start
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                return
            i = chunk.find(MZ)
            while i >= 0:
                if chunk[i + 0x3C:i + 0x40]:
                    lfanew = struct.unpack_from("<I", chunk, i + 0x3C)[0]
                    if chunk[i + lfanew:i + lfanew + 4] == b"PE\\0\\0":
                        print(offset + i)
                i = chunk.find(MZ, i + 1)
            offset += len(chunk)
            if end is not None and offset >= end:
                return
`;

// 1x1 PNG, kelp green. Small enough to keep the fixture textual.
const PNG_1X1 = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkEHrxHwAEcwIYQ5j6SgAAAABJRU5ErkJggg==",
  "base64",
);

async function seedWebServer(root: string, spec: RunSpec): Promise<void> {
  const [a0, a1, a2, a3, a4, a5] = ids(spec).map((id) => createContext(root, id));
  const m = spec.started_min_ago;
  await event(root, a0.agentId, "agent_start", {}, { ok: true }, m);
  await event(root, a1.agentId, "agent_start", {}, { ok: true }, m, 2);
  await event(root, a2.agentId, "agent_start", {}, { ok: true }, m, 3);
  await event(root, a3.agentId, "agent_start", {}, { ok: true }, m, 4);
  await event(root, a4.agentId, "agent_start", {}, { ok: true }, m, 5);
  await event(root, a5.agentId, "agent_start", {}, { ok: true }, m, 6);

  const intro = async (ctx: ReturnType<typeof createContext>, name: string, line: string, minAgo: number) => {
    const p = await postMessage(ctx, { tag: "intro", body: `Call me ${name}. ${line}` });
    await backdate(p.path, minAgo);
    await event(root, ctx.agentId, "post", { tag: "intro", thread: "main" }, { ok: true, id: p.id }, minAgo);
  };
  await intro(a0, CALLSIGNS[0], "I will take the IIS logs and the first request.", m - 1);
  await intro(a1, CALLSIGNS[1], "The web shell and what it dropped are mine.", m - 1.2);
  await intro(a2, CALLSIGNS[2], "I will take the registry: services, Run keys, shimcache.", m - 1.5);
  await intro(a3, CALLSIGNS[3], "Taking Prefetch and the scheduled tasks.", m - 1.7);
  await intro(a4, CALLSIGNS[5], "Event logs. Starting with Security.evtx.", m - 2);
  await intro(a5, CALLSIGNS[4], "I review the timeline against the evidence before anyone calls done.", m - 2.1);

  await event(
    root,
    a1.agentId,
    "inbox",
    {},
    inboxLogResult({
      swarm_done: false,
      seen: 5,
      posts: [
        { id: 1, from: a0.agentId },
        { id: 2, from: a1.agentId },
        { id: 3, from: a2.agentId },
        { id: 4, from: a3.agentId },
        { id: 5, from: a4.agentId },
      ],
    }),
    m - 2.5,
  );
  await event(root, a0.agentId, "list_team", {}, { n: 6 }, m - 2.6);

  // Reasoning, in the shape the harness writes it: empty args, text in the
  // result, `chars` giving the full length when only the opening was kept.
  // Two agents think, four never do — the fixture carries the same asymmetry
  // the real runs have, so the THINKING panel and its empty state both have
  // something to render.
  await event(
    root,
    a0.agentId,
    "thinking",
    {},
    { text: "The access log is the only thing every other artefact hangs off. I will read it first and post the window before anyone claims a file.", chars: 133 },
    m - 2.7,
  );
  await event(
    root,
    a0.agentId,
    "thinking",
    {},
    { text: `${"The upload endpoint is the obvious hop, but I want the timestamps before I say so. ".repeat(2)}…`, chars: 640 },
    m - 2.8,
  );
  await event(
    root,
    a1.agentId,
    "thinking",
    {},
    { text: "Two shells, one path. I should claim the diagram before I draw the second hop.", chars: 77 },
    m - 2.9,
  );

  const svg = join(root, "work", "attack-path.svg");
  await claimFile(a1, "work/attack-path.svg", { reason: "fixture: drawing the attack path" });
  await event(root, a1.agentId, "claim_file", { path: "work/attack-path.svg" }, { ok: true, owner: a1.agentId }, m - 3);
  await writeFile(svg, ATTACK_PATH_SVG.replace(/<rect x="336"[\s\S]*?persistence<\/text>/, ""), "utf8");
  await recordFileVersion(root, "work/attack-path.svg", a1.agentId);
  await event(root, a1.agentId, "write", { path: "work/attack-path.svg" }, { ok: true, rev: 1 }, m - 3, 20);
  const hold = await postMessage(a1, { tag: "claim", body: "Claimed work/attack-path.svg to add the web shell hop. Release in ~2 min." });
  await backdate(hold.path, m - 3.5);
  await releaseFile(a1, "work/attack-path.svg");
  await event(root, a1.agentId, "release_file", { path: "work/attack-path.svg" }, { ok: true }, m - 4);

  // Doubter writes without a claim: Layer B blocks and logs claim_violation.
  await event(
    root,
    a2.agentId,
    "claim_violation",
    { tool: "write", path: "work/attack-path.svg" },
    { blocked: true, reason: "claim violation: work/attack-path.svg (no lock)" },
    m - 4.5,
  );
  const veto = await postMessage(a5, { tag: "veto", to: a2.agentId, body: "Doubter, you wrote without a claim. Claim first, then write. The guard blocked it." });
  await backdate(veto.path, m - 4.6);
  await event(root, a5.agentId, "post", { tag: "veto", thread: "main" }, { ok: true, id: veto.id }, m - 4.6);

  await claimFile(a0, "work/attack-path.svg", { reason: "fixture: drawing the attack path" });
  await event(root, a0.agentId, "claim_file", { path: "work/attack-path.svg" }, { ok: true, owner: a0.agentId }, m - 5);
  await writeFile(svg, ATTACK_PATH_SVG, "utf8");
  await recordFileVersion(root, "work/attack-path.svg", a0.agentId);
  await event(root, a0.agentId, "edit", { path: "work/attack-path.svg" }, { ok: true, rev: 2 }, m - 5, 30);
  await event(root, a0.agentId, "file_history", { path: "work/attack-path.svg" }, { revisions: 2 }, m - 5, 40);
  const result = await postMessage(a0, { tag: "result", body: "First request is 203.0.113.24 at 02:57:12 UTC, u_ex260211.log line 4418. Stitch: the shell upload is 40 seconds later; put it on the path." });
  await backdate(result.path, m - 6);

  // Legs agent claimed a file ~20 minutes ago and went silent.
  await claimFile(a4, "work/prefetch.csv", { reason: "fixture: parsing Prefetch" });
  await event(root, a4.agentId, "claim_file", { path: "work/prefetch.csv" }, { ok: true }, m - 1.9);

  // Everyone else is fresh, so the harness reaper only touches the silent one.
  await event(
    root,
    a0.agentId,
    "inbox",
    {},
    inboxLogResult({
      swarm_done: false,
      seen: 8,
      posts: [
        { id: 6, from: a5.agentId },
        { id: 7, from: a1.agentId },
        { id: 8, from: a0.agentId },
      ],
    }),
    0.6,
  );
  await event(
    root,
    a1.agentId,
    "inbox",
    {},
    inboxLogResult({
      swarm_done: false,
      seen: 7,
      posts: [
        { id: 6, from: a5.agentId },
        { id: 7, from: a1.agentId },
      ],
    }),
    0.5,
  );
  await claimFile(a2, "work/registry-notes.md", { reason: "fixture: writing up the Run keys" });
  await event(root, a2.agentId, "claim_file", { path: "work/registry-notes.md" }, { ok: true }, 0.4);
  await event(root, a3.agentId, "budget", {}, { remaining_usd: 1.72, over_budget: false }, 0.3);
  await event(root, a5.agentId, "read", { path: "work/attack-path.svg" }, { bytes: ATTACK_PATH_SVG.length }, 0.2);
  await event(root, a5.agentId, "bash", { command: "test -f work/attack-path.svg && echo ok" }, { exit: 0 }, 0.1);
  await reapStalledAgents(root, { stallMs: 60_000 });
  const fresh = await postMessage(a1, { tag: "ask", body: "Scout, is the first-request time confirmed against the log? I want to hand the timeline to Referee." });
  await backdate(fresh.path, 0.3);
  await event(root, a1.agentId, "post", { tag: "ask", thread: "main" }, { ok: true, id: fresh.id }, 0.3);

  // A side thread nobody joined: it goes dark.
  const side = await postMessage(a3, { thread: "prefetch", tag: "ask", body: "Anyone want to pair on the Prefetch run counts?" });
  await backdate(side.path, m - 8);
  const ops = await postMessage(a5, { thread: "review", tag: "hold", body: "HOLD: no one calls done until every ledger event cites the artefact it came from." });
  await backdate(ops.path, 1);

  await applySessionUsage(root, a0.agentId, usage(0.41, 812_400, 61));
  await applySessionUsage(root, a1.agentId, usage(0.37, 640_100, 48));
  await applySessionUsage(root, a2.agentId, usage(0.22, 420_900, 33));
  await applySessionUsage(root, a3.agentId, usage(0.19, 388_000, 29));
  await applySessionUsage(root, a4.agentId, usage(0.06, 91_200, 7));
  await applySessionUsage(root, a5.agentId, usage(0.08, 130_500, 12));
  await writeFile(join(root, "work", "notes.md"), "# Notes\n\n## Proven\n\n- First request from 203.0.113.24 at 02:57:12 UTC, u_ex260211.log line 4418.\n- `upload.aspx` written at 02:57:52 UTC, inode 33194-128-4.\n\n## Not proven\n\n- Whether the same actor created the scheduled task. The times are consistent with one\n  actor and do not establish one.\n", "utf8");
  // The operator handed this swarm two read-only inputs; a1's shell tried to
  // write one and the harness healed it; the scout vouched for them at done.
  await seedInputs(root, {
    "brief.md": "# Brief\n\nIIS web server, suspected compromise 2026-02-11. Establish entry, persistence and scope.\n",
    "logs/u_ex260211.log": "#Fields: date time c-ip cs-uri-stem sc-status\n2026-02-11 02:57:12 203.0.113.24 /upload.aspx 200\n2026-02-11 02:57:52 203.0.113.24 /upload.aspx 200\n",
  }, "seatbelt");
  // Scout forged a tool the critic then used; one call failed on a bad path.
  const forged = await forgeTool(createContext(root, a0.agentId), {
    name: "timeline_stats",
    description: "Count rows per executable in a timeline CSV and report the first and last timestamp",
    runtime: "python3",
    script: "import csv, json, sys\nargs = json.load(sys.stdin)\nrows = list(csv.DictReader(open(args['path'], encoding='utf-8')))\nkey = args.get('column', 'executable')\nby = {}\nfor r in rows:\n    by[r.get(key, '')] = by.get(r.get(key, ''), 0) + 1\nstamps = sorted(r.get('ts', '') for r in rows if r.get('ts'))\nprint(json.dumps({'rows': len(rows), 'by_' + key: by, 'first': stamps[0] if stamps else None, 'last': stamps[-1] if stamps else None}))\n",
    params: {
      path: { type: "string", required: true, description: "sandbox-relative path to the CSV" },
      column: { type: "string", required: false, description: "which column to count by; default executable" },
    },
    example: 'timeline_stats(path="work/prefetch.csv")',
  });
  if (!forged.ok) throw new Error(forged.reason);
  await event(root, a0.agentId, "make_tool", { name: "timeline_stats", runtime: "python3", params: "path,column" }, { ok: true, forged: true, created: true, version: 1, sha256: forged.manifest.sha256.slice(0, 8), duration_ms: 12 }, 0.5);
  await event(root, a5.agentId, "tool_loaded", { name: "timeline_stats", version: 1, by: a0.agentId }, { ok: true, forged: true }, 0.45);
  await event(root, a5.agentId, "timeline_stats", { path: "work/prefetch.csv" }, { ok: true, forged: true, by: a0.agentId, version: 1, exit_code: 0, timed_out: false, truncated: false, bytes: 38, duration_ms: 41 }, 0.4);
  await event(root, a5.agentId, "timeline_stats", { path: "work/missing.csv" }, { ok: false, forged: true, by: a0.agentId, version: 1, exit_code: 1, timed_out: false, truncated: false, bytes: 0, error: "FileNotFoundError: work/missing.csv", duration_ms: 39 }, 0.3);
  await event(root, a1.agentId, "timeline_stats", { path: "work/prefetch.csv" }, { ok: true, forged: true, by: a0.agentId, version: 1, exit_code: 0, timed_out: false, truncated: false, bytes: 38, duration_ms: 37 }, 0.05);
  await event(root, a0.agentId, "inputs_guard", { files: 2 }, { ok: true, mode: "seatbelt", enforced: "kernel", guard: "seatbelt", enforce: "auto" }, 0.045);
  await event(root, a5.agentId, "inputs_guard", { files: 2 }, { ok: true, mode: "none", enforced: "none", guard: "seatbelt", enforce: "auto" }, 0.04);
  await event(root, a1.agentId, "inputs_violation", { tool: "write", path: "inputs/brief.md" }, { blocked: true, detected: false, via: "write", reason: "read-only input: inputs/brief.md" }, 0.035);
  await event(root, a1.agentId, "inputs_violation", { tool: "bash", path: "inputs/data/readings.csv" }, { blocked: false, detected: true, via: "bash", healed: "restored" }, 0.03);
  await event(root, a0.agentId, "inputs_check", {}, { ok: true, checked: 2, modified: [], missing: [], added: [] }, 0.02);
  // The ledger: two dated events (one recorded by two agents), an indicator and a finding.
  for (const [ctx, entry] of [
    [a0, { kind: "event", ts: "2026-02-11T02:57:12Z", value: "First request from 203.0.113.24 reaches /upload.aspx", source: "inputs/logs/u_ex260211.log", evidence: "line 4418, sc-status 200" }],
    [a1, { kind: "event", ts: "2026-02-11T02:57:12Z", value: "First request from 203.0.113.24 reaches /upload.aspx", source: "inputs/logs/u_ex260211.log", evidence: "line 4418, sc-status 200" }],
    [a5, { kind: "event", ts: "2026-02-11T02:57:52Z", value: "upload.aspx written to the web root", source: "work/attack-path.svg", evidence: "inode 33194-128-4, MFT $SI created" }],
    [a0, { kind: "ioc", value: "203.0.113.24", source: "inputs/logs/u_ex260211.log", evidence: "40 requests between 02:57 and 03:11", confidence: "high" }],
    [a5, { kind: "finding", value: "Entry was an unauthenticated upload to /upload.aspx, not a stolen credential", source: "work/notes.md", evidence: "no 4624 before 02:57:12 in Security.evtx; the upload precedes every logon", confidence: "medium" }],
  ] as const) {
    const r = await recordEntry(ctx, entry);
    if (!r.ok) throw new Error(r.reason);
  }
  await mkdir(join(root, "work", ".browser"), { recursive: true });
  await writeFile(join(root, "work", ".browser", "evtx-chart.png"), PNG_1X1);
  // A hive pulled out of the image: hashed in the artifact index, never
  // packaged, because it came out of the evidence.
  await mkdir(join(root, "work", "extracted"), { recursive: true });
  await writeFile(join(root, "work", "extracted", "SOFTWARE"), "regf\u0000\u0000\u0000stub hive bytes for the fixture\n", "utf8");
  await writeFile(join(root, "work", "prefetch.csv"), PREFETCH_CSV, "utf8");
  await writeFile(
    join(root, "layout.json"),
    `${JSON.stringify({ n: 6, tabs: 1, extra_workspaces: 0, split_failures: 0, panes_per_tab_cap: 30, panes: ["w7:p1", "w7:p2", "w7:p3", "w7:p4", "w7:p5", "w7:p6"] }, null, 2)}\n`,
    "utf8",
  );
}

async function seedUsbPolicy(root: string, spec: RunSpec): Promise<void> {
  const [a0, a1] = ids(spec).map((id) => createContext(root, id));
  const m = spec.started_min_ago;
  await event(root, a0.agentId, "agent_start", {}, { ok: true }, m);
  await event(root, a1.agentId, "agent_start", {}, { ok: true }, m, 1);
  const p0 = await postMessage(a0, { tag: "intro", body: `${a0.agentId} here. I take USBSTOR and write the first block.` });
  await backdate(p0.path, m - 1);
  const p1 = await postMessage(a1, { tag: "intro", body: `${a1.agentId} here. I take MountedDevices and append after you.` });
  await backdate(p1.path, m - 1.2);
  const listing = join(root, "work", "usb-devices.txt");
  await claimFile(a0, "work/usb-devices.txt", { reason: "fixture: listing USB devices" });
  await event(root, a0.agentId, "claim_file", { path: "work/usb-devices.txt" }, { ok: true }, m - 2);
  await writeFile(listing, USB_FIRST, "utf8");
  await recordFileVersion(root, "work/usb-devices.txt", a0.agentId);
  await event(root, a0.agentId, "write", { path: "work/usb-devices.txt" }, { ok: true, rev: 1 }, m - 2, 10);
  await releaseFile(a0, "work/usb-devices.txt");
  await event(root, a0.agentId, "release_file", { path: "work/usb-devices.txt" }, { ok: true }, m - 2, 15);
  await claimFile(a1, "work/usb-devices.txt", { reason: "fixture: listing USB devices" });
  await event(root, a1.agentId, "claim_file", { path: "work/usb-devices.txt" }, { ok: true }, m - 3);
  await writeFile(listing, `${USB_FIRST}${USB_SECOND}`, "utf8");
  await recordFileVersion(root, "work/usb-devices.txt", a1.agentId);
  await event(root, a1.agentId, "write", { path: "work/usb-devices.txt" }, { ok: true, rev: 2 }, m - 3, 10);
  await releaseFile(a1, "work/usb-devices.txt");
  await event(root, a1.agentId, "release_file", { path: "work/usb-devices.txt" }, { ok: true }, m - 3, 15);
  const r = await postMessage(a1, { tag: "result", body: "usb-devices.txt has both devices with first and last connection. Calling done." });
  await backdate(r.path, m - 4);
  await applySessionUsage(root, a0.agentId, usage(0.0412, 61_300, 9));
  await applySessionUsage(root, a1.agentId, usage(0.0388, 57_900, 8));
  await markDone(a1, { reason: "DoD checks passed", outputFile: "work/usb-devices.txt" });
  await event(root, a1.agentId, "done", { reason: "DoD checks passed", output_file: "work/usb-devices.txt" }, { created_sentinel: true }, m - 4.5);
  await event(root, a1.agentId, "agent_stop", {}, { ok: true }, m - 4.5, 2);
  await markDone(a0, { reason: "done/SWARM_DONE exists", outputFile: "work/usb-devices.txt" });
  await event(root, a0.agentId, "done", { reason: "done/SWARM_DONE exists", output_file: "work/usb-devices.txt" }, { created_sentinel: false }, m - 4.6);
  await event(root, a0.agentId, "agent_stop", {}, { ok: true }, m - 4.6, 2);
  await backdate(join(root, "done", "SWARM_DONE"), m - 4.6);
}

async function seedRansomware(root: string, spec: RunSpec): Promise<void> {
  const agents = ids(spec).map((id) => createContext(root, id));
  const m = spec.started_min_ago;
  let sec = 0;
  for (const [i, ctx] of agents.entries()) {
    await event(root, ctx.agentId, "agent_start", {}, { ok: true }, m, sec++);
    const p = await postMessage(ctx, { tag: "intro", body: `I'm ${CALLSIGNS[i]}. Taking slice ${i + 1} of the triage.` });
    await backdate(p.path, m - 0.5 - i * 0.1);
    await event(root, ctx.agentId, "post", { tag: "intro", thread: "main" }, { ok: true, id: p.id }, m - 0.5 - i * 0.1);
  }
  await claimFile(agents[0], "work/report.html", { reason: "fixture: land the triage report" });
  await event(root, agents[0].agentId, "claim_file", { path: "work/report.html" }, { ok: true }, m - 2);
  await writeFile(join(root, "work", "report.html"), TRIAGE_REPORT_HTML, "utf8");
  await recordFileVersion(root, "work/report.html", agents[0].agentId);
  await event(root, agents[0].agentId, "write", { path: "work/report.html" }, { ok: true, rev: 1 }, m - 2, 20);
  await event(root, agents[0].agentId, "playwright", { url: "work/report.html", screenshot: `work/${agents[0].agentId}/.browser/report.png` }, { ok: true, title: "Ransomware triage" }, m - 1.5);
  await mkdir(join(root, "work", agents[0].agentId, ".browser"), { recursive: true });
  await writeFile(join(root, "work", agents[0].agentId, ".browser", "report.png"), PNG_1X1);
  await claimFile(agents[3], "work/summary.md", { reason: "fixture: one line per agent" });
  await event(root, agents[3].agentId, "claim_file", { path: "work/summary.md" }, { ok: true }, 0.4);
  await writeFile(join(root, "work", "summary.md"), agents.slice(0, 4).map((a, i) => `${a.agentId} slice ${i + 1} done`).join("\n") + "\n", "utf8");
  await recordFileVersion(root, "work/summary.md", agents[3].agentId);
  await event(root, agents[3].agentId, "write", { path: "work/summary.md" }, { ok: true, rev: 1 }, 0.3);
  for (const [i, ctx] of agents.entries()) {
    await applySessionUsage(root, ctx.agentId, usage(0.11 + i * 0.013, 180_000 + i * 21_000, 14 + i));
    if (i > 0) {
      await event(
        root,
        ctx.agentId,
        "inbox",
        {},
        inboxLogResult({
          swarm_done: false,
          seen: 1,
          posts: [{ id: 1, from: agents[0].agentId }],
        }),
        0.2,
        i,
      );
    }
  }
}

async function seedSingleHive(root: string, spec: RunSpec): Promise<void> {
  const [a0] = ids(spec).map((id) => createContext(root, id));
  const m = spec.started_min_ago;
  await event(root, a0.agentId, "agent_start", {}, { ok: true }, m);
  await event(root, a0.agentId, "inbox", {}, inboxLogResult({ swarm_done: false, seen: 0, posts: [] }), m, 4);
  const p = await postMessage(a0, { tag: "intro", body: "Single agent. Taking the SOFTWARE hive Run keys into work/triage.txt." });
  await backdate(p.path, m - 0.2);
  await event(root, a0.agentId, "post", { tag: "intro", thread: "main", body: p.body }, { ok: true, id: p.id }, m - 0.2);
  await claimFile(a0, "work/triage.txt", { reason: "fixture: listing the Run keys" });
  await event(root, a0.agentId, "claim_file", { path: "work/triage.txt" }, { ok: true, owner: a0.agentId }, m - 0.3);
  await writeFile(join(root, "work", "triage.txt"), RUN_KEYS, "utf8");
  await recordFileVersion(root, "work/usb-devices.txt", a0.agentId);
  await event(root, a0.agentId, "write", { path: "work/usb-devices.txt" }, { ok: true, rev: 1 }, m - 0.4);
  await releaseFile(a0, "work/usb-devices.txt");
  await event(root, a0.agentId, "release_file", { path: "work/usb-devices.txt" }, { ok: true }, m - 0.5);
  await applySessionUsage(root, a0.agentId, usage(0.0071, 9_800, 4));
  await markDone(a0, { reason: "DoD checks passed", outputFile: "work/triage.txt" });
  await event(root, a0.agentId, "done", { reason: "DoD checks passed", output_file: "work/triage.txt" }, { created_sentinel: true }, m - 0.6);
  await event(root, a0.agentId, "agent_stop", {}, { ok: true }, m - 0.6, 1);
  await backdate(join(root, "done", "SWARM_DONE"), m - 0.6);
}

async function seedStopped(root: string, spec: RunSpec): Promise<void> {
  const [a0, a1, a2] = ids(spec).map((id) => createContext(root, id));
  const m = spec.started_min_ago;
  for (const ctx of [a0, a1, a2]) await event(root, ctx.agentId, "agent_start", {}, { ok: true }, m);
  const p = await postMessage(a0, { tag: "intro", body: "Starting on the PE header scan over unallocated." });
  await backdate(p.path, m - 1);
  await claimFile(a0, "work/carve.py", { reason: "fixture: writing the carver" });
  await writeFile(join(root, "work", "carve.py"), CARVE_PY, "utf8");
  await recordFileVersion(root, "work/carve.py", a0.agentId);
  await event(root, a0.agentId, "write", { path: "work/carve.py" }, { ok: true, rev: 1 }, m - 2);
  await releaseFile(a0, "work/carve.py");
  await applySessionUsage(root, a0.agentId, usage(0.31, 402_000, 40));
  await applySessionUsage(root, a1.agentId, usage(0.44, 610_000, 52));
  await applySessionUsage(root, a2.agentId, usage(0.27, 350_000, 31));
  await event(root, a1.agentId, "budget", {}, { remaining_usd: -0.02, over_budget: true }, m - 30);
  const stop = await postMessage(a1, { tag: "stop", body: "Cap hit mid-scan. Operator stopped the swarm from the CLI; unallocated is only 38% covered." });
  await backdate(stop.path, m - 31);
}

/**
 * A microVM run the hub finished, as its files would read: three VMs, one of
 * which the hub refused a peer's directory and stopped at its own cap, one
 * whose finish found msb's database busy; every VM put away with its disk
 * kept; custody taken; a correction and a search that found nothing in the
 * ledger; a post from a seat's own harness code (`via`); the operator's
 * record and one examiner decision.
 */
async function seedMicroVm(root: string, spec: RunSpec, runsDir: string): Promise<void> {
  const [a0, a1, a2] = ids(spec).map((id) => createContext(root, id));
  const m = spec.started_min_ago;
  await seedInputs(root, { "web/access.log": "10.0.0.5 - - [03/Feb/2026:09:12:41 +0000] \"GET /shell.php HTTP/1.1\" 200\n", "web/shell.php": "<?php system($_GET['c']); ?>\n" }, "microvm");
  const manifestPath = join(root, "inputs.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as Record<string, unknown>;
  manifest.held = "copy";
  manifest.source_checked = { by: "content", files: 2, mismatches: [], seconds: 0.1 };
  for (const f of manifest.files as Array<Record<string, unknown>>) {
    const text = f.path === "inputs/web/access.log" ? "10.0.0.5 - - [03/Feb/2026:09:12:41 +0000] \"GET /shell.php HTTP/1.1\" 200\n" : "<?php system($_GET['c']); ?>\n";
    f.md5 = createHash("md5").update(text).digest("hex");
    f.sha1 = createHash("sha1").update(text).digest("hex");
  }
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  for (const ctx of [a0, a1, a2]) await event(root, ctx.agentId, "agent_start", {}, { ok: true }, m);
  for (const ctx of [a0, a1, a2]) await event(root, "system", "hub_link", { agent: ctx.agentId }, { up: true }, m - 0.5);
  const intro = await postMessage(a0, { tag: "intro", body: "Taking the access log and the web root, in my VM." });
  await backdate(intro.path, m - 1);
  const via = await postMessage(systemContext(root), { tag: "result", body: "Harness code in this seat's VM: the shell write under work/ was refused; publish through the hub.", via: a1.agentId });
  await backdate(via.path, m - 5);
  await event(root, "system", "hub_call", { agent: a1.agentId, fn: "claimFile" }, { ok: false, error: `work/${a0.agentId}/notes.md is in ${a0.agentId}'s own directory` }, m - 6);
  await event(root, "system", "hub_call", { agent: a1.agentId, fn: "claimFile" }, { ok: false, error: `work/${a0.agentId}/notes.md is in ${a0.agentId}'s own directory`, repeated: 3 }, m - 5);
  // As hub-supervise.sh writes them: the system's lines, the restart numbered.
  await event(root, "system", "hub_restarted", { dir: `/hubs/dfs-${spec.id}.fixture`, by: "hub-supervise", restart: 1 }, { ok: true }, m - 40);
  await event(root, "system", "collector_restarted", { by: "hub-supervise", restart: 1 }, { ok: true }, m - 42);
  // One seat's link dropped while the hub was down, and came back.
  await event(root, "system", "hub_link", { agent: a1.agentId }, { up: false }, m - 39.5);
  await event(root, "system", "hub_link", { agent: a1.agentId }, { up: true }, m - 41);
  await event(root, "system", "agent_cap_stop", { agent: a2.agentId }, { ok: true }, m - 60);
  await event(root, "system", "publish_file", { agent: a0.agentId }, { ok: true }, m - 70);
  await event(root, a0.agentId, "publish_file", { path: `work/${a0.agentId}/report.md`, to: "work/report.md" }, { ok: true }, m - 71);
  await mkdir(join(root, "work"), { recursive: true });
  await writeFile(join(root, "work", "report.md"), "# Web server\n\nA web shell (inputs/web/shell.php) was requested at 2026-02-03T09:12:41Z.\n", "utf8");
  const e1 = await recordEntry(a0, { kind: "event", ts: "2026-02-03T09:12:41Z", value: "GET /shell.php answered 200", source: "inputs/web/access.log", evidence: "line 1" });
  const f1 = await recordEntry(a1, { kind: "finding", value: "The web shell was uploaded through the admin panel", source: "inputs/web/access.log", evidence: "line 1", confidence: "low" });
  await recordEntry(a1, { kind: "finding", value: "The web shell was requested once; how it arrived is not in the log", source: "inputs/web/access.log", evidence: "line 1; no POST to the admin panel", confidence: "medium", supersedes: (f1 as { entry: { seq: number } }).entry.seq } as Parameters<typeof recordEntry>[1]);
  await recordEntry(a2, { kind: "absence", value: "a POST to /admin/upload", source: "inputs/web/access.log", evidence: "grep -c 'POST /admin' (GNU grep 3.11) · the whole log, allocated file only" } as Parameters<typeof recordEntry>[1]);
  void e1;
  await applySessionUsage(root, a0.agentId, usage(0.41, 520_000, 44));
  await applySessionUsage(root, a1.agentId, usage(0.38, 470_000, 39));
  await applySessionUsage(root, a2.agentId, usage(0.66, 800_000, 61));
  for (const ctx of [a0, a1, a2]) await markDone(ctx, { reason: "complete", outputFile: "work/report.md" }).catch(() => undefined);
  for (const [i, ctx] of [a0, a1, a2].entries()) await event(root, ctx.agentId, "agent_stop", { reason: "done" }, { ok: true }, 14 - i);
  await event(root, "system", "vm_finish", { via: "hub", all_out: true }, { ok: true, msb_db: [{ agent: a0.agentId, name: `dfs-${spec.id}-${a0.agentId}`, msb_db: "scrubbed" }, { agent: a2.agentId, name: `dfs-${spec.id}-${a2.agentId}`, msb_db: "busy" }] }, 10);
  await event(root, "system", "custody", { via: "hub" }, { ok: true }, 9);
  await event(root, "operator", "artifact_scripts", { path: "work/report.md", sha256: "0".repeat(64), via: "web", os_user: "examiner" }, { ok: true, opened_with_scripts: true }, 5);
  // Each VM's record, as vm.ts wrote it at kickoff and finish.
  await mkdir(join(root, "vm"), { recursive: true });
  const probe = (inputsFiles: number) => ({
    hub: true, base: "ro", work: "ro", scratch: "rw", extracted: "rw", extracted_exec: "noexec", quarantine_exec: "noexec",
    peers_extracted_exec: "noexec", peers_quarantine_exec: "noexec", tool_output: "rw", session: "rw", inputs: "ro", inputs_exec: "noexec",
    inputs_files: inputsFiles, pi: "0.87.0", clock_skew_s: 0, reach: [{ target: "api.openai.com:443", ok: true }], missing_binaries: [],
  });
  const vms = [a0.agentId, a1.agentId, a2.agentId];
  for (const [i, agent] of vms.entries()) {
    const rec = {
      agent, name: `dfs-${spec.id}-${agent}`, run: spec.id, runtime: { name: "microsandbox", version: "0.7.2" },
      image: { ref: "dfirswarm-base:dev-arm64", manifest_digest: "sha256:6b1f0c2e9a", expected_digest: "sha256:6b1f0c2e9a" },
      cpus: 2, memory_mib: 2048, max_duration_sec: 1500,
      mounts: [{ host: join(root), guest: "/run/sandbox", mode: "ro" }, { host: join(root, "work", agent), guest: join("/run/sandbox/work", agent), mode: "rw" }, { host: join(root, "work", "extracted", agent), guest: join("/run/sandbox/work/extracted", agent), mode: "rw", noexec: true }],
      network: { default: "deny", allow_hosts: ["api.openai.com"], host_ports: [] },
      secrets: [{ name: "OPENAI_API_KEY", hosts: ["api.openai.com"] }],
      probe: probe(2), created_at: iso(m), stopped_at: iso(11),
      snapshot: { path: `${root}.vm-snapshots/${agent}.qcow2`, sha256: createHash("sha256").update(agent).digest("hex"), bytes: 734_003_200 + i, integrity: true },
      logs: `${root}.vm-snapshots/${agent}.logs`,
      msb_db: i === 2 ? "busy" : "scrubbed",
    };
    await writeFile(join(root, "vm", `${agent}.json`), `${JSON.stringify(rec, null, 2)}\n`, "utf8");
  }
  const jobs = await seedJobStore(root, [a0.agentId, a1.agentId, a2.agentId], m);
  // The host's custody verdict, as custody.ts writes it.
  const custody = {
    at: iso(9), summary: `evidence unchanged (2 files re-hashed); trace chain intact; ledger chain intact; 3 VMs put away · ${jobs.line}`,
    store: jobs.check,
    inputs: { files: 2, bytes: 90, unchanged: true, complete: true, changed: [], missing: [], added: [], skipped: [], unreadable: [], checked: { files: 2, links: 0, special: 0 }, digests_compared: { sha256: 2, md5: 2, sha1: 2 }, manifest_sha256: "a".repeat(64), manifest_anchored: true },
    sessions: { files: [], digest: "b".repeat(64), not_files: [] },
    trace: { lines: 40, intact: true, detail: "", unverified: 0, disputed: 0, spilled: [], gaps: [] },
    ledger: { entries: 4, chained: 4, intact: true, detail: "", missing_from_ledger: [], not_on_trace: [] },
    tool_outputs: { referenced: 0, verified: 0, missing: [], mismatched: [], refused: [] },
    artifacts: { files: 1, bytes: 90, skipped: 0, index_sha256: "c".repeat(64) },
    vms: vms.map((agent, i) => ({ agent, record_sha256: createHash("sha256").update(`rec-${agent}`).digest("hex"), stopped: true, snapshot: { verified: true, msb_verified: true }, image: "sha256:6b1f0c2e9a", expected_image: "sha256:6b1f0c2e9a", msb_db: i === 2 ? "busy" : "scrubbed", secret_violations: [], installed_outside: {} })),
  };
  await writeFile(join(root, "custody.json"), `${JSON.stringify(custody, null, 2)}\n`, "utf8");
  // An examiner's note, after the run and after custody read the journal
  // (evidence-store.ts note): the journal is one line longer than custody saw.
  await jobs.journal.append({ type: "note", at: iso(4), by: "H. Examiner", text: "j000002 failed on the log's quoting, not on the evidence: j000001 read the same lines. Its partial timeline is not relied on.", jobs: ["j000002"] });
  // The operator's record for this run, chained as swarm.sh writes it.
  const auditFile = join(runsDir, "operator-audit.jsonl");
  const prevText = await readFile(auditFile, "utf8").then((t) => t.trimEnd().split("\n").filter(Boolean).at(-1) ?? null).catch(() => null);
  let prev = prevText === null ? null : createHash("sha256").update(prevText).digest("hex");
  const lines: string[] = [];
  for (const [cmd, argv, via, at] of [
    ["start", ["--isolation", "microvm", "--label", spec.label, spec.id], "console", iso(m)],
    ["stop", [spec.id, "--after-hub"], "hub", iso(9)],
  ] as Array<[string, string[], string, string]>) {
    const line = JSON.stringify({ at, command: cmd, argv, cwd: ROOT, os_user: "examiner", host: "fixture-host", via, prev });
    lines.push(line);
    prev = createHash("sha256").update(line).digest("hex");
  }
  await writeFile(auditFile, `${lines.join("\n")}\n`, { flag: "a" });
  // One examiner decision, in the review file outside the run.
  await mkdir(join(runsDir, "reviews"), { recursive: true });
  const review = JSON.stringify({ v: 1, seq: 1, at: iso(3), examiner: "H. Examiner", os_user: "examiner", host: "fixture-host", action: "accept", entry_seq: (e1 as { entry: { seq: number } }).entry.seq, entry_hash: null, note: null, prev: null });
  await writeFile(join(runsDir, "reviews", `${spec.id}.jsonl`), `${review}\n`, "utf8");
}

/**
 * A microVM run's job service, as it leaves the store: the journal, chained
 * and anchored, with a command job that ran and was sealed (one link left
 * out), a tool job that failed and was sealed all the same, and one
 * cancelled before it started; each job's job.json, manifest and logs.
 * Written with the store's own Journal and sealTree, so every shape is the
 * service's. Returns custody's check of it and the line custody writes.
 */
async function seedJobStore(root: string, agents: string[], m: number): Promise<{ journal: Journal; check: StoreCheck | null; line: string }> {
  const P = storePaths(root);
  await mkdir(P.jobs, { recursive: true });
  const journal = await Journal.open(root);
  const [a0, a1, a2] = agents;
  const requester = (agent: string, name: string, doing: string) => ({ agent, name, doing });
  const accessible = [
    { path: join(root, "inputs"), access: "read-only, no-exec" },
    { path: join(root, "work"), access: "read-only; every agent's live scratch and the shared files: they may change while the job runs" },
  ];
  await journal.append({ type: "store_opened", at: iso(m), inputs_sha256: null, census_sha256: null, plan_sha256: null });
  await journal.append({ type: "revision_published", at: iso(m), revision: 0, generations: 0, manifest_sha256: "0".repeat(64) });

  // Each job's staging directory, sealed into the store as the service seals a fenced worker's.
  const seal = async (job: string, sealedAt: string, files: Record<string, string>, logs: Record<string, string>, links: Record<string, string> = {}) => {
    const staging = join(root, ".seed-staging", `${job}-1`);
    await mkdir(staging, { recursive: true });
    for (const [rel, text] of Object.entries(files)) {
      await mkdir(dirname(join(staging, rel)), { recursive: true });
      await writeFile(join(staging, rel), text, "utf8");
    }
    for (const [rel, to] of Object.entries(links)) await symlink(to, join(staging, rel));
    const sealed = await sealTree(root, staging, join(P.jobs, job, "out"), job, 1);
    await rm(join(root, ".seed-staging"), { recursive: true, force: true });
    // Sealed when the fixture's clock says, not when the seeding ran.
    const manifestPath = join(P.jobs, job, "manifest.json");
    const text = `${JSON.stringify({ ...sealed.manifest, sealed_at: sealedAt })}\n`;
    await chmod(manifestPath, 0o644);
    await writeFile(manifestPath, text, "utf8");
    await chmod(manifestPath, 0o444);
    sealed.manifestSha256 = createHash("sha256").update(text).digest("hex");
    const shas: Record<string, string> = {};
    for (const [name, text] of Object.entries(logs)) {
      await writeFile(join(P.jobs, job, name), text, { encoding: "utf8", mode: 0o444 });
      shas[name] = await sha256File(join(P.jobs, job, name));
    }
    return { outputs: { manifest_sha256: sealed.manifestSha256, files: sealed.manifest.totals.files, bytes: sealed.manifest.totals.bytes, rejected: sealed.manifest.rejected.length, path: `store/jobs/${job}/out` }, logs: shas };
  };
  const project = async (record: Record<string, unknown>) => {
    await mkdir(join(P.jobs, String(record.id)), { recursive: true });
    await writeFile(join(P.jobs, String(record.id), "job.json"), `${JSON.stringify(record, null, 2)}\n`, { encoding: "utf8", mode: 0o444 });
  };

  // j000001: a command over the access log, run and sealed.
  const command = "grep -n 'shell.php' inputs/web/access.log > \"$OUT/hits.tsv\"\nawk '{print $1}' inputs/web/access.log | sort | uniq -c > \"$OUT/clients.txt\"\nln -s /etc/passwd \"$OUT/passwd\"\ncat \"$OUT/hits.tsv\"";
  const spec1 = { kind: "command", command, inputs: ["input:web/access.log"], timeout_seconds: 900, network: "off" };
  const who1 = requester(a0, "Scout", "the access log");
  await journal.append({ type: "job_accepted", at: iso(m - 20), job: "j000001", spec: spec1, requester: who1 });
  await journal.append({ type: "job_started", at: iso(m - 20, 2), job: "j000001", attempt: 1, worker: `dfs-svm1d-job-j000001-1`, image: "dfirswarm-base:dev-arm64", declared: spec1.inputs, accessible, observed: "unknown", network: "none", cpus: 1, memory_mib: 1024 });
  const hits = "1:10.0.0.5 - - [03/Feb/2026:09:12:41 +0000] \"GET /shell.php HTTP/1.1\" 200\n";
  const one = await seal("j000001", iso(m - 21, 1), { "hits.tsv": hits, "clients.txt": "      1 10.0.0.5\n" }, { "stdout.log": hits, "stderr.log": "" }, { passwd: "/etc/passwd" });
  await journal.append({ type: "job_finished", at: iso(m - 21), job: "j000001", attempt: 1, exit: 0, status: "ok", duration_ms: 58_200, create_ms: 3_400 });
  await journal.append({ type: "job_fenced", at: iso(m - 21, 1), job: "j000001", attempt: 1, fenced: true });
  await journal.append({ type: "job_committed", at: iso(m - 21, 2), job: "j000001", attempt: 1, status: "ok", exit: 0, outputs: one.outputs, logs: one.logs });
  await journal.append({ type: "job_notified", at: iso(m - 21, 3), job: "j000001", to: a0, how: "status" });
  await project({ id: "j000001", attempt: 1, spec: spec1, requester: who1, state: "committed", status: "ok", accepted_at: iso(m - 20), started_at: iso(m - 20, 2), finished_at: iso(m - 21), exit: 0, worker: "dfs-svm1d-job-j000001-1", worker_size: "1 vCPU, 1024 MiB", image: "dfirswarm-base:dev-arm64", accessible, network: "none", outputs: one.outputs });

  // j000002: a tool that failed. Its output is sealed all the same: committed is where the output stands, not what the job did.
  // A forged tool's name held apart: `tool: "<name>"` is how the shell
  // watchdogs name their events, and reserved-names reads it so.
  const forged = "log_timeline";
  const spec2 = { kind: "tool", tool: forged, args: { path: "inputs/web/access.log", out: "{OUT}/timeline.csv" }, inputs: ["input:web/access.log"], timeout_seconds: 900, network: "off" };
  const who2 = requester(a1, "Stitch", "the timeline");
  await journal.append({ type: "job_accepted", at: iso(m - 24), job: "j000002", spec: spec2, requester: who2 });
  await journal.append({ type: "job_started", at: iso(m - 24, 2), job: "j000002", attempt: 1, worker: `dfs-svm1d-job-j000002-1`, image: "dfirswarm-base:dev-arm64", tool_sha256: "5".repeat(64), declared: spec2.inputs, accessible, observed: "unknown", network: "none", cpus: 1, memory_mib: 1024 });
  const stderr2 = "Traceback (most recent call last):\n  File \"tools/log_timeline/run.py\", line 41, in <module>\n    ts = parse(line)\nValueError: unexpected quoting at line 1: '\"GET /shell.php HTTP/1.1\"'\n";
  const two = await seal("j000002", iso(m - 24, 41), { "timeline.csv": "ts,event\n" }, { "stdout.log": "reading inputs/web/access.log\n", "stderr.log": stderr2 });
  await journal.append({ type: "job_finished", at: iso(m - 24, 40), job: "j000002", attempt: 1, exit: 2, status: "failed", reason: "exit 2", duration_ms: 38_600, create_ms: 2_900 });
  await journal.append({ type: "job_fenced", at: iso(m - 24, 41), job: "j000002", attempt: 1, fenced: true });
  await journal.append({ type: "job_committed", at: iso(m - 24, 42), job: "j000002", attempt: 1, status: "failed", exit: 2, reason: "exit 2", outputs: two.outputs, logs: two.logs });
  await journal.append({ type: "job_notified", at: iso(m - 24, 43), job: "j000002", to: a1, how: "post" });
  await project({ id: "j000002", attempt: 1, spec: spec2, requester: who2, state: "committed", status: "failed", reason: "exit 2", accepted_at: iso(m - 24), started_at: iso(m - 24, 2), finished_at: iso(m - 24, 40), exit: 2, worker: "dfs-svm1d-job-j000002-1", worker_size: "1 vCPU, 1024 MiB", image: "dfirswarm-base:dev-arm64", tool_sha256: "5".repeat(64), accessible, network: "none", outputs: two.outputs });

  // j000003: cancelled by its requester before a worker was free. It never ran.
  const spec3 = { kind: "command", command: "strings -n 8 inputs/web/shell.php", inputs: ["input:web/shell.php"], timeout_seconds: 900, network: "off" };
  const who3 = requester(a2, "Doubter", "checking the web root");
  await journal.append({ type: "job_accepted", at: iso(m - 30), job: "j000003", spec: spec3, requester: who3 });
  await journal.append({ type: "job_cancel_requested", at: iso(m - 30, 20), job: "j000003", by: a2 });
  await journal.append({ type: "job_cancelled", at: iso(m - 30, 20), job: "j000003", reason: `cancelled by ${a2} before it started` });
  await project({ id: "j000003", attempt: 1, spec: spec3, requester: who3, state: "cancelled", status: "cancelled", reason: `cancelled by ${a2} before it started`, accepted_at: iso(m - 30), cancel_requested: a2 });

  const check = await checkStore(root);
  const j = check?.journal;
  const line = check && j
    ? `store: ${check.jobs} jobs, ${check.committed} committed, journal ${j.lines} lines chain intact, its anchor matches, ${check.outputs.verified} of ${check.outputs.files} output files verified against their manifests, ${check.generations} catalogue generations, ${check.revisions} revision`
    : "store: not checked";
  return { journal, check, line };
}

/** Put write bits back on a tree seedInputs made read-only, so rm can clear it. */
async function restoreWriteBits(dir: string): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) {
      await chmod(abs, 0o755).catch(() => undefined);
      await restoreWriteBits(abs);
    } else if (entry.isFile()) {
      await chmod(abs, 0o644).catch(() => undefined);
    }
  }
}

export async function seedFixtureRuns(runsDir: string): Promise<string[]> {
  // seedInputs leaves inputs/ and .inputs-pristine/ read-only, exactly as a
  // real run does, and rm cannot remove a directory it may not write. Put the
  // bits back first so re-seeding the same directory works — `npm run
  // ui:fixture` runs against runs-fixture/ over and over.
  await restoreWriteBits(runsDir);
  await rm(runsDir, { recursive: true, force: true });
  await mkdir(runsDir, { recursive: true });
  const registry: Record<string, unknown>[] = [];
  const seeders: Record<string, (root: string, spec: RunSpec) => Promise<void>> = {
    s7a1c: seedWebServer,
    s3f09: seedUsbPolicy,
    sbe12: seedRansomware,
    s1e77: seedSingleHive,
    s0d4e: seedStopped,
    svm1d: (root, spec) => seedMicroVm(root, spec, runsDir),
  };
  for (const spec of RUNS) {
    const root = join(runsDir, spec.id);
    const agentIds = ids(spec);
    const roles = agentIds.map((_, i) => (spec.n >= 4 && spec.n < 10 && i === spec.n - 1 ? "critic" : "worker"));
    await initSandbox(root, {
      reset: true,
      swarmId: spec.id,
      agentIds,
      capUsd: spec.cap_usd,
      wallClockMinutes: spec.wall,
      goal: spec.goal,
      roles,
    });
    const startedAt = iso(spec.started_min_ago);
    const budgetPath = join(root, "budget.json");
    const budget = JSON.parse(await readFile(budgetPath, "utf8")) as Record<string, unknown>;
    budget.started_at = startedAt;
    await writeFile(budgetPath, `${JSON.stringify(budget, null, 2)}\n`, "utf8");
    // reap.sh reads the inbox cursor mtime as an activity signal; a fresh
    // fixture must not look alive just because it was seeded a moment ago.
    for (const id of agentIds) {
      await backdate(join(root, "inbox", id, CURSORS_REL), spec.started_min_ago);
    }
    await seeders[spec.id](root, spec);
    registry.push({
      id: spec.id,
      label: spec.label,
      workspace_id: spec.workspace_id,
      workspace_ids: [spec.workspace_id],
      sandbox: root,
      n: spec.n,
      model: spec.model,
      cap_usd: spec.cap_usd,
      wall_clock_minutes: spec.wall,
      hard_kill: false,
      tool_forging: false,
      self_compact: { enabled: true, notice_at: "40%", warn_at: "50%", compact_at: "60%", prompt: null },
      goal: spec.goal,
      agents: agentIds,
      started_at: startedAt,
      state: spec.state,
      inputs: spec.id === "s7a1c" ? { source: "/srv/evidence/webserver-2026-02", files: 2, bytes: 78, enforce: "auto", guard: "seatbelt" } : null,
      ...(spec.id === "svm1d"
        ? {
            isolation: { mode: "microvm", runtime: "microsandbox", image: "dfirswarm-base:dev-arm64", image_digest: "sha256:6b1f0c2e9a", cpus: 2, memory_mib: 2048, disk_mib: 8192, snapshot: true, oauth_allowed: false },
            netguard_mode: "microvm",
            provenance: { harness_commit: "0123456789abcdef0123456789abcdef01234567", harness_dirty: false, node_version: "v24.13.1", pi_version: "0.87.0", pi_on_path: null, msb_version: "0.7.2", image_digest: "sha256:6b1f0c2e9a", os: "Darwin 27.0.0", arch: "arm64" },
            host_clock: { tz: "Europe/Istanbul", abbreviation: "+03", utc_offset: "+0300", synced: null, source: null, run_processes_tz: "UTC" },
            custody_timeout_sec: 14400,
            idle_nudge_sec: 300,
            disk_encryption: "on",
            pack_secrets: {},
          }
        : {}),
    });
  }
  await writeFile(join(runsDir, "registry.json"), `${JSON.stringify({ runs: registry }, null, 2)}\n`, "utf8");
  return RUNS.map((r) => r.id);
}

const isMain = Boolean(process.argv[1]) && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  const target = process.argv[2] ? resolve(process.argv[2]) : join(ROOT, "runs-fixture");
  const seeded = await seedFixtureRuns(target);
  console.log(`Seeded ${seeded.length} fixture swarms into ${target}`);
  console.log(`Browse: SWARM_RUNS_DIR=${target} scripts/swarm.sh ui --port 43173`);
}
