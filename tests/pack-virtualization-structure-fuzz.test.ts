/**
 * virtualization-backup-forensics: a structure-aware fuzz. Where tests/pack-virtualization-fuzz.test.ts damages valid files
 * byte by byte, this one BUILDS the evidence: chains of disks of every format with random topology (missing parents, cycles,
 * wrong identities), configuration files, task indexes and exports, whose names, hints, descriptions and cells are drawn from a
 * hostile dictionary (plain names, ESXi paths, 4,000-character names, non-ASCII, a lone surrogate's bytes, and random secrets
 * of the shapes the tools claim to withhold, glued to letters, split by invisible characters, behind a secret's name), run
 * with random arguments in and out of a job. Every run must end in one JSON document, exit 0 or 1 as its status says, print
 * nothing on stderr, stay inside max_seconds plus a margin, write only under the output directory, leave no temporary paging
 * file, and show no random secret whole or in a 12-character piece.
 *
 * VIRT_SFUZZ_N sets the number of cases per tool (default 24, a few seconds); VIRT_SFUZZ_SEED changes the seed;
 * VIRT_SFUZZ_REPORT=1 prints the statuses, the slowest run and the secrets planted. The review of this change ran 5,000 per
 * tool on macOS and 1,500 per tool in a Linux container.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import {
  AUDIT, CHAIN, INVENTORY, prng, qcow2, vhdDifferencing, vhdDynamic, vhdx, vmdkDescriptor, vmdkSparse, vmsd, vmx,
} from "./pack-virtualization-harness.ts";

const N = Number(process.env.VIRT_SFUZZ_N ?? 24);
const SEED = Number(process.env.VIRT_SFUZZ_SEED ?? 20261015);
const REPORT = process.env.VIRT_SFUZZ_REPORT === "1";
const SLACK_MS = Number(process.env.VIRT_SFUZZ_SLACK_MS ?? 12_000);
const HAVE_QEMU = spawnSync("qemu-img", ["--version"]).status === 0;

type R = () => number;
const UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", LO = "abcdefghijklmnopqrstuvwxyz", DIG = "0123456789", AL = UP + LO + DIG, B64 = AL + "+/";
const pick = <T,>(r: R, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];
const rs = (r: R, n: number, a = AL): string => Array.from({ length: n }, () => a[Math.floor(r() * a.length)]).join("");
const mixed = (r: R, n: number): string => { let s = ""; while (s.length < n) s += rs(r, 1, UP) + rs(r, 1, LO) + rs(r, 1, DIG) + rs(r, 2); return s.slice(0, n); };
const GAPS = ["\u2066", "\u2067", "\u2068", "\u2069", "\u061c", "\ufe0f", "\ufe00", "\u{e0041}", "\u034f", "\u3164", "\u0301", "\u200b", "\u00ad", "\ufeff", "\u2060", "\u200e"];
const NAMES = ["vncPassword", "rootPassword", "adminPassword", "accessToken", "apiToken", "appSecret", "SecretAccessKey", "PWD", "pass", "pw", "credential", "auth", "PGPASSWORD", "MYSQL_PWD", "sig", "cipassword", "api_key", "Password", "secret", "token"];

/** A secret: the text to plant and the random parts a leak would show. */
type Secret = { text: string; cores: string[]; residual?: true };      // a residual shape is one the changelog lists as shown at a measured rate: planted, not asserted

function secret(r: R): Secret {
  const k = Math.floor(r() * 16);
  const spread = (t: string, every: number): string => { const g = pick(r, GAPS); return Array.from(t).reduce((o, c, i) => o + (i > 0 && i % every === 0 ? g : "") + c, ""); };
  if (k === 0) { const c = mixed(r, 36); return { text: "ghp_" + c, cores: [c] }; }
  if (k === 1) { const c = rs(r, 16, UP + DIG); return { text: "AKIA" + c, cores: [c] }; }
  if (k === 2) { const c = rs(r, 40, B64); return { text: c, cores: [c] }; }
  if (k === 3) { const c = rs(r, 40, "0123456789abcdef"); return { text: c, cores: [c] }; }
  if (k === 4) { const c = mixed(r, 36); return { text: spread("ghp_" + c, 2 + Math.floor(r() * 12)), cores: [c] }; }
  if (k === 5) { const c = rs(r, 16, UP + DIG); return { text: spread("AKIA" + c, 2 + Math.floor(r() * 12)), cores: [c] }; }
  if (k === 6) { const c = rs(r, 12 + Math.floor(r() * 12)); return { text: `${pick(r, NAMES)}${pick(r, ["=", ": ", "=\"", ":"])}${c}`, cores: [c] }; }
  if (k === 7) { const c = rs(r, 12 + Math.floor(r() * 12)); return { text: `${rs(r, 3, LO)}${pick(r, NAMES)}=${c}`, cores: [c] }; }
  if (k === 8) { const c = mixed(r, 14); return { text: `https://svc:${c}@h.example.test/x`, cores: [c] }; }
  if (k === 9) { const c = mixed(r, 14); return { text: `svc:${c}@nas01`, cores: [c] }; }
  if (k === 10) { const a = mixed(r, 12), b = mixed(r, 12); return { text: `svc:${a}@${b}@host.example.test`, cores: [a, b] }; }
  if (k === 11) { const c = rs(r, 22, B64).replace(/=+$/, ""); return { text: c, cores: [c], residual: true }; }
  if (k === 12) { const a = rs(r, 9, UP), b = rs(r, 5, UP); const c = mixed(r, 30); return { text: `eyJ${a}.eyJ${b}.${c}`, cores: [a, b, c] }; }
  if (k === 13) { const c = mixed(r, 40); return { text: `aws_secret_access_key=${c}`, cores: [c] }; }
  if (k === 14) { const c = mixed(r, 36); return { text: "ghp_" + c.slice(0, 20) + "\\u2066" + c.slice(20), cores: [c.slice(0, 20), c.slice(20)] }; }
  const c = rs(r, 24, LO + DIG); return { text: c, cores: [c], residual: true };
}

/** A name or text for a slot: mostly ordinary, sometimes hostile; the secrets planted are collected. */
function hostile(r: R, planted: string[], fileSafe = false, forbid?: RegExp): string {
  for (let tries = 0; tries < 8; tries++) {
    const mine: string[] = [];
    const t = hostile1(r, mine, fileSafe);
    if (forbid && forbid.test(t)) continue;
    planted.push(...mine);
    return t;
  }
  return "node1";
}

function hostile1(r: R, planted: string[], fileSafe: boolean): string {
  const k = r();
  if (k < 0.3) return pick(r, ["web01", "Web-Server-01 (clone)", "Win2019-DC01", "db-prod-02", "vm-100-disk-1", "snap1", "Before upgrade", "datastore1"]);
  if (k < 0.4) return pick(r, ["/vmfs/volumes/5f3d1a2b-9c8d7e6f-1a2b-0123456789ab/web01/web01.vmdk", "[datastore1] web01/web01.vmdk", "C:\\Hyper-V\\web01.vhdx", "local-lvm:vm-100-disk-0"]);
  if (k < 0.5) return "a_".repeat(Math.floor(r() * 2000) + 50);
  if (k < 0.55) return pick(r, ["Sunucu-Üretim-01", "测试服务器01", "Ünïcödé", "RTL \u202e text"]);
  if (k < 0.6) return rs(r, 60 + Math.floor(r() * 200), B64);
  const s = secret(r);
  if (!s.residual) planted.push(...s.cores);
  const around = r();
  const t = around < 0.5 ? s.text : around < 0.75 ? `${pick(r, ["vm-14", "web01 ", "x", "7", "srv:"])}${s.text}` : `${s.text} ${pick(r, ["end", "backup", "clone"])}`;
  return fileSafe ? t.replace(/[/\0]/g, "_") : t;
}

const T0 = 1_700_000_000;
const hex = (n: number): string => n.toString(16).toUpperCase().padStart(8, "0");
type Files = Record<string, string | Buffer>;
type Case = { files: Files; args: Record<string, unknown>; planted: string[] };

function chainCase(r: R): Case {
  const planted: string[] = [], files: Files = {};
  const n = 1 + Math.floor(r() * 9);
  const names = Array.from({ length: n }, (_, i) => `d${i}`);
  const parentOf = (i: number): string => (r() < 0.15 ? hostile(r, planted, true) : names[Math.floor(r() * n)]);
  for (let i = 0; i < n; i++) {
    const kind = pick(r, ["vmdk", "vmdk", "sparse", "vhd", "vhdx", "qcow2"]);
    const hasParent = r() < 0.7 && i > 0;
    const hint = hasParent ? parentOf(i) : undefined;
    if (kind === "vmdk") files[`vm/${names[i]}.vmdk`] = vmdkDescriptor({ cid: rs(r, 8, "0123456789abcdef"), parentCid: hasParent ? rs(r, 8, "0123456789abcdef") : "ffffffff", parentHint: hint === undefined ? undefined : `${hint}.vmdk`, extents: [{ sectors: 8, type: "FLAT", name: r() < 0.3 ? hostile(r, planted, true) : `${names[i]}-flat.vmdk` }] });
    else if (kind === "sparse") files[`vm/${names[i]}.vmdk`] = vmdkSparse({ descriptor: vmdkDescriptor({ cid: rs(r, 8, "0123456789abcdef"), parentCid: "ffffffff", createType: "monolithicSparse", parentHint: hint, extents: [{ sectors: 2048, type: "SPARSE", name: `${names[i]}.vmdk` }] }) });
    else if (kind === "vhd") files[`hv/${names[i]}.vhd`] = hasParent ? vhdDifferencing({ uid: `11111111-aaaa-bbbb-cccc-${String(i).padStart(12, "0")}`, parentUid: `11111111-aaaa-bbbb-cccc-${String(Math.floor(r() * n)).padStart(12, "0")}`, parentName: (hint ?? "x").slice(0, 250), locators: r() < 0.5 ? [{ code: "W2ru", text: hostile(r, planted) }] : [] }) : vhdDynamic({ uid: `11111111-aaaa-bbbb-cccc-${String(i).padStart(12, "0")}` });
    else if (kind === "vhdx") files[`hv/${names[i]}.vhdx`] = vhdx({ diskId: `AAAAAAAA-0000-4000-8000-${String(i).padStart(12, "0")}`, parent: hasParent ? { linkage: r() < 0.5 ? "22222222-2222-2222-2222-222222222222" : `bbbbbbbb-0000-4000-8000-${String(i).padStart(12, "0")}`, relative: hostile(r, planted), absolute: hostile(r, planted) } : undefined });
    else files[`q/${names[i]}.qcow2`] = qcow2({ backing: hint, backingFormat: r() < 0.3 ? hostile(r, planted, true) : undefined, snapshots: r() < 0.4 ? [{ id: hostile(r, planted, true).slice(0, 60), name: hostile(r, planted, true).slice(0, 120), date: T0 }] : [] });
  }
  if (r() < 0.6) files["vm/vm.vmx"] = vmx([["displayName", hostile(r, planted, true)], ["scsi0:0.fileName", hostile(r, planted, true)], ["scsi0:0.present", "TRUE"]]);
  if (r() < 0.5) files["vm/vm.vmsd"] = vmsd({ snapshots: [{ index: 0, uid: "1", name: hostile(r, planted, true), disks: [hostile(r, planted, true)] }, { index: 1, uid: "2", name: "t", parent: "1", disks: ["gone.vmdk"] }] });
  if (r() < 0.2) files[`vm/${hostile(r, planted, true).slice(0, 100)}.vmdk`] = "x";
  return { files, planted, args: { root: "inputs", ...common(r, true) } };
}

function inventoryCase(r: R): Case {
  const planted: string[] = [], files: Files = {};
  if (r() < 0.7) files["vm/a.vmx"] = vmx([["displayName", hostile(r, planted, true)], ["guestOS", hostile(r, planted, true)], ["annotation", hostile(r, planted)], ["scsi0:0.fileName", hostile(r, planted, true)], ["RemoteDisplay.vnc.password", hostile(r, planted)], ["uuid.bios", hostile(r, planted)], ["ethernet0.networkName", hostile(r, planted)], ["ethernet0.address", hostile(r, planted)]]);
  if (r() < 0.5) files["vm/a.vmsd"] = vmsd({ snapshots: [{ index: 0, uid: hostile(r, planted, true), name: hostile(r, planted, true), disks: [hostile(r, planted, true)] }] });
  if (r() < 0.5) files["lv/d.xml"] = `<domain type='kvm'><name>${xml(hostile(r, planted))}</name><uuid>${xml(hostile(r, planted))}</uuid><devices><disk type='file' device='disk'><source file='${xml(hostile(r, planted, true))}'/><target dev='vda'/></disk><graphics type='vnc' passwd='${xml(hostile(r, planted))}'/></devices></domain>`;
  if (r() < 0.4) files["pve/nodes/pve1/qemu-server/100.conf"] = [`name: ${hostile(r, planted)}`, `description: ${hostile(r, planted)}`, `scsi0: ${hostile(r, planted, true)},size=32G`, `cipassword: ${hostile(r, planted)}`, `net0: virtio=${hostile(r, planted)},bridge=vmbr0`, "", `[${rs(r, 6, LO)}]`, `snaptime: ${T0}`, `parent: ${hostile(r, planted)}`, ""].join("\n");
  if (r() < 0.3) files["pve/storage.cfg"] = [`dir: ${rs(r, 5, LO)}`, `\tpath ${hostile(r, planted, true)}`, "", "pbs: b", `\tdatastore ${hostile(r, planted)}`, `\tserver ${hostile(r, planted)}`, `\tusername ${hostile(r, planted)}`, `\tpassword ${hostile(r, planted)}`, ""].join("\n");
  if (r() < 0.3) files["esxi/vmInventory.xml"] = `<ConfigRoot><ConfigEntry id="1"><objID>1</objID><vmxCfgPath>/vmfs/volumes/${xml(hostile(r, planted, true))}/a/a.vmx</vmxCfgPath></ConfigEntry></ConfigRoot>`;
  if (Object.keys(files).length === 0) files["vm/a.vmx"] = vmx([["displayName", "web01"]]);
  return { files, planted, args: { root: "inputs", ...common(r, false) } };
}

const xml = (s: string): string => s.replace(/[&<>'"\0-\x08\x0b\x0c\x0e-\x1f]/g, "_");

function auditCase(r: R): Case {
  const planted: string[] = [], files: Files = {};
  const kind = pick(r, ["index", "log", "csv", "jsonl", "xml"]);
  const common2 = common(r, false);
  if (kind === "index") {
    const lines = Array.from({ length: 1 + Math.floor(r() * 30) }, (_, i) => `UPID:${pick(r, ["pve1", hostile(r, planted, true, /[:\n]/)])}:${hex(1 + i)}:${hex(2)}:${hex(T0 + i)}:${pick(r, ["vzdump", "qmsnapshot", "qmdelsnapshot", "newkind"])}:${pick(r, ["100", hostile(r, planted, true, /[:\n]/)])}:${pick(r, ["root@pam", hostile(r, planted, true, /[:\n@]/) + "@pam"])}: ${hex(T0 + i + 5)} ${pick(r, ["OK", "unknown", `error ${hostile(r, planted).replace(/\n/g, " ")}`])}`);
    files["a/index"] = lines.join("\n") + "\n";
    return { files, planted, args: { path: "inputs/a/index", ...common2 } };
  }
  if (kind === "log") {
    files["a/task.log"] = ["INFO: starting new backup job: vzdump 100", `INFO: creating vzdump archive '${hostile(r, planted, true)}'`, `INFO: removing backup '${hostile(r, planted)}'`, `ERROR: Backup of VM 101 failed - ${hostile(r, planted).replace(/\n/g, " ")}`, `WARN: ${hostile(r, planted).replace(/\n/g, " ")}`, "TASK ERROR: job errors"].join("\n") + "\n";
    return { files, planted, args: { path: "inputs/a/task.log", ...common2 } };
  }
  const cell = (): string => hostile(r, planted).replace(/[\r\n]/g, " ");
  const map = { time: "t", action: "a", result: "r", actor: "u", object: "o", host: "h", job: "j", message: "m" };
  if (kind === "csv") {
    const q = (s: string): string => `"${s.replace(/"/g, '""')}"`;
    files["a/x.csv"] = ["t,a,r,u,o,h,j,m", ...Array.from({ length: 1 + Math.floor(r() * 12) }, () => [pick(r, ["2024-01-05T02:00:00Z", "last tuesday", String(T0)]), q(cell()), q(cell()), q(cell()), q(cell()), q(cell()), q(cell()), q(cell())].join(","))].join("\n") + "\n";
    return { files, planted, args: { path: "inputs/a/x.csv", format: "declared_csv", mapping: map, time_format: pick(r, ["iso8601", "epoch_seconds"]), ...common2 } };
  }
  if (kind === "jsonl") {
    files["a/x.jsonl"] = Array.from({ length: 1 + Math.floor(r() * 12) }, () => JSON.stringify({ t: pick(r, ["2024-01-05T02:00:00Z", T0, "x"]), a: cell(), r: cell(), u: cell(), o: cell(), h: r() < 0.2 ? [cell()] : cell(), j: cell(), m: cell(), [cell().slice(0, 80)]: cell() })).join("\n") + "\n";
    return { files, planted, args: { path: "inputs/a/x.jsonl", format: "declared_jsonl", mapping: map, ...common2 } };
  }
  files["a/x.xml"] = `<?xml version="1.0"?><X>${Array.from({ length: 1 + Math.floor(r() * 12) }, () => `<R when="${pick(r, ["2024-01-05T02:00:00Z", "x"])}" id="${xml(cell())}"><A>${xml(cell())}</A><Res v="${xml(cell())}"/><W><N>${xml(cell())}</N></W><M>${xml(cell())}</M></R>`).join("")}</X>`;
  return { files, planted, args: { path: "inputs/a/x.xml", format: "declared_xml", record_tag: "R", mapping: { time: "@when", action: "A", result: "Res@v", actor: "W/N", object: "@id", message: "M" }, ...common2 } };
}

function common(r: R, chain: boolean): Record<string, unknown> {
  return { limit: pick(r, [1, 2, 5, 200]), max_seconds: pick(r, [2, 5, 50]), ...(chain && HAVE_QEMU && r() < 0.15 ? { qemu_img: "auto" } : {}) };
}

type Done = { code: number | null; stdout: string; stderr: string; ms: number };

function run(script: string, cwd: string, args: unknown, env: Record<string, string>): Promise<Done> {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn("python3", [script], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    const out: Buffer[] = [], err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    const timer = setTimeout(() => child.kill("SIGKILL"), 90_000);
    child.on("close", (code) => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), ms: Date.now() - started }); });
    child.stdin.end(JSON.stringify(args));
  });
}

async function walk(dir: string, rel = ""): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...(await walk(join(dir, e.name), r))); else out.push(r);
  }
  return out;
}

async function campaign(label: string, script: string, build: (r: R) => Case): Promise<void> {
  const r = prng(SEED + label.length * 7919);
  const statuses: Record<string, number> = {};
  let slowest = 0, planted = 0, shown = 0;
  const base = await mkdtemp(join(tmpdir(), `virt-sfuzz-${label}-`));
  try {
    for (let i = 0; i < N; i++) {
      const c = build(r);
      const dir = join(base, `c${i}`);
      await mkdir(join(dir, "work", "s1"), { recursive: true });
      for (const [rel, data] of Object.entries(c.files)) {
        const full = join(dir, "inputs", rel);
        await mkdir(dirname(full), { recursive: true });
        await writeFile(full, data).catch(() => undefined);        // a name the file system cannot hold is skipped
      }
      const job = r() < 0.4;
      const env: Record<string, string> = job ? { JOB_ID: `j${String(100000 + i).padStart(6, "0")}`, OUT: join(dir, "out") } : {};
      if (job) await mkdir(env.OUT, { recursive: true });
      const args: Record<string, unknown> = { ...c.args, ...(job && r() < 0.5 ? { write_text: true } : {}) };
      const tag = `${label} case ${i} (seed ${SEED})`;
      const before = new Set(await walk(dir));
      const res = await run(script, dir, args, env);
      slowest = Math.max(slowest, res.ms);
      assert.equal(res.stderr, "", `${tag}: stderr ${res.stderr.slice(-300)}`);
      assert.ok(res.code === 0 || res.code === 1, `${tag}: exit ${res.code}`);
      let doc: { status?: string };
      try { doc = JSON.parse(res.stdout); } catch { assert.fail(`${tag}: not JSON: ${res.stdout.slice(0, 200)}`); }
      statuses[doc.status ?? "none"] = (statuses[doc.status ?? "none"] ?? 0) + 1;
      assert.ok(["complete", "partial", "failed"].includes(doc.status as string), `${tag}: status ${doc.status}`);
      assert.equal(res.code === 1, doc.status === "failed", `${tag}: exit and status disagree`);
      assert.ok(res.ms < ((args.max_seconds as number) + 2) * 1000 + SLACK_MS, `${tag}: ${res.ms} ms at max_seconds ${args.max_seconds}`);
      const written = (await walk(dir)).filter((f) => !before.has(f));
      assert.ok(written.every((f) => f.startsWith("out/") || f.startsWith("work/")), `${tag}: wrote outside out/ and work/: ${written.join(", ")}`);
      assert.equal(written.some((f) => /\/\.[^/]*$/.test(f) || /\.jsonl-\w+$/.test(f)), false, `${tag}: a temporary paging file is left: ${written.join(", ")}`);
      const texts = [res.stdout];
      for (const f of written) {
        if (/-values\.jsonl$/.test(f)) { assert.equal((await stat(join(dir, f))).mode & 0o777, 0o600, `${tag}: ${f} is private`); continue; }
        texts.push(f, await readFile(join(dir, f), "latin1"));
      }
      const hay = texts.join("\n").normalize("NFKC").replace(/[\u00ad\u034f\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\u{e0000}-\u{e0fff}\u0301]/gu, "");
      for (const core of new Set(c.planted.map((x) => x.normalize("NFKC")))) {
        if (core.length < 12) continue;
        planted += 1;
        for (let k = 0; k + 12 <= core.length; k += 6) if (hay.includes(core.slice(k, k + 12))) {
          shown += 1;
          if (process.env.VIRT_SFUZZ_KEEP) await cp(dir, join(process.env.VIRT_SFUZZ_KEEP, `${label}-${i}`), { recursive: true });
          assert.fail(`${tag}: ${core.slice(k, k + 12)} of a planted secret is shown`);
        }
      }
      await rm(dir, { recursive: true, force: true });
    }
    if (REPORT) console.log(`# structure fuzz ${label}: ${N} cases (seed ${SEED}), statuses ${JSON.stringify(statuses)}, slowest ${slowest} ms, ${planted} planted secrets, ${shown} shown`);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
}

test(`${N} built chains of every format end in snapshot_chain_check's own JSON and show no planted secret`, async () => { await campaign("chain", CHAIN, chainCase); });
test(`${N} built configurations end in virtualization_inventory's own JSON and show no planted secret`, async () => { await campaign("inventory", INVENTORY, inventoryCase); });
test(`${N} built exports end in backup_audit_normalise's own JSON and show no planted secret`, async () => { await campaign("audit", AUDIT, auditCase); });
