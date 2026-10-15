/**
 * virtualization-backup-forensics: the three tools read files the evidence supplied, so a damaged file must end in the
 * tool's own JSON, whatever is wrong with it. A seeded mutation fuzz (the seed is fixed, so a failure repeats): files built
 * from the formats' layouts (tests/pack-virtualization-harness.ts) are damaged byte by byte, truncated, padded, spliced,
 * have a field overwritten with an extreme value, and (for text) a line repeated or a number made huge; every run must
 * exit 0 or 1, print one JSON document, never a Python traceback, finish inside the time cap, and stay inside a memory cap.
 *
 * VIRT_FUZZ_N sets the number of mutants per tool (default 120, which keeps this suite to seconds); the full run of the
 * review used 3000 per tool. VIRT_FUZZ_SEED changes the seed. VIRT_FUZZ_RSS=1 watches each run's resident size.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  AUDIT, CANARY, CHAIN, INVENTORY, filesUnder, prng, qcow2, vhdDifferencing, vhdDynamic, vhdFixed, vhdx, vmdkDescriptor, vmdkSparse, vmsd, vmx,
} from "./pack-virtualization-harness.ts";

const N = Number(process.env.VIRT_FUZZ_N ?? 120);
const SEED = Number(process.env.VIRT_FUZZ_SEED ?? 20261014);
const WATCH_RSS = process.env.VIRT_FUZZ_RSS === "1";
const TIME_CAP_MS = 30_000;
const RSS_CAP_KB = 1_500_000;
const CONCURRENCY = Number(process.env.VIRT_FUZZ_CONCURRENCY ?? 4);

type Seed = { rel: string; data: Buffer };

function flat(name: string, text: string): Seed { return { rel: name, data: Buffer.from(text) }; }

const UID = (n: number): string => `11111111-aaaa-bbbb-cccc-${String(n).padStart(12, "0")}`;

/** The seed set of each tool: valid files of every format it reads, side by side so that edges resolve. */
function chainSeeds(): Seed[] {
  return [
    flat("base.vmdk", vmdkDescriptor({ cid: "aabbccdd", extents: [{ sectors: 8, type: "FLAT", name: "base-flat.vmdk", offset: 0 }] })),
    { rel: "base-flat.vmdk", data: Buffer.alloc(8 * 512) },
    flat("base-000001.vmdk", vmdkDescriptor({ cid: "11223344", parentCid: "aabbccdd", createType: "vmfsSparse", parentHint: `base.vmdk/../${CANARY.hex}.vmdk`, extents: [{ sectors: 8, type: "VMFSSPARSE", name: "base-000001-delta.vmdk" }] })),
    { rel: "base-000001-delta.vmdk", data: vmdkSparse({}) },
    { rel: "mono.vmdk", data: vmdkSparse({ descriptor: vmdkDescriptor({ cid: "00000001", createType: "monolithicSparse", extents: [{ sectors: 2048, type: "SPARSE", name: "mono.vmdk" }] }), unclean: true }) },
    { rel: "dyn.vhd", data: vhdDynamic({ uid: UID(1) }) },
    { rel: "diff.vhd", data: vhdDifferencing({ uid: UID(2), parentUid: UID(1), parentName: "C:\\VMs\\dyn.vhd", locators: [{ code: "W2ru", text: ".\\dyn.vhd" }, { code: "MacX", text: "file:///x/dyn.vhd", encoding: "utf8" }] }) },
    { rel: "fixed.vhd", data: vhdFixed(UID(3)) },
    { rel: "base.vhdx", data: vhdx({ diskId: "AAAAAAAA-0000-4000-8000-000000000001" }) },
    { rel: "child.avhdx", data: vhdx({ diskId: "AAAAAAAA-0000-4000-8000-000000000002", parent: { linkage: "22222222-2222-2222-2222-222222222222", relative: ".\\base.vhdx", absolute: "C:\\VMs\\base.vhdx" }, headers: [{ logGuid: "CCCCCCCC-0000-4000-8000-000000000001", logLength: 4096 }, {}] }) },
    { rel: "q-base.qcow2", data: qcow2({ snapshots: [{ id: "1", name: "one", date: 1_700_000_000, extra: Buffer.alloc(16) }, { id: "2", name: "two", date: 1_700_000_100 }], incompat: 1n }) },
    { rel: "q-top.qcow2", data: qcow2({ backing: `q-base.qcow2`, backingFormat: "qcow2" }) },
    { rel: "q3.qcow2", data: qcow2({ backing: `/srv/${CANARY.github}/q-base.qcow2`, snapshots: [{ id: CANARY.hex, name: `snap-${CANARY.aws}`, date: 5 }] }) },
    { rel: "q2.qcow2", data: qcow2({ version: 2, backing: "q-top.qcow2" }) },
    flat("vm.vmx", vmx([["displayName", `x ${CANARY.github}`], ["scsi0:0.fileName", "base-000001.vmdk"], ["scsi0:0.present", "TRUE"]])),
    flat("vm.vmsd", vmsd({ snapshots: [{ index: 0, uid: "1", name: "s", disks: ["base-000001.vmdk"] }, { index: 1, uid: "2", name: "t", parent: "1", disks: ["gone.vmdk"] }] })),
  ];
}

function inventorySeeds(): Seed[] {
  return [
    flat("web.vmx", vmx([["displayName", `web ${CANARY.aws}`], ["guestOS", "ubuntu-64"], ["scsi0:0.fileName", `https://${CANARY.userinfo}@h.example.test/${CANARY.hex}.vmdk`], ["scsi0:1.fileName", "d.vmdk"], ["scsi0:1.mode", "independent-persistent"], ["ethernet0.generatedAddress", "00:0c:29:aa:bb:cc"], ["RemoteDisplay.vnc.password", "x"]])),
    flat("web.vmsd", vmsd({ snapshots: [{ index: 0, uid: "1", name: "s", disks: ["web-000001.vmdk"] }, { index: 1, uid: "2", name: "t", parent: "1", disks: ["web-000002.vmdk"] }] })),
    flat("guest.xml", `<domain type='kvm'><name>g-${CANARY.github}</name><uuid>1</uuid><memory unit='KiB'>1</memory><os><type arch='x86_64' machine='q35'>hvm</type></os><devices><disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='/i/${CANARY.aws}/top.qcow2'/><backingStore type='file'><format type='qcow2'/><source file='/i/base.qcow2'/><backingStore/></backingStore><target dev='vda' bus='virtio'/></disk><graphics type='vnc' passwd='p'/></devices></domain>`),
    flat("snap.xml", `<domainsnapshot><name>s</name><state>running</state><creationTime>1700000000</creationTime><parent><name>p</name></parent><memory snapshot='internal'/><disks><disk name='vda' snapshot='external'><source file='/i/t.qcow2'/></disk></disks><domain><name>g</name></domain></domainsnapshot>`),
    flat("pool.xml", `<pool type='dir'><name>default</name><uuid>1</uuid><target><path>/var/lib/libvirt/images</path></target></pool>`),
    flat("vmInventory.xml", `<ConfigRoot><ConfigEntry id="0001"><objID>1</objID><vmxCfgPath>/vmfs/volumes/ds/web/web.vmx</vmxCfgPath></ConfigEntry></ConfigRoot>`),
    flat("pve/qemu-server/100.conf", `#notes\nboot: order=scsi0\ncores: 2\nmemory: 4096\nname: web01-${CANARY.aws}\nostype: l26\nscsi0: local-lvm:vm-100-disk-0,size=32G,backup=0\nnet0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0\ncipassword: x\nparent: s1\n\n[s1]\ncores: 2\nparent: s0\nsnaptime: 1700000000\nvmstate: local-lvm:vm-100-state\nscsi0: local-lvm:vm-100-disk-0,size=32G\n`),
    flat("pve/storage.cfg", `dir: local\n\tpath /var/lib/vz\n\tcontent iso,backup\n\nlvmthin: local-lvm\n\tthinpool data\n\tvgname pve\n\npbs: backup\n\tdatastore s\n\tserver h\n\tusername u@pbs\n\tpassword p\n`),
    { rel: "vm.vmcx", data: Buffer.from("VMCX\0\0") },
    flat("m.vbox", `<VirtualBox><Machine name="x"/></VirtualBox>`),
  ];
}

const T0 = 1_700_000_000;
const upid = (i: number, type: string, status: string): string => `UPID:pve1:${(2931 + i).toString(16).toUpperCase().padStart(8, "0")}:0000D2C5:${(T0 + i * 7).toString(16).toUpperCase()}:${type}:${100 + i}:root@pam!${CANARY.github}: ${(T0 + i * 7 + 3).toString(16).toUpperCase()} ${status}`;

type AuditSeed = Seed & { args: Record<string, unknown> };
function auditSeeds(): AuditSeed[] {
  const csvMap = { time: "When", action: "Operation", result: "Outcome", actor: "User", object: "Object", message: "Details" };
  return [
    { rel: "index", data: Buffer.from(["vzdump", "qmdelsnapshot", "qmdestroy", "prunejob", "garbage_collection", "newkind"].map((t, i) => upid(i, t, i % 2 ? "OK" : "error x")).join("\n") + "\nUPID:pve1:00000001:00000001:00000001:t::u:\n"), args: { format: "pve_task_index" } },
    { rel: "task.log", data: Buffer.from(`INFO: starting new backup job: vzdump 100\nINFO: Starting Backup of VM 100 (qemu)\nINFO: Backup started at 2024-01-05 02:00:01\nINFO: creating vzdump archive '/d/${CANARY.aws}/x.vma.zst'\nINFO: Finished Backup of VM 100 (00:00:45)\nERROR: Backup of VM 101 failed - x\nINFO: removing backup 'local:backup/${CANARY.hex}'\nWARN: odd\nINFO: Backup job finished with errors\nTASK ERROR: job errors\n`), args: { format: "pve_vzdump_log", time_zone_offset_minutes: 60 } },
    { rel: "export.csv", data: Buffer.from(`\ufeffWhen,Operation,Outcome,User,Object,Details\n2024-01-05T02:00:00Z,Delete restore point,Success,${CANARY.github},vm100-${CANARY.aws},\"a\nb\"\n2024-01-05 03:00:00,Job start,Failed,svc,vm101,x\n`), args: { format: "declared_csv", mapping: csvMap, category_map: { "delete restore point": "retention_remove" }, result_map: { success: "ok" } } },
    { rel: "export.jsonl", data: Buffer.from(`{"ts":1700000000123,"event":{"name":"SnapshotRemove","result":"FAILED"},"who":{"id":"${CANARY.github}"},"target":"vm9-${CANARY.aws}"}\n{"ts":"x"}\n[1]\n`), args: { format: "declared_jsonl", time_format: "epoch_milliseconds", mapping: { time: "ts", action: "event.name", result: "event.result", actor: "who.id", object: "target" } } },
    { rel: "export.xml", data: Buffer.from(`<?xml version="1.0"?><Audit><Record id="1" when="2024-01-05T02:00:00Z"><Action>Delete</Action><Who><Name>${CANARY.github}</Name></Who><Result>Success</Result></Record><Record id="2" when="2024-01-05T03:00:00Z"><Action>Run</Action></Record></Audit>`), args: { format: "declared_xml", record_tag: "Record", mapping: { time: "@when", action: "Action", actor: "Who/Name", result: "Result", object: "@id" } } },
  ];
}

const EXTREME = [0n, 1n, 2n, 0x7fn, 0x80n, 0xffn, 0x7fffn, 0xffffn, 0x7fffffffn, 0x80000000n, 0xffffffffn, 0x7fffffffffffffffn, 0xffffffffffffffffn];

function mutate(data: Buffer, random: () => number, text: boolean): Buffer {
  const pick = (n: number): number => Math.floor(random() * n);
  let b = Buffer.from(data);
  for (let k = 1 + pick(6); k > 0; k--) {
    if (b.length === 0) b = Buffer.from([pick(256)]);
    const mode = random();
    if (mode < 0.22) {
      b[pick(b.length)] = pick(256);
    } else if (mode < 0.32) {
      b[pick(b.length)] = random() < 0.5 ? 0 : 0xff;
    } else if (mode < 0.44) {
      b = b.subarray(0, 1 + pick(b.length));
    } else if (mode < 0.52) {
      const at = pick(b.length + 1);
      b = Buffer.concat([b.subarray(0, at), Buffer.from(Array.from({ length: 1 + pick(32) }, () => pick(256))), b.subarray(at)]);
    } else if (mode < 0.6) {
      const at = pick(b.length), n = 1 + pick(Math.min(64, b.length - at));
      b = Buffer.concat([b.subarray(0, at), b.subarray(at + n)]);
    } else if (mode < 0.68) {
      const at = pick(b.length), n = 1 + pick(Math.min(4096, b.length - at)), times = 1 + pick(40);
      b = Buffer.concat([b.subarray(0, at), ...Array.from({ length: times }, () => b.subarray(at, at + n)), b.subarray(at)]);
    } else if (mode < 0.86 || !text) {
      // overwrite an aligned integer with an extreme value, either endian
      const width = [1, 2, 4, 8][pick(4)];
      if (b.length >= width) {
        const at = pick(Math.floor((b.length - width) / width) + 1) * width;
        const v = EXTREME[pick(EXTREME.length)] & ((1n << BigInt(width * 8)) - 1n);
        const buf = Buffer.alloc(width);
        const le = random() < 0.5;
        if (width === 1) buf[0] = Number(v);
        else if (width === 2) le ? buf.writeUInt16LE(Number(v)) : buf.writeUInt16BE(Number(v));
        else if (width === 4) le ? buf.writeUInt32LE(Number(v)) : buf.writeUInt32BE(Number(v));
        else le ? buf.writeBigUInt64LE(v) : buf.writeBigUInt64BE(v);
        buf.copy(b, at);
      }
    } else if (text) {
      const s = b.toString("latin1");
      const t = random();
      let out = s;
      if (t < 0.3) {
        const lines = s.split("\n");
        const i = pick(lines.length);
        out = [...lines.slice(0, i), ...Array.from({ length: 1 + pick(2000) }, () => lines[i]), ...lines.slice(i + 1)].join("\n");
      } else if (t < 0.55) {
        out = s.replace(/\d+/, () => "9".repeat(1 + pick(40)));
      } else if (t < 0.75) {
        const at = pick(s.length + 1);
        out = s.slice(0, at) + ["<a>".repeat(1 + pick(300)), "[".repeat(1 + pick(5000)), "\"".repeat(1 + pick(9)), "\u0000".repeat(1 + pick(9)), "&#x41;&amp;&lt;", "<!DOCTYPE x [<!ENTITY e \"y\">]>", "\r\n".repeat(1 + pick(20))][pick(7)] + s.slice(at);
      } else {
        out = s.split("\n").filter(() => random() > 0.2).join("\n");
      }
      b = Buffer.from(out, "latin1");
    }
  }
  return b;
}

type Run = { code: number | null; stdout: string; stderr: string; ms: number; rssKb: number; timedOut: boolean };

/** Runs the tool under a wrapper that reports the peak resident size of the tool process itself (wait4's rusage). */
const WRAPPER = "import os,sys\npid=os.fork()\nif pid==0:\n os.execvp('python3',['python3',sys.argv[1]])\n_,st,ru=os.wait4(pid,0)\nopen(sys.argv[2],'w').write(str(ru.ru_maxrss))\nsys.exit(os.waitstatus_to_exitcode(st))\n";

function run(script: string, cwd: string, args: unknown): Promise<Run> {
  return new Promise((resolve) => {
    const started = Date.now();
    const rssFile = join(cwd, "..", `rss-${Math.random().toString(36).slice(2)}`);
    const child = WATCH_RSS
      ? spawn("python3", ["-c", WRAPPER, script, rssFile], { cwd, env: { ...process.env, AGENT_ID: "s1" } })
      : spawn("python3", [script], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    const out: Buffer[] = [], err: Buffer[] = [];
    let timedOut = false;
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, TIME_CAP_MS);
    child.on("close", async (code) => {
      clearTimeout(timer);
      let rssKb = 0;
      if (WATCH_RSS) {
        const raw = Number(await readFile(rssFile, "utf8").catch(() => "0")) || 0;
        rssKb = process.platform === "darwin" ? Math.round(raw / 1024) : raw;
        await rm(rssFile, { force: true });
      }
      resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), ms: Date.now() - started, rssKb, timedOut });
    });
    child.stdin.end(JSON.stringify(args));
  });
}

async function fuzz(name: string, script: string, seeds: Seed[], argsFor: (mutated: Seed, dir: string) => unknown, textOf: (s: Seed) => boolean): Promise<{ cases: number; slowest: number; rss: number; statuses: Record<string, number> }> {
  const random = prng(SEED + name.length);
  const base = await mkdtemp(join(tmpdir(), `virt-fuzz-${name}-`));
  let slowest = 0, rss = 0;
  const statuses: Record<string, number> = {};
  try {
    const jobs: Array<() => Promise<void>> = [];
    for (let n = 0; n < N; n++) {
      const which = Math.floor(random() * seeds.length);
      const seed = seeds[which];
      let data = mutate(seed.data, random, textOf(seed));
      // some cases splice in another seed's bytes
      if (random() < 0.1) { const other = seeds[Math.floor(random() * seeds.length)]; data = Buffer.concat([data.subarray(0, Math.floor(data.length / 2)), other.data.subarray(Math.floor(other.data.length / 2))]); }
      const index = n;
      jobs.push(async () => {
        const dir = join(base, `c${index}`);
        await mkdir(join(dir, "work", "s1"), { recursive: true });
        for (const s of seeds) {
          const path = join(dir, "inputs", s.rel);
          await mkdir(join(path, ".."), { recursive: true });
          await writeFile(path, s === seed ? data : s.data);
        }
        const res = await run(script, dir, argsFor(seed, dir));
        try {
          await check(res);
        } catch (error) {
          if (process.env.VIRT_FUZZ_KEEP) await cp(dir, join(process.env.VIRT_FUZZ_KEEP, `${name}-${index}`), { recursive: true });
          throw error;
        }
        await rm(dir, { recursive: true, force: true });
        return;
        async function check(res: Run): Promise<void> {
        slowest = Math.max(slowest, res.ms);
        rss = Math.max(rss, res.rssKb);
        const label = `${name} case ${index} (seed ${SEED}, file ${seed.rel})`;
        assert.equal(res.timedOut, false, `${label} ran past ${TIME_CAP_MS} ms`);
        assert.doesNotMatch(res.stderr, /Traceback/, `${label}: ${res.stderr.slice(-400)}`);
        assert.ok(res.code === 0 || res.code === 1, `${label} exited ${res.code}`);
        let doc: { status?: string; error?: string };
        assert.doesNotThrow(() => { doc = JSON.parse(res.stdout); }, `${label} printed no JSON: ${res.stdout.slice(0, 200)}`);
        doc = JSON.parse(res.stdout);
        statuses[doc.status ?? "none"] = (statuses[doc.status ?? "none"] ?? 0) + 1;
        assert.ok(doc.status === "complete" || doc.status === "partial" || doc.status === "failed", `${label} has no status`);
        assert.equal(res.code === 1, doc.status === "failed", `${label}: exit code and status disagree`);
        // whatever the damage, no planted token reaches the answer or a page an agent reads (a short password with no user-info structure left is not a shape the tools recognise: tests/pack-virtualization-*.test.ts hold the user-info case)
        const pages = await Promise.all((await filesUnder(join(dir, "work"))).map((f) => readFile(join(dir, "work", f), "utf8").catch(() => "")));
        for (const text of [res.stdout, res.stderr, ...pages]) for (const secret of [CANARY.github, CANARY.aws, CANARY.hex]) assert.equal(text.includes(secret), false, `${label} printed a planted secret`);
        if (WATCH_RSS) assert.ok(res.rssKb < RSS_CAP_KB, `${label} used ${res.rssKb} KB`);
        }
      });
    }
    let next = 0;
    await Promise.all(Array.from({ length: CONCURRENCY }, async () => { while (next < jobs.length) await jobs[next++](); }));
    console.log(`# fuzz ${name}: ${jobs.length} mutants (seed ${SEED}), statuses ${JSON.stringify(statuses)}, slowest ${slowest} ms, largest RSS ${rss} KB`);
    return { cases: jobs.length, slowest, rss, statuses };
  } finally {
    await rm(base, { recursive: true, force: true });
  }
}

test(`${N} damaged descriptor sets end in snapshot_chain_check's own JSON, never a traceback`, async () => {
  const r = await fuzz("chain", CHAIN, chainSeeds(), (_s, _d) => ({ root: "inputs", qemu_img: "off" }), (s) => /\.(vmdk|vmx|vmsd)$/.test(s.rel) && !s.rel.includes("mono") && !s.rel.endsWith("delta.vmdk") && !s.rel.endsWith("flat.vmdk"));
  assert.equal(r.cases, N);
});

test(`${N} damaged configuration files end in virtualization_inventory's own JSON, never a traceback`, async () => {
  const r = await fuzz("inventory", INVENTORY, inventorySeeds(), (_s, _d) => ({ root: "inputs" }), (s) => !s.rel.endsWith("vmcx"));
  assert.equal(r.cases, N);
});

test(`${N} damaged job records end in backup_audit_normalise's own JSON, never a traceback`, async () => {
  const seeds = auditSeeds();
  const r = await fuzz("audit", AUDIT, seeds, (s, _d) => ({ path: `inputs/${s.rel}`, ...(seeds.find((x) => x.rel === s.rel) as AuditSeed).args }), () => true);
  assert.equal(r.cases, N);
});
