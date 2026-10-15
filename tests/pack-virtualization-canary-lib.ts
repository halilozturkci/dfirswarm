/**
 * The canary harness of the virtualization-backup-forensics tools, as a library: the shapes, the slots and the sweep. The
 * suites that use it are split by tool and by part so that no one file nears the 300 s the node runner allows a file:
 * tests/pack-virtualization-canary.test.ts (chain and inventory, the single-token backstop test, the one block),
 * -canary-audit-{1..4}.test.ts (the audit tool, a quarter of the shapes each) and -canary-backstop*.test.ts (the check
 * alone, with the seal and the shape check removed on purpose).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import {
  AUDIT, CHAIN, INVENTORY, VIRT, prng, qcow2, tool, vhdDifferencing, vhdDynamic, vhdx, vmdkSparse, withCwd,
} from "./pack-virtualization-harness.ts";
import type { Json } from "./pack-virtualization-harness.ts";


export type Shape = { value: string; secret: string; fileSafe: boolean; nameLike: boolean; colonFree: boolean };

function shapes(): Record<string, Shape> {
  const r = prng(20261015);
  const pick = (alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[Math.floor(r() * alphabet.length)]).join("");
  const UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", LO = "abcdefghijklmnopqrstuvwxyz", DIG = "0123456789", AL = UP + LO + DIG, B64 = AL + "+/";
  const spread = (text: string, ch: string, every: number): string => Array.from(text).reduce((out, c, i) => out + (i > 0 && i % every === 0 ? ch : "") + c, "");
  // mixed random text that always carries digits between letters, as a generated secret does
  const mixed = (n: number): string => { let s = ""; while (s.length < n) s += pick(UP, 1) + pick(LO, 1) + pick(DIG, 1) + pick(AL, 2); return s.slice(0, n); };
  const pw = mixed(18);
  const make = (value: string, secret = value): Shape => ({
    value, secret, fileSafe: !value.includes("/") && value.length <= 200, nameLike: /^[A-Za-z0-9_]+$/.test(value), colonFree: !value.includes(":"),
  });
  const s40a = mixed(13) + "/" + mixed(7) + "/" + mixed(18), s40b = mixed(20) + "/" + mixed(19);
  const s40c = mixed(13) + "/" + mixed(26), s40d = mixed(9) + "/" + mixed(15) + "/" + mixed(14), pw2 = mixed(16), pw3 = mixed(17);
  const ghp2 = "ghp_" + mixed(36), akia2 = "AKIA" + pick(UP + DIG, 16), b88 = pick(AL + "+/", 86) + "==";
  const jwt2 = "eyJ" + mixed(24) + "." + "eyJ" + mixed(36) + "." + mixed(43);
  return {
    aws_key: make("AKIA" + pick(UP + DIG, 16)),
    aws_key_after_letter: make("Q" + "AKIA" + pick(UP + DIG, 16)),
    aws_secret_two_slashes: make(s40a),
    aws_secret_one_slash: make(s40b),
    github: make("ghp_" + mixed(36)),
    github_lower: make("ghp_" + pick(LO, 36)),
    github_pat: make("github_pat_" + mixed(22) + "_" + mixed(59)),
    slack: make("xoxb-" + pick(DIG, 12) + "-" + pick(DIG, 12) + "-" + mixed(24)),
    openai: make("sk-proj-" + mixed(40)),
    jwt: make("eyJ" + mixed(20) + "." + "eyJ" + mixed(30) + "." + mixed(43)),
    hex40: make(pick("0123456789abcdef", 40)),
    hex64: make(pick("0123456789abcdef", 64)),
    base64_key16: make(mixed(10) + "/" + mixed(11) + "=="),
    url_userinfo: make(`https://svc:${pw}@h.example.test/x`, pw),
    bare_userinfo: make(`svc:${pw}@h.example.test`, pw),
    userinfo_odd_host: make(`svc:${pw}@-mon1.example.test`, pw),
    storage_userinfo: make(`cephstore:svc:${pw}@mon1.example.test`, pw),
    path_userinfo: make(`/mnt/svc:${pw}@nas/share`, pw),
    long129: make(mixed(129)),
    long600: make(mixed(600)),
    // shapes of the second review: a name shaped like the tool's own paging or values file with a token inside the id, a
    // secret right after a name and `=`, a JWT inside a path, user-info that starts `UPID:` or holds an `@` in the password,
    // prefixes the shared block does not know, and a run of digits (also planted where a tool reads an integer)
    own_path_work: make(`work/${ghp2}/tool-output/a_b-c-0123456789012345.jsonl`, ghp2),
    own_path_store: make(`store/jobs/${akia2}/out/x-values.jsonl`, akia2),
    key_after_eq: make(`key=${s40c}`, s40c),
    aws_secret_after_eq: make(`aws_secret_access_key=${s40d}`, s40d),
    account_key: make(`AccountKey=${b88}`, b88),
    password_after_eq: make(`Password=${pw2}`, pw2),
    jwt_in_path: make(`dd/${jwt2}/vm.vmdk`, jwt2),
    upid_userinfo: make(`UPID:node:0:svc:${pw3}@host.example.test`, pw3),
    at_in_password: make(`svc:p@${pw3}@host.example.test`, pw3),
    gitlab: make("glpat-" + mixed(20)),
    stripe: make("sk_live_" + mixed(24)),
    sendgrid: make("SG." + mixed(22) + "." + mixed(43)),
    digits40: make(pick(DIG, 40)),
    zero_width_split: ((k: string): Shape => make(k.slice(0, 13) + "\u200b" + k.slice(13, 26) + "\u200b" + k.slice(26), k))(mixed(39)),
    // shapes of the third review: a token split by every other invisible or formatting character (bidi isolates, variation
    // selectors, tag characters, combining marks, fillers), a secret name glued to a letter or written in CamelCase, a key
    // without padding, and a real-format AWS secret key
    bidi_isolate_split: ((k: string): Shape => make(spread("ghp_" + k, "\u2066", 9), "ghp_" + k))(mixed(36)),
    variation_selector_split: ((k: string): Shape => make(spread("AKIA" + k, "\ufe0f", 6), "AKIA" + k))(pick(UP + DIG, 16)),
    tag_split: ((k: string): Shape => make(spread(k, "\u{e0041}", 8), k))(mixed(40)),
    combining_split: ((k: string): Shape => make(spread("ghp_" + k, "\u0301", 11), "ghp_" + k))(mixed(36)),
    filler_split: ((k: string): Shape => make(spread("ghp_" + k, "\u3164", 10), "ghp_" + k))(mixed(36)),
    escaped_split: ((k: string): Shape => make(spread("ghp_" + k, "\\u2066", 12), "ghp_" + k))(mixed(36)),
    vnc_password: make(`vncPassword=${pw}`, pw),
    admin_password: make(`adminPassword=${pw2}`, pw2),
    access_token: make(`accessToken: ${pw3}`, pw3),
    secret_access_key: make(`SecretAccessKey: ${s40b}`, s40b),
    odbc_pwd: make(`Server=db1;UID=sa;PWD=${pw2};`, pw2),
    pass_eq: make(`pass=${pw3}`, pw3),
    credential_eq: make(`credential=${pw}`, pw),
    auth_eq: make(`auth=${pw2}`, pw2),
    pgpassword: make(`PGPASSWORD=${pw3}`, pw3),
    mysql_pwd: make(`MYSQL_PWD=${pw}`, pw),
    sig_eq: make(`sig=${pw2}`, pw2),
    cipassword: make(`cipassword: ${pw3}`, pw3),
    base64_key16_nopad: ((k: string): Shape => make(k, k))(mixed(10) + "/" + mixed(5) + "+" + mixed(5)),
    aws_real: make(pick(B64, 40), undefined),
  };
}

/** The pieces a leak would show: every 12 characters of the secret (past a fixed prefix), its base64 and its digests. */
export function needles(shape: Shape): string[] {
  const s = shape.secret;
  const from = /^(AKIA|ghp_|github_pat_|xoxb-|sk-proj-|eyJ|glpat-|sk_live_|SG\.)/.exec(s)?.[0].length ?? 0;
  const out = new Set<string>();
  for (let k = from; k + 12 <= s.length; k++) for (const v of [s.slice(k, k + 12), s.slice(k, k + 12).toLowerCase(), s.slice(k, k + 12).toUpperCase()]) out.add(v);
  out.add(Buffer.from(s).toString("base64").slice(0, 16));
  out.add(Buffer.from(s).toString("base64url").slice(0, 16));
  for (const algo of ["sha256", "sha1", "md5"]) out.add(createHash(algo).update(s).digest("hex").slice(0, 16));
  out.add(Buffer.from(s).toString("hex").slice(0, 24));
  return [...out];
}

// ---- slots: one file per slot, so that a damaged slot cannot hide another ------------------------------------------

export type Files = Record<string, string | Buffer>;

export function chainFiles(c: Shape): Files {
  const v = c.value, f: Files = {};
  const desc = (lines: string[]): string => ["# Disk DescriptorFile", "version=1", ...lines, "", "# Extent description"].join("\n") + "\n";
  f["vm/hint.vmdk"] = desc(["CID=aabbccd1", "parentCID=aabbccd0", 'createType="vmfsSparse"', `parentFileNameHint="${v}"`, 'RW 8 FLAT "x"']);
  f["vm/extent.vmdk"] = desc(["CID=aabbccd2", "parentCID=ffffffff", 'createType="monolithicFlat"', `RW 8 FLAT "${v}" 0`]);
  if (c.nameLike) f["vm/type.vmdk"] = desc(["CID=aabbccd3", "parentCID=ffffffff", 'createType="monolithicFlat"', `RW 8 ${v} "x"`]);
  f["vm/create.vmdk"] = desc(["CID=aabbccd4", "parentCID=ffffffff", `createType="${v}"`, 'RW 8 ZERO']);
  f["vm/cid.vmdk"] = desc([`CID=${v}`, `parentCID=${v}`, 'createType="monolithicFlat"', 'RW 8 ZERO']);
  f["vm/ddb.vmdk"] = desc(["CID=aabbccd5", "parentCID=ffffffff", `encoding="${v}"`, `isNativeSnapshot="${v}"`, 'RW 8 ZERO', `ddb.uuid = "${v}"`, `ddb.adapterType = "${v}"`]);
  f["vm/version.vmdk"] = desc([`version=${v}`, "CID=aabbccd6", "parentCID=ffffffff", 'RW 8 ZERO']);
  if (/^[0-9]+$/.test(v)) f["vm/sectors.vmdk"] = desc(["CID=aabbccda", "parentCID=ffffffff", `RW ${v} FLAT "x" ${v}`, `RW ${v} ZERO`]);    // integers a tool reads
  f["vm/sparse.vmdk"] = vmdkSparse({ descriptor: desc(["CID=aabbccd7", "parentCID=aabbccd0", `parentFileNameHint="${v}"`, `RW 8 SPARSE "${v}"`]) });
  f["vm/vm.vmx"] = `.encoding = "UTF-8"\ndisplayName = "${v}"\nscsi0:0.fileName = "${v}"\nide1:0.fileName = "${v}"\n`;
  f["vm/vm.vmsd"] = [".encoding = \"UTF-8\"", `snapshot.lastUID = "${v}"`, `snapshot.current = "${v}"`, `snapshot.numSnapshots = "${v}"`,
    `snapshot0.uid = "${v}"`, `snapshot0.filename = "${v}"`, `snapshot0.displayName = "${v}"`, `snapshot0.description = "${v}"`, `snapshot0.parent = "${v}"`,
    `snapshot0.createTimeHigh = "${v}"`, `snapshot0.createTimeLow = "${v}"`, `snapshot0.disk0.fileName = "${v}"`, `snapshot0.type = "${v}"`, ...(/^[0-9]+$/.test(v) ? [`snapshot${v}.displayName = "x"`] : [])].join("\n") + "\n";
  f["vm/delta-vm.vmx"] = `scsi0:0.fileName = "hint.vmdk"\n`;
  f["q/backing.qcow2"] = qcow2({ backing: v });
  f["q/format.qcow2"] = qcow2({ backing: "backing.qcow2", backingFormat: v });
  f["q/snap.qcow2"] = qcow2({ snapshots: [{ id: v, name: v, date: 1 }] });
  const ext = qcow2({ incompat: 4n });
  const nm = Buffer.from(v);
  Buffer.concat([Buffer.from([0x44, 0x41, 0x54, 0x41]), Buffer.from([0, 0, (nm.length >> 8) & 255, nm.length & 255]), nm, Buffer.alloc((-nm.length) & 7), Buffer.alloc(8)]).copy(ext, 104);
  f["q/datafile.qcow2"] = ext;
  const uid = "11111111-aaaa-bbbb-cccc-000000000001";
  f["hv/base.vhd"] = vhdDynamic({ uid });
  f["hv/name.vhd"] = vhdDifferencing({ uid: "11111111-aaaa-bbbb-cccc-000000000002", parentUid: uid, parentName: v.slice(0, 250) });
  f["hv/loc.vhd"] = vhdDifferencing({ uid: "11111111-aaaa-bbbb-cccc-000000000003", parentUid: uid, parentName: "base.vhd", locators: [{ code: "W2ru", text: v }, { code: "MacX", text: v, encoding: "utf8" }] });
  f["hv/x.avhdx"] = vhdx({ diskId: "AAAAAAAA-0000-4000-8000-000000000002", parent: { linkage: v, linkage2: v, relative: v, absolute: v, volume: v } });
  if (c.fileSafe) {
    f[`vm/${v}.vmdk`] = desc(["CID=aabbccd8", "parentCID=ffffffff", 'RW 8 ZERO']);
    f[`vm/n.${v}`] = "x";
    f[`vm/${v}.lck/x`] = "x";
  } else {
    // a value with `/` (or too long for one name) is planted across directory names, in pieces of at most 200 characters
    f[`vm/d-${v.match(/.{1,200}/g)?.join("/")}/a.vmdk`] = desc(["CID=aabbccd9", "parentCID=ffffffff", 'RW 8 ZERO']);
  }
  return f;
}

export function inventoryFiles(c: Shape): Files {
  const v = c.value, f: Files = {};
  f["vm/web.vmx"] = [".encoding = \"UTF-8\"", `displayName = "${v}"`, `guestOS = "${v}"`, `nvram = "${v}"`, `uuid.bios = "${v}"`, `uuid.location = "${v}"`, `vc.uuid = "${v}"`,
    `memsize = "${v}"`, `numvcpus = "${v}"`, `firmware = "${v}"`, `config.version = "${v}"`, `virtualHW.version = "${v}"`,
    `ethernet0.networkName = "${v}"`, `ethernet0.address = "${v}"`, `ethernet0.virtualDev = "${v}"`,
    `scsi0:0.fileName = "${v}"`, `scsi0:0.deviceType = "${v}"`, `scsi0:0.mode = "${v}"`, `scsi0:0.present = "${v}"`, `scsi0:0.redo = "${v}"`,
    `RemoteDisplay.vnc.password = "${v}"`, `annotation = "${v}"`, ...(c.nameLike ? [`x.${v}.password = "y"`, `${v} = "y"`] : [])].join("\n") + "\n";
  f["vm/web.vmsd"] = [".encoding = \"UTF-8\"", `snapshot.numSnapshots = "${v}"`, `snapshot.current = "${v}"`, `snapshot.lastUID = "${v}"`, `snapshot0.uid = "${v}"`,
    `snapshot0.filename = "${v}"`, `snapshot0.displayName = "${v}"`, `snapshot0.parent = "${v}"`, `snapshot0.createTimeHigh = "${v}"`, `snapshot0.createTimeLow = "${v}"`,
    `snapshot0.disk0.fileName = "${v}"`, `snapshot0.type = "${v}"`, ...(/^[0-9]+$/.test(v) ? [`snapshot${v}.displayName = "x"`] : [])].join("\n") + "\n";
  f["lv/domain.xml"] = `<domain type='${v}'><name>${v}</name><uuid>${v}</uuid><memory unit='${v}'>${v}</memory><vcpu>${v}</vcpu><os><type arch='${v}' machine='${v}'>hvm</type></os><devices>`
    + `<disk type='file' device='${v}'><driver name='qemu' type='${v}'/><source file='${v}'/><backingStore type='file'><format type='${v}'/><source file='${v}'/><backingStore/></backingStore><target dev='${v}' bus='${v}'/></disk>`
    + `<disk type='network' device='disk'><source protocol='${v}' name='${v}'/><target dev='vdb'/></disk><graphics type='vnc' passwd='${v}'/></devices></domain>`;
  f["lv/snap.xml"] = `<domainsnapshot><name>${v}</name><description>${v}</description><state>${v}</state><creationTime>${v}</creationTime><parent><name>${v}</name></parent><memory snapshot='${v}'/><disks><disk name='${v}' snapshot='${v}'><source file='${v}'/></disk></disks><domain><name>${v}</name></domain></domainsnapshot>`;
  f["lv/pool.xml"] = `<pool type='${v}'><name>${v}</name><uuid>${v}</uuid><target><path>${v}</path></target></pool>`;
  f["esxi/vmInventory.xml"] = `<ConfigRoot><ConfigEntry id="${v}"><objID>${v}</objID><vmxCfgPath>${v}</vmxCfgPath></ConfigEntry><ConfigEntry id="2"><objID>2</objID><vmxCfgPath>/vmfs/volumes/${v}/a/a.vmx</vmxCfgPath></ConfigEntry></ConfigRoot>`;
  const sect = v.includes("]") ? "s1" : v;
  f[`pve/nodes/${c.fileSafe ? v : "pve1"}/qemu-server/100.conf`] = [`name: ${v}`, `ostype: ${v}`, `machine: ${v}`, `cores: ${v}`, `memory: ${v}`, `bios: ${v}`, `lock: ${v}`, `tags: ${v}`,
    `scsi0: ${v},size=${v},backup=${v}`, `scsi1: local:${v},size=8G`, `virtio0: ${v}:vm-100-disk-1.qcow2`, `net0: virtio=${v},bridge=${v}`, `cipassword: ${v}`, `sshkeys: ${v}`, `parent: ${v}`,
    `description: ${v}`, "", `[${sect}]`, `parent: ${v}`, `snaptime: ${v}`, `vmstate: ${v}`, `scsi0: ${v},size=1G`, `cipassword: ${v}`, "", `[special:${sect}]`, `cipassword: ${v}`, ""].join("\n");
  f["pve/lxc/200.conf"] = [`hostname: ${v}`, `rootfs: ${v},size=8G`, `mp0: ${v},mp=/data`, `arch: ${v}`, ""].join("\n");
  f["pve/storage.cfg"] = [`dir: ${v.replace(/\s/g, "")}`, `\tpath ${v}`, `\tcontent ${v}`, "", "pbs: backup", `\tdatastore ${v}`, `\tserver ${v}`, `\tusername ${v}`, `\tpassword ${v}`, `\tfingerprint ${v}`, ""].join("\n");
  if (c.fileSafe) {
    f[`vm/${v}.vmx`] = `displayName = "x"\n`;
    f[`vm/n.${v}`] = "x";
  } else {
    f[`vm/d-${v.match(/.{1,200}/g)?.join("/")}/a.vmx`] = `displayName = "x"\n`;
  }
  return f;
}

const hex = (n: number): string => n.toString(16).toUpperCase().padStart(8, "0");

export type AuditCall = { args: Record<string, unknown>; files: Files };

export function auditCalls(c: Shape): AuditCall[] {
  const v = c.value, T = 1_700_000_000;
  const calls: AuditCall[] = [];
  const nc = c.colonFree ? v : v.replace(/:/g, "_");
  calls.push({ args: { path: "inputs/a/index", format: "pve_task_index" }, files: { "a/index": [
    `UPID:${nc}:${hex(1)}:${hex(2)}:${hex(T)}:${nc}:${nc}:${nc}: ${hex(T + 5)} ${v}`,
    `UPID:pbs1:${hex(1)}:${hex(2)}:${hex(3)}:${hex(T)}:${nc}:${nc}:${nc}: ${hex(T + 5)} ${v}`,
    `UPID:pve1:${hex(1)}:${hex(2)}:${hex(T)}:vzdump::root@pam: ${hex(T + 5)} ${v}`, `not a upid ${v}`].join("\n") + "\n" } });
  calls.push({ args: { path: "inputs/a/task.log", format: "pve_vzdump_log" }, files: { "a/task.log": [
    `INFO: starting new backup job: vzdump ${v}`, "INFO: Starting Backup of VM 100 (qemu)", `INFO: Backup started at ${v}`, `INFO: creating vzdump archive '${v}'`,
    `INFO: removing backup '${v}'`, `ERROR: Backup of VM 101 failed - ${v}`, `WARN: ${v}`, `INFO: ${v}`, `TASK ERROR: ${v}`, `${v}`].join("\n") + "\n" } });
  const csv = ["When,Op,Res,Who,Obj,Host,Job,Msg", `${v},${v},${v},${v},${v},${v},${v},${v}`, `2024-01-05T02:00:00Z,${v},${v},${v},${v},${v},${v},${v}`].join("\n") + "\n";
  const map = { time: "When", action: "Op", result: "Res", actor: "Who", object: "Obj", host: "Host", job: "Job", message: "Msg" };
  for (const time_format of ["iso8601", "epoch_seconds", "epoch_milliseconds", "strptime:%Y-%m-%d %H:%M:%S"]) {
    calls.push({ args: { path: "inputs/a/x.csv", format: "declared_csv", mapping: map, time_format, category_map: { [v.slice(0, 200).toLowerCase()]: "restore" } }, files: { "a/x.csv": csv } });
  }
  calls.push({ args: { path: "inputs/a/x.csv", format: "declared_csv", mapping: { ...map, actor: v.slice(0, 200) } }, files: { "a/x.csv": csv } });
  const j = JSON.stringify;
  calls.push({ args: { path: "inputs/a/x.jsonl", format: "declared_jsonl", mapping: { time: "t", action: "a.b", result: "r", actor: "u", object: "o", host: "h", job: v.slice(0, 200), message: "m" } },
    files: { "a/x.jsonl": `${j({ t: v, a: { b: v }, r: v, u: v, o: { k: v }, h: [v], m: v, [v]: v })}\n${j({ t: 1700000000, a: { b: v }, r: v, u: v })}\n${j([v])}\n${v}\n` } });
  calls.push({ args: { path: "inputs/a/x.xml", format: "declared_xml", record_tag: "R", mapping: { time: "@when", action: "A", result: "Res@v", actor: "W/N", object: "@id", message: "M" } },
    files: { "a/x.xml": `<?xml version="1.0"?><X><R when="${v}" id="${v}"><A>${v}</A><Res v="${v}"/><W><N>${v}</N></W><M>${v}</M></R><R><A>${v}</A></R><R>${"<Z/>".repeat(3)}${v}</R></X>` } });
  calls.push({ args: { path: `inputs/a/${c.fileSafe ? v : "none"}`, paths: [`inputs/${v}`], format: "pve_task_index" }, files: {} });
  calls.push({ args: { path: "inputs/a/index", product: v.slice(0, 200) }, files: { "a/index": "UPID:x\n" } });
  calls.push({ args: { path: "inputs/a/u.txt" }, files: { "a/u.txt": `${v}\n` } });
  return calls;
}

// ---- running and searching -------------------------------------------------------------------------------------------

export async function plant(cwd: string, files: Files): Promise<void> {
  for (const [rel, data] of Object.entries(files)) {
    const full = join(cwd, "inputs", rel);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, data);
  }
}

/** Every file a call made outside the evidence, with its name: (path, bytes). */
export async function made(cwd: string): Promise<[string, string][]> {
  const out: [string, string][] = [];
  const walk = async (d: string, rel: string): Promise<void> => {
    for (const e of await readdir(d, { withFileTypes: true }).catch(() => [])) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (r === "inputs" || r === "bin" || r === "lib-eval" || /^inputs\//.test(r)) continue;
      if (e.isDirectory()) { out.push([r, ""]); await walk(join(d, e.name), r); } else out.push([r, await readFile(join(d, e.name), "latin1")]);
    }
  };
  await walk(cwd, "");
  return out;
}

const MODES = [{ job: false, limit: 1 }, { job: false, limit: 200 }, { job: true, limit: 1 }, { job: true, limit: 200 }];
let jobSeq = 0;

export async function sweep(script: string, shapeName: string, shape: Shape, calls: AuditCall[], label: string): Promise<{ runs: number; leaks: string[] }> {
  const leaks: string[] = [];
  let runs = 0;
  const wanted = needles(shape);
  for (const mode of MODES) {
    await withCwd(async (cwd) => {
      for (const call of calls) await plant(cwd, call.files);
      for (const call of calls) {
        jobSeq += 1;
        const env: Record<string, string> = mode.job ? { JOB_ID: `j${String(900000 + jobSeq).padStart(6, "0")}`, OUT: join(cwd, `out${jobSeq}`) } : {};
        if (mode.job) await mkdir(env.OUT, { recursive: true });
        const args = { ...call.args, limit: mode.limit, ...(mode.job ? { write_text: true } : {}) };
        const run = await tool(script, cwd, args, env);
        runs += 1;
        assert.doesNotMatch(run.stderr, /Traceback/, `${label} ${shapeName}: ${run.stderr.slice(-300)}`);
        const doc: Json = JSON.parse(run.stdout);
        assert.ok(["complete", "partial", "failed"].includes(doc.status), `${label} ${shapeName}: status ${doc.status}`);
        assert.equal(doc.boundary?.strings_replaced_by_the_check ?? 0, 0, `${label} ${shapeName}: the backstop had to replace ${JSON.stringify(doc.boundary?.replaced_at)} (the seal let a string through)`);
        const texts: [string, string][] = [["stdout", run.stdout], ["stderr", run.stderr]];
        for (const [rel, bytes] of await made(cwd)) {
          texts.push([`name of ${rel}`, rel]);
          if (/(^|\/)(chain|inventory|audit)-values\.jsonl$/.test(rel)) {
            assert.equal((await stat(join(cwd, rel))).mode & 0o777, 0o600, `${rel} is private`);
            continue;     // the one file that holds originals, by design, when a job asks for it
          }
          texts.push([rel, bytes]);
        }
        for (const [where, text] of texts) {
          for (const n of wanted) if (text.includes(n)) leaks.push(`${label} ${shapeName} job=${mode.job} limit=${mode.limit} args=${JSON.stringify(call.args).slice(0, 80)}: ${where} holds "${n}" near "${text.slice(Math.max(0, text.indexOf(n) - 60), text.indexOf(n) + 30).replace(/\s+/g, " ")}"`);
        }
      }
    });
  }
  return { runs, leaks };
}

export const ALL = shapes();
const ONLY = process.env.VIRT_CANARY_SHAPES?.split(",");
export const PICKED = Object.entries(ALL).filter(([k]) => !ONLY || ONLY.includes(k));

const UNSEALED = `
import importlib.util, io, json, sys
spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
def let_through(value, depth=0):           # the seal removed on purpose: everything goes out as the code made it
    return json.loads(json.dumps(value, default=str))
tool.seal = let_through
tool.Shower.__call__ = lambda self, text, where=None, field=None: None if text is None else tool.Shown(str(text))   # and the shape check before it
sys.stdin = io.TextIOWrapper(io.BytesIO(sys.argv[2].encode()))
try:
    code = tool.main()
except SystemExit as exc:
    code = exc.code
sys.exit(code or 0)
`;

export function unsealed(script: string, cwd: string, args: unknown): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn("python3", ["-c", UNSEALED, script, JSON.stringify(args)], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    const o: Buffer[] = [], e: Buffer[] = [];
    child.stdout.on("data", (b: Buffer) => o.push(b));
    child.stderr.on("data", (b: Buffer) => e.push(b));
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(o).toString(), stderr: Buffer.concat(e).toString() }));
  });
}


type Build = (c: Shape) => AuditCall[];
export const TOOLS: Record<string, { script: string; build: Build }> = {
  snapshot_chain_check: { script: CHAIN, build: (c) => [{ args: { root: "inputs" }, files: chainFiles(c) }] },
  virtualization_inventory: { script: INVENTORY, build: (c) => [{ args: { root: "inputs" }, files: inventoryFiles(c) }] },
  backup_audit_normalise: { script: AUDIT, build: auditCalls },
};

/** The canary sweep of one tool: every shape (every `parts`th one from `part`) in every slot, in and out of a job. */
export function registerCanary(label: string, part = 0, parts = 1): void {
  const { script, build } = TOOLS[label];
  const picked = PICKED.filter((_, i) => i % parts === part);
  const suffix = parts > 1 ? ` (part ${part + 1} of ${parts})` : "";
  test(`${label}: no canary of ${picked.length} shapes, planted in every slot, reaches an answer, a paging file or a file name, in or out of a job, with a page of one row or two hundred${suffix}`, async () => {
    let runs = 0;
    const leaks: string[] = [];
    for (const [name, shape] of picked) {
      const r = await sweep(script, name, shape, build(shape), label);
      runs += r.runs;
      leaks.push(...r.leaks);
    }
    console.log(`# canary ${label}${suffix}: ${runs} runs, ${picked.length} shapes, ${leaks.length} leak(s)`);
    const places = new Map<string, number>();
    for (const l of leaks) {
      const key = l.replace(/ job=\S+ limit=\d+ args=.*?: /, " ").replace(/ holds .*/, "").replace(/-\d{16}\.jsonl/, ".jsonl").replace(/out\d+\//, "out/");
      places.set(key, (places.get(key) ?? 0) + 1);
    }
    for (const [k, n] of places) console.log(`#   ${n} ${k}`);
    assert.deepEqual(leaks.slice(0, 20), [], `${leaks.length} leak(s)`);
  });
}

/** The check on the way out alone (the seal and the shape check removed on purpose), every shape in every slot of the tools named. */
export function registerBackstopAlone(labels: string[]): void {
  test(`the backstop alone, for every shape in every slot of ${labels.join(" and ")}: with the seal and the shape check removed on purpose, no canary reaches the answer, an error answer, a paging file or a file name`, async () => {
    let runs = 0, replaced = 0;
    const leaks: string[] = [];
    for (const label of labels) {
      const { script, build } = TOOLS[label];
      for (const [name, shape] of PICKED) {
        const calls = build(shape);
        await withCwd(async (cwd) => {
          for (const call of calls) await plant(cwd, call.files);
          for (const call of calls) {
            const run = await unsealed(script, cwd, { ...call.args, limit: 1 });
            runs += 1;
            assert.doesNotMatch(run.stderr, /Traceback/, `${label} ${name}: ${run.stderr.slice(-300)}`);
            const doc: Json = JSON.parse(run.stdout);
            replaced += doc.boundary?.strings_replaced_by_the_check ?? 0;
            const texts: [string, string][] = [["stdout", run.stdout]];
            for (const [rel, bytes] of await made(cwd)) texts.push([`name of ${rel}`, rel], [rel, bytes]);
            for (const [where, text] of texts) for (const n of needles(shape)) if (text.includes(n)) leaks.push(`${label} ${name} ${JSON.stringify(call.args).slice(0, 60)}: ${where} holds "${n}"`);
          }
        });
      }
    }
    console.log(`# backstop alone, ${labels.join(" and ")}: ${runs} runs, ${PICKED.length} shapes, ${replaced} string(s) replaced, ${leaks.length} leak(s)`);
    assert.ok(replaced > 0);
    assert.deepEqual(leaks.slice(0, 20), [], `${leaks.length} leak(s)`);
  });
}
