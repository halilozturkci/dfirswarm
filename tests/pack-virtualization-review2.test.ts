/**
 * virtualization-backup-forensics: the second review's findings, each held by a test that failed on the code it reviewed.
 *
 * The way out (the shared BOUNDARY block of the three tools): a name of the paging-file or values-file shape is shown
 * whole only when this run made it; a secret right after `=` is withheld; the shared block's rules run on the whole
 * string first, so that a JWT in a path is found whole; user-info runs to the last `@` before the host; a string that
 * starts `UPID:` is judged like any other; an integer of more than 18 digits is withheld; a value after a name that says
 * it is a secret is withheld; and the backstop's second check, written apart from the rules, still catches what a gap in
 * the rules would let through (it is shown here with the seal, the shape check and the rules all removed on purpose).
 *
 * The readers: one XML file in an encoding the reader does not know fails that file, not the run; a header whose checksum
 * fails is named and makes the answer partial; a chain the max_chain_depth limit stopped makes the answer partial; a
 * Proxmox Backup Server worker id is withheld in its escaped form whenever its unescaped form is, and a task whose status
 * is `unknown` is not called an error; the snapshot sections of one Proxmox configuration are named up to a cap and paged
 * whole as snapshot rows.
 *
 * Every fixture is built from the formats' public descriptions (tests/pack-virtualization-harness.ts), never from a tool's
 * output.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import {
  AUDIT, CHAIN, INVENTORY, prng, put, qcow2, tool, vhdDynamic, vhdFooter, vhdx, vmdkDescriptor, vmx, withCwd,
} from "./pack-virtualization-harness.ts";
import type { Json } from "./pack-virtualization-harness.ts";

const r = prng(20261016);
const pick = (alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[Math.floor(r() * alphabet.length)]).join("");
const UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", LO = "abcdefghijklmnopqrstuvwxyz", DIG = "0123456789", AL = UP + LO + DIG, B64 = AL + "+/";
const mixed = (n: number): string => { let s = ""; while (s.length < n) s += pick(UP, 1) + pick(LO, 1) + pick(DIG, 1) + pick(AL, 2); return s.slice(0, n); };
const GHP = "ghp_" + mixed(36);
const AKIA = "AKIA" + pick(UP + DIG, 16);
const DASHED = mixed(14) + "-" + mixed(14) + "-" + mixed(14);      // a token whose `-` a systemd unescape turns into `/`

/** Every twelve characters of a secret (past a fixed prefix): a leak shows at least one of them. */
function pieces(secret: string, from = 0): string[] {
  const out: string[] = [];
  for (let k = from; k + 12 <= secret.length; k++) out.push(secret.slice(k, k + 12));
  return out;
}

async function everything(cwd: string): Promise<string> {
  const parts: string[] = [];
  const walk = async (d: string, rel: string): Promise<void> => {
    for (const e of await readdir(d, { withFileTypes: true }).catch(() => [])) {
      const p = rel ? `${rel}/${e.name}` : e.name;
      if (p === "inputs" || p.startsWith("inputs/")) continue;
      parts.push(p);
      if (e.isDirectory()) await walk(join(d, e.name), p);
      else if (!/-values\.jsonl$/.test(e.name)) parts.push(await readFile(join(d, e.name), "latin1"));
    }
  };
  await walk(cwd, "");
  return parts.join("\n");
}

function assertNoPiece(text: string, secret: string, what: string, from = 0): void {
  for (const p of pieces(secret, from)) assert.equal(text.includes(p), false, `${what} holds "${p}" near ${JSON.stringify(text.slice(Math.max(0, text.indexOf(p) - 60), text.indexOf(p) + 30))}`);
}

// ---- unit level: the block's functions, loaded from each tool --------------------------------------------------------

const PROBE = `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
data = json.load(sys.stdin)
print(json.dumps({"sealed": [tool.seal_text(s) for s in data["texts"]], "suspect": [tool._suspect(s) if hasattr(tool, "_suspect") else "no second check" for s in data["checked"]],
                  "ints": [tool.seal(int(v)) for v in data["ints"]]}))
`;

async function probe(script: string, texts: string[], checked: string[] = [], ints: string[] = []): Promise<{ sealed: string[]; suspect: (string | null)[]; ints: unknown[] }> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", PROBE, script]);
    const o: Buffer[] = [], e: Buffer[] = [];
    child.stdout.on("data", (b: Buffer) => o.push(b));
    child.stderr.on("data", (b: Buffer) => e.push(b));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) return reject(new Error(Buffer.concat(e).toString()));
      resolve(JSON.parse(Buffer.concat(o).toString()));
    });
    child.stdin.end(JSON.stringify({ texts, checked, ints }));
  });
}

const slashed = (slashes: number): string => {
  const s = Array.from(pick(AL + "+", 40));
  for (let i = 0; i < slashes; i++) s[4 + Math.floor(r() * 32)] = "/";
  return s.join("");
};

test("a secret key right after `=` (key=, aws_secret_access_key=, AccountKey=) is withheld as it is when it stands alone: 0 of 600 random keys with one or two `/` are shown", async () => {
  const keys = Array.from({ length: 300 }, () => slashed(1)).concat(Array.from({ length: 300 }, () => slashed(2))).filter((k) => /[A-Za-z]/.test(k));
  const texts = keys.flatMap((k, i) => [`${["key", "aws_secret_access_key", "SecretAccessKey", "AccountKey"][i % 4]}=${k}`]);
  for (const script of [CHAIN, INVENTORY, AUDIT]) {
    const got = await probe(script, texts);
    const alone = await probe(script, keys);
    let shownAfterEq = 0, shownAlone = 0;
    got.sealed.forEach((s, i) => { if (s.includes(keys[i])) shownAfterEq++; });
    alone.sealed.forEach((s, i) => { if (s === keys[i]) shownAlone++; });
    assert.equal(shownAfterEq, shownAlone, `${script}: after "=" ${shownAfterEq} shown, alone ${shownAlone}`);
    assert.ok(shownAfterEq <= 3, `${script}: ${shownAfterEq} of ${keys.length} keys shown whole after "="`);
  }
});

test("a JWT inside a path is found whole before the added rules split it: no twelve characters of 300 signatures are shown", async () => {
  const b64u = AL + "_-";
  const cases = Array.from({ length: 300 }, () => {
    const jwt = "eyJ" + pick(b64u, 30) + ".eyJ" + pick(b64u, 40) + "." + pick(b64u, 43);
    return { text: `${pick(LO, 2)}/${jwt}/${pick(LO, 2)}.vmdk`, jwt };
  });
  const got = await probe(CHAIN, cases.map((c) => c.text));
  got.sealed.forEach((s, i) => assertNoPiece(s, cases[i].jwt, `JWT in a path ${cases[i].text}`, 3));
});

test("user-info is withheld to the last `@` before the host, also in a URL, and a string that starts `UPID:` is judged like any other", async () => {
  const pw = mixed(16);
  const texts = [`svc:p@${pw}@host.example.test`, `https://svc:p@${pw}@host.example.test/share`, `UPID:node:0:svc:${pw}@host.example.test`, `cephstore:svc:${pw}@mon1.example.test`];
  for (const script of [CHAIN, INVENTORY, AUDIT]) {
    const got = await probe(script, texts);
    got.sealed.forEach((s, i) => assertNoPiece(s, pw, `${texts[i]} -> ${s}`));
    assert.match(got.sealed[0], /^<userinfo withheld \d+ characters>@host\.example\.test$/);
  }
});

test("the prefixes the shared block does not know (glpat-, sk_live_, SG., AIza), a value after a name that says it is a secret, and a run of more than 18 digits are withheld; an integer of more than 18 digits is withheld by its size", async () => {
  const secrets = ["glpat-" + mixed(20), "sk_live_" + mixed(24), "SG." + mixed(22) + "." + mixed(43), "AIza" + mixed(35)];
  const prefixes = [6, 8, 3, 4];
  const values = [mixed(14), mixed(10), mixed(12), mixed(12), pick(B64, 86) + "=="];
  const named = [`Password=${values[0]}`, `password: ${values[1]}`, `client_secret=${values[2]}`, `api_key="${values[3]}"`, `DefaultEndpointsProtocol=https;AccountName=x;AccountKey=${values[4]}`];
  const digits = [pick(DIG, 19), pick(DIG, 25)];
  const got = await probe(CHAIN, [...secrets, ...named, ...digits], [], ["1234567890123456789012345678901234567890", "999999999999999999", "1000000000000000000"]);
  secrets.forEach((s, i) => assertNoPiece(got.sealed[i], s, s, prefixes[i]));
  named.forEach((s, i) => {
    const sealed = got.sealed[secrets.length + i];
    assert.equal(sealed.includes(values[i]), false, `${s} -> ${sealed}`);
    assertNoPiece(sealed, values[i], `${s} -> ${sealed}`);
  });
  digits.forEach((d, i) => assert.equal(got.sealed[secrets.length + named.length + i].includes(d), false, d));
  assert.match(String(got.ints[0]), /^<withheld: an integer of \d+ bits>$/);
  assert.equal(got.ints[1], 999999999999999999, "eighteen digits are a number");
  assert.match(String(got.ints[2]), /^<withheld: an integer of 60 bits>$/);
});

test("the second check passes what an answer shows: GUIDs, VMware and VMFS identifiers, versions, VM, file and snapshot names, hosts, paths, times, Proxmox volume names", async () => {
  const realistic = [
    "6F1E2A3B-1C2D-4E5F-8A9B-0C1D2E3F4A5B", "{6f1e2a3b-1c2d-4e5f-8a9b-0c1d2e3f4a5b}", "56 4d 2c 1f 0a 9b 8c 7d-6e 5f 4a 3b 2c 1d 0e 0f", "60 00 C2 9a 1b 2c 3d 4e 5f 60 71 82 93 a4 b5 c6",
    "ESXi 8.0 Update 2 (Build 22380479)", "vmx-19", "pc-q35-8.1+pve0", "Microsoft Windows Server 2022 (64-bit)", "windows2019srvNext-64", "10.0.20348.2113",
    "WebServer01", "PROD-SQL01-Cluster-NodeA", "PostgresPrimaryDbBackup07", "win2019-dc01", "ubuntu-22.04-template", "k8s-worker-node-17", "Exchange 2019 (Mailbox)",
    "vm-000001-delta.vmdk", "Win10-x64-000003-sesparse.vmdk", "web01-flat.vmdk", "Windows10_22H2_Pro_x64_en-US.iso", "ElasticQaMasterCrm96.qcow2",
    "Before patching 2024-01-15", "pre-upgrade_2023_11_14", "VEEAM BACKUP TEMPORARY SNAPSHOT", "autodaily202401150300",
    "esx01.corp.example.com", "pve-node3.lab.local", "ip-10-0-3-17.ec2.internal", "fe80::1c2d:3e4f:5a6b:7c8d",
    "/vmfs/volumes/datastore1/web/web.vmx", "[datastore1] web/web-000001.vmdk", "/var/lib/libvirt/images/WebServer01.qcow2", "local-lvm:vm-100-disk-0",
    "local:backup/vzdump-qemu-100-2024_01_05-02_00_00.vma.zst", "C:\\ProgramData\\Microsoft\\Windows\\Hyper-V\\Virtual Machines\\6F1E2A3B-1C2D-4E5F-8A9B-0C1D2E3F4A5B.vmcx",
    "2024-01-05T02:00:00Z", "root@pam", "backup@pbs!nightly", "00:50:56:a1:b2:c3", "virtio=BC:24:11:2A:3B:4C,bridge=vmbr0,firewall=1",
    "work/s1/tool-output/snapshot_chain_check-disks-0123456789012345.jsonl", "match_via_parent_linkage2", "keys_that_look_like_credentials",
    "Nothing withheld or shortened is kept. write_text: true, in a job run with secret_output: true, keeps the original of each in a private file under $OUT.",
    "<token-shaped text withheld 40 characters>", "Password=<secret withheld 14 characters>", "<withheld: an integer of 133 bits>",
  ];
  for (const script of [CHAIN, INVENTORY, AUDIT]) {
    const got = await probe(script, realistic, realistic);
    const sealedAgain = await probe(script, [], got.sealed);
    assert.deepEqual(sealedAgain.suspect.map((s, i) => s ? `${got.sealed[i]}: ${s}` : null).filter(Boolean), [], `${script}: the second check would replace a sealed realistic string`);
  }
});

// ---- end to end: the slots that printed a secret --------------------------------------------------------------------

test("a name shaped like the tool's own paging or values file, with a token inside the id, is withheld in every tool; the names the run made itself are shown whole", async () => {
  const ownWork = `work/${GHP}/tool-output/a_b-c-0123456789012345.jsonl`, ownStore = `store/jobs/${AKIA}/out/x-values.jsonl`;
  for (const job of [false, true]) {
    await withCwd(async (cwd) => {
      const env: Record<string, string> = job ? { JOB_ID: "j000777", OUT: join(cwd, "out") } : {};
      if (job) await mkdir(env.OUT, { recursive: true });
      await put(cwd, "inputs/vm/a.vmdk", vmdkDescriptor({ cid: "aabbccd1", parentCid: "aabbccd0", createType: "vmfsSparse", parentHint: ownWork, extents: [{ sectors: 8, type: "FLAT", name: ownStore }] }));
      await put(cwd, "inputs/vm/b.vmdk", vmdkDescriptor({ cid: "aabbccd2", parentHint: ownStore, extents: [{ sectors: 8, type: "FLAT", name: ownWork }] }));
      await put(cwd, "inputs/vm/a.vmx", vmx([["displayName", ownWork], ["scsi0:0.fileName", ownStore], ["guestOS", ownStore]]));
      await put(cwd, "inputs/vm/b.vmx", vmx([["displayName", ownStore]]));
      await put(cwd, "inputs/a/x.jsonl", [JSON.stringify({ t: 1700000000, a: ownWork, u: ownStore }), JSON.stringify({ t: 1700000001, a: ownStore, u: ownWork })].join("\n") + "\n");
      for (const [script, args] of [[CHAIN, { root: "inputs/vm" }], [INVENTORY, { root: "inputs/vm" }],
        [AUDIT, { path: "inputs/a/x.jsonl", format: "declared_jsonl", mapping: { time: "t", action: "a", actor: "u" }, time_format: "epoch_seconds" }]] as const) {
        const run = await tool(script, cwd, { ...args, limit: 1, ...(job ? { write_text: true } : {}) }, env);
        assert.doesNotMatch(run.stderr, /Traceback/);
        const doc: Json = JSON.parse(run.stdout);
        const all = run.stdout + "\n" + await everything(cwd);
        assertNoPiece(all, GHP, `${script} job=${job}`, 4);
        assertNoPiece(all, AKIA, `${script} job=${job}`, 4);
        assert.equal(doc.boundary.strings_replaced_by_the_check, 0, JSON.stringify(doc.boundary));
        const named = Object.values(doc.pages as Record<string, Json>).map((p) => p.all_results).filter(Boolean);
        assert.ok(named.length > 0, `${script}: the call paged`);
        for (const n of named) assert.match(n, job ? /^store\/jobs\/j000777\/out\/tool-output\/[a-z_]+-[a-z_]+-\d{16}\.jsonl$/ : /^work\/s1\/tool-output\/[a-z_]+-[a-z_]+-\d{16}\.jsonl$/, "the run's own page is shown whole");
        if (job) assert.match(doc.text.file, /^store\/jobs\/j000777\/out\/(chain|inventory|audit)-values\.jsonl$/);
      }
    });
  }
});

test("end to end, a secret after `=`, a JWT in a path, user-info with `@` in the password and a UPID-shaped name with a password are withheld in the slots that printed them", async () => {
  const key = mixed(20) + "/" + mixed(19), pw = mixed(16);
  const jwt = "eyJ" + mixed(30) + ".eyJ" + mixed(40) + "." + mixed(43);
  const values = [`aws_secret_access_key=${key}`, `dd/${jwt}/vm.vmdk`, `svc:p@${pw}@host.example.test`, `UPID:node:0:svc:${pw}@host.example.test`];
  for (const v of values) {
    await withCwd(async (cwd) => {
      await put(cwd, "inputs/vm/a.vmdk", ["# Disk DescriptorFile", "version=1", "CID=aabbccd1", "parentCID=aabbccd0", `parentFileNameHint="${v}"`, `RW 8 FLAT "${v}"`, "", `ddb.toolsVersion = "${v}"`, `ddb.uuid = "${v}"`].join("\n") + "\n");
      await put(cwd, "inputs/vm/a.vmx", vmx([["displayName", v], ["guestOS", v], ["scsi0:0.fileName", v]]));
      await put(cwd, "inputs/a/x.csv", `t,a,u,o\n2024-01-05T02:00:00Z,${v},${v},${v}\n`);
      for (const [script, args] of [[CHAIN, { root: "inputs/vm" }], [INVENTORY, { root: "inputs/vm" }], [AUDIT, { path: "inputs/a/x.csv", format: "declared_csv", mapping: { time: "t", action: "a", actor: "u", object: "o" } }]] as const) {
        for (const limit of [1, 200]) {
          const run = await tool(script, cwd, { ...args, limit });
          const all = run.stdout + "\n" + await everything(cwd);
          for (const secret of [key, jwt, pw]) if (v.includes(secret)) assertNoPiece(all, secret, `${script} ${v.slice(0, 30)}`, secret === jwt ? 3 : 0);
          assert.equal(JSON.parse(run.stdout).boundary.strings_replaced_by_the_check, 0);
        }
      }
    });
  }
});

test("an integer of 40 digits in a descriptor's extent line is not printed: it is withheld by its size", async () => {
  await withCwd(async (cwd) => {
    const n = "1234567890123456789012345678901234567890";
    await put(cwd, "inputs/vm/a.vmdk", ["# Disk DescriptorFile", "version=1", "CID=aabbccd1", "parentCID=ffffffff", `RW ${n} FLAT "a-flat.vmdk" ${n}`].join("\n") + "\n");
    await put(cwd, "inputs/vm/b.vmdk", ["# Disk DescriptorFile", "version=1", "CID=aabbccd2", "parentCID=ffffffff", `RW ${n} ZERO`].join("\n") + "\n");
    for (const limit of [1, 200]) {
      const run = await tool(CHAIN, cwd, { root: "inputs/vm", limit });
      const all = run.stdout + "\n" + await everything(cwd);
      assertNoPiece(all, n, "a 40-digit integer");
      assert.match(all, /<withheld: an integer of 130 bits>/);
    }
  });
});

// ---- the backstop's second check, alone -------------------------------------------------------------------------------

const NO_RULES = `
import importlib.util, io, json, sys
spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
def let_through(value, depth=0):           # the seal removed on purpose
    return json.loads(json.dumps(value, default=str))
tool.seal = let_through
tool.Shower.__call__ = lambda self, text, where=None, field=None: None if text is None else tool.Shown(str(text))   # the shape check removed
tool._rules_once = lambda text, kind="boundary": text      # and the rules themselves: what is left is the second check
sys.stdin = io.TextIOWrapper(io.BytesIO(sys.argv[2].encode()))
try:
    code = tool.main()
except SystemExit as exc:
    code = exc.code
sys.exit(code or 0)
`;

function noRules(script: string, cwd: string, args: unknown, env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn("python3", ["-c", NO_RULES, script, JSON.stringify(args)], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    const o: Buffer[] = [], e: Buffer[] = [];
    child.stdout.on("data", (b: Buffer) => o.push(b));
    child.stderr.on("data", (b: Buffer) => e.push(b));
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(o).toString(), stderr: Buffer.concat(e).toString() }));
  });
}

test("the second check is not the rules again: with the seal, the shape check and the rules all removed on purpose, it still replaces every planted secret in the answer and in every paging file, names the place and the check, and makes the answer partial", async () => {
  const pw = mixed(14);
  const secrets: [string, string, number][] = [
    [GHP, GHP, 4], [AKIA, AKIA, 4], [mixed(20) + "/" + mixed(19), "", 0], ["eyJ" + mixed(30) + ".eyJ" + mixed(40) + "." + mixed(43), "", 3],
    [`Password=${pw}`, pw, 0], ["glpat-" + mixed(20), "", 6], [pick(DIG, 25), "", 0], [`https://svc:${pw}@h.example.test/x`, pw, 0], [mixed(40), "", 0],
    ["-----BEGIN RSA PRIVATE KEY-----", "BEGIN RSA PRIVATE KEY", 0], [(() => { const k = mixed(39); return k.slice(0, 13) + "\u200b" + k.slice(13, 26) + "\u200b" + k.slice(26); })(), "", 0],
  ];
  for (const [value, secretPart, from] of secrets) {
    const secret = (secretPart || value).replace(/\u200b/g, "");
    for (const [label, script, files, args] of [
      ["snapshot_chain_check", CHAIN, { "vm/a.vmdk": `# Disk DescriptorFile\nCID=aabbccdd\nparentCID=11223344\nparentFileNameHint="${value}"\nRW 8 FLAT "${value}"\n`, "vm/b.vmdk": `# Disk DescriptorFile\nCID=aabbccde\nparentCID=ffffffff\nRW 8 FLAT "${value}"\n` }, { root: "inputs" }],
      ["virtualization_inventory", INVENTORY, { "vm/a.vmx": `displayName = "${value}"\nscsi0:0.fileName = "${value}"\n`, "vm/b.vmx": `displayName = "${value}"\n` }, { root: "inputs" }],
      ["backup_audit_normalise", AUDIT, { "a/x.csv": `t,a\n2024-01-05T02:00:00Z,${value}\n2024-01-05T03:00:00Z,${value}\n` }, { path: "inputs/a/x.csv", format: "declared_csv", mapping: { time: "t", action: "a" } }],
    ] as const) {
      for (const limit of [1, 200]) {
        await withCwd(async (cwd) => {
          for (const [rel, data] of Object.entries(files)) { await mkdir(dirname(join(cwd, "inputs", rel)), { recursive: true }); await writeFile(join(cwd, "inputs", rel), data); }
          const run = await noRules(script, cwd, { ...args, limit });
          assert.doesNotMatch(run.stderr, /Traceback/, run.stderr.slice(-500));
          const doc: Json = JSON.parse(run.stdout);
          assertNoPiece(run.stdout + "\n" + await everything(cwd), secret, `${label} limit ${limit} ${value.slice(0, 24)}`, from);
          assert.ok(doc.boundary.strings_replaced_by_the_check > 0, `${label}: the second check replaced nothing`);
          assert.ok(Object.keys(doc.boundary.replaced_by_check).every((k: string) => k.startsWith("second check: ")), JSON.stringify(doc.boundary.replaced_by_check));
          assert.ok(doc.boundary.replaced_at.every((p: Json) => typeof p.at === "string" && p.check.startsWith("second check")), JSON.stringify(doc.boundary.replaced_at.slice(0, 3)));
          assert.equal(doc.status, "partial", `${label} limit ${limit}: ${doc.status_basis}`);
        });
      }
    }
  }
});

test("a token split by zero-width or NUL characters into pieces too short for the rules is judged with those characters taken out: the seal withholds it and nothing of it is shown", async () => {
  const token = mixed(39);
  for (const sep of ["\u200b", "\u0000", "\u2060"]) {
    const split = token.slice(0, 13) + sep + token.slice(13, 26) + sep + token.slice(26);
    await withCwd(async (cwd) => {
      await put(cwd, "inputs/vm/a.vmx", `displayName = "${split}"\nguestOS = "/vmfs/volumes/${split}/a/a.vmx"\n`);
      const run = await tool(INVENTORY, cwd, { root: "inputs/vm" });
      const doc: Json = JSON.parse(run.stdout);
      for (const piece of [token.slice(0, 13), token.slice(13, 26), token.slice(26)]) assert.equal(run.stdout.includes(piece.slice(0, 12)), false, `${JSON.stringify(sep)}: ${piece}`);
      assert.equal(doc.status, "complete", doc.status_basis);
      assert.equal(doc.boundary.strings_replaced_by_the_check, 0);
      assert.match(doc.vms[0].name, /^<(?:token-shaped text withheld \d+ characters|withheld: \d+ bytes, field displayName)>$/);
    });
  }
});

// ---- the readers ------------------------------------------------------------------------------------------------------

test("an XML file in an encoding the reader does not know fails that file, and the run goes on: the other file is read, the answer is partial, never an unexpected failure", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/lv/good.xml", "<domain type='kvm'><name>web01</name><uuid>6f1e2a3b-1c2d-4e5f-8a9b-0c1d2e3f4a5b</uuid></domain>");
    await put(cwd, "inputs/lv/odd.xml", "<?xml version='1.0' encoding='x-unknown'?><domain type='kvm'><name>db01</name></domain>");
    const inv: Json = JSON.parse((await tool(INVENTORY, cwd, { root: "inputs/lv" })).stdout);
    assert.equal(inv.status, "partial", inv.error ?? inv.status_basis);
    const by = Object.fromEntries(inv.sources.map((s: Json) => [s.file, s]));
    assert.equal(by["good.xml"].state, "parsed");
    assert.equal(by["odd.xml"].state, "failed");
    assert.match(by["odd.xml"].reason, /encoding/);
    assert.deepEqual(inv.vms.map((v: Json) => v.name), ["web01"]);
    await put(cwd, "inputs/a/good.xml", "<X><R when='2024-01-05T02:00:00Z'><A>backup</A></R></X>");
    await put(cwd, "inputs/a/odd.xml", "<?xml version='1.0' encoding='x-unknown'?><X><R when='2024-01-05T03:00:00Z'><A>restore</A></R></X>");
    const aud: Json = JSON.parse((await tool(AUDIT, cwd, { paths: ["inputs/a/good.xml", "inputs/a/odd.xml"], format: "declared_xml", record_tag: "R", mapping: { time: "@when", action: "A" } })).stdout);
    assert.equal(aud.status, "partial", aud.error ?? aud.status_basis);
    assert.deepEqual(aud.sources.map((s: Json) => s.state), ["parsed", "failed"]);
    assert.equal(aud.counts.events, 1);
    assert.match(aud.read_errors.join(" "), /^S000002: the XML stopped being readable/);
  });
});

test("a VHD footer or dynamic-disk header whose checksum fails, and a VHDX whose two region tables both fail their CRC, are named by a marker and make the answer partial; one damaged region-table copy is read from the other", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/f/fixed.vhd", Buffer.concat([Buffer.alloc(4096, 0x41), vhdFooter({ type: 2, uid: "11111111-aaaa-bbbb-cccc-000000000001", breakChecksum: true })]));
    const dyn = vhdDynamic({ uid: "11111111-aaaa-bbbb-cccc-000000000002" });
    dyn[512 + 36] ^= 0xff;                                   // the dynamic header's checksum (offset 36 of the header at 512)
    await put(cwd, "inputs/d/dyn.vhd", dyn);
    const both = vhdx({ diskId: "AAAAAAAA-0000-4000-8000-000000000001" });
    both[196608 + 4] ^= 1; both[262144 + 4] ^= 1;               // both region tables' CRC-32C
    await put(cwd, "inputs/x/both.vhdx", both);
    const one = vhdx({ diskId: "AAAAAAAA-0000-4000-8000-000000000002" });
    one.writeBigUInt64LE(0n, 196608 + 48 + 16);                  // the first copy's metadata entry points at nothing: its CRC no longer holds
    await put(cwd, "inputs/o/one.vhdx", one);
    for (const [dir, kind] of [["f", "vhd_footer_checksum_fail"], ["d", "vhd_dynamic_header_checksum_fail"], ["x", "vhdx_region_table_checksum_fail"]]) {
      const out: Json = JSON.parse((await tool(CHAIN, cwd, { root: `inputs/${dir}` })).stdout);
      assert.ok(out.markers.some((m: Json) => m.kind === kind), `${dir}: ${JSON.stringify(out.markers.map((m: Json) => m.kind))}`);
      assert.equal(out.status, "partial", `${dir}: ${out.status_basis}`);
      assert.match(out.status_basis, /failed their checksum/);
    }
    const out: Json = JSON.parse((await tool(CHAIN, cwd, { root: "inputs/o" })).stdout);
    assert.equal(out.sources[0].state, "parsed", out.sources[0].reason);
    assert.equal(out.sources[0].info.region_table_offset, 262144);
    assert.ok(out.markers.some((m: Json) => m.kind === "vhdx_region_table_copy_damaged"));
  });
});

test("a chain the max_chain_depth limit stopped makes the answer partial and names the limit; it never says every limit held", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/q/q0.qcow2", qcow2({}));
    for (let i = 1; i <= 6; i++) await put(cwd, `inputs/q/q${i}.qcow2`, qcow2({ backing: `q${i - 1}.qcow2`, backingFormat: "qcow2" }));
    const out: Json = JSON.parse((await tool(CHAIN, cwd, { root: "inputs/q", max_chain_depth: 3 })).stdout);
    assert.equal(out.chains[0].status, "too_deep");
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /max_chain_depth \(3\) was reached on 1 chain/);
    assert.doesNotMatch(out.status_basis, /every limit held/);
    const whole: Json = JSON.parse((await tool(CHAIN, cwd, { root: "inputs/q", max_chain_depth: 10 })).stdout);
    assert.equal(whole.status, "complete");
  });
});

test("a Proxmox Backup Server worker id is withheld in both its forms whenever either form is (also when unescaping `-` to `/` splits a token), and a task whose status is `unknown` is not called an error", async () => {
  await withCwd(async (cwd) => {
    const escaped = AKIA.split("").map((c, i) => (i % 3 === 1 ? `\\x${c.charCodeAt(0).toString(16)}` : c)).join("");
    const hex = (n: number): string => n.toString(16).toUpperCase().padStart(8, "0");
    await put(cwd, "inputs/a/index", [
      `UPID:pbs1:${hex(1)}:${hex(2)}:${hex(3)}:${hex(1700000000)}:verify:store1${escaped}:root@pam: ${hex(1700000060)} OK`,
      `UPID:pbs1:${hex(1)}:${hex(2)}:${hex(4)}:${hex(1700000100)}:garbage_collection:store1:root@pam: ${hex(1700000160)} unknown`,
      `UPID:pbs1:${hex(1)}:${hex(2)}:${hex(5)}:${hex(1700000200)}:verify:x-${DASHED}:root@pam: ${hex(1700000260)} OK`,
    ].join("\n") + "\n");
    const run = await tool(AUDIT, cwd, { path: "inputs/a/index", format: "pve_task_index" });
    const out: Json = JSON.parse(run.stdout);
    assertNoPiece(run.stdout, AKIA, "PBS worker id", 4);
    for (const piece of escaped.match(/.{1,12}/g) ?? []) if (piece.length === 12) assert.equal(run.stdout.includes(JSON.stringify(piece).slice(1, -1)), false, piece);
    assert.match(out.events[0].task.worker_id_as_written, /^<withheld: \d+ bytes, field worker id>$/);
    assert.match(out.events[0].object, /^<withheld: \d+ bytes, field worker id>$/);
    for (const piece of DASHED.split("-")) assertNoPiece(run.stdout, piece, "a token split by unescaping");
    assert.match(out.events[2].object, /^<withheld: \d+ bytes, field worker id>$/);
    assert.equal(out.events[1].task.worker_id_as_written, "store1");
    assert.equal(out.events[1].result, "unknown");
    assert.match(out.events[1].result_basis, /status unknown/);
  });
});

test("the snapshot sections of one Proxmox configuration are named up to a cap with their total, and every one is a row of snapshots, paged whole", async () => {
  await withCwd(async (cwd) => {
    const lines = ["name: big", "memory: 1024", ""];
    for (let i = 0; i < 3000; i++) lines.push(`[s${i}]`, `snaptime: ${1700000000 + i}`, "");
    await put(cwd, "inputs/pve/nodes/pve1/qemu-server/100.conf", lines.join("\n"));
    const run = await tool(INVENTORY, cwd, { root: "inputs/pve", limit: 1 });
    const out: Json = JSON.parse(run.stdout);
    const vm = out.vms[0];
    assert.equal(vm.snapshot_sections.length, 200);
    assert.equal(vm.snapshot_sections_total, 3000);
    assert.equal(out.pages.snapshots.matched, 3000);
    assert.ok(run.stdout.length < 100_000, `the answer at limit 1 is ${run.stdout.length} bytes`);
    assert.equal(out.status, "complete");
  });
});
