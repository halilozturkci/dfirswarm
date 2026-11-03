/**
 * virtualization-backup-forensics: the follow-ups to the identifier grammar, in the three tools' way out (the BOUNDARY block).
 *
 *   1  a lower-case (one-case) random serial or target in a t10. or iqn. id is not made readable by the id around it in free text
 *   2  a secret's name and a short tag, a counter, a date, a file extension or Veeam's `D2024` is a name and is shown; a value is not
 *   3  a placeholder followed, after a space, by a value of one class (8 or 14 small letters, capitals or digits) is not the placeholder
 *   4  every `*-key`, `*_key` and `*secret*` flag hides its value, and `--key-file x`, `--keyboard x` and `-keep-alive x` are left alone
 *   5  a t10. piece that holds `2D` by chance is judged; the hyphen drives write as 2D is read in the forms drives carry
 *
 * The block is run in a Python host (the tool loaded as a module), so that hundreds of random canaries per shape take seconds;
 * every canary is made here at random and none is a real secret. VIRT_RATE_N raises the number per shape (default 400).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { AUDIT, CHAIN, INVENTORY, asJob, prng, put, tool, vmdkDescriptor, vmx, withCwd } from "./pack-virtualization-harness.ts";
import { made } from "./pack-virtualization-canary-lib.ts";
import type { Json } from "./pack-virtualization-harness.ts";

const N = Number(process.env.VIRT_RATE_N ?? 400);

const HOST = String.raw`
import importlib.util, json, random, sys, string, zlib

spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
req = json.loads(sys.stdin.read())

CLASSES = {"b62": string.ascii_letters + string.digits, "lower": string.ascii_lowercase, "upper": string.ascii_uppercase, "digits": string.digits,
           "lowdig": string.ascii_lowercase + string.digits, "updig": string.ascii_uppercase + string.digits, "hex": "0123456789abcdef"}
CTX = {"name": ("name", "%s"), "path": ("file", "vm/%s/disk.vmdk"), "text": (None, "note %s end"), "state": ("state", "%s"), "file": ("file", "%s")}


def rs(r, n, a):
    return "".join(r.choice(a) for _ in range(n))


def reset():
    tool._STOP["chars"] = 0
    tool._STOP["by"] = None


def judge():
    out = []
    for field, text in req["items"]:
        reset()
        out.append({"sealed": tool.seal_text(text, "boundary", field), "suspect": tool._suspect(text)})
    return out


def rates():
    """For each form (a template with %s for the value), context, class and length: how many of n plants show the value whole (seal alone) and how many the second check alone misses."""
    out = {}
    for form in req["forms"]:
        for ctx in req["contexts"]:
            field, fmt = CTX[ctx]
            for cls in req["classes"]:
                for n in req["lengths"]:
                    r = random.Random(zlib.crc32(("%s|%s|%s|%d|%d" % (form, ctx, cls, n, req["seed"])).encode()))
                    whole = missed = 0
                    for _ in range(req["n"]):
                        reset()
                        v = rs(r, n, CLASSES[cls])
                        text = fmt % (form % v)
                        final = tool.seal_text(text, "boundary", field)
                        whole += v in final
                        missed += tool._suspect(text) is None
                    out["%s | %s | %s | %d" % (form, ctx, cls, n)] = {"whole": whole, "missed": missed}
    return out


def pieces_2d():
    """Random pieces of capitals and digits that the token test calls random and that hold 2D with both halves under 16 characters: how many a name shows."""
    out = {}
    for n in req["lengths"]:
        r = random.Random(zlib.crc32(("2d|%d|%d" % (n, req["seed"])).encode()))
        made = shown = 0
        while made < req["n"]:
            piece = rs(r, n, CLASSES["updig"])
            at = r.randrange(2, n - 3)
            piece = piece[:at] + "2D" + piece[at + 2:]
            if "2D" not in piece or any(len(p) >= 16 for p in piece.split("2D")) or tool._plain_segment(piece, 0):
                continue
            made += 1
            reset()
            text = "t10.AB_%s_SN1234" % piece
            shown += tool.seal_text(text, "boundary", "file") == text
        out[str(n)] = {"made": made, "shown": shown}
    return out


def plain():
    out = []                    # a word after a secret's name is a word when a name that holds it is shown as it is
    for w, dotted in req["words"]:
        text = ("Password." if dotted else "password-") + w
        reset()
        out.append(tool.seal_text(text, "boundary", "name") == text)
    return out


print(json.dumps({"judge": judge, "rates": rates, "pieces_2d": pieces_2d, "plain": plain}[req["op"]]()))
`;

function host(script: string, req: Json, timeoutMs = 240_000): Promise<Json> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", HOST, script], { stdio: ["pipe", "pipe", "pipe"] });
    const out: Buffer[] = [], err: Buffer[] = [];
    child.stdout.on("data", (b: Buffer) => out.push(b));
    child.stderr.on("data", (b: Buffer) => err.push(b));
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(`host exited ${code}: ${Buffer.concat(err).toString().slice(-600)}`));
      try { resolve(JSON.parse(Buffer.concat(out).toString())); } catch (e) { reject(new Error(`host printed no JSON: ${Buffer.concat(out).toString().slice(0, 300)} ${Buffer.concat(err).toString().slice(-300)}`)); }
    });
    child.stdin.end(JSON.stringify(req));
  });
}

const TOOLS: [string, string][] = [["snapshot_chain_check", CHAIN], ["virtualization_inventory", INVENTORY], ["backup_audit_normalise", AUDIT]];
type Rate = { whole: number; missed: number };

// ---- 1: a t10. or iqn. wrapper does not make one case of random letters readable in free text ---------------------------------

test("a random serial, model or target of one case of letters in a t10. or iqn. id is not shown in free text, by the seal or by the second check alone (it was shown in every plant)", async () => {
  const forms = ["t10.ATA_____Model_X_____%s", "t10.AB_%s_SN1234", "t10.ATA_____WDC_%s_____WD2DWCC7K1234567", "iqn.2004-12.com.example:%s"];
  for (const [label, script] of TOOLS) {
    const got = { ...await host(script, { op: "rates", n: N, seed: 31, forms, contexts: ["text"], classes: ["lower", "upper"], lengths: [20, 24, 30, 40] }),
                  ...await host(script, { op: "rates", n: N, seed: 31, forms: ["iqn.2004-12.%s.com:t1"], contexts: ["text"], classes: ["lower"], lengths: [20, 24, 30, 40] }) };
    for (const [key, v] of Object.entries(got as Record<string, Rate>)) {
      // CHANGED with the one text: the authority part of an iqn. name (iqn.2004-12.<letters>.com:t1) is judged as a name, so random letters of one case are shown in up to 20% of the plants there (measured 15.5% at 20 letters); every other place stays within 2%
      assert.ok(v.whole <= Math.ceil(N * (key.startsWith("iqn.2004-12.%s.com") ? 0.2 : 0.02)), `${label} ${key}: ${v.whole} of ${N} shown whole by the seal`);
      assert.ok(v.missed <= Math.ceil(N * (/\| 20$/.test(key) ? 0.07 : 0.03)), `${label} ${key}: the second check alone missed ${v.missed} of ${N}`);
    }
  }
});

test("the fixed example of the review (24 small letters as the serial of a t10. id) is withheld in free text and found by the second check alone; the real ids in free text are no more withheld than before", async () => {
  const serial = "bazsjdocavbxirjstyziomdz";
  const items: [string | null, string][] = [[null, `t10.ATA_____Model_X_____${serial}`], [null, `disk t10.ATA_____Model_X_____${serial.toUpperCase()}, then`], [null, `iqn.2004-12.com.example:${serial}`]];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items });
    got.forEach((g: Json, i: number) => {
      assert.equal(g.sealed.toLowerCase().includes(serial.slice(2, 16)), false, `${label}: ${items[i][1]} -> ${g.sealed}`);
      assert.notEqual(g.suspect, null, `${label}: the second check alone must find ${items[i][1]}`);
    });
    const plain = await host(script, { op: "judge", items: [[null, "boot disk iqn.2004-12.com.example:sql-f1f9be4b was lost"], [null, "t10.ATA_____VBOX_HARDDISK___________VB1234abcd-5678ef90 attached"], [null, "naa.6818b904ce6087413e3b266f850f1578 offline"]] });
    plain.forEach((g: Json, i: number) => assert.equal(g.suspect, null, `${label}: a plain id in free text is not a find of the second check (${i})`));
  }
});

// ---- 2: a secret's name and a name, a tag, a counter, a date, an extension -----------------------------------------------------

test("a secret's name followed by a short tag, a counter, a date, a file extension or Veeam's D2024 is a name and is shown in a name, a path and a state field; a value is not", async () => {
  const shown: [string, string][] = [
    ["name", "pwd-srv01"], ["name", "token-db02"], ["name", "Token-20240312"], ["name", "secret-dc02"], ["name", "password-sql01"], ["name", "Password_pg14"], ["name", "Token.7d4f"], ["name", "pwd svc02"],
    ["name", "Token-20240312153000"], ["name", "Password-000001"], ["name", "Secret-s001"], ["name", "Credentials-cifs"], ["name", "Password-vmware"], ["name", "Token-vcenter7"], ["name", "pwd-update"],
    ["file", "/vmfs/volumes/ds/Token/Token.vmdk"], ["file", "D:\\Hyper-V\\Password\\Virtual Hard Disks\\Password.vhdx"], ["file", "/vmfs/volumes/ds/Secret/Secret.nvram"], ["file", "/var/lib/libvirt/images/Password.qcow2"],
    ["file", "/vmfs/volumes/ds/pwd/pwd.vmsn"], ["file", "/vmfs/volumes/ds/Password/Password-000001-delta.vmdk"], ["file", "/vmfs/volumes/ds/Secret/Secret.vmsd"], ["file", "[ds1] Token/Token.vmx"],
    ["state", "Password.vmdk"], ["state", "pwd-srv01"], ["state", "Token-20240312"],
  ];
  const withheld: [string, string][] = [
    ["name", "pwd-Zq7kP2mR"], ["name", "Token Zq7kP2mR"], ["name", "passwordZq7kP2mR"], ["name", "secret_x9y8z7q1"], ["name", "Token-20240312ab"], ["name", "password-ab12cd34"], ["name", "pwd-Zq7kP2mRD2024"],
    ["name", "-password Zq7kP2mR"], ["name", "--secret-key Zq7kP2mR"], ["name", "-key Zq7kP2mR"], ["name", "pwd.Zq7kP2mR"], ["file", "vm/pwd-Zq7kP2mR/a.vmdk"], ["file", "/vmfs/volumes/ds/Token/Token.Zq7kP2mR"],
    ["state", "token-Zq7kP2mR"],
  ];
  const FIELD: Record<string, string> = { name: "name", file: "file", state: "state" };
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items: [...shown, ...withheld].map(([k, t]) => [FIELD[k], t]) });
    shown.forEach(([k, t], i) => assert.equal(got[i].sealed, t, `${label}: a ${k} that is not a secret is shown as it is (${t})`));
    withheld.forEach(([k, t], i) => assert.match(got[shown.length + i].sealed, /<withheld \d+ (?:characters|bytes): [a-z0-9 ,:.-]+>/, `${label}: ${k} ${t} -> ${got[shown.length + i].sealed}`));
  }
});

test("the word after a secret's name reads as a word for the Veeam job name (the D2024 its time stamp starts with is not part of it), a file extension after a dot, a counter, a date and a short tag, and not for a value", async () => {
  const words: [string, boolean][] = [["ManagerD2024", false], ["ProxyD2024", false], ["vmdk", true], ["vhdx", true], ["qcow2", true], ["nvram", true], ["json", true], ["000001", false], ["20240312", false],
    ["20240312153000", false], ["srv01", false], ["db02", false], ["pg14", false], ["sql001", false], ["7d4f", false], ["Vault", false], ["Server01", false]];
  const values: [string, boolean][] = [["Zq7kP2mRD2024", false], ["Zq7kP2mR", false], ["vmdkabc", false], ["x9y8z7q1", false], ["48201937", false], ["abcdefgh", false], ["ab12cd34", false], ["srv01abc", false], ["20241345", false]];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "plain", words: [...words.map(([w]) => [w, w === "vmdk" || w === "vhdx" || w === "qcow2" || w === "nvram" || w === "json"]), ...values] });
    words.forEach(([w], i) => assert.equal(got[i], true, `${label}: ${w} reads as a word`));
    values.forEach(([w], i) => assert.equal(got[words.length + i], false, `${label}: ${w} reads as a value`));
  }
});

test("random canaries: a secret's name, a separator and a value of 8, 14 or 24 characters is still not shown in a name, a path component or a state field (the values the short tags let through are 7 characters or fewer)", async () => {
  const forms = ["password %s", "password-%s", "password_%s", "token %s", "secret %s", "pwd %s", "password%s", "Credentials %s", "-pwd%s", "-token%s", "x-password%s", "pwd.%s", "Token-%s"];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "rates", n: Math.min(N, 200), seed: 32, forms, contexts: ["name", "path", "state"], classes: ["b62", "lowdig", "updig", "hex", "digits", "upper", "lower"], lengths: [8, 14, 24] });
    const bad = Object.entries(got as Record<string, Rate>).filter(([k, v]) => v.whole > Math.ceil(Math.min(N, 200) * (/ \| lower \| 8$/.test(k) ? 0.2 : 0.04))).map(([k, v]) => `${k}: ${v.whole}`);
    assert.deepEqual(bad, [], `${label}: values shown whole by the seal, of ${Math.min(N, 200)} plants a cell`);
  }
});

// ---- 3: a placeholder and, after a space, a value of one class -----------------------------------------------------------------

test("random canaries: a placeholder followed after a space by 8 or 14 digits, or by 14 small letters or capitals, hides the value in the seal and in the second check alone; 8 letters of one case are shown in at most 12%", async () => {
  const forms = ["password=<redacted> %s", "password: <password> %s", "-token <masked> %s", "set password <hidden> %s", "pwd=<***> %s"];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "rates", n: N, seed: 33, forms, contexts: ["text"], classes: ["lower", "upper", "digits"], lengths: [8, 14] });
    for (const [key, v] of Object.entries(got as Record<string, Rate>)) {
      const letters8 = /\| (lower|upper) \| 8$/.test(key), bound = Math.ceil(N * (letters8 ? 0.12 : / digits /.test(key) ? 0 : 0.03));
      assert.ok(v.whole <= bound, `${label} ${key}: ${v.whole} of ${N} shown by the seal (bound ${bound})`);
      assert.ok(v.missed <= bound, `${label} ${key}: the second check alone missed ${v.missed} of ${N} (bound ${bound})`);
    }
  }
});

test("a word after a placeholder is still a word: the placeholder stays, in the seal and in the second check", async () => {
  const items: [string | null, string][] = [[null, "password=<redacted> successfully"], [null, "token: <secret> restoration of the share"], [null, "password: <password> information follows"], [null, "-token <masked> maintenance window"],
    [null, "password=<redacted> was reset"], [null, "pwd=<***> transport"]];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items });
    got.forEach((g: Json, i: number) => {
      assert.equal(g.sealed, items[i][1], `${label}: ${items[i][1]} -> ${g.sealed}`);
      assert.equal(g.suspect, null, `${label}: the second check alone finds ${items[i][1]}`);
    });
  }
});

// ---- 4: the flags that take a key or a secret ----------------------------------------------------------------------------------

const KEY_FLAGS = ["--secret-key %s", "--master-key %s", "--shared-key %s", "--signing-key %s", "--encryption-key %s", "--ssh-key %s", "-key %s", "--secret-access-key %s", "--db-password %s", "--admin-password %s", "--sshKey %s", "--client-secret %s", "--clientsecret %s", "--secrets %s", "-master_key %s"];

test("random canaries: --secret-key, --master-key, --shared-key, --signing-key, --encryption-key, --ssh-key, -key and every other flag that ends in -key, _key or Key or holds `secret` hide a value of 8, 14 or 24 characters of every class in a name, a path, a state field and free text (the seal alone), and the second check alone finds them in free text", async () => {
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "rates", n: Math.min(N, 100), seed: 34, forms: KEY_FLAGS, contexts: ["name", "path", "state", "text"], classes: ["b62", "lower", "upper", "digits", "lowdig", "updig", "hex"], lengths: [8, 14, 24] });
    const shown = Object.entries(got as Record<string, Rate>).filter(([k, v]) => v.whole > 0 || (/ \| text \|/.test(k) && v.missed > 0)).map(([k, v]) => `${k}: ${v.whole}/${v.missed}`);
    assert.deepEqual(shown, [], `${label}: values shown whole by the seal or missed by the second check`);
  }
});

test("a flag that only looks like a key flag is left alone: --key-file, --keyboard, -keep-alive, --keyring-backend, --monkey, --hotkey, --key-size", async () => {
  const lines = ["qemu-system-x86_64 --keyboard us -m 2048", "ssh --key-file /etc/ssh/key.pem host", "curl -keep-alive 30 http://x", "gpg --keyring-backend file --home /x", "run --monkey banana1 --hotkey F5 now", "openssl genrsa --key-size 4096"];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items: lines.map((l): [string | null, string] => [null, l]) });
    got.forEach((g: Json, i: number) => {
      assert.equal(g.sealed, lines[i], `${label}: ${lines[i]} -> ${g.sealed}`);
      assert.equal(g.suspect, null, `${label}: the second check alone finds ${lines[i]}`);
    });
  }
});

// ---- 5: the 2D of a t10. piece -----------------------------------------------------------------------------------------------

test("random pieces of capitals and digits that hold 2D by chance (both halves under 16 characters, the token test says random) are not shown in a path component: 0 of every 300 pieces of 22 to 24 characters; the forms drives carry stay readable", async () => {
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "pieces_2d", n: Math.min(N, 300), seed: 35, lengths: [22, 23, 24] });
    for (const [n, v] of Object.entries(got as Record<string, { made: number; shown: number }>)) assert.equal(v.shown, 0, `${label}: ${v.shown} of ${v.made} random pieces of ${n} characters shown`);
    const real = ["/vmfs/devices/disks/t10.ATA_____WDC_WD40EFRX2D68N32N0_____WD2DWCC7K1234567", "/vmfs/devices/disks/t10.ATA_____ST4000DM0042D2CV104_____ZDH1ABCD", "/vmfs/devices/disks/t10.ATA_____SAMSUNG_MZ7LN256HCHP2D000L2_____S2XXNX0J123456",
      "/vmfs/devices/disks/t10.ATA_____WDC_WD10EZEX2D00BN5A0_____WD2DWCC6Y0123456", "/vmfs/devices/disks/t10.ATA_____ST3000DM0012D1CH166_____Z1F12345", "/vmfs/devices/disks/t10.ATA_____WDC_WD80EFAX2D68KNBN0_____VGH1ABCD"];
    const kept = await host(script, { op: "judge", items: real.map((t): [string, string] => ["file", t]) });
    kept.forEach((g: Json, i: number) => assert.equal(g.sealed, real[i], `${label}: ${real[i]} -> ${g.sealed}`));
  }
});

// ---- end to end: the values planted in the fields of the three tools ---------------------------------------------------------------

test("end to end: a key flag with its value, a placeholder with a one-class value behind it and a t10. or iqn. id around small letters, planted in the names, paths and free-text fields of the three tools, reach no answer, no paging file and no file name, in and out of a job", async () => {
  const r = prng(20261020);
  const UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", LO = "abcdefghijklmnopqrstuvwxyz", DG = "0123456789";
  const classes = [UP + LO + DG, LO, UP, DG, LO + DG, UP + DG];
  const pick = (alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[Math.floor(r() * alphabet.length)]).join("");
  const flags = ["--secret-key %", "--master-key %", "--shared-key %", "--signing-key %", "--encryption-key %", "--ssh-key %", "-key %", "--db-password %"];
  const spaced = ["password=<redacted> %", "token: <secret> %", "set password <hidden> %", "-token <masked> %"];
  const wrapped = ["t10.ATA_____Model_X_____%", "iqn.2004-12.com.example:%"];
  const plants: { text: string; value: string; flag: boolean }[] = [];
  for (const [forms, lens, alphabets, flag] of [[flags, [8, 14, 24], classes, true], [spaced, [8, 14], [DG], false], [spaced, [14], [LO, UP], false], [wrapped, [24, 30], [LO, UP], false]] as const) {
    for (const form of forms) for (const n of lens) {
      const value = pick(alphabets[plants.length % alphabets.length], n);
      plants.push({ text: form.replace("%", value), value, flag });
    }
  }
  const cell = (t: string): string => t.replace(/"/g, "'");
  const inventory: Record<string, string> = {}, chain: Record<string, string> = {};
  plants.forEach((p, i) => {
    inventory[`vm/p${i}.vmx`] = vmx([["displayName", cell(p.text)], ["annotation", cell(p.text)], ["guestOS", cell(p.text)], ["scsi0:0.fileName", `${cell(p.text)}.vmdk`]]);
    inventory[`lv/pool${i}.xml`] = `<pool type='dir'><name>${p.text.replace(/[<>&]/g, "_")}</name><uuid>5c1bb0ef-6bd0-4f1d-9f3e-0123456789${String(10 + (i % 90))}</uuid><target><path>/var/lib/libvirt/images</path></target></pool>`;
    chain[`vm/p${i}.vmdk`] = vmdkDescriptor({ cid: i.toString(16).padStart(8, "0"), parentCid: "ffffffff", parentHint: cell(p.text), extents: [{ sectors: 8, type: "FLAT", name: `${cell(p.text)}-flat.vmdk` }] });
    if (p.flag) {
      inventory[`vm/d-${p.text}/a.vmx`] = vmx([["displayName", "x"]]);
      chain[`vm/d-${p.text}/a.vmdk`] = vmdkDescriptor({ cid: (i + 4096).toString(16).padStart(8, "0"), parentCid: "ffffffff", extents: [{ sectors: 8, type: "FLAT", name: "a-flat.vmdk" }] });
    }
  });
  // the free-text slots: a Proxmox VM's lock, a storage's server and user name, and the actor, host, job and result of an audit record
  plants.forEach((p, i) => { inventory[`pve/etc/pve/nodes/pve1/qemu-server/${100 + i}.conf`] = `name: v${i}\ncores: 2\nlock: ${p.text}\n`; });
  inventory["pve/etc/pve/storage.cfg"] = plants.map((p, i) => `pbs: b${i}\n\tdatastore s${i}\n\tserver ${p.text}\n\tusername ${p.text}\n`).join("\n");
  const c2 = (t: string): string => cell(t).replace(/,/g, ";");
  const csv = ["t,a,o,m,u,h,j,r", ...plants.map((p) => `2024-01-05T02:00:00Z,Backup,${c2(p.text)},note ${c2(p.text)} end,${c2(p.text)},${c2(p.text)},${c2(p.text)},${c2(p.text)}`)].join("\n") + "\n";
  for (const job of [false, true]) {
    for (const [label, script, files, args] of [
      ["inventory", INVENTORY, inventory, { root: "inputs", limit: 400 }],
      ["chain", CHAIN, chain, { root: "inputs", limit: 400 }],
      ["audit", AUDIT, { "x.csv": csv }, { path: "inputs/x.csv", format: "declared_csv", mapping: { time: "t", action: "a", object: "o", message: "m", actor: "u", host: "h", job: "j", result: "r" }, limit: 400 }],
    ] as const) {
      await withCwd(async (cwd) => {
        for (const [rel, data] of Object.entries(files)) await put(cwd, `inputs/${rel}`, data);
        const run = job ? await asJob(script, cwd, { ...args, write_text: true }) : await tool(script, cwd, args);
        assert.doesNotMatch(run.stderr, /Traceback/, run.stderr.slice(-300));
        const doc = JSON.parse(run.stdout);
        assert.ok(["complete", "partial"].includes(doc.status), `${label}: ${doc.status} ${doc.error ?? ""}`);
        const texts: [string, string][] = [["answer", run.stdout]];
        for (const [rel, bytes] of await made(cwd)) {
          texts.push([`name of ${rel}`, rel]);
          if (!/-values\.jsonl$/.test(rel)) texts.push([rel, bytes]);
        }
        const leaks = plants.flatMap((p) => texts.filter(([, t]) => t.includes(p.value)).map(([where]) => `${p.text} in ${where}`));
        assert.deepEqual(leaks, [], `${label} job=${job}: a value reached the answer or a file`);
      });
    }
  }
});
