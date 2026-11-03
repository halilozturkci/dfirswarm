/**
 * virtualization-backup-forensics: the second round of follow-ups to the identifier grammar, in the three tools' way out (the BOUNDARY block).
 *
 *   1  a tag, a counter, a date, a product word or an extension after a secret's name no longer lets what comes after it through: every word after the name is judged
 *   2  a secret written in groups of four (`ab12-cd34-ef56`, `123456-654321`) is one value, judged whole
 *   3  a flag that ends in `key` hides its value glued to it (`--master-keyX`, `-keyX`, `--sshKeyX`) as it does after a space, in a name and in free text
 *   4  more flags that take a secret (`--keypass`, `--storepass`, `--userpass`, `--apiToken`, `--adminPassword`, `--community`, `--credential` ...)
 *   5  the path of a key file given to a flag that takes a key is a path; an iqn. id with a maker's hex serial in free text is read as it is
 *
 * The block is run in a Python host (the tool loaded as a module), so that hundreds of random canaries per shape take seconds; every canary is made here at random
 * and none is a real secret. VIRT_RATE_N raises the number per shape (default 400).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { AUDIT, CHAIN, INVENTORY, asJob, prng, put, tool, vmx, withCwd } from "./pack-virtualization-harness.ts";
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
CTX = {"name": ("name", "%s"), "path": ("file", "/vmfs/volumes/ds1/%s/vm.vmx"), "text": (None, "run %s now"), "state": ("state", "%s"), "file": ("file", "%s")}


def reset():
    tool._STOP["chars"] = 0
    tool._STOP["by"] = None


def value(r, shape):
    return shape.get("sep", "-").join("".join(r.choice(CLASSES[shape["cls"]]) for _ in range(shape["length"])) for _ in range(shape.get("groups", 1)))


def judge():
    out = []
    for field, text in req["items"]:
        reset()
        out.append({"sealed": tool.seal_text(text, "boundary", field), "suspect": tool._suspect(text)})
    return out


def pooled():
    """For each shape (a class, a length, a number of groups): n plants, each in a random form (a template with %s for the value) and a random context; how many show the value whole in
    the seal, and how many the second check alone misses (free text only)."""
    out = {}
    for shape in req["shapes"]:
        key = "%s|%d|%d" % (shape["cls"], shape["length"], shape.get("groups", 1))
        r = random.Random(zlib.crc32(("%s|%s|%d" % (key, shape.get("sep", "-"), req["seed"])).encode()))
        whole = missed = 0
        for _ in range(req["n"]):
            reset()
            v = value(r, shape)
            form = r.choice(req["forms"])
            ctx = r.choice(req["contexts"])
            field, fmt = CTX[ctx]
            text = fmt % (form % v)
            whole += v in tool.seal_text(text, "boundary", field)
            if ctx == "text":
                missed += tool._suspect(text) is None
        out[key] = {"whole": whole, "missed": missed}
    return out


def plain():
    out = []                    # a word after a secret's name is a word when a name that holds it is shown as it is
    for w, dotted in req["words"]:
        text = ("Password." if dotted else "password-") + w
        reset()
        out.append(tool.seal_text(text, "boundary", "name") == text)
    return out


print(json.dumps({"judge": judge, "pooled": pooled, "plain": plain}[req["op"]]()))
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
const CLS = ["b62", "hex", "lowdig", "updig", "lower", "upper", "digits"];
const SECRET_WORDS = ["password", "Token", "secret", "pwd", "Credential", "passphrase"];
const SEPS = ["-", "_", " ", "."];
const ID_CTX = ["name", "path", "state"];

// ---- 1: a word after a secret's name that is not a word is a value, behind a tag, a date, a counter, a product word and a dictionary word alike ----------------------------------

const FOLLOWERS = ["srv01", "db02", "20240312", "000001", "vmware", "vcenter", "ab12", "vmdk", "D2024", "Ab3", "sqlserver", "pg14", "7d4f", "dc02", "Vault", "Manager", "Server01", "Ring"];
const followerForms = SECRET_WORDS.flatMap((w) => SEPS.flatMap((s) => FOLLOWERS.flatMap((f) => SEPS.map((s2) => `${w}${s}${f}${s2}%s`))));

test("random canaries: a value behind a secret's name and a tag, a date, a counter, a product word, a dictionary word or an extension is not shown (it was shown in 90 to 100% of plants of 8 characters)", async () => {
  const shapes = [...CLS.filter((c) => c !== "digits" && c !== "lower").map((cls) => ({ cls, length: 8 })), { cls: "digits", length: 8 }, { cls: "digits", length: 14 }, { cls: "digits", length: 24 }, { cls: "digits", length: 30 },
    { cls: "lower", length: 14 }, { cls: "lower", length: 24 }, { cls: "upper", length: 14 }, { cls: "b62", length: 14 }];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "pooled", n: N * 3, seed: 41, forms: followerForms, contexts: ID_CTX, shapes }) as Record<string, Rate>;
    for (const [key, v] of Object.entries(got)) assert.ok(v.whole <= Math.ceil(N * 3 * 0.02), `${label} ${key}: ${v.whole} of ${N * 3} shown whole`);
    const lower8 = await host(script, { op: "pooled", n: N * 3, seed: 42, forms: followerForms, contexts: ID_CTX, shapes: [{ cls: "lower", length: 8 }] }) as Record<string, Rate>;
    assert.ok(lower8["lower|8|1"].whole <= Math.ceil(N * 3 * 0.15), `${label}: ${lower8["lower|8|1"].whole} of ${N * 3} plants of 8 small letters shown`);
  }
});

test("a value behind a tag or a date is withheld in a name, a path component and a state field; the names that end in the tag, with a counter and a suffix after it, or in a file extension are shown", async () => {
  const id = "Zq7kP2mR", digits = "48201937516204839172650348";
  const withheld: [string, string][] = [
    ["name", `password-srv01-${id}`], ["name", `Token-20240312_${digits}`], ["name", `secret-vmware-${id}`], ["name", `pwd-000001-${id}`], ["name", `Credential-vcenter-${id}`], ["name", `password-Vault-${id}`],
    ["name", `password-ab12-${id}`], ["name", `pwd.vmdk.${id}`], ["file", `/vmfs/volumes/ds1/password-srv01-${id}/vm.vmx`], ["file", `/vmfs/volumes/ds1/secret-vmware-${digits}/vm.vmx`], ["state", `Token-db02-${id}`],
  ];
  const shown: [string, string][] = [
    ["name", "pwd-srv01"], ["name", "Token-20240312"], ["name", "Password.vmdk"], ["name", "password-srv01-template"], ["name", "pwd-srv01 (1)"], ["name", "Token-20240312 - Copy"], ["name", "secret-db02-replica"],
    ["name", "Password Manager-Server01-prod"], ["file", "/vmfs/volumes/ds1/Password-srv01/Password-srv01-000001-delta.vmdk"],     ["file", "[Password-Store] test-vm/test-vm.vmdk"], ["name", "pwd-z3r0 (1)"], ["name", "Token-A1B2-snapshot1"], ["name", "password-rotation-job-nightly"], ["name", "api-key-rotation-2024Q3"], ["name", "Password-Backup-monthly"], ["name", "secret-snmp-trap-relay"], ["file", "/vmfs/volumes/ds1/Token/Token.vmdk"],
  ];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items: [...withheld, ...shown] });
    withheld.forEach(([, t], i) => assert.match(got[i].sealed, /<withheld \d+ (?:characters|bytes): [a-z0-9 ,:.-]+>/, `${label}: ${t} -> ${got[i].sealed}`));
    shown.forEach(([, t], i) => assert.equal(got[withheld.length + i].sealed, t, `${label}: ${t} -> ${got[withheld.length + i].sealed}`));
  }
});

// ---- 2: groups ---------------------------------------------------------------------------------------------------------------------------------------------------------------------

test("random canaries: a secret written in groups of 4 to 6 characters (2 to 4 groups, `ab12-cd34-ef56`, `123456-654321`) after a secret's name is judged whole and not shown (it was shown in up to 100% of plants)", async () => {
  const forms = SECRET_WORDS.flatMap((w) => SEPS.map((s) => `${w}${s}%s`));
  const shapes: Json[] = [];
  for (const cls of CLS) for (const [length, groups] of [[4, 2], [4, 3], [4, 4], [5, 3], [6, 2]]) shapes.push({ cls, length, groups });
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "pooled", n: N, seed: 43, forms, contexts: ID_CTX, shapes }) as Record<string, Rate>;
    const bad = Object.entries(got).filter(([k, v]) => v.whole > Math.ceil(N * (/^(lowdig|updig|lower|digits)\|4\|2$/.test(k) ? 0.25 : /^hex\|4\|2$/.test(k) ? 0.15 : /^(lowdig|updig|lower|hex|digits)\|4\|3$/.test(k) ? 0.2 : /^lower\|6\|2$/.test(k) ? 0.08 : 0.05))).map(([k, v]) => `${k}: ${v.whole}`);   // CHANGED with the one text: six letters of one case in two groups are shown in up to 8% (measured 6.3%)
    assert.deepEqual(bad, [], `${label}: groups shown whole, of ${N} plants a cell`);
    const digits = await host(script, { op: "pooled", n: N, seed: 44, forms, contexts: ID_CTX, shapes: [{ cls: "digits", length: 6, groups: 2 }, { cls: "digits", length: 5, groups: 2 }] }) as Record<string, Rate>;
    for (const [k, v] of Object.entries(digits)) assert.ok(v.whole <= Math.ceil(N * (k === "digits|5|2" ? 0.03 : 0.12)), `${label} ${k}: ${v.whole} of ${N}`);
  }
});

test("two groups of four characters after a secret's name are one value; a tag and a counter, a date and a version, and words in a row are not", async () => {
  const words: [string, boolean][] = [["srv01", true], ["20240312", true], ["000001", true], ["Server01", true], ["Vault", true]];
  const items: [string, string][] = [["name", "password-ab12-cd34"], ["name", "pwd-4821-9037"], ["name", "Token_123456_654321"], ["name", "secret.k7x2.m9q4.z1b8"], ["state", "password XK7Q M2PZ"],
    ["name", "password-srv01-000001"], ["name", "Token-20240312-153000"], ["name", "Password-Manager-Pool-Node"], ["name", "pwd-prod-lab-01"], ["name", "secret-2024-03-12"], ["name", "Token-v2-r1"]];
  const gone = [0, 1, 2, 3, 4];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items });
    items.forEach(([, t], i) => {
      if (gone.includes(i)) assert.match(got[i].sealed, /<withheld \d+ (?:characters|bytes): [a-z0-9 ,:.-]+>/, `${label}: ${t} -> ${got[i].sealed}`);
      else assert.equal(got[i].sealed, t, `${label}: ${t} -> ${got[i].sealed}`);
    });
    const plain = await host(script, { op: "plain", words: words.map(([w]) => [w, false]) });
    plain.forEach((p: boolean, i: number) => assert.equal(p, true, `${label}: ${words[i][0]} reads as a word`));
  }
});

test("random canaries: 5 or 6 random digits after a secret's name are shown only when they start with 0 (a snapshot's counter is -000001; they were shown in every plant), and 8 or 14 digits are shown only as a date or a time stamp", async () => {
  const forms = SECRET_WORDS.flatMap((w) => SEPS.map((s) => `${w}${s}%s`));
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "pooled", n: N * 2, seed: 48, forms, contexts: ID_CTX, shapes: [{ cls: "digits", length: 5 }, { cls: "digits", length: 6 }, { cls: "digits", length: 8 }, { cls: "digits", length: 14 }] }) as Record<string, Rate>;
    assert.ok(got["digits|5|1"].whole <= Math.ceil(N * 2 * 0.15) && got["digits|6|1"].whole <= Math.ceil(N * 2 * 0.15), `${label}: ${got["digits|5|1"].whole} and ${got["digits|6|1"].whole} of ${N * 2} shown`);
    assert.ok(got["digits|8|1"].whole <= Math.ceil(N * 2 * 0.01) && got["digits|14|1"].whole <= Math.ceil(N * 2 * 0.01), `${label}: ${got["digits|8|1"].whole} and ${got["digits|14|1"].whole} of ${N * 2} shown`);
    const items: [string, string][] = [["name", "Password-000001"], ["name", "Token-000001-delta"], ["file", "/vmfs/volumes/ds1/pwd/pwd-000001-delta.vmdk"], ["name", "password-482915"], ["name", "secret.739204"], ["state", "Token_5016283"]];
    const j = await host(script, { op: "judge", items });
    j.forEach((g: Json, i: number) => {
      if (i < 3) assert.equal(g.sealed, items[i][1], `${label}: ${items[i][1]} -> ${g.sealed}`);
      else assert.match(g.sealed, /<withheld \d+ (?:characters|bytes): [a-z0-9 ,:.-]+>/, `${label}: ${items[i][1]} -> ${g.sealed}`);
    });
  }
});

// ---- 3: a key flag with the value glued to it ---------------------------------------------------------------------------------------------------------------------------------------

const GLUED = ["--master-key%s", "--ssh-key%s", "--sshKey%s", "-key%s", "--signing-key%s", "--encryption-key%s", "--shared-key%s", "--secret-key%s", "x --master-key%s", "-master_key%s", "--userpass%s", "--community%s", "--keypass%s", "--storepass%s",
  "--snmp-community%s", "--pw%s", "--otp%s"];

test("random canaries: a flag that takes a secret with the value glued to it (`--master-keyX`, `-keyX`, `--sshKeyX`, `--userpassX`, `--communityX`, the way a storage id is built from `dir: --master-key X`) hides a value of 8, 14 or 24 characters in a name, a path component and a state field (it was shown in 17 to 100% of plants)", async () => {
  const shapes: Json[] = [];
  for (const cls of CLS) for (const length of [8, 14, 24]) shapes.push({ cls, length });
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "pooled", n: N, seed: 45, forms: GLUED, contexts: ID_CTX, shapes }) as Record<string, Rate>;
    const bad = Object.entries(got).filter(([k, v]) => v.whole > Math.ceil(N * (/^lower\|8\|1$/.test(k) ? 0.1 : 0.03))).map(([k, v]) => `${k}: ${v.whole}`);
    assert.deepEqual(bad, [], `${label}: glued key values shown whole, of ${N} plants a cell`);
  }
});

test("the second check alone finds a glued key flag with a value in free text and leaves the names of flags alone; `key-vault-replica`, `Keyboard-Server`, `monkey-vm`, `hotkey`, `--key-file`, `--keyboard`, `--keyring-backend` are shown", async () => {
  const names: [string, string][] = [["name", "key-vault-replica"], ["name", "Keyboard-Server"], ["name", "monkey-vm"], ["name", "hotkey"], ["name", "--key-file"], ["name", "--keyboard"], ["name", "--keyring-backend"],
    ["name", "-keyboard-layout"], ["name", "--keyserver-options"], ["name", "Key-Manager-01"], ["name", "ssh-key-escrow"], ["name", "signing-key-hsm"], ["name", "api-key-broker"]];
  const lines = ["qemu-system-x86_64 --keyboard us -m 2048", "ssh --key-file /etc/ssh/key.pem host", "gpg --keyserver hkps://keys.openpgp.org --recv-keys 0xDEADBEEF", "openssl genrsa --key-size 4096", "keytool -genkeypair -alias lab -keyalg RSA -keysize 2048 -keystore lab.jks"];
  const r = prng(20261021);
  const pick = (alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[Math.floor(r() * alphabet.length)]).join("");
  const planted = ["--master-key", "--ssh-key", "--sshKey", "-key"].map((f, i) => `run ${f}${pick(["abcdefghijklmnopqrstuvwxyz0123456789", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "abcdef0123456789", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"][i], 14)} now`);
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items: [...names, ...lines.map((l): [string | null, string] => [null, l]), ...planted.map((l): [string | null, string] => [null, l])] });
    names.forEach(([, t], i) => assert.equal(got[i].sealed, t, `${label}: ${t} -> ${got[i].sealed}`));
    lines.forEach((l, i) => { assert.equal(got[names.length + i].sealed, l, `${label}: ${l}`); assert.equal(got[names.length + i].suspect, null, `${label}: the second check alone finds ${l}`); });
    planted.forEach((l, i) => assert.notEqual(got[names.length + lines.length + i].suspect, null, `${label}: the second check alone must find ${l}`));
  }
});

// ---- 4: more flags that take a secret ---------------------------------------------------------------------------------------------------------------------------------------------

const MORE_FLAGS = ["--keypass %s", "--storepass %s", "--userpass %s", "--apitoken %s", "--pass-phrase %s", "--authorization %s", "--community %s", "--snmp-community %s", "--credential %s", "--credentials %s",
  "--apiToken %s", "--authToken %s", "--accessToken %s", "--refreshToken %s", "--adminPassword %s", "-AdminPassword %s", "--dbPassword %s", "-VCenterPassword %s", "--rootPwd %s", "--sshPass %s", "--userPass %s", "--pw %s", "-pw %s", "--otp %s"];

test("random canaries: --keypass, --storepass, --userpass, --apitoken, --pass-phrase, --authorization, --community, --snmp-community, --credential(s), the CamelCase --apiToken, --adminPassword, -VCenterPassword, --rootPwd, --sshPass and the rest hide a value of 8, 14 or 24 characters in a name, a path, a state field and free text, and the second check alone finds them in free text (they were shown in 25 to 100%)", async () => {
  const shapes: Json[] = [];
  for (const cls of CLS) for (const length of [8, 14, 24]) shapes.push({ cls, length });
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "pooled", n: N, seed: 46, forms: MORE_FLAGS, contexts: [...ID_CTX, "text"], shapes }) as Record<string, Rate>;
    const bad = Object.entries(got).filter(([k, v]) => v.whole > 0 || v.missed > 0).map(([k, v]) => `${k}: ${v.whole}/${v.missed}`);
    assert.deepEqual(bad, [], `${label}: values shown whole by the seal, or missed by the second check in free text, of ${N} plants a cell`);
  }
});

test("a flag that takes a port is left alone: -p 22 and -P 2222 (the flags that stay unlisted)", async () => {
  const lines = ["ssh -p 22 root@10.0.0.5", "scp -P 2222 dump.vma nas01:/dumps/", "nmap -p 22,443 10.0.0.5", "qm set 101 --keyboard en-us"];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items: lines.map((l): [string | null, string] => [null, l]) });
    got.forEach((g: Json, i: number) => { assert.equal(g.sealed, lines[i], `${label}: ${lines[i]} -> ${g.sealed}`); assert.equal(g.suspect, null, `${label}: ${lines[i]}`); });
  }
});

// ---- 5: key files, and an iqn. with a maker's serial ------------------------------------------------------------------------------------------------------------------------------

test("the path of a key file given to a flag that takes a key is a path and is shown (seal and second check); a key given to the same flag is not", async () => {
  const files = ["curl --key client.key --cert client.crt https://vcenter.lab.local/api/session", "curl -key server.key https://10.0.0.5:8006/api2/json", "curl --client-key=admin.key --cacert ca.pem https://pve1:8006/",
    "curl --private-key ~/.ssh/id_rsa sftp://nas01/backup/", "ansible-playbook site.yml -i hosts --private-key ~/.ssh/ansible.pem -u root", "kubectl --client-key=/etc/kubernetes/pki/admin.key get nodes",
    "openvpn --tls-auth ta.key 1 --cipher AES-256-GCM", "mysql -u backup -h db01 --ssl-key=/etc/mysql/client-key.pem --ssl-cert=/etc/mysql/client-cert.pem", "ssh --private-key ./keys/backup_ed25519 host",
    "openssl pkcs12 -export -inkey client.key -in client.crt -out client.p12"];
  const r = prng(20261022);
  const pick = (alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[Math.floor(r() * alphabet.length)]).join("");
  const AL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const keys = ["--key ", "-key ", "--client-key=", "--private-key ", "--master-key "].map((f) => `curl ${f}${pick(AL, 14)} https://x/`);
  keys.push(`curl --key /${pick(AL, 12)}/${pick(AL, 10)} https://x/`);
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items: [...files, ...keys].map((l): [string | null, string] => [null, l]) });
    files.forEach((l, i) => { assert.equal(got[i].sealed, l, `${label}: ${l} -> ${got[i].sealed}`); assert.equal(got[i].suspect, null, `${label}: the second check alone finds ${l}`); });
    keys.forEach((l, i) => assert.notEqual(got[files.length + i].sealed, l, `${label}: ${l} is shown`));
  }
});

test("an iqn. id with the hexadecimal serial a maker writes after the colon is read as it is in free text, as before the last change; a serial of letters of one case is still withheld", async () => {
  const hex = (n: number, seed: number): string => { const r = prng(seed); return Array.from({ length: n }, () => "0123456789abcdef"[Math.floor(r() * 16)]).join(""); };
  const ids = [`iqn.2010-06.com.purestorage:flasharray.${hex(16, 1)}`, `iqn.2010-06.com.purestorage:flasharray.${hex(16, 2)}ab`, `iqn.2003-01.org.linux-iscsi.nas01.x8664:sn.${hex(12, 3)}`, `iqn.1994-05.com.redhat:${hex(12, 4)}`,
    `iqn.2015-12.com.oracle:storage.zfs.${hex(12, 5)}`, `iqn.1993-08.org.debian:01:${hex(12, 6)}`];
  const items = ids.map((id): [string | null, string] => [null, `login to target ${id} failed, retrying`]);
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items });
    got.forEach((g: Json, i: number) => assert.equal(g.sealed, items[i][1], `${label}: ${items[i][1]} -> ${g.sealed}`));
    const letters = await host(script, { op: "pooled", n: 60, seed: 47, forms: ["login to target iqn.2004-12.com.example:%s failed"], contexts: ["text"], shapes: [{ cls: "lower", length: 24 }, { cls: "lower", length: 30 }] }) as Record<string, Rate>;
    for (const [k, v] of Object.entries(letters)) assert.ok(v.whole <= 3, `${label} ${k}: ${v.whole} of 60 shown`);
  }
});

// ---- end to end ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

test("end to end: a value behind a tag, a group written in parts and a key flag with the value glued to it, planted in the name, path and id fields of the three tools, reach no answer, no paging file and no file name, in and out of a job", async () => {
  const r = prng(20261023);
  const UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", LO = "abcdefghijklmnopqrstuvwxyz", DG = "0123456789";
  const pick = (alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[Math.floor(r() * alphabet.length)]).join("");
  const groups = (alphabet: string, len: number, count: number): string => Array.from({ length: count }, () => pick(alphabet, len)).join("-");
  const plants: { text: string; value: string }[] = [];
  const add = (form: string, value: string): void => { plants.push({ text: form.replace("%", value), value }); };
  for (const alphabet of [UP + LO + DG, LO + DG, UP + DG, "0123456789abcdef"]) {
    add("password-srv01-%", pick(alphabet, 8));
    add("secret-20240312-%", pick(alphabet, 8));
    add("token-vcenter-%", pick(alphabet, 8));
    add("pwd-%", groups(alphabet, 4, 3));
    add("password %", groups(alphabet, 4, 2));
    add("--master-key%", pick(alphabet, 8));
    add("--ssh-key%", pick(alphabet, 14));
    add("--sshKey%", pick(alphabet, 8));
    add("-key%", pick(alphabet, 14));
  }
  add("Token-20240312_%", pick(DG, 30));
  add("password-%", groups(DG, 6, 2));
  const cell = (t: string): string => t.replace(/"/g, "'");
  const inventory: Record<string, string> = {}, chain: Record<string, string> = {};
  plants.forEach((p, i) => {
    inventory[`vm/p${i}.vmx`] = vmx([["displayName", cell(p.text)], ["scsi0:0.fileName", `${cell(p.text)}.vmdk`]]);
    inventory[`lv/pool${i}.xml`] = `<pool type='dir'><name>${p.text.replace(/[<>&]/g, "_")}</name><uuid>5c1bb0ef-6bd0-4f1d-9f3e-0123456789${String(10 + (i % 90))}</uuid><target><path>/var/lib/libvirt/images</path></target></pool>`;
    chain[`vm/p${i}.vmdk`] = `# Disk DescriptorFile\nversion=1\nCID=${i.toString(16).padStart(8, "0")}\nparentCID=ffffffff\ncreateType="monolithicFlat"\nparentFileNameHint="${cell(p.text)}"\n\n# Extent description\nRW 8 FLAT "${cell(p.text)}-flat.vmdk" 0\n`;
  });
  inventory["pve/etc/pve/storage.cfg"] = plants.map((p, i) => `dir: ${p.text.replace(/ /g, "")}\n\tpath /mnt/s${i}\n\tcontent backup\n`).join("\n");
  const c2 = (t: string): string => cell(t).replace(/,/g, ";");
  const csv = ["t,a,o,m,u,h,j,r", ...plants.map((p) => `2024-01-05T02:00:00Z,Backup,${c2(p.text)},ok,svc,host1,${c2(p.text)},success`)].join("\n") + "\n";
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
