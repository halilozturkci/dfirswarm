/**
 * virtualization-backup-forensics: the way out, in three layers (the BOUNDARY block, the same text in the three tools).
 *
 *   layer 1  an allow-list per field type: a name, a path, an identifier or a simple value is shown only when it fits the
 *            plain grammar of its type, else it is `<withheld: N bytes, field F>` and the original goes to the values file;
 *   layer 2  a deny-list for every other string, run on a copy normalised by Unicode property, with the value after a
 *            secret's name found anywhere, in linear time;
 *   layer 3  a check of its own, written apart from the two layers above, on what was serialised.
 *
 * The tests below run the block in a Python host (the tool is loaded as a module, as tests/pack-virtualization-canary.test.ts
 * does for its backstop test) so that thousands of random canaries per shape take seconds, and run the tools themselves for
 * the claims about the whole: time bounds, a lone surrogate, a signal, the files left behind. Every canary is random, made
 * here and not taken from a tool; VIRT_RATE_N raises the number per shape (default 400; the measurements in the changelog
 * were made with 5,000).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import {
  AUDIT, CHAIN, INVENTORY, asJob, body, filesUnder, json, prng, put, qcow2, startDetached, tool, vhdDynamic, vhdx, vmdkDescriptor, vmx, withCwd,
} from "./pack-virtualization-harness.ts";
import { made } from "./pack-virtualization-canary-lib.ts";
import { LADDER_PY, ladderOk } from "./pack-re-timing.ts";
import type { Json } from "./pack-virtualization-harness.ts";

// each step four times the one before: a linear rule takes four times as long, a quadratic one sixteen
const SIZES = [6250, 25000, 100000];
const N = Number(process.env.VIRT_RATE_N ?? 400);
// the number of forms of each family in the Python host above
const FLAG_FORMS = 15, BARE_FORMS = 11, PH_FORMS = 7, PH_SPACE_FORMS = 3;

const HOST = String.raw`
import importlib.util, json, random, sys, time, unicodedata, zlib, string, base64

${LADDER_PY}

spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
req = json.loads(sys.stdin.read())

ALNUM = string.ascii_letters + string.digits
B64 = ALNUM + "+/"
DI = set(range(0xFE00, 0xFE10)) | set(range(0xE0000, 0xE1000)) | {0x3164, 0xFFA0, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x034F} | set(range(0x180B, 0x1810))


def norm(t):
    return "".join(c for c in t if unicodedata.category(c) not in ("Mn", "Me", "Cc", "Cf") and ord(c) not in DI)


def rs(r, n, a=ALNUM):
    return "".join(r.choice(a) for _ in range(n))


def mixed(r, n):
    while True:
        s = rs(r, n)
        if sum(c.isdigit() for c in s) >= 3 and any(c.islower() for c in s) and any(c.isupper() for c in s):
            return s


def b64(r, n):
    return base64.b64encode(bytes(r.getrandbits(8) for _ in range(n))).decode()


def with_slash(r, n):
    while True:
        s = b64(r, n)
        if "/" in s.rstrip("="):
            return s


SPLIT = {"lri": "\u2066", "rli": "\u2067", "fsi": "\u2068", "pdi": "\u2069", "alm": "\u061c", "vs16": "\ufe0f", "vs1": "\ufe00", "tag": "\U000e0041", "cgj": "\u034f",
         "hfill": "\u3164", "ffa0": "\uffa0", "comb": "\u0301", "enclose": "\u20dd", "zw": "\u200b", "shy": "\u00ad", "bom": "\ufeff", "wj": "\u2060", "lrm": "\u200e",
         "nul": "\x00", "ls": "\u2028", "mvs": "\u180e", "esc": "\\u2066", "escx": "\\x00"}
NAMES = ["vncPassword", "rootPassword", "adminPassword", "accessToken", "apiToken", "appSecret", "SecretAccessKey", "awsSecretKey", "masterKey", "PWD", "pass", "pw", "credential",
         "auth", "PGPASSWORD", "MYSQL_PWD", "sig", "cipassword", "api_key", "client_secret", "Password", "passwd", "secret", "token", "dbPass", "AccountKey", "oauth"]


# a flag with its value, a secret's name and a word that is not one, a placeholder and a value after it: values of 8, 14 and 24 characters of every class
FORMS = {
    "flag": ["-password %s", "--password %s", "set password %s", "enable secret %s", "-pwd %s", "-token %s", "--token %s", "-secret %s", "-pass %s", "--api-key %s", "-auth %s",
             "-bearer %s", "-psk %s", "d--pwd %s", "d---pass %s"],
    "bare": ["password %s", "password-%s", "password_%s", "token %s", "secret %s", "pwd %s", "password%s", "Credentials %s", "-pwd%s", "-token%s", "x-password%s"],
    "ph": ["password=<redacted>%s", "--password <redacted>%s", "token: <secret>%s", "set password <hidden>%s", "pwd=<***>%s", "password=<>%s", "api_key=<value>%s"],
    "phs": ["password: <password> %s", "password=<redacted> %s", "-token <masked> %s"],
}
VALUE_CLASSES = [ALNUM, string.ascii_lowercase, string.ascii_uppercase, string.digits, string.ascii_lowercase + string.digits, string.ascii_uppercase + string.digits, "0123456789abcdef"]
MIXED_CLASSES = [ALNUM, string.ascii_lowercase + string.digits, string.ascii_uppercase + string.digits]
SERIAL_CLASSES = {"hex": "0123456789abcdef", "HEX": "0123456789ABCDEF", "updig": string.ascii_uppercase + string.digits, "lowdig": string.ascii_lowercase + string.digits,
                  "lower": string.ascii_lowercase, "upper": string.ascii_uppercase, "base62": ALNUM}


def make(shape, r):
    """(plant, cores): cores are the random parts a leak would show."""
    if shape == "ghp":
        c = mixed(r, 36); return "ghp_" + c, [c]
    if shape == "akia":
        c = rs(r, 16, string.ascii_uppercase + string.digits); return "AKIA" + c, [c]
    if shape == "github_pat":
        c = rs(r, 22) + "_" + rs(r, 59); return "github_pat_" + c, [c]
    if shape == "xoxb":
        a, b, c = rs(r, 12, string.digits), rs(r, 13, string.digits), mixed(r, 24); return "xoxb-%s-%s-%s" % (a, b, c), [c]
    if shape == "glpat":
        c = rs(r, 20, ALNUM + "_-"); return "glpat-" + c, [c]
    if shape == "sk_live":
        c = rs(r, 24); return "sk_live_" + c, [c]
    if shape == "sendgrid":
        a, b = rs(r, 22, ALNUM + "_-"), rs(r, 43, ALNUM + "_-"); return "SG.%s.%s" % (a, b), [a, b]
    if shape == "aiza":
        c = rs(r, 35, ALNUM + "_-"); return "AIza" + c, [c]
    if shape == "jwt":
        h = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
        p = base64.urlsafe_b64encode(('{"sub":"%s"}' % rs(r, 10)).encode()).decode().rstrip("=")
        s = base64.urlsafe_b64encode(bytes(r.getrandbits(8) for _ in range(32))).decode().rstrip("=")
        return h + "." + p + "." + s, [p, s]
    if shape == "hex40":
        c = rs(r, 40, "0123456789abcdef"); return c, [c]
    if shape == "hex64":
        c = rs(r, 64, "0123456789abcdef"); return c, [c]
    if shape in ("aws", "aws1", "aws2"):
        while True:
            k = rs(r, 40, B64)
            if shape == "aws" or k.count("/") == int(shape[3]):
                return k, [k]
    if shape == "aws_eq":
        k = rs(r, 40, B64); return "aws_secret_access_key=" + k, [k]
    if shape == "b64_16":
        k = with_slash(r, 16); return k, [k]
    if shape == "b64_20":
        k = with_slash(r, 20); return k, [k]
    if shape == "b64_32":
        k = with_slash(r, 32); return k, [k]
    if shape == "accountkey":
        k = b64(r, 64); return "AccountName=a;AccountKey=%s;" % k, [k]
    if shape == "url_userinfo":
        pw = mixed(r, 14); return "https://svcuser:%s@backup.example.test/repo" % pw, [pw]
    if shape == "bare_userinfo":
        pw = mixed(r, 14); return "svcuser:%s@nas01" % pw, [pw]
    if shape == "at_in_pw":
        a, b = mixed(r, 12), mixed(r, 12); return "https://svcuser:%s@%s@backup.example.test/repo" % (a, b), [a, b]
    if shape == "pem":
        body = b64(r, 48); return "-----BEGIN PRIVATE KEY-----" + body + "-----END PRIVATE KEY-----", [body]
    if shape.startswith("named_"):
        nm = NAMES[int(shape[6:]) % len(NAMES)]
        glue = r.choice(["", "vm-1 ", "x", "web01 ", "7", "srv:", "-", "."])
        d = r.choice(["=", ": ", "=\"", ": \"", " = ", ":"])
        v = rs(r, r.randrange(10, 25))
        return "%s%s%s%s%s" % (glue, nm, d, v, '"' if d.endswith('"') else ""), [v]
    if shape.split("_")[0] in FORMS:
        kind, i = shape.split("_")
        forms = FORMS[kind]
        v = rs(r, r.choice([8, 14, 24]), r.choice(MIXED_CLASSES if kind == "phs" else VALUE_CLASSES))
        return forms[int(i) % len(forms)] % v, [v]
    if shape.startswith("t10serial_"):
        _, cls, n = shape.split("_")
        v = rs(r, int(n), SERIAL_CLASSES[cls])
        return "t10.ATA_____Model_X_____" + v, [v]
    if shape.startswith("split_"):
        _, sp, fam = shape.split("_")
        if fam == "akia":
            c = rs(r, 16, string.ascii_uppercase + string.digits); t = "AKIA" + c
        elif fam == "aws":
            c = rs(r, 40, B64); t = c
        else:
            c = mixed(r, 36); t = "ghp_" + c
        out, i = [], 0
        while i < len(t):
            step = r.randrange(2, 20); out.append(t[i:i + step]); i += step
        return SPLIT[sp].join(out), [c]
    raise KeyError(shape)


CTX = {"name": ("name", "%s"), "path": ("file", "vm/%s/disk.vmdk"), "text": (None, "note %s end"), "state": ("state", "%s"),
       "paren": ("file", "snap (%s)"), "braces": ("file", "{%s}"), "squote": ("file", "'%s'"), "pve": ("volume", "local:%s.qcow2")}


def rates():
    out = {}
    for shape in req["shapes"]:
        for ctx in req["contexts"]:
            field, fmt = CTX[ctx]
            r = random.Random(zlib.crc32(("%s|%s|%d" % (shape, ctx, req["seed"])).encode()))
            whole = frag = backstop_alone = 0
            for _ in range(req["n"]):
                tool.RUN["chars"] = 0
                tool.RUN["stop"] = None
                plant, cores = make(shape, r)
                text = fmt % plant
                final = tool.seal_text(text, "boundary", field)
                flagged = False if req.get("seal_only") else tool._suspect(final) is not None
                ns = norm(final)
                if not flagged and all(c in ns for c in cores):
                    whole += 1
                elif not flagged and any(c[i:i + 12] in ns for c in cores for i in range(max(1, len(c) - 11))):
                    frag += 1
                backstop_alone += tool._suspect(text) is None
            out["%s/%s" % (shape, ctx)] = {"whole": whole, "frag": frag, "backstop_alone_misses": backstop_alone}
    return out


def judge():
    out = []
    for field, text in req["items"]:
        sealed = tool.seal_text(text, "boundary", field)
        out.append({"sealed": sealed, "suspect": tool._suspect(text)})
    return out


def linear():
    out = {}
    for name, make_text in (("words", lambda n: ("web-server-prod-db-" * n)[:n]), ("a_a", lambda n: ("a_" * n)[:n]), ("b64", lambda n: rs(random.Random(1), n, B64)),
                            ("colons", lambda n: ("~:" * n)[:n]), ("dashes", lambda n: ("a-" * n)[:n]), ("slashes", lambda n: ("Ab1/" * n)[:n]), ("ghp", lambda n: ("ghp_" * n)[:n]),
                            ("equals", lambda n: ("a=" * n)[:n]), ("at", lambda n: ("u:p@" * n)[:n]), ("invisible", lambda n: ("a\u2066" * n)[:n]), ("pass", lambda n: ("password=" * n)[:n]),
                            ("backslashes", lambda n: "\\" * n), ("eyj", lambda n: ("eyJ" * n)[:n]), ("escape_halves", lambda n: ("\\u20" * n)[:n]),
                            ("t10_underscores", lambda n: ("t10.AB" + "_" * n)[:n]), ("t10_runs", lambda n: ("t10.AB_" * n)[:n]), ("t10_words", lambda n: ("t10.ATA_x_" * n)[:n]),
                            ("iqn_dots", lambda n: ("iqn.2020-01.a." * n)[:n]), ("iqn_tail", lambda n: ("iqn.2020-01.a:" + "a" * n)[:n]), ("naa", lambda n: ("naa." + "a" * n)[:n]),
                            ("eui_wwn_vml", lambda n: ("eui.wwn-0xvml." * n)[:n]), ("win", lambda n: ("WIN-" + "A" * n)[:n]), ("password_brackets", lambda n: ("password=<" * n)[:n]),
                            ("flag_brackets", lambda n: ("-password <" * n)[:n]), ("key_flags", lambda n: ("--a-b-c-d-e-key " * n)[:n]), ("key_dashes", lambda n: ("-a" * n)[:n]),
                            ("placeholder_words", lambda n: ("password=<redacted> abcdefgh " * n)[:n]), ("t10_free_letters", lambda n: ("t10.ATA_____x_____" + "a" * n)[:n]),
                            ("iqn_letters", lambda n: ("iqn.2020-01.a:" + "a" * n)[:n]), ("two_d", lambda n: ("t10.AB_" + "WD2D" * n)[:n]), ("secret_tags", lambda n: ("pwd-srv01 " * n)[:n]),
                            ("secret_words", lambda n: ("password" * n)[:n]), ("secret_dots", lambda n: ("pwd.vmdk" * n)[:n]),
                            ("secret_groups", lambda n: ("password-ab12-cd34-" * n)[:n]), ("secret_counters", lambda n: ("Token-000001-" * n)[:n]), ("secret_stamps", lambda n: ("pwd-D2024-10-04T020013_AB12 " * n)[:n]),
                            ("secret_brackets", lambda n: ("[token-(pwd-" * n)[:n]), ("glued_flags", lambda n: ("--master-keyabcdefgh --userpass" * n)[:n]), ("camel_flags", lambda n: ("--apiToken -AdminPassword " * n)[:n]),
                            ("key_files", lambda n: ("--key ~/.ssh/id_rsa --tls-auth ta.key " * n)[:n]), ("iqn_hex", lambda n: ("iqn.2010-06.com.purestorage:flasharray." + "a1" * n)[:n]), ("flag_dashes", lambda n: ("--a-b-c-d-e-password" * n)[:n]),
                            ("secret_tags_long", lambda n: ("pwd-" + "srv01-" * n)[:n])):
        def once(text):
            tool._SEALED.clear(); tool._CHECKED.clear(); tool.RUN["chars"] = 0; tool.RUN["stop"] = None
            tool.seal_text(text, "boundary", req.get("field"))
            tool._suspect(text)
        times = ladder(once, [make_text(n) for n in req["sizes"]])
        out[name] = dict(zip((str(n) for n in req["sizes"]), (None if t is None else round(t, 4) for t in times)))
        if not ladder_ok(times):
            break  # the test names this shape; the rest would only take longer
    return out


def stop():
    tool.RUN["deadline"] = time.monotonic() - 1
    tool.RUN["stop"] = None
    a = tool.seal_text("a plain sentence that was not judged before " + str(random.random()), "boundary", None)
    b = tool.seal_text("web01", "boundary", "name")
    return {"after_deadline": a, "short_name": b, "stop": tool.RUN["stop"], "count": tool.RUN["stopped_strings"]}


def answer():
    tool.RUN["deadline"] = time.monotonic() - 1
    tool.RUN["stop"] = None
    tool.seal_text("a plain sentence nobody judged before " + str(random.random()), "boundary", None)
    doc = json.loads(tool.answer_text({"status": "complete", "status_basis": "every file was read", "note": "hello"}))
    return {"status": doc["status"], "basis": doc["status_basis"], "stopped_by": doc["boundary"]["stopped_by"], "withheld_by_the_stop": doc["boundary"]["strings_withheld_by_the_stop"], "note": doc["note"]}


def cap():
    tool.RUN["cap"] = 100
    tool.RUN["chars"] = 0
    tool.RUN["stop"] = None
    a = tool.seal_text("ab cd " * 10 + "q1", "boundary", None)
    b = tool.seal_text("ef gh " * 10 + "q2", "boundary", None)
    return {"first": a == "ab cd " * 10 + "q1", "second": b, "stop": tool.RUN["stop"]}


print(json.dumps({"rates": rates, "judge": judge, "linear": linear, "stop": stop, "answer": answer, "cap": cap}[req["op"]]()))
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

// ---- layer 1: what is shown --------------------------------------------------------------------------------------------

test("an identifier field shows a plain name, a path, a device id and a content id, and withholds a token-shaped or odd one with its size and field", async () => {
  const shown: [string, string][] = [
    ["name", "Web-Server-01 (clone)"], ["name", "SRV-WEB01"], ["name", "Ubuntu 22.04 LTS"], ["name", "VM Snapshot 10%2f4%2f2024, 10:15:30 AM"], ["name", "nyc-grafana-57 - (10/05/2024 - 18:48:16)"],
    ["name", "ProxyK8sMgmtNode10"], ["name", "Sunucu-Üretim-01"], ["name", "iqn.2004-12.com.example:sql-f1f9be4b"], ["name", "ExchangeMailboxServerPrimary01"],
    ["path", "/vmfs/volumes/5f3d1a2b-9c8d7e6f-1a2b-0123456789ab/web01/web01-000002.vmdk"], ["path", "[datastore1] web01/web01.vmdk"], ["path", "/vmfs/volumes/datastore1/My VM/My VM.vmdk"],
    ["path", "C:\\ClusterStorage\\Volume1\\ProxyHr19\\VcenterOracle13_D41A224A-5C97-FDC1-1593-D7243F90EE4F.avhdx"], ["path", "/dev/disk/by-id/naa.6818b904ce6087413e3b266f850f1578"],
    ["path", "/vmfs/devices/disks/t10.ATA_____Samsung_SSD_870_EVO_1TB_____S5Y2NX0T571161"], ["path", "local-lvm:vm-100-disk-0"], ["path", "local:100/vm-100-disk-1.qcow2"], ["path", "/var/lib/vz/images/100/vm-100-disk-1.qcow2"],
    ["path", "/dev/disk/by-id/wwn-0x5000c500a1b2c3d4"], ["path", "pvc-24aa1734-4d10-79ab-5e32-0f4a02e50777.qcow2"],
    ["id", "56 4d 4f 9a 8b 7c 6d 5e-12 34 56 78 9a bc de f0"], ["id", "56e64dc3cd6089065c3146e80a9c2226"], ["id", "naa.6818b904ce6087413e3b266f850f1578"], ["id", "5f3d1a2b-9c8d7e6f-1a2b-0123456789ab"],
    ["id", "{236EBA1F-5CB5-8B8E-1799-E72821AF214A}"], ["id", "00:50:56:e7:a4:26"], ["id", "d4ea65d0"], ["id", "12"],
    ["name", "password-vault-backup"], ["name", "Token Ring VM"], ["name", "pwd-server01"], ["name", "Passwords DB snapshot"], ["name", "Secret Server 2019 (prod)"], ["name", "Credential Guard W10 template"],
    ["name", "AWS Secret Key Rotation"], ["name", "Hashicorp Vault Token Broker"], ["name", "SecretsManager-clone"], ["simple", "token ring 4"],
    ["path", "/vmfs/volumes/vsan:52f3b0b5a8c6e1d2-9a8b7c6d5e4f3a2b/c1b3a65e-1f2a-3b4c-5d6e-7f8091a2b3c4/web01.vmdk"], ["path", "/vmfs/devices/disks/t10.ATA_____WDC_WD40EFRX2D68N32N0_____WD2DWCC7K1234567"],
    ["path", "/vmfs/devices/disks/t10.ATA_____INTEL_SSDSC2BB480G4_____BTWL123456AB480BGN"], ["path", "/vmfs/devices/disks/t10.ATA_____KINGSTON_SA400S37240G_____50026B7783D6A1C8"],
    ["path", "/vmfs/devices/disks/t10.ATA_____Samsung_SSD_870_EVO_1TB_____S5Y2NX0T571161"], ["path", "/vmfs/devices/disks/t10.ATA_____ST4000DM0042D2CV104_____ZDH1ABCD"],
    ["simple", "windows9Server64Guest"], ["simple", "pve-manager/7.3-12"], ["simple", "2024-05-09T03:47:47+03:00"], ["simple", "vmx-19"], ["simple", "monolithicSparse"],
  ];
  const FIELD: Record<string, string> = { name: "name", path: "file", id: "uid", simple: "version" };
  const withheld: [string, string][] = [
    ["name", "Q7fZx9LmR2kT4vb8nwc1y6pd3shJ0aXe5uQz"], ["name", "AKIAIOSFODNN7EXAMPLE"], ["name", "web01 vncPassword=Q7fZxLmRkTvbnwcy"], ["name", "svc:Pa55w0rd@nas01"], ["name", "a".repeat(161)],
    ["name", "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"], ["path", "/var/lib/libvirt/images/web01.qcow2?rootPassword=hJaXeuQzWpLmNbVc/x"], ["path", "https://svc:Pa55w0rdQ7fZ@nas01/share"], ["path", "pass:OfmHIEuiuW9NBS1"], ["path", "vm-Snapshot99130122398bae6eecece52413628fd183c188c7.vmsn"], ["path", "auth:abc"],
    ["name", "-password Zq7kP2mR"], ["name", "--password Zq7kP2mR"], ["name", "set password Zq7kP2mR"], ["name", "-pwd Zq7kP2mR"], ["name", "-token Zq7kP2mR"], ["name", "-secret Zq7kP2mR"],
    ["name", "d--pwd Zq7kP2mR"], ["name", "pwd-Zq7kP2mR"], ["name", "Token Zq7kP2mR"], ["name", "-pwdZq7kP2mR"], ["name", "-password abcdef"], ["path", "vm/-password Zq7kP2mR/a.vmdk"], ["simple", "-token Zq7kP2mR"],
    ["path", "/vmfs/volumes/vsan:" + "0123456789abcdef" + "0123456789abcdef" + "01234567/a/b.vmdk"], ["path", "/vmfs/devices/disks/t10.ATA_____Model_X_____" + "q7fz" + "x9lm" + "r2kt" + "4vb8nwc1"],
    ["id", "pwd-Zq7kP2mR"], ["id", "Q7fZx9LmR2kT4vb8nwc1y6pd3shJ0aXe5uQz"], ["id", "d41d8cd98f00b204e9800998ecf8427e5ca9d41d8cd98f00b204e9800998ecf8"], ["simple", "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"], ["simple", "x=1"],
  ];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items: [...shown, ...withheld].map(([k, t]) => [FIELD[k], t]) });
    shown.forEach(([k, t], i) => assert.equal(got[i].sealed, t, `${label}: a ${k} that is not a secret is shown as it is`));
    withheld.forEach(([k, t], i) => {
      const s: string = got[shown.length + i].sealed;
      assert.match(s, /<withheld: \d+ bytes, field [a-z_ ]+>|<token-shaped text withheld \d+ characters>/, `${label}: ${k} ${t.slice(0, 30)} -> ${s}`);
      if (t.length > 30) assert.equal(s.includes(t.slice(8, 30)), false);
    });
  }
});

test("the layers are not the same check: every name the allow-list shows, the second check also lets through (it would otherwise replace it and make the answer partial)", async () => {
  const items: [string | null, string][] = [];
  for (const k of ["web-server-prod-db-01-eu-west-1", "Production-Database-Server-Primary-Node-01", "kube-system-coredns-5d78c9869d-x7k2p", "SQLServerProd2019-clone", "esxi-01.corp.example.com"]) items.push(["name", k]);
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items });
    got.forEach((g: Json, i: number) => assert.equal(g.suspect, null, `${label}: ${items[i][1]}`));
  }
});

// ---- the random canaries: the rate of what is shown whole, for each context, asserted ---------------------------------------

const CERTAIN = ["ghp", "akia", "github_pat", "xoxb", "glpat", "sk_live", "sendgrid", "aiza", "jwt", "hex40", "hex64", "aws_eq", "accountkey", "url_userinfo", "bare_userinfo", "at_in_pw", "pem"];
const SPLITS = Object.keys({ lri: 1, rli: 1, fsi: 1, pdi: 1, alm: 1, vs16: 1, vs1: 1, tag: 1, cgj: 1, hfill: 1, ffa0: 1, comb: 1, enclose: 1, zw: 1, shy: 1, bom: 1, wj: 1, lrm: 1, nul: 1, ls: 1, mvs: 1, esc: 1, escx: 1 });

test("random canaries: a prefixed token, a JWT, a hex digest, user-info, a key after a name, a PEM key and AWS-style keys are not shown whole in a name, a path or free text, at any random split by an invisible character", async () => {
  const shapes = [...CERTAIN, "aws", "aws1", "aws2", "b64_16", "b64_20", "b64_32", ...SPLITS.flatMap((s) => [`split_${s}_ghp`, `split_${s}_akia`, `split_${s}_aws`])];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "rates", n: N, seed: 11, shapes, contexts: ["name", "path", "text"] });
    for (const [key, v] of Object.entries(got as Record<string, { whole: number; frag: number }>)) {
      const shape = key.split("/")[0];
      const bound = /^(aws|aws1|aws2|b64_16|b64_20|b64_32)$/.test(shape) || shape.endsWith("_aws") ? Math.ceil(N * 0.02) : 0;       // base64 keys with `/` cut into pieces under 16 characters: measured, listed in the changelog
      assert.ok(v.whole <= bound, `${label} ${key}: ${v.whole} of ${N} shown whole (bound ${bound})`);
    }
  }
});

test("random canaries: the value after a secret's name is not shown, glued to a letter or CamelCase, in free text, and a name field holding one is withheld whole", async () => {
  const shapes = Array.from({ length: 27 }, (_, i) => `named_${i}`);
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "rates", n: N, seed: 5, shapes, contexts: ["name", "path", "text"] });
    for (const [key, v] of Object.entries(got as Record<string, { whole: number }>)) assert.ok(v.whole <= Math.ceil(N * 0.005), `${label} ${key}: ${v.whole} of ${N} shown whole`);
  }
});

const idx = (n: number, prefix: string): string[] => Array.from({ length: n }, (_, i) => `${prefix}_${i}`);

test("random canaries: a flag with its value (-password x, --password x, set password x, -pwd x, -token x and the others, also glued to a word or to the name) is not shown in a name, a path component, a state field or, at the start of a word, free text, for values of 8, 14 and 24 characters of every class: the seal alone, without the second check", async () => {
  for (const [label, script] of TOOLS) {
    const shown: string[] = [];
    // forms 0 to 12 start a word (free text judges them too); the rest are glued behind a letter or a dash, which only the identifier fields judge
    for (const [shapes, contexts] of [[idx(13, "flag"), ["name", "path", "state", "text"]], [idx(FLAG_FORMS, "flag").slice(13), ["name", "path", "state"]]] as const) {
      const got = await host(script, { op: "rates", n: N, seed: 21, shapes, contexts, seal_only: true });
      for (const [key, v] of Object.entries(got as Record<string, { whole: number }>)) if (v.whole > 0) shown.push(`${key}: ${v.whole}`);
    }
    assert.deepEqual(shown, [], `${label}: values shown whole by the seal, of ${N} plants a cell`);
  }
});

test("random canaries: a secret's name, a separator and a value that is not a word (password-x, token x, secret_x, pwd x, glued or not) is not shown in a name, a path component or a state field, for values of 8, 14 and 24 characters (the seal alone; a word after the name, Token Ring or Password Vault, is a name)", async () => {
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "rates", n: N, seed: 22, shapes: idx(BARE_FORMS, "bare"), contexts: ["name", "path", "state"], seal_only: true });
    const bad = Object.entries(got as Record<string, { whole: number }>).filter(([, v]) => v.whole > Math.ceil(N * 0.02)).map(([k, v]) => `${k}: ${v.whole}`);
    assert.deepEqual(bad, [], `${label}: more than 2% of ${N} shown whole by the seal`);
  }
});

test("random canaries: a placeholder with a value glued behind it (password=<redacted>x, --password <redacted>x, token: <secret>x, set password <hidden>x, pwd=<***>x, password=<>x) hides the value in the seal and in the second check alone; after a space the value is hidden unless it reads as a word or has no digit before a letter and no small letter before a capital", async () => {
  for (const [label, script] of TOOLS) {
    const glued = await host(script, { op: "rates", n: N, seed: 23, shapes: idx(PH_FORMS, "ph"), contexts: ["text"], seal_only: true });
    for (const [key, v] of Object.entries(glued as Record<string, { whole: number; backstop_alone_misses: number }>)) {
      assert.equal(v.whole, 0, `${label} ${key}: ${v.whole} of ${N} shown by the seal`);
      assert.equal(v.backstop_alone_misses, 0, `${label} ${key}: the second check alone missed ${v.backstop_alone_misses} of ${N}`);
    }
    const spaced = await host(script, { op: "rates", n: N, seed: 24, shapes: idx(PH_SPACE_FORMS, "phs"), contexts: ["text"], seal_only: true });
    for (const [key, v] of Object.entries(spaced as Record<string, { whole: number; backstop_alone_misses: number }>)) {
      assert.ok(v.whole <= Math.ceil(N * 0.04), `${label} ${key}: ${v.whole} of ${N} shown by the seal`);
      assert.ok(v.backstop_alone_misses <= Math.ceil(N * 0.04), `${label} ${key}: the second check alone missed ${v.backstop_alone_misses} of ${N}`);
    }
  }
});

test("random canaries: a padded 16- or 20-byte base64 key with a / that has a short padding piece and glue after it (snap (KEY), {KEY}, 'KEY', local:KEY.qcow2) leaves no piece of 12 characters, no whole key", async () => {
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "rates", n: Math.max(N, 1000), seed: 25, shapes: ["b64_16", "b64_20"], contexts: ["paren", "braces", "squote", "pve"], seal_only: true });
    for (const [key, v] of Object.entries(got as Record<string, { whole: number; frag: number }>)) {
      assert.equal(v.whole, 0, `${label} ${key}: ${v.whole} of 1000 shown whole`);
      assert.ok(v.frag <= 3, `${label} ${key}: a piece of 12 characters in ${v.frag} of 1000`);
    }
  }
});

test("random canaries: a random serial in a t10. device id is judged as it is without the id around it: hexadecimal of 20 to 24 characters (16 digits are a 64-bit id and shown), and 24 characters of capitals and digits, small letters and digits, one case of letters or letters and digits in both cases, are shown in at most one in ten", async () => {
  const shapes = ["hex_20", "hex_24", "HEX_20", "HEX_24", "updig_24", "lowdig_24", "lower_24", "upper_24", "base62_24", "base62_20"].map((k) => `t10serial_${k}`);
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "rates", n: N, seed: 26, shapes, contexts: ["name", "path"], seal_only: true });
    for (const [key, v] of Object.entries(got as Record<string, { whole: number }>)) {
      const bound = /hex_|HEX_/.test(key) ? Math.ceil(N * 0.03) : Math.ceil(N * 0.1);
      assert.ok(v.whole <= bound, `${label} ${key}: ${v.whole} of ${N} shown whole (bound ${bound})`);
    }
  }
});

test("end to end: a flag with its value or a placeholder with a value behind it, planted in the names, paths and free-text fields of the three tools, reaches no answer, no paging file and no file name, in and out of a job", async () => {
  const r = prng(20261016);
  const UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", LO = "abcdefghijklmnopqrstuvwxyz", DG = "0123456789";
  const classes = [UP + LO + DG, LO, UP, DG, LO + DG, UP + DG];
  const pick = (alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[Math.floor(r() * alphabet.length)]).join("");
  const flags = ["-password %", "--password %", "set password %", "-pwd %", "-token %", "--token %", "-secret %", "-pass %", "--api-key %", "d--pwd %", "-pwd%", "-token%", "x-password%"];
  const holders = ["password=<redacted>%", "--password <redacted>%", "token: <secret>%", "set password <hidden>%", "pwd=<***>%", "password=<>%"];
  const plants: { text: string; value: string; flag: boolean }[] = [];
  for (const [forms, flag] of [[flags, true], [holders, false]] as const) {
    for (const form of forms) for (const n of [8, 14, 24]) {
      const value = pick(classes[plants.length % classes.length], n);
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
  const csv = ["t,a,o,m", ...plants.map((p) => `2024-01-05T02:00:00Z,Backup,${cell(p.text).replace(/,/g, ";")},note ${cell(p.text).replace(/,/g, ";")} end`)].join("\n") + "\n";
  for (const job of [false, true]) {
    for (const [label, script, files, args] of [
      ["inventory", INVENTORY, inventory, { root: "inputs", limit: 200 }],
      ["chain", CHAIN, chain, { root: "inputs", limit: 200 }],
      ["audit", AUDIT, { "x.csv": csv }, { path: "inputs/x.csv", format: "declared_csv", mapping: { time: "t", action: "a", object: "o", message: "m" }, limit: 200 }],
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

test("the second check alone finds the named secrets, the prefixed tokens and the invisible splits the layers above withhold", async () => {
  const shapes = ["ghp", "akia", "jwt", "url_userinfo", "bare_userinfo", "at_in_pw", "pem", ...Array.from({ length: 27 }, (_, i) => `named_${i}`), "split_lri_ghp", "split_tag_ghp", "split_vs16_akia", "split_comb_ghp", "split_zw_ghp", "split_alm_akia"];
  const got = await host(CHAIN, { op: "rates", n: Math.min(N, 200), seed: 3, shapes, contexts: ["text"] });
  for (const [key, v] of Object.entries(got as Record<string, { backstop_alone_misses: number }>)) assert.ok(v.backstop_alone_misses <= Math.ceil(Math.min(N, 200) * 0.02), `${key}: the second check alone missed ${v.backstop_alone_misses}`);
});

// ---- invisible characters, glued names, the review's repros --------------------------------------------------------------

test("a token split by a bidi isolate, a variation selector, a tag character, a combining mark or a filler is withheld in all three tools (the first review repro, end to end)", async () => {
  for (const [label, script, mk] of [
    ["chain", CHAIN, (v: string) => ({ "vm/a.vmdk": vmdkDescriptor({ cid: "aabbccdd", parentCid: "11223344", parentHint: v, extents: [{ sectors: 8, type: "FLAT", name: "a-flat.vmdk" }] }) })],
    ["inventory", INVENTORY, (v: string) => ({ "vm/a.vmx": vmx([["displayName", v], ["guestOS", v]]) })],
  ] as const) {
    for (const split of ["\u2066", "\u2067", "\u2068", "\u2069", "\u061c", "\ufe0f", "\ufe00", "\u{e0041}", "\u034f", "\u3164", "\uffa0", "\u0301", "\u20dd", "\u200b"]) {
      await withCwd(async (cwd) => {
        const secret = "Q7fZx9LmR2kT4vb8nwc1y6pd3shJ0aXe5uQz";
        const planted = `ghp_${secret.slice(0, 13)}${split}${secret.slice(13, 26)}${split}${secret.slice(26)}`;
        for (const [rel, data] of Object.entries(mk(planted))) await put(cwd, `inputs/${rel}`, data);
        const out = await tool(script, cwd, { root: "inputs" });
        const text = out.stdout.normalize("NFKC");
        for (let k = 0; k + 12 <= secret.length; k++) assert.equal(text.includes(secret.slice(k, k + 12)), false, `${label}: ${split.codePointAt(0)?.toString(16)} leaves ${secret.slice(k, k + 12)}`);
        const doc = JSON.parse(out.stdout);
        assert.equal(doc.boundary.strings_replaced_by_the_check, 0, `${label}: the seal did the work, not the check`);
      });
    }
  }
  await withCwd(async (cwd) => {
    const split = "\u2066", secret = "Q7fZx9LmR2kT4vb8nwc1y6pd3shJ0aXe5uQz";
    await put(cwd, "inputs/x.csv", `t,a,h\n2024-01-05T02:00:00Z,Backup,AKIA${split}IOSFODNN7EXAMPLE\n2024-01-05T02:00:01Z,Backup,ghp_${secret.slice(0, 10)}${split}${secret.slice(10)}\n`);
    const out = await tool(AUDIT, cwd, { path: "inputs/x.csv", format: "declared_csv", mapping: { time: "t", action: "a", host: "h" } });
    assert.equal(out.stdout.normalize("NFKC").includes("IOSFODNN7EXAMPLE"), false);
    assert.equal(out.stdout.normalize("NFKC").includes(secret.slice(10, 25)), false);
  });
});

test("a secret name glued to a letter or written in CamelCase (adminPassword=, vncPassword=, accessToken:, SecretAccessKey:, PWD=, pass=, credential=, PGPASSWORD=, MYSQL_PWD=, --password x, sig=, cipassword:) hides its value in free text, and a name field holding one is withheld whole", async () => {
  const value = "hJaXeuQzWpLmNbVc3";
  const lines = ['["rootPassword=\\"', '["token=\\"', "web01 vncPassword=", "vm-1 adminPassword=", "repo accessToken: ", "SecretAccessKey: ", "Server=db1;UID=sa;PWD=", "x pass=", "a pw=", "credential=", "x auth=", "PGPASSWORD=", "MYSQL_PWD=", "cipassword: ", "https://h/x?sig=", "mysql --password ", "dbpass=", "apikey: ", "AccountKey="];
  const items: [string | null, string][] = lines.map((l) => [null, `${l}${value}`]);
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items: [...items, ...lines.map((l): [string, string] => ["name", `${l}${value}`])] });
    got.forEach((g: Json, i: number) => {
      assert.equal(g.sealed.includes(value.slice(2, 14)), false, `${label}: ${items[i % lines.length][1]} -> ${g.sealed}`);
      assert.notEqual(g.suspect, null, `${label}: the second check alone must find ${lines[i % lines.length]}`);
    });
    const prose = await host(script, { op: "judge", items: [[null, "the job ran with secret_output: true"], [null, "S000001: the XML stopped being readable (unclosed token: line 1, column 25)"], [null, "bypass: yes compass: north"]] });
    assert.deepEqual(prose.map((p: Json) => [p.sealed, p.suspect]), [["the job ran with secret_output: true", null], ["S000001: the XML stopped being readable (unclosed token: line 1, column 25)", null], ["bypass: yes compass: north", null]], `${label}: words are not secrets`);
  }
});

// ---- time and size: every layer is linear ---------------------------------------------------------------------------------

test("the layers take time proportional to the length of a string: 6,250, 25,000 and 100,000 characters of each pathological shape (`a-a-a-...`, `a_a_a_...`, `~:~:`, `Ab1/Ab1/`, `u:p@u:p@`, `password=password=`, a run of backslashes, `eyJeyJ`, `\\u20\\u20`, `t10.AB` and a run of underscores, `iqn.`, `naa.`, `eui.`, `WIN-` runs, `password=<` runs, `--a-b-c-key` flags, `password=<redacted> abcdefgh` repeated, `t10.` and `iqn.` ids with a long run of one letter, `WD2D` runs, `pwd-srv01` and `pwd.vmdk` repeated, groups of four, counters, time stamps and brackets after a secret's name, glued and CamelCase flags, key files, `iqn.` ids with a hexadecimal serial), in CPU seconds, the least of up to three rounds, each step at most 8 times the one before", async () => {
  for (const [label, script] of TOOLS) {
    for (const field of [null, "name", "file", "uid"]) {
      const t = await host(script, { op: "linear", sizes: SIZES, field });
      for (const [shape, row] of Object.entries(t as Record<string, Record<string, number | null>>)) {
        const times = SIZES.map((n) => row[String(n)]);
        assert.ok(ladderOk(times), `${label} ${field} ${shape}: ${SIZES.map((n, i) => `${n} characters ${times[i] === null ? "not run" : `${times[i]} s`}`).join(", ")} is not linear (best of up to three rounds, each step four times the length)`);
        assert.ok((times[times.length - 1] as number) < 3, `${label} ${field} ${shape}: 100 KB took ${times[times.length - 1]} s`);
      }
    }
  }
});

test("past its time or character budget a string is withheld by its size, and the answer says it stopped", async () => {
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "stop" });
    assert.match(got.after_deadline, /^<withheld: \d+ bytes, run limit>$/, label);
    assert.equal(got.stop, "max_seconds");
    assert.ok(got.count >= 1);
  }
});

test("a run that passes its time or its character cap says so in the answer: partial, boundary.stopped_by, and the strings it could not judge withheld by size", async () => {
  for (const [label, script] of TOOLS) {
    const a = await host(script, { op: "answer" });
    assert.equal(a.status, "partial", label);
    assert.equal(a.stopped_by, "max_seconds");
    assert.match(a.basis, /judging the strings stopped at max_seconds/);
    assert.ok(a.withheld_by_the_stop >= 1);
    assert.equal(a.note, "hello", "the final answer itself is still judged and shown");
    const c = await host(script, { op: "cap" });
    assert.equal(c.first, true);
    assert.match(c.second, /^<withheld: 62 bytes, run limit>$/);
    assert.match(c.stop, /cap of \d+ characters/);
  }
});

function pathological(): { vmsd: string; names: string[] } {
  const U = (n: number, i: number): string => "a_".repeat(n / 2).slice(0, n - 6) + String(i).padStart(6, "0");
  const lines = [".encoding = \"UTF-8\"", "snapshot.numSnapshots = \"300\""];
  for (let i = 0; i < 300; i++) lines.push(`snapshot${i}.uid = "${i + 1}"`, `snapshot${i}.displayName = "${U(4000, i)}"`, `snapshot${i}.numDisks = "0"`);
  return { vmsd: lines.join("\n") + "\n", names: [] };
}

test("the second review's slow inputs finish inside max_seconds plus two: 300 snapshot names of 4,000 characters in a .vmsd and 100 random base64 names, in both tools that read it", async () => {
  for (const [label, script] of [["chain", CHAIN], ["inventory", INVENTORY]] as const) {
    await withCwd(async (cwd) => {
      await put(cwd, "inputs/vmsd/vm.vmsd", pathological().vmsd);
      let started = Date.now();
      const out = await tool(script, cwd, { root: "inputs/vmsd", max_seconds: 5 });
      const wall = (Date.now() - started) / 1000;
      const doc = json(out);
      assert.ok(["complete", "partial"].includes(doc.status), `${label}: ${doc.status}`);
      assert.ok(wall < 7, `${label}: ${wall} s for 300 names of 4,000 characters at max_seconds 5`);
      assert.equal(out.stderr, "");
      const r = (s: number): string => Array.from({ length: 4000 }, (_, i) => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(Math.imul(i + 1, 2654435761 + s) >>> 7) % 64]).join("");
      const lines = [".encoding = \"UTF-8\"", "snapshot.numSnapshots = \"100\""];
      for (let i = 0; i < 100; i++) lines.push(`snapshot${i}.uid = "${i + 1}"`, `snapshot${i}.displayName = "${r(i)}"`);
      await put(cwd, "inputs/b64/vm.vmsd", lines.join("\n") + "\n");
      started = Date.now();
      const out2 = await tool(script, cwd, { root: "inputs/b64", max_seconds: 5 });
      assert.ok((Date.now() - started) / 1000 < 7, `${label}: random base64 names took ${(Date.now() - started) / 1000} s`);
      assert.ok(["complete", "partial"].includes(json(out2).status));
      assert.equal(out2.stderr, "");
    });
  }
});

test("an audit CSV of 300 rows with a 4,000-character object and a 1 MB single field finish inside max_seconds plus two, and the answer is JSON", async () => {
  await withCwd(async (cwd) => {
    const U = (i: number): string => "a_".repeat(2000).slice(0, 3994) + String(i).padStart(6, "0");
    await put(cwd, "inputs/x.csv", ["t,a,o", ...Array.from({ length: 300 }, (_, i) => `2026-01-02T03:04:05Z,Backup,${U(i)}`)].join("\n") + "\n");
    let started = Date.now();
    const out = await tool(AUDIT, cwd, { path: "inputs/x.csv", format: "declared_csv", mapping: { time: "t", action: "a", object: "o" }, max_seconds: 5 });
    assert.ok((Date.now() - started) / 1000 < 7, `${(Date.now() - started) / 1000} s`);
    assert.ok(["complete", "partial"].includes(json(out).status));
    await put(cwd, "inputs/big.csv", `t,a,o\n2026-01-02T03:04:05Z,Backup,${"ab1_".repeat(262144)}\n`);
    started = Date.now();
    const big = await tool(AUDIT, cwd, { path: "inputs/big.csv", format: "declared_csv", mapping: { time: "t", action: "a", object: "o" }, max_seconds: 5, max_line_bytes: 4_194_304 });
    assert.ok((Date.now() - started) / 1000 < 7, `a 1 MB field took ${(Date.now() - started) / 1000} s`);
    assert.ok(["complete", "partial"].includes(json(big).status));
  });
});

// ---- a lone surrogate, a signal, the paging file --------------------------------------------------------------------------

test("a lone surrogate in a JSON Lines value neither fails the run nor loses the good event, and leaves no unnamed paging file", async () => {
  await withCwd(async (cwd) => {
    const good = JSON.stringify({ t: "2024-01-05T02:00:00Z", a: "Backup", u: "alice" });
    await put(cwd, "inputs/x.jsonl", `${good}\n{"t":"2024-01-05T02:00:01Z","a":"mzk1FFU7RMdD6clrY/7NKQ==y\\ud83d","u":"\\ud83d"}\n${good}\n`);
    await mkdir(join(cwd, "out"), { recursive: true });
    for (const limit of [1, 200]) {
      const out = await asJob(AUDIT, cwd, { path: "inputs/x.jsonl", format: "declared_jsonl", mapping: { time: "t", action: "a", actor: "u" }, limit }, undefined, {}, `out${limit}`);
      const doc = body(out);
      assert.notEqual(doc.status, "failed", doc.error);
      assert.equal(doc.counts.events, 3);
      assert.equal(out.stderr, "");
      const files = await filesUnder(join(cwd, `out${limit}`));
      assert.equal(files.some((f) => /\.jsonl-\w+$/.test(f) || /\/\.[^/]*$/.test(f)), false, `no temporary paging file is left: ${files.join(", ")}`);
    }
  });
});

test("SIGTERM during a run: one JSON answer that names the signal and the rows kept, exit 128+15, and no temporary paging file left unnamed (all three tools)", async () => {
  for (const [label, script, args, files] of [
    ["audit", AUDIT, { path: "inputs/x.csv", format: "declared_csv", mapping: { time: "t", action: "a", object: "o" }, limit: 1 }, { "x.csv": ["t,a,o", ...Array.from({ length: 400000 }, (_, i) => `2026-01-02T03:04:05Z,Backup,vm-${i}`)].join("\n") + "\n" }],
    ["inventory", INVENTORY, { root: "inputs/d", limit: 1 }, Object.fromEntries(Array.from({ length: 3000 }, (_, i) => [`d/vm${i}.vmx`, vmx([["displayName", `vm${i}`], ["scsi0:0.fileName", `vm${i}.vmdk`]])]))],
    ["chain", CHAIN, { root: "inputs/d", limit: 1 }, Object.fromEntries(Array.from({ length: 3000 }, (_, i) => [`d/vm${i}.vmdk`, vmdkDescriptor({ cid: i.toString(16).padStart(8, "0"), parentCid: "ffffffff", extents: [{ sectors: 8, type: "FLAT", name: `vm${i}-flat.vmdk` }] })]))],
  ] as const) {
    await withCwd(async (cwd) => {
      for (const [rel, data] of Object.entries(files)) await put(cwd, `inputs/${rel}`, data as string);
      await mkdir(join(cwd, "out"), { recursive: true });
      const child = startDetached(script, cwd, args, { JOB_ID: "j000777", OUT: join(cwd, "out") });
      const dir = join(cwd, "out", "tool-output");
      let temp = false;
      for (let i = 0; i < 400 && !temp; i++) {
        await new Promise((r) => setTimeout(r, 25));
        temp = (await readdir(dir).catch(() => [] as string[])).some((f) => f.startsWith("."));
        if (child.stdout().includes('"status"')) break;
      }
      if (!temp) return;                      // the run finished before there was a temporary file: nothing to test on this machine
      child.signal("SIGTERM");
      const code = await child.closed;
      for (let i = 0; i < 800 && !child.stdout().includes('"status"'); i++) await new Promise((r) => setTimeout(r, 25));      // the pipe drains after the exit event
      assert.equal(code, 143, `${label} exit code`);
      const doc = JSON.parse(child.stdout());
      assert.equal(doc.status, "partial");
      assert.equal(doc.stopped_by_signal, "SIGTERM");
      assert.ok(Array.isArray(doc.paging_files_left) && doc.paging_files_left.length >= 1, `${label}: ${JSON.stringify(doc).slice(0, 400)}`);
      const left = await readdir(dir);
      assert.equal(left.some((f) => f.startsWith(".")), false, `${label}: a temporary paging file was left: ${left.join(", ")}`);
      assert.ok(left.some((f) => f.endsWith(".partial")), `${label}: the rows kept are named .partial`);
      assert.equal(doc.paging_files_left.every((n: string) => left.includes(n.split("/").pop() as string)), true, "every file the answer names exists");
    });
  }
});

// ---- the declared time, the damaged headers -------------------------------------------------------------------------------

test("a declared time that never parses makes the answer partial and says why", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/x.csv", "t,a\nlast tuesday,Backup\nnext week,Backup\n");
    const doc = body(await tool(AUDIT, cwd, { path: "inputs/x.csv", format: "declared_csv", mapping: { time: "t", action: "a" } }));
    assert.equal(doc.status, "partial");
    assert.match(doc.status_basis, /declared time field never parsed/);
    assert.equal(doc.time.not_derived, 2);
  });
});

test("a VHDX with one header that fails its CRC and a VHD whose end footer is missing are named by a marker and make the answer partial", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/a.vhdx", vhdx({ diskId: "AAAAAAAA-0000-4000-8000-000000000001", headers: [{ breakCrc: true }, {}] }));
    const dyn = vhdDynamic({ uid: "11111111-aaaa-bbbb-cccc-000000000001" });
    await put(cwd, "inputs/b.vhd", dyn.subarray(0, dyn.length - 512));
    const out = body(await tool(CHAIN, cwd, { root: "inputs" }));
    assert.equal(out.status, "partial");
    const kinds = new Set<string>(out.markers.map((m: Json) => m.kind));
    assert.ok(kinds.has("vhdx_header_copy_damaged"), [...kinds].join(", "));
    assert.ok(kinds.has("vhd_footer_copy_missing"), [...kinds].join(", "));
    assert.match(out.status_basis, /failed their checksum/);
  });
});

test("a QCOW2 child that declares a qcow2 backing format over a raw file is parent_unreadable, and the chain note says so", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/base.raw", Buffer.alloc(4096, 7));
    await put(cwd, "inputs/top.qcow2", qcow2({ backing: "base.raw", backingFormat: "qcow2" }));
    const out = body(await tool(CHAIN, cwd, { root: "inputs" }));
    assert.equal(out.chains[0].status, "parent_unreadable");
    assert.match(out.chain_note, /declares its backing format as qcow2 over a file that is raw/);
  });
});

test("the files a run writes: the values file holds the original of a name the allow-list withheld, only with write_text in a job", async () => {
  await withCwd(async (cwd) => {
    const secret = "Q7fZx9LmR2kT4vb8nwc1y6pd3shJ0aXe5uQz";
    await put(cwd, "inputs/vm/a.vmx", vmx([["displayName", secret], ["guestOS", "ubuntu-64"]]));
    const plain = await tool(INVENTORY, cwd, { root: "inputs" });
    assert.equal(plain.stdout.includes(secret), false);
    assert.match(JSON.parse(plain.stdout).vms[0].name, /^<withheld: 36 bytes, field displayName>$/);
    const out = await asJob(INVENTORY, cwd, { root: "inputs", write_text: true }, undefined, {}, "outv");
    const doc = body(out);
    assert.equal(out.stdout.includes(secret), false);
    const file = (await filesUnder(join(cwd, "outv"))).find((f) => f.endsWith("inventory-values.jsonl"));
    assert.ok(file);
    assert.equal((await stat(join(cwd, "outv", file as string))).mode & 0o777, 0o600);
    const rows = (await readFile(join(cwd, "outv", file as string), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.ok(rows.some((r: Json) => r.value === secret && r.field === "displayName"), "the original is in the private file");
    assert.equal(doc.text.written >= 1, true);
  });
});

test("the block is the same text in the three tools, and the shared withholding block is untouched", async () => {
  const cut = async (p: string, name: string): Promise<string> => {
    const text = await readFile(p, "utf8");
    const a = text.indexOf(`# BEGIN SHARED ${name}`), b = text.indexOf(`# END SHARED ${name}`);
    assert.ok(a > 0 && b > a);
    return text.slice(a, b);
  };
  for (const name of ["BOUNDARY", "COMMON"]) {
    const first = await cut(CHAIN, name);
    for (const p of [INVENTORY, AUDIT]) assert.equal(await cut(p, name), first, `${name} is one text`);
  }
});
