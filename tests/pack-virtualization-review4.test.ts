/**
 * virtualization-backup-forensics: the fourth review's findings, each held by a test that failed on the code it reviewed.
 *
 *   - a run of backslashes (and `eyJeyJ...`) is read once by the way out: 65,536 and 131,072 characters take a fraction of
 *     a second in every field kind and in the second check, and a vmInventory.xml whose <vmxCfgPath> is 131,072
 *     backslashes finishes inside max_seconds plus two (it took 81 s, past the manifest's 60 s, before);
 *   - the second check alone decodes `\uXXXX` followed by a hex digit, `\u{...}`, `\UXXXXXXXX` and `\xNN`, so a token split by
 *     escapes is found without the seal (misses 0 of 300 in every cell; 14% before);
 *   - a base64 key cut by its `/` in a path field is withheld in every piece (a padded 16- or 20-byte key left 12-character
 *     fragments in 5 to 8% of path fields), and the plain words either side of it stay readable;
 *   - an ESXi path whose VM folder carries the name Windows gives a machine nobody named (WIN-, DESKTOP-, LAPTOP-) is shown
 *     (91, 79 and 83% of them were withheld whole, `vmfs` and the datastore included);
 *   - `--password <placeholder>` is not replaced by the second check, and the secret names added since the third review
 *     are withheld by the seal and found by the second check alone.
 *
 * Every canary is random and made here (the generators are the ones tests/pack-virtualization-boundary.test.ts uses, not a
 * tool's). VIRT_REVIEW4_N raises the plants per cell (default 1,000, the owner's ceiling for one shape).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { AUDIT, CHAIN, INVENTORY, json, put, tool, withCwd } from "./pack-virtualization-harness.ts";
import type { Json } from "./pack-virtualization-harness.ts";

const N = Number(process.env.VIRT_REVIEW4_N ?? 1000);
/** One string of up to 131,072 characters is read in well under this many CPU seconds (the quadratic code took 36 at 65,536). */
const ONE_STRING_CPU_SECONDS = 2;
const MAX_SECONDS = 5;
/** The tools stop at max_seconds and answer within a short grace: the documented limit is max_seconds plus two. */
const WALL_LIMIT_SECONDS = MAX_SECONDS + 2;

const HOST = String.raw`
import importlib.util, json, random, sys, time, base64, string

spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
req = json.loads(sys.stdin.read())

ALNUM = string.ascii_letters + string.digits
UP, DIG = string.ascii_uppercase, string.digits


def fresh():
    tool.RUN.update({"values": None, "deadline": None, "stop": None, "stopped_strings": 0, "chars": 0, "cap": 10 ** 12, "record": True})
    tool._SEALED.clear()
    tool._CHECKED.clear()


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


def timing():
    out = {}
    for name, make in (("backslashes", lambda n: "\\" * n), ("eyj", lambda n: "eyJ" * (n // 3)), ("backslash_then_u", lambda n: "\\" * n + "u20")):
        for n in req["sizes"]:
            text = make(n)
            for field in (None, "name", "file", "vmxCfgPath", "key"):
                fresh()
                t0 = time.process_time()
                tool.seal_text(text, "boundary", field)
                sealed = time.process_time() - t0
                t0 = time.process_time()
                tool._suspect(text)
                out["%s/%d/%s" % (name, n, field)] = [round(sealed, 3), round(time.process_time() - t0, 3)]
            fresh()
            t0 = time.process_time()
            tool.seal_head(text, "boundary", "vmxCfgPath")
            out["%s/%d/head" % (name, n)] = [round(time.process_time() - t0, 3), 0]
    # an escape written after a very long run of backslashes is still read once (double escaping is decoded)
    fresh()
    out["double_escape_decoded"] = tool._flat("ghp\\\\\\\\u2066abc") == "ghpabc"
    return out


def escapes():
    SPLITS = {"u2066": "\\u2066", "u200b": "\\u200b", "x00": "\\x00", "U000e0041": "\\U000e0041", "braces": "\\u{200b}", "double": "\\\\u2066", "real_zwsp": "\u200b", "real_bidi": "\u2066"}
    r = random.Random(20261017)

    def plant(shape):
        if shape == "ghp":
            return "ghp_" + mixed(r, 36)
        if shape == "akia":
            return "AKIA" + rs(r, 16, UP + DIG)
        if shape == "xoxb":
            return "xoxb-%s-%s-%s" % (rs(r, 12, DIG), rs(r, 13, DIG), mixed(r, 24))
        if shape == "sk_live":
            return "sk_live_" + rs(r, 24)
        if shape == "b64_32":
            return with_slash(r, 32)
        if shape == "hex64":
            return rs(r, 64, "0123456789abcdef")
        if shape == "jwt":
            h = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
            return h + "." + base64.urlsafe_b64encode(("{\"sub\":\"%s\"}" % rs(r, 10)).encode()).decode().rstrip("=") + "." + base64.urlsafe_b64encode(bytes(r.getrandbits(8) for _ in range(32))).decode().rstrip("=")
        raise KeyError(shape)

    misses = {}
    for shape in req["shapes"]:
        for sname, ch in SPLITS.items():
            miss = 0
            for _ in range(req["n"]):
                t = plant(shape)
                step, start, parts, i = r.randint(2, 9), r.randint(0, 3), [], 0
                text = "".join((ch if (j > start and (j - start) % step == 0) else "") + c for j, c in enumerate(t))
                fresh()
                if tool._suspect(text) is None:
                    miss += 1
            misses["%s/%s" % (shape, sname)] = miss
    return misses


def keys():
    out = {}
    CTX = {"bare": lambda t: t, "leaf": lambda t: "/vmfs/volumes/ds1/vm/" + t + "-flat.vmdk", "dir": lambda t: "/srv/exports/" + t, "win": lambda t: "D:\\backup\\" + t}
    for nbytes in req["sizes"]:
        for cname, ctx in CTX.items():
            r = random.Random(nbytes * 100 + len(cname))
            whole = frag = 0
            for _ in range(req["n"]):
                core = with_slash(r, nbytes)
                body = core.rstrip("=")
                fresh()
                shown = tool.seal_text(ctx(core), "boundary", "file", "")
                whole += body in shown
                frag += any(body[i:i + 12] in shown for i in range(len(body) - 11))
            out["%d/%s" % (nbytes, cname)] = [whole, frag]
    # the words either side of a withheld key stay readable
    r = random.Random(5)
    kept = 0
    for _ in range(req["n"]):
        core = with_slash(r, 16)
        fresh()
        shown = tool.seal_text("/vmfs/volumes/ds1/" + core + "/disk.vmdk", "boundary", "file", "")
        kept += shown.startswith("/vmfs/volumes/ds1/") and shown.endswith("/disk.vmdk")
    out["readable_around_a_key"] = kept
    return out


def esxi():
    r = random.Random(5150)
    NAMES = {"web01": lambda: "web01", "WIN": lambda: "WIN-" + rs(r, 11, UP + DIG), "DESKTOP": lambda: "DESKTOP-" + rs(r, 7, UP + DIG), "LAPTOP": lambda: "LAPTOP-" + rs(r, 8, UP + DIG),
             "template": lambda: "Win2019-Template"}
    FORMS = ["/vmfs/volumes/{ds}/{v}/{v}_1-flat.vmdk", "/vmfs/volumes/{ds}/{v}/{v}.vmdk", "/vmfs/volumes/{ds}/{v}/{v}-flat.vmdk", "/vmfs/volumes/{ds}/{v}/{v}.vmx",
             "/vmfs/volumes/{ds}/{v}/{v}-000001.vmdk", "/vmfs/volumes/{ds}/{v}/{v}-000001-delta.vmdk", "/vmfs/volumes/{ds}/{v}/{v}.vmsd", "/vmfs/volumes/{ds}/{v}/{v}-Snapshot3.vmsn",
             "/vmfs/volumes/{ds}/{v}/{v}.nvram", "/vmfs/volumes/{ds}/{v}/vmware.log", "D:\\Hyper-V\\{v}\\Virtual Hard Disks\\{v}.vhdx", "/var/lib/libvirt/images/{v}.qcow2"]
    DS = [lambda: "ds1", lambda: "datastore1", lambda: "%s-%s-%s-%s" % (rs(r, 8, "0123456789abcdef"), rs(r, 8, "0123456789abcdef"), rs(r, 4, "0123456789abcdef"), rs(r, 12, "0123456789abcdef"))]
    out = {}
    for vn, vg in NAMES.items():
        changed = total = unreadable_base = 0
        for form in FORMS:
            for _ in range(req["n"]):
                t = form.format(ds=r.choice(DS)(), v=vg())
                fresh()
                shown = tool.seal_text(t, "boundary", "file", "")
                total += 1
                changed += shown != t
                if shown != t and ("/vmfs/" in t) and not shown.startswith("/vmfs/volumes/"):
                    unreadable_base += 1
        out[vn] = [changed, total, unreadable_base]
    return out


def judge():
    out = []
    for field, text in req["items"]:
        fresh()
        out.append({"sealed": tool.seal_text(text, "boundary", field), "suspect": tool._suspect(text)})
    return out


print(json.dumps({"timing": timing, "escapes": escapes, "keys": keys, "esxi": esxi, "judge": judge}[req["op"]]()))
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

// ---- P1: a run of backslashes (and `eyJeyJ...`) is read once ---------------------------------------------------------------

test("a run of 65,536 or 131,072 backslashes, or of `eyJ`, takes a fraction of a second in every field kind, in the second check and through seal_head, and a double-escaped character is still decoded", async () => {
  for (const [label, script] of TOOLS) {
    const t = await host(script, { op: "timing", sizes: [65536, 131072] });
    assert.equal(t.double_escape_decoded, true, label);
    for (const [shape, [sealed, checked]] of Object.entries(t as Record<string, [number, number]>).filter(([k]) => k !== "double_escape_decoded")) {
      assert.ok(sealed < ONE_STRING_CPU_SECONDS, `${label} ${shape}: sealed in ${sealed} CPU s (limit ${ONE_STRING_CPU_SECONDS})`);
      assert.ok(checked < ONE_STRING_CPU_SECONDS, `${label} ${shape}: the second check took ${checked} CPU s (limit ${ONE_STRING_CPU_SECONDS})`);
    }
  }
});

test("a vmInventory.xml whose <vmxCfgPath> is 131,072 backslashes finishes inside max_seconds plus two, in the inventory, and a .vmx name of that length does the same in the chain tool", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/vmInventory.xml", `<ConfigRoot><ConfigEntry id="0001"><objID>vm1</objID><vmxCfgPath>${"\\".repeat(131072)}</vmxCfgPath></ConfigEntry></ConfigRoot>`);
    const started = Date.now();
    const out = await tool(INVENTORY, cwd, { root: "inputs", max_seconds: MAX_SECONDS });
    const wall = (Date.now() - started) / 1000;
    assert.ok(wall < WALL_LIMIT_SECONDS, `the inventory took ${wall} s for a 131,072-backslash vmxCfgPath at max_seconds ${MAX_SECONDS} (limit ${WALL_LIMIT_SECONDS})`);
    const doc = json(out);
    assert.ok(["complete", "partial"].includes(doc.status), doc.status);
    if (doc.status === "partial") assert.ok(doc.boundary.stopped_by === "max_seconds" || /max_seconds/.test(JSON.stringify(doc.partial_reasons ?? "")), "a stop names its limit");
    assert.equal(out.stderr, "");
    assert.ok(out.stdout.length < 50_000, `the answer stays small (${out.stdout.length} bytes)`);
  });
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/vm.vmx", `.encoding = "UTF-8"\ndisplayName = "${"\\\\".repeat(65536)}"\nscsi0:0.fileName = "a.vmdk"\n`);
    const started = Date.now();
    const out = await tool(CHAIN, cwd, { root: "inputs", max_seconds: MAX_SECONDS });
    const wall = (Date.now() - started) / 1000;
    assert.ok(wall < WALL_LIMIT_SECONDS, `the chain tool took ${wall} s (limit ${WALL_LIMIT_SECONDS})`);
    json(out);
    assert.equal(out.stderr, "");
  });
});

// ---- P2-1: the second check alone decodes the escapes ---------------------------------------------------------------------

test("the second check alone finds a token split by escapes (\\u2066 and \\u200b followed by a hex digit, \\x00, \\U000e0041, \\u{200b}, a doubled backslash) or by real invisible characters: 0 misses in 300 plants per cell", async () => {
  const shapes = ["ghp", "akia", "xoxb", "sk_live", "b64_32", "hex64", "jwt"];
  for (const [label, script] of TOOLS) {
    const misses = await host(script, { op: "escapes", shapes, n: 300 });
    const bad = Object.entries(misses as Record<string, number>).filter(([, m]) => m > 0);
    assert.deepEqual(bad, [], `${label}: cells with a miss (of 300 plants)`);
    assert.equal(Object.keys(misses).length, shapes.length * 8);
  }
});

// ---- P2-2: a key cut by its `/` is withheld in every piece -----------------------------------------------------------------

test("a padded 16- or 20-byte base64 key with a `/` in a path field leaves no 12 characters of itself, whole or in pieces (1,000 plants per cell), and the 32- and 48-byte keys the same; the unpadded 24-byte key is the documented residual class", async () => {
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "keys", sizes: [16, 20, 32, 48], n: N });
    for (const [cell, [whole, frag]] of Object.entries(got as Record<string, [number, number]>).filter(([k]) => k !== "readable_around_a_key")) {
      assert.equal(whole, 0, `${label} ${cell}: whole keys shown`);
      assert.equal(frag, 0, `${label} ${cell}: ${frag} of ${N} plants showed 12 characters of the key`);
    }
    assert.ok(got.readable_around_a_key >= 0.99 * N, `${label}: the words either side of a withheld key stay readable (${got.readable_around_a_key} of ${N})`);
    const residual = await host(script, { op: "keys", sizes: [24], n: N });
    for (const [cell, [whole]] of Object.entries(residual as Record<string, [number, number]>).filter(([k]) => k !== "readable_around_a_key")) {
      assert.ok(whole <= 0.05 * N, `${label} ${cell}: an unpadded 24-byte key (32 characters) with a '/' shown whole in ${whole} of ${N}; the documented rate is at most 3% (5% bound)`);
    }
  }
});

// ---- P2-3: Windows default machine names -----------------------------------------------------------------------------------

test("ESXi, Hyper-V and libvirt paths whose VM is named WIN-xxxxxxxxxxx, DESKTOP-xxxxxxx or LAPTOP-xxxxxxxx are shown, and `vmfs`, `volumes` and the datastore are never withheld with them", async () => {
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "esxi", n: Math.max(50, Math.floor(N / 10)) });
    for (const [name, [changed, total, unreadableBase]] of Object.entries(got as Record<string, [number, number, number]>)) {
      assert.ok(changed <= 0.01 * total, `${label} ${name}: ${changed} of ${total} paths had a part withheld (limit 1%)`);
      assert.equal(unreadableBase, 0, `${label} ${name}: /vmfs/volumes/ withheld`);
    }
  }
});

// ---- P3: the second check and the unlisted secret names --------------------------------------------------------------------

test("`--password <placeholder>` left by the seal is not replaced again, and the secret names added after the third review are withheld by the seal and found by the second check alone", async () => {
  const v = "hJaXeuQzWpLmNbVc3";
  const forms = [
    "Authorization: Token ", "authorization=", "bearer=", "psk=", "PSK: ", "otp=", "pin=", "dsn=", "connection_string=", "webhook_url=", "ssh_key=", "snmp_community=", "password1=", "pass_word: ",
    "pass-word=", "set password ", "enable secret 5 ", "--passphrase ", "--client_secret ", "--client-secret=", "--bearer ", "--api_key ",
  ];
  for (const [label, script] of TOOLS) {
    const items = forms.map((f): [string | null, string] => [null, `${f}${v}`]);
    const got = await host(script, { op: "judge", items: [...items, [null, "run --password " + v], [null, "run --password <secret withheld 15 characters>"], [null, "the job ran with secret_output: true"]] });
    forms.forEach((f, i) => {
      assert.equal(got[i].sealed.includes(v.slice(2, 14)), false, `${label}: ${f} -> ${got[i].sealed}`);
      assert.notEqual(got[i].suspect, null, `${label}: the second check alone must find ${f}`);
    });
    assert.equal(got[forms.length].sealed.includes(v.slice(2, 14)), false, label);
    assert.equal(got[forms.length + 1].suspect, null, `${label}: a withheld placeholder after --password is not a secret`);
    assert.equal(got[forms.length + 2].suspect, null, label);
  }
});

test("a t10. or iqn. device id is shown in an identifier field as it is in a name or a path, and a secret dressed as one is not", async () => {
  const shown = ["t10.ATA_____Samsung_SSD_870_EVO_1TB_____S5Y2NX0T571161", "iqn.2004-12.com.example:sql-f1f9be4b", "naa.6818b904ce6087413e3b266f850f1578", "eui.0025385b71b0a1d3"];
  const hidden = ["t10.ATA_____x=pw_____AB12CD34", "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5", "Q7fZx9LmR2kT4vb8nwc1y6pd3shJ0aXe5uQz"];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items: [...shown, ...hidden].map((t): [string, string] => ["uid", t]) });
    shown.forEach((t, i) => assert.equal(got[i].sealed, t, `${label}: ${t} must be readable`));
    hidden.forEach((t, i) => assert.match(got[shown.length + i].sealed, /^<withheld: \d+ bytes, field uid>$/, `${label}: ${t}`));
  }
});
