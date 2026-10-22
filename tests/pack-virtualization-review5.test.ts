/**
 * virtualization-backup-forensics: the fifth review's findings, each held by a test that failed on the code it reviewed.
 *
 *   - a `t10.` device id with a run of underscores was read in quadratic time (`t10.AB` and 4,096 underscores took 3 s of CPU,
 *     a file of such values ate max_seconds): every id kind of the identifier grammar now takes time proportional to the
 *     string, at the 4,096 characters the Shower examines and at 32,768;
 *   - a base64 key with a `/` in a field that holds a path is withheld in every piece also when its end pieces carry
 *     something that is not key (`local:`, `special:`, `[ds1] `, `C:`, a quote and a brace of a JSON text, an error message);
 *   - a text cut where a run of name characters continues beyond the cut shows no part of the run;
 *   - a value in angle brackets after a secret's name is a value unless it is a placeholder word the tool knows; `-password x`
 *     (one dash) is a flag like `--password x`;
 *   - an iqn. or t10. id exempts only what holds names, not a stretch of random text.
 *
 * Every canary is random and made here. VIRT_REVIEW5_N raises the plants per cell (default 1,000, the owner's ceiling for one shape).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { AUDIT, CHAIN, INVENTORY, json, put, tool, withCwd } from "./pack-virtualization-harness.ts";
import { LADDER_PY } from "./pack-re-timing.ts";
import type { Json } from "./pack-virtualization-harness.ts";

const N = Number(process.env.VIRT_REVIEW5_N ?? 1000);
/** One string of up to 32,768 characters of an id shape is read in well under this many CPU seconds (the quadratic code took 3 at 4,096). */
const ONE_STRING_CPU_SECONDS = 2;

const HOST = String.raw`
import importlib.util, json, random, sys, time, base64, string

${LADDER_PY}

spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
req = json.loads(sys.stdin.read())

ALNUM = string.ascii_letters + string.digits
HEXL = "0123456789abcdef"


def fresh():
    tool.RUN.update({"values": None, "deadline": None, "stop": None, "stopped_strings": 0, "chars": 0, "cap": 10 ** 12, "record": True})
    tool._SEALED.clear()
    tool._CHECKED.clear()


def rs(r, n, a=ALNUM):
    return "".join(r.choice(a) for _ in range(n))


def b64(r, n):
    return base64.b64encode(bytes(r.getrandbits(8) for _ in range(n))).decode()


def with_slash(r, n):
    while True:
        s = b64(r, n)
        if "/" in s.rstrip("="):
            return s


def windows(key, w=12):
    body = key.rstrip("=")
    return [body[i:i + w] for i in range(len(body) - w + 1)]


def cpu(fn, *a):
    t0 = time.process_time()
    fn(*a)
    return time.process_time() - t0


def ids_time():
    # every id kind of the identifier grammar, in the shapes that make a pattern try one split after another: each combination on a ladder of sizes, the least
    # CPU time of up to three rounds, and the combinations whose time is not linear named (the first few: the rest would only take longer)
    heads = ["t10.AB", "t10.AB_", "t10.AB_x", "t10.ATA_____Model", "iqn.2020-01.a", "iqn.2020-01.a:", "naa.", "eui.", "wwn-0x", "vml.", "WIN-", "DESKTOP-", "LAPTOP-", "a1b2c3d4-", "{", "00112233-44556677-8899-"]
    fillers = ["_", "-", "a", "A1", ".", ":", " ", "_a", "a_", "0", "f", "Ab"]
    worst = {str(n): 0.0 for n in req["sizes"]}
    bad = []
    for h in heads:
        for f in fillers:
            for form in (0, 1):
                unit = h + f * 3
                texts = [h + (f * (n // len(f) + 1))[:n - len(h)] if form == 0 else (unit * (n // len(unit) + 1))[:n] for n in req["sizes"]]
                for field in (None, "name", "file", "uid", "state_file", "section", "version", "suspect"):
                    def once(text):
                        fresh()
                        if field == "suspect":
                            tool._suspect(text)
                        else:
                            tool.seal_text(text, "boundary", field)
                    times = ladder(once, texts)
                    for n, t in zip(req["sizes"], times):
                        if t is not None:
                            worst[str(n)] = max(worst[str(n)], t)
                    if not ladder_ok(times):
                        bad.append({"head": h, "filler": f, "form": form, "field": field, "seconds": [None if t is None else round(t, 3) for t in times]})
                    if len(bad) >= 3:
                        return {"worst": worst, "bad": bad}
    return {"worst": {k: round(v, 3) for k, v in worst.items()}, "bad": bad}


def ids_judge():
    out = []
    for field, text in req["items"]:
        fresh()
        out.append(tool.seal_text(text, "boundary", field) == text)
    return out


def ids_random():
    r = random.Random(20261018)
    out = {}
    SHAPES = {
        "iqn_tail_30": lambda: "iqn.2020-01.com.example:" + rs(r, 30),
        "iqn_tail_24": lambda: "iqn.2020-01.com.example:" + rs(r, 24),
        "iqn_domain_40": lambda: "iqn.2020-01." + rs(r, 40, string.ascii_lowercase + string.digits),
        "t10_middle_30": lambda: "t10.AB_" + rs(r, 30) + "_abcd",
        "t10_serial_24": lambda: "t10.ATA_____x_____" + rs(r, 24),
        "t10_serial_30": lambda: "t10.ATA_____x_____" + rs(r, 30),
    }
    for name, make in SHAPES.items():
        for field in ("name", "file", "uid", "version"):
            shown = 0
            for _ in range(req["n"]):
                text = make()
                fresh()
                shown += tool.seal_text(text, "boundary", field) == text
            out["%s/%s" % (name, field)] = shown
    return out


def key_ctx():
    out = {}
    CTX = {
        "volume_local": ("volume", lambda k: "local:" + k),
        "section_special": ("section", lambda k: "special:" + k),
        "file_bracket": ("file", lambda k: "[ds1] " + k),
        "file_drive": ("file", lambda k: "C:" + k),
        "volume_dir_after": ("volume", lambda k: "backup:" + k + "/x"),
        "file_suffix_text": ("file", lambda k: k + " is not a valid volume"),
        "file_prefix_text": ("file", lambda k: "cannot open " + k),
        "object_json": ("object", lambda k: json.dumps({"volume": k})),
        "object_json_nested": ("object", lambda k: json.dumps({"a": {"b": k, "c": 1}})),
        "file_quoted": ("file", lambda k: '"' + k + '"'),
        "file_plain": ("file", lambda k: k),
        "file_after_dir": ("file", lambda k: "/vmfs/volumes/ds1/vm/" + k),
        "state_file": ("state_file", lambda k: k),
    }
    for nbytes in req["sizes"]:
        for population in ("forced", "natural"):
            for cname, (field, ctx) in CTX.items():
                r = random.Random(nbytes * 1000 + len(cname) * 10 + (1 if population == "forced" else 2))
                whole = frag = 0
                for _ in range(req["n"]):
                    core = with_slash(r, nbytes) if population == "forced" else b64(r, nbytes)
                    body = core.rstrip("=")
                    fresh()
                    shown = tool.seal_text(ctx(core), "boundary", field, "")
                    whole += body in shown
                    frag += any(w in shown for w in windows(core))
                out["%d/%s/%s" % (nbytes, population, cname)] = [whole, frag]
    return out


def readable():
    # the paths an examiner reads must stay readable: realistic ESXi, Hyper-V, libvirt, Proxmox and Veeam paths, five classes
    r = random.Random(4242)
    words = ["web", "db", "app", "sql", "dc", "file", "mail", "proxy", "build", "jump", "backup", "test", "prod", "dev", "qa", "k8s", "worker", "master", "node", "cache", "ldap", "dns", "nginx", "redis", "mongo", "esx", "vcsa", "veeam", "exch", "sap"]
    UP, DIG = string.ascii_uppercase, string.digits

    def vm():
        k = r.random()
        if k < 0.35: return r.choice(words) + "%02d" % r.randint(1, 99)
        if k < 0.5: return "%s-%s-%02d" % (r.choice(words).upper(), r.choice(["Prod", "Dev", "Test"]), r.randint(1, 20))
        if k < 0.6: return "Windows Server %d (%d)" % (r.choice([2012, 2016, 2019, 2022]), r.randint(1, 5))
        if k < 0.7: return "ubuntu-%d.04-template" % r.choice([18, 20, 22, 24])
        if k < 0.8: return "WIN-" + rs(r, 11, UP + DIG)
        if k < 0.85: return "DESKTOP-" + rs(r, 7, UP + DIG)
        if k < 0.88: return "LAPTOP-" + rs(r, 8, UP + DIG)
        if k < 0.93: return "%s_%s" % (r.choice(words), r.choice(["clone", "copy", "old", "restored", "snap1"]))
        return r.choice(["Win2019-Template", "SQL Server 2019 (prod)", "CentOS7_base", "Kali_Linux_2024", "pfSense-FW1"])

    def ds():
        return r.choice(["datastore1", "ds-prod-01", "SSD_RAID10", "vsanDatastore", "nfs-iso", "Local-SSD-%d" % r.randint(1, 4), "esx%d-local" % r.randint(1, 9)])

    def volid():
        return "%s-%s-%s-%s" % (rs(r, 8, HEXL), rs(r, 8, HEXL), rs(r, 4, HEXL), rs(r, 12, HEXL))

    def esxi():
        v, d = vm(), ds()
        if r.random() < 0.3:
            d = volid()
        f = r.choice(["%s.vmx", "%s.vmdk", "%s-flat.vmdk", "%s_1.vmdk", "%s-000001-delta.vmdk", "%s-Snapshot3.vmsn", "%s.nvram", "%s.vmsd", "vmware.log"])
        return "/vmfs/volumes/%s/%s/%s" % (d, v, f % v if "%s" in f else f)

    def hyperv():
        v, g = vm(), "{%s-%s-%s-%s-%s}" % (rs(r, 8, HEXL).upper(), rs(r, 4, HEXL).upper(), rs(r, 4, HEXL).upper(), rs(r, 4, HEXL).upper(), rs(r, 12, HEXL).upper())
        return r.choice(["D:\\Hyper-V\\Virtual Hard Disks\\%s.vhdx" % v, "D:\\Hyper-V\\%s\\Snapshots\\%s_%s.avhdx" % (v, v, g), "C:\\ClusterStorage\\Volume1\\%s\\%s.vhdx" % (v, v)])

    def libvirt():
        v = vm()
        return r.choice(["/var/lib/libvirt/images/%s.qcow2" % v, "/var/lib/libvirt/images/%s-snap%d.qcow2" % (v, r.randint(1, 9)), "/var/lib/libvirt/qemu/snapshot/%s/%s.xml" % (v, r.choice(["before-upgrade", "snap1"]))])

    def proxmox():
        i = r.randint(100, 999)
        return r.choice(["local-lvm:vm-%d-disk-%d" % (i, r.randint(0, 3)), "/var/lib/vz/images/%d/vm-%d-disk-1.qcow2" % (i, i), "backup:backup/vm/%d/2026-10-15T02:00:00Z" % i,
                         "/etc/pve/nodes/pve%d/qemu-server/%d.conf" % (r.randint(1, 5), i), "local:iso/debian-12.%d.0-amd64-netinst.iso" % r.randint(0, 9), "local:snippets/user-data-%d.yaml" % i])

    def veeam():
        j = r.choice(["Backup Job %d" % r.randint(1, 20), "Daily_Prod", "SQL-Backup", "Replica_%s" % r.choice(words)])
        d = "2026-%02d-%02dT%02d%02d%02d" % (r.randint(1, 12), r.randint(1, 28), r.randint(0, 23), r.randint(0, 59), r.randint(0, 59))
        return r.choice(["/backups/%s/%sD%s.vbk" % (j, j.replace(" ", ""), d), "E:\\Backup\\%s\\%s.vbm" % (j, j), "/backups/%s/%s_%s.vib" % (j, vm(), d)])

    out = {}
    for name, make in (("esxi", esxi), ("hyperv", hyperv), ("libvirt", libvirt), ("proxmox", proxmox), ("veeam", veeam)):
        changed = 0
        for _ in range(req["n"]):
            p = make()
            fresh()
            changed += tool.seal_text(p, "boundary", "file") != p
        out[name] = changed
    return out


def cuts():
    r = random.Random(77)
    lim = req["limit"]
    out = {"head_shown": 0, "tail_shown": 0, "plain_kept": 0, "total": req["n"]}
    for _ in range(req["n"]):
        token = rs(r, 40)
        # the token starts 12 to 32 characters before the cut and goes on 8 to 28 characters beyond it; words follow it
        at = lim - r.randint(12, 32)
        text = ("alpha beta " * 500)[:at - 1] + " " + token + " tail words"
        shown = tool.cut_safely(text, lim)
        out["head_shown"] += token[:12] in shown
        out["tail_shown"] += token[-12:] in shown
        # a cut at a space ends no run: the words before it stay
        words = "alpha beta gamma delta " * 300
        cut = words.index(" ", lim)
        kept = tool.cut_safely(words, cut)
        out["plain_kept"] += kept == words[:cut]
    return out


def judge():
    out = []
    for field, text in req["items"]:
        fresh()
        out.append({"sealed": tool.seal_text(text, "boundary", field), "suspect": tool._suspect(text)})
    return out


print(json.dumps({"ids_time": ids_time, "ids_judge": ids_judge, "ids_random": ids_random, "key_ctx": key_ctx, "readable": readable, "cuts": cuts, "judge": judge}[req["op"]]()))
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

// ---- P2-T: every id kind is read in time proportional to the string ---------------------------------------------------------

test("an id of every kind (t10., iqn., naa., eui., wwn-, vml., WIN-, DESKTOP-, LAPTOP-, a GUID) followed by 2,048, 8,192 or 32,768 characters of underscores, dashes, dots, colons or letters is judged in time proportional to its length (0.3 CPU s at 32,768 characters), in every field kind and in the second check; the least of up to three rounds, each step at most 8 times the one before", async () => {
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "ids_time", sizes: [2048, 8192, 32768] }) as { worst: Record<string, number>; bad: unknown[] };
    assert.deepEqual(got.bad, [], `${label}: not linear (the least CPU seconds of up to three rounds at 2,048, 8,192 and 32,768 characters, each step four times the length)`);
    assert.ok(got.worst["8192"] < 0.5, `${label}: 8,192 characters took ${got.worst["8192"]} CPU s (the quadratic pattern took 3 at 4,096)`);
    assert.ok(got.worst["32768"] < ONE_STRING_CPU_SECONDS, `${label}: 32,768 characters took ${got.worst["32768"]} CPU s (limit ${ONE_STRING_CPU_SECONDS})`);
  }
});

test("a vmx of 40 lines, each a `t10.AB` id with 4,080 underscores, is read in a few seconds and answers complete JSON (it took 52 s and stopped at max_seconds before)", async () => {
  await withCwd(async (cwd) => {
    const lines = ['.encoding = "UTF-8"', 'displayName = "vm"'];
    for (let i = 0; i < 40; i += 1) lines.push(`scsi0:${i}.fileName = "t10.AB${"_".repeat(4080)}${i}"`, `scsi0:${i}.present = "TRUE"`);
    await put(cwd, "inputs/vm.vmx", lines.join("\n") + "\n");
    const started = Date.now();
    const out = await tool(INVENTORY, cwd, { root: "inputs", max_seconds: 20 });
    const wall = (Date.now() - started) / 1000;
    assert.ok(wall < 12, `the inventory took ${wall} s for 40 lines of t10.AB and 4,080 underscores`);
    const doc = json(out);
    assert.equal(doc.boundary.stopped_by, null, "the run did not stop on its time");
    assert.equal(out.stderr, "");
  });
});

// ---- P3: an iqn. or t10. id exempts only what holds names ----------------------------------------------------------------

test("real iqn., t10., naa., eui. ids are shown in a name, a path, an id and a simple field, and an iqn. or t10. id that holds a stretch of random text is not", async () => {
  const real = [
    "t10.ATA_____Samsung_SSD_860_EVO_1TB_________________S3Z9NB0K123456A", "t10.ATA_____WDC_WD40EFRX2D68N32N0_____________________WD2DWCC7K1234567",
    "t10.NVMe____Samsung_SSD_970_EVO_Plus_500GB___________B8A2E0B0123456AB", "iqn.1998-01.com.vmware:esx01-5f3a2b1c", "iqn.2005-10.org.freenas.ctl:target0",
    "iqn.1991-05.com.microsoft:win-sql01.corp.example.com", "naa.6818b904ce6087413e3b266f850f1578", "eui.0025385b71b0a1d3",
  ];
  const mixedCase = "aB3dE5gH7jK9mN1pQ3sT5vX7yZ1bC";
  const fake = [`iqn.2020-01.com.example:${mixedCase}`, `iqn.2020-01.${mixedCase.toLowerCase()}`, `t10.AB_x_${mixedCase.slice(0, 24)}`, `t10.AB_${mixedCase}_abcd`];
  for (const [label, script] of TOOLS) {
    for (const field of ["name", "file", "uid", "version"]) {
      const got = await host(script, { op: "ids_judge", items: [...real, ...fake].map((t): [string, string] => [field, t]) });
      real.forEach((t, i) => {
        if (field === "version" && t.length > 96) return;
        assert.equal(got[i], true, `${label} ${field}: ${t} must be readable`);
      });
      fake.forEach((t, i) => assert.equal(got[real.length + i], false, `${label} ${field}: ${t} must be withheld`));
    }
  }
});

test("random text dressed as an iqn. tail or domain, or as the model or serial of a t10. id, is shown in at most 5% of 1,000 plants per field (it was shown in all of them; measured 0.1 to 3.8%)", async () => {
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "ids_random", n: N });
    for (const [cell, shown] of Object.entries(got as Record<string, number>)) {
      assert.ok(shown <= Math.ceil(0.05 * N), `${label} ${cell}: ${shown} of ${N} shown (measured at most 3.8%)`);
    }
  }
});

// ---- P2-A: a key cut by its `/` while an end piece carries something that is not key --------------------------------------

test("a padded 16- or 20-byte base64 key with a '/' (forced, and natural keys) leaves no 12 characters of itself in a path-kind field, whether the key stands alone or is glued to `local:`, `special:`, `[ds1] `, `C:`, `backup:...`/x, a quote, a JSON text or an error message (at most 0.3% of 1,000 plants per cell; was 14 to 18% of the forced keys)", async () => {
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "key_ctx", sizes: [16, 20, 32, 48], n: N });
    for (const [cell, [whole, frag]] of Object.entries(got as Record<string, [number, number]>)) {
      assert.equal(whole, 0, `${label} ${cell}: whole keys shown`);
      assert.ok(frag <= Math.ceil(0.003 * N), `${label} ${cell}: ${frag} of ${N} plants showed 12 characters of the key`);
    }
  }
});

test("the paths of ESXi, Hyper-V, libvirt, Proxmox and Veeam stay readable: at most 0.5% of 1,000 realistic paths per class have a part withheld (0.08% over the five classes before)", async () => {
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "readable", n: N });
    const total = Object.values(got as Record<string, number>).reduce((a, b) => a + b, 0);
    assert.ok(total <= 0.002 * 5 * N, `${label}: ${total} of ${5 * N} paths had a part withheld ${JSON.stringify(got)}`);
  }
});

// ---- P3-1: a cut leaves no run open --------------------------------------------------------------------------------------

test("a text cut inside a run of name characters shows no part of the run, whatever follows the run (the first 18 to 20 characters stayed before); a cut at a space keeps the words", async () => {
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "cuts", n: 300, limit: 4096 });
    assert.equal(got.head_shown, 0, `${label}: the head of a token the cut split was shown`);
    assert.equal(got.tail_shown, 0, label);
    assert.equal(got.plain_kept, got.total, `${label}: words before a cut at a space must stay`);
  }
});

// ---- P3-2 and P3-4: a value in angle brackets, a flag with one dash -----------------------------------------------------

test("the value after a secret's name is withheld also in angle brackets (password=<x>, token: <x>, --password <x>, set password <x>) unless it is a placeholder word the tool knows, in the seal and in the second check alone", async () => {
  const v8 = "hJaXeuQz", v14 = "hJaXeuQzWpLmNb";
  const secret = [`password=<${v8}>`, `password=<${v14}>`, `token=<${v8}>`, `token: <${v14}>`, `pwd=<${v8}>`, `--password <${v8}>`, `--password <${v14}>`, `--token <${v14}>`, `set password <${v8}>`, `api_key=<${v14}>`];
  const placeholders = ["password=<redacted>", "--password <redacted>", "--password <password>", "token=<token>", "set password <secret>", "pwd=<***>", "secret=<your-password>", "password=<withheld: 8 bytes>", "--password <secret withheld 15 characters>", "token=<>"];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items: [...secret, ...placeholders].map((t): [string | null, string] => [null, `run ${t} now`]) });
    secret.forEach((t, i) => {
      assert.equal(got[i].sealed.includes(v8.slice(2)) || got[i].sealed.includes(v14.slice(2)), false, `${label}: ${t} -> ${got[i].sealed}`);
      assert.notEqual(got[i].suspect, null, `${label}: the second check alone must find ${t}`);
    });
    placeholders.forEach((t, i) => {
      assert.equal(got[secret.length + i].sealed, `run ${t} now`, `${label}: a placeholder must stay readable (${t} -> ${got[secret.length + i].sealed})`);
      assert.equal(got[secret.length + i].suspect, null, `${label}: a placeholder is not a secret to the second check (${t})`);
    });
  }
});

test("a flag with one dash (-password x, -pwd x, -token x, -secret x, -pass x, -apikey x) hides its value like the flag with two, in the seal and in the second check alone", async () => {
  const v = "hJaXeuQz";
  const flags = ["-password", "-pwd", "-token", "-secret", "-pass", "-passphrase", "-api-key", "-client-secret", "-psk", "-bearer", "-auth"];
  for (const [label, script] of TOOLS) {
    const got = await host(script, { op: "judge", items: flags.map((f): [string | null, string] => [null, `run ${f} ${v} now`]) });
    flags.forEach((f, i) => {
      assert.equal(got[i].sealed.includes(v), false, `${label}: ${f} -> ${got[i].sealed}`);
      assert.notEqual(got[i].suspect, null, `${label}: the second check alone must find ${f}`);
    });
    const words = ["the well-known token system", "a pass-through port", "the -x flag and -v flag", "co-author: a name"];
    const prose = await host(script, { op: "judge", items: words.map((t): [string | null, string] => [null, t]) });
    words.forEach((w, i) => assert.equal(prose[i].sealed, w, `${label}: ordinary words and other single-dash flags stay (${w})`));
  }
});

// ---- the three tools carry the same text ---------------------------------------------------------------------------------

test("the inventory, the chain tool and the audit carry one id grammar: the t10. pattern has one underscore between its parts, not a run", async () => {
  const { readFile } = await import("node:fs/promises");
  for (const [label, script] of TOOLS) {
    const text = await readFile(script, "utf8");
    assert.ok(text.includes(String.raw`t10\.[A-Za-z]{2,12}_[A-Za-z0-9 _.-]{1,50}_[A-Za-z0-9]{4,24}`), `${label} carries the linear t10. pattern`);
    assert.ok(!text.includes("_+[A-Za-z0-9 _.-]{1,50}_+"), `${label} does not carry the pattern that tried every split of a run of underscores`);
  }
});
