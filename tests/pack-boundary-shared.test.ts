/**
 * The SHARED BOUNDARY block, the one text. Every run.py under packs/ and tool-library/ that carries it is found by its markers (no list of tools),
 * the lines strictly between the markers are digested, and the copies must fall into the variants declared here, with the declared number of
 * carriers each. A third variant, a copy that differs, or a changed count fails the suite: a new carrier has to be declared on purpose, and a
 * sweep that missed a copy cannot pass.
 *
 * There is one variant with 16 carriers: the windows-forensics tools, the macos-forensics tools, the tool-library twins and the three virtualization
 * tools (backup_audit_normalise, snapshot_chain_check, virtualization_inventory).
 *
 * The second half drives the one text from a windows carrier (regkv) for what the virtualization tools needed of it: the identifier kinds of virtualized
 * storage and machines, the table of field kinds the caller passes in, the bound of a run (a cap of characters judged, with boundary.stopped_by), and that
 * it defines no name that another shared block of the same tool defines.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const BEGIN = "# BEGIN SHARED BOUNDARY";
const END = "# END SHARED BOUNDARY";

async function runFiles(dir: string, out: string[] = []): Promise<string[]> {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (e.name === "node_modules" || e.name === ".git") continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) await runFiles(p, out);
    else if (e.name === "run.py") out.push(p);
  }
  return out;
}

type Copy = { file: string; digest: string; lines: number };

/** Every copy of the block, by markers: the digest is the sha256 (first 10 hex digits) of the lines strictly between them, joined with LF. */
async function copies(): Promise<Copy[]> {
  const found: Copy[] = [];
  for (const root of ["packs", "tool-library"]) {
    for (const file of (await runFiles(join(ROOT, root))).sort()) {
      const lines = (await readFile(file, "utf8")).split("\n");
      const begins = lines.flatMap((l, i) => (l.trim() === BEGIN ? [i] : []));
      const ends = lines.flatMap((l, i) => (l.trim() === END ? [i] : []));
      const rel = relative(ROOT, file).split(sep).join("/");
      assert.equal(begins.length, ends.length, `${rel}: a BEGIN without its END`);
      assert.ok(begins.length <= 1, `${rel}: the block twice`);
      for (let k = 0; k < begins.length; k++) {
        assert.ok(ends[k] > begins[k], `${rel}: END before BEGIN`);
        const body = lines.slice(begins[k] + 1, ends[k]);
        found.push({ file: rel, digest: createHash("sha256").update(body.join("\n")).digest("hex").slice(0, 10), lines: body.length });
      }
    }
  }
  return found;
}

/** The variants that exist, and how many carriers each has. Declared, not discovered: a second variant or another count is a failure. */
const VARIANTS = [{ name: "the one text", carriers: 25, owns: (_f: string) => true }];

test("every copy of the BOUNDARY block is one of the declared variants, with the declared number of carriers", async () => {
  const all = await copies();
  const byDigest = new Map<string, Copy[]>();
  for (const c of all) byDigest.set(c.digest, [...(byDigest.get(c.digest) ?? []), c]);
  const summary = [...byDigest].map(([d, cs]) => `${d} (${cs.length}): ${cs.map((c) => c.file).join(", ")}`).join("\n");
  assert.equal(byDigest.size, VARIANTS.length, `the copies fall into ${byDigest.size} variants, ${VARIANTS.length} are declared:\n${summary}`);
  const groups = [...byDigest.values()];
  for (const v of VARIANTS) {
    const group = groups.find((g) => g.every((c) => v.owns(c.file)));
    assert.ok(group, `${v.name}: no variant holds exactly its carriers:\n${summary}`);
    assert.equal(group.length, v.carriers, `${v.name}: ${group.length} carriers, ${v.carriers} declared:\n${summary}`);
    assert.equal(new Set(group.map((c) => c.lines)).size, 1);
  }
  assert.equal(all.length, VARIANTS.reduce((n, v) => n + v.carriers, 0));
  const windows = groups.find((g) => g.some((c) => c.file === "packs/windows-forensics/tools/regkv/run.py"));
  assert.ok(windows && windows.length === 25 && windows[0].lines > 1300, "the one text is the windows text, which the virtualization tools moved onto");
});

// ---- the one text, driven from a windows carrier ------------------------------------------------------------------------------------------------

const SCRIPT = String.raw`
import importlib.util, json, random, string, sys, time
spec = importlib.util.spec_from_file_location("block", sys.argv[1])
blk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(blk)
rnd = random.Random(20261101)
A = string.ascii_letters + string.digits
def rs(n, alphabet=A):
    return "".join(rnd.choice(alphabet) for _ in range(n))
def seal(kind, text):
    return blk.seal({"v": blk.T(kind, text)})["v"]
GOOD = {
    "vmfs": ["5f2b9c1e-3a4d7e8f-1b2c-0a1b2c3d4e5f"],
    "device": ["naa.600508b1001c8b2d6e4f90a1b2c3d4e5", "naa.600508b1001c8b2d", "eui.0025385a71b2c3d4", "wwn-0x5000c500a1b2c3d4",
               "vml.0200000000600508b1001c8b2d4e", "t10.ATA_____Samsung_SSD_860_EVO_500GB_____S3Z2NB0K123456A_____"],
    "iqn": ["iqn.1998-01.com.vmware:esx01-6a7b8c9d", "iqn.2005-03.com.example:storage.disk1"],
    "vmuuid": ["56 4d 1a 2b 3c 4d 5e 6f-70 81 92 a3 b4 c5 d6 e7"],
    "cid": ["fffffffe", "6c0d1a2b"],
    "winhost": ["WIN-AB3DEF12XYZ"],
}
CHARS = {"vmfs": "0123456789abcdef-", "device": "naa.0123456789abcdefABCDEF_", "iqn": "iqn.0123456789-abcdefxyz:", "vmuuid": "0123456789abcdef -",
         "cid": "0123456789abcdef", "winhost": "WIN-ABCDEFGHIJ0123456789"}
out = {"shown": {}, "glued": {}, "random": {}, "slow": {}}
for kind, goods in GOOD.items():
    out["shown"][kind] = [seal(kind, g) == g for g in goods]
    glued = []
    for g in goods:
        token = "gh" + "p_" + rs(36)
        for text in (g + token, g + " password=" + rs(20), token + g):
            shown = seal(kind, text)
            ans = json.dumps(blk.answer_object({"status": "complete", "v": blk.T(kind, text)}), ensure_ascii=False)
            glued.append(shown != text and token not in shown and token not in ans and "password=" not in ans)
    out["glued"][kind] = glued
    # a run of the characters of the kind, 1 MiB: judged whatever its shape, in time that does not grow with the length
    t0 = time.time()
    for n in (1 << 18, 1 << 20):
        run = (CHARS[kind] * (n // len(CHARS[kind]) + 1))[:n]
        seal(kind, run)
    out["slow"][kind] = round(time.time() - t0, 3)
# the ids that hold a name a person chose are shown when it reads as a name and withheld when it reads as random text
tail = rs(40)
out["random"]["t10_shown"] = tail in seal("device", "t10." + tail)
tail = rs(40)
out["random"]["iqn_shown"] = tail in seal("iqn", "iqn.2005-03.com.example:" + tail)
# the table the caller passes in
blk.bind_fields({"vol": "vmfs", "ethernet#.address": "mac", "dev": "device"}, {"disks": "device"})
doc = {"vol": GOOD["vmfs"][0], "ethernet0.address": "00:50:56:ab:cd:ef", "ethernet12.address": "00:50:56:ab:cd:f0", "dev": GOOD["device"][0],
       "disks": {GOOD["device"][2]: 1}}
out["table"] = {"same": blk.seal(doc) == doc}
refused = []
for bad in ({"a": "nosuchkind"}, {1: "name"}):
    try:
        blk.bind_fields(bad)
        refused.append(False)
    except ValueError:
        refused.append(True)
out["table"]["refused"] = refused
# a fresh run: nothing counted yet, so an answer of a run that was not stopped carries no stop
blk.BOUNDARY.update(withheld=0, replaced=0, not_listed=0)
for counter in (blk.BOUNDARY["by"], blk.BOUNDARY["replaced_by"], blk.BOUNDARY["where"]):
    counter.clear()
clean = blk.answer_object({"status": "complete", "status_basis": "all"})
out["clean"] = {"stopped_by": "stopped_by" in clean["boundary"], "status": clean["status"]}
# the cap of characters judged in one run: the strings past it are withheld by their size, the final answer is still judged and says so
blk._STOP["cap"] = blk._STOP["chars"] + 5000
rows = ["alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau upsilon phi %d" % i for i in range(100)]
sealed = [blk.row_object({"r": r})["r"] for r in rows]
final = blk.answer_object({"status": "complete", "status_basis": "all the rows", "tail": "a plain final sentence"})
out["cap"] = {"first_shown": sealed[0] == rows[0], "last_withheld": sealed[-1].startswith("<withheld"), "final_shown": final["tail"] == "a plain final sentence",
              "status": final["status"], "basis": final["status_basis"], "stopped_by": final["boundary"].get("stopped_by"),
              "strings": final["boundary"].get("strings_withheld_by_the_stop"), "withheld": sum(s.startswith("<withheld") for s in sealed)}
# the rules the virtualization tools needed of the free-text layer and of the names: a secret's name and a value after a space, a flag, a placeholder; a device id inside a path
V = "Zq7kP2mR"
flags = ["-password " + V, "--token " + V, "-auth " + V, "set password " + V, "enable secret " + V, "password=<redacted>" + V, "--password <redacted>" + V, "token: <secret> " + V + "9", "sig=" + V, "Authorization: Token " + V + "x"]
out["flags"] = [V not in blk.seal(f) and V not in json.dumps(blk.answer_object({"status": "complete", "v": f})) for f in flags]
keep = ["password=<redacted>", "unclosed token: line 1, column 25", "design=fancy", "run --keyfile /etc/k --keyboard us", "ssh --key client.key host"]
out["kept"] = [blk.seal(k) == k for k in keep]
shown_names = ["pwd-server01", "Token Ring VM", "Passwords DB snapshot", "Token-20240312", "password-sql01"]
hidden_names = ["pwd-" + V, "Token " + V, "-password " + V, "d--pwd " + V, "password-srv01-" + V, "password-ab12-cd34"]
out["names"] = {"shown": [blk.seal(blk.T("name", n)) == n for n in shown_names], "hidden": [V not in blk.seal(blk.T(k, n)) and blk.seal(blk.T(k, n)) != n for k in ("name", "path") for n in hidden_names if n != "password-ab12-cd34" or k == "name"]}
ids = ["56 4d 4f 9a 8b 7c 6d 5e-12 34 56 78 9a bc de f0", "56e64dc3cd6089065c3146e80a9c2226", "naa.6818b904ce6087413e3b266f850f1578", "5f3d1a2b-9c8d7e6f-1a2b-0123456789ab", "00:50:56:e7:a4:26", "12"]
out["id"] = {"shown": [blk.seal(blk.T("id", i)) == i for i in ids], "hidden": [blk.seal(blk.T("id", "d41d8cd98f00b204e9800998ecf8427e5ca9d41d8cd98f00b204e9800998ecf8")) != "d41d8cd98f00b204e9800998ecf8427e5ca9d41d8cd98f00b204e9800998ecf8", blk.seal(blk.T("id", "pwd-" + V)) != "pwd-" + V]}
paths = ["/dev/disk/by-id/naa.6818b904ce6087413e3b266f850f1578", "/dev/disk/by-id/wwn-0x5000c500a1b2c3d4", "/vmfs/devices/disks/t10.ATA_____Samsung_SSD_870_EVO_1TB_____S5Y2NX0T571161",
         "/vmfs/volumes/vsan:52f3b0b5a8c6e1d2-9a8b7c6d5e4f3a2b/c1b3a65e-1f2a-3b4c-5d6e-7f8091a2b3c4/web01.vmdk"]
out["device_paths"] = {"shown": [blk.seal(blk.T("path", x)) == x for x in paths],
                       "hidden": [blk.seal(blk.T("path", "/vmfs/devices/disks/t10.ATA_____Model_X_____" + h)) != "/vmfs/devices/disks/t10.ATA_____Model_X_____" + h for h in ("0123456789abcdef0123", "bazsjdocavbxirjstyziomdz")]}
BSL = chr(92)
tok = "ghp_" + rs(36)
split = "".join((BSL + "u2066" if (j > 1 and j % 4 == 0) else "") + c for j, c in enumerate(tok))
out["escaped"] = {"backstop": blk._suspect(split) is not None, "layers": tok[4:16] not in blk.seal(split)}
key = rs(10) + "/" + rs(11) + "=="
out["padded_in_path"] = [key[:12] not in blk.seal(blk.T("path", "/srv/exports/" + key)), blk._suspect("inputs/" + key) is not None]
# what the virtualization tools' suites asked of the text on top of that: a value in angle brackets, groups written in parts, the pieces around a key, the second check's names
ang = ["password=<hJaXeuQz>", "token: <hJaXeuQzWpLmNb>", "--password <hJaXeuQz>", "set password <hJaXeuQz>"]
ang_ok = ["password=<redacted>", "secret=<your-password>", "--password <password>", "token=<>"]
out["angle"] = {"hidden": [("hJaXeuQ" not in blk.seal("run " + x + " now")) and blk._suspect("run " + x + " now") is not None for x in ang],
                "kept": [blk.seal("run " + x + " now") == "run " + x + " now" and blk._suspect("run " + x + " now") is None for x in ang_ok]}
out["groups"] = {"hidden": [blk.seal(blk.T("name", n)) != n for n in ("secret.yIgK-paUn", "password KHIL-MS4S", "Token_7F3v-lfFr", "password-Zk3q-mRzP-b1X9")],
                 "shown": [blk.seal(blk.T("name", n)) == n for n in ("Password-Manager-Pool-Node", "pwd-prod-lab-01", "Token-A1B2-snapshot1", "password-ESXI-prod", "Token-v2-r1")]
                          + [blk.seal(blk.T("path", "/vmfs/volumes/ds1/pwd/pwd-000001-delta.vmdk")) == "/vmfs/volumes/ds1/pwd/pwd-000001-delta.vmdk"]}
cut = "W/+tXC37i7ggthGcuo/4hw=="
around = blk.seal(blk.T("path", "/vmfs/volumes/ds1/" + cut + "/disk.vmdk"))
out["key_around"] = [around.startswith("/vmfs/volumes/ds1/"), around.endswith("/disk.vmdk"), "tXC37i7ggth" not in around]
v17 = "hJaXeuQzWpLmNbVc3"
out["second_check"] = {"found": [blk._suspect(f + v17) is not None for f in ("psk=", "otp=", "password1=", "ssh_key=", "bearer=", "PSK: ")] + [blk._suspect("run --sshKeyb1185bce74632a now") is not None, blk._suspect("target iqn.2004-12.bazsjdocavbxirjstyziomdz.com:t1 failed") is not None],
                       "quiet": [blk._suspect(x) is None for x in ("authorization: failed", "pin=1234", "dsn=main", "otp: required", "/vmfs/volumes/95f26c46-d7e3b46c-b2e1-6fbd012c0188/web01/web01-Snapshot3.vmsn", "target iqn.2004-12.com.example:nas01 failed")]}
out["big_name_collision"] = [hasattr(blk, "_b_withheld"), not hasattr(blk, "_withheld"), not hasattr(blk, "_USERINFO"), hasattr(blk, "_B_USERINFO")]
print(json.dumps(out))
`;

async function drive(): Promise<Record<string, any>> { // eslint-disable-line @typescript-eslint/no-explicit-any
  const text = await readFile(join(ROOT, "packs", "windows-forensics", "tools", "regkv", "run.py"), "utf8");
  const dir = await mkdtemp(join(tmpdir(), "boundary-shared-"));
  try {
    const file = join(dir, "block.py");
    await writeFile(file, "import re, json, os, sys\nfrom pathlib import Path\n" + text.slice(text.indexOf(BEGIN), text.indexOf(END) + END.length) + "\n");
    return await new Promise((resolve, reject) => {
      const child = spawn("python3", ["-c", SCRIPT, file]);
      const out: Buffer[] = [];
      const err: Buffer[] = [];
      const timer = setTimeout(() => child.kill("SIGKILL"), 120_000);
      child.stdout.on("data", (c: Buffer) => out.push(c));
      child.stderr.on("data", (c: Buffer) => err.push(c));
      child.on("error", reject);
      child.on("close", (code) => {
        clearTimeout(timer);
        if (code !== 0) reject(new Error(`exit ${code}: ${Buffer.concat(err).toString("utf8")}`));
        else resolve(JSON.parse(Buffer.concat(out).toString("utf8")));
      });
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const driven = drive();

test("a well-formed id of each new kind is shown as it is", async () => {
  const r = await driven;
  for (const [kind, shown] of Object.entries(r.shown as Record<string, boolean[]>)) assert.ok(shown.every(Boolean), `${kind}: ${JSON.stringify(shown)}`);
  assert.deepEqual(Object.keys(r.shown).sort(), ["cid", "device", "iqn", "vmfs", "vmuuid", "winhost"]);
});

test("a secret glued to an id, or written after it, is withheld in each new kind", async () => {
  const r = await driven;
  for (const [kind, held] of Object.entries(r.glued as Record<string, boolean[]>)) assert.ok(held.length >= 3 && held.every(Boolean), `${kind}: ${JSON.stringify(held)}`);
});

test("a t10. or iqn. id is shown when what it holds reads as a name and withheld when it is random text", async () => {
  const r = await driven;
  assert.equal(r.random.t10_shown, false, "a random tail after t10. is withheld");
  assert.equal(r.random.iqn_shown, false, "a random tail after an iqn. name is withheld");
});

test("a run of 256 KiB and of 1 MiB of the characters of each kind is judged in bounded time", async () => {
  const r = await driven;
  for (const [kind, seconds] of Object.entries(r.slow as Record<string, number>)) assert.ok(seconds < 10, `${kind}: ${seconds} s`);
});

test("the rules the virtualization tools needed: a secret's name with a value after a space, a flag or a placeholder is withheld and a placeholder alone is not; a name that holds a secret's name and a value is withheld; the id kind; device ids inside a path", async () => {
  const r = await driven;
  assert.deepEqual(r.flags, new Array(10).fill(true), "flags, set password, placeholders with a glued or spaced value, sig=, Authorization: Token x");
  assert.deepEqual(r.kept, new Array(5).fill(true), "a placeholder alone, `token: line 1`, design=, other flags and a key file are left alone");
  assert.ok(r.names.shown.every(Boolean), JSON.stringify(r.names.shown));
  assert.ok(r.names.hidden.length >= 11 && r.names.hidden.every(Boolean), JSON.stringify(r.names.hidden));
  assert.ok(r.id.shown.every(Boolean), JSON.stringify(r.id.shown));
  assert.ok(r.id.hidden.every(Boolean), JSON.stringify(r.id.hidden));
  assert.ok(r.device_paths.shown.every(Boolean), JSON.stringify(r.device_paths.shown));
  assert.ok(r.device_paths.hidden.every(Boolean), JSON.stringify(r.device_paths.hidden));
  assert.deepEqual(r.escaped, { backstop: true, layers: true }, "a token split by escapes of invisible characters, with hexadecimal digits behind an escape");
  assert.deepEqual(r.padded_in_path, [true, true]);
  assert.deepEqual(r.big_name_collision, [true, true, true, true], "the one text keeps its own names clear of the WITHHOLDING block");
  assert.deepEqual(r.angle.hidden, [true, true, true, true], "a value in angle brackets after a secret's name is withheld, by the seal and found by the second check");
  assert.deepEqual(r.angle.kept, [true, true, true, true], "a placeholder word in angle brackets stays");
  assert.ok(r.groups.hidden.every(Boolean), `groups written in parts after a secret's name, whatever their case: ${JSON.stringify(r.groups.hidden)}`);
  assert.ok(r.groups.shown.every(Boolean), `words, tags, dates and the end of a file name after a secret's name stay: ${JSON.stringify(r.groups.shown)}`);
  assert.deepEqual(r.key_around, [true, true, true], "a key with a `/` in a path is withheld and the directory and the file name around it stay readable");
  assert.ok(r.second_check.found.every(Boolean), `the second check names psk, otp, a digit after password, ssh_key, bearer, a camel-case flag with its value glued on and an iqn. authority of random letters: ${JSON.stringify(r.second_check.found)}`);
  assert.ok(r.second_check.quiet.every(Boolean), `and leaves a log line, a pin, a dsn, a VMFS volume id and a plain iqn. name alone: ${JSON.stringify(r.second_check.quiet)}`);
});

test("the table of field kinds is passed in, a digit run in a field name stands for any number, and an unknown kind is refused", async () => {
  const r = await driven;
  assert.equal(r.table.same, true);
  assert.deepEqual(r.table.refused, [true, true]);
});

test("a run that judged more than its cap withholds the strings after it by their size, still judges the final answer, and says so", async () => {
  const r = await driven;
  assert.deepEqual(r.clean, { stopped_by: false, status: "complete" }, "an answer of a run that was not stopped carries no stop");
  assert.equal(r.cap.first_shown, true);
  assert.equal(r.cap.last_withheld, true);
  assert.equal(r.cap.final_shown, true);
  assert.equal(r.cap.status, "partial");
  assert.match(r.cap.stopped_by, /^the cap of \d+ characters judged in one run$/);
  assert.equal(r.cap.strings, r.cap.withheld);
  assert.match(r.cap.basis, /^all the rows; \d+ string\(s\) still held a secret-shaped text when the answer was checked on its way out and were replaced; judging the strings stopped at the cap of \d+ characters judged in one run: \d+ string\(s\) after it were withheld by their size \(see boundary\)$/);
});

// ---- a carrier defines no name of its own that the one text defines ---------------------------------------------------------------------------------

const COLLIDE = String.raw`
import ast, json, sys
def names(src):
    out = set()
    for n in ast.parse(src).body:
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)):
            out.add(n.name)
        elif isinstance(n, (ast.Assign, ast.AnnAssign, ast.For)):
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                out.update(x.id for x in ast.walk(t) if isinstance(x, ast.Name))
    return out
res = {}
for path in sys.argv[1:]:
    lines = open(path, encoding="utf-8").read().split("\n")
    b = [i for i, l in enumerate(lines) if l.strip() == "# BEGIN SHARED BOUNDARY"][0]
    e = [i for i, l in enumerate(lines) if l.strip() == "# END SHARED BOUNDARY"][0]
    inside = names("\n".join(lines[b + 1:e]))
    outside = names("\n".join(lines[:b] + [""] * (e - b + 1) + lines[e + 1:]))
    res[path] = sorted(inside & outside)
print(json.dumps(res))
`;

test("no carrier defines a name that the one text defines (the text is placed after the other shared blocks and would replace it)", async () => {
  const files = (await copies()).map((c) => join(ROOT, c.file));
  const found = await new Promise<Record<string, string[]>>((resolve, reject) => {
    const child = spawn("python3", ["-c", COLLIDE, ...files]);
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve(JSON.parse(Buffer.concat(out).toString("utf8"))) : reject(new Error(Buffer.concat(err).toString("utf8")))));
  });
  const bad = Object.entries(found).filter(([, names]) => names.length > 0).map(([f, names]) => `${relative(ROOT, f)}: ${names.join(", ")}`);
  assert.deepEqual(bad, []);
});
