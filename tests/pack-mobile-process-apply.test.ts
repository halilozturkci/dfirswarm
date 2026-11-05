/**
 * PKG-P6 (the mobile-forensics pack in the process sweep). The shared PROCESS block ends what a program leaves behind (settle()); the mobile tools and recipes that run a
 * program and report files that program wrote call process_apply and put a line under problems, so that a program that exits 0 and leaves a writer behind, or a host
 * where the absence of one cannot be proven, never answers `complete` over a file the program wrote. Stand-ins only, with real abandoned children (the leftovers are
 * described in network-process-harness.ts and process-apply-cases.ts):
 *   heic_inspect    heif-convert (the preview) and exiftool (the original's metadata, a file the tool reads) each leave a process
 *   backup_decrypt  the library's extract_file (a Python stand-in module, run in the tool's own child process) leaves a process that writes to a decrypted file
 *   android-aleapp, android-backup-apps, ios-ileapp   ALEAPP / iLEAPP leaves a process that writes to a report file or to the log the recipe reads
 * The cases that fail on the batch head (before the tools called process_apply) are the ones that expect `partial` and program_group: the answer was `complete`.
 * Every tool is also probed with leftovers that hold what it reads and never end (a sleeper on every descriptor, a slow writer, a holder of the standard input): it must answer in time, partial, and end them.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { ROOT, runPySnippet } from "./tool-library-harness.ts";
import { FEW, HOLDERS, LEAVE_SH, PY_LEAVE, VARIANTS, exec, sh, stubDir } from "./network-process-harness.ts";
import { register } from "./process-apply-cases.ts";
import type { Case } from "./process-apply-cases.ts";

const PACK = process.env.MOBILE_PACK ?? join(ROOT, "packs", "mobile-forensics");
const HEIC = join(PACK, "tools", "heic_inspect", "run.py");
const DECRYPT = join(PACK, "tools", "backup_decrypt", "run.py");
const RECIPES = join(PACK, "recipes");

async function stub(bin: string, name: string, script: string): Promise<void> {
  await mkdir(bin, { recursive: true });
  await writeFile(join(bin, name), script, { mode: 0o755 });
  await chmod(join(bin, name), 0o755);
}

// ---- heic_inspect ----------------------------------------------------------------------------------------------------------------------------------

const u16 = (n: number): Buffer => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32 = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const cc = (s: string): Buffer => Buffer.from(s, "latin1");
const box = (type: string, ...parts: Buffer[]): Buffer => { const p = Buffer.concat(parts); return Buffer.concat([u32(8 + p.length), cc(type), p]); };
const full = (type: string, version: number, flags: number, ...parts: Buffer[]): Buffer => box(type, Buffer.from([version, (flags >> 16) & 255, (flags >> 8) & 255, flags & 255]), ...parts);

/** A one-image HEIC (item 1, hvc1, 4032 x 3024, its data in mdat): the layouts of ISO/IEC 14496-12 and 23008-12, no codec data. */
function simpleHeic(): Buffer {
  const data = Buffer.from("not codec data, the walk does not read it");
  const build = (dataOffset: number): Buffer => Buffer.concat([
    box("ftyp", cc("heic"), u32(0), cc("mif1"), cc("heic")),
    full("meta", 0, 0,
      full("hdlr", 0, 0, u32(0), cc("pict"), Buffer.alloc(12), Buffer.from([0])),
      full("pitm", 0, 0, u16(1)),
      full("iinf", 0, 0, u16(1), full("infe", 2, 0, u16(1), u16(0), cc("hvc1"), Buffer.from([0]))),
      full("iloc", 0, 0, Buffer.from([0x44, 0x00]), u16(1), Buffer.concat([u16(1), u16(0), u16(1), u32(dataOffset), u32(data.length)])),
      box("iprp", box("ipco", full("ispe", 0, 0, u32(4032), u32(3024)), box("irot", Buffer.from([1]))),
        full("ipma", 0, 0, u32(1), Buffer.concat([u16(1), Buffer.from([2]), Buffer.from([0x81, 0x82])])))),
    box("mdat", data),
  ]);
  const first = build(0);
  return build(first.length - data.length);
}
/** A JPEG with a SOF0 header of the given size, the way a decoder writes one: enough for the tool to read the size. */
function jpeg(w: number, h: number, pad = 0): Buffer {
  const sof = Buffer.concat([Buffer.from([0xff, 0xc0, 0x00, 0x0b, 0x08]), u16(h), u16(w), Buffer.from([0x01, 0x01, 0x11, 0x00])]);
  return Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00]), sof, Buffer.alloc(pad, 7), Buffer.from([0xff, 0xd9])]);
}

const EXIF_JSON = JSON.stringify([{ SourceFile: "x", "EXIF:Make": "StandInMake", "IFD0:Model": "StandInModel" }]);

async function runHeic(cwd: string, bin: string, left: string | undefined, host: "linux" | "darwin" | "refused", on: "convert" | "exiftool"): Promise<{ answer: any; run: any }> { // eslint-disable-line @typescript-eslint/no-explicit-any
  const dir = await stubDir(cwd);
  const out = join(cwd, "out");
  await mkdir(out, { recursive: true });
  await writeFile(join(dir, "stub.jpg"), jpeg(4032, 3024, 50));
  const original = join(cwd, "work", "photo.heic");
  await writeFile(original, simpleHeic());
  // the tool gives the programs a clean environment: the stand-ins carry the leftover's settings themselves
  const pre = `export STUB_DIR="${dir}" STUB_LEFT="${left ?? ""}"\n`;
  await stub(bin, "heif-convert", sh(`${pre}for a in "$@"; do out="$a"; done
cp "$STUB_DIR/stub.jpg" "$out"
${on === "convert" ? 'leave "$out"' : ""}
exit 0
`));
  await stub(bin, "exiftool", sh(`${pre}cat <<'JSON'
${EXIF_JSON}
JSON
${on === "exiftool" ? 'leave "$PWD/exiftool.out"' : ""}
exit 0
`));
  const run = await exec(HEIC, [], { path: original, convert: true }, cwd, bin, { STUB_DIR: dir, JOB_ID: "j-1", OUT: out, ...(left ? { STUB_LEFT: left } : {}) }, host);
  assert.equal(run.code, 0, run.stderr + run.stdout);
  return { answer: JSON.parse(run.stdout), run };
}
const heicConvert: Case = { name: "heic_inspect (heif-convert's preview)", variants: VARIANTS, holdsFiles: true, holders: HOLDERS, invoke: (cwd, bin, left, host) => runHeic(cwd, bin, left, host, "convert") };
register(heicConvert);
const heicExif: Case = { name: "heic_inspect (exiftool's output)", variants: FEW, holdsFiles: true, holders: HOLDERS, invoke: (cwd, bin, left, host) => runHeic(cwd, bin, left, host, "exiftool") };
register(heicExif);

// ---- backup_decrypt ----------------------------------------------------------------------------------------------------------------------------------

/** The stand-in library (a toy cipher, XOR 0x5A, and a password check by SHA-256), as in pack-mobile-backup-decrypt.test.ts; the first extract_file leaves a process. */
const STANDIN = String.raw`
import hashlib, json, os, sqlite3, tempfile, time
` + PY_LEAVE + String.raw`
def hold_behind(d, variant, target):
    # a child that never ends and holds what the library had: every descriptor (sleeper), writes to its standard output now and then (slow), or only the standard input (stdin)
    r, w = os.pipe()
    if os.fork() != 0:
        os.close(w)
        os.read(r, 1)
        os.close(r)
        return
    os.close(r)
    open(os.path.join(d, "left.pids"), "a").write("%d\n" % os.getpid())
    if variant == "stdin":
        os.close(1)
        os.close(2)
    os.write(w, b"1")
    os.close(w)
    while True:
        if variant == "slow":
            try:
                os.write(1, b"x")
            except OSError:
                pass
        time.sleep(0.2)
def _x(b):
    return bytes(c ^ 0x5A for c in b)
class IncorrectPassphraseError(ValueError):
    pass
class EncryptedBackup:
    def __init__(self, backup_directory=None, passphrase=None):
        self.dir = backup_directory
        meta = json.load(open(os.path.join(backup_directory, "standin.json")))
        if hashlib.sha256(passphrase.encode()).hexdigest() != meta["sha"]:
            raise IncorrectPassphraseError("Incorrect passphrase")
        self.tmp = tempfile.NamedTemporaryFile(dir=tempfile.gettempdir(), delete=False)
        self.tmp.write(_x(open(os.path.join(self.dir, "Manifest.db"), "rb").read()))
        self.tmp.close()
    def save_manifest_file(self, output_filename="manifest.db"):
        with open(output_filename, "wb") as fh:
            fh.write(_x(open(os.path.join(self.dir, "Manifest.db"), "rb").read()))
    def extract_file(self, *, relative_path=None, domain_like=None, output_filename):
        con = sqlite3.connect(self.tmp.name)
        row = con.execute("SELECT fileID FROM Files WHERE relativePath = ? AND domain LIKE ? AND flags=1 ORDER BY domain, relativePath LIMIT 1", (relative_path, domain_like)).fetchone()
        if row is None:
            raise KeyError("no such row")
        blob = open(os.path.join(self.dir, row[0][:2], row[0]), "rb").read()
        with open(output_filename, "wb") as fh:
            fh.write(_x(blob))
        d = os.environ.get("STUB_DIR")
        v = os.environ.get("STUB_LEFT")
        if v and d and not os.path.exists(os.path.join(d, "left.pids")):
            if v in ("sleeper", "slow", "stdin"):
                hold_behind(d, v, output_filename)
            else:
                leave_behind(d, v, output_filename)
`;

/** An encrypted backup directory from a spec: the plain map is built, then the map and the blobs are XORed. */
const ENCBACKUP = String.raw`
import hashlib, json, os, plistlib, sqlite3, sys
dest = sys.argv[1]
spec = json.load(sys.stdin)
os.makedirs(dest, exist_ok=True)
def x(b): return bytes(c ^ 0x5A for c in b)
def archive(size):
    return plistlib.dumps({"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"root": plistlib.UID(1)},
        "$objects": ["$null", {"Size": size, "Mode": 0o100644, "$class": plistlib.UID(2)}, {"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]}]}, fmt=plistlib.FMT_BINARY)
plain = os.path.join(dest, "Manifest.plain")
con = sqlite3.connect(plain)
con.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
for e in spec["entries"]:
    data = bytes((i * 7 + 3) % 256 for i in range(e.get("size", 10)))
    con.execute("INSERT INTO Files VALUES (?,?,?,?,?)", (e["id"], e.get("domain", "HomeDomain"), e["path"], e.get("flags", 1), archive(len(data))))
    os.makedirs(os.path.join(dest, e["id"][:2]), exist_ok=True)
    with open(os.path.join(dest, e["id"][:2], e["id"]), "wb") as fh: fh.write(x(data))
con.commit(); con.close()
raw = open(plain, "rb").read(); os.unlink(plain)
open(os.path.join(dest, "Manifest.db"), "wb").write(x(raw))
with open(os.path.join(dest, "Manifest.plist"), "wb") as fh: plistlib.dump({"Version": "10.0", "IsEncrypted": True, "BackupKeyBag": b"KB" * 40, "ManifestKey": b"MK" * 20}, fh)
json.dump({"sha": hashlib.sha256(spec["password"].encode()).hexdigest()}, open(os.path.join(dest, "standin.json"), "w"))
`;
const fid = (n: number): string => "aa" + n.toString(16).padStart(38, "0");

const decrypt: Case = {
  name: "backup_decrypt",
  variants: ["plain", "setsid", "double"],
  holdsFiles: true,
  holders: HOLDERS,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    const lib = join(cwd, "standin", "iphone_backup_decrypt");
    await mkdir(lib, { recursive: true });
    await writeFile(join(lib, "__init__.py"), STANDIN, "utf8");
    const backup = join(cwd, "work", "b");
    const made = await runPySnippet(ENCBACKUP, [backup], { password: "stand-in-password-1", entries: [
      { id: fid(1), path: "Library/SMS/sms.db", size: 40 }, { id: fid(2), path: "Media/DCIM/IMG_0001.JPG", size: 300, domain: "CameraRollDomain" }] });
    assert.equal(made.code, 0, made.stderr);
    const ref = join(cwd, "work", "pw.txt");
    await writeFile(ref, "stand-in-password-1\n", { mode: 0o600 });
    await chmod(ref, 0o600);
    const out = join(cwd, "out");
    await mkdir(out, { recursive: true });
    const run = await exec(DECRYPT, [], { backup, password_ref: ref }, cwd, bin,
      { STUB_DIR: dir, JOB_ID: "j-1", OUT: out, SECRET_OUTPUT: "1", PYTHONPATH: join(cwd, "standin"), ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout), run };
  },
};
register(decrypt);

// ---- the three leapp recipes ---------------------------------------------------------------------------------------------------------------------------

const TAR = String.raw`
import io, json, sys, tarfile
path, spec = sys.argv[1], json.loads(sys.argv[2])
with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as archive:
    for name, size in spec:
        info = tarfile.TarInfo(name)
        info.size = size
        info.mtime = 1700000000
        archive.addfile(info, io.BytesIO(b"x" * size))
`;
const AB = String.raw`
import json, sys, tarfile, zlib
path, spec = sys.argv[1], json.loads(sys.argv[2])
with open(path, "wb") as out:
    out.write(b"ANDROID BACKUP\n5\n1\nnone\n")
    comp = zlib.compressobj(9)
    for name, size in spec["members"]:
        info = tarfile.TarInfo(name)
        info.size = size
        info.mtime = 1700000000
        out.write(comp.compress(bytes(info.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape"))))
        out.write(comp.compress(b"\0" * size + b"\0" * ((-size) % 512)))
    out.write(comp.compress(b"\0" * 1024))
    out.write(comp.flush())
`;
const REPORT = String.raw`d="$out/Reports_2026-10-01"; mkdir -p "$d/_TSV Exports" "$d/_Timeline" "$d/_HTML"; : > "$d/_Timeline/tl.db"; : > "$d/_HTML/index.html"`;
const FOUND = (name: string): string =>
  `echo "[1/1] ${name} [${name.toLowerCase()}] artifact started at 09:29:44 UTC"; printf 'a\\tb\\n1\\t2\\n' > "$d/_TSV Exports/${name}.tsv"; echo "Found 2 records for ${name}"; echo "${name} [${name.toLowerCase()}] artifact completed in 0.0s"`;

async function leapp(bin: string, name: string, body: string): Promise<void> {
  await stub(bin, name, `#!/usr/bin/env bash\n${LEAVE_SH}\nwhile [[ $# -gt 0 ]]; do case "$1" in -o) out="$2"; shift 2;; -t) kind="$2"; shift 2;; -i) src="$2"; shift 2;; *) shift;; esac; done\n${body}\n`);
}

function recipe(name: string, program: string, marker: string | "ab", leaves: "report" | "log"): Case {
  return {
    name: `${name} recipe`,
    variants: VARIANTS,
    holdsFiles: true,
  holders: HOLDERS,
    skipOk: true,
    invoke: async (cwd, bin, left, host) => {
      const dir = await stubDir(cwd);
      const target = join(cwd, "work", marker === "ab" ? "bk.ab" : "acq.tar");
      const made = marker === "ab"
        ? await runPySnippet(AB, [target, JSON.stringify({ members: [["apps/com.example/f/a.txt", 100]] })], null)
        : await runPySnippet(TAR, [target, JSON.stringify([[marker, 16]])], null);
      assert.equal(made.code, 0, made.stderr);
      await leapp(bin, program, `${REPORT}\necho "Artifact to parse: 1"\n${FOUND("Messages")}\n${leaves === "report" ? 'leave "$d/_TSV Exports/Messages.tsv"' : 'leave "$d/_HTML/index.html"'}\necho "Processes completed."\nexit 0`);
      const out = join(cwd, "recipe-out");
      const run = await exec(join(RECIPES, name, "run.py"), ["run", "--target", JSON.stringify({ paths: [target] }), "--out", out], undefined, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
      assert.ok(run.code === 0 || run.code === 1, run.stderr + run.stdout);
      return { answer: JSON.parse(run.stdout.trim().split("\n").pop() ?? "{}"), run };
    },
  };
}
register(recipe("android-aleapp", "aleapp", "data/system/packages.xml", "report"));
register(recipe("ios-ileapp", "ileapp", "private/var/mobile/Library/SMS/sms.db", "report"));
register(recipe("android-backup-apps", "aleapp", "ab", "log"));
