/**
 * images/install.py unpacks a pinned NuGet package (.nupkg, a zip file) and runs a download on the interpreter its architecture's own
 * entry names. A package comes from a registry anyone can publish to, so the sha256 pin is checked first and the unpacking then refuses
 * every shape a hostile archive can take: a name that leaves the directory, a link, a device, an encrypted member, a method other than
 * stored or deflate, a name twice, a file where a directory is, a pre-existing link on the way, more members or more bytes than the bounds
 * (a member by its declared size before it is written, all of them by what is written). A refused package leaves nothing behind but its own archive.
 *
 * The driver below imports install.py, points its directories at a scratch tree and builds each archive with zipfile, from the format's
 * specification (APPNOTE): no archive here is the unpacker's own output. Nothing is downloaded: the pins are file:// URLs.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const INSTALL = join(ROOT, "images", "install.py");

const DRIVER = String.raw`
import hashlib, importlib.util, json, os, stat, struct, sys, zipfile
from pathlib import Path

work = Path(sys.argv[2])
os.environ["DFIRSWARM_TOOLS_DIR"] = str(work / "tools")
os.environ["DFIRSWARM_BIN_DIR"] = str(work / "bin")
os.environ["DFIRSWARM_FETCH_BACKOFF"] = "0,0"
spec = importlib.util.spec_from_file_location("install", sys.argv[1])
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)
(work / "tools").mkdir()
(work / "bin").mkdir()
install.arch = lambda: "amd64"
out = {}
counter = [0]


def build(members, name="pkg.nupkg"):
    """members: (name, bytes, options) with options: mode (unix st_mode), system, flag, method, dir"""
    counter[0] += 1
    d = work / ("src%d" % counter[0])
    d.mkdir()
    path = d / name
    with zipfile.ZipFile(path, "w") as z:
        for m in members:
            fname, data, opt = (m + ({},))[:3] if len(m) == 2 else m
            zi = zipfile.ZipInfo(fname, (2026, 1, 1, 0, 0, 0))
            zi.compress_type = opt.get("method", zipfile.ZIP_DEFLATED)
            zi.create_system = opt.get("system", 3)
            zi.external_attr = (opt.get("mode", 0o100644) << 16)
            zi.flag_bits |= opt.get("flag", 0)
            z.writestr(zi, data)
    return path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pin(path, bin="tools/any/linux-x64/prog", name="prog", run=None, extra=None):
    d = {"name": name, "version": "1", "amd64": {"url": "file://" + str(path), "sha256": sha(path), "bin": bin}}
    if run:
        d["amd64"]["run"] = run
    return d


def tree(root):
    root = Path(root)
    return sorted(str(p.relative_to(root)) + ("/" if p.is_dir() else "") for p in root.rglob("*")) if root.exists() else None


GOOD = [("[Content_Types].xml", b"<Types/>"), ("tools/any/linux-x64/prog", b"#!/bin/sh\necho hi\n"), ("tools/any/linux-x64/", b"", {"mode": 0o040755}),
        ("README.md", b"readme")]

# 1. a good package: unpacked whole under the program's directory, sha256 checked first, archive removed, wrapper on PATH
p = build(GOOD)
got, why = install.fetch(pin(p), [])
prog = work / "tools" / "prog" / "tools/any/linux-x64/prog"
out["good"] = {"why": why, "kind": (got or {}).get("kind"), "sha": (got or {}).get("sha256") == sha(p), "tree": tree(work / "tools" / "prog"),
               "mode": oct(stat.S_IMODE(prog.stat().st_mode)) if prog.exists() else None,
               "wrapper": (work / "bin" / "prog").read_text() if (work / "bin" / "prog").exists() else None}

# 2. the pin is wrong: nothing is unpacked
q = build(GOOD)
bad = pin(q, name="wrongsha")
bad["amd64"]["sha256"] = "0" * 64
got, why = install.fetch(bad, [])
out["wrong_sha"] = {"got": got, "why": why, "tree": tree(work / "tools" / "wrongsha")}


def set_flag(path, member):
    """Set the encryption bit (general purpose bit 0) in a member's local and central headers: zipfile's writer will not write it."""
    data = bytearray(Path(path).read_bytes())
    name = member.encode()
    for sig, flag_at, name_at in ((b"PK\x03\x04", 6, 30), (b"PK\x01\x02", 8, 46)):
        at = data.find(sig)
        while at != -1:
            if data[at + name_at: at + name_at + len(name)] == name:
                data[at + flag_at] |= 1
            at = data.find(sig, at + 4)
    Path(path).write_bytes(bytes(data))


def hostile(label, members, flag_member=None, **kw):
    path = build(members)
    if flag_member:
        set_flag(path, flag_member)
    name = "h_" + label
    got, why = install.fetch(pin(path, name=name, **kw), [])
    out[label] = {"got": got, "why": why, "tree": tree(work / "tools" / name), "archive_left": (work / "tools" / name / "pkg.nupkg").exists()}


first = ("tools/any/linux-x64/prog", b"x")
hostile("dotdot", [first, ("../escape", b"x")])
hostile("dotdot_inside", [first, ("a/../../escape", b"x")])
hostile("absolute", [first, ("/tmp/escape-abs", b"x")])
hostile("drive", [first, ("C:/escape", b"x")])
hostile("backslash", [first, ("..\\escape", b"x")])
hostile("empty_component", [first, ("a//b", b"x")])
hostile("dot_component", [first, ("a/./b", b"x")])
hostile("control", [first, ("a\x01b", b"x")])
hostile("long_name", [first, ("a" * 600, b"x")])
hostile("long_component", [first, ("a" * 300, b"x")])
hostile("symlink", [first, ("link", b"/etc/passwd", {"mode": 0o120777})])
hostile("symlink_dir_name", [first, ("linkdir/", b"", {"mode": 0o120777})])
hostile("device", [first, ("dev", b"", {"mode": 0o060666})])
hostile("fifo", [first, ("pipe", b"", {"mode": 0o010644})])
hostile("socket", [first, ("sock", b"", {"mode": 0o140644})])
hostile("encrypted", [first, ("secret", b"x")], flag_member="secret")
hostile("bzip2", [first, ("b", b"x" * 100, {"method": zipfile.ZIP_BZIP2})])
hostile("lzma", [first, ("l", b"x" * 100, {"method": zipfile.ZIP_LZMA})])
hostile("twice", [first, ("dup", b"1"), ("dup", b"2")])
hostile("file_then_dir", [first, ("f", b"1"), ("f/g", b"2")])
hostile("dir_then_file", [first, ("d/", b"", {"mode": 0o040755}), ("d", b"2")])
hostile("dir_named_as_file", [first, ("x", b"", {"mode": 0o040755})])
hostile("file_named_as_dir", [first, ("y/", b"", {"mode": 0o100644})])
hostile("dos_system", [first, ("dosfile", b"ok", {"system": 0, "mode": 0})])
# a mode the archive claims is never honoured: setuid, setgid, sticky, world-writable
hostile("modes", [first, ("tools/any/linux-x64/setuid", b"x", {"mode": 0o104777}), ("w", b"x", {"mode": 0o100666})])
Path(work / "src_garbage").mkdir()
(work / "src_garbage" / "pkg.nupkg").write_bytes(b"this is not a zip file at all" * 10)
got, why = install.fetch(pin(work / "src_garbage" / "pkg.nupkg", name="h_notzip"), [])
out["notzip"] = {"got": got, "why": why, "tree": tree(work / "tools" / "h_notzip")}

# a link already on the way: the package must not write through it
outside = work / "outside"
outside.mkdir()
(work / "tools" / "h_onway").mkdir()
os.symlink(str(outside), str(work / "tools" / "h_onway" / "tools"))
path = build(GOOD)
got, why = install.fetch(pin(path, name="h_onway"), [])
out["link_on_way"] = {"got": got, "why": why, "outside": tree(outside)}

# a file already in the way: nothing is replaced
(work / "tools" / "h_exists").mkdir()
(work / "tools" / "h_exists" / "README.md").write_text("mine")
path = build(GOOD)
got, why = install.fetch(pin(path, name="h_exists"), [])
out["exists"] = {"got": got, "why": why, "kept": (work / "tools" / "h_exists" / "README.md").read_text(), "tree": tree(work / "tools" / "h_exists")}

# the bounds, by what is written: a member that declares less than it holds cannot be made with zipfile, so the bounds are lowered
path = build([first, ("big", b"\0" * 5000), ("small", b"x")])
install.NUPKG_MAX_FILE_BYTES = 4096
got, why = install.fetch(pin(path, name="h_filebytes"), [])
out["file_bytes"] = {"got": got, "why": why, "tree": tree(work / "tools" / "h_filebytes")}
install.NUPKG_MAX_FILE_BYTES = 256 << 20
path = build([first, ("a", b"\0" * 3000), ("b", b"\0" * 3000)])
install.NUPKG_MAX_TOTAL_BYTES = 4096
got, why = install.fetch(pin(path, name="h_total"), [])
out["total_bytes"] = {"got": got, "why": why, "tree": tree(work / "tools" / "h_total")}
install.NUPKG_MAX_TOTAL_BYTES = 512 << 20
path = build([first] + [("f%d" % i, b"x") for i in range(20)])
install.NUPKG_MAX_FILES = 10
got, why = install.fetch(pin(path, name="h_count"), [])
out["count"] = {"got": got, "why": why, "tree": tree(work / "tools" / "h_count")}
install.NUPKG_MAX_FILES = 2000

# a declared size past the bound is refused before anything of that member is written; a compression bomb is a declared size
install.NUPKG_MAX_FILE_BYTES = 1 << 20
path = build([first, ("zeros", b"\0" * (2 << 20))])
got, why = install.fetch(pin(path, name="h_bomb"), [])
install.NUPKG_MAX_FILE_BYTES = 256 << 20
out["bomb"] = {"got": got, "why": why, "tree": tree(work / "tools" / "h_bomb"), "archive_bytes": path.stat().st_size}

# strip and skip are not taken for a package
try:
    install.unpack(Path(work / "x.nupkg"), "x.nupkg", work, strip=True)
    out["strip"] = "taken"
except ValueError as e:
    out["strip"] = "refused"

# the interpreter: an architecture's own run wins over the download's, and an entry without one takes the download's
d = {"name": "n", "run": "dotnet", "amd64": {"url": "u", "sha256": "0" * 64}, "arm64": {"url": "u", "sha256": "0" * 64, "run": "dotnet"}}
install.arch = lambda: "amd64"
a = install.download_run(d)
d2 = {"name": "n", "run": "dotnet", "amd64": {"url": "u", "sha256": "0" * 64, "run": ""}}
b = install.download_run(d2)
c = install.download_run({"name": "n", "amd64": {"url": "u"}})
install.arch = lambda: "arm64"
e2 = install.download_run({"name": "n", "amd64": {"url": "u"}, "arm64": {"url": "u", "run": "dotnet"}})
out["run"] = [a, b, c, e2]
out["escaped"] = [x for x in ("/tmp/escape-abs", str(work / "escape"), str(work / "tools" / "escape"), str(work / "tools" / "h_dotdot" / "C:")) if os.path.exists(x)]
out["modes_perm"] = {n: oct(stat.S_IMODE((work / "tools" / "h_modes" / n).stat().st_mode)) for n in ("tools/any/linux-x64/setuid", "w")
                     if (work / "tools" / "h_modes" / n).exists()}
print("RESULT " + json.dumps(out))
`;

function drive(): Record<string, any> {
  const work = mkdtempSync(join(tmpdir(), "install-nupkg-"));
  const script = join(work, "driver.py");
  mkdirSync(join(work, "w"), { recursive: true });
  writeFileSync(script, DRIVER);
  try {
    const r = spawnSync("python3", ["-I", script, INSTALL, join(work, "w")], { encoding: "utf8", timeout: 120_000, maxBuffer: 64 << 20 });
    assert.equal(r.status, 0, `driver failed: ${r.stderr.slice(-2000)}`);
    const line = r.stdout.split("\n").filter((l) => l.startsWith("RESULT ")).pop();
    assert.ok(line, "the driver printed its result");
    return JSON.parse(line.slice(7));
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

const out = drive();

test("a good package is checked against its sha256, unpacked whole under the program's directory, its archive removed, and its program put on PATH by a wrapper", () => {
  const g = out.good;
  assert.equal(g.why, null);
  assert.equal(g.kind, "download");
  assert.equal(g.sha, true);
  assert.deepEqual(g.tree, ["README.md", "[Content_Types].xml", "tools/", "tools/any/", "tools/any/linux-x64/", "tools/any/linux-x64/prog"]);
  assert.equal(g.mode, "0o755", "the wrapper makes the program executable, the archive's mode is not what does");
  assert.match(g.wrapper, /exec ".*tools\/prog\/tools\/any\/linux-x64\/prog" "\$@"/);
});

test("a package whose bytes are not the pinned ones is not unpacked", () => {
  assert.equal(out.wrong_sha.got, null);
  assert.match(out.wrong_sha.why, /sha256 .* is not the pinned/);
  assert.deepEqual(out.wrong_sha.tree, []);
});

const REFUSED: Array<[string, RegExp]> = [
  ["dotdot", /leaves the download's directory/],
  ["dotdot_inside", /leaves the download's directory/],
  ["absolute", /absolute name/],
  ["drive", /absolute name/],
  ["backslash", /backslash or a control character/],
  ["empty_component", /empty component/],
  ["dot_component", /empty component/],
  ["control", /backslash or a control character/],
  ["long_name", /member name of 600 characters/],
  ["long_component", /component longer than 255/],
  ["symlink", /is a symbolic link/],
  ["symlink_dir_name", /is a symbolic link/],
  ["device", /is a special file/],
  ["fifo", /is a special file/],
  ["socket", /is a special file/],
  ["encrypted", /is encrypted/],
  ["bzip2", /compression method 12; only stored and deflate/],
  ["lzma", /compression method 14; only stored and deflate/],
  ["twice", /in the package twice/],
  ["file_then_dir", /not a directory/],
  ["dir_then_file", /in the package twice/],
  ["dir_named_as_file", /not named as one/],
  ["file_named_as_dir", /not named as one/],
];
for (const [label, why] of REFUSED) {
  test(`a hostile package is refused whole and leaves nothing but its own archive: ${label}`, () => {
    const r = out[label];
    assert.equal(r.got, null, `${label} must not be reported installed`);
    assert.match(r.why, /could not unpack/);
    assert.match(r.why, why);
    assert.deepEqual(r.tree, ["pkg.nupkg"], "the members written before the refusal are removed");
  });
}

test("a member name that leaves the directory writes nothing outside it", () => {
  assert.deepEqual(out.escaped, []);
  assert.equal(existsSync("/tmp/escape-abs"), false);
});

test("a DOS-created entry (no unix mode) is unpacked as a plain file, and the archive's mode bits are never honoured", () => {
  assert.equal(out.dos_system.got?.kind, "download");
  assert.equal(out.modes.got?.kind, "download");
  assert.deepEqual(out.modes_perm, { "tools/any/linux-x64/setuid": "0o644", w: "0o644" }, "setuid and world-writable bits are not carried");
});

test("a text that is not a zip file is refused as such", () => {
  assert.equal(out.notzip.got, null);
  assert.match(out.notzip.why, /could not unpack: File is not a zip file/);
});

test("a symbolic link already on the way is not written through", () => {
  assert.equal(out.link_on_way.got, null);
  assert.match(out.link_on_way.why, /could not unpack/);
  assert.deepEqual(out.link_on_way.outside, [], "nothing was written outside the program's directory");
});

test("a file already in the way is not replaced", () => {
  assert.equal(out.exists.got, null);
  assert.equal(out.exists.kept, "mine");
  assert.match(out.exists.why, /could not unpack/);
});

test("the bounds: a member past the per-member bound, members past the total bound by what is written, and more members than the bound", () => {
  for (const label of ["file_bytes", "total_bytes", "count"]) {
    assert.equal(out[label].got, null, label);
    assert.match(out[label].why, /could not unpack/, label);
  }
  assert.match(out.file_bytes.why, /big declares 5000 bytes; at most 4096/);
  assert.match(out.total_bytes.why, /grows past the bounds/);
  assert.match(out.count.why, /21 members; at most 10/);
  for (const label of ["file_bytes", "total_bytes", "count"]) assert.deepEqual(out[label].tree, ["pkg.nupkg"], `${label} left only its archive`);
});

test("a compression bomb is refused by its declared size before its member is written", () => {
  assert.equal(out.bomb.got, null);
  assert.match(out.bomb.why, /declares 2097152 bytes; at most 1048576/);
  assert.deepEqual(out.bomb.tree, ["pkg.nupkg"]);
  assert.ok(out.bomb.archive_bytes < 1 << 20, "a few hundred kilobytes of archive");
});

test("strip and skip are not taken for a package", () => {
  assert.equal(out.strip, "refused");
});

test("an architecture's own `run` wins over the download's; an empty one means the program runs by itself; the download's applies otherwise", () => {
  assert.deepEqual(out.run, ["dotnet", null, null, "dotnet"]);
});
