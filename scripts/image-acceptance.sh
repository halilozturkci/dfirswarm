#!/bin/sh
# Accept a built image: run INSIDE it (a container of the image, or the microVM
# booted from it), with the packs of its profile mounted, and write receipts.
#
#   sh scripts/image-acceptance.sh [--packs DIR[:DIR...]] [--summary FILE]
#
# Two kinds of receipt, as a markdown table each (on stdout; appended to FILE
# when --summary is given, which the image-boot workflow points at the job
# summary):
#
#   programs  Every program the image's record (/etc/dfirswarm/image.json,
#             `binaries`) names: found on PATH or not, the first line its
#             version command printed (--version, -V, -version, version, -v:
#             the first that answers), and the version the pack pinned
#             (`downloads`). A program the record names that is not on PATH
#             fails, unless the build was told it may lack it
#             (`missing_allowed`); a version that answers with a number and
#             does not contain the pinned version fails.
#   tools     Every tool of the packs named by --packs, run as a job runs one
#             (JSON arguments on stdin, the answer one JSON document on
#             stdout), on an empty file for each argument that names a path,
#             and, where the tool's manifest names a format this script can
#             build from its specification (a pcap with no packet, an empty
#             zip, an empty SQLite database, a JSON object, a text file), on
#             that smallest valid file too. The receipt is the tool, the
#             input, the exit code, the answer's `status` and the seconds. A
#             tool that gives no JSON, dies on a signal or runs past its
#             manifest's timeout fails. What the tool says about the input
#             (failed, partial, complete) is recorded, not judged: an empty
#             file is an input every tool must answer, not one that must
#             succeed.
#
# Nothing here is evidence or a secret; the fixtures are made up and thrown
# away, in a directory this script makes and removes.
set -u
packs=""
summary=""
while [ $# -gt 0 ]; do
  case "$1" in
    --packs) packs="${2-}"; shift 2 ;;
    --summary) summary="${2-}"; shift 2 ;;
    *) echo "usage: image-acceptance.sh [--packs DIR[:DIR...]] [--summary FILE]" >&2; exit 2 ;;
  esac
done
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
python3 - "$packs" "$T" >"$T/report.md" <<'PY'
import json, os, re, shutil, signal, sqlite3, struct, subprocess, sys, time, zipfile
from pathlib import Path

packs_arg, tmp = sys.argv[1], Path(sys.argv[2])
etc = Path(os.environ.get("DFIRSWARM_ETC_DIR", "/etc/dfirswarm"))
failures = []

def cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ")[:160]

def table(title, head, rows):
    out = [f"### {title}", "", "| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"

try:
    record = json.loads((etc / "image.json").read_text())
    binaries = record["binaries"]
    assert isinstance(binaries, dict)
except (OSError, ValueError, KeyError, AssertionError) as e:
    print(f"image acceptance: the image's record ({etc}/image.json) could not be read: {e}")
    sys.exit(3)
allowed = set(record.get("missing_allowed") or [])
downloads = record.get("downloads") or {}

# --- programs -----------------------------------------------------------------
VERSION_ARGS = (["--version"], ["-V"], ["-version"], ["-ver"], ["version"], ["-v"])
NUMBER = re.compile(r"\d+\.\d+|\d{6,}")

def first_line(text):
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""

def version_of(exe):
    for args in VERSION_ARGS:
        try:
            r = subprocess.run([exe, *args], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20,
                               env={**os.environ, "LC_ALL": "C"})
        except (subprocess.TimeoutExpired, OSError):
            continue
        line = first_line(r.stdout) or first_line(r.stderr)
        if line and NUMBER.search(line) and r.returncode in (0, 1):
            return " ".join(args), line
    return "", ""

rows = []
for name in sorted(binaries):
    exe = shutil.which(name, path=os.environ.get("PATH"))
    pin = (downloads.get(name) or {}).get("version") or "-"
    if not exe:
        if name in allowed:
            rows.append((name, "-", "-", pin, "missing, as the build allowed"))
        else:
            rows.append((name, "-", "-", pin, "MISSING"))
            failures.append(f"{name} is named by this image and is not on PATH")
        continue
    cmd, line = version_of(exe)
    if not line:
        rows.append((name, "-", "-", pin, "on PATH, no version output"))
    elif pin != "-" and pin.lstrip("v") not in line:
        rows.append((name, cmd, line, pin, "DIFFERS from the pin"))
        failures.append(f"{name}: `{cmd}` printed {line!r}, pinned {pin}")
    else:
        rows.append((name, cmd, line, pin, "ok" if pin != "-" else "ok, not pinned by version"))
report = [table("Programs", ["program", "command", "version string", "pinned", "receipt"], rows)]

# --- tools --------------------------------------------------------------------
def pcap(path):
    # The classic libpcap file header (magic, 2.4, thiszone 0, sigfigs 0, snaplen 65535, Ethernet) and no packet.
    path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

def empty_zip(path):
    with zipfile.ZipFile(path, "w"):
        pass

def empty_sqlite(path):
    con = sqlite3.connect(path)
    con.execute("create table t (a)")
    con.commit()
    con.close()

BUILDERS = {
    (".pcap", ".pcapng", ".cap"): ("pcap with no packet", pcap),
    (".zip",): ("empty zip", empty_zip),
    (".sqlite", ".sqlite3", ".db"): ("empty SQLite database", empty_sqlite),
    (".json",): ("JSON object", lambda p: p.write_text("{}\n")),
    (".txt", ".log", ".csv", ".tsv"): ("text file", lambda p: p.write_text("a\n")),
}
PATHISH = re.compile(r"(^|_)(path|file|image|hive|pcap|input|dir|directory|folder|archive|dump|evidence)(_|$)", re.I)

def path_params(manifest):
    out = []
    for key, spec in (manifest.get("params") or {}).items():
        if not isinstance(spec, dict) or spec.get("type") != "string":
            continue
        if PATHISH.search(key) or re.match(r"(path|file|directory|folder)\b", str(spec.get("description", "")), re.I):
            out.append(key)
    return out

def builder_for(manifest):
    names = [str(n).lower() for n in ((manifest.get("use") or {}).get("names") or [])]
    for exts, built in BUILDERS.items():
        if any(n.endswith(exts) for n in names):
            return built
    return None

def run_tool(pack, tool_dir, manifest, label, make):
    work = tmp / "tools" / f"{pack}-{tool_dir.name}-{label}".replace(" ", "_")
    (work / "out").mkdir(parents=True)
    params = path_params(manifest)
    args = {}
    if params:
        fixture = work / "input"
        make(fixture)
        args[params[0]] = str(fixture)
    # A required argument that names no path gets the plainest value of its type.
    plain = {"string": "a", "integer": 1, "number": 1, "boolean": False}
    for key, spec in (manifest.get("params") or {}).items():
        if isinstance(spec, dict) and spec.get("required") is True and key not in args and spec.get("type") in plain:
            args[key] = plain[spec["type"]]
    limit = min(int(manifest.get("timeout_seconds") or 60), 120)
    started = time.monotonic()
    try:
        r = subprocess.run([sys.executable, str(tool_dir / manifest.get("entry", "run.py"))], input=json.dumps(args), cwd=work,
                           capture_output=True, text=True, timeout=limit,
                           env={**os.environ, "OUT": str(work / "out"), "PYTHONDONTWRITEBYTECODE": "1"})
    except subprocess.TimeoutExpired:
        failures.append(f"{pack}/{tool_dir.name} ({label}) ran past its {limit} s")
        return (pack, tool_dir.name, label, "-", "-", f">{limit}", "TIMED OUT")
    seconds = f"{time.monotonic() - started:.1f}"
    status, ok, where = "-", False, "answered"
    # The answer is one JSON document on stdout; a refusal that exits with its
    # JSON as the message (SystemExit) has it on stderr, and is taken as an answer too.
    for text, place in ((r.stdout, "answered"), (r.stderr, "answered (refusal on stderr)")):
        try:
            doc = json.loads(text)
        except ValueError:
            continue
        if isinstance(doc, dict):
            status = str(doc.get("status") or ("refused" if doc.get("ok") is False else "no status"))
            ok, where = True, place
            break
    if r.returncode < 0:
        failures.append(f"{pack}/{tool_dir.name} ({label}) died on signal {-r.returncode}")
        return (pack, tool_dir.name, label, r.returncode, "-", seconds, "KILLED")
    if not ok:
        failures.append(f"{pack}/{tool_dir.name} ({label}) gave no JSON answer (exit {r.returncode})")
        return (pack, tool_dir.name, label, r.returncode, "-", seconds, "NO JSON")
    return (pack, tool_dir.name, label, r.returncode, status, seconds, where)

trows = []
for p in [x for x in packs_arg.split(":") if x]:
    pack = Path(p)
    for mf in sorted((pack / "tools").glob("*/manifest.json")):
        try:
            manifest = json.loads(mf.read_text())
        except ValueError:
            failures.append(f"{pack.name}/{mf.parent.name}: manifest.json is not JSON")
            continue
        trows.append(run_tool(pack.name, mf.parent, manifest, "empty file", lambda path: path.write_bytes(b"")))
        built = builder_for(manifest)
        if built and path_params(manifest):
            trows.append(run_tool(pack.name, mf.parent, manifest, built[0], built[1]))
if packs_arg:
    report.append(table("Tools", ["pack", "tool", "input", "exit", "status", "seconds", "receipt"], trows))

print(f"## Image acceptance ({record.get('profile', '?')}, {record.get('arch', '?')})\n")
print("\n".join(report))
if failures:
    print("### Failed\n")
    for f in failures:
        print(f"- {f}")
    sys.exit(1)
print(f"{len(rows)} programs and {len(trows)} tool runs: no program missing, no pin differing, no tool without an answer.")
PY
rc=$?
cat "$T/report.md"
[ -n "$summary" ] && cat "$T/report.md" >> "$summary"
exit "$rc"
