#!/usr/bin/env bash
# The parsers the platform packs carry, against data built from the documented
# formats rather than from the parsers themselves.
#
# Each case builds its input by hand from the format's specification, so a test
# passing means the parser reads the format — not that it agrees with itself.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
P="$ROOT/packs"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || { echo "skip - no python3"; exit 0; }

run() { "$PY" "$P/$1/run.py"; }

"$PY" - "$P" <<'EOF' || fail "a pack parser did not read its format"
import datetime, gzip, json, os, random, socket, sqlite3, struct, subprocess, sys, tempfile

PACKS = sys.argv[1]
WORK = tempfile.mkdtemp()
failures = []


def tool(pack_tool, args, cwd=None):
    out = subprocess.run([sys.executable, os.path.join(PACKS, pack_tool, "run.py")],
                         input=json.dumps(args), capture_output=True, text=True, cwd=cwd)
    try:
        return json.loads(out.stdout)
    except ValueError:
        return {"_stdout": out.stdout[:400], "_stderr": out.stderr[-400:]}


def check(name, condition, detail=""):
    if condition:
        print("ok - %s" % name)
    else:
        failures.append("%s %s" % (name, detail))
        print("FAIL: %s %s" % (name, detail))


# --- linux-forensics/utmp_parse: the glibc struct, built from its own layout ---
def utmp(kind, user, line, host, ip, when, pid=1234):
    b = bytearray(384)
    struct.pack_into("<hxxi", b, 0, kind, pid)
    b[0x008:0x008 + len(line)] = line.encode()
    b[0x02C:0x02C + len(user)] = user.encode()
    b[0x04C:0x04C + len(host)] = host.encode()
    struct.pack_into("<ii", b, 0x154, when, 0)
    if ip:
        b[0x15C:0x160] = socket.inet_aton(ip)
    return bytes(b)


stamp = int(datetime.datetime(2026, 2, 14, 9, 30, tzinfo=datetime.timezone.utc).timestamp())
path = os.path.join(WORK, "wtmp")
open(path, "wb").write(utmp(2, "reboot", "~", "6.8.0", None, stamp - 3600, 0)
                       + utmp(7, "root", "pts/1", "203.0.113.9", "203.0.113.9", stamp))
got = tool("linux-forensics/tools/utmp_parse", {"path": path})
check("utmp_parse reads a boot record and a session with its source address",
      got.get("boots") == 1
      and [r["user"] for r in got.get("records", [])] == ["reboot", "root"]
      and got["records"][1]["address"] == "203.0.113.9"
      and got["records"][1]["time"] == "2026-02-14T09:30:00Z", got.get("error", ""))

# --- linux-forensics/auth_log: the year syslog does not record -----------------
d = os.path.join(WORK, "log"); os.makedirs(d, exist_ok=True)
with gzip.open(os.path.join(d, "auth.log.1.gz"), "wt") as fh:
    fh.write("Dec 31 23:58:01 web01 sshd[1]: Failed password for invalid user a from 203.0.113.9 port 1 ssh2\n"
             "Jan  1 00:02:11 web01 sshd[2]: Accepted publickey for deploy from 10.0.0.7 port 2 ssh2: RSA SHA256:zz\n")
open(os.path.join(d, "auth.log"), "w").write(
    "Jan  1 00:05:44 web01 sudo:   deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/id\n")
import time
os.utime(os.path.join(d, "auth.log.1.gz"), (time.time(), time.mktime((2026, 1, 1, 0, 0, 0, 0, 0, 0))))
os.utime(os.path.join(d, "auth.log"), (time.time(), time.mktime((2026, 1, 2, 0, 0, 0, 0, 0, 0))))
got = tool("linux-forensics/tools/auth_log", {"path": d})
times = [r["time"] for r in got.get("records", [])]
check("auth_log follows the rotation and crosses new year correctly",
      times == ["2025-12-31T23:58:01", "2026-01-01T00:02:11", "2026-01-01T00:05:44"], str(times))

# --- macos-forensics/fsevents_parse: a gzip page of DLS records ----------------
def fsevent(path_, eid, flags, node):
    return path_.encode() + b"\x00" + struct.pack("<QI", eid, flags) + struct.pack("<Q", node)


body = fsevent("Users/a/payroll.xlsx", 1001, 0x01000000 | 0x00008000, 12) \
     + fsevent("Users/a/payroll.xlsx", 1042, 0x02000000 | 0x00008000, 12)
page = b"2SLD" + b"\x00" * 4 + struct.pack("<I", 12 + len(body)) + body
fs = os.path.join(WORK, ".fseventsd"); os.makedirs(fs, exist_ok=True)
with gzip.open(os.path.join(fs, "0000000000000fff"), "wb") as fh:
    fh.write(page)
got = tool("macos-forensics/tools/fsevents_parse", {"path": fs})
check("fsevents_parse decodes the flags and keeps the event id order",
      got.get("record_count") == 2
      and got["records"][0]["flags"] == ["FileEvent", "Created"]
      and got["records"][1]["flags"] == ["FileEvent", "Removed"]
      and got["event_id_range"] == [1001, 1042], got.get("error", ""))

# --- mobile-forensics/sqlite_freespace: a row SQLite no longer lists -----------
db = os.path.join(WORK, "sms.db")
con = sqlite3.connect(db)
# Some distributions compile SQLite with secure delete on, which zeroes a freed
# cell instead of leaving it. That is a property of the build, not of the parser,
# so ask for it off and say which it was if the row does not survive.
con.execute("PRAGMA secure_delete=OFF")
secure_delete = con.execute("PRAGMA secure_delete").fetchone()[0]
con.execute("CREATE TABLE message (id INTEGER PRIMARY KEY, handle TEXT, text TEXT)")
con.executemany("INSERT INTO message (handle, text) VALUES (?,?)",
                [("+1", "lunch at one"), ("+2", "burn the drive at midnight"), ("+3", "see you")])
con.commit(); con.execute("DELETE FROM message WHERE id = 2"); con.commit(); con.close()
got = tool("mobile-forensics/tools/sqlite_freespace", {"db": db, "contains": "burn"})
recovered = got.get("fragment_count", 0) >= 1 and \
    "burn the drive" in (got.get("fragments") or [{}])[0].get("text", "")
if not recovered and secure_delete:
    print("skip - sqlite_freespace: this SQLite is built with secure delete (%s), so a freed "
          "cell is zeroed and there is nothing for any parser to recover" % secure_delete)
else:
    check("sqlite_freespace recovers a deleted row from the page freeblock chain", recovered,
          "secure_delete=%s fragments=%s"
          % (secure_delete, json.dumps(got.get("fragments", []))[:200]))

# --- network-forensics/pcap_summary and beacon_score ---------------------------
def packet(src, dst, sport, dport, flags, payload=b""):
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 8192, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + tcp
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip


cap = os.path.join(WORK, "c.pcap")
base = 1771070000
with open(cap, "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i in range(6):
        for when, body in ((base + i * 60, packet("10.0.0.5", "203.0.113.7", 50000 + i, 443, 0x02)),
                           (base + i * 60 + 0.2, packet("203.0.113.7", "10.0.0.5", 443, 50000 + i, 0x18, b"x" * 120))):
            fh.write(struct.pack("<IIII", int(when), int((when % 1) * 1e6), len(body), len(body)))
            fh.write(body)
got = tool("network-forensics/tools/pcap_summary",
           {"path": cap, "group": "endpoint", "with_syn_times": True})
conversation = (got.get("endpoint_aggregates") or [{}])[0]
check("pcap_summary reads a classic pcap and groups a service endpoint",
      got.get("packets") == 12 and conversation.get("service_port") == 443
      and conversation.get("syn_observations") == 6 and conversation.get("syn_unique") == 6,
      got.get("error", ""))
got2 = tool("network-forensics/tools/beacon_score",
            {"timestamps": conversation.get("syn_times", []), "label": "t"})
check("beacon_score calls a fixed sixty-second interval a tight cluster, not a verdict",
      got2.get("median_interval_seconds") == 60.0 and got2.get("shape") == "tight_cluster",
      json.dumps({k: got2.get(k) for k in ("median_interval_seconds", "shape", "error")}))

# --- encrypted-containers/crypto_id: a LUKS1 header with three enabled slots ---
# Built from the LUKS1 on-disk specification, not from the parser: 208 bytes of
# fixed fields (the UUID at 168), then eight 48-byte slots of active (4),
# iterations (4), salt (32), key material offset (4) and stripes (4), big-endian.
h = bytearray(592)
h[0:6] = b"LUKS\xba\xbe"; struct.pack_into(">H", h, 6, 1)
h[8:11] = b"aes"; h[40:51] = b"xts-plain64"; h[72:78] = b"sha256"
struct.pack_into(">I", h, 108, 64)
h[168:168 + 36] = b"2f4a8e0c-1b5d-4c3a-9e7f-0a1b2c3d4e5f"
for i in range(8):
    struct.pack_into(">II32sII", h, 208 + i * 48, 0x00AC71F3 if i < 3 else 0x0000DEAD, 1000 + i,
                     bytes([0xA0 + i]) * 32, 8 + i * 256, 4000)
luks = os.path.join(WORK, "luks.img"); open(luks, "wb").write(bytes(h))
got = tool("encrypted-containers/tools/crypto_id", {"path": luks})
check("crypto_id reads a LUKS1 key slot table with no key",
      got.get("scheme") == "LUKS1" and got.get("enabled_slots") == 3
      and got.get("cipher") == "aes"
      and got.get("uuid") == "2f4a8e0c-1b5d-4c3a-9e7f-0a1b2c3d4e5f"
      and [s["stripes"] for s in got.get("key_slots", [])] == [4000] * 8
      and [s["key_material_offset_sectors"] for s in got.get("key_slots", [])] == [8 + i * 256 for i in range(8)]
      and [s["iterations"] for s in got.get("key_slots", [])] == [1000 + i for i in range(8)],
      got.get("error", json.dumps(got.get("key_slots", [])[:2])))

# --- ransomware-response/encrypted_survey: the bytes every sampled tail ends with ---
# An observation pending a reference match (basis "observation"), not a family marker;
# tests/pack-encrypted-survey.test.ts and tests/pack-ransom-note-scan.test.ts hold the rest of the
# pack's tools' contract.
random.seed(11)
share = os.path.join(WORK, "share"); os.makedirs(share, exist_ok=True)
for i in range(6):
    open(os.path.join(share, "f%d.xlsx.LOCKD" % i), "wb").write(
        bytes(random.getrandbits(8) for _ in range(120000)) + b"\xde\xad\xbe\xefKEYBLOB1")
# The survey writes its census under work/<agent>/tool-output of its working directory.
got = tool("ransomware-response/tools/encrypted_survey", {"root": share}, cwd=WORK)
shared = got.get("shared_tail_suffix") or {}
check("encrypted_survey reports the bytes every sampled file ends with, as an observation",
      shared.get("suffix_hex") == b"\xde\xad\xbe\xefKEYBLOB1".hex() and shared.get("basis") == "observation"
      and got.get("appended_extension_observations", [{}])[0].get("extension") == ".lockd", str(shared))

# --- triage-collection/collection_index: the stream a collector renamed --------
coll = os.path.join(WORK, "kape", "C", "Users", "a"); os.makedirs(coll, exist_ok=True)
for name in ("report.txt_Zone.Identifier", "holiday_photos.jpg"):
    open(os.path.join(coll, name), "wb").write(b"x")
got = tool("triage-collection/tools/collection_index",
           {"root": os.path.join(WORK, "kape")})
streams = got.get("possible_renamed_streams") or []
hyp = {e["in_collection"]: e["source_path_hypothesis"] for e in got.get("entries", [])}
check("collection_index reads a path by convention as a labelled hypothesis and spots a renamed stream",
      len(streams) == 1 and streams[0]["possible_original"] == "report.txt:Zone.Identifier"
      and hyp.get(os.path.join("C", "Users", "a", "holiday_photos.jpg"), {}).get("path") == r"C:\Users\a\holiday_photos.jpg"
      and hyp.get(os.path.join("C", "Users", "a", "holiday_photos.jpg"), {}).get("confidence") == "low"
      and "single letter" in hyp.get(os.path.join("C", "Users", "a", "holiday_photos.jpg"), {}).get("method", "")
      and all(e.get("source_path_observed") is None and "original_path" not in e for e in got.get("entries", [])),
      json.dumps(streams))

# --- summary tables are whole: nothing past a top 10, 20 or 30 ------------------
# collection_index kept the ten commonest modification dates, cloudtrail_parse
# and ual_parse the top 20 or 30 of each table, and nothing said so.
dated = os.path.join(WORK, "dated")
for i in range(12):
    os.makedirs(os.path.join(dated, "C"), exist_ok=True)
    f = os.path.join(dated, "C", "f%02d.txt" % i)
    open(f, "wb").write(b"x")
    t = datetime.datetime(2026, 1, 1 + i, 12, tzinfo=datetime.timezone.utc).timestamp()
    os.utime(f, (t, t))
got = tool("triage-collection/tools/collection_index", {"root": dated})
check("collection_index names every modification date, not the ten commonest",
      len(got.get("modification_dates") or {}) == 12, json.dumps(got.get("modification_dates")))

trail = os.path.join(WORK, "trail.json")
json.dump({"Records": [{"eventTime": "2026-02-14T09:%02d:00Z" % i, "eventName": "Event%02d" % i,
                        "eventSource": "iam.amazonaws.com", "sourceIPAddress": "198.51.100.%d" % i,
                        "errorCode": "AccessDenied", "eventID": "e%02d" % i,
                        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/u%02d" % i}}
                       for i in range(35)]}, open(trail, "w"))
got = tool("cloud-forensics/tools/cloudtrail_parse", {"path": trail})
check("cloudtrail_parse keeps every row of its tables and every identity refused",
      [len(got.get(k) or []) for k in ("by_event", "by_identity", "by_address", "refusals_by_identity")] == [35, 35, 35, 35],
      json.dumps({k: len(got.get(k) or []) for k in ("by_event", "by_identity", "by_address", "refusals_by_identity")}))

ual = os.path.join(WORK, "ual.json")
json.dump([{"CreationDate": "2026-02-14T09:%02d:00" % i, "Operations": "Op%02d" % i, "UserIds": "u%02d@example.org" % i,
            "AuditData": json.dumps({"Operation": "Op%02d" % i, "UserId": "u%02d@example.org" % i,
                                     "ClientIP": "203.0.113.%d" % i, "Id": "r%02d" % i})}
           for i in range(35)], open(ual, "w"))
got = tool("cloud-forensics/tools/ual_parse", {"path": ual})
check("ual_parse keeps every row of its tables",
      [len(got.get(k) or []) for k in ("by_operation", "by_user", "by_address")] == [35, 35, 35],
      json.dumps({k: len(got.get(k) or []) for k in ("by_operation", "by_user", "by_address")}))

# --- mobile-forensics/protobuf_peek: the wire format, built by hand ------------
def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


inner = varint((1 << 3) | 2) + varint(len(b"com.example.beacon")) + b"com.example.beacon"
blob = varint((1 << 3) | 2) + varint(len(inner)) + inner + varint((3 << 3) | 0) + varint(42)
got = tool("mobile-forensics/tools/protobuf_peek", {"hex": blob.hex()})
check("protobuf_peek unwraps a nested message without a schema",
      got.get("looks_like_protobuf") is True
      and got.get("strings", [{}])[0].get("text") == "com.example.beacon",
      json.dumps(got.get("problems", []))[:200])

# --- computer-forensics-base/timestamp_decode ---------------------------------
got = tool("computer-forensics-base/tools/timestamp_decode", {"value": "133502964000000000"})
readings = {r["epoch"]: r["when"] for r in got.get("readings", [])}
check("timestamp_decode reads a FILETIME as a FILETIME",
      readings.get("FILETIME (100 ns)") == "2024-01-21T07:40:00Z", json.dumps(readings))

# --- linux-forensics/cron_dump: systemd timers, as systemd.timer(5) writes them
def timers_under(name, files):
    units = os.path.join(WORK, name, "etc", "systemd", "system")
    os.makedirs(units)
    for fname, text in files.items():
        open(os.path.join(units, fname), "w").write(text)
    try:
        out = subprocess.run([sys.executable, os.path.join(PACKS, "linux-forensics/tools/cron_dump/run.py")],
                             input=json.dumps({"root": os.path.join(WORK, name)}),
                             capture_output=True, text=True, timeout=15)
        got = json.loads(out.stdout)
    except (subprocess.TimeoutExpired, ValueError) as exc:
        got = {"_error": type(exc).__name__}
    return got, {os.path.basename(e.get("file", "")): e
                 for e in got.get("entries", []) if e.get("source") == "systemd"}


got, timers = timers_under("cron-crlf", {"backup.timer":
    "[Unit]\r\nDescription=Nightly backup\r\n\r\n[Timer]\r\n  OnCalendar = *-*-* 02:00:00 \r\nPersistent=true\r\nUnit=\nDescription=x\n"})
backup = timers.get("backup.timer", {})
check("cron_dump reads a CRLF timer and does not take the next line for an empty key",
      backup.get("schedule") == "*-*-* 02:00:00" and backup.get("persistent") == "true"
      and backup.get("unit") == "backup.service", json.dumps(got)[:300])

# Blank lines are legal anywhere in a unit file. Before the parser kept its
# whitespace to one line, these took minutes (quadratic in the line count) and
# the tool's 60 s timeout ended the sweep with nothing printed.
got, timers = timers_under("cron-blank", {"zz.timer": "\n" * 100000 + "[Timer]\nOnBootSec=5min\n"})
check("cron_dump reads a timer padded with blank lines in linear time",
      timers.get("zz.timer", {}).get("schedule") == "5min" and timers["zz.timer"].get("at_reboot") is True,
      json.dumps(got)[:300])

# An empty key followed by a long run of spaces: a pattern that backtracks
# between the spaces and the value spends seconds per key on this.
pad = " " * 100000
got, timers = timers_under("cron-spaces", {"sp.timer":
    "[Timer]\nOnCalendar=%s\nUnit=%s\nPersistent=%s\nOnBootSec=5min\n" % (pad, pad, pad)})
sp = timers.get("sp.timer", {})
check("cron_dump reads a timer whose empty keys are padded with spaces in linear time",
      sp.get("schedule") == "5min" and sp.get("unit") == "sp.service" and sp.get("persistent") is None,
      json.dumps(got)[:300])

raise SystemExit(1 if failures else 0)
EOF
echo "pack-parsers: all checks passed"
