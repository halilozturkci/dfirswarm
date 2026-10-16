#!/usr/bin/env python3
"""Catalogue a capture: capinfos metadata and complete listings of selected tshark fields.

    run.py detect --target T          exit 0 when the file has a pcap or pcapng signature, 1 when it does not
    run.py run --target T --out DIR

What the catalogue is: a complete listing of the SELECTED FIELDS of every packet (packets.tsv) and of the DNS,
HTTP and TLS packets (dns.tsv, http.tsv, tls.tsv), and of HTTP/2 and QUIC packets (http2.tsv, quic.tsv) when the
installed tshark lists the fields they need. It is a projection the installed tshark made, not the capture: the
capture stays the authority at the byte level, and every listing is one tshark's reading. A table with no rows
does not show that the protocol is absent: packets may be truncated, encrypted, malformed or of a protocol the
build does not decode (coverage.json counts the truncated ones).

The receipt, coverage.json, exists from the first moment and is rewritten after every step, so a run that is cut off
(the outer time limit, a signal, a kill) leaves what was done: status "partial" with finished false until the last
step, then "complete" (every step ran and exited 0 and no listing lacks a field), "partial" (a step failed, timed out or was
not attempted, or a listing was made without a field the installed tshark does not list: the status_basis names it) or
"failed". "complete" is an execution result. It does not say what the capture holds. Every step records its
status, exit code, seconds and rows; the versions of tshark and capinfos are recorded; one deadline
(NETWORK_CAPTURE_SECONDS, default 3300, under the recipe's 3600) covers every step, a step that uses it up is killed
with everything it started and the steps after it are not_attempted.

http2.tsv and quic.tsv are listed only after `tshark -G fields` shows that the installed build has the fields; the
ones it does not have are named in the step (fields_missing) and left out. Nothing is assumed about what a version
supports.

SENSITIVE: http.tsv holds request URIs, hosts and user agents, dns.tsv query and answer names, tls.tsv server names and
certificate strings, http2.tsv the :authority and :path of requests; all of it can carry credentials, tokens and
identifiers. The receipt marks each table (secret_bearing). Every file the recipe writes is private (the directory 0700,
files 0600, and what tshark writes too), but the mark is informational: nothing in the harness reads it, so run the
recipe's job as a sensitive output when the capture can hold any.

Every field a listing asks for is checked against `tshark -G fields` first: a field the installed build does not list is
named in the step (fields_missing) and left out of that listing, so one missing field never makes a whole listing fail.
If the list of fields cannot be read, the fields are asked for unchecked and the step says so.
"""
import json
import os
import shutil
import select
import signal
import subprocess
import sys
import time

MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
          b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
DEADLINE = min(float(os.environ.get("NETWORK_CAPTURE_SECONDS", "3300")), 3500.0)   # under the recipe's 3600-second limit, so that it stops its own steps
RECIPE = "network-capture"

# name, display filter, fields, the fields whose existence `tshark -G fields` must show before the listing is made
LISTINGS = [
    ("packets.tsv", None, ["frame.number", "frame.time_epoch", "frame.cap_len", "frame.len", "_ws.col.Protocol", "ip.src", "ipv6.src", "tcp.srcport", "udp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport", "udp.dstport"], []),
    ("dns.tsv", "dns", ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "dns.id", "dns.flags.response", "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa", "dns.resp.name", "dns.flags.rcode"], []),
    ("http.tsv", "http", ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.stream", "http.request.method", "http.host", "http.request.uri", "http.response.code", "http.content_length", "http.user_agent"], []),
    ("tls.tsv", "tls", ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.stream", "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.ja3", "x509sat.uTF8String"], []),
    ("http2.tsv", "http2", ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.stream", "http2.streamid", "http2.type", "http2.headers.method", "http2.headers.authority", "http2.headers.path", "http2.headers.status"],
     ["http2.streamid", "http2.type", "http2.headers.method", "http2.headers.authority", "http2.headers.path", "http2.headers.status"]),
    ("quic.tsv", "quic", ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "udp.srcport", "ip.dst", "ipv6.dst", "udp.dstport", "quic.connection.number", "quic.version", "quic.long.packet_type", "quic.dcid", "quic.scid"],
     ["quic.connection.number", "quic.version", "quic.long.packet_type", "quic.dcid", "quic.scid"]),
]
SECRET_BEARING = {
    "http.tsv": "request URIs, hosts and user agents can carry credentials, tokens and session identifiers",
    "dns.tsv": "query and answer names can carry tokens, identifiers and exfiltrated data in a label",
    "tls.tsv": "server names and certificate strings can carry identifiers and tokens",
    "http2.tsv": "the :authority and :path of a request can carry credentials, tokens and session identifiers",
}
# A conditional listing is made only if at least one of these exists in the installed build.
NEEDS_ONE_OF = {"http2.tsv": ["http2.streamid", "http2.type"], "quic.tsv": ["quic.version", "quic.long.packet_type", "quic.dcid", "quic.connection.number"]}


def target_of(arg):
    text = open(arg, encoding="utf-8").read() if os.path.isfile(arg) else arg
    target = json.loads(text)
    paths = target.get("paths") if isinstance(target, dict) else None
    if not isinstance(paths, list) or not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def detect(path):
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        return False, "unreadable: %s" % (exc.strerror or exc)
    if magic in MAGICS:
        return True, "pcap or pcapng file signature"
    return False, "no pcap or pcapng file signature"


# BEGIN SHARED PROCESS
# The same text is in pcap_extract, zeek_run, suricata_run, the network-capture recipe and computer-forensics-base's
# archive_extract; tests/pack-network-withholding.test.ts holds the four network copies equal and tests/pack-base-shared.test.ts
# holds archive_extract's to them. A program an engine tool runs is started in THIS tool's process group, never in a session of
# its own: the harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid,
# SIGKILL)), and an engine in a group of its own goes on writing into the output directory after the tool is gone. On
# Linux the kernel is also asked to kill it if the tool dies. A deadline kills the program and what it started by
# walking the process tree, and SIGTERM, SIGINT and SIGHUP do the same and then give the tool a last word. Only what is
# below a program this tool started and has not yet waited for is ever signalled: the walk starts at that program's pid
# and nowhere else, and a program that has been waited for (its pid may be another process's by now) is left alone. The
# walk has no bound but the number of processes. Two cases leave the tree running: a ps that needs more than PS_WAIT
# seconds, and a sandbox that denies both libproc and ps (macOS).
try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
ACTIVE = []                    # the programs running now

def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    return subprocess.Popen(argv, **kwargs)


def _children_libproc(pid):
    """The direct children of `pid` on macOS, from libproc (macOS only: proc_listchildpids is not a symbol of the other
    BSDs; a library call, so no program is started and nothing can be slow); None when the library, the symbol or the
    call is not there."""
    try:
        import ctypes.util
        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        lib.proc_listchildpids.restype = ctypes.c_int
        size = 256
        while size <= 1 << 16:
            buf = (ctypes.c_int * size)()
            if lib.proc_listchildpids(pid, buf, ctypes.sizeof(buf)) < 0:
                return None
            found = []
            for value in buf:
                if value <= 0:
                    break
                found.append(int(value))
            if len(found) < size:
                return found
            size *= 4
        return found
    except Exception:  # noqa: BLE001 - no library, no symbol: the caller falls back
        return None


PS_WAIT = 10    # seconds the ps fallback is given: ps is slow on a heavily loaded host, and a tree that is not found is a program left running


def _below(kids, pid):
    found, seen, stack = [], {pid}, [pid]
    while stack:
        for child in kids.get(stack.pop(), []):
            if child not in seen:
                seen.add(child)
                found.append(child)
                stack.append(child)
    return found


def descendants(pid):
    """Every process below `pid` (never one beside it): from /proc where there is one, else from libproc, else from ps
    (given PS_WAIT seconds). libproc is believed when it lists a child; an empty answer is believed only when libproc has
    just listed this tool's own child `pid` (a library that answers nothing for a live child is not working, as in a
    sandbox that denies it), and otherwise ps is asked."""
    kids = {}
    try:
        if os.path.isdir("/proc/self"):
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        kids.setdefault(int(fields[1]), []).append(int(entry))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            first = _children_libproc(pid)
            if first:
                found, seen, stack = list(first), {pid, *first}, list(first)
                while stack:
                    for child in _children_libproc(stack.pop()) or []:
                        if child not in seen:
                            seen.add(child)
                            found.append(child)
                            stack.append(child)
                return found
            if first is not None and pid in (_children_libproc(os.getpid()) or []):
                return []
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=PS_WAIT).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    return _below(kids, pid)


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it. A program already waited for is not touched: its pid is free to
    be another process's, and the walk below it would be that process's children."""
    if proc.poll() is not None:
        return
    victims = descendants(proc.pid)
    try:
        proc.kill()
    except OSError:
        pass
    for pid in victims:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def _on_signal(signum, _frame):
    for proc in list(ACTIVE):
        kill_tree(proc)
    last_word = STATE.get("last_word")
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def preflight(argv, seconds):
    """Run a short program, bounded; (exit code or None, stdout bytes, stderr bytes, timed out)."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, b"", describe(exc).encode("utf-8", "replace"), False
    ACTIVE.append(proc)
    try:
        out, err = proc.communicate(timeout=max(1.0, seconds))
        return proc.returncode, out, err, False
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        out, err = proc.communicate()
        return None, out, err, True
    finally:
        ACTIVE.remove(proc)


def run_to_files(argv, stdout_path, stderr_path, seconds, cwd=None):
    """One program with its output in files, killed with what it started at `seconds`. (exit code, timed out)."""
    with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
        proc = spawn(argv, stdout=stdout, stderr=stderr, cwd=cwd)
        ACTIVE.append(proc)
        try:
            return proc.wait(timeout=max(0.1, seconds)), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            proc.wait()
            return None, True
        finally:
            ACTIVE.remove(proc)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS


class Receipt:
    """coverage.json and index.tsv, rewritten whole (under a temporary name, then moved into place) after every step."""

    def __init__(self, out_dir, target, path):
        self.out_dir = out_dir
        self.data = {"recipe": RECIPE, "target": target.get("name") or path, "status": "partial", "finished": False,
                     "covered": "capture metadata and complete listings of the selected fields of every packet and of the DNS, HTTP and TLS packets "
                                "(and of HTTP/2 and QUIC packets when the installed tshark lists their fields)",
                     "not_covered": "payload content, encrypted payloads, protocols or fields the installed tshark does not decode, and packets absent from the source; "
                                    "a listing with no rows does not show a protocol is absent",
                     "status_basis": "the recipe has not finished", "errors": [], "files": [], "steps": [], "tools": {}, "deadline_seconds": DEADLINE,
                     "secret_bearing": {}, "limits_on_what_the_listings_show": {}}

    def write(self):
        for name, content in (("coverage.json", json.dumps(self.data, indent=2) + "\n"), ("index.tsv", self._index())):
            final = os.path.join(self.out_dir, name)
            tmp = final + ".tmp"
            with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, final)

    def _index(self):
        lines = ["path\tdescription\trows"]
        for item in self.data["files"]:
            lines.append("%s\t%s\t%s" % (item["path"], item["description"], item.get("rows", "")))
        return "\n".join(lines) + "\n"


def count_rows(path):
    with open(path, "rb") as fh:
        return max(0, sum(1 for _ in fh) - 1)


def truncated_packets(path):
    """How many packets were captured shorter than they were on the wire, from packets.tsv's cap_len and len columns;
    (count or None when the columns are absent, rows whose lengths could not be read)."""
    cut = unreadable = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        header = [c.strip('"') for c in fh.readline().rstrip("\n").split("\t")]
        try:
            i, j = header.index("frame.cap_len"), header.index("frame.len")
        except ValueError:
            return None, 0
        for line in fh:
            cells = [c.strip('"') for c in line.rstrip("\n").split("\t")]
            try:
                if int(cells[i]) < int(cells[j]):
                    cut += 1
            except (ValueError, IndexError):
                unreadable += 1
    return cut, unreadable


def describe(exc):
    return "%s: %s" % (type(exc).__name__, getattr(exc, "strerror", None) or exc)


def first_line(argv, seconds=30):
    """The first line a program prints, and why it could not be had; (line or None, reason or None)."""
    code, out, err, timed_out = preflight(argv, seconds)
    if timed_out:
        return None, "did not finish in %d seconds" % seconds
    text = (out or err).decode("utf-8", "replace").strip().splitlines()
    if code != 0:
        return None, "exited %s" % code if code is not None else (err.decode("utf-8", "replace").strip() or "could not be run")
    return (text[0].strip() if text else None), None


def field_names(tshark, wanted, seconds):
    """Which of `wanted` the installed tshark lists as fields (`tshark -G fields`, read as a stream, with select so that
    the deadline needs no second thread); (the names found, why the list could not be read or None)."""
    found = set()
    lowered = {w.lower(): w for w in wanted if w.startswith("_ws.col.")}
    try:
        proc = spawn([tshark, "-G", "fields"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as exc:
        return found, "tshark -G fields could not be run (%s)" % (exc.strerror or exc)
    ACTIVE.append(proc)
    stop_at = time.monotonic() + max(1.0, seconds)
    killed, buffer = False, b""
    try:
        fd = proc.stdout.fileno()
        while True:
            left = stop_at - time.monotonic()
            if left <= 0:
                killed = True
                kill_tree(proc)
                break
            ready, _, _ = select.select([fd], [], [], min(1.0, left))
            if not ready:
                continue
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            buffer += chunk
            *lines, buffer = buffer.split(b"\n")
            for raw in lines:
                cells = raw.decode("utf-8", "replace").split("\t")
                if len(cells) > 2 and cells[0] == "F":
                    # column pseudo-fields are listed in lower case (_ws.col.protocol) and accepted in either
                    name = cells[2]
                    if name in wanted:
                        found.add(name)
                    elif name.startswith("_ws.col.") and name in lowered:
                        found.add(lowered[name])
    finally:
        try:
            proc.stdout.close()
        except OSError:
            pass
        code = proc.wait()
        ACTIVE.remove(proc)
    if killed:
        return found, "tshark -G fields did not finish in time"
    if code != 0:
        return found, "tshark -G fields exited %d" % code
    return found, None


def main():
    if len(sys.argv) < 4 or sys.argv[2] != "--target":
        print(json.dumps({"ok": False, "error": "usage: run.py detect --target T | run --target T --out DIR"}))
        return 2
    mode, target_arg = sys.argv[1], sys.argv[3]
    try:
        target, path = target_of(target_arg)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    applies, why = detect(path)
    if mode == "detect":
        print(json.dumps({"applies": applies, "why": why}))
        return 0 if applies else 1
    if mode != "run" or "--out" not in sys.argv[4:] or sys.argv.index("--out") + 1 >= len(sys.argv):
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    out_dir = sys.argv[sys.argv.index("--out") + 1]
    os.umask(0o077)       # the directory 0700, every file 0600, tshark's and capinfos's own output too
    try:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        os.chmod(out_dir, 0o700)
    except OSError as exc:
        print(json.dumps({"ok": False, "error": "the output directory could not be created (%s)" % describe(exc), "out": out_dir}))
        return 2
    receipt = Receipt(out_dir, target, path)
    data = receipt.data
    if not applies:
        data.update(status="unsupported", status_basis="the file has no pcap or pcapng signature, so nothing was listed", finished=True, why=why)
        receipt.write()
        return 2
    tshark, capinfos = shutil.which("tshark"), shutil.which("capinfos")
    if not tshark or not capinfos:
        data.update(status="failed", status_basis="a program the recipe needs is not on PATH", finished=True,
                    errors=["missing program(s): " + ", ".join(name for name, value in (("tshark", tshark), ("capinfos", capinfos)) if not value)])
        receipt.write()
        return 2
    started = time.monotonic()
    deadline = started + DEADLINE
    data["steps"] = ([{"step": "capinfos", "status": "not_attempted", "reason": "planned"}, {"step": "tshark -G fields", "status": "not_attempted", "reason": "planned"}]
                     + [{"step": name, "status": "not_attempted", "reason": "planned"} for name, *_ in LISTINGS])
    receipt.write()

    def step(name):
        return next(s for s in data["steps"] if s["step"] == name)

    def last_word(signum):
        # the running step is killed first (by the handler of the process block), then the receipt says what was done
        for step_entry in data["steps"]:
            if step_entry["status"] == "running":
                step_entry.update(status="interrupted", reason="the recipe was stopped by signal %d while this step ran; its file is partial" % signum)
        data["errors"].append("the recipe was stopped by signal %d before it finished" % signum)
        data["status_basis"] = "the recipe was stopped by signal %d: the listings written so far are whole files, the one running is partial" % signum
        receipt.write()
        print(json.dumps({"ok": False, "status": "partial", "status_basis": data["status_basis"], "interrupted_by_signal": signum}), flush=True)

    STATE["last_word"] = last_word
    install_signal_handlers()
    for tool_name, binary in (("tshark", tshark), ("capinfos", capinfos)):
        line, why_not = first_line([binary, "--version"], min(30, max(1, deadline - time.monotonic())))
        data["tools"][tool_name] = {"path": binary, "version": line, **({"version_error": why_not} if why_not else {})}
    receipt.write()

    def execute(name, argv, output):
        """One step: its own process group, its output in a file, killed when the shared deadline ends.
        Returns False when the step could not start because the deadline was already used up."""
        entry = step(name)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            entry.update(status="not_attempted", reason="the shared deadline was used up by an earlier step")
            data["errors"].append("%s was not attempted: the shared deadline was used up" % name)
            return False
        stderr = output + ".stderr"
        began = time.monotonic()
        entry.pop("reason", None)
        entry.update(status="running", command=[os.path.basename(argv[0])] + argv[1:])
        receipt.write()
        code, timed_out = run_to_files(argv, output, stderr, remaining)
        if os.path.getsize(stderr) == 0:
            os.remove(stderr)
        else:
            data["files"].append({"path": os.path.basename(stderr), "description": "complete stderr for " + name})
        entry.update(exit_code=code, seconds=round(time.monotonic() - began, 3))
        if timed_out:
            entry.update(status="timed_out", reason="killed with everything it started when the shared deadline ended; its file is partial")
            data["errors"].append("%s timed out at the shared deadline" % name)
        elif code != 0:
            entry["status"] = "failed"
            data["errors"].append("%s (%s) exited %d" % (name, os.path.basename(argv[0]), code))
        else:
            entry["status"] = "ok"
        return True

    execute("capinfos", [capinfos, "-M", "-c", "-a", "-e", "-u", "-s", "-x", path], os.path.join(out_dir, "capture.txt"))
    data["files"].append({"path": "capture.txt", "description": "capinfos capture metadata"})
    receipt.write()

    needed = {f for _, _, fields, _ in LISTINGS for f in fields}
    entry = step("tshark -G fields")
    entry.pop("reason", None)
    entry.update(status="running", command=[os.path.basename(tshark), "-G", "fields"])
    receipt.write()                       # a kill during this step leaves it running, not planned
    available, field_problem = field_names(tshark, needed, min(300.0, max(1.0, deadline - time.monotonic())))
    entry.update(status="ok" if field_problem is None else "failed", fields_checked=sorted(needed), fields_found=sorted(available))
    if field_problem:
        entry["reason"] = field_problem
        data["errors"].append(field_problem)
    receipt.write()

    base = [tshark, "-n", "-r", path, "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a"]
    rows = {}
    for name, display_filter, fields, check in LISTINGS:
        entry = step(name)
        if check:
            missing = [f for f in check if f not in available]
            if field_problem or not any(f in available for f in NEEDS_ONE_OF[name]):
                entry.update(status="skipped", fields_missing=missing,
                             reason=("the installed tshark's fields could not be checked, so %s was not listed" % name) if field_problem else
                             "the installed tshark does not list the fields this needs (%s): no listing was made, which says nothing about whether the capture holds the protocol" % ", ".join(missing))
                receipt.write()
                continue
        if not field_problem:
            # Every field is checked, not only the conditional listings': a field the build lacks is named and left out, never a failed listing.
            missing = [f for f in fields if f not in available]
            fields = [f for f in fields if f not in missing]
            if missing:
                entry["fields_missing"] = missing
                if not fields:
                    entry.update(status="skipped", reason="the installed tshark lists none of the fields this needs: no listing was made")
                    receipt.write()
                    continue
        elif check:
            entry["fields_missing"] = []
        argv = list(base)
        if display_filter:
            argv += ["-Y", display_filter]
        for field in fields:
            argv += ["-e", field]
        output = os.path.join(out_dir, name)
        entry["fields"] = fields
        if name in SECRET_BEARING:
            entry["secret_bearing"] = True
            data["secret_bearing"][name] = SECRET_BEARING[name]
        if not execute(name, argv, output):
            try:
                os.remove(output)
            except OSError:
                pass
            receipt.write()
            continue
        complete = entry["status"] == "ok"
        listed = {"path": name, "description": "complete %s listing of the selected fields%s" % (name[:-4], "" if complete else " (PARTIAL: the step did not finish)")}
        listed["rows"] = rows[name] = entry["rows"] = count_rows(output)
        data["files"].append(listed)
        if name == "packets.tsv" and complete:
            cut, unreadable = truncated_packets(output)
            data["limits_on_what_the_listings_show"] = {
                "packets": rows[name], "truncated_packets": cut, "packets_whose_lengths_could_not_be_read": unreadable,
                "meaning": "a truncated packet was captured shorter than it was on the wire: the fields past the captured bytes are not in any listing"}
        receipt.write()
    data["limits_on_what_the_listings_show"]["rows_by_listing"] = rows
    unfinished = [s["step"] for s in data["steps"] if s["status"] in ("not_attempted", "running", "failed", "timed_out")]
    # A listing made without a field the installed tshark lacks is a listing with a column fewer than asked for: that is not a complete answer.
    narrowed = {s["step"]: s["fields_missing"] for s in data["steps"] if s.get("fields_missing") and s["status"] == "ok"}
    data.update(status="complete" if not data["errors"] and not unfinished and not narrowed else "partial", finished=True, elapsed_seconds=round(time.monotonic() - started, 3))
    reasons = []
    if data["errors"] or unfinished:
        reasons.append("%d error(s) and %d step(s) that did not finish (coverage.json names each)" % (len(data["errors"]), len(unfinished)))
    if narrowed:
        reasons.append("%d listing(s) were made without a field the installed tshark does not list (%s): a column of each is missing"
                       % (len(narrowed), "; ".join("%s: %s" % (name, ", ".join(fields)) for name, fields in sorted(narrowed.items()))))
    data["status_basis"] = "every step ran and exited 0 and every listing was written" if not reasons else "; ".join(reasons)
    if narrowed:
        data["listings_without_fields"] = narrowed
    receipt.write()
    print(json.dumps({"ok": not data["errors"], "status": data["status"], "status_basis": data["status_basis"]}))
    return 0 if not data["errors"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
