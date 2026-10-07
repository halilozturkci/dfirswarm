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
step, then "complete" (every step ran and exited 0), "partial" (a step failed, timed out or was not attempted) or
"failed". "complete" is an execution result. It does not say what the capture holds. Every step records its
status, exit code, seconds and rows; the versions of tshark and capinfos are recorded; one deadline
(NETWORK_CAPTURE_SECONDS, default 3300, under the recipe's 3600) covers every step, a step that uses it up is killed
with everything it started and the steps after it are not_attempted.

http2.tsv and quic.tsv are listed only after `tshark -G fields` shows that the installed build has the fields; the
ones it does not have are named in the step (fields_missing) and left out. Nothing is assumed about what a version
supports.

SENSITIVE: http.tsv holds request URIs, hosts and user agents, which can carry credentials and tokens. The receipt
marks it (secret_bearing); run the recipe's job as a sensitive output when the capture can hold any.
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
SECRET_BEARING = {"http.tsv": "request URIs, hosts and user agents can carry credentials, tokens and session identifiers"}
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
# The same text is in pcap_extract, zeek_run, suricata_run and the network-capture recipe; tests/pack-network-process.test.ts
# holds the copies equal. A program an engine tool runs is started in THIS tool's process group, never in a session of
# its own: the harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid,
# SIGKILL)), and an engine in a group of its own goes on writing into the output directory after the tool is gone. On
# Linux the kernel is also asked to kill it if the tool dies. A deadline kills the program and what it started by
# walking the process tree, and SIGTERM, SIGINT and SIGHUP do the same and then give the tool a last word.
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


def descendants(pid):
    """Every process below `pid`, from /proc where there is one, else from ps."""
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
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    found, stack = [], [pid]
    while stack:
        for child in kids.get(stack.pop(), []):
            found.append(child)
            stack.append(child)
    return found


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it."""
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
                     "errors": [], "files": [], "steps": [], "tools": {}, "deadline_seconds": DEADLINE,
                     "secret_bearing": {}, "limits_on_what_the_listings_show": {}}

    def write(self):
        for name, content in (("coverage.json", json.dumps(self.data, indent=2) + "\n"), ("index.tsv", self._index())):
            final = os.path.join(self.out_dir, name)
            tmp = final + ".tmp"
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
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
                if len(cells) > 2 and cells[0] == "F" and cells[2] in wanted:
                    found.add(cells[2])
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
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as exc:
        print(json.dumps({"ok": False, "error": "the output directory could not be created (%s)" % describe(exc), "out": out_dir}))
        return 2
    receipt = Receipt(out_dir, target, path)
    data = receipt.data
    if not applies:
        data.update(status="unsupported", finished=True, why=why)
        receipt.write()
        return 2
    tshark, capinfos = shutil.which("tshark"), shutil.which("capinfos")
    if not tshark or not capinfos:
        data.update(status="failed", finished=True,
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
        receipt.write()

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

    needed = {f for _, _, _, check in LISTINGS for f in check}
    available, field_problem = field_names(tshark, needed, min(300.0, max(1.0, deadline - time.monotonic())))
    entry = step("tshark -G fields")
    entry.pop("reason", None)
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
            fields = [f for f in fields if f not in missing]
            entry["fields_missing"] = missing
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
    data.update(status="complete" if not data["errors"] and not unfinished else "partial", finished=True, elapsed_seconds=round(time.monotonic() - started, 3))
    receipt.write()
    print(json.dumps({"ok": not data["errors"], "status": data["status"]}))
    return 0 if not data["errors"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
