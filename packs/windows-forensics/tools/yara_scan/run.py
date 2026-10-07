#!/usr/bin/env python3
"""Sweep a file or directory with a YARA rule file and report where every rule matched.

No rules ship with this. A curated rule set is a maintenance commitment that
does not belong in a tool library, and a stale rule reads like a finding. The
caller names the rules it trusts; this runs them and reports what matched,
where, and at what offset. A rule match is not a verdict on the file: it says
the rule's condition held, and a rule written for one family matches other
things.

Extracted material is the usual target, and the quarantine guard means the
files there cannot execute, which is why scanning them is safe and running
them is not. Links inside a scanned directory are not followed (-N, when the
installed yara has it).

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"). `yara -s`
prints the bytes a string matched, so a rule that finds `password=` or a key header puts the
secret in the output. The answer here carries the rule, the file, the string identifier, the
offset and the length of every string match, and never the matched bytes. The bytes are
written only when the caller asks (`write_matches: true`), only when this runs as a job
(JOB_ID and OUT set; the skill says the job runs with `secret_output: true`), and only to a
file under $OUT (JSON Lines, mode 0600, one row per string match carrying the same
`finding_id`); outside a job the request is refused and nothing is written. The matched bytes
are not written to disk otherwise: yara's output is read as a stream and its text discarded.

Nothing is held whole in memory: yara's output is parsed line by line as it arrives. A run
that is stopped by its time limit says complete: false and keeps what was read.
"""
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output (in a job, $OUT/tool-output)
# and named.

class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _cannot_write(self, exc: BaseException) -> None:
        """The whole result cannot be kept: say so as JSON and stop, never a traceback."""
        import sys as _sys
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        text = json.dumps(row, ensure_ascii=False, default=str)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name that is not UTF-8): escape it, lose nothing.
            text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                os.replace(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


class SecretValuesRefused(Exception):
    pass


def describe(exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    return "%s: %s" % (type(exc).__name__, exc)


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The secret-safe output pattern of docs/packs.md ("Secrets and sensitive output"),
    copied from its reference implementation (recovery_key_scan, encrypted-containers)
    and parameterised by the tool, the flag and the file's name. Call `add` once per
    finding with the finding's id, its locator and the value. With `enabled` false it
    writes nothing and `summary()` says so.
    """

    def __init__(self, enabled, tool, flag, name):
        self.enabled = enabled
        self.tool = tool
        self.flag = flag
        self.name = name
        self.written = 0
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "%s is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=%s with "
                "secret_output: true, and ask again there. Nothing was written." % (flag, tool)
            )
        self.path = Path(self.out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), name)
        # Created now, before anything is scanned: a file or a link already at that name is
        # refused by name at once (O_EXCL does not follow a link, a dangling one included),
        # instead of failing, or writing through it, after the scan. With nothing found it
        # stays as an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=False))
        self._fh.write("\n")
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self, format_note):
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": format_note if self.enabled else None,
        }


PARSER = "yara_scan/4"


# BEGIN SHARED PROCESS
# The same text is in esedb_query, extract_stream, sigma_hunt, vss_stores and yara_scan; tests/pack-windows-forensics-process.test.ts
# holds the copies equal. A program a tool runs is started in THIS tool's process group, never in a session of its own: the
# harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid, SIGKILL)), and a
# program in a group of its own goes on writing after the tool is gone. On Linux the kernel is also asked to kill it if the
# tool dies. The tool's own deadline kills the program and what it started by walking the process tree, and SIGTERM, SIGINT
# and SIGHUP do the same and then give the tool a last word.
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


def wait_for(proc, seconds):
    """(exit code, timed out): wait for the program for at most `seconds`; at the deadline it and what it started are killed."""
    ACTIVE.append(proc)
    try:
        try:
            return proc.wait(timeout=seconds), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            return proc.wait(), True
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)


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


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS
# `0x6:20:$a: data` with -s -L; `0x6:$a: data` with -s alone (an older yara has no -L).
SCAN_ERROR = re.compile(r"^error scanning (.+)$")
STRING_LINE = re.compile(r"^0x([0-9a-fA-F]+):(?:(\d+):)?(\$[A-Za-z0-9_]*): ?")


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tool_output_dir():
    out, job = os.environ.get("OUT"), os.environ.get("JOB_ID")
    if job and out:
        return Path(out) / "tool-output", "store/jobs/%s/out/tool-output" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
    d = Path("work") / re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool") / "tool-output"
    return d, str(d)


def main():
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    rules = args.get("rules")
    target = args.get("target")
    if not isinstance(rules, str) or not rules:
        fail("rules is required: a path to a .yar or .yara file")
    if not os.path.isfile(rules):
        fail("no such rules file", rules=rules)
    if not isinstance(target, str) or not target:
        fail("target is required: a file or directory to scan")
    if not os.path.exists(target):
        fail("no such target", target=target)

    timeout = args.get("timeout_seconds", 60)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
        fail("timeout_seconds must be a positive integer")
    timeout = min(timeout, 110)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))
    write_matches = args.get("write_matches", False)
    if not isinstance(write_matches, bool):
        fail("write_matches must be true or false")

    if shutil.which("yara") is None:
        fail("yara is not on PATH", hint="brew install yara; scripts/toolbox.sh reports it with the dfir set")

    values = None
    for number in range(1, 1000):
        name = "yara-matched-strings.jsonl" if number == 1 else "yara-matched-strings-%d.jsonl" % number
        try:
            values = SecretValues(write_matches, "yara_scan", "write_matches", name)
            break
        except SecretValuesRefused as exc:
            # A values file of an earlier run in this job is never replaced and never a reason not to scan: the
            # next free number is this run's file, and the answer names it.
            if write_matches and "already exists" in str(exc):
                continue
            fail(str(exc))
    if values is None:
        fail("no free name for the values file after 999 tries")

    # A target that is not a regular file or a directory (a FIFO, a socket, a device) is not opened: yara would wait
    # on it until the time limit. In a directory yara skips such entries itself; they are looked for here and said.
    if not (os.path.isdir(target) or os.path.isfile(target)):
        values.close()
        fail("target is not a regular file or a directory (a FIFO, a socket or a device is not scanned)", target=target, not_attempted=1)

    try:
        version = subprocess.run(["yara", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10).stdout.decode("utf-8", "replace").strip()
        help_text = subprocess.run(["yara", "--help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        values.close()
        fail("yara could not be run", reason=str(exc))

    # -s prints the matching strings (read here, never returned), -L their lengths, -r recurses,
    # -N does not follow links out of the scanned tree. A flag the installed yara lacks is left out.
    argv = ["yara", "-s"]
    if "--print-string-length" in help_text:
        argv.append("-L")
    if os.path.isdir(target):
        argv.append("-r")
        if "--no-follow-symlinks" in help_text:
            argv.append("-N")
    argv += [rules, target]

    # What yara will not scan, said before it runs: special files in a directory (it skips them without a word) and,
    # when it does not follow links (-N), the links it passes over.
    not_attempted = LosslessPage("yara_scan", [rules, target, "not_attempted"], limit)
    skipped_links = "-N" in argv
    if os.path.isdir(target):
        for root, dirs, names in os.walk(target, followlinks=False):
            for entry in sorted(dirs + names):
                full = os.path.join(root, entry)
                try:
                    mode = os.lstat(full).st_mode
                except OSError as exc:
                    not_attempted.add({"file": full, "reason": "could not be examined: %s" % describe(exc)})
                    continue
                if stat.S_ISLNK(mode):
                    if skipped_links:
                        not_attempted.add({"file": full, "reason": "a symbolic link, not followed (yara -N)"})
                elif not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    kind = "a FIFO" if stat.S_ISFIFO(mode) else "a socket" if stat.S_ISSOCK(mode) else "a device" if (stat.S_ISCHR(mode) or stat.S_ISBLK(mode)) else "a special file"
                    not_attempted.add({"file": full, "reason": "%s: yara does not scan it" % kind})

    outdir, outshown = tool_output_dir()
    key = [rules, target, timeout, argv]
    digest = hashlib.sha256(json.dumps(key, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    rule_rows = LosslessPage("yara_scan", [rules, target, "rules"], limit)
    string_rows = LosslessPage("yara_scan", [rules, target, "strings"], limit)

    errfd, errname = tempfile.mkstemp(prefix=".yara-stderr-", dir=_ensure(outdir))
    timed_out = [False]
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=errfd)
    except OSError as exc:
        os.close(errfd)
        values.close()
        fail("yara could not be started", reason=str(exc))
    os.close(errfd)
    ACTIVE.append(proc)

    def interrupted(signum):
        try:
            values.close()
        except OSError:
            pass
        print(json.dumps({"error": "stopped by signal %d before yara finished" % signum, "status": "interrupted", "signal": signum,
                          "note": "No statement about matches follows from an interrupted run; what was written to the values file, if one was asked for, is partial."}), flush=True)

    STATE["last_word"] = interrupted

    def stop():
        timed_out[0] = True
        kill_tree(proc)

    timer = threading.Timer(timeout, stop)
    timer.start()
    current = None            # [rule, file, string count]
    files_with_matches = set()
    string_total = 0
    unparsed = 0          # string lines seen before any rule line: counted, never shown (a line holds matched bytes)
    try:
        for raw in proc.stdout:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not line.strip():
                continue
            m = STRING_LINE.match(line)
            if m:
                if current is None:
                    unparsed += 1
                    continue
                string_total += 1
                finding = "S%06d" % string_total
                offset = int(m.group(1), 16)
                length = int(m.group(2)) if m.group(2) is not None else None
                row = {"finding_id": finding, "rule": current[0], "file": current[1], "identifier": m.group(3),
                       "offset": offset, "offset_hex": "0x%x" % offset, "length": length}
                string_rows.add(row)
                current[2] += 1
                # The matched bytes are the rest of the line. They go nowhere unless the caller asked, in a job.
                values.add(finding, {"rule": current[0], "file": current[1], "identifier": m.group(3), "offset": offset, "length": length},
                           line[m.end():])
                continue
            if current is not None:
                rule_rows.add({"rule": current[0], "file": current[1], "string_matches": current[2]})
            rule, _, path = line.partition(" ")
            current = [rule.strip(), path.strip(), 0]
            files_with_matches.add(current[1])
        if current is not None:
            rule_rows.add({"rule": current[0], "file": current[1], "string_matches": current[2]})
    finally:
        timer.cancel()
        rc = proc.wait()
        if proc in ACTIVE:
            ACTIVE.remove(proc)
        values.close()

    stderr_bytes = Path(errname).read_bytes()
    stderr_file = None
    stderr_lines = [l for l in stderr_bytes.decode("utf-8", "replace").splitlines() if l.strip()]
    if stderr_lines:
        # Never over an earlier run's file: the next free number names this one.
        for number in range(1, 1000):
            final = outdir / ("yara_scan-%s.stderr.txt" % digest if number == 1 else "yara_scan-%s.stderr.%d.txt" % (digest, number))
            try:
                os.link(errname, final)
                os.unlink(errname)
                break
            except FileExistsError:
                continue
            except OSError:
                if not os.path.lexists(final):
                    os.rename(errname, final)
                    break
        else:
            fail("no free name for the standard error file after 999 tries")
        stderr_file = "%s/%s" % (outshown, final.name)
    else:
        os.unlink(errname)

    # `error scanning <file>: <reason>` is yara's own word that it could not scan a file; it exits 0 all the same.
    scan_errors = LosslessPage("yara_scan", [rules, target, "scan_errors"], limit)
    for line in stderr_lines:
        m = SCAN_ERROR.match(line)
        if m:
            path, _, reason = m.group(1).rpartition(": ")
            scan_errors.add({"file": path if path else m.group(1), "reason": reason if path else None, "line": line})

    rule_page, string_page = rule_rows.finish(), string_rows.finish()
    error_page, skipped_page = scan_errors.finish(), not_attempted.finish()
    complete = rc == 0 and not timed_out[0] and error_page["matched"] == 0 and skipped_page["matched"] == 0
    errors = [l for l in stderr_lines if "error" in l.lower()]
    if complete:
        status = "complete"
    elif (rc == 0 and not timed_out[0]) or timed_out[0] or rule_page["matched"] or string_page["matched"]:
        status = "partial"
    else:
        status = "failed"
    answer = {
        "parser": PARSER,
        "status": status,
        "complete": complete,
        "yara_version": version,
        "yara_argv": argv,
        "yara_exit_status": rc,
        "timed_out": timed_out[0],
        "timeout_seconds": timeout,
        "rules": rules,
        "rules_sha256": sha256_of(rules),
        "target": target,
        "matches": rule_rows.page,
        "match_count": rule_page["matched"],
        "matches_page": rule_page,
        "string_matches": string_rows.page,
        "string_match_count": string_page["matched"],
        "string_matches_page": string_page,
        "files_with_matches": len(files_with_matches),
        "unparsed_string_lines": unparsed,
        "scan_errors": scan_errors.page,
        "scan_error_count": error_page["matched"],
        "scan_errors_page": error_page,
        "not_attempted": not_attempted.page,
        "not_attempted_count": skipped_page["matched"],
        "not_attempted_page": skipped_page,
        "stderr_file": stderr_file,
        "stderr_line_count": len(stderr_lines),
        "warnings": stderr_lines[:20],
        "first_errors": errors[:5],
        "matched_bytes": "not in this answer; write_matches: true, in a job run with secret_output: true, writes them to a file under $OUT",
        "secret_values": values.summary("JSON Lines, mode 0600: finding_id, rule, file, identifier, offset, length, value (as yara prints it)"),
        "note": "A rule match says the rule's condition held, not that the file is malicious. Rules that `include` other files are not hashed beyond the file named. "
                + ("" if complete else "The run did not complete: what is listed is what was read before it stopped."),
    }
    print(json.dumps(answer, indent=2))
    if status == "failed":
        raise SystemExit(1)


def _ensure(path):
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


if __name__ == "__main__":
    try:
        main()
    except OSError as exc:
        fail("a file operation failed: %s" % describe(exc), reason=type(exc).__name__)
