#!/usr/bin/env python3
"""Diff inputs/ against inputs.json. Always-OK hashing is a false negative.

The manifest is validated whole before any file is hashed: every entry must be an object with a
path (its `path_b64` when the name is not UTF-8), no path may appear twice, a regular file needs
its size (`bytes`) and a sha256, a link its target (`link`), a device, pipe or socket its kind
(`special`). An entry that fails is reported as malformed, never skipped, and an entry with no
sha256 is `digest_missing`: it could be checked by size alone, which is not a verification, so the
run does not pass. A file that cannot be opened is `unreadable`, a file not reached before the
time budget is `not_checked`; neither is a pass. Every file's result is written to a receipts
file as it is checked, so a long hash leaves a record even if the run is cut short.

The answer lists at most LISTED paths of each kind (with the count of all of them); the receipts
file holds a row for every one, the files added under inputs/ and the manifest's malformed and
duplicate entries included. The walk over inputs/ for added files reads the clock for every entry
and, when its time runs out (the budget is for the manifest and the hashing, which run to max_seconds; the walk then has
a fifth of it more, at least 1 and at most 60 seconds, so the whole run can take max_seconds plus that), says where it
stopped as a `not_checked` entry.

`status` is complete when every file was checked and the walk finished, whatever they showed;
partial when a file is `not_checked`, `unreadable`, `malformed` or `digest_missing` (not
verified); failed when the tool refused (no manifest, a bad parameter) and checked nothing. `ok` is
the agreement verdict and `status_basis` says which.

A pass says: every file the manifest lists is here and has the bytes and digest it lists, and
nothing else is under inputs/. It does not say the evidence is authentic, or complete, or that the
baseline (the manifest) was right when it was made. This is the pack tool's receipt; the harness's
own `inputs_check` event is written by the harness at completion, not by this tool.

Exit 0 only when every check passed.
"""
import base64
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
from pathlib import Path


# BEGIN SHARED STOP
# The same text is in every tool that carries this block (tests/pack-shared-stop.test.ts holds the copies equal). SIGTERM, SIGINT and SIGHUP end the tool with JSON
# (status failed with interrupted true: a stop is not a status, the statuses are complete, partial and failed; exit 128 + the signal) and remove the temporary file a page was writing; the tool's own clock (set_deadline) is below the manifest's.
# The handlers are in as soon as the module has run as far as this block, with a minimal last word until main() installs the tool's own (only
# the start of the interpreter and the compiling of the file come before it). The first signal counts: a second one does nothing while the
# first is answered. print_answer holds the stop signals back while the answer is printed, so exactly one complete document is written
# (the ransomware tools print through it; the windows tools hold the signals in the emit of their boundary block, and carry this text unused).
import signal
import time

STOP = {"last_word": None, "deadline": None}


def set_deadline(seconds):
    STOP["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)
    for page in list(globals().get("PAGES", ())):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    last_word = STOP["last_word"]
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def install_signal_handlers(last_word=None):
    STOP["last_word"] = last_word
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def interrupted_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "failed", "interrupted": True,
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back: a signal that came in the middle of the write would end the process there, with the
    answer cut. The tool ends by itself right after, so a signal that is held is not lost for good."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    STOP["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


install_signal_handlers(lambda signum: interrupted_answer(signum))
# END SHARED STOP

import os as _os
import sys as _sys
import threading as _threading

# ---- the one protected printer of an answer (outside the shared block) ------------------------------------------------------------
# The stop signals are held while the answer is written, so that a signal cannot cut the document. A reader that stops taking it (a full
# pipe) would make that tool unkillable by SIGTERM: the held write is therefore bounded. If a stop signal is waiting when
# HELD_WRITE_SECONDS have passed, the tool says so on stderr and ends with 128 plus that signal; nothing is claimed about the answer.
HELD_WRITE_SECONDS = int(_os.environ.get("TOOL_HELD_WRITE_SECONDS") or 30)       # the environment variable is for the tests
_STOPS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def _unstick():
    try:
        waiting = signal.sigpending()
    except (AttributeError, OSError):
        waiting = set()
    held = [s for s in _STOPS if s in waiting]
    if held:
        try:
            _os.write(2, ("the answer could not be written in %d seconds (the reader is not taking it); ended by the stop signal that was held\n" % HELD_WRITE_SECONDS).encode())
        except OSError:
            pass
        _os._exit(128 + int(held[0]))
    again = _threading.Timer(1.0, _unstick)
    again.daemon = True
    again.start()


ERROR_FLAGS = ("all_results_error", "all_matches_error", "receipt_error", "receipts_error", "rows_file_error", "rows_error", "invalid_lines_file_error",
               "write_error", "values_error")


def _flagged(node, depth=0):
    """The first error flag found in an answer (top level, and two levels of dicts below it), or None."""
    if not isinstance(node, dict) or depth > 2:
        return None
    for key in ERROR_FLAGS:
        if node.get(key):
            return key
    for value in node.values():
        found = _flagged(value, depth + 1)
        if found:
            return found
    return None


def _reconcile(answer):
    """status, complete and ok are one fact: an error flag in the answer (a file that should hold the rest could not be written) is not a
    complete answer, and a complete or ok that survives a partial or failed status is a wrong claim. Said once, here, for every answer."""
    if not isinstance(answer, dict):
        return
    flag = _flagged(answer)
    if flag and answer.get("status") == "complete":
        answer["status"] = "partial"
        basis = answer.get("status_basis")
        answer["status_basis"] = ("%s; but %s says part of what was asked for could not be kept" % (basis, flag)) if basis else "%s says part of what was asked for could not be kept" % flag
    if answer.get("status") in ("partial", "failed") or flag:
        if answer.get("complete") is True:
            answer["complete"] = False
    if answer.get("status") == "failed" and answer.get("ok") is True:
        answer["ok"] = False


# BEGIN SHARED TEMPS
# One lifecycle for the hidden temporary files of a run. A file is made by temp_create (or its name is registered with temp_hold before it is
# made), it is registered before anything else is done with it, and it stays registered until temp_done says it was renamed into place. What is
# still registered when the run ends is removed: by atexit on a normal end or any exception, by drop_temporaries in the last-resort handler, and
# by the stop signal's own cleanup, which removes the _tmp of every object in PAGES (a registered name is one such object).
import atexit
import tempfile

if "PAGES" not in globals():
    PAGES = []                 # objects with a hidden temporary file (_tmp) that a stop removes


class _HeldTemp:
    def __init__(self, name):
        self._tmp = name


def temp_hold(name):
    """Register a temporary file that is about to be made (or has been): it is removed on every way out unless temp_done is called."""
    held = _HeldTemp(os.fspath(name))
    PAGES.append(held)
    return held._tmp


def temp_create(directory, prefix, suffix=""):
    """tempfile.mkstemp with the new name registered at once: (fd, name)."""
    fd, name = tempfile.mkstemp(dir=os.fspath(directory), prefix=prefix, suffix=suffix)
    temp_hold(name)
    return fd, name


def temp_done(name):
    """The file was renamed into place (or is kept on purpose): it is no longer a temporary."""
    name = os.fspath(name)
    PAGES[:] = [p for p in PAGES if not (isinstance(p, _HeldTemp) and p._tmp == name)]


def temp_drop(name):
    """Remove one temporary now; False when it could not be removed (it stays registered, and the end of the run tries again)."""
    try:
        os.unlink(name)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    temp_done(name)
    return True


def temp_replace(tmp, dest):
    os.replace(tmp, dest)
    temp_done(tmp)


def drop_temporaries():
    """Remove every temporary still registered (the pages being written and the held names); the names that could not be removed come back."""
    left = []
    for page in list(PAGES):
        tmp = None
        try:
            tmp = getattr(page, "_tmp", None)
            if tmp is not None:
                os.unlink(tmp)
        except FileNotFoundError:
            pass
        except Exception:   # noqa: BLE001 - every one is tried
            left.append(str(tmp))
    return left


atexit.register(drop_temporaries)
# END SHARED TEMPS


def _guarded_write(write):
    try:
        before = signal.pthread_sigmask(signal.SIG_BLOCK, set(_STOPS))      # before the timer thread exists, so that the thread holds them too
    except (AttributeError, ValueError, OSError):
        before = None
    watch = _threading.Timer(HELD_WRITE_SECONDS, _unstick)
    watch.daemon = True
    watch.start()
    try:
        write()
        _sys.stdout.flush()
    except BrokenPipeError:                       # the reader is gone: there is nobody to tell
        _os._exit(1)
    watch.cancel()
    if before is not None:
        # The document is whole. A stop that came while it was written is delivered now; the last word was cleared, so it ends the tool
        # (128 plus the signal) with nothing more on stdout. The mask is also what an in-process caller (a test) had before.
        signal.pthread_sigmask(signal.SIG_SETMASK, before)


_shared_print_answer = print_answer


def print_answer(answer, **dumps_kwargs):
    _reconcile(answer)
    _guarded_write(lambda: _shared_print_answer(answer, **dumps_kwargs))

TOOL = {"name": "check_inputs", "version": 12}
MANIFEST = "inputs.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SPECIALS = {"fifo": stat.S_ISFIFO, "socket": stat.S_ISSOCK, "char": stat.S_ISCHR, "block": stat.S_ISBLK}
DEFAULT_SECONDS = 1500
SECONDS_MAX = 1700                     # the tool's own time limit is 1800 seconds: a budget beyond it would be killed, not reported
LISTED = 200
STARTED = time.monotonic()
NONBLOCK = getattr(os, "O_NONBLOCK", 0)
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def done(obj, code):
    print_answer(obj)
    sys.exit(code)


def refuse(obj):
    """A refusal: nothing was checked."""
    obj.setdefault("ok", False)
    obj["status"] = "failed"
    obj["status_basis"] = "the tool stopped with an error and checked nothing (see error)"
    done(obj, 1)


def unexpected(kind, value, _tb):
    """An error nobody expected is an answer too: its class only, since its message can quote a name from the evidence."""
    print(json.dumps({"tool": TOOL, "status": "failed", "ok": False, "error": "internal error: %s" % kind.__name__,
                      "status_basis": "the tool stopped with an error and checked nothing (see error)"}))
    sys.stdout.flush()
    os._exit(1)


sys.excepthook = unexpected


class Capped:
    """A list that keeps the first LISTED items and counts all of them: what the answer shows, and how many there were."""

    def __init__(self):
        self.items, self.total = [], 0

    def append(self, item):
        self.total += 1
        if len(self.items) < LISTED:
            self.items.append(item)

    def __len__(self):
        return self.total

    def __bool__(self):
        return self.total > 0


def name_of(entry, key):
    """A name as bytes on disk: key_b64 when the manifest kept the raw bytes, else the text."""
    raw_b64 = entry.get(key + "_b64")
    if raw_b64 is not None:
        try:
            return os.fsdecode(base64.b64decode(raw_b64, validate=True))
        except (ValueError, TypeError):
            return None
    value = entry.get(key)
    return value if isinstance(value, str) else None


def sha256_file(path, deadline):
    # In chunks: an input can be tens of gigabytes, and reading one whole is
    # both a MemoryError in a small VM and against the ground rules. Opened without blocking and checked to be a regular file
    # on the descriptor, so a pipe put where the file was cannot hold the run.
    digest = hashlib.sha256()
    size = 0
    fd = os.open(path, os.O_RDONLY | NONBLOCK | NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise OSError(0, "not a regular file any more")
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
            if time.monotonic() > deadline:
                return None, size
    return digest.hexdigest(), size


class Receipts:
    """One new file per run, written row by row in place: a run that is killed leaves the rows it had.

    The name carries the time and the process, so a second check in the same run directory does not
    replace the first one's record; the file is created exclusively and never opened over.
    """

    def __init__(self):
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        name = "check_inputs-receipts-%s-%d.jsonl" % (stamp, os.getpid())
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self.fh, self.error, self.count, self.created = None, None, 0, False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            self.fh = os.fdopen(fd, "w", encoding="ascii")
            self.created = True
        except OSError as exc:
            self.error = "the receipts could not be written (%s: %s)" % (self.path.parent, exc.strerror or exc)

    def add(self, row):
        if self.fh:
            try:
                self.fh.write(json.dumps(row) + "\n")       # ASCII escapes: a name that is not UTF-8 is written, not lost
                self.fh.flush()                                # a receipt is on disk before the next file is read
                self.count += 1
            except OSError as exc:
                self.error = "the receipts stopped being written after %d rows (%s)" % (self.count, exc.strerror or exc)
                self.fh = None

    def finish(self):
        if self.fh:
            try:
                self.fh.flush()
                os.fsync(self.fh.fileno())
                self.fh.close()
            except OSError as exc:
                self.error = "the receipts were not synced (%s)" % (exc.strerror or exc)


# A job sees the run's directories, not the run's inputs.json: the job service gives a job that sees all of inputs/ a copy
# of it, named by SWARM_INPUTS_MANIFEST. A job with a narrower scope gets none (it sees part of the evidence, and the
# comparison would call the rest missing).
IN_JOB = bool(os.environ.get("JOB_ID"))
if IN_JOB and os.environ.get("SWARM_INPUTS_MANIFEST"):
    MANIFEST = os.environ["SWARM_INPUTS_MANIFEST"]
if not os.path.isfile(MANIFEST):
    refuse({"ok": False, "tool": TOOL,
            "error": "inputs.json not found" + (": a job is given a copy of it only when it sees all of inputs/ (inputs left out, or "
                                                "[\"all\"]) and the manifest is within the job service's size limit; otherwise run "
                                                "check_inputs in your own VM" if IN_JOB else "")})
try:
    args = json.load(sys.stdin) if not sys.stdin.isatty() else {}
except (ValueError, RecursionError):
    args = {}
budget = args.get("max_seconds", DEFAULT_SECONDS) if isinstance(args, dict) else DEFAULT_SECONDS
if not isinstance(budget, int) or isinstance(budget, bool) or not 1 <= budget <= SECONDS_MAX:
    refuse({"ok": False, "error": "max_seconds is a whole number from 1 to %d" % SECONDS_MAX, "tool": TOOL})
try:
    with open(MANIFEST, encoding="utf-8") as fh:
        man = json.load(fh)
except (ValueError, RecursionError) as err:      # JSONDecodeError and UnicodeDecodeError are ValueErrors; a JSON nested thousands deep is a RecursionError
    refuse({"ok": False, "error": f"inputs.json is not JSON this tool can read: {type(err).__name__}: {str(err)[:200]}", "tool": TOOL})
files = man.get("files") if isinstance(man, dict) else None
if not isinstance(files, list):
    refuse({"ok": False, "error": "inputs.json has no files list", "tool": TOOL})

# The whole run is on one clock that starts with the tool. The budget is for reading the manifest and hashing; the walk over
# inputs/ for added files gets the time after it, a fifth of the budget at most 60 seconds, so the run ends at most
# SECONDS_MAX + 60 seconds after it began, inside the tool's own 1800.
hash_deadline = STARTED + budget
deadline = hash_deadline + max(1, min(60, budget // 5))


def _stopped(signum):
    mine = globals().get("receipts")
    print(json.dumps({"tool": TOOL, "ok": False, "status": "partial", "interrupted": True, "signal": signum,
                      "receipts_file": mine.shown if mine is not None and mine.created else None, "receipts": mine.count if mine is not None else 0,
                      "status_basis": "the tool was stopped by signal %d: the files checked so far have a row in the receipts file, the rest were not checked, and nothing here is a pass" % signum}), flush=True)


install_signal_handlers(_stopped)
receipts = Receipts()

# --- the whole manifest first -------------------------------------------------------------------
malformed, duplicates, digest_missing = Capped(), Capped(), Capped()
entries, known = [], {}
for i, entry in enumerate(files):
    if not isinstance(entry, dict):
        malformed.append({"index": i, "why": "not an object"})
        receipts.add({"manifest_entry": i, "result": "malformed: not an object"})
        continue
    rel = name_of(entry, "path")
    if rel is None:
        malformed.append({"index": i, "why": "no readable path (path, or a path_b64 that is not base64)"})
        receipts.add({"manifest_entry": i, "result": "malformed: no readable path"})
        continue
    # Where the entry really points: `inputs/../x`, `inputs//a/./b` and `/etc/passwd` are named by their normal form, and a
    # place that is not under inputs/ is not the evidence's: it is not hashed, and it is reported as malformed.
    orig = rel
    rel = os.path.normpath(rel) if rel else rel
    if not rel or os.path.isabs(rel) or rel == "inputs" or not rel.startswith("inputs" + os.sep) or ".." in rel.split(os.sep):
        malformed.append({"index": i, "path": orig, "why": "the path is outside inputs/ (as written, or once ../ and ./ are resolved: %s)" % rel})
        receipts.add({"manifest_entry": i, "path": orig, "result": "malformed: the path is outside inputs/"})
        continue
    if rel in known:
        duplicates.append(rel)
        receipts.add({"manifest_entry": i, "path": rel, "result": "duplicate: the path is listed more than once"})
        continue
    kind = "link" if "link" in entry or "link_b64" in entry else "special" if "special" in entry else "file"
    why = None
    nodigest = False
    if kind == "link":
        if name_of(entry, "link") is None:
            why = "a link with no readable target"
    elif kind == "special":
        if entry.get("special") not in SPECIALS:
            why = "special is not one of %s" % ", ".join(sorted(SPECIALS))
    else:
        if not isinstance(entry.get("bytes"), int) or isinstance(entry.get("bytes"), bool) or entry["bytes"] < 0:
            why = "a regular file with no valid size (bytes)"
        elif entry.get("sha256") in (None, ""):
            digest_missing.append(rel)
            nodigest = True
        elif not isinstance(entry.get("sha256"), str) or not SHA256.match(entry["sha256"]):
            why = "sha256 is not 64 hexadecimal digits"
    if why:
        malformed.append({"index": i, "path": rel, "why": why})
        receipts.add({"manifest_entry": i, "path": rel, "result": "malformed: " + why})
        known[rel] = entry
        continue
    known[rel] = entry
    entries.append((rel, kind, entry, nodigest))

# --- each entry against the disk ----------------------------------------------------------------
modified, missing, unreadable, not_checked = Capped(), Capped(), Capped(), Capped()
bytes_hashed = 0
for rel, kind, entry, nodigest in entries:
    row = {"path": rel, "kind": kind}
    try:
        if kind == "link":
            want = name_of(entry, "link")
            if not os.path.islink(rel):
                missing.append(rel)
                row["result"] = "missing"
            elif os.readlink(rel) != want:
                modified.append(rel)
                row["result"] = "modified: the link target differs"
            else:
                row["result"] = "ok"
        elif kind == "special":
            if not os.path.lexists(rel):
                missing.append(rel)
                row["result"] = "missing"
            elif not SPECIALS[entry["special"]](os.lstat(rel).st_mode):
                modified.append(rel)
                row["result"] = "modified: not a %s any more" % entry["special"]
            else:
                row["result"] = "ok"
        elif os.path.islink(rel):
            modified.append(rel)
            row["result"] = "modified: a link where a file was recorded"
        elif not os.path.isfile(rel):
            missing.append(rel)
            row["result"] = "missing"
        elif time.monotonic() > hash_deadline:
            not_checked.append(rel)
            row["result"] = "not checked: the time budget was used"
        else:
            size_on_disk = os.path.getsize(rel)
            row["bytes"] = size_on_disk
            if entry.get("bytes") is not None and size_on_disk != entry["bytes"]:
                # A different size is a different file; there is no need to read it to say so.
                modified.append(rel)
                row["result"] = "modified: the size differs (%d, recorded %d)" % (size_on_disk, entry["bytes"])
            elif nodigest:
                row["result"] = "digest missing: the size matches, and that is all that was checked"
            else:
                digest, size = sha256_file(rel, hash_deadline)
                bytes_hashed += size
                if digest is None:
                    not_checked.append(rel)
                    row["result"] = "not checked: the time budget ran out after %d bytes" % size
                elif digest != entry["sha256"]:
                    modified.append(rel)
                    row["sha256"] = digest
                    row["result"] = "modified: the sha256 differs"
                elif size != size_on_disk:
                    modified.append(rel)
                    row["result"] = "modified: the size changed while it was read"
                else:
                    row["sha256"] = digest
                    row["result"] = "ok"
    except (OSError, ValueError) as exc:         # a name with a NUL is a ValueError, and is not a file
        why = (getattr(exc, "strerror", None) or str(exc))
        unreadable.append({"path": rel, "why": why})
        row["result"] = "unreadable: %s" % why
    receipts.add(row)

# Several sets, each at inputs/<name>/: one held in place is a link there,
# walked through as the set it is.
sets = [s.get("name") for s in (man.get("sets") or []) if isinstance(s, dict) and isinstance(s.get("name"), str)]

added = Capped()
walk_entries = 0
walk_stopped = None


def unlisted(path, exc):
    """A directory under inputs/ that could not be listed: named in `unreadable` and given a row in the receipts, like a file that cannot be read."""
    why = "a directory under inputs/ could not be listed: %s" % (exc.strerror or exc)
    unreadable.append({"path": path, "why": why})
    receipts.add({"path": path, "kind": "directory", "result": "unreadable: %s" % why})


def walk_for_added(walked, under, top, held):
    """The names under `walked` that the manifest does not list, one directory at a time and the clock read for every entry.
    A directory link is a name of its own, not a place to walk into. Returns where the clock stopped it, or None."""
    global walk_entries
    stack = [walked]
    while stack:
        root = stack.pop()
        where = os.path.relpath(root, walked).replace("\\", "/")
        try:
            scan = os.scandir(root)
        except OSError as exc:
            unlisted(under if where == "." else under + where, exc)
            continue
        with scan:
            while True:
                try:
                    entry = next(scan)
                except StopIteration:
                    break
                except OSError as exc:
                    unlisted(under if where == "." else under + where, exc)
                    break
                walk_entries += 1
                if time.monotonic() > deadline:
                    return under if where == "." else under + where
                try:
                    is_dir, is_link = entry.is_dir(), entry.is_symlink()
                except OSError:
                    is_dir, is_link = False, False
                if is_dir and not is_link:
                    stack.append(entry.path)
                    continue
                if is_dir and root == top and entry.name in held:
                    continue
                rel = under + os.path.relpath(entry.path, walked).replace("\\", "/")
                if rel not in known:
                    added.append(rel)
                    receipts.add({"path": rel, "kind": "added", "result": "added: not in the manifest"})
    return None


if os.path.isdir("inputs"):
    top = os.path.realpath("inputs")
    held = [n for n in sets if "/" not in n and os.path.islink(os.path.join(top, n))]
    for walked, under in [(top, "inputs/")] + [(os.path.realpath(os.path.join(top, n)), "inputs/" + n + "/") for n in held]:
        stopped = walk_for_added(walked, under, top, held)
        if stopped is not None:
            walk_stopped = stopped
            not_checked.append("%s (the walk for added files stopped at the time budget after %d entries, in %s; what is under it, and in the sets "
                               "not yet walked, was not looked at)" % ("inputs/", walk_entries, stopped))
            receipts.add({"path": stopped, "kind": "walk", "result": "not checked: the walk for added files stopped at the time budget after %d entries" % walk_entries})
            break
receipts.finish()

ok = not (modified or missing or added or malformed or duplicates or digest_missing or unreadable or not_checked)
unverified = bool(not_checked or unreadable or malformed or digest_missing)
lists = {"modified": modified, "missing": missing, "added": added, "malformed": malformed, "duplicates": duplicates,
         "digest_missing": digest_missing, "unreadable": unreadable, "not_checked": not_checked}
cut = [n for n, v in lists.items() if v.total > LISTED]
kept = receipts.created and receipts.error is None
if unverified:
    status = "partial"
    basis = ("%d file(s) or entries were not verified: not_checked %d, unreadable %d, malformed %d, digest_missing %d (see the lists); what was checked "
             "is in the lists and the receipts, and the rest is not a pass" % (not_checked.total + unreadable.total + malformed.total + digest_missing.total,
                                                                              not_checked.total, unreadable.total, malformed.total, digest_missing.total))
elif cut and not kept:
    status = "partial"
    basis = ("every file was checked, but the lists %s are cut at %d and the receipts file that should hold the rest could not be written "
             "(receipts_error)" % (", ".join(cut), LISTED))
elif ok:
    status = "complete"
    basis = "every file of the manifest was found and its size and sha256 agree, and nothing else is under inputs/"
else:
    status = "complete"
    basis = ("every file of the manifest was checked and the walk over inputs/ finished, and the result differs from the baseline "
             "(see modified, missing, added and duplicates)")
result = {
    "tool": TOOL,
    "status": status,
    "status_basis": basis,
    "ok": ok,
    "modified": modified.items,
    "missing": missing.items,
    "added": added.items,
    "modified_total": modified.total,
    "missing_total": missing.total,
    "added_total": added.total,
    "checked": len(known),
    "malformed": malformed.items,
    "duplicates": duplicates.items,
    "digest_missing": digest_missing.items,
    "unreadable": unreadable.items,
    "not_checked": not_checked.items,
    "bytes_hashed": bytes_hashed,
    "inputs_entries_walked": walk_entries,
    "receipts_file": receipts.shown if receipts.created else None,
    "receipts": receipts.count,
    "baseline": ("a copy of the run's inputs.json the job service gave this job when it started (SWARM_INPUTS_MANIFEST)"
                 if MANIFEST != "inputs.json" else "the run's inputs.json"),
    "does_not_show": "that the evidence is authentic or complete, or that the manifest was right when it was made: a pass is agreement with the baseline",
}
if receipts.error:
    result["receipts_error"] = receipts.error
for name in cut:
    if name not in ("modified", "missing", "added"):
        result[name + "_total"] = lists[name].total
    result[name + "_note"] = ("the first %d are listed; every one is a row of the receipts file" % LISTED) if kept else \
        ("the first %d are listed; the rest could not be kept (see receipts_error)" % LISTED)
done(result, 0 if ok else 1)
