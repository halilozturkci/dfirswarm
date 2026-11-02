#!/usr/bin/env python3
"""Inventory the container runtimes of an extracted Linux root: Docker first, then Podman rootless and Kubernetes node logs.

From the files a runtime keeps on the host, with no runtime running and nothing started, it gives container ids, image ids, the
locators of the configuration, the command and its arguments (as counts and lengths), mounts, capabilities and security options,
lifecycle values (created, started, finished, restart count), a log inventory (file, size, first and last record time, rotation) and
the references from an image to its layers. Each runtime is read from its own on-disk shape and reports on its own:

  docker       var/lib/docker/containers/<id>/{config.v2.json,hostconfig.json,<id>-json.log*} and
               var/lib/docker/image/overlay2/{repositories.json,imagedb/content/sha256/*,layerdb/sha256/*}. config.v2.json is read by the
               fields the engine writes (ID, Created, Path, Args, Config, State, Image, Name, RestartCount, Driver, MountPoints, LogPath);
               a container directory with the older config.json only, or with neither, is listed as unsupported.
  podman       <home>/.local/share/containers/storage and var/lib/containers/storage:
               overlay-containers/containers.json, overlay-images/images.json, overlay-layers/layers.json (containers/storage's JSON lists)
  kubernetes   var/log/pods/<namespace>_<pod>_<uid>/<container>/<restart>.log in the CRI log format `<RFC3339Nano> <stdout|stderr> <P|F> <text>`
  containerd   var/lib/containerd's bolt metadata database is listed and NOT read (`unsupported`): the standard library cannot read it.

A JSON file is read to at most 8 MiB, parsed with the standard library with its depth, duplicate keys and any value that is not the
expected type reported and never guessed at; a file that does not parse is named with the reason, never turned into an empty result.
The layer references are followed by identifier: an image's rootfs.diff_ids give its layer chain (chain id = sha256 of the parent chain id,
a space and the diff id: the construction in the image specification), each layer is looked up in layerdb, and a layer the layerdb does
not hold is `missing`. A log is checked line by line for its record shape and parsed at its first and last record: the 50 MB log of a busy
container is streamed, never held.

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"). An environment, a command line, a label and a log
line can hold a secret. The answer carries counts and lengths of them, never the text; a mount is shown as a source, destination and
mode only when each has the shape of a path; capabilities and security options only in their own shapes. The command, its arguments, the
environment and the labels of each container go to container-text.jsonl (mode 0600) only on `write_text`, in a job run as secret output;
a log's text is not copied (it is in the evidence at the file and line).
"""
import datetime
import hashlib
import json
import math
import os
import re
import secrets
import signal
import stat
import sys
import tempfile
import time
from pathlib import Path

TOOL = "container_inventory"
PARSER = "container_inventory/1"


# BEGIN LINUX STOP
# The same text is in auth_log, cron_dump, shell_history and utmp_parse (tests/pack-linux-parts.test.ts holds the copies equal); journal_export's
# stop is its SHARED PROCESS block. A signal ends the tool with a last word. The harness ends a tool that runs too long with SIGTERM before it
# kills the group, and a tool that ignored it left its paging files as unfinished temporary files nobody could name. The rows written so far are
# kept under their final names and the text file is closed, so the last word can say where they are; the answer itself was never built.
#
# This block comes right after TOOL and PARSER and installs the handlers as its last line, before any parts, constants or arguments exist: a
# signal from then on gets one document (until the parts below are defined there is no page or text file to name, and the document says
# none was kept). What is before it is the interpreter's own start-up and the imports, which no code of this file can cover.
#
# Two moments are not the handler's. Python can run a handler inside a buffered file's own write (its flush looks for signals between
# writes), and there the file refuses the last word's flush: a signal that came while a row was being written left that paging file
# unfinished and unnamed. So while a file the last word closes is being written, the handler only notes the signal, and the write
# gives the last word once it is done. And while the answer, or an error answer, is being written, a signal is not answered: the
# answer stands, and no second document follows it. The last word disarms the regex clock (SIGALRM) before anything else, and a file
# that cannot be flushed inside it is named with its error and does not start an error document of its own (STATE["stopping"]). One
# window cannot be closed from inside Python: an alarm that is already pending when a stop signal arrives runs its handler at the
# first instruction of the last word, in the last word's frame, and the exception it raises there is taken by the tool's own
# expression-timeout handling; the tool then ends partial within max_seconds and not at the signal.
STATE = {"pages": [], "text": None, "writing": 0, "pending": None, "answering": False, "stopping": False}


def _writing():
    STATE["writing"] += 1


def _written():
    STATE["writing"] -= 1
    if not STATE["writing"] and STATE["pending"] is not None:
        signum, STATE["pending"] = STATE["pending"], None
        _on_signal(signum, None)


def _on_signal(signum, _frame):
    if hasattr(signal, "setitimer"):
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)     # the regex clock stops first: its alarm inside the last word left a paging file unnamed
            signal.signal(signal.SIGALRM, signal.SIG_IGN)
        except BaseException:  # noqa: BLE001
            pass
    if STATE["answering"]:
        return
    if STATE["writing"]:
        STATE["pending"] = signum
        return
    STATE["answering"] = STATE["stopping"] = True       # the last word is the answer now: a second signal does not start another
    kept, unflushed = {}, []
    for page in STATE["pages"]:
        try:
            shown = page.stop_here()
        except BaseException:  # noqa: BLE001 - a last word is best effort
            shown = None
        if shown:
            kept[page.key] = shown
        if getattr(page, "stop_error", None):
            unflushed.append(page.key)
    text = STATE["text"]
    text_file = getattr(text, "shown", None) if text is not None and getattr(text, "written", 0) else None
    if text is not None:
        try:
            text.close()
        except BaseException:  # noqa: BLE001
            pass
    try:
        sys.stdout.write(json.dumps({
            "parser": PARSER, "status": "failed", "stopped_by_signal": signum,
            "status_basis": "this tool was stopped by signal %d before it finished: no answer was built, and what it had read is not a complete result" % signum,
            "paging_files_kept": kept, "paging_files_not_flushed": unflushed, "text_file_kept": text_file,
            "text_file_close_error": getattr(text, "close_error", None),
            "kept_note": "the rows each file holds were written in the order read, up to where the tool was stopped; the files are named here and nowhere else",
        }) + "\n")
        sys.stdout.flush()
    except Exception:  # noqa: BLE001
        pass
    os._exit(128 + signum)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


install_signal_handlers()
# END LINUX STOP
DEFAULT_LIMIT = 100
DEFAULT_SECONDS = 60.0
MAX_SECONDS = 105.0           # the most a caller may ask for (the manifest allows 120)
TEXT_NAME = "container-text.jsonl"
MAX_JSON = 8 << 20            # one JSON file; the files a runtime writes are kilobytes
MAX_LISTED_NAMES = 200000
LOG_BLOCK = 1 << 20
MAX_SHOWN = 64                # items of one list inside a row
MAX_DEPTH_LAYERS = 4096       # the layers of one image that are followed
RUNTIMES = ("docker", "podman", "kubernetes", "containerd")

# BEGIN LINUX PARTS
# ---- The parts every tool of this pack that pages or keeps text copies (a tool is standalone; none imports another) ----
# The same text is in auth_log, cron_dump, journal_export, shell_history and utmp_parse (tests/pack-linux-parts.test.ts holds the copies
# equal). It uses STATE, _writing and _written, which are LINUX STOP's in four tools and, in journal_export, whose stop is its SHARED PROCESS
# block, two stand-ins below the SHARED PROCESS block's STATE.


def fail(message, **extra):
    """An error answer: JSON, exit 1, and the same `status` every answer of this pack carries."""
    STATE["answering"] = True       # a signal from here on is not answered: this answer stands alone
    print(json.dumps({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}))
    raise SystemExit(1)


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def read_args():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


def want_str(args, key, required=None):
    value = args.get(key)
    if value is None:
        if required:
            fail(required)
        return None
    if not isinstance(value, str):
        fail("%s must be a string" % key)
    if required and not value:
        fail(required)
    return value


def want_str_list(args, key):
    value = args.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        fail("%s must be a list of strings" % key)
    return value


def want_seconds(args, key, default, maximum=3600):
    """A time budget: a finite number above zero and no more than `maximum` (NaN and Infinity are not budgets)."""
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 or value > maximum:
        fail("%s must be a number of seconds above 0 and at most %d" % (key, maximum))
    return float(value)


def decode(data):
    """Bytes as text with no byte lost: an undecodable byte is a lone surrogate, which the text file writes as an escape
    and which encodes back to the byte (`blen` counts the bytes the original had)."""
    return data.decode("utf-8", "surrogateescape")


def blen(text):
    return len(text.encode("utf-8", "surrogateescape"))


def bound(value, limit=1024):
    """(shown, bytes or None): a string longer than `limit` characters is shown cut, with its whole length. The
    whole is kept where the record's text is kept (the text file, the evidence at the record's locator)."""
    if isinstance(value, str) and len(value) > limit:
        return value[:limit], blen(value)
    return value, None


def want_flag(args, key):
    value = args.get(key, False)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def want_limit(args):
    limit = args.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive integer")
    return limit


def status_of(complete, failed, basis_complete, basis_partial, basis_failed):
    """The `status` every answer of this pack carries, with the reason for it: complete (everything the request asked
    for was read and nothing was left out), partial (some of it was, and the answer names what was not) or failed."""
    if failed:
        return {"status": "failed", "status_basis": basis_failed}
    if complete:
        return {"status": "complete", "status_basis": basis_complete}
    return {"status": "partial", "status_basis": basis_partial}


def touches_withheld_text(has_filter):
    """A filter that matches the text of a record is a search over text the answer withholds: it is honoured only in a job
    (whose output is sealed), and the answer says it was used."""
    return bool(has_filter) and in_job()


MAX_PAGING_BYTES = 128 << 20  # all the paging files of one call hold this much together; a row past it is counted and located, not written
MAX_TEXT_BYTES = 256 << 20    # the text file of one call holds this much; a record past it is counted and located, not written
PAGING = {"left": MAX_PAGING_BYTES}      # what the paging files of this call may still hold, in bytes, all of them together
TEXTING = {"left": MAX_TEXT_BYTES}       # what the text file may still hold, in bytes


# Lossless paging (the same in every library tool that pages): the page an agent reads stays small, and when
# there are more rows the whole result is written as JSON Lines under work/<agent>/tool-output (in a job,
# $OUT/tool-output) and named. The file name is random: it is never a digest of anything asked for. A write
# that fails is an error answer naming the file, never a traceback and never a silent loss: the rows written
# before the error are kept under the file's name and the answer says so, or says the temporary was removed.
class LosslessPage:
    def __init__(self, tool, key, limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.key = key
        self.page = []
        self.total = 0
        self.not_written = 0        # rows after the paging cap: counted in `total`, not in the file
        self.stop_error = None
        self._out = None
        self._tmp = None
        name = "%s-%s.jsonl" % (self.tool, secrets.token_hex(8))
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self._done = False
        STATE.setdefault("pages", []).append(self)     # every page is the last word's to name, from the moment it exists

    def _abandon(self):
        """A write failed (ENOSPC, EIO): what is already in the temporary is kept under the file's own name, or the temporary is removed.
        Returns what the answer says about it."""
        out, self._out = self._out, None
        if out is not None:
            try:
                out.close()
            except OSError:
                pass
        if self._tmp is None:
            return "no paging file was left"
        try:
            os.replace(self._tmp, self.path)
            self._done = True
            return "the rows written before the error are in %s (the last row may be cut)" % self.path
        except OSError:
            pass
        try:
            os.unlink(self._tmp)
            return "the temporary paging file was removed"
        except OSError as exc:
            return "the temporary paging file %s could not be renamed or removed (%s)" % (self._tmp, describe(exc))

    def _write(self, row, kept=False):
        data = json.dumps(row, ensure_ascii=False, default=str) + "\n"
        size = len(data.encode("utf-8", "backslashreplace"))
        if not kept and (self.not_written or size > PAGING["left"]):
            self.not_written += 1       # once a row is refused no later one is written: the file stays the first rows in order
            return
        PAGING["left"] = max(0, PAGING["left"] - size)
        _writing()
        try:
            self._out.write(data)     # one write: a stop never leaves half a row
        except OSError as exc:
            fail("the whole result could not be written to %s: %s" % (self.path, describe(exc)), paging_file=str(self.path), paging_file_state=self._abandon())
        finally:
            _written()

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                # The name is known before the file exists, so a signal at any point after this line finds the file by it.
                self._tmp = self.path.parent / (".%s-%s" % (self.path.name, secrets.token_hex(8)))
                fd = os.open(str(self._tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                self._out = os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace")
            except OSError as exc:
                state = "no paging file was left" if self._tmp is None or not os.path.lexists(self._tmp) else self._abandon()
                fail("the whole result could not be written: %s cannot be created (%s)" % (self.path, describe(exc)), paging_file=str(self.path), paging_file_state=state)
            for kept in self.page:
                self._write(kept, kept=True)
        self._write(row)

    def stop_here(self):
        """The rows written so far, kept under the final name (a signal ended the tool): the path as shown, or None where nothing was written.
        A file that cannot be flushed is still renamed (what reached the disk is kept) and `stop_error` says it."""
        if self._tmp is None:
            return None
        if self._done:
            return self.shown           # finish() had put it under its name: it holds every row
        out, self._out = self._out, None
        if out is not None:
            try:
                out.flush()
                os.fsync(out.fileno())
            except OSError as exc:
                self.stop_error = describe(exc)
            try:
                out.close()
            except OSError as exc:
                self.stop_error = self.stop_error or describe(exc)
        if not os.path.exists(self._tmp):
            return None
        os.replace(self._tmp, self.path)
        return self.shown

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            _writing()
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                os.replace(self._tmp, self.path)
                self._done = True
            except OSError as exc:
                fail("the whole result could not be written to %s: %s" % (self.path, describe(exc)), paging_file=str(self.path), paging_file_state=self._abandon())
            finally:
                _written()
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        if self.not_written:
            result["not_written"] = self.not_written
            result["not_written_why"] = ("the paging files of one call hold at most %d bytes together: the first %d rows are in the file, in order; "
                                         "the %d after them are counted in `matched` and are in the evidence at the file and line each entry names"
                                         % (MAX_PAGING_BYTES, self.total - self.not_written, self.not_written))
        return result


def require_job(flag):
    """What leaves a record's text is held to the secret-safe output pattern (docs/packs.md, "Secrets and
    sensitive output"): the text goes into the answer or into a file only in a job, whose output the skill
    says to seal with secret_output: true. Outside a job, and in a job the harness did not run as secret output (it sets
    SECRET_OUTPUT=1 in the environment of such a job's process, from the manifest's declaration or the agent's flag), the
    request is refused and nothing is written."""
    if not in_job():
        fail("%s is refused outside a job: a command line, a message or an environment value written or "
             "printed here would be an ordinary file or an ordinary answer, not a sealed output. Run this as "
             "job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, TOOL))
    if os.environ.get("SECRET_OUTPUT") != "1":
        fail("%s is refused: this job was not run as secret output, so what it wrote or printed would be sealed as an ordinary "
             "output. The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. Run this as "
             "job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, TOOL))


class TextRefused(Exception):
    pass


class TextFile:
    """Where the text of a tool's records goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan's SecretValues, for rows. With `enabled` false it
    writes nothing and `summary()` says so. Enabled, it is refused outside a job; inside one the file is
    created before anything is read (mode 0600, exclusively: a file or a link already at that name is
    refused by name) under $OUT, and the answer names it and says it may hold secrets. A byte that is not
    UTF-8 is written as a JSON escape of its lone surrogate and reads back as the byte: the file keeps the whole.
    The file holds at most MAX_TEXT_BYTES: once a record would pass it, that record and every one after it are
    counted in `not_written` and not written (the file stays the first records, in order), and `summary()` says so.
    """

    def __init__(self, name, enabled, what, flag="write_text"):
        self.enabled = enabled
        self.written = 0
        self.not_written = 0        # records after the cap: counted, not in the file
        self.capped = False
        self.cut_record = False     # a record's first pieces (add_bytes_raw) were written and the cap came before its last
        self._open_piece = False
        self.close_error = None
        self.what = what
        self.flag = flag
        self._fh = None
        self.path = None
        self.shown = None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            raise TextRefused("%s is refused outside a job: the text of the records written here would be an "
                              "ordinary file, not a sealed output. Run this as job_run tool=%s with secret_output: "
                              "true, and ask again there. Nothing was written." % (flag, TOOL))
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise TextRefused("%s is refused: this job was not run as secret output, so the text of the records written here would be sealed "
                              "as an ordinary output. The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. "
                              "Run this as job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, TOOL))
        self.path = Path(out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise TextRefused("the text file already exists: %s" % self.path)
        except OSError as exc:
            raise TextRefused("the text file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "wb")

    def _put(self, data):
        _writing()
        try:
            self._fh.write(data)
        except OSError as exc:
            fail("the text file could not be written: %s (%s)" % (self.path, describe(exc)), text_file=str(self.path))
        finally:
            _written()

    def _room(self, size):
        """Whether `size` more bytes fit under the cap; the first that does not closes the file to every later record."""
        if self.capped or size > TEXTING["left"]:
            self.capped = True
            return False
        TEXTING["left"] -= size
        return True

    def add(self, row):
        if self._fh is None:
            return
        data = json.dumps(row, ensure_ascii=False, default=str).encode("utf-8", "backslashreplace") + b"\n"
        if not self._room(len(data)):
            self.not_written += 1
            return
        self.written += 1
        self._put(data)

    def add_bytes_raw(self, data):
        """A piece of a source's own bytes, written as it came; the record it belongs to is counted by count_record."""
        if self._fh is None:
            return
        if self._room(len(data)):
            self._open_piece = True
            self._put(data)
        elif self._open_piece:
            self.cut_record = True

    def count_record(self):
        if self._fh is not None:
            self._open_piece = False
            if self.capped:
                self.not_written += 1
            else:
                self.written += 1

    def add_bytes(self, data):
        """One record exactly as its source wrote it (a native export's line, newline included)."""
        if self._fh is None:
            return
        if not self._room(len(data)):
            self.not_written += 1
            return
        self.written += 1
        self._put(data)

    def close(self):
        if self._fh is not None:
            _writing()
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()
                self._fh = None
            except OSError as exc:
                if STATE.get("stopping"):
                    self.close_error = describe(exc)    # the last word names it: one document, not an error document and then the last word
                    self._fh = None
                else:
                    fail("the text file could not be closed: %s (%s)" % (self.path, describe(exc)), text_file=str(self.path))
            finally:
                _written()

    def summary(self, preview=False):
        """What the answer says about text. `preview` is true when the answer itself carries it (preview_text)."""
        shown = {"answer_contains_text_that_may_hold_secrets": bool(preview)}
        if not self.enabled:
            hint = ("No text of any record is in a file." if not preview else
                    "The answer's records carry their text (preview); no file of it was written, and the paging file, if there is one, holds none.")
            return {"requested": False, "written": 0, "file": None, "contains_text_that_may_hold_secrets": False, **shown,
                    "hint": hint + " %s: true, in a job run with secret_output: true, keeps the whole of each record in a private file under $OUT." % self.flag}
        result = {"requested": True, "written": self.written, "file": self.shown,
                  "contains_text_that_may_hold_secrets": self.written > 0, **shown, "format": self.what}
        if self.not_written or self.capped:
            result["not_written"] = self.not_written
            result["not_written_why"] = ("the text file of one call holds at most %d bytes: the first %d records are in it, in order; the %d after them are "
                                         "counted and are in the evidence at the file and line each record names%s"
                                         % (MAX_TEXT_BYTES, self.written, self.not_written,
                                            "; the last record in the file may be cut short" if self.cut_record else ""))
        return result


def capped_why(pages, text=None):
    """The sentence for an answer that is partial because a cap was reached (the paging files' or the text file's), or None. `pages` is
    the answer's `pages` dictionary; `text` the TextFile."""
    cut = ["%d of %s" % (page["not_written"], name) for name, page in pages.items() if page.get("not_written")]
    held = []
    if cut:
        held.append("the paging files reached their cap of %d bytes: %s row(s) are counted and are not in a paging file (see not_written in `pages`)"
                    % (MAX_PAGING_BYTES, ", ".join(cut)))
    if text is not None and (text.not_written or text.capped):
        held.append("the text file reached its cap of %d bytes: %d record(s) are counted and are not in it (see not_written in `text`)"
                    % (MAX_TEXT_BYTES, text.not_written))
    if not held:
        return None
    return "; ".join(held) + "; each is in the evidence at the file and line it names"


INLINE_LIST = 200       # items of any list that grows with the evidence (files, homes, errors, links) kept inline in the answer


class Listed(list):
    """A list of the answer that grows with the evidence (one item per file, home, link or error): its first INLINE_LIST items are the list, and
    every item, those too, is kept in a paging file that the answer names under pages.<key> (`page.total` is how many there were; `settle()`
    finishes the file and returns the page's entry for the answer's `pages`)."""

    def __init__(self, key):
        super().__init__()
        self.page = LosslessPage(TOOL, key, INLINE_LIST)

    def append(self, item):
        self.page.add(item)
        if len(self) < INLINE_LIST:
            super().append(item)

    def settle(self):
        return self.page.finish()
# END LINUX PARTS

ID64 = re.compile(r"[0-9a-f]{64}")
SHA_ID = re.compile(r"(?:sha256:)?[0-9a-f]{64}")
PATHY = re.compile(r"/[A-Za-z0-9_.@:/+%=,\-]{0,300}")
CAP = re.compile(r"[A-Z][A-Z_]{1,40}")
PLAIN = re.compile(r"[A-Za-z0-9_.:@/\-]{1,255}")
SECOPT = re.compile(r"(?:no-new-privileges|seccomp=unconfined|apparmor=unconfined|label=disable|label:disable|seccomp:unconfined|apparmor:unconfined|systempaths=unconfined)(?::true|=true)?")
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,18}(?:Z|[+-][0-9]{2}:[0-9]{2})")
CRI_LINE = re.compile(rb"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,18}(?:Z|[+-][0-9]{2}:[0-9]{2})) (stdout|stderr) ([PF])(?: |$)")
POD_DIR = re.compile(r"([a-z0-9][a-z0-9.\-]{0,252})_([a-z0-9][a-z0-9.\-]{0,252})_([0-9a-f\-]{8,64})")


class Overtime(Exception):
    pass


def want_runtimes(args):
    value = args.get("runtimes")
    if value is None:
        return list(RUNTIMES)
    if not isinstance(value, list) or not value or not all(isinstance(x, str) for x in value) or any(x not in RUNTIMES for x in value):
        fail("runtimes must be a non-empty list of: %s" % ", ".join(RUNTIMES))
    return [r for r in RUNTIMES if r in value]


def want_dirs(args, key):
    value = args.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 16 or not all(isinstance(x, str) and x and len(x) <= 4096 and "\x00" not in x for x in value):
        fail("%s must be a list of at most 16 directory names" % key)
    for item in value:
        try:
            os.fsencode(item)
        except (UnicodeEncodeError, ValueError):
            fail("%s holds a name a file cannot have (a lone surrogate)" % key)
    return value


def iso_mtime(path):
    try:
        return datetime.datetime.fromtimestamp(os.lstat(path).st_mtime, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OSError, ValueError, OverflowError):
        return None


def inside(root, path):
    try:
        return os.path.commonpath((os.path.realpath(root), os.path.realpath(path))) == os.path.realpath(root)
    except (OSError, ValueError):
        return False


def open_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file (a pipe, a socket or a device is never read)")
        return fd, info.st_size
    except BaseException:
        os.close(fd)
        raise


def read_head(path, limit):
    """Up to `limit` bytes of a regular file: opened without waiting and without following a link, and looked at with fstat first, so a FIFO,
    a device or a directory at this name is an OSError and never holds the tool."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file (a pipe, a socket or a device is never read)")
        chunks, left = [], limit
        while left > 0:
            part = os.read(fd, min(left, 1 << 20))
            if not part:
                break
            chunks.append(part)
            left -= len(part)
        return b"".join(chunks)
    finally:
        os.close(fd)


class Duplicates(Exception):
    pass


def pairs_hook(pairs):
    """Objects as dicts, with a repeated key counted (the last value wins, as the standard library does; the engine that wrote the file did not repeat one)."""
    out = {}
    repeats = 0
    for key, value in pairs:
        if key in out:
            repeats += 1
        out[key] = value
    if repeats:
        out["\x00duplicate_keys"] = repeats
    return out


def read_json(run, path):
    """(object, note) of a JSON file of at most MAX_JSON bytes. A file that cannot be read or parsed is (None, the reason), and is in run.read_errors."""
    try:
        fd, size = open_regular(path)
    except OSError as exc:
        run.error(path, describe(exc))
        return None, describe(exc)
    try:
        if size > MAX_JSON:
            reason = "%d bytes is larger than the %d this tool parses" % (size, MAX_JSON)
            run.error(path, reason)
            return None, reason
        chunks, total = [], 0
        while total <= MAX_JSON:
            part = os.read(fd, 1 << 20)
            if not part:
                break
            chunks.append(part)
            total += len(part)
        data = b"".join(chunks)
    except OSError as exc:
        run.error(path, describe(exc))
        return None, describe(exc)
    finally:
        os.close(fd)
    try:
        return json.loads(data.decode("utf-8", "surrogateescape"), object_pairs_hook=pairs_hook), None
    except RecursionError:
        reason = "nested deeper than the parser reads"
    except ValueError as exc:
        reason = "not JSON (%s)" % type(exc).__name__
    run.error(path, reason)
    return None, reason


def duplicates_of(obj):
    return obj.get("\x00duplicate_keys", 0) if isinstance(obj, dict) else 0


def clean(obj):
    """The object without the duplicate-key marker (a key no runtime writes)."""
    if isinstance(obj, dict):
        obj.pop("\x00duplicate_keys", None)
    return obj


def text_field(obj, key):
    value = obj.get(key) if isinstance(obj, dict) else None
    return value if isinstance(value, str) else None


def count_of(value):
    return len(value) if isinstance(value, (list, dict)) else None


def sized(value):
    """(count, bytes) of a list of strings or one string: lengths only."""
    if isinstance(value, str):
        return {"count": 1, "bytes": blen(value)}
    if isinstance(value, list):
        return {"count": len(value), "bytes": sum(blen(x) if isinstance(x, str) else 0 for x in value), "not_text": sum(1 for x in value if not isinstance(x, str))}
    return {"count": 0, "bytes": 0} if value is None else {"count": None, "bytes": None, "not_a_list": type(value).__name__}


def shown_stamp(value):
    """A time as the config wrote it, only when it has the shape of one (the raw text is the value; it is not converted)."""
    return value if isinstance(value, str) and STAMP.fullmatch(value) else None


def shown_path(value):
    if isinstance(value, str) and PATHY.fullmatch(value):
        return {"path": value}
    return {"path_bytes": blen(value), "path_withheld": True} if isinstance(value, str) else {"path_bytes": None}


class Run:
    def __init__(self, root, text, entries, layers, logs, deadline, seconds):
        self.root, self.text, self.entries, self.layers_page, self.logs_page = root, text, entries, layers, logs
        self.deadline, self.seconds = deadline, seconds
        self.locations = LosslessPage(TOOL, "locations", INLINE_LIST)
        self.read_errors, self.walk_errors = Listed("read_errors"), Listed("walk_errors")
        self.unsupported = Listed("unsupported")
        self.by_state, self.kinds, self.seen_real = {}, {}, {}
        self.seq = 0
        self.partial_reason = None
        self.images = {}            # (runtime, image id) -> the image row's id, for the join with containers
        self.container_images = {}  # (runtime, image id) -> how many containers use it
        self.missing_layers = 0
        self.layer_total = 0
        self.log_files = 0
        self.known_images = set()

    def check(self):
        if time.monotonic() > self.deadline:
            raise Overtime()

    def census(self, rel, state, **extra):
        self.locations.add({"path": rel, "state": state, **extra})
        key = state.split(":")[0].split(" (")[0]
        self.by_state[key] = self.by_state.get(key, 0) + 1

    def entry(self, row):
        self.seq += 1
        row = {"id": "K%06d" % self.seq, "parser": PARSER, **row}
        self.kinds[row["kind"]] = self.kinds.get(row["kind"], 0) + 1
        self.entries.add(row)
        return row

    def error(self, path, reason):
        self.read_errors.append({"file": path, "error": reason})

    def not_supported(self, runtime, path, why):
        self.unsupported.append({"runtime": runtime, "path": path, "why": why})


def names_of(run, directory):
    names = []
    with os.scandir(directory) as it:
        for number, item in enumerate(it):
            if (number & 1023) == 0:
                run.check()
            if len(names) >= MAX_LISTED_NAMES:
                run.partial_reason = run.partial_reason or "%s holds more than %d names: only the first %d were looked in" % (directory, MAX_LISTED_NAMES, MAX_LISTED_NAMES)
                break
            names.append(item.name)
    return sorted(names)


def locate(run, rel):
    """The directory for a place in the root, or None with the census saying why (missing, a link not followed, not a directory, an alias of one read)."""
    run.check()
    full = os.path.join(run.root, rel)
    try:
        if not os.path.lexists(full):
            run.census(rel, "missing")
            return None
        if os.path.islink(full) or not inside(run.root, full):
            run.census(rel, "link or outside the root: not followed")
            return None
        if not os.path.isdir(full):
            run.census(rel, "not a directory")
            return None
        real = os.path.realpath(full)
    except OSError as exc:
        run.walk_errors.append({"path": full, "error": describe(exc)})
        run.census(rel, "error: %s" % describe(exc))
        return None
    if real in run.seen_real:
        run.census(rel, "alias of %s (the same directory reached through a link in its path): read once, there" % run.seen_real[real])
        return None
    run.seen_real[real] = rel
    return full


def log_inventory(run, path, rel_kind):
    """The log's size, line count, record-shape check and first and last record time, streamed in blocks (the clock is read every block).
    `rel_kind` is "docker" (json-file: {"log":...,"stream":...,"time":...}) or "cri"."""
    run.check()
    row = {"file": path, "bytes": None, "lines": 0, "records_in_shape": 0, "lines_out_of_shape": 0, "first_time": None, "last_time": None, "rotation": None,
           "format": "docker json-file" if rel_kind == "docker" else "CRI", "complete": False}
    m = re.search(r"\.log(?:\.([0-9]+))?(?:\.gz)?$", path)
    if m and m.group(1):
        row["rotation"] = int(m.group(1))
    try:
        fd, size = open_regular(path)
    except OSError as exc:
        row["error"] = describe(exc)
        run.error(path, describe(exc))
        run.logs_page.add(row)
        return row
    row["bytes"] = size
    first_line = last_line = None
    carry = b""
    try:
        gz = os.pread(fd, 2, 0) == b"\x1f\x8b"
        if gz:
            row["error"] = "a gzip log is listed and not read here (its records are in the evidence at this file)"
            row["complete"] = False
            run.logs_page.add(row)
            return row
        while True:
            run.check()
            block = os.read(fd, LOG_BLOCK)
            if not block:
                break
            block = carry + block
            cut = block.rfind(b"\n")
            if cut < 0:
                carry = block if len(block) <= (1 << 22) else b""
                if len(block) > (1 << 22):
                    row["lines"] += 1
                    row["lines_out_of_shape"] += 1
                continue
            carry = block[cut + 1:]
            for line in block[:cut].split(b"\n"):
                row["lines"] += 1
                if rel_kind == "docker":
                    ok = line.startswith(b'{"log":') and line.endswith(b"}")
                else:
                    ok = CRI_LINE.match(line) is not None
                if ok:
                    row["records_in_shape"] += 1
                    if first_line is None:
                        first_line = line
                    last_line = line
                else:
                    row["lines_out_of_shape"] += 1
        if carry:
            row["lines"] += 1
            row["lines_out_of_shape"] += 1
            row["final_line_without_newline"] = True
        row["complete"] = True
    except OSError as exc:
        row["error"] = describe(exc)
        run.error(path, describe(exc))
    finally:
        os.close(fd)
    for which, line in (("first_time", first_line), ("last_time", last_line)):
        if line is None:
            continue
        if rel_kind == "docker":
            try:
                value = json.loads(line.decode("utf-8", "replace")).get("time")
                row[which] = value if isinstance(value, str) and STAMP.fullmatch(value) else None
            except (ValueError, AttributeError, RecursionError):
                row[which] = None
        else:
            m2 = CRI_LINE.match(line)
            row[which] = m2.group(1).decode("ascii") if m2 else None
    run.log_files += 1
    run.logs_page.add(row)
    return row


def docker_state(state):
    if not isinstance(state, dict):
        return None
    out = {}
    for key in ("Running", "Paused", "Restarting", "OOMKilled", "Dead"):
        if isinstance(state.get(key), bool):
            out[key.lower()] = state[key]
    for key in ("Pid", "ExitCode"):
        if isinstance(state.get(key), int) and not isinstance(state.get(key), bool):
            out[key.lower()] = state[key]
    for key in ("StartedAt", "FinishedAt"):
        out[key.lower()] = shown_stamp(state.get(key))
    return out


def docker_container(run, base, cid):
    run.check()
    directory = os.path.join(base, "containers", cid)
    config_path = os.path.join(directory, "config.v2.json")
    host_path = os.path.join(directory, "hostconfig.json")
    row = {"kind": "container", "runtime": "docker", "container_id": cid, "directory": directory, "config_file": config_path, "hostconfig_file": host_path,
           "config_version": None, "errors": []}
    if not os.path.lexists(config_path):
        legacy = os.path.join(directory, "config.json")
        why = "no config.v2.json" + (": config.json is the older layout this tool does not read" if os.path.lexists(legacy) else "")
        run.not_supported("docker", directory, why)
        row.update({"config_version": "unsupported", "errors": [why]})
        row["logs"] = docker_logs(run, directory, cid)
        run.entry(row)
        return
    config, why = read_json(run, config_path)
    if not isinstance(config, dict):
        row.update({"config_version": "unreadable", "errors": [why or "the top level is not an object"]})
        row["logs"] = docker_logs(run, directory, cid)
        run.entry(row)
        return
    row["config_version"] = "v2"
    dup = duplicates_of(config)
    clean(config)
    if dup:
        row["errors"].append("%d repeated key(s) at the top level of config.v2.json: the last value was used" % dup)
    own = text_field(config, "ID")
    if own is not None and own != cid:
        row["errors"].append("config.v2.json's ID is not the directory's name")
    cfg = config.get("Config") if isinstance(config.get("Config"), dict) else {}
    if config.get("Config") is not None and not isinstance(config.get("Config"), dict):
        row["errors"].append("Config is not an object")
    clean(cfg)
    image = text_field(config, "Image")
    row.update({
        "name": text_field(config, "Name") if PLAIN.fullmatch(text_field(config, "Name") or "") else None,
        "name_bytes": blen(text_field(config, "Name") or ""),
        "created": shown_stamp(config.get("Created")), "created_raw_bytes": blen(config.get("Created")) if isinstance(config.get("Created"), str) else None,
        "image_id": image if image and SHA_ID.fullmatch(image) else None, "image_ref_bytes": blen(image) if image else None,
        "driver": text_field(config, "Driver") if PLAIN.fullmatch(text_field(config, "Driver") or "") else None,
        "restart_count": config.get("RestartCount") if isinstance(config.get("RestartCount"), int) and not isinstance(config.get("RestartCount"), bool) else None,
        "state": docker_state(config.get("State")),
        "command": {"path": sized(config.get("Path")), "args": sized(config.get("Args")), "entrypoint": sized(cfg.get("Entrypoint")), "cmd": sized(cfg.get("Cmd"))},
        "environment": sized(cfg.get("Env")),
        "labels": {"count": count_of(cfg.get("Labels")), "bytes": sum(blen(k) + (blen(v) if isinstance(v, str) else 0) for k, v in (cfg.get("Labels") or {}).items()) if isinstance(cfg.get("Labels"), dict) else None},
        "user_bytes": blen(cfg.get("User")) if isinstance(cfg.get("User"), str) else None,
        "working_dir": shown_path(cfg.get("WorkingDir")) if isinstance(cfg.get("WorkingDir"), str) and cfg.get("WorkingDir") else None,
        "log_path": shown_path(config.get("LogPath")) if isinstance(config.get("LogPath"), str) else None,
        "config_file_modified": iso_mtime(config_path),
    })
    mounts = []
    points = config.get("MountPoints")
    if isinstance(points, dict):
        for key in sorted(points)[:MAX_SHOWN]:
            point = points[key] if isinstance(points[key], dict) else {}
            mounts.append({"destination": shown_path(point.get("Destination") if isinstance(point.get("Destination"), str) else key),
                           "source": shown_path(point.get("Source")), "type": point.get("Type") if isinstance(point.get("Type"), str) and PLAIN.fullmatch(point.get("Type")) else None,
                           "read_write": point.get("RW") if isinstance(point.get("RW"), bool) else None})
    elif points is not None:
        row["errors"].append("MountPoints is not an object")
    row["mounts"] = mounts
    row["mounts_total"] = len(points) if isinstance(points, dict) else 0
    host, why_h = read_json(run, host_path) if os.path.lexists(host_path) else (None, "no hostconfig.json")
    if isinstance(host, dict):
        hdup = duplicates_of(host)
        clean(host)
        caps_add = [c for c in host.get("CapAdd") or [] if isinstance(c, str)] if isinstance(host.get("CapAdd"), list) else []
        caps_drop = [c for c in host.get("CapDrop") or [] if isinstance(c, str)] if isinstance(host.get("CapDrop"), list) else []
        binds = host.get("Binds") if isinstance(host.get("Binds"), list) else []
        shown_binds = []
        for bind in binds[:MAX_SHOWN]:
            if isinstance(bind, str):
                parts = bind.split(":")
                shown_binds.append({"source": shown_path(parts[0]), "destination": shown_path(parts[1]) if len(parts) > 1 else None, "mode": parts[2] if len(parts) > 2 and re.fullmatch(r"[a-z,]{1,20}", parts[2]) else None})
        sec = [s for s in host.get("SecurityOpt") or [] if isinstance(s, str)] if isinstance(host.get("SecurityOpt"), list) else []
        policy = host.get("RestartPolicy") if isinstance(host.get("RestartPolicy"), dict) else {}
        row["host_config"] = {
            "privileged": host.get("Privileged") if isinstance(host.get("Privileged"), bool) else None,
            "cap_add": [c for c in caps_add if CAP.fullmatch(c)][:MAX_SHOWN], "cap_add_total": len(caps_add),
            "cap_drop": [c for c in caps_drop if CAP.fullmatch(c)][:MAX_SHOWN], "cap_drop_total": len(caps_drop),
            "binds": shown_binds, "binds_total": len(binds),
            "security_opt": [s for s in sec if SECOPT.fullmatch(s)][:MAX_SHOWN], "security_opt_total": len(sec),
            "network_mode": host.get("NetworkMode") if isinstance(host.get("NetworkMode"), str) and PLAIN.fullmatch(host.get("NetworkMode")) else None,
            "pid_mode": host.get("PidMode") if isinstance(host.get("PidMode"), str) and PLAIN.fullmatch(host.get("PidMode") or "x") else None,
            "restart_policy": policy.get("Name") if isinstance(policy.get("Name"), str) and PLAIN.fullmatch(policy.get("Name") or "x") else None,
            "devices": count_of(host.get("Devices")), "port_bindings": count_of(host.get("PortBindings")),
            "log_driver": (host.get("LogConfig") or {}).get("Type") if isinstance(host.get("LogConfig"), dict) and isinstance((host.get("LogConfig") or {}).get("Type"), str) and PLAIN.fullmatch((host.get("LogConfig") or {}).get("Type") or "x") else None,
        }
        if hdup:
            row["errors"].append("%d repeated key(s) in hostconfig.json" % hdup)
    else:
        row["host_config"] = None
        row["errors"].append("hostconfig.json: %s" % why_h)
    if image:
        key = ("docker", image if image.startswith("sha256:") else "sha256:" + image)
        run.container_images[key] = run.container_images.get(key, 0) + 1
        row["image_in_imagedb"] = key[1] in run.known_images
    row["logs"] = docker_logs(run, directory, cid)
    if run.text.enabled:
        run.text.add({"record_type": "container", "runtime": "docker", "container_id": cid, "name": config.get("Name"), "path": config.get("Path"), "args": config.get("Args"),
                      "entrypoint": cfg.get("Entrypoint"), "cmd": cfg.get("Cmd"), "env": cfg.get("Env"), "labels": cfg.get("Labels"),
                      "binds": host.get("Binds") if isinstance(host, dict) else None, "working_dir": cfg.get("WorkingDir"), "user": cfg.get("User")})
    run.entry(row)


def docker_logs(run, directory, cid):
    found = []
    try:
        names = [n for n in names_of(run, directory) if n == "%s-json.log" % cid or n.startswith("%s-json.log." % cid)]
    except OSError as exc:
        run.walk_errors.append({"path": directory, "error": describe(exc)})
        return found
    for name in names:
        found.append(log_inventory(run, os.path.join(directory, name), "docker"))
    return [{k: v for k, v in f.items()} for f in found[:MAX_SHOWN]]


def chain_ids(diff_ids):
    """The chain ids of a layer stack: chain(1) = diff(1), chain(n) = sha256("<chain(n-1)> <diff(n)>") (the image specification's construction)."""
    chain, out = None, []
    for diff in diff_ids:
        chain = diff if chain is None else "sha256:" + hashlib.sha256((chain + " " + diff).encode("ascii")).hexdigest()
        out.append(chain)
    return out


def docker_images(run, base):
    image_root = os.path.join(base, "image", "overlay2")
    repos, repo_names = {}, {}
    path = os.path.join(image_root, "repositories.json")
    if os.path.lexists(path):
        doc, why = read_json(run, path)
        if isinstance(doc, dict) and isinstance(doc.get("Repositories"), dict):
            for repo, tags in doc["Repositories"].items():
                if isinstance(tags, dict):
                    for ref, image_id in tags.items():
                        if isinstance(image_id, str) and SHA_ID.fullmatch(image_id):
                            repo_names.setdefault(image_id, []).append(ref if PLAIN.fullmatch(ref) and "@sha256:" not in ref else None)
        elif doc is not None:
            run.error(path, "repositories.json has no Repositories object")
    content = os.path.join(image_root, "imagedb", "content", "sha256")
    layerdb = os.path.join(image_root, "layerdb", "sha256")
    try:
        names = [n for n in names_of(run, content) if re.fullmatch(r"[0-9a-f]{64}", n)] if os.path.isdir(content) else []
    except OSError as exc:
        run.walk_errors.append({"path": content, "error": describe(exc)})
        names = []
    for name in names:
        run.check()
        config_path = os.path.join(content, name)
        doc, why = read_json(run, config_path)
        row = {"kind": "image", "runtime": "docker", "image_id": "sha256:" + name, "config_file": config_path, "errors": []}
        if not isinstance(doc, dict):
            row["errors"].append(why or "the top level is not an object")
            run.entry(row)
            continue
        clean(doc)
        rootfs = doc.get("rootfs") if isinstance(doc.get("rootfs"), dict) else {}
        diffs = [d for d in rootfs.get("diff_ids", []) if isinstance(d, str) and SHA_ID.fullmatch(d)] if isinstance(rootfs.get("diff_ids"), list) else []
        if isinstance(rootfs.get("diff_ids"), list) and len(diffs) != len(rootfs["diff_ids"]):
            row["errors"].append("%d diff id(s) are not sha256 digests" % (len(rootfs["diff_ids"]) - len(diffs)))
        diffs = diffs[:MAX_DEPTH_LAYERS]
        cfg = doc.get("config") if isinstance(doc.get("config"), dict) else {}
        row.update({"created": shown_stamp(doc.get("created")), "architecture": doc.get("architecture") if isinstance(doc.get("architecture"), str) and PLAIN.fullmatch(doc.get("architecture")) else None,
                    "os": doc.get("os") if isinstance(doc.get("os"), str) and PLAIN.fullmatch(doc.get("os")) else None,
                    "references": [r for r in repo_names.get("sha256:" + name, [])][:MAX_SHOWN], "reference_count": len(repo_names.get("sha256:" + name, [])),
                    "command": {"entrypoint": sized(cfg.get("Entrypoint")), "cmd": sized(cfg.get("Cmd"))}, "environment": sized(cfg.get("Env")),
                    "history_entries": count_of(doc.get("history")), "layers": len(diffs)})
        missing = 0
        for index, (diff, chain) in enumerate(zip(diffs, chain_ids(diffs))):
            run.check()
            chain_hex = chain.split(":")[-1]
            entry_dir = os.path.join(layerdb, chain_hex)
            state, cache_id, size = "missing", None, None
            if os.path.isdir(entry_dir) and not os.path.islink(entry_dir):
                state = "present"
                cache_file = os.path.join(entry_dir, "cache-id")
                try:
                    cache = read_head(cache_file, 200).decode("utf-8", "replace").strip()
                    cache_id = cache if re.fullmatch(r"[0-9a-f]{64}", cache) else None
                except OSError as exc:
                    state = "present (no cache-id)"
                    if not isinstance(exc, FileNotFoundError):
                        run.error(cache_file, describe(exc))
                size_file = os.path.join(entry_dir, "size")
                try:
                    raw = read_head(size_file, 30).decode("ascii", "replace").strip()
                    size = int(raw) if raw.isdigit() and len(raw) < 16 else None
                except OSError as exc:
                    if not isinstance(exc, FileNotFoundError):
                        run.error(size_file, describe(exc))
            else:
                missing += 1
            run.layer_total += 1
            run.layers_page.add({"runtime": "docker", "image_id": "sha256:" + name, "index": index, "diff_id": diff, "chain_id": chain, "layerdb": state,
                                 "overlay_directory": cache_id, "size_bytes": size, "layerdb_file": entry_dir})
        run.missing_layers += missing
        row["layers_missing"] = missing
        run.images[("docker", "sha256:" + name)] = row
        row["containers_using"] = run.container_images.get(("docker", "sha256:" + name), 0)
        run.entry(row)


def docker_root(run, base_rel):
    base = locate(run, base_rel)
    if base is None:
        return
    before = run.seq
    cdir = os.path.join(base, "containers")
    run.known_images = set()
    content = os.path.join(base, "image", "overlay2", "imagedb", "content", "sha256")
    try:
        if os.path.isdir(content) and not os.path.islink(content):
            run.known_images = {"sha256:" + n for n in names_of(run, content) if re.fullmatch(r"[0-9a-f]{64}", n)}
    except OSError as exc:
        run.walk_errors.append({"path": content, "error": describe(exc)})
    try:
        if os.path.isdir(cdir) and not os.path.islink(cdir):
            for cid in names_of(run, cdir):
                run.check()
                if ID64.fullmatch(cid) and os.path.isdir(os.path.join(cdir, cid)) and not os.path.islink(os.path.join(cdir, cid)):
                    docker_container(run, base, cid)
                elif not ID64.fullmatch(cid):
                    run.not_supported("docker", os.path.join(cdir, cid), "not a container id (64 hexadecimal digits): not read")
        else:
            run.census(base_rel + "/containers", "missing or not a directory")
        docker_images(run, base)
        for dirname in ("volumes", "overlay2", "buildkit", "plugins"):
            if os.path.lexists(os.path.join(base, dirname)):
                run.census("%s/%s" % (base_rel, dirname), "present: not read by this tool (see container_layers for overlay2)")
    except Overtime:
        run.census(base_rel, "stopped: the inventory ended inside this place (see partial_reason)", entries=run.seq - before)
        raise
    run.census(base_rel, "read", entries=run.seq - before)


def json_list(run, path):
    doc, why = read_json(run, path) if os.path.lexists(path) else (None, "missing")
    if isinstance(doc, list):
        return [clean(x) for x in doc if isinstance(x, dict)], len(doc), None
    return [], 0, why if doc is None else "the top level is not a list"


def podman_root(run, rel, owner=None):
    base = locate(run, rel)
    if base is None:
        return
    before = run.seq
    layer_sets = {}
    layers, total, why = json_list(run, os.path.join(base, "overlay-layers", "layers.json"))
    for item in layers:
        if isinstance(item.get("id"), str) and ID64.fullmatch(item["id"]):
            layer_sets[item["id"]] = item
    images, img_total, why_i = json_list(run, os.path.join(base, "overlay-images", "images.json"))
    containers, ctr_total, why_c = json_list(run, os.path.join(base, "overlay-containers", "containers.json"))
    for item in images[:MAX_LISTED_NAMES]:
        run.check()
        iid = item.get("id") if isinstance(item.get("id"), str) and ID64.fullmatch(item.get("id")) else None
        layer = item.get("layer") if isinstance(item.get("layer"), str) else None
        names = [n for n in item.get("names", []) if isinstance(n, str)] if isinstance(item.get("names"), list) else []
        run.entry({"kind": "image", "runtime": "podman", "storage": rel, "owner_home": owner, "image_id": iid, "created": shown_stamp(item.get("created")),
                   "references": [n for n in names if PLAIN.fullmatch(n)][:MAX_SHOWN], "reference_count": len(names), "top_layer": layer if layer and ID64.fullmatch(layer) else None,
                   "top_layer_listed": bool(layer and layer in layer_sets), "errors": [] if iid else ["no usable id"]})
    for item in layers[:MAX_LISTED_NAMES]:
        run.check()
        parent = item.get("parent") if isinstance(item.get("parent"), str) else None
        run.layers_page.add({"runtime": "podman", "storage": rel, "layer_id": item.get("id") if isinstance(item.get("id"), str) and ID64.fullmatch(item.get("id")) else None,
                             "parent": parent if parent and ID64.fullmatch(parent) else None, "parent_listed": bool(parent and parent in layer_sets) if parent else None,
                             "created": shown_stamp(item.get("created")), "diff_size": item.get("diff-size") if isinstance(item.get("diff-size"), int) and not isinstance(item.get("diff-size"), bool) else None})
        run.layer_total += 1
        if parent and parent not in layer_sets:
            run.missing_layers += 1
    for item in containers[:MAX_LISTED_NAMES]:
        run.check()
        cid = item.get("id") if isinstance(item.get("id"), str) and ID64.fullmatch(item.get("id")) else None
        names = [n for n in item.get("names", []) if isinstance(n, str)] if isinstance(item.get("names"), list) else []
        meta = item.get("metadata")
        meta_obj = None
        if isinstance(meta, str) and len(meta) <= MAX_JSON:
            try:
                meta_obj = json.loads(meta)
            except (ValueError, RecursionError):
                meta_obj = None
        layer = item.get("layer") if isinstance(item.get("layer"), str) else None
        row = {"kind": "container", "runtime": "podman", "storage": rel, "owner_home": owner, "container_id": cid,
               "names": [n for n in names if PLAIN.fullmatch(n)][:MAX_SHOWN], "image_id": item.get("image") if isinstance(item.get("image"), str) and ID64.fullmatch(item.get("image")) else None,
               "created": shown_stamp(item.get("created")), "layer": layer if layer and ID64.fullmatch(layer) else None, "layer_listed": bool(layer and layer in layer_sets),
               "metadata": {"parsed": isinstance(meta_obj, dict), "bytes": blen(meta) if isinstance(meta, str) else None},
               "config_file": os.path.join(base, "overlay-containers", cid, "userdata", "config.json") if cid else None, "errors": []}
        spec_path = row["config_file"]
        if spec_path and os.path.lexists(spec_path):
            spec, why_s = read_json(run, spec_path)
            if isinstance(spec, dict):
                proc = spec.get("process") if isinstance(spec.get("process"), dict) else {}
                row["command"] = {"args": sized(proc.get("args"))}
                row["environment"] = sized(proc.get("env"))
                if run.text.enabled:
                    run.text.add({"record_type": "container", "runtime": "podman", "container_id": cid, "args": proc.get("args"), "env": proc.get("env")})
            else:
                row["errors"].append("userdata/config.json: %s" % why_s)
        if not cid:
            row["errors"].append("no usable id")
        run.entry(row)
    for label, count, w in (("layers.json", total, why), ("images.json", img_total, why_i), ("containers.json", ctr_total, why_c)):
        if w and w != "missing":
            run.error(os.path.join(base, label), w)
    run.census(rel, "read", entries=run.seq - before, layers=total, images=img_total, containers=ctr_total)


def kubernetes_logs(run, rel):
    base = locate(run, rel)
    if base is None:
        return
    before = run.seq
    try:
        for pod in names_of(run, base):
            run.check()
            pod_path = os.path.join(base, pod)
            m = POD_DIR.fullmatch(pod)
            if not m or not os.path.isdir(pod_path) or os.path.islink(pod_path):
                run.not_supported("kubernetes", pod_path, "not a <namespace>_<pod>_<uid> directory")
                continue
            for container in names_of(run, pod_path):
                run.check()
                cpath = os.path.join(pod_path, container)
                if not os.path.isdir(cpath) or os.path.islink(cpath):
                    continue
                logs = []
                for name in names_of(run, cpath):
                    if re.fullmatch(r"[0-9]{1,6}\.log(?:\.[0-9A-Za-z\-]{1,40})?(?:\.gz)?", name):
                        logs.append(log_inventory(run, os.path.join(cpath, name), "cri"))
                run.entry({"kind": "pod_container", "runtime": "kubernetes", "namespace": m.group(1), "pod": m.group(2), "pod_uid": m.group(3),
                           "container": container if PLAIN.fullmatch(container) else None, "container_bytes": blen(container), "directory": cpath,
                           "restarts_seen": len(logs), "logs": [{k: v for k, v in x.items()} for x in logs[:MAX_SHOWN]], "logs_total": len(logs),
                           "node_scope": "this node's log files only: the pod's spec, its owner and the control plane's records are not here"})
    except Overtime:
        run.census(rel, "stopped: the inventory ended inside this place (see partial_reason)", entries=run.seq - before)
        raise
    run.census(rel, "read", entries=run.seq - before)


def containerd_root(run, rel):
    base = locate(run, rel)
    if base is None:
        return
    meta = os.path.join(base, "io.containerd.metadata.v1.bolt", "meta.db")
    if os.path.lexists(meta):
        try:
            size = os.lstat(meta).st_size
        except OSError:
            size = None
        run.not_supported("containerd", meta, "containerd's bolt metadata database cannot be read with the standard library: its containers, images, snapshots and namespaces are not listed")
        run.entry({"kind": "unsupported", "runtime": "containerd", "file": meta, "bytes": size, "state": "unsupported",
                   "why": "bolt database: not read. The rest of var/lib/containerd (snapshots, content) is not listed either; this is not a statement that nothing ran under containerd"})
    run.census(rel, "read" if os.path.lexists(meta) else "no bolt metadata database in it")


def homes_of(run):
    homes = []
    home_dir = os.path.join(run.root, "home")
    try:
        if os.path.isdir(home_dir) and not os.path.islink(home_dir):
            homes += ["home/" + n for n in names_of(run, home_dir)]
    except OSError as exc:
        run.error(home_dir, describe(exc))
    homes.append("root")
    return homes


# BEGIN LINUX IMAGE
# ---- A disk image given where this tool reads a file or an extracted root (the same in every such tool of this pack) ----

# What linux_triage takes as an image: these first bytes, or one of its names with a boot sector's signature at 510.
IMAGE_MAGIC = ((0, b"EVF\x09\x0d\x0a\xff\x00"), (0, b"EVF2\x0d\x0a\x81\x00"), (0, b"vhdxfile"), (0, b"conectix"), (0, b"KDMV"),
               (0, b"QFI\xfb"))
IMAGE_SUFFIXES = (".e01", ".ex01", ".dd", ".img", ".raw", ".vhd", ".vhdx", ".vmdk", ".qcow2")
IMAGE_ROUTES = ("this tool reads the files of an extracted file system, not a disk image. For a Linux image: the catalogue's "
                "linux-target artefacts (catalog/README.md says where) hold what dissect.target parsed from it, LVM included; "
                "linux_triage reads the image itself as a job; and to give this tool the files, extract them first in a job, a "
                "directory at a time, with target-fs -q <image> cp <dir> -o \"$OUT/root<dir>\" (for example /etc, /var/log, "
                "/var/spool/cron, /home and /root), then pass the extracted path under store/jobs/<id>/out/root/. The copies "
                "carry the time of extraction as their modification time, and links are not copied as links.")


def refuse_disk_image(path, key):
    """A regular file whose first bytes, or whose name and boot-sector signature, say disk image is refused with the routes
    that read one; anything else goes on to this tool's own checks. It reads 512 bytes and nothing else. A path the system
    cannot take (a NUL in it, a lone surrogate) is left to those checks too, which answer it in JSON."""
    try:
        if os.path.islink(path) or not stat.S_ISREG(os.stat(path).st_mode):
            return
        # Without blocking: a regular file whose read waits (/proc/kmsg, read as root) answers at once, and is no image.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            head = os.read(fd, 512)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        return
    named = path.lower().endswith(IMAGE_SUFFIXES)
    if any(head[o:o + len(m)] == m for o, m in IMAGE_MAGIC) or (named and head[510:512] == b"\x55\xaa"):
        fail("%s is a disk image: %s" % (key, IMAGE_ROUTES), **{key: path})
# END LINUX IMAGE


def main():
    args = read_args()
    root = want_str(args, "root", "root is required: the directory of an extracted Linux root (var/, home/, ...)")
    runtimes = want_runtimes(args)
    storage = want_dirs(args, "storage_roots")
    limit = want_limit(args)
    write_text = want_flag(args, "write_text")
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    try:
        if os.path.islink(root) or not os.path.isdir(root):
            if not os.path.exists(root):
                fail("no such directory", root=root)
            fail("root must be a directory of the evidence and not a link, a file or a device", root=root)
    except (OSError, ValueError) as exc:
        fail("the root cannot be read: %s" % describe(exc), root=root)
    refuse_disk_image(root, "root")
    try:
        text = TextFile(TEXT_NAME, write_text, "JSON Lines, mode 0600: each container's command, arguments, environment, labels and binds as the runtime stored them", flag="write_text")
    except TextRefused as exc:
        fail(str(exc))
    STATE["text"] = text
    entries = LosslessPage(TOOL, "entries", limit)
    layers = LosslessPage(TOOL, "layers", INLINE_LIST)
    logs = LosslessPage(TOOL, "logs", INLINE_LIST)
    deadline = time.monotonic() + seconds
    run = Run(root, text, entries, layers, logs, deadline, seconds)
    stopped = None
    storage_rel = []
    for item in storage:
        full = item if os.path.isabs(item) else os.path.join(root, item)
        if not inside(root, full):
            fail("storage_roots must name directories inside the root: a path outside it is never read", path=item)
        storage_rel.append(os.path.relpath(full, root))
    try:
        if "docker" in runtimes:
            docker_root(run, "var/lib/docker")
        if "podman" in runtimes:
            podman_root(run, "var/lib/containers/storage")
            for home in homes_of(run):
                run.check()
                podman_root(run, "%s/.local/share/containers/storage" % home, owner=home)
        if "kubernetes" in runtimes:
            kubernetes_logs(run, "var/log/pods")
        if "containerd" in runtimes:
            containerd_root(run, "var/lib/containerd")
        for rel in storage_rel:
            run.check()
            base = os.path.join(root, rel)
            if os.path.isdir(os.path.join(base, "overlay-containers")) or os.path.isdir(os.path.join(base, "overlay-layers")):
                podman_root(run, rel)
            elif os.path.isdir(os.path.join(base, "containers")) or os.path.isdir(os.path.join(base, "image")):
                docker_root(run, rel)
            else:
                run.census(rel, "a storage root that holds neither Docker's containers/ and image/ nor containers/storage's overlay-*: not read")
    except Overtime:
        stopped = "max_seconds (%s) passed: the inventory stopped there and the places after it were not looked in" % seconds
    text.close()
    pages = {"entries": entries.finish(), "layers": layers.finish(), "logs": logs.finish(), "locations": run.locations.finish()}
    listed = {}
    for key, items in (("read_errors", run.read_errors), ("walk_errors", run.walk_errors), ("unsupported", run.unsupported)):
        pages[key] = items.settle()
        listed[key] = {"total": items.page.total, "shown": list(items)}
    problems = []
    if stopped:
        problems.append(stopped)
    if run.partial_reason:
        problems.append(run.partial_reason)
    if pages["read_errors"]["matched"] or pages["walk_errors"]["matched"]:
        problems.append("%d file(s) or director(ies) could not be read or parsed (see read_errors, walk_errors)" % (pages["read_errors"]["matched"] + pages["walk_errors"]["matched"]))
    if pages["unsupported"]["matched"]:
        problems.append("%d place(s) hold a layout this tool does not read (see unsupported)" % pages["unsupported"]["matched"])
    if run.missing_layers:
        problems.append("%d layer(s) an image names are not in the layer store (see layers)" % run.missing_layers)
    capped = capped_why(pages, text)
    if capped:
        problems.append(capped)
    outcome = status_of(not problems, False, "every place named in locations was looked in and every file in it was read and parsed",
                        "; ".join(problems) or "partial", "")
    users = {}
    for (runtime, image_id), count in run.container_images.items():
        users[image_id] = count
    out = {"parser": PARSER, "root": root, **outcome, "runtimes_asked": runtimes, "entries_total": pages["entries"]["matched"], "by_kind": run.kinds,
           "locations_tried": pages["locations"]["matched"], "locations_by_state": run.by_state,
           "locations": {"shown": run.locations.page, "all": pages["locations"].get("all_results"), "note": "every place tried is in pages.locations"},
           "layer_summary": {"total": run.layer_total, "missing_or_unlisted": run.missing_layers, "where": "pages.layers"},
           "log_summary": {"files": run.log_files, "where": "pages.logs (and each container's own list)"},
           "images_used_by_containers": {"distinct_images": len(users), "most_containers_on_one_image": max(users.values()) if users else 0,
                                         "note": "containers on one image share its layers; a container's image_id names it"},
           "containerd": "unsupported: its bolt metadata database is listed and not read" if "containerd" in runtimes else "not asked for",
           **listed, "text": text.summary(), "entries": entries.page, "layers": layers.page, "logs": logs.page, "pages": pages, "truncated": pages["entries"]["truncated"],
           "note": "this is what the host's runtime files say was created, and when: it does not show that a container ran, what it did, or what its processes saw. "
                   "Commands, arguments, environments, labels and log text are lengths; they are in the evidence at the files named, and in the text file when write_text was asked."}
    if stopped:
        out["stopped_because"] = stopped
    STATE["answering"] = True
    print(json.dumps(out, indent=2))


def last_resort(exc):
    if STATE.get("answering"):
        os._exit(1)
    STATE["answering"] = True
    kept = {}
    for page in STATE["pages"]:
        try:
            shown = page.stop_here()
        except BaseException:  # noqa: BLE001
            shown = None
        if shown:
            kept[page.key] = shown
    text = STATE["text"]
    shown_text = getattr(text, "shown", None) if text is not None and getattr(text, "written", 0) else None
    if text is not None:
        try:
            text.close()
        except BaseException:  # noqa: BLE001
            pass
    try:
        sys.stdout.write(json.dumps({"parser": PARSER, "error": "the tool stopped on an unexpected %s" % type(exc).__name__, "status": "failed",
                                     "status_basis": "an internal error ended the tool before it built an answer: nothing here is a complete result",
                                     "paging_files_kept": kept, "text_file_kept": shown_text}) + "\n")
        sys.stdout.flush()
    except BaseException:  # noqa: BLE001
        pass
    os._exit(1)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - the last resort
        last_resort(exc)
