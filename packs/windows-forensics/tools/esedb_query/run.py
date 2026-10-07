#!/usr/bin/env python3
"""Read an ESE (Extensible Storage Engine) database as tables.

The gap this closes is recorded in a delivered report's own words: "No
`esedbexport`: WebCacheV01.dat and spartan.edb could not be parsed as
tables". That file appears in four of the fifteen measured runs across 144
trace events and was never once read as tables. The same wrapper opens
SRUDB.dat (the System Resource Usage Monitor) and Edge's database, so one
tool covers three artefacts that a Windows case asks for every time.

Backed by `esedbexport` (libesedb), which writes one TSV per table into a
directory. This wraps it: list the tables, or read one, and return JSON either
way. It exports TABLES, as text: it does not decode what a table means (a SRUM
table is not joined to the application or user it names, a WebCache container
is not resolved to a browser), and it does not read an ESE log.

The export is made once per database, into `esedb-export/<sha256 of the database,
first 16 hex>/` under the job's $OUT (or the agent's own work directory), with the
exporter's whole standard output and standard error in files beside it and an
`export-manifest.json` that records the database's digest, the exporter's version, argv
and exit status and every table file. A later call with the same database reuses a
complete export. An exporter that exits non-zero, or is stopped by its time limit, leaves a
PARTIAL export: the answer says status: partial, never lists it as the database's tables,
and keeps the logs. A table name that matches more than one export file is refused with
the candidates, never resolved by taking the first. An earlier export is reused only when its
manifest was written by this version of the tool, its exit status was 0, and every table file
it lists is on disk with the size it recorded and nothing else is there; otherwise it is made again.

SENSITIVE OUTPUT. The export directory holds every table whole, so it holds whatever the database
holds (a WebCache URL with a token in it, a SRUM user, the password material of an Active Directory
database): it is made with mode 0700 (its files 0600), it is a sensitive output of the job that made it, and
it is cited by file and table, never by value. The answer withholds, in the rows it returns, the cells
of a column whose name says password, secret, token, encrypted, credential, a card, an IBAN or an SSN,
and of the attributes of an Active Directory datatable that carry password hashes, their history,
supplemental credentials and the password encryption keys, replacing each by a marker that holds only its
length (`columns_withheld`); and the secrets of every URL in a cell (a token or password in its query
string, fragment or user-info), listed in `url_secrets_withheld`. A URL's text is written whole only with
`write_url_secrets: true`, in a job run with secret_output: true, to a file under $OUT of mode 0600; the
request is refused anywhere else. Binary cells are exported as text by esedbexport and are not inspected.
"""
import csv
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


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


PARSER = "esedb_query/6"
MAX_EXPORT_SECONDS = 270


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


# ---- URL secrets: one design in browser_history, utf16_urls and esedb_query (a test holds the three copies identical)
#
# A URL can carry a session token, an API key or a password in its query string, its fragment or its user-info. Every URL in an
# answer has those values replaced by a marker that holds only their length ("[withheld: 12 characters]"), and the answer says how
# many were withheld, of what kind and where. The text is written whole only when the caller asks (write_url_secrets: true), only in
# a job (JOB_ID and OUT), to a file of mode 0600 that is created first and never replaced. NOT covered: a secret in a URL's path or
# title, a URL whose scheme this does not see, and a secret in free text.
import urllib.parse


class SecretValuesRefused(Exception):
    pass


def describe(exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    return "%s: %s" % (type(exc).__name__, exc)


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it (the secret-safe pattern of docs/packs.md)."""

    def __init__(self, enabled, tool, flag, name):
        self.enabled = enabled
        self.tool = tool
        self.flag = flag
        self.written = 0
        self._fh = None
        self.shown = None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            raise SecretValuesRefused(
                "%s is refused outside a job: a value written here would be an ordinary file, not a sealed secret output. "
                "Run this as job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, tool)
            )
        path = Path(out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        # Created now, before anything is read: a file or a link already at that name is refused by name at once (O_EXCL does
        # not follow a link, a dangling one included). With nothing found it stays an empty file, mode 0600.
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if self._fh is None:
            return
        text = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=True)
        self._fh.write(text + "\n")
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


URL_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.\-]{1,15}://[^\s\"'<>\\^`{|}\x00-\x1f]+")
SECRET_SUBSTRINGS = ("token", "secret", "passw", "pwd", "auth", "bearer", "session", "signature", "credential", "assertion",
                     "jwt", "csrf", "xsrf", "ticket", "apikey", "accesskey")
SECRET_WORDS = {"sig", "sid", "key", "code", "pass", "otp", "sas", "saml", "hmac"}


def secret_parameter(name):
    """A query or fragment parameter whose name says its value is a credential: by a whole word (key, sig, code) or a substring (token)."""
    lowered = urllib.parse.unquote(name).lower()
    if any(s in lowered for s in SECRET_SUBSTRINGS):
        return True
    return any(w.lower() in SECRET_WORDS for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", urllib.parse.unquote(name)))


def url_marker(value):
    return "[withheld: %d characters]" % len(value)


def mask_parameters(text, kind, found, url):
    parts = re.split(r"([&;])", text)
    for i, part in enumerate(parts):
        if "=" not in part or part in ("&", ";"):
            continue
        key, value = part.split("=", 1)
        if value and secret_parameter(key):
            found.append((kind, key, value, url))
            parts[i] = key + "=" + url_marker(value)
    return "".join(parts)


def mask_url(url):
    """The URL with its secrets replaced by markers, and what was withheld: [(kind, parameter, value, url)]."""
    found = []
    start = url.index("://") + 3
    rest = url[start:]
    boundary = re.search(r"[/?#]", rest)
    cut = boundary.start() if boundary else len(rest)
    authority, tail = rest[:cut], rest[cut:]
    if "@" in authority:
        userinfo, host = authority.rsplit("@", 1)
        if ":" in userinfo:
            user, password = userinfo.split(":", 1)
            if password:
                found.append(("userinfo_password", None, password, url))
                userinfo = user + ":" + url_marker(password)
        elif len(userinfo) >= 16 and re.fullmatch(r"[A-Za-z0-9_.~%\-]+", userinfo):
            found.append(("userinfo_token", None, userinfo, url))
            userinfo = url_marker(userinfo)
        authority = userinfo + "@" + host
    before_hash, hash_mark, fragment = tail.partition("#")
    path, query_mark, query = before_hash.partition("?")
    if query:
        query = mask_parameters(query, "query_parameter", found, url)
    if "=" in fragment:
        fragment = mask_parameters(fragment, "fragment_parameter", found, url)
    return url[:start] + authority + path + query_mark + query + hash_mark + fragment, found


def mask_text(text):
    """`text` with the secrets of every URL in it withheld, and what was withheld."""
    if "://" not in text:
        return text, []
    found = []

    def one(match):
        masked, withheld = mask_url(match.group(0))
        found.extend(withheld)
        return masked

    return URL_RE.sub(one, text), found


class UrlSecrets:
    """Counts and locates what mask_text withheld; the values themselves go only to `values` (a SecretValues)."""

    def __init__(self, values, tool, key, limit):
        self.values = values
        self.count = 0
        self.by_kind = {}
        self.by_parameter = {}
        self.locators = LosslessPage(tool + "-url-secrets", key, limit)

    def mask(self, text, where):
        masked, found = mask_text(text)
        for kind, parameter, value, url in found:
            self.count += 1
            finding_id = "U%06d" % self.count
            self.by_kind[kind] = self.by_kind.get(kind, 0) + 1
            if parameter is not None:
                self.by_parameter[parameter] = self.by_parameter.get(parameter, 0) + 1
            self.locators.add({"finding_id": finding_id, "kind": kind, "parameter": parameter, "length": len(value), **where})
            self.values.add(finding_id, {"kind": kind, "parameter": parameter, **where, "url": url}, value)
        return masked

    def summary(self):
        page = self.locators.finish()
        return {
            "count": self.count,
            "by_kind": self.by_kind,
            "by_parameter": self.by_parameter,
            "locators": self.locators.page,
            "locators_page": page,
            "marker": "a withheld value is replaced by [withheld: N characters] (N is its length in the URL's own text); "
                      "where it was, its kind and its length are in locators; the value is not in this answer",
            "not_covered": "a secret in a URL's path, in a title, in free text, or in a URL whose scheme is not followed by ://",
        }
# ---- end of URL secrets


# Columns whose cells are withheld from the rows an answer returns: by name, and the attributes of an Active Directory datatable
# (NTDS.dit is an ESE database) that carry password hashes, their history, supplemental credentials and the password encryption keys.
CREDENTIAL_ATTRIBUTES = {"attk589914", "attk589879", "attk589918", "attk589984", "attk590689", "attk589949"}
SENSITIVE_NAME = re.compile(r"passw(or)?d|passwd|\bpwd\b|secret|token|api_?key|private_?key|encrypted|card_?number|cvc|cvv|bearer|credential", re.I)
CARD_WORDS = {"cc", "cvc", "cvv", "cvc2", "pin", "ssn", "iban", "card", "cards", "creditcard", "cardnumber", "ccnumber"}


def words(name):
    return {w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", name)}


def withheld_column(name):
    """Why the cells of a column are withheld, or None."""
    if name.lower() in CREDENTIAL_ATTRIBUTES:
        return "directory_credential_attribute"
    if SENSITIVE_NAME.search(name) or CARD_WORDS & words(name):
        return "name"
    return None


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def work_root():
    """Where exports live, and the name they are cited by: $OUT/esedb-export in a job, else the agent's own directory."""
    out, job = os.environ.get("OUT"), os.environ.get("JOB_ID")
    if job and out:
        return Path(out) / "esedb-export", "store/jobs/%s/out/esedb-export" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
    d = Path("work") / re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool") / "esedb-export"
    return d, str(d)


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def exporter_version():
    try:
        p = subprocess.run(["esedbexport", "-V"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        lines = p.stdout.decode("utf-8", "replace").strip().splitlines()
        return lines[0].strip() if p.returncode == 0 and lines else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def table_files(export):
    """The export's files, by table name. libesedb names each export file <table>.<its index>
    (Containers.4, Container_1.6): the table is the part before the index, the name an agent
    knows it by."""
    files = {}
    for f in sorted(os.listdir(export)):
        full = os.path.join(export, f)
        if os.path.isfile(full) and not os.path.islink(full):
            base = f[: -len(".csv")] if f.endswith(".csv") else f
            m = re.fullmatch(r"(.+)\.(\d+)", base)
            files[f] = m.group(1) if m else base
    return files


def reusable(record, base, digest, path):
    """An earlier export is trusted only when this tool wrote its manifest, it finished, and its files are the files it lists."""
    try:
        if record.get("parser") != PARSER or record.get("db_sha256") != digest or record.get("db_bytes") != os.path.getsize(path):
            return False
        if record.get("exporter_exit_status") != 0 or record.get("timed_out"):
            return False
        export = base / "db.export"
        if export.is_symlink() or not export.is_dir():
            return False
        files = record.get("files")
        if not isinstance(files, dict) or not files:
            return False
        recorded = {f: [v["table"], v["bytes"]] for f, v in files.items()}
        on_disk = {}
        for f in os.listdir(export):
            st = os.lstat(os.path.join(export, f))
            on_disk[f] = st.st_size if stat.S_ISREG(st.st_mode) else None
        if {f: v[1] for f, v in recorded.items()} != on_disk:
            return False
        if {f: v[0] for f, v in recorded.items()} != table_files(str(export)):
            return False
        return all((base / record[k]).is_file() for k in ("stdout_file", "stderr_file"))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return False


def make_export(path, digest, timeout, root):
    """Run esedbexport once into root/<digest[:16]>/, or reuse a complete export of the same bytes.
    Returns (record, reused). The record is the export-manifest.json content. The export holds every table
    whole, so its directory is 0700 and its files 0600."""
    base = root / digest[:16]
    manifest_path = base / "export-manifest.json"
    if base.is_symlink():
        fail("the export directory is a link, which this tool does not follow", status="failed", export_dir=str(base))
    if manifest_path.is_file():
        try:
            record = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            record = None
        if isinstance(record, dict) and reusable(record, base, digest, path):
            return record, True
        shutil.rmtree(base, ignore_errors=True)       # a partial, unreadable or changed earlier export is made again
    if base.exists():
        shutil.rmtree(base, ignore_errors=True)       # a directory with no manifest is an export that was stopped: made again
    old_umask = os.umask(0o077)
    try:
        try:
            base.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = str(base / "db")
            out_file, err_file = base / "esedbexport.stdout.txt", base / "esedbexport.stderr.txt"
            # -t names the export root; libesedb appends ".export". No -q: the esedbexport Debian
            # ships (20181229) has none, and refused the call.
            argv = ["esedbexport", "-t", target, path]
            def interrupted(signum):
                print(json.dumps({"error": "stopped by signal %d before esedbexport finished" % signum, "status": "interrupted", "signal": signum,
                                  "export_dir": str(base),
                                  "note": "The export is not complete and has no manifest; the next call makes it again."}), flush=True)

            STATE["last_word"] = interrupted
            with open(out_file, "wb") as so, open(err_file, "wb") as se:
                proc = spawn(argv, stdout=so, stderr=se)
                rc, timed_out = wait_for(proc, timeout)
            export = target + ".export"
            files = {}
            if os.path.isdir(export):
                files = {f: {"table": t, "bytes": os.path.getsize(os.path.join(export, f))} for f, t in table_files(export).items()}
            record = {
                "parser": PARSER,
                "db": path,
                "db_bytes": os.path.getsize(path),
                "db_sha256": digest,
                "exporter_argv": argv,
                "exporter_version": exporter_version(),
                "exporter_exit_status": rc,
                "timed_out": timed_out,
                "export_dir": "db.export" if os.path.isdir(export) else None,
                "stdout_file": out_file.name,
                "stderr_file": err_file.name,
                "files": files,
            }
            manifest_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        except OSError as exc:
            fail("the export could not be made: its directory could not be created or written, or esedbexport could not be run",
                 status="failed", export_dir=str(base), reason=describe(exc))
    finally:
        os.umask(old_umask)
    # Whatever the exporter's own umask made, nothing in the export is readable by anyone but its owner.
    try:
        for dirpath, dirnames, filenames in os.walk(base):
            os.chmod(dirpath, 0o700)
            for name in filenames:
                full = os.path.join(dirpath, name)
                if not os.path.islink(full):
                    os.chmod(full, 0o600)
    except OSError:
        pass
    return record, False


def main():
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the .dat or .edb file to read", path=args.get("path"))
    if not os.path.isfile(path):
        fail("no such file", path=path)

    table = args.get("table")
    if table is not None and not isinstance(table, str):
        fail("table must be a string", table=table)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))
    limit = min(limit, 20000)
    timeout = args.get("export_timeout_seconds", 240)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
        fail("export_timeout_seconds must be a positive integer", export_timeout_seconds=args.get("export_timeout_seconds"))
    timeout = min(timeout, MAX_EXPORT_SECONDS)       # the tool's own limit is 300 s: esedbexport stops before it

    write_url_secrets = args.get("write_url_secrets", False)
    if not isinstance(write_url_secrets, bool):
        fail("write_url_secrets must be true or false")

    if shutil.which("esedbexport") is None:
        fail(
            "esedbexport is not on PATH",
            hint="brew install libesedb, or apt-get install libesedb-utils; "
            "scripts/toolbox.sh reports it with the dfir set",
        )

    try:
        values = SecretValues(write_url_secrets, "esedb_query", "write_url_secrets", "esedb_query-url-secrets.jsonl")
    except SecretValuesRefused as exc:
        fail(str(exc))
    url_secrets = UrlSecrets(values, "esedb_query", [path, table, limit], limit)

    root, shown_root = work_root()
    try:
        full = sha256_of(path)
    except OSError as exc:
        values.close()
        fail("the database could not be read: nothing was exported", path=path, status="failed", reason=describe(exc))
    digest = full[:16]
    # The directory is named by the first 16 hex digits; the manifest holds the whole digest.
    record, reused = make_export(path, full, timeout, root)
    base = root / digest
    export = base / "db.export"
    shown = "%s/%s" % (shown_root, digest)
    complete = record["exporter_exit_status"] == 0 and not record["timed_out"]
    logs = {"stdout_file": "%s/%s" % (shown, record["stdout_file"]), "stderr_file": "%s/%s" % (shown, record["stderr_file"])}
    try:
        stderr_text = (base / record["stderr_file"]).read_text(encoding="utf-8", errors="replace")
    except OSError:
        stderr_text = ""
    common = {
        "parser": PARSER,
        "path": path,
        "db_sha256": full,
        "exporter_version": record["exporter_version"],
        "exporter_exit_status": record["exporter_exit_status"],
        "timed_out": record["timed_out"],
        "export_reused": reused,
        "export_manifest": "%s/export-manifest.json" % shown,
        "export_dir": "%s/db.export" % shown,
        "export_dir_sensitive": "the export directory holds every table whole, including the cells and URL secrets this answer withholds: "
                               "it is mode 0700, a sensitive output of the job that made it, and is cited by file and table, never by value",
        **logs,
    }
    if not os.path.isdir(str(export)) or not record["files"]:
        fail("esedbexport produced no tables",
             **{**common, "status": "failed", "stderr_first_lines": stderr_text.strip().splitlines()[:10]})

    files = {f: v["table"] for f, v in record["files"].items()}
    names = sorted(set(files.values()))
    if not complete:
        common.update({
            "status": "partial",
            "complete": False,
            "warning": "esedbexport %s: this is a PARTIAL export, and a table missing from it, or short, is not absent from the database; "
                       "the exporter's own output is in stdout_file and stderr_file" % ("was stopped by its time limit" if record["timed_out"] else "exited with status %s" % record["exporter_exit_status"]),
            "stderr_first_lines": stderr_text.strip().splitlines()[:10],
        })
    else:
        common.update({"status": "complete", "complete": True})

    if table is None:
        sizes = {}
        for f, name in files.items():
            sizes[name] = sizes.get(name, 0) + record["files"][f]["bytes"]
        listing = {"tables_in_partial_export" if not complete else "tables": names}
        print(json.dumps({
            **common,
            **listing,
            "table_count": len(names),
            "bytes_per_table": sizes,
            "files": {f: v["bytes"] for f, v in record["files"].items()},
            "hint": "call again with table=<name> to read one; the export is kept and reused",
        }, indent=2))
        values.close()
        return

    # By its name, or by the export file's own name (index and all).
    wanted = table.lower()
    exact = sorted(f for f in files if wanted in (f.lower(), f.lower().removesuffix(".csv")))
    hits = exact or sorted(f for f, name in files.items() if name.lower() == wanted)
    if not hits:
        fail("no such table", table=table, tables=names, **{k: common[k] for k in ("status", "complete")})
    if len(hits) > 1:
        fail("the table name matches more than one export file; name one of them", table=table, candidates=hits)
    chosen = files[hits[0]]
    # Tab-separated, whatever the extension says.
    src = str(export / hits[0])

    # A cell can be megabytes (a SRUM or WebCache blob): the reader's default field limit would stop on it.
    csv.field_size_limit(min(sys.maxsize, 2 ** 31 - 1))
    rows = LosslessPage("esedb_query", [path, table, hits[0], full], limit)
    try:
        fh = open(src, "r", encoding="utf-8", errors="replace", newline="")
    except OSError as exc:
        values.close()
        fail("the exported table file could not be read", table=chosen, export_file=hits[0], status="failed", reason=describe(exc))
    with fh:
        reader = csv.reader(fh, delimiter="\t")
        header = next(reader, [])
        # Two columns of one name would overwrite each other in a row; the later ones are numbered.
        names_seen, columns = {}, []
        for h in header:
            names_seen[h] = names_seen.get(h, 0) + 1
            columns.append(h if names_seen[h] == 1 else "%s_%d" % (h, names_seen[h]))
        renamed = [c for c, h in zip(columns, header) if c != h]
        # Cells of a credential column are replaced by a marker that holds only their length; every other cell has the secrets of
        # its URLs withheld.
        why = {i: withheld_column(h) for i, h in enumerate(header)}
        withheld = {i: {"column": columns[i], "rule": r, "cells_withheld": 0, "total_length": 0} for i, r in why.items() if r}
        ordinal = 0
        for row in reader:
            ordinal += 1
            cells = {}
            for i, v in enumerate(row):
                name = columns[i] if i < len(columns) else "col%d" % i
                if i in withheld and v != "":
                    withheld[i]["cells_withheld"] += 1
                    withheld[i]["total_length"] += len(v)
                    v = "[withheld: %d characters]" % len(v)
                else:
                    v = url_secrets.mask(v, {"table": chosen, "row": ordinal, "column": name}) if "://" in v else v
                cells[name] = v
            rows.add({"_row": ordinal, **cells})
    page = rows.finish()
    print(json.dumps({
        **common,
        "table": chosen,
        "export_file": hits[0],
        "columns": header,
        "duplicate_columns_renamed": renamed,
        "rows": rows.page,
        "row_count": page["matched"],
        "row_ordinals": "_row is the 1-based position of the row in the exported table file",
        "columns_withheld": list(withheld.values()),
        "url_secrets_withheld": url_secrets.summary(),
        "secret_values": values.summary("JSON Lines, mode 0600: finding_id, kind, parameter, table, row, column, url (the whole text), value (the secret)"),
        **page,
    }, indent=2))
    values.close()


if __name__ == "__main__":
    main()
