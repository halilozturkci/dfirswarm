#!/usr/bin/env python3
"""Query an EVTX event log: filter its records and return them with named data fields.

What a run reports, separately: `records_examined` (every record the reader produced), `events_matched`
(records that parsed and passed every filter), `parse_errors` (records or chunk chains that could not be
read, each with its offset). An error row is never counted as a match, and an event log that could not be
read to its end says status: partial. Every matched event, with its whole XML, is kept in the result file
(JSON Lines) the answer names; the inline `events` is a page of `limit` of them.

Every row carries where it came from: `record_offset` (the byte offset of the record in the file),
`chunk_offset`, the EventRecordID, and `record_filetime` (the FILETIME in the record's header, as a decimal
string, with `record_time_utc` from it by integer arithmetic) beside `timestamp`, the SystemTime the XML
carries. The filters are `event_ids`, `contains` (a case-insensitive substring of the XML), the EventRecordID
range `start_record` to `end_record`, and `start_time` to `end_time`. A time is `YYYY-MM-DD`, then optionally
`THH`, `THH:MM`, `THH:MM:SS` or `THH:MM:SS.fffffff`, and from the hour on optionally `Z` or a numeric offset such as
`+03:00`; no zone means UTC. What it names is the span its precision gives (`2026-09-01` the whole day,
`2026-09-01T10:00` that minute): start_time is the beginning of its span, end_time the end of its. Each bound is
converted to UTC and compared with the SystemTime of the record as a number of 100 ns ticks, not as text. A word
(`yesterday`), a malformed time or a range that ends before it starts is refused, never answered with an empty list.
A record whose XML has no SystemTime cannot be placed in a time range: it is left out and counted under
`events_without_time_excluded`, and the run is partial.

The whole of the log is accounted for: `chunks_declared` (what the file header says the file holds),
`chunks_read` (what the reader gave), `bytes_expected` and `file_bytes`. A file shorter than its header says, or a
reader that gave fewer chunks than the header declares, is status partial with a problem naming both numbers: a log
cut short is not a log with no records.

The file is read to its end, not to the header's count: `chunks_in_file` is what the file holds, and a chunk past the declared count that
has an ElfChnk signature and passes the chunk-header checks is read (`chunk_beyond_declared: true` on its rows; `header_flags` and
`header_dirty` say whether the log was open and changed). A chunk whose string or template table loops or points outside the chunk is
not given to python-evtx, which follows those tables without end; the library is called under a timer per chunk, the run has a clock of
its own below the manifest's, and a stop signal ends it with a partial file that is named as one.

The XML is rendered by python-evtx; a record whose template it cannot expand is an error row, not a skip.
Event data can hold command lines and text typed into a command line, which can hold a secret: run it as a
job with secret_output: true when the log may.
"""
import datetime
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

PARSER = "evtx_query/4"
CHUNK_BYTES = 0x10000
DEADLINE_SECONDS = 57             # the manifest allows 60
FILE_MAGIC = b"ElfFile\x00"


# BEGIN SHARED PLACE
# The same text is in every windows-forensics tool that keeps a result file (a windows-forensics test holds the copies equal).
# A result file that is there is never replaced by another result: a file of the same bytes is named again, any other result takes the next free
# <stem>-<n><suffix>. The name is taken first, with an exclusive create, so a result written at the same moment cannot be replaced either.
def same_bytes(a, b):
    """Whether two files hold the same bytes (read in blocks, never whole)."""
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(1 << 20), fb.read(1 << 20)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there. The name is taken first, with an exclusive create, so a
    result written at the same moment cannot be replaced either. Returns the path that holds it."""
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        try:
            fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            if not os.path.islink(candidate) and same_bytes(tmp, candidate):
                os.unlink(tmp)
                return candidate
            continue
        os.close(fd)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
        return candidate
    raise OSError("no free name beside %s" % path)
# END SHARED PLACE


# BEGIN SHARED EVTX READ
# The same text is in evtx_query and evtx_carve (a windows-forensics test holds the copies equal). python-evtx follows a chunk's string and
# template tables without a bound: a table entry whose next pointer names itself never ends, and nothing in the library has a clock. So a
# chunk is checked before the library is given it (chain_problem), whatever else it holds is read under a timer of its own (chunk_guard,
# which raises ChunkTimeout inside the library and gives the chunk up), and the whole run has a clock below the manifest's (out_of_time).
# SIGTERM, SIGINT and SIGHUP are cooperative: inside the library they unwind it (Interrupted), elsewhere they are noted and the next
# check_stop() raises, so that a result file is closed between two rows and never in the middle of one.
import signal
import struct
import time

CHUNK_MAGIC = b"ElfChnk\x00"
CHUNK_SIZE = 65536
HEADER_BYTES = 0x80
CHUNK_SECONDS = 8
CLOCK = {"deadline": None}
STOP = {"signal": None, "in_library": False}


class ChunkTimeout(BaseException):
    """A chunk took longer than CHUNK_SECONDS to read. BaseException: a library that catches Exception does not swallow it."""


class Interrupted(BaseException):
    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


def set_deadline(seconds):
    CLOCK["deadline"] = time.monotonic() + seconds


def out_of_time():
    return CLOCK["deadline"] is not None and time.monotonic() > CLOCK["deadline"]


def _on_alarm(signum, _frame):
    raise ChunkTimeout()


def _on_signal(signum, _frame):
    if STOP["in_library"]:
        raise Interrupted(signum)
    STOP["signal"] = signum


def install_signal_handlers():
    signal.signal(signal.SIGALRM, _on_alarm)
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def check_stop():
    if STOP["signal"] is not None:
        raise Interrupted(STOP["signal"])


class chunk_guard:
    """`with chunk_guard():` the library is called under a CHUNK_SECONDS timer (and never longer than the run's clock has left); a stop
    signal unwinds it. Not for code that writes a result: that runs outside it."""

    def __enter__(self):
        left = CLOCK["deadline"] - time.monotonic() if CLOCK["deadline"] is not None else CHUNK_SECONDS
        check_stop()
        STOP["in_library"] = True
        signal.setitimer(signal.ITIMER_REAL, max(0.05, min(CHUNK_SECONDS, left)))
        return self

    def __exit__(self, *exc):
        signal.setitimer(signal.ITIMER_REAL, 0)
        STOP["in_library"] = False
        return False


def reject_signature(head):
    """Why the 128 bytes after an ElfChnk signature are not a chunk header, or None when they could be one. The layout is the format's (the
    libevtx notes on the EVTX chunk header): the first and last record numbers at 0x08 and 0x10, the header size (0x80) at 0x28, the offset
    of the last record at 0x2C and of the free space at 0x30, each inside the 64 KiB chunk. python-evtx's ChunkHeader reads whatever it is
    given without complaint, so this check is the tool's own."""
    if len(head) < HEADER_BYTES:
        return "the file ends %d bytes after the signature and a chunk header is %d bytes" % (len(head), HEADER_BYTES)
    first, last = struct.unpack_from("<QQ", head, 0x08)
    header_size, last_offset, next_offset = struct.unpack_from("<III", head, 0x28)
    if header_size != HEADER_BYTES:
        return "its header size is %d, not %d" % (header_size, HEADER_BYTES)
    if last_offset > CHUNK_SIZE or next_offset > CHUNK_SIZE:
        return ("its record offsets (last %d, free space %d) lie outside a %d-byte chunk"
                % (last_offset, next_offset, CHUNK_SIZE))
    if next_offset > 0x200 and first > last:
        return "its first record number %d is after its last, %d" % (first, last)
    return None


def chain_problem(raw):
    """Why `raw` (one chunk) must not be handed to python-evtx, or None. It mirrors ChunkHeader._load_strings and _load_templates, which
    follow 64 string chains and 32 template chains until a next pointer of 0: a pointer that names an offset already seen is a loop, one
    outside the chunk is a read past it."""
    if len(raw) < 0x200:
        return "the chunk is shorter than its 0x200-byte header area"
    for count, base, label in ((64, 0x80, "string"), (32, 0x180, "template")):
        for i in range(count):
            ofs = struct.unpack_from("<I", raw, base + 4 * i)[0]
            seen = set()
            while ofs > 0:
                if ofs in seen:
                    return "%s table entry %d loops back to offset 0x%x" % (label, i, ofs)
                seen.add(ofs)
                if label == "string":
                    if ofs + 8 > len(raw):
                        return "%s table entry %d points outside the chunk (0x%x)" % (label, i, ofs)
                    ofs = struct.unpack_from("<I", raw, ofs)[0]
                else:
                    if ofs < 10 or ofs + 4 > len(raw):
                        return "%s table entry %d points outside the chunk (0x%x)" % (label, i, ofs)
                    if raw[ofs - 10] != 0x0C or struct.unpack_from("<I", raw, ofs - 4)[0] != ofs:
                        break                       # python-evtx stops here itself (it logs "Unexpected token")
                    ofs = struct.unpack_from("<I", raw, ofs)[0]
                if len(seen) > 100000:
                    return "%s table entry %d chain longer than any chunk can hold" % (label, i)
    return None
# END SHARED EVTX READ

NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
FILETIME_EPOCH_SECONDS = 11644473600


def fail(message, **extra):
    print(dumps_row({'error': message, 'status': 'failed', 'status_basis': 'the tool stopped with an error (see error); no record was examined', **extra}))
    raise SystemExit(1)


def whole(args, name, default, low=None):
    v = args.get(name, default)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int) or (low is not None and v < low):
        fail('%s must be a whole number%s' % (name, ' of at least %d' % low if low is not None else ''), **{name: args.get(name)})
    return v


def filetime_iso(ft):
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or an unrepresentable date."""
    import datetime
    if not ft:
        return None
    try:
        whole_s, ticks = divmod(ft, 10_000_000)
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=whole_s)
        return base.strftime('%Y-%m-%dT%H:%M:%S') + '.%07dZ' % ticks
    except (OverflowError, ValueError):
        return None


TIME_ARG = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2})(?::(\d{2})(?::(\d{2})(?:\.(\d{1,7}))?)?)?(Z|[+-]\d{2}:\d{2})?)?$')
SYSTEM_TIME = re.compile(r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|\+00:00)?$')
EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
TICKS = 10_000_000


def ticks_of(year, month, day, hour, minute, second):
    moment = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
    return (moment - EPOCH) // datetime.timedelta(seconds=1) * TICKS


def time_window(text, name):
    """The span of UTC time (in 100 ns ticks since 1970, [low, high)) an ISO 8601 time argument names: a date is
    its whole day, an hour its hour, down to the number of fractional digits given. No zone is UTC; `Z` and a numeric
    offset are applied. Anything else is refused."""
    m = TIME_ARG.match(text.strip())
    if not m:
        fail('%s is not an ISO 8601 UTC time: use YYYY-MM-DD, optionally with THH, THH:MM, THH:MM:SS or THH:MM:SS.fffffff '
             'and, from the hour on, Z or an offset such as +03:00' % name, **{name: text})
    year, month, day, hour, minute, second, fraction, zone = m.groups()
    try:
        low = ticks_of(int(year), int(month), int(day), int(hour or 0), int(minute or 0), int(second or 0))
    except ValueError as exc:
        fail('%s is not a real date or time: %s' % (name, exc), **{name: text})
    if fraction is not None:
        digits = len(fraction)
        low += int(fraction) * 10 ** (7 - digits)
        unit = 10 ** (7 - digits)
    elif second is not None:
        unit = TICKS
    elif minute is not None:
        unit = 60 * TICKS
    elif hour is not None:
        unit = 3600 * TICKS
    else:
        unit = 86400 * TICKS
    if zone and zone != 'Z':
        sign = 1 if zone[0] == '+' else -1
        offset_hours, offset_minutes = int(zone[1:3]), int(zone[4:6])
        if offset_hours > 23 or offset_minutes > 59:
            fail('%s has an offset that is not a real zone' % name, **{name: text})
        low -= sign * (offset_hours * 3600 + offset_minutes * 60) * TICKS
    return low, low + unit


def system_ticks(text):
    """The SystemTime attribute of a record as ticks since 1970 UTC (python-evtx writes it with a space and six digits,
    and no zone); None when it is absent or not a time."""
    m = SYSTEM_TIME.match((text or '').strip())
    if not m:
        return None
    year, month, day, hour, minute, second, fraction = m.groups()
    try:
        base = ticks_of(int(year), int(month), int(day), int(hour), int(minute), int(second))
    except ValueError:
        return None
    return base + int((fraction or '0')[:7].ljust(7, '0'))


def dumps_row(row):
    """One JSON line, whole; a lone surrogate (text that was not UTF-8) is escaped, not lost."""
    text = json.dumps(row, ensure_ascii=False)
    try:
        text.encode('utf-8')
    except UnicodeEncodeError:
        text = json.dumps(row, ensure_ascii=True)
    return text


class ResultWriteError(Exception):
    """The whole result could not be written: not a record that failed to parse."""


def main():
    set_deadline(DEADLINE_SECONDS)
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail('arguments are not valid JSON', reason=str(exc))
    if not isinstance(args, dict):
        fail('the arguments must be a JSON object')
    path = args.get('path')
    if not isinstance(path, str) or not path:
        fail('path is required: the EVTX file')
    try:
        mode = os.stat(path).st_mode
    except (OSError, ValueError):
        fail('no such file', path=path)
    if not stat.S_ISREG(mode):
        # A named pipe or a device would be opened and waited on: it is not read.
        fail('the path is not a regular file, so it was not opened', path=path, not_attempted=1)
    raw_ids = args.get('event_ids') or []
    if not isinstance(raw_ids, list) or any(isinstance(i, bool) or not isinstance(i, int) for i in raw_ids):
        fail('event_ids must be a list of whole numbers', event_ids=args.get('event_ids'))
    event_ids = set(raw_ids)
    contains = args.get('contains')
    if contains is not None and not isinstance(contains, str):
        fail('contains must be a string', contains=contains)
    contains_l = contains.lower() if contains else None
    limit = whole(args, 'limit', 200, 1)
    start_record = whole(args, 'start_record', None, 0)
    end_record = whole(args, 'end_record', None, 0)
    if start_record is not None and end_record is not None and start_record > end_record:
        fail('start_record is after end_record: the range is empty', start_record=start_record, end_record=end_record)
    start_time, end_time = args.get('start_time'), args.get('end_time')
    for name, v in (('start_time', start_time), ('end_time', end_time)):
        if v is not None and not isinstance(v, str):
            fail('%s must be an ISO 8601 UTC string' % name, **{name: v})
    time_low = time_high = None
    if start_time is not None:
        time_low = time_window(start_time, 'start_time')[0]
    if end_time is not None:
        time_high = time_window(end_time, 'end_time')[1]
    if time_low is not None and time_high is not None and time_low >= time_high:
        fail('start_time is after end_time: the range is empty', start_time=start_time, end_time=end_time)

    root_dir = Path.cwd().resolve()
    # The name of the whole result is made from the arguments that say where and what was asked, and never from `contains`:
    # a needle can be a secret, and a name, like the answer, is not a place for it or for a digest of it.
    named = {k: v for k, v in args.items() if k not in ('contains', 'out_file')}
    named['contains'] = bool(contains)
    default_name = 'evtx-query-' + hashlib.sha256(json.dumps(named, sort_keys=True).encode()).hexdigest()[:16] + '.jsonl'
    in_job = bool(os.environ.get('JOB_ID') and os.environ.get('OUT'))
    # The whole result: in a job, under $OUT (sealed as the job's output); in an
    # agent's VM, under its own work/<id>/, the only part of work/ it can write.
    if in_job:
        default_path = os.path.join(os.environ['OUT'], default_name)
    else:
        default_path = 'work/%s/tool-output/%s' % (re.sub(r'[^A-Za-z0-9_.-]', '_', os.environ.get('AGENT_ID') or 'tool'), default_name)
    out_file = args.get('out_file')
    if out_file is not None and (not isinstance(out_file, str) or not out_file):
        fail('out_file must be a path', out_file=out_file)
    # The directory is resolved (a link in it is followed to where it lands, and judged there); the name is not: a link
    # left at the name itself is never written through, the placement below refuses it.
    try:
        wanted = Path(os.path.normpath(root_dir / Path(out_file or default_path)))
        result_path = wanted.parent.resolve() / wanted.name
        os.fsencode(str(result_path))
    except (UnicodeEncodeError, ValueError, OSError):
        fail('out_file is not a path this tool can create (it holds bytes that are not text)', status='failed')
    allowed = [root_dir]
    if in_job:
        allowed.append(Path(os.environ['OUT']).resolve())
    if not any(result_path != base and base in result_path.parents for base in allowed):
        fail('out_file must stay inside the run directory' + (' or $OUT' if in_job else ''), out_file=out_file)
    inputs = root_dir / 'inputs'
    if result_path == inputs or inputs in result_path.parents:
        fail('out_file cannot be under inputs/')

    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:
        fail('python-evtx is not installed', hint='python3 -m pip install python-evtx', reason=str(exc))
    try:
        with open(path, 'rb') as fh:
            magic = fh.read(len(FILE_MAGIC))
    except OSError as exc:
        fail('the file could not be read', path=path, reason='%s: %s' % (type(exc).__name__, exc.strerror or exc))
    if magic != FILE_MAGIC:
        fail('not an EVTX file: it does not begin with ElfFile', path=path, begins_with=magic.hex())
    try:
        evtx = Evtx(path)
        evtx.__enter__()
    except Exception as exc:
        fail('could not open the event log', path=path, reason='%s: %s' % (type(exc).__name__, exc))

    def close_evtx():
        try:
            evtx.__exit__(None, None, None)
        except Exception:
            pass

    def shown_result(p):
        """Where a reader finds the whole result: a job's $OUT is sealed as
        store/jobs/<id>/out/, the path to cite; otherwise the run-relative path."""
        out = os.environ.get('OUT')
        if os.environ.get('JOB_ID') and out and Path(out).resolve() in p.parents:
            return 'store/jobs/%s/out/%s' % (re.sub(r'[^A-Za-z0-9_.-]', '_', os.environ['JOB_ID']), p.relative_to(Path(out).resolve()))
        return os.path.relpath(p, root_dir)

    # What the file header says the log holds, to set against what the file holds and what the reader gave.
    problems = []
    declared = {'chunks_declared': None, 'bytes_expected': None, 'next_record_number': None, 'flags': None}
    file_bytes = os.path.getsize(path)
    header_bytes = 0x1000
    header = None
    try:
        header = evtx.get_file_header()
        header_bytes = int(header.header_chunk_size())
        declared['chunks_declared'] = int(header.chunk_count())
        declared['next_record_number'] = int(header.next_record_number())
        declared['flags'] = int(header.flags())
        declared['bytes_expected'] = header_bytes + declared['chunks_declared'] * CHUNK_BYTES
        if file_bytes < declared['bytes_expected']:
            problems.append('the file is %d bytes and its header declares %d chunks, which take %d: the log is cut short'
                            % (file_bytes, declared['chunks_declared'], declared['bytes_expected']))
    except Exception as exc:
        problems.append('the file header could not be read, so what the log should hold is not known: %s' % exc)

    # The whole result is written to a private temporary file beside its place and put there at the end, under a name that is free:
    # a run that is stopped leaves a file that says it is partial, never one under the name of a result.
    try:
        result_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=result_path.parent, prefix='.%s-' % result_path.name)
        full = os.fdopen(fd, 'w', encoding='utf-8')
        tmp_path = Path(tmp_name)
    except OSError as exc:
        close_evtx()
        fail('the whole result cannot be written to %s: %s. Outside a job the place is your own work/<your id>/ directory; '
             'in a job it is $OUT.' % (os.path.relpath(result_path, root_dir), exc), status='failed')

    def write_row(row):
        try:
            full.write(dumps_row(row) + '\n')
        except OSError as exc:
            raise ResultWriteError(str(exc))

    events, errors = [], []
    counts = {'examined': 0, 'matched': 0, 'parse_errors': 0, 'without_time': 0, 'chunks_read': 0, 'beyond_read': 0, 'beyond_rejected': 0,
              'slots_empty_beyond': 0, 'declared_unreadable': 0, 'tables_refused': 0, 'timed_out': 0}
    highest_record = None
    stopped = {'time': None, 'signal': None}
    chunk_report = []                      # [offset, why] of every chunk not read, whole in the result file as a parse_error row

    def error_row(row):
        write_row(row)
        counts['parse_errors'] += 1
        if len(errors) < limit:
            errors.append(row)

    def read_chunk(chunk):
        """The records of one chunk as [(kind, record_offset, xml, filetime, message)], read under the chunk's timer. kind is 'record' (xml
        is there), 'record_error' (the library could not render that record), 'chain' (the chain of records broke: nothing after it in
        the chunk) or 'timeout' (the chunk went past its timer and was given up)."""
        items = []
        try:
            with chunk_guard():
                for rec in chunk.records():
                    offset = xml = ft = None
                    try:
                        offset = rec.offset()
                        xml = rec.xml()
                        try:
                            ft = rec.unpack_qword(0x10)
                        except Exception:
                            ft = None
                        items.append(('record', offset, xml, ft, None))
                    except Exception as e:
                        items.append(('record_error', offset, xml, ft, str(e)))
        except ChunkTimeout:
            counts['timed_out'] += 1
            items.append(('timeout', None, None, None, None))
        except Exception as e:
            items.append(('chain', None, None, None, 'the record chain of this chunk broke: %s' % e))
        return items

    def handle(offset, xml, record_filetime, chunk_offset, beyond):
        nonlocal highest_record
        counts['examined'] += 1
        root = ET.fromstring(xml)
        sysnode = root.find('e:System', NS)
        eid_text = sysnode.findtext('e:EventID', default='', namespaces=NS) if sysnode is not None else ''
        try:
            eid = int(eid_text)
        except Exception:
            eid = None
        recid_text = sysnode.findtext('e:EventRecordID', default='', namespaces=NS) if sysnode is not None else ''
        try:
            recid = int(recid_text)
        except Exception:
            recid = None
        time_created = ''
        if sysnode is not None:
            t = sysnode.find('e:TimeCreated', NS)
            if t is not None:
                time_created = t.attrib.get('SystemTime', '')
        if recid is not None and (highest_record is None or recid > highest_record):
            highest_record = recid
        if start_record is not None and (recid is None or recid < start_record):
            return
        if end_record is not None and (recid is None or recid > end_record):
            return
        if event_ids and eid not in event_ids:
            return
        if time_low is not None or time_high is not None:
            placed = system_ticks(time_created)
            if placed is None:
                counts['without_time'] += 1
                return
            if (time_low is not None and placed < time_low) or (time_high is not None and placed >= time_high):
                return
        if contains_l and contains_l not in xml.lower():
            return
        channel = sysnode.findtext('e:Channel', default='', namespaces=NS) if sysnode is not None else ''
        computer = sysnode.findtext('e:Computer', default='', namespaces=NS) if sysnode is not None else ''
        provider = ''
        if sysnode is not None:
            p = sysnode.find('e:Provider', NS)
            if p is not None:
                provider = p.attrib.get('Name', '')
        eventdata = {}
        for section in ('EventData', 'UserData'):
            sec = root.find('e:%s' % section, NS)
            if sec is not None:
                for elem in sec.iter():
                    if elem is sec:
                        continue
                    tag = elem.tag.rsplit('}', 1)[-1]
                    text = (elem.text or '').strip()
                    if not text:
                        continue
                    name = elem.attrib.get('Name') or tag
                    if name in eventdata:
                        if isinstance(eventdata[name], list):
                            eventdata[name].append(text)
                        else:
                            eventdata[name] = [eventdata[name], text]
                    else:
                        eventdata[name] = text
        entry = {
            'timestamp': time_created,
            'record_filetime': str(record_filetime) if record_filetime is not None else None,
            'record_time_utc': filetime_iso(record_filetime) if record_filetime is not None else None,
            'event_id': eid,
            'channel': channel,
            'computer': computer,
            'provider': provider,
            'record_id': recid,
            'record_offset': offset,
            'chunk_offset': chunk_offset,
            'chunk_beyond_declared': beyond,
            'data': eventdata,
            'xml': xml,
        }
        write_row(entry)
        counts['matched'] += 1
        if len(events) < limit:
            events.append({k: v for k, v in entry.items() if k != 'xml'})

    declared_n = declared['chunks_declared']
    slot_index = [-1]
    try:
        try:
            with open(path, 'rb') as raw_fh:
                slots = (file_bytes - header_bytes) // CHUNK_BYTES if file_bytes > header_bytes else 0
                trailing = (file_bytes - header_bytes) - slots * CHUNK_BYTES if file_bytes > header_bytes else 0
                chunk_iter = iter(header.chunks(include_inactive=True)) if header is not None else iter(())
                index = -1
                while True:
                    check_stop()
                    if out_of_time():
                        stopped['time'] = 'the tool\'s own time limit (%d seconds) was reached after chunk %d of %d' % (DEADLINE_SECONDS, index + 1, slots)
                        break
                    try:
                        with chunk_guard():
                            chunk = next(chunk_iter)
                    except StopIteration:
                        break
                    except ChunkTimeout:
                        break
                    except Exception as e:
                        last = header_bytes + index * CHUNK_BYTES if index >= 0 else None
                        problems.append('the chunks of the log could not be enumerated past offset %s: %s' % (last, e))
                        error_row({'parse_error': 'the chunk enumeration failed after offset %s: %s' % (last, e), 'chunk_offset': last, 'enumeration_failed': True})
                        break
                    index += 1
                    slot_index[0] = index
                    chunk_offset = header_bytes + index * CHUNK_BYTES
                    raw_fh.seek(chunk_offset)
                    raw = raw_fh.read(CHUNK_BYTES)
                    beyond = declared_n is not None and index >= declared_n
                    has_magic = raw[:len(CHUNK_MAGIC)] == CHUNK_MAGIC
                    if not has_magic:
                        if beyond:
                            counts['slots_empty_beyond'] += 1
                        else:
                            counts['declared_unreadable'] += 1
                            chunk_report.append([chunk_offset, 'no ElfChnk signature'])
                            error_row({'parse_error': 'the chunk the file header declares at this offset has no ElfChnk signature and was not read', 'chunk_offset': chunk_offset})
                        continue
                    refusal = reject_signature(raw[:HEADER_BYTES]) if beyond else None
                    if refusal is not None:
                        counts['beyond_rejected'] += 1
                        chunk_report.append([chunk_offset, refusal])
                        error_row({'parse_error': 'past the chunks the file header declares, an ElfChnk signature that is not a chunk: %s' % refusal, 'chunk_offset': chunk_offset})
                        continue
                    loop = chain_problem(raw)
                    if loop is not None:
                        counts['tables_refused'] += 1
                        chunk_report.append([chunk_offset, loop])
                        error_row({'parse_error': 'the chunk was not read: its %s' % loop, 'chunk_offset': chunk_offset})
                        continue
                    counts['chunks_read'] += 1
                    if beyond:
                        counts['beyond_read'] += 1
                    for kind, offset, xml, ft, err in read_chunk(chunk):
                        check_stop()
                        if kind == 'timeout':
                            chunk_report.append([chunk_offset, 'the chunk took more than %d seconds to read' % CHUNK_SECONDS])
                            error_row({'parse_error': 'the chunk took more than %d seconds to read; the records after this point in it were not read' % CHUNK_SECONDS, 'chunk_offset': chunk_offset})
                        elif kind == 'chain':
                            error_row({'parse_error': err, 'chunk_offset': chunk_offset})
                        elif kind == 'record_error':
                            counts['examined'] += 1
                            error_row({'parse_error': err, 'record_offset': offset, 'chunk_offset': chunk_offset, 'xml': xml})
                        else:
                            try:
                                handle(offset, xml, ft, chunk_offset, beyond)
                            except ResultWriteError:
                                raise
                            except Exception as e:
                                error_row({'parse_error': str(e), 'record_offset': offset, 'chunk_offset': chunk_offset, 'xml': xml})
                if trailing and file_bytes > header_bytes:
                    raw_fh.seek(header_bytes + slots * CHUNK_BYTES)
                    if raw_fh.read(len(CHUNK_MAGIC)) == CHUNK_MAGIC:
                        problems.append('the file ends %d bytes into a chunk (a chunk is %d): the records in that part are not read here (evtx_carve reads a chunk cut by the end of the file)' % (trailing, CHUNK_BYTES))
        except Interrupted as stop:
            stopped['signal'] = stop.signum
        full.flush()
        os.fsync(full.fileno())
        full.close()
    except ResultWriteError as exc:
        close_evtx()
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        fail('the whole result could not be written to %s after %d records: %s. Outside a job the place is your own '
             'work/<your id>/ directory; in a job it is $OUT.' % (os.path.relpath(result_path, root_dir), counts['examined'], exc),
             status='failed', records_examined=counts['examined'], events_matched=counts['matched'])
    finally:
        close_evtx()
    if stopped['signal'] is not None:
        # The file is closed between two rows; it is kept beside its place as a partial result and named, never as a result.
        keep = result_path.with_name('%s.partial%s' % (result_path.stem, result_path.suffix))
        partial = tmp_path
        for n in range(1, 1000):
            candidate = keep if n == 1 else keep.with_name('%s-%d%s' % (keep.stem, n, keep.suffix))
            try:
                os.link(tmp_path, candidate)
                os.unlink(tmp_path)
                partial = candidate
                break
            except FileExistsError:
                continue
            except OSError:
                break
        print(dumps_row({'error': 'stopped by signal %d before the whole log was read' % stopped['signal'], 'status': 'interrupted',
                         'status_basis': 'the tool was stopped by signal %d; the records examined so far are in a partial file, which is not a result' % stopped['signal'],
                         'signal': stopped['signal'], 'records_examined': counts['examined'], 'events_matched': counts['matched'],
                         'partial_result_file': shown_result(partial)}), flush=True)
        sys.exit(128 + stopped['signal'])
    made_path = place_without_replacing(tmp_path, result_path)
    chunks_read = counts['chunks_read']
    if counts['without_time']:
        problems.append('%d record(s) have no usable SystemTime and could not be placed in the time range: they are left out'
                        % counts['without_time'])
    if counts['beyond_read'] or counts['beyond_rejected']:
        problems_note = ('the file holds %d chunk(s) past the %d its header declares: %d were read (chunk_beyond_declared: true on their rows)%s'
                         % (counts['beyond_read'] + counts['beyond_rejected'], declared_n, counts['beyond_read'],
                            ', %d did not pass the chunk header checks and were not read' % counts['beyond_rejected'] if counts['beyond_rejected'] else ''))
        if declared['flags'] is not None and declared['flags'] & 1:
            problems_note += '; the header says the log is dirty (it was opened and changed, and the header was not brought up to date)'
        if counts['beyond_rejected']:
            problems.append(problems_note)
        notes_beyond = problems_note
    else:
        notes_beyond = None
    if counts['declared_unreadable']:
        problems.append('%d chunk(s) the file header declares have no ElfChnk signature and were not read' % counts['declared_unreadable'])
    if counts['tables_refused']:
        problems.append('%d chunk(s) were not given to the reader because a string or template table in them loops or points outside the chunk (chunk_report)' % counts['tables_refused'])
    if counts['timed_out']:
        problems.append('%d chunk(s) took more than %d seconds to read and were given up (chunk_report)' % (counts['timed_out'], CHUNK_SECONDS))
    if stopped['time']:
        problems.append(stopped['time'] + '; the chunks after it were not read')
    visited = min(max(slot_index[0] + 1, 0), declared_n) if declared_n is not None else None
    if visited is not None and visited < declared_n and not stopped['time']:
        problems.append('the reader gave %d of the %d chunks the file header declares: records in the others were not read' % (visited, declared_n))
    time_range = None
    if time_low is not None or time_high is not None:
        def tick_iso(t):
            return None if t is None else (EPOCH + datetime.timedelta(seconds=t // TICKS)).strftime('%Y-%m-%dT%H:%M:%S') + '.%07dZ' % (t % TICKS)
        time_range = {'from': tick_iso(time_low), 'until_exclusive': tick_iso(time_high)}
    complete = counts['parse_errors'] == 0 and not problems
    if complete:
        basis = ('every chunk slot of the file was examined: %d chunk(s) read%s, none failed' %
                 (chunks_read, ' (%d of them past the header\'s count)' % counts['beyond_read'] if counts['beyond_read'] else ''))
    else:
        reasons = []
        if counts['parse_errors']:
            reasons.append('%d record(s) or chunk(s) could not be read (parse_errors)' % counts['parse_errors'])
        if problems:
            reasons.append('%d problem(s) are named under problems' % len(problems))
        basis = '; '.join(reasons)
    answer = {
        'parser': PARSER,
        'status': 'complete' if complete else 'partial',
        'status_basis': basis,
        'path': path,
        'file_bytes': file_bytes,
        'header_flags': declared['flags'],
        'header_dirty': bool(declared['flags'] & 1) if declared['flags'] is not None else None,
        'chunks_declared': declared_n,
        'chunks_in_file': (file_bytes - header_bytes) // CHUNK_BYTES if file_bytes > header_bytes else 0,
        'chunks_read': chunks_read,
        'chunks_read_beyond_declared': counts['beyond_read'],
        'chunks_beyond_declared_rejected': counts['beyond_rejected'],
        'chunk_slots_beyond_declared_empty': counts['slots_empty_beyond'],
        'chunks_not_read': chunk_report[:100],
        'chunks_not_read_count': len(chunk_report),
        'beyond_declared_note': notes_beyond,
        'bytes_expected': declared['bytes_expected'],
        'next_record_number_declared': declared['next_record_number'],
        'highest_record_id_read': highest_record,
        'records_examined': counts['examined'],
        'events_matched': counts['matched'],
        'parse_errors': counts['parse_errors'],
        'events_without_time_excluded': counts['without_time'],
        'walk_stopped_by_time_limit': stopped['time'] is not None,
        'time_range_utc': time_range,
        'count': counts['matched'],
        'returned': len(events),
        'events': events,
        'errors': errors,
        'problems': problems,
        'truncated': counts['matched'] > len(events),
        'result_file': shown_result(made_path),
        'note': 'count is the events that matched the filters; parse_errors are records or chunks that could not be read and are in the result '
                'file as rows with parse_error. A record the reader could not produce is not examined, and a run with parse_errors is partial: '
                'an absence of events is bounded by the records examined, by chunks_read against chunks_declared and chunks_in_file, and by file_bytes '
                'against bytes_expected. The result file holds the whole XML of every matched event (event data can hold a secret): it is mode 0600.',
    }
    if made_path != result_path:
        answer['result_file_requested'] = shown_result(result_path)
        answer['result_file_requested_note'] = ('that name was already taken by an earlier, different result, which is kept as it was; this run '
                                                'wrote %s' % shown_result(made_path))
    print(dumps_row(answer))


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except Interrupted as stop:
        print(dumps_row({'error': 'stopped by signal %d' % stop.signum, 'status': 'interrupted', 'status_basis': 'the tool was stopped by signal %d' % stop.signum, 'signal': stop.signum}), flush=True)
        sys.exit(128 + stop.signum)
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        print(dumps_row({'error': 'the read failed', 'status': 'failed', 'status_basis': 'the tool stopped with an unexpected error', 'reason': '%s: %s' % (type(exc).__name__, exc)}))
        sys.exit(1)
