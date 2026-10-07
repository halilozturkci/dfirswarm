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

The XML is rendered by python-evtx; a record whose template it cannot expand is an error row, not a skip.
Event data can hold command lines and text typed into a command line, which can hold a secret: run it as a
job with secret_output: true when the log may.
"""
import datetime
import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

PARSER = "evtx_query/3"
CHUNK_BYTES = 0x10000
NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
FILETIME_EPOCH_SECONDS = 11644473600


def fail(message, **extra):
    print(json.dumps({'error': message, **extra}))
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


def create_exclusive(path):
    """Create `path` and nothing else: never truncate or follow what is already there. When the name is taken (by a
    file, a link or a directory) the first free <stem>-<n><suffix> beside it is used. Returns the open file and the
    path that was made."""
    for n in range(1, 10000):
        candidate = path if n == 1 else path.with_name('%s-%d%s' % (path.stem, n, path.suffix))
        try:
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o644)
        except FileExistsError:
            continue
        return os.fdopen(fd, 'w', encoding='utf-8'), candidate
    raise OSError('no free name beside %s' % path)


def records(evtx, problems, counter):
    """Every record, chunk by chunk, as (record, chunk_offset, None); a break in a chunk's record chain, or in the
    enumeration of the chunks themselves, yields (None, offset, row) with the reason and ends that chain (the
    next chunk is still read; a failed enumeration ends the run, said). One malformed record must not cost the
    records after it."""
    chunk_iter = iter(evtx.chunks())
    last_chunk = None
    while True:
        try:
            chunk = next(chunk_iter)
        except StopIteration:
            return
        except Exception as e:
            problems.append('the chunks of the log could not be enumerated past offset %s: %s' % (last_chunk, e))
            yield None, last_chunk, {'parse_error': 'the chunk enumeration failed after offset %s: %s' % (last_chunk, e),
                                     'chunk_offset': last_chunk, 'enumeration_failed': True}
            return
        try:
            chunk_offset = chunk.offset()
        except Exception:
            chunk_offset = None
        last_chunk = chunk_offset
        counter['chunks_read'] += 1
        try:
            chain = chunk.records()
        except Exception as e:
            yield None, chunk_offset, {'parse_error': 'the record chain of this chunk could not be opened: %s' % e, 'chunk_offset': chunk_offset}
            continue
        while True:
            try:
                rec = next(chain)
            except StopIteration:
                break
            except Exception as e:
                yield None, chunk_offset, {'parse_error': 'the record chain of this chunk broke: %s' % e, 'chunk_offset': chunk_offset}
                break
            yield rec, chunk_offset, None


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail('arguments are not valid JSON', reason=str(exc))
    if not isinstance(args, dict):
        fail('the arguments must be a JSON object')
    path = args.get('path')
    if not isinstance(path, str) or not path:
        fail('path is required: the EVTX file')
    if not os.path.isfile(path):
        fail('no such file', path=path)
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
    # left at the name itself is never written through, the exclusive create below refuses it.
    wanted = Path(os.path.normpath(root_dir / Path(out_file or default_path)))
    result_path = wanted.parent.resolve() / wanted.name
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

    # What the file header says the log holds, to set against what the reader gave.
    problems = []
    declared = {'chunks_declared': None, 'bytes_expected': None, 'next_record_number': None}
    file_bytes = os.path.getsize(path)
    try:
        header = evtx.get_file_header()
        header_bytes = int(header.header_chunk_size())
        declared['chunks_declared'] = int(header.chunk_count())
        declared['next_record_number'] = int(header.next_record_number())
        declared['bytes_expected'] = header_bytes + declared['chunks_declared'] * CHUNK_BYTES
        if file_bytes < declared['bytes_expected']:
            problems.append('the file is %d bytes and its header declares %d chunks, which take %d: the log is cut short'
                            % (file_bytes, declared['chunks_declared'], declared['bytes_expected']))
    except Exception as exc:
        problems.append('the file header could not be read, so what the log should hold is not known: %s' % exc)

    try:
        result_path.parent.mkdir(parents=True, exist_ok=True)
        full, made_path = create_exclusive(result_path)
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
    examined = matched = parse_errors = without_time = 0
    counter = {'chunks_read': 0}
    highest_record = None
    try:
        with full:
            for rec, chunk_offset, broken in records(evtx, problems, counter):
                if broken is not None:
                    write_row(broken)
                    parse_errors += 1
                    if len(errors) < limit:
                        errors.append(broken)
                    continue
                examined += 1
                xml = None
                record_offset = None
                try:
                    record_offset = rec.offset()
                    xml = rec.xml()
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
                        continue
                    if end_record is not None and (recid is None or recid > end_record):
                        continue
                    if event_ids and eid not in event_ids:
                        continue
                    if time_low is not None or time_high is not None:
                        placed = system_ticks(time_created)
                        if placed is None:
                            without_time += 1
                            continue
                        if (time_low is not None and placed < time_low) or (time_high is not None and placed >= time_high):
                            continue
                    if contains_l and contains_l not in xml.lower():
                        continue
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
                    record_filetime = None
                    try:
                        record_filetime = rec.unpack_qword(0x10)
                    except Exception:
                        record_filetime = None
                    entry = {
                        'timestamp': time_created,
                        'record_filetime': str(record_filetime) if record_filetime is not None else None,
                        'record_time_utc': filetime_iso(record_filetime) if record_filetime is not None else None,
                        'event_id': eid,
                        'channel': channel,
                        'computer': computer,
                        'provider': provider,
                        'record_id': recid,
                        'record_offset': record_offset,
                        'chunk_offset': chunk_offset,
                        'data': eventdata,
                        'xml': xml,
                    }
                    write_row(entry)
                    matched += 1
                    if len(events) < limit:
                        events.append({k: v for k, v in entry.items() if k != 'xml'})
                except ResultWriteError:
                    raise
                except Exception as e:
                    if xml is None:
                        try:
                            xml = rec.xml()
                        except Exception as xml_error:
                            xml = None
                            e = RuntimeError('%s; XML unavailable: %s' % (e, xml_error))
                    entry = {'parse_error': str(e), 'record_offset': record_offset, 'chunk_offset': chunk_offset, 'xml': xml}
                    write_row(entry)
                    parse_errors += 1
                    if len(errors) < limit:
                        errors.append({'parse_error': str(e), 'record_offset': record_offset, 'chunk_offset': chunk_offset})
    except ResultWriteError as exc:
        close_evtx()
        fail('the whole result could not be written to %s after %d records: %s. Outside a job the place is your own '
             'work/<your id>/ directory; in a job it is $OUT.' % (os.path.relpath(made_path, root_dir), examined, exc),
             status='failed', records_examined=examined, events_matched=matched)
    finally:
        close_evtx()
    chunks_read = counter['chunks_read']
    if declared['chunks_declared'] is not None and chunks_read < declared['chunks_declared']:
        problems.append('the reader gave %d of the %d chunks the file header declares: records in the others were not read'
                        % (chunks_read, declared['chunks_declared']))
    if without_time:
        problems.append('%d record(s) have no usable SystemTime and could not be placed in the time range: they are left out'
                        % without_time)
    time_range = None
    if time_low is not None or time_high is not None:
        def tick_iso(t):
            return None if t is None else (EPOCH + datetime.timedelta(seconds=t // TICKS)).strftime('%Y-%m-%dT%H:%M:%S') + '.%07dZ' % (t % TICKS)
        time_range = {'from': tick_iso(time_low), 'until_exclusive': tick_iso(time_high)}
    complete = parse_errors == 0 and not problems
    answer = {
        'parser': PARSER,
        'status': 'complete' if complete else 'partial',
        'path': path,
        'file_bytes': file_bytes,
        'chunks_declared': declared['chunks_declared'],
        'chunks_read': chunks_read,
        'bytes_expected': declared['bytes_expected'],
        'next_record_number_declared': declared['next_record_number'],
        'highest_record_id_read': highest_record,
        'records_examined': examined,
        'events_matched': matched,
        'parse_errors': parse_errors,
        'events_without_time_excluded': without_time,
        'time_range_utc': time_range,
        'count': matched,
        'returned': len(events),
        'events': events,
        'errors': errors,
        'problems': problems,
        'truncated': matched > len(events),
        'result_file': shown_result(made_path),
        'note': 'count is the events that matched the filters; parse_errors are records or chunks that could not be read and are in the result '
                'file as rows with parse_error. A record the reader could not produce is not examined, and a run with parse_errors is partial: '
                'an absence of events is bounded by the records examined, by chunks_read against chunks_declared and by file_bytes against '
                'bytes_expected.',
    }
    if made_path != result_path:
        answer['result_file_requested'] = shown_result(result_path)
        answer['result_file_requested_note'] = ('that name was already taken by an earlier result, which is kept as it was; this run '
                                                'wrote %s' % shown_result(made_path))
    print(json.dumps(answer, ensure_ascii=False))


if __name__ == '__main__':
    main()
