#!/usr/bin/env python3
"""Measure how tightly a series of event times clusters around its median interval.

That is all this measures. It reports the median interval, the median absolute
deviation (MAD) and the MAD as a fraction of the median, a density ratio, and
the longest stretch at the end of the series. A series that clusters tightly is
regular; regular is not malicious (update checks, telemetry, NTP, revocation
checks and monitoring agents are all more regular than most malware), and an
irregular series says nothing about a destination either. The shape names
describe dispersion, with fixed cut-offs that are conventions of this tool, not
properties of any implant. A score is a measurement to be set against comparable
hosts and services, not a verdict.

What a result can and cannot say:

  - The series is what the caller supplied. A time with no zone is refused unless
    the caller says to read it as UTC (assume_utc), and every such value is
    counted. A value that is not a finite number of seconds, or is not epoch
    seconds at all (a millisecond count), is counted and named, never scored.
  - Duplicate times are counted apart from distinct events; the minimum event
    count applies to the distinct ones.
  - long_final_gap is an observation: the last interval is more than four times
    the median, and it ENDS IN AN OBSERVED EVENT, so the series resumed. It is
    not a cessation. Whether anything stopped needs a declared observation
    window (window_end) and a statement that the sensor kept recording over it
    (sensor_coverage_confirmed); only then is the silence after the last event
    stated, as a bounded negative about this series alone.
  - event_density_ratio is the distinct events divided by the count a constant
    schedule at the median interval would give over the same span. Below 1 it
    means fewer events than that schedule, for any reason (pauses, jitter, a
    series that is not periodic, missing records); it does not establish that
    events are missing.
  - The whole interval list is kept: inline a bounded page, the rest in a file
    the answer names (and intervals.tsv in out_dir when one is given).
"""
import datetime
import json
import math
import os
import re
import secrets
import statistics
import sys
import tempfile
from pathlib import Path

TOOL = {"name": "beacon_score", "version": 3}
MAX_EPOCH = 4_102_444_800        # 2100-01-01: a number above it is not epoch seconds (milliseconds, microseconds, nanoseconds)
MAX_EVENTS = 5_000_000
DEFAULT_LIMIT = 40
MAX_VALUE_CHARS = 4096          # a longer line of a timestamps_file is not a time


def describe(exc):
    return "%s: %s" % (type(exc).__name__, getattr(exc, "strerror", None) or str(exc))


def fail(message, **extra):
    print(json.dumps({"error": message, "tool": TOOL, **extra}))
    raise SystemExit(1)


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place
    outside it, the run directory itself, or anything under inputs/ is refused.
    In a job it is a directory under $OUT, the one place a job writes."""
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    if in_job():
        job_out = Path(os.environ["OUT"]).resolve()
        if dest != job_out and job_out not in dest.parents:
            fail("in a job %s is a directory under $OUT, the one place a job writes" % what, **{what: str(out), "out": str(job_out)})
    return str(dest.relative_to(root))


# Lossless paging (the same in every pack tool that pages); see pcap_summary.
class LosslessPage:
    def __init__(self, tool, limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page = []
        self.total = 0
        self._out = None
        self._tmp = None
        name = "%s-%s.jsonl" % (self.tool, secrets.token_hex(8))
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        self._out.write(json.dumps(row, ensure_ascii=True, default=str))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            os.replace(self._tmp, self.path)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


def read_time(value, assume_utc):
    """(seconds since the epoch, None) or (None, reason). A reason is one of unparseable, non_finite, out_of_range,
    naive: nothing is guessed, and a number is epoch seconds."""
    if isinstance(value, bool) or value is None:
        return None, "unparseable"
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        text = value.strip()
        try:
            number = float(text)
        except ValueError:
            number = None
        if number is None:
            candidate = text[:-1] + "+00:00" if text[-1:] in ("Z", "z") else text
            try:
                parsed = datetime.datetime.fromisoformat(candidate)
            except ValueError:
                return None, "unparseable"
            if parsed.tzinfo is None:
                if not assume_utc:
                    return None, "naive"
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
                number = parsed.timestamp()
                if not math.isfinite(number):
                    return None, "non_finite"
                return number, "assumed_utc"
            try:
                number = parsed.timestamp()
            except (OverflowError, OSError, ValueError):
                return None, "out_of_range"
    else:
        return None, "unparseable"
    if not math.isfinite(number):
        return None, "non_finite"
    if number < 0 or number > MAX_EPOCH:
        return None, "out_of_range"
    return number, None


def sealed_path(path):
    """In a job, where a file under $OUT is cited once the job is sealed; otherwise the path as it is."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if not path or not (job and out):
        return path
    try:
        rel = Path(path).resolve().relative_to(Path(out).resolve())
    except ValueError:
        return path
    return "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), rel)


def iso(stamp):
    try:
        return datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, OSError, ValueError):
        return None


def shape_of(relative):
    if relative is None:
        return "unmeasurable"
    if relative <= 0.02:
        return "tight_cluster"
    if relative <= 0.25:
        return "clustered"
    if relative <= 0.6:
        return "loose_cluster"
    return "dispersed"


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    raw, file_arg = args.get("timestamps"), args.get("timestamps_file")
    if raw is not None and file_arg is not None:
        fail("give one of timestamps or timestamps_file, not both")
    if raw is None and file_arg is None:
        fail("timestamps is required: a list of event times, epoch seconds or ISO 8601 with a zone (or timestamps_file, one per line)")
    minimum = args.get("min_events", 6)
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 3:
        fail("min_events must be an integer of at least 3")
    limit = args.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive integer")
    assume_utc = args.get("assume_utc", False)
    confirmed = args.get("sensor_coverage_confirmed", False)
    for key, value in (("assume_utc", assume_utc), ("sensor_coverage_confirmed", confirmed)):
        if not isinstance(value, bool):
            fail("%s must be true or false" % key)
    out_dir = args.get("out_dir")
    if out_dir is not None:
        if not isinstance(out_dir, str) or not out_dir:
            fail("out_dir must be a non-empty string")
        out_dir = resolve_output(out_dir, "out_dir")
        try:
            if os.path.exists(out_dir) and os.listdir(out_dir):
                fail("out_dir already holds files", out_dir=out_dir)
        except OSError as exc:
            fail("out_dir cannot be listed (%s)" % describe(exc), out_dir=out_dir)

    long_lines = 0
    if file_arg is not None:
        if not isinstance(file_arg, str) or not file_arg:
            fail("timestamps_file must be a path")
        try:
            with open(file_arg, "r", encoding="utf-8", errors="replace") as fh:
                values = []
                while True:
                    line = fh.readline(MAX_VALUE_CHARS + 1)
                    if not line:
                        break
                    if len(line) > MAX_VALUE_CHARS and not line.endswith("\n"):
                        # a line that long is no time: it is counted as unreadable, and the rest of it is skipped, not held
                        while line and not line.endswith("\n"):
                            line = fh.readline(MAX_VALUE_CHARS)
                        values.append(None)
                        long_lines += 1
                        if len(values) > MAX_EVENTS:
                            fail("the series has more than %d events: split it by destination or by window" % MAX_EVENTS, timestamps_file=file_arg)
                        continue
                    text = line.strip()
                    if not text or text.startswith("#"):
                        continue
                    values.append(text)
                    if len(values) > MAX_EVENTS:
                        fail("the series has more than %d events: split it by destination or by window" % MAX_EVENTS, timestamps_file=file_arg)
        except OSError as exc:
            fail("timestamps_file could not be read (%s)" % describe(exc), timestamps_file=file_arg)
    else:
        if not isinstance(raw, list) or not raw:
            fail("timestamps is required: a non-empty list of event times, epoch seconds or ISO 8601 with a zone")
        if len(raw) > MAX_EVENTS:
            fail("the series has more than %d events: split it by destination or by window" % MAX_EVENTS)
        values = raw

    parsed, rejected, first_rejected, assumed = [], {"unparseable": 0, "non_finite": 0, "out_of_range": 0}, [], 0
    naive = 0
    first_naive = []
    for index, value in enumerate(values):
        seconds, reason = read_time(value, assume_utc)
        if reason == "naive":
            naive += 1
            if len(first_naive) < 5:
                first_naive.append({"index": index, "value": str(value)[:80]})
            continue
        if reason == "assumed_utc":
            assumed += 1
        elif reason:
            rejected[reason] += 1
            if len(first_rejected) < 5:
                first_rejected.append({"index": index, "value": str(value)[:80], "reason": reason})
            continue
        parsed.append((round(seconds, 6), index))
    if naive:
        fail("%d of the times carry no time zone; a series that is not UTC cannot be read as UTC without being told to. Give the zone in each time "
             "(Z or +hh:mm), or pass assume_utc: true if the source is known to be UTC" % naive,
             timestamps_without_zone=naive, first_without_zone=first_naive)

    window_end = None
    if args.get("window_end") is not None:
        window_end, why = read_time(args["window_end"], assume_utc)
        if window_end is None:
            fail("window_end could not be read as a time (%s): epoch seconds or ISO 8601 with a zone" % why, window_end=str(args["window_end"])[:80])

    first_index = {}
    for seconds, index in parsed:
        first_index.setdefault(seconds, index)
    distinct = sorted(first_index)
    if len(distinct) < minimum:
        fail("too few distinct usable times to score", usable=len(parsed), distinct_events=len(distinct), needed=minimum,
             rejected=rejected, first_rejected=first_rejected,
             note="A handful of distinct events cannot show periodicity, and scoring them would invent a pattern. Identical times count once.")
    if window_end is not None and window_end < distinct[-1]:
        fail("window_end is earlier than the last event: the window cannot end before the series does",
             window_end=iso(window_end), last_event=iso(distinct[-1]))

    intervals = [round(b - a, 6) for a, b in zip(distinct, distinct[1:])]
    median = statistics.median(intervals)
    mad = statistics.median([abs(i - median) for i in intervals])
    relative = (mad / median) if median else None
    span = distinct[-1] - distinct[0]
    expected = (span / median + 1) if median else None
    density = (len(distinct) / expected) if expected else None

    final_gap = {"present": False}
    if len(intervals) >= 3 and median and intervals[-1] > median * 4:
        final_gap = {"present": True, "from": iso(distinct[-2]), "to": iso(distinct[-1]),
                     "final_interval_seconds": intervals[-1], "median_interval_seconds": round(median, 6),
                     "ratio": round(intervals[-1] / median, 3), "threshold": "more than four times the median interval",
                     "meaning": "The last interval is long and ends in an observed event: the series resumed, or was only sparsely observed in that "
                                "stretch. It is an observation about the series, not a cessation, and no time of any stopping follows from it."}

    cessation = {"assessed": False}
    if window_end is None:
        cessation["reason_not_assessed"] = ("no observation window was declared. Whether anything stopped is a statement about the time after the last "
                                            "event, and it needs window_end (when the sensor's coverage of this series ends) and "
                                            "sensor_coverage_confirmed")
    elif not confirmed:
        cessation["reason_not_assessed"] = ("a window_end was declared without sensor_coverage_confirmed: silence after the last event means nothing "
                                            "unless the sensor was recording over it, and this tool cannot tell")
        cessation["declared_window_end"] = iso(window_end)
    else:
        silent = round(window_end - distinct[-1], 6)
        over = bool(median) and silent > median * 4
        cessation = {"assessed": True, "declared_window_end": iso(window_end), "sensor_coverage_confirmed": True,
                     "silent_after_last_event_seconds": silent, "silent_over_4x_median": over}
        if over:
            cessation["statement"] = ("No event in this series from %s to the declared window end %s (%s seconds, %.1f times the median interval), "
                                      "with the sensor confirmed recording over that window. This is a bounded negative about this series as it was "
                                      "defined, nothing more: it does not show that a channel ended, changed or moved, and says nothing about other "
                                      "series, destinations or protocols." % (iso(distinct[-1]), iso(window_end), silent, silent / median))
        else:
            cessation["statement"] = ("The series has events up to %s seconds before the declared window end; no silence longer than four median "
                                      "intervals is observed at its end." % silent)

    page = LosslessPage("beacon_intervals", limit)
    tsv = None
    tsv_path = None
    try:
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            tsv_path = os.path.join(out_dir, "intervals.tsv")
            tsv = open(tsv_path, "w", encoding="utf-8", newline="\n")
            tsv.write("index\tfrom_utc\tto_utc\tseconds\tfrom_input_index\tto_input_index\n")
        for i, (a, b, gap) in enumerate(zip(distinct, distinct[1:], intervals)):
            row = {"index": i, "from": iso(a), "to": iso(b), "seconds": gap, "from_input_index": first_index[a], "to_input_index": first_index[b]}
            page.add(row)
            if tsv is not None:
                tsv.write("%d\t%s\t%s\t%s\t%d\t%d\n" % (i, row["from"], row["to"], gap, row["from_input_index"], row["to_input_index"]))
        pages = page.finish()
    except OSError as exc:
        fail("the interval list could not be written (%s)" % describe(exc), out_dir=out_dir)
    finally:
        if tsv is not None:
            tsv.close()

    print(json.dumps({
        "tool": TOOL,
        "label": args.get("label"),
        "events": len(parsed),
        "distinct_events": len(distinct),
        "duplicate_timestamps": len(parsed) - len(distinct),
        "values_supplied": len(values),
        "rejected": rejected,
        "first_rejected": first_rejected,
        "naive_timestamps_assumed_utc": assumed,
        "first": iso(distinct[0]), "last": iso(distinct[-1]),
        "span_seconds": round(span, 3),
        "median_interval_seconds": round(median, 3),
        "median_absolute_deviation_seconds": round(mad, 3),
        "mad_over_median": round(relative, 4) if relative is not None else None,
        "shape": shape_of(relative),
        "shape_cutoffs": "mad_over_median <= 0.02 tight_cluster, <= 0.25 clustered, <= 0.6 loose_cluster, above dispersed: conventions of this tool",
        "event_density_ratio": round(density, 3) if density else None,
        "intervals": {"count": len(intervals), "min_seconds": min(intervals), "max_seconds": max(intervals)},
        "intervals_inline": [r["seconds"] for r in page.page],
        "intervals_page": pages,
        "intervals_tsv": sealed_path(tsv_path),
        "input_index_note": "from_input_index and to_input_index are positions in the series you supplied (0-based; in a timestamps_file, among its non-comment lines), the first occurrence when a time is repeated",
        "lines_over_limit": long_lines,
        "long_final_gap": final_gap,
        "observation_window": {"declared_end": iso(window_end) if window_end is not None else None},
        "cessation": cessation,
        "note": "A tight cluster is a measurement, not a verdict: update checks, telemetry, NTP, revocation checks and monitoring agents are all "
                "more regular than most malware, and a command channel can be irregular, or one long connection with no schedule at all. Set the "
                "median interval and the transfer sizes against comparable hosts and services, and corroborate with host or service evidence "
                "before calling a series anything. event_density_ratio compares the distinct events with the count a constant schedule at the "
                "median would give over the span; below 1 it does not say events are missing. A long final gap is an interval that ended in "
                "another event; cessation is assessed only with a declared window and a confirmed sensor.",
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
