#!/usr/bin/env python3
"""Build a super timeline with Plaso, and hand back something a swarm can read.

Our own timeline is the ledger: facts an agent decided were worth recording,
each with a citation. Plaso's is the opposite and the two are complementary —
every timestamp on the volume, from every parser, with no judgement applied.
An examiner wants both: the machine timeline to find the window, the ledger to
say what happened in it.

Two things this wrapper exists to enforce.

The first is the parser filter. A default log2timeline run over a 60 GB image
takes hours and returns tens of millions of events, most of them filestat
noise. Naming the parsers you actually need turns that into minutes, and the
output says which filter produced it so a reviewer can repeat it.

The second is the timezone. Plaso writes UTC, but it needs the evidence
machine's own zone to interpret the formats that store local time. Getting it
wrong shifts a whole class of artefacts and nothing in the output says so,
which is why the zone used is returned with the result.
"""
import datetime
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_TIMEOUT = 1800


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    return dest


def readable(stamp):
    """Plaso writes microseconds since the epoch; an examiner reads ISO 8601 UTC."""
    if stamp is None:
        return None
    if isinstance(stamp, str):
        return stamp
    try:
        return datetime.datetime.fromtimestamp(
            int(stamp) / 1_000_000, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError, TypeError):
        return str(stamp)


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    source = args.get("source")
    if not isinstance(source, str) or not source:
        fail("source is required: an image, a partition or a collection directory")
    if not os.path.exists(source):
        fail("no such source", source=source)

    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: a directory under work/ for the storage file and the output")
    resolve_output(out_dir)

    l2t = shutil.which("log2timeline.py") or shutil.which("log2timeline")
    psort = shutil.which("psort.py") or shutil.which("psort")
    if not l2t or not psort:
        fail("Plaso is not on PATH",
             missing=[n for n, p in (("log2timeline.py", l2t), ("psort.py", psort)) if not p],
             install="python3 -m pip install plaso, or apt-get install -y plaso-tools")

    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 30:
        fail("timeout_seconds must be an integer of at least 30")
    sample = args.get("sample", 20)
    if not isinstance(sample, int) or isinstance(sample, bool) or sample < 0:
        fail("sample must be a non-negative integer")

    os.makedirs(out_dir, exist_ok=True)
    store = os.path.join(out_dir, "timeline.plaso")
    output = os.path.join(out_dir, "timeline.jsonl")

    collect = [l2t, "--status_view", "none", "--partitions", "all", "--volumes", "all",
               "--unattended", "--quiet"]
    if args.get("parsers"):
        collect += ["--parsers", str(args["parsers"])]
    if args.get("timezone"):
        collect += ["--timezone", str(args["timezone"])]
    collect += ["--storage_file", store, source]

    try:
        first = subprocess.run(collect, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        fail("log2timeline did not finish in time; narrow it with parsers",
             after_seconds=timeout, command=" ".join(collect), partial_storage=store)
    if first.returncode != 0 and not os.path.isfile(store):
        fail("log2timeline failed", exit_code=first.returncode,
             stderr=(first.stderr or "").strip(), command=" ".join(collect))

    export = [psort, "--status_view", "none", "-o", "json_line", "-w", output]
    if args.get("psort_filter"):
        export += ["--filter", str(args["psort_filter"])]
    export += [store]
    try:
        second = subprocess.run(export, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        fail("psort did not finish in time", after_seconds=timeout, storage=store)
    if second.returncode != 0 and not os.path.isfile(output):
        fail("psort failed", exit_code=second.returncode,
             stderr=(second.stderr or "").strip(), command=" ".join(export))

    events, head = 0, []
    first_event = last_event = None
    parsers_seen = {}
    try:
        with open(output, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                events += 1
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                stamp = readable(row.get("datetime") or row.get("timestamp"))
                if stamp is not None:
                    if first_event is None:
                        first_event = stamp
                    last_event = stamp
                name = row.get("parser") or row.get("data_type") or "unknown"
                parsers_seen[name] = parsers_seen.get(name, 0) + 1
                if len(head) < sample:
                    entry = {k: row.get(k) for k in
                             ("timestamp_desc", "parser", "data_type", "display_name")
                             if row.get(k) is not None}
                    entry["datetime"] = stamp
                    entry["message"] = row.get("message") or ""
                    head.append(entry)
    except OSError as exc:
        fail("psort wrote nothing this tool could read", output=output, reason=str(exc))

    top = sorted(parsers_seen.items(), key=lambda kv: -kv[1])[:15]
    print(json.dumps({
        "source": source,
        "storage_file": store,
        "output": output,
        "events": events,
        "first_event": first_event,
        "last_event": last_event,
        "by_parser": [{"parser": n, "events": c} for n, c in top],
        "parsers_filter": args.get("parsers") or "all (the default, and usually the wrong choice)",
        "timezone_used": args.get("timezone") or "not given; Plaso assumed UTC for formats that store local time",
        "psort_filter": args.get("psort_filter"),
        "sample": head,
        "note": "Timestamps here are UTC. This is every timestamp on the volume, not a set of "
                "findings: take what matters into the ledger with a citation, and say in the "
                "report which parser filter and which timezone produced the timeline.",
    }, indent=2))


if __name__ == "__main__":
    main()
