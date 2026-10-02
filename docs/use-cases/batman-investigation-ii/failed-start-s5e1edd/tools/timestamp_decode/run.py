#!/usr/bin/env python3
"""Say what a number could be as a date, under every epoch that matters.

A field in an artefact holds a number and the documentation does not say which
clock wrote it. Guess wrong and the answer is off by decades, or by 66 years,
or by a factor of a thousand — and the report reads as though it were
established. This has cost the published runs real time, and it is the kind of
arithmetic a tool should absorb.

The epochs, and where each one shows up:

    Unix seconds            1970-01-01  syslog, sqlite, most Linux
    Unix milliseconds       1970-01-01  Java, Android, many app databases
    Unix microseconds       1970-01-01  Chromium's older tables, systemd
    FILETIME                1601-01-01  everything Windows, in 100 ns ticks
    WebKit / Chrome         1601-01-01  Chromium history, in microseconds
    Apple absolute (Cocoa)  2001-01-01  macOS and iOS plists, seconds
    Apple, nanoseconds      2001-01-01  KnowledgeC and biome, sometimes
    HFS+                    1904-01-01  older Mac file systems, seconds
    OLE automation          1899-12-30  Office metadata, days as a float
    DOS date and time       1980-01-01  FAT, ZIP, shell items; packed, LOCAL time

A DOS value is local time on the machine that wrote it, not UTC, and the output
says so. Everything else here is returned as UTC.
"""
import datetime
import json
import struct
import sys

UTC = datetime.timezone.utc
UNIX = datetime.datetime(1970, 1, 1, tzinfo=UTC)
FILETIME = datetime.datetime(1601, 1, 1, tzinfo=UTC)
APPLE = datetime.datetime(2001, 1, 1, tzinfo=UTC)
HFS = datetime.datetime(1904, 1, 1, tzinfo=UTC)
OLE = datetime.datetime(1899, 12, 30, tzinfo=UTC)


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def offset(base, **kw):
    try:
        return iso(base + datetime.timedelta(**kw))
    except (OverflowError, OSError, ValueError):
        return None


def dos(value):
    """Packed FAT date and time: date in the high word, time in the low word."""
    if value < 0 or value > 0xFFFFFFFF:
        return None
    date, time = (value >> 16) & 0xFFFF, value & 0xFFFF
    for d, t in ((date, time), (time, date)):        # both packing orders exist in the wild
        year = ((d >> 9) & 0x7F) + 1980
        month, day = (d >> 5) & 0x0F, d & 0x1F
        hour, minute, second = (t >> 11) & 0x1F, (t >> 5) & 0x3F, (t & 0x1F) * 2
        if 1 <= month <= 12 and 1 <= day <= 31 and hour < 24 and minute < 60 and second < 60:
            try:
                return "%04d-%02d-%02dT%02d:%02d:%02d (local time, not UTC)" % (
                    year, month, day, hour, minute, second)
            except ValueError:
                continue
    return None


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    raw = args.get("value")
    if raw is None:
        fail("value is required: the number to read as a date")
    text = str(raw).strip().replace("_", "").replace(",", "")
    try:
        if text.lower().startswith("0x") or args.get("hex"):
            value = int(text, 16)
        else:
            value = int(float(text)) if "." in text else int(text)
    except ValueError:
        fail("value is not a number", value=raw)

    readings = [
        {"epoch": "Unix seconds", "when": offset(UNIX, seconds=value), "used_by": "syslog, sqlite, most Linux"},
        {"epoch": "Unix milliseconds", "when": offset(UNIX, milliseconds=value), "used_by": "Java, Android, app databases"},
        {"epoch": "Unix microseconds", "when": offset(UNIX, microseconds=value), "used_by": "systemd, some Chromium tables"},
        {"epoch": "FILETIME (100 ns)", "when": offset(FILETIME, microseconds=value // 10), "used_by": "Windows, everywhere"},
        {"epoch": "WebKit / Chrome (µs)", "when": offset(FILETIME, microseconds=value), "used_by": "Chromium history and cookies"},
        {"epoch": "Apple absolute (s)", "when": offset(APPLE, seconds=value), "used_by": "macOS and iOS plists"},
        {"epoch": "Apple absolute (ns)", "when": offset(APPLE, microseconds=value / 1000), "used_by": "KnowledgeC, biome"},
        {"epoch": "HFS+ (s)", "when": offset(HFS, seconds=value), "used_by": "older Mac file systems"},
        {"epoch": "OLE automation (days)", "when": offset(OLE, days=value), "used_by": "Office document metadata"},
        {"epoch": "DOS date and time", "when": dos(value), "used_by": "FAT, ZIP, shell items"},
    ]
    readings = [r for r in readings if r["when"]]

    now = datetime.datetime.now(UTC)
    low, high = now.replace(year=1995), now.replace(year=now.year + 20)
    EPOCHS = {"Unix seconds": UNIX, "Unix milliseconds": UNIX, "Unix microseconds": UNIX,
              "FILETIME (100 ns)": FILETIME, "WebKit / Chrome (µs)": FILETIME,
              "Apple absolute (s)": APPLE, "Apple absolute (ns)": APPLE, "HFS+ (s)": HFS,
              "OLE automation (days)": OLE}

    def plausible(reading):
        head = reading["when"][:19]
        try:
            when = datetime.datetime.fromisoformat(head).replace(tzinfo=UTC)
        except ValueError:
            return False
        # A reading that lands on its own epoch means the value was far too small for
        # that clock — it is arithmetic, not a date, and it drowns the real answer.
        base = EPOCHS.get(reading["epoch"])
        if base is not None and abs((when - base).total_seconds()) < 86400 * 366:
            return False
        return low <= when <= high
    for reading in readings:
        reading["plausible"] = plausible(reading)

    kept = [r for r in readings if r["plausible"]] if args.get("plausible_only", True) else readings
    print(json.dumps({
        "value": value,
        "hex": hex(value),
        "readings": kept,
        "reading_count": len(kept),
        "dropped_as_implausible": len(readings) - len(kept),
        "note": "More than one reading can be plausible; the artefact decides which, not this tool. "
                "Say in the report which epoch you applied and why the artefact uses it. A DOS "
                "value is the local time of the machine that wrote it and needs that machine's "
                "timezone before it can join a UTC timeline.",
    }, indent=2))


if __name__ == "__main__":
    main()
