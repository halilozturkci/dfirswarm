#!/usr/bin/env python3
"""Say what a number could be as a date, under every epoch that matters.

A field in an artefact holds a number and the documentation does not say which
clock wrote it. Guess wrong and the answer is off by decades, or by 66 years,
or by a factor of a thousand, and the report reads as though it were
established. This tool lists the candidates. The artefact's schema decides
which one is right, not this tool, and a plausible date is not a determination.

The epochs, and where each one shows up:

    Unix seconds            1970-01-01  syslog, sqlite, most Linux
    Unix milliseconds       1970-01-01  Java, Android, many app databases
    Unix microseconds       1970-01-01  Chromium's older tables, systemd
    Unix nanoseconds        1970-01-01  APFS, many log formats
    FILETIME                1601-01-01  everything Windows, in 100 ns ticks
    WebKit / Chrome         1601-01-01  Chromium history, in microseconds
    Apple absolute (Cocoa)  2001-01-01  macOS and iOS plists, seconds
    Apple, nanoseconds      2001-01-01  KnowledgeC and biome, sometimes
    HFS+                    1904-01-01  older Mac file systems, seconds
    OLE automation          1899-12-30  Office metadata, days as a float
    DOS date and time       1980-01-01  FAT, ZIP, shell items; packed, LOCAL time

The arithmetic is exact: the value is read as a decimal (or a hexadecimal
integer), never through a float, and a fraction of a second or of a day is kept
to the nanosecond; whatever lies beyond the ninth digit is returned as
`remainder_s`, not dropped. A DOS value and an OLE automation date carry no
zone: they are returned without a `Z`, as the writing machine's own local time.
Every other reading is UTC, which is what its epoch defines. Nothing here reads
the wall clock: plausibility is judged against an explicit range, so the same
input gives the same answer on any day.
"""
import datetime
import decimal
import json
import re
import sys

TOOL = {"name": "timestamp_decode", "version": 2}

UTC = datetime.timezone.utc
CTX = decimal.Context(prec=120, traps=[decimal.InvalidOperation, decimal.Overflow, decimal.DivisionByZero])
D = decimal.Decimal

# Epoch bases, as naive components: whether a reading is UTC is said per clock.
UNIX = datetime.datetime(1970, 1, 1)
FILETIME = datetime.datetime(1601, 1, 1)
APPLE = datetime.datetime(2001, 1, 1)
HFS = datetime.datetime(1904, 1, 1)
OLE = datetime.datetime(1899, 12, 30)

DEFAULT_FROM = "1990-01-01"
DEFAULT_TO = "2040-01-01"
MAX_DIGITS = 40
MAX_SIGNIFICANT = 60
TEXT_MAX = 80                    # characters of the value as written (an exponent or a hexadecimal run included)
SHOWN_DIGITS = 9


def fail(message, **extra):
    print(json.dumps({"error": message, "tool": TOOL, **extra}))
    raise SystemExit(1)


# Each clock: its epoch, the length of one unit in seconds (exact), the digits of
# fraction its own resolution has, whether the epoch defines UTC, and its use.
CLOCKS = [
    ("Unix seconds", UNIX, D(1), 0, True, "1 s", "syslog, sqlite, most Linux"),
    ("Unix milliseconds", UNIX, D("0.001"), 3, True, "1 ms", "Java, Android, app databases"),
    ("Unix microseconds", UNIX, D("0.000001"), 6, True, "1 µs", "systemd, some Chromium tables"),
    ("Unix nanoseconds", UNIX, D("0.000000001"), 9, True, "1 ns", "APFS, many log formats"),
    ("FILETIME (100 ns)", FILETIME, D("0.0000001"), 7, True, "100 ns", "Windows, everywhere"),
    ("WebKit / Chrome (µs)", FILETIME, D("0.000001"), 6, True, "1 µs", "Chromium history and cookies"),
    ("Apple absolute (s)", APPLE, D(1), 0, True, "1 s", "macOS and iOS plists"),
    ("Apple absolute (ns)", APPLE, D("0.000000001"), 9, True, "1 ns", "KnowledgeC, biome"),
    ("HFS+ (s)", HFS, D(1), 0, True, "1 s", "older Mac file systems"),
]


def parse_value(raw, as_hex):
    """The value as an exact decimal. Booleans and anything that is not a number are refused."""
    if isinstance(raw, bool) or raw is None:
        fail("value is required: the number to read as a date", value=raw)
    text = str(raw).strip().replace("_", "")
    if not text:
        fail("value is empty")
    if len(text) > TEXT_MAX:
        fail("value is longer than %d characters: no clock here is written with more" % TEXT_MAX, length=len(text))
    if "," in text:
        fail("a comma is ambiguous (a thousands separator or a decimal comma): write the number without one", value=raw)
    try:
        if re.fullmatch(r"[+-]?0[xX][0-9a-fA-F]+", text) or (as_hex and re.fullmatch(r"[+-]?[0-9a-fA-F]+", text)):
            number = D(int(text, 16))
        elif as_hex:
            raise ValueError(text)
        elif re.fullmatch(r"[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)", text):
            number = CTX.create_decimal(text)
        elif re.fullmatch(r"[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)[eE][+-]?[0-9]{1,3}", text):
            number = CTX.create_decimal(text)
        else:
            raise ValueError(text)
    except (ValueError, decimal.DecimalException):
        fail("value is not a number: a decimal, a decimal with a fraction, or hexadecimal", value=raw)
    if number != 0 and (number.adjusted() > MAX_DIGITS or number.adjusted() < -MAX_DIGITS):
        fail("value is outside what this tool reads (more than %d digits)" % MAX_DIGITS, value=raw)
    if len(number.as_tuple().digits) > MAX_SIGNIFICANT:
        fail("value has more than %d significant digits: the arithmetic here is exact up to that and no further" % MAX_SIGNIFICANT, value=raw)
    return text, number


def fraction_digits(frac):
    """The digits of a fraction in [0, 1), exactly: ('123456789', 'beyond') split at the ninth."""
    text = format(frac, "f")
    digits = text.split(".", 1)[1].rstrip("0") if "." in text else ""
    return digits[:SHOWN_DIGITS], digits[SHOWN_DIGITS:]


def stamp(base, seconds, utc, min_digits):
    """(when, remainder_s) for `seconds` after `base`, or (None, reason)."""
    whole = int(seconds.to_integral_value(rounding=decimal.ROUND_FLOOR))
    frac = CTX.subtract(seconds, D(whole))
    try:
        moment = base + datetime.timedelta(seconds=whole)
    except OverflowError:
        return None, "outside the years 1 to 9999 that a date can hold"
    shown, beyond = fraction_digits(frac)
    when = moment.replace(microsecond=0).isoformat() + ("." + shown if shown else "") + ("Z" if utc else "")
    # What lies beyond the ninth digit, as the decimal number of seconds it is.
    return when, ("0." + "0" * SHOWN_DIGITS + beyond if beyond else "0")


def dos_readings(number):
    """Packed FAT date and time. Both word orders are tried and each valid one is
    its own reading: date in the high word and time in the low (ZIP's and the
    directory entry's order), or the reverse. A reading is made through a real
    date, so month 13 or 30 February is refused, and the refusal is said."""
    if number != number.to_integral_value() or number < 0 or number > 0xFFFFFFFF:
        return [], ["DOS date and time: not a 32-bit unsigned integer"]
    value = int(number)
    high, low = (value >> 16) & 0xFFFF, value & 0xFFFF
    readings, refused = [], []
    for label, d, t in (("date in the high word", high, low), ("date in the low word", low, high)):
        year, month, day = ((d >> 9) & 0x7F) + 1980, (d >> 5) & 0x0F, d & 0x1F
        hour, minute, second = (t >> 11) & 0x1F, (t >> 5) & 0x3F, (t & 0x1F) * 2
        try:
            moment = datetime.datetime(year, month, day, hour, minute, second)
        except ValueError as exc:
            refused.append("DOS date and time (%s): %04d-%02d-%02d %02d:%02d:%02d is not a calendar date and time (%s)"
                           % (label, year, month, day, hour, minute, second, exc))
            continue
        readings.append({
            "epoch": "DOS date and time (%s)" % label, "when": moment.isoformat(), "zone": "none stated: the local time of the machine that wrote it",
            "precision": "2 s", "remainder_s": "0", "used_by": "FAT, ZIP, shell items", "_moment": moment, "_base": datetime.datetime(1980, 1, 1)})
    return readings, refused


def ole_reading(number):
    """OLE automation date: days from 1899-12-30. For a negative value the
    integer part is the day and the fraction is the time of day counted
    forwards, so -1.25 is 29 December 1899 06:00, not 18:00."""
    whole = number.to_integral_value(rounding=decimal.ROUND_DOWN)
    frac = abs(CTX.subtract(number, whole))
    try:
        day = OLE + datetime.timedelta(days=int(whole))
    except OverflowError:
        return None, "OLE automation date: outside the years 1 to 9999 that a date can hold"
    seconds = CTX.multiply(frac, D(86400))
    when, remainder = stamp(day, seconds, False, 0)
    if when is None:
        return None, "OLE automation date: " + remainder
    return {"epoch": "OLE automation (days)", "when": when, "zone": "none stated: the local time of the writing application",
            "precision": "1 day, with a fraction of a day", "remainder_s": remainder, "used_by": "Office document metadata",
            "_moment": datetime.datetime.fromisoformat(when[:19]), "_base": OLE}, None


def parse_day(text, name):
    try:
        return datetime.datetime.strptime(text, "%Y-%m-%d")
    except (TypeError, ValueError):
        fail("%s is a date as YYYY-MM-DD" % name, **{name: text})


def main():
    try:
        # A JSON number is kept as the text it was written in, never read through a float.
        args = json.load(sys.stdin, parse_float=str, parse_int=int)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    as_hex = args.get("hex", False)
    if not isinstance(as_hex, bool):
        fail("hex is true or false")

    text, number = parse_value(args.get("value"), as_hex)
    low = parse_day(args.get("plausible_from", DEFAULT_FROM), "plausible_from")
    high_day = parse_day(args.get("plausible_to", DEFAULT_TO), "plausible_to")
    if low >= high_day:
        fail("plausible_from must be before plausible_to", plausible_from=args.get("plausible_from"), plausible_to=args.get("plausible_to"))
    high = high_day + datetime.timedelta(days=1)          # plausible_to is a day, and the whole day is inside
    explicit_range = "plausible_from" in args or "plausible_to" in args
    plausible_only = args.get("plausible_only", False)
    if not isinstance(plausible_only, bool):
        fail("plausible_only is true or false")

    readings, refused, out_of_range = [], [], []
    for epoch, base, unit, digits, utc, precision, used in CLOCKS:
        seconds = CTX.multiply(number, unit)
        when, remainder = stamp(base, seconds, utc, digits)
        if when is None:
            out_of_range.append(epoch)
            continue
        readings.append({"epoch": epoch, "when": when, "zone": "UTC, as the epoch defines it", "precision": precision,
                         "remainder_s": remainder, "used_by": used,
                         "_moment": datetime.datetime.fromisoformat(when[:19]), "_base": base})
    ole, why = ole_reading(number)
    if ole:
        readings.append(ole)
    else:
        out_of_range.append("OLE automation (days)")
    if out_of_range:
        refused.append("outside the years 1 to 9999 that a date can hold, under: " + ", ".join(out_of_range))
    dos, dos_refused = dos_readings(number)
    readings += dos
    refused += dos_refused

    for r in readings:
        moment, base = r.pop("_moment"), r.pop("_base")
        # A reading that lands within a year of its own epoch means the value was far
        # too small for that clock: it is arithmetic, not a date, and it drowns the real answer.
        # (Only with the default range: a caller who names a range decides what is plausible.)
        near = (not explicit_range) and not r["epoch"].startswith("DOS") and abs((moment - base).total_seconds()) < 86400 * 366
        r["plausible"] = bool(low <= moment <= high and not near)
        if near:
            r["why_not_plausible"] = "within a year of its own epoch: the value is too small for this clock"
        elif not r["plausible"]:
            r["why_not_plausible"] = "outside the reference range"
    ranked = sorted(readings, key=lambda r: not r["plausible"])
    kept = [r for r in ranked if r["plausible"]] if plausible_only else ranked
    print(json.dumps({
        "tool": TOOL,
        "value": text,
        "hex": hex(int(number)) if number == number.to_integral_value() else None,
        "reference_range": {"from": low.date().isoformat(), "to": high_day.date().isoformat(),
                            "meaning": "a ranking aid supplied by the caller or defaulted, not evidence: a date outside it can still be right"},
        "readings": kept,
        "reading_count": len(kept),
        "dropped_as_implausible": len(ranked) - len(kept),
        "refused": refused,
        "note": "More than one reading can be plausible; the artefact decides which, not this tool. "
                "Say in the report which epoch you applied and why the artefact uses it. A DOS "
                "value or an OLE date has no zone: it is the local time of the machine or application that "
                "wrote it, and needs that machine's timezone (with its daylight-saving history for that date) "
                "before it can join a UTC timeline. Keep the raw value beside any converted time.",
    }, indent=2))


if __name__ == "__main__":
    main()
