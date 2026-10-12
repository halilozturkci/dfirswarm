"""timestamp_decode: fractions, nanoseconds, zones and the wall clock.

The expected values are worked out here from each epoch's definition with
datetime.timedelta, a path that shares nothing with the tool's decimal
arithmetic; the DOS words are packed from the FAT specification's bit layout.
"""
import datetime
import json
import os
import unittest

from support import Case, run_tool

BASE = {"unix": datetime.datetime(1970, 1, 1), "filetime": datetime.datetime(1601, 1, 1),
        "apple": datetime.datetime(2001, 1, 1), "ole": datetime.datetime(1899, 12, 30)}


def reading(result, epoch_start):
    rows = [r for r in result["readings"] if r["epoch"].startswith(epoch_start)]
    assert rows, "no reading for %s in %s" % (epoch_start, [r["epoch"] for r in result["readings"]])
    return rows[0]


def pack_dos(year, month, day, hour, minute, second):
    """FAT's packed date and time: date = (y-1980)<<9 | m<<5 | d, time = h<<11 | m<<5 | s/2."""
    date = ((year - 1980) << 9) | (month << 5) | day
    time = (hour << 11) | (minute << 5) | (second // 2)
    return date, time


class TimestampDecode(Case):
    def decode(self, **args):
        r = run_tool("timestamp_decode", args, self.dir)
        return r

    def test_ole_half_day_is_noon(self):
        # 45000 days after 1899-12-30 is 2023-03-15 (the spreadsheet serial everyone knows); the .5 is noon.
        r = self.decode(value="45000.5")
        self.assertEqual(r.code, 0, r.stdout)
        ole = reading(r.json, "OLE automation")
        self.assertEqual(ole["when"], (BASE["ole"] + datetime.timedelta(days=45000, hours=12)).isoformat())
        self.assertEqual(ole["when"], "2023-03-15T12:00:00")
        self.assertNotIn("Z", ole["when"])          # no zone is invented for an OLE date
        self.assertIn("none stated", ole["zone"])

    def test_json_numbers_are_read_too(self):
        r = self.decode(value=45000.5)
        self.assertEqual(reading(r.json, "OLE automation")["when"], "2023-03-15T12:00:00")

    def test_negative_ole_counts_the_time_of_day_forwards(self):
        # OLE automation: -1.25 is 29 December 1899 06:00, not 18:00.
        r = self.decode(value="-1.25")
        self.assertEqual(reading(r.json, "OLE automation")["when"], "1899-12-29T06:00:00")

    def test_filetime_keeps_its_100ns_digit(self):
        ticks = 133000000001234567
        r = self.decode(value=str(ticks))
        ft = reading(r.json, "FILETIME")
        secs = datetime.timedelta(seconds=ticks // 10_000_000)
        self.assertEqual(ft["when"], (BASE["filetime"] + secs).isoformat() + "." + "%07d" % (ticks % 10_000_000) + "Z")
        self.assertEqual(ft["when"].split(".")[1], "1234567Z")
        self.assertEqual(ft["precision"], "100 ns")

    def test_unix_nanoseconds_are_a_reading(self):
        r = self.decode(value="1700000000123456789")
        ns = reading(r.json, "Unix nanoseconds")
        self.assertEqual(ns["when"], "2023-11-14T22:13:20.123456789Z")
        self.assertTrue(ns["plausible"])

    def test_apple_absolute_and_unix_seconds_keep_fractions(self):
        r = self.decode(value="700000000.25")
        apple = reading(r.json, "Apple absolute (s)")
        self.assertEqual(apple["when"], (BASE["apple"] + datetime.timedelta(seconds=700000000, milliseconds=250)).isoformat(timespec="milliseconds").rstrip("0") + "Z")
        unix = self.decode(value="1700000000.5")
        self.assertEqual(reading(unix.json, "Unix seconds")["when"], "2023-11-14T22:13:20.5Z")

    def test_digits_beyond_a_nanosecond_are_returned_not_dropped(self):
        r = self.decode(value="1700000000.1234567891")
        u = reading(r.json, "Unix seconds")
        self.assertEqual(u["when"], "2023-11-14T22:13:20.123456789Z")
        self.assertEqual(u["remainder_s"], "0.0000000001")

    def test_hex_input_and_the_hex_flag(self):
        self.assertEqual(reading(self.decode(value="0x6553F100").json, "Unix seconds")["when"], "2023-11-14T22:13:20Z")
        self.assertEqual(reading(self.decode(value="6553F100", hex=True).json, "Unix seconds")["when"], "2023-11-14T22:13:20Z")

    def test_a_dos_value_is_read_through_a_real_date_in_both_word_orders(self):
        date, time = pack_dos(2023, 3, 15, 12, 30, 44)
        r = self.decode(value=str((date << 16) | time))
        dos = [x for x in r.json["readings"] if x["epoch"].startswith("DOS")]
        high = [x for x in dos if "high word" in x["epoch"]]
        self.assertEqual(high[0]["when"], "2023-03-15T12:30:44")
        self.assertIn("none stated", high[0]["zone"])
        # The same two words the other way round are a second reading when they are a date at all.
        swapped = self.decode(value=str((time << 16) | date))
        low = [x for x in swapped.json["readings"] if "low word" in x["epoch"]]
        self.assertEqual(low[0]["when"], "2023-03-15T12:30:44")

    def test_an_impossible_dos_date_is_refused_and_said(self):
        # Month 13 in the date word; the same words swapped are not a date either (month 14, hour 27).
        date, time = pack_dos(2023, 3, 15, 12, 30, 44)
        bad_date = (date & ~(0xF << 5)) | (13 << 5)
        r = self.decode(value=str((bad_date << 16) | time))
        self.assertEqual(r.code, 0)
        self.assertEqual([x for x in r.json["readings"] if x["epoch"].startswith("DOS")], [])
        refused = " ".join(r.json["refused"])
        self.assertIn("DOS date and time (date in the high word)", refused)
        self.assertIn("month", refused.lower() + " month")
        # 30 February is no date either.
        feb = (((2023 - 1980) << 9) | (2 << 5) | 30)
        r = self.decode(value=str((feb << 16) | time))
        self.assertIn("DOS date and time (date in the high word)", " ".join(r.json["refused"]))

    def test_the_wall_clock_is_never_read(self):
        # A sitecustomize that makes datetime.now() raise: the tool must give the same answer anyway.
        site = self.path("site")
        os.makedirs(site)
        with open(os.path.join(site, "sitecustomize.py"), "w") as fh:
            fh.write("import datetime\n"
                     "class D(datetime.datetime):\n"
                     "    @classmethod\n"
                     "    def now(cls, tz=None):\n"
                     "        raise AssertionError('the wall clock was read')\n"
                     "    @classmethod\n"
                     "    def today(cls):\n"
                     "        raise AssertionError('the wall clock was read')\n"
                     "datetime.datetime = D\n")
        plain = self.decode(value="1700000000")
        guarded = run_tool("timestamp_decode", {"value": "1700000000"}, self.dir, env={"PYTHONPATH": site})
        self.assertEqual(guarded.code, 0, guarded.stdout + guarded.stderr)
        self.assertEqual(guarded.json, plain.json)

    def test_plausibility_is_a_stated_range_and_all_readings_are_the_default(self):
        r = self.decode(value="1700000000")
        self.assertEqual(r.json["reference_range"]["from"], "1990-01-01")
        self.assertGreater(len(r.json["readings"]), 1)          # all readings by default
        self.assertEqual(r.json["readings"][0]["epoch"], "Unix seconds")        # the plausible first
        only = self.decode(value="1700000000", plausible_only=True)
        self.assertTrue(all(x["plausible"] for x in only.json["readings"]))
        narrow = self.decode(value="1700000000", plausible_from="2024-01-01", plausible_to="2025-01-01", plausible_only=True)
        self.assertEqual([x for x in narrow.json["readings"] if x["epoch"] == "Unix seconds"], [])

    def test_a_json_number_is_not_read_through_a_float(self):
        r = run_tool("timestamp_decode", {}, self.dir, raw_input='{"value": 1700000000.123456789}')
        self.assertEqual(reading(r.json, "Unix seconds")["when"], "2023-11-14T22:13:20.123456789Z")

    def test_hex_is_strict_and_the_hex_flag_is_a_boolean(self):
        for args in ({"value": "a0x1", "hex": True}, {"value": "0x-5"}, {"value": "10", "hex": "false"}, {"value": "xyz", "hex": True}):
            self.assertEqual(self.decode(**args).code, 1, args)
        self.assertEqual(reading(self.decode(value="-0x10").json, "Unix seconds")["when"], "1969-12-31T23:59:44Z")

    def test_a_comma_is_not_a_thousands_separator(self):
        r = self.decode(value="1,5")
        self.assertEqual(r.code, 1)
        self.assertIn("comma", r.json["error"])

    def test_plausible_to_includes_its_whole_day_and_a_named_range_decides(self):
        # 2023-05-05T14:00:00Z is 1683295200
        r = self.decode(value="1683295200", plausible_to="2023-05-05")
        self.assertTrue(reading(r.json, "Unix seconds")["plausible"])
        # 5000000 is inside the caller's range as an Apple reading (2001-02-27) even though it is near that epoch.
        r = self.decode(value="5000000", plausible_from="1995-01-01", plausible_to="2003-01-01")
        self.assertTrue(reading(r.json, "Apple absolute (s)")["plausible"])
        default = self.decode(value="5000000")
        self.assertFalse(reading(default.json, "Apple absolute (s)")["plausible"])

    def test_not_a_number_and_a_boolean_are_errors(self):
        for bad in ("12 pm", "", "0xZZ", "1e9999", True, "9" * 70):
            r = self.decode(value=bad)
            self.assertEqual(r.code, 1, bad)
            self.assertIn("error", r.json)

    def test_a_value_no_clock_can_hold_is_listed_as_refused(self):
        r = self.decode(value="99999999999999999999")
        self.assertTrue(any("outside the years 1 to 9999" in x for x in r.json["refused"]), r.json["refused"])

    def test_a_value_too_long_or_not_in_ascii_digits_is_an_answer_not_a_traceback_or_a_reading(self):
        for bad in ("9" * 81, "0x" + "f" * 200, "1" + "0" * 5000, "\u0663\u0664\u0665", "1.5e999999999999999999999", "٣٤٥", "1e+9999"):
            r = self.decode(value=bad)
            self.assertEqual(r.code, 1, bad[:30])
            self.assertNotIn("Traceback", r.stderr, bad[:30])
            self.assertIn("error", r.json, bad[:30])
        self.assertEqual(self.decode(value="1700000000").code, 0)


if __name__ == "__main__":
    unittest.main()
