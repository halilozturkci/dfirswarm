"""browser_storage: an inventory of a Chromium or Electron LevelDB directory over ccl_chromium_reader, with every way it can be wrong said.

The LevelDB log and table files, the snappy streams, the IndexedDB key layout and the Blink/V8 values are built by
browser_storage_fixtures.py from the formats' specifications. The cases that need the reader run only where a venv holds it: the image's
/opt/dfir/src/ccl_indexeddb_dump/.venv, or the one BROWSER_STORAGE_VENV names (a venv with ccl_chromium_reader 0.3.18, ccl_simplesnappy,
Brotli and zstd). The cases of the wrapper itself (a missing venv, a venv without the reader, a reader that makes no document, the
refusals before the reader is started) need no reader and always run.
"""
import base64
import json
import math
import os
import random
import signal
import stat
import struct
import subprocess
import sys
import time
import unittest
import uuid

import browser_storage_fixtures as F
from support import Case, run_tool, tool_path

READER_VENV = os.environ.get("BROWSER_STORAGE_VENV") or ("/opt/dfir/src/ccl_indexeddb_dump/.venv" if os.path.isfile("/opt/dfir/src/ccl_indexeddb_dump/.venv/bin/python") else None)
NEEDS_READER = unittest.skipUnless(READER_VENV, "no venv with ccl_chromium_reader 0.3.18 (set BROWSER_STORAGE_VENV)")
LINUX = unittest.skipUnless(sys.platform.startswith("linux"), "needs /proc and Linux address-space limits")
ORIGIN = "https://app.example.test"
SPLIT_BOUND = {"nul_split": 0.17, "zwsp_split": 0.17, "utf16_split": 0.12}


def wilson_upper(misses, n, z=1.96):
    p = misses / n
    return (p + z * z / (2 * n) + z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / (1 + z * z / n)


class Base(Case):
    def src(self, venv=None, script=None):
        """A DFIRSWARM_SRC_DIR holding a ccl_indexeddb_dump venv: `venv` (the real one) linked in, a python that is a shell script (a reader that does
        something else), or, with neither, a python that is a link to this interpreter (a venv without the reader)."""
        root = self.path("src-%d" % len(os.listdir(self.dir)))
        top = os.path.join(root, "ccl_indexeddb_dump")
        os.makedirs(top)
        if venv is not None:
            os.symlink(venv, os.path.join(top, ".venv"))
            return root
        vbin = os.path.join(top, ".venv", "bin")
        os.makedirs(vbin)
        py = os.path.join(vbin, "python")
        if script is not None:
            with open(py, "w") as fh:
                fh.write("#!/bin/sh\n" + script)
            os.chmod(py, 0o755)
        else:
            os.symlink(sys.executable, py)
        return root

    def real(self):
        return self.src(venv=READER_VENV)

    def call(self, args, src=None, job=False, out=None, env=None, timeout=120):
        e = {"DFIRSWARM_SRC_DIR": src or self.real()}
        if job:
            e.update({"JOB_ID": "j1", "OUT": out or self.path("out"), "SECRET_OUTPUT": "1"})
        e.update(env or {})
        return run_tool("browser_storage", args, self.dir, env=e, timeout=timeout)

    def store(self, name="idb", files=None):
        d = self.path(name)
        os.makedirs(d, exist_ok=True)
        for fname, data in (files or {}).items():
            with open(os.path.join(d, fname), "wb") as fh:
                fh.write(data)
        return d

    def meta(self, stores=None, db=1, name="appdb", origin=ORIGIN):
        return F.global_metadata([(db, origin, name, max(stores or {1: 1}), stores or {1: "messages"})])


def log_of(*batches, **kw):
    return F.log_file([F.write_batch(seq, entries) for seq, entries in batches], **kw)


def rec(store, key, body, **kw):
    return (F.record_key(1, store, key), F.idb_value(body, **kw))


class Wrapper(Base):
    """Cases that need no reader."""

    def test_a_missing_venv_is_failed_and_unavailable_and_never_an_empty_inventory(self):
        d = self.store(files={"000003.log": log_of((1, self.meta()))})
        r = self.call({"path": d}, src=self.path("nowhere"))
        self.assertEqual(r.code, 1)
        self.assertEqual(r.json["status"], "failed")
        self.assertIs(r.json["unavailable"], True)
        self.assertNotIn("indexeddb", r.json)
        self.assertNotIn("files", r.json)
        self.assertIn("not an empty store", r.json["error"])

    def test_a_venv_without_the_reader_is_failed_and_unavailable(self):
        d = self.store(files={"000003.log": log_of((1, self.meta()))})
        r = self.call({"path": d}, src=self.src())
        self.assertEqual((r.code, r.json["status"]), (1, "failed"))
        self.assertIs(r.json["unavailable"], True)
        self.assertEqual(r.json["failure"], "reader_version")
        self.assertIn("0.3.18", r.json["status_basis"])
        self.assertNotIn("indexeddb", r.json)

    def test_a_reader_that_makes_no_document_is_failed_and_leaves_no_values_file(self):
        d = self.store(files={"000003.log": log_of((1, self.meta()))})
        out = self.path("out")
        os.makedirs(out)
        r = self.call({"path": d, "write_values": True}, src=self.src(script="echo not json\nexit 3\n"), job=True, out=out)
        self.assertEqual((r.code, r.json["status"], r.json["failure"]), (1, "failed", "no_document"))
        self.assertEqual(os.listdir(out), [], "the values file made for the run is removed when nothing was written")
        self.assertIsNone(r.json["values_file"])

    def test_a_reader_that_never_ends_is_killed_with_what_it_started_and_the_answer_is_failed_json(self):
        d = self.store(files={"000003.log": log_of((1, self.meta()))})
        pidfile = self.path("pids")
        script = "sleep 300 &\necho $! > %s\nsleep 300\n" % pidfile
        t0 = time.monotonic()
        r = self.call({"path": d, "max_seconds": 5}, src=self.src(script=script))
        self.assertLess(time.monotonic() - t0, 30)
        self.assertEqual((r.code, r.json["status"], r.json["failure"]), (1, "failed", "no_document"))
        self.assertIn("killed at its clock", r.json["status_basis"])
        pid = int(self.read("pids").split()[0])
        time.sleep(0.3)
        self.assertFalse(os.path.exists("/proc/%d" % pid) and "sleep" in open("/proc/%d/cmdline" % pid).read(), "the sleep the reader started was ended")

    def test_a_values_file_without_its_end_line_is_a_prefix_and_the_status_says_so(self):
        d = self.store(files={"000003.log": log_of((1, self.meta()))})
        out = self.path("out")
        doc = ('{"ok":true,"versions":{},"files":[{"name":"000003.log","kind":"log","status":"read"}],"format":"leveldb","records_total":0,"counts":{},'
               '"previews":[],"decode_errors":{},"write":{"requested":true,"records":2}}')
        # a reader that writes two whole lines to the descriptor it was given and says it is done, without the end line
        script = r"""spec=$(cat)
fd=$(printf '%s' "$spec" | sed -n 's/.*"write_fd": *\([0-9]*\).*/\1/p')
eval "printf '{\"header\": true}\n{\"n\": 1}\n' >&$fd"
echo '""" + doc + "'\n"
        r = self.call({"path": d, "write_values": True}, src=self.src(script=script), job=True, out=out)
        self.assertEqual((r.code, r.json["status"]), (1, "partial"), r.stdout[:600])
        sv = r.json["secret_values"]
        self.assertEqual((sv["end_line"], sv["lines_counted"]), (False, 2))
        self.assertIn("no end line", r.json["status_basis"])
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(out, "browser-storage-records.jsonl")).st_mode), 0o600)

    def test_write_values_is_refused_as_json_outside_a_job_and_in_a_job_without_secret_output_before_anything_is_made(self):
        d = self.store(files={"000003.log": log_of((1, self.meta()))})
        out = self.path("out")
        os.makedirs(out)
        r = self.call({"path": d, "write_values": True}, src=self.path("nowhere"))
        self.assertEqual((r.code, r.json["status"], r.json["write_values"]), (1, "failed", "refused"))
        self.assertIn("outside a job", r.json["error"])
        r = self.call({"path": d, "write_values": True}, src=self.path("nowhere"), job=True, out=out, env={"SECRET_OUTPUT": "0"})
        self.assertEqual((r.code, r.json["write_values"]), (1, "refused"))
        self.assertIn("not run as secret output", r.json["error"])
        self.assertEqual(os.listdir(out), [])

    def test_arguments_are_checked(self):
        d = self.store(files={"000003.log": log_of((1, self.meta()))})
        for args, word in (({"path": d, "bogus": 1}, "unknown parameter"), ({}, "path is required"), ({"path": d, "preview_records": 26}, "preview_records"),
                           ({"path": d, "preview_chars": 7}, "preview_chars"), ({"path": d, "db_id": -1}, "db_id"), ({"path": d, "store_id": True}, "store_id"),
                           ({"path": d, "max_seconds": 4}, "max_seconds"), ({"path": d, "write_values": "yes"}, "write_values"), ({"path": 5}, "path is required")):
            r = self.call(args, src=self.path("nowhere"))
            self.assertEqual((r.code, r.json["status"]), (1, "failed"), args)
            self.assertIn(word, r.json["error"], args)
        r = run_tool("browser_storage", None, self.dir, raw_input="{", env={"DFIRSWARM_SRC_DIR": self.path("nowhere")})
        self.assertEqual((r.code, r.json["status"]), (1, "failed"))

    def test_the_input_is_refused_before_the_reader_runs(self):
        src = self.src(script="echo ran > %s\nexit 1\n" % self.path("ran"))
        r = self.call({"path": self.path("absent")}, src=src)
        self.assertEqual((r.code, r.json["status"]), (1, "failed"))
        link = self.path("link")
        os.symlink(self.store(), link)
        r = self.call({"path": link}, src=src)
        self.assertIn("symbolic link", r.json["error"])
        plain = self.write("plainfile", b"x")
        r = self.call({"path": plain}, src=src)
        self.assertIn("not a directory", r.json["error"])
        empty = self.store("empty", {"CURRENT": b"MANIFEST-000001\n", "LOCK": b""})
        r = self.call({"path": empty}, src=src)
        self.assertEqual((r.code, r.json["status"]), (1, "failed"))
        self.assertEqual(r.json["unsupported"], "no LevelDB data files")
        big = self.store("big")
        with open(os.path.join(big, "000005.ldb"), "wb") as fh:
            fh.truncate(257 * 1024 * 1024)
        r = self.call({"path": big}, src=src)
        self.assertEqual((r.code, r.json["status"]), (1, "failed"))
        self.assertEqual(r.json["input_limit"], 256 * 1024 * 1024)
        self.assertFalse(os.path.exists(self.path("ran")), "none of these started the reader")

    def test_a_fifo_or_a_link_under_a_data_file_name_is_refused_and_never_opened(self):
        good = log_of((1, self.meta()))
        d = self.store(files={"000003.log": good})
        os.mkfifo(os.path.join(d, "000004.log"))
        secret = self.write("elsewhere.log", good)
        os.symlink(secret, os.path.join(d, "000005.log"))
        os.mkdir(os.path.join(d, "000006.ldb"))
        t0 = time.monotonic()
        r = self.call({"path": d}, src=self.src(script="cat > /dev/null\necho '{\"ok\":true,\"versions\":{},\"files\":[{\"name\":\"000003.log\",\"kind\":\"log\",\"status\":\"read\"}],\"format\":\"leveldb\",\"records_total\":0,\"counts\":{},\"previews\":[],\"decode_errors\":{}}'\n"))
        self.assertLess(time.monotonic() - t0, 20, "a FIFO is not waited on")
        refused = {x["name"]: x["why"] for x in r.json["refused_entries"]}
        self.assertEqual(sorted(refused), ["000004.log", "000005.log", "000006.ldb"])
        self.assertIn("FIFO", refused["000004.log"])
        self.assertIn("symbolic link", refused["000005.log"])
        self.assertEqual(r.json["status"], "partial")
        self.assertIn("refused", r.json["status_basis"])


@NEEDS_READER
class Reader(Base):
    """Cases that run the real ccl_chromium_reader."""

    def idb(self, **kw):
        recs = [
            rec(1, F.key_string("m1"), F.v8_object([("text", F.v8_string("hello")), ("n", F.v8_int(-1)), ("when", F.v8_date(1700000000000.0))])),
            rec(1, F.key_number(7), F.v8_array([F.v8_string("a"), F.v8_int(5)]), snappy=True),
            rec(2, F.key_string("theme"), F.v8_object([("password", F.v8_string("hunter2plain")), ("size", F.v8_int(3))]), blink_version=16),
        ]
        files = {"000003.log": log_of((1, self.meta({1: "messages", 2: "settings"})), (100, recs))}
        files.update(kw.get("extra", {}))
        return self.store(files=files)

    # ---- the inventory ----
    def test_an_indexeddb_is_inventoried_by_database_store_state_and_key_type(self):
        k1, k2 = F.record_key(1, 1, F.key_string("m1")), F.record_key(1, 1, F.key_string("m2"))
        log = log_of((1, self.meta({1: "messages", 2: "settings"})), (100, [(k1, F.idb_value(F.v8_string("v1"))), (k2, F.idb_value(F.v8_string("v2")))]),
                     (110, [(k1, F.idb_value(F.v8_string("v1b")))]), (120, [(k2, None)]), (130, [(F.record_key(1, 2, F.key_date(1700000000000.0)), F.idb_value(F.V8_TRUE))]))
        d = self.store(files={"000003.log": log})
        r = self.call({"path": d})
        self.assertEqual((r.code, r.json["status"]), (0, "complete"), r.stdout[:600])
        j = r.json
        self.assertEqual(j["format"], "indexeddb")
        self.assertEqual(j["reader"]["ccl_chromium_reader"], "0.3.18")
        db = j["indexeddb"]["databases"][0]
        self.assertEqual((db["id"], db["name"], db["origin"], db["max_store_id"]), (1, "appdb", ORIGIN, 2))
        s1, s2 = db["stores"]
        self.assertEqual((s1["name"], s1["data_records"], s1["put"], s1["delete"], s1["distinct_keys"], s1["current_keys"], s1["deleted_keys"]), ("messages", 4, 3, 1, 2, 1, 1))
        self.assertEqual(s1["key_types"], {"String": 4})
        self.assertEqual((s2["name"], s2["key_types"], s2["current_keys"]), ("settings", {"Date": 1}, 1))
        self.assertEqual(j["indexeddb"]["schema_version"], 3)
        self.assertEqual(j["records"], {"total": 11, "puts": 10, "deletes": 1, "unknown": 0})
        self.assertEqual(j["files"][0]["status"], "read")

    def test_a_table_file_is_read_with_and_without_snappy_and_both_are_located(self):
        meta = self.meta({1: "messages"})
        rows = [(F.record_key(1, 1, F.key_string("k%02d" % i)), 10 + i, F.idb_value(F.v8_string("value %d " % i * 3))) for i in range(12)]
        plain = F.table_file(rows, snappy=False)
        packed = F.table_file(rows, snappy=True)
        self.assertLess(len(packed), len(plain))
        for name, table, offset_is, compressed in (("plain", plain, "record", 0), ("packed", packed, "block_start", 12)):
            d = self.store(name, {"000003.log": log_of((1, meta)), "000004.ldb": table})
            r = self.call({"path": d, "preview_records": 12})
            self.assertEqual((r.code, r.json["status"]), (0, "complete"), (name, r.stdout[:500]))
            f = {x["name"]: x for x in r.json["files"]}
            self.assertEqual((f["000004.ldb"]["records"], f["000004.ldb"]["records_in_compressed_blocks"]), (12, compressed))
            items = [i for p in r.json["previews"] for i in p["records"] if i["locator"]["file"] == "000004.ldb"]
            self.assertEqual({i["locator"]["offset_is"] for i in items}, {offset_is})
            self.assertEqual(sorted(i["key"] for i in items), ["k%02d" % i for i in range(12)])
            self.assertEqual(r.json["indexeddb"]["databases"][0]["stores"][0]["current_keys"], 12)

    def test_the_reader_does_not_check_checksums_and_the_answer_says_so(self):
        d = self.store(files={"000003.log": F.log_file([F.write_batch(1, self.meta())], wrong_crc=True), "000004.ldb": F.table_file([(F.record_key(1, 1, F.key_string("a")), 5, F.idb_value(F.V8_TRUE))], wrong_crc=True)})
        r = self.call({"path": d})
        self.assertEqual((r.code, r.json["status"]), (0, "complete"))
        self.assertTrue(any("CRC32C" in x for x in r.json["not_checked"]))

    def test_value_variants_a_trailer_none_snappy_a_blob_and_a_negative_integer(self):
        d = self.idb(extra={"000004.log": log_of((200, [(F.record_key(1, 1, F.key_string("ext")), F.external_value())]))})
        r = self.call({"path": d, "preview_records": 10})
        self.assertEqual((r.code, r.json["status"]), (0, "complete"))
        by = {(p["store"], i["key"]): i for p in r.json["previews"] for i in p["records"]}
        self.assertEqual(by[(1, "m1")]["value"], {"text": "hello", "n": -1, "when": {"$date": "2023-11-14T22:13:20.000Z"}})
        self.assertEqual(by[(1, 7.0)]["value"], ["a", 5])
        self.assertEqual(by[(1, "ext")]["value_error"], "value_outside_the_database")
        self.assertEqual(r.json["records_not_decoded"], {"value_outside_the_database": 1})
        for n in (-1, -2, -64, -65, -(2 ** 31), 2 ** 31 - 1, 0, 1):
            body = F.v8_int(n)
            d2 = self.store("neg%d" % (n % 1000), {"000003.log": log_of((1, self.meta()), (2, [rec(1, F.key_string("n"), body)]))})
            got = self.call({"path": d2}).json["previews"][0]["records"][0]["value"]
            self.assertEqual(got, n, "V8 zig-zag: %d" % n)

    def test_the_reader_alone_reads_a_negative_integer_one_too_high(self):
        """The defect the tool corrects, measured on the reader itself: the zig-zag of -1 is 1, and the reader returns 0."""
        code = ("import io, sys;from ccl_chromium_reader.serialization_formats import ccl_v8_value_deserializer as v;"
                "print([v.Deserializer(io.BytesIO(bytes.fromhex(a)), host_object_delegate=None).read() for a in sys.argv[1:]])")
        args = [(b"\xff\x0fI" + F.varint(u)).hex() for u in (1, 3, 129)]            # zig-zag values 1, 3 and 129: -1, -2 and -65
        out = subprocess.run([os.path.join(READER_VENV, "bin", "python"), "-I", "-c", code] + args, capture_output=True, text=True).stdout
        self.assertEqual(out.strip(), "[0, -1, -64]", "V8 reads -1, -2 and -65")

    # ---- damage ----
    def test_a_file_the_reader_cannot_read_is_named_and_the_others_are_still_read(self):
        good = F.table_file([(F.record_key(1, 1, F.key_string("a")), 5, F.idb_value(F.V8_TRUE))])
        d = self.store(files={"000003.log": log_of((1, self.meta())), "000004.ldb": good, "000005.ldb": good[:30], "000006.ldb": good[:-8] + b"\0" * 8,
                              "000007.ldb": b"", "000008.log": b""})
        r = self.call({"path": d})
        self.assertEqual((r.code, r.json["status"]), (1, "partial"))
        f = {x["name"]: x for x in r.json["files"]}
        self.assertEqual(f["000003.log"]["status"], "read")
        self.assertEqual(f["000004.ldb"]["status"], "read")
        self.assertEqual((f["000005.ldb"]["status"], f["000005.ldb"]["stage"]), ("failed", "open"))
        self.assertIn("error_class", f["000005.ldb"])
        self.assertEqual((f["000006.ldb"]["status"], f["000006.ldb"]["error_class"]), ("failed", "ValueError"))
        self.assertEqual(f["000007.ldb"]["status"], "failed")
        self.assertEqual((f["000008.log"]["status"], f["000008.log"]["records"]), ("read", 0))
        self.assertIn("could not be read to their end", r.json["status_basis"])
        self.assertEqual(r.json["indexeddb"]["databases"][0]["stores"][0]["current_keys"], 1, "the readable files are still inventoried")

    def test_a_log_cut_in_a_block_gives_the_records_before_it_and_is_partial(self):
        first = F.write_batch(1, self.meta())
        second = F.write_batch(100, [rec(1, F.key_string("a"), F.V8_TRUE)])
        log = F.log_file([first, second])
        cut = len(F.log_file([first])) + 7 + 3
        damaged = log[:cut] + b"\x07" + log[cut + 1:]            # an impossible record type where the third record header starts
        damaged = F.log_file([first]) + struct.pack("<IHB", 0, 5, 9) + b"xxxxx"
        d = self.store(files={"000003.log": damaged})
        r = self.call({"path": d})
        self.assertEqual((r.code, r.json["status"]), (1, "partial"))
        f = r.json["files"][0]
        self.assertEqual((f["status"], f["stage"], f["error_class"], f["problem"]), ("partial", "records", "Damaged", "invalid_record_type"))
        self.assertGreater(f["records"], 0, "the records before the damage are kept")
        self.assertEqual(r.json["indexeddb"]["databases"][0]["name"], "appdb")

    def test_deep_nesting_and_a_huge_declared_array_are_errors_of_the_value_and_not_a_crash(self):
        deep = b"o" + b"".join(F.v8_string("k") + b"o" for _ in range(3000))
        huge = b"A" + F.varint(2 ** 32 - 1)
        d = self.store(files={"000003.log": log_of((1, self.meta()), (2, [rec(1, F.key_string("deep"), deep), rec(1, F.key_string("huge"), huge), rec(1, F.key_string("ok"), F.V8_TRUE)]))})
        r = self.call({"path": d, "preview_records": 5})
        self.assertEqual((r.code, r.json["status"]), (0, "complete"), r.stdout[:400])
        errs = {i["key"]: i["value_error"] for i in r.json["previews"][0]["records"]}
        self.assertIsNone(errs["ok"])
        self.assertIn(errs["deep"], ("RecursionError", "ValueError", "AssertionError"))
        self.assertIsNotNone(errs["huge"])

    @LINUX
    def test_a_slow_block_ends_at_the_readers_clock_with_what_was_read(self):
        elements = 12_000_000
        raw = F.varint(elements * 16 + 1) + b"\x00A" + (b"\x3e\x01\x00" * elements)       # one literal byte, then copies of 16 bytes from one byte back
        good_first = F.table_file([(F.record_key(1, 1, F.key_string("a")), 5, F.idb_value(F.V8_TRUE))])
        bomb = bytearray(good_first)
        d = self.store(files={"000003.log": log_of((1, self.meta())), "000004.ldb": good_first})
        # a table whose one data block is the long snappy stream
        block = raw
        crc = F.masked(F.crc32c(block + b"\x01"))
        body = block + b"\x01" + struct.pack("<I", crc)
        idx = F._block([(F.internal_key(F.record_key(1, 1, F.key_string("z")), 9), F.varint(0) + F.varint(len(block)))], restart_every=1)
        idx_trailer = idx + b"\x00" + struct.pack("<I", F.masked(F.crc32c(idx + b"\x00")))
        meta_block = F._block([])
        meta_trailer = meta_block + b"\x00" + struct.pack("<I", F.masked(F.crc32c(meta_block + b"\x00")))
        out = bytearray(body)
        meta_off = len(out)
        out += meta_trailer
        idx_off = len(out)
        out += idx_trailer
        footer = F.varint(meta_off) + F.varint(len(meta_block)) + F.varint(idx_off) + F.varint(len(idx))
        footer += b"\x00" * (40 - len(footer)) + struct.pack("<Q", 0xDB4775248B80FB57)
        self.write("idb/000005.ldb", bytes(out) + footer)
        del bomb
        t0 = time.monotonic()
        r = self.call({"path": d, "max_seconds": 5})
        took = time.monotonic() - t0
        self.assertLess(took, 20)
        self.assertEqual((r.code, r.json["status"]), (1, "partial"), r.stdout[:600])
        f = {x["name"]: x for x in r.json["files"]}
        self.assertEqual(f["000005.ldb"]["status"], "failed")
        self.assertEqual(f["000005.ldb"].get("reason"), "deadline", r.stdout[:900])
        self.assertEqual(f["000003.log"]["status"], "read")
        self.assertIn("5-second clock", r.json["status_basis"])

    @LINUX
    def test_a_stop_signal_ends_the_reader_and_what_it_started_with_one_json_answer(self):
        d = self.store(files={"000003.log": log_of((1, self.meta()))})
        marker = self.path("child.pid")
        script = "echo $$ > %s\nsleep 300 &\nwait\n" % marker
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            proc = subprocess.Popen([sys.executable, tool_path("browser_storage")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.dir,
                                    env={**os.environ, "DFIRSWARM_SRC_DIR": self.src(script=script)})
            try:
                proc.stdin.write(json.dumps({"path": d}).encode())
                proc.stdin.close()
                for _ in range(100):
                    if os.path.exists(marker) and self.read(marker).strip():
                        break
                    time.sleep(0.05)
                pid = int(self.read(marker))
                proc.send_signal(sig)
                out = proc.stdout.read()
                proc.wait(timeout=20)
                proc.stdout.close()
                proc.stderr.close()
            finally:
                if proc.poll() is None:
                    proc.kill()
            self.assertEqual(proc.returncode, 128 + sig, sig)
            doc = json.loads(out)
            self.assertEqual((doc["status"], doc["interrupted"], doc["signal"]), ("partial", True, int(sig)))
            time.sleep(0.3)
            self.assertFalse(os.path.exists("/proc/%d" % pid), "the reader's process was ended")
            os.unlink(marker)

    def reader_alone(self, directory, name):
        """What ccl_chromium_reader gives for one file on its own: (records, error class or None)."""
        code = ("import sys, pathlib;from ccl_chromium_reader.storage_formats import ccl_leveldb as l;"
                "f=(l.LogFile if sys.argv[2].endswith('log') else l.LdbFile)(pathlib.Path(sys.argv[1], sys.argv[2]));n=0\n"
                "try:\n    for r in f: n+=1\n    print(n, None)\nexcept Exception as e:\n    print(n, type(e).__name__)\n")
        out = subprocess.run([os.path.join(READER_VENV, "bin", "python"), "-I", "-c", code, directory, name], capture_output=True, text=True).stdout.split()
        return int(out[0]), (None if out[1] == "None" else out[1])

    def test_damage_the_reader_reads_past_is_found_by_the_formats_rules_and_never_counted_complete(self):
        meta = F.write_batch(1, self.meta())
        small = F.write_batch(50, [rec(1, F.key_string("a"), F.V8_TRUE)])
        big = F.write_batch(100, [rec(1, F.key_string("big"), F.v8_string("z" * 70000))])
        whole = F.log_file([meta, small, big])
        intact = F.log_file([meta, small])
        lk, lv = rec(1, F.key_string("b"), F.V8_TRUE)
        lying = bytearray(F.write_batch(60, [(lk, lv)]))
        lying[12 + 1 + len(F.varint(len(lk))) + len(lk)] = len(lv) + 50            # the value length of the one entry, 50 more than the value holds
        extra = bytearray(small) + b"\x01"                                         # a batch longer than its one entry
        cases = {
            "cut_after_the_first_fragment": (whole[:32768], "spanning_record_never_ends"),
            "cut_inside_the_second_fragment": (whole[:32768 + 10], "cut_inside_record"),
            "cut_inside_record_data": (intact[:-5], "cut_inside_record"),
            "value_length_past_the_batch": (F.log_file([meta, bytes(lying)]), "value_past_the_batch"),
            "batch_longer_than_its_entries": (F.log_file([meta, bytes(extra)]), "batch_longer_than_its_entries"),
            "zero_fill_after_the_records": (intact + b"\x00" * 20, "zero_fill"),
            "garbage_tail": (intact + b"\xff" * 20, "invalid_record_type"),
            "a_header_cut_in_the_last_block": (intact + b"\x01\x02\x03", "cut_header_or_trailer_not_zero"),
        }
        for name, (data, problem) in cases.items():
            d = self.store(name, {"000003.log": data})
            r = self.call({"path": d})
            f = r.json["files"][0]
            self.assertEqual((r.code, r.json["status"], f["status"], f["problem"]), (1, "partial", "partial", problem), (name, r.stdout[:500]))
            self.assertEqual(f["error_class"], "Damaged")
            self.assertIn("problem_offset", f)
        # the reader on its own: three of them are read to the end without an error, which is the defect this tightens
        d = self.store("alone", {"000003.log": whole[:32768], "000004.log": intact[:-5], "000005.log": F.log_file([meta, bytes(lying)])})
        for name in ("000003.log", "000004.log", "000005.log"):
            self.assertIsNone(self.reader_alone(d, name)[1], name)
        # an intact log with a record that spans three blocks is read whole, with the offsets the reader gives
        d = self.store("whole", {"000003.log": whole})
        r = self.call({"path": d})
        self.assertEqual((r.code, r.json["status"], r.json["files"][0]["records"]), (0, "complete", 7))

    def test_a_table_block_that_lies_about_an_entry_or_uses_another_compression_is_named_and_not_read(self):
        rows = [(F.record_key(1, 1, F.key_string("k%d" % i)), 5 + i, F.idb_value(F.V8_TRUE)) for i in range(3)]

        def lie(raw):
            out = bytearray(raw)
            out[2] = 0x7F                  # the value length of the first entry
            return bytes(out)
        for name, kw, problem in (("entry", {"tamper": lie}, "entry_past_the_restart_array"), ("zstd", {"block_type": 2}, "block_compression_type_2_not_read")):
            d = self.store(name, {"000003.log": log_of((1, self.meta())), "000004.ldb": F.table_file(rows, **kw)})
            r = self.call({"path": d})
            f = {x["name"]: x for x in r.json["files"]}["000004.ldb"]
            self.assertEqual((r.code, r.json["status"], f["status"], f["problem"], f["stage"]), (1, "partial", "failed", problem, "records"), (name, r.stdout[:400]))
        d = self.store("fine", {"000003.log": log_of((1, self.meta())), "000004.ldb": F.table_file(rows)})
        self.assertEqual(self.call({"path": d}).json["status"], "complete")

    # ---- a plain LevelDB ----
    def test_a_plain_leveldb_is_counted_and_previewed_and_a_credential_named_key_is_withheld(self):
        recs = [(b"_https://site.test\x00\x01theme", b"\x01dark"), (b"_https://site.test\x00\x01api_token", b"\x01" + b"plainsecret1"), (b"VERSION", b"1"),
                (b"_https://site.test\x00\x01wide", b"\x00" + "hi there".encode("utf-16-le"))]
        d = self.store(files={"000003.log": log_of((1, recs), (5, [(b"VERSION", None)]))})
        r = self.call({"path": d, "preview_records": 10})
        self.assertEqual((r.code, r.json["status"]), (0, "complete"))
        self.assertEqual(r.json["format"], "leveldb")
        self.assertEqual(r.json["leveldb"], {"distinct_keys": 4, "current_keys": 3, "deleted_keys": 1})
        shown = {p["key"]: p["value"] for p in r.json["previews"]}
        self.assertEqual(shown["_https://site.test\\x01theme"], "dark")
        self.assertEqual(shown["_https://site.test\\x01wide"], "hi there")
        self.assertEqual(shown["_https://site.test\\x01api_token"], "<withheld: credential-named key>")
        self.assertNotIn("plainsecret1", r.stdout)
        self.assertTrue(any("not interpreted" in x for x in r.json["not_checked"]))

    def test_the_highest_numbered_manifest_is_read_and_a_damaged_one_makes_the_answer_partial(self):
        files = {"000003.log": log_of((1, self.meta())), "MANIFEST-000002": F.log_file([F.manifest_edit()]),
                 "MANIFEST-000010": F.log_file([F.manifest_edit([(0, 4, 100, b"a", b"z"), (1, 5, 200, b"b", b"y")])]), "CURRENT": b"MANIFEST-000010\n"}
        d = self.store(files=files)
        r = self.call({"path": d})
        self.assertEqual((r.code, r.json["status"]), (0, "complete"))
        self.assertEqual(r.json["manifest"], {"name": "MANIFEST-000010", "status": "read", "table_files_added": 2})
        self.assertEqual(r.json["other_entries"] + 1 + 1 + 1, 4)
        files["MANIFEST-000011"] = F.log_file([F.manifest_edit()])[:20]
        d2 = self.store("damaged", files)
        r2 = self.call({"path": d2})
        self.assertEqual((r2.code, r2.json["status"]), (1, "partial"))
        self.assertEqual(r2.json["manifest"]["name"], "MANIFEST-000011")
        self.assertEqual(r2.json["manifest"]["status"], "failed")
        self.assertIn("MANIFEST", r2.json["status_basis"])

    def test_the_readers_own_schema_version_field_is_empty_and_the_tool_reads_the_record_itself(self):
        d = self.store(files={"000003.log": log_of((1, self.meta()))})
        code = ("import sys;from ccl_chromium_reader import ccl_chromium_indexeddb as i;db=i.IndexedDb(sys.argv[1]);"
                "print(db.global_metadata.backing_store_schema_version, db.global_metadata.max_allocated_db_id)")
        out = subprocess.run([os.path.join(READER_VENV, "bin", "python"), "-I", "-c", code, d], capture_output=True, text=True).stdout
        self.assertEqual(out.strip(), "None None", "the reader looks the keys up as str and they are bytes")
        self.assertEqual(self.call({"path": d}).json["indexeddb"]["schema_version"], 3)

    def test_previews_and_the_values_file_can_be_narrowed_to_a_database_and_a_store_and_ids_without_a_store_are_not_listed(self):
        meta = F.global_metadata([(1, ORIGIN, "appdb", 10 ** 9, {1: "messages", 2: "settings"})])
        d = self.store(files={"000003.log": log_of((1, meta), (2, [rec(1, F.key_string("a"), F.V8_TRUE), rec(2, F.key_string("b"), F.V8_FALSE)]))})
        r = self.call({"path": d, "store_id": 2})
        self.assertEqual((r.code, r.json["status"]), (0, "complete"))
        self.assertEqual([(p["store"], len(p["records"])) for p in r.json["previews"]], [(2, 1)])
        self.assertEqual([s["id"] for s in r.json["indexeddb"]["databases"][0]["stores"]], [1, 2])
        self.assertEqual(r.json["indexeddb"]["databases"][0]["max_store_id"], 10 ** 9)
        self.assertEqual(self.call({"path": d, "db_id": 7}).json["previews"], [])

    # ---- previews and the values file ----
    def test_a_preview_withholds_by_shape_and_by_the_name_of_a_field_and_is_bounded(self):
        token = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
        body = F.v8_object([("note", F.v8_string("see " + token + " and more words " * 30)), ("password", F.v8_string("hunter2plain")), ("n", F.v8_int(5)),
                            ("nested", F.v8_object([("deep", F.v8_object([("deeper", F.v8_object([("deepest", F.v8_object([("x", F.v8_int(1))]))]))]))]))] + [("f%d" % i, F.V8_TRUE) for i in range(20)])
        d = self.store(files={"000003.log": log_of((1, self.meta()), (2, [rec(1, F.key_string(token), body)]))})
        r = self.call({"path": d, "preview_chars": 40})
        self.assertEqual((r.code, r.json["status"]), (0, "complete"))
        self.assertNotIn(token, r.stdout)
        self.assertNotIn("hunter2plain", r.stdout)
        item = r.json["previews"][0]["records"][0]
        self.assertTrue(item["key"].startswith("<") and "withheld" in item["key"], item["key"])
        v = item["value"]
        self.assertEqual(v["password"], "<withheld: credential-named field>")
        self.assertLessEqual(len(v["note"]), 43)
        self.assertEqual(v["nested"]["deep"]["deeper"]["deepest"], {"$deeper": True})
        self.assertIn("$more", v)
        r0 = self.call({"path": d, "preview_records": 0})
        self.assertEqual(r0.json["previews"], [])
        self.assertIs(r0.json["values_inline"], False)

    def test_the_values_file_holds_every_record_whole_and_the_answer_holds_no_value(self):
        canary = "cnry-Zk93-plain-text-value"
        recs = [rec(1, F.key_string("a"), F.v8_object([("text", F.v8_string(canary)), ("n", F.v8_int(-5))])), rec(1, F.key_number(2.5), F.v8_array([F.v8_int(1)]), snappy=True),
                rec(2, F.key_string("b"), F.v8_string("other"))]
        d = self.store(files={"000003.log": log_of((1, self.meta({1: "messages", 2: "settings"})), (100, recs), (200, [(F.record_key(1, 1, F.key_string("a")), None)]))})
        out = self.path("out")
        r = self.call({"path": d, "write_values": True}, job=True, out=out)
        self.assertEqual((r.code, r.json["status"]), (0, "complete"), r.stdout[:500])
        self.assertNotIn(canary, r.stdout)
        self.assertNotIn(canary, r.stderr)
        self.assertIs(r.json["values_inline"], False)
        self.assertNotIn("previews", r.json)
        sv = r.json["secret_values"]
        self.assertEqual((sv["records_written"], sv["end_line"], sv["stopped"], sv["contains_secret_values"]), (4, True, None, True))
        self.assertEqual(sv["values_file"], "store/jobs/j1/out/browser-storage-records.jsonl")
        path = os.path.join(out, "browser-storage-records.jsonl")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        lines = [json.loads(x) for x in open(path, encoding="ascii")]
        header, rows, end = lines[0], lines[1:-1], lines[-1]
        self.assertEqual((header["header"], header["parser"], header["reader"], header["format"]), (True, "browser_storage/1", "0.3.18", "indexeddb"))
        self.assertEqual(end, {"end": True, "records": 4, "stopped": None, "oversized": 0})
        self.assertEqual([x["n"] for x in rows], [1, 2, 3, 4])
        by = {(x["locator"]["seq"], x["store"]): x for x in rows}
        first = by[(100, 1)]
        self.assertEqual(first["value"], {"text": canary, "n": -5})
        self.assertEqual(base64.b64decode(first["raw_b64"]), recs[0][1], "raw_b64 is the record's value bytes whole")
        self.assertEqual(base64.b64decode(first["key_raw_b64"]), F.key_string("a"))
        self.assertEqual((first["database_name"], first["origin"], first["store_name"], first["locator"]["state"], first["parser"]), ("appdb", ORIGIN, "messages", "put", "browser_storage/1"))
        self.assertEqual(by[(101, 1)]["key"], 2.5)
        self.assertEqual(by[(101, 1)]["value"], [1])
        deleted = by[(200, 1)]
        self.assertEqual((deleted["locator"]["state"], deleted["value"]), ("delete", None))
        # a second export in the job, and a file or a link already at the name, are refused with nothing written
        r2 = self.call({"path": d, "write_values": True}, job=True, out=out)
        self.assertEqual((r2.code, r2.json["write_values"]), (1, "refused"))
        self.assertEqual(len(open(path).readlines()), 6)
        out2 = self.path("out2")
        os.makedirs(out2)
        os.symlink(self.path("target"), os.path.join(out2, "browser-storage-records.jsonl"))
        r3 = self.call({"path": d, "write_values": True}, job=True, out=out2)
        self.assertEqual((r3.code, r3.json["write_values"]), (1, "refused"))
        self.assertFalse(os.path.exists(self.path("target")), "no write went through the link")
        # selection by database and store
        out3 = self.path("out3")
        r4 = self.call({"path": d, "write_values": True, "store_id": 2}, job=True, out=out3)
        rows4 = [json.loads(x) for x in open(os.path.join(out3, "browser-storage-records.jsonl"))][1:-1]
        self.assertEqual([x["store"] for x in rows4], [2])
        self.assertEqual(r4.json["secret_values"]["records_written"], 1)
        out4 = self.path("out4")
        r5 = self.call({"path": d, "write_values": True, "db_id": 9}, job=True, out=out4)
        self.assertEqual((r5.json["secret_values"]["records_written"], r5.json["status"]), (0, "complete"))
        self.assertIn("matched no data record", r5.json["secret_values"]["note"])

    def test_the_values_file_stops_at_its_quota_with_an_end_line_and_the_status_says_so(self):
        recs = [rec(1, F.key_string("k%03d" % i), F.v8_string("x" * 200)) for i in range(40)]
        d = self.store(files={"000003.log": log_of((1, self.meta()), (100, recs))})
        out = self.path("out")
        r = self.call({"path": d, "write_values": True}, job=True, out=out, env={"BROWSER_STORAGE_FILE_QUOTA": "9000"})
        self.assertEqual((r.code, r.json["status"]), (1, "partial"))
        sv = r.json["secret_values"]
        self.assertEqual(sv["stopped"], "file_quota")
        lines = [json.loads(x) for x in open(os.path.join(out, "browser-storage-records.jsonl"))]
        self.assertTrue(lines[-1]["end"])
        self.assertEqual(lines[-1]["stopped"], "file_quota")
        self.assertEqual(lines[-1]["records"], len(lines) - 2)
        self.assertEqual(sv["records_written"], len(lines) - 2)
        self.assertLess(len(lines) - 2, 40)
        self.assertLessEqual(sv["file_bytes_read_back"], 9000)

    def test_a_value_over_the_line_limit_is_named_without_its_bytes_and_is_partial(self):
        big = F.idb_value(F.v8_string("y" * 10)) + b"\0" * (49 * 1024 * 1024)
        d = self.store(files={"000003.log": log_of((1, self.meta()), (2, [(F.record_key(1, 1, F.key_string("big")), big), rec(1, F.key_string("small"), F.V8_TRUE)]))})
        out = self.path("out")
        r = self.call({"path": d, "write_values": True}, job=True, out=out, timeout=300)
        self.assertEqual((r.code, r.json["status"]), (1, "partial"))
        self.assertEqual(r.json["secret_values"]["records_over_the_line_limit"], 1)
        rows = [json.loads(x) for x in open(os.path.join(out, "browser-storage-records.jsonl"))][1:-1]
        self.assertEqual({x["key"]: x.get("not_written") for x in rows}, {"big": "over_the_line_limit", "small": None})
        self.assertIsNone(next(x for x in rows if x["key"] == "big")["raw_b64"])

    # ---- names ----
    def test_names_from_the_evidence_are_withheld_by_shape(self):
        key = "AKIA" + "ABCDEFGH23456789"
        meta = F.global_metadata([(1, "https://user:p%40ssw0rd@app.example.test", "db-" + key, 1, {1: "store " + "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"})])
        d = self.store(files={"000003.log": log_of((1, meta))})
        r = self.call({"path": d})
        self.assertEqual((r.code, r.json["status"]), (0, "complete"))
        for needle in (key, "ghp_aB3d", "p%40ssw0rd"):
            self.assertNotIn(needle, r.stdout)
        self.assertGreaterEqual(r.json["withholding"]["counts"]["names"] + r.json["withholding"]["counts"]["text"] + r.json["withholding"]["counts"]["urls"], 3)

    # ---- canaries ----
    def test_random_canaries_of_many_shapes_in_values_do_not_reach_a_preview(self):
        rng = random.Random(20261104)
        alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        b64 = alnum + "+/"

        def forced(chars, n):
            """n characters drawn uniformly at random from `chars`: no condition on them (a plant may hold no digit, or no capital)."""
            return "".join(rng.choice(chars) for _ in range(n))

        def b64_of(nbytes):
            return base64.b64encode(bytes(rng.getrandbits(8) for _ in range(nbytes))).decode("ascii")      # the base64 of random bytes, padding included

        def shape(prefix, chars, n, suffix=""):
            def make():
                core = forced(chars, n)
                return prefix + core + suffix, core
            return make

        def whole(make_core):
            def make():
                core = make_core()
                return core, core
            return make

        def whole_prefixed(prefix, chars, n):
            """A key id: the characters are drawn from `chars` as they are, as AWS draws its key ids (capitals and digits, no lower case)."""
            def make():
                core = "".join(rng.choice(chars) for _ in range(n))
                return prefix + core, core
            return make

        def pem():
            a, b = forced(b64, 64), forced(b64, 64)
            return "-----BEGIN PRIVATE KEY-----\n%s\n%s\n-----END PRIVATE KEY-----" % (a, b), a

        def jwt():
            a, b, c = forced(alnum, 17), forced(alnum, 40), forced(alnum + "-_", 43)
            return "eyJ%s.%s.%s" % (a, b, c), b

        def split(kind):
            def make():
                core = forced(alnum, 24)
                if kind == "utf16":
                    return "".join(c + "\x00" for c in "token " + core), core
                sep = "\x00" if kind == "nul" else "​"
                return "AKIA" + sep.join(core[i:i + 4] for i in range(0, len(core), 4)), core
            return make
        shapes = {
            "aws_key": whole_prefixed("AKIA", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 16), "b64_16": whole(lambda: b64_of(16)), "b64_20": whole(lambda: b64_of(20)),
            "b64_32": whole(lambda: b64_of(32)), "jwt": jwt, "pem": pem, "userinfo": shape("https://svc:", alnum + "@", 14, "@host.example.test/path"),
            "password_eq": shape("Password=", alnum, 14), "password_colon_quoted": shape('password: "', alnum, 14, '"'), "gh_token": shape("ghp_", alnum, 36),
            "cookie_sid_26": shape("SID=", alnum, 26), "uuid": whole(lambda: str(uuid.UUID(int=rng.getrandbits(128), version=4))),
            "hex_secret": whole(lambda: "".join(rng.choice("0123456789abcdef") for _ in range(40))),
            "nul_split": split("nul"), "zwsp_split": split("zwsp"), "utf16_split": split("utf16"),
        }
        stores, per_store = 40, 25
        meta = self.meta({s: "s%d" % s for s in range(1, stores + 1)})
        names = list(shapes)
        recs, plants = [], []
        for sid in range(1, stores + 1):
            for _ in range(per_store):
                texts, cores = {}, {}
                for name in names:
                    texts[name], cores[name] = shapes[name]()
                half = len(names) // 2
                body = F.v8_object([("a", F.v8_object([(n, v8_text(texts[n])) for n in names[:half]])), ("b", F.v8_object([(n, v8_text(texts[n])) for n in names[half:]]))])
                recs.append((F.record_key(1, sid, F.key_string("k%d" % len(recs))), F.idb_value(body, snappy=len(recs) % 3 == 0)))
                plants.append(cores)
        d = self.store(files={"000003.log": log_of((1, meta), (100, recs))})
        r = self.call({"path": d, "preview_records": 25, "preview_chars": 200}, timeout=240)
        self.assertEqual((r.code, r.json["status"]), (0, "complete"), r.stdout[:300])
        leaves = []

        def walk(node):
            if isinstance(node, str):
                leaves.append(node)
            elif isinstance(node, dict):
                for k, v in node.items():
                    walk(k)
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
        walk(r.json["previews"])
        shown = sum(len(p["records"]) for p in r.json["previews"])
        self.assertEqual(shown, stores * per_store)
        blob = "\n".join(leaves).replace("\\x00", "").replace("​", "")       # the escape the printer wrote for NUL, and the zero-width space itself

        def windows(core):
            if len(core) <= 12:
                return [core]
            return [core[:12], core[len(core) // 2 - 6:len(core) // 2 + 6], core[-12:]]
        misses = {n: sum(1 for cores in plants if any(w in blob for w in windows(cores[n]))) for n in names}
        n = len(plants)
        rates = {name: {"misses": m, "n": n, "wilson95_upper": round(wilson_upper(m, n), 4)} for name, m in misses.items()}
        print("browser_storage canaries (preview slots): %s" % json.dumps(rates, sort_keys=True), file=sys.stderr)
        for name in ("aws_key", "jwt", "pem", "password_eq", "password_colon_quoted", "gh_token", "hex_secret"):
            self.assertEqual(misses[name], 0, "%s reached a preview: %s" % (name, rates[name]))
        # The plants are uniformly random (no letter, capital or digit is forced), 1,000 of each shape here; the manifest's rates are from 6,000. The shapes the withholding only half knows: a random base64 text of 16, 20 or 32 bytes (22, 27 or 43 characters) and the password
        # of user-info that holds an @. The rates measured with this seed are in the manifest; a worse rate fails here.
        for name, bound in (("b64_16", 0.23), ("b64_20", 0.28), ("b64_32", 0.04), ("userinfo", 0.09), ("cookie_sid_26", 0.10), ("uuid", 0.03)):
            self.assertLessEqual(rates[name]["wilson95_upper"], bound, "%s: %s" % (name, rates[name]))
        for name in ("nul_split", "zwsp_split", "utf16_split"):
            self.assertLessEqual(rates[name]["wilson95_upper"], SPLIT_BOUND[name], "%s: %s" % (name, rates[name]))


def v8_text(text):
    """A V8 string of any text: one-byte when it is latin-1, else two-byte (UTF-16LE; the reader skips the padding V8 puts before it)."""
    try:
        return F.v8_string(text)
    except UnicodeEncodeError:
        data = text.encode("utf-16-le")
        return b"c" + F.varint(len(data)) + data


if __name__ == "__main__":
    unittest.main()
