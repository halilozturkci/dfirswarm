"""image_verify: a receipt for an EWF set, with every way it can be wrong said.

The segments are built from the EWF1 file layout (the file header, then sections that each start with a 76-byte descriptor holding the section's
type, the offset of the next one, its size and an Adler-32 of the first 72 bytes), so the tests need no imager. ewfinfo and ewfverify are
stand-ins that print the wording libewf 20140814 uses; a last test runs the real programs over a set ewfacquire made when the host has them.
"""
import json
import os
import signal
import struct
import subprocess
import sys
import time
import unittest
import zlib

from support import CLEAN, Case, have, run_tool, stand_in, tool_path

SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
MD5 = "0123456789abcdef0123456789abcdef"
SHA1 = "0123456789abcdef0123456789abcdef01234567"
OTHER = "fedcba9876543210fedcba9876543210"
SECTOR = 512
SECTORS = 4096
MEDIA = SECTOR * SECTORS


def descriptor(kind, offset, size):
    """A section descriptor as the EWF1 layout writes it; a next or a done section points at itself."""
    body = kind.ljust(16, b"\0") + struct.pack("<QQ", offset if kind in (b"next", b"done") else offset + 76 + size, 76 + size) + b"\0" * 40
    return body + struct.pack("<I", zlib.adler32(body) & 0xFFFFFFFF)


def segment(number, last, payload=b"", break_checksum=False, header_number=None):
    out = bytearray(SIGNATURE + b"\x01" + struct.pack("<H", header_number or number) + b"\0\0")
    body = b"volume-data" * 4 + payload
    out += descriptor(b"volume", len(out), len(body)) + body
    out += descriptor(b"done" if last else b"next", len(out), 0)
    if break_checksum:
        out[13 + 5] ^= 0x55
    return bytes(out)


def verify_text(stored=MD5, calc=MD5, sha_stored=SHA1, sha_calc=SHA1, bytes_read=MEDIA, last="ewfverify: SUCCESS"):
    return ("ewfverify 20140814\n\nVerify started at: Nov 03, 2026 13:05:48\nThis could take a while.\n\nVerify completed at: Nov 03, 2026 13:05:48\n\n"
            "Read: 2.0 MiB (%d bytes) in 0 second(s).\n\n"
            "MD5 hash stored in file:\t\t%s\nMD5 hash calculated over data:\t\t%s\n"
            "SHA1 hash stored in file:\t\t%s\nSHA1 hash calculated over data:\t\t%s\n\n%s\n" % (bytes_read, stored, calc, sha_stored, sha_calc, last))


def info_text(md5=MD5, sha1=SHA1, media=MEDIA):
    return ("ewfinfo 20140814\n\nAcquiry information\n\tCase number:\t\tc\n\tAcquisition date:\tTue Nov  3 13:05:48 2026\n"
            "\tSoftware version used:\t20140814\n\nEWF information\n\tFile format:\t\tEnCase 6\n\tSectors per chunk:\t64\n\nMedia information\n"
            "\tBytes per sector:\t%d\n\tNumber of sectors:\t%d\n\tMedia size:\t\t2.0 MiB (%d bytes)\n\nDigest hash information\n\tMD5:\t\t\t%s\n\tSHA1:\t\t\t%s\n"
            % (SECTOR, media // SECTOR, media, md5, sha1))


def program(text, code=0, extra=""):
    return "%scat <<'EOF'\n%sEOF\nexit %d\n" % (extra, text, code)


class ImageVerify(Case):
    def build(self, count=3, name="disk", **kwargs):
        paths = []
        for n in range(1, count + 1):
            paths.append(self.write("evidence/%s.E%02d" % (name, n), segment(n, n == count, payload=bytes([n]) * 40, **kwargs)))
        return paths

    def tools(self, verify=None, info=None, verify_body=None):
        d = self.path("bin")
        os.makedirs(d, exist_ok=True)
        stand_in(d, "ewfinfo", info if info is not None else program(info_text()))
        stand_in(d, "ewfverify", verify_body if verify_body is not None else (
            'if [ "$1" = "-V" ]; then echo "ewfverify 20140814"; exit 0; fi\n' + (verify if verify is not None else program(verify_text()))))
        return d

    def run_it(self, args, path_dirs=None, **kwargs):
        args = dict(args)
        args.setdefault("out_dir", self.path("out", "receipt"))
        return run_tool("image_verify", args, self.dir, path_dirs=path_dirs if path_dirs is not None else [self.tools()], **kwargs)

    def first(self, paths):
        return {"path": paths[0]}

    # ---- the answers
    def test_a_whole_set_whose_digests_agree_is_complete_and_never_authentic(self):
        paths = self.build()
        res = self.run_it(self.first(paths))
        self.assertEqual(res.code, 0, res.stderr)
        a = res.json
        self.assertEqual((a["status"], a["verification"], a["complete"]), (CLEAN, "digests_agree", CLEAN == "complete"), a["status_basis"])
        self.assertEqual([r["index"] for r in a["segments"]], [1, 2, 3])
        self.assertTrue(all(len(r["sha256"]) == 64 for r in a["segments"]))
        self.assertEqual(a["segments"][-1]["ends_with"], "done")
        self.assertEqual(a["segments_in_file"], 3)
        self.assertEqual(len(self.read(os.path.join(a["out_dir"], "segments.jsonl")).splitlines()), 3)
        for word in ("authentic", "genuine"):
            self.assertNotIn(word, res.stdout.lower().replace("never", ""), "the answer says " + word)
        self.assertTrue(os.path.isfile(os.path.join(a["out_dir"], "ewfverify.stdout.txt")))
        self.assertEqual(oct(os.stat(os.path.join(a["out_dir"], "receipt.json")).st_mode & 0o777), "0o600")
        self.assertEqual(a["ewfverify"]["argv"][:3], ["ewfverify", "-d", "sha1"])
        self.assertEqual(a["ewfverify"]["version"], "ewfverify 20140814")

    def test_an_explicit_ordered_list_gives_the_same_answer(self):
        paths = self.build()
        a = self.run_it({"segments": paths}).json
        self.assertEqual(a["status"], CLEAN, a["status_basis"])

    def test_a_version_that_cannot_be_read_makes_the_receipt_partial_and_names_it(self):
        paths = self.build()
        for body in ('if [ "$1" = "-V" ]; then exit 0; fi' + chr(10), 'if [ "$1" = "-V" ]; then exec sleep 120; fi' + chr(10)):
            d = self.tools(verify_body=body + program(verify_text()))
            res = self.run_it(dict(self.first(paths), out_dir=self.path("out", "v%d" % len(body))), path_dirs=[d])
            a = res.json
            self.assertEqual((res.code, a["status"], a["verification"]), (0, "partial", "digests_agree"), a["status_basis"])
            self.assertIn("version of ewfverify is not recorded", a["status_basis"])
            self.assertIsNone(a["ewfverify"]["version"])

    def test_a_stored_digest_that_differs_from_the_recomputed_one_is_failed(self):
        paths = self.build()
        d = self.tools(verify=program(verify_text(calc=OTHER, last="ewfverify: FAILURE"), 1))
        a = self.run_it(self.first(paths), path_dirs=[d]).json
        self.assertEqual((a["status"], a["verification"], a["complete"]), ("failed", "digests_differ", False), a["status_basis"])
        self.assertFalse(a["digests"]["md5"]["agree"])

    def test_a_nonzero_exit_with_garbage_is_partial_not_complete(self):
        paths = self.build()
        d = self.tools(verify=program("segmentation fault, core dumped\n", 139))
        a = self.run_it(self.first(paths), path_dirs=[d]).json
        self.assertEqual((a["status"], a["complete"]), ("partial", False))
        self.assertNotEqual(a["verification"], "digests_agree")

    def test_exit_zero_with_garbage_is_partial(self):
        paths = self.build()
        d = self.tools(verify=program("all is well, trust me\n", 0))
        a = self.run_it(self.first(paths), path_dirs=[d]).json
        self.assertEqual((a["status"], a["verification"]), ("partial", "not_understood"))

    def test_a_success_line_with_no_stored_digest_compared_is_partial(self):
        paths = self.build()
        text = "Read: 2.0 MiB (%d bytes) in 0 second(s).\n\nMD5 hash stored in file:\t\tN/A\nMD5 hash calculated over data:\t\t%s\n\newfverify: SUCCESS\n" % (MEDIA, MD5)
        d = self.tools(verify=program(text.replace("\\n", "\n")))
        a = self.run_it(self.first(paths), path_dirs=[d]).json
        self.assertEqual((a["status"], a["verification"]), ("partial", "nothing_stored"))

    def test_ewfinfo_and_ewfverify_that_disagree_on_the_media_size_are_failed(self):
        paths = self.build()
        d = self.tools(info=program(info_text(media=MEDIA * 2)))
        a = self.run_it(self.first(paths), path_dirs=[d]).json
        self.assertEqual(a["status"], "failed")
        self.assertIn("media", a["status_basis"])

    def test_ewfinfo_that_reads_another_stored_digest_is_failed(self):
        paths = self.build()
        d = self.tools(info=program(info_text(md5=OTHER)))
        a = self.run_it(self.first(paths), path_dirs=[d]).json
        self.assertEqual(a["status"], "failed")

    def test_a_missing_program_is_partial_with_the_reason(self):
        paths = self.build()
        res = run_tool("image_verify", {"path": paths[0], "out_dir": self.path("out", "r")}, self.dir, only_path="")
        a = res.json
        self.assertEqual((a["status"], a["complete"]), ("partial", False))
        self.assertIn("ewfverify is not on PATH", a["status_basis"])
        self.assertEqual(len(a["segments"]), 3)

    def test_a_program_that_outlives_the_budget_is_ended_and_nothing_is_verified(self):
        paths = self.build()
        pids = self.path("pids")
        d = self.tools(verify_body='if [ "$1" = "-V" ]; then echo "ewfverify 20140814"; exit 0; fi\necho $$ > %s\nexec sleep 60\n' % pids)
        started = time.monotonic()
        a = self.run_it({"path": paths[0], "max_seconds": 5}, path_dirs=[d]).json
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual((a["status"], a["verification"], a["ewfverify"]["timed_out"]), ("partial", "not_run", True))
        pid = int(self.read("pids").strip())
        time.sleep(0.3)
        self.assertFalse(os.path.exists("/proc/%d" % pid) and open("/proc/%d/stat" % pid).read().split()[2] != "Z", "ewfverify is still running")

    def test_a_stop_signal_ends_the_program_and_gives_one_partial_document(self):
        paths = self.build()
        pids = self.path("pids")
        d = self.tools(verify_body='if [ "$1" = "-V" ]; then echo "ewfverify 20140814"; exit 0; fi\necho $$ > %s\nexec sleep 60\n' % pids)
        env = dict(os.environ, PATH=d + os.pathsep + os.environ["PATH"])
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            env.pop(k, None)
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            out = self.path("out", "s%d" % signum)
            spec = self.write("spec%d.json" % signum, json.dumps({"path": paths[0], "out_dir": out}))
            stdin = open(spec, "rb")
            self.addCleanup(stdin.close)
            proc = subprocess.Popen([sys.executable, tool_path("image_verify")], stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.dir, env=env,
                                    start_new_session=True)
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline and not (os.path.exists(pids) and self.read("pids").strip()):
                    time.sleep(0.05)
                pid = int(self.read("pids").strip())
                os.kill(proc.pid, signum)
                stdout, _ = proc.communicate(timeout=20)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
            self.assertEqual(proc.returncode, 128 + signum)
            doc = json.loads(stdout)
            self.assertEqual((doc["status"], doc["interrupted"], doc["signal"]), ("partial", True, signum))
            time.sleep(0.3)
            self.assertFalse(os.path.exists("/proc/%d" % pid) and open("/proc/%d/stat" % pid).read().split()[2] != "Z", "ewfverify was left running")
            os.unlink(pids)

    def test_a_segment_that_changes_while_ewfverify_runs_fails_the_receipt(self):
        paths = self.build()
        d = self.tools(verify_body='if [ "$1" = "-V" ]; then echo "ewfverify 20140814"; exit 0; fi\nprintf x >> "%s"\ncat <<\'EOF\'\n%sEOF\n' % (paths[0], verify_text()))
        a = self.run_it(self.first(paths), path_dirs=[d]).json
        self.assertEqual(a["status"], "failed")
        self.assertIn("changed", a["status_basis"])

    # ---- the set
    def test_a_missing_middle_segment_is_named_and_ewfverify_is_not_run(self):
        paths = self.build(count=4)
        os.unlink(paths[1])
        a = self.run_it(self.first(paths)).json
        self.assertEqual((a["status"], a["segments_missing"], a["verification"]), ("failed", [".E02"], "not_run"))
        self.assertEqual(a["segments_total"], 3)
        self.assertFalse(a["ewfverify"]["run"])

    def test_a_missing_last_segment_is_found_from_the_chain_of_the_last_one_present(self):
        paths = self.build(count=3)
        os.unlink(paths[2])
        a = self.run_it(self.first(paths)).json
        self.assertEqual(a["status"], "failed")
        self.assertIn("does not end the set", a["status_basis"])

    def test_segments_out_of_order_are_refused(self):
        paths = self.build()
        a = self.run_it({"segments": [paths[0], paths[2], paths[1]]}).json
        self.assertEqual((a["status"], a["segments_in_order"], a["verification"]), ("failed", False, "not_run"))

    def test_a_list_that_skips_a_number_names_the_gap(self):
        paths = self.build()
        a = self.run_it({"segments": [paths[0], paths[2]]}).json
        self.assertEqual((a["status"], a["segments_missing"]), ("failed", [".E02"]))

    def test_a_truncated_last_segment_is_failed(self):
        paths = self.build()
        with open(paths[2], "r+b") as fh:
            fh.truncate(os.path.getsize(paths[2]) - 30)
        a = self.run_it(self.first(paths)).json
        self.assertEqual(a["status"], "failed")
        self.assertTrue(a["segments"][2]["problems"])

    def test_a_section_descriptor_whose_checksum_is_wrong_is_failed(self):
        paths = self.build(count=2)
        with open(paths[0], "rb") as fh:
            data = bytearray(fh.read())
        data[13 + 5] ^= 0x01
        with open(paths[0], "wb") as fh:
            fh.write(bytes(data))
        a = self.run_it(self.first(paths)).json
        self.assertEqual(a["status"], "failed")
        self.assertIn("checksum", " ".join(a["segments"][0]["problems"]))

    def test_a_header_that_names_another_segment_number_is_failed(self):
        paths = self.build(count=2)
        self.write("evidence/disk.E02", segment(2, True, header_number=7))
        a = self.run_it(self.first(paths)).json
        self.assertEqual(a["status"], "failed")
        self.assertIn("header says this is segment 7", a["status_basis"])

    def test_a_file_that_is_not_ewf_is_failed(self):
        path = self.write("evidence/disk.E01", b"MZ" + b"\0" * 500)
        a = self.run_it({"path": path}).json
        self.assertEqual(a["status"], "failed")

    def test_ewf2_is_read_but_never_complete(self):
        head = b"EVF2\x0d\x0a\x81\x00" + b"\x01\x00\x01\x00" + struct.pack("<I", 1) + b"\xaa" * 16
        path = self.write("evidence/disk.Ex01", head + b"\0" * 100)
        a = self.run_it({"path": path}).json
        self.assertNotEqual(a["status"], "complete")
        self.assertEqual(a["format"], "EWF2 (.Ex01)")

    def test_a_logical_evidence_file_is_unsupported(self):
        path = self.write("evidence/disk.L01", b"LVF\x09\x0d\x0a\xff\x00" + b"\0" * 100)
        res = run_tool("image_verify", {"path": path}, self.dir)
        self.assertEqual(res.code, 1)
        self.assertEqual(res.json["status"], "failed")
        self.assertIn("unsupported", res.json)

    def test_the_run_goes_past_e99(self):
        sys.path.insert(0, os.path.dirname(tool_path("image_verify")))
        import importlib.util
        spec = importlib.util.spec_from_file_location("iv_under_test", tool_path("image_verify"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        got = [mod.expected_ext("E01", n) for n in (1, 99, 100, 101, 125, 126, 775, 776, 777)]
        self.assertEqual(got, ["E01", "E99", "EAA", "EAB", "EAZ", "EBA", "EZZ", "FAA", "FAB"])
        self.assertEqual([mod.expected_ext("Ex01", n) for n in (99, 100)], ["Ex99", "ExAA"])
        self.assertEqual(mod.expected_ext("s01", 100), "saa")
        for n in (1, 50, 99, 100, 300, 775, 776, 5000):
            self.assertEqual(mod.number_of("E01", mod.expected_ext("E01", n)), n)
        self.assertIsNone(mod.number_of("E01", "EaB"))

    # ---- hostile sources
    def test_a_symlink_a_fifo_and_a_directory_are_refused_and_nothing_waits(self):
        for kind in ("symlink", "fifo", "dir"):
            paths = self.build(count=3, name="d" + kind)
            os.unlink(paths[1])
            target = paths[1]
            if kind == "symlink":
                os.symlink(paths[0], target)
            elif kind == "fifo":
                os.mkfifo(target)
            else:
                os.mkdir(target)
            started = time.monotonic()
            res = self.run_it({"path": paths[0], "out_dir": self.path("out", kind)}, timeout=30)
            self.assertLess(time.monotonic() - started, 15, kind)
            a = res.json
            self.assertEqual(a["status"], "failed", kind)
            self.assertIn("refused", " ".join(a["segments"][1]["problems"]), kind)
            self.assertFalse(a["ewfverify"]["run"], kind)

    def test_a_first_segment_that_is_a_symlink_is_refused(self):
        paths = self.build(count=1)
        link = self.path("evidence", "other.E01")
        os.symlink(paths[0], link)
        a = self.run_it({"path": link}).json
        self.assertEqual(a["status"], "failed")

    @unittest.skipUnless(sys.platform.startswith("linux"), "a file name that is not UTF-8 needs Linux")
    def test_a_segment_name_that_is_not_utf8_is_handled(self):
        raw = os.fsencode(self.path("evidence")) + b"/caf\xe9.E01"
        os.makedirs(self.path("evidence"), exist_ok=True)
        with open(raw, "wb") as fh:
            fh.write(segment(1, True))
        a = self.run_it({"path": os.fsdecode(raw)}).json
        self.assertEqual(a["status"], CLEAN, a["status_basis"])
        json.dumps(a, ensure_ascii=True)

    def test_a_name_shaped_like_a_token_is_not_printed(self):
        token = "AKIAIOSFODNN7EXAMPLEzzqq0987654321"
        path = self.write("evidence/%s.E01" % token, segment(1, True))
        res = self.run_it({"path": path})
        self.assertNotIn(token, res.stdout)
        self.assertNotIn(token, res.stderr)
        a = res.json
        self.assertEqual(a["names_withheld"], 1)
        out = a["out_dir"]
        self.assertNotIn(token, self.read(os.path.join(out, "segments.jsonl")))
        self.assertNotIn(token, self.read(os.path.join(out, "receipt.json")))
        self.assertIn(token, self.read(os.path.join(out, "withheld-names.jsonl")))
        self.assertEqual(oct(os.stat(os.path.join(out, "withheld-names.jsonl")).st_mode & 0o777), "0o600")

    def test_an_out_dir_that_holds_files_is_refused_and_nothing_is_replaced(self):
        paths = self.build()
        os.makedirs(self.path("out", "taken"))
        self.write("out/taken/receipt.json", b"earlier")
        res = self.run_it({"path": paths[0], "out_dir": self.path("out", "taken")})
        self.assertEqual(res.code, 1)
        self.assertEqual(self.read("out/taken/receipt.json"), "earlier")

    def test_the_arguments_are_checked(self):
        paths = self.build(count=1)
        for args in ({}, {"path": paths[0], "segments": paths}, {"path": paths[0], "extra": 1}, {"path": "evidence/disk.dd"}, {"path": paths[0], "max_seconds": 1},
                     {"segments": []}, {"segments": [3]}):
            res = run_tool("image_verify", args, self.dir)
            self.assertEqual(res.code, 1, args)
            self.assertEqual(res.json["status"], "failed", args)

    def test_a_file_size_limit_makes_the_answer_partial_and_the_counts_are_what_the_file_holds(self):
        import resource
        paths = self.build()
        env = dict(os.environ, PATH=self.tools() + os.pathsep + os.environ["PATH"])
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            env.pop(k, None)
        out = self.path("out", "limited")
        proc = subprocess.run([sys.executable, tool_path("image_verify")], input=json.dumps({"path": paths[0], "out_dir": out}).encode(), capture_output=True, cwd=self.dir, env=env,
                              timeout=60, preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (700, 700)))
        a = json.loads(proc.stdout)
        self.assertNotEqual(a["status"], "complete", a["status_basis"])
        self.assertTrue(a.get("rows_file_error") or a.get("receipt_error") or a["status"] == "failed", a)
        text = self.read(os.path.join(out, "segments.jsonl")) if os.path.exists(os.path.join(out, "segments.jsonl")) else ""
        self.assertEqual(a["segments_in_file"], text.count(chr(10)))
        leftovers = [n for n in os.listdir(out) if n.startswith(".") or ".tmp." in n]
        self.assertEqual(leftovers, [])

    # ---- the real programs
    @unittest.skipUnless(have("ewfacquire") and have("ewfverify") and have("ewfinfo"), "ewf-tools are not installed")
    def test_a_real_set_made_by_ewfacquire_is_complete_and_a_flipped_byte_is_not(self):
        raw = self.write("raw.bin", os.urandom(SECTOR * 4096))
        base = self.path("evidence", "real")
        os.makedirs(self.path("evidence"))
        made = subprocess.run(["ewfacquire", "-u", "-t", base, "-c", "none", "-S", "1MiB", "-m", "fixed", "-M", "logical", "-f", "encase6", "-d", "sha1",
                               "-C", "c", "-D", "d", "-e", "e", "-E", "ev", "-N", "n", raw], capture_output=True, timeout=120)
        self.assertEqual(made.returncode, 0, made.stderr)
        first = base + ".E01"
        a = run_tool("image_verify", {"path": first, "out_dir": self.path("out", "real")}, self.dir).json
        self.assertEqual(a["status"], CLEAN, a["status_basis"])
        self.assertGreaterEqual(a["segments_total"], 2)
        self.assertEqual(a["segments"][-1]["ends_with"], "done")
        # one byte of the media stream flipped in the middle of the second segment: the section chain is intact, the data is not
        second = base + ".E02"
        with open(second, "r+b") as fh:
            fh.seek(os.path.getsize(second) // 2)
            byte = fh.read(1)
            fh.seek(-1, os.SEEK_CUR)
            fh.write(bytes([byte[0] ^ 0xFF]))
        b = run_tool("image_verify", {"path": first, "out_dir": self.path("out", "flipped")}, self.dir).json
        self.assertEqual(b["status"], "failed", b["status_basis"])
        self.assertNotEqual(b["status"], "complete")


if __name__ == "__main__":
    unittest.main()
