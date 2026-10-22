"""Every answer of a tool carries `status` and `status_basis` (docs/packs.md, "The tool contract"): what the status rests on, in one sentence."""
import json
import os
import unittest

from support import Case, run_tool

WORDS = {"complete", "partial", "failed", "OK", "FAIL"}


class StatusBasis(Case):
    def check(self, name, args, **kw):
        r = run_tool(name, args, self.dir, **kw)
        self.assertIsNotNone(r.json, "%s: %s %s" % (name, r.stdout[:200], r.stderr[-200:]))
        self.assertIn(r.json.get("status"), WORDS, name)
        self.assertTrue(isinstance(r.json.get("status_basis"), str) and len(r.json["status_basis"]) > 20, "%s has no status_basis" % name)
        return r

    def test_the_scanners_and_the_single_shot_tools_say_what_their_status_rests_on(self):
        blob = self.write("work/blob.bin", b"\0" * 64 + b"needle" + b"\0" * 64 + b"PK\x03\x04" + b"\0" * 64)
        self.assertEqual(self.check("ioc_scan", {"path": blob, "needles": "needle"}).json["status"], "complete")
        self.assertEqual(self.check("chunk_needles", {"path": blob, "needles": "needle"}).json["status"], "complete")
        self.assertEqual(self.check("sig_carve", {"path": blob}).json["status"], "complete")
        self.assertEqual(self.check("file_type", {"path": blob}).json["status"], "complete")
        self.assertEqual(self.check("timestamp_decode", {"value": "1700000000"}).json["status"], "complete")
        self.write("inputs.json", json.dumps({"files": []}))
        self.assertEqual(self.check("check_inputs", {}).json["status"], "OK")

    def test_a_refusal_says_failed_and_why(self):
        r = run_tool("file_carver", {"path": self.write("work/x.bin", b"\0" * 64), "offset": 0, "sig_type": "PNG"}, self.dir)
        self.assertEqual((r.json["status"], r.json["ok"]), ("failed", False))
        self.assertIn("error", r.json["status_basis"])


if __name__ == "__main__":
    unittest.main()
