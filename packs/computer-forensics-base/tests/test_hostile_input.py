"""Hostile caller input every tool and recipe answers as JSON, never as a traceback.

A JSON nested 100,000 deep is a RecursionError in Python's parser, not a ValueError; a symlink loop, a 300-character name or a lone surrogate
in an output directory is an OSError, RuntimeError or ValueError out of Path.resolve(). Each of these used to end a tool with no document at all.
"""
import json
import os
import subprocess
import sys
import unittest

from support import Case, PACK_DIR, recipe_path, run_tool, tool_path

TOOLS = ["archive_extract", "catalog_search", "check_inputs", "chunk_needles", "feature_scan", "file_carver", "file_type", "icat_extract",
         "image_layout", "ioc_scan", "sig_carve", "sqlite_query", "sqlite_snapshot", "timeline_super", "timestamp_decode"]
DEEP = "[" * 100000
DEEP_OBJECT = '{"a":' * 20000       # 100 KB: one argument of a command line may not be longer than 128 KB


def clean_env():
    e = dict(os.environ)
    for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
        e.pop(k, None)
    return e


class DeepJson(Case):
    def test_every_tool_answers_a_deeply_nested_stdin_as_json(self):
        for name in TOOLS:
            for text in (DEEP, DEEP_OBJECT):
                with self.subTest(tool=name, shape=text[:5]):
                    r = run_tool(name, None, self.dir, raw_input=text, timeout=60)
                    self.assertNotIn("Traceback", r.stderr[-400:], name)
                    self.assertIsNotNone(r.json, "%s printed no JSON: %r" % (name, r.stdout[:200]))
                    self.assertIn(r.json.get("status"), ("failed", None), name)

    def test_ad1_extract_answers_a_deeply_nested_stdin_as_json(self):
        r = run_tool("ad1_extract", None, self.dir, raw_input=DEEP, timeout=60)
        self.assertNotIn("Traceback", r.stderr[-400:])
        self.assertIsNotNone(r.json, r.stdout[:200])

    def run_recipe(self, name, entry, verb, target, *extra):
        cmd = ([sys.executable] if entry.endswith(".py") else ["bash"]) + [recipe_path(name, entry), verb, "--target", target] + list(extra)
        return subprocess.run(cmd, capture_output=True, text=True, cwd=self.dir, env=clean_env(), timeout=60)

    def test_every_recipe_answers_a_deeply_nested_target_as_json(self):
        recipes = [("ad1-items", "run.py"), ("archive-members", "run.py"), ("disk-timeline", "run.py"),
                   ("disk-volumes", "run.sh"), ("memory-windows", "run.sh")]
        for name, entry in recipes:
            for verb in ("detect", "run"):
                for target in (DEEP, DEEP_OBJECT):
                    with self.subTest(recipe=name, verb=verb, shape=target[:5]):
                        extra = ("--out", self.path("out")) if verb == "run" else ()
                        p = self.run_recipe(name, entry, verb, target, *extra)
                        self.assertNotIn("Traceback", p.stderr[-400:], name)
                        try:
                            doc = json.loads(p.stdout.strip().splitlines()[-1])
                        except (ValueError, IndexError):
                            self.fail("%s %s printed no JSON: %r %r" % (name, verb, p.stdout[:200], p.stderr[-200:]))
                        self.assertIsInstance(doc, dict)


class HostileOutDir(Case):
    """An out_dir the file system cannot resolve is a refusal the caller can read."""

    def hostile(self):
        loop = self.path("work", "loop")
        os.makedirs(self.path("work"), exist_ok=True)
        os.symlink("loop", loop)
        return {"symlink loop": "work/loop/x", "300 characters": "work/" + "n" * 300, "lone surrogate": "work/\udcff"}

    def test_a_hostile_out_dir_is_a_json_refusal(self):
        image = self.write("work/blob.bin", b"\0" * 4096)
        cases = {
            "archive_extract": lambda out: {"path": image, "out_dir": out},
            "timeline_super": lambda out: {"source": image, "out_dir": out},
            "file_carver": lambda out: {"path": image, "offset": 0, "sig_type": "PE", "output": out},
            "feature_scan": lambda out: {"path": image, "out_dir": out},
            "sqlite_snapshot": lambda out: {"db_path": image, "out_dir": out},
            "icat_extract": lambda out: {"image": image, "inode": "5", "output": out},
        }
        for label, out in self.hostile().items():
            for name, make in cases.items():
                with self.subTest(tool=name, out=label):
                    try:
                        data = json.dumps(make(out))
                    except UnicodeEncodeError:
                        continue
                    r = run_tool(name, None, self.dir, raw_input=data, timeout=60)
                    self.assertNotIn("Traceback", r.stderr[-400:], r.stderr[-400:])
                    self.assertIsNotNone(r.json, "%s printed no JSON: %r" % (name, r.stdout[:200]))


if __name__ == "__main__":
    unittest.main()
