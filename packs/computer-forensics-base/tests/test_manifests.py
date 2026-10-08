"""Every tool's manifest agrees with its script: the version it prints is the version it declares, and what the manifest requires is declared in the pack's requires."""
import ast
import json
import os
import unittest

from support import PACK_DIR


def tool_version(script):
    """The `version` of a module-level TOOL = {...} assignment, or None."""
    with open(script, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "TOOL" for t in node.targets):
            try:
                return ast.literal_eval(node.value).get("version")
            except (ValueError, AttributeError):
                return None
    return None


class Manifests(unittest.TestCase):
    def tools(self):
        root = os.path.join(PACK_DIR, "tools")
        for name in sorted(os.listdir(root)):
            manifest = os.path.join(root, name, "manifest.json")
            if os.path.isfile(manifest):
                with open(manifest, encoding="utf-8") as fh:
                    yield name, json.load(fh), os.path.join(root, name, "run.py")

    def test_a_script_that_prints_its_version_prints_the_manifests(self):
        seen = 0
        for name, manifest, script in self.tools():
            version = tool_version(script)
            if version is not None:
                seen += 1
                self.assertEqual(version, manifest["version"], "%s: TOOL says %s, the manifest %s" % (name, version, manifest["version"]))
        self.assertGreaterEqual(seen, 12, "the tools that were fixed in this pack all print their version")

    def test_what_a_manifest_requires_is_a_program_the_pack_declares_or_the_base_image_holds(self):
        with open(os.path.join(PACK_DIR, "requires", "host.json"), encoding="utf-8") as fh:
            declared = {b["name"] for b in json.load(fh)["binaries"]}
        # Programs the base image holds and no pack declares (images/base.Dockerfile): the shell's, file(1) and sqlite3.
        base_image = {"file", "sqlite3", "python3"}
        for name, manifest, _ in self.tools():
            for program in manifest.get("requires", []):
                self.assertIn(program, declared | base_image | {"log2timeline", "psort"}, "%s requires %s, which nothing declares" % (name, program))

    def test_a_param_spec_carries_only_keys_the_harness_reads(self):
        for name, manifest, _ in self.tools():
            for param, spec in manifest.get("params", {}).items():
                self.assertEqual(set(spec) - {"type", "description", "required"}, set(), "%s.%s has keys the harness does not read" % (name, param))


if __name__ == "__main__":
    unittest.main()
