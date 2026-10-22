/**
 * What the second review changed in the shared blocks of the memory-forensics tools: the vendor prefixes the withholding reads, counted on
 * 100 planted keys per prefix, kind and tool (and none of the 12-character fragments of them), and the figures the documentation states.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";
import { FS, PROFILE } from "./memory-f1-support.ts";

test("rk_live_, pk_live_ and whsec_ keys are withheld in a name, a path and an engine line, whole and in 12-character pieces", () => {
  const code = [
    "import importlib.util, random, string, sys",
    "spec = importlib.util.spec_from_file_location('t', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
    "r = random.Random(2026)",
    "b62 = string.ascii_letters + string.digits",
    "prefixes = [('rk_' + 'live_', 24), ('pk_' + 'live_', 24), ('sk_' + 'live_', 24), ('whsec' + '_', 32)]",
    "leaked = 0; planted = 0",
    "for prefix, n in prefixes:",
    "    for _ in range(100):",
    "        key = prefix + ''.join(r.choice(b62) for _ in range(n))",
    "        for kind in ('name', 'path', 'text'):",
    "            for text in (key, 'proc_' + key + '.exe', 'key ' + key + ' rejected'):",
    "                planted += 1",
    "                shown = str(m.shown(text, kind))",
    "                if key in shown or any(key[i:i + 12] in shown for i in range(len(key) - 11)): leaked += 1",
    "print(planted, leaked)",
  ].join("\n");
  for (const tool of [FS, PROFILE]) {
    const out = spawnSync("python3", ["-c", code, tool], { encoding: "utf8", timeout: 120_000 });
    assert.equal(out.status, 0, out.stderr);
    assert.equal(out.stdout.trim(), "3600 0", tool);
  }
});

test("the README, the manifests and the changelog fragment state the measured rates, in the same figures", async () => {
  const readme = await readFile(join(ROOT, "packs", "memory-forensics", "README.md"), "utf8");
  const fragment = await readFile(join(ROOT, "changelog.d", "claude-pack-memory-p1-fixes.md"), "utf8");
  const fs = JSON.parse(await readFile(join(ROOT, "packs", "memory-forensics", "tools", "mem_fs", "manifest.json"), "utf8")) as { description: string };
  const profile = JSON.parse(await readFile(join(ROOT, "packs", "memory-forensics", "tools", "mem_profile", "manifest.json"), "utf8")) as { description: string };
  assert.match(profile.description, /closed list/);
  assert.match(profile.description, /walk_complete/);
  for (const [name, text] of Object.entries({ readme, fragment, fs: fs.description })) {
    assert.match(text, /2\.9 per cent/, `${name}: the worst measured rate of a key in a process name`);
    assert.match(text, /UUID/, `${name}: the classes the boundary does not read are named`);
    assert.match(text, /base32/, `${name}: base32 seeds`);
    assert.match(text, /rk_live_/, `${name}: the vendor prefixes added`);
  }
  assert.doesNotMatch(fragment, /at most 0\.4 per cent/);
});
