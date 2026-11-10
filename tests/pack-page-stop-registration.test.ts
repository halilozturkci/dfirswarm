/**
 * The hidden temporary file of a result page is registered the moment it exists. LosslessPage.add() makes it with tempfile.mkstemp and
 * names it in `_tmp` on the next line; a stop signal between the two found no file for the handler to remove and left a hidden
 * `.<name>-*` file behind (macOS CI, `usn_journal: SIGTERM at temp`, 1 run in many). NoReplacePage (the SHARED PAGE block that
 * 32 tools carry) now holds the stop signals while it makes and registers the file.
 *
 * Here the signal is sent at that very point, deterministically: mkstemp is replaced by a function that makes the file and then sends
 * the process SIGTERM before it returns. Without the hold the handler runs before `_tmp` is set (exit 143, the file left); with it the
 * signal waits for the registration and the handler removes the file (exit 143, nothing left). Every tool that carries the block is
 * checked from its own script.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { test } from "node:test";
import { filesUnder } from "./pack-network-harness.ts";
import { ROOT } from "./tool-library-harness.ts";
import { PYTHON3 } from "./host-gates.ts";

const carriers: string[] = [];
for (const pack of readdirSync(join(ROOT, "packs"))) {
  const tools = join(ROOT, "packs", pack, "tools");
  try {
    if (!statSync(tools).isDirectory()) continue;
  } catch {
    continue;
  }
  for (const tool of readdirSync(tools)) {
    const script = join(tools, tool, "run.py");
    try {
      const text = readFileSync(script, "utf8");
      if (text.includes('STOP["in_library"]')) continue;      // evtx_carve and powershell_blocks: their handler only sets a flag that the tool checks (nothing runs in the handler)
      if (!text.includes("def install_signal_handlers(")) continue;      // recovery_key_scan: its own stop machinery (a hard stop after a grace time), another entry point
      if (text.includes("# BEGIN SHARED PAGE") && /PAGES\.append\(self\)\n\n    def add\(self, row: object\) -> None:\n        """The hidden temporary file/.test(text)) carriers.push(script);
    } catch {
      /* not a tool */
    }
  }
}

const PROGRAM = `
import importlib.util, os, signal, sys, tempfile
spec = importlib.util.spec_from_file_location("carrier", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
def last_word(signum):                          # what a tool's main() gives its handler: remove the temporary file of its pages
    for page in list(mod.PAGES):
        if page._tmp is not None:
            try:
                os.unlink(page._tmp)
            except OSError:
                pass
install = mod.install_signal_handlers          # what main() does: the stop handlers of the STOP block are in
if install.__code__.co_argcount:
    install(last_word)
else:
    install()
    for holder in ("STATE", "STOP"):
        if hasattr(mod, holder):
            getattr(mod, holder)["last_word"] = last_word
real = tempfile.mkstemp
def mkstemp(*a, **k):
    made = real(*a, **k)
    os.kill(os.getpid(), signal.SIGTERM)       # right after the file exists, before the caller has named it
    return made
tempfile.mkstemp = mkstemp
page = mod.NoReplacePage("carrier", ["k"], 1)
for i in range(5):
    page.add({"row": i})
print("survived")
`;

test("the block is carried by the tools it is held for", () => {
  assert.ok(carriers.length >= 29, `${carriers.length} carriers`);
});

test(`a stop signal right after mkstemp leaves no hidden file, in each of the tools that carry the page block`, { timeout: 280_000 }, async () => {
  const bad: string[] = [];
  for (const script of carriers) {
    const cwd = mkdtempSync(join(tmpdir(), "page-stop-"));
    try {
      const run = spawnSync(PYTHON3, ["-c", PROGRAM, script], { cwd, env: { ...process.env, AGENT_ID: "s1" }, encoding: "utf8", timeout: 30_000 });
      const left = (await filesUnder(join(cwd, "work"))).filter((f) => basename(f).startsWith("."));
      if (/is not installed/.test(run.stdout)) continue;       // a library the tool needs is not on this host: nothing to run
      if (run.status !== 143 || left.length > 0 || /survived/.test(run.stdout)) bad.push(`${script.slice(ROOT.length + 1)}: exit ${run.status}${run.signal ? ` (${run.signal})` : ""}, left ${JSON.stringify(left.map((f) => basename(f)))}${run.stderr ? `, ${run.stderr.trim().split("\n").pop()}` : ""}${run.status === 1 ? ` ${run.stdout.slice(0, 160)}` : ""}`);
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  }
  assert.deepEqual(bad, []);
});