/**
 * recovery_key_scan's walk reads the clock itself, not only between the files it yields: a run of links, directories or special
 * files yields nothing, and 300,000 links held the walk past the hard stop, whose answer then dropped what had been found. The walk
 * stops at the clock with the entry in hand and everything after it left to unreached(), and the answer is partial.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = join(import.meta.dirname, "..");
const TOOL = join(ROOT, "packs", "encrypted-containers", "tools", "recovery_key_scan", "run.py");

const PROBE = String.raw`
import importlib.util, json, sys, time
spec = importlib.util.spec_from_file_location("rks", sys.argv[1]); rks = importlib.util.module_from_spec(spec); spec.loader.exec_module(rks)
class Sink:
    def __init__(self): self.rows = []
    def add(self, row): self.rows.append(row)
counters = {k: 0 for k in ("files_attempted", "files_read", "files_partial", "files_failed", "files_stopped", "entries_skipped",
                            "directories_failed", "entries_not_started", "directories_not_entered")}
sink = Sink()
rks.STOP["deadline"] = time.monotonic() + float(sys.argv[3])
walk = rks.Walk(sys.argv[2], sink, counters)
yielded = [p for p, _ in walk]
rest, unentered, more = walk.unreached()
print(json.dumps({"stopped": walk.stopped, "yielded": len(yielded), "skipped": counters["entries_skipped"], "rest": len(rest), "unentered": len(unentered)}))
`;

test("the walk reads the clock among entries it does not yield, and leaves the rest to unreached()", () => {
  const top = join(mkdtempSync(join(tmpdir(), "rks-walk-")), "top");
  mkdirSync(join(top, "links"), { recursive: true });
  mkdirSync(join(top, "zz"), { recursive: true });
  writeFileSync(join(top, "zz", "late.txt"), "x");
  for (let i = 0; i < 3000; i += 1) symlinkSync("/nonexistent", join(top, "links", `l${String(i).padStart(5, "0")}`));
  const past = spawnSync("python3", ["-c", PROBE, TOOL, top, "-1"], { encoding: "utf8" });
  assert.equal(past.status, 0, past.stderr);
  const a = JSON.parse(past.stdout);
  assert.deepEqual([a.stopped, a.yielded], [true, 0], "a clock already out stops the walk among the links, before the file after them");
  assert.ok(a.skipped < 300 && a.rest > 2700 && a.unentered === 1, JSON.stringify(a));
  const whole = spawnSync("python3", ["-c", PROBE, TOOL, top, "60"], { encoding: "utf8" });
  const b = JSON.parse(whole.stdout);
  assert.deepEqual([b.stopped, b.yielded, b.skipped, b.rest, b.unentered], [false, 1, 3000, 0, 0], "with time left every entry is looked at");
});

test("a stop with many directories waiting names the first 2,000 and counts the rest, so the answer comes before the hard stop and keeps what was found", () => {
  const top = join(mkdtempSync(join(tmpdir(), "rks-dirs-")), "top");
  // 6,000 directories in the top one, and a file that sorts after them: the walk has found every directory when it reaches the file.
  mkdirSync(top, { recursive: true });
  for (let i = 0; i < 6000; i += 1) mkdirSync(join(top, `d${String(i).padStart(5, "0")}`));
  writeFileSync(join(top, "zz.txt"), "note\n");
  const out = mkdtempSync(join(tmpdir(), "rks-out-"));
  // A clock that moves half a second every time the tool looks at it: the stop comes at once, with every directory still waiting.
  const site = mkdtempSync(join(tmpdir(), "rks-site-"));
  writeFileSync(join(site, "sitecustomize.py"), "import time\n_t = [0.0]\ndef monotonic():\n    _t[0] += 0.5\n    return _t[0]\ntime.monotonic = monotonic\n");
  const r = spawnSync("python3", [TOOL], { input: JSON.stringify({ path: top, max_seconds: 1 }), encoding: "utf8", env: { ...process.env, OUT: out, JOB_ID: "j000001", AGENT_ID: "s1", PYTHONPATH: site }, maxBuffer: 64 << 20 });
  assert.equal(r.status, 0, r.stderr);
  const a = JSON.parse(r.stdout);
  assert.equal(a.status, "partial");
  assert.notEqual(a.hard_stopped, true);
  // The clock is read every 256 entries, so the stop leaves thousands of entries of the chunk unreached: the first 2,000 are named, the rest counted.
  assert.ok(a.coverage.entries_not_started > 2000, JSON.stringify(a.coverage));
  const all = readFileSync(join(out, a.pages.exceptions.all_results.replace(/^.*\/out\//, "")), "utf8").trimEnd().split("\n").map((l) => JSON.parse(l) as { path: string; reason: string });
  assert.ok(all.length <= 2 * 2000 + 4, `${all.length} rows written`);
  assert.ok(all.some((r) => /^\(\d+ more entries\)$/.test(r.path)), "one row says how many entries were not named");
});
