/**
 * recovery_key_scan's walk reads the clock itself, not only between the files it yields: a run of links, directories or special
 * files yields nothing, and 300,000 links held the walk past the hard stop, whose answer then dropped what had been found. The walk
 * stops at the clock with the entry in hand and everything after it left to unreached(), and the answer is partial.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
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
