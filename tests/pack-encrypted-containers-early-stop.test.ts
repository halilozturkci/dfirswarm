/**
 * ENC-05 / ENC-07: the SHARED STOP block now runs right after the standard-library imports in archive_probe,
 * crypto_id and recovery_key_scan (and, for the same reason, in password_recover and tcrypt_header, written in
 * this same change), before the PLACE, PAGE, WITHHOLDING, NAMES and PROCESS blocks and their module-level work
 * (regex compiles and the rest). A stop signal in that window used to get the interpreter's default action, no
 * JSON answer; moving the block first narrows it (the interpreter's own start-up and the module's compile, which
 * happen before any of the module's own code runs, are not claimed).
 *
 * The structural check below is exact, deterministic and fails on the previous head, where STOP still sits
 * after those blocks: it is the regression test for this change. A random-delay SIGTERM run (the method #210
 * used: 80 SIGTERMs per tool, a random 0-250 ms delay) was also run by hand, before and after, on a native
 * filesystem path (this checkout's own cross-OS mount adds triple-digit milliseconds of its own, which would
 * swamp the few milliseconds this fix moves): archive_probe 24 to 20, crypto_id 12 to 11, recovery_key_scan 13
 * to 9, tcrypt_header 24 to 11, password_recover 13 to 23 of 80. Four of five improved; password_recover did not,
 * on that run. Repeating the random-delay run inside this suite (sharing the host with every other test file
 * running at the same time) swung as high as 36 of 40 missing for a tool that measured 9-20 of 80 alone moments
 * earlier: host contention, not the block's position, dominates the count once many processes compete for the
 * CPU, so no timing bound is asserted here as a pass/fail gate; the measurements above are the record of it.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const ENC = join(ROOT, "packs", "encrypted-containers", "tools");
const TOOLS = ["archive_probe", "crypto_id", "recovery_key_scan", "password_recover", "tcrypt_header", "crypto_metadata", "crypto_selftest", "archive_metadata", "materialise_decrypted"];

function blockStart(text: string, name: string): number {
  const i = text.indexOf(`# BEGIN SHARED ${name}`);
  assert.ok(i >= 0, `${name} block is present`);
  return i;
}

test("the STOP block's source position is before PLACE, PAGE, WITHHOLDING, NAMES and PROCESS in every carrier (the fix: this is false on the previous head)", async () => {
  for (const name of TOOLS) {
    const text = await readFile(join(ENC, name, "run.py"), "utf8");
    const stop = blockStart(text, "STOP");
    for (const other of ["PLACE", "PAGE", "WITHHOLDING", "NAMES", "PROCESS"]) {
      if (!text.includes(`# BEGIN SHARED ${other}`)) continue; // not every tool carries PLACE/PAGE/PROCESS
      const at = blockStart(text, other);
      assert.ok(stop < at, `${name}: STOP (at ${stop}) must come before ${other} (at ${at})`);
    }
  }
});

test("the STOP block's own text is still the pinned encrypted lineage, unchanged by the move (byte count only, as a quick check; tests/pack-shared-stop.test.ts holds the full digest)", async () => {
  for (const name of TOOLS) {
    const text = await readFile(join(ENC, name, "run.py"), "utf8");
    const start = text.indexOf("# BEGIN SHARED STOP");
    const end = text.indexOf("# END SHARED STOP") + "# END SHARED STOP".length;
    assert.equal(end - start, 7919, `${name}: the STOP block's byte span changed`);      // 7838 before round 10's hold in claim_answer and hard_stop
  }
});
