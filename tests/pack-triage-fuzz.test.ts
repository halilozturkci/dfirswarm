/**
 * triage-collection: a structure-aware fuzz of the four manifest tools and the collection-intake recipe (tests/pack-triage-fuzz.py).
 * Each case is a collection built from the formats' own definitions (KAPE copy, skip and console logs, UAC's log and hash lists, a
 * Velociraptor container), with a ground truth kept beside it and then damaged: wrong sizes and digests, missing, unexpected,
 * case-twin, linked, FIFO and unreadable files, credential-store names whose digests are canaries, broken CSV and JSON Lines, an
 * unlistable directory, a nested archive. The recipe reads the same tree packed as zip, tar, tgz, tbz2 or txz, sometimes cut,
 * joined to a second archive, or over its bound on the records it keeps. The oracles: every answer is JSON, in time, with no
 * traceback; no digest of a credential-store file, measured or claimed, is in any output; an independent model of the join says what
 * verify reports for the plain KAPE rows; an incomplete census never says absent; the tools agree on the files an ambiguous record may
 * name; the recipe agrees with verify on the same tree and is never complete for a cut tar. TRIAGE_FUZZ_CASES sets the number of
 * cases (40 here; the full run is 1,000 per tool), TRIAGE_FUZZ_SEED the seed, TRIAGE_PACK another copy of the pack.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";
import { TRIAGE } from "./pack-triage-harness.ts";

const PACK = process.env.TRIAGE_PACK ?? TRIAGE;
const CASES = process.env.TRIAGE_FUZZ_CASES ?? "40";
const SEED = process.env.TRIAGE_FUZZ_SEED ?? "7";

test(`fuzz: ${CASES} structure-aware collections through the four tools and the recipe find nothing`, { timeout: 900000 }, async () => {
  const work = await mkdtemp(join(tmpdir(), "triage-fuzz-"));
  try {
    const out: Buffer[] = [];
    const code = await new Promise<number | null>((resolve, reject) => {
      const child = spawn("python3", [join(ROOT, "tests", "pack-triage-fuzz.py"), "--pack", PACK, "--cases", CASES, "--seed", SEED, "--work", work], { cwd: work });
      child.stdout.on("data", (c: Buffer) => out.push(c));
      child.stderr.on("data", (c: Buffer) => out.push(c));
      child.on("error", reject);
      child.on("close", resolve);
    });
    const text = Buffer.concat(out).toString("utf8");
    assert.equal(code, 0, text.slice(-3000));
    const summary = JSON.parse(text.slice(text.indexOf("\n{") + 1));
    assert.equal(Object.keys(summary.runs).length, 5, "every tool ran");
    for (const n of Object.values(summary.runs) as number[]) assert.equal(n, Number(CASES));
    assert.deepEqual(summary.findings_by_kind, {}, JSON.stringify(summary.findings_by_kind, null, 1));
  } finally {
    await rm(work, { recursive: true, force: true });
  }
});
