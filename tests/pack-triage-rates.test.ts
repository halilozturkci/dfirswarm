/**
 * triage-collection: the measured rates of the withholding, asserted. Random secrets of every shape in tests/pack-triage-canaries.ts
 * (a seeded generator per shape, never one hand-built string) are planted alone and in six contexts (a path, a file name, a log
 * line, a URL path, an option, glued to letters), judged exactly as an answer is (the withholding, then the independent check that
 * replaces what it still finds suspect), and the share whose core, whole or in a 12-character window, comes out is asserted from
 * above for what the withholding claims and from below for what it does not claim, so the sentence in the manifests, the changelog
 * and the skills ("withholding is by shape; a secret of another shape is printed") stays true in both directions.
 *
 * The measured table (1,000 plants per shape and context) is in the changelog fragment; this suite runs 200 per cell.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { runPySnippet } from "./tool-library-harness.ts";
import { ID, INDEX } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";
import { CANARY_PY } from "./pack-triage-canaries.ts";

const N = Number(process.env.TRIAGE_RATE_PLANTS ?? 200);

const CODE = CANARY_PY + String.raw`
import json, os, random, sys, tempfile
os.chdir(tempfile.mkdtemp())
data = json.load(sys.stdin)
ns = {}
exec(data["block"], ns)
scrub, suspect = ns["scrub"], ns["_b_suspect"]
CTX = {"alone": lambda s: s, "path": lambda s: "Users/a/AppData/Roaming/%s/data.txt" % s, "zipname": lambda s: "backup_%s.zip" % s,
       "logline": lambda s: "2026-02-14 09:12:00 +0000 ERR could not open %s: Permission denied" % s, "urlpath": lambda s: "https://h.example.test/api/%s/x?y=1" % s,
       "option": lambda s: "--opt %s --next" % s, "glued": lambda s: "x%sy" % s}
rng = random.Random(data["seed"])
n = data["n"]
report = {}
for name, (gen, safe, group) in SHAPES.items():
    cells = {}
    for cname, ctx in CTX.items():
        whole = frag = 0
        for _ in range(n):
            text, cores = gen(rng)
            out = scrub(ctx(text))
            if suspect(out):
                out = "<withheld>"
            out = out.replace("\x00", "")
            big = [c for c in cores if len(c) >= 12]
            if big:
                frag += any(c[k:k + 12] in out for c in big for k in range(len(c) - 11))
                whole += all(c in out for c in big)
            else:
                frag += any(c in out for c in cores)
                whole += any(c in out for c in cores)
        cells[cname] = [whole, frag]
    report[name] = {"group": group, "cells": cells}
print(json.dumps(report))
`;

async function measure(tool: string, seed: number): Promise<Record<string, { group: string; cells: Record<string, [number, number]> }>> {
  const text = await readFile(tool, "utf8");
  const block = text.slice(text.indexOf("# ---- BEGIN SHARED BLOCK"), text.indexOf("# ---- END SHARED BLOCK"));
  const run = await runPySnippet(CODE, [], { block, seed, n: N });
  assert.equal(run.code, 0, run.stderr);
  return JSON.parse(run.stdout);
}

// What the withholding does not take out, measured at 1,000 plants per cell and given a margin: the shapes with a larger residual.
const BOUND_PERCENT: Record<string, number> = { b64_16_bytes: 8, base62_20: 6, base36_lower_32: 40, base36_upper_24: 30 };
const DEFAULT_BOUND_PERCENT = 3;                         // listed families and encodings, AWS-shaped and 20-48 byte base64 keys, base62 of 32

test("the withholding takes the listed and the unlisted shapes out of every context at the rates written in the manifest and the changelog, and prints the residual ones", async () => {
  const report = await measure(ID, 11);
  assert.ok(Object.keys(report).length >= 70);
  const over: string[] = [];
  for (const [name, { group, cells }] of Object.entries(report)) {
    if (group === "residual") continue;
    const bound = BOUND_PERCENT[name] ?? DEFAULT_BOUND_PERCENT;
    for (const [context, [whole, frag]] of Object.entries(cells)) {
      const rate = (100 * Math.max(whole, frag)) / N;
      if (rate > bound) over.push(`${name}/${context}: ${rate.toFixed(1)}% (bound ${bound}%)`);
    }
  }
  assert.deepEqual(over, []);
  // the residual classes are printed, so the sentence "withholding is by shape; a secret of another shape is printed" is true
  for (const [name, { group, cells }] of Object.entries(report)) {
    if (group !== "residual") continue;
    const [whole] = cells.alone;
    assert.ok((100 * whole) / N >= 90, `${name} is printed alone (${whole} of ${N})`);
  }
});

test("collection_index carries the same withholding as collection_id: the same plants come out at the same rates", async () => {
  const a = await measure(ID, 12);
  const b = await measure(INDEX, 12);
  assert.deepEqual(a, b);
});
