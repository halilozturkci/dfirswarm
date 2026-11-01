/**
 * The six collection_* tools carry one shared block (tests/pack-triage-shared.test.ts), and its failure answers carry the status pair
 * (docs/packs.md, section 8): `status` failed and a one-sentence `status_basis`, with exit 1. Given nothing, a root that is not there, a root of the
 * wrong type and a limit that is no number, and given a stop signal before the tool has read anything.
 */
import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";

const TOOLS = ["collection_coverage", "collection_id", "collection_index", "collection_manifest_parse", "collection_manifest_verify", "collection_path_map"];

for (const tool of TOOLS) {
  test(`${tool}: a refusal is one JSON answer with status failed and a status_basis, exit 1`, async () => {
    await withCwd(async (cwd) => {
      await mkdir(join(cwd, "work"), { recursive: true });
      const script = join(ROOT, "packs", "triage-collection", "tools", tool, "run.py");
      const cases: [string, unknown][] = [
        ["{}", {}],
        ["a root that is not there", { root: "work/does-not-exist" }],
        ["a root of the wrong type", { root: 5 }],
        ["a limit that is no number", { root: "work", limit: "many" }],
        ["a list where an object belongs", []],
      ];
      for (const [label, args] of cases) {
        const r = await runPy(script, cwd, args, undefined, { AGENT_ID: "s1" });
        const where = `${tool} given ${label}: exit ${r.code}, stdout ${r.stdout.slice(0, 160)}, stderr ${r.stderr.slice(-160)}`;
        assert.doesNotMatch(r.stderr, /Traceback/, where);
        const doc = JSON.parse(r.stdout) as { status?: string; status_basis?: string; error?: string };
        assert.ok(typeof doc.status_basis === "string" && doc.status_basis.length > 0 && !doc.status_basis.includes("\n"), where);
        if (doc.status === "failed") {
          assert.equal(r.code, 1, where);
          assert.ok(doc.error, where);
        } else assert.ok(["complete", "partial"].includes(doc.status ?? ""), where);
      }
    });
  });
}
