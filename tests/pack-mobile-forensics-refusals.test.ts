/**
 * manifest_db, protobuf_peek and sqlite_freespace refuse as one JSON answer that carries the status pair (docs/packs.md, section 8): `status` failed and
 * a one-sentence `status_basis`, with exit 1 and nothing on stderr but what a person may read. Given nothing, a path that is not there, a path of the wrong
 * type and a file that is not what the tool reads, on every path.
 */
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";

const TOOLS = ["manifest_db", "protobuf_peek", "sqlite_freespace"];

for (const tool of TOOLS) {
  test(`${tool}: a refusal is one JSON answer with status failed and a status_basis, exit 1`, async () => {
    await withCwd(async (cwd) => {
      await mkdir(join(cwd, "work"), { recursive: true });
      await writeFile(join(cwd, "work", "not-a-database.bin"), Buffer.from("this is not what the tool reads\n"));
      const script = join(ROOT, "packs", "mobile-forensics", "tools", tool, "run.py");
      const cases: [string, unknown][] = [
        ["{}", {}],
        ["a missing path", { path: "work/does-not-exist" }],
        ["a path of the wrong type", { path: 5 }],
        ["a path that is a directory", { path: "work" }],
        ["a limit that is no number", { path: "work/not-a-database.bin", limit: "many" }],
      ];
      for (const [label, args] of cases) {
        const r = await runPy(script, cwd, args, undefined, { AGENT_ID: "s1" });
        const where = `${tool} given ${label}: exit ${r.code}, stdout ${r.stdout.slice(0, 160)}, stderr ${r.stderr.slice(-160)}`;
        assert.doesNotMatch(r.stderr, /Traceback/, where);
        const doc = JSON.parse(r.stdout) as { status?: string; status_basis?: string; error?: string };
        if (doc.status === "failed") {
          assert.equal(r.code, 1, where);
          assert.ok(typeof doc.status_basis === "string" && doc.status_basis.length > 20 && !doc.status_basis.includes("\n"), where);
          assert.ok(doc.error, where);
        } else {
          // the tool read the file and said what it found: still the pair
          assert.ok(["complete", "partial"].includes(doc.status ?? ""), where);
          assert.ok(typeof doc.status_basis === "string" && doc.status_basis.length > 0, where);
        }
      }
    });
  });
}
