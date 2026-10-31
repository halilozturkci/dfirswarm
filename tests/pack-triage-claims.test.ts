/**
 * triage-collection: what the manifests and the README say about secret output is what the tools do. Since the job service sets
 * SECRET_OUTPUT=1 for a job that is run as secret output, every triage tool reads it (secret_job()) and refuses `write_values` without
 * it; the manifests and the README used to give, as the reason to run as a secret_output job, that "the tool cannot see whether the job
 * was run so", which is false. The memory pack removed the same sentence and tests for its absence (pack-memory-shared.test.ts).
 */
import assert from "node:assert/strict";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TRIAGE, TOOLS, asJob, refused, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const NAMES = ["collection_id", "collection_index", "collection_manifest_parse", "collection_manifest_verify", "collection_path_map", "collection_coverage"];

const description = async (name: string): Promise<string> => (JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8")) as Json).description as string;

test("no triage manifest and not the README says the tools cannot see whether a job was run as secret output", async () => {
  for (const name of NAMES) assert.doesNotMatch(await description(name), /cannot see whether/i, `${name}: the old reason is back in its description`);
  assert.doesNotMatch(await readFile(join(TRIAGE, "README.md"), "utf8"), /cannot see whether/i, "the README");
});

test("each description says that withholding by shape applies in every call and that write_values needs a job run as secret output", async () => {
  for (const name of NAMES) {
    const text = await description(name);
    assert.match(text, /withholding by shape applies in every call/, `${name}: withholding by shape`);
    assert.match(text, /write_values: true is refused unless the job runs as secret output, which the tool checks/, `${name}: write_values needs a secret-output job`);
    assert.match(text, /secret_output: true/, `${name}: still advises a secret_output job`);
  }
  const readme = await readFile(join(TRIAGE, "README.md"), "utf8").then((t) => t.replace(/\s+/g, " "));
  assert.match(readme, /write_values` is refused unless the job runs as secret output, which the tools check/);
});

/** The arguments each tool needs to reach its write_values check from a small tree. */
const ARGS: Record<string, Json> = {
  collection_id: { root: "work/ev" },
  collection_index: { root: "work/ev" },
  collection_manifest_parse: { root: "work/ev" },
  collection_manifest_verify: { root: "work/ev" },
  collection_path_map: { root: "work/ev", paths: ["a.txt"] },
  collection_coverage: { root: "work/ev", questions: [{ id: "q1", source_paths: ["a.txt"] }] },
};

test("write_values: true in a job environment is refused without SECRET_OUTPUT=1 and accepted with it, as the descriptions now say", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "a.txt"), "hello\n");
    for (const name of NAMES) {
      const script = join(TOOLS, name, "run.py");
      const args = { ...ARGS[name]!, write_values: true };
      // asJob sets SECRET_OUTPUT=1 for a call that sets write_values, as the job service does; "0" overrides it to the job that was not run so.
      const without = refused(await asJob(script, cwd, args, { SECRET_OUTPUT: "0" }, `out-${name}-0`));
      assert.match(String(without.error), /not run as secret output \(SECRET_OUTPUT is not 1\)/, `${name}: ${JSON.stringify(without).slice(0, 200)}`);
      const withIt = await asJob(script, cwd, args, { SECRET_OUTPUT: "1" }, `out-${name}-1`);
      assert.equal(withIt.code, 0, `${name}: ${withIt.stderr}${withIt.stdout.slice(0, 300)}`);
      const answer = JSON.parse(withIt.stdout) as Json;
      assert.notEqual(answer.status, "failed", `${name}: accepted with SECRET_OUTPUT=1`);
    }
  });
});
