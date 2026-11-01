/**
 * ransomware-response: ransomware_scope_report on a census of 10 million rows. The tool reads it line by line into a SQLite index, so its
 * memory does not follow the row count: the resident size of the tool is read from the operating system and bounded here at 120 MB (it was
 * 24 MB when measured; the margin is for other machines). This is a deep-tier suite: it writes about 700 MB and runs about a minute.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { PACK } from "./ransomware-pack-harness.ts";

const REPORT = join(PACK, "ransomware_scope_report", "run.py");

const DRIVER = String.raw`
import json, os, resource, subprocess, sys
os.chdir(sys.argv[1])
rows = [json.dumps({"record": "file", "file": "x/%d" % i, "bytes": 100 + i % 7, "status": "candidate" if i % 10 == 0 else "noncandidate"}) for i in range(1000)]
chunk = ("\n".join(rows) + "\n").encode()
with open("census.jsonl", "wb") as f:
    for _ in range(10000):
        f.write(chunk)
    f.write((json.dumps({"record": "receipt", "rows": 10000000, "parser": "encrypted_survey/3", "status": "complete"}) + "\n").encode())
size = os.path.getsize("census.jsonl")
run = subprocess.run([sys.executable, sys.argv[2]], input=json.dumps({"censuses": [{"host": "big", "file": "census.jsonl"}], "max_seconds": 600}).encode(),
                     capture_output=True, env={**os.environ, "AGENT_ID": "deep"})
answer = json.loads(run.stdout)
print(json.dumps({"code": run.returncode, "status": answer["status"], "status_basis": answer["status_basis"], "files": answer["coverage_statement"]["census_files"],
                  "candidates": answer["coverage_statement"]["candidate_files"], "rss_kb": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss, "census_bytes": size,
                  "index": answer["index"]["file"], "stderr": run.stderr.decode()[:500]}))
`;

test("a census of 10 million rows is aggregated into the index in bounded memory, and the numbers are exact", async () => {
  const dir = await mkdtemp(join(tmpdir(), "scope-deep-"));
  try {
    const r = spawnSync("python3", ["-c", DRIVER, dir, REPORT], { encoding: "utf8", timeout: 900_000, maxBuffer: 1 << 24 });
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout) as { code: number; status: string; status_basis: string; files: number; candidates: number; rss_kb: number; census_bytes: number; index: string; stderr: string };
    assert.equal(out.code, 0, out.stderr);
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.files, 10_000_000);
    assert.equal(out.candidates, 1_000_000);
    assert.ok(out.census_bytes > 500_000_000, `${out.census_bytes} bytes of census`);
    assert.ok(out.rss_kb < 120_000, `the tool's resident size was ${out.rss_kb} KB, over the bound of 120,000 KB`);
    assert.ok((await stat(join(dir, out.index))).size < 1_000_000, "the index holds sums, not rows");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
