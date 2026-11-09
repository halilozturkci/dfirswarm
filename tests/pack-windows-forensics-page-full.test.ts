/**
 * The windows LosslessPage (one text in every windows-forensics tool that pages and in its tool-library twin): a page whose result
 * cannot be written (a full disk, a quota; here RLIMIT_FSIZE with SIGXFSZ ignored, so a write past the limit is EFBIG, as ENOSPC
 * is for a full disk) ends as JSON with status failed, and leaves no hidden temporary file behind.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const PAGERS = [
  "amcache_apps", "browser_history", "esedb_query", "evtx_carve", "indx_carve", "jumplist", "lnk_jumplist", "lnk_parse", "mam_scan", "mft_records",
  "recyclebin_i", "registry_recover", "regkv", "shellbags", "usn_journal", "utf16_urls", "yara_scan",
];
const TWINS = ["amcache_apps", "browser_history", "esedb_query", "lnk_parse", "mam_scan", "recyclebin_i", "regkv", "usn_journal", "utf16_urls", "yara_scan"];

const CASE = String.raw`
from __future__ import annotations
import hashlib, json, os, re, resource, signal, sys, tempfile
from pathlib import Path
src = open(sys.argv[1]).read()
start = src.index("class LosslessPage")
end = src.index("# BEGIN SHARED PLACE")
ns = {"hashlib": hashlib, "json": json, "os": os, "re": re, "sys": sys, "tempfile": tempfile, "Path": Path}
exec(compile(src[start:end], "page", "exec"), ns)
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
os.environ.pop("JOB_ID", None)
os.environ["AGENT_ID"] = "t"
page = ns["LosslessPage"]("t", "k", 1)
page.add({"i": 0})
page.add({"i": 1})
resource.setrlimit(resource.RLIMIT_FSIZE, (64, 64))
for i in range(5000):
    page.add({"i": i, "pad": "x" * 200})
page.finish()
`;

async function check(file: string): Promise<void> {
  const cwd = await mkdtemp(join(tmpdir(), "w10-page-"));
  try {
    const ran = spawnSync("python3", ["-c", CASE, file], { encoding: "utf8", timeout: 60_000, cwd });
    assert.equal(ran.status, 1, file + ran.stderr + ran.stdout);
    const answer = JSON.parse(ran.stdout) as { status: string; error: string };
    assert.equal(answer.status, "failed");
    assert.match(answer.error, /cannot be written/);
    const left = (await readdir(join(cwd, "work", "t", "tool-output"))).filter((n) => n.startsWith("."));
    assert.deepEqual(left, [], file + " left its hidden temporary file");
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}

test("a page that cannot be written leaves no hidden file, in every windows tool that pages", async () => {
  for (const t of PAGERS) await check(join(ROOT, "packs", "windows-forensics", "tools", t, "run.py"));
  for (const t of TWINS) await check(join(ROOT, "tool-library", t, "run.py"));
});
