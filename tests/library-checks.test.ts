/**
 * The finish-line checks the library's goals carry, run for real against small
 * fixtures: an honest run must pass them and a broken run must fail them.
 * Each check is read out of the goal file that ships it, so a fix in one goal
 * that is not made in the others shows here. The harness runs a check under
 * `set -euo pipefail`; so does this file.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const REPO = dirname(dirname(fileURLToPath(import.meta.url)));

/** The check (a `- \`...\`` line of the goal's Checks section) containing `needle`. */
function checkOf(file: string, needle: string): string {
  const hits = readFileSync(join(REPO, file), "utf8")
    .split("\n")
    .filter((l) => l.startsWith("- `") && l.endsWith("`") && l.includes(needle));
  assert.equal(hits.length, 1, `${file}: ${hits.length} checks contain ${needle}`);
  return hits[0].slice(3, -1);
}

function scratch<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "library-checks-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function put(dir: string, rel: string, body: string, mode = 0o644): string {
  const p = join(dir, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, body);
  chmodSync(p, mode);
  return p;
}

function runCheck(dir: string, cmd: string, env: NodeJS.ProcessEnv = process.env): number {
  const r = spawnSync("/bin/bash", ["-euo", "pipefail", "-c", cmd], { cwd: dir, env, encoding: "utf8", timeout: 20000 });
  assert.equal(r.error, undefined, String(r.error));
  return r.status ?? -1;
}

const NO_EXEC_GOALS = [
  "library/memory/ransomware-in-memory.md",
  "library/malware/script-deobfuscation.md",
  "library/malware/sample-static-triage.md",
  "library/malware/ransomware-sample.md",
  "library/malware/document-malware.md",
  "library/malware/unallocated-carving.md",
];

test("the execute-bit check lets the panes' TMPDIR and the toolchain be, and still catches work/", () => {
  for (const goal of NO_EXEC_GOALS) {
    const cmd = checkOf(goal, "-perm -u+x");
    scratch((dir) => {
      put(dir, "work/report.md", "x");
      put(dir, "work/.tmp/helper.sh", "#!/bin/sh\n", 0o755);
      put(dir, "work/.toolchain/bin/pip", "#!/bin/sh\n", 0o755);
      assert.equal(runCheck(dir, cmd), 0, `${goal}: executables under work/.tmp and work/.toolchain pass`);
      put(dir, "work/x/payload.bin", "MZ", 0o755);
      assert.notEqual(runCheck(dir, cmd), 0, `${goal}: an executable under work/x fails`);
    });
    scratch((dir) => {
      put(dir, "work/.tmpx/payload.bin", "MZ", 0o755);
      assert.notEqual(runCheck(dir, cmd), 0, `${goal}: only work/.tmp itself is left out`);
    });
  }
  const readme = readFileSync(join(REPO, "library/README.md"), "utf8");
  assert.ok(readme.includes("-path work/.toolchain -o -path work/.tmp"), "the README's standard check prunes work/.tmp too");
});

test("the inventory check fails closed when jq or inputs.json is missing", () => {
  const cmd = checkOf("library/malware/sample-static-triage.md", "n=$(jq");
  const rows = (n: number) => "| path | what |\n| --- | --- |\n" + Array.from({ length: n }, (_, i) => `| f${i} | x |`).join("\n") + "\n";
  scratch((dir) => {
    // A stand-in jq that counts as the real one would: two files to inventory.
    const bin = join(dir, "bin");
    put(dir, "bin/jq", "#!/bin/sh\necho 2\n", 0o755);
    for (const t of ["grep", "cat"]) symlinkSync(spawnSync("which", [t], { encoding: "utf8" }).stdout.trim(), join(bin, t));
    const withJq = { ...process.env, PATH: bin };
    put(dir, "inputs.json", "{}");
    put(dir, "work/inventory.md", rows(3));
    assert.equal(runCheck(dir, cmd, withJq), 0, "header + 2 rows for 2 files passes");
    put(dir, "work/inventory.md", rows(1));
    assert.notEqual(runCheck(dir, cmd, withJq), 0, "too few rows fails");
    // No jq on PATH at all: the old check computed `$(( + 1 ))` = 1 and passed.
    rmSync(join(bin, "jq"));
    put(dir, "work/inventory.md", rows(3));
    assert.notEqual(runCheck(dir, cmd, withJq), 0, "no jq fails");
  });
  scratch((dir) => {
    put(dir, "work/inventory.md", rows(3));
    assert.notEqual(runCheck(dir, cmd), 0, "no inputs.json fails");
  });
  scratch((dir) => {
    // The real jq, if the machine has one: the filter itself is the one that ships.
    if (spawnSync("jq", ["--version"]).status !== 0) return;
    put(dir, "inputs.json", JSON.stringify({ files: [{ path: "a.bin" }, { path: "CASE-brief.md" }, { path: "r.yar" }] }));
    put(dir, "work/inventory.md", rows(2));
    assert.equal(runCheck(dir, cmd), 0, "one file counts, the brief and the rule file do not");
    put(dir, "work/inventory.md", rows(0));
    assert.notEqual(runCheck(dir, cmd), 0, "a header alone is too few");
  });
});

test("the carving offset check accepts every way an offset is written and rejects junk", () => {
  const cmd = checkOf("library/malware/unallocated-carving.md", "work/carvings.md)\" -ge 3");
  const table = (cells: string[]) => "| Offset | Type |\n| --- | --- |\n" + cells.map((c) => `| ${c} | jpeg |`).join("\n") + "\n";
  const accepted: Record<string, string[]> = {
    "decimal with hex in brackets": ["675840 (0xA5000)", "1 (0x1)", "4096 (0x1000)"],
    "bold decimal": ["**675840**", "**4096**", "**12**"],
    "upper-case 0X": ["0X0A5000", "0X1000", "0XFF"],
    "lower-case 0x": ["0xa5000", "0x1000", "0xff"],
    "offsets under 100": ["7", "42", "99"],
    "thousands separators": ["1,048,576", "2,000", "12,345,678"],
  };
  for (const [name, cells] of Object.entries(accepted)) {
    scratch((dir) => {
      put(dir, "work/carvings.md", table(cells));
      assert.equal(runCheck(dir, cmd), 0, name);
    });
  }
  const junk = ["TBD", "n/a", "offset", "0xZZ", "12 apples", "abc123", "", "---", "see below"];
  scratch((dir) => {
    put(dir, "work/carvings.md", table(junk));
    assert.notEqual(runCheck(dir, cmd), 0, "junk in the first column does not count");
  });
  scratch((dir) => {
    put(dir, "work/carvings.md", table(["4096", "8192", ...junk]));
    assert.notEqual(runCheck(dir, cmd), 0, "two real offsets are not three");
  });
});

test("the carvings header check reads every table, not the first", () => {
  const cmd = checkOf("library/malware/unallocated-carving.md", "^[|] *offset");
  scratch((dir) => {
    put(dir, "work/carvings.md", "# Carvings\n\n| Note | Value |\n| --- | --- |\n| a | b |\n\n| Offset | Type |\n| --- | --- |\n| 4096 | jpeg |\n");
    assert.equal(runCheck(dir, cmd), 0, "an Offset table after another table is found");
    put(dir, "work/carvings.md", "| Note | Value |\n| --- | --- |\n| a | b |\n");
    assert.notEqual(runCheck(dir, cmd), 0, "no Offset table fails");
  });
});

const TIMELINE_GOALS: [string, string, string, string][] = [
  ["library/cloud/aws-cloudtrail.md", "identity", "| Time (UTC) | Identity | Event |", "| Time (UTC) | Event |"],
  ["library/cloud/m365-bec.md", "account", "| UTC | Account | Event |", "| UTC | Event |"],
  ["library/cloud/identity-provider-logs.md", "account", "| Time | Account | Event |", "| Time | Event |"],
  ["library/logs/siem-edr-export.md", "host", "| Date | Host | Event |", "| Date | Event |"],
  ["library/logs/windows-event-logs.md", "host.*account", "| UTC | Host | Account | Event |", "| UTC | Host | Event |"],
];

test("a timeline header check finds the timeline table after a table that is not one", () => {
  for (const [goal, , good, bad] of TIMELINE_GOALS) {
    const cmd = checkOf(goal, "(time|utc|date)");
    const side = "| Time | Note |\n| --- | --- |\n| 1 | a |\n\n";
    scratch((dir) => {
      put(dir, "work/timeline.md", `# Timeline\n\nSome words.\n\n${side}${good}\n| --- | --- | --- |\n| 2026-01-01T00:00:00Z | a | b |\n`);
      assert.equal(runCheck(dir, cmd), 0, `${goal}: the timeline table after a side table is found`);
      put(dir, "work/timeline.md", `# Timeline\n\n${side}${bad}\n| --- | --- |\n| 2026-01-01T00:00:00Z | a |\n`);
      assert.notEqual(runCheck(dir, cmd), 0, `${goal}: a timeline without the column fails`);
    });
  }
});

for (const goal of ["library/memory/disk-and-memory-correlation.md", "library/memory/ransomware-in-memory.md"]) {
  test(`${goal}: the manifest re-hash skips a big dump and still catches a bad hash`, () => {
    const cmd = checkOf(goal, "shasum -a 256 -c");
    const hashOf = (p: string) => spawnSync("sha256sum", [p], { encoding: "utf8" }).stdout.split(" ")[0];
    scratch((dir) => {
      const f = put(dir, "work/extracted/a/dump.bin", "hello\n");
      put(dir, "work/extracted/a/SHA256SUMS", `${hashOf(f)}  dump.bin\n`);
      assert.equal(runCheck(dir, cmd), 0, "an honest manifest passes");
      put(dir, "work/extracted/a/SHA256SUMS", `${"0".repeat(64)}  dump.bin\n`);
      assert.notEqual(runCheck(dir, cmd), 0, "a wrong hash fails");
      put(dir, "work/extracted/a/SHA256SUMS", `${hashOf(f)}  gone.bin\n`);
      assert.notEqual(runCheck(dir, cmd), 0, "a hash of a missing file fails");
    });
    scratch((dir) => {
      // A file over 256 MiB (sparse, so it costs nothing) is not re-hashed: the 30 s check limit.
      const big = put(dir, "work/extracted/b/big.raw", "");
      truncateSync(big, 300 * 1024 * 1024);
      put(dir, "work/extracted/b/SHA256SUMS", `${"0".repeat(64)}  big.raw\n`);
      const t = Date.now();
      assert.equal(runCheck(dir, cmd), 0, "the big dump is skipped, not hashed");
      assert.ok(Date.now() - t < 5000, "and quickly");
      // A small manifest beside it is still checked.
      put(dir, "work/extracted/c/small.bin", "x");
      put(dir, "work/extracted/c/SHA256SUMS", `${"0".repeat(64)}  small.bin\n`);
      assert.notEqual(runCheck(dir, cmd), 0, "a bad hash next to a skipped one still fails");
    });
  });
}
