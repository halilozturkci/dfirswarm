/**
 * network-forensics: the check that out_dir is empty looks at one entry, never at the whole listing of a directory the caller chose (a directory of
 * millions of names would be read whole, with no clock, to answer a yes or a no). Each tool that checks it holds `holds_files`, and its refusal
 * ("out_dir already holds files") still comes for a directory with something in it.
 */
import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { BEACON, EXTRACT, LOGS, SUMMARY, SURICATA, ZEEK, drop, frameTcp4, pcapClassic, put, refused, tool, TCP, withCwd } from "./pack-network-harness.ts";

const SCRIPTS: Array<[string, string]> = [["beacon_score", BEACON], ["network_log_summary", LOGS], ["pcap_extract", EXTRACT], ["pcap_summary", SUMMARY], ["suricata_run", SURICATA], ["zeek_run", ZEEK]];

test("no tool lists the whole of out_dir to know whether it is empty: holds_files looks at one entry, even where listdir would fail", { timeout: 60_000 }, async () => {
  await withCwd(async (cwd) => {
    for (const [name, script] of SCRIPTS) {
      const source = await readFile(script, "utf8");
      assert.doesNotMatch(source, /os\.path\.exists\(out_dir\) and os\.listdir\(out_dir\)/, `${name} lists out_dir whole`);
      assert.match(source, /os\.path\.exists\(out_dir\) and holds_files\(out_dir\)/, `${name} asks holds_files`);
      const code = `import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("t", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
def boom(*a, **k): raise AssertionError("listdir was called")
os.listdir = boom
empty, full = sys.argv[2], sys.argv[3]
print(m.holds_files(empty), m.holds_files(full))
`;
      await put(cwd, `${name}/full/a`, "x");
      await mkdir(join(cwd, name, "empty"), { recursive: true });
      const run = spawnSync("python3", ["-c", code, script, join(cwd, name, "empty"), join(cwd, name, "full")], { encoding: "utf8", timeout: 15_000 });
      assert.equal(run.stdout.trim(), "False True", `${name}: ${run.stderr}`);
    }
  });
});

test("a tool still refuses an out_dir that holds something, as JSON", { timeout: 60_000 }, async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/full/a", "x");
    const cap = await drop(cwd, "work/c.pcap", pcapClassic([{ sec: 1_771_070_000, frame: frameTcp4({ src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, flags: TCP.SYN }) }]));
    const err = refused(await tool(SUMMARY, cwd, { path: cap, out_dir: "work/full" }));
    assert.match(err.error, /out_dir already holds files/);
    const beacon = refused(await tool(BEACON, cwd, { timestamps: [1, 2, 3, 4, 5, 6, 7], out_dir: "work/full" }));
    assert.match(beacon.error, /out_dir already holds files/);
  });
});
