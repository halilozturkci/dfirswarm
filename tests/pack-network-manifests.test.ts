/**
 * network-forensics: the six tool manifests say what each tool reads, carry the sha256 of the script they
 * describe, and name exactly the parameters the script reads (a parameter a manifest promises and the script
 * ignores, or the other way round, is a defect an agent meets as a silent no-op).
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS } from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";

const MAGIC = ["d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d", "0a0d0d0a"];
const NAMES = ["pcap_summary", "beacon_score", "pcap_extract", "zeek_run", "suricata_run", "network_log_summary"];
// Names a script still accepts for a parameter that was renamed; the manifest names the new one only.
const ALIASES: Record<string, string[]> = { pcap_summary: ["with_starts", "max_packets"] };

test("every manifest has a use, a version above 1, and the sha256 of its script", async () => {
  for (const name of NAMES) {
    const manifest: Json = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
    assert.ok(manifest.use, `${name} says what it reads`);
    assert.ok(manifest.version >= 2, `${name} version raised`);
    assert.equal(manifest.sha256, createHash("sha256").update(await readFile(join(TOOLS, name, "run.py"))).digest("hex"), `${name} sha256`);
    assert.ok(manifest.timeout_seconds > 0);
    if (["pcap_summary", "pcap_extract", "zeek_run", "suricata_run"].includes(name)) {
      assert.deepEqual(manifest.use.magic.map((m: Json) => m.hex), MAGIC, `${name} magic`);
      assert.deepEqual([...manifest.use.extensions].sort(), [".cap", ".pcap", ".pcapng"]);
    }
    assert.ok(manifest.description.length > 200, `${name} description says what is and is not measured`);
  }
  const requires: Record<string, string[]> = { pcap_extract: ["tshark"], zeek_run: ["zeek"], suricata_run: ["suricata"] };
  for (const [name, programs] of Object.entries(requires)) {
    assert.deepEqual(JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8")).requires, programs);
  }
  for (const name of ["pcap_summary", "beacon_score", "network_log_summary"]) {
    assert.equal(JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8")).requires, undefined, `${name} needs no program`);
  }
});

test("the parameters a manifest names are the parameters its script reads", async () => {
  for (const name of NAMES) {
    const manifest: Json = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
    const script = await readFile(join(TOOLS, name, "run.py"), "utf8");
    const read = new Set<string>();
    for (const m of script.matchAll(/args\.get\("([a-z_]+)"/g)) read.add(m[1]);
    for (const m of script.matchAll(/optional_int\(args, "([a-z_]+)"/g)) read.add(m[1]);
    for (const m of script.matchAll(/(?<![A-Za-z_])args\[\s*"([a-z_]+)"\s*\]/g)) read.add(m[1]);
    for (const alias of ALIASES[name] ?? []) read.delete(alias);
    const named = new Set(Object.keys(manifest.params));
    assert.deepEqual([...read].filter((p) => !named.has(p)).sort(), [], `${name}: parameters the script reads and the manifest does not name`);
    assert.deepEqual([...named].filter((p) => !read.has(p)).sort(), [], `${name}: parameters the manifest names and the script does not read`);
    // The example is a call the manifest's own parameters accept.
    const example = JSON.parse(manifest.example);
    for (const key of Object.keys(example)) assert.ok(named.has(key), `${name} example uses ${key}`);
  }
});

// --- D-network-F1: every manifest example runs as a job -----------------------------------------------------------------------

import { mkdir } from "node:fs/promises";
import { AGENT, SUMMARY, BEACON, EXTRACT, ZEEK, SURICATA, LOGS, asJob, drop, frameTcp4, pcapClassic, put, stub, TCP, withCwd } from "./pack-network-harness.ts";

const SCRIPTS: Record<string, string> = { pcap_summary: SUMMARY, beacon_score: BEACON, pcap_extract: EXTRACT, zeek_run: ZEEK, suricata_run: SURICATA, network_log_summary: LOGS };

/** The harness maps work/<agent id>/x to {OUT}/x for a job (extensions/protocol-core.ts ownPlace); here OUT is the directory `out`. */
const asTheAgentWouldGiveIt = (example: string): string => example.replaceAll("<your id>", AGENT.AGENT_ID);
const asTheJobGetsIt = (example: string): string => asTheAgentWouldGiveIt(example).replaceAll(`work/${AGENT.AGENT_ID}/`, "out/");

test("every manifest example is written as the agent gives it (work/<your id>/...) and runs as a job: the place it writes is the job's own output", async () => {
  for (const name of NAMES) {
    const manifest: Json = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
    const given = JSON.parse(asTheAgentWouldGiveIt(manifest.example));
    for (const [key, value] of Object.entries(given)) {
      if (typeof value === "string" && /^(out_dir|out_file|results_to|extract_to)$/.test(key)) {
        assert.match(value as string, /^work\/s1\/[^/]/, `${name}.${key} is a place the agent writes: work/<your id>/...`);
      }
    }
  }
  await withCwd(async (cwd, bin) => {
    await stub(bin, "tshark", `#!/bin/sh\ncase "$1" in --version) echo 'TShark (Wireshark) 4.6.9'; exit 0;; --export-objects) echo '    http' >&2; echo '    smb' >&2; exit 0;; -G) exit 0;; esac\nexit 0\n`);
    await stub(bin, "zeek", `#!/bin/sh\ncase "$1" in --version) echo 'zeek version 8.0.0'; exit 0;; esac\nprintf '#separator \\\\x09\\n#set_separator\\t,\\n#empty_field\\t(empty)\\n#unset_field\\t-\\n#path\\tconn\\n#fields\\tts\\tuid\\n#types\\ttime\\tstring\\n1.0\\tC1\\n' > conn.log\nexit 0\n`);
    await stub(bin, "suricata", `#!/bin/sh\nfor a in "$@"; do case "$a" in --build-info) echo 'This is Suricata version 7.0.0'; exit 0;; esac; done\nlogdir=""; while [ $# -gt 0 ]; do case "$1" in -l) logdir="$2"; shift;; esac; shift; done\n[ -n "$logdir" ] && echo '{"timestamp":"2023-11-14T22:13:20.123456+0000","event_type":"flow"}' > "$logdir/eve.json"\nexit 0\n`);
    await drop(cwd, "inputs/capture.pcap", pcapClassic([{ sec: 1_700_000_000, frame: frameTcp4({ src: "10.0.0.5", dst: "203.0.113.7", sport: 50000, dport: 80, flags: TCP.SYN, seq: 1 }) }]));
    await put(cwd, "inputs/access.log", '192.0.2.1 - - [14/Nov/2023:23:13:20 +0100] "GET /a HTTP/1.1" 200 12 "-" "ua"\n');
    await put(cwd, "work/case.rules", 'alert tcp any any -> any any (msg:"t"; sid:1; rev:1;)\n');
    await mkdir(join(cwd, "out"), { recursive: true });
    for (const name of NAMES) {
      const manifest: Json = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
      const result = await asJob(SCRIPTS[name], cwd, JSON.parse(asTheJobGetsIt(manifest.example)), bin);
      assert.doesNotMatch(result.stderr, /Traceback/, name);
      const out = JSON.parse(result.stdout);
      assert.equal(out.error, undefined, `${name}: the manifest's own example is refused in a job: ${out.error}`);
    }
  });
});

// --- the manifest declares secret output (docs/packs.md, "Secrets and sensitive output") -----------------------------------

test("pcap_extract and network_log_summary declare secret_output: required (zeek_run and suricata_run follow in the next pull request); pcap_summary and beacon_score print addresses, ports and counts and do not", async () => {
  for (const name of ["pcap_extract", "network_log_summary"]) {
    const manifest: Json = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
    assert.equal(manifest.secret_output, "required", name);
    assert.match(manifest.description, /secret_output: "required"/);
  }
  for (const name of ["pcap_summary", "beacon_score"]) {
    assert.equal(JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8")).secret_output, undefined, name);
  }
});
