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
