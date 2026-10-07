/**
 * network-forensics: the skills are held to the size and shape rules for a skill leaf (a leaf is at most 800
 * tokens, estimated as bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..."; `needs` is at
 * most two deep; an index entry is at most 40 tokens), and the tool fields they name are fields the tools
 * really write, so a skill cannot keep teaching a field name a tool no longer has.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { NET, TOOLS } from "./pack-network-harness.ts";

const SKILLS = join(NET, "skills");
const BASE_SKILLS = join(NET, "..", "computer-forensics-base", "skills");
const TOKENS = (text: string): number => Buffer.byteLength(text) / 4.245;

type Skill = { id: string; meta: Record<string, string | string[]>; body: string; text: string };

async function load(root: string): Promise<Map<string, Skill>> {
  const out = new Map<string, Skill>();
  const walk = async (dir: string): Promise<void> => {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (e.isDirectory()) await walk(join(dir, e.name));
      else if (e.name.endsWith(".md") && e.name !== "INDEX.md") {
        const text = await readFile(join(dir, e.name), "utf8");
        const m = /^---\n([\s\S]*?)\n---\n/.exec(text);
        assert.ok(m, `${e.name} has front matter`);
        const meta: Record<string, string | string[]> = {};
        for (const line of m[1].split("\n")) {
          const [k, ...rest] = line.split(":");
          const v = rest.join(":").trim();
          meta[k.trim()] = v.startsWith("[") ? v.slice(1, -1).split(",").map((x) => x.trim()).filter(Boolean) : v;
        }
        out.set(String(meta.id), { id: String(meta.id), meta, body: text.slice(m[0].length), text });
      }
    }
  };
  await walk(root);
  return out;
}

test("every skill is a leaf within the budget, opens with Use when ... Not for ..., and has a short index entry", async () => {
  const skills = await load(SKILLS);
  assert.equal(skills.size, 12);
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= 800, `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, /^Use when /, `${s.id} opens with Use when`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    for (const part of ["Shows", "Does not show", "Record"]) assert.match(s.body, new RegExp(`${part}:`), `${s.id} has ${part}`);
  }
  const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  for (const id of skills.keys()) assert.ok(index.includes(`\`${id}\``), `${id} is in the index`);
});

test("needs is at most two deep and its chain is at most 2,000 tokens, counting the base skills it reaches", async () => {
  const all = new Map([...(await load(BASE_SKILLS)), ...(await load(SKILLS))]);
  const chain = (id: string, seen: string[] = []): { depth: number; ids: string[] } => {
    const s = all.get(id);
    assert.ok(s, `${id} resolves`);
    const needs = (s.meta.needs as string[]) ?? [];
    let best = { depth: 0, ids: [id] };
    for (const n of needs) {
      assert.ok(!seen.includes(n), `no cycle at ${n}`);
      const sub = chain(n, [...seen, id]);
      if (sub.depth + 1 > best.depth) best = { depth: sub.depth + 1, ids: [id, ...sub.ids] };
    }
    return best;
  };
  for (const id of (await load(SKILLS)).keys()) {
    const { depth, ids } = chain(id);
    assert.ok(depth <= 2, `${id} needs ${depth} deep: ${ids.join(" > ")}`);
    const total = new Set(ids.flatMap((i) => [i, ...(((all.get(i)?.meta.needs as string[]) ?? []))]));
    const tokens = [...total].reduce((n, i) => n + TOKENS(all.get(i)?.text ?? ""), 0);
    assert.ok(tokens <= 2000, `${id} chain is ${Math.round(tokens)} tokens`);
  }
});

test("every second-level leaf is pointed to by a leaf that says when to open it", async () => {
  const skills = await load(SKILLS);
  const pointers: Record<string, string> = {
    "capture/derivatives": "capture/what-you-have", "sessions/objects": "sessions/reconstruct",
    "metadata/fingerprints": "metadata/dns-tls", "exfil/counters": "exfil/volume",
  };
  for (const [child, parent] of Object.entries(pointers)) {
    const p = skills.get(parent);
    assert.ok(p, parent);
    assert.ok(p.body.includes(`\`${child}\``), `${parent} points to ${child}`);
    assert.match(p.body, /[Oo]nly if|read it before|before you quote/, `${parent} says when`);
  }
});

// Fields and names a skill teaches, each of which a tool must write or read: tool -> [skill, names].
const TAUGHT: Array<[string, string, string[]]> = [
  ["pcap_summary", "capture/what-you-have", ["truncation", "payload_bytes_captured_total"]],
  ["pcap_summary", "beacons/periodicity", ["with_syn_times", "syn_unique"]],
  ["pcap_summary", "exfil/counters", ["bytes_original", "bytes_captured", "top_talkers"]],
  ["beacon_score", "beacons/periodicity", ["assume_utc", "mad_over_median", "event_density_ratio", "long_final_gap", "window_end", "sensor_coverage_confirmed"]],
  ["zeek_run", "sessions/reconstruct", ["hashes_produced", "hash_fields"]],
  ["zeek_run", "exfil/counters", ["engine_diagnostics"]],
  ["zeek_run", "capture/what-you-have", ["engine_diagnostics"]],
  ["suricata_run", "metadata/fingerprints", ["tls_fingerprints", "checksum_mode"]],
  ["pcap_extract", "sessions/objects", ["receipt.json", "index.tsv", "matched_by_content", "ambiguous", "unmapped", "write_values", "pcap-extract-values.jsonl", "withheld-", "timed_out", "not_attempted"]],
  ["network_log_summary", "logs/web-proxy-firewall", ["decoding_substituted", "timestamp_raw", "timestamp_utc", "timezone_source", "unparsed", "blank", "parsed"]],
];

test("the tool fields a skill names are fields its tool writes", async () => {
  const skills = await load(SKILLS);
  for (const [tool, skillId, names] of TAUGHT) {
    const script = await readFile(join(TOOLS, tool, "run.py"), "utf8");
    const body = skills.get(skillId)?.body ?? "";
    for (const name of names) {
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      assert.ok(script.includes(name), `${tool} has ${name}, which ${skillId} teaches`);
    }
  }
});

test("no skill states a version fact about a tool, the old claims are gone, and secret handling is stated where a tool can reach one", async () => {
  const skills = await load(SKILLS);
  for (const s of skills.values()) {
    assert.doesNotMatch(s.body, /Suricata 7|since (version )?\d|as of (20|19)\d\d/i, `${s.id} states no version fact`);
    assert.doesNotMatch(s.body, /Every question about content is unanswerable|You will not read a TLS payload|a hash per object|which is when either becomes conclusive|will produce|almost nothing legitimate/i, `${s.id} still carries an overclaim`);
    assert.doesNotMatch(s.body, /`(connection_starts|starts|jitter_fraction|completeness|stopped|with_starts)`|\bconnection starts?\b/, `${s.id} uses a renamed field`);
  }
  for (const id of ["capture/what-you-have", "capture/carve-from-images", "sessions/reconstruct", "sessions/objects", "metadata/dns-tls", "metadata/fingerprints", "logs/web-proxy-firewall"]) {
    assert.match(skills.get(id)!.body, /secret_output: true/, `${id} says the job runs with secret_output: true`);
  }
});
