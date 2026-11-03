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
import { routerChecks } from "./pack-router-checks.ts";

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

// The pack's one router: shown alone when a run's index is over budget, and names every other skill once (routerChecks below).
const ROUTER = "network/router";

test("every skill is a leaf within the budget, opens with Use when ... Not for ..., and has a short index entry", async () => {
  const skills = await load(SKILLS);
  assert.equal(skills.size, 17);
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= (s.id === ROUTER ? 400 : 800), `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, /^Use when /, `${s.id} opens with Use when`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    // The router reads no artefact: it names notes and holds no rule, so it has none of the three parts.
    if (s.id !== ROUTER) for (const part of ["Shows", "Does not show", "Record"]) assert.match(s.body, new RegExp(`${part}:`), `${s.id} has ${part}`);
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
  ["pcap_summary", "beacons/periodicity", ["with_syn_times", "syn_unique", "syn_folded", "syn_unique_is_lower_bound", "syn_observations"]],
  ["pcap_summary", "exfil/counters", ["bytes_original", "bytes_captured", "top_talkers", "top_ports"]],
  ["beacon_score", "beacons/periodicity", ["assume_utc", "mad_over_median", "event_density_ratio", "long_final_gap", "window_end", "sensor_coverage_confirmed"]],
  ["zeek_run", "sessions/reconstruct", ["hashes_produced"]],
  ["zeek_run", "exfil/counters", ["engine_diagnostics"]],
  ["zeek_run", "capture/what-you-have", ["engine_diagnostics"]],
  ["suricata_run", "metadata/fingerprints", ["tls_fingerprints", "checksum_mode"]],
  ["pcap_extract", "sessions/objects", ["receipt.json", "index.tsv", "matched_by_content", "ambiguous", "unmapped", "write_values", "pcap-extract-values.jsonl", "withheld-names.jsonl", "withheld-", "timed_out", "not_attempted"]],
  ["suricata_run", "metadata/fingerprints", ["home_net", "rule_load", "inputs/"]],
  ["network_log_summary", "logs/web-proxy-firewall", ["referer"]],
  ["network_log_summary", "logs/web-proxy-firewall", ["decoding_substituted", "timestamp_raw", "timestamp_utc", "timezone_source", "unparsed", "blank", "parsed"]],
  ["suricata_run", "analysis/engines-and-coverage", ["dry_run", "rule_load", "known", "effective_configuration", "dump_config", "not_covered", "checksum_mode"]],
  ["zeek_run", "analysis/engines-and-coverage", ["dry_run", "script_load_status", "logs_requested_not_written", "logs_empty", "engine_diagnostics", "checksum_validation"]],
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
  for (const id of ["capture/what-you-have", "capture/carve-from-images", "sessions/reconstruct", "sessions/objects", "metadata/dns-tls", "metadata/fingerprints", "logs/web-proxy-firewall",
    "evidence/captured-secrets", "metadata/encrypted-dns", "analysis/engines-and-coverage"]) {
    assert.match(skills.get(id)!.body, /secret_output: true/, `${id} says the job runs with secret_output: true`);
  }
});

// The fields of the Zeek logs a skill names, against the columns Zeek's log definitions give them. A skill that names a
// column Zeek does not have, as one skill once named `conn_uids` after Zeek had replaced it with `uid` and `id` (version
// 5.1), teaches a field no reader will find. The files.log list is a review's reading of Zeek's own files/main.zeek (the
// 8.0.9 tag); the others are from Zeek's log documentation and are used only for the columns a skill names. The tool does
// not parse these names; this list is the test's own.
const ZEEK_FIELDS: Record<string, string[]> = {
  "conn.log": ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"],
  "files.log": ["ts", "fuid", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "source", "depth", "analyzers", "mime_type", "filename", "duration", "local_orig", "is_orig", "seen_bytes", "total_bytes", "missing_bytes", "overflow_bytes", "timedout", "parent_fuid", "md5", "sha1", "sha256", "extracted", "extracted_cutoff", "extracted_size"],
  "reporter.log": ["ts", "level", "message", "location"],
  "weird.log": ["ts", "uid", "name", "addl", "notice", "peer"],
  "capture_loss.log": ["ts", "ts_delta", "peer", "gaps", "acks", "percent_lost"],
};
// A name that was a column of an older Zeek and is not one now.
const GONE_FROM_ZEEK = ["conn_uids", "tx_hosts", "rx_hosts"];
// What each skill says about which log a column belongs to: skill -> log -> columns it names for it.
const SKILL_ZEEK: Array<[string, string, string[]]> = [
  ["sessions/reconstruct", "files.log", ["fuid", "uid", "id.*"]],
  ["exfil/counters", "conn.log", ["orig_bytes", "resp_bytes", "conn_state"]],
];

test("a Zeek column a skill names is a column Zeek has, and a column Zeek dropped is named by no skill", async () => {
  const skills = await load(SKILLS);
  for (const s of skills.values()) {
    for (const gone of GONE_FROM_ZEEK) assert.equal(new RegExp(`\\b${gone}\\b`).test(s.body), false, `${s.id} names ${gone}, which Zeek no longer has`);
  }
  for (const [skillId, log, names] of SKILL_ZEEK) {
    const body = skills.get(skillId)?.body ?? "";
    for (const name of names) {
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      const real = name.endsWith(".*") ? ZEEK_FIELDS[log].some((f) => f.startsWith(name.slice(0, -1))) : ZEEK_FIELDS[log].includes(name);
      assert.ok(real, `${name} is not a column of ${log}`);
    }
  }
});

// ---- The four leaves of the first skills package: captured secrets, flow records, encrypted DNS, engines and coverage. ----

const NEW_LEAVES = ["evidence/captured-secrets", "flows/interpret", "metadata/encrypted-dns", "analysis/engines-and-coverage"];
const PACKS = join(NET, "..");

/** Every tool a skill of this pack can name: the pack's own and those of the packs it depends on. */
async function toolNames(): Promise<Set<string>> {
  const names = new Set<string>();
  for (const pack of ["network-forensics", "computer-forensics-base"]) {
    for (const e of await readdir(join(PACKS, pack, "tools"), { withFileTypes: true })) if (e.isDirectory()) names.add(e.name);
  }
  return names;
}

test("each new leaf opens Use when ... Not for, names only tools that exist, and is named once by the router", async () => {
  const skills = await load(SKILLS);
  const tools = await toolNames();
  const router = skills.get(ROUTER)!.body;
  for (const id of NEW_LEAVES) {
    const s = skills.get(id);
    assert.ok(s, `${id} exists`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, /^Use when .*\bNot for\b/, `${id} opens with Use when ... Not for`);
    for (const t of (s.meta.tools as string[]) ?? []) assert.ok(tools.has(t), `${id} lists the tool ${t}, which no pack of the closure carries`);
    assert.equal(router.split(`\`${id}\``).length - 1, 1, `${id} is named once by the router`);
    for (const part of ["Shows", "Does not show", "Record"]) assert.match(s.body, new RegExp(`${part}:`), `${id} has ${part}`);
  }
});

test("flows/interpret names the flow tool once it exists, and the leaf, the capture leaf and the README no longer say a flow reader is missing", async () => {
  const skills = await load(SKILLS);
  const s = skills.get("flows/interpret")!;
  const exists = (await toolNames()).has("flow_reader");
  assert.equal(((s.meta.tools as string[]) ?? []).includes("flow_reader"), exists);
  assert.equal(s.body.includes("flow_reader"), exists, "the leaf and the tool agree");
  if (!exists) assert.match(s.body, /no flow reader/i, "it says a flow reader is not provided");
  // It agrees with the capture leaf and the README on that point, whichever side of it the pack is on.
  assert.equal(/no flow reader/i.test(skills.get("capture/what-you-have")!.body), !exists);
  const readme = await readFile(join(NET, "README.md"), "utf8");
  assert.equal(/no flow reader is provided/.test(readme), !exists);
  assert.equal(/No tool here reads flow records/.test(readme), !exists);
  assert.equal(JSON.parse(await readFile(join(NET, "pack.json"), "utf8")).description.includes("No flow-record reader"), !exists);
  if (exists) {
    assert.deepEqual((s.meta.requires_host as string[]) ?? [], ["nfdump"], "the leaf names the program the tool runs");
    assert.match(s.body, /counters_exact/);
    assert.match(s.body, /refuses a capture and sFlow by name/);
  }
});

test("evidence/captured-secrets is a prerequisite of the three leaves that reach secrets, and no chain enters the warning band", async () => {
  const all = new Map([...(await load(BASE_SKILLS)), ...(await load(SKILLS))]);
  for (const id of ["sessions/reconstruct", "capture/carve-from-images", "logs/web-proxy-firewall"]) {
    const needs = (all.get(id)!.meta.needs as string[]) ?? [];
    assert.ok(needs.includes("evidence/captured-secrets"), `${id} needs evidence/captured-secrets`);
    const ids = new Set<string>([id, ...needs, ...needs.flatMap((n) => (all.get(n)!.meta.needs as string[]) ?? [])]);
    const tokens = [...ids].reduce((n, i) => n + TOKENS(all.get(i)!.text), 0);
    assert.ok(tokens <= 1750, `${id} chain is ${Math.round(tokens)} tokens, in the warning band from 1,750`);
    assert.ok(TOKENS(all.get(id)!.text) <= 800, `${id} stays a leaf of at most 800 tokens`);
  }
  assert.ok(TOKENS(all.get("evidence/captured-secrets")!.text) <= 330, "the leaf every secret-reaching chain carries stays small");
});

test("no leaf tells the reader to record a secret's value, a fragment or a hash, and an attempt is not a success", async () => {
  const skills = await load(SKILLS);
  const secrets = skills.get("evidence/captured-secrets")!.body;
  assert.match(secrets, /secret_output: true/);
  assert.match(secrets, /[Aa]n attempt is not a success/);
  assert.match(secrets, /[Nn]ever the value, a fragment or a hash/);
  for (const s of skills.values()) assert.doesNotMatch(s.body, /\b(record|report|note|keep) (the |its |a )?(secret|credential|password|token) value/i, `${s.id} asks for a value`);
});

test("the encrypted-DNS clause of dns-tls is gone and the leaf agrees with it", async () => {
  const skills = await load(SKILLS);
  assert.doesNotMatch(skills.get("metadata/dns-tls")!.body, /QUIC or encrypted-DNS method/);
  assert.ok(skills.get("metadata/dns-tls")!.body.includes("`metadata/encrypted-dns`"), "dns-tls points to the leaf");
  const dns = skills.get("metadata/encrypted-dns")!.body;
  assert.match(dns, /DoH/);
  assert.match(dns, /DoT/);
  assert.match(dns, /DoQ/);
  assert.match(dns, /"No DNS queries" is wrong when only port 53 was examined/);
});

// ---- The router: the one entry a run shows for this pack when its index is over the run's budget. ----

routerChecks({
  pack: "network-forensics",
  router: ROUTER,
  before: [
    "beacons/periodicity", "capture/carve-from-images", "capture/derivatives", "capture/what-you-have", "correlate/host", "exfil/counters",
    "exfil/volume", "logs/web-proxy-firewall", "metadata/dns-tls", "metadata/fingerprints", "sessions/objects", "sessions/reconstruct",
    "analysis/engines-and-coverage", "evidence/captured-secrets", "flows/interpret", "metadata/encrypted-dns",
  ],
  profiles: ["network", "full"],
});
