/**
 * virtualization-backup-forensics: the skills are held to the size and shape rules for a skill leaf (a leaf is at most
 * 800 tokens, estimated as bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..."; `needs` is at most two
 * deep; an index entry is at most 40 tokens), every leaf says what it shows, what it does not show and what to record, the
 * names and fields a skill teaches are names and fields the tools really have, and the voice rules of the pack standard
 * (section 8) hold: no version fact the author cannot source, no verdict from a marker, no credential used.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, VIRT } from "./pack-virtualization-harness.ts";

const SKILLS = join(VIRT, "skills");
const BASE_SKILLS = join(VIRT, "..", "computer-forensics-base", "skills");
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

const IDS = ["router/start", "evidence/boundaries", "control-plane/chronology", "hypervisor/activity", "hypervisor/inventory", "snapshots/chain-integrity", "snapshots/markers", "snapshots/header-markers", "backup/catalogues-and-retention", "backup/deletion-vs-loss", "recovery/survivability"];

test("every skill is a leaf within the budget, opens with Use when ... Not for ..., says what it shows, does not show and records, and has a short index entry", async () => {
  const skills = await load(SKILLS);
  assert.deepEqual([...skills.keys()].sort(), [...IDS].sort());
  for (const s of skills.values()) {
    const limit = s.meta.router === "true" ? 400 : 800;
    assert.ok(TOKENS(s.text) <= limit, `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, /^Use when /, `${s.id} opens with Use when`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    if (s.id !== "router/start") for (const part of ["Shows", "Does not show", "Record"]) assert.match(s.body, new RegExp(`\\*\\*${part}\\.\\*\\*`), `${s.id} has ${part}`);
  }
  const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  for (const id of skills.keys()) assert.ok(index.includes(`\`${id}\``), `${id} is in the index`);
  assert.match(index, /^Router: `router\/start`$/m);
});

test("the pack has one router, and it names every other skill", async () => {
  const skills = await load(SKILLS);
  const routers = [...skills.values()].filter((s) => s.meta.router === "true");
  assert.equal(routers.length, 1);
  for (const id of IDS.filter((i) => i !== "router/start")) assert.ok(routers[0].body.includes(`\`${id}\``), `the router names ${id}`);
});

test("needs is at most two deep and its chain is at most 1,900 tokens, counting the base skills it reaches", async () => {
  const all = new Map([...(await load(BASE_SKILLS)), ...(await load(SKILLS))]);
  const chain = (id: string, seen: string[] = []): { depth: number; ids: string[] } => {
    const s = all.get(id);
    assert.ok(s, `${id} resolves`);
    let best = { depth: 0, ids: [id] };
    for (const n of (s.meta.needs as string[]) ?? []) {
      assert.ok(!seen.includes(n), `no cycle at ${n}`);
      const sub = chain(n, [...seen, id]);
      if (sub.depth + 1 > best.depth) best = { depth: sub.depth + 1, ids: [id, ...sub.ids] };
    }
    return best;
  };
  for (const id of (await load(SKILLS)).keys()) {
    const { depth, ids } = chain(id);
    assert.ok(depth <= 2, `${id} needs ${depth} deep: ${ids.join(" > ")}`);
    const total = new Set(ids);
    assert.ok([...total].reduce((n, i) => n + TOKENS(all.get(i)?.text ?? ""), 0) <= 1900, `${id} chain`);
  }
});

test("the second-level leaves are pointed to by the leaf that says when to open them", async () => {
  const skills = await load(SKILLS);
  assert.ok(skills.get("snapshots/chain-integrity")!.body.includes("`snapshots/markers`"));
  assert.deepEqual(skills.get("snapshots/markers")!.meta.needs, ["snapshots/chain-integrity"]);
  assert.ok(skills.get("snapshots/markers")!.body.includes("`snapshots/header-markers`"));
  assert.deepEqual(skills.get("snapshots/header-markers")!.meta.needs, ["snapshots/chain-integrity"]);
});

const SOURCE = async (tool: string): Promise<string> => readFile(join(TOOLS, tool, "run.py"), "utf8");

// What a skill teaches by name, each of which a tool must write: tool -> [skill, names].
const TAUGHT: Array<[string, string, string[]]> = [
  ["snapshot_chain_check", "snapshots/chain-integrity", ["resolved_to", "id_check", "identity_mismatch", "complete", "broken", "cycle", "too_deep", "missing", "short", "qemu_img", "match", "match_via_parent_linkage2", "mismatch", "not_available",
    "parent_unreadable", "identity_not_compared", "extent_missing", "data_file_missing", "issues", "base_note", "parent_linkage", "DataWriteGuid", "skipped"]],
  ["snapshot_chain_check", "snapshots/header-markers", ["vhd_saved_state_flag", "vhd_footer_copy_differs", "newline_detection_mismatch", "vhdx_headers_checksum_fail", "vhd_footer_checksum_fail", "vhd_dynamic_header_checksum_fail", "vhdx_region_table_checksum_fail", "vhdx_region_table_copy_damaged", "descriptor_problem", "duplicate_cid",
    "parent_missing", "parent_ambiguous", "parent_names_disagree", "parent_cid_mismatch", "parent_unique_id_mismatch", "parent_linkage_mismatch", "extent_missing", "extent_short", "external_data_file_missing",
    "chain_cycle", "qemu_img_disagrees", "resolution", "id_check"]],
  ["snapshot_chain_check", "snapshots/markers", ["unclean_shutdown_flag", "qcow2_dirty_bit", "qcow2_corrupt_bit", "vhdx_log_guid_set", "running_disk_is_a_delta_without_snapshots", "delta_not_in_snapshot_database", "snapshot_disk_missing", "lock_artefact", "extent_without_descriptor"]],
  ["virtualization_inventory", "hypervisor/inventory", ["in_set", "snaptime", "creationTime", "special_sections"]],
  ["backup_audit_normalise", "backup/catalogues-and-retention", ["category_map", "declared_fields_absent"]],
  ["backup_audit_normalise", "backup/deletion-vs-loss", ["snapshot_delete", "retention_prune", "retention_gc", "retention_remove", "vm_delete", "disk_delete"]],
  ["backup_audit_normalise", "control-plane/chronology", ["time_zone_offset_minutes", "time_utc"]],
  ["backup_audit_normalise", "hypervisor/activity", ["declared_csv", "declared_jsonl", "declared_xml"]],
];

test("the names and fields a skill teaches are names and fields its tool has", async () => {
  const skills = await load(SKILLS);
  for (const [tool, skillId, names] of TAUGHT) {
    const script = await SOURCE(tool);
    const manifest = await readFile(join(TOOLS, tool, "manifest.json"), "utf8");
    const body = skills.get(skillId)?.body ?? "";
    for (const name of names) {
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      assert.ok(script.includes(name) || manifest.includes(name), `${tool} has ${name}, which ${skillId} teaches`);
    }
  }
  // Every marker kind the tool can raise is named, by its own name, in one of the two marker tables: none is left to a wildcard.
  const source = await SOURCE("snapshot_chain_check");
  const kinds = new Set([...source.matchAll(/marker\(\s*"([a-z0-9_]+)"|"kind": "([a-z0-9_]+)"/g)].map((m) => m[1] ?? m[2]));
  for (const m of source.matchAll(/marker\(\{([^}]*)\}\[/g)) for (const k of m[1].matchAll(/"([a-z0-9_]+_mismatch)"/g)) kinds.add(k[1]);
  assert.ok(kinds.size >= 25, `the tool's marker kinds were found (${kinds.size})`);
  const tables = skills.get("snapshots/markers")!.body + skills.get("snapshots/header-markers")!.body;
  for (const kind of kinds) assert.ok(new RegExp(`\`${kind}\``).test(tables), `${kind} is a marker no table names`);
});

test("the skills state no product release as a fact, give no verdict from a marker, use no credential, and say the job runs with secret_output where a tool can reach a secret", async () => {
  const skills = await load(SKILLS);
  for (const s of skills.values()) {
    assert.doesNotMatch(s.body, /\b(?:ESXi|vSphere|vCenter|Hyper-V|Proxmox(?: VE| Backup Server)?|Veeam|Commvault|Rubrik|QEMU|libvirt)\s+v?\d+(?:\.\d+)?\b/, `${s.id} states a release`);
    assert.doesNotMatch(s.body, /as of (?:20|19)\d\d|since (?:version )?\d/i, `${s.id} states a dated version fact`);
    assert.doesNotMatch(s.body, /cannot be recovered|is proof of|proves that|confirms that|was tampered|has been tampered|definitely|certainly/i, `${s.id} overclaims`);
    assert.doesNotMatch(s.body, /\b(?:hashcat|john the ripper|mimikatz|impacket)\b/i, `${s.id} names a credential tool`);
    // a destructive product command is named only as something not to do
    for (const m of s.body.matchAll(/qemu-img (commit|rebase|convert|resize|amend)/g)) {
      const line = s.body.split("\n").find((l) => l.includes(m[0]))!;
      assert.match(line, /Never|Convert only a copy|changes the chain|not to|Do not/i, `${s.id} names ${m[0]} without a prohibition`);
    }
    if (/`(?:snapshot_chain_check|virtualization_inventory|backup_audit_normalise)`/.test(s.body) && !["router/start"].includes(s.id)) {
      assert.match(s.body, /secret_output: true/, `${s.id} says the job runs with secret_output: true`);
    }
  }
  const boundaries = skills.get("evidence/boundaries")!.body;
  assert.match(boundaries, /Credentials in the evidence are indicators, not logins/);
  assert.match(boundaries, /never run the product/i);
  assert.match(skills.get("backup/catalogues-and-retention")!.body, /Never infer a vendor.s layout from a sample or start the product against the evidence/);
});

test("every skill id a skill names exists: in this pack, in the base pack, or in another pack of the repository (a rename elsewhere breaks this)", async () => {
  const mine = await load(SKILLS);
  const known = new Set<string>();
  for (const pack of await readdir(join(VIRT, ".."))) {
    const dir = join(VIRT, "..", pack, "skills");
    for (const id of (await load(dir).catch(() => new Map<string, Skill>())).keys()) known.add(id);
  }
  const named = new Set<string>();
  for (const s of mine.values()) for (const m of s.body.matchAll(/`([a-z][a-z-]*\/[a-z][a-z-]*)`/g)) named.add(m[1]);
  assert.ok(named.size >= 12, "the skills point to each other and to other packs");
  for (const id of named) assert.ok(known.has(id), `${id} is named and no pack carries it`);
  // the places where this pack's reading ends and another pack's begins are named
  const bodies = (id: string): string => mine.get(id)!.body;
  assert.match(bodies("hypervisor/activity"), /`encryptor\/backup-infrastructure`/);
  assert.match(bodies("backup/catalogues-and-retention"), /`encryptor\/destroyed-backups`/);
  assert.match(bodies("recovery/survivability"), /`recovery\/what-is-possible`/);
  assert.deepEqual(mine.get("backup/deletion-vs-loss")!.meta.mentions, ["vss_stores"]);
});

test("the skills name every tool of the pack, and the pack's method-only leaves are the ones that name none of its tools", async () => {
  const skills = await load(SKILLS);
  const all = [...skills.values()].map((s) => s.body).join("\n");
  for (const t of ["virtualization_inventory", "snapshot_chain_check", "backup_audit_normalise"]) assert.ok(all.includes(`\`${t}\``), `${t} is named`);
  const pack = JSON.parse(await readFile(join(VIRT, "pack.json"), "utf8"));
  const methodOnly: string[] = pack.method_only.map((m: { path: string }) => m.path).sort();
  const namesNone = [...skills.values()].filter((s) => !/`(?:snapshot_chain_check|virtualization_inventory|backup_audit_normalise)`/.test(s.body)).map((s) => `skills/${s.id}.md`).sort();
  assert.deepEqual(methodOnly, namesNone);
});
