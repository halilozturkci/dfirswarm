/**
 * reverse-engineering: the skills are held to the size and shape rules for a skill leaf (a leaf is at most 800
 * tokens, estimated as bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..."; `needs` is at most
 * two deep; an index entry is at most 40 tokens), and the tool fields they name are fields the tools really write,
 * so a skill cannot keep teaching a field name a tool no longer has. The claims the review found overclaimed
 * (a no-exec mount "prevents" execution, entropy "is packed", a valid signature "means a stolen certificate",
 * an external relationship "fetches on open") are held out of every body.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_PROBE, FUZZY, PE_INFO, RE, SCN_CODE, SCN_EXEC, SCN_READ, SCN_WRITE, TOOLS, asJob, body, buildElf, buildMacho, buildPe, buildZip, filesUnder, put, rels, stub, tool, withCwd } from "./pack-re-harness.ts";

const SKILLS = join(RE, "skills");
const BASE_SKILLS = join(RE, "..", "computer-forensics-base", "skills");
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
        for (const line of m[1]!.split("\n")) {
          const [k, ...rest] = line.split(":");
          const v = rest.join(":").trim();
          meta[k!.trim()] = v.startsWith("[") ? v.slice(1, -1).split(",").map((x) => x.trim()).filter(Boolean) : v;
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
    const first = s.body.trim().split("\n")[0]!;
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
    const tokens = ids.reduce((n, i) => n + TOKENS(all.get(i)?.text ?? ""), 0);
    assert.ok(tokens <= 2000, `${id} chain is ${Math.round(tokens)} tokens`);
  }
});

test("every second-level leaf is pointed to by a leaf that says when to open it", async () => {
  const skills = await load(SKILLS);
  const pointers: Record<string, string> = {
    "pe/signature-and-resources": "pe/structure",
    "elf/packing-and-identity": "elf/structure",
    "strings/decoding-and-similarity": "strings/obfuscated",
    "documents/external-and-active-content": "documents/macros",
    "rules/authoring": "rules/yara",
  };
  for (const [child, parent] of Object.entries(pointers)) {
    const p = skills.get(parent);
    assert.ok(p, parent);
    assert.ok(p.body.includes(`\`${child}\``), `${parent} points to ${child}`);
    assert.match(p.body, /Only if /, `${parent} says when`);
    assert.deepEqual(skills.get(child)!.meta.needs, [], `${child} needs nothing: it is opened from ${parent}`);
  }
});

// Fields and names a skill teaches. Each must be something the tool really writes, observed: the keys and string values of
// its answers (and of the files it writes) over fixtures built from the formats, or a parameter its manifest declares.
// A name that merely appears somewhere in the tool's source proves nothing ("status" and "members" always do).
const TAUGHT: Array<[string, string, string[]]> = [
  ["pe_info", "pe/structure", ["header_timestamp_raw", "header_timestamp_utc", "max_seconds", "writable_and_executable", "overlay_offset", "overlay_is_certificate_table", "declares_clr_runtime_header", "declares_tls", "declares_delay_imports", "declares_resources", "entropy_note", "status", "problems", "coverage"]],
  ["pe_info", "pe/signature-and-resources", ["export_name", "certificate_table_declared", "certificate_table", "within_file"]],
  ["pe_info", "elf/structure", ["section_headers_absent", "stripped", "needed_libraries", "soname", "rpath", "runpath", "interpreter", "entry_point", "segments", "PT_DYNAMIC", "withheld_fields", "file_offset"]],
  ["pe_info", "triage/quarantine", ["commands"]],
  ["doc_probe", "documents/macros", ["extension_content_disagreement", "members", "parts", "modified", "extract_to", "status", "withheld_names_file"]],
  ["doc_probe", "documents/external-and-active-content", ["external_targets", "finding_id", "write_values", "doc-probe-values.jsonl", "markers", "encrypt_marker_present", "objdata_markers", "classes"]],
  ["fuzzy_hash", "strings/decoding-and-similarity", ["insufficient_input", "tlsh_status"]],
];

function collect(v: unknown, into: Set<string>): void {
  if (Array.isArray(v)) for (const x of v) collect(x, into);
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) { into.add(k); collect(x, into); }
  else if (typeof v === "string") into.add(v);
}

/** What each tool writes, observed over fixtures: the keys and string values of its answers and of the files it wrote. */
async function observed(): Promise<Record<string, Set<string>>> {
  const seen: Record<string, Set<string>> = { pe_info: new Set(), doc_probe: new Set(), fuzzy_hash: new Set() };
  await withCwd(async (cwd, bin) => {
    const run = async (name: string, script: string, rel: string, data: Buffer | string, args: Record<string, unknown> = {}, job = false): Promise<void> => {
      await put(cwd, rel, data);
      const out = job ? await asJob(script, cwd, { path: rel, ...args }, bin) : await tool(script, cwd, { path: rel, ...args }, {}, bin);
      collect(body(out), seen[name]!);
    };
    // PE: a section both writable and executable, an export directory, a certificate table that is the whole overlay, and the
    // CLR, TLS, delay-import and resource directories; then the same file under a work budget too small to measure entropy.
    const plain = buildPe({});
    const cert = Buffer.alloc(16);
    cert.writeUInt32LE(16, 0);
    cert.writeUInt16LE(0x200, 4);
    cert.writeUInt16LE(2, 6);
    const signed = buildPe({
      sections: [{ name: ".text", data: Buffer.alloc(4096, 7), flags: SCN_CODE | SCN_EXEC | SCN_READ | SCN_WRITE }],
      exportName: "x.dll",
      trailing: cert,
      certificate: { offset: plain.file.length, size: 16 },
      extraDirectories: { 14: { rva: 0x1000, size: 72 }, 9: { rva: 0x1000, size: 24 }, 13: { rva: 0x1000, size: 32 }, 2: { rva: 0x1000, size: 16 } },
    });
    await run("pe_info", PE_INFO, "work/a.exe", signed.file, { max_seconds: 30 });
    await run("pe_info", PE_INFO, "work/b.exe", signed.file, { max_entropy_bytes: 1 });
    // ELF: dependencies read through PT_DYNAMIC with a run path that carries a credential (withheld, with its offset).
    const runpath = "/opt/lib:https://svc:hunter2pw@pkg.example/lib?sig=Zk3pQ9x7LmN2vB8dTrYw5uHc1aEf";
    await run("pe_info", PE_INFO, "work/c.elf", buildElf({ cls: 64, needed: ["libc.so.6"], soname: "libx.so", rpath: "$ORIGIN", runpath, interp: "/lib64/ld-linux-x86-64.so.2", entry: 0x401000 }));
    await run("pe_info", PE_INFO, "work/d.elf", buildElf({ cls: 64, needed: ["libc.so.6"], sections: [{ name: ".text", type: 1 }] }));
    await run("pe_info", PE_INFO, "work/e.dylib", buildMacho({ commands: [{ segment: "__TEXT", fileoff: 0, filesize: 64 }, { dylib: "/usr/lib/libSystem.B.dylib", cmd: 0xc }] }));
    // Documents: an OOXML package with an external relationship, a code-related part and a part named like a token, extracted
    // in a job with the values file requested; a PDF with action markers and an RTF with an embedded object.
    const types = Buffer.from('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>');
    const rel = rels([{ id: "rId1", type: "attachedTemplate", target: "https://u:pw@files.example.org/t.dotm?sig=Zk3pQ9x7LmN2vB8dTrYw5uHc1aEf", mode: "External" }]);
    const docx = buildZip([
      { name: "[Content_Types].xml", data: types },
      { name: "word/_rels/document.xml.rels", data: Buffer.from(rel) },
      { name: "word/vbaProject.bin", data: Buffer.from("vba project bytes") },
      { name: "word/embeddings/Qx7Lm2VbN9pTkR4sYw6Zc1HgDf8J.bin", data: Buffer.from("object") },
    ]);
    await run("doc_probe", DOC_PROBE, "work/invoice.docx", docx, { write_values: true, extract_to: join(cwd, "out", "parts") }, true);
    const values = (await filesUnder(join(cwd, "out"))).find((f) => f.endsWith("doc-probe-values.jsonl"));
    assert.ok(values, "the job wrote the values file");
    seen.doc_probe!.add("doc-probe-values.jsonl");
    for (const line of (await readFile(join(cwd, "out", values!), "utf8")).trim().split("\n")) collect(JSON.parse(line), seen.doc_probe!);
    await run("doc_probe", DOC_PROBE, "work/a.pdf", "%PDF-1.4\n1 0 obj << /OpenAction 2 0 R /AA << >> /JS (x) /JavaScript /EmbeddedFile /Encrypt 3 0 R >> endobj\n");
    await run("doc_probe", DOC_PROBE, "work/a.rtf", "{\\rtf1{\\object{\\*\\objclass Word.Document.8}{\\*\\objdata 0105000002000000}}}");
    // fuzzy_hash against stand-ins: tlsh says the file is too short (TNULL).
    await stub(bin, "ssdeep", `if [ "$1" = "-V" ]; then echo "2.14.1"; exit 0; fi\necho 'ssdeep,1.1--blocksize:hash:hash,filename'\necho "3::,\\"$(basename "$3")\\""`);
    await stub(bin, "tlsh", `if [ "$1" = "-version" ]; then echo "tlsh 4.12.0"; exit 0; fi\nprintf 'TNULL\\t%s\\n' "$2"`);
    await run("fuzzy_hash", FUZZY, "work/tiny.bin", "abc");
  });
  return seen;
}

test("the tool fields a skill names are fields its tool writes, observed over fixtures", async () => {
  const skills = await load(SKILLS);
  const seen = await observed();
  for (const [tool, skillId, names] of TAUGHT) {
    const params = Object.keys((JSON.parse(await readFile(join(TOOLS, tool, "manifest.json"), "utf8")) as { params: Record<string, unknown> }).params);
    const body = skills.get(skillId)?.body ?? "";
    for (const name of names) {
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      assert.ok(seen[tool]!.has(name) || params.includes(name), `${tool} writes (or takes) ${name}, which ${skillId} teaches`);
    }
  }
});

test("every backticked field or parameter a skill attributes to a tool is one it writes or takes", async () => {
  // The reverse direction: the snake_case names in a body that belong to pe_info, doc_probe, entropy_map or fuzzy_hash are
  // checked against what those tools write, so a skill cannot keep a name the tools dropped (compile_timestamp_raw, packed_shape).
  const skills = await load(SKILLS);
  const seen = await observed();
  const known = new Set<string>();
  for (const t of ["pe_info", "doc_probe", "fuzzy_hash"]) for (const n of seen[t]!) known.add(n);
  for (const t of ["pe_info", "doc_probe", "entropy_map", "fuzzy_hash"]) {
    for (const n of Object.keys((JSON.parse(await readFile(join(TOOLS, t, "manifest.json"), "utf8")) as { params: Record<string, unknown> }).params)) known.add(n);
  }
  const elsewhere = new Set(["secret_output", ...(await readdir(join(RE, "..", "computer-forensics-base", "tools"))), ...(await readdir(TOOLS))]);   // the harness's own job flag and tool names
  for (const s of skills.values()) {
    const named = [...s.body.matchAll(/`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)(?:\[\])?`/g)].map((m) => m[1]!);
    for (const name of named) {
      if (elsewhere.has(name) || known.has(name)) continue;
      assert.fail(`${s.id} names \`${name}\`, which no tool writes or takes`);
    }
  }
  for (const stale of ["compile_timestamp", "packed_shape", "carries_code", "entropy-windows.tsv"]) {
    for (const s of skills.values()) assert.ok(!s.body.includes(stale), `${s.id} still teaches ${stale}`);
  }
});

test("the per-engine status fields fuzzy_hash writes are the ones the skill names", async () => {
  const body = (await load(SKILLS)).get("strings/decoding-and-similarity")!.body;
  const script = await readFile(join(TOOLS, "fuzzy_hash", "run.py"), "utf8");
  assert.ok(body.includes("tlsh_status"));
  assert.ok(script.includes('engine + "_status"') && script.includes('("ssdeep", ') && script.includes('"tlsh", '), "the script writes <engine>_status for ssdeep and tlsh");
});

// The overclaims the review found, as patterns that a paraphrase does not escape. Each is proved to match a paraphrase
// below, so a regex that has gone soft fails the suite rather than letting the claim back in.
const PARAPHRASED_OVERCLAIMS: RegExp[] = [
  /\bentropy\b(?:[^.]|\d\.\d){0,40}?(?<!not )(?<!n't )\b(?:indicates|means|proves|confirms)\b[^.]{0,20}\b(?:packing|packed|encrypted|encryption|malware)/i,
  /(?:kernel|mount)[^.]{0,60}\b(?:prevents|guarantees|ensures|enforces)\b[^.]{0,40}\b(?:execution|running|a run)\b/i,
  /\b(?:valid|signed|signature)\b[^.]{0,60}?(?<!not )(?<!n't )\b(?:means|indicates|implies|suggests)\b[^.]{0,20}\b(?:stolen|compromised|theft)/i,
  /\b(?:imports?|APIs?)\b[^.]{0,60}?(?<!not )(?<!n't )\b(?:shows?|proves?|confirms?|indicates?)\b[^.]{0,30}\b(?:a connection|injection|encryption|network activity|communication)/i,
  /\b(?:external|remote)\b[^.]{0,60}\b(?:is fetched|will be fetched|is downloaded|is loaded)\b[^.]{0,30}\bwhen (?:the document|it) (?:is )?opens?/i,
  /\b(?:nothing references it|no references?)\b[^.]{0,20}?(?<!not )(?<!n't )\b(?:means|shows|proves)\b[^.]{0,20}\bunused/i,
  /\bmutex(?:es)?\b[^.]{0,40}\b(?:is|are) (?:unique|family-specific|stable)\b/i,
  /\b(?:has|have|was|were) (?:been )?renamed\b|\bis a renamed\b|\bproves? (?:a )?renam/i,
  /\bbuild[ -]?id\b[^.]{0,60}?(?<!not )(?<!n't )(?<!never )\b(?:proves|establishes|guarantees)\b[^.]{0,20}\b(?:identity|equivalence)/i,
  /\bcapa\b[^.]{0,30}?(?<!not )(?<!n't )\b(?:proves|confirms|shows)\b[^.]{0,20}\b(?:the sample|it) (?:does|performs|connects)/i,
];

const PARAPHRASES = [
  "Entropy above 7.5 indicates packing.",
  "A no-exec mount at the kernel prevents execution of the sample.",
  "A valid signature on this file means a stolen certificate.",
  "Its imports show a connection to a server.",
  "The external target is fetched when the document opens.",
  "No references means the string is unused.",
  "The mutex name is unique to the family.",
  "The file has been renamed from a document.",
  "The build ID proves identity across rebuilds.",
  "capa confirms the sample performs injection.",
];

test("the overclaim patterns catch a paraphrase of each claim the review removed", () => {
  for (const text of PARAPHRASES) assert.ok(PARAPHRASED_OVERCLAIMS.some((rx) => rx.test(text)), `no pattern catches: ${text}`);
});


test("no skill states a version fact, the old overclaims are gone, and secret handling is stated where a tool can reach a secret", async () => {
  const skills = await load(SKILLS);
  const overclaims = [
    /held no-exec by the kernel|a sample cannot run even if|the harness enforces that rather than trusting/i,
    /A section at 7\.9|is packed, and a disassembly|means? "packed"/i,
    /means a stolen certificate|certificate theft/i,
    /has been renamed|\.docx` cannot carry a macro/i,
    /run on open|run on their own|runs when the document opens|fetches when the document opens|fetch(es)? something when opened/i,
    /what it was built to do|what this is for|the sample hides|hide exactly this/i,
    /not from the strings|will keep matching|still be right next month|survives a rename and most repacking/i,
    /identifies a binary across rebuilds|what a dropped tool usually looks like|runs on any distribution/i,
    /tells whoever wrote it that they are being investigated|breaks the custody chain/i,
    ...PARAPHRASED_OVERCLAIMS,
  ];
  for (const s of skills.values()) {
    assert.doesNotMatch(s.body, /\bas of (20|19)\d\d\b|since (version )?\d|\b(UPX|capa|radare2|r2|FLOSS) \d+\.\d/i, `${s.id} states no version fact`);
    for (const rx of overclaims) assert.doesNotMatch(s.body, rx, `${s.id} still carries an overclaim (${rx})`);
  }
  for (const id of ["triage/quarantine", "strings/obfuscated", "strings/decoding-and-similarity", "documents/macros", "documents/external-and-active-content", "rules/yara"]) {
    assert.match(skills.get(id)!.body, /secret_output: true/, `${id} says the job runs with secret_output: true`);
    assert.match(skills.get(id)!.body, /Sensitive output:/, `${id} has a Sensitive output line`);
  }
});

test("the quarantine leaf says no-exec does not stop an interpreter, as the worker prompt does", async () => {
  const skills = await load(SKILLS);
  assert.match(skills.get("triage/quarantine")!.body, /does not stop an interpreter/);
  const prompt = await readFile(join(RE, "..", "..", "prompts", "worker-system.md"), "utf8");
  assert.match(prompt, /No-exec does not stop\s+an interpreter reading a file/);
});

test("front matter lists what the body names: every tool and program is one the pack or its dependency carries", async () => {
  const skills = await load(SKILLS);
  const host = JSON.parse(await readFile(join(RE, "requires", "host.json"), "utf8")) as { binaries: { name: string }[] };
  const programs = new Set(host.binaries.map((b) => b.name));
  const own = new Set(await readdir(TOOLS));
  const base = new Set(await readdir(join(RE, "..", "computer-forensics-base", "tools")));
  for (const s of skills.values()) {
    for (const t of (s.meta.tools as string[]) ?? []) assert.ok(own.has(t) || base.has(t), `${s.id}: tool ${t} resolves`);
    for (const p of (s.meta.requires_host as string[]) ?? []) assert.ok(programs.has(p), `${s.id}: program ${p} is declared by the pack`);
  }
});

test("the review's wording fixes are in the leaves and the goal, and the goal's checks are the ones they were", async () => {
  const skills = await load(SKILLS);
  const text = (id: string): string => skills.get(id)!.body;
  // A library and a position-independent executable can both carry an interpreter and an entry point.
  assert.match(text("elf/structure"), /leads, not a test/);
  assert.match(text("elf/structure"), /FLAGS_1/);
  assert.match(text("elf/structure"), /readelf --dyn-syms -W/);
  assert.match(text("elf/structure"), /`file_offset`/);
  // upx rewrites its input in place: the leaf names an output.
  assert.match(text("elf/packing-and-identity"), /upx -d -o "\$OUT\//);
  assert.match(text("elf/packing-and-identity"), /never without `-o`/);
  // axt lists nothing before an analysis pass.
  assert.match(text("strings/obfuscated"), /axt <addr>[^.]*only after an analysis pass/);
  // Program output that can carry a value goes to a file under $OUT and the columns are read.
  for (const [id, rx] of [
    ["pe/signature-and-resources", /izz[^.]*> "\$OUT\/izz\.txt"/],
    ["capabilities/mapping", /capa -j SAMPLE > "\$OUT\/capa\.json"/],
    ["rules/yara", /yara -s RULES SAMPLE > "\$OUT\/yara-s\.txt"/],
    ["strings/obfuscated", /strings -a -t x SAMPLE > "\$OUT\/strings\.txt"/],
  ] as Array<[string, RegExp]>) assert.match(text(id), rx, `${id} writes value-bearing output to a file under $OUT`);
  assert.match(text("pe/signature-and-resources"), /secret_output: true/);
  assert.match(text("capabilities/mapping"), /Sensitive output:/);
  // Header time: the epoch is stated.
  assert.match(text("pe/structure"), /seconds counted from 1970-01-01 UTC/);
  // Documents.
  const macros = text("documents/macros");
  assert.match(macros, /path under `\$OUT`/);
  assert.match(macros, /`parts\[\]\.modified`[^.]*no zone, two-second resolution/);
  assert.match(macros, /does not provide: record the comparison as not made/);
  assert.match(macros, /`vbaProject\.bin`[^.]*OLE compound file/);
  assert.match(macros, /`AutoOpen`, `Document_Open` and `Workbook_Open`/);
  assert.match(text("documents/external-and-active-content"), /`\/JavaScript` and `\/JS`[^.]*`\/EmbeddedFile`/);
  // Rules.
  assert.match(text("rules/authoring"), /A hit on the specimen a rule was written from is not corroboration/);
  assert.match(text("rules/authoring"), /file names, header timestamps, absolute addresses, library strings/);
  // The goal: the definition of done asks for inspected evidence, not an address or an import; the question about strings
  // bounds the negative; the checks are the eight they were, the event minimum included (flagged for the owner, not changed).
  const goal = await readFile(join(RE, "goals", "sample-triage.md"), "utf8");
  const done = goal.slice(goal.indexOf("## Definition of done"), goal.indexOf("## Checks")).replace(/\s+/g, " ");
  assert.match(done, /Every material capability inference cites inspected code or structured feature evidence with its locator and limitations; an import alone supports only a dependency observation\./);
  assert.doesNotMatch(done, /carries an address or an import/);
  assert.match(goal.replace(/\s+/g, " "), /which analysis recovered no reference to it \(a bounded negative: function discovery, indirect addressing and decoding limit it\)/);
  assert.doesNotMatch(goal, /a plain statement that nothing references it/);
  const checks = goal.slice(goal.indexOf("## Checks")).split("\n").filter((l) => l.startsWith("- `"));
  assert.equal(checks.length, 8);
  assert.ok(checks.some((c) => c.includes('-ge 3')), "the event minimum is still there");
  // The counts outside the pack follow the pack.
  for (const file of ["docs/packs.md", "README.md"]) {
    const doc = await readFile(join(RE, "..", "..", file), "utf8");
    assert.match(doc, /^\| `reverse-engineering` \| 12 \| 4 \| 1 \|/m, `${file} counts twelve skills`);
  }
});
