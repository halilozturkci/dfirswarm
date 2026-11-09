/**
 * The process sweep's coverage is a checked fact (docs/packs.md, "What a program leaves behind"; AGENTS.md rule 2).
 *
 * The sweep put one shared PROCESS block (`# BEGIN SHARED PROCESS`, 62 copies) into every tool that starts a program, and wired each tool to say
 * what the block ended. A new tool that starts a program, or an old one that loses its call, would be skipped by the sweep without any test noticing.
 * tests/process-sweep-coverage.json lists every carrier (a python file under packs/ or tool-library/ outside tests/ that starts a program, and every shell
 * file there), with its class, and this file holds the list to the code. It is static: no program runs, the whole file reads about eighty sources.
 *
 * It fails when:
 *   a  a carrier found by the discovery below is not in the registry, or a registry path does not exist, or is no carrier any more, or is listed twice
 *   b  a `held` entry's file does not call `process_apply`, or the local function its `apply` names (a local one must also deal with `unproven`)
 *   c  a `held` or `pipe-only` entry's file carries the shared block but no call that makes a `program_group` (`process_verdict`, `process_apply`, or `apply`)
 *   d  a listed test does not exist or does not mention the carrier's name (the directory name), or a `held`, `pipe-only` or `twin` entry lists no test with a
 *      real abandoned child (setsid, double fork, late writer, holder or leftover in the text), or a `local-mechanism` entry lists no test and gives no `known_gap`
 *   e  a `no-program` entry's file does start a program (Popen, subprocess, spawn) after all
 *   f  a twin differs from its pack file by a byte, or its pack file is not a carrier of the registry
 *   h  a held or pipe-only tool reads a pipe through the block and neither calls process_apply, nor reads PIPE_CUT, nor names a `cut_through` function, and
 *      has no `pipe_cut_gap` that says so (and a `pipe_cut_gap` that is stale)
 *   g  the carriers of the registry that carry the shared block are not as many as the census counts (tests/shared-blocks.json, family PROCESS), or as the
 *      discovery finds
 * and the checking function is exported and tried on damaged copies of the registry at the end (the negative self-test).
 *
 * Why there is no all-carrier dynamic late-writer test here: each tool takes its own arguments, inputs and stand-in programs, so a generic table would repeat the
 * per-pack suites (tests/pack-*-process-apply.test.ts, tests/pack-re-pipe-matrix.test.ts, the python packs/computer-forensics-base/tests/test_process_apply.py and
 * test_pipe_shapes.py), which already run a real abandoned child (plain, stdout holder, setsid, double fork, rewrite, periodic) against each wired tool. The registry
 * names, for each carrier, the suites that do, and check d holds that.
 */
import assert from "node:assert/strict";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, sep } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const REGISTRY = join(ROOT, "tests", "process-sweep-coverage.json");

export const CLASSES = ["held", "pipe-only", "no-program", "local-mechanism", "twin"] as const;
type Class = (typeof CLASSES)[number];

export type Entry = {
  path: string;
  class: Class;
  source?: string;
  apply?: string;
  pack_file?: string;
  mechanism?: string;
  marker?: string;
  tests?: string[];
  reason?: string;
  known_gap?: string;
  pipe_cut_gap?: string;
  cut_through?: string;
  note?: string;
};
export type Registry = { entries: Entry[] };

const BLOCK_BEGIN = "# BEGIN SHARED PROCESS";
const BLOCK = /# BEGIN SHARED PROCESS[\s\S]*?# END SHARED PROCESS[^\n]*\n/;
/** A program is started: the block's spawn(), subprocess, os.spawn*, Popen. */
const STARTS = /\bPopen\(|\bsubprocess\.|\bos\.spawn|(^|[^\w.])spawn\(/m;
/** What a real abandoned child leaves in a test's text. */
const ABANDONED = /setsid|double[- _]fork|\blate\b|holder|leftover|abandon/i;

/** The text of a source without the shared block and without whole-line comments (what the tool itself does). */
export function ownText(text: string): string {
  return text.replace(BLOCK, "").split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
}

async function walk(dir: string, out: string[]): Promise<void> {
  for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    if (e.name === "node_modules" || e.name === ".git" || e.name === "__pycache__" || e.name === "tests") continue;
    const path = join(dir, e.name);
    if (e.isDirectory()) await walk(path, out);
    else if (/\.(py|sh)$/.test(e.name)) out.push(path);
  }
}

export type Reader = (rel: string) => Promise<string | null>;
export function readerFor(root: string): Reader {
  const cache = new Map<string, string | null>();
  return async (rel) => {
    if (!cache.has(rel)) cache.set(rel, await readFile(join(root, rel), "utf8").catch(() => null));
    return cache.get(rel) ?? null;
  };
}

/** Every carrier: python files that carry the block or start a program by their own code, and every shell file, under packs/ and tool-library/ outside tests/. */
export async function discover(root: string, read: Reader): Promise<{ block: string[]; other: string[]; shell: string[] }> {
  const files: string[] = [];
  for (const top of ["packs", "tool-library"]) await walk(join(root, top), files);
  const block: string[] = [];
  const other: string[] = [];
  const shell: string[] = [];
  for (const file of files.sort()) {
    const rel = relative(root, file).split(sep).join("/");
    if (rel.endsWith(".sh")) {
      shell.push(rel);
      continue;
    }
    const text = (await read(rel)) ?? "";
    if (text.includes(BLOCK_BEGIN)) block.push(rel);
    else if (STARTS.test(text)) other.push(rel);
  }
  return { block, other, shell };
}

const nameOf = (path: string): string => basename(dirname(path));

/** The number of carriers the census declares for the PROCESS block. */
export async function censusCount(read: Reader): Promise<number> {
  const declared = JSON.parse((await read("tests/shared-blocks.json")) ?? "{}");
  const variants: { carriers: number }[] = declared.families?.PROCESS?.variants ?? [];
  return variants.reduce((sum, v) => sum + v.carriers, 0);
}

/** What is wrong with a registry, judged against the sources under `root`. Empty when it holds. */
export async function checkRegistry(registry: Registry, root: string, read: Reader = readerFor(root)): Promise<string[]> {
  const problems: string[] = [];
  const found = await discover(root, read);
  const discovered = new Set([...found.block, ...found.other, ...found.shell]);
  const listed = new Map<string, Entry>();
  for (const e of registry.entries) {
    if (listed.has(e.path)) problems.push(`${e.path}: listed twice`);
    listed.set(e.path, e);
  }

  // a
  for (const path of discovered) if (!listed.has(path)) problems.push(`${path}: starts a program (or carries the shared PROCESS block) and is not in the registry`);
  let blockEntries = 0;
  for (const e of registry.entries) {
    const where = e.path;
    if (!(CLASSES as readonly string[]).includes(e.class)) {
      problems.push(`${where}: class ${JSON.stringify(e.class)} is not one of ${CLASSES.join(", ")}`);
      continue;
    }
    if (!e.source) problems.push(`${where}: no source for its class`);
    const text = await read(e.path);
    if (text === null) {
      problems.push(`${where}: the path does not exist`);
      continue;
    }
    if (!discovered.has(e.path) && e.class !== "no-program") problems.push(`${where}: not found by the discovery any more (no program is started in it), so it can only be no-program`);
    const carriesBlock = text.includes(BLOCK_BEGIN);
    if (carriesBlock) blockEntries++;
    const own = ownText(text);

    // b, c
    if (e.class === "held" || e.class === "pipe-only") {
      if (!carriesBlock) problems.push(`${where}: ${e.class} but the file does not carry the shared PROCESS block`);
      const apply = e.apply ?? "";
      if (e.class === "held") {
        if (!apply) problems.push(`${where}: held without \`apply\` (process_apply, or the local function that does its job)`);
        else {
          if (!new RegExp(`\\b${apply}\\(`).test(own)) problems.push(`${where}: held but the tool never calls ${apply}()`);
          if (apply !== "process_apply" && !/unproven/.test(own)) problems.push(`${where}: held through ${apply}() but the tool's own code never deals with \`unproven\``);
        }
      }
      // h: a pipe read through the shared block that is cut at its byte cap makes a complete answer partial only through process_apply (or PIPE_CUT read by the tool, or the function `cut_through` names, which puts process_notes() into the reasons)
      const readsPipe = /\b(communicate_bounded|preflight|run_to_files)\(/.test(own);
      const reportsCut = /\bprocess_apply\(/.test(own) || /PIPE_CUT/.test(own) || (!!e.cut_through && new RegExp(`\\b${e.cut_through}\\(`).test(own));
      if (readsPipe && !reportsCut && !e.pipe_cut_gap) {
        problems.push(`${where}: reads a pipe through the shared block, does not call process_apply and does not read PIPE_CUT: a cut pipe leaves the status alone; say so in pipe_cut_gap or wire it`);
      }
      if (e.pipe_cut_gap && (!readsPipe || reportsCut)) problems.push(`${where}: pipe_cut_gap is stale (the tool reports a cut now, or reads no pipe through the block)`);
      const group = [/\bprocess_verdict\(/, /\bprocess_apply\(/, ...(apply ? [new RegExp(`\\b${apply}\\(`)] : [])];
      if (!group.some((re) => re.test(own))) problems.push(`${where}: no call that makes a program_group (process_verdict, process_apply${apply ? ", " + apply : ""})`);
    }
    // e
    if (e.class === "no-program") {
      if (!e.reason) problems.push(`${where}: no-program without a reason`);
      if (STARTS.test(text)) problems.push(`${where}: listed as no-program but the file starts a program (Popen, subprocess or spawn)`);
    }
    if (e.class === "local-mechanism") {
      if (!e.mechanism) problems.push(`${where}: local-mechanism without \`mechanism\``);
      if (!e.marker) problems.push(`${where}: local-mechanism without \`marker\``);
      else if (!text.includes(e.marker)) problems.push(`${where}: the marker ${JSON.stringify(e.marker)} of its mechanism is not in the file any more`);
    }
    // f
    if (e.class === "twin") {
      const packFile = e.pack_file ?? "";
      const pack = packFile ? await read(packFile) : null;
      if (pack === null) problems.push(`${where}: twin of ${JSON.stringify(packFile)}, which does not exist`);
      else {
        if (pack !== text) problems.push(`${where}: differs from its pack file ${packFile}`);
        if (!listed.has(packFile)) problems.push(`${where}: its pack file ${packFile} is not a carrier of the registry`);
        if (nameOf(packFile) !== nameOf(e.path)) problems.push(`${where}: its pack file ${packFile} has another tool name`);
      }
    }
    // d
    const tests = e.tests ?? [];
    const name = nameOf(e.path);
    let abandoned = false;
    for (const t of tests) {
      const body = await read(t);
      if (body === null) problems.push(`${where}: the test ${t} does not exist`);
      else {
        if (!body.includes(name)) problems.push(`${where}: the test ${t} does not mention ${name}`);
        if (ABANDONED.test(body)) abandoned = true;
      }
    }
    if (e.class === "held" || e.class === "pipe-only" || e.class === "twin") {
      if (!tests.length) problems.push(`${where}: ${e.class} lists no test`);
      else if (!abandoned) problems.push(`${where}: none of its tests has an abandoned child (setsid, double fork, late writer, holder or leftover)`);
    }
    if (e.class === "local-mechanism" && !tests.length && !e.known_gap) problems.push(`${where}: local-mechanism with neither a test nor a known_gap`);
  }

  // g
  const census = await censusCount(read);
  if (blockEntries !== census) problems.push(`the registry has ${blockEntries} carriers of the shared PROCESS block, the census counts ${census}`);
  if (found.block.length !== census) problems.push(`the discovery finds ${found.block.length} carriers of the shared PROCESS block, the census counts ${census}`);
  return problems;
}

export async function loadRegistry(path: string = REGISTRY): Promise<Registry> {
  return JSON.parse(await readFile(path, "utf8")) as Registry;
}

test("the registry covers every carrier and every claim in it holds", async () => {
  const problems = await checkRegistry(await loadRegistry(), ROOT);
  assert.deepEqual(problems, []);
});

test("the registry names the 62 copies of the block and every class it documents", async () => {
  const registry = await loadRegistry();
  const counts: Record<string, number> = {};
  for (const e of registry.entries) counts[e.class] = (counts[e.class] ?? 0) + 1;
  const read = readerFor(ROOT);
  let withBlock = 0;
  for (const e of registry.entries) if ((await read(e.path))?.includes(BLOCK_BEGIN)) withBlock++;
  assert.equal(withBlock, 62);
  for (const c of ["held", "pipe-only", "local-mechanism", "twin"]) assert.ok((counts[c] ?? 0) > 0, );
});

// The negative self-test: the check must fail on a registry that has lost an entry or a claim.
test("self-test: a registry copy on disk with one entry removed fails the check", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sweep-coverage-"));
  try {
    const registry = await loadRegistry();
    const victim = registry.entries.find((e) => e.class === "held" && e.apply === "process_apply");
    assert.ok(victim);
    const copy = join(dir, "registry.json");
    await writeFile(copy, JSON.stringify({ entries: registry.entries.filter((e) => e.path !== victim.path) }));
    const problems = await checkRegistry(await loadRegistry(copy), ROOT);
    assert.ok(problems.some((p) => p.startsWith(victim.path) && /not in the registry/.test(p)), problems.join("\n"));
    assert.ok(problems.some((p) => /census counts/.test(p)), "the block-carrier count no longer matches the census: " + problems.join("\n"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

type Damage = { name: string; apply: (r: Registry) => void; expect: RegExp };
const pick = (r: Registry, f: (e: Entry) => boolean): Entry => {
  const e = r.entries.find(f);
  assert.ok(e, "no entry to damage");
  return e;
};
const DAMAGES: Damage[] = [
  { name: "an entry for a path that does not exist", apply: (r) => r.entries.push({ path: "packs/none/tools/gone/run.py", class: "no-program", source: "x", reason: "x" }), expect: /gone\/run\.py: the path does not exist/ },
  { name: "a path listed twice", apply: (r) => r.entries.push({ ...r.entries[0]! }), expect: /listed twice/ },
  { name: "a class that does not exist", apply: (r) => { pick(r, (e) => e.class === "held").class = "mostly" as Class; }, expect: /is not one of/ },
  { name: "a held tool that does not call what `apply` names", apply: (r) => { pick(r, (e) => e.class === "held").apply = "no_such_call"; }, expect: /never calls no_such_call\(\)/ },
  { name: "a held tool without `apply`", apply: (r) => { delete pick(r, (e) => e.class === "held").apply; }, expect: /held without `apply`/ },
  { name: "a pipe-only tool whose file has no program_group call", apply: (r) => { const e = pick(r, (e) => e.class === "pipe-only"); e.path = pick(r, (x) => x.class === "local-mechanism" && x.path.endsWith(".py") && !x.path.includes("tool-library")).path; e.apply = "none_such"; }, expect: /does not carry the shared PROCESS block|no call that makes a program_group/ },
  { name: "a stale pipe_cut_gap", apply: (r) => { pick(r, (e) => e.class === "held" && !e.pipe_cut_gap && e.apply === "process_apply").pipe_cut_gap = "x"; }, expect: /pipe_cut_gap is stale/ },
  { name: "a no-program entry for a file that starts a program", apply: (r) => { const e = pick(r, (x) => x.class === "held"); e.class = "no-program"; e.reason = "wrongly"; }, expect: /listed as no-program but the file starts a program/ },
  { name: "a listed test that does not exist", apply: (r) => { (pick(r, (e) => e.class === "held").tests ??= []).push("tests/no-such-file.test.ts"); }, expect: /no-such-file\.test\.ts does not exist/ },
  { name: "a listed test that does not mention the carrier", apply: (r) => { (pick(r, (e) => e.class === "held").tests ??= []).push("tests/tool-library-twins-allowed.json"); }, expect: /does not mention/ },
  { name: "a held tool with no test", apply: (r) => { pick(r, (e) => e.class === "held").tests = []; }, expect: /held lists no test/ },
  { name: "a pipe-only tool whose only test has no abandoned child", apply: (r) => { const e = pick(r, (x) => x.class === "pipe-only"); e.tests = ["tests/tool-library-twins.test.ts"]; }, expect: /does not mention|none of its tests has an abandoned child/ },
  { name: "a local mechanism without a test and without a known_gap", apply: (r) => { const e = pick(r, (x) => x.class === "local-mechanism" && !!x.tests?.length); e.tests = []; delete e.known_gap; }, expect: /neither a test nor a known_gap/ },
  { name: "a marker of a local mechanism that is not in the file", apply: (r) => { pick(r, (e) => e.class === "local-mechanism").marker = "def no_such_mechanism_here"; }, expect: /marker .* is not in the file any more/ },
  { name: "a twin pointing at another pack file", apply: (r) => { const e = pick(r, (x) => x.class === "twin"); e.pack_file = pick(r, (x) => x.class === "held").path; }, expect: /differs from its pack file|another tool name/ },
  { name: "a twin whose pack file is not in the registry", apply: (r) => { const e = pick(r, (x) => x.class === "twin"); const pf = e.pack_file; r.entries = r.entries.filter((x) => x.path !== pf); }, expect: /not a carrier of the registry|not in the registry/ },
];

for (const damage of DAMAGES) {
  test(`self-test: ${damage.name} fails the check`, async () => {
    const registry = structuredClone(await loadRegistry());
    damage.apply(registry);
    const problems = await checkRegistry(registry, ROOT);
    assert.ok(problems.some((p) => damage.expect.test(p)), `expected ${damage.expect} in:\n${problems.join("\n") || "(no problem found)"}`);
  });
}

// Every carrier that reads a pipe through the block reports a cut now (no `pipe_cut_gap` is left), so the check is proven on a scratch tree: the same tool text with every
// PIPE_CUT renamed (the block's own use is excluded from what the tool does), listed as pipe-only without a `cut_through`, must fail.
test("self-test: a pipe read through the block by a tool that never reads PIPE_CUT fails the check (scratch copy of audit_events)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sweep-cut-"));
  try {
    const { mkdir } = await import("node:fs/promises");
    const rel = "packs/linux-forensics/tools/audit_events/run.py";
    const real = (await readFile(join(ROOT, rel), "utf8")).replaceAll("PIPE_CUT", "PIPE_CUX");
    await mkdir(join(dir, "tests"), { recursive: true });
    await mkdir(join(dir, "packs", "linux-forensics", "tools", "audit_events"), { recursive: true });
    await mkdir(join(dir, "tool-library"), { recursive: true });
    await writeFile(join(dir, "tests", "shared-blocks.json"), JSON.stringify({ families: { PROCESS: { variants: [{ carriers: 1 }] } } }));
    await writeFile(join(dir, rel), real);
    const entry: Entry = { path: rel, class: "pipe-only", apply: "program_group_problems", source: "x", tests: [] };
    const problems = await checkRegistry({ entries: [entry] }, dir);
    assert.ok(problems.some((p) => /a cut pipe leaves the status alone/.test(p)), problems.join(" | ") || "(no problem found)");
    const gap = await checkRegistry({ entries: [{ ...entry, pipe_cut_gap: "named" }] }, dir);
    assert.ok(!gap.some((p) => /a cut pipe leaves the status alone/.test(p)), "a named gap is accepted: " + gap.join(" | "));
    const through = await checkRegistry({ entries: [{ ...entry, cut_through: "program_group_problems" }] }, dir);
    assert.ok(!through.some((p) => /a cut pipe leaves the status alone/.test(p)), "a function that is called counts: " + through.join(" | "));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("self-test: a carrier the registry does not know is found in a scratch tree", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sweep-tree-"));
  try {
    const { mkdir } = await import("node:fs/promises");
    await mkdir(join(dir, "tests"), { recursive: true });
    await mkdir(join(dir, "packs", "p", "tools", "newtool"), { recursive: true });
    await mkdir(join(dir, "tool-library"), { recursive: true });
    await writeFile(join(dir, "tests", "shared-blocks.json"), JSON.stringify({ families: { PROCESS: { variants: [{ carriers: 0 }] } } }));
    await writeFile(join(dir, "packs", "p", "tools", "newtool", "run.py"), "import subprocess\nsubprocess.Popen(['true'])\n");
    const problems = await checkRegistry({ entries: [] }, dir);
    assert.deepEqual(problems, ["packs/p/tools/newtool/run.py: starts a program (or carries the shared PROCESS block) and is not in the registry"]);
    const named = await checkRegistry({ entries: [{ path: "packs/p/tools/newtool/run.py", class: "no-program", source: "x", reason: "x" }] }, dir);
    assert.deepEqual(named, ["packs/p/tools/newtool/run.py: listed as no-program but the file starts a program (Popen, subprocess or spawn)"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
