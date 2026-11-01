/**
 * Tool-library twins: a tool that lives in tool-library/<name> and also in packs/<pack>/tools/<name>.
 *
 * A run started with `--tools-from tool-library` installs the library's copy. A copy that has
 * drifted from the pack's fixed tool hands the run the defect the pack fixed (a credential printed,
 * a stream cut, a count missing), and a pack PR that edits its tool without the copy leaves exactly
 * that. The packs own the tools: the library holds copies, byte for byte.
 *
 * One test holds all of them. Every twin must have the same files (every file of the two directories, at any depth: run.*, manifest.json and any
 * helper or data file), byte for byte, and no file on one side only, unless tests/tool-library-twins-allowed.json declares the difference: the tool, the
 * file, why it is deliberate, and the two digests of the difference as it is today. The digests are
 * the check that the difference is still the declared one: a changed side fails the entry until
 * someone re-reads it, and an entry whose files are equal again is stale and fails too. The list
 * only shrinks; its ceiling below is the number of entries it holds today (two), so adding one
 * means editing this file as well, in plain view of the review.
 *
 * The library README's row for every twin names the manifest's runtime and version.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { LIB, ROOT } from "./tool-library-harness.ts";

const ALLOWED = join(ROOT, "tests", "tool-library-twins-allowed.json");
const ALLOWED_CEILING = 2; // the two provenance records marshal_inspect's library copy keeps and its pack does not
const TWINS_FLOOR = 21; // the twins today; a tool leaving the library or a pack is a deliberate edit of this number

type Allowed = { tool: string; file: string; why: string; library_sha256: string; pack_sha256: string };
type Twin = { tool: string; library: string; pack: string; packName: string };

const isDir = (path: string) => stat(path).then((s) => s.isDirectory(), () => false);
const sha256 = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
const read = (path: string) => readFile(path).catch(() => null);

/** Every tool-library/<name> that also exists as <packs>/<pack>/tools/<name>. */
async function findTwins(libRoot: string, packsRoot: string): Promise<Twin[]> {
  const twins: Twin[] = [];
  const packs = (await readdir(packsRoot).catch(() => [] as string[])).sort();
  for (const tool of (await readdir(libRoot)).sort()) {
    const library = join(libRoot, tool);
    if (!(await isDir(library))) continue;
    for (const packName of packs) {
      const pack = join(packsRoot, packName, "tools", tool);
      if (await isDir(pack)) twins.push({ tool, library, pack, packName });
    }
  }
  return twins;
}

/**
 * Every file of a twin directory, at any depth, as a path relative to it: a helper or a data file next to run.py is part of the tool, so a file that is
 * on one side only is a drift too. Compiled caches (`__pycache__`) are not files of the tool.
 */
async function comparedFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (d: string, prefix: string): Promise<void> => {
    for (const e of await readdir(d, { withFileTypes: true })) {
      if (e.name === "__pycache__" || e.name.endsWith(".pyc")) continue;
      if (e.isDirectory()) await walk(join(d, e.name), `${prefix}${e.name}/`);
      else out.push(`${prefix}${e.name}`);
    }
  };
  await walk(dir, "");
  return out.sort();
}

/** What is wrong with the twins under these roots, as sentences; empty when they are as declared. */
async function twinProblems(libRoot: string, packsRoot: string, allowed: Allowed[]): Promise<string[]> {
  const problems: string[] = [];
  const twins = await findTwins(libRoot, packsRoot);
  const names = new Set(twins.map((t) => t.tool));
  const used = new Set<number>();
  const seen = new Set<string>();
  for (const entry of allowed) {
    const key = `${entry.tool}/${entry.file}`;
    if (seen.has(key)) problems.push(`allow-list: ${key} appears twice`);
    seen.add(key);
    if (typeof entry.why !== "string" || entry.why.trim().length < 20) problems.push(`allow-list: ${key} needs a reason of at least a sentence`);
    if (!names.has(entry.tool)) problems.push(`allow-list: ${entry.tool} is not a twin any more (remove ${key})`);
  }
  for (const twin of twins) {
    const where = `${twin.tool} (packs/${twin.packName})`;
    const files = [...new Set([...(await comparedFiles(twin.library)), ...(await comparedFiles(twin.pack))])].sort();
    if (!files.includes("manifest.json")) problems.push(`${where}: no manifest.json on either side`);
    for (const file of files) {
      const [lib, pack] = await Promise.all([read(join(twin.library, file)), read(join(twin.pack, file))]);
      const index = allowed.findIndex((entry) => entry.tool === twin.tool && entry.file === file);
      const equal = lib !== null && pack !== null && lib.equals(pack);
      if (index < 0) {
        if (lib === null) problems.push(`${where}: ${file} is in the pack and not in the library`);
        else if (pack === null) problems.push(`${where}: ${file} is in the library and not in the pack`);
        else if (!equal) problems.push(`${where}: ${file} has drifted from the pack's: copy the pack's file into tool-library/${twin.tool}/`);
        continue;
      }
      used.add(index);
      const entry = allowed[index];
      if (equal) problems.push(`allow-list: ${twin.tool}/${file} is equal again: remove the entry`);
      else if ((lib ? sha256(lib) : "absent") !== entry.library_sha256 || (pack ? sha256(pack) : "absent") !== entry.pack_sha256) {
        problems.push(`allow-list: ${twin.tool}/${file} differs, but no longer as declared ("${entry.why}"): re-read the difference and update the entry or copy the pack's file`);
      }
    }
  }
  for (const [i, entry] of allowed.entries()) {
    if (!used.has(i) && names.has(entry.tool)) problems.push(`allow-list: ${entry.tool}/${entry.file} names a file the twins do not have`);
  }
  return problems;
}

/** The README's table row for each tool: runtime and version. */
async function readmeRows(): Promise<Map<string, { runtime: string; version: string }>> {
  const rows = new Map<string, { runtime: string; version: string }>();
  for (const line of (await readFile(join(LIB, "README.md"), "utf8")).split("\n")) {
    if (!/^\| `[a-z0-9_]+` \|/.test(line)) continue;
    const cells = line.slice(2, -2).split(" | ");
    rows.set(cells[0].replaceAll("`", ""), { runtime: cells[1], version: cells[3] });
  }
  return rows;
}

test("every tool that is in tool-library and in a pack has run.* and manifest.json byte-equal to the pack's, bar the declared differences", async () => {
  const twins = await findTwins(LIB, join(ROOT, "packs"));
  assert.ok(twins.length >= TWINS_FLOOR, `twins found: ${twins.map((t) => t.tool).join(", ")}`);
  const allowed = (JSON.parse(await readFile(ALLOWED, "utf8")) as { entries: Allowed[] }).entries;
  assert.ok(allowed.length <= ALLOWED_CEILING, "the allow-list only shrinks: a new entry needs the ceiling raised in this file, with the reason in plain view");
  assert.deepEqual(await twinProblems(LIB, join(ROOT, "packs"), allowed), []);
});

test("a tool name is in at most one pack, so a library copy has one owner", async () => {
  const twins = await findTwins(LIB, join(ROOT, "packs"));
  const owners = new Map<string, string[]>();
  for (const twin of twins) owners.set(twin.tool, [...(owners.get(twin.tool) ?? []), twin.packName]);
  for (const [tool, packs] of owners) assert.equal(packs.length, 1, `${tool} is in several packs (${packs.join(", ")}): which one the library copies is undefined`);
});

test("the library README row of every twin names the manifest's runtime and version", async () => {
  const rows = await readmeRows();
  for (const twin of await findTwins(LIB, join(ROOT, "packs"))) {
    const manifest = JSON.parse(await readFile(join(twin.library, "manifest.json"), "utf8")) as { runtime: string; version: number };
    const packManifest = JSON.parse(await readFile(join(twin.pack, "manifest.json"), "utf8")) as { version: number };
    const row = rows.get(twin.tool);
    assert.ok(row, `${twin.tool}: no row in tool-library/README.md`);
    assert.equal(row.version, String(manifest.version), `${twin.tool}: the README row says version ${row.version}, the library manifest ${manifest.version}`);
    assert.equal(row.version, String(packManifest.version), `${twin.tool}: the README row says version ${row.version}, the pack manifest ${packManifest.version}`);
    assert.equal(row.runtime, manifest.runtime, `${twin.tool}: runtime`);
  }
});

test("the comparison finds a drifted twin, a missing file and a stray run.sh, honours a declared difference, and fails a stale or changed one", async () => {
  const dir = await mkdtemp(join(tmpdir(), "twins-"));
  try {
    const lib = join(dir, "tool-library");
    const packs = join(dir, "packs");
    const put = async (root: string, tool: string, files: Record<string, string>) => {
      await mkdir(join(root, tool), { recursive: true });
      for (const [name, text] of Object.entries(files)) await writeFile(join(root, tool, name), text);
    };
    const same = { "run.py": "print(1)\n", "manifest.json": '{"version": 1}\n' };
    await put(lib, "same", same);
    await put(join(packs, "p", "tools"), "same", same);
    await put(lib, "solo", same); // no pack twin: not compared
    await put(lib, "drift", { ...same, "run.py": "print(2)\n" });
    await put(join(packs, "p", "tools"), "drift", same);
    await put(lib, "extra", { ...same, "run.sh": "echo 1\n" });
    await put(join(packs, "p", "tools"), "extra", same);
    await put(lib, "nomanifest", { "run.py": "x\n" });
    await put(join(packs, "p", "tools"), "nomanifest", { "run.py": "x\n" });
    await put(lib, "helper", same);
    await put(join(packs, "p", "tools"), "helper", { ...same, "table.py": "T = 1\n" }); // a helper on the pack's side only, not named run.* or manifest.json
    await put(lib, "bytecode", same);
    await put(join(packs, "p", "tools"), "bytecode", same);
    await mkdir(join(lib, "bytecode", "__pycache__"), { recursive: true });
    await writeFile(join(lib, "bytecode", "__pycache__", "run.cpython-312.pyc"), "x"); // a compiled cache is no file of the tool

    const sorted = async (allowed: Allowed[]) => (await twinProblems(lib, packs, allowed)).sort();
    assert.deepEqual(await sorted([]), [
      "drift (packs/p): run.py has drifted from the pack's: copy the pack's file into tool-library/drift/",
      "extra (packs/p): run.sh is in the library and not in the pack",
      "helper (packs/p): table.py is in the pack and not in the library",
      "nomanifest (packs/p): no manifest.json on either side",
    ]);

    const declared: Allowed = {
      tool: "drift",
      file: "run.py",
      why: "the library copy is deliberately a different build",
      library_sha256: sha256(Buffer.from("print(2)\n")),
      pack_sha256: sha256(Buffer.from("print(1)\n")),
    };
    const rest = (await sorted([declared])).filter((p) => !p.startsWith("extra") && !p.startsWith("nomanifest") && !p.startsWith("helper"));
    assert.deepEqual(rest, [], "a declared difference with both digests as declared passes");

    const changed = { ...declared, pack_sha256: sha256(Buffer.from("print(3)\n")) };
    assert.match((await sorted([changed])).join("\n"), /drift\/run\.py differs, but no longer as declared/);

    await writeFile(join(lib, "drift", "run.py"), "print(1)\n");
    assert.match((await sorted([declared])).join("\n"), /drift\/run\.py is equal again: remove the entry/);

    assert.match((await sorted([{ ...declared, tool: "gone" }])).join("\n"), /gone is not a twin any more/);
    assert.match((await sorted([{ ...declared, why: "x" }])).join("\n"), /needs a reason/);
    assert.match((await sorted([{ ...declared, file: "run.rb" }])).join("\n"), /drift\/run\.rb names a file the twins do not have/);
    assert.match((await sorted([declared, declared])).join("\n"), /drift\/run\.py appears twice/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
