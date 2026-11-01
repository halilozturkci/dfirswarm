/**
 * Two repo-wide checks of every bundled tool (packs/*\/tools/*) against the tool contract (docs/packs.md, section 8), read from the manifests and the
 * sources, nothing run:
 *
 *  1. A manifest with a parameter that writes values (`write_*`, `with_resident`, `extract_to`) declares `secret_output`: values go to a file only in a
 *     job the harness runs as secret output. A parameter that writes no value is allow-listed with the reason.
 *  2. The version a tool states of itself equals its manifest's `version`: the label `TOOL = {"name": ..., "version": N}`, and, in the packs whose
 *     answers carry `PARSER = "<tool>/N"` as the tool's own version (linux-forensics and mobile-forensics), that label. In every other pack a `PARSER` label is
 *     the version of a parser inside the tool, which is allowed to lag the tool's, and is not compared.
 *
 * tests/tool-contract-allowed.json names every current failure with the item or package that removes it. It may only shrink: a failure with no entry fails,
 * and so does an entry that no longer fails ("remove it").
 */
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

type Manifest = { name: string; version: number; params?: Record<string, unknown>; secret_output?: unknown };
type Tool = { id: string; pack: string; dir: string; manifest: Manifest };
type Entry = { tool: string; item: string; why: string };

async function bundledTools(root = ROOT): Promise<Tool[]> {
  const out: Tool[] = [];
  const packs = join(root, "packs");
  for (const pack of (await readdir(packs)).sort()) {
    const tools = join(packs, pack, "tools");
    for (const name of await readdir(tools).catch(() => [] as string[])) {
      const manifest = await readFile(join(tools, name, "manifest.json"), "utf8").then((t) => JSON.parse(t) as Manifest, () => null);
      if (manifest) out.push({ id: `${pack}/${name}`, pack, dir: join(tools, name), manifest });
    }
  }
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

async function allowed(test: string): Promise<Entry[]> {
  const all = JSON.parse(await readFile(join(ROOT, "tests", "tool-contract-allowed.json"), "utf8")) as Record<string, Entry[]>;
  const list = all[test];
  assert.ok(Array.isArray(list), `tests/tool-contract-allowed.json has no list "${test}"`);
  for (const e of list) assert.ok(e.tool && e.item && e.why && !/\n/.test(e.why), `${test}: an entry needs tool, item and a one-line why: ${JSON.stringify(e)}`);
  assert.equal(new Set(list.map((e) => e.tool)).size, list.length, `${test}: a tool twice`);
  return list;
}

/** The failures against the allow-list: a failure with no entry, and an entry that no longer fails. */
function settle(name: string, failures: Map<string, string>, list: Entry[]): void {
  const known = new Set(list.map((e) => e.tool));
  const fresh = [...failures].filter(([tool]) => !known.has(tool)).map(([tool, why]) => `  ${tool}: ${why}`);
  assert.equal(fresh.length, 0, `${name}: ${fresh.length} tool(s) fail with no entry in tests/tool-contract-allowed.json (fix the tool, or add an entry naming the item that will):\n${fresh.join("\n")}`);
  const stale = list.filter((e) => !failures.has(e.tool)).map((e) => `  ${e.tool} (${e.item})`);
  assert.equal(stale.length, 0, `${name}: ${stale.length} entr(ies) of tests/tool-contract-allowed.json no longer fail, remove them:\n${stale.join("\n")}`);
}

// ---- 1. secret_output ------------------------------------------------------------------------------------------------------------------------

const VALUE_PARAM = /^write_|^with_resident$|^extract_to$/;

/** The tools with a parameter that writes values and no `secret_output` declaration. */
export function undeclared(tools: Tool[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const t of tools) {
    const params = Object.keys(t.manifest.params ?? {}).filter((p) => VALUE_PARAM.test(p));
    if (params.length && t.manifest.secret_output === undefined) out.set(t.id, `${params.join(", ")} without secret_output`);
  }
  return out;
}

test("a manifest with a parameter that writes values declares secret_output, or is allow-listed with a reason", async () => {
  const tools = await bundledTools();
  assert.ok(tools.length >= 80, `${tools.length} tools found`);
  settle("secret_output", undeclared(tools), await allowed("secret_output"));
});

test("the check finds a planted manifest with write_text and no declaration, and takes a declared one", () => {
  const plant = (params: string[], secret_output?: unknown): Tool => ({ id: "p/t", pack: "p", dir: "", manifest: { name: "t", version: 1, params: Object.fromEntries(params.map((p) => [p, {}])), secret_output } });
  assert.deepEqual([...undeclared([plant(["write_text", "path"])]).keys()], ["p/t"]);
  assert.deepEqual([...undeclared([plant(["with_resident"])]).keys()], ["p/t"]);
  assert.deepEqual([...undeclared([plant(["extract_to"])]).keys()], ["p/t"]);
  assert.equal(undeclared([plant(["write_text"], { when_args: ["write_text"] })]).size, 0);
  assert.equal(undeclared([plant(["write_text"], "required")]).size, 0);
  assert.equal(undeclared([plant(["path", "limit"])]).size, 0);
});

// ---- 2. the version a tool states of itself ----------------------------------------------------------------------------------------------------

const PARSER_IS_THE_TOOL = new Set(["linux-forensics", "mobile-forensics"]);

/** The version a tool's source states of the tool itself, or null when it states none. */
export function labelOf(source: string, pack: string): { kind: string; version: number } | null {
  const tool = /^TOOL\s*=\s*\{[^}\n]*"version":\s*(\d+)/m.exec(source);
  if (tool) return { kind: "TOOL", version: Number(tool[1]) };
  const plain = /^(?:TOOL_)?VERSION\s*=\s*(\d+)\s*(?:#.*)?$/m.exec(source);
  if (plain) return { kind: "VERSION", version: Number(plain[1]) };
  if (PARSER_IS_THE_TOOL.has(pack)) {
    const parser = /^PARSER\s*=\s*"[A-Za-z0-9_]+\/(\d+)"/m.exec(source);
    if (parser) return { kind: "PARSER", version: Number(parser[1]) };
  }
  return null;
}

test("a tool's own version label equals its manifest's version", async () => {
  const tools = await bundledTools();
  const failures = new Map<string, string>();
  let labelled = 0;
  for (const t of tools) {
    const label = labelOf(await readFile(join(t.dir, "run.py"), "utf8"), t.pack);
    if (!label) continue;
    labelled++;
    if (label.version !== t.manifest.version) failures.set(t.id, `${label.kind} says ${label.version}, the manifest ${t.manifest.version}`);
  }
  assert.ok(labelled >= 30,`${labelled} tools state their version`);
  settle("version_label", failures, await allowed("version_label"));
});

test("the label check finds a planted wrong label and reads each convention", () => {
  assert.deepEqual(labelOf('TOOL = {"name": "x", "version": 5}\n', "p"), { kind: "TOOL", version: 5 });
  assert.deepEqual(labelOf("VERSION = 7  # the tool\n", "p"), { kind: "VERSION", version: 7 });
  assert.deepEqual(labelOf('PARSER = "auth_log/15"\n', "linux-forensics"), { kind: "PARSER", version: 15 });
  assert.equal(labelOf('PARSER = "regkv/4"\n', "windows-forensics"), null, "a parser label inside a tool of another pack is not the tool's version");
  assert.equal(labelOf("print(1)\n", "p"), null);
  const planted = labelOf('TOOL = {"name": "x", "version": 5}\n', "p");
  assert.notEqual(planted?.version, 6, "a tool whose label says 5 and whose manifest says 6 fails the check above");
});
