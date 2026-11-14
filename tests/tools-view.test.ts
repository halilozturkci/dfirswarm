/**
 * The `tools` answer: one line a tool by default, one tool whole by name.
 */
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { aboutLine, toolsListing, type ToolRow } from "../extensions/tools-view.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Every tool of every pack in the checkout, as a run with all packs would hold them. */
function everyPackTool(): ToolRow[] {
  const out: ToolRow[] = [];
  for (const pack of readdirSync(join(ROOT, "packs"))) {
    let tools: string[] = [];
    try { tools = readdirSync(join(ROOT, "packs", pack, "tools")); } catch { continue; }
    for (const t of tools) {
      try {
        const m = JSON.parse(readFileSync(join(ROOT, "packs", pack, "tools", t, "manifest.json"), "utf8")) as { name?: string; description?: string; example?: string };
        out.push({ name: m.name ?? t, description: m.description, example: m.example, pack, params: { path: "string" } });
      } catch { /* a directory that is not a tool */ }
    }
  }
  return out;
}

test("the list is one line a tool, grouped by pack, and stays small with every pack's tools in it", () => {
  const all = [...everyPackTool(), { name: "azr_try", description: "Tries a key on a file. And more.", by: "a1", pack: null }];
  assert.ok(all.length > 80, `the checkout's packs hold ${all.length} tools`);
  const whole = JSON.stringify(all).length;
  const l = toolsListing(all);
  assert.ok(l.ok && "packs" in l);
  if (!l.ok || !("packs" in l)) return;
  const size = JSON.stringify(l).length;
  assert.ok(size < 40_000, `the list is ${size} characters (the tools whole are ${whole})`);
  assert.ok(size < whole / 8);
  assert.deepEqual(l.forged, ["azr_try: Tries a key on a file. (by a1)"]);
  assert.ok(Object.keys(l.packs).includes("computer-forensics-base"));
  assert.equal(l.count, all.length);
  assert.ok(Object.values(l.packs).flat().every((line) => line.length <= 220));
});

test("a name gives that tool whole; a name nobody has gives the nearest", () => {
  const all: ToolRow[] = [{ name: "regkv", description: "Reads a key.", pack: "windows-forensics", example: "{}", params: { hive: "string" } }, { name: "registry_recover", description: "Replays logs.", pack: "windows-forensics" }];
  const one = toolsListing(all, "regkv");
  assert.deepEqual(one, { ok: true, tool: all[0] });
  assert.deepEqual(toolsListing(all, "REGKV"), { ok: true, tool: all[0] });
  const none = toolsListing(all, "reg");
  assert.equal(none.ok, false);
  if (!none.ok) assert.deepEqual(none.nearest, ["regkv", "registry_recover"]);
  assert.equal(toolsListing([]).ok, true);
});

test("a tool's line is its description's first sentence, bounded", () => {
  assert.equal(aboutLine("Reads a hive. Then more."), "Reads a hive.");
  assert.equal(aboutLine("x".repeat(500)).length, 140);
  assert.equal(aboutLine(undefined), "");
});
