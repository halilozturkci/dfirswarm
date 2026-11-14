/**
 * A manifest's `not_for` lines (IMPROVEMENT-PLAN-2 D4): what the tool is not
 * for, and the tool that is. Every line of every pack and library manifest
 * names a tool that exists and is not itself, at most four a manifest, and
 * the description an agent sees carries them.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { notForWords } from "../extensions/protocol-core.ts";

const ROOT = join(import.meta.dirname, "..");

function manifests(): Array<{ at: string; m: Record<string, unknown> }> {
  const out: Array<{ at: string; m: Record<string, unknown> }> = [];
  for (const pack of readdirSync(join(ROOT, "packs")).sort()) {
    const dir = join(ROOT, "packs", pack, "tools");
    if (!existsSync(dir)) continue;
    for (const t of readdirSync(dir).sort()) {
      const f = join(dir, t, "manifest.json");
      if (existsSync(f)) out.push({ at: `packs/${pack}/tools/${t}`, m: JSON.parse(readFileSync(f, "utf8")) });
    }
  }
  const lib = join(ROOT, "tool-library");
  for (const t of existsSync(lib) ? readdirSync(lib).sort() : []) {
    const f = join(lib, t, "manifest.json");
    if (existsSync(f)) out.push({ at: `tool-library/${t}`, m: JSON.parse(readFileSync(f, "utf8")) });
  }
  return out;
}

test("every not_for line names another tool that exists, at most four a manifest, each said in a sentence of its own", () => {
  const all = manifests();
  const names = new Set(all.map((x) => String(x.m.name)));
  for (const { at, m } of all) {
    if (m.not_for === undefined) continue;
    assert.ok(Array.isArray(m.not_for), `${at}: not_for is a list`);
    const rows = m.not_for as Array<Record<string, unknown>>;
    assert.ok(rows.length >= 1 && rows.length <= 4, `${at}: one to four not_for lines`);
    for (const r of rows) {
      assert.deepEqual(Object.keys(r).sort(), ["use", "what"], `${at}: a line is {what, use}`);
      assert.equal(typeof r.what, "string");
      assert.ok((r.what as string).length >= 8 && (r.what as string).length <= 160, `${at}: what is 8 to 160 characters`);
      assert.ok(names.has(String(r.use)), `${at}: not_for names ${String(r.use)}, which is no tool of the packs or the library`);
      assert.notEqual(r.use, m.name, `${at}: a tool is not the tool to use instead of itself`);
    }
  }
});

test("the description shows the lines, and a manifest without them shows nothing", () => {
  assert.equal(notForWords({}), "");
  assert.equal(notForWords({ not_for: "x" }), "");
  assert.equal(notForWords({ not_for: [{ what: "a damaged or carved log", use: "evtx_carve" }, { what: 1, use: "x" }] }), " Not for: a damaged or carved log (use evtx_carve).");
});
