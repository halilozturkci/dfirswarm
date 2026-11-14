/**
 * A note's card (`card:` in its front matter) is what a seat is shown with
 * the first result of one of the note's tools, whether or not it ever loads
 * the note (extensions/skills.ts). It is written as rules with argument
 * forms, so it is held to the tools' manifests here: it fits the card's
 * size, the tools the note names exist, the card names one of them, and
 * every argument key it writes as JSON is a parameter of one of them.
 */
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { CARD_MAX_CHARS } from "../extensions/skills.ts";

const ROOT = join(import.meta.dirname, "..");
const PACKS = join(ROOT, "packs");

type Note = { pack: string; id: string; tools: string[]; card: string };

function notes(): Note[] {
  const out: Note[] = [];
  for (const pack of readdirSync(PACKS).sort()) {
    const skills = join(PACKS, pack, "skills");
    if (!existsSync(skills)) continue;
    for (const dir of readdirSync(skills, { withFileTypes: true })) {
      if (!dir.isDirectory()) continue;
      for (const f of readdirSync(join(skills, dir.name)).sort()) {
        if (!f.endsWith(".md")) continue;
        const text = readFileSync(join(skills, dir.name, f), "utf8");
        const fm = /^---\n([\s\S]*?)\n---\n/.exec(text)?.[1];
        if (!fm) continue;
        const card = /^card:[ \t]*(.+)$/m.exec(fm)?.[1]?.trim();
        if (!card) continue;
        const tools = (/^tools:[ \t]*\[(.*?)\]/m.exec(fm)?.[1] ?? "").split(",").map((t) => t.trim()).filter(Boolean);
        out.push({ pack, id: `${dir.name}/${f.slice(0, -3)}`, tools, card });
      }
    }
  }
  return out;
}

/** A tool's parameter names and its manifest's whole text (a key inside a parameter's value, as key_sources' {"candidates": …}, is described there). */
function params(pack: string, tool: string): { keys: Set<string>; text: string } | null {
  for (const p of [pack, ...readdirSync(PACKS)]) {
    const m = join(PACKS, p, "tools", tool, "manifest.json");
    if (!existsSync(m)) continue;
    const text = readFileSync(m, "utf8");
    return { keys: new Set(Object.keys((JSON.parse(text) as { params?: Record<string, unknown> }).params ?? {})), text };
  }
  return null;
}

const all = notes();

test("every card fits a card, and a note with a card names tools that exist", () => {
  assert.ok(all.length >= 2, "the packs carry cards");
  for (const n of all) {
    assert.ok(n.card.length <= CARD_MAX_CHARS, `${n.pack}:${n.id}: its card is ${n.card.length} characters, more than ${CARD_MAX_CHARS} (it would be cut)`);
    assert.ok(n.tools.length, `${n.pack}:${n.id}: a card is shown with a tool's result, and the note names no tool`);
    for (const t of n.tools) assert.ok(params(n.pack, t), `${n.pack}:${n.id}: names the tool ${t}, and no pack has it`);
    assert.ok(n.tools.some((t) => n.card.includes(t)), `${n.pack}:${n.id}: its card names none of its tools (${n.tools.join(", ")})`);
  }
});

test("every argument a card writes as JSON is named by the manifest of one of the note's tools", () => {
  for (const n of all) {
    const tools = n.tools.map((t) => params(n.pack, t)).filter((x): x is { keys: Set<string>; text: string } => Boolean(x));
    // A parameter by name, or a key of a parameter's value that the manifest writes out.
    const known = { has: (k: string) => tools.some((t) => t.keys.has(k) || new RegExp(`\\b${k}\\b`).test(t.text)) };
    // Keys of the JSON a card writes: "key": at any depth of a {...} it shows.
    for (const obj of n.card.match(/\{[^{}]*\}/g) ?? []) {
      for (const m of obj.matchAll(/"([A-Za-z_][A-Za-z0-9_]*)"\s*:/g)) {
        assert.ok(known.has(m[1]!), `${n.pack}:${n.id}: its card writes the argument "${m[1]}" (${obj.slice(0, 80)}), which no manifest of these tools names: ${n.tools.join(", ")}`);
      }
    }
  }
});
