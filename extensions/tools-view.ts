/**
 * What the `tools` tool answers.
 *
 * With no name: one line a tool, the packs' tools grouped by pack and the
 * ones this run forged apart. With a name: that tool whole (its description,
 * parameters, example and how to call it). The whole library in one answer
 * was 472,000 characters in a run with five packs (the runs s571aaa and
 * s68ce47): a compaction followed within three turns after each of 65 calls,
 * and a seat's first one came in minute 2.
 */

export type ToolRow = { name: string; description?: string; by?: string; version?: number | string; pack?: string | null; runtime?: string; example?: string; params?: unknown; call?: string };

/** A description's first sentence, bounded. */
export function aboutLine(description: string | undefined, max = 140): string {
  const first = String(description ?? "").replace(/\s+/g, " ").trim().split(/(?<=[.:;])\s/)[0] ?? "";
  return first.length > max ? `${first.slice(0, max - 1)}…` : first;
}

export type ToolsListing =
  | { ok: true; packs: Record<string, string[]>; forged: string[]; count: number; hint: string }
  | { ok: true; tool: ToolRow }
  | { ok: false; reason: string; nearest?: string[] };

/** The listing (no name), or one tool whole (a name; a name nobody has gets the nearest ones). */
export function toolsListing(all: readonly ToolRow[], name?: string): ToolsListing {
  if (name !== undefined && name !== "") {
    const hit = all.find((t) => t.name === name) ?? all.find((t) => t.name.toLowerCase() === name.toLowerCase());
    if (hit) return { ok: true, tool: hit };
    const want = name.toLowerCase();
    const nearest = all.map((t) => t.name).filter((n) => n.toLowerCase().includes(want) || want.includes(n.toLowerCase())).slice(0, 8);
    return { ok: false, reason: `no tool named ${name}: tools() lists every name`, ...(nearest.length ? { nearest } : {}) };
  }
  const packs: Record<string, string[]> = {};
  const forged: string[] = [];
  for (const t of [...all].sort((a, b) => a.name.localeCompare(b.name))) {
    const line = `${t.name}: ${aboutLine(t.description)}`;
    if (t.pack) (packs[t.pack] ??= []).push(line);
    else forged.push(`${line}${t.by ? ` (by ${t.by})` : ""}`);
  }
  return {
    ok: true,
    packs,
    forged,
    count: all.length,
    hint: all.length
      ? "One line a tool. tools(name: \"<tool>\") gives that tool's parameters, example and how to call it; a pack's tool is its pack's, tested there, and the ones under forged were written in this run."
      : "Nothing forged yet. make_tool writes one and shares it.",
  };
}
