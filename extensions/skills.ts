/**
 * Skills: a run's packs as a seat meets them.
 *
 * A pack's method is a tree of small files (docs/packs.md, section 1). Four
 * things decide whether a seat uses it, and this module is all four:
 *
 * - The index is a section of the seat's system prompt. The kickoff renders it
 *   into `.pi/APPEND_SYSTEM.md` (scripts/seat-prompt.ts), which Pi puts in
 *   its own prompt sections for every run: a prompt section is checkpointed
 *   and replayed after a compaction, a tool result is not, and the summary of a
 *   compaction keeps 2,000 characters of one. It is not left to the forced
 *   prompt of `before_agent_start`: that prompt lasts for the run a user prompt
 *   starts, and the run a hand-off starts (a custom message, which has no
 *   `before_agent_start`) goes back to Pi's own sections (tests/skills-e2e.test.ts
 *   shows it through the real CLI). `promptSection` is the fallback for a prompt
 *   that does not carry the section. Measured on 458 seats: 88 % never called
 *   `skill` when the index only came back from `skill()`.
 * - The `skill` tool returns plain Markdown (no front matter, no JSON
 *   envelope), names the pack that served it, lists `needs` with their cost
 *   instead of loading them, and does not send a body the seat already holds.
 * - Every load is on the trace with the file's sha256 and its token count, so
 *   a report can say which version of which note a conclusion rests on.
 * - `skill_done(id, note)` says a seat is finished with a body. It marks the
 *   body releasable in the ledger below and records the event. Releasing it
 *   (replacing it in the seat's context with a stub) is the unloader's job and
 *   is not done here: `SkillLedger.releasable()` is its entry point.
 *
 * The module knows no pack and no tool by name: it reads `skills/INDEX.md` and
 * `skills/<id>.md` of whatever `SWARM_PACK_DIRS` lists, and nothing else.
 */
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

/** The estimator the pack lint will use: bytes per token over every shipped skill (o200k_base). */
export const BYTES_PER_TOKEN = 4.245;

/**
 * What the index may cost the seat that carries it, in estimated tokens: one
 * entry, one pack's index, the index of the whole run. Above the pack or the
 * run budget the prompt shows each pack's router only.
 */
export const SKILL_BUDGET = { entry: 40, pack: 1_000, run: 2_500 } as const;
export type SkillBudget = { entry: number; pack: number; run: number };

/** Bodies a seat may hold at once before the harness reminds it to finish one. */
export const MAX_LIVE_SKILLS = 3;

/** First line of the section in the prompt; the tests and the audit look for it. */
export const SKILLS_SECTION_TITLE = "Skills carried by this run";

export function estimateTokens(text: string): number {
  const bytes = Buffer.byteLength(text, "utf8");
  return bytes === 0 ? 0 : Math.ceil(bytes / BYTES_PER_TOKEN);
}

function sha256Of(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

// ---------------------------------------------------------------------------
// Packs and their indexes
// ---------------------------------------------------------------------------

export type PackRef = { id: string; version: string; dir: string; /** How many skills pack.json says the pack carries, when it says. */ declared?: number };
export type IndexEntry = { id: string; line: string; tokens: number };
export type PackIndex = PackRef & {
  entries: IndexEntry[];
  /** The skill the pack declares as its router (`Router:` line of INDEX.md), when it names one the index lists. */
  router: string | null;
  /** Tokens of every entry line. */
  tokens: number;
  /** Why the pack's index could not be read, when it carries skills and it could not. */
  error?: string;
};

const PACK_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;

export function packDirsFromEnv(env: NodeJS.ProcessEnv = process.env): string[] {
  return (env.SWARM_PACK_DIRS || "").split(":").filter(Boolean);
}

export async function readPackRef(dir: string): Promise<PackRef> {
  let id = basename(dir);
  let version = "";
  let declared: number | undefined;
  try {
    const manifest = JSON.parse(await readFile(join(dir, "pack.json"), "utf8")) as { id?: unknown; version?: unknown; skills?: unknown };
    if (typeof manifest.id === "string" && PACK_ID.test(manifest.id)) id = manifest.id;
    if (typeof manifest.version === "string") version = manifest.version;
    if (typeof manifest.skills === "number" && Number.isInteger(manifest.skills)) declared = manifest.skills;
  } catch {
    // a pack directory without a readable manifest is still a directory of skills
  }
  return { id, version, dir, ...(declared !== undefined ? { declared } : {}) };
}

/** The entries of one INDEX.md, and the router it names. */
export function parseIndex(text: string): { entries: IndexEntry[]; router: string | null } {
  const entries: IndexEntry[] = [];
  let router: string | null = null;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    const entry = /^- `([^`]+)`/.exec(line);
    if (entry) {
      entries.push({ id: entry[1]!, line, tokens: estimateTokens(line) });
      continue;
    }
    const named = /^Router: `([^`]+)`\s*$/.exec(line);
    if (named) router = named[1]!;
  }
  if (router && !entries.some((e) => e.id === router)) router = null;
  return { entries, router };
}

async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

export async function readPackIndex(dir: string): Promise<PackIndex> {
  const ref = await readPackRef(dir);
  const out: PackIndex = { ...ref, entries: [], router: null, tokens: 0 };
  let text: string;
  try {
    text = await readFile(join(dir, "skills", "INDEX.md"), "utf8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    // A pack of tools or recipes alone has no skills directory and no index.
    if (code === "ENOENT" && !(await exists(join(dir, "skills")))) return out;
    out.error = code === "ENOENT" ? "skills/ has no INDEX.md" : `skills/INDEX.md cannot be read (${code ?? "error"})`;
    return out;
  }
  const parsed = parseIndex(text);
  out.entries = parsed.entries;
  out.router = parsed.router;
  out.tokens = parsed.entries.reduce((sum, e) => sum + e.tokens, 0);
  // An index that lists nothing for a pack that counts skills is a broken index, not a pack with none.
  if (parsed.entries.length === 0 && (out.declared ?? 0) > 0) out.error = `skills/INDEX.md lists no skill although pack.json counts ${out.declared}`;
  return out;
}

export async function readPackIndexes(dirs: string[]): Promise<PackIndex[]> {
  return Promise.all(dirs.map((dir) => readPackIndex(dir)));
}

/** Ids more than one pack of the run carries. */
export function collidingIds(packs: PackIndex[]): Set<string> {
  const seen = new Map<string, number>();
  for (const pack of packs) for (const id of new Set(pack.entries.map((e) => e.id))) seen.set(id, (seen.get(id) ?? 0) + 1);
  return new Set([...seen].filter(([, n]) => n > 1).map(([id]) => id));
}

/** `pack:id` where the bare id would be ambiguous, the entry line otherwise as the pack wrote it. */
function entryLine(pack: PackIndex, entry: IndexEntry, colliding: Set<string>): string {
  return colliding.has(entry.id) ? entry.line.replace(/^- `[^`]+`/, `- \`${pack.id}:${entry.id}\``) : entry.line;
}

// ---------------------------------------------------------------------------
// The section of the prompt
// ---------------------------------------------------------------------------

export type SectionReport = {
  /** Every pack's entries are in the section, or at least one pack shows its router only. */
  mode: "full" | "routers";
  packs: Array<{ id: string; version: string; skills: number; tokens: number; shown: "full" | "router"; router: string | null }>;
  /** Tokens of every entry of every pack, and of the entries the section carries. */
  index_tokens: number;
  shown_tokens: number;
  /** The whole section, with its words. */
  section_tokens: number;
  chars: number;
  sha256: string;
  budget: SkillBudget;
  /** A budget that was passed, in words: "pack x 1,200 > 1,000", "run 3,000 > 2,500". */
  over_budget: string[];
  /** Packs over budget that name no router, so they are shown in full. */
  no_router: string[];
  /** Entries over the entry budget, shown whole: the pack's seal refuses them, the prompt never cuts one. */
  long_entries: Array<{ pack: string; id: string; tokens: number }>;
  collisions: string[];
  /** Packs whose index could not be read. */
  unreadable: Array<{ pack: string; reason: string }>;
};

const fmt = (n: number) => n.toLocaleString("en-US");

/**
 * The Skills section of a seat's system prompt, from the packs' indexes.
 *
 * Within budget every entry is shown, as the pack's own INDEX.md line. A pack
 * whose entries pass the pack budget shows its router only; when the run's
 * entries still pass the run budget, every pack that names a router does. A
 * pack with no router cannot be shortened and is shown whole (the report says
 * so): the section never cuts an entry, and `skill()` with no id lists them all.
 */
export function renderSkillsSection(packs: PackIndex[], budget: SkillBudget = SKILL_BUDGET): { text: string; report: SectionReport } {
  const live = packs.filter((p) => p.entries.length > 0);
  const colliding = collidingIds(live);
  const shown = new Map<string, "full" | "router">(live.map((p) => [p.id, "full"]));
  const overBudget: string[] = [];
  const cost = () => live.reduce((sum, p) => sum + (shown.get(p.id) === "router" ? p.entries.find((e) => e.id === p.router)!.tokens : p.tokens), 0);
  const indexTokens = live.reduce((sum, p) => sum + p.tokens, 0);

  for (const p of live) {
    if (p.tokens > budget.pack) {
      overBudget.push(`pack ${p.id} ${fmt(p.tokens)} > ${fmt(budget.pack)}`);
      if (p.router) shown.set(p.id, "router");
    }
  }
  const runOver = cost() > budget.run;
  if (runOver) {
    overBudget.push(`run ${fmt(indexTokens)} > ${fmt(budget.run)}`);
    for (const p of live) if (p.router) shown.set(p.id, "router");
  }
  // A pack that was part of the overrun and names no router: nothing to shorten it to.
  const noRouter = live.filter((p) => !p.router && (p.tokens > budget.pack || runOver)).map((p) => p.id);
  const collapsed = live.some((p) => shown.get(p.id) === "router");

  const lines: string[] = [SKILLS_SECTION_TITLE, ""];
  lines.push(
    "The packs this run was started with carry method notes. Below is their index: one line per skill, what it is for and when to reach for it. " +
      'Load a body with skill(id) before you work that kind of artefact ("Skills" above says how). A skill more than one pack carries is listed as pack:id.',
  );
  if (collapsed) {
    lines.push(
      `This index is over its budget (${fmt(indexTokens)} tokens of entries; ${fmt(budget.pack)} a pack, ${fmt(budget.run)} the run), so a pack marked "router only" shows the one note that routes to the rest: load it and it names the notes under it. skill() with no id lists every skill of every pack.`,
    );
  }
  let shownTokens = 0;
  for (const p of live) {
    const router = shown.get(p.id) === "router";
    lines.push("");
    lines.push(`${p.id}${p.version ? ` ${p.version}` : ""} (${p.entries.length} skill${p.entries.length === 1 ? "" : "s"}${router ? ", router only" : ""})`);
    for (const entry of p.entries) {
      if (router && entry.id !== p.router) continue;
      lines.push(entryLine(p, entry, colliding));
      shownTokens += entry.tokens;
    }
  }
  const text = live.length ? lines.join("\n") : "";
  const report: SectionReport = {
    mode: collapsed ? "routers" : "full",
    packs: live.map((p) => ({ id: p.id, version: p.version, skills: p.entries.length, tokens: p.tokens, shown: shown.get(p.id)!, router: p.router })),
    index_tokens: indexTokens,
    shown_tokens: shownTokens,
    section_tokens: estimateTokens(text),
    chars: text.length,
    sha256: sha256Of(text),
    budget,
    over_budget: overBudget,
    no_router: noRouter,
    long_entries: live.flatMap((p) => p.entries.filter((e) => e.tokens > budget.entry).map((e) => ({ pack: p.id, id: e.id, tokens: e.tokens }))),
    collisions: [...colliding].sort(),
    unreadable: packs.filter((p) => p.error).map((p) => ({ pack: p.id, reason: p.error! })),
  };
  return { text, report };
}

/** Every entry of every pack, whole: what `skill()` with no id answers when the prompt shows routers only. */
export function renderFullIndex(packs: PackIndex[]): string {
  const live = packs.filter((p) => p.entries.length > 0);
  if (!live.length) return "The packs carry no skills.";
  const colliding = collidingIds(live);
  const out: string[] = [];
  for (const p of live) {
    out.push(`${p.id}${p.version ? ` ${p.version}` : ""} (${p.entries.length} skill${p.entries.length === 1 ? "" : "s"})`);
    for (const entry of p.entries) out.push(entryLine(p, entry, colliding));
    out.push("");
  }
  return out.join("\n").trimEnd();
}

// ---------------------------------------------------------------------------
// A skill file
// ---------------------------------------------------------------------------

export type SkillMeta = Record<string, string | string[]>;

/** The front matter pack.sh validates, and the body after it. A file without front matter is all body. */
export function splitSkill(text: string): { meta: SkillMeta; body: string } {
  // pack.sh reads a file with universal newlines, so a CRLF skill seals; its front matter has to strip all the same.
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n/.exec(text);
  if (!m) return { meta: {}, body: text.trim() };
  const meta: SkillMeta = {};
  for (const line of m[1]!.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("#") || !line.includes(":")) continue;
    const at = line.indexOf(":");
    const key = line.slice(0, at).trim();
    const value = line.slice(at + 1).trim();
    meta[key] = value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1).split(",").map((x) => x.trim()).filter(Boolean) : value;
  }
  return { meta, body: text.slice(m[0].length).trim() };
}

function listOf(value: string | string[] | undefined): string[] {
  return Array.isArray(value) ? value : value ? [value] : [];
}

export type SkillFile = {
  pack: PackRef;
  id: string;
  title: string;
  /** sha256 of the file as the pack ships it, the number pack.json's checksums carry. */
  sha256: string;
  bytes: number;
  /** What the seat receives: the body without front matter. */
  body: string;
  tokens: number;
  needs: string[];
  tools: string[];
};

const SKILL_ID = /^[a-z0-9][a-z0-9_/-]{0,127}$/;

export async function readSkillFile(pack: PackRef, id: string): Promise<SkillFile | null> {
  let raw: Buffer;
  try {
    raw = await readFile(join(pack.dir, "skills", `${id}.md`));
  } catch {
    return null;
  }
  const { meta, body } = splitSkill(raw.toString("utf8"));
  return {
    pack,
    id,
    title: typeof meta.title === "string" ? meta.title : "",
    sha256: sha256Of(raw),
    bytes: raw.length,
    body,
    tokens: estimateTokens(body),
    needs: listOf(meta.needs),
    tools: listOf(meta.tools),
  };
}

// ---------------------------------------------------------------------------
// Which skill the seat meant
// ---------------------------------------------------------------------------

export type Wanted = { pack: string | null; id: string };

/** `pack:id` or the pack-relative id; null when it is neither. */
export function parseWanted(raw: string): Wanted | null {
  const m = /^(?:([a-z0-9][a-z0-9-]{0,63}):)?(.+)$/.exec(raw.trim());
  if (!m) return null;
  const id = m[2]!;
  if (!SKILL_ID.test(id) || id.includes("..")) return null;
  return { pack: m[1] ?? null, id };
}

export type Located = { pack: PackRef; id: string; /** The other packs of the run that carry the same bare id. */ others: PackRef[] };

export async function locateSkill(packs: PackRef[], wanted: Wanted): Promise<{ found: Located } | { missing: "no such pack" | "no such skill" }> {
  const has = (pack: PackRef) => exists(join(pack.dir, "skills", `${wanted.id}.md`));
  if (wanted.pack) {
    const pack = packs.find((p) => p.id === wanted.pack);
    if (!pack) return { missing: "no such pack" };
    return (await has(pack)) ? { found: { pack, id: wanted.id, others: [] } } : { missing: "no such skill" };
  }
  const carrying: PackRef[] = [];
  for (const pack of packs) if (await has(pack)) carrying.push(pack);
  if (!carrying.length) return { missing: "no such skill" };
  return { found: { pack: carrying[0]!, id: wanted.id, others: carrying.slice(1) } };
}

const squash = (text: string) => text.toLowerCase().replace(/\.md$/, "").replace(/[^a-z0-9/]/g, "");

/**
 * Ids a seat probably meant, or none. The shape that fails is the id with a pack
 * in front of it ("windows/execution/prefetch", 17 of 143 calls): a leading
 * segment that is the start of a pack id of this run is taken off, dashes do
 * not count ("anti-forensics" is "antiforensics"), and only a close match is
 * named (the same id in another place, the same last segment, a directory of
 * that name). A weak match is worse than none: it sends the seat to a note
 * about something else.
 */
export function suggestIds(packs: PackIndex[], asked: string, limit = 5): string[] {
  const afterPack = asked.toLowerCase().replace(/^.*:/, "");
  const raw = afterPack.split("/").filter(Boolean);
  const packIds = packs.map((p) => p.id.toLowerCase());
  const head = raw[0] ?? "";
  const segments = (raw.length > 0 && head.length >= 3 && packIds.some((id) => id.startsWith(head)) ? raw.slice(1) : raw).map(squash).filter(Boolean);
  if (!segments.length) return [];
  const wanted = segments.join("/");
  const last = segments[segments.length - 1]!;
  const lastTwo = segments.slice(-2).join("/");
  const colliding = collidingIds(packs);
  const scored: Array<{ ref: string; score: number }> = [];
  for (const pack of packs) {
    for (const entry of pack.entries) {
      const id = squash(entry.id);
      let score = 0;
      if (id === wanted) score = 5;
      else if (lastTwo && id === lastTwo) score = 4;
      else if (id === last || id.endsWith(`/${last}`) || id.startsWith(`${wanted}/`)) score = 3;
      if (score) scored.push({ ref: colliding.has(entry.id) ? `${pack.id}:${entry.id}` : entry.id, score });
    }
  }
  const best = scored.reduce((m, x) => Math.max(m, x.score), 0);
  return scored
    .filter((x) => x.score === best)
    .sort((a, b) => a.ref.localeCompare(b.ref))
    .slice(0, limit)
    .map((x) => x.ref);
}

// ---------------------------------------------------------------------------
// What this seat has loaded
// ---------------------------------------------------------------------------

export type SkillLoad = {
  /** `pack:id`. */
  key: string;
  pack: string;
  id: string;
  /** The turn the load happened in (the number of turns finished, plus the one it was in). */
  turn: number;
  at: string;
  sha256: string;
  tokens: number;
  /** The tool call that delivered the body: how an unloader finds its result in the session. */
  toolCallId: string;
  /** Set by `skill_done`. */
  done?: { turn: number; note: string };
};

type SessionEntryLike = {
  type?: string;
  id?: string;
  timestamp?: string;
  message?: { role?: string; toolName?: string; toolCallId?: string; details?: Record<string, unknown> };
};

/**
 * The skill bodies the session's own entries hold, in the order they were
 * loaded: what `buildContextEntries()` returns is exactly what the model sees
 * (the compaction, the kept tail, everything after), so a ledger rebuilt from
 * it is exact where one kept in memory can only guess. The tool results'
 * `details` carry the id, pack, hash, tokens and turn; a `skill_done` result
 * marks its body. Also the turn the index was last listed in, when a
 * `skill()` index answer is still in the context.
 */
export function loadsFromEntries(entries: readonly unknown[]): { loads: SkillLoad[]; indexTurn: number | null } {
  const byKey = new Map<string, SkillLoad>();
  let indexTurn: number | null = null;
  for (const raw of entries) {
    const e = raw as SessionEntryLike | null;
    if (e?.type !== "message" || e.message?.role !== "toolResult") continue;
    const m = e.message;
    const d = m.details ?? {};
    if (m.toolName === "skill") {
      if (d.ok !== true) continue;
      if (d.index === true) {
        if (d.in_prompt !== true && typeof d.turn === "number") indexTurn = d.turn;
        continue;
      }
      if (d.already_loaded === true || typeof d.id !== "string" || typeof d.pack !== "string") continue;
      const key = SkillLedger.key(d.pack, d.id);
      byKey.set(key, {
        key,
        pack: d.pack,
        id: d.id,
        turn: typeof d.turn === "number" ? d.turn : 0,
        at: typeof e.timestamp === "string" ? e.timestamp : "",
        sha256: typeof d.sha256 === "string" ? d.sha256 : "",
        tokens: typeof d.tokens === "number" ? d.tokens : 0,
        toolCallId: typeof m.toolCallId === "string" ? m.toolCallId : (e.id ?? ""),
      });
    } else if (m.toolName === "skill_done" && d.ok === true && typeof d.id === "string" && typeof d.pack === "string") {
      const load = byKey.get(SkillLedger.key(d.pack, d.id));
      if (load && !load.done) load.done = { turn: typeof d.turn === "number" ? d.turn : load.turn, note: typeof d.note === "string" ? d.note : "" };
    }
  }
  return { loads: [...byKey.values()], indexTurn };
}

/** Assistant messages on the session's path: the turns this seat has had, so a restarted process counts on from them. */
export function assistantTurns(entries: readonly unknown[]): number {
  return entries.filter((raw) => {
    const e = raw as SessionEntryLike | null;
    return e?.type === "message" && e.message?.role === "assistant";
  }).length;
}

/**
 * The bodies one seat holds, as far as the harness can know: loaded since
 * the context was last cut. A compaction keeps the newest part of the
 * history verbatim (Pi's `keepRecentTokens`), so what a compaction takes out
 * is not every body: `reconcile` is given the bodies the session says are
 * still in context and keeps exactly those, and `restore` does the same for a
 * process that starts on a session that already has some.
 *
 * The unloader (not built here) takes `releasable()` at a turn boundary,
 * replaces each body's tool result with a stub and calls `release(key)`; from
 * then on `skill(id)` delivers the body again.
 */
export class SkillLedger {
  private live = new Map<string, SkillLoad>();
  /** What the last compaction took out of the context, not fetched again since. */
  private lost: SkillLoad[] = [];
  private indexTurn: number | null = null;

  static key(pack: string, id: string): string {
    return `${pack}:${id}`;
  }

  get(key: string): SkillLoad | undefined {
    return this.live.get(key);
  }

  record(load: SkillLoad): void {
    this.live.set(load.key, load);
    this.lost = this.lost.filter((l) => l.key !== load.key);
  }

  /** The bodies held and not yet marked done. */
  working(): SkillLoad[] {
    return [...this.live.values()].filter((l) => !l.done);
  }

  /** Marks a held body done; null when this seat does not hold it. */
  markDone(key: string, turn: number, note: string): SkillLoad | null {
    const load = this.live.get(key);
    if (!load) return null;
    if (!load.done) load.done = { turn, note };
    return load;
  }

  /** Bodies the seat said it is finished with and that are still in its context: the unloader's input. */
  releasable(): SkillLoad[] {
    return [...this.live.values()].filter((l) => l.done);
  }

  /** The unloader replaced this body in the context: it is no longer held. */
  release(key: string): void {
    this.live.delete(key);
  }

  /** Nothing is known to be in the context any more (the session could not be read after a compaction). */
  onCompaction(): SkillLoad[] {
    const taken = [...this.live.values()];
    this.lost = taken;
    this.live.clear();
    this.indexTurn = null;
    return taken;
  }

  /** A compaction ran, and `inContext` is what the session says is still there: the rest is lost. */
  reconcile(inContext: readonly SkillLoad[], indexTurn: number | null): { kept: SkillLoad[]; lost: SkillLoad[] } {
    const before = [...this.live.values()];
    const next = new Map<string, SkillLoad>();
    for (const load of inContext) {
      const prior = before.find((b) => b.key === load.key && b.toolCallId === load.toolCallId);
      next.set(load.key, { ...load, ...(load.done ? {} : prior?.done ? { done: prior.done } : {}) });
    }
    const lost = before.filter((b) => !next.has(b.key) || next.get(b.key)!.toolCallId !== b.toolCallId);
    this.live = next;
    this.lost = lost;
    this.indexTurn = indexTurn;
    return { kept: [...next.values()], lost };
  }

  /** A process started on a session that already holds some bodies. */
  restore(inContext: readonly SkillLoad[], indexTurn: number | null): void {
    this.reconcile(inContext, indexTurn);
    this.lost = [];
  }

  /** Skills the seat held when it last handed off, for the line under the hand-off header. */
  handoffIds(): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const load of this.lost) {
      if (seen.has(load.key)) continue;
      seen.add(load.key);
      out.push(load.key);
    }
    return out;
  }

  indexShownAt(): number | null {
    return this.indexTurn;
  }

  markIndexShown(turn: number): void {
    this.indexTurn = turn;
  }

  wasLostAtCompaction(key: string): boolean {
    return this.lost.some((l) => l.key === key);
  }
}

// ---------------------------------------------------------------------------
// The tools
// ---------------------------------------------------------------------------

export type SkillsDeps = {
  packDirs: string[];
  agentId: () => string;
  /** One trace line; the extension's own `logEvent`, so attribution and the collector are the same. */
  trace: (cwd: string, tool: string, args: Record<string, unknown>, result: unknown, durationMs?: number) => Promise<void>;
  /** How many turns this seat has finished. */
  turns: () => number;
  /** A process that starts on an existing session counts its turns on from the session's. */
  restoreTurns?: (turns: number) => void;
  /** A fault the operator and the peers should see (the extension posts it on the board). */
  fault: (cwd: string, message: string) => Promise<void>;
};

export type SkillsHandle = {
  /**
   * What to add to the forced system prompt, with its leading blank line:
   * nothing when `basePrompt` (Pi's own rendering of the seat's prompt) already
   * carries this run's index whole, the index when it does not (with a word
   * when the prompt carries another one), and nothing when the packs carry no
   * skills. Writes the one `skills_index` row of the process.
   */
  promptSection: (cwd: string, basePrompt: string) => Promise<string>;
  /** The lines the hand-off header carries: the skill bodies a compaction took out of this seat's context and, when its prompt does not carry the index, the index. Empty when none. */
  handoffLine: () => string;
  ledger: SkillLedger;
};

/** Where the seat's prompt got the index from: Pi's own prompt (the kickoff's file), the extension (that run only), or nowhere. */
export type IndexSource = "prompt" | "stale" | "extension" | "none";

function text(value: string, details: Record<string, unknown>) {
  return { content: [{ type: "text" as const, text: value }], details };
}

export function registerSkills(pi: ExtensionAPI, deps: SkillsDeps): SkillsHandle {
  const ledger = new SkillLedger();
  let indexes: Promise<PackIndex[]> | null = null;
  const packIndexes = () => (indexes ??= readPackIndexes(deps.packDirs));
  let section: Promise<{ text: string; report: SectionReport }> | null = null;
  let sectionLogged = false;
  let source: IndexSource | null = null;
  let sectionText = "";

  const sectionOnce = async () => (section ??= packIndexes().then((all) => renderSkillsSection(all)));

  // Pi runs the tool calls of one assistant message at the same time. Both of ours read
  // and write one ledger with awaits between, so they take turns, in the order the
  // message lists them (executionMode "sequential" would hold a message's bash calls back too).
  let chain: Promise<void> = Promise.resolve();
  const inTurn = <A extends unknown[], R>(run: (...args: A) => Promise<R>) => (...args: A): Promise<R> => {
    const next = chain.then(() => run(...args));
    chain = next.then(() => undefined, () => undefined);
    return next;
  };

  /** The Skills section, and the one trace row that says what it carried, where it came from, or that it could not be built. */
  async function promptSection(cwd: string, basePrompt: string): Promise<string> {
    let built: { text: string; report: SectionReport };
    try {
      built = await sectionOnce();
    } catch (err) {
      built = { text: "", report: { unreadable: [{ pack: "*", reason: err instanceof Error ? err.message : String(err) }] } as SectionReport };
    }
    // Pi's own rendering of the prompt carries it when the kickoff wrote .pi/APPEND_SYSTEM.md. Having the heading is not
    // having the index: a file written for other packs, or a one-line heading, is a section that lists the wrong skills.
    const exact = built.text !== "" && basePrompt.includes(built.text);
    const headed = built.text !== "" && basePrompt.includes(SKILLS_SECTION_TITLE);
    const now: IndexSource = built.text === "" ? "none" : exact ? "prompt" : headed ? "stale" : "extension";
    source = now;
    sectionText = built.text;
    if (!sectionLogged) {
      sectionLogged = true;
      const { report } = built;
      const failed = report.unreadable ?? [];
      await deps
        .trace(cwd, "skills_index", {}, { ok: failed.length === 0 && now !== "stale", source: now, ...(headed ? { matches_packs: exact } : {}), ...report })
        .catch(() => undefined);
      if (failed.length) {
        await deps
          .fault(
            cwd,
            `HARNESS FAULT: the Skills section of ${deps.agentId() || "this agent"}'s prompt could not list ${failed.map((f) => `${f.pack} (${f.reason})`).join(", ")}. Those packs' skills are not in the index this seat was given: it can still call skill() with no id and skill(id).`,
          )
          .catch(() => undefined);
      }
      if (now === "stale") {
        await deps
          .fault(
            cwd,
            `HARNESS FAULT: ${deps.agentId() || "this agent"}'s prompt carries a Skills section that is not the index of this run's packs (a .pi/APPEND_SYSTEM.md written for other packs, or a heading with no index under it). The current index is added after it for this run; the file is wrong, and a run a hand-off starts will show the old one. Tell the operator.`,
          )
          .catch(() => undefined);
      }
    }
    if (!built.text || exact) return "";
    return `\n\n${now === "stale" ? "The Skills section above does not list this run's packs; this is their index:\n\n" : ""}${built.text}`;
  }

  function handoffLine(): string {
    const ids = ledger.handoffIds();
    const lines: string[] = [];
    if (ids.length) lines.push(`Skill bodies a compaction took out of your context: ${ids.join(", ")}. Load again (skill(id)) the ones you still need.`);
    // A prompt the extension had to add the index to loses it with the run a hand-off starts: it comes back here.
    if (sectionText && (source === "extension" || source === "stale")) lines.push(`The index of this run's packs (your prompt no longer carries it):\n${sectionText}`);
    return lines.join("\n");
  }

  pi.on("session_start", async (_event, ctx) => {
    try {
      const inContext = loadsFromEntries(ctx.sessionManager.buildContextEntries());
      ledger.restore(inContext.loads, inContext.indexTurn);
      deps.restoreTurns?.(assistantTurns(ctx.sessionManager.getBranch()));
    } catch {
      // a session that cannot be read starts with an empty ledger: a body is sent once more, nothing worse
    }
  });

  pi.on("session_compact", async (_event, ctx) => {
    let result: { kept: SkillLoad[]; lost: SkillLoad[] };
    try {
      const inContext = loadsFromEntries(ctx.sessionManager.buildContextEntries());
      result = ledger.reconcile(inContext.loads, inContext.indexTurn);
    } catch {
      result = { kept: [], lost: ledger.onCompaction() };
    }
    if (result.kept.length || result.lost.length) {
      const ref = (l: SkillLoad) => ({ key: l.key, turn: l.turn });
      await deps.trace(ctx.cwd, "skills_compacted", {}, { ok: true, kept: result.kept.map(ref), lost: result.lost.map(ref) }).catch(() => undefined);
    }
  });

  const packRefs = async (): Promise<PackIndex[]> => packIndexes();
  const sampleId = (all: PackIndex[]) => all.find((p) => p.entries.length)?.entries[0]?.id ?? "area/topic";

  async function runSkill(toolCallId: string, params: { id?: string }, _signal: unknown, _onUpdate: unknown, toolCtx: { cwd: string }) {
    const started = Date.now();
    const cwd = toolCtx.cwd;
    const turn = deps.turns() + 1;
    const wantedRaw = typeof params?.id === "string" ? params.id.trim() : "";
    const all = await packRefs();

    if (!wantedRaw) {
      const built = await sectionOnce().catch(() => null);
      // The prompt carries the index whole only when the kickoff's file put it there and no pack is shown by its router alone.
      const inPrompt = built !== null && built.text !== "" && built.report.mode === "full" && source === "prompt";
      const shownAt = ledger.indexShownAt();
      let out: string;
      if (inPrompt) out = `The whole index of this run's packs is in your instructions, under "${SKILLS_SECTION_TITLE}". Load a note with skill(id).`;
      else if (shownAt !== null) out = `The index was already listed at turn ${shownAt}; it is still in your context. Load a note with skill(id).`;
      else {
        out = renderFullIndex(all);
        ledger.markIndexShown(turn);
      }
      await deps.trace(cwd, "skill", { id: "INDEX" }, { ok: true, bytes: Buffer.byteLength(out), tokens: estimateTokens(out), in_prompt: inPrompt, ...(shownAt !== null && !inPrompt ? { already_loaded: true, loaded_at_turn: shownAt } : {}) }, Date.now() - started);
      return text(out, { ok: true, index: true, in_prompt: inPrompt, turn: shownAt ?? turn });
    }

    const wanted = parseWanted(wantedRaw);
    if (!wanted) {
      await deps.trace(cwd, "skill", { id: wantedRaw }, { ok: false, error: "bad id" }, Date.now() - started);
      const sample = sampleId(all);
      const out = `A skill id is lower case and slash separated, as listed in your instructions ("${sample}"), optionally with its pack in front ("${all.find((p) => p.entries.length)?.id ?? "pack"}:${sample}").`;
      return text(out, { ok: false, error: "bad id" });
    }

    const located = await locateSkill(all, wanted);
    if ("missing" in located) {
      const maybe = suggestIds(all, wantedRaw);
      await deps.trace(cwd, "skill", { id: wantedRaw }, { ok: false, error: located.missing, ...(maybe.length ? { suggested: maybe } : {}) }, Date.now() - started);
      const which = located.missing === "no such pack" ? `No pack "${wanted.pack}" in this run (it carries: ${all.map((p) => p.id).join(", ") || "none"}).` : `No skill "${wantedRaw}" in this run's packs.`;
      const hint = maybe.length ? ` Did you mean: ${maybe.join(", ")}?` : ` No close match; read the index in your instructions ("${SKILLS_SECTION_TITLE}") for the id of the note you want.`;
      const out = `${which}${hint} skill() with no id lists the ids.`;
      return text(out, { ok: false, error: located.missing, suggested: maybe });
    }

    const { pack, id, others } = located.found;
    const key = SkillLedger.key(pack.id, id);
    const held = ledger.get(key);
    if (held) {
      const out = `\`${id}\` (${pack.id}) is already in your context, loaded at turn ${held.turn}${held.done ? " and marked done" : ""}; not sent again.`;
      await deps.trace(cwd, "skill", { id }, { ok: true, already_loaded: true, pack: pack.id, loaded_at_turn: held.turn, turn, sha256: held.sha256, tokens_saved: held.tokens }, Date.now() - started);
      return text(out, { ok: true, already_loaded: true, id, pack: pack.id, loaded_at_turn: held.turn });
    }

    const file = await readSkillFile(pack, id);
    if (!file) {
      await deps.trace(cwd, "skill", { id: wantedRaw }, { ok: false, error: "no such skill" }, Date.now() - started);
      return text(`No skill "${wantedRaw}" in this run's packs.`, { ok: false, error: "no such skill" });
    }

    // What it builds on, with the cost of each: the seat chooses, nothing is loaded for it.
    const needs: Array<{ ref: string; id: string; pack: string | null; tokens: number | null; loaded_at_turn?: number }> = [];
    for (const need of file.needs) {
      const wantedNeed = parseWanted(need);
      if (!wantedNeed) {
        needs.push({ ref: need, id: need, pack: null, tokens: null });
        continue;
      }
      // The pack that carries the skill first; the others in the run's order.
      const order = wantedNeed.pack ? all.filter((p) => p.id === wantedNeed.pack) : [pack, ...all.filter((p) => p.dir !== pack.dir)];
      let found: SkillFile | null = null;
      for (const p of order) {
        found = await readSkillFile(p, wantedNeed.id);
        if (found) break;
      }
      if (!found) {
        needs.push({ ref: need, id: wantedNeed.id, pack: null, tokens: null });
        continue;
      }
      const heldNeed = ledger.get(SkillLedger.key(found.pack.id, found.id));
      const crossPack = found.pack.dir !== pack.dir;
      const clash = all.filter((p) => p.entries.some((e) => e.id === found!.id)).length > 1;
      needs.push({ ref: crossPack || clash ? `${found.pack.id}:${found.id}` : found.id, id: found.id, pack: found.pack.id, tokens: found.tokens, ...(heldNeed ? { loaded_at_turn: heldNeed.turn } : {}) });
    }

    const reload = ledger.wasLostAtCompaction(key);
    const working = ledger.working();
    const lines: string[] = [`Skill \`${id}\` (pack ${pack.id}${pack.version ? ` ${pack.version}` : ""}, about ${fmt(file.tokens)} tokens)${file.title ? `: ${file.title}` : ""}`, "", file.body];
    const tail: string[] = [];
    if (needs.length) {
      tail.push(
        `Builds on, not loaded: ${needs.map((n) => (n.tokens === null ? `\`${n.ref}\` (not carried by this run's packs)` : n.loaded_at_turn !== undefined ? `\`${n.ref}\` (already loaded, turn ${n.loaded_at_turn})` : `\`${n.ref}\` (about ${fmt(n.tokens)} tokens)`)).join(", ")}. Load those you need.`,
      );
    }
    if (others.length) tail.push(`Also carried by ${others.map((p) => p.id).join(", ")}: skill("${others[0]!.id}:${id}") loads that one.`);
    if (working.length >= MAX_LIVE_SKILLS) tail.push(`You hold ${working.length} notes you have not marked done (${working.map((l) => l.id).join(", ")}). Mark the ones you have finished with skill_done before you load more.`);
    const delivered = [...lines, ...(tail.length ? ["", ...tail] : [])].join("\n");

    ledger.record({ key, pack: pack.id, id, turn, at: new Date().toISOString(), sha256: file.sha256, tokens: file.tokens, toolCallId });
    await deps.trace(
      cwd,
      "skill",
      { id, ...(wantedRaw !== id ? { requested: wantedRaw } : {}) },
      {
        ok: true,
        pack: pack.id,
        pack_version: pack.version,
        bytes: file.bytes,
        sha256: file.sha256,
        tokens: file.tokens,
        turn,
        tools: file.tools,
        needs: file.needs,
        ...(others.length ? { also_in: others.map((p) => p.id) } : {}),
        ...(reload ? { reload_after_compaction: true } : {}),
        ...(working.length >= MAX_LIVE_SKILLS ? { holding: working.length } : {}),
      },
      Date.now() - started,
    );
    return text(delivered, { ok: true, id, pack: pack.id, pack_version: pack.version, sha256: file.sha256, bytes: file.bytes, tokens: file.tokens, turn, needs, also_in: others.map((p) => p.id) });
  }

  async function runSkillDone(_toolCallId: string, params: { id: string; note?: string }, _signal: unknown, _onUpdate: unknown, toolCtx: { cwd: string }) {
    const started = Date.now();
    const cwd = toolCtx.cwd;
    const turn = deps.turns() + 1;
    const raw = typeof params?.id === "string" ? params.id.trim() : "";
    const note = typeof params?.note === "string" ? params.note : "";
    const wanted = parseWanted(raw);
    // Which loaded note it names: the exact key, or the bare id when one held note has it.
    const held = wanted ? [...ledger.working(), ...ledger.releasable()].filter((l) => l.id === wanted.id && (!wanted.pack || l.pack === wanted.pack)) : [];
    const target = held.length === 1 ? held[0]! : null;
    if (!target) {
      const reason = !wanted ? "bad id" : held.length > 1 ? "ambiguous" : "not loaded";
      await deps.trace(cwd, "skill_done", { id: raw, ...(note ? { note } : {}) }, { ok: false, error: reason, turn }, Date.now() - started);
      const out =
        reason === "ambiguous"
          ? `More than one pack's \`${raw}\` is loaded: name it as pack:id (${held.map((l) => l.key).join(", ")}).`
          : `\`${raw}\` is not among the notes you have loaded (none, or a compaction took it out of your context). Nothing to mark done.`;
      return text(out, { ok: false, error: reason });
    }
    const already = Boolean(target.done);
    ledger.markDone(target.key, turn, note);
    await deps.trace(
      cwd,
      "skill_done",
      { id: target.id, ...(note ? { note } : {}) },
      { ok: true, pack: target.pack, sha256: target.sha256, tokens: target.tokens, loaded_turn: target.turn, held_turns: turn - target.turn, turn, releasable: true, ...(already ? { already_done: true } : {}) },
      Date.now() - started,
    );
    return text(already ? `\`${target.id}\` was already marked done (turn ${target.done!.turn}).` : `Recorded: \`${target.id}\` is done. Load it again with skill("${target.id}") if you need it later.`, { ok: true, id: target.id, pack: target.pack, turn, note });
  }

  pi.registerTool({
    name: "skill",
    label: "Skill",
    description:
      'Method notes from this run\'s packs. The index is in your instructions ("Skills carried by this run"): load a note with skill(id) before you work that kind of artefact. Plain Markdown comes back, with the notes it builds on listed with their cost (not loaded). id is as listed, or pack:id when more than one pack carries it (pack:area/topic). A note already in your context is not sent again. With no id: the index, when your instructions do not carry it whole. Finish a note with skill_done.',
    promptSnippet: "Load a method note from an installed pack",
    promptGuidelines: [
      'Before you work an artefact class, find it in the index under "Skills carried by this run" and load its note with skill(id).',
      "Load a note once, apply it, then skill_done(id, note); load again after a compaction if you still need it.",
    ],
    parameters: Type.Object({
      id: Type.Optional(Type.String({ description: "Skill id as listed (area/topic), or pack:id (pack:area/topic). Omit for the index." })),
    }),
    execute: inTurn(runSkill),
  });

  pi.registerTool({
    name: "skill_done",
    label: "Skill done",
    description:
      "Say you are finished with a skill note you loaded: its id, and one line on what you took from it or why it did not apply. It is recorded for the report, and the note may leave your context; skill(id) brings it back.",
    promptSnippet: "Mark a loaded skill note finished",
    promptGuidelines: ["Call skill_done(id, note) when the topic a note covers is finished, before you load a fourth."],
    parameters: Type.Object({
      id: Type.String({ description: "The id you loaded, as skill() gave it." }),
      note: Type.Optional(Type.String({ description: "One line: what you took from it, or why it did not apply." })),
    }),
    execute: inTurn(runSkillDone),
  });

  return { promptSection, handoffLine, ledger };
}
