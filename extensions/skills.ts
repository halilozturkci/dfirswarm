/**
 * Skills: a run's packs as a seat meets them.
 *
 * A pack's method is a tree of small files (docs/packs.md, section 1). Four
 * things decide whether a seat uses it, and this module is all four:
 *
 * - The index is a section of the seat's system prompt. The kickoff renders it
 *   into `.pi/APPEND_SYSTEM.md` (scripts/skills-section.ts), which Pi puts in
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
 *   body releasable in the ledger below and records the event.
 * - The unloader replaces a finished body in the seat's context with a one-line
 *   stub ("<id> released (N tokens). Re-load with skill('<id>')."). It is a
 *   persisted `context_edit` draft returned from `turn_end` (Pi 0.87.1,
 *   dist/core/agent-session.js `_dispatchTurnEndBoundary`: the drafts are
 *   committed before the next request is built from the session's projection),
 *   so the raw tool result stays in the session file (custody and replay see
 *   what they always saw) and only what the model is sent changes. Which body
 *   leaves when depends on the model (`releaseClassOf`) and on `--skill-release`
 *   (`SWARM_SKILL_RELEASE`); `planRelease` holds the rules and docs/packs.md
 *   section 1 says why.
 *
 * The module knows no pack and no tool by name: it reads `skills/INDEX.md` and
 * `skills/<id>.md` of whatever `SWARM_PACK_DIRS` lists, and nothing else.
 */
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import type { ExtensionAPI, SessionBoundaryDraft } from "@earendil-works/pi-coding-agent";
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

/**
 * What `--skill-release` (env `SWARM_SKILL_RELEASE`) says about the bodies a
 * seat has finished with:
 * - `auto`: a body marked done leaves at the next turn boundary on a model
 *   whose history may be edited, and only at a compaction on a model that
 *   signs its thinking blocks (`releaseClassOf`);
 * - `compaction`: bodies leave only at a compaction, whatever the model;
 * - `off`: nothing is released and the summary input is not shaped (the
 *   behaviour of a seat before the unloader existed).
 */
export type ReleaseMode = "auto" | "compaction" | "off";
export const RELEASE_MODES: readonly ReleaseMode[] = ["auto", "compaction", "off"];
export const DEFAULT_RELEASE_MODE: ReleaseMode = "auto";

export function parseReleaseMode(raw: string | undefined | null): ReleaseMode | null {
  const value = (raw ?? "").trim().toLowerCase();
  return (RELEASE_MODES as readonly string[]).includes(value) ? (value as ReleaseMode) : null;
}

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
  /** The session entry holding the result, when the ledger was read off the session (the unloader's edit target). */
  entryId?: string;
  /** Set by `skill_done`. */
  done?: { turn: number; note: string };
};

type SessionEntryLike = {
  type?: string;
  id?: string;
  timestamp?: string;
  targetId?: string;
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
 *
 * A `context_edit` entry (the unloader's stubs, Pi's own omissions after an
 * overflow) changes what the model is sent of the entry it targets, and the
 * entry itself stays in the session: a body whose result has been edited is
 * not in the context any more, so it is returned in `released`, not in `loads`.
 * The latest edit of a target wins, and an edit is only ever of an earlier entry.
 */
export function loadsFromEntries(entries: readonly unknown[]): { loads: SkillLoad[]; released: SkillLoad[]; indexTurn: number | null } {
  const byKey = new Map<string, SkillLoad>();
  const released: SkillLoad[] = [];
  const edited = new Set<string>();
  for (const raw of entries) {
    const e = raw as SessionEntryLike | null;
    if (e?.type === "context_edit" && typeof e.targetId === "string") edited.add(e.targetId);
  }
  let indexTurn: number | null = null;
  for (const raw of entries) {
    const e = raw as SessionEntryLike | null;
    if (e?.type !== "message" || e.message?.role !== "toolResult") continue;
    const m = e.message;
    const d = m.details ?? {};
    const gone = typeof e.id === "string" && edited.has(e.id);
    if (m.toolName === "skill") {
      if (d.ok !== true) continue;
      if (d.index === true) {
        if (!gone && d.in_prompt !== true && typeof d.turn === "number") indexTurn = d.turn;
        continue;
      }
      if (d.already_loaded === true || typeof d.id !== "string" || typeof d.pack !== "string") continue;
      const key = SkillLedger.key(d.pack, d.id);
      const load: SkillLoad = {
        key,
        pack: d.pack,
        id: d.id,
        turn: typeof d.turn === "number" ? d.turn : 0,
        at: typeof e.timestamp === "string" ? e.timestamp : "",
        sha256: typeof d.sha256 === "string" ? d.sha256 : "",
        tokens: typeof d.tokens === "number" ? d.tokens : 0,
        toolCallId: typeof m.toolCallId === "string" ? m.toolCallId : (e.id ?? ""),
        ...(typeof e.id === "string" ? { entryId: e.id } : {}),
      };
      if (gone) released.push(load);
      else byKey.set(key, load);
    } else if (m.toolName === "skill_done" && d.ok === true && typeof d.id === "string" && typeof d.pack === "string") {
      const load = byKey.get(SkillLedger.key(d.pack, d.id));
      if (load && !load.done) load.done = { turn: typeof d.turn === "number" ? d.turn : load.turn, note: typeof d.note === "string" ? d.note : "" };
    }
  }
  return { loads: [...byKey.values()], released, indexTurn };
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
 * The unloader (registerSkills' `turn_end` handler) takes `releasable()` at a
 * turn boundary, appends a stub for each body that `planRelease` lets go and
 * calls `release(key)`; from then on `skill(id)` delivers the body again, and
 * the ledger remembers that it was released: a body released once in a context
 * epoch (the time between two compactions) is not released a second time, so a
 * seat that keeps needing one does not make the harness rewrite its history
 * over and over.
 */
export class SkillLedger {
  private live = new Map<string, SkillLoad>();
  /** What the last compaction took out of the context, not fetched again since. */
  private lost: SkillLoad[] = [];
  /** Bodies released by a stub in this epoch, the latest of each key (kept when the key is loaded again). */
  private released = new Map<string, SkillLoad & { releasedTurn: number; reason: string }>();
  /** What stood in the context when the last compaction ran: the hand-off line's account of it. */
  private compacted: { kept: SkillLoad[]; released: Array<SkillLoad & { releasedTurn: number; reason: string }> } = { kept: [], released: [] };
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

  /** Every body held, in the order loaded. */
  held(): SkillLoad[] {
    return [...this.live.values()];
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

  /** The unloader replaced this body in the context: it is no longer held, and the ledger remembers when and why. */
  release(key: string, info: { turn: number; reason: string } = { turn: 0, reason: "released" }): SkillLoad | null {
    const load = this.live.get(key);
    if (!load) return null;
    this.live.delete(key);
    this.released.set(key, { ...load, releasedTurn: info.turn, reason: info.reason });
    return load;
  }

  /** A release that never landed (the edit is not in the session): the body is still in the context and held again, with its done mark. */
  unrelease(key: string, turn: number): SkillLoad | null {
    const gone = this.released.get(key);
    if (!gone || gone.releasedTurn !== turn) return null;
    this.released.delete(key);
    const { releasedTurn: _turn, reason: _reason, ...load } = gone;
    this.live.set(key, load);
    return load;
  }

  /** The ledger held a body the session no longer shows in the context: forget it, without calling it a release. */
  drop(key: string): void {
    this.live.delete(key);
  }

  /** The bodies released in this context epoch, the latest of each key. */
  releasedLoads(): SkillLoad[] {
    return [...this.released.values()];
  }

  /** The turn this key was last released in, in this context epoch; undefined when it was not (or a compaction has been since). */
  releasedAt(key: string): number | undefined {
    return this.released.get(key)?.releasedTurn;
  }

  /** Nothing is known to be in the context any more (the session could not be read after a compaction). */
  onCompaction(): SkillLoad[] {
    const taken = [...this.live.values()];
    this.compacted = { kept: [], released: [...this.released.values()] };
    this.lost = taken;
    this.live.clear();
    this.released.clear();
    this.indexTurn = null;
    return taken;
  }

  /**
   * A compaction ran, and `inContext` is what the session says is still there:
   * the rest is lost. `stubs` are the bodies the context still holds as stubs
   * (a released result in the kept tail): their release stays on the record.
   */
  reconcile(inContext: readonly SkillLoad[], indexTurn: number | null, stubs: readonly SkillLoad[] = []): { kept: SkillLoad[]; lost: SkillLoad[] } {
    const before = [...this.live.values()];
    const next = new Map<string, SkillLoad>();
    for (const load of inContext) {
      const prior = before.find((b) => b.key === load.key && b.toolCallId === load.toolCallId);
      next.set(load.key, { ...load, ...(load.done ? {} : prior?.done ? { done: prior.done } : {}) });
    }
    const lost = before.filter((b) => !next.has(b.key) || next.get(b.key)!.toolCallId !== b.toolCallId);
    this.compacted = { kept: [...next.values()], released: [...this.released.values()] };
    this.live = next;
    this.lost = lost;
    this.indexTurn = indexTurn;
    this.released = new Map(stubs.map((s) => [s.key, { ...s, releasedTurn: s.turn, reason: "edit" }]));
    return { kept: [...next.values()], lost };
  }

  /** A process started on a session that already holds some bodies (and some stubs). */
  restore(inContext: readonly SkillLoad[], indexTurn: number | null, stubs: readonly SkillLoad[] = []): void {
    this.reconcile(inContext, indexTurn, stubs);
    this.lost = [];
    this.compacted = { kept: [], released: [] };
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

  /**
   * What the last compaction left of the notes the seat had read: the ones it
   * took out (not loaded again since), the ones the newest part of the history
   * kept, and the ones the unloader had already replaced by a stub. Ids, sizes
   * and whether the seat said it was done; never a body.
   */
  compactionAccount(): { lost: SkillLoad[]; kept: SkillLoad[]; released: Array<SkillLoad & { releasedTurn: number; reason: string }> } {
    return { lost: [...this.lost], kept: this.compacted.kept.filter((k) => this.live.has(k.key)), released: this.compacted.released };
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
// Releasing a body: which model, which policy, which bodies, what the stub says
// ---------------------------------------------------------------------------

/**
 * The model facts the policy reads: Pi's own catalogue entry for the seat's
 * model (`ctx.model`; `api` and `reasoning` are catalogue fields), never its
 * name.
 */
export type ModelFacts = { api?: string; provider?: string; id?: string; reasoning?: boolean };

/**
 * APIs whose reasoning blocks the provider signs and Pi sends back with the
 * history (pi-ai's dist/api/anthropic-messages.js, `thinkingSignature`).
 * Anthropic's own guide says a client-side edit of an earlier turn "can
 * invalidate the thinking blocks in every later assistant turn" on Claude
 * Fable 5.1, Opus 5.5 and Sonnet 5.5 (Sonnet 5 in Pi 0.87.1's catalogue); the same API serves the older Claude
 * models and Bedrock serves Claude through the other one, so the class is the
 * API, not the three names. Pi sends those blocks back unchanged after an edit
 * (tests/skill-unload.test.ts builds its request offline); whether the provider
 * accepts the history is what nobody has asked it.
 */
export const SIGNED_THINKING_APIS: ReadonlySet<string> = new Set(["anthropic-messages", "bedrock-converse-stream"]);

/**
 * - `open`: nothing the model replays can be invalidated by an edit of an
 *   earlier tool result (OpenAI Responses and Codex, which carry reasoning as
 *   encrypted items tied to their own calls; chat-completions servers, local
 *   models; a model that does not think; a thinking model with thinking off).
 * - `signed-thinking`: the catalogue marks the model as reasoning, its API
 *   signs the thinking blocks, and thinking is on.
 * - `unknown`: the session names no model. Treated like `signed-thinking`.
 */
export type ReleaseClass = "open" | "signed-thinking" | "unknown";

export function releaseClassOf(model: ModelFacts | undefined, thinkingLevel?: string): { cls: ReleaseClass; why: string } {
  if (!model) return { cls: "unknown", why: "the session reports no model" };
  const api = typeof model.api === "string" ? model.api : "";
  if (!SIGNED_THINKING_APIS.has(api)) return { cls: "open", why: `api ${api || "unknown"} does not sign the reasoning it replays` };
  if (model.reasoning !== true) return { cls: "open", why: `the catalogue marks this ${api} model as not reasoning, so its history has no thinking blocks` };
  if (thinkingLevel === "off") return { cls: "open", why: "thinking is off, so the history has no thinking blocks to invalidate" };
  return { cls: "signed-thinking", why: `the catalogue marks this model as reasoning, its api (${api}) signs thinking blocks and thinking is on: a client-side edit of an earlier turn can invalidate them` };
}

/** What the policy comes to for this seat right now. */
export type EffectiveRelease = "boundary" | "compaction" | "off";

export function effectiveRelease(mode: ReleaseMode, cls: ReleaseClass): EffectiveRelease {
  if (mode === "off") return "off";
  if (mode === "compaction") return "compaction";
  return cls === "open" ? "boundary" : "compaction";
}

/** The stub that stands in the context for a released body. One line; names the way back. */
export function stubText(ref: string, tokens: number): string {
  return `${ref} released (${tokens} tokens). Re-load with skill('${ref}').`;
}

const STUB_RE = /^(\S+) released \((\d+) tokens\)\. Re-load with skill\('([^']+)'\)\.$/;

/** True when a tool result's text is a stub `stubText` wrote. */
export function isStub(text: string): boolean {
  return STUB_RE.test(text.trim());
}

/**
 * About how many tokens follow a session entry in the model's context (Pi's
 * own estimate, characters over four): what a provider's prompt cache has to
 * write again when that entry is edited. The unloader puts it on the
 * `skill_unload` row, so a run can say what its releases cost.
 */
export function suffixTokens(contextEntries: readonly unknown[], entryId: string): number | null {
  const at = contextEntries.findIndex((e) => (e as { sourceEntry?: { id?: string } } | null)?.sourceEntry?.id === entryId);
  if (at < 0) return null;
  let chars = 0;
  for (const entry of contextEntries.slice(at + 1)) {
    for (const message of (entry as { messages?: unknown[] }).messages ?? []) {
      const m = message as { content?: unknown };
      if (typeof m.content === "string") chars += m.content.length;
      else if (Array.isArray(m.content)) {
        for (const block of m.content as Array<{ type?: string; text?: string; thinking?: string; arguments?: unknown }>) {
          if (block.type === "text") chars += (block.text ?? "").length;
          else if (block.type === "thinking") chars += (block.thinking ?? "").length;
          else if (block.type === "toolCall") chars += JSON.stringify(block.arguments ?? {}).length;
        }
      }
    }
  }
  return Math.ceil(chars / 4);
}

export type ReleaseTrigger = "turn_end" | "compaction";

export type ReleasePlan = {
  release: SkillLoad[];
  /** Held bodies the plan leaves alone, and the rule that left them. */
  keep: Array<{ load: SkillLoad; why: string }>;
};

/**
 * Which held bodies leave the context at a boundary. The rules, in the order
 * they are asked (docs/packs.md section 1 has the reasons):
 * - only a body the seat marked done is ever released. A body it has not
 *   finished with is never touched, however many it holds: the three newest
 *   (`MAX_LIVE_SKILLS`) are the ones it is working from;
 * - not while the policy says otherwise: `off` releases nothing, and a policy
 *   of `compaction` releases only at a compaction (`trigger: "compaction"`);
 * - not a body the model has not had a turn with: one loaded in the turn that is
 *   ending was never read by an assistant message, whatever was marked;
 * - not a second time in one context epoch (`releasedAt`): a body the seat
 *   loaded again after a release is held until the next compaction, so history
 *   is not rewritten back and forth for one note (never toggle). At a compaction
 *   the prefix is rewritten anyway, so that rule does not apply there.
 * Every body the plan releases is released in the same boundary: one edit of
 * the history, however many bodies.
 */
export function planRelease(input: {
  held: readonly SkillLoad[];
  /** The turn that is ending: turns finished, this one included. */
  turn: number;
  effective: EffectiveRelease;
  trigger: ReleaseTrigger;
  releasedAt: (key: string) => number | undefined;
}): ReleasePlan {
  const plan: ReleasePlan = { release: [], keep: [] };
  for (const load of input.held) {
    const keep = (why: string) => plan.keep.push({ load, why });
    if (!load.done) keep("not marked done");
    else if (input.effective === "off") keep("release is off");
    else if (input.trigger === "turn_end" && input.effective !== "boundary") keep("this model's bodies leave at a compaction only");
    else if (load.turn >= input.turn) keep("no turn has read it yet");
    else if (input.trigger === "turn_end" && input.releasedAt(load.key) !== undefined) keep("released once already in this context");
    else plan.release.push(load);
  }
  return plan;
}

// ---------------------------------------------------------------------------
// What a compaction's summary is told of the notes a seat read
// ---------------------------------------------------------------------------

type MessageLike = { role?: string; toolName?: string; toolCallId?: string; details?: Record<string, unknown>; content?: unknown };

/** One note a seat read, as the summary input and the hand-off header list it: ids and sizes, never text. */
export type SkillRead = { key: string; id: string; pack: string; tokens: number; turn: number; done: boolean; released: boolean };

function textOfContent(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((b) => (b && typeof b === "object" && (b as { type?: string }).type === "text" ? String((b as { text?: string }).text ?? "") : "")).join("");
}

/**
 * The part of a conversation a compaction is going to summarise, with every
 * skill body in it replaced by one line that names the note and its size (a
 * body the unloader already released is a stub and stays one), and the list of
 * notes read. Pi serialises each tool result for the summariser cut to 2,000
 * characters; a note's first 2,000 characters are method, not case facts, and
 * not what the summary should be written from. The messages are not changed in
 * place: the session keeps the whole result.
 */
export function shapeForSummary(messages: readonly unknown[]): { messages: unknown[]; reads: SkillRead[] } {
  const reads = new Map<string, SkillRead>();
  const shaped = messages.map((raw) => {
    const m = raw as MessageLike | null;
    if (m?.role !== "toolResult" || m.toolName !== "skill") return raw;
    const d = m.details ?? {};
    if (d.ok !== true) return raw;
    if (d.index === true) {
      const turn = typeof d.turn === "number" ? d.turn : 0;
      return { ...m, content: [{ type: "text", text: `[the skill index was listed at turn ${turn}; it is not part of this summary input]` }] };
    }
    if (d.already_loaded === true || typeof d.id !== "string" || typeof d.pack !== "string") return raw;
    const key = SkillLedger.key(d.pack, d.id);
    const tokens = typeof d.tokens === "number" ? d.tokens : 0;
    const turn = typeof d.turn === "number" ? d.turn : 0;
    const released = isStub(textOfContent(m.content));
    reads.set(typeof m.toolCallId === "string" ? m.toolCallId : `${key}@${turn}`, { key, id: d.id, pack: d.pack, tokens, turn, done: released, released });
    if (released) return raw;
    return { ...m, content: [{ type: "text", text: `[note ${key}: ${tokens} tokens, read at turn ${turn}; its text is not part of this summary input]` }] };
  });
  // A skill_done result marks the latest read of that note it follows.
  const order = [...reads.values()];
  for (const raw of messages) {
    const m = raw as MessageLike | null;
    if (m?.role !== "toolResult" || m.toolName !== "skill_done" || m.details?.ok !== true) continue;
    const d = m.details;
    if (typeof d.id !== "string" || typeof d.pack !== "string") continue;
    const key = SkillLedger.key(d.pack, d.id);
    const open = [...order].reverse().find((r) => r.key === key && !r.done);
    if (open) open.done = true;
  }
  return { messages: shaped, reads: order };
}

/** The block the summary call is given beside the conversation. Facts only; the summary prompt says what to do with them. */
export function renderSkillsRead(reads: readonly SkillRead[]): string {
  if (!reads.length) return "";
  const lines = [
    "<skills-read>",
    "Method notes this agent read in the conversation above. Only their ids and sizes are here, never their text:",
  ];
  for (const r of reads) {
    lines.push(`- ${r.key}: ${r.tokens} tokens, read at turn ${r.turn}, ${r.released ? "marked done and released from its context" : r.done ? "marked done" : "not marked done"}`);
  }
  const open = reads.filter((r) => !r.done);
  if (open.length) lines.push(`Not marked done (probably still needed after the compaction): ${[...new Set(open.map((r) => r.key))].join(", ")}.`);
  lines.push("</skills-read>");
  return lines.join("\n");
}

/**
 * The hand-off header's account of the notes the seat read before a compaction:
 * the ones it took out, the ones the unloader had replaced by a stub, the ones
 * still in the context, each with its size and whether the seat marked it done,
 * and which are probably still needed. Empty when the compaction took nothing a
 * seat had read.
 */
export function renderHandoffReads(account: { lost: readonly SkillLoad[]; kept: readonly SkillLoad[]; released: ReadonlyArray<SkillLoad & { releasedTurn: number }> }): string {
  if (!account.lost.length && !account.released.length) return "";
  const parts: string[] = [];
  for (const l of account.lost) parts.push(`${l.key} ${l.tokens} (${l.done ? "marked done" : "not marked done"})`);
  for (const l of account.released) parts.push(`${l.key} ${l.tokens} (marked done, released)`);
  for (const l of account.kept) parts.push(`${l.key} ${l.tokens} (${l.done ? "marked done; " : ""}still in your context)`);
  const lines = [`Method notes you read since your last compaction, with their size in tokens (never their text): ${parts.join(", ")}.`];
  const needed = [...new Set(account.lost.filter((l) => !l.done).map((l) => l.key))];
  if (needed.length) lines.push(`Not marked done, so probably still needed: ${needed.join(", ")}.`);
  return lines.join("\n");
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
  /** `--skill-release` as the kickoff passed it (`SWARM_SKILL_RELEASE`): auto, compaction or off. Anything else is auto, and the policy row says so. */
  release?: string;
  /** True while a hand-off compaction is about to run (the seat saved its note): the prefix is rewritten anyway, so finished bodies leave with it. */
  compactionPending?: () => boolean;
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
  /**
   * The part of the conversation a compaction is going to summarise, shaped for
   * the summary call: every skill body in it is one line naming the note and its
   * size, and `block` lists the notes read (ids and sizes, with whether each was
   * marked done). Unchanged, with an empty block, when the release policy is off.
   */
  summaryInput: (history: readonly unknown[], turnPrefix: readonly unknown[]) => { history: unknown[]; turnPrefix: unknown[]; block: string };
  ledger: SkillLedger;
};

/** Where the seat's prompt got the index from: Pi's own prompt (the kickoff's file), the extension (that run only), or nowhere. */
export type IndexSource = "prompt" | "stale" | "extension" | "none";

function text(value: string, details: Record<string, unknown>) {
  return { content: [{ type: "text" as const, text: value }], details };
}

export function registerSkills(pi: ExtensionAPI, deps: SkillsDeps): SkillsHandle {
  const ledger = new SkillLedger();
  const requestedRelease = parseReleaseMode(deps.release);
  const releaseMode: ReleaseMode = requestedRelease ?? DEFAULT_RELEASE_MODE;
  /** The policy row is written when this changes: the model, the thinking level, what they come to. */
  let policyKey = "";
  /** Releases whose edit the session has not been seen to hold yet: checked at the next boundary. */
  let unverified: Array<{ load: SkillLoad; entryId: string; turn: number; reason: string }> = [];
  /** Bodies whose edit did not land in this context epoch: not tried again until a compaction. */
  const unreleasable = new Set<string>();
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
    if (releaseMode !== "off") {
      const account = renderHandoffReads(ledger.compactionAccount());
      if (account) lines.push(account);
    }
    // A prompt the extension had to add the index to loses it with the run a hand-off starts: it comes back here.
    if (sectionText && (source === "extension" || source === "stale")) lines.push(`The index of this run's packs (your prompt no longer carries it):\n${sectionText}`);
    return lines.join("\n");
  }

  pi.on("session_start", async (_event, ctx) => {
    try {
      const inContext = loadsFromEntries(ctx.sessionManager.buildContextEntries());
      ledger.restore(inContext.loads, inContext.indexTurn, inContext.released);
      deps.restoreTurns?.(assistantTurns(ctx.sessionManager.getBranch()));
    } catch {
      // a session that cannot be read starts with an empty ledger: a body is sent once more, nothing worse
    }
  });

  pi.on("session_compact", async (_event, ctx) => {
    let result: { kept: SkillLoad[]; lost: SkillLoad[] };
    try {
      const inContext = loadsFromEntries(ctx.sessionManager.buildContextEntries());
      result = ledger.reconcile(inContext.loads, inContext.indexTurn, inContext.released);
    } catch {
      result = { kept: [], lost: ledger.onCompaction() };
    }
    // A compaction rebuilt the ledger from the session: what was waiting to be checked is settled by it.
    unverified = [];
    unreleasable.clear();
    const stubbed = ledger.compactionAccount().released;
    if (result.kept.length || result.lost.length || stubbed.length) {
      const ref = (l: SkillLoad) => ({ key: l.key, turn: l.turn });
      await deps
        .trace(ctx.cwd, "skills_compacted", {}, { ok: true, kept: result.kept.map(ref), lost: result.lost.map(ref), ...(stubbed.length ? { released: stubbed.map(ref) } : {}) })
        .catch(() => undefined);
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
    const releasedTurn = ledger.releasedAt(key);
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
        ...(releasedTurn !== undefined ? { reload_after_release: true, released_turn: releasedTurn } : {}),
        ...(working.length >= MAX_LIVE_SKILLS ? { holding: working.length } : {}),
        call: toolCallId,
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
      // A note this seat finished with and the harness already released is not "unknown": it says so.
      const gone = wanted && reason === "not loaded" ? ledger.releasedLoads().find((l) => l.id === wanted.id && (!wanted.pack || l.pack === wanted.pack)) : undefined;
      await deps.trace(cwd, "skill_done", { id: raw, ...(note ? { note } : {}) }, { ok: false, error: reason, turn, ...(gone ? { released: true } : {}) }, Date.now() - started);
      const out =
        reason === "ambiguous"
          ? `More than one pack's \`${raw}\` is loaded: name it as pack:id (${held.map((l) => l.key).join(", ")}).`
          : gone
            ? `\`${raw}\` was already marked done and has been released from your context (a one-line stub stands in its place); skill("${raw}") loads it again. Nothing to mark done.`
            : `\`${raw}\` is not among the notes you have loaded (none, a compaction took it out of your context, or it was released). Nothing to mark done.`;
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

  // -------------------------------------------------------------------------
  // The unloader: a finished body is replaced by a stub at a turn boundary
  // -------------------------------------------------------------------------

  type BoundaryCtx = {
    cwd: string;
    model?: ModelFacts;
    thinkingLevel?: string;
    sessionManager: { buildContextEntries: () => unknown[] };
  };
  type BoundaryEvent = { entries?: SessionBoundaryDraft[]; outcome?: string; context?: { contextEntries?: readonly unknown[] } };

  /** What the policy comes to for this seat now, and the one trace row that says so whenever it changes. */
  async function settlePolicy(ctx: BoundaryCtx): Promise<{ effective: EffectiveRelease; cls: ReleaseClass }> {
    let level: string | undefined;
    try {
      level = ctx.thinkingLevel;
    } catch {
      level = undefined;
    }
    const model = ctx.model;
    const { cls, why } = releaseClassOf(model, level);
    const effective = effectiveRelease(releaseMode, cls);
    const name = model ? `${model.provider ?? "?"}/${model.id ?? "?"}` : null;
    const key = [releaseMode, effective, cls, model?.api ?? "", name ?? "", level ?? ""].join("|");
    if (key !== policyKey) {
      policyKey = key;
      await deps
        .trace(
          ctx.cwd,
          "skill_release_policy",
          {},
          {
            ok: deps.release === undefined || requestedRelease !== null,
            mode: releaseMode,
            ...(deps.release !== undefined && requestedRelease === null ? { requested: deps.release } : {}),
            effective,
            class: cls,
            why,
            model: name,
            api: model?.api ?? null,
            reasoning: model?.reasoning ?? null,
            thinking_level: level ?? null,
          },
        )
        .catch(() => undefined);
    }
    return { effective, cls };
  }

  /**
   * The releases of the last boundary, checked against the session: a draft Pi
   * did not commit (an older Pi, or a boundary another extension's invalid
   * draft cancelled) leaves the body in the context, and the ledger and the trace
   * must not say otherwise. The body is held again, said on the trace, and not
   * tried again until a compaction.
   */
  async function verifyReleases(ctx: BoundaryCtx): Promise<void> {
    if (!unverified.length) return;
    const pending = unverified;
    unverified = [];
    let entries: unknown[];
    try {
      entries = ctx.sessionManager.buildContextEntries();
    } catch {
      return;
    }
    const edited = new Set(entries.map((e) => e as { type?: string; targetId?: string }).filter((e) => e.type === "context_edit").map((e) => e.targetId));
    for (const p of pending) {
      if (edited.has(p.entryId)) continue;
      if (ledger.unrelease(p.load.key, p.turn)) unreleasable.add(p.load.key);
      await deps
        .trace(ctx.cwd, "skill_unload", { id: p.load.id }, { ok: false, error: "the edit was not committed; the body is still in the context", pack: p.load.pack, call: p.load.toolCallId, entry: p.entryId, reason: p.reason, turn: p.turn })
        .catch(() => undefined);
    }
  }

  /**
   * At the end of a turn: replace every body the seat finished with, and the
   * policy lets go, by a stub; all of them in this one return, so the history
   * is rewritten once however many bodies leave. The result is a `context_edit`
   * draft per body (Pi appends them before it builds the next request); the
   * session keeps the raw tool result. The ledger is told only for the bodies
   * the session shows are in the context and not yet edited: it is read off the
   * session here, as at a compaction, so a stale ledger cannot aim an edit at
   * an entry that is gone.
   */
  async function releaseAtBoundary(event: BoundaryEvent, ctx: BoundaryCtx): Promise<{ entries: SessionBoundaryDraft[] } | undefined> {
    await verifyReleases(ctx);
    const policy = await settlePolicy(ctx);
    if (policy.effective === "off") return undefined;
    if (event.outcome !== undefined && event.outcome !== "completed") return undefined;
    if (!ledger.releasable().length) return undefined;
    const turn = deps.turns();
    // A seat that saved its hand-off note is about to compact: the prefix is rewritten anyway, so this is the free moment.
    const compacting = deps.compactionPending?.() === true;
    const trigger: ReleaseTrigger = compacting ? "compaction" : "turn_end";
    const plan = planRelease({ held: ledger.held().filter((l) => !unreleasable.has(l.key)), turn, effective: policy.effective, trigger, releasedAt: (key) => ledger.releasedAt(key) });
    if (!plan.release.length) return undefined;

    let inContext: ReturnType<typeof loadsFromEntries>;
    try {
      inContext = loadsFromEntries(ctx.sessionManager.buildContextEntries());
    } catch {
      return undefined;
    }
    const colliding = collidingIds(await packIndexes());
    const reason = trigger === "compaction" ? "compaction" : "done";
    const drafts: SessionBoundaryDraft[] = [];
    const rows: Array<{ load: SkillLoad; entryId: string; stub: string }> = [];
    for (const load of plan.release) {
      const hit = inContext.loads.find((l) => l.key === load.key && l.toolCallId === load.toolCallId && l.entryId !== undefined);
      if (!hit) {
        // The ledger holds a body the session no longer shows in the context (a compaction took it, or someone else edited it).
        ledger.drop(load.key);
        await deps.trace(ctx.cwd, "skill_unload", { id: load.id }, { ok: false, error: "not in the context", pack: load.pack, call: load.toolCallId, reason, turn }).catch(() => undefined);
        continue;
      }
      const stub = stubText(colliding.has(load.id) ? load.key : load.id, load.tokens);
      drafts.push({ type: "context_edit", targetId: hit.entryId!, replacement: { content: [{ type: "text", text: stub }] } });
      rows.push({ load, entryId: hit.entryId!, stub });
    }
    if (!drafts.length) return undefined;
    for (const { load, entryId, stub } of rows) {
      ledger.release(load.key, { turn, reason });
      unverified.push({ load, entryId, turn, reason });
      await deps
        .trace(
          ctx.cwd,
          "skill_unload",
          { id: load.id },
          {
            ok: true,
            pack: load.pack,
            sha256: load.sha256,
            tokens: load.tokens,
            call: load.toolCallId,
            entry: entryId,
            reason,
            turn,
            loaded_turn: load.turn,
            done_turn: load.done?.turn ?? null,
            held_turns: turn - load.turn,
            batch: rows.length,
            stub_tokens: estimateTokens(stub),
            suffix_tokens: suffixTokens(event.context?.contextEntries ?? [], entryId),
            policy: releaseMode,
            class: policy.cls,
          },
        )
        .catch(() => undefined);
    }
    return { entries: [...(event.entries ?? []), ...drafts] };
  }

  pi.on("turn_end", async (event, ctx) => {
    try {
      return await releaseAtBoundary(event as unknown as BoundaryEvent, ctx as unknown as BoundaryCtx);
    } catch {
      // a release that cannot be made leaves the body where it is: nothing worse than before the unloader
      return undefined;
    }
  });

  function summaryInput(history: readonly unknown[], turnPrefix: readonly unknown[]): { history: unknown[]; turnPrefix: unknown[]; block: string } {
    if (releaseMode === "off") return { history: [...history], turnPrefix: [...turnPrefix], block: "" };
    const shaped = shapeForSummary([...history, ...turnPrefix]);
    return { history: shaped.messages.slice(0, history.length), turnPrefix: shaped.messages.slice(history.length), block: renderSkillsRead(shaped.reads) };
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

  return { promptSection, handoffLine, summaryInput, ledger };
}
