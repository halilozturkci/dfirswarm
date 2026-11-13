#!/usr/bin/env node
/**
 * What enters a run after its kickoff, from outside the evidence it was
 * given (docs/adr/0014): evidence acquired later (`swarm.sh evidence <run>
 * add`) and material the operator supplies (`swarm.sh material <run> add`,
 * and a question's attachment given as a file).
 *
 * Both go the store's import path: the file (or directory) is copied into a
 * staging directory of this addition's own, outside the run, each copy held
 * to its source's sha256; an import id is reserved (a directory made once,
 * which no other addition can make again); the copy is sealed as
 * `store/imports/<id>/` (read-only, every file in a manifest that must name
 * exactly the files copied, the bytes kept once in the store's blobs), and
 * the addition is committed by its record (`material.json`, the reason whole)
 * and its line on the store journal, taken one addition at a time under the
 * run's material lock, across processes.
 *
 * What it can be read as: every seat's VM mounts the run's directory
 * read-only, live, so once sealed the files are there at once, at
 * store/imports/<id>/out/, as they are to a host run's panes; jobs read them
 * as `import:<id>/<path>`. A finding cites them as import:<id>/<file> however
 * they were read; what they are (their class, who supplied them, when, what
 * they may be used for) is the ledger's external entry, never the path a
 * seat happened to read them by.
 *
 * What follows from a committed addition is derived from its record, each
 * step once and found again by the addition's id (the transactional outbox):
 * its external entry on the ledger (kind `external`, with its provenance
 * {supplied_by, at, from, sha256, permitted_use}; `acquired_evidence` for
 * evidence, `operator_supplied` or `case_material` for material; what each
 * class may be used for is the case policy's `material_use`); an
 * acquisition's received and validated stages (`--for R-n`, validated
 * against the sha256 the copy was held to); the closed leads resting on the
 * evidence as it was (under its questions, resolved through the question
 * register, and the request's own lead) reopened; the answers recorded
 * before it made stale and the acceptances made before it lifted; the
 * reverse sweep of its files for every standing coverage record's
 * looked_for strings started once it is committed, never inside it
 * (extensions/store-sweep.ts: a pass at a time in the hub's background or a
 * detached step, its hits delivered on the board and to the questions they
 * bear on, holding nothing); the catalogue queued when the
 * run's is on; the board told. The journal's
 * `addition_applied` line says all of it is recorded. A process that dies
 * after the commit leaves the rest to the next reconciliation (the hub's
 * round, the next addition, `swarm.sh evidence <run> list`), and the finish
 * line refuses a done while an addition's effects are not all recorded.
 *
 * A tool is material too (`swarm.sh tool-supply <run> add`): a program no image
 * holds, handed to a running run by the operator with what the harness cannot
 * know and the seats need to weigh it by: where it came from, how it was built
 * (both the operator's statement, recorded as such), and hashes the operator
 * checked, which the harness does check against the bytes it seals (a hash of
 * anything else goes in the words). It is sealed as `operator_supplied`, never
 * as evidence; its ledger entry carries that provenance in the chained core
 * (`provenance.tool`) and the board post tells the seats that a sealed file has
 * no execute bit and how to run it (a copy in an executable temporary directory
 * inside a job). The case policy's rules are the material's own: a policy that
 * says `operator_supplied=none` refuses it, because nothing recorded on its
 * output could be kept. The harness names no program and knows no format: the
 * file is whatever the operator says it is.
 *
 * Evidence is an inventory revision: its journal line counts it
 * (`inventory_rev`), and the negative bar's inventory revision moves with
 * it. Under the case policy's `more_evidence: no` it is refused: the case
 * admits no evidence after its kickoff.
 *
 * While the run's hub runs it is the store journal's one writer, so the act
 * is handed to it on its admin socket; with no hub the act is made here.
 *
 *   material.ts evidence-add <sandbox> PATH --why W [--for R-n] [--question Q-n]...
 *        [--sha256 HEX] [--as ID] [--via cli|console] [--hub-admin SOCKET]
 *   material.ts material-add <sandbox> PATH --why W [--class operator_supplied|case_material]
 *        [--sensitive] [--as ID] [--via cli|console] [--hub-admin SOCKET]
 *   material.ts tool-add <sandbox> PATH --why W --source TEXT [--built TEXT] [--sha256 HEX]...
 *        [--for R-n|L-n]... [--as ID] [--via cli|console] [--hub-admin SOCKET]
 *   material.ts list <sandbox> [--json] [--hub-admin SOCKET]
 *
 * Prints one JSON line.
 */
import { createHash } from "node:crypto";
import { createReadStream, existsSync } from "node:fs";
import { chmod, copyFile, lstat, mkdir, mkdtemp, readdir, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import * as R from "../extensions/requests.ts";
import * as SW from "../extensions/store-sweep.ts";
import { permittedUse, readCasePolicy, type SourceClass } from "./case-policy.ts";
import { Journal, sealTree, storePaths, type JournalLine } from "./evidence-store.ts";

export type MaterialMode = "evidence" | "material";

/** What the operator says of a tool they supply (swarm.sh tool-supply). */
export type ToolSupply = {
  /** Where it came from, in words: a package and its version, a URL, who built it. Required, never cut. */
  source: string;
  /** How it was built or made fit for the run, in words; none when it is used as published. */
  built?: string;
  /** Hashes the operator checked: each must be one of the supplied files' sha256, and is held to it. */
  sha256?: string[];
  /** The requests (R-n) and leads (L-n) it was supplied for. */
  for?: string[];
};

/** A tool as its record keeps it: the statements whole, the hashes checked against the sealed bytes, the requests and leads (a request's own lead beside it). */
export type ToolProvenance = { source: string; built?: string; checked: string[]; for?: string[] };

/** The longest reason or statement an operator gives (--why, --source, --built): longer is refused, never cut. */
export const TEXT_MAX = 4000;

export type MaterialRequest = {
  mode: MaterialMode;
  /** The host path: a file or a directory, outside the run. */
  path: string;
  why: string;
  /** Evidence: the acquisition request it answers (R-<n>). */
  for?: string;
  /** Evidence: the questions it bears on, beside the request's. */
  questions?: string[];
  /** Evidence: an acquisition hash of the one file given, held against the copy. */
  sha256?: string;
  /** Material: its class (operator_supplied by default, or case_material). */
  cls?: "operator_supplied" | "case_material";
  /** Material: what it says is sensitive (names, labels and questions may not carry it). */
  sensitive?: boolean;
  /** Material: a tool supplied to be run (always operator_supplied): what the operator says of it. */
  tool?: ToolSupply;
  /** Who supplied it, in words (an enrolled person as a claim, or the OS account on this host). */
  supplied_by: string;
  via: string;
};

export type MaterialResult = Record<string, unknown> & { ok: boolean };

/** An addition as store/imports/<id>/material.json keeps it: what was added, why (whole), and the state of the run it was committed against. */
export type MaterialRecord = {
  v: 1 | 2;
  import: string;
  mode: MaterialMode;
  class: SourceClass;
  at: string;
  supplied_by: string;
  via: string;
  from: string;
  why: string;
  files: Array<{ path: string; sha256: string; bytes: number }>;
  manifest_sha256: string;
  permitted_use: string;
  request?: string;
  questions?: string[];
  inventory_rev?: number;
  sensitive?: boolean;
  /** A tool supplied to be run (swarm.sh tool-supply): where it came from, how it was built, the hashes checked, what for. */
  tool?: ToolProvenance;
  /** The ledger's last entry when the addition was committed: the answers up to it were recorded without it. */
  ledger_seq?: number;
  /** The lead register's length when it was committed: a close up to it was made without it. */
  lead_seq?: number;
};

/** The run's lock for additions: one commit (and what follows from it) at a time, across processes. */
export const MATERIAL_LOCK = "material";

type AdditionOptions = {
  journal?: Journal;
  catalogue?: (target: string, note: string) => Promise<{ ok: boolean; job?: string; reason?: string }>;
  catalogueOn?: boolean;
  /** A reverse sweep pass's budget, when not the environment's (tests). */
  sweepBudget?: { maxBytes?: number; maxMs?: number };
  /**
   * Where the reverse sweep runs once the addition is committed, never
   * inside it: in this process's background (the hub, which goes on), or as
   * a detached step (the CLI, which exits once it has answered).
   */
  reverse?: "background" | "detached";
};

const sha256Of = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

async function fileSha(path: string): Promise<string> {
  const h = createHash("sha256");
  await new Promise<void>((ok, fail) => {
    createReadStream(path).on("data", (c) => h.update(c)).on("end", () => ok()).on("error", fail);
  });
  return h.digest("hex");
}

function within(child: string, parent: string): boolean {
  const r = relative(parent, child);
  return r === "" || (!r.startsWith("..") && !r.startsWith(sep));
}

/**
 * An import id with this prefix (ev-0001, mat-0001), reserved: its
 * directory made once, which fails for every other addition that picks the
 * same number, in this process or another; the next number is tried then.
 */
async function reserveImportId(S: string, prefix: "ev" | "mat"): Promise<string> {
  const dir = storePaths(S).imports;
  await mkdir(dir, { recursive: true });
  const names = await readdir(dir).catch(() => [] as string[]);
  let n = Math.max(0, ...names.map((x) => Number(new RegExp(`^${prefix}-(\\d{4,})$`).exec(x)?.[1] ?? 0))) + 1;
  for (;;) {
    const id = `${prefix}-${String(n).padStart(4, "0")}`;
    try {
      await mkdir(join(dir, id));
      return id;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      n += 1;
    }
  }
}

type Walked = { rel: string; abs: string; bytes: number };

/**
 * Every regular file under a path, by lstat: a link inside (never followed)
 * or anything but a file or a directory is named and refused. A link given
 * as the path itself is the operator's, and is followed once, as --inputs
 * follows one.
 */
async function walkSource(root: string): Promise<{ ok: true; top: "file" | "dir"; files: Walked[] } | { ok: false; reason: string }> {
  let real: string;
  try {
    real = await realpath(root);
  } catch {
    return { ok: false, reason: `${root} does not exist` };
  }
  const st = await stat(real);
  if (st.isFile()) return { ok: true, top: "file", files: [{ rel: basename(root), abs: real, bytes: st.size }] };
  if (!st.isDirectory()) return { ok: false, reason: `${root} is neither a file nor a directory` };
  const files: Walked[] = [];
  const refused: string[] = [];
  const visit = async (dir: string, rel: string): Promise<void> => {
    for (const d of await readdir(dir, { withFileTypes: true })) {
      const abs = join(dir, d.name);
      const r = rel ? `${rel}/${d.name}` : d.name;
      if (d.isSymbolicLink()) refused.push(`${r} (a link)`);
      else if (d.isDirectory()) await visit(abs, r);
      else if (d.isFile()) files.push({ rel: r, abs, bytes: (await lstat(abs)).size });
      else refused.push(`${r} (not a regular file)`);
    }
  };
  await visit(real, "");
  if (refused.length) return { ok: false, reason: `${root} holds what is not a regular file: ${refused.join(", ")}; give the files themselves` };
  if (!files.length) return { ok: false, reason: `${root} holds no file` };
  return { ok: true, top: "dir", files };
}

/** The store journal's lines, read without opening it for writing: what was committed, and what of it was applied. */
async function journalLines(S: string): Promise<JournalLine[]> {
  const text = await readFile(storePaths(S).journal, "utf8").catch(() => "");
  const out: JournalLine[] = [];
  for (const l of text.split("\n")) {
    if (!l.trim()) continue;
    try {
      out.push(JSON.parse(l) as JournalLine);
    } catch {
      // a torn last line: the journal's own check names it
    }
  }
  return out;
}

const ADDED = new Set(["evidence_added", "material_added"]);

/** The additions committed (on the store journal) whose effects are not all recorded yet, oldest first. */
export async function unappliedAdditions(sandbox: string): Promise<Array<{ import: string; type: string; by: string; at: string }>> {
  const lines = await journalLines(resolve(sandbox));
  const applied = new Set(lines.filter((l) => l.type === "addition_applied").map((l) => String(l.import)));
  return lines.filter((l) => ADDED.has(l.type) && !applied.has(String(l.import))).map((l) => ({ import: String(l.import), type: l.type, by: String(l.by ?? ""), at: l.at }));
}

/**
 * The material a run holds: each import with its record, oldest first;
 * `committed` when the store journal names it, `applied` when everything
 * that follows from it is recorded. An id reserved by an addition that never
 * committed (it failed, or its process died first) is named as such.
 */
export async function listMaterial(S: string): Promise<Array<Record<string, unknown>>> {
  const out: Array<Record<string, unknown>> = [];
  const dir = storePaths(S).imports;
  const lines = await journalLines(S);
  const committed = new Set(lines.filter((l) => ADDED.has(l.type)).map((l) => String(l.import)));
  const applied = new Set(lines.filter((l) => l.type === "addition_applied").map((l) => String(l.import)));
  for (const id of (await readdir(dir).catch(() => [] as string[])).sort()) {
    if (!/^(ev|mat)-\d{4,}$/.test(id)) continue;
    if (!committed.has(id)) {
      out.push({ import: id, committed: false, note: "reserved by an addition that never committed: no store journal line names it, and nothing cites it" });
      continue;
    }
    try {
      out.push({ ...(JSON.parse(await readFile(join(dir, id, "material.json"), "utf8")) as Record<string, unknown>), committed: true, applied: applied.has(id) });
    } catch {
      out.push({ import: id, unreadable: true, committed: true, applied: applied.has(id) });
    }
  }
  return out;
}

/** A question as the register names it (Q-3), from whatever an addition, a request or a lead calls it (Q-3, 3, question:3, a custom section such as bonus). */
function canonicalQuestion(qs: Q.QuestionsSnapshot | null, raw: string): string {
  const q = qs ? Q.findQuestion(qs, raw) : null;
  return q?.id ?? R.questionId(raw);
}

/** Why a path cannot be added to the run: it is inside the run (cited as it is, never added again) or holds it (the run, and every run beside it, would be copied); null when it is neither. */
export async function runPathRefusal(S: string, src: string, shown: string): Promise<string | null> {
  const realSrc = await realpath(src).catch(() => src);
  const realS = await realpath(S).catch(() => S);
  if (within(src, S) || within(realSrc, realS)) return `${shown} is inside the run: what is in the run is cited as it is (input:, job:, import:), never added again`;
  if (within(S, src) || within(realS, realSrc)) return `${shown} holds the run (${S}): adding it would copy the run, and every run beside it if it is the runs directory; give the files themselves`;
  return null;
}

/**
 * What the operator says of a tool they supply, held before anything is
 * copied and without reading the registers (the CLI holds it too, before it
 * hands the act to a hub that may be older than this checkout): it is
 * material (never evidence added later) of the class the operator supplies,
 * the policy must let a record rest on that class, it says where it came
 * from, what it says is not cut, and the hashes are hashes. The words are the
 * operator's statement and are recorded as such; only the hashes are checked
 * against the bytes.
 */
export function checkToolStatements(req: MaterialRequest, policy: ReturnType<typeof readCasePolicy>): { ok: true; source: string; built?: string; hashes: string[] } | { ok: false; reason: string } {
  const t = req.tool!;
  if (req.mode !== "material") return { ok: false, reason: "a tool is supplied as material (swarm.sh tool-supply), never as evidence added after the kickoff" };
  if (req.cls !== undefined && req.cls !== "operator_supplied") return { ok: false, reason: "a tool is operator-supplied material: --class is not for it" };
  if (policy.material_use.operator_supplied === "none") {
    return { ok: false, reason: `case policy ${policy.policy} does not let a record cite or rest on material of class operator_supplied (material_use operator_supplied=none): a tool supplied under it could be run but nothing recorded on its output could be kept; nothing was added` };
  }
  const source = String(t.source ?? "").trim();
  if (!source) return { ok: false, reason: "tool supply says where the tool came from (--source): a package and its version, a URL, who built it" };
  if (source.length > TEXT_MAX) return { ok: false, reason: `--source is at most ${TEXT_MAX} characters: nothing is cut, so a longer one is refused` };
  const built = t.built === undefined ? "" : String(t.built).trim();
  if (built.length > TEXT_MAX) return { ok: false, reason: `--built is at most ${TEXT_MAX} characters: nothing is cut, so a longer one is refused` };
  const hashes: string[] = [];
  for (const raw of t.sha256 ?? []) {
    const h = String(raw).trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(h)) return { ok: false, reason: `--sha256 is a file's sha256, 64 hex characters (got ${JSON.stringify(raw)})` };
    if (!hashes.includes(h)) hashes.push(h);
  }
  return { ok: true, source, ...(built ? { built } : {}), hashes };
}

/** The first hash given that is none of the files' sha256, said with every file's; null when each is one of them. */
export function strayHash(hashes: string[], files: Array<{ path: string; sha256: string }>): string | null {
  const stray = hashes.find((h) => !files.some((f) => f.sha256 === h));
  return stray ? `the hash ${stray} is none of the supplied files' sha256 (${files.map((f) => `${f.path} is ${f.sha256}`).join("; ")}): a hash of anything else, a source archive or a signed index, goes in --source or --built; nothing was added` : null;
}

/** The hidden files and directories (a name beginning with a dot) among the files of a supplied directory, in the way they are said: a .env, a .git/config, a .netrc go with a directory sealed whole. */
export function hiddenIn(files: Array<{ rel: string }>): string[] {
  return files.filter((f) => f.rel.split("/").some((c) => c.startsWith("."))).map((f) => f.rel);
}

/** The requests (R-n) and leads (L-n) a tool is for, each read from its register: the ids as named, a request's own lead beside it. */
async function readToolFor(S: string, ids: string[] | undefined): Promise<{ ok: true; for: string[] } | { ok: false; reason: string }> {
  const forWhat: string[] = [];
  const add = (id: string) => {
    if (!forWhat.includes(id)) forWhat.push(id);
  };
  for (const raw of ids ?? []) {
    const m = /^([RL])-?([1-9]\d{0,6})$/i.exec(String(raw).trim());
    if (!m) return { ok: false, reason: `--for names a request or a lead, R-<n> or L-<n> (got ${JSON.stringify(raw)})` };
    const id = `${m[1]!.toUpperCase()}-${Number(m[2])}`;
    if (id.startsWith("R-")) {
      await R.reconcileRequests(S).catch(() => undefined);
      const request = (await R.requestsSnapshot(S)).requests.get(id);
      if (!request) return { ok: false, reason: `${id} is not a request of this run (swarm.sh requests <run> list)` };
      add(id);
      if (request.lead) add(request.lead);
    } else {
      if (!(await L.leadsSnapshot(S)).state.leads.has(id)) return { ok: false, reason: `${id} is not a lead of this run (swarm.sh lead <run> list)` };
      add(id);
    }
  }
  return { ok: true, for: forWhat };
}

/**
 * The addition: checked, copied into a staging directory of its own and
 * held to its source, then, under the run's material lock, an id reserved,
 * sealed, committed (material.json, the store journal line) and what follows
 * from it applied (applyAddition). Refused before anything is committed when
 * it cannot be made whole. The hub passes its journal (it is the journal's
 * one writer) and its catalogue.
 */
export async function admitMaterial(sandbox: string, req: MaterialRequest, o: AdditionOptions = {}): Promise<MaterialResult> {
  const S = resolve(sandbox);
  if (req.mode !== "evidence" && req.mode !== "material") return { ok: false, reason: "an addition is evidence or material" };
  const why = String(req.why ?? "").trim();
  if (!why) return { ok: false, reason: `${req.tool ? "tool supply" : req.mode === "evidence" ? "evidence add" : "material add"} says why (--why): what it is and what it is for` };
  if (why.length > TEXT_MAX) return { ok: false, reason: `--why is at most ${TEXT_MAX} characters: nothing is cut, so a longer one is refused` };
  const policy = readCasePolicy(S);
  const cls: SourceClass = req.mode === "evidence" ? "acquired_evidence" : (req.cls ?? "operator_supplied");
  if (req.mode === "material" && !["operator_supplied", "case_material"].includes(cls)) return { ok: false, reason: "--class is operator_supplied or case_material" };
  const stated = req.tool ? checkToolStatements(req, policy) : null;
  if (stated && !stated.ok) return stated;
  const toolFor = stated?.ok ? await readToolFor(S, req.tool!.for) : null;
  if (toolFor && !toolFor.ok) return toolFor;
  const tool = stated?.ok && toolFor?.ok ? { ...stated, for: toolFor.for } : null;
  if (req.mode === "evidence" && policy.more_evidence === "no") {
    return { ok: false, reason: `this case admits no evidence after its kickoff (case policy ${policy.policy}, more_evidence: no): nothing was added. An agent's acquisition is answered "${R.NO_MORE_EVIDENCE}"; a case that must take this evidence is a new run, or material supplied for reference (swarm.sh material <run> add)` };
  }
  const src = resolve(String(req.path ?? ""));
  if (!req.path) return { ok: false, reason: "name the file or directory to add" };
  const placed = await runPathRefusal(S, src, req.path);
  if (placed) return { ok: false, reason: placed };
  // The acquisition it answers, asked now and again under the lock.
  const requestRefusal = async (): Promise<{ request: R.OperatorRequest | null; reason?: string }> => {
    if (!req.for) return { request: null };
    if (req.mode !== "evidence") return { request: null, reason: "--for names the acquisition request evidence answers; material answers none" };
    const m = /^R-?([1-9]\d{0,6})$/i.exec(req.for.trim());
    if (!m) return { request: null, reason: `--for names a request, R-<n> (got ${JSON.stringify(req.for)})` };
    await R.reconcileRequests(S).catch(() => undefined);
    const request = (await R.requestsSnapshot(S)).requests.get(`R-${Number(m[1])}`) ?? null;
    if (!request) return { request: null, reason: `R-${Number(m[1])} is not a request of this run (swarm.sh requests <run> list)` };
    if (request.kind !== "acquisition") return { request, reason: `${request.rid} is a ${request.kind} request, not an acquisition: evidence answers an acquisition` };
    if (request.stage === "declined" || request.stage === "unavailable" || request.stage === "validated") return { request, reason: `${request.rid} is ${request.stage}${request.closed ? ` (${request.closed.text})` : ""}: add the evidence without --for, naming the questions it bears on (--question Q-n)` };
    return { request };
  };
  const first = await requestRefusal();
  if (first.reason) return { ok: false, reason: first.reason };
  const expected = req.sha256 ? String(req.sha256).trim().toLowerCase() : "";
  if (expected && !/^[0-9a-f]{64}$/.test(expected)) return { ok: false, reason: "--sha256 is the file's sha256, 64 hex characters" };
  const walked = await walkSource(src);
  if (!walked.ok) return walked;
  if (tool && walked.top === "dir") {
    const hidden = hiddenIn(walked.files);
    if (hidden.length) return { ok: false, reason: `${req.path} holds hidden files or directories (${hidden.join(", ")}): a directory supplied as a tool is sealed whole and every seat reads all of it, so a .env, a .git/config or a .netrc would go with it; remove them or give the files themselves; nothing was added` };
  }
  if (expected && walked.files.length !== 1) return { ok: false, reason: "--sha256 holds one file to its acquisition hash; a directory's files are each held to their own sha256 as they are copied" };
  const P_ = storePaths(S);
  // A staging directory of this addition's own: no other addition writes or removes it.
  await mkdir(P_.staging, { recursive: true });
  const staging = await mkdtemp(join(P_.staging, "addition-"));
  try {
    // Each file copied, then held to the sha256 its source had before the copy: a source that changed while it was copied is refused.
    const files: Array<{ path: string; sha256: string; bytes: number }> = [];
    try {
      for (const f of walked.files) {
        const before = await fileSha(f.abs);
        const dest = join(staging, f.rel);
        await mkdir(dirname(dest), { recursive: true });
        await copyFile(f.abs, dest);
        const copied = await fileSha(dest);
        if (copied !== before) return { ok: false, reason: `${f.rel} changed while it was copied (sha256 ${before} before, ${copied} as copied): add it again once it is still; nothing was added` };
        if (expected && copied !== expected) return { ok: false, reason: `${f.rel}'s sha256 is ${copied}, not the acquisition hash given (${expected}): nothing was added` };
        files.push({ path: f.rel, sha256: copied, bytes: f.bytes });
      }
    } catch (err) {
      return { ok: false, reason: `the copy failed (${(err as Error).message}): nothing was added` };
    }
    // A tool's hashes, each held to the files copied: the harness vouches for what it checked, and for nothing else.
    if (tool) {
      const stray = strayHash(tool.hashes, files);
      if (stray) return { ok: false, reason: stray };
    }
    let locked: MaterialResult;
    try {
      locked = await P.withNamedLock(S, MATERIAL_LOCK, async (): Promise<MaterialResult> => {
        // The request, read again: another addition may have answered it while this one copied.
        const again = await requestRefusal();
        if (again.reason) return { ok: false, reason: again.reason };
        const request = again.request;
        const id = await reserveImportId(S, req.mode === "evidence" ? "ev" : "mat");
        const journal = o.journal ?? (await Journal.open(S));
        let sealed: Awaited<ReturnType<typeof sealTree>>;
        try {
          sealed = await sealTree(S, staging, join(P_.imports, id, "out"), id, 1, join(P_.imports, id, "manifest.json"));
        } catch (err) {
          return { ok: false, reason: `the copy could not be sealed (${(err as Error).message}): store/imports/${id} is kept for the record and cited by nothing; nothing was added` };
        }
        // The sealed copy, held again to what was copied, file for file: "validated" means these hashes, and nothing else is in it.
        const byPath = new Map(sealed.manifest.files.map((f) => [f.path, f.sha256]));
        const differ = files.filter((f) => byPath.get(f.path) !== f.sha256).map((f) => f.path);
        const extra = sealed.manifest.files.map((f) => f.path).filter((p) => !files.some((f) => f.path === p));
        if (differ.length || extra.length || sealed.manifest.rejected.length) {
          return { ok: false, reason: `the sealed copy is not what was copied (${[differ.length ? `${differ.join(", ")} do${differ.length === 1 ? "es" : ""} not hash as copied` : "", extra.length ? `${extra.join(", ")} ${extra.length === 1 ? "was" : "were"} not copied by this addition` : "", sealed.manifest.rejected.length ? `${sealed.manifest.rejected.length} path(s) refused by the seal` : ""].filter(Boolean).join("; ")}): store/imports/${id} is kept for the record and cited by nothing; nothing was added` };
        }
        const at = new Date().toISOString();
        const inventoryRev = req.mode === "evidence" ? journal.of("evidence_added").length + 1 : null;
        const qs = await Q.questionsSnapshot(S).catch(() => null);
        const questions = req.mode === "evidence" ? [...new Set([...(request?.questions ?? []), ...(req.questions ?? [])].map((q) => canonicalQuestion(qs, q)).filter(Boolean))] : [];
        // The hub says whether its catalogue is on; with no hub, a run with a job service catalogues it at the hub's next round (a resume).
        const catalogueOn = req.mode === "evidence" && (o.catalogueOn ?? existsSync(join(S, "store", "jobs")));
        const ledgerSeq = (await P.readLedger(S, { raw: true }).catch(() => [] as P.LedgerEntry[])).at(-1)?.seq ?? 0;
        const leadSeq = (await L.readLeadEvents(S).catch(() => ({ events: [] as L.LeadEvent[] }))).events.length;
        const record: MaterialRecord = {
          v: 2,
          import: id,
          mode: req.mode,
          class: cls,
          at,
          supplied_by: req.supplied_by,
          via: req.via,
          from: src,
          why,
          files,
          manifest_sha256: sealed.manifestSha256,
          permitted_use: permittedUse(policy, cls),
          ...(request ? { request: request.rid } : {}),
          ...(questions.length ? { questions } : {}),
          ...(inventoryRev !== null ? { inventory_rev: inventoryRev } : {}),
          ...(req.sensitive ? { sensitive: true } : {}),
          ...(tool ? { tool: { source: tool.source, ...(tool.built ? { built: tool.built } : {}), checked: tool.hashes, ...(tool.for.length ? { for: tool.for } : {}) } } : {}),
          ledger_seq: ledgerSeq,
          lead_seq: leadSeq,
        };
        const recordText = `${JSON.stringify(record, null, 2)}\n`;
        await writeFile(join(P_.imports, id, "material.json"), recordText, { mode: 0o444 });
        await chmod(join(P_.imports, id, "material.json"), 0o444).catch(() => undefined);
        // The commit.
        await journal.append({
          type: req.mode === "evidence" ? "evidence_added" : "material_added",
          import: id,
          class: cls,
          files,
          manifest_sha256: sealed.manifestSha256,
          material_json_sha256: sha256Of(recordText),
          by: req.supplied_by,
          why,
          ...(request ? { request: request.rid } : {}),
          ...(questions.length ? { questions } : {}),
          ledger_seq: ledgerSeq,
          lead_seq: leadSeq,
          ...(inventoryRev !== null ? { inventory_rev: inventoryRev, catalogue: !catalogueOn ? "off" : o.catalogue ? "queued" : "at the hub's next round" } : {}),
        });
        return applyAddition(S, id, { ...o, journal, catalogueOn });
      });
    } catch (err) {
      return { ok: false, reason: /Timed out waiting for locks/.test((err as Error).message) ? "another addition is being committed to this run: nothing was added; add it again in a moment" : `${(err as Error).message}: nothing was added` };
    }
    return locked;
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined);
  }
}

/**
 * The standing answers an addition leaves stale (the ledger gate's
 * evidenceStale, extensions/protocol.ts): every negative, not-determinable
 * or partial answer whose coverage predates the evidence's ledger entry,
 * whether or not the addition named its question. An established answer is
 * not staled.
 */
export async function answersStaledBy(sandbox: string, entrySeq: number | null): Promise<Array<{ section: string; answer: number; result: string; coverage: number[] }>> {
  if (entrySeq === null) return [];
  const entries = await P.readLedger(sandbox).catch(() => [] as P.LedgerEntry[]);
  const attestations = await P.readAttestations(sandbox).catch(() => [] as P.LedgerAttestation[]);
  const replaced = P.supersededBy(entries);
  const out: Array<{ section: string; answer: number; result: string; coverage: number[] }> = [];
  for (const e of entries) {
    if (e.kind !== "answer" || replaced.has(e.seq) || !e.section?.startsWith("question:")) continue;
    const st = P.evidenceStale(e, entries, attestations);
    if (!st || !st.additions.some((x) => x.seq === entrySeq)) continue;
    out.push({ section: e.section, answer: e.seq, result: e.result ?? (e.inconclusive ? "not_determinable" : ""), coverage: st.coverage });
  }
  return out;
}

/** The stale answers in words, for the board post and the operator's reply. */
export function staleAnswersWords(list: Array<{ section: string; answer: number; result: string; coverage: number[] }>): string {
  return list.map((x) => `${x.section} (E-${x.answer}, ${x.result.replace(/_/g, " ") || "no result stated"}${x.coverage.length ? `; coverage ${x.coverage.map((n) => `E-${n}`).join(", ")}` : ""})`).join("; ");
}

/** Words that name the reason given whole, or where it is kept whole when it would not fit: never a part of it. */
function withReason(head: string, why: string, max: number, id: string): string {
  const whole = `${head}: ${why}`;
  return whole.length <= max ? whole : `${head}; the reason given (${why.length} characters) is kept whole in store/imports/${id}/material.json and on the store journal`;
}

/**
 * What the seats are told of a tool supplied: what it is and what the
 * operator says of it (as their statement), what the harness checked, that it
 * is material and is weighed as such, and how to run it, since a sealed file
 * has no execute bit and no place a job can read it from executes.
 */
function toolPostBody(rec: MaterialRecord, tool: ToolProvenance, entry: number | null, use: string): string {
  const id = rec.import;
  const files = rec.files;
  const inputs = JSON.stringify([files.length === 1 ? `import:${id}/${files[0]!.path}` : `import:${id}`]);
  const cite = files.length === 1 ? `import:${id}/${files[0]!.path}` : `import:${id}/<file>`;
  return [
    `TOOL SUPPLIED as import:${id} (${rec.class}; use: ${use}), ${files.length} file(s): ${files.map((f) => `${f.path} (${f.bytes} bytes, sha256 ${f.sha256})`).join("; ")}, by ${rec.supplied_by}: ${rec.why}.`,
    `Where it came from, as the operator states it: ${tool.source}.`,
    tool.built ? `How it was built, as the operator states it: ${tool.built}.` : "How it was built: not stated by the operator.",
    tool.checked.length ? `Hashes the operator gave, each checked against the bytes sealed: ${tool.checked.join(", ")}.` : "Hashes the operator gave: none; the harness holds the bytes to the sha256 each had before it was copied.",
    tool.for?.length ? `It was supplied for ${tool.for.join(", ")}.` : "",
    "It is supplied material, and the harness vouches for the bytes only: where it came from and how it was built are the operator's statement. Test it on input whose answer you know before you rely on it, and say in the record that you did.",
    `It is readable now, read-only, at store/imports/${id}/out/. Nothing in the store or in a job's $OUT can be executed where it stands (sealed files have no execute bit, $OUT is no-exec), so run it in a job that names it: job_run with programs ["import:${id}"] (and inputs ${inputs} when you declare them) copies it into an executable directory in the worker, its bin/ on PATH and its lib/ on LD_LIBRARY_PATH ($PROGRAMS names the directory), and your command calls it by name.`,
    `A finding that rests on its output cites the job and ${cite}, and says what the tool is; what rests on it is flagged with its class. It is on the ledger as E-${entry ?? "?"} (kind external).`,
  ].filter(Boolean).join(" ");
}

/**
 * What follows from a committed addition, derived from its record, each
 * step found again by the addition's id and made once: the external entry,
 * the acquisition's stages, the leads reopened, the questions' arrivals,
 * the catalogue, the board. Then `addition_applied` on the store journal.
 * A step that could not be made is named (`pending`), and the addition is
 * applied again at the next reconciliation.
 */
export async function applyAddition(sandbox: string, id: string, o: AdditionOptions & { journal: Journal }): Promise<MaterialResult> {
  const S = resolve(sandbox);
  const journal = o.journal;
  const P_ = storePaths(S);
  // Whether the addition's reverse sweep is to be started once it is committed (evidence on the ledger).
  let reverseDue = false;
  const line = journal.lines.find((l) => ADDED.has(l.type) && l.import === id);
  if (!line) return { ok: false, reason: `import:${id} is not on the store journal: it was never committed` };
  let recordText: string;
  let rec: MaterialRecord;
  try {
    recordText = await readFile(join(P_.imports, id, "material.json"), "utf8");
    rec = JSON.parse(recordText) as MaterialRecord;
  } catch (err) {
    return { ok: false, reason: `store/imports/${id}/material.json cannot be read (${(err as Error).message}): nothing follows from it until it can` };
  }
  if (line.material_json_sha256 && sha256Of(recordText) !== line.material_json_sha256) return { ok: false, reason: `store/imports/${id}/material.json is not the record the store journal committed (line ${line.seq}): nothing follows from it` };
  const policy = readCasePolicy(S);
  const pending: string[] = [];
  const notes: string[] = [];
  const cls = rec.class;
  const files = rec.files;
  const inventoryRev = rec.inventory_rev ?? null;
  const why = rec.why;
  // On the ledger: external material, with its provenance in the chained core. Recorded once, by its refs and class.
  const refs = files.length <= P.LEDGER_MAX_REFS - 1 ? files.map((f) => `import:${id}/${f.path}`) : [`import:${id}`];
  const head = rec.mode === "evidence" ? `Evidence added after the kickoff (inventory revision ${inventoryRev}): ${files.length} file(s) as import:${id}${rec.request ? `, for ${rec.request}` : ""}` : `${rec.tool ? "Tool" : "Material"} supplied (${cls}): ${files.length} file(s) as import:${id}`;
  const external = await P.recordExternal(S, {
    value: withReason(head, why, P.LEDGER_VALUE_MAX_CHARS, id),
    source: `swarm.sh ${rec.tool ? "tool-supply" : rec.mode} add, by ${rec.supplied_by} (${rec.via})`,
    evidence: `store/imports/${id}/material.json and manifest.json; store journal line ${line.seq}`,
    refs,
    source_class: cls,
    provenance: {
      supplied_by: rec.supplied_by,
      at: rec.at,
      from: rec.from,
      sha256: files.length === 1 ? files[0].sha256 : rec.manifest_sha256,
      permitted_use: rec.permitted_use ?? permittedUse(policy, cls),
      import: id,
      files: files.map((f) => ({ path: f.path, sha256: f.sha256, bytes: f.bytes })),
      ...(files.length > 1 ? { sha256_of: "the import's manifest" } : {}),
      ...(rec.request ? { request: rec.request } : {}),
      ...(inventoryRev !== null ? { inventory_rev: inventoryRev } : {}),
      ...(rec.tool ? { tool: rec.tool } : {}),
    },
    ...(rec.sensitive ? { sensitive: true } : {}),
  }).catch((err: Error) => ({ ok: false as const, reason: err.message }));
  if (!external.ok) pending.push(`its external entry on the ledger (${external.reason})`);
  const entry = external.ok ? external.entry.seq : null;
  const out: MaterialResult = { ok: true, import: id, mode: rec.mode, class: cls, files, manifest_sha256: rec.manifest_sha256, journal_seq: line.seq, ...(inventoryRev !== null ? { inventory_rev: inventoryRev } : {}), entry, permitted_use: rec.permitted_use ?? permittedUse(policy, cls), ...(rec.tool ? { tool: rec.tool } : {}) };
  if (rec.mode === "evidence") {
    // The acquisition answered: received, then validated against the hashes the copy was held to; each stage once, by the import.
    if (rec.request) {
      const request = (await R.requestsSnapshot(S)).requests.get(rec.request) ?? null;
      const has = (st: R.AcquisitionStage) => Boolean(request?.stages.some((x) => x.stage === st && x.import === id));
      let received = has("received") || has("validated");
      let validated = has("validated");
      const said: string[] = [];
      const act = async (a: Parameters<typeof R.requestAct>[2]): Promise<boolean> => {
        const r = await R.requestAct(S, rec.request!, a);
        if (r.ok) return true;
        const now = (await R.requestsSnapshot(S)).requests.get(rec.request!);
        // A request another act closed since the commit is said, not retried; anything else is retried at the next reconciliation.
        if (now && (now.closed || ["declined", "unavailable", "validated"].includes(now.stage ?? ""))) notes.push(`${rec.request} was ${now.closed?.ev ?? now.stage} before the addition's stages could be recorded: ${r.reason}`);
        else pending.push(`${rec.request}'s ${a.stage} stage (${r.reason})`);
        said.push(r.reason);
        return false;
      };
      if (request && !received) {
        if (request.stage === "requested") await act({ ev: "stage", by: rec.supplied_by, stage: "authorised", why: "the operator supplied the evidence" });
        received = await act({ ev: "stage", by: rec.supplied_by, stage: "received", why, import: id, ...(inventoryRev !== null ? { inventory_rev: inventoryRev } : {}), sha256: files.map((f) => f.sha256) });
      }
      if (request && received && !validated) validated = await act({ ev: "stage", by: "harness", stage: "validated", why: "every file held to the sha256 it had before it was copied, and the seal to the copy", import: id, sha256: files.map((f) => f.sha256) });
      if (!request) pending.push(`${rec.request} cannot be read from requests/requests.jsonl`);
      out.request = { id: rec.request, received, validated, ...(said.length ? { reason: said.join("; ") } : {}) };
    }
    // What rested on the evidence as it was, reopened: the closed leads under its questions (resolved through the question register), and the request's own lead.
    const snap = await L.leadsSnapshot(S);
    const qs = snap.questions ?? (await Q.questionsSnapshot(S).catch(() => null));
    const wanted = new Set((rec.questions ?? []).map((q) => canonicalQuestion(qs, q)));
    const requestLead = rec.request ? ((await R.requestsSnapshot(S)).requests.get(rec.request)?.lead ?? null) : null;
    const reopened: string[] = [];
    const reopenWhy = withReason(`new evidence: import:${id}${rec.request ? ` for ${rec.request}` : ""} (inventory revision ${inventoryRev})`, why, L.LEAD_WHY_MAX, id);
    const closedBefore = (l: L.Lead): boolean => (rec.lead_seq !== undefined ? (l.closed?.seq ?? 0) <= rec.lead_seq : !l.closed || l.closed.at <= rec.at);
    for (const l of snap.state.leads.values()) {
      const serves = l.answers.some((a) => wanted.has(canonicalQuestion(qs, a)));
      if (!serves && l.id !== requestLead) continue;
      // Reopened for this import already (by this record, or before records named the import): once.
      if (l.reopened.some((x) => x.import === id || (!x.import && x.cause === "evidence_added" && x.why.includes(`import:${id} `)))) {
        reopened.push(l.id);
        continue;
      }
      if (!l.closed || l.closed.disposition === "duplicate" || l.closed.disposition === "withdrawn" || !closedBefore(l)) continue;
      const r = await L.reopenLead(S, l.id, "harness", reopenWhy, "evidence_added", { import: id, ...(rec.lead_seq !== undefined ? { closedBy: rec.lead_seq } : {}) });
      if (r.ok) reopened.push(l.id);
      else pending.push(`reopening ${l.id} (${r.reason})`);
    }
    // Every standing negative, not-determinable or partial answer whose coverage predates it, whether or not a question was named: stale until examined against it (the gate's evidence_stale).
    const staleAnswers = await answersStaledBy(S, entry);
    out.stale_answers = staleAnswers;
    // The reverse sweep (docs/adr/0013, "Late evidence: the reverse sweep and the delta"): the import's files, and only
    // they, searched for every standing coverage record's looked_for strings. It runs once the addition is committed and
    // applied, outside the material lock, a pass at a time within a budget of its own (store-sweep.ts); each pass's hits
    // follow on the board when it completes, and hold nothing by themselves (the Fable review of the limits branch, P2-4).
    let reverse: { records: number; terms: number } | null = null;
    if (external.ok && external.entry.hash) {
      reverseDue = true;
      const standing = SW.recordsStandingAt(await P.readLedger(S), external.entry.seq);
      reverse = { records: standing.length, terms: new Set(standing.flatMap((c) => (c.looked_for ?? []).map((t) => t.toLowerCase()))).size };
      out.reverse_sweep = { runs: o.reverse === "detached" ? "as a detached step" : "in the background", ...reverse };
    }
    const arrival = rec.questions?.length ? await Q.recordEvidenceArrival(S, rec.questions, { import: `import:${id}`, request: rec.request ?? null, inventory_rev: inventoryRev, why, ...(rec.ledger_seq !== undefined ? { ledger_seq: rec.ledger_seq } : {}) }).catch((err: Error) => { pending.push(`the questions' arrivals (${err.message})`); return { recorded: [] as string[], unknown: [] as string[] }; }) : { recorded: [], unknown: [] };
    out.reopened = { leads: reopened, questions: arrival.recorded, ...(arrival.unknown.length ? { unknown_questions: arrival.unknown } : {}) };
    // Catalogued when the run's catalogue is on and a catalogue is at hand: a detect pass over each file, as the system's own, once.
    const catalogueOn = o.catalogueOn ?? existsSync(join(S, "store", "jobs"));
    const queued = journal.of("evidence_catalogue_queued").some((l) => l.import === id);
    if (catalogueOn && o.catalogue && !queued) {
      const jobs: string[] = [];
      const refused: string[] = [];
      for (const f of files) {
        const c: { ok: boolean; job?: string; reason?: string } = await o.catalogue(`import:${id}/${f.path}`, `evidence added: import:${id}${rec.request ? ` for ${rec.request}` : ""}`).catch((err: Error) => ({ ok: false, reason: err.message }));
        if (c.ok && c.job) jobs.push(c.job);
        else refused.push(`${f.path}: ${c.reason ?? "refused"}`);
      }
      await journal.append({ type: "evidence_catalogue_queued", import: id, jobs, ...(refused.length ? { refused } : {}) });
      out.catalogue = { jobs, ...(refused.length ? { refused } : {}) };
    } else out.catalogue = queued ? "queued" : catalogueOn ? "at the hub's next round, when the run's catalogue is on" : "off in this run (no job service)";
    await P.systemPost(S, {
      tag: "ask",
      key: `addition:${id}`,
      body: [
        `EVIDENCE ADDED (inventory revision ${inventoryRev}) as import:${id}${rec.request ? `, for ${rec.request}` : ""}${rec.questions?.length ? `, on ${rec.questions.join(", ")}` : ""}, by ${rec.supplied_by}: ${why}.`,
        `Files: ${files.map((f) => `${f.path} (${f.bytes} bytes, sha256 ${f.sha256})`).join("; ")}.`,
        `It is readable now, read-only, at store/imports/${id}/out/ (every seat's VM mounts the run's directory live), and jobs read it as import:${id}/<file>. Cite it as import:${id}/<file> however you read it: its class and provenance are its ledger entry's, not the path you read it by.`,
        reopened.length ? `Reopened: ${reopened.join(", ")}.` : "",
        arrival.recorded.length ? `Answers to ${arrival.recorded.join(", ")} recorded before it are stale until recorded again, and an acceptance made before it no longer stands.` : "",
        reverse
          ? reverse.records
            ? `The reverse sweep runs now, outside this addition: import:${id}'s files searched for the ${reverse.terms} string(s) of the ${reverse.records} coverage record(s) standing at it, a pass at a time; each pass's hits follow on the board when it completes. A hit is a string a coverage record looked for, found in the new files: weigh it for its question; it holds nothing by itself.`
            : `No coverage record standing at it names looked_for strings: the reverse sweep has nothing to search import:${id} for.`
          : "",
        staleAnswers.length
          ? `Now stale, whatever question the evidence was added for: ${staleAnswersWords(staleAnswers)}. Each is examined against import:${id} before it stands, and the examination says how the new evidence bears on the answer: record what it shows as an entry whose refs name the import's files, with a delta, rel [{to: <the answer's seq>, kind: supports | contradicts | adds_part | irrelevant | inconclusive}]; a coverage record naming import:${id} among its objects and that entry among its results, which another seat reviews; then the answer again citing it (or the answer again citing that entry, once another seat has attested it). A citation of the import is not an examination of it. A review made before this evidence does not count for an answer recorded after it. Until then the finish line holds it (evidence_stale), unless the operator accepts the question's limits now.`
          : "",
        `It is on the ledger as E-${entry ?? "?"} (kind external, class acquired_evidence).`,
      ].filter(Boolean).join(" "),
    }).catch((err: Error) => pending.push(`the board post (${err.message})`));
    await R.renderViews(S).catch(() => undefined);
  } else if (rec.tool) {
    await P.systemPost(S, { tag: "ask", key: `addition:${id}`, body: toolPostBody(rec, rec.tool, entry, rec.permitted_use ?? permittedUse(policy, cls)) }).catch((err: Error) => pending.push(`the board post (${err.message})`));
  } else {
    await P.systemPost(S, { tag: "ask", key: `addition:${id}`, body: `MATERIAL SUPPLIED as import:${id} (${cls}; use: ${rec.permitted_use ?? permittedUse(policy, cls)}), ${files.length} file(s): ${files.map((f) => `${f.path} (sha256 ${f.sha256})`).join(", ")}, by ${rec.supplied_by}: ${why}. It is supplied material and proves nothing by itself: it is readable now, read-only, at store/imports/${id}/out/; cite it as import:${id}/<file> and say what it establishes, with its limits; it is on the ledger as E-${entry ?? "?"} (kind external).` }).catch((err: Error) => pending.push(`the board post (${err.message})`));
  }
  if (notes.length) out.notes = notes;
  if (pending.length) {
    if (reverseDue) startReverseSweep(S, o);
    out.complete = false;
    out.pending = pending;
    out.pending_note = "committed: the addition is sealed and on the store journal; what is pending is recorded at the next reconciliation (the hub's round, the next addition, or swarm.sh evidence <run> list), and the finish line holds a done until it is";
    return out;
  }
  await journal.append({ type: "addition_applied", import: id, entry, ...(out.reopened ? { reopened: (out.reopened as { leads: string[] }).leads, questions: (out.reopened as { questions: string[] }).questions } : {}), ...(rec.request ? { request: rec.request } : {}) });
  out.complete = true;
  if (reverseDue) startReverseSweep(S, o);
  return out;
}

/** The reverse sweeps started, never awaited: in this process's background, or as a detached step (AdditionOptions.reverse). */
function startReverseSweep(S: string, o: AdditionOptions): void {
  if (o.reverse === "detached") SW.detachReverseSweeps(S);
  else void SW.reverseSweepInBackground(S, o.sweepBudget ?? {});
}

/**
 * Every committed addition whose effects are not all recorded, applied
 * again (applyAddition), oldest first, under the material lock. Reads the
 * journal first without opening it: with nothing to apply, nothing is
 * opened, locked or written.
 */
export async function reconcileAdditions(sandbox: string, o: AdditionOptions = {}): Promise<MaterialResult[]> {
  const S = resolve(sandbox);
  if (!(await unappliedAdditions(S)).length) return [];
  return P.withNamedLock(S, MATERIAL_LOCK, async () => {
    const journal = o.journal ?? (await Journal.open(S));
    const applied = new Set(journal.of("addition_applied").map((l) => String(l.import)));
    const out: MaterialResult[] = [];
    for (const l of journal.lines.filter((x) => ADDED.has(x.type) && !applied.has(String(x.import)))) out.push(await applyAddition(S, String(l.import), { ...o, journal }));
    return out;
  });
}

async function main(argv: string[]): Promise<void> {
  const [cmd, sandboxArg, ...rest] = argv;
  if (!cmd || !sandboxArg) {
    process.stderr.write("usage: material.ts evidence-add|material-add|tool-add|list <sandbox> ...\n");
    process.exit(2);
  }
  const S = resolve(sandboxArg);
  const emit = (r: Record<string, unknown>) => {
    process.stdout.write(`${JSON.stringify(r)}\n`);
    process.exit(r.ok === false ? 1 : 0);
  };
  const valued = new Set(["--why", "--for", "--question", "--sha256", "--class", "--source", "--built", "--as", "--via", "--hub-admin"]);
  if (cmd === "list") {
    // What a crash left committed and not applied is applied first: by the hub when one runs (the journal's one writer), else here.
    const i = rest.indexOf("--hub-admin");
    const hub = i >= 0 ? rest[i + 1] : undefined;
    const QC = await import("./questions-cli.ts");
    const replayed = await QC.admit(S, hub, { op: "material_reconcile" }, async () => {
      const applied = await reconcileAdditions(S, { reverse: "detached" });
      // A reverse sweep left undone (a pass its budget ended, a step that died): continued as a step of its own.
      if ((await SW.pendingImportSweeps(S).catch(() => [])).length) SW.detachReverseSweeps(S);
      return { ok: true, applied };
    }).catch((err: Error) => ({ ok: false, reason: err.message }));
    const list = await listMaterial(S);
    emit({ ok: true, material: list, ...((replayed as { applied?: unknown[] }).applied?.length ? { replayed: (replayed as { applied: unknown[] }).applied } : {}), ...(replayed.ok === false ? { replay_failed: (replayed as { reason?: string }).reason } : {}) });
  }
  const pos: string[] = [];
  const opts = new Map<string, string[]>();
  const flags = new Set<string>();
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (valued.has(a)) {
      opts.set(a, [...(opts.get(a) ?? []), rest[i + 1] ?? ""]);
      i += 1;
    } else if (a.startsWith("--")) flags.add(a);
    else pos.push(a);
  }
  const one = (k: string) => opts.get(k)?.at(-1);
  if (cmd !== "evidence-add" && cmd !== "material-add" && cmd !== "tool-add") {
    process.stderr.write("usage: material.ts evidence-add|material-add|tool-add|list <sandbox> ...\n");
    process.exit(2);
  }
  if (!pos[0]) emit({ ok: false, reason: `${cmd === "evidence-add" ? "evidence add" : cmd === "tool-add" ? "tool supply" : "material add"} needs the path of the file or directory` });
  // Who supplies it: an enrolled person (a claim), or this host's OS account.
  const QC = await import("./questions-cli.ts");
  const via = one("--via") === "console" ? "console" : "cli";
  const who = QC.actorFor({ ...(one("--as") ? { as: one("--as") } : {}), via });
  if ("why" in who) emit({ ok: false, reason: who.why });
  const actor = (who as { actor: Q.Actor }).actor;
  const tool: ToolSupply | null =
    cmd === "tool-add"
      ? { source: one("--source") ?? "", ...(one("--built") !== undefined ? { built: one("--built") } : {}), ...(opts.get("--sha256")?.length ? { sha256: opts.get("--sha256") } : {}), ...(opts.get("--for")?.length ? { for: opts.get("--for") } : {}) }
      : null;
  const req: MaterialRequest = {
    mode: cmd === "evidence-add" ? "evidence" : "material",
    path: resolve(pos[0]),
    why: one("--why") ?? "",
    ...(tool ? { tool } : {}),
    ...(!tool && one("--for") ? { for: one("--for") } : {}),
    ...(opts.get("--question")?.length ? { questions: opts.get("--question") } : {}),
    ...(!tool && one("--sha256") ? { sha256: one("--sha256") } : {}),
    ...(one("--class") ? { cls: one("--class") as MaterialRequest["cls"] } : {}),
    ...(flags.has("--sensitive") ? { sensitive: true } : {}),
    supplied_by: Q.originWords(Q.originOf(actor)),
    via,
  };
  // A tool's statements, hashes and files are held here too, before the act is handed to a hub that may be older than this checkout and would take it as plain material, with none of them applied.
  if (tool) {
    const stated = checkToolStatements(req, readCasePolicy(S));
    if (!stated.ok) {
      emit(stated);
      return;
    }
    const placed = await runPathRefusal(S, req.path, req.path);
    if (placed) {
      emit({ ok: false, reason: placed });
      return;
    }
    const walked = await walkSource(req.path);
    if (walked.ok) {
      const hidden = walked.top === "dir" ? hiddenIn(walked.files) : [];
      if (hidden.length) {
        emit({ ok: false, reason: `${req.path} holds hidden files or directories (${hidden.join(", ")}): a directory supplied as a tool is sealed whole and every seat reads all of it, so a .env, a .git/config or a .netrc would go with it; remove them or give the files themselves; nothing was added` });
        return;
      }
      const stray = strayHash(stated.hashes, await Promise.all(walked.files.map(async (f) => ({ path: f.rel, sha256: await fileSha(f.abs) }))));
      if (stray) {
        emit({ ok: false, reason: stray });
        return;
      }
    }
  }
  // With no hub running the addition is made here, and this process exits once it has answered: its reverse sweep runs as a step of its own.
  const r = await QC.admit(S, one("--hub-admin"), { op: "material", request: req }, () => admitMaterial(S, req, { reverse: "detached" }));
  emit(r);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => {
    process.stdout.write(`${JSON.stringify({ ok: false, reason: err instanceof Error ? err.message : String(err) })}\n`);
    process.exit(1);
  });
}
