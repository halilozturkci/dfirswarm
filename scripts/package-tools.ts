#!/usr/bin/env node
/**
 * A package's two checks beyond its MANIFEST.txt (swarm.sh package, verify):
 *
 * redact <sandbox> <package dir>
 *   What a sensitive ledger entry says, and the objects it cites, are taken
 *   out of a package before it is handed over (GDPR or similar laws ask for
 *   no more than the purpose needs). A chained file keeps its chain: a
 *   redacted line is replaced by `{"redacted": true, "line_sha256": <the
 *   line's own hash>}` (a ledger entry keeps its seq, kind, prev and hash),
 *   so a recipient re-walks every chain and sees which lines it cannot read.
 *   Any other text file of the package with a sensitive entry's words in it
 *   has them replaced; a file a sensitive entry cites is replaced whole.
 *   REDACTIONS.txt lists every change with the file's sha256 before and
 *   after, so the owner of the original can match it.
 *
 * verify <package dir>
 *   The chains the package carries, re-walked: the trace, the ledger, its
 *   attestations and the store's journal, each held to the custody verdict's
 *   seal (its lines and heads), and the verdict to its anchor.
 *
 * Nothing here knows a tool or an evidence format.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, lstatSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readLedger, verifyAttestationChain, verifyLedgerChain, type LedgerEntry } from "../extensions/protocol.ts";
import { verifyJournalText } from "./evidence-store.ts";

const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");
const REDACTED = "[redacted: marked sensitive]";

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const d of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, d.name);
    if (d.isDirectory()) out.push(...walk(p));
    else if (d.isFile()) out.push(p);
  }
  return out;
}

/** The words a sensitive standing entry says, long enough to be told from ordinary text. */
function sensitiveWords(entries: LedgerEntry[]): string[] {
  const replaced = new Set(entries.map((e) => e.supersedes).filter((n): n is number => typeof n === "number"));
  const words = new Set<string>();
  for (const e of entries) {
    if (!e.sensitive) continue;
    // A corrected sensitive entry is still sensitive: both say the secret.
    void replaced;
    for (const w of [e.value, e.evidence ?? "", e.attribution?.subject ?? "", ...(e.locators ?? []).map((l) => l.at)]) {
      if (w && w.trim().length >= 6) words.add(w.trim());
      // A key, a token or a password is said in other words elsewhere: each
      // long run with a digit in it is taken on its own too.
      for (const t of (w ?? "").match(/[^\s"'`,;()]{12,}/g) ?? []) if (/\d/.test(t)) words.add(t);
    }
  }
  return [...words].sort((a, b) => b.length - a.length);
}

/** Package paths a sensitive entry's refs name, as the package lays them out. */
function citedPaths(entries: LedgerEntry[]): string[] {
  const out = new Set<string>();
  for (const e of entries) {
    if (!e.sensitive) continue;
    for (const r of e.refs ?? []) {
      const m = /^job:(j\d{6})\/(.+)$/.exec(r);
      if (!m) continue;
      if (/^(stdout\.log|stderr\.log)$/.test(m[2])) out.add(`store/jobs/${m[1]}/${m[2]}`);
      else out.add(`store/jobs/${m[1]}/out/${m[2].replace(/^out\//, "")}`);
    }
  }
  return [...out];
}

export async function redactPackage(sandbox: string, dir: string): Promise<{ entries: number; files: number; lines: number }> {
  const entries = await readLedger(sandbox);
  const words = sensitiveWords(entries);
  const sensitiveSeqs = new Set(entries.filter((e) => e.sensitive).map((e) => e.seq));
  const log: string[] = [];
  let lines = 0;
  const change = (rel: string, before: Buffer, after: Buffer | string, why: string) => {
    writeFileSync(join(dir, rel), after);
    log.push(`${sha256(before)}  ${sha256(after)}  ${rel}  ${why}`);
  };
  // The ledger: a sensitive entry's line keeps what chains it.
  const ledgerRel = "ledger.jsonl";
  if (existsSync(join(dir, ledgerRel))) {
    const before = readFileSync(join(dir, ledgerRel));
    const out = before
      .toString("utf8")
      .split("\n")
      .map((l) => {
        if (!l.trim()) return l;
        try {
          const e = JSON.parse(l) as LedgerEntry;
          if (!sensitiveSeqs.has(e.seq)) return l;
          lines += 1;
          return JSON.stringify({ v: e.v, seq: e.seq, kind: e.kind, redacted: true, line_sha256: sha256(l), ...(e.prev ? { prev: e.prev } : {}), ...(e.hash ? { hash: e.hash } : {}), ...(e.refs ? { refs: e.refs } : {}) });
        } catch {
          return l;
        }
      })
      .join("\n");
    if (out !== before.toString("utf8")) change(ledgerRel, before, out, `${sensitiveSeqs.size} sensitive entr${sensitiveSeqs.size === 1 ? "y" : "ies"} replaced by their seq, kind, chain hashes and line hash`);
  }
  // The trace: a line with a sensitive entry's words is replaced by its own hash, which the next line's prev names.
  for (const rel of ["trace/events.jsonl"]) {
    if (!existsSync(join(dir, rel)) || !words.length) continue;
    const before = readFileSync(join(dir, rel));
    let n = 0;
    const out = before
      .toString("utf8")
      .split("\n")
      .map((l) => {
        if (!l.trim() || !words.some((w) => l.includes(w) || l.includes(JSON.stringify(w).slice(1, -1)))) return l;
        n += 1;
        return JSON.stringify({ redacted: true, line_sha256: sha256(l) });
      })
      .join("\n");
    lines += n;
    if (n) change(rel, before, out, `${n} line(s) holding a sensitive entry's words replaced by their own sha256`);
  }
  // The store's journal: a job's command can carry a secret too; a line is replaced keeping its seq, its prev and its own hash.
  for (const rel of ["store/journal.jsonl"]) {
    if (!existsSync(join(dir, rel)) || !words.length) continue;
    const before = readFileSync(join(dir, rel));
    let n = 0;
    const out = before
      .toString("utf8")
      .split("\n")
      .map((l) => {
        if (!l.trim() || !words.some((w) => l.includes(w) || l.includes(JSON.stringify(w).slice(1, -1)))) return l;
        n += 1;
        const o = JSON.parse(l) as { v?: number; seq?: number; prev?: string | null; type?: string; job?: string };
        return JSON.stringify({ v: o.v, seq: o.seq, type: o.type, ...(o.job ? { job: o.job } : {}), redacted: true, line_sha256: sha256(l), prev: o.prev ?? null });
      })
      .join("\n");
    lines += n;
    if (n) change(rel, before, out, `${n} journal line(s) holding a sensitive entry's words replaced, keeping seq, prev and their own sha256`);
  }
  // A file a sensitive entry cites, whole.
  for (const rel of citedPaths(entries)) {
    if (!existsSync(join(dir, rel))) continue;
    const before = readFileSync(join(dir, rel));
    change(rel, before, `${REDACTED}: cited by a sensitive ledger entry; its sha256 before redaction is ${sha256(before)}\n`, "cited by a sensitive entry, replaced whole");
  }
  // Every other text file: the words replaced where they appear.
  const skip = new Set(["MANIFEST.txt", "MANIFEST.txt.sig", "SIGNER.txt", "signer.pub", "REDACTIONS.txt", ledgerRel, "trace/events.jsonl", "store/journal.jsonl", "ledger-attestations.jsonl"]);
  let files = 0;
  if (words.length) {
    for (const abs of walk(dir)) {
      const rel = relative(dir, abs);
      if (skip.has(rel) || lstatSync(abs).size > 64 * 1024 * 1024) continue;
      const before = readFileSync(abs);
      if (before.subarray(0, 8192).includes(0)) continue;
      let text = before.toString("utf8");
      let hit = false;
      for (const w of words) {
        for (const form of [w, JSON.stringify(w).slice(1, -1)]) {
          if (form && text.includes(form)) {
            text = text.split(form).join(REDACTED);
            hit = true;
          }
        }
      }
      if (hit) {
        files += 1;
        change(rel, before, text, "a sensitive entry's words replaced");
      }
    }
  }
  writeFileSync(
    join(dir, "REDACTIONS.txt"),
    [
      "Redactions",
      "==========",
      "",
      `This package was made with --redact. ${sensitiveSeqs.size} ledger entr${sensitiveSeqs.size === 1 ? "y was" : "ies were"} marked sensitive (seq ${[...sensitiveSeqs].join(", ") || "none"}).`,
      "What they say, and the objects they cite, are not in it. A chained file keeps its chain: a redacted",
      "line carries the sha256 of the line it replaces, which the next line's prev names. Each change below",
      "is the file's sha256 before and after, so the owner of the original can match it.",
      "",
      "sha256 before                                                    sha256 after                                                     path  why",
      ...log,
      "",
    ].join("\n"),
  );
  return { entries: sensitiveSeqs.size, files, lines };
}

// --- verify ------------------------------------------------------------------------------

/** The trace chain, a redacted line counting as the line it replaced. */
function traceChain(text: string): { ok: boolean; lines: number; redacted: number; detail: string; lineHashes: string[] } {
  let previous = "";
  let started = false;
  let n = 0;
  let redacted = 0;
  const hashes: string[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    n += 1;
    let o: { prev?: unknown; redacted?: unknown; line_sha256?: unknown };
    try {
      o = JSON.parse(line);
    } catch {
      return { ok: false, lines: n, redacted, detail: `line ${n} is not JSON`, lineHashes: hashes };
    }
    let own = sha256(line);
    if (o.redacted === true && typeof o.line_sha256 === "string") {
      redacted += 1;
      own = o.line_sha256;
      previous = own;
      hashes.push(own);
      started = true;
      continue;
    }
    if (typeof o.prev === "string") {
      started = true;
      if (o.prev !== previous) return { ok: false, lines: n, redacted, detail: `line ${n}'s prev does not name the line before it`, lineHashes: hashes };
    } else if (started) return { ok: false, lines: n, redacted, detail: `line ${n} has no prev after chained lines`, lineHashes: hashes };
    previous = own;
    hashes.push(own);
  }
  return { ok: true, lines: n, redacted, detail: `${n} lines, chain intact${redacted ? `, ${redacted} redacted (their hashes kept)` : ""}`, lineHashes: hashes };
}

/** The ledger chain, a redacted entry's hash taken as it stands (its core is not in the package). */
function ledgerChain(text: string): { ok: boolean; entries: number; redacted: number; head: string | null; detail: string } {
  const lines = text.split("\n").filter((l) => l.trim());
  const redacted = lines.filter((l) => l.includes('"redacted":true')).length;
  if (!redacted) {
    const v = verifyLedgerChain(text);
    return { ok: v.ok, entries: v.total, redacted: 0, head: v.hashes.at(-1) ?? null, detail: v.ok ? `${v.total} entries, chain intact` : `broken at entry ${v.broken_at} (${v.reason})` };
  }
  // With redactions: each unredacted entry's core is re-derived; a redacted one's hash is taken, and the next must name it.
  let last: string | null = null;
  let n = 0;
  for (const l of lines) {
    n += 1;
    const e = JSON.parse(l) as LedgerEntry & { redacted?: boolean };
    if (e.redacted) {
      if (last !== null && e.prev !== last) return { ok: false, entries: n, redacted, head: null, detail: `redacted entry ${e.seq}'s prev does not name the entry before it` };
      last = e.hash ?? null;
      continue;
    }
    const one = verifyLedgerChain(JSON.stringify(e));
    // A single line checks its own core only when it starts the chain; later ones are checked by prev and hash.
    if (last !== null && e.prev !== last) return { ok: false, entries: n, redacted, head: null, detail: `entry ${e.seq}'s prev does not name the entry before it` };
    if (last === null && !one.ok && e.prev === "genesis") return { ok: false, entries: n, redacted, head: null, detail: `entry ${e.seq}: ${one.reason}` };
    last = e.hash ?? null;
  }
  return { ok: true, entries: n, redacted, head: last, detail: `${n} entries, chain intact, ${redacted} redacted (their hashes kept, their cores not in the package)` };
}

/** The journal's chain, a redacted line counting as the line it replaced. */
function journalChain(text: string): { ok: boolean; lines: number; redacted: number; head: string | null; detail: string } {
  if (!text.includes('"redacted":true')) {
    const j = verifyJournalText(text);
    return { ok: !j.error, lines: j.lines.length, redacted: 0, head: j.head, detail: j.error ? `CHAIN BROKEN (${j.error})` : `${j.lines.length} lines, chain intact` };
  }
  let prev: string | null = null;
  let n = 0;
  let redacted = 0;
  for (const raw of text.split("\n")) {
    if (!raw) continue;
    const o = JSON.parse(raw) as { seq?: number; prev?: string | null; redacted?: boolean; line_sha256?: string };
    if ((o.prev ?? null) !== prev) return { ok: false, lines: n, redacted, head: null, detail: `CHAIN BROKEN (line ${n + 1} does not chain to the line before)` };
    if (o.seq !== n) return { ok: false, lines: n, redacted, head: null, detail: `CHAIN BROKEN (line ${n + 1} has seq ${o.seq})` };
    prev = o.redacted && o.line_sha256 ? o.line_sha256 : sha256(raw);
    if (o.redacted) redacted += 1;
    n += 1;
  }
  return { ok: true, lines: n, redacted, head: prev, detail: `${n} lines, chain intact, ${redacted} redacted (their hashes kept)` };
}

export function verifyPackage(dir: string): { ok: boolean; lines: string[] } {
  const out: string[] = [];
  let ok = true;
  const read = (rel: string) => (existsSync(join(dir, rel)) ? readFileSync(join(dir, rel), "utf8") : null);
  const custodyText = read("custody.json");
  const custody = custodyText ? (JSON.parse(custodyText) as { seal?: { trace?: { lines?: number; last_line_sha256?: string | null }; ledger?: { entries?: number; head?: string | null }; attestations?: { lines?: number; head?: string | null }; journal?: { lines?: number; head?: string | null } | null } }) : null;
  const seal = custody?.seal;
  // The verdict against the anchor it was written with.
  const anchorText = read("trace/custody-anchor.json");
  if (custodyText && anchorText) {
    const verdicts = ((JSON.parse(anchorText) as { custody?: Array<{ sha256?: string }> }).custody ?? []);
    const matches = verdicts.at(-1)?.sha256 === sha256(custodyText);
    out.push(`Verdict:      custody.json ${matches ? "matches the last verdict its anchor names" : "DOES NOT MATCH the last verdict its anchor names"}`);
    ok &&= matches;
  } else out.push(`Verdict:      ${custodyText ? "no anchor in the package to hold it to" : "no custody.json in the package"}`);
  // The trace.
  const trace = read("trace/events.jsonl");
  if (trace !== null) {
    const t = traceChain(trace);
    let sealNote = "";
    if (seal?.trace?.lines) {
      const at = t.lineHashes[seal.trace.lines - 1];
      const same = at === seal.trace.last_line_sha256;
      sealNote = same ? `; the ${seal.trace.lines} lines the verdict sealed are there, ${t.lines - seal.trace.lines} after` : "; THE SEALED LINE IS NOT THE ONE THE VERDICT NAMES";
      ok &&= same;
    }
    out.push(`Trace:        ${t.detail}${sealNote}`);
    ok &&= t.ok;
  }
  // The ledger and its attestations.
  const ledger = read("ledger.jsonl");
  if (ledger !== null) {
    const l = ledgerChain(ledger);
    const sealed = seal?.ledger?.head === undefined || seal.ledger.head === null || seal.ledger.head === l.head;
    out.push(`Ledger:       ${l.detail}${seal?.ledger ? (sealed ? "; its head is the one the verdict sealed" : "; ITS HEAD IS NOT THE ONE THE VERDICT SEALED") : ""}`);
    ok &&= l.ok && sealed;
  }
  const att = read("ledger-attestations.jsonl");
  if (att !== null) {
    const a = verifyAttestationChain(att);
    const sealed = !seal?.attestations?.head || seal.attestations.head === a.head;
    out.push(`Attestations: ${a.ok ? `${a.total} lines, chain intact` : `CHAIN BROKEN at line ${a.broken_at} (${a.reason})`}${seal?.attestations ? (sealed ? "; head sealed" : "; HEAD NOT THE ONE SEALED") : ""}`);
    ok &&= a.ok && sealed;
  }
  // The store's journal.
  const journal = read("store/journal.jsonl");
  if (journal !== null) {
    const j = journalChain(journal);
    const sealed = !seal?.journal?.head || seal.journal.head === j.head;
    out.push(`Journal:      ${j.detail}${seal?.journal ? (sealed ? "; head sealed" : "; HEAD NOT THE ONE SEALED") : ""}`);
    ok &&= j.ok && sealed;
  }
  if (existsSync(join(dir, "REDACTIONS.txt"))) out.push("Redacted:     this package was made with --redact (REDACTIONS.txt)");
  return { ok, lines: out };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [cmd, a, b] = process.argv.slice(2);
  if (cmd === "redact" && a && b) {
    const r = await redactPackage(a, b);
    console.log(JSON.stringify(r));
  } else if (cmd === "verify" && a) {
    const r = verifyPackage(a);
    console.log(r.lines.join("\n"));
    process.exit(r.ok ? 0 : 1);
  } else {
    console.error("usage: package-tools.ts redact <sandbox> <package dir> | verify <package dir>");
    process.exit(2);
  }
}
