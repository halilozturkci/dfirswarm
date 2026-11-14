/**
 * The sensitive words (split from extensions/protocol.ts, which re-exports it): what a sensitive
 * entry says, as redaction and the leak scan read it, and the refusal of a text that would repeat it.
 */

import { execFile, execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  closeSync,
  createReadStream,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  writeSync,
} from "node:fs";
import { connect, type Socket } from "node:net";
import {
  appendFile,
  chmod,
  copyFile,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  readlink,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { basename, dirname, join, posix, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import * as NB from "./negative-bar.ts";
import * as PM from "./premises.ts";
import * as PR from "./preparation.ts";
import { importHitExamined, importHitsFor, importHitWords, unexaminedHits, type ImportSweepRecord, type SweepRecord, type UnexaminedHit } from "./store-sweep.ts";
import type { LedgerEntry } from "./protocol-core.ts";
import { readLedger } from "./ledger-rules.ts";

/** The fields of an entry, of any version, that can hold what it says. */
const ENTRY_TEXT_FIELDS = ["value", "evidence", "source", "indicates", "confidence_why", "reasoning", "would_change", "alternatives_open", "alternatives_none_why", "because", "time_range", "search_method", "settings", "coverage_actual", "skipped", "failures", "qualifier", "value_changed_because", "decoy"] as const;

/** One of a sensitive entry's words, with the entry it came from; `exact` when it is a value B9 matches as a whole phrase, never inside another word. */
export type SensitiveToken = { token: string; seq: number; exact?: boolean };

/**
 * What a sensitive entry says, as the words redaction looks for: each text
 * field whole (six characters or more, or four with a digit in it), and
 * each identifier-like run inside one (eight characters or more with a
 * digit, an @, a dot, a slash, a backslash or a colon in it: a key, a
 * token, an address, a path, an account), longest first, each with the
 * entry it came from. This is what a redacted package takes out and its
 * leak scan looks for, broad on purpose; B9 reads the narrower
 * b9SensitiveValues.
 */
export function sensitiveTokens(entries: LedgerEntry[]): SensitiveToken[] {
  const out = new Map<string, number>();
  const add = (t: string, seq: number) => {
    if (!out.has(t)) out.set(t, seq);
  };
  for (const e of entries) {
    if (!e.sensitive) continue;
    const raw = e as unknown as Record<string, unknown>;
    const texts: string[] = [];
    for (const f of ENTRY_TEXT_FIELDS) if (typeof raw[f] === "string") texts.push(raw[f] as string);
    if (e.attribution?.subject) texts.push(e.attribution.subject);
    for (const l of e.locators ?? []) texts.push(l.at);
    for (const a of (raw.alternatives as Array<{ explanation?: string; why?: string }> | undefined) ?? []) texts.push(a.explanation ?? "", a.why ?? "");
    for (const q of (raw.qualifies as Array<{ why?: string }> | undefined) ?? []) texts.push(q.why ?? "");
    for (const c of (raw.control as Array<{ found?: string }> | undefined) ?? []) texts.push(c.found ?? "");
    for (const c of (raw.carriers as Array<{ carrier?: string; why?: string }> | undefined) ?? []) texts.push(c.carrier ?? "", c.why ?? "");
    // A candidate is a value the entry weighs (a second reading of a password, a decoy's string): as sensitive as value.
    for (const c of (raw.candidates as Array<{ value?: string; why?: string }> | undefined) ?? []) texts.push(c.value ?? "", c.why ?? "");
    for (const n of (raw.carrier_names as string[] | undefined) ?? []) texts.push(n);
    if (raw.decoy_check && typeof raw.decoy_check === "object") texts.push((raw.decoy_check as { why?: string }).why ?? "");
    // A sensitive coverage record's looked_for strings are what its sweep searched for: sensitive words too.
    for (const t of e.looked_for ?? []) texts.push(t);
    for (const w of texts) {
      const whole = (w ?? "").trim();
      if (whole.length >= 6 || (whole.length >= 4 && /\d/.test(whole))) add(whole, e.seq);
      for (const t of whole.match(/[^\s"'`,;()<>[\]{}]{8,}/g) ?? []) if (/[\d@./\\:]/.test(t)) add(t.replace(/[.:]+$/, ""), e.seq);
    }
  }
  return [...out].map(([token, seq]) => ({ token, seq })).sort((a, b) => b.token.length - a.token.length || a.token.localeCompare(b.token));
}

/**
 * Whether a word taken out of a sensitive entry's value is a value on its own
 * (B9): distinctive by its shape, never because it happens to stand in a
 * sensitive sentence. Generic, with no dictionary: at least eight
 * characters (a short technical word such as SHA-256 or python3 is not a
 * value), and a digit in it, or a symbol (anything but a letter, a digit, a
 * hyphen or an apostrophe: a path, an address, a key, `Qx7!pass`), or a
 * capital inside it (`PurpleElephant`), or twelve letters or more that do
 * not read as a word (under a fifth of them vowels, or five consonants in a
 * row: a random string). Never the run's own ids (E-12, L-3, j000129, ev-0001, and their
 * possessives), a number or a date, a time or a timestamp (a question asks
 * about times), and never an ordinary word, whatever sentence it came from
 * ("activity", "entries"). A short value is caught whole, as its entry's
 * recorded value (b9SensitiveValues).
 */
export function distinctiveValue(word: string): boolean {
  const w = String(word ?? "").replace(/^[(["'`<{]+/, "").replace(/[)\]"'`>},.;:!?]+$/, "").replace(/['’]s$/i, "");
  const letters = w.replace(/[^\p{L}]/gu, "");
  if (sensitiveFold(w).length < 8) return false;
  // The run's own ids, alone, in a list (E-157/E-158) or as a bare reference (job:j000115).
  const ID = "(?:[A-Z]{1,2}-\\d+|#\\d+|j\\d{6}|(?:ev|mat)-\\d{4,}|(?:job|import):[a-z0-9-]+)";
  if (new RegExp(`^${ID}(?:[/,]${ID})*$`, "i").test(w)) return false;
  // A time or a timestamp, however written: what a question asks about.
  if (/^\d{4}-\d{2}-\d{2}(?:[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)?$/i.test(w)) return false;
  if (/^\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?$/i.test(w)) return false;
  if (!letters) {
    // A number, an amount, a date, a version: only a long run of digits (an account, a card, a phone) is a value.
    return (w.match(/\d/g) ?? []).length >= 9;
  }
  if (/\d/.test(w)) return true;
  // Plain words joined by a slash or a dash (and/or, added/visited, channel—and) are words.
  const joined = /^[\p{L}'’\p{Pd}]+(?:\/[\p{L}'’\p{Pd}]+)*$/u.test(w);
  if (!joined && /[^\p{L}\p{N}'’\p{Pd}]/u.test(w)) return true;
  if (/\p{Ll}\p{Lu}/u.test(w)) return true;
  if (letters.length >= 12) {
    const vowels = (letters.match(/[aeiouy]/gi) ?? []).length / letters.length;
    const run = Math.max(0, ...(letters.toLowerCase().match(/[^aeiouy]+/g) ?? []).map((x) => x.length));
    return vowels < 0.2 || run >= 5;
  }
  return false;
}

/**
 * The values B9 holds a name, a `doing` label and a question's words to,
 * from every entry recorded sensitive: an entry marks sensitivity as a
 * whole (`sensitive: true`), and its `value` is what it records, so that
 * value is held whole, as a phrase matched word for word (a short value
 * such as "Alice", a multi-word one such as "Secret Word", or the whole
 * sentence), never as its words one by one; and from the fields that hold
 * what it records (its value, and the subject an attribution names), the
 * words that are values on their own (distinctiveValue: a key, a password,
 * an address, a path, an account). Never from its evidence, its source,
 * its method, what it indicates or any other note: those say how the value
 * was found, and name tools and files an analyst's question names too (the
 * c10 pilot refused "PowerShell" and "meeting.txt" so). The redaction
 * scanner reads the broader sensitiveTokens.
 */
export function b9SensitiveValues(entries: LedgerEntry[]): SensitiveToken[] {
  const out = new Map<string, SensitiveToken>();
  for (const e of entries) {
    if (!e.sensitive) continue;
    const value = String(e.value ?? "").trim();
    // A candidate beside the value (a second reading, a decoy's string) is a value the entry records too.
    const candidates = (e.candidates ?? []).map((c) => String(c.value ?? "").trim());
    for (const v of [value, ...candidates]) if (sensitiveFold(v).length >= 3 && !out.has(v)) out.set(v, { token: v, seq: e.seq, exact: true });
    for (const text of [value, ...candidates, e.attribution?.subject ?? ""]) {
      for (const raw of String(text ?? "").split(/\s+/)) {
        const w = raw.replace(/^[(["'`<{]+/, "").replace(/[)\]"'`>},.;:!?]+$/, "").replace(/['’]s$/i, "");
        if (w && !out.has(w) && distinctiveValue(w)) out.set(w, { token: w, seq: e.seq });
      }
    }
  }
  return [...out.values()].sort((a, b) => b.token.length - a.token.length || a.token.localeCompare(b.token));
}

/**
 * A text as B9 compares it: Unicode folded to its compatibility form (NFKC:
 * a full-width or composed letter is the letter), invisible format and
 * default-ignorable characters removed, case folded, and the markup a name
 * loses when it is tidied (backquote, asterisk, underscore, brackets)
 * dropped and whitespace collapsed, so what is compared is what a board
 * would show.
 */
export function sensitiveFold(text: string): string {
  return String(text ?? "")
    .normalize("NFKC")
    .replace(/[\p{Cf}\p{Default_Ignorable_Code_Point}]/gu, "")
    .toLowerCase()
    .normalize("NFKC")
    .replace(/[`*_\[\]]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Every value the run marks sensitive, whatever its origin (B9, docs/adr/0014):
 * what each ledger entry recorded sensitive says, of any kind and by anyone
 * (an agent's finding or answer, external material the operator supplied as
 * sensitive), standing or superseded, since a value once marked sensitive
 * stays so. There is no "answer value" concept and no exemption for words
 * the goal itself uses: a value is sensitive wherever it first appeared.
 */
export async function runSensitiveTokens(sandboxRoot: string): Promise<SensitiveToken[]> {
  const entries = await readLedger(sandboxRoot, { raw: true }).catch(() => [] as LedgerEntry[]);
  return entries.some((e) => e.sensitive) ? b9SensitiveValues(entries) : [];
}

/**
 * The first sensitive value a text holds, or null: both folded the same way
 * (sensitiveFold). An entry's recorded value (`exact`) is found as a whole
 * phrase, word for word, never inside another word; a distinctive value is
 * found inside the text, or with the spaces a line break or a tidy put in
 * it taken out.
 */
export function sensitiveHit(text: string, tokens: SensitiveToken[]): SensitiveToken | null {
  if (!text || !tokens.length) return null;
  const folded = sensitiveFold(text);
  const squeezed = folded.replace(/ /g, "");
  for (const t of tokens) {
    const f = sensitiveFold(t.token);
    if (!f) continue;
    if (t.exact) {
      if (new RegExp(`(?<![\\p{L}\\p{N}])${f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\p{L}\\p{N}])`, "u").test(folded)) return t;
      continue;
    }
    if (folded.includes(f) || (f.length >= 8 && squeezed.includes(f.replace(/ /g, "")))) return t;
  }
  return null;
}

/**
 * The refusal for words that would carry a value the run marks sensitive
 * (a name, a `doing` label, a question's text, its reasons and hints),
 * naming the field and the entry, never the value; null when none does.
 */
export async function sensitiveRefusalOf(sandboxRoot: string, texts: Array<[string, string | undefined | null]>): Promise<string | null> {
  const tokens = await runSensitiveTokens(sandboxRoot);
  if (!tokens.length) return null;
  for (const [name, text] of texts) {
    const hit = text ? sensitiveHit(text, tokens) : null;
    if (hit) return `${name} holds a value the run marks sensitive (E-${hit.seq}): say it without the value; the entry can be cited by its number`;
  }
  return null;
}
