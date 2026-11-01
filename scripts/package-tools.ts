#!/usr/bin/env node
/**
 * A package's two checks beyond its MANIFEST.txt (swarm.sh package, verify):
 *
 * redact <sandbox> <package dir> [--leaks fail|list]
 *   What a sensitive ledger entry says, and the objects it cites, are taken
 *   out of a package before it is handed over (GDPR or similar laws ask for
 *   no more than the purpose needs). A chained file keeps its chain: a
 *   redacted line is replaced by `{"redacted": true, "line_sha256": <the
 *   line's own hash>}` (a ledger entry keeps its seq, kind, prev and hash;
 *   an attestation or a dispute its act, target, prev and hash), so a
 *   recipient re-walks every chain and sees which lines it cannot read. A
 *   JSON file is redacted field by field, keeping its shape; any other text
 *   file word by word; a file a sensitive entry cites is replaced whole; a
 *   PDF a release printed is withheld. REDACTIONS.txt lists every change
 *   with the file's sha256 before and after, so the owner of the original
 *   can match it, and REDACTIONS.json what each replaced (the sha256 of the
 *   original, why, which entry). Then every file is scanned for each
 *   sensitive entry's words, normalised: a hit refuses the package (exit 5),
 *   or with --leaks list is recorded and said.
 *
 * components <sandbox> <package dir>
 *   COMPONENTS.json: each part a recipient holds the record to (the verdict,
 *   its anchor, its signature and token, the index of work/ custody sealed,
 *   the trace, the ledger, its attestations, the store's journal, the
 *   examiner's review), present or absent with why. Written before the
 *   manifest, so it is under the manifest's hash and its signature: a part
 *   taken out of a package, and out of the list, breaks the signature.
 *
 * verify <package dir>
 *   Every part the package should carry is there or declared absent; the
 *   chains it carries, re-walked (every ledger entry's core recomputed, a
 *   redacted one's hash taken as it stands): the trace, the ledger, its
 *   attestations, the store's journal and the examiner's review, each held
 *   to the custody verdict's seal (its lines and heads), the verdict to its
 *   anchor; every packaged work/ file held to the index custody sealed, and
 *   that index to the anchor.
 *
 * Nothing here knows a tool or an evidence format.
 */
import { createHash, createHmac, randomBytes } from "node:crypto";
import { closeSync, existsSync, lstatSync, openSync, readFileSync, readSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { attestationHash, disputeHash, ledgerHash, readLedger, sensitiveTokens, type LedgerAttestation, type LedgerDispute, type LedgerEntry, type SensitiveToken } from "../extensions/protocol.ts";
import { leadEventHash, type LeadEvent } from "../extensions/leads.ts";
import { sweepHash, type SweepRecord } from "../extensions/store-sweep.ts";
import { REVIEW_ACTIONS } from "./review.ts";
import { packageLayout, verifyReleases } from "./release-record.ts";
import { outputWords, sensitiveEntries, sensitiveIndex, withheldPaths } from "./output-hygiene.ts";
import { MultiMatch } from "./multi-match.ts";

const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

/** A file's sha256, read 8 MiB at a time: never the whole file in memory. */
function sha256FileSync(path: string): string {
  const h = createHash("sha256");
  const fd = openSync(path, "r");
  try {
    const buf = Buffer.allocUnsafe(8 * 1024 * 1024);
    for (let n = readSync(fd, buf, 0, buf.length, null); n > 0; n = readSync(fd, buf, 0, buf.length, null)) h.update(buf.subarray(0, n));
  } finally {
    closeSync(fd);
  }
  return h.digest("hex");
}
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

// What a sensitive entry says, as the words redaction looks for (protocol.ts, where the question register reads them too).
export { sensitiveTokens, type SensitiveToken };

/** Package paths a sensitive entry's refs name, as the package lays them out, with the entry. */
function citedPaths(entries: LedgerEntry[]): Array<{ path: string; seq: number }> {
  const out = new Map<string, number>();
  for (const e of entries) {
    if (!e.sensitive) continue;
    for (const r of e.refs ?? []) {
      const m = /^job:(j\d{6})\/(.+)$/.exec(r);
      if (!m) continue;
      const p = /^(stdout\.log|stderr\.log)$/.test(m[2]) ? `store/jobs/${m[1]}/${m[2]}` : `store/jobs/${m[1]}/out/${m[2].replace(/^out\//, "")}`;
      if (!out.has(p)) out.set(p, e.seq);
    }
  }
  return [...out].map(([path, seq]) => ({ path, seq }));
}

/** What one redaction replaced: the sha256 of the original (never the original), why, and which entry's words it held. */
export type Replaced = { what: "entry" | "line" | "file" | "field" | "text"; entry: number | null; sha256_of_original: string; line?: number; pointer?: string; count?: number; why: string };
export type RedactionChange = { path: string; before_sha256: string; after_sha256: string; why: string; replaced: Replaced[] };
/** A hit of the scan: the file, the ledger entry whose words it holds (0 for a sensitive output's own text or a digest, named in `output`/`why`), a commitment to the word (its sha256, or an opaque id for low-entropy content), and how it was found. */
export type LeakHit = { path: string; entry: number; token_sha256: string; as: string; output?: string };
/** A word the scan looks for: a sensitive entry's (protocol.ts sensitiveTokens), or a small sensitive output's whole text (`output`: job/path); `id` is a keyed commitment reported in place of the word's sha256 for low-entropy content. */
export type ScanToken = SensitiveToken & { output?: string; id?: string };
/** What a redacted package withheld whole, and why: never its bytes, always its sha256. */
export type Withheld = { path: string; job: string | null; why: string; sha256_of_original: string; bytes: number };

/** A sensitive entry's words as they may stand in a file: as written, JSON-escaped. */
const forms = (t: string) => [...new Set([t, JSON.stringify(t).slice(1, -1)])];

/**
 * Where a sensitive word counts as standing in a text. A long word (eight
 * characters or more) counts wherever it stands. A short one (a PIN, a short
 * code) counts wherever it stands too, a letter touching it included
 * ("PIN4821"), except where it is part of a longer run that makes it
 * something else:
 * - its digits run on into more digits: a bigger number, a timestamp's
 *   fraction ("12.482145Z"), a count;
 * - a run of sixteen hex characters or more with digits of its own beyond
 *   the word: a sha256, a keyed id (hidden-…);
 * - a run of twenty base64 or base64url characters or more with letters and
 *   digits of their own and few separators (under one in eight of '+', '/',
 *   '-', '_'): an encoded blob, where a path's or a sentence's are not.
 * Four digits inside a hash are chance, and every chained record a package
 * carries is full of hashes: redacted there, a line would lose its content
 * for one; found there, the scan would refuse the package for a leak that is
 * not one. Leaving a real value in is the worse failure, so every other place
 * counts. The redaction and the scan hold to the same rule, over text, UTF-8
 * and UTF-16LE bytes and file names; it reads ASCII classes only, so the
 * scan's lower-cased text and the original agree.
 */
const SHORT_WORD = 8;
/** How far a run is read either side of the word: enough to tell a hash or a blob, bounded for a file of one. */
const RUN_WINDOW = 64;
const isDigit = (c: number | undefined) => c !== undefined && c >= 0x30 && c <= 0x39;
const isLetter = (c: number | undefined) => c !== undefined && ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a));
const isHex = (c: number | undefined) => isDigit(c) || (c !== undefined && ((c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66)));
const isBase64 = (c: number | undefined) => isDigit(c) || isLetter(c) || c === 0x2b || c === 0x2f;
const isBase64Url = (c: number | undefined) => isDigit(c) || isLetter(c) || c === 0x2d || c === 0x5f;
/**
 * Whether a short word found at a place is part of a longer run that makes
 * it something else (the rule above). `at(k)` is the character k places from
 * where the word starts (negative before it), undefined past either end; the
 * word is `n` characters.
 */
function partOfLongerRun(at: (k: number) => number | undefined, n: number): boolean {
  if ((isDigit(at(0)) && isDigit(at(-1))) || (isDigit(at(n - 1)) && isDigit(at(n)))) return true;
  const run = (ok: (c: number | undefined) => boolean): [number, number] | null => {
    for (let k = 0; k < n; k += 1) if (!ok(at(k))) return null;
    let l = 0;
    while (l > -RUN_WINDOW && ok(at(l - 1))) l -= 1;
    let r = n;
    while (r < n + RUN_WINDOW && ok(at(r))) r += 1;
    return [l, r];
  };
  /** Whether the run holds a character of this class outside the word itself. */
  const own = ([l, r]: [number, number], test: (c: number | undefined) => boolean) => {
    for (let k = l; k < r; k += 1) if ((k < 0 || k >= n) && test(at(k))) return true;
    return false;
  };
  const hex = run(isHex);
  if (hex && hex[1] - hex[0] >= 16 && own(hex, isDigit)) return true;
  for (const ok of [isBase64, isBase64Url]) {
    const b = run(ok);
    if (!b || b[1] - b[0] < 20 || !own(b, isDigit) || !own(b, isLetter)) continue;
    let separators = 0;
    for (let k = b[0]; k < b[1]; k += 1) if (!isDigit(at(k)) && !isLetter(at(k))) separators += 1;
    if (separators * 8 < b[1] - b[0]) return true;
  }
  return false;
}
/** Each place `word` stands in `text` by that rule. */
function wordPlaces(text: string, word: string): number[] {
  const out: number[] = [];
  if (!word) return out;
  const short = word.length < SHORT_WORD;
  for (let i = text.indexOf(word); i >= 0; i = text.indexOf(word, i + 1)) {
    if (short && partOfLongerRun((k) => (i + k >= 0 && i + k < text.length ? text.charCodeAt(i + k) : undefined), word.length)) continue;
    out.push(i);
  }
  return out;
}
const holdsWord = (text: string, word: string) => wordPlaces(text, word).length > 0;
/** `text` with every place `word` stands replaced by `by`, and how many there were. */
function replaceWord(text: string, word: string, by: string): { text: string; count: number } {
  let out = "";
  let from = 0;
  let count = 0;
  for (const i of wordPlaces(text, word)) {
    if (i < from) continue;
    out += text.slice(from, i) + by;
    from = i + word.length;
    count += 1;
  }
  return { text: out + text.slice(from), count };
}
/** The same rule over bytes: `unit` is 1 for UTF-8, 2 for UTF-16LE (a character is a little-endian code unit). */
function bytesHoldWord(buf: Buffer, word: Buffer, unit: 1 | 2, short: boolean): boolean {
  if (!short) return buf.includes(word);
  for (let i = buf.indexOf(word); i >= 0; i = buf.indexOf(word, i + 1)) {
    const at = (k: number): number | undefined => {
      const j = i + k * unit;
      if (j < 0 || j + unit > buf.length) return undefined;
      return unit === 1 ? buf[j] : buf[j] | (buf[j + 1] << 8);
    };
    if (!partOfLongerRun(at, word.length / unit)) return true;
  }
  return false;
}

/** The files a package seals as they are: signatures, tokens, a release's record and its sidecars. Scanned, never rewritten. */
function sealedAsIs(rel: string): boolean {
  if (["MANIFEST.txt", "MANIFEST.txt.sig", "SIGNER.txt", "signer.pub", "REDACTIONS.txt", "REDACTIONS.json", "COMPONENTS.json", "custody.json.sig", "custody.json.tsr"].includes(rel)) return true;
  return /^release\/v\d+\/(release\.json(\.sig(\.tsr|\.ots)?)?|timestamp\.json|mirror-\d+\.json|print-\d+\.json|transparency-\d+\.json|case-file\.txt)$/.test(rel);
}

const MAX_MARK_FILE = 8 * 1024 * 1024;

/**
 * The files a coverage or receipt marks secret_bearing: its `secret_bearing` object, `{ "<file>": "<why>" }`, read by shape. A name must be a plain relative
 * path (no `..`, not absolute, no NUL) and the reason a string, one line, cut at 160 characters; any other entry is no mark, and every mark of the file is read
 * (a file is read whole up to 8 MiB). A file that carries the word `secret_bearing` and cannot be read as a mark (over 8 MiB, or not JSON) is `unread`: the
 * caller withholds what stands beside it, never lets it through.
 */
export function secretBearingMarks(file: string): { marks: Array<{ name: string; why: string }>; unread: string | null } {
  const none = { marks: [], unread: null };
  let size: number;
  try {
    size = statSync(file).size;
  } catch {
    return none;
  }
  if (size > MAX_MARK_FILE) {
    // too big to parse: is it a mark file at all? The word is looked for in the bytes, a block at a time.
    let found = false;
    let fd = -1;
    try {
      fd = openSync(file, "r");
      const buf = Buffer.alloc(1 << 20);
      let tail = "";
      for (;;) {
        const n = readSync(fd, buf, 0, buf.length, null);
        if (n <= 0) break;
        const text = tail + buf.subarray(0, n).toString("latin1");
        if (text.includes("secret_bearing")) {
          found = true;
          break;
        }
        tail = text.slice(-16);
      }
    } catch {
      found = true; // a file that cannot be read to the end is not shown to be no mark
    } finally {
      if (fd >= 0) closeSync(fd);
    }
    return found ? { marks: [], unread: `larger than ${MAX_MARK_FILE} bytes` } : none;
  }
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    return { marks: [], unread: "it could not be read" };
  }
  if (!text.includes("secret_bearing")) return none;
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return { marks: [], unread: "it is not JSON that parses" };
  }
  const mark = doc && typeof doc === "object" && !Array.isArray(doc) ? (doc as Record<string, unknown>).secret_bearing : undefined;
  if (!mark || typeof mark !== "object" || Array.isArray(mark)) return none;
  const marks: Array<{ name: string; why: string }> = [];
  for (const [name, why] of Object.entries(mark as Record<string, unknown>)) {
    if (typeof why !== "string" || !name || name.includes("\0") || isAbsolute(name) || name.split(/[\\/]/).includes("..")) continue;
    marks.push({ name, why: why.replace(/\s+/g, " ").slice(0, 160) });
  }
  return { marks, unread: null };
}

/** A JSON value with every string that holds a sensitive entry's words replaced whole; each replacement recorded by its pointer. */
function redactJsonValue(v: unknown, pointer: string, tokens: SensitiveToken[], replaced: Replaced[]): unknown {
  if (typeof v === "string") {
    const hit = tokens.find((t) => holdsWord(v, t.token));
    if (!hit) return v;
    const t = hit as ScanToken;
    replaced.push({ what: "field", entry: t.output ? null : t.seq, sha256_of_original: t.id ?? sha256(t.token), pointer, why: t.output ? `a field holding the text of a sensitive output (${t.output}), replaced whole` : "a field holding a sensitive entry's words, replaced whole" });
    return REDACTED;
  }
  if (Array.isArray(v)) return v.map((x, i) => redactJsonValue(x, `${pointer}/${i}`, tokens, replaced));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, redactJsonValue(x, `${pointer}/${k.replace(/~/g, "~0").replace(/\//g, "~1")}`, tokens, replaced)]));
  return v;
}

/**
 * How much of a file one look holds, beside the overlap that keeps a word
 * across two looks whole. Its text is decoded and normalised a window at a
 * time, which costs several copies of the window: 8 MiB keeps the scan of a
 * 4 GB package under 1 GB of memory, at the same speed as 32 MiB.
 */
export const SCAN_WINDOW = 8 * 1024 * 1024;

/**
 * Every packaged file searched for what redaction should have taken out:
 * each sensitive entry's words, normalised (lower case, one kind of path
 * separator, JSON escapes read), in a text file's text, and as UTF-8 and
 * UTF-16 bytes in any file (a PDF's compressed text is not read); with
 * `digests`, each sensitive output's sha256 as it may stand in a record;
 * with `filenames`, a path whose own name holds a sensitive value. A hit is
 * named by the file and a commitment to the word (its sha256, or a keyed id
 * for low-entropy content), never the word.
 *
 * Linear in the bytes read: every word and digest is found in one pass of
 * one automaton per form (multi-match.ts), the file read in windows of
 * SCAN_WINDOW that overlap by the longest form and the context a short word
 * is judged by, nothing left unread. Each window is text when no NUL stands
 * in its first 8 KiB. It used to search for each word and each digest on its
 * own, over 32 MiB at a time: the Breadcrumbs package (2,700 words, 1,600
 * digests, 4.2 GB with a 1.37 GB job stderr.log) was still being scanned
 * after two hours at full CPU; it is scanned in under a minute and a half.
 */
export function leakScan(dir: string, tokens: ScanToken[], o: { digests?: ReadonlySet<string>; filenames?: boolean } = {}): { files: number; hits: LeakHit[] } {
  const hits: LeakHit[] = [];
  let files = 0;
  const norm = (s: string) => s.replace(/\\"/g, '"').replace(/\\\//g, "/").replace(/\\\\/g, "\\").toLowerCase().replace(/\\/g, "/");
  const wanted = tokens.map((t) => ({ ...t, n: norm(t.token), raw: [Buffer.from(t.token, "utf8"), Buffer.from(t.token, "utf16le"), Buffer.from(t.token.toLowerCase(), "utf8")] }));
  const digests = [...(o.digests ?? [])];
  // The text forms (each word normalised, then each digest) and the byte forms (UTF-8, UTF-16LE, lower-case UTF-8: word i's at 3i, 3i+1, 3i+2).
  const textForms = [...wanted.map((w) => Buffer.from(w.n, "utf8")), ...digests.map((d) => Buffer.from(d, "utf8"))];
  const byteForms = wanted.flatMap((w) => w.raw);
  const textMatch = new MultiMatch(textForms);
  const byteMatch = new MultiMatch(byteForms);
  const longest = Math.max(0, ...textForms.map((b) => b.length), ...byteForms.map((b) => b.length));
  const overlap = scanOverlap(longest);
  for (const abs of walk(dir)) {
    const rel = relative(dir, abs).split("\\").join("/");
    if (rel === "REDACTIONS.txt" || rel === "REDACTIONS.json" || rel === "HYGIENE.json" || rel.startsWith("MANIFEST.txt")) continue;
    files += 1;
    const size = lstatSync(abs).size;
    const seen = new Set<string>();
    const note = (commit: string, entry: number, as: string, extra: { output?: string } = {}) => {
      if (seen.has(`${commit}\u0000${as}`)) return;
      seen.add(`${commit}\u0000${as}`);
      hits.push({ path: rel, entry, token_sha256: commit, as, ...(extra.output ? { output: extra.output } : {}) });
    };
    // A filename that itself holds a sensitive word (an agent named an output after the secret).
    if (o.filenames) for (const w of wanted) if (holdsWord(norm(rel), w.n)) note(w.id ?? sha256(w.token), w.seq, "filename", { output: w.output });
    if (!wanted.length && !digests.length) continue;
    const fd = openSync(abs, "r");
    const buf = Buffer.allocUnsafe(Math.max(1, Math.min(size, SCAN_WINDOW + overlap)));
    try {
      for (let off = 0; off < Math.max(size, 1); off += SCAN_WINDOW) {
        const len = Math.min(SCAN_WINDOW + overlap, size - off);
        if (len <= 0) break;
        let got = 0;
        while (got < len) {
          const n = readSync(fd, buf, got, len - got, off + got);
          if (n <= 0) break;
          got += n;
        }
        const win = buf.subarray(0, got);
        // A short word is judged only where its context is whole in this
        // window: the file's own start or end, or RUN_WINDOW characters on
        // each side. One cut by the window's edge is judged in the window
        // where it is whole (the overlap gives every occurrence one): judged
        // cut, a PIN at the start of a hash that ran on past the edge read
        // as a leak, and a redacted package was refused for it.
        const first = off === 0;
        const last = off + got >= size;
        const whole = (b: Buffer, start: number, end: number, unit: 1 | 2) => (first || start >= RUN_WINDOW * unit) && (last || end + RUN_WINDOW * unit <= b.length);
        const inText = new Uint8Array(wanted.length);
        const inBytes = new Uint8Array(wanted.length);
        const digestHit = new Uint8Array(digests.length);
        // Text when no NUL stands in its first 8 KiB; any window's bytes are searched either way.
        const text = !win.subarray(0, 8192).includes(0) ? Buffer.from(norm(win.toString("utf8")), "utf8") : null;
        if (text) {
          textMatch.scan(text, (id, end) => {
            const n = textMatch.lengths[id]!;
            for (const k of textMatch.owners[id]!) {
              if (k >= wanted.length) {
                digestHit[k - wanted.length] = 1;
                continue;
              }
              if (inText[k]) continue;
              // The text's classes are ASCII: its UTF-8 bytes tell a longer run as its characters do.
              if (wanted[k]!.n.length < SHORT_WORD && (!whole(text, end - n, end, 1) || partOfLongerRun(byteAt(text, end - n, 1), n))) continue;
              inText[k] = 1;
            }
          });
        }
        byteMatch.scan(win, (id, end) => {
          const n = byteMatch.lengths[id]!;
          for (const k of byteMatch.owners[id]!) {
            const i = Math.floor(k / 3);
            if (inText[i] || inBytes[i]) continue;
            const unit = k % 3 === 1 ? 2 : 1;
            if (wanted[i]!.token.length < SHORT_WORD && (!whole(win, end - n, end, unit) || partOfLongerRun(byteAt(win, end - n, unit), n / unit))) continue;
            inBytes[i] = 1;
          }
        });
        wanted.forEach((w, i) => {
          if (inText[i]) note(w.id ?? sha256(w.token), w.seq, "text", { output: w.output });
          else if (inBytes[i]) note(w.id ?? sha256(w.token), w.seq, "bytes", { output: w.output });
        });
        // A sensitive output's digest left in a record: named, never printed.
        if (text) digests.forEach((d, i) => {
          if (digestHit[i]) note(`digest:${d.slice(0, 12)}`, 0, "digest");
        });
      }
    } finally {
      closeSync(fd);
    }
  }
  return { files, hits };
}

/**
 * How far one window of the scan runs past the next one's start, for forms
 * at most `longest` bytes: a form whole in some window (twice its length: an
 * escaped character takes two bytes in the file for one in the text), and a
 * short word's context whole there on both sides (RUN_WINDOW characters,
 * with room for UTF-16, escapes and case folding that shortens a character).
 * An occurrence starting at p is whole in the window that starts at the
 * last multiple of SCAN_WINDOW at or before p minus that context.
 */
export function scanOverlap(longest: number): number {
  return 2 * longest + 16 * RUN_WINDOW;
}

/** The character `k` places from `start` in `buf`, read `unit` bytes a character (1 for UTF-8, 2 for UTF-16LE), undefined past either end. */
function byteAt(buf: Buffer, start: number, unit: 1 | 2): (k: number) => number | undefined {
  return (k: number) => {
    const j = start + k * unit;
    if (j < 0 || j + unit > buf.length) return undefined;
    return unit === 1 ? buf[j] : buf[j]! | (buf[j + 1]! << 8);
  };
}

/**
 * Redact a package in place: what every sensitive entry says, and what it
 * cites, taken out before the manifest is written, and each change
 * recorded with what it replaced (the sha256 of the original, why, which
 * entry). The chained files keep their chains: a redacted line carries the
 * hash the next line names (the ledger, its attestations and disputes keep
 * seq, kind or act, target, prev and hash; the trace, the journal and the
 * review, the line's own sha256). A JSON file is redacted field by field,
 * keeping its shape; any other text file word by word; a PDF a release
 * printed, which words cannot be taken out of, is withheld. The signed
 * records (a release, a token, a signature) are sealed as they are. Then
 * every file is scanned for what should have been taken out: `leaks: fail`
 * (the default) refuses the package on a hit, `list` records the hits.
 */
export async function redactPackage(sandbox: string, dir: string, opts: { leaks?: "fail" | "list" } = {}): Promise<{ entries: number; files: number; lines: number; leaks: LeakHit[]; scanned: number; withheld: Withheld[] }> {
  // An entry citing a sensitive output is sensitive whether or not it was
  // recorded so (an entry from before the harness marked such entries):
  // taken out the same way (docs/adr/0016).
  const raw = await readLedger(sandbox, { raw: true });
  const derived = await sensitiveEntries(sandbox, raw);
  const entries = raw.map((e) => (derived.has(e.seq) && !e.sensitive ? { ...e, sensitive: true } : e));
  const index = await sensitiveIndex(sandbox);
  const words = await outputWords(sandbox);
  const sensitiveSeqs = new Set(entries.filter((e) => e.sensitive).map((e) => e.seq));
  const unmarked = raw.filter((e) => !e.sensitive && derived.has(e.seq)).map((e) => e.seq);
  const sensitiveHashes = new Set(entries.filter((e) => e.sensitive && e.hash).map((e) => e.hash as string));
  // The bytes a sensitive job wrote, by digest (its outputs and logs), so a
  // copy anywhere in the run is withheld by its content, not by its path; the
  // empty digest is not one of them, or every empty file would be withheld.
  const EMPTY = sha256(Buffer.alloc(0));
  const sensitiveDigests = new Set([...index.content.keys()].filter((d) => d !== EMPTY));
  // A keyed, non-reversible commitment for what is withheld or matched: a
  // recipient cannot brute-force a low-entropy value from it, and the key
  // lives only in the private sidecar the run's owner keeps, outside the
  // handover (docs/adr/0016). The real digests and paths go there too.
  const key = randomBytes(32);
  const hidden = new Map<string, string>();
  const idFor = (value: string): string => {
    const got = hidden.get(value);
    if (got) return got;
    const id = `hidden-${createHmac("sha256", key).update(value).digest("hex").slice(0, 24)}`;
    hidden.set(value, id);
    return id;
  };
  const privateMap: Record<string, { of: "digest" | "path" | "word"; sha256?: string; path?: string; why?: string }> = {};
  /** Hide a real digest behind its keyed id, and record the truth in the private sidecar. */
  const hideDigest = (sha: string, why: string, path?: string): string => {
    const id = idFor(`digest:${sha}`);
    privateMap[id] = { of: "digest", sha256: sha, ...(path ? { path } : {}), why };
    return id;
  };
  /** A path fit to appear in the handover's own records: a basename holding a sensitive word is hidden behind a keyed id, the real path kept in the sidecar. */
  const safePath = (rel: string): string => {
    if (!tokens.some((t) => forms(t.token).some((f) => holdsWord(rel, f)))) return rel;
    const dir_ = rel.includes("/") ? `${rel.slice(0, rel.lastIndexOf("/"))}/` : "";
    const id = idFor(`path:${rel}`);
    privateMap[id] = { of: "path", path: rel, why: "a path whose name holds a sensitive value" };
    return `${dir_}${id}`;
  };
  // The words the scan and the field redaction look for: a sensitive entry's,
  // and the whole text of each small sensitive output (a low-entropy secret),
  // the latter behind a keyed id so a hit names no recoverable value.
  const tokens: ScanToken[] = [
    ...sensitiveTokens(entries).map((t) => {
      const id = idFor(`word:${t.token}`);
      privateMap[id] = { of: "word", why: `a sensitive entry's words (E-${t.seq})` };
      return { ...t, id } as ScanToken;
    }),
    ...words.map((w) => {
      const id = idFor(`word:${w.token}`);
      privateMap[id] = { of: "word", why: `the text of a sensitive output (job ${w.job}, ${w.path})` };
      return { token: w.token, seq: 0, output: `job ${w.job}, ${w.path}`, id } as ScanToken;
    }),
  ];
  const changes: RedactionChange[] = [];
  let lines = 0;
  const change = (rel: string, before: Buffer, after: Buffer | string, why: string, replaced: Replaced[]) => {
    writeFileSync(join(dir, rel), after);
    changes.push({ path: rel, before_sha256: sha256(before), after_sha256: sha256(after), why, replaced });
  };
  const holds = (l: string) => tokens.find((t) => forms(t.token).some((f) => holdsWord(l, f)));
  const handled = new Set<string>();
  // A chained file, line by line: `keep` says what a redacted line keeps of the one it replaces.
  const chained = (rel: string, judge: (o: Record<string, unknown>, raw: string) => { seq: number | null; why: string } | null, keep: (o: Record<string, unknown>, raw: string) => Record<string, unknown>, what: Replaced["what"], why: string) => {
    handled.add(rel);
    if (!existsSync(join(dir, rel))) return;
    const before = readFileSync(join(dir, rel));
    const replaced: Replaced[] = [];
    let n = 0;
    const out = before
      .toString("utf8")
      .split("\n")
      .map((l) => {
        if (!l.trim()) return l;
        n += 1;
        let o: Record<string, unknown>;
        try {
          o = JSON.parse(l) as Record<string, unknown>;
        } catch {
          return l;
        }
        const j = judge(o, l);
        if (!j) return l;
        replaced.push({ what, entry: j.seq, sha256_of_original: sha256(l), line: n, why: j.why });
        return JSON.stringify(keep(o, l));
      })
      .join("\n");
    if (replaced.length) {
      lines += replaced.length;
      change(rel, before, out, `${replaced.length} ${why}`, replaced);
    }
  };
  const byWords = (l: string) => {
    const t = holds(l);
    return t ? { seq: t.output ? null : t.seq, why: t.output ? `holds the text of a sensitive output (${t.output})` : "holds a sensitive entry's words" } : null;
  };
  // The ledger: a sensitive entry, and any entry that repeats one's words, keeps what chains it.
  chained(
    "ledger.jsonl",
    (o, l) => (sensitiveSeqs.has(Number(o.seq)) ? { seq: Number(o.seq), why: "marked sensitive" } : byWords(l)),
    (o, l) => ({ v: o.v, seq: o.seq, kind: o.kind, redacted: true, line_sha256: sha256(l), ...(o.prev ? { prev: o.prev } : {}), ...(o.hash ? { hash: o.hash } : {}), ...(o.refs ? { refs: o.refs } : {}) }),
    "entry",
    "entr(y|ies) sensitive, or holding a sensitive entry's words, replaced by their seq, kind, chain hashes and line hash",
  );
  // An agent's act on a sensitive entry, or one that says its words: the act, the target and the chain kept.
  for (const rel of ["ledger-attestations.jsonl", "ledger-disputes.jsonl"]) {
    chained(
      rel,
      (o, l) => (typeof o.target === "string" && sensitiveHashes.has(o.target) ? { seq: Number(o.seq), why: "an act on a sensitive entry" } : byWords(l)),
      (o, l) => ({ ...(o.v !== undefined ? { v: o.v } : {}), ...(o.act ? { act: o.act } : {}), seq: o.seq, ...(o.target ? { target: o.target } : {}), redacted: true, line_sha256: sha256(l), prev: o.prev, hash: o.hash }),
      "line",
      "act(s) on or holding a sensitive entry, replaced keeping act, target, prev and hash",
    );
  }
  // A store sweep of a sensitive coverage record, one that found its strings in a sensitive job's output, or one that says a sensitive entry's words (its looked_for terms, its hits' refs): the sweep kept by what chains it.
  chained(
    "ledger-sweeps.jsonl",
    (o, l) => {
      if (typeof o.target === "string" && sensitiveHashes.has(o.target)) return { seq: Number(o.seq), why: "the sweep of a sensitive coverage record" };
      type Hit = { ref?: string; also?: string[]; origins?: Array<{ by?: string; reads?: string[] }> };
      const hits = [...((o.hits as Hit[] | undefined) ?? []), ...((o.named_hits as Hit[] | undefined) ?? []), ...((o.echoes as Hit[] | undefined) ?? [])];
      const refs = hits.flatMap((h) => [h.ref ?? "", ...(h.also ?? []), ...(h.origins ?? []).flatMap((x) => [x.by ?? "", ...(x.reads ?? [])])]);
      const job = refs.map((r) => /^job:([^/]+)/.exec(r)?.[1]).find((id) => id && index.jobs.has(id));
      if (job) return { seq: Number(o.seq), why: `found its strings in a sensitive output (job ${job})` };
      return byWords(l);
    },
    (o, l) => ({ v: o.v, seq: o.seq, target: o.target, state: o.state, redacted: true, line_sha256: sha256(l), prev: o.prev, hash: o.hash }),
    "line",
    "store sweep(s) of a sensitive record, or holding a sensitive word or a sensitive output's ref, replaced keeping seq, target, state, prev and hash",
  );
  if (tokens.length) {
    // The finish register: an event that repeats a sensitive entry's words (an ack's why, a resolution), kept by what chains it.
    chained("finish.jsonl", (_o, l) => byWords(l), (o, l) => ({ v: o.v, seq: o.seq, ev: o.ev, redacted: true, line_sha256: sha256(l), prev: o.prev, hash: o.hash }), "line", "finish event(s) holding a sensitive entry's words replaced, keeping seq, ev, prev and hash");
    // A lead that repeats a sensitive entry's words: its event kept by what chains it.
    chained("leads.jsonl", (_o, l) => byWords(l), (o, l) => ({ v: o.v, seq: o.seq, ev: o.ev, ...(o.lead ? { lead: o.lead } : {}), redacted: true, line_sha256: sha256(l), prev: o.prev, hash: o.hash }), "line", "lead event(s) holding a sensitive entry's words replaced, keeping seq, ev, lead, prev and hash");
    // A question that repeats a sensitive entry's words, the same way.
    chained("questions.jsonl", (_o, l) => byWords(l), (o, l) => ({ v: o.v, seq: o.seq, ev: o.ev, ...(o.q ? { q: o.q } : {}), redacted: true, line_sha256: sha256(l), prev: o.prev, hash: o.hash }), "line", "question event(s) holding a sensitive entry's words replaced, keeping seq, ev, q, prev and hash");
    if (existsSync(join(dir, "questions.md"))) {
      const before = readFileSync(join(dir, "questions.md"));
      const hit = holds(before.toString("utf8"));
      handled.add("questions.md");
      if (hit) change("questions.md", before, `${REDACTED}: the rendered question register repeats a sensitive entry's words; questions.jsonl carries every event (those redacted by their hashes); its sha256 before redaction is ${sha256(before)}\n`, "the rendered register holds a sensitive entry's words, replaced whole", [{ what: "file", entry: hit.seq, sha256_of_original: sha256(before), why: "repeats a sensitive entry's words" }]);
    }
    if (existsSync(join(dir, "leads.md"))) {
      const before = readFileSync(join(dir, "leads.md"));
      const hit = holds(before.toString("utf8"));
      handled.add("leads.md");
      if (hit) change("leads.md", before, `${REDACTED}: the rendered lead register repeats a sensitive entry's words; leads.jsonl carries every event (those redacted by their hashes); its sha256 before redaction is ${sha256(before)}\n`, "the rendered register holds a sensitive entry's words, replaced whole", [{ what: "file", entry: hit.seq, sha256_of_original: sha256(before), why: "repeats a sensitive entry's words" }]);
    }
    chained("trace/events.jsonl", (_o, l) => byWords(l), (_o, l) => ({ redacted: true, line_sha256: sha256(l) }), "line", "line(s) holding a sensitive entry's words replaced by their own sha256");
    chained("store/journal.jsonl", (_o, l) => byWords(l), (o, l) => ({ v: o.v, seq: o.seq, type: o.type, ...(o.job ? { job: o.job } : {}), redacted: true, line_sha256: sha256(l), prev: o.prev ?? null }), "line", "journal line(s) holding a sensitive entry's words replaced, keeping seq, prev and their own sha256");
    chained("review.jsonl", (_o, l) => byWords(l), (o, l) => ({ v: o.v, seq: o.seq, action: o.action, redacted: true, line_sha256: sha256(l), prev: o.prev ?? null }), "line", "review line(s) holding a sensitive entry's words replaced, keeping seq, action, prev and their own sha256");
  }
  // A sensitive output, and its job's stdout and stderr, withheld whole
  // (docs/adr/0016): by the bytes they hold, so a copy anywhere in the run —
  // work/, a catalogue link, a second job's output — is withheld too, not
  // only the canonical store path. The bytes are not read to decide what in
  // them is secret, and the handover names each by a keyed id, never by the
  // sha256 that would let a low-entropy value be brute-forced; the real
  // digest and path are in the private sidecar. A basename that itself holds
  // a secret is hidden in the recorded path.
  const withheld: Withheld[] = [];
  const patterns = withheldPaths(index);
  const withholdPath = (rel: string, before: Buffer, why: string, jobId: string | null) => {
    const sha = sha256(before);
    const id = hideDigest(sha, why, rel);
    handled.add(rel);
    change(rel, before, `[withheld: sensitive content (${why}); matched ${id}. Its bytes, digest and path are in the run owner's private sidecar, not here.]\n`, `sensitive content, withheld whole (${why})`, [{ what: "file", entry: null, sha256_of_original: id, why }]);
    withheld.push({ path: safePath(rel), job: jobId, why, sha256_of_original: id, bytes: before.length });
  };
  if (patterns.length || sensitiveDigests.size) {
    for (const abs of walk(dir)) {
      const rel = relative(dir, abs).split("\\").join("/");
      if (handled.has(rel) || sealedAsIs(rel)) continue;
      const before = readFileSync(abs);
      const byContent = sensitiveDigests.has(sha256(before)) ? (index.content.get(sha256(before)) ?? null) : null;
      const byPath = patterns.find((p) => p.rel.test(rel));
      if (byContent) withholdPath(rel, before, `bytes a sensitive job wrote (job ${byContent})`, byContent);
      else if (byPath) withholdPath(rel, before, byPath.why, byPath.job);
    }
  }
  // A file a recipe's coverage or receipt marks secret_bearing, whole, by the mark's shape and never by the name of a tool or a recipe: a JSON file with a
  // `secret_bearing` object that maps a file name (a plain relative path beside the JSON) to the reason as a string. A recipe cannot declare secret_output
  // (the seal refuses the key in recipe.json), so this mark is how it says "this file holds what the evidence holds"; the file is withheld the way a
  // sensitive job's output is, its digest and path in the private sidecar. A `secret_bearing` of counts (a number) or a list is an answer field, not a mark.
  // A mark that cannot be honoured fails closed: a file that carries the word and cannot be read as a mark (over 8 MiB, not JSON), and a mark that names a
  // link or anything but a regular file inside the package, withhold every file of the directory the mark file stands in, and below it. The record says so.
  const besideUnreadable = (markRel: string, why: string) => {
    const root = markRel.includes("/") ? markRel.slice(0, markRel.lastIndexOf("/") + 1) : "";
    for (const abs2 of walk(dir)) {
      const rel2 = relative(dir, abs2).split("\\").join("/");
      if (rel2 === markRel || handled.has(rel2) || sealedAsIs(rel2) || (root && !rel2.startsWith(root))) continue;
      withholdPath(rel2, readFileSync(abs2), `beside ${markRel}, a secret_bearing mark that was not honoured whole (${why})`, null);
    }
  };
  for (const abs of walk(dir)) {
    const rel = relative(dir, abs).split("\\").join("/");
    if (!/\.json$/i.test(rel) || handled.has(rel) || sealedAsIs(rel)) continue;
    const read = secretBearingMarks(abs);
    if (read.unread) {
      besideUnreadable(rel, read.unread);
      continue;
    }
    for (const m of read.marks) {
      const target = relative(dir, resolve(dirname(abs), m.name)).split("\\").join("/");
      if (target.startsWith("..") || isAbsolute(target) || sealedAsIs(target)) continue;
      if (handled.has(target) || !existsSync(join(dir, target))) continue;
      if (!lstatSync(join(dir, target)).isFile()) {
        besideUnreadable(rel, `it names ${JSON.stringify(m.name.slice(0, 80))}, which is not a regular file`);
        continue;
      }
      withholdPath(target, readFileSync(join(dir, target)), `marked secret_bearing by ${rel}: ${m.why}`, null);
    }
  }
  // A file a sensitive entry cites, whole; by a keyed id, its digest and path in the sidecar.
  for (const c of citedPaths(entries)) {
    if (!existsSync(join(dir, c.path)) || handled.has(c.path)) continue;
    const before = readFileSync(join(dir, c.path));
    const id = hideDigest(sha256(before), `cited by a sensitive entry (E-${c.seq})`, c.path);
    handled.add(c.path);
    change(c.path, before, `${REDACTED}: cited by a sensitive ledger entry (E-${c.seq}); matched ${id} (its bytes and digest are in the run owner's private sidecar)\n`, "cited by a sensitive entry, replaced whole", [{ what: "file", entry: c.seq, sha256_of_original: id, why: "cited by a sensitive entry" }]);
  }
  // Every occurrence of a sensitive digest in a text file (a manifest, a
  // job record, the store journal, a revision index) is the content's name:
  // replaced by its keyed id, so the handover carries no digest a low-entropy
  // value could be brute-forced from.
  const digestList = [...sensitiveDigests];
  const replaceDigests = (text: string, replaced: Replaced[]): string => {
    let t = text;
    for (const sha of digestList) {
      if (!t.includes(sha)) continue;
      const id = hideDigest(sha, "the digest of a sensitive output");
      const count = t.split(sha).length - 1;
      t = t.split(sha).join(id);
      replaced.push({ what: "text", entry: null, sha256_of_original: id, count, why: "the digest of a sensitive output" });
    }
    return t;
  };
  let files = 0;
  if (sensitiveSeqs.size || tokens.length || withheld.length || sensitiveDigests.size) {
    for (const abs of walk(dir)) {
      const rel = relative(dir, abs).split("\\").join("/");
      if (handled.has(rel) || sealedAsIs(rel)) continue;
      const before = readFileSync(abs);
      // A PDF a release printed: words cannot be taken out of it, so it is withheld (by a keyed id, not its digest).
      if (/^release\/v\d+\/.+\.pdf$/.test(rel)) {
        withholdPath(rel, before, "a release's PDF: words cannot be taken out of it", null);
        files += 1;
        continue;
      }
      if (before.subarray(0, 8192).includes(0)) continue;
      const text = before.toString("utf8");
      const hasWord = tokens.length > 0 && Boolean(holds(text));
      const hasDigest = digestList.some((d) => text.includes(d));
      if (!hasWord && !hasDigest) continue;
      const replaced: Replaced[] = [];
      let after: string | null = null;
      // JSON, field by field, keeping its shape.
      if (/\.json$/.test(rel)) {
        try {
          const v = hasWord ? redactJsonValue(JSON.parse(text), "", tokens, replaced) : JSON.parse(text);
          after = `${JSON.stringify(v, null, /\n\s+"/.test(text) ? 2 : undefined)}${text.endsWith("\n") ? "\n" : ""}`;
          after = replaceDigests(after, replaced);
        } catch {
          after = null;
        }
      } else if (/\.jsonl$/.test(rel)) {
        const out: string[] = [];
        let ok = true;
        text.split("\n").forEach((l, i) => {
          if (!l.trim() || (!holds(l) && !digestList.some((d) => l.includes(d)))) return out.push(l);
          try {
            const v = holds(l) ? redactJsonValue(JSON.parse(l), `${i + 1}`, tokens, replaced) : JSON.parse(l);
            out.push(replaceDigests(JSON.stringify(v), replaced));
          } catch {
            ok = false;
            out.push(l);
          }
        });
        after = ok ? out.join("\n") : null;
      }
      if (after === null) {
        // Any other text: the words and the digests replaced where they stand.
        replaced.length = 0;
        let t = text;
        for (const tok of tokens) {
          for (const f of forms(tok.token)) {
            const r = replaceWord(t, f, REDACTED);
            const count = r.count;
            if (!count) continue;
            t = r.text;
            replaced.push({ what: "text", entry: tok.output ? null : tok.seq, sha256_of_original: tok.id ?? sha256(tok.token), count, why: tok.output ? `the text of a sensitive output (${tok.output})` : "a sensitive entry's words" });
          }
        }
        t = replaceDigests(t, replaced);
        after = t;
      }
      if (replaced.length) {
        files += 1;
        change(rel, before, after, /\.jsonl?$/.test(rel) && replaced.every((r) => r.what === "field") ? "fields holding a sensitive entry's words replaced whole" : "a sensitive entry's words or output digests replaced", replaced);
      }
    }
  }
  // The records' own paths are sanitised: a filename that holds a secret is a keyed id here too.
  const changesOut = changes.map((c) => ({ ...c, path: safePath(c.path) }));
  // What should have been taken out, looked for everywhere now, over the whole
  // package including the records generated below and the filenames.
  const scan = leakScan(dir, tokens, { digests: sensitiveDigests, filenames: true });
  const hitsOut = scan.hits.map((h) => ({ ...h, path: safePath(h.path) }));
  const mode = opts.leaks ?? "fail";
  // The private sidecar, beside the package and never inside it: the run's
  // owner matches a keyed id to its real digest, path or word through this; a
  // recipient never has it (docs/adr/0016). Written after every id is minted,
  // and it is not under the package's directory, so the scan never reads it.
  writeFileSync(`${dir.replace(/\/$/, "")}.private.json`, `${JSON.stringify({ v: 1, note: "Kept by the run's owner, NEVER handed over: the keyed ids in this package's REDACTIONS and withheld stubs, each to the real digest, path or word it stands for. Without it the ids reveal nothing.", key_note: "The ids are HMAC-SHA256 of the value under a per-package key held only here.", map: privateMap }, null, 2)}\n`, { mode: 0o600 });
  writeFileSync(
    join(dir, "REDACTIONS.txt"),
    [
      "Redactions",
      "==========",
      "",
      `This package was made with --redact. ${sensitiveSeqs.size} ledger entr${sensitiveSeqs.size === 1 ? "y was" : "ies were"} marked sensitive (seq ${[...sensitiveSeqs].join(", ") || "none"})${unmarked.length ? `, ${unmarked.length} of them because ${unmarked.length === 1 ? "it cites" : "they cite"} a sensitive output (seq ${unmarked.join(", ")})` : ""}.`,
      `${index.jobs.size} job${index.jobs.size === 1 ? "'s" : "s'"} outputs were sensitive (${[...index.jobs.values()].map((j) => `${j.id}: ${j.sensitivity.why === "secret_output" ? "secret_output" : `derived from ${j.sensitivity.from.join(", ")}`}`).join("; ") || "none"}).`,
      "What they say, and the objects they cite, are not in it. A chained file keeps its chain: a redacted",
      "line carries the sha256 of the line it replaces, which the next line's prev names. Withheld or matched",
      "sensitive content is named by a keyed id, never by a digest a low-entropy value could be brute-forced",
      "from; the run's owner matches it through the private sidecar kept outside this package. REDACTIONS.json",
      "records each change, what was withheld whole and the leak scan over every file.",
      `Leak scan: ${scan.hits.length ? `${scan.hits.length} HIT(S) over ${scan.files} file(s), LISTED in REDACTIONS.json (made with --redact-leaks list)` : `nothing found over ${scan.files} file(s)`}.`,
      "",
      `Withheld whole: ${withheld.length ? "" : "nothing"}`,
      ...withheld.map((w) => `${w.sha256_of_original}  ${String(w.bytes).padStart(12)}  ${w.path}  ${w.why}`),
      "",
      "sha256 before                                                    sha256 after                                                     path  why",
      ...changesOut.map((c) => `${c.before_sha256}  ${c.after_sha256}  ${c.path}  ${c.why}`),
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(dir, "REDACTIONS.json"),
    `${JSON.stringify(
      {
        v: 1,
        note: "What this package's redaction replaced: each change with what it replaced (a keyed id, or the sha256 of a line that carries no secret), why, and which entry; then every file scanned. Sensitive content is named by a keyed id whose truth is in the private sidecar the run's owner keeps, outside this package. Under MANIFEST.txt and its signature.",
        entries: entries.filter((e) => e.sensitive).map((e) => ({ seq: e.seq, kind: e.kind, hash: e.hash ?? null, why: derived.get(e.seq) ?? "marked sensitive" })),
        sensitive_outputs: [...index.jobs.values()].map((j) => ({ job: j.id, why: j.sensitivity.why, from: j.sensitivity.from, status: j.status, files: j.files.length, withheld: withheld.filter((w) => w.job === j.id).length })),
        words: tokens.length,
        output_words: words.length,
        withheld: withheld.map((w) => ({ id: w.sha256_of_original, job: w.job, why: w.why, bytes: w.bytes, path: w.path })),
        changes: changesOut,
        leak_scan: { mode, files: scan.files, hits: hitsOut },
      },
      null,
      2,
    )}\n`,
  );
  return { entries: sensitiveSeqs.size, files, lines, leaks: scan.hits, scanned: scan.files, withheld };
}

/**
 * The hygiene of a package made without --redact (docs/adr/0016): what in it
 * is sensitive, named, never taken out. Every sensitive ledger entry (marked,
 * or citing a sensitive output) and every sensitive job output with whether
 * the package carries it, then every file of the package scanned for the
 * sensitive entries' words and the small sensitive outputs' text, each hit
 * by file, entry or output, and the word's sha256. Written to HYGIENE.json,
 * under the manifest. A package to hand over is made with --redact.
 */
export async function hygieneReport(sandbox: string, dir: string): Promise<{ entries: number; outputs: number; carried: number; hits: LeakHit[]; scanned: number }> {
  const raw = await readLedger(sandbox, { raw: true });
  const derived = await sensitiveEntries(sandbox, raw);
  const entries = raw.map((e) => (derived.has(e.seq) && !e.sensitive ? { ...e, sensitive: true } : e));
  const index = await sensitiveIndex(sandbox);
  const words = await outputWords(sandbox);
  // HYGIENE.json names what in the package is sensitive but must not itself
  // disclose a value: a low-entropy output's text and a secret-bearing path
  // are named by a keyed id whose truth is in a private sidecar kept outside
  // the package (docs/adr/0016).
  const key = randomBytes(32);
  const privateMap: Record<string, { of: "word" | "path"; why?: string }> = {};
  const idFor = (value: string) => `hidden-${createHmac("sha256", key).update(value).digest("hex").slice(0, 24)}`;
  const tokens: ScanToken[] = [
    ...sensitiveTokens(entries).map((t) => {
      const id = idFor(`word:${t.token}`);
      privateMap[id] = { of: "word", why: `a sensitive entry's words (E-${t.seq})` };
      return { ...t, id } as ScanToken;
    }),
    ...words.map((w) => {
      const id = idFor(`word:${w.token}`);
      privateMap[id] = { of: "word", why: `the text of a sensitive output (job ${w.job}, ${w.path})` };
      return { token: w.token, seq: 0, output: `job ${w.job}, ${w.path}`, id } as ScanToken;
    }),
  ];
  const EMPTY = sha256(Buffer.alloc(0));
  const sensitiveDigests = new Set([...index.content.keys()].filter((d) => d !== EMPTY));
  // Each file's digest read as a stream (a job's log can be gigabytes), the paths' patterns made once.
  const withheldRules = withheldPaths(index);
  const carriedPaths = walk(dir).map((abs) => relative(dir, abs).split("\\").join("/")).filter((rel) => withheldRules.some((p) => p.rel.test(rel)) || index.content.has(sha256FileSync(join(dir, rel))));
  const scan = tokens.length || sensitiveDigests.size ? leakScan(dir, tokens, { digests: sensitiveDigests, filenames: true }) : { files: 0, hits: [] as LeakHit[] };
  if (derived.size || index.jobs.size) {
    writeFileSync(`${dir.replace(/\/$/, "")}.private.json`, `${JSON.stringify({ v: 1, note: "Kept by the run's owner, NEVER handed over: the keyed ids HYGIENE.json uses, each to the value it stands for.", map: privateMap }, null, 2)}\n`, { mode: 0o600 });
    writeFileSync(
      join(dir, "HYGIENE.json"),
      `${JSON.stringify(
        {
          v: 1,
          note: "This package was made without --redact: what in it is sensitive is named here and left in. Every file was scanned for the sensitive entries' words, the text of the small sensitive outputs and the sensitive outputs' digests; a hit names the file, the entry or output, and a keyed commitment (a sha256, or an id whose truth is in the private sidecar), never the word. A package to hand over is made with --redact.",
          entries: [...derived.entries()].map(([seq, why]) => ({ seq, why })),
          sensitive_outputs: [...index.jobs.values()].map((j) => ({ job: j.id, why: j.sensitivity.why, from: j.sensitivity.from, status: j.status, files: j.files.length, carried: carriedPaths.filter((c) => c.startsWith(`store/jobs/${j.id}/`)).length })),
          carried: carriedPaths.length,
          scan: { files: scan.files, words: tokens.length, hits: scan.hits },
        },
        null,
        2,
      )}\n`,
    );
  }
  return { entries: derived.size, outputs: index.jobs.size, carried: carriedPaths.length, hits: scan.hits, scanned: scan.files };
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

/**
 * The ledger chain, walked as verifyLedgerChain walks it, a redacted entry's
 * hash taken as it stands (its core is not in the package): every other
 * entry's core is recomputed and must give its hash, whatever came before
 * it. A walk that recomputed only the first core let a rewritten entry
 * after a redaction pass on its prev alone.
 */
export function ledgerChain(text: string): { ok: boolean; entries: number; redacted: number; head: string | null; detail: string } {
  const lines = text.split("\n").filter((l) => l.trim());
  let last = "genesis";
  let chained = 0;
  let redacted = 0;
  let newest = 1;
  let n = 0;
  const broken = (why: string) => ({ ok: false, entries: n, redacted, head: null, detail: `broken at entry ${n} (${why})` });
  for (const l of lines) {
    n += 1;
    let e: LedgerEntry & { redacted?: boolean };
    try {
      e = JSON.parse(l) as LedgerEntry & { redacted?: boolean };
    } catch {
      return broken("not json");
    }
    // Versions only go up along the chain, as verifyLedgerChain holds them (ledgerHash dispatches on each).
    const version = typeof e.v === "number" ? e.v : 1;
    if (version < newest) return broken(`a version ${version} entry after version ${newest} ones`);
    newest = version;
    if (e.redacted === true) {
      // Its core is not here: its hash is taken, and it must name the entry before it.
      if (e.prev !== last) return broken(`redacted entry ${e.seq}'s prev does not name the entry before it`);
      if (typeof e.hash !== "string") return broken(`redacted entry ${e.seq} carries no hash`);
      redacted += 1;
      chained += 1;
      last = e.hash;
      continue;
    }
    if (!e.prev && !e.hash) {
      if (chained > 0) return broken("an entry without the chain after chained ones");
      last = ledgerHash(e, "genesis");
      continue;
    }
    if (e.prev !== last) return broken("prev does not name the entry before it");
    if (e.hash !== ledgerHash(e, e.prev)) return broken("the entry's core was rewritten");
    chained += 1;
    last = e.hash;
  }
  const head = chained ? last : null;
  return { ok: true, entries: n, redacted, head, detail: `${n} entries, chain intact${redacted ? `, ${redacted} redacted (their hashes kept, their cores not in the package)` : ""}` };
}

/** The journal's chain, a redacted line counting as the line it replaced; each line's hash and type, to hold it to a sealed head. */
function journalChain(text: string): { ok: boolean; lines: number; redacted: number; head: string | null; detail: string; hashes: string[]; types: string[] } {
  let prev: string | null = null;
  let n = 0;
  let redacted = 0;
  const hashes: string[] = [];
  const types: string[] = [];
  for (const raw of text.split("\n")) {
    if (!raw) continue;
    let o: { seq?: number; prev?: string | null; redacted?: boolean; line_sha256?: string; type?: string };
    try {
      o = JSON.parse(raw);
    } catch {
      return { ok: false, lines: n, redacted, head: null, detail: `CHAIN BROKEN (line ${n + 1} is not JSON)`, hashes, types };
    }
    if ((o.prev ?? null) !== prev) return { ok: false, lines: n, redacted, head: null, detail: `CHAIN BROKEN (line ${n + 1} does not chain to the line before)`, hashes, types };
    if (o.seq !== n) return { ok: false, lines: n, redacted, head: null, detail: `CHAIN BROKEN (line ${n + 1} has seq ${o.seq})`, hashes, types };
    prev = o.redacted && o.line_sha256 ? o.line_sha256 : sha256(raw);
    hashes.push(prev);
    types.push(String(o.type ?? ""));
    if (o.redacted) redacted += 1;
    n += 1;
  }
  return { ok: true, lines: n, redacted, head: prev, detail: `${n} lines, chain intact${redacted ? `, ${redacted} redacted (their hashes kept)` : ""}`, hashes, types };
}

/**
 * An act chain (the attestations, the disputes: each line's hash over its
 * core and the line before), a redacted line's hash taken as it stands (its
 * core is not in the package) once it names the line before it: every other
 * line's hash is recomputed. The same as verifyAttestationChain and
 * verifyDisputeChain on an unredacted chain.
 */
export /**
 * The lead register's chain as a package holds it: each line chains to the
 * one before by its hash; a redacted line keeps its hash, and only its link
 * is checked, as the ledger's are.
 */
function leadChain(text: string): { ok: boolean; total: number; head: string | null; broken_at: number | null; reason: string | null; redacted: number } {
  let prev = "genesis";
  let total = 0;
  let redacted = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let o: Record<string, unknown>;
    try {
      o = JSON.parse(line) as Record<string, unknown>;
    } catch {
      return { ok: false, total, head: null, broken_at: total, reason: "the line is not JSON", redacted };
    }
    if (o.prev !== prev) return { ok: false, total, head: null, broken_at: total, reason: "the line does not chain to the one before", redacted };
    if (o.redacted === true) redacted += 1;
    else if (o.hash !== leadEventHash(o as unknown as LeadEvent, prev)) return { ok: false, total, head: null, broken_at: total, reason: "the line was rewritten", redacted };
    prev = String(o.hash);
  }
  return { ok: true, total, head: total ? prev : null, broken_at: null, reason: null, redacted };
}

function actChain(text: string, hash: (line: Record<string, unknown>, prev: string) => string): { ok: boolean; total: number; redacted: number; head: string | null; broken_at: number | null; reason: string | null } {
  let last = "genesis";
  let total = 0;
  let redacted = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let o: Record<string, unknown>;
    try {
      o = JSON.parse(line) as Record<string, unknown>;
    } catch {
      return { ok: false, total, redacted, head: null, broken_at: total, reason: "not json" };
    }
    if (o.prev !== last) return { ok: false, total, redacted, head: null, broken_at: total, reason: "prev does not name the line before it" };
    if (o.redacted === true) {
      if (typeof o.hash !== "string") return { ok: false, total, redacted, head: null, broken_at: total, reason: "a redacted line carries no hash" };
      redacted += 1;
      last = o.hash;
      continue;
    }
    if (o.hash !== hash(o, last)) return { ok: false, total, redacted, head: null, broken_at: total, reason: "the line was rewritten" };
    last = String(o.hash);
  }
  return { ok: true, total, redacted, head: total ? last : null, broken_at: null, reason: null };
}

/** The examiner's review chain (scripts/review.ts), a redacted line counting as the line it replaced. */
function reviewChain(text: string): { ok: boolean; lines: number; redacted: number; detail: string; signed: { ledger_head?: string; ledger_entries?: number; report_path?: string; report_sha256?: string | null; examiner?: string; at?: string } | null } {
  let prev: string | null = null;
  let n = 0;
  let redacted = 0;
  let signed: ReturnType<typeof reviewChain>["signed"] = null;
  for (const raw of text.split("\n")) {
    if (!raw) continue;
    n += 1;
    let o: { seq?: number; prev?: string | null; action?: string; redacted?: boolean; line_sha256?: string };
    try {
      o = JSON.parse(raw);
    } catch {
      return { ok: false, lines: n, redacted, detail: `BROKEN (line ${n} is not JSON)`, signed };
    }
    if (o.seq !== n) return { ok: false, lines: n, redacted, detail: `BROKEN (line ${n} says seq ${o.seq})`, signed };
    if ((o.prev ?? null) !== prev) return { ok: false, lines: n, redacted, detail: `BROKEN (line ${n} does not follow the line before it)`, signed };
    if (!(REVIEW_ACTIONS as readonly string[]).includes(String(o.action))) return { ok: false, lines: n, redacted, detail: `BROKEN (line ${n} has no known action)`, signed };
    if (o.redacted) redacted += 1;
    else if (o.action === "sign") signed = o as NonNullable<typeof signed>;
    prev = o.redacted && o.line_sha256 ? o.line_sha256 : sha256(raw);
  }
  return { ok: true, lines: n, redacted, detail: `${n} act(s), chain intact${redacted ? `, ${redacted} redacted` : ""}`, signed };
}

/**
 * Every part a recipient holds the record to, by its path in the package:
 * what it is and why it would be absent. `core` parts must be there or be
 * declared absent; `sealed` parts must be there when the verdict sealed any
 * of them; `since` parts were first packaged then, so a package from before
 * it carries none and says so.
 */
export const PACKAGE_COMPONENTS: ReadonlyArray<{ path: string; source: string; what: string; absent: string; core?: true; sealed?: "trace" | "ledger" | "attestations" | "disputes" | "sweeps" | "leads" | "finish" | "questions" | "requests" | "grants" | "fetches" | "journal" | "model_gateway" | "artifacts"; since?: string }> = [
  { path: "custody.json", source: "custody.json", what: "the custody verdict", absent: "no custody was taken for this run (swarm.sh stop takes it)", core: true },
  { path: "trace/custody-anchor.json", source: "<sandbox>.custody-anchor.json", what: "the verdict's anchor, kept outside the run", absent: "the kickoff wrote no custody anchor for this run", core: true },
  { path: "custody.json.sig", source: "custody.json.sig", what: "the verdict's signature", absent: "custody.json was not signed (--custody-sign-key)" },
  { path: "custody.json.tsr", source: "custody.json.tsr", what: "the verdict's RFC 3161 timestamp token", absent: "custody.json was not timestamped (--custody-timestamp-url)" },
  { path: "artifacts.sealed.json", source: "artifacts.json", what: "the index of work/ custody sealed at stop", absent: "no custody verdict indexed work/", sealed: "artifacts", since: "2026-09-27" },
  { path: "trace/events.jsonl", source: "traces/events.jsonl", what: "the trace", absent: "the run has no trace", sealed: "trace" },
  { path: "trace/trace-anchor.json", source: "<sandbox>.trace-anchor.json", what: "the trace's anchor", absent: "no collector anchored the trace" },
  { path: "ledger.jsonl", source: "ledger/entries.jsonl", what: "the ledger", absent: "nothing was recorded", sealed: "ledger" },
  { path: "ledger-attestations.jsonl", source: "ledger/attestations.jsonl", what: "the ledger's attestations", absent: "no entry has a second author", sealed: "attestations" },
  { path: "ledger-disputes.jsonl", source: "ledger/disputes.jsonl", what: "the agents' disputes of entries", absent: "no agent disputed an entry", sealed: "disputes", since: "2026-09-27" },
  { path: "ledger-sweeps.jsonl", source: "ledger/sweeps.jsonl", what: "the store sweeps: what the hub found when it searched every output the run held for each coverage record's strings, and each evidence addition's reverse sweep of its files for the standing records' strings (a chain of its own, sealed by custody)", absent: "no store sweep ran (no coverage record named what a hit would contain)", sealed: "sweeps", since: "2026-09-29" },
  { path: "finish.jsonl", source: "leads/finish.jsonl", what: "the finish register: the coordinator's lease, readiness, the checks and the report's reviews (unsigned, sealed by custody)", absent: "the run has no finish register (no seat coordinated a finish, or a run from before it)", sealed: "finish", since: "2026-09-29" },
  { path: "leads.jsonl", source: "leads/leads.jsonl", what: "the lead register: how the investigation proceeded (unsigned, sealed by custody)", absent: "no lead was opened", sealed: "leads", since: "2026-09-28" },
  { path: "leads.md", source: "leads/leads.md", what: "the lead register, rendered", absent: "no lead was opened", since: "2026-09-28" },
  { path: "questions.jsonl", source: "questions/questions.jsonl", what: "the question register: what the examination was asked, by whom (the goal, an agent, a person, claimed or signed), and how each question stood (unsigned as a whole, sealed by custody)", absent: "the run wrote no question event", sealed: "questions", since: "2026-09-28" },
  { path: "questions.md", source: "questions/questions.md", what: "the question register, rendered", absent: "the run wrote no question event", since: "2026-09-28" },
  { path: "operator-requests.jsonl", source: "operator-requests.jsonl", what: "what the run asked of the operator, one line per request as it stood", absent: "nothing was asked of the operator", since: "2026-09-28" },
  { path: "requests.jsonl", source: "requests/requests.jsonl", what: "the operator requests' chain: every request (a lead's needs, an acquisition, a clarification, a network item, a stop proposed) with its id and lifecycle (unsigned, sealed by custody)", absent: "nothing was asked of the operator, or the run is from before the chain", sealed: "requests", since: "2026-09-28" },
  { path: "requests.md", source: "requests/requests.md", what: "the operator requests, rendered", absent: "nothing was asked of the operator", since: "2026-09-28" },
  { path: "material", source: "store/imports/", what: "what entered the run after its kickoff (evidence add, material add): each addition's provenance record and manifest; the bytes stay with the evidence", absent: "no evidence or material was added after the kickoff", since: "2026-09-28" },
  { path: "network/grants.jsonl", source: "network/grants.jsonl", what: "the dynamic network's requests, decisions and grants (a chain of its own, sealed by custody)", absent: "the run made no network request", sealed: "grants", since: "2026-09-29" },
  { path: "network/fetches.jsonl", source: "network/fetches.jsonl", what: "every fetch the fetch service made (a chain of its own, sealed by custody)", absent: "the run fetched nothing", sealed: "fetches", since: "2026-09-29" },
  { path: "operator-hosts.jsonl", source: "operator-hosts.jsonl", what: "the hosts the operator allowed while the run went on", absent: "the operator allowed no host during the run", since: "2026-09-28" },
  { path: "store/journal.jsonl", source: "store/journal.jsonl", what: "the store's journal", absent: "the run had no job service", sealed: "journal" },
  { path: "trace/model-gateway.jsonl", source: "traces/model-gateway.jsonl", what: "the model gateway's call log (a chain of its own, sealed by custody by its lines and their sha256)", absent: "the run had no model gateway (a host run)", sealed: "model_gateway", since: "2026-09-29" },
  { path: "trace/journal-anchor.json", source: "<sandbox>.journal-anchor.json", what: "the journal's anchor", absent: "the run had no job service" },
  { path: "review.jsonl", source: "<runs>/reviews/<run>.jsonl", what: "the examiner's review", absent: "no examiner has reviewed this run", since: "2026-09-27" },
  { path: "release", source: "release/", what: "the report's releases: the machine's drafts and the examiner's adoptions, each signed", absent: "no release was sealed for this run (no custody taken, or a run from before releases)", since: "2026-09-27" },
];

/** COMPONENTS.json for a package: each part present, or absent with why. */
export function writeComponents(sandbox: string, dir: string): { present: number; absent: number } {
  const custodyText = existsSync(join(sandbox, "custody.json")) ? readFileSync(join(sandbox, "custody.json"), "utf8") : null;
  let custody: { artifacts?: unknown } | null = null;
  try {
    custody = custodyText ? (JSON.parse(custodyText) as { artifacts?: unknown }) : null;
  } catch {
    custody = null;
  }
  const out = PACKAGE_COMPONENTS.map((c) => {
    if (existsSync(join(dir, c.path))) return { path: c.path, what: c.what, present: true };
    let reason = c.absent;
    if (c.sealed === "artifacts") reason = !custodyText ? "no custody was taken, so nothing sealed work/" : !custody?.artifacts ? "the verdict indexed no work files (a custody from before the index was sealed, or one that did not reach it)" : "artifacts.json, the index the verdict sealed, is not in the run (or is not a regular file there)";
    else if (!c.source.startsWith("<") && existsSync(join(sandbox, c.source))) reason = `in the run, and not copied: it is not a regular file there, or it is empty`;
    return { path: c.path, what: c.what, present: false, reason };
  });
  writeFileSync(
    join(dir, "COMPONENTS.json"),
    `${JSON.stringify({ v: 1, note: "Each part a recipient holds this record to: present, or absent with why. It is under MANIFEST.txt, and its signature: a part taken out of the package, and out of this list, breaks it. swarm.sh verify fails on a part that is missing and not declared absent.", components: out }, null, 2)}\n`,
  );
  return { present: out.filter((c) => c.present).length, absent: out.filter((c) => !c.present).length };
}

/** LEFT-BEHIND.txt's rows: each binary left in the sandbox, by path, with its sha256. */
function leftBehind(text: string | null): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of (text ?? "").split("\n")) {
    const m = /^([0-9a-f]{64})\s+\d+\s+(work\/.+)$/.exec(line);
    if (m) out.set(m[2], m[1]);
  }
  return out;
}

/** REDACTIONS.txt's rows: each file changed by redaction, with its sha256 before and after. */
function redactions(text: string | null): Map<string, { before: string; after: string }> {
  const out = new Map<string, { before: string; after: string }>();
  for (const line of (text ?? "").split("\n")) {
    const m = /^([0-9a-f]{64})  ([0-9a-f]{64})  (.+?)  \S.*$/.exec(line);
    if (m) out.set(m[3], { before: m[1], after: m[2] });
  }
  return out;
}

function packagedFiles(dir: string, under: string): string[] {
  const root = join(dir, under);
  if (!existsSync(root)) return [];
  return walk(root).map((abs) => relative(dir, abs).split("\\").join("/")).sort();
}

type SealedChain = { lines?: number; head?: string | null };
type SealShape = { trace?: { lines?: number; last_line_sha256?: string | null }; ledger?: { entries?: number; head?: string | null }; attestations?: SealedChain; disputes?: SealedChain; sweeps?: SealedChain; leads?: SealedChain; finish?: SealedChain; questions?: SealedChain; requests?: SealedChain; network?: { grants?: SealedChain; fetches?: SealedChain }; journal?: SealedChain | null; model_gateway?: { lines?: number; sha256?: string | null } | null };

export function verifyPackage(dir: string): { ok: boolean; lines: string[] } {
  const out: string[] = [];
  let ok = true;
  const fail = (line: string) => {
    out.push(line);
    ok = false;
  };
  const read = (rel: string) => (existsSync(join(dir, rel)) ? readFileSync(join(dir, rel), "utf8") : null);
  const redacted = redactions(read("REDACTIONS.txt"));
  const custodyText = read("custody.json");
  type Verdict = { seal?: SealShape; artifacts?: { index_sha256?: string } | null };
  let custody: Verdict | null = null;
  try {
    custody = custodyText ? (JSON.parse(custodyText) as Verdict) : null;
  } catch {
    fail("Verdict:      custody.json is not JSON");
  }
  const seal = custody?.seal;
  const anchorText = read("trace/custody-anchor.json");
  let lastAnchored: { sha256?: string; artifacts_sha256?: string | null; signature?: { file?: string; error?: string }; timestamp?: { file?: string; error?: string } } | undefined;
  try {
    lastAnchored = anchorText ? ((JSON.parse(anchorText) as { custody?: Array<NonNullable<typeof lastAnchored>> }).custody ?? []).at(-1) : undefined;
  } catch {
    fail("Anchor:       trace/custody-anchor.json is not JSON");
  }
  let anchoredReleases = 0;
  try {
    const rs = anchorText ? (JSON.parse(anchorText) as { releases?: unknown }).releases : undefined;
    anchoredReleases = Array.isArray(rs) ? rs.length : 0;
  } catch {
    anchoredReleases = 0;
  }
  // A file whose sha256 is anchored: the same bytes, or redacted from those bytes (REDACTIONS.txt names its sha256 before).
  const heldTo = (rel: string, text: string, want: string | null | undefined): "matches" | "redacted" | "differs" => {
    const have = sha256(text);
    if (have === want) return "matches";
    const r = redacted.get(rel);
    return r && r.before === want && r.after === have ? "redacted" : "differs";
  };

  // Every part: there, or declared absent.
  const componentsText = read("COMPONENTS.json");
  let declared: Map<string, { present: boolean; reason?: string }> | null = null;
  try {
    declared = componentsText ? new Map(((JSON.parse(componentsText) as { components?: Array<{ path: string; present: boolean; reason?: string }> }).components ?? []).map((c) => [c.path, c])) : null;
  } catch {
    fail("Components:   COMPONENTS.json is not JSON");
  }
  const expected = (c: (typeof PACKAGE_COMPONENTS)[number]): string | null => {
    if (!seal && !custody) return null;
    switch (c.sealed) {
      case "trace":
        return (seal?.trace?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.trace?.lines} trace lines` : null;
      case "ledger":
        return (seal?.ledger?.entries ?? 0) > 0 ? `the verdict sealed ${seal?.ledger?.entries} ledger entries` : null;
      case "attestations":
        return (seal?.attestations?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.attestations?.lines} attestation lines` : null;
      case "disputes":
        return (seal?.disputes?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.disputes?.lines} dispute lines` : null;
      case "leads":
        return (seal?.leads?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.leads?.lines} lead events` : null;
      case "questions":
        return (seal?.questions?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.questions?.lines} question events` : null;
      case "requests":
        return (seal?.requests?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.requests?.lines} operator request events` : null;
      case "sweeps":
        return (seal?.sweeps?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.sweeps?.lines} store sweeps` : null;
      case "finish":
        return (seal?.finish?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.finish?.lines} finish events` : null;
      case "grants":
      case "fetches":
        return (seal?.network?.[c.sealed]?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.network?.[c.sealed]?.lines} network ${c.sealed} lines` : null;
      case "model_gateway":
        return (seal?.model_gateway?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.model_gateway?.lines} model gateway lines` : null;
      case "journal":
        return seal?.journal ? `the verdict sealed a journal of ${seal.journal.lines} lines` : null;
      case "artifacts":
        return custody?.artifacts?.index_sha256 ? "the verdict sealed an index of work/" : null;
      default:
        if (c.path === "release" && anchoredReleases > 0) return `the anchor names ${anchoredReleases} release(s)`;
        if (c.path === "custody.json.sig" && lastAnchored?.signature?.file) return "the anchor says the verdict was signed";
        if (c.path === "custody.json.tsr" && lastAnchored?.timestamp?.file) return "the anchor says the verdict was timestamped";
        return null;
    }
  };
  const missing: string[] = [];
  const absent: string[] = [];
  const notCarried: string[] = [];
  for (const c of PACKAGE_COMPONENTS) {
    if (existsSync(join(dir, c.path))) {
      if (declared && declared.get(c.path)?.present === false) missing.push(`${c.path} (declared absent, and there)`);
      continue;
    }
    const d = declared?.get(c.path);
    const want = expected(c);
    if (d?.present === true) missing.push(`${c.path} (declared present)`);
    else if (want) missing.push(`${c.path} (${want}${d ? `; declared absent: ${d.reason ?? "no reason"}` : ""})`);
    else if (d) absent.push(`${c.path}: ${d.reason ?? "no reason given"}`);
    else if (!declared && c.since) notCarried.push(c.path);
    else if (c.core) missing.push(`${c.path} (not declared absent)`);
    else absent.push(`${c.path}: not there (not declared)`);
  }
  if (missing.length) fail(`Components:   MISSING, AND NOT DECLARED ABSENT OR AGAINST THE SEAL: ${missing.join("; ")}`);
  else out.push(`Components:   ${declared ? "every part is there or declared absent (COMPONENTS.json)" : "NO COMPONENTS.json (a package made before 2026-09-27): each part held to the verdict's seal only"}`);
  if (absent.length) out.push(`Absent:       ${absent.join("; ")}`);
  if (notCarried.length) out.push(`Not carried:  ${notCarried.join(", ")} (packaged since 2026-09-27; this package is older)`);

  // The verdict against the anchor it was written with.
  if (custodyText && lastAnchored) {
    const held = heldTo("custody.json", custodyText, lastAnchored.sha256);
    if (held === "differs") fail("Verdict:      custody.json DOES NOT MATCH the last verdict its anchor names");
    else out.push(`Verdict:      custody.json ${held === "matches" ? "matches the last verdict its anchor names" : "was redacted (REDACTIONS.txt names its sha256 before redaction, the one its anchor names)"}`);
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
  let ledgerHead: string | null = null;
  if (ledger !== null) {
    const l = ledgerChain(ledger);
    ledgerHead = l.head;
    const sealed = !seal?.ledger || (seal.ledger.head ?? null) === l.head && (seal.ledger.entries === undefined || seal.ledger.entries === l.entries);
    out.push(`Ledger:       ${l.detail}${seal?.ledger ? (sealed ? "; its head and length are the ones the verdict sealed" : `; NOT THE LEDGER THE VERDICT SEALED (sealed ${seal.ledger.entries ?? "?"} entries, head ${seal.ledger.head ?? "none"}; here ${l.entries}, head ${l.head ?? "none"})`) : ""}`);
    ok &&= l.ok && sealed;
  }
  const att = read("ledger-attestations.jsonl");
  if (att !== null) {
    const a = actChain(att, (o, prev) => attestationHash(o as unknown as LedgerAttestation, prev));
    const sealed = !seal?.attestations || ((seal.attestations.head ?? null) === a.head && (seal.attestations.lines === undefined || seal.attestations.lines === a.total));
    out.push(`Attestations: ${a.ok ? `${a.total} lines, chain intact${a.redacted ? `, ${a.redacted} redacted (their hashes kept)` : ""}` : `CHAIN BROKEN at line ${a.broken_at} (${a.reason})`}${seal?.attestations ? (sealed ? "; head sealed" : "; HEAD NOT THE ONE SEALED") : ""}`);
    ok &&= a.ok && sealed;
  }
  // The agents' disputes: their own chain, held to the seal when the verdict sealed them.
  const disp = read("ledger-disputes.jsonl");
  if (disp !== null) {
    const d = actChain(disp, (o, prev) => disputeHash(o as unknown as LedgerDispute, prev));
    const sealed = !seal?.disputes || ((seal.disputes.head ?? null) === d.head && (seal.disputes.lines === undefined || seal.disputes.lines === d.total));
    out.push(`Disputes:     ${d.ok ? `${d.total} lines, chain intact${d.redacted ? `, ${d.redacted} redacted (their hashes kept)` : ""}` : `CHAIN BROKEN at line ${d.broken_at} (${d.reason})`}${seal?.disputes ? (sealed ? "; head sealed" : "; HEAD NOT THE ONE SEALED") : "; not sealed by this verdict (a custody from before disputes were sealed)"}`);
    ok &&= d.ok && sealed;
  } else if ((seal?.disputes?.lines ?? 0) > 0) {
    // Named by the components check above; said here too, beside the other chains.
    out.push(`Disputes:     NOT IN THE PACKAGE, and the verdict sealed ${seal?.disputes?.lines} lines`);
  }
  // The lead register: its own chain, sealed unsigned, held to the seal when the verdict sealed it.
  const leadsText = read("leads.jsonl");
  if (leadsText !== null) {
    const l = leadChain(leadsText);
    const sealed = !seal?.leads || ((seal.leads.head ?? null) === l.head && (seal.leads.lines === undefined || seal.leads.lines === l.total));
    out.push(`Leads:        ${l.ok ? `${l.total} events, chain intact${l.redacted ? `, ${l.redacted} redacted (their hashes kept)` : ""}` : `CHAIN BROKEN at line ${l.broken_at} (${l.reason})`}${seal?.leads ? (sealed ? "; head sealed" : "; HEAD NOT THE ONE SEALED") : "; not sealed by this verdict (a custody from before the lead register was sealed)"}`);
    ok &&= l.ok && sealed;
  } else if ((seal?.leads?.lines ?? 0) > 0) {
    out.push(`Leads:        NOT IN THE PACKAGE, and the verdict sealed ${seal?.leads?.lines} events`);
  }
  // The question register: the same chain code, held to the seal the same way.
  const questionsText = read("questions.jsonl");
  if (questionsText !== null) {
    const q = leadChain(questionsText);
    const sealed = !seal?.questions || ((seal.questions.head ?? null) === q.head && (seal.questions.lines === undefined || seal.questions.lines === q.total));
    out.push(`Questions:    ${q.ok ? `${q.total} events, chain intact${q.redacted ? `, ${q.redacted} redacted (their hashes kept)` : ""}` : `CHAIN BROKEN at line ${q.broken_at} (${q.reason})`}${seal?.questions ? (sealed ? "; head sealed" : "; HEAD NOT THE ONE SEALED") : "; not sealed by this verdict (a custody from before the question register was sealed)"}`);
    ok &&= q.ok && sealed;
  } else if ((seal?.questions?.lines ?? 0) > 0) {
    out.push(`Questions:    NOT IN THE PACKAGE, and the verdict sealed ${seal?.questions?.lines} events`);
  }
  // The chains checked the same way: each its own chain (a redacted line keeps its hash), held to the seal when the verdict sealed it.
  const heldChains: Array<{ label: string; rel: string; what: string; unit: string; sealed: SealedChain | undefined; verify: (t: string) => { ok: boolean; total: number; head: string | null; broken_at: number | null; reason: string | null; redacted: number } }> = [
    { label: "Sweeps:       ", rel: "ledger-sweeps.jsonl", what: "store sweeps", unit: "lines", sealed: seal?.sweeps, verify: (t) => actChain(t, (o, prev) => sweepHash(o as unknown as SweepRecord, prev)) },
    { label: "Finish:       ", rel: "finish.jsonl", what: "the finish register", unit: "events", sealed: seal?.finish, verify: leadChain },
    { label: "Requests:     ", rel: "requests.jsonl", what: "the operator requests", unit: "events", sealed: seal?.requests, verify: leadChain },
    { label: "Net grants:   ", rel: "network/grants.jsonl", what: "the network grants", unit: "lines", sealed: seal?.network?.grants, verify: leadChain },
    { label: "Net fetches:  ", rel: "network/fetches.jsonl", what: "the network fetches", unit: "lines", sealed: seal?.network?.fetches, verify: leadChain },
  ];
  for (const h of heldChains) {
    const text = read(h.rel);
    if (text === null) {
      if ((h.sealed?.lines ?? 0) > 0) out.push(`${h.label}NOT IN THE PACKAGE, and the verdict sealed ${h.sealed?.lines} ${h.unit}`);
      continue;
    }
    const v = h.verify(text);
    const sealed = !h.sealed || ((h.sealed.head ?? null) === v.head && (h.sealed.lines === undefined || h.sealed.lines === v.total));
    out.push(`${h.label}${v.ok ? `${v.total} ${h.unit}, chain intact${v.redacted ? `, ${v.redacted} redacted (their hashes kept)` : ""}` : `CHAIN BROKEN at line ${v.broken_at} (${v.reason})`}${h.sealed ? (sealed ? "; head sealed" : "; HEAD NOT THE ONE SEALED") : `; not sealed by this verdict (a custody from before ${h.what} were sealed)`}`);
    ok &&= v.ok && sealed;
  }
  // The model gateway's log: each line names the sha256 of the one before (the first, null); its first sealed lines hash to what the verdict sealed.
  const gateway = read("trace/model-gateway.jsonl");
  if (gateway !== null) {
    const lines = gateway.split("\n").filter((l) => l.trim());
    let prev: string | null = null;
    let broken: string | null = null;
    lines.forEach((l, i) => {
      if (broken) return;
      try {
        const o = JSON.parse(l) as { prev?: unknown };
        if ((o.prev ?? null) !== prev) broken = `line ${i + 1} does not name the line before it`;
      } catch {
        broken = `line ${i + 1} is not JSON`;
      }
      prev = sha256(l);
    });
    const n = seal?.model_gateway?.lines ?? 0;
    const sealedOk = !seal?.model_gateway || (lines.length >= n && (!seal.model_gateway.sha256 || !n || sha256(`${lines.slice(0, n).join("\n")}\n`) === seal.model_gateway.sha256));
    out.push(`Gateway log:  ${broken ? `CHAIN BROKEN (${broken})` : `${lines.length} lines, chain intact`}${seal?.model_gateway ? (sealedOk ? `; the ${n} lines the verdict sealed are there` : "; NOT THE LINES THE VERDICT SEALED") : ""}`);
    ok &&= !broken && sealedOk;
  } else if ((seal?.model_gateway?.lines ?? 0) > 0) out.push(`Gateway log:  NOT IN THE PACKAGE, and the verdict sealed ${seal?.model_gateway?.lines} lines`);
  // The store's journal: the sealed line where the seal says, and only examiner notes after it.
  const journal = read("store/journal.jsonl");
  if (journal !== null) {
    const j = journalChain(journal);
    let note = "";
    let sealed = true;
    if (seal?.journal) {
      const at = seal.journal.lines ? j.hashes[(seal.journal.lines ?? 0) - 1] : null;
      const rest = j.types.slice(seal.journal.lines ?? 0);
      sealed = (at ?? null) === (seal.journal.head ?? null) && rest.every((t) => t === "note");
      note = sealed ? `; head sealed${rest.length ? `, ${rest.length} examiner note(s) after it` : ""}` : "; HEAD NOT THE ONE SEALED, or lines after it that are not an examiner's notes";
    }
    out.push(`Journal:      ${j.detail}${note}`);
    ok &&= j.ok && sealed;
  }
  // work/ against the index custody sealed, and that index against the anchor and the verdict.
  const sealedText = read("artifacts.sealed.json");
  if (sealedText !== null) {
    const want = custody?.artifacts?.index_sha256;
    const byVerdict = heldTo("artifacts.sealed.json", sealedText, want);
    const byAnchor = lastAnchored?.artifacts_sha256 === undefined ? null : heldTo("artifacts.sealed.json", sealedText, lastAnchored.artifacts_sha256);
    if (byVerdict === "differs" || byAnchor === "differs") fail(`Sealed index: artifacts.sealed.json IS NOT THE INDEX ${byVerdict === "differs" ? "THE VERDICT" : "THE ANCHOR"} NAMES (${sha256(sealedText)}, sealed ${(byVerdict === "differs" ? want : lastAnchored?.artifacts_sha256) ?? "none"})`);
    else {
      let index: { files?: Array<{ path: string; sha256: string; packaged?: boolean }>; skipped?: Array<{ path: string }> } = {};
      try {
        index = JSON.parse(sealedText);
      } catch {
        fail("Sealed index: artifacts.sealed.json is not JSON");
      }
      const left = leftBehind(read("LEFT-BEHIND.txt"));
      // What today's indexer covers, from the index generated with this package: a file it leaves out is not one custody could have sealed.
      let fresh: Set<string> | null = null;
      try {
        const f = read("artifacts.json");
        fresh = f ? new Set(((JSON.parse(f) as { files?: Array<{ path: string }> }).files ?? []).map((x) => x.path)) : null;
      } catch {
        fresh = null;
      }
      const sealedFiles = new Map((index.files ?? []).map((f) => [f.path, f]));
      const sealedSkipped = new Set((index.skipped ?? []).map((f) => f.path));
      const changed: string[] = [];
      const gone: string[] = [];
      let same = 0;
      let redactedFiles = 0;
      let behind = 0;
      for (const f of sealedFiles.values()) {
        if (f.packaged === false) continue;
        if (!f.path.startsWith("work/") || f.path.split("/").includes("..")) {
          changed.push(`${f.path} (not a path under work/)`);
          continue;
        }
        if (existsSync(join(dir, f.path))) {
          const have = sha256(readFileSync(join(dir, f.path)));
          const r = redacted.get(f.path);
          if (have === f.sha256) same += 1;
          else if (r && r.before === f.sha256 && r.after === have) redactedFiles += 1;
          else changed.push(f.path);
        } else if (left.get(f.path) === f.sha256) behind += 1;
        else gone.push(f.path);
      }
      const added: string[] = [];
      const outside: string[] = [];
      for (const rel of packagedFiles(dir, "work")) {
        if (sealedFiles.has(rel) || rel.endsWith("/.gitkeep")) continue;
        if (sealedSkipped.has(rel)) added.push(`${rel} (not hashed at custody)`);
        else if (fresh && !fresh.has(rel)) outside.push(rel);
        else added.push(rel);
      }
      const bad = [
        ...(changed.length ? [`${changed.length} CHANGED (${changed.join(", ")})`] : []),
        ...(gone.length ? [`${gone.length} MISSING (${gone.join(", ")})`] : []),
        ...(added.length ? [`${added.length} NOT IN THE SEALED INDEX (${added.join(", ")})`] : []),
      ];
      const held = byVerdict === "redacted" ? "redacted (REDACTIONS.txt names its sha256 before, the sealed one)" : `the one the verdict${byAnchor ? " and the anchor" : ""} name${byAnchor ? "" : "s"}`;
      const counts = `${same} as sealed${redactedFiles ? `, ${redactedFiles} redacted from the sealed bytes (REDACTIONS.txt)` : ""}${behind ? `, ${behind} left in the sandbox with the sealed sha256 (LEFT-BEHIND.txt)` : ""}`;
      if (bad.length) fail(`Work files:   NOT AS SEALED: ${bad.join("; ")}; ${counts}; the index is ${held}`);
      else out.push(`Work files:   every packaged work/ file is the one custody sealed: ${counts}; the index is ${held}`);
      if (outside.length) out.push(`Unindexed:    ${outside.length} work/ file(s) outside what the index covers, neither sealed nor indexed: ${outside.join(", ")}`);
    }
  } else if (existsSync(join(dir, "work"))) out.push(`Work files:   not held to a sealed index (${declared?.get("artifacts.sealed.json")?.reason ?? "the package carries none"}): only MANIFEST.txt holds them`);
  // The examiner's review, and what its sign-off is over.
  const review = read("review.jsonl");
  if (review !== null) {
    const r = reviewChain(review);
    if (!r.ok) fail(`Review:       CHAIN ${r.detail}`);
    else if (!r.signed) out.push(`Review:       ${r.detail}; not signed`);
    else {
      const reportPath = r.signed.report_path && !r.signed.report_path.startsWith("/") && !r.signed.report_path.split("/").includes("..") ? r.signed.report_path : null;
      const reportHere = reportPath && existsSync(join(dir, reportPath)) ? sha256(readFileSync(join(dir, reportPath))) : null;
      const overLedger = ledgerHead === null ? "the ledger is not in the package" : r.signed.ledger_head === ledgerHead ? "this ledger" : `AN EARLIER LEDGER (head ${r.signed.ledger_head}; this one's ${ledgerHead})`;
      const overReport = !r.signed.report_sha256 ? "NO REPORT" : !reportPath ? "a report path that is not under the run" : reportHere === null ? `${reportPath} as it was (sha256 ${r.signed.report_sha256}), which is not in the package` : reportHere === r.signed.report_sha256 ? `this ${reportPath}` : `${reportPath} AS IT WAS (sha256 ${r.signed.report_sha256}), NOT THE ONE IN THE PACKAGE (${reportHere})`;
      out.push(`Review:       ${r.detail}; signed by ${r.signed.examiner ?? "?"} at ${r.signed.at ?? "?"} over ${overLedger} and ${overReport}`);
    }
  }
  if (existsSync(join(dir, "REDACTIONS.txt"))) {
    // What each redaction replaced, and what the scan after it found.
    let lineage = "";
    try {
      const r = JSON.parse(read("REDACTIONS.json") ?? "") as { changes?: Array<{ path: string; replaced?: unknown[] }>; leak_scan?: { mode?: string; files?: number; hits?: Array<{ path: string; entry: number }> } };
      const rows = redactions(read("REDACTIONS.txt"));
      const listed = new Set((r.changes ?? []).map((c) => c.path));
      const unrecorded = [...rows.keys()].filter((p) => !listed.has(p));
      const hits = r.leak_scan?.hits ?? [];
      const withheld = (r as { withheld?: Array<{ path: string }> }).withheld ?? [];
      lineage = `; REDACTIONS.json records what ${(r.changes ?? []).reduce((n, c) => n + (c.replaced?.length ?? 0), 0)} redaction(s) replaced (the sha256 of each original, why, which entry)${unrecorded.length ? `, and NOT ${unrecorded.join(", ")}` : ""}${withheld.length ? `; ${withheld.length} file(s) withheld whole, each named with its sha256 (${withheld.map((w) => w.path).join(", ")})` : ""}; the leak scan after it ${hits.length ? `FOUND ${hits.length} HIT(S), LISTED: ${hits.map((h) => `${h.path} (entry ${h.entry})`).join(", ")}` : `found nothing over ${r.leak_scan?.files ?? "?"} file(s)`}`;
      if (unrecorded.length) ok = false;
    } catch {
      lineage = "; no REDACTIONS.json (a package made before redactions were recorded): what each replaced is not said";
    }
    out.push(`Redacted:     this package was made with --redact (REDACTIONS.txt)${lineage}`);
  }
  return { ok, lines: out };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [cmd, a, b] = process.argv.slice(2);
  if (cmd === "redact" && a && b) {
    const leaks = process.argv.includes("--leaks") ? process.argv[process.argv.indexOf("--leaks") + 1] : "fail";
    if (leaks !== "fail" && leaks !== "list") {
      console.error("redact: --leaks fail|list");
      process.exit(2);
    }
    const r = await redactPackage(a, b, { leaks });
    console.log(JSON.stringify({ entries: r.entries, files: r.files, lines: r.lines, scanned: r.scanned, leaks: r.leaks.length, withheld: r.withheld.length }));
    // A word that should have been taken out and is still there: named by file, entry and the word's sha256, never the word.
    for (const h of r.leaks) console.error(`  ${h.path}: ${h.output ? `the text of a sensitive output (${h.output})` : `entry ${h.entry}'s words`} (sha256 ${h.token_sha256.slice(0, 16)}…, as ${h.as})`);
    if (r.leaks.length && leaks === "fail") process.exit(5);
  } else if (cmd === "hygiene" && a && b) {
    const r = await hygieneReport(a, b);
    console.log(JSON.stringify({ entries: r.entries, outputs: r.outputs, carried: r.carried, hits: r.hits.length, scanned: r.scanned }));
  } else if (cmd === "components" && a && b) {
    console.log(JSON.stringify(writeComponents(a, b)));
  } else if (cmd === "verify" && a) {
    const rest = process.argv.slice(4);
    const opt = (name: string) => (rest.indexOf(name) >= 0 ? rest[rest.indexOf(name) + 1] : undefined);
    const r = verifyPackage(a);
    console.log(r.lines.join("\n"));
    // The report's releases: every signature, the bytes each binds, the chain between them.
    const rel = await verifyReleases(packageLayout(a), { allowedSigners: opt("--allowed-signers"), tsaCa: opt("--tsa-ca"), ca: opt("--ca"), caIntermediate: opt("--ca-intermediate") });
    console.log(rel.lines.join("\n"));
    const unchecked = rel.signatures.some((s) => s.adopted && s.state !== "verified");
    process.exit(!r.ok || !rel.ok ? 1 : unchecked && opt("--allowed-signers") ? 3 : 0);
  } else {
    console.error("usage: package-tools.ts redact <sandbox> <package dir> | hygiene <sandbox> <package dir> | components <sandbox> <package dir> | verify <package dir>");
    process.exit(2);
  }
}
