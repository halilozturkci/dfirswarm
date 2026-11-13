/**
 * The answer format a question asks for, and whether an answer's value gives
 * it.
 *
 * A case's questions often say how the answer is graded: "Format:
 * *Name_md5(file)*", "Format: *DD-MM-YYYY-HH-MM*", "Format: *ip:port*". On the
 * Batman III runs answers that were right lost their marks for the form (a
 * date as 2024-03-12 14:02 where DD-MM-YYYY-HH-MM was asked, a hash with no
 * name, a name and time zone as a sentence). The format is read from the
 * question's words into a pattern; an answer whose value holds no line in that
 * form is told so when it is recorded. It is a note, never a refusal: the
 * pattern is a reading of free text, and the value stands as written.
 */

export type AnswerFormat = { format: string; pattern: RegExp; parts: string[] };

/** A hash placeholder (md5(file), sha256(text), …) and its length in hex digits. */
const HASHES: Record<string, number> = { md5: 32, sha1: 40, sha256: 64, sha512: 128 };

/** Date and time placeholders, each with the digits it takes. */
const CLOCK: Record<string, string> = {
  YYYY: "\\d{4}",
  YY: "\\d{2}",
  MM: "\\d{1,2}",
  DD: "\\d{1,2}",
  HH: "\\d{1,2}",
  hh: "\\d{1,2}",
  mm: "\\d{1,2}",
  SS: "\\d{1,2}",
  ss: "\\d{1,2}",
};

const IPV4 = "(?:\\d{1,3}\\.){3}\\d{1,3}";
const SEPARATORS = /([_:/|,;@])/;
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * The format a question's words ask for, from a `Format:` (or `Answer
 * format:`) line: the text after it, without the emphasis or code marks
 * around it. Null when the question names none, or names one the reader
 * cannot make a pattern of.
 */
export function questionFormat(text: string): AnswerFormat | null {
  const m = /(?:^|[\s(])(?:answer\s+)?format\s*[:：]\s*(.+)$/im.exec(String(text ?? ""));
  if (!m) return null;
  let raw = m[1].trim().replace(/[)\].]+$/, "").trim();
  // The emphasis or code marks around it: *x*, **x**, _x_ (only a whole wrap), `x`.
  for (;;) {
    const w = /^(\*\*|\*|`|"|')(.+)\1$/.exec(raw);
    if (!w) break;
    raw = w[2].trim();
  }
  if (!raw || raw.length > 120) return null;
  const parts: string[] = [];
  let re = "";
  for (const piece of raw.split(SEPARATORS)) {
    if (piece.trim() === "") continue;
    if (/^[_:/|,;@]$/.test(piece)) {
      re += piece === "_" ? "_" : `\\s*${escapeRe(piece)}\\s*`;
      continue;
    }
    const [frag, kind] = pieceRe(piece.trim());
    re += frag;
    parts.push(kind);
  }
  // A format of free words alone says no more than "something", unless separators join several (Name_Value): then the joins are the form.
  if (!parts.some((p) => p !== "text") && parts.length < 2) return null;
  return { format: raw, pattern: new RegExp(`^${re}$`, "i"), parts };
}

/** One piece of a format between separators, as a pattern and what it is (hash, clock, ip, port, email, text). */
function pieceRe(piece: string): [string, string] {
  const hash = /^(md5|sha1|sha256|sha512)\s*\(.*\)$/i.exec(piece);
  if (hash) return [`[0-9a-f]{${HASHES[hash[1].toLowerCase()]}}`, "hash"];
  if (/^(md5|sha1|sha256|sha512)$/i.test(piece)) return [`[0-9a-f]{${HASHES[piece.toLowerCase()]}}`, "hash"];
  // A clock: placeholders joined by '-' or '.', every one of them known (DD-MM-YYYY-HH-MM).
  const clock = piece.split(/([-.])/);
  if (clock.length > 1 && clock.every((c, i) => (i % 2 ? c === "-" || c === "." : c in CLOCK))) {
    return [clock.map((c, i) => (i % 2 ? escapeRe(c) : CLOCK[c])).join(""), "clock"];
  }
  if (piece in CLOCK && piece.length >= 4) return [CLOCK[piece], "clock"];
  if (/^ip(v4)?$/i.test(piece) || /^ip[-_ ]?address$/i.test(piece)) return [IPV4, "ip"];
  if (/^port$/i.test(piece)) return ["\\d{1,5}", "port"];
  if (/^e-?mail$/i.test(piece)) return ["[^\\s@]+@[^\\s@]+\\.[^\\s@]+", "email"];
  return ["[^\\n]+?", "text"];
}

/** The lines of a value a format is looked for in: each line, and each of its spans in code marks, without list or emphasis marks. */
function candidates(value: string): string[] {
  const out = new Set<string>();
  for (const line of String(value ?? "").split(/\r?\n/)) {
    const bare = line.replace(/^\s*(?:[-*+]|\d+[.)])\s+/, "").replace(/\*\*|__/g, "").trim();
    if (bare) out.add(bare.replace(/^`(.+)`$/, "$1").replace(/^\*(.+)\*$/, "$1").trim());
    for (const m of line.matchAll(/`([^`]+)`/g)) out.add(m[1].trim());
    // The span after a label ("Answer: x", "Flag: x").
    const label = /^[^:]{1,30}:\s+(\S.*)$/.exec(bare);
    if (label) out.add(label[1].trim());
  }
  return [...out];
}

/**
 * Whether an answer's value gives the format: null when it does (or the
 * question names none), else what it asks, for the note.
 */
export function formatMiss(questionText: string, value: string): { format: string; parts: string[] } | null {
  const f = questionFormat(questionText);
  if (!f) return null;
  return candidates(value).some((c) => f.pattern.test(c)) ? null : { format: f.format, parts: f.parts };
}

/** The note an answer recorded out of its question's format gets. */
export function formatNote(section: string, miss: { format: string; parts: string[] }): string {
  const what = [...new Set(miss.parts.filter((p) => p !== "text"))]
    .map((p) => ({ hash: "a hash as its hex digits", clock: "a date and time in the placeholders' order, as digits", ip: "an address as four numbers", port: "a port as a number", email: "an address with @" })[p] ?? p)
    .join(", ");
  return `${section} asks for its answer in the format ${miss.format}, and no line of the value is in it (${what}): the answer is graded on that format, so give it as one line exactly in that form (the value, or its first line), with the words around it elsewhere. Recorded as written; record it again with supersedes when you have it in the form`;
}
