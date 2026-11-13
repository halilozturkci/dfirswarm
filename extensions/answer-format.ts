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

/**
 * The first line of a value, as a grader reads it: without list, emphasis or code marks around the whole of it. An
 * answer is graded on how its value starts, so that line is the one held to the format. The first version of this
 * check took any line and any span in code marks, and "The C2 endpoint is **`192.168.1.33:6969`**. It was ..." passed
 * nine times in one run (s01a4f4, questions 5 and 6: right values, never in the form).
 */
export function firstLine(value: string): string {
  const line = String(value ?? "").split(/\r?\n/).map((l) => l.trim()).find((l) => l !== "") ?? "";
  let bare = line.replace(/^\s*(?:[-*+]|\d+[.)])\s+/, "").trim();
  for (;;) {
    const w = /^(\*\*|__|\*|`)(.+)\1$/.exec(bare);
    if (!w) break;
    bare = w[2].trim();
  }
  return bare;
}

/** An example of a value in a format, built from its parts: what the note shows beside the format's own words. */
export function formatExample(f: AnswerFormat): string {
  const sample: Record<string, string> = { hash: "<32 or more hex digits>", clock: "<digits in the placeholders' order>", ip: "192.0.2.7", port: "8080", email: "name@example.org", text: "<text>" };
  let i = 0;
  return f.format.split(SEPARATORS).map((piece) => {
    if (piece.trim() === "") return "";
    if (/^[_:/|,;@]$/.test(piece)) return piece;
    const kind = f.parts[i] ?? "text";
    i += 1;
    if (kind === "hash") {
      const m = /^(md5|sha1|sha256|sha512)/i.exec(piece.trim());
      return `<${HASHES[(m?.[1] ?? "md5").toLowerCase()]} hex digits>`;
    }
    if (kind === "clock") return piece.trim().replace(/[A-Za-z]+/g, (w) => "0".repeat(w.length));
    return sample[kind] ?? "<text>";
  }).join("");
}

/**
 * Whether an answer's value gives the format: null when its first line does (or the question names none), else what it
 * asks, for the note. `seenAnywhere` says the form is in the value but not as its first line, so the note can say
 * "move it up" instead of "it is missing".
 */
export function formatMiss(questionText: string, value: string): { format: string; parts: string[]; example: string; first_line: string; seen_elsewhere: boolean } | null {
  const f = questionFormat(questionText);
  if (!f) return null;
  const first = firstLine(value);
  if (f.pattern.test(first)) return null;
  const elsewhere = String(value ?? "").split(/\r?\n/).some((l) => f.pattern.test(firstLine(l))) || [...String(value ?? "").matchAll(/`([^`]+)`/g)].some((m) => f.pattern.test(m[1].trim()));
  return { format: f.format, parts: f.parts, example: formatExample(f), first_line: first.length > 120 ? `${first.slice(0, 117)}...` : first, seen_elsewhere: elsewhere };
}

/** The note an answer recorded out of its question's format gets. */
export function formatNote(section: string, miss: { format: string; parts: string[]; example?: string; first_line?: string; seen_elsewhere?: boolean }): string {
  const what = [...new Set(miss.parts.filter((p) => p !== "text"))]
    .map((p) => ({ hash: "a hash as its hex digits", clock: "a date and time in the placeholders' order, as digits", ip: "an address as four numbers", port: "a port as a number", email: "an address with @" })[p] ?? p)
    .join(", ");
  const shape = miss.example ? ` It looks like: ${miss.example}` : "";
  const where = miss.seen_elsewhere
    ? "the value holds it, but not as its first line: an answer is graded on how its value starts, so put that one line first, alone, and the words after it"
    : "the value's first line is not in it";
  return `${section} asks for its answer in the format ${miss.format}${what ? ` (${what})` : ""}, and ${where}.${shape} Recorded as written; record it again with supersedes, the value's first line exactly in that form and nothing else on that line (no sentence, no label, no second candidate). If part of it is not known yet, say so in the lines after the first; this note is not a reason to guess a part`;
}
