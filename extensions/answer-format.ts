/**
 * The answer format a question asks for, and whether an answer's value gives
 * it.
 *
 * A case's questions often say how the answer is graded: "Format:
 * *Name_md5(file)*", "Format: *DD-MM-YYYY-HH-MM*", "Format: *ip:port*". On the
 * runs of one case answers that were right lost their marks for the form (a
 * date as 2024-03-12 14:02 where DD-MM-YYYY-HH-MM was asked, a hash with no
 * name, a name and time zone as a sentence). The format is read from the
 * question's words into a pattern; an answer whose value holds no line in that
 * form is told so when it is recorded. It is a note, never a refusal: the
 * pattern is a reading of free text, and the value stands as written.
 */

export type AnswerFormat = { format: string; pattern: RegExp; parts: string[]; pieces: Array<{ re: string; kind: string; join: string }> };

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
  // Each piece with the separator before it: an answer with one part open gives the pieces it has (knownPart).
  const pieces: AnswerFormat["pieces"] = [];
  let re = "";
  let join = "";
  for (const piece of raw.split(SEPARATORS)) {
    if (piece.trim() === "") continue;
    if (/^[_:/|,;@]$/.test(piece)) {
      join = piece === "_" ? "_" : `\\s*${escapeRe(piece)}\\s*`;
      re += join;
      continue;
    }
    const [frag, kind] = pieceRe(piece.trim());
    re += frag;
    parts.push(kind);
    pieces.push({ re: frag, kind, join });
    join = "";
  }
  // A format of free words alone says no more than "something", unless separators join several (Name_Value): then the joins are the form.
  if (!parts.some((p) => p !== "text") && parts.length < 2) return null;
  return { format: raw, pattern: new RegExp(`^${re}$`, "i"), parts, pieces };
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
 * Whether a line reads as a sentence and not as an asked string: eight words or more, four or more that end in a
 * full stop, or four or more around "is", "was", "are". A format of free text (Name_Value) takes any line with its
 * separator, and "The PC name is X and the time zone is Y_Z" passed it: on the run s082123 the answers to five
 * questions were sentences in the ledger while the report held the exact strings.
 */
export function looksLikeSentence(line: string): boolean {
  const words = line.trim().split(/\s+/).filter(Boolean);
  if (words.length >= 8) return true;
  if (words.length >= 4 && /[.;]$/.test(line.trim())) return true;
  return words.length >= 4 && /\b(?:is|was|are|were|has|have|shows?|holds?)\b/i.test(line);
}

/** How many digests of a format's hash lengths a line holds: a second one on the first line of an md5 answer is a second candidate. */
function digestsIn(f: AnswerFormat, line: string): { held: number; asked: number } {
  const asked = f.parts.filter((p) => p === "hash").length;
  if (!asked) return { held: 0, asked: 0 };
  const lengths = new Set(f.pieces.filter((p) => p.kind === "hash").map((p) => Number(/\{(\d+)\}/.exec(p.re)?.[1] ?? 32)));
  const held = [...line.matchAll(/(?<![0-9a-f])[0-9a-f]{32,128}(?![0-9a-f])/gi)].filter((m) => lengths.has(m[0].length)).length;
  return { held, asked };
}

/**
 * Whether a line gives some of a format's pieces and nothing else: one piece, or a run of pieces with their
 * separators (the first hash of md5(a)_md5(b), the name of Name_md5(file)). It is how an answer with one part still
 * open gives what it has, so that the note never asks for the open part (on the runs s01a4f4 and sf4406b eight of
 * twelve notes went to an answer that could not satisfy them, and one seat then guessed the missing half).
 */
export function knownPart(f: AnswerFormat, line: string): boolean {
  if (!line || looksLikeSentence(line)) return false;
  for (let i = 0; i < f.pieces.length; i += 1) {
    let re = "";
    for (let j = i; j < f.pieces.length; j += 1) {
      re += (j > i ? f.pieces[j]!.join : "") + f.pieces[j]!.re;
      if (j - i + 1 === f.pieces.length) continue;
      if (new RegExp(`^${re}$`, "i").test(line)) return true;
    }
  }
  return false;
}

/**
 * Whether an answer's value gives the format: null when its first line does (or the question names none), else what it
 * asks, for the note. `seenAnywhere` says the form is in the value but not as its first line, so the note can say
 * "move it up" instead of "it is missing". `open` is an answer that declares a part open (a partial answer with an
 * open or limited part): its first line may hold the pieces it has (knownPart), and an empty value asks nothing.
 * `extra_digests` is a first line that fits and holds more digests than the format asks.
 */
export function formatMiss(questionText: string, value: string, opts: { open?: boolean } = {}): { format: string; parts: string[]; example: string; first_line: string; seen_elsewhere: boolean; open?: true; extra_digests?: number } | null {
  const f = questionFormat(questionText);
  if (!f) return null;
  const first = firstLine(value);
  if (opts.open && (!first || knownPart(f, first))) return null;
  const digests = digestsIn(f, first);
  const extra = digests.held > digests.asked;
  const sentence = f.parts.includes("text") && looksLikeSentence(first);
  if (f.pattern.test(first) && !extra && !sentence) return null;
  const elsewhere = String(value ?? "").split(/\r?\n/).some((l) => f.pattern.test(firstLine(l))) || [...String(value ?? "").matchAll(/`([^`]+)`/g)].some((m) => f.pattern.test(m[1].trim()));
  return { format: f.format, parts: f.parts, example: formatExample(f), first_line: first.length > 120 ? `${first.slice(0, 117)}...` : first, seen_elsewhere: elsewhere, ...(opts.open ? { open: true as const } : {}), ...(extra ? { extra_digests: digests.held } : {}) };
}

/** The note an answer recorded out of its question's format gets. */
export function formatNote(section: string, miss: { format: string; parts: string[]; example?: string; first_line?: string; seen_elsewhere?: boolean; open?: boolean; extra_digests?: number }): string {
  const what = [...new Set(miss.parts.filter((p) => p !== "text"))]
    .map((p) => ({ hash: "a hash as its hex digits", clock: "a date and time in the placeholders' order, as digits", ip: "an address as four numbers", port: "a port as a number", email: "an address with @" })[p] ?? p)
    .join(", ");
  const shape = miss.example ? ` It looks like: ${miss.example}` : "";
  const where = miss.extra_digests
    ? `the value's first line holds ${miss.extra_digests} digests where the format asks ${miss.parts.filter((p) => p === "hash").length}: one answer is graded, so the first line holds one, and a second candidate goes in qualifier`
    : miss.seen_elsewhere
      ? "the value holds it, but not as its first line: an answer is graded on how its value starts, so put that one line first, alone, and the words after it"
      : "the value's first line is not in it";
  // An answer with a part open is asked only for the pieces it has: never for the open one.
  if (miss.open) return `${section} asks for its answer in the format ${miss.format}${what ? ` (${what})` : ""}, and ${where}.${shape} Recorded as written. This answer declares a part open, so nothing is asked for that part: record it again with supersedes, value holding only the piece of the format that is established, alone (or value empty), and everything else in qualifier. This note is not a reason to guess the open part`;
  return `${section} asks for its answer in the format ${miss.format}${what ? ` (${what})` : ""}, and ${where}.${shape} Recorded as written; record it again with supersedes, value exactly in that form and nothing else (no sentence, no label, no second candidate), and the words that go with it in qualifier. If part of it is not known yet, record the answer partial with that part open and value holding the piece that is known; this note is not a reason to guess a part`;
}
