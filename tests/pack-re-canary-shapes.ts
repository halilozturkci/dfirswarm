/**
 * Every shape of secret the reverse-engineering tools' one way out says it withholds, as canaries, for the slot-by-slot harness
 * (tests/pack-re-canary-slots.test.ts) and the unit checks of the sanitiser. Each maker takes the longest text the slot can hold and
 * returns what to plant, the strings no nine characters of which may reach any output, and a password no six characters of which may.
 *
 * The shapes are the token families the shared withholding block names (an AWS key id, GitHub tokens, Slack tokens, `sk-` keys, a
 * JWT, a long hex run, a base64 run with `=` padding, the AWS secret access key shape: base64 joined by `/`), the user-info of a URL,
 * a bare `name:password@` cut off right after the `@` (no host follows), a mailto: address with a password, a connection string's
 * `Password=` value, a PEM body after its header, and a token head that a letter precedes (`XAKIA...`). Each is generated from a
 * fixed seed, so a failure names the same canary every run.
 */

export type Canary = { plant: string; check: string[]; pw?: string };
export type Shape = (max: number, rnd: () => number) => Canary | null;

/** mulberry32: a small deterministic generator. */
export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const AL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const LOW = "abcdefghijklmnopqrstuvwxyz";
const CAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIG = "0123456789";
const pick = (rnd: () => number, a: string, n: number): string => Array.from({ length: n }, () => a[Math.floor(rnd() * a.length)]).join("");
/** A random piece that always holds a lower-case letter, a capital and a digit: what a base64 token's piece between two `/` looks like. */
const piece = (rnd: () => number, n: number): string => {
  const s = (pick(rnd, AL, n - 3) + pick(rnd, LOW, 1) + pick(rnd, CAP, 1) + pick(rnd, DIG, 1)).split("");
  for (let i = s.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [s[i], s[j]] = [s[j]!, s[i]!];
  }
  return s.join("");
};
const password = (rnd: () => number): string => "Pw" + piece(rnd, 10);

export const SHAPES: Record<string, Shape> = {
  akia: (_m, r) => { const s = "AKIA" + pick(r, UP, 16); return { plant: s, check: [s] }; },
  // a key id cut to fourteen characters with a letter in front of it (a name cut by a declared length): the head of a token still
  akia_after_letter: (m, r) => { if (m < 15) return null; const k = "AKIA" + pick(r, UP, 10); return { plant: "X" + k, check: [k] }; },
  ghp: (m, r) => { const s = "ghp_" + piece(r, Math.min(36, m - 4)); return s.length >= 24 ? { plant: s, check: [s] } : null; },
  github_pat: (m, r) => { const s = "github_pat_" + piece(r, Math.min(29, m - 11)); return s.length >= 31 ? { plant: s, check: [s] } : null; },
  xox: (m, r) => { const s = "xoxb-" + pick(r, DIG, 12) + "-" + piece(r, Math.min(13, m - 18)); return s.length >= 28 ? { plant: s, check: [s] } : null; },
  sk: (m, r) => { const s = "sk-" + piece(r, Math.min(32, m - 3)); return s.length >= 23 ? { plant: s, check: [s] } : null; },
  jwt: (m, r) => {
    if (m < 31) return null;
    const n = Math.min(17, Math.floor((m - 8) / 3));
    const s = "eyJ" + piece(r, n) + ".eyJ" + piece(r, n) + "." + piece(r, n);
    return { plant: s, check: [s] };
  },
  hex: (m, r) => { const s = pick(r, "0123456789abcdef", Math.min(40, m)); return s.length >= 32 ? { plant: s, check: [s] } : null; },
  base64: (m, r) => { const s = piece(r, Math.min(42, m - 3)) + "+=="; return s.length >= 26 ? { plant: s, check: [s] } : null; },
  // The AWS secret access key shape: base64 of 40 characters joined by `/` (the published example is wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY).
  aws_secret: (m, r) => { if (m < 40) return null; const s = piece(r, 13) + "/" + piece(r, 7) + "/" + piece(r, 18); return { plant: s, check: [s] }; },
  aws_secret_30: (m, r) => { if (m < 30) return null; const s = piece(r, 9) + "/" + piece(r, 9) + "/" + piece(r, 10); return { plant: s, check: [s] }; },
  pem_body: (m, r) => { if (m < 80) return null; const b = piece(r, 48); return { plant: "-----BEGIN PRIVATE KEY-----" + b, check: [b] }; },
  // a body glued to its header with few case changes and few digits: the header's dashes join the two into one run no shape rule reads
  pem_body_plain: (m, r) => { if (m < 80) return null; const b = pick(r, CAP, 24) + pick(r, LOW, 22) + pick(r, DIG, 2); return { plant: "-----BEGIN PRIVATE KEY-----" + b, check: [b] }; },
  url_userinfo: (m, r) => { const pw = password(r); const s = "https://usr:" + pw + "@host.example/p"; return s.length <= m ? { plant: s, check: [], pw } : null; },
  userinfo_cut: (m, r) => { const pw = password(r); const s = "u:" + pw + "@"; return s.length <= m ? { plant: s, check: [], pw } : null; },
  mailto: (m, r) => { const pw = password(r); const s = "mailto:usr:" + pw + "@host.example"; return s.length <= m ? { plant: s, check: [], pw } : null; },
  connection_string: (m, r) => { const pw = password(r); const s = "Password=" + pw + ";"; return s.length <= m ? { plant: s, check: [], pw } : null; },
};

/** Every shape that fits `max` characters, each made from its own seed. */
export function canaries(max: number, seed: number): [string, Canary][] {
  const out: [string, Canary][] = [];
  let k = 0;
  for (const [name, make] of Object.entries(SHAPES)) {
    const c = make(max, prng(seed * 131 + k++));
    if (c) out.push([name, c]);
  }
  return out;
}

/** The forms a window can take in an output: its bytes, hex (both cases), UTF-16 and the hex of that. */
export function forms(w: string): Buffer[] {
  const b = Buffer.from(w, "latin1");
  const u = Buffer.from(w, "utf16le");
  return [b, Buffer.from(b.toString("hex")), Buffer.from(b.toString("hex").toUpperCase()), u, Buffer.from(u.toString("hex")), Buffer.from(u.toString("hex").toUpperCase())];
}

/** Every nine-character window of each checked string and every six characters of the password, in every form. */
export function needles(c: Canary): { label: string; bytes: Buffer }[] {
  const out: { label: string; bytes: Buffer }[] = [];
  for (const s of c.check) {
    for (let i = 0; i + 9 <= s.length; i++) for (const f of forms(s.slice(i, i + 9))) out.push({ label: s.slice(i, i + 9), bytes: f });
  }
  if (c.pw) for (let i = 0; i + 6 <= c.pw.length; i++) out.push({ label: `password ${c.pw.slice(i, i + 6)}`, bytes: Buffer.from(c.pw.slice(i, i + 6), "latin1") });
  return out;
}
