/**
 * Random canaries for the windows tools' withholding boundary. A canary is a fresh random secret of a realistic shape, planted in a slot
 * (a registry name, an event field, a table cell...). A leak is the canary's random core printed whole in the answer, on stderr or in a file
 * the tool wrote. Seeded, so a failing case can be rebuilt; shapes are built from the vendors' public token formats and from common
 * credential spellings, never from a tool's output. The residual shapes (a plain password, a pronounceable passphrase, a UUID-shaped key) are
 * here on purpose: the boundary does not claim them, and a test asserts that, so a sentence in a skill that says so stays true.
 */
import { randomBytes } from "node:crypto";

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const URLSAFE = ALNUM + "-_";
const B64 = ALNUM + "+/";

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

export type Canary = { text: string; cores: string[] };
export type Shape = { name: string; family: string; make: (r: () => number) => Canary; /** usable as a file name (no `/`, NUL or control character) */ fileOk: boolean; /** the boundary does not claim this shape */ residual?: boolean };

const rs = (r: () => number, n: number, alpha = ALNUM): string => Array.from({ length: n }, () => alpha[Math.floor(r() * alpha.length)]).join("");
const b64n = (r: () => number, n: number): string => Buffer.from(Array.from({ length: n }, () => Math.floor(r() * 256))).toString("base64");
const one = (text: string, core: string): Canary => ({ text, cores: [core] });
const WORDS = ["harbor", "violet", "mango", "quartz", "falcon", "meadow", "copper", "anchor", "pepper", "winter", "garden", "silver", "rocket", "planet", "bridge", "castle"];

export const SHAPES: Shape[] = [
  { name: "ghp", family: "token prefix families", fileOk: true, make: (r) => { const c = rs(r, 36); return one("ghp_" + c, c); } },
  { name: "github_pat", family: "token prefix families", fileOk: true, make: (r) => { const a = rs(r, 22), b = rs(r, 59); return { text: `github_pat_${a}_${b}`, cores: [a, b] }; } },
  { name: "akia", family: "token prefix families", fileOk: true, make: (r) => { const c = rs(r, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"); return one("AKIA" + c, c); } },
  { name: "glpat", family: "token prefix families", fileOk: true, make: (r) => { const c = rs(r, 20, URLSAFE); return one("glpat-" + c, c); } },
  { name: "sk_live", family: "token prefix families", fileOk: true, make: (r) => { const c = rs(r, 24); return one("sk_live_" + c, c); } },
  { name: "sendgrid", family: "token prefix families", fileOk: true, make: (r) => { const a = rs(r, 22, URLSAFE), b = rs(r, 43, URLSAFE); return { text: `SG.${a}.${b}`, cores: [a, b] }; } },
  { name: "aiza", family: "token prefix families", fileOk: true, make: (r) => { const c = rs(r, 35, URLSAFE); return one("AIza" + c, c); } },
  { name: "npm", family: "token prefix families", fileOk: true, make: (r) => { const c = rs(r, 36); return one("npm_" + c, c); } },
  { name: "jwt", family: "JWT", fileOk: true, make: (r) => { const p = Buffer.from(JSON.stringify({ sub: rs(r, 8), iat: Math.floor(r() * 1e9) })).toString("base64url"); const s = rs(r, 43, URLSAFE); return { text: `eyJhbGciOiJIUzI1NiJ9.${p}.${s}`, cores: [p, s] }; } },
  { name: "aws_secret40", family: "AWS-shaped and base64 keys", fileOk: false, make: (r) => { const c = rs(r, 40, B64); return one(c, c); } },
  { name: "b64_16", family: "AWS-shaped and base64 keys", fileOk: false, make: (r) => { const c = b64n(r, 16); return one(c, c); } },
  { name: "b64_20", family: "AWS-shaped and base64 keys", fileOk: false, make: (r) => { const c = b64n(r, 20); return one(c, c); } },
  { name: "b64_32", family: "AWS-shaped and base64 keys", fileOk: false, make: (r) => { const c = b64n(r, 32); return one(c, c); } },
  { name: "pem", family: "PEM private key", fileOk: false, make: (r) => { const b = b64n(r, 48); return one(`-----BEGIN PRIVATE KEY-----${b}-----END PRIVATE KEY-----`, b); } },
  { name: "pw_assign", family: "named secrets and user-info", fileOk: false, make: (r) => { const c = rs(r, 14, ALNUM + "!#$%^&*"); return one(`Password="${c}"`, c); } },
  { name: "pw_colon", family: "named secrets and user-info", fileOk: true, make: (r) => { const c = rs(r, 14); return one(`password: ${c}`, c); } },
  { name: "userinfo_at", family: "named secrets and user-info", fileOk: false, make: (r) => { const c = rs(r, 8) + "@" + rs(r, 8); return one(`https://svc:${c}@host.example.test/repo`, c); } },
  { name: "nul_split", family: "invisible splits", fileOk: false, make: (r) => { const c = rs(r, 36); const t = "ghp_" + c; return { text: t.slice(0, 20) + "\u0000" + t.slice(20), cores: [c.slice(0, 16)] }; } },
  { name: "zw_split", family: "invisible splits", fileOk: true, make: (r) => { const c = rs(r, 36); const t = "ghp_" + c; return { text: t.slice(0, 20) + "​" + t.slice(20), cores: [c.slice(0, 16)] }; } },
  { name: "random_base62_24", family: "generic random token", fileOk: true, make: (r) => { const c = rs(r, 24); return one(c, c); } },
  { name: "random_base62_40", family: "generic random token", fileOk: true, make: (r) => { const c = rs(r, 40); return one(c, c); } },
  // not claimed by the boundary (stated in the manifests and skills)
  { name: "plain_password", family: "residual: plain password", fileOk: true, residual: true, make: (r) => { const c = WORDS[Math.floor(r() * WORDS.length)] + Math.floor(r() * 9000 + 1000); return one(c, c); } },
  { name: "passphrase", family: "residual: pronounceable text", fileOk: true, residual: true, make: (r) => { const c = Array.from({ length: 4 }, () => WORDS[Math.floor(r() * WORDS.length)]).join("-"); return one(c, c); } },
  { name: "uuid_secret", family: "residual: UUID-shaped key", fileOk: true, residual: true, make: () => { const h = randomBytes(16).toString("hex"); const c = `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`; return one(c, c); } },
];

/** `n` canaries of a shape, seeded by the shape's name and `seed`. */
export function plant(shape: Shape, n: number, seed = 1): Canary[] {
  let h = seed;
  for (const ch of shape.name) h = (Math.imul(h, 31) + ch.charCodeAt(0)) >>> 0;
  const r = prng(h);
  return Array.from({ length: n }, () => shape.make(r));
}

const INVISIBLE = /[\u0000-\u0008\u000b-\u001f\u007f­​-‏‪-‮⁠-⁤﻿]/g;

/** How many canaries have every core printed whole in `outputs` (raw, or with invisible characters taken out and NFKC applied). */
export function leaked(canaries: Canary[], outputs: string[]): number {
  const hay = outputs.flatMap((o) => [o, o.replace(INVISIBLE, "").normalize("NFKC")]);
  return canaries.filter((c) => c.cores.every((core) => hay.some((h) => h.includes(core)))).length;
}

/** A fragment (12 consecutive characters of a core, or the core when shorter) printed, whole or not: the count of canaries with any. */
export function fragmentLeaked(canaries: Canary[], outputs: string[]): number {
  const hay = outputs.flatMap((o) => [o, o.replace(INVISIBLE, "").normalize("NFKC")]);
  return canaries.filter((c) => c.cores.some((core) => {
    const w = Math.min(12, core.length);
    for (let i = 0; i + w <= core.length; i++) if (hay.some((h) => h.includes(core.slice(i, i + w)))) return true;
    return false;
  })).length;
}
