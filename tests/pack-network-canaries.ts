/**
 * Random, realistic secrets for the network-forensics suites: a seeded generator and the shapes the shared withholding
 * block withholds today (a vendor prefix with a random body of the real length, a three-part JWT). A suite plants many of
 * them in every slot a tool prints and counts the ones that come out; one hand-built string per slot would show only that
 * the one string is caught. The shapes the block does not yet catch are the shared block's to widen, not these suites'.
 */
export type Rng = () => number;

/** mulberry32: small, seeded, good enough for test data. */
export function createRng(seed: number): Rng {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const URLSAFE = B62 + "-_";
const UPPER32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function pick(rng: Rng, alphabet: string, n: number): string {
  let out = "";
  for (let i = 0; i < n; i++) out += alphabet[Math.floor(rng() * alphabet.length)];
  return out;
}

function b64url(rng: Rng, bytes: number): string {
  return pick(rng, URLSAFE, Math.ceil((bytes * 4) / 3));
}

export type Shape = "ghp" | "akia" | "jwt" | "xoxb" | "github_pat" | "sk";

export function planted(rng: Rng, shape: Shape): string {
  switch (shape) {
    case "ghp": return "ghp_" + pick(rng, B62, 36);
    case "akia": return "AKIA" + pick(rng, UPPER32, 16);
    case "jwt": return "eyJ" + b64url(rng, 24) + "." + "eyJ" + b64url(rng, 36) + "." + b64url(rng, 32);
    case "xoxb": return `xoxb-${Math.floor(rng() * 9e11 + 1e11)}-${Math.floor(rng() * 9e11 + 1e11)}-` + pick(rng, B62, 24);
    case "github_pat": return "github_pat_" + pick(rng, B62, 22) + "_" + pick(rng, B62, 59);
    case "sk": return "sk-" + pick(rng, B62, 48);
  }
}
