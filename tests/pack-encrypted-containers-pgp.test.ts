/**
 * encrypted-containers: recovery_key_scan locates what its manifest says. An OpenPGP armored private key (RFC 4880 section 6.2,
 * "-----BEGIN PGP PRIVATE KEY BLOCK-----") is a private-key header and is located by offset, never by text; the located types are
 * the manifest's list; a recovery password written with a group missing (seven groups) is not located, and the manifest says so.
 * Bodies are random bytes made by the test and are never a real key.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";

const SCAN = join(ROOT, "packs", "encrypted-containers", "tools", "recovery_key_scan", "run.py");
const MANIFEST = join(ROOT, "packs", "encrypted-containers", "tools", "recovery_key_scan", "manifest.json");
type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

async function scan(cwd: string, args: Json): Promise<{ out: Json; stdout: string }> {
  const run = await runPy(SCAN, cwd, args, undefined, { AGENT_ID: "s1" });
  assert.equal(run.code, 0, run.stderr + run.stdout);
  assert.doesNotMatch(run.stderr, /Traceback/);
  return { out: JSON.parse(run.stdout) as Json, stdout: run.stdout };
}

const armor = (type: string, body: string): string => `-----BEGIN ${type}-----\nVersion: test\n\n${body}\n-----END ${type}-----\n`;

test("an armored OpenPGP private key is located as a private key of type PGP, with its file and offset, beside RSA, OPENSSH and PKCS#8 controls", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    // Random bodies: the canaries are what must never come back.
    const canary = () => randomBytes(48).toString("base64").replace(/=+$/, "");
    const bodies = { pgp: canary(), rsa: canary(), ssh: canary(), pkcs8: canary() };
    await writeFile(join(cwd, "work", "ev", "gpg-secret.asc"), "preamble line\n" + armor("PGP PRIVATE KEY BLOCK", bodies.pgp));
    await writeFile(join(cwd, "work", "ev", "rsa.pem"), armor("RSA PRIVATE KEY", bodies.rsa));
    await writeFile(join(cwd, "work", "ev", "ssh.key"), armor("OPENSSH PRIVATE KEY", bodies.ssh));
    await writeFile(join(cwd, "work", "ev", "pkcs8.pem"), armor("PRIVATE KEY", bodies.pkcs8));
    // The public block is not a private key.
    await writeFile(join(cwd, "work", "ev", "public.asc"), armor("PGP PUBLIC KEY BLOCK", canary()));
    const { out, stdout } = await scan(cwd, { path: "work/ev" });
    const found = Object.fromEntries(out.findings.filter((f: Json) => f.kind === "private key").map((f: Json) => [String(f.file).split("/").pop(), f]));
    assert.deepEqual(Object.keys(found).sort(), ["gpg-secret.asc", "pkcs8.pem", "rsa.pem", "ssh.key"], "four private keys, and the public block is none");
    assert.equal(found["gpg-secret.asc"].key_type, "PGP PRIVATE KEY BLOCK");
    assert.equal(found["gpg-secret.asc"].offset, "preamble line\n".length, "its offset is the header's");
    assert.equal(found["rsa.pem"].key_type, "RSA PRIVATE KEY");
    assert.equal(found["ssh.key"].key_type, "OPENSSH PRIVATE KEY");
    assert.equal(found["pkcs8.pem"].key_type, "PRIVATE KEY");
    for (const body of Object.values(bodies)) assert.ok(!stdout.includes(body), "a key's text is never echoed");
    assert.ok(!stdout.includes("Version: test"), "nor the armor's header lines");
    assert.equal(out.status, "complete");
  });
});

test("a BLOCK header of another type is 'other', and a type of three words is not located, as the manifest says", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "odd.asc"), armor("FOO PRIVATE KEY BLOCK", randomBytes(30).toString("base64")));
    await writeFile(join(cwd, "work", "ev", "three.pem"), armor("ONE TWO THREE PRIVATE KEY", randomBytes(30).toString("base64")));
    await writeFile(join(cwd, "work", "ev", "two.pem"), armor("ONE TWO PRIVATE KEY", randomBytes(30).toString("base64")));
    const { out } = await scan(cwd, { path: "work/ev" });
    const types = Object.fromEntries(out.findings.filter((f: Json) => f.kind === "private key").map((f: Json) => [String(f.file).split("/").pop(), f.key_type]));
    assert.deepEqual(types, { "odd.asc": "other", "two.pem": "other" });
    const manifest = JSON.parse(await readFile(MANIFEST, "utf8")) as Json;
    assert.match(manifest.description, /PGP PRIVATE KEY BLOCK/);
    assert.match(manifest.description, /three or more words[^;]*not located/);
  });
});

test("a recovery password written with seven groups is not located, and the manifest says that", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    const group = () => String(Math.floor(Math.random() * 90_000) * 11 + 110_000).slice(0, 6).padStart(6, "0");
    const seven = Array.from({ length: 7 }, group).join("-");
    const eight = Array.from({ length: 8 }, group).join("-");
    await writeFile(join(cwd, "work", "ev", "seven.txt"), `recovery key: ${seven}\n`);
    await writeFile(join(cwd, "work", "ev", "eight.txt"), `recovery key: ${eight}\n`);
    const { out, stdout } = await scan(cwd, { path: "work/ev" });
    const files = out.findings.map((f: Json) => String(f.file).split("/").pop());
    assert.deepEqual(files, ["eight.txt"], "only the eight-group transcription is located");
    assert.ok(!stdout.includes(seven) && !stdout.includes(eight), "no value is printed");
    const manifest = JSON.parse(await readFile(MANIFEST, "utf8")) as Json;
    assert.match(manifest.description, /seven groups\) or with groups of another size is not located/);
  });
});
