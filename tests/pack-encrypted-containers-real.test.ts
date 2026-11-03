/**
 * The encrypted-containers pack against real volumes, not against volumes built from the specifications.
 *
 * Every other encrypted-containers suite feeds the tools headers built from the formats' documents and stand-in readers that print what
 * the libraries document. This file runs the tools (crypto_id, crypto_metadata, tcrypt_header) against volumes the real programs made
 * or read, and compares each answer with what the reader itself prints:
 *
 *   - LUKS1 and LUKS2 volumes are made here with `cryptsetup luksFormat` and `luksAddKey` on sparse files, with random throwaway
 *     passphrases that live in 0600 files of this test's scratch directory and are removed with it. They are made and read inside
 *     `docker run --network none` (the image named by DFIR_LINUX_IMAGE, default dfirswarm-linux:dev-amd64, which must already be on
 *     the machine: nothing is pulled), or, when there is no such image, with the programs on this host's PATH.
 *   - The owner's BitLocker, FileVault (Core Storage) and VeraCrypt volumes are read only from paths the owner gives in the environment
 *     (mounted read-only; never copied into the repository, never printed):
 *       DFIR_REAL_BITLOCKER, DFIR_REAL_BITLOCKER_OFFSET (bytes, default 0)
 *       DFIR_REAL_FILEVAULT, DFIR_REAL_FILEVAULT_OFFSET (bytes, default 0)
 *       DFIR_REAL_VERACRYPT, DFIR_REAL_VERACRYPT_PASSWORD_FILE (a 0600 file holding the volume's password)
 *     A case whose variable is unset, or whose program is missing, skips and says which.
 *
 * A skip is not a pass: the report names what did not run. Run it under `timeout`.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import type { TestContext } from "node:test";
import { type Json } from "./pack-network-harness.ts";
import { ROOT } from "./tool-library-harness.ts";

const IMAGE = process.env.DFIR_LINUX_IMAGE || "dfirswarm-linux:dev-amd64";
const ONE_MIB = 1048576;

// --- where the programs run ----------------------------------------------------------------------------------------------------------

type Where = { mode: "docker" | "host"; programs: string[] };
type Ran = { status: number | null; stdout: string; stderr: string };

function run(cmd: string, args: string[], opts: { env?: Record<string, string>; timeout?: number } = {}): Ran {
  const r = spawnSync(cmd, args, { encoding: "utf8", timeout: opts.timeout ?? 60_000, env: { ...process.env, ...opts.env } });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

let containers = 0;

/**
 * Run a shell script where the programs are. In docker mode: a throwaway container with no network, the repository read-only at /repo,
 * the scratch directory at /s, each mount (a variable name and a host path) read-only, as the caller's own user, removed by name
 * afterwards. In host mode: `sh -c` with the same variables (REPO, S, the mounts and the plain `vars`) set to the real paths.
 */
function inside(where: Where, scratch: string, script: string, mounts: Record<string, string> = {}, vars: Record<string, string> = {}): Ran {
  const timeout = 240_000;
  if (where.mode === "host") {
    return run("sh", ["-c", `cd "$S" && ${script}`], { env: { REPO: ROOT, S: scratch, ...mounts, ...vars }, timeout });
  }
  containers += 1;
  const name = `b42-real-${process.pid}-${containers}-${randomBytes(3).toString("hex")}`;
  const args = ["run", "--rm", "--name", name, "--network", "none", "--entrypoint", "sh", "-w", "/s",
    "--user", `${process.getuid?.() ?? 0}:${process.getgid?.() ?? 0}`, "-e", "HOME=/tmp", "-e", "REPO=/repo", "-e", "S=/s",
    "-v", `${scratch}:/s`, "-v", `${ROOT}:/repo:ro`];
  for (const [name2, path] of Object.entries(mounts)) args.push("-v", `${path}:/m/${name2}:ro`, "-e", `${name2}=/m/${name2}`);
  for (const [name2, value] of Object.entries(vars)) args.push("-e", `${name2}=${value}`);
  args.push(IMAGE, "-c", script);
  try {
    return run("docker", args, { timeout });
  } finally {
    run("docker", ["rm", "-f", name], { timeout: 30_000 }); // gone already after a normal run; this ends one a timeout left behind
  }
}

let located: Where | undefined;

/** Docker with a local image, else the host's own programs; never a pull. */
function locate(): Where {
  if (located) return located;
  const probe = "for p in cryptsetup bdeinfo fvdeinfo python3; do command -v $p >/dev/null 2>&1 && echo $p; done; true";
  if (run("docker", ["image", "inspect", IMAGE, "--format", "{{.Id}}"], { timeout: 30_000 }).status === 0) {
    const d: Where = { mode: "docker", programs: [] };
    const r = inside(d, tmpdir(), probe);
    if (r.status === 0) {
      d.programs = r.stdout.split("\n").filter(Boolean);
      return (located = d);
    }
  }
  const r = run("sh", ["-c", probe]);
  return (located = { mode: "host", programs: r.stdout.split("\n").filter(Boolean) });
}

/** The place to run in, or a skip that names the missing programs. */
function need(t: TestContext, ...programs: string[]): Where | undefined {
  const where = locate();
  const missing = ["python3", ...programs].filter((p) => !where.programs.includes(p));
  if (missing.length) {
    t.skip(`${missing.join(", ")} not available ${where.mode === "docker" ? `in image ${IMAGE}` : `on this host's PATH (and no local docker image ${IMAGE})`}`);
    return undefined;
  }
  t.diagnostic(where.mode === "docker" ? `programs run in docker --network none (${IMAGE})` : "programs run on this host");
  return where;
}

/** The owner's volume for a case: its path from the environment, or a skip that names the variable. */
function owner(t: TestContext, variable: string): string | undefined {
  const path = process.env[variable];
  if (!path) {
    t.skip(`${variable} is not set; the owner supplies this volume (read-only, by path)`);
    return undefined;
  }
  if (!existsSync(path) || !statSync(path).isFile()) {
    t.skip(`${variable} does not name a regular file on this machine`);
    return undefined;
  }
  return path;
}

function offsetOf(variable: string): number {
  const v = process.env[variable];
  if (v === undefined || v === "") return 0;
  assert.match(v, /^[0-9]+$/, `${variable} is a byte offset`);
  return Number(v);
}

// --- the tools, as a job runs them -----------------------------------------------------------------------------------------------------

/** A shell function `tool <name> <label> <json>`: a pack tool run as a secret-output job, its answer, stderr and exit status kept under ans/. */
const TOOL_FN = [
  "mkdir -p ans",
  "tool() { o=\"$S/out-$2\"; mkdir -p \"$o\";",
  "  AGENT_ID=s1 JOB_ID=j$2 OUT=\"$o\" SECRET_OUTPUT=1 timeout 110 python3 \"$REPO/packs/encrypted-containers/tools/$1/run.py\" >\"ans/$2.json\" 2>\"ans/$2.err\" <<J",
  "$3",
  "J",
  "  echo $? >\"ans/$2.rc\"; }",
].join("\n");

async function answer(scratch: string, label: string): Promise<Json> {
  const rc = (await readFile(join(scratch, "ans", `${label}.rc`), "utf8")).trim();
  const err = await readFile(join(scratch, "ans", `${label}.err`), "utf8");
  assert.equal(rc, "0", `${label}: exit status ${rc}: ${err}`);
  assert.doesNotMatch(err, /Traceback/);
  return JSON.parse(await readFile(join(scratch, "ans", `${label}.json`), "utf8"));
}

const scratches: string[] = [];

async function scratchDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "b42-real-"));
  scratches.push(dir);
  return dir;
}

after(async () => {
  for (const dir of scratches) await rm(dir, { recursive: true, force: true });
});

/** Every file under a directory, as text. */
async function textUnder(dir: string): Promise<string> {
  let all = "";
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    all += e.isDirectory() ? await textUnder(p) : (await readFile(p, "latin1")) + "\n";
  }
  return all;
}

// --- LUKS volumes made by cryptsetup -----------------------------------------------------------------------------------------------------

type Luks = { scratch: string; passphrases: string[] };

let luks: Promise<Luks> | undefined;

/** One LUKS1 and one LUKS2 volume with two key slots each (LUKS2: argon2id and pbkdf2), and a copy of the LUKS2 one at a 1 MiB offset. */
function luksVolumes(where: Where): Promise<Luks> {
  luks ??= (async () => {
    const scratch = await scratchDir();
    const passphrases = [randomBytes(24).toString("base64"), randomBytes(24).toString("base64")];
    await writeFile(join(scratch, "pw1"), passphrases[0], { mode: 0o600 });
    await writeFile(join(scratch, "pw2"), passphrases[1], { mode: 0o600 });
    const script = [
      "set -e",
      "mkdir -p ref",
      "truncate -s 32M luks1.img luks2.img",
      "cryptsetup luksFormat -q --type luks1 --pbkdf-force-iterations 1000 --key-file pw1 luks1.img",
      "cryptsetup luksAddKey -q --pbkdf-force-iterations 1000 --key-file pw1 luks1.img pw2",
      "cryptsetup luksFormat -q --type luks2 --pbkdf argon2id --pbkdf-memory 1024 --pbkdf-parallel 1 --pbkdf-force-iterations 4 --key-file pw1 luks2.img",
      "cryptsetup luksAddKey -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file pw1 luks2.img pw2",
      "cryptsetup luksDump luks1.img > ref/luks1.txt",
      "cryptsetup luksDump luks2.img > ref/luks2.txt",
      "cryptsetup luksDump --dump-json-metadata luks2.img > ref/luks2.json",
      "{ head -c 1048576 /dev/zero; cat luks2.img; } > luks2-at-1mib.img",
      TOOL_FN,
      "set +e",
      "tool crypto_id id-luks1 '{\"path\":\"luks1.img\"}'",
      "tool crypto_id id-luks2 '{\"path\":\"luks2.img\"}'",
      `tool crypto_id id-off '{"path":"luks2-at-1mib.img","offset":${ONE_MIB}}'`,
      "tool crypto_metadata md-luks1 '{\"path\":\"luks1.img\"}'",
      "tool crypto_metadata md-luks2 '{\"path\":\"luks2.img\"}'",
      `tool crypto_metadata md-off '{"path":"luks2-at-1mib.img","offset":${ONE_MIB}}'`,
      "true",
    ].join("\n");
    const r = inside(where, scratch, script);
    const clean = (s: string): string => passphrases.reduce((acc, p) => acc.replaceAll(p, "<withheld>"), s);
    assert.equal(r.status, 0, `making the LUKS volumes failed (exit ${r.status}): ${clean(r.stderr)}`);
    return { scratch, passphrases };
  })();
  return luks;
}

const refText = (l: Luks, name: string): Promise<string> => readFile(join(l.scratch, "ref", name), "utf8");

/** A `Label:   value` line of cryptsetup's text dump. */
function field(dump: string, label: string): string {
  const m = dump.match(new RegExp(`^${label}:[ \\t]*(.*?)[ \\t]*$`, "m"));
  assert.ok(m, `the reader prints a "${label}" line`);
  return m[1];
}

type Slot = { slot: number; enabled: boolean; iterations: number; offset: number; stripes: number };

/** The LUKS1 key slot table of `cryptsetup luksDump`. */
function luks1Slots(dump: string): Slot[] {
  const heads = [...dump.matchAll(/^Key Slot (\d):\s+(ENABLED|DISABLED)\s*$/gm)];
  return heads.map((m, i) => {
    const start = (m.index ?? 0) + m[0].length;
    const block = dump.slice(start, i + 1 < heads.length ? heads[i + 1].index : undefined);
    const num = (label: string): number => Number(block.match(new RegExp(`${label}:\\s*(\\d+)`))?.[1] ?? 0);
    return { slot: Number(m[1]), enabled: m[2] === "ENABLED", iterations: num("Iterations"), offset: num("Key material offset"), stripes: num("AF stripes") };
  });
}

/** No passphrase in any answer, error or output file the tools left. */
async function noPassphrase(l: Luks): Promise<void> {
  let all = await textUnder(join(l.scratch, "ans"));
  for (const n of await readdir(l.scratch)) if (n.startsWith("out-")) all += await textUnder(join(l.scratch, n));
  for (const p of l.passphrases) assert.ok(!all.includes(p), "a passphrase reached a tool's answer, error or output file");
}

test("real LUKS1 (cryptsetup luksFormat): crypto_id agrees with cryptsetup luksDump on every field it prints", async (t) => {
  const where = need(t, "cryptsetup");
  if (!where) return;
  const l = await luksVolumes(where);
  const dump = await refText(l, "luks1.txt");
  const a = await answer(l.scratch, "id-luks1");
  assert.equal(a.scheme, "LUKS1");
  assert.equal(a.version, 1);
  assert.equal(a.status, "complete", a.status_basis);
  assert.equal(a.cipher, field(dump, "Cipher name"));
  assert.equal(a.cipher_mode, field(dump, "Cipher mode"));
  assert.equal(a.hash, field(dump, "Hash spec"));
  assert.equal(a.payload_offset_sectors, Number(field(dump, "Payload offset")));
  assert.equal(a.key_bytes, Number(field(dump, "MK bits")) / 8);
  assert.equal(a.uuid, field(dump, "UUID"));
  const slots = luks1Slots(dump);
  assert.equal(slots.length, 8);
  assert.equal(a.key_slots.length, 8);
  for (const s of slots) {
    const got = a.key_slots[s.slot];
    assert.equal(got.slot, s.slot);
    assert.equal(got.state, s.enabled ? "enabled" : "disabled");
    if (s.enabled) {
      assert.equal(got.iterations, s.iterations);
      assert.equal(got.key_material_offset_sectors, s.offset);
      assert.equal(got.stripes, s.stripes);
    }
  }
  assert.equal(a.enabled_slots, slots.filter((s) => s.enabled).length);
  assert.equal(a.enabled_slots, 2);
  await noPassphrase(l);
});

test("real LUKS2 (cryptsetup luksFormat): crypto_id agrees with cryptsetup luksDump on the header fields it prints", async (t) => {
  const where = need(t, "cryptsetup");
  if (!where) return;
  const l = await luksVolumes(where);
  const dump = await refText(l, "luks2.txt");
  const json = JSON.parse(await refText(l, "luks2.json"));
  const a = await answer(l.scratch, "id-luks2");
  assert.equal(a.scheme, "LUKS2");
  assert.equal(a.version, 2);
  assert.equal(a.status, "complete", a.status_basis);
  assert.equal(a.uuid, field(dump, "UUID"));
  assert.equal(a.sequence_id, Number(field(dump, "Epoch")));
  assert.equal(a.header_size_bytes, Number(json.config.json_size) + 4096, "the binary header is 4096 bytes, then the JSON area");
  assert.equal(a.label, "", "no label was set");
  await noPassphrase(l);
});

test("real LUKS2 at a 1 MiB offset: crypto_id reads the same header through the byte offset", async (t) => {
  const where = need(t, "cryptsetup");
  if (!where) return;
  const l = await luksVolumes(where);
  const plain = await answer(l.scratch, "id-luks2");
  const off = await answer(l.scratch, "id-off");
  assert.equal(off.scheme, "LUKS2");
  assert.equal(off.offset_bytes, ONE_MIB);
  assert.equal(off.uuid, plain.uuid);
  assert.equal(off.sequence_id, plain.sequence_id);
  assert.equal(off.header_size_bytes, plain.header_size_bytes);
});

test("real LUKS: crypto_metadata never calls a volume complete that cryptsetup refused, and says so", async (t) => {
  const where = need(t, "cryptsetup");
  if (!where) return;
  const l = await luksVolumes(where);
  for (const label of ["md-luks1", "md-luks2", "md-off"]) {
    const a = await answer(l.scratch, label);
    assert.equal(a.reader.program, "cryptsetup", label);
    assert.ok(["LUKS1", "LUKS2"].includes(a.scheme), label);
    if (a.reader.exit_code !== 0) {
      assert.notEqual(a.status, "complete", `${label}: ${a.status_basis}`);
      assert.deepEqual(a.records, [], `${label}: a refused reader gives no key slot list`);
      assert.match(a.status_basis, /not an empty list|exited|did not/, label);
    }
  }
  await noPassphrase(l);
});

// FINDING at the head this file was written on: crypto_metadata runs cryptsetup luksDump on a 32768-byte copy of the volume's start, and
// the real cryptsetup refuses that copy ("Device ... is too small. Need at least 16777216 bytes" for LUKS2, 2066432 bytes for LUKS1),
// so on a real LUKS volume the answer is `partial` with no key slots. The stand-in readers of the other suites accept any file, so no
// other test shows it. The case below states what the tool is for; it is a todo until the tool reads a real volume, and then it
// is a passing test.
test("real LUKS: crypto_metadata lists the key slots, digests and segments that cryptsetup luksDump lists",
  { todo: "crypto_metadata gives cryptsetup a 32768-byte copy, which a real cryptsetup refuses as too small" }, async (t) => {
    const where = need(t, "cryptsetup");
    if (!where) return;
    const l = await luksVolumes(where);
    const one = await answer(l.scratch, "md-luks1");
    assert.equal(one.status, "complete", one.status_basis);
    assert.equal(one.reader.exit_code, 0);
    assert.equal(one.counts.keyslot, 2);
    const json = JSON.parse(await refText(l, "luks2.json"));
    for (const label of ["md-luks2", "md-off"]) {
      const a = await answer(l.scratch, label);
      assert.equal(a.status, "complete", `${label}: ${a.status_basis}`);
      assert.equal(a.reader.exit_code, 0);
      assert.equal(a.counts.keyslot, Object.keys(json.keyslots).length);
      assert.equal(a.counts.segment, Object.keys(json.segments).length);
      assert.equal(a.counts.digest, Object.keys(json.digests).length);
      assert.equal(a.counts.token, Object.keys(json.tokens).length);
      const kdfs = a.records.filter((r: Json) => r.kind === "keyslot").map((r: Json) => r.kdf.type);
      assert.deepEqual(kdfs, Object.keys(json.keyslots).map((k) => json.keyslots[k].kdf.type));
    }
  });

// --- the owner's volumes, by path ----------------------------------------------------------------------------------------------------

/** crypto_id and crypto_metadata on one owner volume, and the reader once for the reference. */
async function ownerVolume(where: Where, path: string, offset: number, reader: string): Promise<{ id: Json; md: Json; ref: string }> {
  const scratch = await scratchDir();
  const json = "$(printf '{\"path\":\"%s\",\"offset\":%s}' \"$VOL\" \"$OFF\")";
  const script = ["set -e", "mkdir -p ref", TOOL_FN, "set +e",
    `tool crypto_id id "${json}"`, `tool crypto_metadata md "${json}"`, `${reader} > ref/reader.txt 2>&1`, "true"].join("\n");
  const r = inside(where, scratch, script, { VOL: path }, { OFF: String(offset) });
  assert.equal(r.status, 0, r.stderr);
  return { id: await answer(scratch, "id"), md: await answer(scratch, "md"), ref: await readFile(join(scratch, "ref", "reader.txt"), "utf8") };
}

test("the owner's BitLocker volume: crypto_id and crypto_metadata agree with bdeinfo", async (t) => {
  const path = owner(t, "DFIR_REAL_BITLOCKER");
  if (!path) return;
  const where = need(t, "bdeinfo");
  if (!where) return;
  const offset = offsetOf("DFIR_REAL_BITLOCKER_OFFSET");
  const { id, md, ref } = await ownerVolume(where, path, offset, 'bdeinfo -o "$OFF" "$VOL"');
  assert.match(id.scheme, /^BitLocker/);
  assert.equal(md.reader.program, "bdeinfo");
  assert.equal(md.reader.exit_code, 0, "bdeinfo reads the volume's metadata");
  assert.equal(md.status, "complete", md.status_basis);
  assert.equal(md.records.length, (ref.match(/^Key protector \d+:/gm) ?? []).length, "one record per key protector bdeinfo lists");
  const method = ref.match(/^\s*Encryption method\s*:\s*(.+?)\s*$/m);
  if (method) assert.equal(md.fields.encryption_method, method[1]);
});

test("the owner's FileVault (Core Storage) volume: crypto_id and crypto_metadata agree with fvdeinfo", async (t) => {
  const path = owner(t, "DFIR_REAL_FILEVAULT");
  if (!path) return;
  const where = need(t, "fvdeinfo");
  if (!where) return;
  const offset = offsetOf("DFIR_REAL_FILEVAULT_OFFSET");
  const { id, md, ref } = await ownerVolume(where, path, offset, 'fvdeinfo -o "$OFF" "$VOL"');
  assert.match(id.scheme, /^Apple Core Storage/);
  assert.equal(md.reader.program, "fvdeinfo");
  assert.equal(md.reader.exit_code, 0, "fvdeinfo reads the volume's metadata");
  assert.equal(md.status, "complete", md.status_basis);
  for (const label of ["number of physical volumes", "number of logical volume groups"]) {
    const m = ref.match(new RegExp(`^\\s*${label}\\s*:\\s*(\\d+)`, "mi"));
    if (m) assert.equal(md.records.find((r: Json) => r.label === label)?.value, Number(m[1]), label);
  }
});

test("the owner's VeraCrypt volume: tcrypt_header decrypts the header the way cryptsetup tcryptDump does", async (t) => {
  const path = owner(t, "DFIR_REAL_VERACRYPT");
  if (!path) return;
  const pwFile = owner(t, "DFIR_REAL_VERACRYPT_PASSWORD_FILE");
  if (!pwFile) return;
  const where = need(t, "cryptsetup");
  if (!where) return;
  assert.equal(statSync(pwFile).mode & 0o077, 0, "the password file is mode 0600 (no access for group or other)");
  const password = (await readFile(pwFile, "utf8")).replace(/\n$/, "");
  const scratch = await scratchDir();
  const script = ["set -e", "mkdir -p ref", TOOL_FN, "set +e",
    "tool tcrypt_header tc \"$(printf '{\"source\":\"%s\",\"password_file\":\"%s\"}' \"$VOL\" \"$PW\")\"",
    "cryptsetup tcryptDump \"$VOL\" < \"$PW\" > ref/reader.txt 2>/dev/null", "true"].join("\n");
  const r = inside(where, scratch, script, { VOL: path, PW: pwFile });
  assert.equal(r.status, 0, r.stderr);
  const a = await answer(scratch, "tc");
  const ref = await readFile(join(scratch, "ref", "reader.txt"), "utf8");
  assert.equal(a.status, "complete", a.status_basis);
  assert.equal(a.decrypted, true, "a header that decrypts with the owner's password");
  for (const [key, label] of [["cipher_chain", "Cipher chain"], ["cipher_mode", "Cipher mode"], ["pbkdf", "PBKDF"], ["key_size_bits", "MK bits"]] as const) {
    assert.equal(a.fields[key], field(ref, label), key);
  }
  const everything = JSON.stringify(a) + (await readFile(join(scratch, "ans", "tc.err"), "utf8"));
  assert.ok(!everything.includes(password), "the password reached the answer or stderr");
});
