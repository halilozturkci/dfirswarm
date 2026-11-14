/**
 * ransomware-response: the ciphers the decryption tools carry (stream_kpa_check, family_decrypt), against the published vectors and against
 * an implementation that shares no code with them (node:crypto, which is OpenSSL):
 *
 *   - ChaCha20: RFC 8439 section 2.3.2 (the block function's keystream at counter 1), and node:crypto's chacha20 over several blocks;
 *   - Salsa20/20: the ECRYPT stream cipher project's verified vectors, set 1 vector 0, for a 256-bit and a 128-bit key;
 *   - AES: FIPS-197 appendix C.1, C.2 and C.3 (one block under a 128, 192 and 256-bit key), the last round key of appendix A.1, and
 *     node:crypto's aes-*-ctr over several blocks, with a counter that carries;
 *   - RC4: RFC 6229, key 0x0102030405, the keystream at offsets 0 and 240;
 *   - the many-blocks-at-once forms equal the one-block form, across the 32-bit carry of the original ChaCha layout and across a piece
 *     boundary of the Keystream class.
 *
 * And the copies: the cipher block and the family block are the same text in both tools (they are not marked as shared blocks of the
 * census, so this file is what holds them equal), and the four rules are the same text in the three tools.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createCipheriv, getCiphers, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { LOAD, PACK } from "./ransomware-pack-harness.ts";

const KPA = join(PACK, "stream_kpa_check", "run.py");
const DECRYPT = join(PACK, "family_decrypt", "run.py");
const SCAN = join(PACK, "cipher_state_scan", "run.py");

/** Run Python with a tool loaded as `m`; the snippet prints one JSON value. */
function py<T>(script: string, snippet: string, input: unknown = null): T {
  const out = spawnSync(PYTHON3, ["-c", `${LOAD}m = load(sys.argv[1])\nARG = json.loads(sys.argv[2])\n${snippet}`, script, JSON.stringify(input)], { encoding: "utf8", maxBuffer: 1 << 26 });
  assert.equal(out.status, 0, out.stderr);
  return JSON.parse(out.stdout) as T;
}

function between(text: string, name: string): string {
  const begin = `# ${name}: begin`;
  const end = `# ${name}: end`;
  const a = text.indexOf(begin);
  const b = text.indexOf(end);
  assert.ok(a >= 0 && b > a, `${name} block`);
  return text.slice(a, b + end.length);
}

for (const [name, script] of [["stream_kpa_check", KPA], ["family_decrypt", DECRYPT]] as const) {
  test(`${name}: ChaCha20 gives the RFC 8439 keystream block, and node:crypto's stream over several blocks`, () => {
    const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
    const block = py<string>(script, "print(json.dumps(m.chacha20_blocks(bytes(range(32)), bytes.fromhex('000000090000004a00000000'), 1, 1).hex()))");
    assert.equal(block, "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    // OpenSSL's chacha20 takes a 16-byte IV: the 32-bit counter, little-endian, then the 12-byte nonce.
    const nonce = randomBytes(12);
    for (const counter of [0, 1, 7]) {
      const iv = Buffer.concat([Buffer.from([counter, 0, 0, 0]), nonce]);
      const want = createCipheriv("chacha20", key, iv).update(Buffer.alloc(1000)).toString("hex");
      const got = py<string>(script, "print(json.dumps(m.Keystream('chacha20-ietf', bytes(range(32)), bytes.fromhex(ARG[0]), ARG[1]).take(1000).hex()))", [nonce.toString("hex"), counter]);
      assert.equal(got, want, `counter ${counter}`);
    }
  });

  test(`${name}: the original ChaCha layout is the IETF one with the counter's high word in the nonce, and carries past 2^32`, () => {
    const same = py<boolean[]>(script, [
      "k = bytes(range(32))",
      "a = m.chacha20_blocks(k, bytes.fromhex('01000000') + bytes(8), 5, 1, 'ietf') == m.chacha20_blocks(k, bytes(8), (1 << 32) + 5, 1, 'original')",
      "whole = m.chacha20_blocks(k, bytes(8), (1 << 32) - 2, 4, 'original')",
      "b = whole == b''.join(m.chacha20_blocks(k, bytes(8), (1 << 32) - 2 + i, 1, 'original') for i in range(4))",
      "c = whole[128:192] == m.chacha20_blocks(k, bytes.fromhex('01000000') + bytes(8), 0, 1, 'ietf')",
      "print(json.dumps([a, b, c]))",
    ].join("\n"));
    assert.deepEqual(same, [true, true, true]);
    const refused = py<string>(script, "try:\n    m.chacha20_blocks(bytes(32), bytes(12), (1 << 32) - 1, 2, 'ietf'); print(json.dumps('ran'))\nexcept ValueError as e:\n    print(json.dumps('refused'))");
    assert.equal(refused, "refused", "a 32-bit counter that would wrap is refused, not wrapped into the nonce");
  });

  test(`${name}: Salsa20/20 gives the ECRYPT vectors for a 256-bit and a 128-bit key`, () => {
    const got = py<string[]>(script, "print(json.dumps([m.salsa20_blocks(bytes.fromhex('80' + '00' * 31), bytes(8), 0, 1).hex(), m.salsa20_blocks(bytes.fromhex('80' + '00' * 15), bytes(8), 0, 1).hex(), m.salsa20_blocks(bytes.fromhex('80' + '00' * 31), bytes(8), 0, 3)[:64].hex()]))");
    const k256 = "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844b22c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117";
    assert.equal(got[0], k256);
    assert.equal(got[1], "4dfa5e481da23ea09a31022050859936da52fcee218005164f267cb65f5cfd7f2b4f97e0ff16924a52df269515110a07f9e460bc65ef95da58f740b7d1dbb0aa");
    assert.equal(got[2], k256, "three blocks at once start with the same first block");
  });

  test(`${name}: AES gives the FIPS-197 appendix C blocks and the appendix A.1 schedule, and node:crypto's CTR streams`, () => {
    const got = py<string[]>(script, [
      "pt = bytes.fromhex('00112233445566778899aabbccddeeff')",
      "out = [m.aes_encrypt_blocks(m.aes_expand_key(bytes(range(n))), pt * 3).hex() for n in (16, 24, 32)]",
      "out.append(m.aes_expand_key(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'))[-16:].hex())",
      "print(json.dumps(out))",
    ].join("\n"));
    assert.equal(got[0], "69c4e0d86a7b0430d8cdb78070b4c55a".repeat(3));
    assert.equal(got[1], "dda97ca4864cdfe06eaf70a0ec0d7191".repeat(3));
    assert.equal(got[2], "8ea2b7ca516745bfeafc49904b496089".repeat(3));
    assert.equal(got[3], "d014f9a8c9ee2589e13f0cc8b6630ca6");
    for (const bits of [128, 192, 256]) {
      const key = randomBytes(bits / 8);
      // A 12-byte nonce and a 32-bit big-endian counter that starts just below a carry into its second byte.
      const nonce = randomBytes(12);
      const want = createCipheriv(`aes-${bits}-ctr`, key, Buffer.concat([nonce, Buffer.from([0, 0, 0, 0xfe])])).update(Buffer.alloc(700)).toString("hex");
      const got12 = py<string>(script, "print(json.dumps(m.Keystream('aes-ctr', bytes.fromhex(ARG[0]), bytes.fromhex(ARG[1]), 254).take(700).hex()))", [key.toString("hex"), nonce.toString("hex")]);
      assert.equal(got12, want, `aes-${bits}-ctr, 12-byte nonce`);
      const iv = Buffer.concat([randomBytes(12), Buffer.from([0xff, 0xff, 0xff, 0xfd])]);
      const want16 = createCipheriv(`aes-${bits}-ctr`, key, iv).update(Buffer.alloc(700)).toString("hex");
      const got16 = py<string>(script, "print(json.dumps(m.Keystream('aes-ctr', bytes.fromhex(ARG[0]), bytes.fromhex(ARG[1]), 0).take(700).hex()))", [key.toString("hex"), iv.toString("hex")]);
      assert.equal(got16, want16, `aes-${bits}-ctr, a whole counter block that carries out of its low 32 bits`);
    }
  });

  test(`${name}: RC4 gives the RFC 6229 keystream at offsets 0 and 240`, () => {
    const got = py<string[]>(script, "s = m.rc4_schedule(bytes.fromhex('0102030405')); a = m.rc4_stream(s, 16); m.rc4_stream(s, 224); print(json.dumps([a.hex(), m.rc4_stream(s, 16).hex()]))");
    assert.deepEqual(got, ["b2396305f03dc027ccc3524a0a1118a8", "28cb1132c96ce286421dcaadb8b69eae"]);
    if (getCiphers().includes("rc4")) {
      let want: string | null = null;
      try {
        want = createCipheriv("rc4", Buffer.from("a key of some length"), null).update(Buffer.alloc(300)).toString("hex");
      } catch {
        want = null;                 // OpenSSL 3 without its legacy provider lists rc4 and refuses it
      }
      if (want !== null) assert.equal(py<string>(script, "print(json.dumps(m.Keystream('rc4', b'a key of some length').take(300).hex()))"), want);
    }
  });

  test(`${name}: a keystream taken in pieces is the keystream taken whole, for every cipher`, () => {
    const same = py<Record<string, boolean>>(script, [
      "out = {}",
      "for c, k, n in (('chacha20-ietf', 32, 12), ('chacha20-original', 32, 8), ('chacha20-ietf', 16, 12), ('salsa20', 32, 8), ('salsa20', 16, 8), ('aes-ctr', 32, 12), ('aes-ctr', 16, 16), ('aes-ctr', 24, 8), ('rc4', 7, 0), ('xor', 5, 0)):",
      "    key, nonce = os.urandom(k), os.urandom(n)",
      "    whole = m.Keystream(c, key, nonce, 1).take(70000)",
      "    s = m.Keystream(c, key, nonce, 1)",
      "    out['%s/%d' % (c, k)] = whole == b''.join(s.take(x) for x in (1, 63, 64, 65, 300, 507, 69000 - 1000, 1000))",
      "print(json.dumps(out))",
    ].join("\n"));
    for (const [what, ok] of Object.entries(same)) assert.ok(ok, what);
    assert.equal(Object.keys(same).length, 10);
  });
}

test("the cipher block and the family block are one text in stream_kpa_check and family_decrypt, and the rules are one text in the three tools", () => {
  const kpa = readFileSync(KPA, "utf8");
  const dec = readFileSync(DECRYPT, "utf8");
  const scan = readFileSync(SCAN, "utf8");
  assert.equal(between(kpa, "CIPHERS"), between(dec, "CIPHERS"));
  assert.equal(between(kpa, "FAMILY"), between(dec, "FAMILY"));
  const rules = (text: string): string => {
    const a = text.indexOf("RULES = [");
    const b = text.indexOf("]\n", a);
    assert.ok(a >= 0 && b > a);
    return text.slice(a, b);
  };
  assert.equal(rules(kpa), rules(scan));
  assert.equal(rules(kpa), rules(dec));
  for (const text of [kpa, dec, scan]) {
    assert.match(rules(text), /Measure what the encryptor added/);
    assert.match(rules(text), /LAST use/);
    assert.match(rules(text), /One known \(file, key\) pair verifies any footer hypothesis/);
    assert.match(rules(text), /negative only after its planted control passed/);
  }
  // The manifests carry the rules too: a seat that reads only a manifest has them.
  for (const tool of ["cipher_state_scan", "stream_kpa_check", "family_decrypt", "encrypted_survey"]) {
    const description = JSON.parse(readFileSync(join(PACK, tool, "manifest.json"), "utf8")).description as string;
    assert.match(description, /measure what the encryptor added/i, tool);
    assert.match(description, /key's last use/i, tool);
    assert.match(description, /one known \(file, key\) pair verifies any footer hypothesis/i, tool);
    assert.match(description, /negative only after its planted control passed/, tool);
  }
});

test("the scanner's tables are the published constants: computed ones checked against values of the standards", () => {
  const got = py<Record<string, string>>(SCAN, "print(json.dumps({name: table.hex() for name, table in m.TABLES}))");
  const first = (name: string, n: number): string => got[name]!.slice(0, 2 * n);
  assert.equal(first("AES S-box", 16), "637c777bf26b6fc53001672bfed7ab76");
  assert.equal(got["AES S-box"]!.slice(-8), "b054bb16");
  assert.equal(first("AES inverse S-box", 8), "52096ad53036a538");
  assert.equal(first("AES Te0 table, big-endian words", 8), "c66363a5f87c7c84");
  assert.equal(first("SHA-256 round constants, big-endian words", 16), "428a2f9871374491b5c0fbcfe9b5dba5");
  assert.equal(got["SHA-256 round constants, big-endian words"]!.slice(-8), "c67178f2");
  assert.equal(first("SHA-256 initial hash values, big-endian words", 8), "6a09e667bb67ae85");
  assert.equal(first("SHA-512 round constants, big-endian words", 16), "428a2f98d728ae227137449123ef65cd");
  assert.equal(got["SHA-512 round constants, big-endian words"]!.slice(-16), "6c44198c4a475817");
  assert.equal(first("MD5 sine table, little-endian words", 8), "78a46ad756b7c7e8");
  assert.equal(got["MD5 sine table, little-endian words"]!.slice(-8), "91d386eb");
  assert.equal(first("CRC-32 table, little-endian words", 12), "00000000963007772c610eee");
  assert.equal(got["CRC-32 table, little-endian words"]!.slice(-8), "8def022d", "the last entry is 0x2d02ef8d");
});
