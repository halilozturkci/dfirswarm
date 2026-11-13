/**
 * computer-forensics-base: cache_body, the reader of one browser HTTP cache entry's body.
 *
 * The fixtures are written here from the two Chromium layouts as their source headers give them (net/disk_cache/simple/
 * simple_entry_format.h: a 24-byte header, the key, stream 1, a 24-byte end record, stream 0, the key's SHA-256, stream 0's end record;
 * net/disk_cache/blockfile/disk_format.h and disk_format_base.h: a 368-byte index header and a hash table of addresses, 8192-byte block
 * file headers, 256-byte entry records), not from the tool's reading of them. They are not caches a browser wrote: that limit is the
 * manifest's own word. Held here: gzip, deflate (wrapped and raw) and a plain file are decoded; brotli is decoded where a module imports
 * and, where none does, the stored bytes are written and the answer is partial and says "brotli: not decodable here"; the body lands
 * under $OUT with its detected type; the key and the header values are in files and never in the answer; a structure that is not the
 * format's is a failed answer that names it, never an empty body.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { call, CFB, filesBelow, py, withRun, type Doc } from "./pack-base-media-fixture.ts";

const KEY = "1/0/https://shop.example.test/a page?session=TOKEN-9f3c";
const COOKIE = "sid=COOKIE-77aa";

/** Writes the fixtures; argv: the output directory. */
const BUILD = String.raw`
import gzip, hashlib, os, struct, sys, zlib
out = sys.argv[1]
INITIAL, FINAL = 0xFCFB6D1BA7725C30, 0xF4FA6F45970D41D8
def headers(coding, media):
    return b"HTTP/1.1 200 OK\x00" + (b"Content-Encoding: " + coding + b"\x00" if coding else b"") + b"Content-Type: " + media + b"; charset=utf-8\x00Set-Cookie: sid=COOKIE-77aa\x00\x00"
def simple(key, stored, head, version=5, sha=True, crc=True):
    stream0 = struct.pack("<II", len(head) + 4, 0x10003) + head
    return (struct.pack("<QIII", INITIAL, version, len(key), 0x5EED) + b"\x00" * 4 + key + stored
            + struct.pack("<QIII", FINAL, 1 if crc else 0, zlib.crc32(stored) & 0xFFFFFFFF if crc else 0, 0) + b"\x00" * 4 + stream0
            + (hashlib.sha256(key).digest() if sha else b"")
            + struct.pack("<QIII", FINAL, 1 | (2 if sha else 0), zlib.crc32(stream0) & 0xFFFFFFFF, len(stream0)) + b"\x00" * 4)
page = b"<!doctype html><html><body>" + b"A line of the cached page. " * 300 + b"</body></html>"
key = sys.argv[2].encode()
w = lambda name, data: open(os.path.join(out, name), "wb").write(data)
w("0123456789abcdef_0", simple(key, gzip.compress(page), headers(b"gzip", b"text/html")))
w("1123456789abcdef_0", simple(key, zlib.compress(page), headers(b"deflate", b"text/html"), sha=False))
raw = zlib.compressobj(9, zlib.DEFLATED, -15)
w("2123456789abcdef_0", simple(key, raw.compress(page) + raw.flush(), headers(b"deflate", b"text/html")))
w("3123456789abcdef_0", simple(key, b"\x1b\x00\x00stored bytes a brotli decoder would read" * 3, headers(b"br", b"text/css")))
noisy = page + b"".join(hashlib.sha256(b"%d" % i).digest() for i in range(600))      # bytes deflate cannot shrink: a cut leaves a decodable part
w("4123456789abcdef_0", simple(key, gzip.compress(noisy)[:-3000], headers(b"gzip", b"text/html")))
w("5123456789abcdef_0", simple(key, b"\x89PNG\r\n\x1a\n" + bytes(300), headers(b"", b"image/png")))
w("6123456789abcdef_0", simple(key, gzip.compress(page), headers(b"gzip", b"text/html"))[:-30])
stored = gzip.compress(noisy)
bad = bytearray(simple(key, stored, headers(b"gzip", b"text/html")))
bad[24 + len(key) + len(stored) - 2] ^= 0xFF          # a byte of the gzip trailer, changed after the entry's CRC-32 was taken
w("7123456789abcdef_0", bytes(bad))
w("plain page.gz", gzip.compress(b'{"answer": 42}'))
w("plain.bin", b"plain text with no coding\n")
# A gzip member that ends exactly at 1 MiB, written from RFC 1952 and RFC 1951 (stored blocks), with 38,000 bytes after it.
import random
rnd = random.Random(7)
data = rnd.randbytes(1048478)
blocks = []
for i in range(0, len(data), 65535):
    part = data[i:i + 65535]
    blocks.append(bytes([1 if i + 65535 >= len(data) else 0]) + struct.pack("<HH", len(part), len(part) ^ 0xFFFF) + part)
member = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff" + b"".join(blocks) + struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data))
assert len(member) == 1 << 20
w("aligned.gz", member + rnd.randbytes(38000))
w("9123456789abcdef_0", simple(key, member + rnd.randbytes(38000), headers(b"gzip", b"application/octet-stream")))
bad = bytearray(simple(key, member + rnd.randbytes(38000), headers(b"gzip", b"application/octet-stream")))
bad[24 + len(key) + (1 << 20) + 5] ^= 0xFF               # a stored byte after the stream's end, changed after the entry's CRC-32 was taken
w("a123456789abcdef_0", bytes(bad))
# An entry with no body CRC whose header says a key 10 bytes longer than the key: the key's SHA-256 does not hold.
lying = bytearray(simple(key, b"plain body bytes. " * 30, headers(b"", b"text/plain"), crc=False))
struct.pack_into("<I", lying, 12, len(key) + 10)
w("b123456789abcdef_0", bytes(lying))
w("plain 5000.bin", (b"0123456789" * 500))
w("plain 3m.bin", b"<html>" + bytes(rnd.randbytes(3 << 20)))
try:
    import brotli
    w("8123456789abcdef_0", simple(key, brotli.compress(page), headers(b"br", b"text/html")))
    print("brotli")
except Exception:
    print("no brotli")

# A block-file cache: three entries reached from the index table, the second chained from the first.
cache = os.path.join(out, "Block Cache")
os.makedirs(cache)
def block_header(number, size):
    return struct.pack("<IIhhiii", 0xC104CAC3, 0x20000, number, 0, size, 0, 0).ljust(8192, b"\x00")
entries = [(b"https://one.example.test/api", headers(b"gzip", b"application/json"), gzip.compress(b'{"k": "v"}' * 100), False),
           (b"https://two.example.test/" + b"long-" * 60, headers(b"", b"image/png"), b"\x89PNG\r\n\x1a\n" + bytes(20000), True),
           (b"https://three.example.test/empty", headers(b"", b"text/plain"), b"", False)]
d1, d2, d3 = bytearray(block_header(1, 256)), bytearray(block_header(2, 1024)), bytearray(block_header(3, 4096))
b1 = b2 = b3 = 0
addresses = []
for i, (k, head, body, external) in enumerate(entries):
    stream0 = struct.pack("<II", len(head) + 4, 0x10003) + head
    n2 = (len(stream0) + 1023) // 1024
    a0 = 0x80000000 | (3 << 28) | ((n2 - 1) << 24) | (2 << 16) | b2
    d2 += stream0.ljust(n2 * 1024, b"\x00")
    b2 += n2
    if external:
        a1 = 0x80000000 | (i + 1)
        open(os.path.join(cache, "f_%06x" % (i + 1)), "wb").write(body)
    elif body:
        n3 = (len(body) + 4095) // 4096
        a1 = 0x80000000 | (4 << 28) | ((n3 - 1) << 24) | (3 << 16) | b3
        d3 += body.ljust(n3 * 4096, b"\x00")
        b3 += n3
    else:
        a1 = 0
    long_key = 0
    stored_key = k
    blocks = min(4, (96 + len(k) + 1 + 255) // 256)
    addresses.append((0x80000000 | (2 << 28) | ((blocks - 1) << 24) | (1 << 16) | b1, blocks, k, len(stream0), len(body), a0, a1, i))
    b1 += blocks
for index, (address, blocks, k, n0, n1, a0, a1, i) in enumerate(addresses):
    nxt = addresses[1][0] if index == 0 else 0            # entry 2 hangs off entry 1's chain
    record = (struct.pack("<IIIiiiQiI", 0xABCD0000 + i, nxt, 0, 0, 0, 0, 13350000000000000 + i * 1000000, len(k), 0)
              + struct.pack("<4i", n0, n1, 0, 0) + struct.pack("<4I", a0, a1, 0, 0) + struct.pack("<I", 0) + b"\x00" * 16 + struct.pack("<I", 0))
    assert len(record) == 96
    d1 += (record + k + b"\x00").ljust(blocks * 256, b"\x00")
table = [0] * 0x10000
table[17] = addresses[0][0]
table[40000] = addresses[2][0]
index = struct.pack("<IIiiIiIi", 0xC103CAC3, 0x20000, 3, 0, 0, 1, 0, 0x10000).ljust(368, b"\x00") + struct.pack("<%dI" % 0x10000, *table)
for name, data in (("index", index), ("data_0", block_header(0, 36)), ("data_1", d1), ("data_2", d2), ("data_3", d3)):
    open(os.path.join(cache, name), "wb").write(bytes(data))
looped = os.path.join(out, "Looped Cache")
os.makedirs(looped)
d1b = bytearray(d1)
struct.pack_into("<I", d1b, 8192 + (addresses[1][0] & 0xFFFF) * 256 + 4, addresses[0][0])     # entry 2's next points back at entry 1
for name, data in (("index", index), ("data_0", block_header(0, 36)), ("data_1", d1b), ("data_2", d2), ("data_3", d3)):
    open(os.path.join(looped, name), "wb").write(bytes(data))
open(os.path.join(looped, "f_000002"), "wb").write(entries[1][2])
linked = os.path.join(out, "Linked Cache")
os.makedirs(linked)
for name, data in (("index", index), ("data_0", block_header(0, 36)), ("data_1", d1), ("data_2", d2), ("data_3", d3)):
    open(os.path.join(linked, name), "wb").write(bytes(data))
open(os.path.join(out, "outside body.bin"), "wb").write(b"a file outside the cache directory\n")
os.symlink(os.path.join("..", "outside body.bin"), os.path.join(linked, "f_000002"))
holed = os.path.join(out, "Holed Cache")
os.makedirs(holed)
table2 = list(table)
table2[50000] = 0x80000000 | (2 << 28) | (4 << 16)        # an entry address in data_4, a file the cache does not have
index2 = struct.pack("<IIiiIiIi", 0xC103CAC3, 0x20000, 4, 0, 0, 1, 0, 0x10000).ljust(368, b"\x00") + struct.pack("<%dI" % 0x10000, *table2)
for name, data in (("index", index2), ("data_0", block_header(0, 36)), ("data_1", d1), ("data_2", d2), ("data_3", d3)):
    open(os.path.join(holed, name), "wb").write(bytes(data))
open(os.path.join(holed, "f_000002"), "wb").write(entries[1][2])
old = os.path.join(out, "Old Cache")
os.makedirs(old)
open(os.path.join(old, "index"), "wb").write(struct.pack("<II", 0xC103CAC3, 0x30000).ljust(368 + 4 * 0x10000, b"\x00"))
`;

const PAGE = Buffer.from("<!doctype html><html><body>" + "A line of the cached page. ".repeat(300) + "</body></html>");
const sha = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

test("a simple-cache entry: gzip and deflate bodies are decoded and written under $OUT with their type; the key and the headers stay in files", async () => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    py(BUILD, [join(run, dir), KEY], run);
    const r = await call("cache_body", run, { path: `${dir}/0123456789abcdef_0` }, { out });
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.stderr, "");
    const a = r.doc;
    assert.equal(a.status, "complete", a.status_basis);
    assert.deepEqual([a.kind, a.format_version, a.body_offset, a.key_bytes, a.key_sha256_matches], ["Chromium simple cache entry", 5, 24 + KEY.length, KEY.length, true]);
    assert.deepEqual(a.response, { status_code: 200, content_type: "text/html", content_encoding: ["gzip"], header_lines: 4 });
    assert.deepEqual(a.encoding, { coding: "gzip", said_by: "the stored response's Content-Encoding header" });
    assert.deepEqual([a.body.decoded_bytes, a.body.sha256, a.body.detected_type, a.body.stored_crc32_matches], [PAGE.length, sha(PAGE), "HTML text", true]);
    assert.deepEqual(a.files, { key: "store/jobs/j000001/out/cache_body/key.txt", headers: "store/jobs/j000001/out/cache_body/headers.txt", body: "store/jobs/j000001/out/cache_body/body.html" });
    assert.deepEqual(filesBelow(out), ["cache_body/body.html", "cache_body/headers.txt", "cache_body/key.txt"]);
    assert.ok((await readFile(join(out, "cache_body", "body.html"))).equals(PAGE));
    assert.equal((await readFile(join(out, "cache_body", "key.txt"), "utf8")).trim(), KEY);
    assert.match(await readFile(join(out, "cache_body", "headers.txt"), "utf8"), /Set-Cookie: sid=COOKIE-77aa/);
    assert.equal((await lstat(join(out, "cache_body", "body.html"))).mode & 0o777, 0o600);
    // Neither the key nor a header value past the two tokens is in the answer.
    for (const secret of [KEY, "TOKEN-9f3c", "shop.example.test", COOKIE, "COOKIE-77aa", "charset"]) assert.ok(!r.stdout.includes(secret), `${secret} is not printed`);
    assert.equal(a.key_in_answer, false);

    const wrapped = await call("cache_body", run, { path: `${dir}/1123456789abcdef_0` }, { out });
    assert.deepEqual([wrapped.doc.status, wrapped.doc.encoding.coding, wrapped.doc.body.sha256, wrapped.doc.key_sha256_matches], ["complete", "deflate", sha(PAGE), undefined]);
    const raw = await call("cache_body", run, { path: `${dir}/2123456789abcdef_0` }, { out });
    assert.deepEqual([raw.doc.status, raw.doc.body.sha256, raw.doc.body.deflate_form], ["complete", sha(PAGE), "raw (no zlib header)"]);
    const png = await call("cache_body", run, { path: `${dir}/5123456789abcdef_0` }, { out });
    assert.deepEqual([png.doc.status, png.doc.encoding.coding, png.doc.body.detected_type, png.doc.files.body.split("/").pop()], ["complete", "identity", "PNG image", "body.png"]);
    assert.match(png.doc.encoding.said_by, /^nothing: no header named a coding/);
  });
});

test("brotli: decoded where a module imports, and \"brotli: not decodable here\" with the stored bytes and a partial answer where none does", async (t) => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    const has = py(BUILD, [join(run, dir), KEY], run).trim() === "brotli";
    // No module: a directory on PYTHONPATH whose brotli, brotlicffi and zstandard refuse to import stands in for an image without them.
    const none = join(run, "work", "no modules");
    await mkdir(none, { recursive: true });
    for (const name of ["brotli", "brotlicffi", "zstandard"]) await writeFile(join(none, `${name}.py`), "raise ImportError('not in this image')\n");
    const r = await call("cache_body", run, { path: `${dir}/3123456789abcdef_0` }, { out, env: { PYTHONPATH: none } });
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.doc.status, "partial");
    assert.equal(r.doc.complete, false);
    assert.deepEqual(r.doc.partial_reasons, ["brotli: not decodable here"]);
    assert.equal(r.doc.encoding.decoded, false);
    assert.match(r.doc.encoding.said, /^brotli: not decodable here .*still compressed$/);
    assert.match(r.doc.body.detected_type, /brotli-compressed bytes, not decoded/);
    assert.equal(r.doc.files.body, "store/jobs/j000001/out/cache_body/body.br");
    assert.equal(r.doc.body.decoded_bytes, r.doc.body.stored_bytes, "the stored bytes were written as they are");
    assert.match(r.doc.status_basis, /brotli: not decodable here/);
    // A plain file named as brotli, in the same image: the same word.
    const plain = await call("cache_body", run, { path: `${dir}/plain.bin`, encoding: "br" }, { out, env: { PYTHONPATH: none } });
    assert.deepEqual([plain.doc.status, plain.doc.partial_reasons], ["partial", ["brotli: not decodable here"]]);
    if (!has) {
      t.diagnostic("the decoded branch was not run: this host's python3 has no brotli module to build the fixture with");
      return;
    }
    const decoded = await call("cache_body", run, { path: `${dir}/8123456789abcdef_0` }, { out });
    assert.deepEqual([decoded.doc.status, decoded.doc.encoding.coding, decoded.doc.body.sha256, decoded.doc.body.detected_type], ["complete", "br", sha(PAGE), "HTML text"]);
    assert.match(decoded.doc.encoding.decoder, /^brotli/);
  });
});

test("a cut stream, a body that fails its CRC, a cut entry and a plain file: each says what it is", async () => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    py(BUILD, [join(run, dir), KEY], run);
    const cutStream = await call("cache_body", run, { path: `${dir}/4123456789abcdef_0` }, { out });
    assert.equal(cutStream.doc.status, "partial");
    assert.match(cutStream.doc.body.decode_error, /the gzip stream (has no end marker|is damaged)/);
    assert.ok(cutStream.doc.body.decoded_bytes > PAGE.length && cutStream.doc.body.decoded_bytes < PAGE.length + 600 * 32, "what decoded before the cut was written");
    const crc = await call("cache_body", run, { path: `${dir}/7123456789abcdef_0` }, { out });
    assert.equal(crc.doc.status, "partial");
    assert.equal(crc.doc.body.stored_crc32_matches, false, "a stored byte changed after the entry's CRC-32 was taken");
    assert.match(crc.doc.body.decode_error, /the gzip stream is damaged/);
    const cutEntry = await call("cache_body", run, { path: `${dir}/6123456789abcdef_0` }, { out });
    assert.equal(cutEntry.code, 1);
    assert.equal(cutEntry.doc.status, "failed");
    assert.match(cutEntry.doc.error, /does not end with a simple-cache end record/);
    assert.match(cutEntry.doc.status_basis, /no body was written, and that is not an empty entry/);
    const plain = await call("cache_body", run, { path: `${dir}/plain page.gz` }, { out });
    assert.deepEqual([plain.doc.status, plain.doc.kind, plain.doc.encoding.coding, plain.doc.body.decoded_bytes, plain.doc.body.detected_type], ["complete", "plain file", "gzip", 14, "text that begins like JSON"]);
    assert.match(plain.doc.encoding.said_by, /own signature/);
    const wrong = await call("cache_body", run, { path: `${dir}/plain.bin`, encoding: "gzip" }, { out });
    assert.equal(wrong.doc.status, "failed", "a file that is no gzip stream decodes to nothing: failed, with the reason");
    assert.match(JSON.stringify(wrong.doc.partial_reasons), /the gzip stream is damaged after 0 decoded bytes/);
    assert.equal(wrong.doc.files.body, undefined, "no empty file stands in for a body");
    const capped = await call("cache_body", run, { path: `${dir}/0123456789abcdef_0`, max_bytes: 1000 }, { out });
    assert.equal(capped.doc.status, "partial");
    assert.match(capped.doc.body.decode_error, /reached max_bytes \(1000\): it was cut there, after 1000 bytes/);
    assert.equal(capped.doc.body.decoded_bytes, 1000);
  });
});

test("a stream that ends on a 1 MiB boundary with bytes after it is partial and says where; the entry's CRC-32 is still checked", async () => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    py(BUILD, [join(run, dir), KEY], run);
    const plain = await call("cache_body", run, { path: `${dir}/aligned.gz` }, { out });
    assert.equal(plain.code, 0, plain.stdout + plain.stderr);
    assert.deepEqual([plain.doc.status, plain.doc.complete, plain.doc.body.decoded_bytes, plain.doc.body.stream_ends_at, plain.doc.body.bytes_after_the_stream_end],
      ["partial", false, 1048478, 1 << 20, 38000]);
    assert.deepEqual(plain.doc.partial_reasons, ["the gzip stream ends at stored byte 1048576 and 38000 stored byte(s) follow it, not decoded"]);
    const entry = await call("cache_body", run, { path: `${dir}/9123456789abcdef_0` }, { out });
    assert.deepEqual([entry.doc.status, entry.doc.body.stream_ends_at, entry.doc.body.bytes_after_the_stream_end, entry.doc.body.stored_crc32_matches], ["partial", 1 << 20, 38000, true]);
    const changed = await call("cache_body", run, { path: `${dir}/a123456789abcdef_0` }, { out });
    assert.equal(changed.doc.body.stored_crc32_matches, false, "a stored byte after the stream's end is covered by the entry's CRC-32");
    assert.ok(changed.doc.partial_reasons.includes("the stored body does not match the CRC-32 its entry records"));
  });
});

test("an entry whose key fails its own SHA-256 is partial and says so; a gzip whose own CRC fails keeps every byte it decoded", async () => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    py(BUILD, [join(run, dir), KEY], run);
    const lying = await call("cache_body", run, { path: `${dir}/b123456789abcdef_0` }, { out });
    assert.equal(lying.code, 0, lying.stdout + lying.stderr);
    assert.deepEqual([lying.doc.status, lying.doc.complete, lying.doc.key_sha256_matches], ["partial", false, false]);
    assert.match(lying.doc.partial_reasons[0], /^the entry's key does not match the SHA-256 the entry records: .*where the body begins is not certain/);
    assert.match(lying.doc.status_basis, /^not everything asked for was done: the entry's key does not match/);
    const crc = await call("cache_body", run, { path: `${dir}/7123456789abcdef_0` }, { out });
    assert.equal(crc.doc.body.decoded_bytes, PAGE.length + 600 * 32, "the output before the failed trailer check is written whole");
    assert.match(crc.doc.body.decode_error, /^the gzip stream is damaged after \d+ decoded bytes \(at stored byte \d+\)$/);
  });
});

test("max_bytes cuts the body file exactly there: the file, its sha256 and decoded_bytes agree, and the answer is partial with the cap", async () => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    py(BUILD, [join(run, dir), KEY], run);
    for (const [name, cap] of [["plain 5000.bin", 1000], ["plain 3m.bin", 2_500_000]] as const) {
      const whole = await readFile(join(run, dir, name));
      const r = await call("cache_body", run, { path: `${dir}/${name}`, max_bytes: cap }, { out });
      assert.equal(r.code, 0, r.stdout + r.stderr);
      const written = await readFile(join(run, r.doc.files.body.replace(/^store\/jobs\/j000001\/out/, out.slice(run.length + 1))));
      assert.equal(written.length, cap, name);
      assert.ok(written.equals(whole.subarray(0, cap)), name);
      assert.deepEqual([r.doc.status, r.doc.complete, r.doc.body.decoded_bytes, r.doc.body.sha256, r.doc.body.truncated, r.doc.body.cap], ["partial", false, cap, sha(written), true, `max_bytes (${cap})`], name);
      assert.match(r.doc.body.whole_kept_in, new RegExp(`^the stored entry itself: its ${whole.length} stored bytes from offset 0`), name);
      assert.deepEqual(r.doc.partial_reasons, [`the decoded body reached max_bytes (${cap}): it was cut there, after ${cap} bytes`], name);
    }
  });
});

/** Runs the tool once as a child and prints its answer and the child's peak resident memory in bytes; argv: tool, args JSON, OUT, PYTHONPATH. */
const PEAK = String.raw`
import json, os, resource, subprocess, sys
env = dict(os.environ, JOB_ID="j000001", OUT=sys.argv[3], AGENT_ID="t1")
if sys.argv[4]:
    env["PYTHONPATH"] = sys.argv[4]
r = subprocess.run([sys.executable, sys.argv[1]], input=sys.argv[2].encode(), capture_output=True, env=env, timeout=120)
peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
print(json.dumps({"peak": peak, "answer": json.loads(r.stdout)}))
`;

test("a brotli stream is expanded a bounded piece at a time: a 512 MiB bomb with max_bytes 1,000,000 stays small in memory, with and without output_buffer_limit", async (t) => {
  await withRun(async (run, out) => {
    const made = py(String.raw`
import os, sys
try:
    import brotli
except Exception:
    print("no brotli"); sys.exit(0)
c = brotli.Compressor(quality=5, lgwin=24)
open(sys.argv[1], "wb").write(b"".join([c.process(bytes(1 << 24)) for _ in range(32)] + [c.finish()]))
# An older module, without output_buffer_limit: brotli refuses to import and brotlicffi wraps the real one with process(data) alone.
older = sys.argv[2]
os.makedirs(older)
open(os.path.join(older, "brotli.py"), "w").write("raise ImportError('hidden')\n")
open(os.path.join(older, "brotlicffi.py"), "w").write(
    "import sys\nhere = sys.path.pop(sys.path.index(__file__.rsplit('/', 1)[0]))\nsys.modules.pop('brotli', None)\nimport brotli as real\n"
    "sys.modules.pop('brotli', None)\nsys.path.insert(0, here)\n"
    "class Decompressor:\n    def __init__(self):\n        self.d = real.Decompressor()\n    def process(self, data):\n        return self.d.process(data)\n"
    "    def is_finished(self):\n        return self.d.is_finished()\n")
print("made")
`, [join(run, "bomb.br"), join(run, "older")], run).trim();
    if (made !== "made") {
      t.diagnostic("not run: this host's python3 has no brotli module to build the fixture with");
      return;
    }
    for (const [older, decoder] of [["", /^brotli /], [join(run, "older"), /^brotlicffi /]] as const) {
      const r = JSON.parse(py(PEAK, [join(CFB, "tools", "cache_body", "run.py"), JSON.stringify({ path: "bomb.br", encoding: "br", max_bytes: 1_000_000 }), join(out, older ? "b" : "a"), older], run)) as Doc;
      assert.ok(r.peak < 200 * 1024 * 1024, `peak resident memory ${r.peak} bytes for 512 MiB of output`);
      assert.match(r.answer.encoding.decoder, decoder);
      assert.deepEqual([r.answer.status, r.answer.body.decoded_bytes, r.answer.body.cap], ["partial", 1_000_000, "max_bytes (1000000)"]);
    }
  });
});

test("a block-file cache is listed first, then one entry is taken by row or address; a chain that loops makes the list partial", async () => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    py(BUILD, [join(run, dir), KEY], run);
    const cache = `${dir}/Block Cache`;
    const list = await call("cache_body", run, { path: cache, list: true }, { out });
    assert.equal(list.code, 0, list.stdout + list.stderr);
    assert.deepEqual([list.doc.status, list.doc.kind, list.doc.format_version, list.doc.entries, list.doc.entries_the_index_says], ["complete", "Chromium block-file cache", "2.0", 3, 3]);
    const rows = (await readFile(join(out, "cache_body", "entries.tsv"), "utf8")).trim().split("\n").map((l) => l.split("\t"));
    assert.deepEqual(rows[0], list.doc.columns);
    // Table order, then chain order: entry 1 (slot 17), entry 2 on its chain, entry 3 (slot 40000).
    assert.deepEqual(rows.slice(1).map((r) => [r[0], r[2], r[3], r[7], r[8], r[10]!.slice(0, 26)]), [
      ["1", "normal", "2024-01-17T21:20:00.000000Z", "39", "data_3", "https://one.example.test/a"],
      ["2", "normal", "2024-01-17T21:20:01.000000Z", "20008", "f_000002", "https://two.example.test/l"],
      ["3", "normal", "2024-01-17T21:20:02.000000Z", "0", "", "https://three.example.test"],
    ]);
    assert.ok(!list.stdout.includes("example.test"), "the keys are in the list file, not in the answer");

    const two = await call("cache_body", run, { path: cache, entry: 2 }, { out });
    assert.deepEqual([two.doc.status, two.doc.address, two.doc.body_in, two.doc.key_bytes, two.doc.body.decoded_bytes, two.doc.body.detected_type], ["complete", rows[2]![1], "f_000002", 325, 20008, "PNG image"]);
    assert.equal(two.doc.created_utc, "2024-01-17T21:20:01.000000Z");
    assert.match(two.doc.created_clock, /microseconds since 1601-01-01 UTC/);
    const one = await call("cache_body", run, { path: cache, address: rows[1]![1] }, { out });
    assert.deepEqual([one.doc.status, one.doc.encoding.coding, one.doc.body.decoded_bytes, one.doc.response.content_type], ["complete", "gzip", 1000, "application/json"]);
    const empty = await call("cache_body", run, { path: cache, entry: 3 }, { out });
    assert.equal(empty.doc.status, "complete");
    assert.match(empty.doc.body.said, /no body bytes/);
    assert.equal(empty.doc.files.body, undefined);

    // The forms the rule names, refused with the rule: no selector, a file of the cache, a row past the end.
    for (const args of [{ path: cache }, { path: `${cache}/index` }, { path: cache, entry: 9 }, { path: cache, list: true, entry: 1 }]) {
      const r = await call("cache_body", run, args, { out });
      assert.equal(r.code, 1, JSON.stringify(args));
      assert.equal(r.doc.status, "failed");
      assert.ok(r.doc.rules.length >= 3 && r.doc.rules.length <= 5);
      if (!("list" in args)) assert.match(r.doc.error, /listed first \(\{"path": "<cache directory>", "list": true\}/, JSON.stringify(args));
    }
    const looped = await call("cache_body", run, { path: `${dir}/Looped Cache`, list: true }, { out });
    assert.deepEqual([looped.doc.status, looped.doc.complete, looped.doc.problems.chains_cut], ["partial", false, 1]);
    // A link inside the cache is not followed; an address into a data file the cache does not have is counted, not fatal.
    const linked = await call("cache_body", run, { path: `${dir}/Linked Cache`, entry: 2 }, { out });
    assert.equal(linked.doc.status, "failed");
    assert.match(linked.doc.error, /the cache file f_000002 is a link, and a link inside the cache is not followed/);
    assert.equal(linked.doc.files, undefined);
    const holed = await call("cache_body", run, { path: `${dir}/Holed Cache`, list: true }, { out });
    assert.equal(holed.code, 0, holed.stdout + holed.stderr);
    assert.deepEqual([holed.doc.status, holed.doc.entries, holed.doc.problems.entries_unreadable], ["partial", 3, 1]);
    assert.match(holed.doc.problems.first_unreadable, /^an entry at address 0xa0040000: the cache file data_4 cannot be opened/);
    const old = await call("cache_body", run, { path: `${dir}/Old Cache`, list: true }, { out });
    assert.equal(old.doc.status, "failed");
    assert.match(old.doc.error, /block-file index version 0x30000: this tool reads 2\.0 and 2\.1/);
  });
});

test("the rules are in the manifest and on the note's card, and the manifest says what was and was not verified", async () => {
  const manifest = JSON.parse(await readFile(join(CFB, "tools", "cache_body", "manifest.json"), "utf8")) as Doc;
  await withRun(async (run, out) => {
    const r = await call("cache_body", run, {}, { out });
    for (const rule of r.doc.rules as string[]) assert.ok(manifest.description.includes(rule));
  });
  assert.match(manifest.description, /not against a cache a browser wrote on this host/);
  assert.match(manifest.description, /"brotli: not decodable here"/);
  const note = await readFile(join(CFB, "skills", "data", "http-cache.md"), "utf8");
  const card = /^card: (.+)$/m.exec(note)?.[1] ?? "";
  assert.ok(card.length > 100 && card.length <= 700);
  assert.match(card, /\{"path": "<dir>", "list": true\}/);
  assert.match(card, /"brotli: not decodable here" means the body file is STILL compressed/);
});
