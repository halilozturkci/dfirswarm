/** A seat's shell output is kept to a bound: its first and last half, with a line between that says so (protocol-core keepToolOutputFromFile). */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { keepToolOutputFromFile, shellKeepMaxBytes } from "../extensions/protocol-core.ts";

const dir = mkdtempSync(join(tmpdir(), "shell-keep-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

test("an output within the bound is kept whole, byte for byte", async () => {
  const body = Buffer.from("line\n".repeat(1000));
  writeFileSync(join(dir, "small"), body);
  for (const max of [body.length, body.length + 1, 1 << 20]) {
    const ref = await keepToolOutputFromFile(dir, "tool-output/a/small.out", join(dir, "small"), max);
    assert.deepEqual([ref.bytes, ref.lines, ref.sha256, ref.cut], [body.length, 1000, sha(body), undefined]);
    assert.ok(readFileSync(join(dir, ref.path)).equals(body));
  }
});

test("an output past the bound is its first and last half, says what is missing, and the reference describes the file that is kept", async () => {
  const body = Buffer.alloc(3_000_000);
  for (let i = 0; i < body.length; i += 1) body[i] = 33 + (i % 90);
  writeFileSync(join(dir, "big"), body);
  const max = 200_000;
  const ref = await keepToolOutputFromFile(dir, "tool-output/a/big.out", join(dir, "big"), max);
  const kept = readFileSync(join(dir, ref.path));
  assert.deepEqual(ref.cut, { whole_bytes: body.length, whole_sha256: sha(body), head_bytes: 100_000, tail_bytes: 100_000 });
  assert.equal(ref.bytes, kept.length);
  assert.equal(ref.sha256, sha(kept), "the reference's hash is the kept file's");
  assert.ok(kept.subarray(0, 100_000).equals(body.subarray(0, 100_000)));
  assert.ok(kept.subarray(kept.length - 100_000).equals(body.subarray(body.length - 100_000)));
  const middle = kept.subarray(100_000, kept.length - 100_000).toString("utf8");
  assert.match(middle, /^\n\[\.\.\. 2800000 bytes of this output are not kept: it was 3000000 bytes \(sha256 [0-9a-f]{64}\), more than the 200000 /);
  assert.ok(kept.length < max + 1000);
});

test("the bound is 64 MiB unless the environment says otherwise", () => {
  assert.equal(shellKeepMaxBytes({}), 64 * 1024 * 1024);
  assert.equal(shellKeepMaxBytes({ SWARM_SHELL_KEEP_MAX_BYTES: "1000000" }), 1_000_000);
  assert.equal(shellKeepMaxBytes({ SWARM_SHELL_KEEP_MAX_BYTES: "12" }), 64 * 1024 * 1024);
});
