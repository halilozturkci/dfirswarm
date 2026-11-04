/**
 * macos-forensics: mac_apt's venv is installed from a hash lock kept in the pack, not from the tag's requirements file,
 * and the text says only what was done: the lock was written from PyPI metadata and has not been installed. fsapfsinfo's
 * text names the image's apt snapshot date as its pin. The lock's form is the one images/install.py lock_problem accepts.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const REQ = join(ROOT, "packs", "macos-forensics", "requires");
const HASHES = /^\s+--hash=sha256:[0-9a-f]{64}( \\)?$/;

type Binary = { name: string; why: string; install: { source?: Record<string, unknown> } };
async function binary(name: string): Promise<Binary> {
  const host = JSON.parse(await readFile(join(REQ, "host.json"), "utf8")) as { binaries: Binary[] };
  const b = host.binaries.find((x) => x.name === name);
  assert.ok(b, `${name} is declared`);
  return b;
}

test("mac_apt installs from a hash lock of the pack, with no plain requirements file", async () => {
  const src = (await binary("mac_apt.py")).install.source!;
  assert.equal(src.pip_lock, "requires/locks/mac_apt.txt");
  assert.equal(src.pip, undefined, "no unhashed pip set remains");
  assert.deepEqual(src.pip_after, ["--no-deps", "./other_dependencies/pyaff4-0.31.2-yk-20251206.zip"]);
  assert.deepEqual(src.arches, ["amd64"]);
});

test("the lock is name==version lines with sha256 hashes and nothing else, and holds the tag's pins", async () => {
  const text = await readFile(join(REQ, "locks", "mac_apt.txt"), "utf8");
  const lines = text.split("\n").filter((l) => l.trim() && !l.startsWith("#"));
  const names = new Map<string, string>();
  let open = false;
  let hashes = 0;
  for (const l of lines) {
    if (/^[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9._+!]+ \\$/.test(l)) {
      assert.ok(!open || hashes > 0, `${l} follows a requirement with no hash`);
      const [n, v] = l.slice(0, -2).split("==");
      assert.ok(!names.has(n), `${n} appears once`);
      names.set(n, v);
      open = true;
      hashes = 0;
    } else {
      assert.match(l, HASHES, `not a requirement or a hash: ${l}`);
      hashes += 1;
    }
  }
  assert.ok(hashes > 0, "the last requirement has a hash");
  for (const [n, v] of [["construct", "2.10.70"], ["mac-alias", "2.2.3"], ["nska-deserialize", "1.5.1"], ["pybindgen", "0.21.0"], ["pytsk3", "20230125"]]) {
    assert.equal(names.get(n), v, `${n} is pinned as the tag's requirements file pins it`);
  }
  for (const n of ["anytree", "bbpb", "biplist", "cryptography", "ds-store", "inflate64", "jsonlines", "kaitaistruct", "libewf-python", "libvmdk-python", "lz4", "packaging", "pillow", "plistutils", "pycryptodome", "pyliblzfse", "pyyaml", "setuptools", "win32-setctime", "xattr", "xlsxwriter"]) {
    assert.ok(names.has(n), `${n} is in the lock`);
  }
  assert.match(text, /not from an install/);
  assert.match(text, /has not been installed anywhere yet/);
});

test("mac_apt's why names the lock, says it was not installed, and no longer says there is no lock", async () => {
  const why = (await binary("mac_apt.py")).why;
  assert.doesNotMatch(why, /without a hash lock/);
  assert.match(why, /hash lock \(requires\/locks\/mac_apt\.txt, pip --require-hashes\)/);
  assert.match(why, /written from PyPI's metadata, not from an install: it has not been installed yet/);
  assert.match(why, /pyaff4 zip is installed after the lock with --no-deps and is not hash-locked/);
});

test("fsapfsinfo names the image's apt snapshot date as its pin and does not call it unpinned", async () => {
  const b = await binary("fsapfsinfo");
  assert.match(b.why, /image's apt snapshot date \(images\/debian-snapshot\)/);
  assert.doesNotMatch(b.why, /unpinned/i);
});
