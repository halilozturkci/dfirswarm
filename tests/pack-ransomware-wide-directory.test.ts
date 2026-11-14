/**
 * ransomware-response: one directory with very many entries. The NAMES block reads a directory through listing() and orders it through
 * print_order(), both under the tool's clock: a directory is read only as far as the clock goes, at most MAX_LISTED of its entries are held
 * (the ones kept are drawn by a keyed hash of their path, not by the order the directory lists them in), and the names not judged when the
 * clock runs out are counted and come last. Before, a walk read its clock only between directories: one directory of two million entries was
 * held whole (900 MB) and had every name judged, for about a minute past a clock of two seconds.
 *
 * The wide directory is a stand-in for os.scandir (no file is made for its entries), so the test costs what the clock allows, not what a
 * million files cost to create. Every name is synthetic.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet, withCwd } from "./tool-library-harness.ts";
import { LOAD, NOTES, PACK, SURVEY, runPatched } from "./ransomware-pack-harness.ts";

const VALIDATE = join(PACK, "recovery_validate", "run.py");
const CARRIERS = ["ransom_note_scan", "encrypted_survey", "recovery_validate", "encryption_extent", "backup_destruction_correlate",
  "ransomware_scope_report", "decryptor_catalog", "ransomware_family_match"].map((t) => join(PACK, t, "run.py"));

/** Python, run with a tool loaded as `m`: os.scandir of a directory named "wide" yields WIDE entries named like notes, made on the fly. */
const WIDE = (count: number): string => String.raw`
_real_scandir = os.scandir
_WORDS = "Restore Your Files Read Carefully Before Contacting Support About Decryption Instructions Quarterly Report Draft".split()
class _Fake:
    __slots__ = ("name", "path")
    def __init__(self, d, i):
        parts = []
        for _ in range(8):
            parts.append(_WORDS[i % len(_WORDS)]); i //= len(_WORDS)
        self.name = "readme %s.txt" % " ".join(parts)
        self.path = os.path.join(d, self.name)
    def is_dir(self, follow_symlinks=True): return False
    def is_symlink(self): return False
    def stat(self, follow_symlinks=True): raise FileNotFoundError(2, "No such file or directory")
class _Wide:
    def __init__(self, d): self.d = d
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def __iter__(self): return (_Fake(self.d, i) for i in range(${count}))
    def close(self): pass
def _scandir(path="."):
    if os.path.basename(os.fspath(path).rstrip("/")) == "wide":
        return _Wide(os.fspath(path))
    return _real_scandir(path)
os.scandir = _scandir
`;

type Answer = {
  status: string; partial_reasons: string[]; coverage: Record<string, unknown>;
  time_limit: { max_seconds: number; reached: boolean; listing_cut?: boolean; entries_not_examined?: number };
};

for (const [name, script, args] of [
  ["encrypted_survey", SURVEY, { root: "work/ev", max_seconds: 1, limit: 1 }],
  ["recovery_validate", VALIDATE, { recovered_root: "work/ev", max_seconds: 1, limit: 1 }],
  ["ransom_note_scan", NOTES, { root: "work/ev", max_seconds: 1, limit: 1 }],
] as const) {
  test(`${name} reads and orders one directory of 1,500,000 entries under its clock and holds at most the bound of them`, async () => {
    await withCwd(async (cwd) => {
      await mkdir(join(cwd, "work", "ev", "wide"), { recursive: true });
      const out = join(cwd, "work", "out");
      await mkdir(out, { recursive: true });
      const started = Date.now();
      const run = await runPatched(script, WIDE(1500000), JSON.stringify(args), cwd, out);
      const seconds = (Date.now() - started) / 1000;
      assert.doesNotMatch(run.stderr, /Traceback/, run.stderr);
      const answer = JSON.parse(run.stdout) as Answer;
      assert.equal(answer.status, "partial");
      assert.equal(answer.time_limit.reached, true);
      // Judged in full, the names alone took tens of seconds on the machine this was written on; under the clock the run ends near it.
      assert.ok(seconds < 1 + 8, `${name} ran ${seconds} s with max_seconds 1`);
      assert.ok((answer.time_limit.entries_not_examined ?? 0) <= 1 << 18, "no more than MAX_LISTED entries of one directory are held");
    });
  });
}

/** Python: the shared listing() and print_order() of every carrier, on a fake directory, with the bound made small. */
const UNIT = LOAD + String.raw`
class E:
    def __init__(self, i):
        self.name = "note %s" % "".join("abcdefghij"[int(c)] for c in str(i))
        self.path = "/wide/" + self.name
    def is_dir(self, follow_symlinks=True): return False
out = []
for p in sys.argv[1:]:
    m = load(p, os.path.basename(os.path.dirname(p)))
    m.MAX_LISTED = 100
    entries = [E(i) for i in range(1000)]
    r = {}
    kept, not_kept, cut = m.listing(iter(entries), late=lambda: False)
    again, _, _ = m.listing(iter(entries[::-1]), late=lambda: False)
    r["bound"] = [len(kept), not_kept, cut]
    r["kept_whatever_the_order"] = sorted(e.path for e in kept) == sorted(e.path for e in again)
    first = sorted(entries[:100], key=lambda e: e.path)
    r["kept_is_not_the_first_listed"] = sorted(e.path for e in kept) != [e.path for e in first]
    calls = [0]
    def late(limit):
        def f():
            calls[0] += 1
            return calls[0] > limit
        return f
    calls[0] = 0
    some, some_not_kept, some_cut = m.listing(iter(entries), late=late(30))
    r["clock"] = [len(some), some_not_kept, some_cut]
    m.NAMES_CUT["not_judged"] = 0
    calls[0] = 0
    ordered = m.print_order(entries[:50], lambda e: True, late=late(20))
    r["not_judged"] = m.NAMES_CUT["not_judged"]
    judged = ordered[:20]
    r["judged_in_print_order"] = [e.name for e in judged] == sorted(e.name for e in entries[:20])
    r["rest_last"] = sorted(e.name for e in ordered[20:]) == sorted(e.name for e in entries[20:50])
    m.NAMES_CUT["not_judged"] = 0
    r["no_clock_no_cut"] = [e.name for e in m.print_order(entries[:50], lambda e: True, late=lambda: False)] == sorted(e.name for e in entries[:50])
    r["no_clock_counted"] = m.NAMES_CUT["not_judged"]
    out.append(r)
print(json.dumps(out))
`;

test("listing() keeps at most MAX_LISTED entries, drawn by the keyed hash and not by the listing order, and stops at the clock; print_order() judges under it", async () => {
  const run = await runPySnippet(UNIT, CARRIERS, null);
  assert.equal(run.code, 0, run.stderr);
  const all = JSON.parse(run.stdout) as Record<string, unknown>[];
  assert.equal(all.length, CARRIERS.length);
  for (const r of all) {
    assert.deepEqual(r.bound, [100, 900, false]);
    assert.equal(r.kept_whatever_the_order, true);
    assert.equal(r.kept_is_not_the_first_listed, true);
    assert.deepEqual(r.clock, [30, 0, true]);
    assert.equal(r.not_judged, 30);
    assert.equal(r.judged_in_print_order, true);
    assert.equal(r.rest_last, true);
    assert.equal(r.no_clock_no_cut, true);
    assert.equal(r.no_clock_counted, 0);
  }
});

for (const [name, script, args, files] of [
  ["encrypted_survey", SURVEY, { root: "work/ev", limit: 1 }, "files"],
  ["recovery_validate", VALIDATE, { recovered_root: "work/ev", limit: 1 }, "files"],
  ["ransom_note_scan", NOTES, { root: "work/ev", limit: 1 }, "notes"],
] as const) {
  test(`${name} counts the entries of a directory past the bound, says so and is partial`, async () => {
    await withCwd(async (cwd) => {
      const dir = join(cwd, "work", "ev", "big");
      await mkdir(dir, { recursive: true });
      for (let i = 0; i < 70; i++) {
        // distinct whatever the case rule of the filesystem: the digits of i spelled as letters
        const stem = String(i).split("").map((d) => "abcdefghij"[Number(d)]).join("");
        await writeFile(join(dir, `${files === "notes" ? "readme" : "file"} ${stem}.txt`), "Your files are encrypted. Read this to restore them.\n");
      }
      const out = await mkdtemp(join(tmpdir(), "wide-out-"));
      try {
        const run = await runPatched(script, "m.MAX_LISTED = 50", JSON.stringify(args), cwd, out);
        assert.doesNotMatch(run.stderr, /Traceback/, run.stderr);
        const answer = JSON.parse(run.stdout) as Answer;
        assert.equal(answer.status, "partial");
        assert.equal(answer.coverage.entries_not_listed, 20);
        assert.equal(answer.coverage.directories_over_entry_bound, 1);
        assert.ok(answer.partial_reasons.some((r) => /1 directories hold more than 50 entries.*20 of their entries were not/.test(r)), answer.partial_reasons.join(" | "));
        assert.equal(answer.time_limit.reached, false);
      } finally {
        await rm(out, { recursive: true, force: true });
      }
    });
  });
}
