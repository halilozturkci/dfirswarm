/**
 * triage-collection, collection_timestamps: the clocks of a collection kept apart (an archive's member times, the delivered files' times)
 * with their precision and zone, compared only where they name the same file. Every fixture is built from the formats' own definitions (a
 * zip header's DOS date and time, a tar and a pax header written by the standard library with the mtime text set by hand, a gzip, bzip2 or xz
 * stream damaged byte by byte), never from the tool's output.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, readdir, symlink } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet } from "./tool-library-harness.ts";
import { CANARY_PY } from "./pack-triage-canaries.ts";
import { TOOLS, asJob, body, refused, tableRows, tool, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

export const TIMESTAMPS = join(TOOLS, "collection_timestamps", "run.py");
const S = 1_000_000_000n;

/** One Python snippet that builds a delivered tree (os.utime in nanoseconds), a tar and a zip from a JSON spec given in argv[1]. */
const BUILD = String.raw`
import bz2, gzip, io, json, lzma, os, struct, sys, tarfile, zipfile
spec = json.load(sys.stdin)
for rel, ns in spec.get("tree", []):
    path = os.path.join(spec["dir"], "x", rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "wb").write(b"x")
    os.utime(path, ns=(int(ns), int(ns)))
t = spec.get("tar")
if t:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT if t.get("pax", True) else tarfile.USTAR_FORMAT) as tf:
        for name, mtime in t["members"]:
            info = tarfile.TarInfo(name)
            info.size = 1
            info.mtime = int(float(mtime))
            if t.get("pax", True) and "." in str(mtime):
                info.pax_headers = {"mtime": str(mtime)}
            tf.addfile(info, io.BytesIO(b"x"))
        for name, mtime in t.get("dirs", []):
            info = tarfile.TarInfo(name); info.type = tarfile.DIRTYPE; info.mtime = int(mtime)
            tf.addfile(info)
    raw = buf.getvalue()
    kind = t.get("compress", "")
    data = {"": raw, "gz": gzip.compress(raw), "bz2": bz2.compress(raw), "xz": lzma.compress(raw)}[kind]
    d = t.get("damage")
    if d == "crc":
        data = data[:-8] + bytes([data[-8] ^ 1]) + data[-7:]
    elif d == "append_gz":
        data += gzip.compress(b"another stream")
    elif d == "append_bz2":
        data += bz2.compress(b"another stream")
    elif d == "append_xz":
        data += lzma.compress(b"another stream")
    elif d == "truncate":
        data = data[: len(data) // 2]
    elif d == "garbage":
        data += b"\x01garbage after the stream"
    elif d == "flip_body":
        mid = len(data) // 2
        data = data[:mid] + bytes([data[mid] ^ 0xFF]) + data[mid + 1:]
    open(os.path.join(spec["dir"], t["path"]), "wb").write(data)
z = spec.get("zip")
if z:
    with zipfile.ZipFile(os.path.join(spec["dir"], z["path"]), "w", zipfile.ZIP_STORED) as zf:
        for name, dt, extra in z["members"]:
            info = zipfile.ZipInfo(name, date_time=tuple(dt))
            if extra:
                info.extra = bytes.fromhex(extra)
            zf.writestr(info, b"x")
`;

async function build(cwd: string, spec: Json): Promise<void> {
  const run = await runPySnippet(BUILD, [], { dir: cwd, ...spec });
  assert.equal(run.code, 0, run.stderr);
}

const ns = (iso: string, fracNs = 0n): string => String(BigInt(Date.parse(iso)) / 1000n * S + fracNs);

function ts(cwd: string, args: Json, env: Record<string, string> = {}) {
  return tool(TIMESTAMPS, cwd, args, env);
}

test("a tar read against its extracted tree: pax nanoseconds kept as a decimal string, equal where the two clocks agree, differs where they do not", async () => {
  await withCwd(async (cwd) => {
    const t0 = BigInt(Date.parse("2026-01-02T03:04:05Z")) / 1000n;
    const exact = `${t0}.123456789`;
    await build(cwd, {
      tar: { path: "c.tar", members: [["pkg/a/one.txt", exact], ["pkg/a/two.txt", String(t0 + 60n)], ["pkg/three.txt", String(t0 + 120n)]] },
      tree: [["a/one.txt", String(t0 * S + 123456789n)], ["a/two.txt", String((t0 + 90n) * S)], ["extra.txt", String(t0 * S)]],
    });
    const out = body(await ts(cwd, { root: "x", archive: "c.tar", member_prefix: "pkg" }));
    assert.equal(out.archive_format, "tar");
    assert.equal(out.clocks.archive_member.latest.time, new Date(Number(t0 + 120n) * 1000).toISOString().replace(".000Z", "Z"));
    assert.equal(out.clocks.archive_member.zone, "UTC");
    assert.match(out.clocks.archive_member.precision, /1 s in a tar header/);
    const rows = await tableRows(cwd, out.tables.comparison);
    const by = (p: string) => rows.find((r: Json) => r.path === p || r.member === p);
    assert.equal(by("a/one.txt").outcome, "equal");
    assert.equal(by("a/one.txt").delivered.modified_epoch_ns, String(t0 * S + 123456789n), "the nanoseconds survive as a decimal string");
    assert.equal(by("a/two.txt").outcome, "differs");
    assert.equal(by("a/two.txt").detail.delta_ns, String(30n * S));
    assert.equal(rows.find((r: Json) => r.outcome === "only_in_archive").member, "pkg/three.txt");
    assert.equal(rows.find((r: Json) => r.outcome === "only_in_delivery").path, "extra.txt");
    assert.deepEqual(out.comparison.outcomes, { equal: 1, differs: 1, only_in_archive: 1, only_in_delivery: 1 });
    assert.equal(out.status, "complete", out.status_basis);
    assert.ok(out.conflicts.some((c: Json) => c.kind === "member_and_delivered_times_differ" && c.files === 1));
  });
});

test("a zip's DOS time is two-second and zoneless: the odd second is lost, no zone is assumed, and a quarter-hour offset is consistent, not determined", async () => {
  await withCwd(async (cwd) => {
    // 2026-02-03 04:05:07 is stored as 04:05:06 (the DOS field holds two-second steps); the file was extracted under UTC+3
    const wall = BigInt(Date.parse("2026-02-03T04:05:06Z")) / 1000n;
    await build(cwd, {
      zip: { path: "c.zip", members: [["c/f.txt", [2026, 2, 3, 4, 5, 7], ""], ["c/g.txt", [2026, 2, 3, 4, 5, 8], ""]] },
      tree: [["f.txt", String((wall - 3n * 3600n) * S + 700_000_000n)], ["g.txt", String((wall + 2n) * S + 5n * S)]],
    });
    const out = body(await ts(cwd, { root: "x", archive: "c.zip", member_prefix: "c" }));
    const clock = out.clocks.archive_member;
    assert.equal(clock.precision, "2 s");
    assert.match(clock.zone, /none stated.*never assumed to be UTC/);
    assert.equal(clock.earliest.time, "2026-02-03T04:05:06", "no Z: a wall-clock reading");
    assert.equal(clock.earliest.raw, "DOS date 2026-02-03, time 04:05:06");
    const rows = await tableRows(cwd, out.tables.comparison);
    const f = rows.find((r: Json) => r.path === "f.txt");
    assert.equal(f.outcome, "consistent_with_zone_offset");
    assert.equal(f.detail.offset_minutes_candidate, -180);
    assert.match(f.detail.note, /not a determination/);
    assert.equal(rows.find((r: Json) => r.path === "g.txt").outcome, "differs");
    assert.equal(out.clocks.delivered_mtime.earliest.modified_epoch_ns, String((wall - 3n * 3600n) * S + 700_000_000n));
  });
});

test("DST-ambiguous and non-existent local times are named under local_zone, and without it nothing is read as UTC", async () => {
  await withCwd(async (cwd) => {
    // Europe/Berlin: 2026-10-25 02:30 happens twice (CEST then CET); 2026-03-29 02:30 never happens
    await build(cwd, {
      zip: { path: "c.zip", members: [["a.txt", [2026, 10, 25, 2, 30, 0], ""], ["b.txt", [2026, 3, 29, 2, 30, 0], ""], ["c.txt", [2026, 6, 1, 12, 0, 0], ""]] },
      tree: [["a.txt", ns("2026-10-25T01:30:00Z")], ["b.txt", ns("2026-03-29T01:30:00Z")], ["c.txt", ns("2026-06-01T10:00:00Z")]],
    });
    const out = body(await ts(cwd, { root: "x", archive: "c.zip", local_zone: "Europe/Berlin" }));
    const rows = await tableRows(cwd, out.tables.comparison);
    const a = rows.find((r: Json) => r.path === "a.txt");
    assert.match(a.member_times[0].local_zone_reading.status, /^ambiguous/);
    assert.deepEqual(a.member_times[0].local_zone_reading.utc, ["2026-10-25T00:30:00Z", "2026-10-25T01:30:00Z"]);
    assert.equal(a.outcome, "equal", "the second of the two readings is the delivered time");
    const b = rows.find((r: Json) => r.path === "b.txt");
    assert.match(b.member_times[0].local_zone_reading.status, /^nonexistent/);
    assert.equal(b.outcome, "differs");
    assert.equal(rows.find((r: Json) => r.path === "c.txt").outcome, "equal");
    assert.deepEqual(out.clocks.archive_member.local_zone_reading, { unambiguous: 1, ambiguous: 1, nonexistent: 1 });
    const bare = body(await ts(cwd, { root: "x", archive: "c.zip" }));
    assert.equal(bare.clocks.archive_member.earliest.time.endsWith("Z"), false);
    assert.equal(JSON.stringify(bare).includes("local_zone_reading"), false);
    const bad = refused(await ts(cwd, { root: "x", archive: "c.zip", local_zone: "../../etc/passwd" }));
    assert.match(bad.error, /IANA zone name/);
    const unknown = refused(await ts(cwd, { root: "x", archive: "c.zip", local_zone: "Nowhere/Land" }));
    assert.match(unknown.error, /no zone is assumed/);
  });
});

test("a zip's extended-timestamp field is its own UTC clock beside the DOS time and is what the comparison uses", async () => {
  await withCwd(async (cwd) => {
    const when = BigInt(Date.parse("2026-05-05T10:00:01Z")) / 1000n;
    const ut = Buffer.alloc(9);
    ut.writeUInt16LE(0x5455, 0); ut.writeUInt16LE(5, 2); ut[4] = 1; ut.writeInt32LE(Number(when), 5);
    await build(cwd, {
      zip: { path: "c.zip", members: [["f.txt", [2026, 5, 5, 13, 0, 0], ut.toString("hex")]] },
      tree: [["f.txt", String(when * S)]],
    });
    const out = body(await ts(cwd, { root: "x", archive: "c.zip" }));
    assert.equal(out.clocks.archive_member_utc_extra.earliest.time, "2026-05-05T10:00:01Z");
    assert.equal(out.clocks.archive_member_utc_extra.zone, "UTC");
    assert.equal(out.clocks.archive_member.zone.startsWith("none stated"), true, "the DOS clock stays zoneless");
    const rows = await tableRows(cwd, out.tables.comparison);
    assert.equal(rows[0].outcome, "equal");
    assert.equal(rows[0].detail.used, "zip_extended_timestamp");
    assert.equal(rows[0].member_times.length, 2, "both clocks of the member are shown");
  });
});

test("a collection whose files are all on one date is reported as apparent flattening, with counts and no cause; real activity is not", async () => {
  await withCwd(async (cwd) => {
    const day = BigInt(Date.parse("2026-04-01T00:00:00Z")) / 1000n;
    const flat = Array.from({ length: 40 }, (_, i) => [`flat/f${i}.txt`, String((day + BigInt(i * 60)) * S)]);
    const varied = Array.from({ length: 40 }, (_, i) => [`real/f${i}.txt`, String((day - BigInt(i) * 86400n * 3n) * S)]);
    await build(cwd, { tree: [...flat, ...varied] });
    const out = body(await ts(cwd, { root: "x/flat" }));
    assert.equal(out.status, "complete");
    assert.equal(out.apparent_flattening.length, 1);
    assert.deepEqual([out.apparent_flattening[0].date, out.apparent_flattening[0].files_on_date, out.apparent_flattening[0].files], ["2026-04-01", 40, 40]);
    assert.doesNotMatch(JSON.stringify(out.apparent_flattening), /because|caused|due to|reset by|tamper/i);
    assert.match(out.apparent_flattening[0].basis, /no cause/);
    const real = body(await ts(cwd, { root: "x/real" }));
    assert.deepEqual(real.apparent_flattening, []);
    assert.equal(real.clocks.delivered_mtime.apparent_flattening, null);
    // twenty files or fewer are never called flattened
    await build(cwd, { tree: Array.from({ length: 20 }, (_, i) => [`few/f${i}.txt`, String(day * S)]) });
    assert.deepEqual(body(await ts(cwd, { root: "x/few" })).apparent_flattening, []);
  });
});

test("mixed clocks: an archive that varies against a tree flattened to one date is a conflict, counted, with no cause", async () => {
  await withCwd(async (cwd) => {
    const base = BigInt(Date.parse("2026-01-10T00:00:00Z")) / 1000n;
    const names = Array.from({ length: 30 }, (_, i) => `d/f${i}.txt`);
    await build(cwd, {
      tar: { path: "c.tar", members: names.map((n, i) => [n, String(base + BigInt(i) * 86400n * 2n)]) },
      tree: names.map((n) => [n, String((BigInt(Date.parse("2026-06-01T12:00:00Z")) / 1000n) * S)]),
    });
    const out = body(await ts(cwd, { root: "x", archive: "c.tar" }));
    assert.equal(out.comparison.outcomes.differs, 30);
    assert.ok(out.conflicts.some((c: Json) => c.kind === "flattened_in_one_clock_only"));
    assert.deepEqual(out.apparent_flattening.map((f: Json) => f.clock), ["delivered_mtime"]);
    assert.equal(out.acquisition.interval, "unknown", "no collector record, so the interval is unknown and not taken from file times");
  });
});

test("names join by NFC and case folding, and a name two delivered files share stays ambiguous", { skip: NO_CASE_SENSITIVE_FS }, async () => {
  await withCwd(async (cwd) => {
    const t = BigInt(Date.parse("2026-03-03T03:03:03Z")) / 1000n;
    const decomposed = "café.txt";      // e + combining acute, as macOS writes it
    const precomposed = "café.txt";
    await build(cwd, {
      tar: { path: "c.tar", members: [[decomposed, String(t)], ["Dup.txt", String(t)]] },
      tree: [[precomposed, String(t * S)], ["dup.txt", String(t * S)], ["DUP.TXT", String(t * S)]],
    });
    const out = body(await ts(cwd, { root: "x", archive: "c.tar" }));
    const rows = await tableRows(cwd, out.tables.comparison);
    assert.equal(rows.find((r: Json) => r.path === precomposed)?.outcome, "equal");
    const dup = rows.find((r: Json) => r.outcome === "ambiguous_join");
    assert.equal(dup.candidates_total, 2);
    assert.equal(rows.some((r: Json) => r.outcome === "only_in_delivery"), false, "both candidates count as named");
  });
});

test("a clean compressed tar is complete; a CRC flip, an appended gzip, bzip2 or xz stream, garbage, a cut stream and a flipped byte are never complete", async () => {
  await withCwd(async (cwd) => {
    const members = Array.from({ length: 400 }, (_, i) => [`m/f${i}.txt`, String(1_700_000_000 + i)]);
    for (const [kind, damage, expect] of [
      ["gz", undefined, "complete"], ["bz2", undefined, "complete"], ["xz", undefined, "complete"],
      ["gz", "crc", "partial"], ["gz", "append_gz", "partial"], ["gz", "garbage", "partial"], ["gz", "truncate", "partial"], ["gz", "flip_body", "partial"],
      ["bz2", "append_bz2", "partial"], ["bz2", "truncate", "partial"], ["bz2", "garbage", "partial"], ["xz", "append_xz", "partial"], ["xz", "truncate", "partial"], ["xz", "flip_body", "partial"],
    ] as const) {
      const path = `c-${kind}-${damage ?? "clean"}.tar`;
      await build(cwd, { tar: { path, members, compress: kind, damage } });
      const out = body(await ts(cwd, { archive: path }));
      if (damage === "truncate" || damage === "flip_body") assert.ok(["partial", "failed"].includes(out.status), `${kind} truncated: ${out.status} ${out.status_basis}`);   // a cut stream may leave no block to read at all: failed, never complete
      else assert.equal(out.status, expect, `${kind} ${damage}: ${out.status_basis}`);
      if (expect === "partial") assert.ok(out.status_basis.length > 20, `${kind} ${damage} says why`);
      if (expect === "complete") assert.equal(out.archive_members.files, 400);
    }
    // a plain tar cut before its end marker is partial too, and a zip with bytes in front of it
    await build(cwd, { tar: { path: "cut.tar", members, compress: "", damage: "truncate" } });
    assert.equal(body(await ts(cwd, { archive: "cut.tar" })).status, "partial");
    await build(cwd, { zip: { path: "z.zip", members: [["a.txt", [2026, 1, 1, 0, 0, 0], ""]] } });
    const zbytes = await readFile(join(cwd, "z.zip"));
    await (await import("node:fs/promises")).writeFile(join(cwd, "front.zip"), Buffer.concat([Buffer.from("PK\x03\x04junkjunkjunk"), zbytes]));
    assert.notEqual(body(await ts(cwd, { archive: "front.zip" })).status, "complete");
  });
});

test("an archive inside the archive is counted and not opened, so the answer is partial; a metadata record over 1 MiB is a refusal in the answer, not a crash", async () => {
  await withCwd(async (cwd) => {
    await build(cwd, { tar: { path: "c.tar", members: [["inner.tar.gz", "1700000000"], ["a.txt", "1700000001"]] } });
    const out = body(await ts(cwd, { archive: "c.tar" }));
    assert.equal(out.status, "partial");
    assert.equal(out.archive_members.nested_archives, 1);
    assert.match(out.status_basis, /were not opened/);
    const big = await runPySnippet(`
import io, sys, tarfile
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
    info = tarfile.TarInfo("a.txt"); info.size = 1
    info.pax_headers = {"comment": "x" * (2 << 20)}
    tf.addfile(info, io.BytesIO(b"x"))
open(sys.argv[1], "wb").write(buf.getvalue())
`, [join(cwd, "big.tar")], null);
    assert.equal(big.code, 0, big.stderr);
    const refusedBig = body(await ts(cwd, { archive: "big.tar" }));
    assert.notEqual(refusedBig.status, "complete");
    assert.match(refusedBig.status_basis, /metadata record|could not be read|could not tell/);
  });
});

test("a huge collection is streamed: the memory bound ends the walk partial with JSON, and a large tree and archive finish complete", async () => {
  await withCwd(async (cwd) => {
    const base = BigInt(Date.parse("2026-01-01T00:00:00Z")) / 1000n;
    const files = Array.from({ length: 3000 }, (_, i) => [`t/${i % 40}/f${i}.txt`, String((base + BigInt(i)) * S)]);
    await build(cwd, { tree: files, tar: { path: "c.tar", members: files.map(([n], i) => [n, String(base + BigInt(i))]) } });
    const whole = body(await ts(cwd, { root: "x/t", archive: "c.tar", member_prefix: "t", limit: 5 }));
    assert.equal(whole.delivered_tree.files, 3000);
    assert.equal(whole.archive_members.files, 3000);
    assert.equal(whole.comparison.outcomes.equal, 3000);
    assert.equal(whole.comparison_page.length, 5, "the page is short");
    assert.equal(whole.tables.comparison.matched, 3000, "the whole is in the file");
    assert.equal((await tableRows(cwd, whole.tables.comparison)).length, 3000);
    const small = body(await ts(cwd, { root: "x/t", archive: "c.tar" }, { COLLECTION_MEMORY_BYTES: "1" }));
    assert.equal(small.status, "partial");
    assert.match(small.status_basis, /memory bound/);
  });
});

test("the tool's own clock ends the read of a decompression bomb partial, with JSON, well inside the time asked", async () => {
  await withCwd(async (cwd) => {
    const run = await runPySnippet(`
import sys, tarfile, zlib, io
out = open(sys.argv[1], "wb")
# 16 GiB of zeros. An M3 Max read the 3 GiB this case used to make in about the 1 s of clock asked below: five runs of the
# tool on it reached the archive's end, not the clock (1.04 to 1.06 s with the interpreter's start), and the file alone failed
# 3 runs of 5. The whole of this one takes 5.6 s there.
info = tarfile.TarInfo("big.bin"); info.size = 16 << 30
# A GNU header: ustar's size field stops below 8 GiB, GNU's takes the size in base 256. One block for a short name.
head = info.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape")
assert len(head) == 512, len(head)                     # (addfile() wants the whole body since Python 3.14: the header block is all that is needed)
c = zlib.compressobj(9, zlib.DEFLATED, 31)
out.write(c.compress(head) + c.flush(zlib.Z_FULL_FLUSH))
# After a full flush the deflate stream refers to nothing before it, so the compressed form of 16 MiB of zeros is the same bytes
# every time: written 1024 times it is 16 GiB of tar body from about 16 MB, without compressing 16 GiB here.
block = c.compress(b"\\0" * (1 << 24)) + c.flush(zlib.Z_FULL_FLUSH)
for _ in range(1024):
    out.write(block)
# (no gzip trailer: a read the clock did not end would say the stream is cut, not the time limit)
`, [join(cwd, "bomb.tar.gz")], null);
    assert.equal(run.code, 0, run.stderr);
    const started = Date.now();
    const out = body(await ts(cwd, { archive: "bomb.tar.gz", time_limit_seconds: 1 }));
    assert.ok(Date.now() - started < 30_000, "it stopped on its own clock");
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /time limit/);
  });
});

test("SIGINT, SIGTERM and SIGHUP leave one JSON answer and the exit status 128 plus the signal", async () => {
  const code = `
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.install_signal_handlers()
os.kill(os.getpid(), getattr(signal, sys.argv[2]))
`;
  for (const [name, status] of [["SIGINT", 130], ["SIGTERM", 143], ["SIGHUP", 129]] as const) {
    const run = await runPySnippet(code, [TIMESTAMPS, name], null);
    assert.equal(run.code, status, run.stderr);
    assert.match(JSON.parse(run.stdout).error, /stopped by signal/);
    assert.doesNotMatch(run.stderr, /Traceback|KeyboardInterrupt/);
  }
});

test("hostile parameters are JSON refusals: wrong types, no input, a file as the root, a pipe, a link and a directory as the archive", async () => {
  await withCwd(async (cwd) => {
    await build(cwd, { tree: [["a/f.txt", "1700000000000000000"]], zip: { path: "z.zip", members: [["a", [2026, 1, 1, 0, 0, 0], ""]] } });
    for (const args of [{}, { root: 5 }, { root: "x/a", limit: "x" }, { root: "x/a", limit: 0 }, { root: "x/a", time_limit_seconds: 99999 }, { root: "x/a", write_values: "yes" },
      { root: "x/a/f.txt" }, { root: "nope" }, { archive: "" }, { root: "x/a", member_prefix: 7 }]) {
      const out = refused(await ts(cwd, args));
      assert.equal(out.status, "failed");
      assert.ok(out.error);
    }
    const mk = await runPySnippet(`import os,sys; os.mkfifo(sys.argv[1])`, [join(cwd, "pipe.tar")], null);
    assert.equal(mk.code, 0, mk.stderr);
    await symlink("z.zip", join(cwd, "link.zip"));
    await mkdir(join(cwd, "dir.tar"));
    for (const archive of ["pipe.tar", "link.zip", "dir.tar", "missing.tar"]) {
      const started = Date.now();
      const out = await ts(cwd, { archive });
      assert.ok(Date.now() - started < 20_000, `${archive} is not waited on`);
      assert.doesNotMatch(out.stderr, /Traceback/);
      const doc = JSON.parse(out.stdout);
      assert.equal(doc.status, "failed", archive);
      assert.match(doc.status_basis, /archive was not read/);
    }
    const unknown = body(await ts(cwd, { root: "x/a", frobnicate: 1 }));
    assert.deepEqual(unknown.ignored_parameters, ["frobnicate"]);
  });
});

test("canaries in member names, delivered paths and the prefix are withheld from the answer and the table files, and the values file exists only in a secret job", async () => {
  await withCwd(async (cwd) => {
    const gen = await runPySnippet(CANARY_PY + String.raw`
import json, random
r = random.Random(38)
picked = [n for n in names(("listed",), safe_only=True)][:6]
print(json.dumps([[n, *make(n, r)] for n in picked]))
`, [], null);
    assert.equal(gen.code, 0, gen.stderr);
    const plants = JSON.parse(gen.stdout) as Array<[string, string, string[]]>;
    const t = 1_700_000_000;
    const members: Array<[string, string]> = plants.map(([, text], i) => [`p/${i}-${text}.txt`, String(t + i)]);
    await build(cwd, { tar: { path: "c.tar", members }, tree: plants.map(([, text], i) => [`${i}-${text}.txt`, String((t + i + 1) * 1_000_000_000)]) });
    const call = await ts(cwd, { root: "x", archive: "c.tar", member_prefix: "p" });
    const out = body(call);
    const rows = JSON.stringify(await tableRows(cwd, out.tables.comparison));
    const all = call.stdout + rows + call.stderr;
    for (const [shape, , cores] of plants) for (const core of cores) for (let i = 0; i + 12 <= core.length; i += 6) assert.ok(!all.includes(core.slice(i, i + 12)), `${shape} shows ${core.slice(i, i + 12)}`);
    assert.ok(out.withheld.strings_withheld >= 1);
    const refusal = refused(await ts(cwd, { root: "x", write_values: true }));
    assert.match(refusal.error, /job|secret/i);
    // as a job with secret_output the values file is 0600 under OUT, and nothing else is written outside it
    const job = await asJob(TIMESTAMPS, cwd, { root: "x", archive: "c.tar", member_prefix: "p", write_values: true });
    const answer = body(job);
    assert.equal(answer.withheld.values.contains_secret_values, true);
    const written = await readdir(join(cwd, "out"));
    assert.ok(written.includes("collection-timestamps-values.jsonl"));
    assert.equal(((await (await import("node:fs/promises")).stat(join(cwd, "out", "collection-timestamps-values.jsonl"))).mode & 0o777).toString(8), "600");
    assert.equal(job.stdout.includes(plants[0][2][0].slice(0, 12)), false);
  });
});

// ---- clocks 1 and 4: the collector's own records (PKG-TRI-10) ---------------------------------------------------------------------------
import { KAPE_COPY_HEADER, kapeCopyRow, put, uac3, veloUploadsRow, veloLogRow } from "./pack-triage-harness.ts";
import { NO_CASE_SENSITIVE_FS } from "./host-gates.ts";

async function setNs(path: string, value: bigint): Promise<void> {
  const run = await runPySnippet("import os,sys; os.utime(sys.argv[1], ns=(int(sys.argv[2]), int(sys.argv[2])))", [path, String(value)], null);
  assert.equal(run.code, 0, run.stderr);
}

const MOD_SECONDS = BigInt(Date.parse("2026-01-02T03:04:05Z")) / 1000n;      // kapeCopyRow's ModifiedOnUtc is 2026-01-02 03:04:05.678

async function kapeFixture(cwd: string): Promise<void> {
  await put(cwd, "k/run_CopyLog.csv", [KAPE_COPY_HEADER, kapeCopyRow("C:\\Users\\a\\NTUSER.DAT", "C\\Users\\a\\NTUSER.DAT"), kapeCopyRow("C:\\Users\\a\\other.txt", "C\\Users\\a\\other.txt"),
    kapeCopyRow("C:\\gone\\x.txt", "C\\gone\\x.txt")].join("\n") + "\n");
  await put(cwd, "k/run_ConsoleLog.txt", "[2026-02-14 09:12:00.123 | INF] KAPE starting\n[2026-02-14 09:14:30.500 | INF] Done\n");
  await put(cwd, "k/C/Users/a/NTUSER.DAT", "x");
  await put(cwd, "k/C/Users/a/other.txt", "x");
  await setNs(join(cwd, "k/C/Users/a/NTUSER.DAT"), MOD_SECONDS * S + 678_000_000n);
}

test("the collector's record times are kept as the collector's own text with the zone it states, and a time with none is never read as UTC", async () => {
  await withCwd(async (cwd) => {
    await kapeFixture(cwd);
    await put(cwd, "u/uac.log", [uac3("INF", "UAC starting", 1), "2026-02-14 09:12:05 DBG a line with no offset", uac3("ERR", "ps failed", 9)].join("\n") + "\n");
    await put(cwd, "v/c1/uploads.json", veloUploadsRow("C:/x/a.txt") + "\n");
    await put(cwd, "v/c1/log.json", veloLogRow("INFO", "start") + "\n");
    const kape = body(await ts(cwd, { root: "k" }));
    const clocks = kape.record_clocks;
    const mod = clocks["KAPE.ModifiedOnUtc"];
    assert.match(mod.zone, /^UTC: the column is named ModifiedOnUtc/);
    assert.equal(mod.earliest.raw, "2026-01-02 03:04:05.678");
    assert.equal(mod.earliest.time, "2026-01-02T03:04:05.678Z");
    assert.match(mod.precision, /up to 3 fractional digit/);
    const copied = clocks["KAPE.CopiedTimestamp (no zone)"];
    assert.match(copied.zone, /^none stated: the writer states no zone: a wall-clock reading, not assumed to be UTC/);
    assert.equal(copied.earliest.time, "2026-02-14T09:12:00.123", "no Z");
    assert.equal(kape.status, "complete", kape.status_basis);
    assert.equal(kape.acquisition.logs[0].start.time, "2026-02-14T09:12:00.123");
    assert.match(kape.acquisition.logs[0].start.zone, /none stated/);
    assert.equal(kape.acquisition.logs[0].end.raw, "2026-02-14 09:14:30.500");
    assert.match(kape.acquisition.logs[0].basis, /not a statement of when it began/);
    const uac = body(await ts(cwd, { root: "u" }));
    const log = uac.record_clocks["UAC.log line"];
    assert.equal(log.files, 2, "the line with a +0000 offset and the ERR line are zoned");
    assert.match(log.zone, /the text states its offset \(UTC\)/);
    assert.equal(uac.record_clocks["UAC.log line (no zone)"].files, 1, "the line with no offset is a wall-clock reading");
    assert.equal(uac.acquisition.logs[0].end.time, "2026-02-14T09:12:09Z");
    const velo = body(await ts(cwd, { root: "v" }));
    assert.equal(velo.record_clocks["Velociraptor.Timestamp"].earliest.time, "2020-10-07T20:43:08Z");
    assert.match(velo.record_clocks["Velociraptor.started"].zone, /the text states its offset \(UTC\)/);
    assert.equal(velo.acquisition.logs[0].start.time, "2020-10-07T20:43:08Z");
  });
});

test("a copy-log row's ModifiedOnUtc is compared with the delivered mtime only where the join names one file; a record with no file or a differing time says so", async () => {
  await withCwd(async (cwd) => {
    await kapeFixture(cwd);
    const out = body(await ts(cwd, { root: "k" }));
    assert.deepEqual(out.records.comparison.outcomes, { equal: 1, differs: 1, not_compared: 1 });
    const rows = await tableRows(cwd, out.tables.record_comparison);
    assert.equal(rows.find((r: Json) => r.path === "C/Users/a/NTUSER.DAT").outcome, "equal");
    assert.equal(rows.find((r: Json) => r.path === "C/Users/a/other.txt").outcome, "differs");
    assert.equal(rows.find((r: Json) => r.outcome === "not_compared").join.status, "missing");
    assert.ok(out.conflicts.some((c: Json) => c.kind === "record_time_differs_from_delivered_mtime" && c.records === 1));
    assert.equal(rows.find((r: Json) => r.path === "C/Users/a/NTUSER.DAT").delivered.modified_epoch_ns, String(MOD_SECONDS * S + 678_000_000n));
  });
});

test("an ambiguous join stays ambiguous: two delivered files that differ only by case are both candidates and neither is compared", { skip: NO_CASE_SENSITIVE_FS }, async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "k/run_CopyLog.csv", [KAPE_COPY_HEADER, kapeCopyRow("C:\\Users\\a\\Note.TXT", "C\\Users\\a\\Note.TXT")].join("\n") + "\n");
    await put(cwd, "k/C/Users/a/note.txt", "x");
    await put(cwd, "k/C/Users/a/NOTE.TXT", "x");
    const out = body(await ts(cwd, { root: "k" }));
    const rows = await tableRows(cwd, out.tables.record_comparison);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].outcome, "ambiguous_join");
    assert.equal(rows[0].candidates_total, 2);
    assert.equal(rows[0].delivered, undefined, "no delivered time is taken from either candidate");
    assert.ok(out.conflicts.some((c: Json) => c.kind === "record_join_ambiguous"));
  });
});

test("records that are cut, malformed or in another encoding make it partial, and a record read cut by the clock is never complete", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "m/run_CopyLog.csv", [KAPE_COPY_HEADER, kapeCopyRow("C:\\a\\b.txt", "C\\a\\b.txt"), "only,three,fields", kapeCopyRow("C:\\a\\c.txt", "C\\a\\c.txt").replace("2026-01-02 03:04:05.678", "not a time")].join("\n") + "\n");
    await put(cwd, "m/C/a/b.txt", "x");
    const mal = body(await ts(cwd, { root: "m" }));
    assert.equal(mal.status, "partial");
    assert.equal(mal.record_clocks["KAPE.ModifiedOnUtc (no zone)"].times_not_readable, 1);
    await put(cwd, "u16/uac.log", Buffer.from("\ufeff" + uac3("INF", "x") + "\n", "utf16le"));
    const wide = body(await ts(cwd, { root: "u16" }));
    assert.equal(wide.status, "partial");
    assert.match(wide.status_basis, /unsupported|uac\.log/);
    assert.equal(wide.acquisition.interval, "unknown");
    const rows = Array.from({ length: 300000 }, (_, i) => kapeCopyRow(`C:\\w\\f${i}.txt`, `C\\w\\f${i}.txt`));
    await put(cwd, "big/run_CopyLog.csv", [KAPE_COPY_HEADER, ...rows].join("\n") + "\n");
    const started = Date.now();
    const cut = body(await ts(cwd, { root: "big", time_limit_seconds: 1 }));
    assert.ok(Date.now() - started < 60_000, "it stops on its own clock");
    assert.equal(cut.status, "partial");
    assert.match(cut.status_basis, /time limit/);
  });
});

test("canaries in copy-log rows, paths and log lines are withheld from the answer and every table file", async () => {
  await withCwd(async (cwd) => {
    const gen = await runPySnippet(CANARY_PY + String.raw`
import json, random
r = random.Random(39)
picked = [n for n in names(("listed",), safe_only=True)][:6]
print(json.dumps([[n, *make(n, r)] for n in picked]))
`, [], null);
    assert.equal(gen.code, 0, gen.stderr);
    const plants = JSON.parse(gen.stdout) as Array<[string, string, string[]]>;
    const rows = plants.map(([, text], i) => kapeCopyRow(`C:\\Users\\${text}\\f${i}.txt`, `C\\Users\\${text}\\f${i}.txt`));
    await put(cwd, "k/run_CopyLog.csv", [KAPE_COPY_HEADER, ...rows].join("\n") + "\n");
    await put(cwd, "k/uac.log", plants.map(([, text], i) => uac3("ERR", `failed for ${text}`, i)).join("\n") + "\n");
    for (const [i, [, text]] of plants.entries()) await put(cwd, `k/C/Users/${text}/f${i}.txt`, "x");
    const call = await ts(cwd, { root: "k" });
    const out = body(call);
    const all = call.stdout + JSON.stringify(await tableRows(cwd, out.tables.record_comparison)) + call.stderr;
    for (const [shape, , cores] of plants) for (const core of cores) for (let i = 0; i + 12 <= core.length; i += 6) assert.ok(!all.includes(core.slice(i, i + 12)), `${shape} shows ${core.slice(i, i + 12)}`);
  });
});
