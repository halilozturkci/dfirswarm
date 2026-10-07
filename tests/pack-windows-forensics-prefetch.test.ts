/**
 * prefetch_mam and mam_scan, against files built from the layouts (tests/windows-prefetch-fixtures.ts) and never from a tool's
 * output, and against two real facts a fixture could not show before:
 *
 *   - the run count of a version 26, 30 or 31 file is not always at 0xD0: Windows 10 files carry a file information of 224 bytes
 *     (the file metrics array offset at 0x54 is 0x130, the run count at 0xD0) and of 216 (0x128, the run count at 0xC8, with
 *     something else at 0xD0);
 *   - dissect.util's decoder takes 32 bits of lookahead and stops when its read position reaches the end of its input, so a stream
 *     that ends without padding comes out a few bytes short of its declared size.
 *
 * The tests that inflate a stream run twice: against a stand-in for dissect.util.compression.lzxpress_huffman
 * (tests/windows-stub-dissect.ts: the same loop and bit buffer, for the one code the encoder writes), always, and against the real
 * library where it is installed. A third test holds the stand-in to the real decoder.
 *
 * To see a test fail on the code it was written against: WINDOWS_PACK_TOOLS=<a copy of the tools before the fix>.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { AGENT, DISSECT, WIN, body, failed, py, stubModule, tool } from "./windows-pack-harness.ts";
import { RUN_1, SAMPLE_NAMES, mam, mamOf, sample, scca, xpressHuffman, type PrefetchOut, type ScanOut } from "./windows-prefetch-fixtures.ts";
import { DISSECT_STAND_IN } from "./windows-stub-dissect.ts";

type Decoder = { name: string; skip: string | false; env: (cwd: string) => Promise<Record<string, string>> };
const DECODERS: Decoder[] = [
  { name: "stand-in decoder", skip: false, env: (cwd) => stubModule(cwd, DISSECT_STAND_IN) },
  { name: "dissect.util", skip: DISSECT, env: async () => ({}) },
];

/** A test of a tool that inflates a stream, run against each decoder. */
function withDecoders(title: string, fn: (decoder: Decoder) => Promise<void>): void {
  for (const decoder of DECODERS) test(`${title} (${decoder.name})`, { skip: decoder.skip }, () => fn(decoder));
}

const TWO_RUNS = [RUN_1, RUN_1 + 10_000_000n, 0n, 0n, 0n, 0n, 0n, 0n];

// --- the run count, by the size of the file information --------------------------

for (const version of [26, 30, 31]) {
  for (const infoSize of [224, 216]) {
    const at = infoSize === 224 ? "0xD0" : "0xC8";
    test(`prefetch_mam reads a version ${version} file whose file information is ${infoSize} bytes: the run count at ${at}, the last runs at 0x80, the size reported`, async () => {
      // Every version 26, 30 and 31 file was read with its run count at 0xD0: a 216-byte file information put another field there.
      await withCwd(async (cwd) => {
        await writeFile(join(cwd, "work", "a.pf"), sample(version, { infoSize, runCount: 7 }));
        const out = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/a.pf" }));
        assert.equal(out.file_information_size, infoSize);
        assert.equal(out.run_count, 7, infoSize === 216 ? "the word at 0xD0 holds 3 and is not the run count" : undefined);
        assert.deepEqual(out.last_runs, ["2023-11-13T00:53:20.1234567Z", "2023-11-13T00:53:21.1234567Z"]);
        assert.equal(out.status, "complete");
        assert.deepEqual(out.filename_strings, SAMPLE_NAMES);
      });
    });
  }
}

test("prefetch_mam reads no run count and no last-run time from a file information size it does not know, and says what the size was", async () => {
  await withCwd(async (cwd) => {
    // The metrics array offset at 0x54 is 0x140 (a file information of 240 bytes), a layout neither known size describes.
    await writeFile(join(cwd, "work", "odd.pf"), sample(30, { metricsAt: 0x140 }));
    const odd = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/odd.pf" }));
    assert.equal(odd.file_information_size, 240);
    assert.equal(odd.run_count, null);
    assert.equal(odd.last_runs, undefined);
    assert.equal(odd.last_runs_detail, undefined);
    assert.equal(odd.status, "partial");
    assert.match(odd.problems.join("\n"), /file information size is 240 .*224 \(run count at 0xD0\) and 216 \(run count at 0xC8\).* not interpreted/);
    assert.equal(odd.exe_name, "EXAMPLE.EXE", "the version-independent header is still read");
    assert.deepEqual(odd.filename_strings, SAMPLE_NAMES, "the sections the first words of the file information locate do not depend on it");
    // A metrics array offset below the header gives no size at all.
    await writeFile(join(cwd, "work", "low.pf"), sample(30, { metricsAt: 0x20 }));
    const low = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/low.pf" }));
    assert.equal(low.run_count, null);
    assert.equal(low.status, "partial");
  });
});

test("prefetch_mam still reads versions 17 and 23 at their own positions, and reports their file information size too", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "v17.pf"), sample(17));
    await writeFile(join(cwd, "work", "v23.pf"), sample(23));
    const a = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/v17.pf" }));
    const b = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/v23.pf" }));
    assert.equal(a.run_count, 7);
    assert.equal(b.run_count, 7);
    assert.equal(a.file_information_size, 0x98 - 0x50);
    assert.equal(b.file_information_size, 0xf0 - 0x50);
    assert.deepEqual(a.last_runs, ["2023-11-13T00:53:20.1234567Z"]);
  });
});

withDecoders("mam_scan reads the run count of a record whose file information is 216 bytes, and one of 224, from the same dump", async (decoder) => {
  await withCwd(async (cwd) => {
    const pad = (n: number): Buffer => Buffer.alloc(n, 0x2e);
    const small = sample(30, { infoSize: 216, runCount: 9, exe: "SMALL.EXE" });
    const large = sample(30, { infoSize: 224, runCount: 4, exe: "LARGE.EXE" });
    await writeFile(join(cwd, "work", "mem.raw"), Buffer.concat([pad(100), mamOf(small), pad(60), mamOf(large), pad(100)]));
    const out = body<ScanOut>(await tool("mam_scan", cwd, { path: "work/mem.raw", min_uncomp: 200 }, await decoder.env(cwd)));
    assert.equal(out.parsed, 2);
    assert.equal(out.status, "complete");
    const byName = Object.fromEntries(out.hits.map((h) => [h.name, h]));
    assert.equal(byName["SMALL.EXE"].run_count, 9);
    assert.equal(byName["SMALL.EXE"].file_information_size, 216);
    assert.equal(byName["LARGE.EXE"].run_count, 4);
    assert.equal(byName["LARGE.EXE"].file_information_size, 224);
  });
});

// --- a stream that ends without padding ------------------------------------------

withDecoders("prefetch_mam inflates a stream that ends with its last data word, no padding after it: the symbols in the decoder's lookahead are still decoded", async (decoder) => {
  // dissect.util stopped when its read position reached the end of its input, with up to 32 bits of symbols not yet decoded:
  // a stream cut from a file (nothing after the last word) came out a few bytes short and was refused as "ended before its
  // declared uncompressed size". The suite's encoder used to end every stream with zero words, which hid it.
  await withCwd(async (cwd) => {
    const plain = sample(30);
    await writeFile(join(cwd, "work", "bare.pf"), mamOf(plain, { bare: true }));
    const out = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/bare.pf" }, await decoder.env(cwd)));
    assert.equal(out.status, "complete");
    assert.equal(out.container.declared_uncompressed_size, plain.length);
    assert.ok(out.container.decompressed_size! >= plain.length);
    assert.equal(out.run_count, 7);
    assert.deepEqual(out.filename_strings, SAMPLE_NAMES);
    assert.equal(out.file_size_matches, true, "the whole of the file came back, not all but its last bytes");
  });
});

withDecoders("mam_scan reads a stream that ends without padding at the very end of the dump", async (decoder) => {
  await withCwd(async (cwd) => {
    const plain = sample(30, { runCount: 11 });
    await writeFile(join(cwd, "work", "mem.raw"), Buffer.concat([Buffer.alloc(300, 0x2e), mamOf(plain, { bare: true })]));
    const out = body<ScanOut>(await tool("mam_scan", cwd, { path: "work/mem.raw", min_uncomp: 200 }, await decoder.env(cwd)));
    assert.equal(out.candidates, 1);
    assert.equal(out.failed, 0, JSON.stringify(out.failed_by_reason));
    assert.equal(out.parsed, 1);
    assert.equal(out.hits[0].run_count, 11);
    assert.equal(out.status, "complete");
  });
});

withDecoders("a stream that is genuinely short is still refused by both tools, with its sizes", async (decoder) => {
  await withCwd(async (cwd) => {
    const env = await decoder.env(cwd);
    await writeFile(join(cwd, "work", "short.pf"), mam(5000, xpressHuffman([...Buffer.alloc(100, 0x41)], { bare: true })));
    assert.match(failed(await tool("prefetch_mam", cwd, { path: "work/short.pf" }, env)).error, /ended before its declared uncompressed size/);
    await writeFile(join(cwd, "work", "mem.raw"), Buffer.concat([Buffer.alloc(64, 0x2e), mam(5000, xpressHuffman([...Buffer.alloc(100, 0x41)], { bare: true }))]));
    const out = body<ScanOut>(await tool("mam_scan", cwd, { path: "work/mem.raw", min_uncomp: 256 }, env));
    assert.deepEqual(out.failed_by_reason, { stream_ended_before_declared_size: 1 });
    assert.equal(out.status, "partial");
  });
});

test("the stand-in decodes the suite's streams exactly as dissect.util does, ends without padding included", { skip: DISSECT }, async () => {
  await withCwd(async (cwd) => {
    const files: string[] = [];
    const streams: Array<[string, Buffer]> = [
      ["padded", mamOf(sample(30)).subarray(8)],
      ["bare", mamOf(sample(30), { bare: true }).subarray(8)],
      ["matches", xpressHuffman([0x41, { match: 17 }, 0x42, { match: 3 }, { match: 9 }, 0x43], { bare: true })],
      ["two chunks", xpressHuffman([...Buffer.alloc(70_000, 0x5a)])],
      ["two chunks, bare", xpressHuffman([...Buffer.alloc(70_000, 0x5a)], { bare: true })],
    ];
    await mkdir(join(cwd, "streams"), { recursive: true });
    for (const [name, data] of streams) {
      const path = join(cwd, "streams", name.replace(/\W+/g, "_"));
      await writeFile(path, data);
      files.push(path);
    }
    const files2 = await stubModule(cwd, DISSECT_STAND_IN);
    const standIn = join(files2.PYTHONPATH, "dissect", "util", "compression", "lzxpress_huffman.py");
    const out = py(
      [
        "import importlib.util, sys",
        "spec = importlib.util.spec_from_file_location('standin', sys.argv[1])",
        "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
        "from dissect.util.compression import lzxpress_huffman as real",
        "for path in sys.argv[2:]:",
        "    data = open(path, 'rb').read()",
        "    a, b = m.decompress(data), real.decompress(data)",
        "    print(path.rsplit('/', 1)[-1], len(a), len(b), a == b)",
      ].join("\n"),
      standIn,
      ...files,
    );
    const rows = out.trim().split("\n").map((l) => l.split(" "));
    assert.equal(rows.length, streams.length);
    for (const [name, a, b, same] of rows) assert.equal(same, "True", `${name}: the stand-in gave ${a} bytes, dissect.util ${b}`);
  });
});

// --- the cap, the short stream, the unsupported variant: the tests that inflated only where dissect.util was installed -------

withDecoders("prefetch_mam inflates a MAM-compressed file to the same reading as the plain one, and says what the container held", async (decoder) => {
  await withCwd(async (cwd) => {
    const env = await decoder.env(cwd);
    const plain = sample(30);
    await writeFile(join(cwd, "work", "c.pf"), mamOf(plain));
    const out = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/c.pf" }, env));
    assert.equal(out.status, "complete");
    assert.equal(out.container.mam, true);
    assert.equal(out.container.declared_uncompressed_size, plain.length);
    assert.equal(out.container.decompressed_size! - out.container.bytes_past_declared_size!, plain.length);
    assert.ok(out.container.bytes_past_declared_size! < 64, "a few bytes past the declared size are the stream's own end");
    assert.deepEqual(out.filename_strings, SAMPLE_NAMES);
    assert.equal(out.run_count, 7);
    // A file larger than one 64 KiB chunk: several chunks of literals, each with its own table.
    const big = Buffer.concat([sample(30), Buffer.alloc(200_000, 0x5a)]);
    big.writeUInt32LE(big.length, 12);
    await writeFile(join(cwd, "work", "big.pf"), mamOf(big));
    const bigOut = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/big.pf" }, env));
    assert.equal(bigOut.container.declared_uncompressed_size, big.length);
    assert.deepEqual(bigOut.filename_strings, SAMPLE_NAMES);
  });
});

withDecoders("prefetch_mam stops a stream that inflates past its declared size at the cap, and does not hold the whole output", async (decoder) => {
  // The whole payload was decompressed before its size was looked at: a stream declared as 1 MiB could grow to any size, since
  // the decoder runs until its input ends. This one is declared 1 MiB and would inflate to about 100 MiB.
  await withCwd(async (cwd) => {
    const ops: Array<number | { match: number }> = [0x41];
    for (let i = 0; i < 6_000_000; i++) ops.push({ match: 17 });
    await writeFile(join(cwd, "work", "bomb.pf"), mam(1024 * 1024, xpressHuffman(ops)));
    const started = Date.now();
    const err = failed(await tool("prefetch_mam", cwd, { path: "work/bomb.pf" }, await decoder.env(cwd)));
    assert.match(err.error, /inflates past its declared size of 1048576 bytes plus 65536/);
    assert.equal(err.cap, 1048576 + 65536);
    assert.ok(Date.now() - started < 60_000, "the decoder was stopped at the cap, not run to the end of its input");
  });
});

withDecoders("prefetch_mam fails on a stream shorter than its declared size, and on a declared size past the cap", async (decoder) => {
  await withCwd(async (cwd) => {
    const env = await decoder.env(cwd);
    await writeFile(join(cwd, "work", "short.pf"), mam(5000, xpressHuffman([...Buffer.alloc(100, 0x41)])));
    assert.match(failed(await tool("prefetch_mam", cwd, { path: "work/short.pf" }, env)).error, /ended before its declared uncompressed size/);
    await writeFile(join(cwd, "work", "huge.pf"), mam(0xffffffff, Buffer.alloc(300)));
    const huge = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/huge.pf" }, env));
    assert.equal(huge.status, "unsupported");
    assert.match(huge.container.why ?? "", /past the 67108864 this tool will inflate/);
  });
});

withDecoders("mam_scan finds a record that straddles a scan window once, with the right offset, and reads it by its layout", async (decoder) => {
  await withCwd(async (cwd) => {
    const record = mamOf(sample(30));
    const junk = Buffer.alloc(4090, 0x2e);
    await writeFile(join(cwd, "work", "mem.raw"), Buffer.concat([junk, record, Buffer.alloc(5000, 0x2e)]));
    // chunk 4096: the record begins 6 bytes before the first window ends, so its header straddles it.
    const out = body<ScanOut>(await tool("mam_scan", cwd, { path: "work/mem.raw", chunk: 4096, min_uncomp: 256 }, await decoder.env(cwd)));
    assert.equal(out.count, 1);
    assert.equal(out.hits[0].offset, 4090);
    assert.equal(out.hits[0].name, "EXAMPLE.EXE");
    assert.equal(out.hits[0].run_count, 7);
    assert.deepEqual(out.hits[0].filename_strings, SAMPLE_NAMES);
    assert.equal(out.candidates, 1);
    assert.equal(out.failed, 0);
    assert.equal(out.status, "complete");
  });
});

withDecoders("mam_scan counts an unsupported version as parsed and unsupported, and every failure before the name filter drops anything", async (decoder) => {
  // A candidate that failed to decompress had no name, so a name filter dropped it without a trace; the fixed 0x80 and 0xD0
  // offsets were applied to every version.
  await withCwd(async (cwd) => {
    const env = await decoder.env(cwd);
    const v99 = sample(30);
    v99.writeUInt32LE(99, 0);
    const rubbish = mam(2048, Buffer.from("this is not an xpress huffman stream at all".repeat(20)));
    const other = scca({ version: 30, exe: "OTHER.EXE", hash: 1, runCount: 2, lastRuns: [RUN_1], names: ["\\VOLUME{x}\\OTHER.EXE"] });
    const pad = (n: number): Buffer => Buffer.alloc(n, 0x2e);
    const dump = Buffer.concat([pad(100), mamOf(sample(30)), pad(60), mamOf(v99), pad(60), rubbish, pad(60), mamOf(other), pad(60), Buffer.from("MAM\x84\x00\x10\x00\x00", "latin1"), pad(100)]);
    await writeFile(join(cwd, "work", "mem.raw"), dump);
    const all = body<ScanOut>(await tool("mam_scan", cwd, { path: "work/mem.raw", min_uncomp: 200 }, env));
    assert.equal(all.candidates, 4);
    assert.equal(all.parsed, 3);
    assert.equal(all.failed, 1);
    assert.equal(Object.keys(all.failed_by_reason).length, 1);
    assert.equal(all.failures.length, 1);
    assert.match(all.failures[0].reason, /^(decompress_failed|stream_ended_before_declared_size|not_prefetch)/);
    assert.equal(all.unsupported_variant_signatures, 1);
    assert.equal(all.status, "partial");
    const unsupported = all.hits.find((h) => h.version === 99);
    assert.ok(unsupported, "an unsupported version is a hit, not a drop");
    assert.equal(unsupported.supported, false);
    assert.equal(unsupported.run_count, undefined);
    assert.equal(unsupported.last_runs, undefined);
    // With a name filter, the failure is still counted.
    const filtered = body<ScanOut>(await tool("mam_scan", cwd, { path: "work/mem.raw", min_uncomp: 200, name_filter: "OTHER.EXE" }, env));
    assert.deepEqual(filtered.hits.map((h) => h.name), ["OTHER.EXE"]);
    assert.equal(filtered.parsed, 3);
    assert.equal(filtered.failed, 1, "the record that could not be read is counted, not lost to the filter");
    assert.equal(filtered.filtered_by_name, 2);
  });
});

withDecoders("mam_scan stops a candidate whose payload inflates past its declared size at that size", async (decoder) => {
  await withCwd(async (cwd) => {
    const ops: Array<number | { match: number }> = [0x41];
    for (let i = 0; i < 2_000_000; i++) ops.push({ match: 17 });
    await writeFile(join(cwd, "work", "mem.raw"), Buffer.concat([Buffer.alloc(64, 0x2e), mam(4096, xpressHuffman(ops)), Buffer.alloc(64, 0x2e)]));
    const started = Date.now();
    const out = body<ScanOut>(await tool("mam_scan", cwd, { path: "work/mem.raw", min_uncomp: 256 }, await decoder.env(cwd)));
    assert.equal(out.candidates, 1);
    assert.deepEqual(out.failed_by_reason, { not_prefetch: 1 });
    assert.ok(Date.now() - started < 30_000);
  });
});

// --- a file that cannot be read, arguments that are not an object -----------------

test("prefetch_mam and mam_scan answer a file they cannot read with a JSON failure, not a traceback", async (t) => {
  if (process.getuid && process.getuid() === 0) return t.skip("root reads a mode 000 file");
  await withCwd(async (cwd) => {
    const path = join(cwd, "work", "locked.pf");
    await writeFile(path, sample(30));
    await chmod(path, 0o000);
    try {
      assert.match(failed(await tool("prefetch_mam", cwd, { path: "work/locked.pf" })).error, /the file cannot be read: .*(Permission denied|EACCES)/i);
      assert.match(failed(await tool("mam_scan", cwd, { path: "work/locked.pf" })).error, /the source could not be read: .*(Permission denied|EACCES)/i);
    } finally {
      await chmod(path, 0o644);
    }
  });
});

test("mam_scan refuses arguments that are not a JSON object, as JSON", async () => {
  await withCwd(async (cwd) => {
    assert.match(failed(await tool("mam_scan", cwd, ["work/x"])).error, /arguments must be a JSON object/);
  });
});

// --- memory ------------------------------------------------------------------------

// The peak of what the tool allocates through Python's allocators (tracemalloc), not the process's resident size: the same code
// peaks at a very different resident size on macOS and on Linux (the C allocator keeps or returns freed windows differently), and
// what this holds the tool to is that it keeps one window at a time.
const PEAK_ALLOCATED = [
  "import runpy, sys, tracemalloc",
  "tracemalloc.start()",
  "try:",
  "    runpy.run_path(sys.argv[1], run_name='__main__')",
  "finally:",
  "    sys.stderr.write('PEAK_ALLOCATED=%d\\n' % tracemalloc.get_traced_memory()[1])",
].join("\n");

test("mam_scan reads a window into one buffer: three windows of 32 MiB peak well under twice a window, not at a copy or two of each", async () => {
  // A window was read, then joined to the bytes carried from the last one (a second copy of it), and the next window was
  // allocated while the last was still held: a window of 256 MiB peaked at about three times that.
  await withCwd(async (cwd) => {
    const MiB = 1024 * 1024;
    await writeFile(join(cwd, "work", "big.raw"), Buffer.alloc(96 * MiB, 0x2e));
    const run = spawnSync("python3", ["-c", PEAK_ALLOCATED, join(WIN, "mam_scan", "run.py")], {
      cwd,
      input: JSON.stringify({ path: "work/big.raw", chunk: 32 * MiB }),
      env: { ...process.env, ...AGENT },
      encoding: "utf8",
    });
    assert.equal(run.status, 0, run.stderr);
    const answer = JSON.parse(run.stdout) as { scanned_to: number; count: number; status: string };
    assert.equal(answer.scanned_to, 96 * MiB);
    assert.equal(answer.status, "complete");
    const peak = Number(/PEAK_ALLOCATED=(\d+)/.exec(run.stderr)![1]);
    assert.ok(peak < 1.5 * 32 * MiB + 24 * MiB, `the scan allocated ${(peak / MiB).toFixed(0)} MiB at its peak`);
  });
});
