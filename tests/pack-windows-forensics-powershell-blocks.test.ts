/**
 * powershell_blocks: Script Block Logging records (event 4104) reassembled into blocks. The fixtures are built to the layout the log
 * documents (EventData names MessageNumber, MessageTotal, ScriptBlockText, ScriptBlockId, Path; Computer, Channel and Level in System), as
 * JSON Lines rows shaped like evtx_query's and as real EVTX bytes (tests/windows-stub-evtx.ts: python-evtx cannot be installed on a CI host).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN, body, failed, stubModule, tool } from "./windows-pack-harness.ts";
import { assertStopped, jobEnv, runTool, scriptOf, stopAt, withDeadline } from "./windows-tool-contract.ts";
import { CHUNK_BYTES, EVTX_CARVE_STUB, evtxChunk, evtxFileHeader, ps4104Xml } from "./windows-stub-evtx.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Row = Record<string, unknown>;

const WINPS = "Microsoft-Windows-PowerShell/Operational";
const CORE = "PowerShellCore/Operational";
const sid = (n: number): string => `${n.toString(16).padStart(8, "0")}-2222-3333-4444-555555555555`;

/** A row as evtx_query writes it for a 4104 record. */
function frag(number: number, total: number, o: { id?: string; text?: string; computer?: string; channel?: string; rec?: number; path?: string; level?: number; eid?: number } = {}): Row {
  const text = o.text ?? `part${number}`;
  return {
    event_id: o.eid ?? 4104, channel: o.channel ?? WINPS, computer: o.computer ?? "WS01", record_id: o.rec ?? number, record_offset: 5000 + number * 100, chunk_offset: 4096,
    data: { MessageNumber: String(number), MessageTotal: String(total), ScriptBlockId: o.id ?? sid(1), ScriptBlockText: text, Path: o.path ?? "" },
    xml: `<Event><System><Level>${o.level ?? 5}</Level></System></Event>`,
  };
}

async function put(cwd: string, rows: Row[], name = "in.jsonl"): Promise<string> {
  await mkdir(join(cwd, "work"), { recursive: true });
  await writeFile(join(cwd, "work", name), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  return `work/${name}`;
}

async function run(cwd: string, args: Row, env: Record<string, string> = {}): Promise<Answer> {
  return body<Answer>(await tool("powershell_blocks", cwd, args, env));
}

const blockOf = (out: Answer, id = sid(1), computer = "WS01", source = "windows_powershell"): Answer => {
  const found = out.blocks.filter((b: Answer) => b.script_block_id === id && b.computer === computer && b.source === source);
  assert.equal(found.length, 1, `one block for ${id}/${computer}/${source}`);
  return found[0];
};

const rowsOf = async (cwd: string, shown: string): Promise<Answer[]> =>
  (await readFile(join(cwd, shown), "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as Answer);

/** A copy of the tool with one constant changed (the line is `NAME = <value>` and a space or a comment follows). */
function withConstant(name: string, value: number): string {
  const text = readFileSync(scriptOf("powershell_blocks"), "utf8");
  const pattern = new RegExp(`^${name} = \\d+(?=[ #])`, "m");
  assert.match(text, pattern, `${name} is a constant of the tool`);
  const dir = join(withDeadline("powershell_blocks", 54), "..");
  const copy = join(dir, "run.py");
  writeFileSync(copy, text.replace(pattern, `${name} = ${value}`));
  return copy;
}

// --- the block's own arithmetic -----------------------------------------------------------------------------------

test("a block of one fragment is complete, with the record id and offset of its part", async () => {
  await withCwd(async (cwd) => {
    const out = await run(cwd, { path: await put(cwd, [frag(1, 1, { rec: 77, path: "C:\\scripts\\a.ps1", level: 3 })]) });
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.input_format, "jsonl");
    assert.equal(out.block_count, 1);
    const b = blockOf(out);
    assert.equal(b.block_status, "complete");
    assert.equal(b.expected_fragments, 1);
    assert.deepEqual(b.records, [[77, 5100]]);
    assert.deepEqual(b.paths, ["C:\\scripts\\a.ps1"]);
    assert.deepEqual(b.levels, [3]);
    assert.equal(b.auto_logged_warning, true, "Level 3 is a Warning: PowerShell logged the block by itself");
    assert.equal(b.text_length, "part1".length);
  });
});

test("seven fragments in order and shuffled are one complete block, in the order of MessageNumber", async () => {
  await withCwd(async (cwd) => {
    const inOrder = [1, 2, 3, 4, 5, 6, 7].map((n) => frag(n, 7));
    const shuffled = [5, 2, 7, 1, 6, 3, 4].map((n) => frag(n, 7, { rec: 100 + n }));
    const a = await run(cwd, { path: await put(cwd, inOrder, "a.jsonl") });
    const b = await run(cwd, { path: await put(cwd, shuffled, "b.jsonl") });
    for (const out of [a, b]) {
      assert.equal(out.status, "complete", out.status_basis);
      assert.equal(blockOf(out).fragment_count, 7);
      assert.equal(blockOf(out).numbers_distinct, 7);
      assert.equal(blockOf(out).missing_count, 0);
    }
    assert.deepEqual(blockOf(b).records.map((r: number[]) => r[0]), [101, 102, 103, 104, 105, 106, 107], "the parts are listed by MessageNumber, not by arrival");
    const parts = await rowsOf(cwd, b.fragments_file);
    assert.deepEqual(parts.map((p) => p.message_number), [1, 2, 3, 4, 5, 6, 7]);
    assert.deepEqual(parts.map((p) => p.arrival), [4, 2, 6, 7, 1, 5, 3], "and the arrival order is kept beside it");
  });
});

test("a missing fragment is gaps with the numbers as ranges, and the answer is partial and says so", async () => {
  await withCwd(async (cwd) => {
    const out = await run(cwd, { path: await put(cwd, [1, 2, 5, 7].map((n) => frag(n, 8))) });
    const b = blockOf(out);
    assert.equal(b.block_status, "gaps");
    assert.deepEqual(b.missing_ranges, [[3, 4], [6, 6], [8, 8]]);
    assert.equal(b.missing_count, 4);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /1 block\(s\) have fragments missing/);
    assert.equal(out.blocks_by_status.gaps, 1);
  });
});

test("a duplicate with the same text and one with different text are told apart", async () => {
  await withCwd(async (cwd) => {
    const same = [frag(1, 2), frag(2, 2), frag(2, 2, { rec: 90 })];
    const differs = [frag(1, 2, { id: sid(2) }), frag(2, 2, { id: sid(2) }), frag(2, 2, { id: sid(2), rec: 91, text: "other" })];
    const out = await run(cwd, { path: await put(cwd, [...same, ...differs]) });
    const a = blockOf(out, sid(1));
    assert.equal(a.block_status, "complete", "a copy that says the same is noted, not a conflict");
    assert.equal(out.status, "partial", "the other block conflicts");
    const only = await run(cwd, { path: await put(cwd, same, "same.jsonl") });
    assert.equal(only.status, "complete");
    assert.match(only.status_basis, /1 extra copy\(ies\) of equal text are listed under duplicates/, "an answer with a duplicate does not say every fragment is there once");
    assert.doesNotMatch(only.status_basis, /once each/);
    assert.deepEqual(a.duplicates, [{ message_number: 2, records: 2, same_text: true }]);
    const b = blockOf(out, sid(2));
    assert.equal(b.block_status, "conflict");
    assert.deepEqual(b.duplicates, [{ message_number: 2, records: 2, same_text: false }]);
    assert.equal(b.unequal_copies, 1);
    const parts = (await rowsOf(cwd, out.fragments_file)).filter((p) => p.block === b.block && p.message_number === 2);
    assert.deepEqual(parts.map((p) => p.same_text_as_first), [null, false]);
    assert.deepEqual(b.records.map((r: number[]) => r[0]), [1, 2, 91], "the copy is a part of the block too, listed after the first");
  });
});

test("MessageTotal values that disagree, and a number past the total, are a conflict", async () => {
  await withCwd(async (cwd) => {
    const out = await run(cwd, { path: await put(cwd, [frag(1, 3), frag(2, 4), frag(3, 3), frag(1, 2, { id: sid(2) }), frag(5, 2, { id: sid(2) })]) });
    const a = blockOf(out, sid(1));
    assert.equal(a.block_status, "conflict");
    assert.equal(a.expected_fragments, null, "no single total is claimed");
    assert.deepEqual(a.message_totals, [3, 4]);
    const b = blockOf(out, sid(2));
    assert.equal(b.block_status, "conflict");
    assert.equal(b.numbers_out_of_range, 1);
  });
});

test("one ScriptBlockId on two computers is two blocks, and the two PowerShell channels are kept apart", async () => {
  await withCwd(async (cwd) => {
    const out = await run(cwd, { path: await put(cwd, [frag(1, 1, { computer: "WS01" }), frag(1, 1, { computer: "WS02" }), frag(1, 1, { channel: CORE })]) });
    assert.equal(out.block_count, 3);
    assert.deepEqual(out.blocks_by_source, { windows_powershell: 2, powershell_core: 1 });
    blockOf(out, sid(1), "WS01");
    blockOf(out, sid(1), "WS02");
    assert.equal(blockOf(out, sid(1), "WS01", "powershell_core").channel, CORE);
  });
});

test("other events are counted and left out, and a 4104 without usable numbers is named, not grouped", async () => {
  await withCwd(async (cwd) => {
    const bad = frag(1, 2, { id: sid(3) });
    (bad.data as Row).MessageNumber = "first";
    const out = await run(cwd, { path: await put(cwd, [frag(1, 1), frag(1, 1, { eid: 4688 }), bad]) });
    assert.equal(out.records_examined, 3);
    assert.equal(out.records_other_events, 1);
    assert.equal(out.fragments_malformed, 1);
    assert.equal(out.block_count, 1);
    assert.equal(out.status, "partial");
    assert.match(out.problems[0].why, /not grouped/);
  });
});

// --- hostile content -----------------------------------------------------------------------------------------------

test("text that is not UTF-8 is kept and counted, and a 1 MB fragment is read without the answer growing", async () => {
  await withCwd(async (cwd) => {
    const lone = frag(1, 2, { id: sid(1) });
    (lone.data as Row).ScriptBlockText = "ok \ud800 not utf-8";
    const big = frag(1, 1, { id: sid(2), text: "A".repeat(1 << 20) });
    const small = await run(cwd, { path: await put(cwd, [lone, frag(2, 2), frag(1, 1, { id: sid(2), text: "A" })], "s.jsonl") });
    const out = await run(cwd, { path: await put(cwd, [lone, frag(2, 2), big], "b.jsonl") });
    assert.equal(out.fragments_with_unpaired_surrogates, 1);
    assert.equal(blockOf(out, sid(2)).text_length, 1 << 20);
    assert.equal(blockOf(small, sid(2)).text_length, 1);
    assert.ok(JSON.stringify(out).length - JSON.stringify(small).length < 200, "the answer holds a length, never the text");
  });
});

test("a canary in a fragment, a path or a computer name never reaches the answer, stderr, a file or a name", async () => {
  await withCwd(async (cwd) => {
    const secret = "ghp_" + "Q8x2LmN4pR7sT1vW3yZ5bC9dF6gH0jK2aE4u";
    const plain = "CANARY-7f3a91c2-script-text";
    const rows = [frag(1, 2, { text: `Invoke-X -Token ${secret} # ${plain}`, path: `C:\\u\\${secret}\\a.ps1` }), frag(2, 2, { text: plain, computer: "WS01" }), frag(1, 1, { id: sid(2), computer: "H-" + secret })];
    const first = await tool("powershell_blocks", cwd, { path: await put(cwd, rows) });
    const out = body<Answer>(first);
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name);
        files.push(p);
        if (e.isDirectory()) walk(p);
      }
    };
    walk(join(cwd, "work", "s1"));
    const everything = [first.stdout, first.stderr, ...files, ...files.filter((f) => statSync(f).isFile()).map((f) => readFileSync(f, "utf8"))].join("\n");
    for (const needle of [secret, secret.slice(4, 24), plain]) assert.ok(!everything.includes(needle), `${needle.slice(0, 8)}... reached an output: ${everything.slice(Math.max(0, everything.indexOf(needle) - 200), everything.indexOf(needle) + 100)}`);
    assert.ok(out.boundary.strings_withheld >= 2, "the path and the computer name were withheld by the boundary, and the answer says how many");
    // the size of the answer does not depend on what the text says, only on how long it is
    const twin = rows.map((r) => JSON.parse(JSON.stringify(r)) as Row);
    for (const r of twin) (r.data as Row).ScriptBlockText = String((r.data as Row).ScriptBlockText).replace(/[A-Za-z]/g, "x");
    const other = body<Answer>(await tool("powershell_blocks", cwd, { path: await put(cwd, twin, "twin.jsonl") }));
    assert.equal(JSON.stringify(other.blocks.map((b: Answer) => [b.text_length, b.text_bytes])), JSON.stringify(out.blocks.map((b: Answer) => [b.text_length, b.text_bytes])));
  });
});

test("a fragment whose text evtx_query withheld is counted, and its block is not taken for the evidence's text", async () => {
  await withCwd(async (cwd) => {
    const out = await run(cwd, { path: await put(cwd, [frag(1, 2, { text: "<withheld 40 characters: token-shaped text>" }), frag(2, 2)]) });
    assert.equal(out.fragments_text_withheld_upstream, 1);
    assert.equal(blockOf(out).text_withheld_upstream, 1);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /withheld/);
  });
});

// --- write_text, a secret output ----------------------------------------------------------------------------------

test("write_text is refused outside a secret-output job, as JSON, before anything is made", async () => {
  await withCwd(async (cwd) => {
    const path = await put(cwd, [frag(1, 1)]);
    for (const env of [{}, { JOB_ID: "j1", OUT: join(cwd, "out") }, { SECRET_OUTPUT: "1" }] as Array<Record<string, string>>) {
      const out = failed(await tool("powershell_blocks", cwd, { path, write_text: true }, env));
      assert.match(out.error, /write_text is refused/);
      assert.equal((out as Answer).status, "failed");
    }
    assert.deepEqual(await readdir(join(cwd, "work")), ["in.jsonl"], "nothing was made");
    await assert.rejects(readdir(join(cwd, "out")));
  });
});

test("in a secret-output job write_text writes the text, 0600, block by block in number order, and leaves no spool", async () => {
  await withCwd(async (cwd) => {
    const text = (n: number): string => `line${n} "quoted" \\ back\n\ttab \u00e9 \ud800`;
    const rows = [3, 1, 2].map((n) => frag(n, 3, { text: text(n) }));
    rows.push(frag(1, 2, { id: sid(2), text: "only first" }));
    const env: Record<string, string> = { ...jobEnv(cwd), SECRET_OUTPUT: "1" };
    const out = await run(cwd, { path: await put(cwd, rows), write_text: true }, env);
    assert.equal(out.text_written, 2);
    assert.match(out.text_file, /^store\/jobs\/j000001\/out\/tool-output\/powershell_blocks-text-[0-9a-f]{16}\.jsonl$/);
    const file = join(env.OUT, "tool-output", out.text_file.split("/").pop() as string);
    assert.equal(statSync(file).mode & 0o777, 0o600, "mode 0600");
    const lines = readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Answer);
    assert.equal(lines.length, 2);
    assert.equal(lines[0].text, text(1) + text(2) + text(3), "the first copy of every number, in the order of MessageNumber");
    assert.equal(lines[0].block_status, "complete");
    assert.equal(lines[1].text, "only first");
    assert.equal(lines[1].block_status, "gaps");
    const hidden: string[] = [];
    for (const dir of [env.OUT, join(env.OUT, "tool-output")]) for (const e of readdirSync(dir)) if (e.startsWith(".")) hidden.push(e);
    assert.deepEqual(hidden, [], "no spool or temporary file is left");
    assert.ok(!JSON.stringify(out).includes("line1"), "the answer holds no text");
  });
});

// --- an .evtx file -------------------------------------------------------------------------------------------------

async function putLog(cwd: string, records: Array<{ number: number; xml: string }>, perChunk = 40): Promise<Record<string, string>> {
  const env = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_CARVE_STUB });
  const chunks: Buffer[] = [];
  for (let i = 0; i < records.length; i += perChunk) chunks.push(evtxChunk(records.slice(i, i + perChunk)));
  await writeFile(join(cwd, "work", "ps.evtx"), Buffer.concat([evtxFileHeader(chunks.length, records.length + 1), ...chunks]));
  await writeFile(join(cwd, "work", "ps.evtx.inject.json"), "{}");
  return env;
}

test("an .evtx file is read through the chunk code: blocks, other events, the Level, and the record offsets", async () => {
  await withCwd(async (cwd) => {
    const recs = [
      { number: 1, xml: ps4104Xml({ id: sid(1), rec: 1, number: 2, total: 3, text: "b & <c>", level: 3 }) },
      { number: 2, xml: ps4104Xml({ id: sid(1), rec: 2, number: 1, total: 3, text: "a" }) },
      { number: 3, xml: ps4104Xml({ id: sid(1), rec: 3, number: 3, total: 3, text: "c" }) },
      { number: 4, xml: ps4104Xml({ rec: 4, number: 1, total: 1, id: sid(2), channel: CORE, computer: "WS09" }) },
      { number: 5, xml: ps4104Xml({ rec: 5, number: 1, total: 1, id: sid(3), eid: 4103 }) },
    ];
    const env = await putLog(cwd, recs);
    const out = await run(cwd, { path: "work/ps.evtx" }, env);
    assert.equal(out.input_format, "evtx");
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.chunks_read, 1);
    assert.equal(out.records_examined, 5);
    assert.equal(out.records_other_events, 1);
    const b = blockOf(out);
    assert.equal(b.block_status, "complete");
    assert.deepEqual(b.levels, [3, 5]);
    assert.deepEqual(b.records.map((r: number[]) => r[0]), [2, 1, 3], "by MessageNumber");
    assert.ok(b.records.every((r: number[]) => r[1] >= 4096 + 0x200), "the byte offset of each record is in the file, past the first chunk header");
    assert.equal(blockOf(out, sid(2), "WS09", "powershell_core").block_status, "complete");
  });
});

test("an .evtx with a chunk that has no signature, and one cut short, is partial and names the chunk", async () => {
  await withCwd(async (cwd) => {
    const env = await putLog(cwd, [1, 2, 3].map((n) => ({ number: n, xml: ps4104Xml({ rec: n, number: n, total: 3 }) })));
    const file = join(cwd, "work", "ps.evtx");
    const data = readFileSync(file);
    writeFileSync(file, Buffer.concat([evtxFileHeader(2, 4), data.subarray(4096), Buffer.alloc(CHUNK_BYTES)]));
    const out = await run(cwd, { path: "work/ps.evtx" }, env);
    assert.equal(out.status, "partial");
    assert.equal(out.chunks_declared, 2);
    assert.equal(out.chunks_not_read, 1);
    assert.ok(out.problems.some((p: Answer) => /no ElfChnk signature/.test(p.why) && p.chunk_offset === 4096 + CHUNK_BYTES));
  });
});

// --- the paths and the clock ----------------------------------------------------------------------------------------

test("a FIFO, a directory and a missing file are refused as JSON without waiting; a link to a file is read", async () => {
  await withCwd(async (cwd) => {
    const path = await put(cwd, [frag(1, 1)]);
    spawnSync("mkfifo", [join(cwd, "work", "pipe.jsonl")]);
    mkdirSync(join(cwd, "work", "dir.jsonl"));
    spawnSync("ln", ["-s", "in.jsonl", join(cwd, "work", "link.jsonl")]);
    const started = Date.now();
    for (const p of ["work/pipe.jsonl", "work/dir.jsonl", "work/missing.jsonl"]) assert.match(failed(await tool("powershell_blocks", cwd, { path: p })).error, /regular file|could not be opened/);
    assert.ok(Date.now() - started < 10_000, "no read waited on a FIFO");
    assert.equal((await run(cwd, { path: "work/link.jsonl" })).block_count, 1);
    assert.equal((await run(cwd, { path })).block_count, 1);
  });
});

test("arguments of the wrong type are refused as JSON", async () => {
  await withCwd(async (cwd) => {
    const path = await put(cwd, [frag(1, 1)]);
    for (const bad of [{ path: 5 }, { path, limit: "x" }, { path, limit: 0 }, { path, limit: true }, { path, write_text: "yes" }, { path, input_format: "xml" }, { path, write_values: 1 }, {}]) {
      const out = failed(await tool("powershell_blocks", cwd, bad));
      assert.equal((out as Answer).status, "failed");
    }
    assert.match(failed(await tool("powershell_blocks", cwd, { path, input_format: "evtx" })).error, /not an EVTX file/);
    const raw = await runTool("powershell_blocks", cwd, undefined, {}, "not json");
    assert.equal(raw.code, 1);
    assert.equal(JSON.parse(raw.stdout).status, "failed");
  });
});

test("a clock that runs out ends the read with a partial answer that names it", async () => {
  await withCwd(async (cwd) => {
    const path = await put(cwd, [1, 2, 3].map((n) => frag(n, 3)));
    const copy = withDeadline("powershell_blocks", 0);
    const done = await runTool(copy, cwd, { path });
    const out = JSON.parse(done.stdout) as Answer;
    assert.equal(done.code, 0, done.stderr);
    assert.equal(out.status, "partial");
    assert.equal(out.stopped_by_time, true);
    assert.match(out.status_basis, /clock/);
  });
});

test("more fragments than the tool keeps is partial and names how many were not kept", async () => {
  await withCwd(async (cwd) => {
    const rows = Array.from({ length: 60 }, (_, i) => frag(i + 1, 60));
    const out = JSON.parse((await runTool(withConstant("MAX_FRAGMENTS", 50), cwd, { path: await put(cwd, rows) })).stdout) as Answer;
    assert.equal(out.fragments_kept, 50);
    assert.equal(out.fragments_not_kept, 10);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /10 fragment\(s\) were not kept/);
    assert.equal(blockOf(out).missing_count, 10, "and the block says what it lacks");
  });
});

test("100,000 fragments of one block are read inside the clock and the answer stays small", async () => {
  await withCwd(async (cwd) => {
    const n = 100_000;
    const lines: string[] = [];
    for (let i = 1; i <= n; i++) lines.push(JSON.stringify(frag(i, n, { text: "x" })));
    await writeFile(join(cwd, "work", "big.jsonl"), lines.join("\n") + "\n");
    const started = Date.now();
    const first = await tool("powershell_blocks", cwd, { path: "work/big.jsonl", limit: 5 });
    const out = body<Answer>(first);
    assert.ok(Date.now() - started < 58_000, "inside the manifest's 60 seconds");
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.fragments_kept, n);
    assert.ok(first.stdout.length < 20_000, "the answer does not grow with the fragments");
    assert.equal((await rowsOf(cwd, out.fragments_file)).length, n, "and the file holds every fragment");
  });
});

test("the clock for listing blocks ends the loop: the blocks not listed are counted and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const rows = Array.from({ length: 40 }, (_, i) => frag(1, 1, { id: sid(i + 1) }));
    const path = await put(cwd, rows);
    const out = JSON.parse((await runTool(withConstant("OUTPUT_SECONDS", 0), cwd, { path })).stdout) as Answer;
    assert.equal(out.block_count, 40);
    assert.equal(out.blocks_not_listed, 40);
    assert.equal(out.blocks_listed, 0);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /40 of 40 block\(s\) were not listed/);
  });
});

test("two other channels with one Computer and ScriptBlockId are one block that shows both channels", async () => {
  await withCwd(async (cwd) => {
    const out = await run(cwd, { path: await put(cwd, [frag(1, 2, { channel: "Other/A" }), frag(2, 2, { channel: "Other/B" })]) });
    assert.equal(out.block_count, 1);
    assert.deepEqual(out.blocks[0].channels, ["Other/A", "Other/B"]);
    assert.equal(out.blocks[0].source, "other");
  });
});

// --- stops ----------------------------------------------------------------------------------------------------------

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
  test(`${signal} while the files are being written ends the run with JSON, exit 128 plus the signal, and no hidden file`, async () => {
    await withCwd(async (cwd) => {
      const n = 30_000;
      const rows = Array.from({ length: n }, (_, i) => frag(1, 1, { id: sid(i + 1), computer: "WS" + (i % 50) }));
      const path = await put(cwd, rows);
      const stopped = await stopAt("powershell_blocks", { path, limit: 1 }, {}, "temp", signal, { cwd });
      const { answered, answer } = assertStopped(stopped, signal);
      assert.ok(answered, "the signal was answered");
      assert.equal(answer.interrupted, true);
    });
  });
}

test("a signal while the tool is secret-output spooling removes the spool and the text file", async () => {
  await withCwd(async (cwd) => {
    const n = 20_000;
    const rows = Array.from({ length: n }, (_, i) => frag(1, 1, { id: sid(i + 1), text: "t".repeat(200) }));
    const path = await put(cwd, rows);
    const env: Record<string, string> = { ...jobEnv(cwd), SECRET_OUTPUT: "1" };
    const stopped = await stopAt("powershell_blocks", { path, limit: 1, write_text: true }, env, "temp", "SIGTERM", { cwd });
    assertStopped(stopped, "SIGTERM");
  });
});

// --- twins and registration ------------------------------------------------------------------------------------------

test("the tool's manifest says what the code does", async () => {
  const manifest = JSON.parse(await readFile(join(WIN, "powershell_blocks", "manifest.json"), "utf8")) as Answer;
  assert.equal(manifest.version, 4);
  assert.ok(manifest.timeout_seconds >= 60);
  assert.deepEqual(manifest.secret_output, { when_args: ["write_text", "write_values"] });
  const text = await readFile(join(WIN, "powershell_blocks", "run.py"), "utf8");
  assert.match(text, /^PARSER = "powershell_blocks\/1"/m);
  assert.match(text, /^DEADLINE_SECONDS = 54 /m);
  assert.ok(manifest.timeout_seconds > 54);
  for (const name of Object.keys(manifest.params)) assert.match(text, new RegExp(`"${name}"`), `${name} is read by the tool`);
});
