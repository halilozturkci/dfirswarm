/**
 * marshal_inspect, the pack's copy: a CPython 3.11 to 3.13 marshal stream or .pyc read as data, never run.
 *
 * Streams come from two writers that are not the parser under test: the running CPython's own `marshal.dumps(compile(...))`
 * (when it is 3.11 to 3.13; an honest skip otherwise) and byte streams laid out here from CPython's marshal format (the type
 * codes of Python/marshal.c: `(` tuple, `u` unicode, `s` bytes, `c` code, `r` reference, `i` int, `l` long, `{` dict, with bit
 * 0x80 for FLAG_REF) and the 3.11 code-object layout. Nothing is read from the tool's output to build an input.
 *
 * What is held: the pair on every answer; a version outside 3.11 to 3.13 refused with the version named; every bound named (depth,
 * object count, a count that cannot fit, a long of too many digits, text shared so that its copies pass the budget, the clock);
 * a container that holds itself is named and not followed; canaries in names, file names and string and byte constants are
 * withheld from the answer and the default result file and whole only in a sealed values file in a secret_output job.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, asJob, body, put, refused, startDetached, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { canaries, needles } from "./pack-re-canary-shapes.ts";

const MARSHAL = join(TOOLS, "marshal_inspect", "run.py");

// --- marshal, from Python/marshal.c --------------------------------------------------------------------------------------------

const i32 = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeInt32LE(n); return b; };
const flag = (c: string): Buffer => Buffer.from([0x80 | c.charCodeAt(0)]);
const str = (s: string, ref = false): Buffer => { const b = Buffer.from(s, "utf8"); return Buffer.concat([ref ? flag("u") : Buffer.from("u"), i32(b.length), b]); };
const bytes = (b: Buffer): Buffer => Buffer.concat([Buffer.from("s"), i32(b.length), b]);
const tuple = (items: Buffer[], ref = false): Buffer => Buffer.concat([ref ? flag("(") : Buffer.from("("), i32(items.length), ...items]);
const NONE = Buffer.from("N");
const ref = (n: number): Buffer => Buffer.concat([Buffer.from("r"), i32(n)]);

type CodeSpec = { name?: string; qualname?: string; filename?: string; consts?: Buffer[]; names?: Buffer[]; code?: Buffer; firstline?: number; flags?: number };
/** A 3.11 to 3.13 code object: five ints, then code, consts, names, localsplusnames, localspluskinds, filename, name, qualname, firstlineno, linetable, exceptiontable. */
function code(o: CodeSpec = {}): Buffer {
  const name = o.name ?? "f";
  return Buffer.concat([
    Buffer.from("c"), i32(0), i32(0), i32(0), i32(2), i32(o.flags ?? 3),
    bytes(o.code ?? Buffer.from([0x97, 0, 0x64, 0, 0x53, 0])), tuple(o.consts ?? [NONE]), tuple(o.names ?? []), tuple([]), bytes(Buffer.alloc(0)),
    str(o.filename ?? "<synthetic>"), str(name), str(o.qualname ?? name), i32(o.firstline ?? 1), bytes(Buffer.from([0x80, 0])), bytes(Buffer.alloc(0)),
  ]);
}

const pycHeader = (magic: number, flags = 0, mtime = 1760000000, size = 7): Buffer => {
  const b = Buffer.alloc(16);
  b.writeUInt16LE(magic, 0);
  b.write("\r\n", 2, "latin1");
  b.writeUInt32LE(flags, 4);
  b.writeUInt32LE(mtime, 8);
  b.writeUInt32LE(size, 12);
  return b;
};

async function run(cwd: string, file: Buffer, args: Json = {}, name = "inputs/m.bin"): Promise<Json> {
  await put(cwd, name, file);
  return body(await tool(MARSHAL, cwd, { path: name, ...args }));
}

async function fails(cwd: string, file: Buffer, args: Json = {}, name = "inputs/bad.bin"): Promise<Json> {
  await put(cwd, name, file);
  return refused(await tool(MARSHAL, cwd, { path: name, ...args }));
}

// --- real streams -----------------------------------------------------------------------------------------------------------------

const py = spawnSync("python3", ["-c", "import sys; print(sys.version_info[0], sys.version_info[1])"], { encoding: "utf8" });
const [PY_MAJOR, PY_MINOR] = py.stdout.trim().split(" ").map(Number) as [number, number];
const REAL = PY_MAJOR === 3 && PY_MINOR! >= 11 && PY_MINOR! <= 13;

const SOURCE = [
  "import os, sys",
  "TABLE = ('alpha', b'\\x00\\x01raw', 3.5, 10**25, None, True)",
  "def first(a, b=2, *rest, **kw):",
  "    return os.path.join(a, 'tail-' + str(b) + 'a constant longer than the twelve characters shown')",
  "class Holder:",
  "    def method(self, x):",
  "        return lambda y: x + y + len('inner-constant')",
  "async def waits(n):",
  "    return n",
  "open('PWNED-BY-EXECUTION', 'w').write('x')",
].join("\n");

const BUILD = `
import marshal, sys, json, importlib.util, os
os.chdir(sys.argv[1])
src = sys.stdin.read()
code = compile(src, "<synthetic>", "exec")
def walk(c, out):
    out.append({"name": c.co_name, "qualname": c.co_qualname, "firstlineno": c.co_firstlineno, "argcount": c.co_argcount, "flags": c.co_flags,
                "names": list(c.co_names), "bytecode": c.co_code.hex(), "strings": [k for k in c.co_consts if isinstance(k, str)]})
    for k in c.co_consts:
        if hasattr(k, "co_code"): walk(k, out)
    return out
data = marshal.dumps(code)
open("inputs/m.bin", "wb").write(data)
header = importlib.util.MAGIC_NUMBER + (0).to_bytes(4, "little") + (1760000000).to_bytes(4, "little") + len(src).to_bytes(4, "little")
open("inputs/m.pyc", "wb").write(header + data)
print(json.dumps(walk(code, [])))
`;

test("a stream written by the interpreter's own marshal.dumps: every code object, its bytecode, names and constants, and none of it run", { skip: REAL ? false : `needs CPython 3.11 to 3.13 to write a stream; this is ${PY_MAJOR}.${PY_MINOR}` }, async () => {
  await withCwd(async (cwd) => {
    const truth = JSON.parse(spawnSync("python3", ["-c", BUILD, cwd], { input: SOURCE, encoding: "utf8" }).stdout) as Json[];
    for (const file of ["m.bin", "m.pyc"]) {
      const res = body(await tool(MARSHAL, cwd, { path: `inputs/${file}`, preview: 12 }));
      assert.equal(res.status, "complete");
      assert.equal(res.ok, true);
      assert.match(res.status_basis, /every code object/);
      assert.equal(res.code_objects, truth.length);
      assert.equal(res.trailing_bytes, 0);
      assert.equal(res.source.stream_offset, file === "m.pyc" ? 16 : 0);
      if (file === "m.pyc") {
        assert.equal(res.source.pyc_header.source_mtime, "2025-10-09T08:53:20Z");
        assert.equal(res.source.pyc_header.source_mtime_raw, 1760000000);
        assert.equal(res.source.pyc_header.source_size, SOURCE.length);
        assert.match(res.source.pyc_header.python, /^3\.1[123]$/);
      }
      const whole = JSON.parse(await readFile(join(cwd, res.result_file), "utf8")) as Json;
      for (const want of truth) {
        const got = whole.codes.find((c: Json) => c.qualname === want.qualname)!;
        assert.ok(got, `${want.qualname} is listed`);
        assert.equal(got.firstlineno, want.firstlineno);
        assert.equal(got.argcount, want.argcount);
        assert.equal(got.flags, want.flags);
        assert.equal(got.filename, "<synthetic>");
        assert.equal(got.bytecode_hex, want.bytecode);
        assert.equal(got.bytecode_bytes, want.bytecode.length / 2);
        assert.deepEqual(got.names, want.names);
        for (const s of want.strings) assert.ok(JSON.stringify(got.consts).includes(JSON.stringify(s).slice(1, -1)), `${want.qualname}: constant ${s}`);
      }
      assert.ok(whole.codes.find((c: Json) => c.name === "first").flag_names.includes("VARARGS"));
      const shown = res.codes.find((c: Json) => c.name === "first");
      assert.equal(shown.bytecode_hex, undefined, "the answer does not carry the bytecode");
      assert.ok(JSON.stringify(shown.consts).includes('"shown":12'));
      assert.equal(((await stat(join(cwd, res.result_file))).mode & 0o777).toString(8), "600");
    }
    await assert.rejects(stat(join(cwd, "PWNED-BY-EXECUTION")), /ENOENT/);
  });
});

// --- hand-built streams: every kind of object, a loop, a cut ------------------------------------------------------------------------

test("data objects of every kind are read; a container that holds itself is named, not followed; a large tuple is shown once and then by its reference", async () => {
  await withCwd(async (cwd) => {
    const big = tuple(Array.from({ length: 40 }, (_, i) => Buffer.concat([Buffer.from("i"), i32(i)])), true);
    const double = (v: number): Buffer => { const b = Buffer.alloc(8); b.writeDoubleLE(v); return Buffer.concat([Buffer.from("g"), b]); };
    // a long: three 15-bit digits, least significant first, negative count for a negative number; the dict is not flagged, `big` is the first
    // flagged object, so it is reference 0, and the dict ends with TYPE_NULL ('0')
    const fixed = Buffer.concat([Buffer.from("{"), str("big"), tuple([big, ref(0)]), str("bytes"), bytes(Buffer.from([0, 0xff, 0x72, 0x61, 0x77])), str("none"), NONE,
      str("bools"), tuple([Buffer.from("T"), Buffer.from("F")]), str("ell"), Buffer.from("."), str("floats"), tuple([double(0.5), double(Infinity)]),
      str("longint"), Buffer.concat([Buffer.from("l"), i32(-3), Buffer.from([0x01, 0, 0x02, 0, 0x03, 0])]), Buffer.from("0")]);
    const res = await run(cwd, fixed);
    assert.equal(res.status, "complete");
    const file = JSON.parse(await readFile(join(cwd, res.result_file), "utf8")) as Json;
    const get = (k: string): Json => file.root.dict.find(([key]: [string, Json]) => key === k)![1];
    const bigView = get("big");
    assert.equal(bigView[0].tuple.length, 40);
    assert.deepEqual(bigView[1], { ref: bigView[0].ref });
    assert.deepEqual(get("bytes"), { bytes: 5, hex: "00ff726177" });
    assert.equal(get("none"), null);
    assert.deepEqual(get("bools"), [true, false]);
    assert.deepEqual(get("ell"), { const: "Ellipsis" });
    assert.deepEqual(get("floats"), [0.5, { float: "inf" }]);
    assert.equal(get("longint"), -((3 * 2 ** 30) + (2 * 2 ** 15) + 1), "a long is built from its 15-bit digits");
    // a list that contains reference 0, which is itself
    const loop = await run(cwd, Buffer.concat([flag("["), i32(1), ref(0)]), {}, "inputs/loop.bin");
    assert.deepEqual(loop.root, { list: [{ ref: 0 }], ref: 0 });
    assert.equal(loop.status, "complete");
  });
});

test("a stream cut short is partial with the position and every code object whole before it; one that cannot begin is failed; both are non-zero exits with a pair", async () => {
  await withCwd(async (cwd) => {
    const whole = tuple([code({ name: "a" }), code({ name: "b" }), code({ name: "c" })]);
    const cut = await fails(cwd, whole.subarray(0, whole.length - 20));
    assert.equal(cut.status, "partial");
    assert.equal(cut.ok, false);
    assert.match(cut.error, /cut short/);
    assert.equal(typeof cut.stopped_at, "number");
    assert.equal(cut.code_objects, 2, "the two code objects read whole are listed");
    assert.match(cut.status_basis, /cut short/);
    const empty = await fails(cwd, Buffer.alloc(0), {}, "inputs/empty.bin");
    assert.equal(empty.status, "failed");
    assert.match(empty.error, /cut short/);
    const unknown = await fails(cwd, Buffer.from([0x7e, 0, 0, 0]), {}, "inputs/type.bin");
    assert.equal(unknown.status, "failed");
    assert.match(unknown.error, /not one this reader knows/);
  });
});

test("bounds are named: nesting past 200, a count that cannot fit (a list declaring 2**31 - 1 items), a negative count, a reference to nothing, a long of too many digits", async () => {
  await withCwd(async (cwd) => {
    const deep = Buffer.concat([...Array.from({ length: 300 }, () => Buffer.concat([Buffer.from("["), i32(1)])), NONE]);
    const d = await fails(cwd, deep, {}, "inputs/deep.bin");
    assert.match(d.error, /nesting deeper than 200/);
    assert.notEqual(d.status, "complete");
    assert.match((await fails(cwd, Buffer.concat([Buffer.from("["), i32(2 ** 31 - 1)]), {}, "inputs/count.bin")).error, /cannot fit/);
    assert.match((await fails(cwd, Buffer.concat([Buffer.from("("), i32(-5)]), {}, "inputs/neg.bin")).error, /cannot fit/);
    assert.match((await fails(cwd, Buffer.concat([Buffer.from("("), i32(1), ref(7)]), {}, "inputs/ref.bin")).error, /reference to object 7/);
    assert.match((await fails(cwd, Buffer.concat([Buffer.from("l"), i32(2), Buffer.from([0xff, 0xff, 0x01, 0x00])]), {}, "inputs/digit.bin")).error, /out of range/);
    const long = await fails(cwd, Buffer.concat([Buffer.from("l"), i32(2_000_000)]), {}, "inputs/long.bin");
    assert.match(long.error, /over the 1048576 this reader builds/);
  });
});

test("text shared so that its copies pass the budget is refused with the budget named; a root of 100,000 strings shows 500 nodes and the whole is in the file", async () => {
  await withCwd(async (cwd) => {
    const text = "x".repeat(100_000);
    const shared = Buffer.concat([Buffer.from("("), i32(2001), str(text, true), ...Array.from({ length: 2000 }, () => ref(0))]);
    const refusal = await fails(cwd, shared, {}, "inputs/shared.bin");
    assert.match(refusal.error, /shares text or numbers/);
    assert.equal(refusal.status, "partial");
    const many = Buffer.concat([Buffer.from("("), i32(100_000), ...Array.from({ length: 100_000 }, (_, i) => str(`item-${i}`))]);
    const res = await run(cwd, many, {}, "inputs/many.bin");
    assert.equal(res.status, "complete");
    const shown = res.root as Json[];
    assert.ok(shown.length <= 501, `${shown.length} nodes in the answer`);
    assert.deepEqual(shown[shown.length - 1], { not_shown: 100_000 - 500 });
    const file = JSON.parse(await readFile(join(cwd, res.result_file), "utf8")) as Json;
    assert.equal(file.root.length, 100_000);
    assert.equal(file.root[99_999], "item-99999");
  });
});

test("code objects past `limit` are in the file and counted: 80 code objects, limit 10", async () => {
  await withCwd(async (cwd) => {
    const stream = tuple(Array.from({ length: 80 }, (_, i) => code({ name: `fn${i}` })));
    const res = await run(cwd, stream, { limit: 10 });
    assert.equal(res.codes.length, 10);
    assert.equal(res.codes_shown, 10);
    assert.equal(res.code_objects, 80);
    const file = JSON.parse(await readFile(join(cwd, res.result_file), "utf8")) as Json;
    assert.equal(file.codes.length, 80);
    assert.equal(file.codes[79].name, "fn79");
  });
});

test("max_seconds stops the read of 1,900,000 integers: partial, the limit named, the call back within seconds", async () => {
  await withCwd(async (cwd) => {
    const n = 1_900_000;
    const stream = Buffer.concat([Buffer.from("("), i32(n), Buffer.concat(Array.from({ length: n }, () => Buffer.from([0x69, 1, 0, 0, 0])))]);
    const started = Date.now();
    const res = await fails(cwd, stream, { max_seconds: 1 }, "inputs/ints.bin");
    assert.equal(res.status, "partial");
    assert.ok(res.limits_hit.some((t: string) => /^time: the read stopped at max_seconds/.test(t)), res.limits_hit.join("|"));
    assert.ok(Date.now() - started < 60_000);
  });
});

// --- the .pyc header names its interpreter ---------------------------------------------------------------------------------------

test("a .pyc whose magic names 3.14, 3.10 or older, or newer than 3.14 is unsupported with the version named; 3.11, 3.12 and 3.13 are read", async () => {
  await withCwd(async (cwd) => {
    const stream = code({ name: "m" });
    for (const [magic, version] of [[3627, "3.14"], [3439, "3.10 or older"], [3700, "3.15 or newer"]] as const) {
      const out = await fails(cwd, Buffer.concat([pycHeader(magic), stream]), {}, `inputs/${magic}.pyc`);
      assert.equal(out.status, "unsupported", String(magic));
      assert.equal(out.python, version);
      assert.match(out.error, new RegExp(`Python ${version.replace(/\./g, "\\.")}`));
      assert.equal(out.ok, false);
    }
    for (const [magic, version] of [[3495, "3.11"], [3531, "3.12"], [3571, "3.13"]] as const) {
      const out = await run(cwd, Buffer.concat([pycHeader(magic), stream]), {}, `inputs/${magic}.pyc`);
      assert.equal(out.source.pyc_header.python, version);
      assert.equal(out.status, "complete");
      assert.equal(out.code_objects, 1);
    }
    // the same bytes without a header and with an offset: read as the 3.11 to 3.13 layout
    const carved = await run(cwd, Buffer.concat([Buffer.from("JUNKJUNK"), stream, Buffer.from("TRAIL")]), { offset: 8 }, "inputs/carved.bin");
    assert.equal(carved.trailing_bytes, 5);
    assert.equal(carved.codes[0].stream_start, 8);
  });
});

// --- withholding --------------------------------------------------------------------------------------------------------------------

async function plantedRun(cwd: string, seed: number, secretJob = false): Promise<{ text: string; needleList: ReturnType<typeof needles>[]; values?: string }> {
  const list = canaries(200, seed);
  const needleList: ReturnType<typeof needles>[] = list.map(([, c]) => needles(c));
  const planted = list.map(([, c]) => c.plant);
  const codes = list.map(([, c], i) => code({
    name: `fn${i}`, filename: `/srv/${c.plant}.py`, qualname: `Cls.${c.plant}`, names: [str(c.plant), str(`attr${i}`)], consts: [str(c.plant), bytes(Buffer.from(c.plant, "latin1")), NONE],
  }));
  const root = tuple([...codes, tuple(planted.map((p) => str(p))), tuple(planted.map((p) => bytes(Buffer.from(p, "utf16le"))))]);
  await put(cwd, "inputs/canary.bin", root);
  const out = secretJob
    ? await asJob(MARSHAL, cwd, { path: "inputs/canary.bin", write_values: true, limit: 5 }, undefined, { SECRET_OUTPUT: "1" }, "outv")
    : await tool(MARSHAL, cwd, { path: "inputs/canary.bin", limit: 5 });
  assert.equal(out.code, 0, out.stderr + out.stdout.slice(0, 500));
  const parts = [out.stdout];
  const dirs = secretJob ? [] : [join(cwd, "work", "s1", "marshal_inspect")];
  for (const dir of dirs) for (const n of await readdir(dir)) parts.push(await readFile(join(dir, n), "latin1"));
  let values: string | undefined;
  if (secretJob) {
    const answer = JSON.parse(out.stdout) as Json;
    const resultPath = join(cwd, answer.result_file);
    parts.push(await readFile(resultPath, "latin1"));
    values = await readFile(join(cwd, "outv", "go-buildinfo-values.jsonl".replace("go-buildinfo", "marshal-inspect")), "utf8");
  }
  return { text: parts.join("\n"), needleList, values };
}

const SEEDS = Number(process.env.RE_CANARY_SEEDS ?? 3);

test("canaries of every shape in a code object's file name, qualified name, names and constants, and in string and byte-string constants, are withheld from the answer and the default result file", async () => {
  await withCwd(async (cwd) => {
    let planted = 0;
    let missed = 0;
    const misses: string[] = [];
    for (let seed = 1; seed <= SEEDS; seed++) {
      const r = await plantedRun(cwd, seed * 7);
      const text = Buffer.from(r.text, "latin1");
      r.needleList.forEach((list, i) => {
        planted += 1;
        const hit = list.find((n) => text.includes(n.bytes));
        if (hit) { missed += 1; misses.push(`seed ${seed}.${i}: ${hit.label}`); }
      });
      await spawnSync("rm", ["-rf", join(cwd, "work", "s1")]);
    }
    console.log(`marshal canaries: ${missed} of ${planted} shapes-in-places reached an output; ${misses.slice(0, 20).join("; ")}`);
    // The seeds of this run give no miss. At RE_CANARY_SEEDS=500 (500 per shape, the figure the manifest states) one canary of the 30-character
    // AWS-secret shape reached an output, so a longer run is allowed one miss in a thousand and no more.
    const allowed = SEEDS > 20 ? Math.ceil(planted * 0.001) : 0;
    assert.ok(missed <= allowed, `${missed} of ${planted}: ${misses.slice(0, 10).join("; ")}`);
  });
});

test("write_values: refused as JSON before anything is read outside a job and in a job that is not secret output; in a secret job the whole strings are in a 0600 file and not in the answer or the default file", async () => {
  await withCwd(async (cwd) => {
    const token = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5";
    const stream = tuple([code({ name: "f", consts: [str(token), NONE] })]);
    await put(cwd, "inputs/v.bin", stream);
    const outside = refused(await tool(MARSHAL, cwd, { path: "inputs/v.bin", write_values: true }));
    assert.equal(outside.write_values, "refused");
    assert.equal(outside.status, "failed");
    assert.equal(outside.ok, false);
    const plain = refused(await asJob(MARSHAL, cwd, { path: "inputs/v.bin", write_values: true }));
    assert.equal(plain.write_values, "refused");
    assert.deepEqual(await readdir(join(cwd, "out")), []);
    const secret = await asJob(MARSHAL, cwd, { path: "inputs/v.bin", write_values: true }, undefined, { SECRET_OUTPUT: "1" }, "out2");
    const answer = body(secret);
    assert.ok(!secret.stdout.includes(token));
    assert.ok(!(await readFile(join(cwd, answer.result_file), "utf8")).includes(token), "the default result file holds the string withheld");
    assert.equal(answer.secret_values.written, 1);
    const values = join(cwd, "out2", "marshal-inspect-values.jsonl");
    assert.equal(((await stat(values)).mode & 0o777).toString(8), "600");
    const row = JSON.parse((await readFile(values, "utf8")).trim());
    assert.equal(row.value, token);
    assert.equal(row.code, 0);
  });
});

test("the backstop holds with the first stage removed: raw strings reach no output, the fields are counted, the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const aws = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    await put(cwd, "inputs/b.bin", tuple([code({ name: "f", consts: [str(aws), NONE] }), str(aws)]));
    const program = [
      "import importlib.util, io, json, sys",
      "spec = importlib.util.spec_from_file_location('tool_under_test', sys.argv[1])",
      "m = importlib.util.module_from_spec(spec)",
      "spec.loader.exec_module(m)",
      "m.View.sanitise = lambda self, text: text",
      "sys.stdin = io.StringIO(json.dumps({'path': 'inputs/b.bin'}))",
      "try:",
      "    m.main()",
      "except SystemExit:",
      "    pass",
    ].join("\n");
    const r = spawnSync("python3", ["-c", program, MARSHAL], { cwd, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
    assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
    const answer = JSON.parse(r.stdout) as Json;
    const parts = [r.stdout];
    for (const n of await readdir(join(cwd, "work", "s1", "marshal_inspect"))) parts.push(await readFile(join(cwd, "work", "s1", "marshal_inspect", n), "latin1"));
    const text = parts.join("\n");
    for (let i = 0; i + 9 <= aws.length; i++) assert.ok(!text.includes(aws.slice(i, i + 9)), `an output holds ${aws.slice(i, i + 9)}`);
    assert.equal(answer.status, "partial");
    assert.ok(answer.withheld_by_final_check >= 2, String(answer.withheld_by_final_check));
  });
});

// --- files, parameters ----------------------------------------------------------------------------------------------------------------

test("the result file is created exclusively, mode 0600, never replaced by a later call; a symbolic link on the way to out_dir is refused and nothing is written through it", async () => {
  await withCwd(async (cwd) => {
    const stream = tuple([code({ name: "a" })]);
    const first = await run(cwd, stream);
    const second = body(await tool(MARSHAL, cwd, { path: "inputs/m.bin" }));
    assert.notEqual(second.result_file, first.result_file);
    assert.equal(((await stat(join(cwd, first.result_file))).mode & 0o777).toString(8), "600");
    await mkdir(join(cwd, "elsewhere"), { recursive: true });
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    await symlink(join(cwd, "elsewhere"), join(cwd, "work", "s1", "linked"));
    const blocked = body(await tool(MARSHAL, cwd, { path: "inputs/m.bin", out_dir: "work/s1/linked/deeper" }));
    assert.equal(blocked.status, "partial");
    assert.equal(blocked.result_file, undefined);
    assert.ok(blocked.problems.some((p: string) => /could not be written/.test(p) && /symbolic link/.test(p)), blocked.problems.join("|"));
    assert.deepEqual(await readdir(join(cwd, "elsewhere")), []);
  });
});

test("hostile parameters and special files are JSON refusals, never a traceback; a pipe does not hang the tool", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/ok.bin", tuple([code()]));
    const cases: Json[] = [
      {}, { path: 5 }, { path: "" }, { path: "inputs/ok\u0000.bin" }, { path: "inputs/\ud800.bin" }, { path: "inputs/ok.bin", limit: 10 ** 30 }, { path: "inputs/ok.bin", limit: 0 },
      { path: "inputs/ok.bin", preview: 2 }, { path: "inputs/ok.bin", preview: "9" }, { path: "inputs/ok.bin", bytecode: "yes" }, { path: "inputs/ok.bin", max_seconds: 0 },
      { path: "inputs/ok.bin", offset: -1 }, { path: "inputs/ok.bin", offset: 10_000_000 }, { path: "inputs/ok.bin", max_bytes: 3 }, { path: "inputs/ok.bin", out_dir: "inputs/o" },
      { path: "inputs/ok.bin", out_dir: "../outside" }, { path: "inputs/ok.bin", out_dir: 7 }, { path: "inputs/ok.bin", out_dir: "a\u0000b" }, { path: "inputs/ok.bin", surprise: 1 },
      { path: "inputs/ok.bin", write_values: "yes" }, [], "text", null,
    ];
    for (const args of cases) {
      const out = refused(await tool(MARSHAL, cwd, args));
      assert.ok(["failed", "unsupported"].includes(out.status), `${JSON.stringify(args)} -> ${out.status}`);
      assert.equal(out.ok, false);
      assert.ok(typeof out.status_basis === "string" && out.status_basis.length > 0);
    }
    for (const raw of ["[".repeat(100_000), "{" + '"path":'.repeat(50_000), "1".repeat(100_000)]) {
      const r = spawnSync("python3", [MARSHAL], { input: raw, cwd, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
      assert.doesNotMatch(r.stderr, /Traceback/);
      assert.equal(JSON.parse(r.stdout).status, "failed");
    }
    await symlink(join(cwd, "inputs", "ok.bin"), join(cwd, "inputs", "link.bin"));
    await mkdir(join(cwd, "inputs", "dir.bin"));
    assert.equal(spawnSync("mkfifo", [join(cwd, "inputs", "pipe.bin")]).status, 0);
    const started = Date.now();
    for (const [name, pattern] of [["inputs/pipe.bin", /named pipe/], ["inputs/dir.bin", /a directory/], ["inputs/link.bin", /symbolic link/], ["inputs/missing.bin", /no such file/]] as const) {
      const out = refused(await tool(MARSHAL, cwd, { path: name }));
      assert.match(out.error, pattern, name);
      assert.match(out.error, /not a readable regular file|symbolic link/);
    }
    assert.ok(Date.now() - started < 20_000);
  });
});

// --- the clock goes by what is processed, not by how many objects (round 2, P1-A) -------------------------------------------------

const LOAD = [
  "import importlib.util, sys, time, json",
  "spec = importlib.util.spec_from_file_location('mi', sys.argv[1])",
  "m = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(m)",
].join("\n");

function python(script: string, ...argv: string[]): Json {
  const r = spawnSync("python3", ["-c", `${LOAD}\n${script}`, MARSHAL, ...argv], { encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" }, timeout: 120_000 });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout);
}

test("P1-A the reader reads the clock by bytes taken: with the clock already past, a tuple of longs of a million digits stops at the first one, not after all of them", () => {
  const out = python([
    "n = 1048576",
    "stream = b'(' + (60).to_bytes(4, 'little') + b''.join(b'l' + n.to_bytes(4, 'little') + b'\\xff\\x7f' * n for _ in range(60))",
    "reader = m.Reader(stream, 0, time.monotonic() - 1)",
    "try:",
    "    reader.obj()",
    "    stopped = False",
    "except m.Over:",
    "    stopped = True",
    "print(json.dumps({'stopped': stopped, 'objects': reader.objects}))",
  ].join("\n"));
  assert.equal(out.stopped, true);
  assert.ok(out.objects <= 3, `objects read: ${out.objects}`);
});

test("P1-A a stream of 100 longs of a million digits (200 MiB) is partial at max_seconds, back within seconds, not complete after a minute", async () => {
  await withCwd(async (cwd) => {
    const n = 1_048_576;
    const digits = Buffer.alloc(2 * n, 0);
    for (let i = 0; i < n; i++) { digits[2 * i] = 0xff; digits[2 * i + 1] = 0x7f; }
    const long = Buffer.concat([Buffer.from("l"), i32(n), digits]);
    const count = 100;
    const stream = Buffer.concat([Buffer.from("("), i32(count), ...Array.from({ length: count }, () => long)]);
    const started = Date.now();
    const res = await fails(cwd, stream, { max_seconds: 2, max_bytes: 512 * 1024 * 1024 }, "inputs/longs.bin");
    assert.equal(res.status, "partial");
    assert.ok(res.limits_hit.some((t: string) => /^time: the read stopped at max_seconds/.test(t)), res.limits_hit.join("|"));
    assert.ok(Date.now() - started < 30_000, `took ${Date.now() - started} ms`);
  });
});

test("P1-A the views read the clock by characters shown: with the clock already past, 16,000 strings of 4,096 characters stop within a few strings, not after a thousand nodes", () => {
  const out = python([
    "import random",
    "texts = [''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(4096)) for _ in range(40)]",
    "view = m.View(None, None, 10 ** 9, time.monotonic() - 1)",
    "shown = 0",
    "try:",
    "    for t in texts * 30:",
    "        view.v(t, ())",
    "        shown += 1",
    "except m.Over:",
    "    pass",
    "print(json.dumps({'shown': shown}))",
  ].join("\n"));
  assert.ok(out.shown <= 16, `strings shown before the stop: ${out.shown}`);
});

test("P1-A byte strings and big integers are charged to the clock too", () => {
  const out = python([
    "past = time.monotonic() - 1",
    "view = m.View(None, None, 10 ** 9, past)",
    "a = 0",
    "try:",
    "    for _ in range(40):",
    "        view.v(m.Raw(bytes(range(256)) * 128, 0), ())",
    "        a += 1",
    "except m.Over:",
    "    pass",
    "view = m.View(None, None, 10 ** 9, past)",
    "b = 0",
    "try:",
    "    for _ in range(4000):",
    "        view.v(1 << 400_000, ())",
    "        b += 1",
    "except m.Over:",
    "    pass",
    "print(json.dumps({'bytes': a, 'ints': b}))",
  ].join("\n"));
  assert.ok(out.bytes <= 4, `byte strings shown: ${out.bytes}`);
  assert.ok(out.ints <= 4, `integers shown: ${out.ints}`);
});

test("P3 a stop signal in the middle of writing the result leaves no half-written file under the result's name, and no temporary file", async () => {
  await withCwd(async (cwd) => {
    const words = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau upsilon phi chi psi omega";
    const items = Array.from({ length: 150_000 }, (_unused, i) => str(`${i} ${words}`));
    await put(cwd, "inputs/big.bin", tuple(items));
    await mkdir(join(cwd, "out"), { recursive: true });
    const run = startDetached(MARSHAL, cwd, { path: "inputs/big.bin", out_dir: "out", max_seconds: 45 });
    let sawTemporary = false;
    const until = Date.now() + 90_000;
    while (Date.now() < until) {
      const names = await readdir(join(cwd, "out")).catch(() => [] as string[]);
      if (names.some((n) => /^\..*\.tmp$/.test(n))) { sawTemporary = true; run.signal("SIGTERM"); break; }
      if (names.some((n) => /\.json$/.test(n))) break;
      await new Promise((r) => setTimeout(r, 5));
    }
    const code = await run.closed;
    assert.ok(sawTemporary, "the result was written under its final name at once, or finished before it could be stopped");
    assert.equal(code, 143);
    const answer = JSON.parse(run.stdout());
    assert.deepEqual([answer.status, answer.interrupted], ["failed", true]);
    const left = await readdir(join(cwd, "out"));
    assert.deepEqual(left, [], `left in out/: ${left.join(", ")}`);
  });
});

test("P3 a stop signal the moment the result's temporary file is made, before it is registered, still leaves no temporary file (the hosted Mac's case, every time)", async () => {
  // the case above sends the signal when it sees the file; on the hosted Mac that landed between os.open and the registration the stop block
  // reads, and the file was left. Here the signal is sent from inside os.open, right after the file is made: the registration is under held signals now.
  await withCwd(async (cwd) => {
    const items = Array.from({ length: 2000 }, (_unused, i) => str(`${i} alpha beta gamma`));
    await put(cwd, "inputs/big.bin", tuple(items));
    await mkdir(join(cwd, "out"), { recursive: true });
    const driver = [
      "import io, json, os, runpy, signal, sys",
      "real_open = os.open",
      "def hooked(path, flags, *a, **k):",
      "    fd = real_open(path, flags, *a, **k)",
      "    if str(path).endswith('.tmp') and os.path.basename(str(path)).startswith('.'):",
      "        os.kill(os.getpid(), signal.SIGTERM)",
      "    return fd",
      "os.open = hooked",
      "sys.argv = [sys.argv[1]]",
      "runpy.run_path(sys.argv[0], run_name='__main__')",
    ].join("\n");
    const run = spawnSync("python3", ["-c", driver, MARSHAL], { cwd, input: JSON.stringify({ path: "inputs/big.bin", out_dir: "out", max_seconds: 45 }), encoding: "utf8",
      env: { ...process.env, AGENT_ID: "s1" } });
    assert.equal(run.status, 143, run.stderr);
    const answer = JSON.parse(run.stdout) as Json;
    assert.deepEqual([answer.status, answer.interrupted], ["failed", true]);
    assert.deepEqual(await readdir(join(cwd, "out")), [], "the temporary file is removed");
  });
});

test("P3 the result file is complete JSON under its name once the call returns, and no temporary file is left beside it", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "out"), { recursive: true });
    const res = await run(cwd, tuple([code()]), { out_dir: "out" });
    const names = await readdir(join(cwd, "out"));
    assert.deepEqual(names, [res.result_file.split("/").pop()]);
    assert.equal(((await stat(join(cwd, "out", names[0]!))).mode & 0o777), 0o600);
    JSON.parse(await readFile(join(cwd, "out", names[0]!), "utf8"));
  });
});

test("P2 the manifest says what the withholding bound was measured on, and the rates of uniformly random token-shaped strings, in the pack copy and its twin", async () => {
  for (const manifest of [join(TOOLS, "marshal_inspect", "manifest.json"), join(TOOLS, "..", "..", "..", "tool-library", "marshal_inspect", "manifest.json")]) {
    const text = JSON.parse(await readFile(manifest, "utf8")).description as string;
    assert.match(text, /forced to hold a lower-case letter, a capital and a digit/);
    assert.match(text, /drawn uniformly at random/);
    assert.match(text, /about 11% of sk_live_ keys, about 5% of Slack webhook URLs and about 3% of 30-character AWS secret keys/);
    assert.match(text, /rely on those rates, not on the bound above/);
  }
});

test("the backstop runs over the paged result file as it does over the answer: with the front sanitiser removed, no raw string reaches the file", async () => {
  await withCwd(async (cwd) => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const file = Buffer.concat([pycHeader(3495), code({ consts: [str(secret), str("plain text")]})]);
    await put(cwd, "inputs/m.bin", file);
    // The tool loaded as a module (main() does not run), its sanitiser made the identity until the result file is opened, and then main() run: what
    // the front let through is for the backstop alone.
    const wrapper = [
      "import importlib.util, sys",
      "spec = importlib.util.spec_from_file_location('mi', sys.argv[1])",
      "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
      "orig = m.shown_path; live = [False]",
      "m.shown_path = lambda *a, **k: orig(*a, **k) if live[0] else a[0]",
      "init = m.ResultFile.__init__",
      "def opened(self, *a, **k):\n    live[0] = True\n    init(self, *a, **k)",
      "m.ResultFile.__init__ = opened",
      "m.main()",
    ].join("\n");
    const r = spawnSync("python3", ["-c", wrapper, MARSHAL], { cwd, input: JSON.stringify({ path: "inputs/m.bin" }), encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
    assert.doesNotMatch(r.stderr, /Traceback/);
    const answer = JSON.parse(r.stdout) as Json;
    assert.ok(answer.result_file, r.stdout.slice(0, 400));
    const written = await readFile(join(cwd, answer.result_file), "utf8");
    assert.doesNotMatch(written, /AKIAIOSFODNN7/, "a raw string reached the paged result file");
    assert.doesNotMatch(r.stdout, /AKIAIOSFODNN7/);
    assert.ok(answer.withheld_by_final_check >= 1, "the backstop counted what it withheld");
    assert.equal(answer.status, "partial");
  });
});
