/**
 * windows-forensics, the fifth verification's three P1s, each in a shared block, and the paths of the same shape found beside them. Every
 * hive is written from the regf layout (tests/windows-hive.ts) and patched field by field here; nothing is taken from a tool's output.
 *
 *   - BOUNDARY: print_order judged a list's names with no clock (it ran inside _quietly, outside _timed) and without counting them toward the
 *     cap of characters; a key with 13,000 names of up to 64 KiB ran for minutes against a 30 s manifest. The ordering and sealed_text now
 *     run under the seal's clock and count toward the cap; what they do not judge comes after the judged items in a random order, is counted
 *     (boundary.strings_not_judged_for_order_or_filter), and the answer is partial.
 *   - HIVE BOUNDS, subkeys: a held key was counted as 1,400 bytes; a name can be 65,535 bytes, held as stored and as decoded, and elements a
 *     byte apart in random bytes each read as a key (11.8 GB). A key is now counted with its name, and the names a walk keeps add up to at
 *     most twice the hive's bytes. Value names count toward the key's and the walk's budgets as their data does.
 *   - HIVE BOUNDS, read_values: data that runs past the end of the file was cut, and data that starts past it was an empty value, both in a
 *     complete answer; a record declaring more than the four bytes it holds was cut to four. Each is now a problem line, not a value.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { REGIPY, WIN, body, py, tool } from "./windows-pack-harness.ts";
import { hive } from "./windows-hive.ts";
import { peakRssPrelude } from "./peak-rss.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const MiB = 1 << 20;
const BASE = 4096;

/** The offset of the "vk" record of the value named `name` (its name is 0x14 bytes in). */
function vkOf(buf: Buffer, name: string): number {
  const at = buf.indexOf(Buffer.concat([Buffer.from([1, 0, 0, 0]), Buffer.from(name, "latin1")]));
  assert.ok(at > 0, name);
  const vk = at - 0x10;
  assert.equal(buf.toString("latin1", vk, vk + 2), "vk");
  return vk;
}

/** The offset of the "nk" record of the key named `name`. */
function nkOf(buf: Buffer, name: string): number {
  for (let at = buf.indexOf("nk", BASE); at >= 0; at = buf.indexOf("nk", at + 1)) {
    if (buf.readUInt16LE(at + 0x48) === name.length && buf.toString("latin1", at + 0x4c, at + 0x4c + name.length) === name) return at;
  }
  throw new Error(name);
}

async function regkv(cwd: string, file: string, data: Buffer, key = "K"): Promise<Answer> {
  await writeFile(join(cwd, "work", file), data);
  return body<Answer>(await tool("regkv", cwd, { hive: `work/${file}`, key }));
}

// ---- read_values: data not wholly inside the file -----------------------------------------------------------------------------------

test("a value whose data runs past the end of the hive file, starts past it, is more than its record holds, or is not the size of its fixed-size type is a problem line, never a cut or empty value", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const base = (): Buffer =>
      hive({ name: "ROOT", children: [{ name: "K", values: [
        { name: "Bin", type: "binary", value: Buffer.from("ABCDEFGH".repeat(8)) },
        { name: "Path", type: "sz", value: "C:\\Program Files\\App\\app.exe" },
        { name: "Num", type: "dword", value: 7 },
        { name: "Ok", type: "dword", value: 1 },
      ] }] });
    const clean = await regkv(cwd, "clean.dat", base());
    assert.equal(clean.status, "complete", JSON.stringify(clean.problems));
    assert.deepEqual(Object.keys(clean.values).sort(), ["Bin", "Num", "Ok", "Path"]);

    const cases: Array<[string, (b: Buffer) => void, string, RegExp]> = [
      ["runs past the end", (b) => b.writeUInt32LE(MiB, vkOf(b, "Bin") + 4), "Bin", /declares 1048576 bytes of data at offset \d+ of a hive file of \d+ bytes, and \d+ of them are past its end/],
      ["starts past the end", (b) => b.writeUInt32LE(0x7fff0000, vkOf(b, "Path") + 8), "Path", /declares \d+ bytes of data at offset \d+ of a hive file of \d+ bytes, which starts past its end/],
      ["more than its record holds", (b) => b.writeUInt32LE(0x80000010, vkOf(b, "Num") + 4), "Num", /declares 16 bytes of data held in its record, which holds 4 at most/],
      ["a DWORD that declares 2 bytes in its record", (b) => b.writeUInt32LE(0x80000002, vkOf(b, "Num") + 4), "Num", /a REG_DWORD is 4 bytes and this one declares 2; its data is not given as the value/],
      ["a DWORD that declares 64 bytes", (b) => b.writeUInt32LE(4, vkOf(b, "Bin") + 12), "Bin", /a REG_DWORD is 4 bytes and this one declares 64; its data is not given as the value/],
      ["a QWORD that declares 64 bytes", (b) => b.writeUInt32LE(11, vkOf(b, "Bin") + 12), "Bin", /a REG_QWORD is 8 bytes and this one declares 64/],
      ["a FILETIME that declares 64 bytes", (b) => b.writeUInt32LE(16, vkOf(b, "Bin") + 12), "Bin", /a REG_FILETIME is 8 bytes and this one declares 64/],
    ];
    for (const [label, patch, name, said] of cases) {
      const data = base();
      patch(data);
      const out = await regkv(cwd, `${name}.dat`, data);
      assert.equal(out.status, "partial", label);
      assert.ok(!(name in out.values), `${label}: ${name} is not given as a value: ${JSON.stringify(out.values[name])?.slice(0, 80)}`);
      assert.equal(out.values.Ok, 1, `${label}: the other values are read`);
      const problems = JSON.stringify(out.problems);
      assert.match(problems, said, label);
      assert.match(problems, /this tool did not read 1 of them/, label);
    }
  });
});

// ---- subkeys and values: what a name takes in memory ----------------------------------------------------------------------------------

/** A hive whose key K lists `n` elements a byte apart in a run of random bytes: regipy reads each as a key with a name of up to 64 KiB. */
function overlappingKeys(total: number, n: number): Buffer {
  const head = hive({ name: "ROOT", children: [{ name: "K", children: [{ name: "C" }] }] });
  const buf = Buffer.alloc(total);
  head.copy(buf);
  const knk = nkOf(buf, "K");
  const region = 0x10000;                                   // where the random bytes start, counted from the end of the base block
  let seed = 0x2545f491;
  const length = n + 0x4c + 0x10000 + 16;
  for (let i = 0; i < length; i++) {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
    buf[BASE + region + i] = seed >>> 24;
  }
  let list = region + length + 64;
  list -= list % 8;
  const cell = 4 + 4 + 4 * n;
  buf.writeInt32LE(-(Math.ceil(cell / 8) * 8), BASE + list);
  buf.write("li", BASE + list + 4, "latin1");
  buf.writeUInt16LE(n, BASE + list + 6);
  for (let i = 0; i < n; i++) buf.writeUInt32LE(region + i, BASE + list + 8 + 4 * i);
  buf.writeUInt32LE(n, knk + 0x14);
  buf.writeUInt32LE(list, knk + 0x1c);
  assert.ok(BASE + list + cell < total);
  return buf;
}

type Peak = { out: Answer; peak: number; wall: number };

async function peakRegkv(cwd: string, args: unknown, seconds = 90): Promise<Peak> {
  const wrapper = peakRssPrelude() + String.raw`
import json
cp, peak = run_peak([sys.executable, sys.argv[1]], input=sys.stdin.buffer.read(), capture_output=True, timeout=float(sys.argv[2]))
sys.stdout.write(json.dumps({"code": cp.returncode, "stdout": cp.stdout.decode("utf-8", "replace"), "stderr": cp.stderr.decode("utf-8", "replace")[-4000:], "peak": peak}))
`;
  const started = Date.now();
  const raw: string = await new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", wrapper, join(WIN, "regkv", "run.py"), String(seconds)], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve(Buffer.concat(out).toString("utf8")) : reject(new Error(`the wrapper ended ${code}`))));
    child.stdin.end(JSON.stringify(args));
  });
  const r = JSON.parse(raw) as { code: number; stdout: string; stderr: string; peak: number };
  assert.equal(r.code, 0, r.stderr);
  return { out: JSON.parse(r.stdout) as Answer, peak: r.peak, wall: Date.now() - started };
}

test("a subkey list of elements a byte apart, each a key with a name of up to 64 KiB, is held to what the names take: a few hundred MB, not gigabytes", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "names.dat"), overlappingKeys(2 * MiB, 20000));
    const { out, peak, wall } = await peakRegkv(cwd, { hive: "work/names.dat", key: "K" });
    assert.ok(peak < 600 * MiB, `peak ${Math.round(peak / MiB)} MiB (20,000 such keys held whole take about 3 GB)`);
    assert.ok(wall < 30_000, `answered in ${wall} ms, within the manifest's 30 s`);
    assert.equal(out.status, "partial");
    assert.match(JSON.stringify(out.problems), /the names of the keys this walk kept add up to more than 2 times the \d+ bytes of the hive/);
  });
});

test("a value list that names one record with a 60,000-character name again and again counts the name toward the key's budget", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const data = hive({ name: "ROOT", children: [{ name: "K", valueListRepeats: 3000, values: [{ name: "N".repeat(60000), type: "dword", value: 1 }] }] });
    await writeFile(join(cwd, "work", "vnames.dat"), data);
    const { out, peak, wall } = await peakRegkv(cwd, { hive: "work/vnames.dat", key: "K" });
    assert.ok(peak < 400 * MiB, `peak ${Math.round(peak / MiB)} MiB`);
    assert.ok(wall < 30_000, `answered in ${wall} ms`);
    assert.equal(out.status, "partial");
    assert.match(JSON.stringify(out.problems), /hold more names and data than a \d+-byte hive can/);
    assert.ok(Object.keys(out.values).length < 20, `${Object.keys(out.values).length} values listed`);
  });
});

// ---- BOUNDARY: the order and the filter judge under the clock and the cap ---------------------------------------------------------------

const PROBE = String.raw`
import json, runpy, sys, time
g = runpy.run_path(sys.argv[1], run_name="probe")
box = g["print_order"].__globals__
mode = sys.argv[2]
items = ["%05d-" % i + "".join(chr(97 + (i * 7 + j * 13) % 26) + "Zq7" for j in range(16000)) for i in range(400)]   # 64 KiB of text each
if mode == "clock":
    box["SEAL_BUDGET"] = 1.0
else:
    box["_STOP"]["cap"] = 200000
t = time.monotonic()
order = g["print_order"](items, "key")
took = time.monotonic() - t
if mode == "clock":
    box["SEAL_BUDGET"] = 0.0          # a filter that begins with no time left
seen = g["sealed_text"](items[-1], "text")
box["SEAL_BUDGET"] = 10.0
out = g["answer_object"]({"status": "complete", "status_basis": "probe"})
print(json.dumps({"took": took, "same": sorted(order) == sorted(items), "count": len(order), "stop": box["_STOP"], "status": out["status"],
                  "basis": out["status_basis"], "boundary": out["boundary"], "seen_is_mark": seen != items[-1] and seen.startswith("<withheld")}))
`;

for (const mode of ["clock", "cap"] as const) {
  test(`print_order and sealed_text stop at the ${mode === "clock" ? "seal's clock" : "cap of characters"}: the rest come after in an order of their own, counted, and the answer is partial`, { skip: REGIPY }, async () => {
    const r = JSON.parse(py(PROBE, join(WIN, "regkv", "run.py"), mode)) as Answer;
    assert.ok(r.took < (mode === "clock" ? 5 : 2), `ordering took ${r.took} s`);
    assert.equal(r.same, true, "every item is in the order, judged or not");
    assert.equal(r.count, 400);
    assert.ok(r.stop.quiet > 0 && r.stop.quiet <= 400, JSON.stringify(r.stop));
    assert.match(String(r.stop.by), mode === "clock" ? /judging time/ : /cap of \d+ characters/);
    assert.equal(r.seen_is_mark, true, "a filter does not see a string it did not judge");
    assert.equal(r.status, "partial");
    assert.ok(r.boundary.strings_not_judged_for_order_or_filter >= r.stop.quiet - 1, JSON.stringify(r.boundary));
    assert.match(r.basis, /put in order or filtered without being judged/);
  });
}

// ---- shellbags: what the lists on the way to a root that is not there said ------------------------------------------------------------

test("shellbags: a root that is not found under a cut list, or under a name that could not be decoded, says so with the root, and the answer is not complete", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const many = Array.from({ length: 500 }, (_, i) => ({ name: "K" + String(i).padStart(5, "0") }));
    // 1. The one root asked for lies under a list an index repeats: the root is not found, and the failure names what the list was cut for.
    await writeFile(join(cwd, "work", "cut.dat"), hive({ name: "ROOT", children: [{ name: "Local Settings", children: many, indexRepeats: 300 }] }));
    const cut = await tool("shellbags", cwd, { hive: "work/cut.dat", key: "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU" });
    const said = JSON.parse(cut.stdout) as Answer;
    assert.equal(said.status, "failed");
    assert.match(JSON.stringify(said.tried[0].problems), /more than once|already named \d+ times in a row/, JSON.stringify(said.tried).slice(0, 400));

    // 2. One root is there and walked; on the way to another, a name could not be decoded (U+FFFD): the root may be under it, and the answer is partial.
    const bag = { name: "BagMRU" };
    const root = (local: string) => hive({ name: "ROOT", children: [
      { name: "Local Settings", children: [{ name: local }] },
      { name: "Software", children: [{ name: "Microsoft", children: [{ name: "Windows", children: [{ name: "Shell", children: [bag] }] }] }] },
    ] });
    await writeFile(join(cwd, "work", "plain.dat"), root("Other"));
    const plain = body<Answer>(await tool("shellbags", cwd, { hive: "work/plain.dat" }));
    assert.equal(plain.status, "complete", plain.status_basis);
    await writeFile(join(cwd, "work", "lost.dat"), root("Softwäre"));
    const lost = body<Answer>(await tool("shellbags", cwd, { hive: "work/lost.dat" }));
    assert.equal(lost.status, "partial");
    assert.match(JSON.stringify(lost.problems), /U\+FFFD/);
  });
});
