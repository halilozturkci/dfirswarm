/**
 * regkv, shellbags and amcache_apps: the withholding boundary against random canaries planted in the slots the tools print (a value's data, its
 * name, a key name, binary data written as hex, a shell item's name, an Amcache path), the share printed whole asserted against the documented
 * rate, the unclaimed shapes asserted to be printed, the backstop shown to fire on every write path with the sanitiser removed, the values
 * file held to a job run as secret output, and strings an examiner must read shown unchanged. Real regipy where it is installed, the stand-in
 * otherwise.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { test } from "node:test";
import { runPy, withCwd } from "./tool-library-harness.ts";
import { WIN, body, everyFileUnder, failed, tool } from "./windows-pack-harness.ts";
import { VARIANTS, type Node, type Val } from "./windows-stub-regipy.ts";
import { SHAPES, leaked, plant, prng, type Canary, type Shape } from "./windows-canary.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const N = 300;
const BOUND: Record<string, number> = {
  "token prefix families": 1, JWT: 1, "PEM private key": 1, "named secrets and user-info": 1, "invisible splits": 1,
  "AWS-shaped and base64 keys": 6, "generic random token": 3,
};
const V = VARIANTS.find((v) => v.real && !v.skip) ?? VARIANTS[0];
const NAMES = ["ghp", "akia", "glpat", "jwt", "aws_secret40", "b64_20", "pem", "pw_assign", "userinfo_at", "zw_split", "random_base62_24", "plain_password", "passphrase", "uuid_secret"];
const shapes = NAMES.map((n) => SHAPES.find((s) => s.name === n)!);

/** Everything the tool left that a reader of the case can reach (not the hive itself). */
async function reachable(cwd: string, skip: (f: string) => boolean = () => false): Promise<string[]> {
  const out: string[] = [];
  for (const f of await everyFileUnder(cwd)) {
    if (/\/work\/[^/]+\.(dat|hve)$/.test(f) || /\/work\/(SECURITY|SOFTWARE|NTUSER\.DAT|UsrClass\.dat|Amcache\.hve)$/.test(f) || f.includes("/pystub/") || skip(f)) continue;
    out.push((await readFile(f)).toString("utf8"));
  }
  return out;
}

function check(shape: Shape, rate: number, where: string): void {
  if (shape.residual) assert.ok(rate >= 90, `${shape.name}: a residual shape is printed in ${where} (${rate}%)`);
  else assert.ok(rate <= BOUND[shape.family], `${shape.name}: ${rate}% printed whole in ${where}, bound ${BOUND[shape.family]}%`);
}

const rate = (canaries: Canary[], outputs: string[]): number => (100 * leaked(canaries, outputs)) / canaries.length;
/** A value of a REG_SZ cannot hold a NUL, and a key or value name cannot hold a backslash or NUL. */
const textOk = (s: Shape): boolean => s.name !== "nul_split";
const nameOk = (s: Shape): boolean => s.name !== "nul_split" && !s.make(() => 0.5).text.includes("\\");

for (const shape of shapes) {
  test(`regkv: ${shape.name} in a value's data, a value name, a key name and binary data`, async () => {
    const canaries = plant(shape, N, 21);
    await withCwd(async (cwd) => {
      const data: Val[] = canaries.map((c, i) => ({ name: `v${i}`, type: "sz" as const, value: c.text.replace(/\u0000/g, "") }));
      const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [{ name: "Data", values: data, children: nameOk(shape) ? canaries.map((c, i) => ({ name: `${i}_${c.text}`.slice(0, 200) })) : [] }] });
      const run = await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Data", limit: 5 }, env);
      const out = body<Answer>(run);
      assert.ok(out.boundary);
      check(shape, rate(canaries, [run.stdout, run.stderr, ...(await reachable(cwd))]), "a value's data or a key name");
      // value names
      if (nameOk(shape)) {
        const names: Val[] = canaries.map((c, i) => ({ name: `${i}_${c.text}`.slice(0, 200), type: "dword" as const, value: i }));
        const env2 = await V.write(cwd, "work/SYSTEM", { name: "HIVE", children: [{ name: "Names", values: names }] });
        const r2 = await tool("regkv", cwd, { hive: "work/SYSTEM", key: "Names" }, env2);
        check(shape, rate(canaries, [r2.stdout, r2.stderr]), "a value name");
      }
      // binary data: the canary written as Latin-1 bytes (the cases a registry holds binary data that is text)
      if (textOk(shape)) {
        const bin: Val[] = canaries.map((c, i) => ({ name: `b${i}`, type: "binary" as const, value: Buffer.concat([Buffer.from([1, 2, 3]), Buffer.from(c.text.replace(/[^\x20-\x7e]/g, ""), "latin1"), Buffer.from([4, 5])]) }));
        const env3 = await V.write(cwd, "work/DEFAULT", { name: "HIVE", children: [{ name: "Bin", values: bin }] });
        const r3 = await tool("regkv", cwd, { hive: "work/DEFAULT", key: "Bin" }, env3);
        const ascii = canaries.map((c) => ({ text: c.text, cores: c.cores.filter((core) => /^[\x20-\x7e]+$/.test(core)) })).filter((c) => c.cores.length);
        // the hex of the bytes is what the answer would print: look for the core as hex and as text
        const asHex = ascii.map((c) => ({ text: c.text, cores: c.cores.map((core) => Buffer.from(core, "latin1").toString("hex")) }));
        const binRate = (100 * (leaked(asHex, [r3.stdout]) + leaked(ascii, [r3.stdout]))) / Math.max(1, ascii.length);
        if (shape.residual) assert.ok(binRate >= 90, `${shape.name}: binary data with a residual shape is shown (${binRate}%)`);
        else assert.ok(binRate <= BOUND[shape.family], `${shape.name}: ${binRate}% printed in binary data, bound ${BOUND[shape.family]}%`);
      }
    });
  });
}

for (const shape of shapes.filter((s) => s.name !== "zw_split" && s.name !== "nul_split")) {
  test(`shellbags: ${shape.name} as the name of a shell item`, async () => {
    const canaries = plant(shape, N, 22).map((c) => ({ ...c, text: c.text.replace(/[^\x20-\x7e]/g, "") })).filter((c) => c.text.length >= 4);
    await withCwd(async (cwd) => {
      const item = (text: string): Buffer => { const content = Buffer.concat([Buffer.from([0x4e, 0x00]), Buffer.from(text, "latin1"), Buffer.from([0])]); const size = Buffer.alloc(2); size.writeUInt16LE(content.length + 2); return Buffer.concat([size, content]); };
      const values: Val[] = canaries.map((c, i) => ({ name: String(i), type: "binary" as const, value: item(c.text) }));
      const bag: Node = { name: "BagMRU", values, children: canaries.map((_, i) => ({ name: String(i) })) };
      const env = await V.write(cwd, "work/UsrClass.dat", { name: "HIVE", children: [{ name: "Local Settings", children: [{ name: "Software", children: [{ name: "Microsoft", children: [{ name: "Windows", children: [{ name: "Shell", children: [bag] }] }] }] }] }] });
      const run = await tool("shellbags", cwd, { hive: "work/UsrClass.dat", limit: 5 }, env);
      const out = body<Answer>(run);
      assert.ok(out.boundary);
      check(shape, rate(canaries, [run.stdout, run.stderr, ...(await reachable(cwd))]), "a shell item's name");
    });
  });
}

for (const shape of shapes.filter(textOk)) {
  test(`amcache_apps: ${shape.name} as a path, a name and a publisher`, async () => {
    const canaries = plant(shape, N, 23).map((c) => ({ ...c, text: c.text.replace(/\u0000/g, "") }));
    await withCwd(async (cwd) => {
      const rows: Node[] = canaries.map((c, i) => ({ name: `${i}`, values: [{ name: "LowerCaseLongPath", type: "sz" as const, value: c.text }, { name: "Publisher", type: "sz" as const, value: c.text }, { name: `N${i}_${nameOk(shape) ? c.text : "x"}`.slice(0, 200), type: "sz" as const, value: "v" }] }));
      const env = await V.write(cwd, "work/Amcache.hve", { name: "HIVE", children: [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: rows }] }] });
      const run = await tool("amcache_apps", cwd, { hive: "work/Amcache.hve", limit: 5 }, env);
      const out = body<Answer>(run);
      assert.ok(out.boundary);
      check(shape, rate(canaries, [run.stdout, run.stderr, ...(await reachable(cwd))]), "a path, a publisher or a value name");
    });
  });
}

test("regkv, shellbags and amcache_apps: with the sanitiser taken out the backstop still replaces the shapes it claims, on the answer and on the pages", async () => {
  await withCwd(async (cwd) => {
    const families = ["token prefix families", "JWT", "PEM private key", "named secrets and user-info"];
    for (const name of ["regkv", "amcache_apps"]) {
      const src = (await readFile(join(WIN, name, "run.py"), "utf8")).replace("    out = _show(str(s), kind, field)\n", "    out = str(s)\n");
      assert.ok(src.includes("    out = str(s)\n"), name);
      await mkdir(join(cwd, "copy", name), { recursive: true });
      await writeFile(join(cwd, "copy", name, "run.py"), src);
      for (const shape of shapes.filter((s) => families.includes(s.family) && textOk(s) && s.name !== "userinfo_at")) {
        const canaries = plant(shape, 120, 7);
        const data: Val[] = canaries.map((c, i) => ({ name: `v${i}`, type: "sz" as const, value: c.text }));
        const rows: Node[] = canaries.map((c, i) => ({ name: `${i}`, values: [{ name: "LowerCaseLongPath", type: "sz" as const, value: c.text }] }));
        const hive = name === "regkv" ? { name: "HIVE", children: [{ name: "Data", values: data }] } : { name: "HIVE", children: [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: rows }] }] };
        const env = await V.write(cwd, `work/${name}.dat`, hive);
        const args = name === "regkv" ? { hive: `work/${name}.dat`, key: "Data" } : { hive: `work/${name}.dat`, limit: 1 };
        const run = await runPy(join(cwd, "copy", name, "run.py"), cwd, args, undefined, { ...env, AGENT_ID: "s1" });
        const out = JSON.parse(run.stdout) as Answer;
        const files = await reachable(cwd, (f) => f.includes("/copy/"));
        const r = rate(canaries, [run.stdout, run.stderr, ...files]);
        assert.ok(r <= 2, `${name}/${shape.name}: ${r}% printed with the sanitiser removed`);
        assert.equal(out.status, "partial", `${name}/${shape.name}`);
        assert.ok(out.boundary.strings_replaced_by_the_backstop > 0, `${name}/${shape.name}`);
      }
    }
  });
});

test("regkv, shellbags and amcache_apps: write_values is held to a job run as secret output, and the originals go to a 0600 file only", async () => {
  await withCwd(async (cwd) => {
    const canaries = plant(SHAPES.find((s) => s.name === "ghp")!, 10, 3);
    const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [{ name: "Data", values: canaries.map((c, i) => ({ name: `v${i}`, type: "sz" as const, value: c.text })) }] });
    const outside = failed(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Data", write_values: true }, env));
    assert.match(outside.error, /write_values is refused/);
    const out = join(cwd, "out");
    await mkdir(out, { recursive: true });
    const job = { ...env, JOB_ID: "j1", OUT: out };
    assert.match(failed(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Data", write_values: true }, job)).error, /write_values is refused/);
    assert.deepEqual(await everyFileUnder(out), []);
    const run = await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Data", write_values: true }, { ...job, SECRET_OUTPUT: "1" });
    const answer = body<Answer>(run);
    const file = join(out, "regkv-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const originals = (await readFile(file, "utf8")).trim().split("\n").map((l) => (JSON.parse(l) as Answer).value as string);
    assert.ok(canaries.every((c) => originals.some((o) => o.includes(c.cores[0]))));
    assert.equal(leaked(canaries, [run.stdout, run.stderr, ...(await reachable(cwd, (f) => f === file))]), 0);
    assert.equal(answer.boundary.values.written, canaries.length);
    for (const name of ["shellbags", "amcache_apps"]) assert.match(failed(await tool(name, cwd, { hive: "work/SOFTWARE", write_values: true }, env)).error, /write_values is refused/, name);
  });
});

test("regkv: 6,000 value names that all become one placeholder are answered in seconds, in bounded output (the renaming was cubic: 77 s and 108 MB)", async () => {
  await withCwd(async (cwd) => {
    const r = prng(77);
    const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const names = new Set<string>();
    while (names.size < 6000) names.add(Array.from({ length: 24 }, () => alpha[Math.floor(r() * alpha.length)]).join(""));
    const values: Val[] = [...names].map((name, i) => ({ name, type: "dword" as const, value: i }));
    const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [{ name: "Many", values }] });
    const started = Date.now();
    const run = await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Many", limit: 5 }, env);
    const seconds = (Date.now() - started) / 1000;
    const out = body<Answer>(run);
    assert.ok(seconds < 20, `${seconds} s`);
    assert.ok(run.stdout.length < 5_000_000, `${run.stdout.length} bytes of output`);
    assert.equal(Object.keys(out.values).length, 6000, "every value is listed under a key of its own");
  });
});

test("shellbags: contains looks at the path as shown, and entries it did not match that have text withheld are counted and make the run partial", async () => {
  await withCwd(async (cwd) => {
    const item = (text: string): Buffer => { const content = Buffer.concat([Buffer.from([0x4e, 0x00]), Buffer.from(text, "latin1"), Buffer.from([0])]); const size = Buffer.alloc(2); size.writeUInt16LE(content.length + 2); return Buffer.concat([size, content]); };
    const secret = SHAPES.find((s) => s.name === "ghp")!.make(prng(5)).text;
    const run = async (names: string[], contains: string): Promise<Answer> => {
      const bag: Node = { name: "BagMRU", values: names.map((n, i) => ({ name: String(i), type: "binary" as const, value: item(n) })), children: names.map((_, i) => ({ name: String(i) })) };
      const env = await V.write(cwd, "work/UsrClass.dat", { name: "HIVE", children: [{ name: "Local Settings", children: [{ name: "Software", children: [{ name: "Microsoft", children: [{ name: "Windows", children: [{ name: "Shell", children: [bag] }] }] }] }] }] });
      return body<Answer>(await tool("shellbags", cwd, { hive: "work/UsrClass.dat", contains }, env));
    };
    const clean = await run(["Reports", "Pictures"], "zzz-not-there");
    assert.equal(clean.entry_count, 0);
    assert.equal(clean.contains_blind_entries, 0);
    assert.equal(clean.status, "complete", "nothing is withheld, so an absence is an absence");
    const blind = await run(["Reports", secret], "zzz-not-there");
    assert.equal(blind.entry_count, 0);
    assert.equal(blind.contains_blind_entries, 1, "one entry was not matched and has text withheld in it");
    assert.equal(blind.status, "partial");
    assert.match(blind.status_basis, /contains looks only in the text the answer prints/);
    const other = await run(["Reports", secret], "another-needle-of-other-length");
    assert.equal(other.contains_blind_entries, 1, "the count says nothing of the needle");
    const hit = await run(["Reports", secret], "report");
    assert.equal(hit.entry_count, 1);
    assert.equal(hit.contains_blind_entries, 1, "an entry that did not match and has text withheld could still hold the needle");
  });
});

/** What an examiner reads in a hive: none of it may be withheld. */
const READABLE_NAMES = [
  "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
  "Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00", "S-1-5-21-1004336348-1177238915-682003330-1001", "Microsoft.WindowsCalculator_10.2103.8.0_x64__8wekyb3d8bbwe",
  "CDPUserSvc_4f2a1", "wuauserv", "Windows NT", "DisplayName", "UninstallString", "ImagePath", "(default)", "MRUListEx", "ControlSet001", "TimeZoneKeyName",
];
const READABLE_DATA = [
  "C:\\Windows\\System32\\svchost.exe -k netsvcs -p", "\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -osint -url \"%1\"", "Microsoft Corporation", "10.0.19045.3803",
  "@%SystemRoot%\\system32\\shell32.dll,-21813", "S-1-5-21-1004336348-1177238915-682003330-1001", "DESKTOP-4F2K9QD", "Pacific Standard Time", "2026-09-01 10:00:00.123456",
  "{54849625-5478-4994-A5BA-3E3B0328C30D}", "Windows Defender Antivirus Service", "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
];

test("regkv: names and data an examiner must be able to read come through unchanged", async () => {
  await withCwd(async (cwd) => {
    const values: Val[] = READABLE_DATA.map((t, i) => ({ name: READABLE_NAMES[i % READABLE_NAMES.length] + (i >= READABLE_NAMES.length ? "_" + i : ""), type: "sz" as const, value: t }));
    const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [{ name: "Readable", values, children: READABLE_NAMES.filter((n) => !n.includes("\\")).map((name) => ({ name })) }] });
    const out = body<Answer>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Readable" }, env));
    assert.deepEqual(out.values, Object.fromEntries(values.map((v) => [v.name, v.value])), "every value, under its name (the order is that of the text shown, not the hive's)");
    assert.deepEqual(out.subkeys.map((s: Answer) => s.name), READABLE_NAMES.filter((n) => !n.includes("\\")).sort(), "the subkeys are listed in the order of their names");
    assert.equal(out.boundary.strings_withheld, 0);
  });
});

/** Every row of every file a run left (JSON lines) and the answer's own object. */
async function rowsOf(cwd: string): Promise<Answer[]> {
  const rows: Answer[] = [];
  for (const text of await reachable(cwd)) {
    for (const line of text.split("\n")) {
      if (!line.startsWith("{")) continue;
      try { rows.push(JSON.parse(line) as Answer); } catch { /* part of an answer printed with indent */ }
    }
  }
  return rows;
}
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const shellItem = (text: string): Buffer => { const content = Buffer.concat([Buffer.from([0x4e, 0x00]), Buffer.from(text, "latin1"), Buffer.from([0])]); const size = Buffer.alloc(2); size.writeUInt16LE(content.length + 2); return Buffer.concat([size, content]); };
const bagHive = (names: string[]): Node => {
  const bag: Node = { name: "BagMRU", values: names.map((n, i) => ({ name: String(i), type: "binary" as const, value: shellItem(n) })), children: names.map((_, i) => ({ name: String(i) })) };
  return { name: "HIVE", children: [{ name: "Local Settings", children: [{ name: "Software", children: [{ name: "Microsoft", children: [{ name: "Windows", children: [{ name: "Shell", children: [bag] }] }] }] }] }] };
};

test("shellbags: contains reads the text the answer prints, so a true piece of a name that only the backstop replaces cannot be told from a wrong needle", async () => {
  await withCwd(async (cwd) => {
    const rnd = prng(78);
    const candidates = Array.from({ length: 2400 }, () => Array.from({ length: 40 }, () => B64[Math.floor(rnd() * 64)]).join(""));
    const env = await V.write(cwd, "work/UsrClass.dat", bagHive(candidates));
    const probe = body<Answer>(await tool("shellbags", cwd, { hive: "work/UsrClass.dat", limit: 3000 }, env));
    const hidden = new Set<number>();
    for (const row of probe.entries as Answer[]) {
      if (typeof row.path === "string" && row.path.includes("backstop: ") && /^\d+$/.test(String(row.slot))) hidden.add(Number(row.slot));
    }
    const found = [...hidden].sort((a, b) => a - b).slice(0, 2).map((i) => candidates[i]);
    assert.ok(found.length >= 1, "the planted names include one that only the backstop replaces");
    for (const c of found) {
      const env2 = await V.write(cwd, "work/UsrClass.dat", bagHive([c, "Reports"]));
      const wrong = Array.from({ length: 10 }, () => B64[Math.floor(rnd() * 64)]).join("");
      const needles = [c.slice(0, 10), c.slice(20, 30), c.slice(30), c, wrong, c.slice(0, 9) + (c[9] === "x" ? "y" : "x")];
      const answers: Array<[number, string, number]> = [];
      for (const contains of needles) {
        const run = await tool("shellbags", cwd, { hive: "work/UsrClass.dat", contains }, env2);
        const a = body<Answer>(run);
        assert.ok(![run.stdout, run.stderr, ...(await reachable(cwd))].some((t) => t.includes(c.slice(0, 12))), "the name is not printed");
        answers.push([a.entry_count, String(a.status), a.contains_blind_entries]);
      }
      assert.equal(new Set(answers.map((a) => JSON.stringify(a))).size, 1, `a true piece, the whole name and a wrong needle give different answers: ${JSON.stringify(answers)}`);
      assert.equal(answers[0][0], 0);
      assert.equal(answers[0][2], 1, "the entry whose name is replaced is counted as one the needle may be in: the same for every needle");
    }
  });
});

/** Subkey names a hive stores alphabetically: these plain ones, and three random ones that start at the d, n and t of them (withheld). */
const PLAIN = ["Alpha", "Charlie", "Echo", "Mike", "Oscar", "Sierra", "Uniform"];
const rnd24 = (rnd: () => number, first: string): string => first + Array.from({ length: 23 }, () => B64[Math.floor(rnd() * 62)]).join("");
const sortedNames = (names: string[]): string[] => [...names].sort((a, b) => (a.toLowerCase() < b.toLowerCase() ? -1 : a.toLowerCase() > b.toLowerCase() ? 1 : 0));

test("regkv: the listing of subkeys and values does not follow the order of the raw names: a withheld name's place says nothing of its first letter (twin trees), and its order changes with the run", async () => {
  await withCwd(async (cwd) => {
    const rnd = prng(79);
    const orders = new Set<string>();
    const positions: Record<string, number[][]> = { A: [], B: [] };
    for (const [tree, firsts] of [["A", ["d", "n", "t"]], ["B", ["b", "x", "z"]]] as const) {
      const raw = firsts.map((f) => rnd24(rnd, f));
      for (let run = 0; run < 6; run++) {
        // each withheld key has as many subkeys as its rank among the three, so that the order of the answer shows whose place is whose
        const kids: Node[] = sortedNames([...PLAIN, ...raw]).map((n) => ({ name: n, children: raw.includes(n) ? Array.from({ length: raw.indexOf(n) + 1 }, (_, k) => ({ name: `c${k}` })) : [] }));
        const values: Val[] = sortedNames([...PLAIN, ...raw]).map((n) => ({ name: n, type: "dword" as const, value: raw.includes(n) ? raw.indexOf(n) + 1 : 0 }));
        const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [{ name: "Data", children: kids, values }] });
        const out = body<Answer>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Data" }, env));
        const names: string[] = out.subkeys.map((s: Answer) => s.name);
        assert.equal(names.filter((n) => n.startsWith("<withheld")).length, 3, "the three random names are withheld");
        assert.deepEqual(names.filter((n) => !n.startsWith("<withheld")), PLAIN, "the plain names are in order");
        positions[tree].push(names.map((n, i) => (n.startsWith("<withheld") ? i : -1)).filter((i) => i >= 0));
        orders.add(out.subkeys.filter((s: Answer) => s.name.startsWith("<withheld")).map((s: Answer) => s.subkeys).join(","));
        const valueNames = Object.keys(out.values);
        assert.deepEqual(valueNames.filter((n) => !n.startsWith("<withheld")), PLAIN, "the plain value names are in order");
        assert.deepEqual(valueNames.map((n, i) => (n.startsWith("<withheld") ? i : -1)).filter((i) => i >= 0), positions[tree][run], "the values follow the same rule as the subkeys");
      }
    }
    assert.deepEqual(positions.A, positions.B, "the places of the withheld names are the same whatever their first letters are");
    assert.ok(new Set(positions.A.map((p) => p.join())).size === 1, "and do not depend on the names");
    assert.ok(orders.size > 1, `the order of the withheld names among themselves changes from run to run: ${[...orders].join(" | ")}`);
    assert.ok(![...orders].every((o) => o === "1,2,3"), "and is not always the order of the raw names");
  });
});

test("regkv and shellbags: the names listed when a key is not found are in the order of the text shown, and a withheld one is not between its alphabetical neighbours", async () => {
  await withCwd(async (cwd) => {
    const rnd = prng(80);
    for (const [tree, firsts] of [["A", ["d", "n", "t"]], ["B", ["b", "x", "z"]]] as const) {
      const raw = firsts.map((f) => rnd24(rnd, f));
      const kids = sortedNames([...PLAIN, ...raw]).map((name) => ({ name }));
      const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: kids });
      const a = failed(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Nope" }, env));
      const there = a.subkeys_there as string[];
      assert.deepEqual(there.map((n) => n.startsWith("<withheld")), [true, true, true, ...PLAIN.map(() => false)], `${tree}: regkv lists the placeholders together, before the plain names`);
      assert.deepEqual(there.slice(3), PLAIN);
      const env2 = await V.write(cwd, "work/UsrClass.dat", { name: "HIVE", children: kids });
      const b = failed(await tool("shellbags", cwd, { hive: "work/UsrClass.dat", key: "Nope" }, env2));
      const tried = (b.tried as Answer[])[0].subkeys_there as string[];
      assert.deepEqual(tried.map((n) => n.startsWith("<withheld")), [true, true, true, ...PLAIN.map(() => false)], `${tree}: shellbags too`);
    }
  });
});

test("amcache_apps: the rows are listed in the order of the text shown for each key, a withheld key's place says nothing of its first letter", async () => {
  await withCwd(async (cwd) => {
    const rnd = prng(81);
    const seen: Record<string, number[]> = {};
    const orders = new Set<string>();
    for (const [tree, firsts] of [["A", ["d", "n", "t"]], ["B", ["b", "x", "z"]]] as const) {
      const raw = firsts.map((f) => rnd24(rnd, f));
      for (let run = 0; run < 6; run++) {
        const rows: Node[] = sortedNames([...PLAIN, ...raw]).map((n) => ({ name: n, values: [{ name: "Name", type: "sz" as const, value: raw.includes(n) ? `withheld-${raw.indexOf(n) + 1}` : n }] }));
        const env = await V.write(cwd, "work/Amcache.hve", { name: "HIVE", children: [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: rows }] }] });
        const out = body<Answer>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve", limit: 50 }, env));
        const keys: string[] = out.entries.map((e: Answer) => e.key);
        assert.equal(keys.filter((k) => k.startsWith("<withheld")).length, 3);
        assert.deepEqual(keys.filter((k) => !k.startsWith("<withheld")), PLAIN);
        seen[tree + run] = keys.map((k, i) => (k.startsWith("<withheld") ? i : -1)).filter((i) => i >= 0);
        orders.add(out.entries.filter((e: Answer) => e.key.startsWith("<withheld")).map((e: Answer) => String(e.Name).replace("withheld-", "")).join(","));
      }
    }
    assert.equal(new Set(Object.values(seen).map((p) => p.join())).size, 1, `the places of the withheld rows do not depend on the names: ${JSON.stringify(seen)}`);
    assert.ok(orders.size > 1 && ![...orders].every((o) => o === "1,2,3"), `the order among them is new every run: ${[...orders].join(" | ")}`);
  });
});

test("regkv: string values of 262,144 characters made of PEM markers with no end (one with a token the layers cut) are sealed in seconds, not the 37 seconds the quadratic window took", async () => {
  await withCwd(async (cwd) => {
    const token = "gh" + "p_" + Array.from({ length: 36 }, (_, i) => B64[(i * 11 + 5) % 62]).join("");
    const rep = (atom: string, lead = ""): string => (lead + atom.repeat(Math.ceil(262144 / atom.length))).slice(0, 262144);
    const values: Val[] = [rep("-----BEGIN PRIVATE KEY-----"), rep("-----BEGIN RSA PRIVATE KEY-----\n", token + " "), rep("-----BEGIN PRIVATE KEY-----", "x ")].map((value, i) => ({ name: `v${i}`, type: "sz" as const, value }));
    const env = await V.write(cwd, "work/SOFTWARE", { name: "HIVE", children: [{ name: "Data", values }] });
    const started = Date.now();
    const run = await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Data", limit: 5 }, env);
    const seconds = (Date.now() - started) / 1000;
    const out = body<Answer>(run);
    assert.ok(seconds < 15, `${seconds} s`);
    assert.ok(![run.stdout, ...(await reachable(cwd))].some((t) => t.includes(token.slice(4, 20))), "the token is not printed");
    assert.ok(["complete", "partial"].includes(out.status));
  });
});

test("the windows-forensics tools that carry the SHARED BOUNDARY block carry it identically", async () => {
  const { readdir: ls } = await import("node:fs/promises");
  const begin = "# BEGIN SHARED BOUNDARY";
  const end = "# END SHARED BOUNDARY";
  const found: Record<string, string> = {};
  for (const name of await ls(WIN)) {
    const text = await readFile(join(WIN, name, "run.py"), "utf8").catch(() => "");
    if (text.includes(begin)) found[name] = text.slice(text.indexOf(begin), text.indexOf(end) + end.length);
  }
  assert.ok(Object.keys(found).length >= 1);
  assert.equal(new Set(Object.values(found).map((b) => createHash("sha256").update(b).digest("hex"))).size, 1, `the block differs between ${Object.keys(found).join(", ")}`);
});
