/**
 * esedb_query's withholding boundary: random canaries planted in every slot the tool prints (a table cell, a column name, a table name), the
 * rate at which each shape is printed whole asserted against the rate the design documents, the shapes the boundary does not claim asserted
 * to be printed (so that the sentence in the skill is true), the backstop shown to fire on every write path with the sanitiser removed, the
 * values file held to a job run as secret output, and a list of strings an examiner must be able to read shown unchanged.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { test } from "node:test";
import { runPy, withCwd } from "./tool-library-harness.ts";
import { WIN, body, everyFileUnder, failed, stub, tool } from "./windows-pack-harness.ts";
import { SHAPES, fragmentLeaked, leaked, plant, prng, type Canary, type Shape } from "./windows-canary.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const N = 400;
/** The bound on the share of canaries printed whole, by family (percent), from the design's measurements with room for 400 plants. */
const BOUND: Record<string, number> = {
  "token prefix families": 1, JWT: 1, "PEM private key": 1, "named secrets and user-info": 1, "invisible splits": 1,
  "AWS-shaped and base64 keys": 6, "generic random token": 3,
};

const COPY_EXPORTER = `
if [ "$1" = "-V" ]; then echo "esedbexport 20231020"; exit 0; fi
root="$2"
mkdir -p "$root.export"
cp "$FIXTURE" "$root.export/T.0"
`;

async function setup(cwd: string, bin: string, table: string): Promise<Record<string, string>> {
  await stub(bin, "esedbexport", COPY_EXPORTER);
  await writeFile(join(cwd, "work", "x.edb"), "ESE stand-in");
  await writeFile(join(cwd, "fixture.tsv"), table, "utf8");
  return { FIXTURE: join(cwd, "fixture.tsv") };
}

/** Everything the tool left that a reader of the case can reach: not the export (the tool's sealed store of the whole tables), not the fixture, not the stand-in. */
async function reachable(cwd: string, skip: (f: string) => boolean = () => false): Promise<string[]> {
  const out: string[] = [];
  for (const f of await everyFileUnder(cwd)) {
    if (f.includes("esedb-export") || f.endsWith("fixture.tsv") || f.includes("/bin/") || f.endsWith("x.edb") || skip(f)) continue;
    out.push((await readFile(f)).toString("utf8"));
  }
  return out;
}

const claimed = SHAPES.filter((s) => !s.residual);
const single = (s: Shape): boolean => s.make(() => 0.5).text.indexOf("\n") < 0;

for (const shape of SHAPES.filter(single)) {
  test(`esedb_query: ${shape.name} planted in a cell, a column name and (where a file name can hold it) a table name`, async () => {
    const canaries: Canary[] = plant(shape, N, 11);
    const cells = canaries.map((c) => c.text.replace(/\t/g, " "));
    await withCwd(async (cwd, bin) => {
      // a cell: the answer inline, and the rows file (limit 1 puts all but one row in the file)
      const env = await setup(cwd, bin, "Id\tData\n" + cells.map((t, i) => `${i}\t${t}`).join("\n") + "\n");
      const run = await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", limit: 20000 }, env, bin);
      const answer = body<Answer>(run);
      const filed = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", limit: 1 }, env, bin));
      assert.ok(filed.all_results);
      const cellRate = (100 * leaked(canaries, [run.stdout, run.stderr, ...(await reachable(cwd))])) / N;
      // a column name
      const header = canaries.map((c, i) => `${i}_${c.text.replace(/[\t\n]/g, " ")}`);
      const env2 = await setup(cwd, bin, header.join("\t") + "\n" + header.map(() => "v").join("\t") + "\n");
      await writeFile(join(cwd, "work", "y.edb"), "ESE stand-in 2");
      const col = await tool("esedb_query", cwd, { path: "work/y.edb", table: "T", limit: 5 }, env2, bin);
      const colRate = (100 * leaked(canaries, [col.stdout, col.stderr])) / N;
      assert.ok(answer.boundary, "the answer says what the boundary did");
      if (shape.residual) {
        assert.ok(cellRate >= 90, `${shape.name}: a residual shape is printed in a cell (${cellRate}%)`);
        assert.ok(colRate >= 90, `${shape.name}: a residual shape is printed in a column name (${colRate}%)`);
      } else {
        assert.ok(cellRate <= BOUND[shape.family], `${shape.name}: ${cellRate}% printed whole in a cell, bound ${BOUND[shape.family]}%`);
        assert.ok(colRate <= BOUND[shape.family], `${shape.name}: ${colRate}% printed whole in a column name, bound ${BOUND[shape.family]}%`);
      }
      // table names: one export file per canary
      if (shape.fileOk && !shape.residual) {
        await writeFile(join(cwd, "work", "z.edb"), "ESE stand-in 3");
        const names = canaries.map((c, i) => `${c.text}.${i}`);
        await writeFile(join(cwd, "names.txt"), names.join("\n"));
        await stub(bin, "esedbexport", `
if [ "$1" = "-V" ]; then echo "esedbexport 20231020"; exit 0; fi
root="$2"
mkdir -p "$root.export"
while IFS= read -r n; do printf 'Id\\n1\\n' > "$root.export/$n"; done < "${join(cwd, "names.txt")}"
`);
        const list = await tool("esedb_query", cwd, { path: "work/z.edb" }, {}, bin);
        const nameRate = (100 * leaked(canaries, [list.stdout, list.stderr])) / N;
        assert.ok(nameRate <= BOUND[shape.family], `${shape.name}: ${nameRate}% printed whole as a table name, bound ${BOUND[shape.family]}%`);
      }
    });
  });
}

test("esedb_query: with the sanitiser taken out the backstop still replaces the shapes it claims, on the answer and on the rows file", async () => {
  await withCwd(async (cwd, bin) => {
    const src = (await readFile(join(WIN, "esedb_query", "run.py"), "utf8")).replace("    out = _show(str(s), kind, field)\n", "    out = str(s)\n");
    assert.ok(src.includes("    out = str(s)\n"));
    await mkdir(join(cwd, "copy"), { recursive: true });
    await writeFile(join(cwd, "copy", "run.py"), src);
    const families = ["token prefix families", "JWT", "PEM private key", "named secrets and user-info"];
    for (const shape of claimed.filter((s) => families.includes(s.family) && single(s))) {
      const canaries = plant(shape, 200, 5);
      const env = await setup(cwd, bin, "Id\tData\n" + canaries.map((c, i) => `${i}\t${c.text}`).join("\n") + "\n");
      await writeFile(join(cwd, "work", "x.edb"), "ESE stand-in " + shape.name);
      const run = await runPy(join(cwd, "copy", "run.py"), cwd, { path: "work/x.edb", table: "T", limit: 1 }, bin, { ...env, AGENT_ID: "s1" });
      const out = JSON.parse(run.stdout) as Answer;
      const files = await reachable(cwd, (f) => f.includes("/copy/"));
      const rate = (100 * leaked(canaries, [run.stdout, run.stderr, ...files])) / canaries.length;
      assert.ok(rate <= 2, `${shape.name}: ${rate}% printed whole with the sanitiser removed`);
      if (shape.name === "userinfo_at") continue; // the tool's own URL masking takes the password first: nothing is left for the backstop
      assert.equal(out.status, "partial", shape.name);
      assert.ok(out.boundary.strings_replaced_by_the_backstop > 0 && out.boundary.replaced_at.length > 0, shape.name);
    }
  });
});

test("esedb_query: write_values is refused outside a secret-output job before anything is made, and in one it writes the originals to a 0600 file only", async () => {
  await withCwd(async (cwd, bin) => {
    const canaries = plant(SHAPES.find((s) => s.name === "ghp")!, 20, 3);
    const env = await setup(cwd, bin, "Id\tData\n" + canaries.map((c, i) => `${i}\t${c.text}`).join("\n") + "\n");
    const outside = failed(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", write_values: true }, env, bin));
    assert.match(outside.error, /write_values is refused/);
    assert.equal(outside.status, "failed");
    const out = join(cwd, "out");
    await mkdir(out, { recursive: true });
    const job = { ...env, JOB_ID: "j1", OUT: out };
    const notSecret = failed(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", write_values: true }, job, bin));
    assert.match(notSecret.error, /write_values is refused/, "a job the harness did not run as secret output");
    assert.deepEqual(await everyFileUnder(out), [], "nothing was written");
    const secret = { ...job, SECRET_OUTPUT: "1" };
    const run = await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", write_values: true }, secret, bin);
    const answer = body<Answer>(run);
    const file = join(out, "esedb_query-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const originals = (await readFile(file, "utf8")).trim().split("\n").map((l) => (JSON.parse(l) as Answer).value as string);
    assert.ok(canaries.every((c) => originals.some((o) => o.includes(c.cores[0]))), "every original is in the values file");
    assert.equal(leaked(canaries, [run.stdout, run.stderr, ...(await reachable(cwd, (f) => f === file))]), 0, "and nowhere else");
    assert.equal(answer.boundary.values.written, canaries.length);
    // a second run in the same job does not crash and does not overwrite
    const again = failed(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", write_values: true }, secret, bin));
    assert.match(again.error, /already exists/);
  });
});

test("esedb_query: write_url_secrets is held to a job run as secret output", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, "Id\tUrl\n1\thttps://a.example.test/x?token=abcdef0123456789\n");
    await mkdir(join(cwd, "out"), { recursive: true });
    const job = { ...env, JOB_ID: "j1", OUT: join(cwd, "out") };
    const refused = failed(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", write_url_secrets: true }, job, bin));
    assert.match(refused.error, /write_url_secrets is refused/);
    assert.deepEqual(await everyFileUnder(join(cwd, "out")), []);
    const ok = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", write_url_secrets: true }, { ...job, SECRET_OUTPUT: "1" }, bin));
    assert.equal(ok.secret_values.written, 1);
  });
});

/** What an examiner reads in a WebCache or SRUM export: none of it may be withheld. */
const READABLE = [
  "http://www.msftconnecttest.com/connecttest.txt", "https://www.bing.com/search?q=how+to+reset+password&form=QBLH", "file:///C:/Users/bob/Documents/Report%20Q3.docx",
  "C:\\Windows\\System32\\svchost.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
  "S-1-5-21-1004336348-1177238915-682003330-1001", "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", "Microsoft.Windows.Cortana_cw5n1h2txyewy",
  "Microsoft-Windows-Security-Auditing", "DESKTOP-4F2K9QD", "Visited: bob@https://outlook.office365.com/mail/inbox", "2026-09-01 10:00:00.123456",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36", "WebCacheV01.dat", "SRUDB.dat",
  "Network Data Usage Monitor", "{973F5D5C-1D90-4944-BE8E-24B94231A174}", "Windows Defender Antivirus Network Inspection Service", "wuauserv",
];

test("esedb_query: strings an examiner must be able to read come through a cell unchanged", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, "Id\tData\n" + READABLE.map((t, i) => `${i}\t${t}`).join("\n") + "\n");
    const out = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T" }, env, bin));
    assert.deepEqual(out.rows.map((r: Answer) => r.Data), READABLE);
    assert.equal(out.boundary.strings_withheld, 0);
    await chmod(join(cwd, "fixture.tsv"), 0o600);
  });
});

/**
 * Twin trees: the same six table sizes under withheld names, once with the names in the order of their sizes and once in the reverse order. If a
 * list printed the names as `sorted` gives them (or as the directory lists them), the order of the sizes would be the order of the raw names and
 * the two trees would give opposite answers every time. They must not: the placeholders are in an order of their own that changes with every run.
 */
test("esedb_query: the order of withheld table names is not the order of the names (twin trees), and plain names are listed by their text", async () => {
  await withCwd(async (cwd, bin) => {
    const r = prng(41);
    const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const raw = new Set<string>();
    while (raw.size < 6) raw.add(Array.from({ length: 24 }, () => alpha[Math.floor(r() * alpha.length)]).join(""));
    const ranked = [...raw].sort(); // the order `sorted` gives
    const plain = ["Containers", "AppIdTable", "SruDbIdMapTable"];
    const orders: Record<string, string[]> = {};
    for (const [tree, names] of [["ascending", ranked], ["descending", [...ranked].reverse()]] as const) {
      const fixture = join(cwd, tree);
      await mkdir(fixture, { recursive: true });
      // table i has 4*(i+1) bytes, so the size says which table it is
      for (let i = 0; i < 6; i++) await writeFile(join(fixture, `${names[i]}.${i + 3}`), "A\n1\n".repeat(i + 1));
      for (let i = 0; i < plain.length; i++) await writeFile(join(fixture, `${plain[i]}.${i + 20}`), "A\n1\n");
      await stub(bin, "esedbexport", `
if [ "$1" = "-V" ]; then echo "esedbexport 20231020"; exit 0; fi
root="$2"
mkdir -p "$root.export"
cp -R "${fixture}"/. "$root.export"/
`);
      await writeFile(join(cwd, "work", `${tree}.edb`), "ESE stand-in " + tree);
      orders[tree] = [];
      const seen = new Set<string>();
      for (let run = 0; run < 12; run++) {
        const out = body<Answer>(await tool("esedb_query", cwd, { path: `work/${tree}.edb` }, {}, bin));
        const sizes = Object.entries(out.bytes_per_table as Record<string, number>).filter(([k]) => k.startsWith("<withheld")).map(([, v]) => v);
        assert.equal(sizes.length, 6, "every withheld table is listed under a key of its own");
        seen.add(sizes.join(","));
        const plainOrder = Object.keys(out.bytes_per_table).filter((k) => !k.startsWith("<withheld"));
        assert.deepEqual(plainOrder, [...plain].sort(), "plain names are listed by their text");
        assert.deepEqual(out.tables.filter((t: string) => !t.startsWith("<withheld")), [...plain].sort());
        // tables and files list the same names the same way
        assert.equal(out.table_count, 9);
        orders[tree].push(sizes.join(","));
      }
      assert.ok(seen.size >= 4, `${tree}: the order of the placeholders changes from run to run (${seen.size} different orders in 12 runs)`);
      const byRank = (tree === "ascending" ? [4, 8, 12, 16, 20, 24] : [24, 20, 16, 12, 8, 4]).join(",");
      assert.ok(orders[tree].some((o) => o !== byRank), `${tree}: the raw order of the names is not always the printed order`);
    }
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

test("esedb_query: a row of three cells of 262,144 characters made of PEM markers with no end (one led by a token) is sealed in seconds, not the 30 the quadratic window took", async () => {
  const token = "gh" + "p_" + Array.from({ length: 36 }, (_, i) => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[(i * 11 + 5) % 62]).join("");
  const rep = (atom: string, lead = ""): string => (lead + atom.repeat(Math.ceil(262144 / atom.length))).slice(0, 262144);
  await withCwd(async (cwd, bin) => {
    const cells = [rep("-----BEGIN PRIVATE KEY-----"), rep("-----BEGIN RSA PRIVATE KEY-----", token + " "), rep("PRIVATE KEY-----", "x ")];
    const env = await setup(cwd, bin, "A\tB\tC\n" + cells.join("\t") + "\n");
    const started = Date.now();
    const run = await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", limit: 2 }, env, bin);
    const seconds = (Date.now() - started) / 1000;
    const out = body<Answer>(run);
    assert.ok(seconds < 15, `${seconds} s`);
    assert.ok(![run.stdout, ...(await reachable(cwd))].some((t) => t.includes(token.slice(4, 20))), "the token is not printed");
    assert.ok(["complete", "partial"].includes(out.status), String(out.status));
  });
});
