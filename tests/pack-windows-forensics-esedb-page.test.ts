/**
 * esedb_query reads the table file as what libesedb's esedbexport writes (tab-separated text, a row to a line, no quoting rule),
 * and keeps what it prints inline bounded while the file it names holds every row and every cell whole.
 *
 * The exporter is a stand-in that copies a table file the test wrote byte for byte; the oracle for what a row holds is a plain
 * split of the bytes the test wrote (never the tool's own output). Seeds, not wall clocks, make the hostile cases repeatable.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";
import { WIN, body, stub, tool } from "./windows-pack-harness.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** esedbexport that copies $FIXTURE to the table file T.0: the program writes the bytes the test chose. */
const COPY_EXPORTER = `
if [ "$1" = "-V" ]; then echo "esedbexport 20231020"; exit 0; fi
root="$2"
mkdir -p "$root.export"
cp "$FIXTURE" "$root.export/T.0"
`;

async function setup(cwd: string, bin: string, table: Buffer | string): Promise<Record<string, string>> {
  await stub(bin, "esedbexport", COPY_EXPORTER);
  await writeFile(join(cwd, "work", "x.edb"), "ESE stand-in");
  const fixture = join(cwd, "fixture.tsv");
  await writeFile(fixture, table);
  return { FIXTURE: fixture };
}

const lines = async (path: string): Promise<Answer[]> => (await readFile(path, "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as Answer);

/** A seeded generator (mulberry32), so a failing case can be rebuilt from its number. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test("esedb_query reads the exporter's text as text: a quote, a carriage return and an unbalanced quote do not merge or split rows", async () => {
  // csv.reader's default quoting took a cell that began with a quote to the next quote across tabs and lines, dropped the quotes
  // inside, and ended a row at a bare carriage return: 5 exported rows came back as 2, status complete.
  await withCwd(async (cwd, bin) => {
    const header = "Id\tTitle\tNote";
    const rows = [
      ["1", '"Hello" - Search', "plain"],
      ["2", '"unbalanced', "second\tcell stays"], // a tab inside is a column boundary, by definition of the format
      ["3", "after the unbalanced quote", '""'],
      ["4", "carriage\rreturn in a cell", "x"],
      ["5", 'ends with a quote"', "'single' \\ backslash"],
    ];
    const text = [header, ...rows.map((r) => r.join("\t"))].join("\n") + "\n";
    const env = await setup(cwd, bin, text);
    const out = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T" }, env, bin));
    assert.equal(out.row_count, 5);
    assert.equal(out.status, "complete");
    assert.ok(typeof out.status_basis === "string" && out.status_basis.length > 10);
    assert.deepEqual(out.rows.map((r: Answer) => r._row), [1, 2, 3, 4, 5], "the ordinals are the lines of the file");
    assert.equal(out.rows[0].Title, '"Hello" - Search', "the quotes are kept");
    assert.equal(out.rows[1].Title, '"unbalanced');
    assert.equal(out.rows[1].Note, "second", "the tab ends the cell; the next cell is a column the header does not name");
    assert.equal(out.rows[1].col3, "cell stays");
    assert.equal(out.rows[2].Note, '""');
    assert.equal(out.rows[3].Title, "carriage\rreturn in a cell");
    assert.equal(out.rows[4].Title, 'ends with a quote"');
    assert.equal(out.rows[4].Note, "'single' \\ backslash");
  });
});

test("esedb_query reads a table the exporter ended its lines with CR LF as that, and says so", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, "Id\tName\r\n1\ta\r\n2\tb\r\n");
    const out = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T" }, env, bin));
    assert.deepEqual(out.columns, ["Id", "Name"]);
    assert.deepEqual(out.rows.map((r: Answer) => [r.Id, r.Name]), [["1", "a"], ["2", "b"]]);
    assert.equal(out.export_file_line_ending, "CR LF");
  });
});

test("esedb_query numbers a column named like a key it adds, instead of letting it overwrite the row ordinal", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, "_row\tName\t_row\n77\ta\t88\n");
    const out = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T" }, env, bin));
    assert.equal(out.rows[0]._row, 1);
    assert.equal(out.rows[0]._row_2, "77");
    assert.equal(out.rows[0]._row_3, "88");
    assert.deepEqual(out.duplicate_columns_renamed, ["_row_2", "_row_3"]);
  });
});

test("esedb_query keeps what it prints inline small however large the cells are, and the file it names holds every row whole", async () => {
  // 100 rows of 1 MiB cells (a 100 MB table) came back as 100 MB on stdout: the page was bounded by a row count only.
  await withCwd(async (cwd, bin) => {
    const rows = Array.from({ length: 80 }, (_, i) => `${i + 1}\t${"x".repeat(5000 - 6)}${String(i).padStart(6, "0")}`);
    const env = await setup(cwd, bin, "Id\tBlob\n" + rows.join("\n") + "\n");
    const run = await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", limit: 20000 }, env, bin);
    assert.ok(run.stdout.length < 400_000, `stdout is ${run.stdout.length} bytes`);
    const out = body<Answer>(run);
    assert.equal(out.row_count, 80);
    assert.ok(out.rows.length < 80, "not every row is inline");
    assert.equal(out.truncated, true);
    assert.equal(out.rows[0].Blob.length, 4096, "a cell is shown cut");
    assert.deepEqual(out.rows[0]._cells_shortened, { Blob: { chars: 5000, shown: 4096 } });
    assert.equal(out.rows_not_inline, 80 - out.rows.length);
    assert.equal(out.status, "complete", "what was not shown is not what was not read");
    const kept = await lines(join(cwd, out.all_results));
    assert.equal(kept.length, 80);
    assert.equal(kept[79].Blob.length, 5000, "the file holds the cell whole");
    assert.ok(kept[79].Blob.endsWith("000079"));
    assert.equal(kept[0]._cells_shortened, undefined, "the file's rows are the table's, with nothing added");
  });
});

test("esedb_query judges a cell up to 256 KiB and withholds what is past that by its length", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, "Id\tBlob\n1\t" + "x".repeat(600 * 1024) + "\n");
    const out = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T" }, env, bin));
    const kept = await lines(join(cwd, out.all_results));
    assert.match(kept[0].Blob, /^x{262144}<withheld 352256 characters: rest of a long string>$/);
  });
});

test("esedb_query writes the file of whole rows when only a cell was cut, and not when nothing was left out", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, "Id\tNote\n1\t" + "n".repeat(5000) + "\n2\tshort\n");
    const cut = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T" }, env, bin));
    assert.equal(cut.returned, 2, "both rows are inline");
    assert.equal(cut.truncated, true);
    assert.equal(cut.rows_with_a_cell_shown_cut, 1);
    assert.equal((await lines(join(cwd, cut.all_results)))[0].Note.length, 5000);
  });
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, "Id\tNote\n1\tshort\n2\tshort\n");
    const whole = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T" }, env, bin));
    assert.equal(whole.truncated, false);
    assert.equal(whole.all_results, undefined);
    assert.deepEqual(await readdir(join(cwd, "work", "s1")).then((l) => l.filter((n) => n !== "esedb-export")), []);
  });
});

test("esedb_query never replaces a result file that is there: another result takes the next free name, the same result is named again", async () => {
  await withCwd(async (cwd, bin) => {
    const table = "Id\tName\n" + Array.from({ length: 30 }, (_, i) => `${i}\tname${i}`).join("\n") + "\n";
    const env = await setup(cwd, bin, table);
    const first = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", limit: 5 }, env, bin));
    const file = join(cwd, first.all_results);
    const again = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", limit: 5 }, env, bin));
    assert.equal(again.all_results, first.all_results, "the same result is the same file");
    // A larger file under that name (an earlier, fuller result) is kept as it is.
    const bigger = (await readFile(file, "utf8")) + JSON.stringify({ _row: 31, Id: "30", Name: "kept" }) + "\n";
    await writeFile(file, bigger);
    const third = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", limit: 5 }, env, bin));
    assert.notEqual(third.all_results, first.all_results);
    assert.match(third.all_results, /-2\.jsonl$/);
    assert.equal(await readFile(file, "utf8"), bigger, "the file that was there is as it was");
    assert.equal((await lines(join(cwd, third.all_results))).length, 30);
  });
});

test("esedb_query stops at its own time limit with the rows read, says partial, and names the whole table", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, "Id\tName\n" + Array.from({ length: 200 }, (_, i) => `${i}\tn`).join("\n") + "\n");
    // The limit is 285 seconds; a copy with a limit of zero stands in for a table that takes longer than that to read.
    const src = (await readFile(join(WIN, "esedb_query", "run.py"), "utf8")).replace("DEADLINE_SECONDS = 285", "DEADLINE_SECONDS = 0");
    assert.ok(src.includes("DEADLINE_SECONDS = 0"));
    await mkdir(join(cwd, "copy"), { recursive: true });
    await writeFile(join(cwd, "copy", "run.py"), src);
    const run = await runPy(join(cwd, "copy", "run.py"), cwd, { path: "work/x.edb", table: "T" }, bin, { ...env, AGENT_ID: "s1" });
    const out = JSON.parse(run.stdout) as Answer;
    assert.equal(out.status, "partial");
    assert.equal(out.rows_complete, false);
    assert.match(out.rows_stopped, /time limit \(0 seconds\)/);
    assert.match(out.status_basis, /rows after it were not read/);
    assert.match(out.export_file, /T\.0/, "the table file that holds the rest is named");
  });
});

test("esedb_query stopped by SIGTERM while it reads a table answers JSON and leaves no temporary file", async () => {
  await withCwd(async (cwd, bin) => {
    const big = "y".repeat(1024 * 1024);
    const env = await setup(cwd, bin, "Id\tBlob\n" + Array.from({ length: 300 }, (_, i) => `${i}\t${big}`).join("\n") + "\n");
    const child = spawn("python3", [join(WIN, "esedb_query", "run.py")], { cwd, env: { ...process.env, ...env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}` } });
    let stdout = "";
    child.stdout.on("data", (c: Buffer) => (stdout += c.toString()));
    const closed = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
    child.stdin.end(JSON.stringify({ path: "work/x.edb", table: "T", limit: 5 }));
    const dir = join(cwd, "work", "s1", "tool-output");
    for (let waited = 0; waited < 20_000; waited += 50) {
      const names = await readdir(dir).catch(() => [] as string[]);
      if (names.some((n) => n.startsWith(".esedb_query"))) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    // Stopped where it is, so that the signal cannot arrive after the table has been read; the handler runs when it goes on.
    child.kill("SIGSTOP");
    child.kill("SIGTERM");
    child.kill("SIGCONT");
    const code = await closed;
    assert.equal(code, 143);
    const out = JSON.parse(stdout) as Answer;
    assert.equal(out.status, "interrupted");
    assert.equal(out.signal, 15);
    assert.deepEqual((await readdir(dir)).filter((n) => n.startsWith(".esedb_query")), []);
  });
});

test("esedb_query refusals carry status failed and a basis", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, "Id\n1\n");
    const run = await tool("esedb_query", cwd, { path: "work/x.edb", table: "Nope" }, env, bin);
    const out = JSON.parse(run.stdout) as Answer;
    assert.equal(run.code, 1);
    assert.equal(out.status, "failed");
    assert.match(out.status_basis, /error/);
    assert.deepEqual(out.tables, ["T"]);
  });
});

/** Hostile tables: 40 seeded cases against a plain-split oracle of the bytes written. */
test("esedb_query reads 40 seeded hostile tables exactly as a plain split of the file does", async () => {
  const alphabet = ['"', '""', "'", "\\", "\r", "​", "é", "中", "a", "0", " ", "=", ";", ",", "{", "%", "\u0001"];
  await withCwd(async (cwd, bin) => {
    await stub(bin, "esedbexport", COPY_EXPORTER);
    await writeFile(join(cwd, "work", "x.edb"), "ESE stand-in");
    for (let seed = 1; seed <= 40; seed++) {
      const rand = prng(seed);
      const pick = <T,>(xs: T[]): T => xs[Math.floor(rand() * xs.length)];
      const ncols = 1 + Math.floor(rand() * 5);
      const header = Array.from({ length: ncols }, (_, i) => `C${i}`);
      const cell = (): string => {
        const kind = rand();
        if (kind < 0.15) return "";
        if (kind < 0.35) return '"' + Array.from({ length: Math.floor(rand() * 20) }, () => pick(alphabet)).join("");
        return Array.from({ length: 1 + Math.floor(rand() * 30) }, () => pick(alphabet)).join("");
      };
      const rows = Array.from({ length: Math.floor(rand() * 40) }, () => Array.from({ length: ncols }, cell));
      const text = [header.join("\t"), ...rows.map((r) => r.join("\t"))].join("\n") + (rand() < 0.7 ? "\n" : "");
      const fixture = join(cwd, "fixture.tsv");
      await writeFile(fixture, text);
      // each case is another database, so the export is made again
      await writeFile(join(cwd, "work", "x.edb"), "ESE stand-in " + seed);
      const out = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", limit: 1000 }, { FIXTURE: fixture }, bin));
      assert.equal(out.row_count, rows.length, `seed ${seed}`);
      out.rows.forEach((r: Answer, k: number) => {
        assert.equal(r._row, k + 1, `seed ${seed}`);
        rows[k].forEach((v, j) => assert.equal(r[`C${j}`], v, `seed ${seed} row ${k + 1} column ${j}`));
      });
    }
  });
});

test("esedb_query's rows file is private to its owner", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, "Id\tN\n" + Array.from({ length: 30 }, (_, i) => `${i}\tz`).join("\n") + "\n");
    const out = body<Answer>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "T", limit: 2 }, env, bin));
    assert.equal((await stat(join(cwd, out.all_results))).mode & 0o777, 0o600);
  });
});

test("esedb_query's tool-library twin is byte-equal to the pack's tool", async () => {
  for (const file of ["run.py", "manifest.json"]) {
    assert.ok((await readFile(join(WIN, "esedb_query", file))).equals(await readFile(join(ROOT, "tool-library", "esedb_query", file))), `${file} differs from the tool-library copy`);
  }
});
