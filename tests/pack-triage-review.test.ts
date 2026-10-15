/**
 * triage-collection: the findings of the independent verification of the second part, one test per finding. Every test here fails
 * on the tools it replaced (TRIAGE_TOOLS names another copy of the tools to show it):
 *   - the user-info budget failed open one candidate early and left `ftp://admin:<password>` of the 4,097th `@` in the answer;
 *   - `contains` accepted `(a|a)` repeated, which takes 2^N steps, and the time limit did not interrupt it;
 *   - names that print alike came out in the order of the listing, so under a name-sorted listing their finding ids followed the
 *     rank of the raw names;
 *   - the possible original of a stream name was built before the withholding and broke tokens that hold `_`;
 *   - a results `Error` or a log.json `message` that is not a string was serialised with ASCII escapes before it was judged.
 * Every secret here is built from random pieces at run time, never written as a literal.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet } from "./tool-library-harness.ts";
import {
  ID, INDEX, KAPE_COPY_HEADER, asJob, body, filesUnder, kapeCopyRow, put, refused, tool, uac3, veloLogRow, veloResultRow, veloUploadsRow, withCwd,
} from "./pack-triage-harness.ts";
import type { Json, Run } from "./pack-triage-harness.ts";

const A62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const B64U = A62 + "-_";

/** A deterministic random string, so a failure repeats. */
function rand(n: number, alphabet: string, seed: number): string {
  let x = seed;
  let out = "";
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    out += alphabet[(x >> 8) % alphabet.length];
  }
  return out;
}

async function sharedBlock(script: string): Promise<string> {
  const text = await readFile(script, "utf8");
  return text.slice(text.indexOf("# ---- BEGIN SHARED BLOCK"), text.indexOf("# ---- END SHARED BLOCK"));
}

/** Everything a run wrote or printed, as one text: stdout, stderr and every file under the working directory except the inputs. */
async function everything(cwd: string, run: Run): Promise<string> {
  const parts = [run.stdout, run.stderr];
  for (const rel of await filesUnder(cwd)) {
    if (rel.startsWith("inputs/")) continue;
    parts.push(await readFile(join(cwd, rel), "utf8").catch(() => ""));
  }
  return parts.join("\n");
}

/** The first window of `width` characters of `secret` that is in `text`, or null. */
function leaked(text: string, secret: string, width = 8): string | null {
  for (let i = 0; i + width <= secret.length; i++) if (text.includes(secret.slice(i, i + width))) return secret.slice(i, i + width);
  return null;
}

// ---- P1-A: the budget of `@` candidates withholds from the segment, not from the `@` -----------------------------------------

const BUDGET_CODE = String.raw`
import json, os, random, string, sys, tempfile
os.chdir(tempfile.mkdtemp())
ns = {}
exec(json.load(sys.stdin)["block"], ns)
scrub, cap = ns["scrub"], ns["MAX_CANDIDATES"]
A = string.ascii_letters + string.digits
rnd = random.Random(11)
out = {"cap": cap}
for extra in (-1, 0, 1, 2):                      # candidates before the real one: cap-1, cap, cap+1, cap+2
    for pad in (0, 20000):                       # 20000: the text is judged in windows
        printed = 0
        for _ in range(20):
            pw = "".join(rnd.choice(A) for _ in range(14))
            text = ("filler words " * (pad // 13)) + "@a " * (cap + extra) + "ftp://admin:" + pw + "@srv.example.org/x"
            got = scrub(text)
            printed += any(pw[i:i + 8] in got for i in range(7))
        out["%d:%d" % (extra, pad)] = printed
print(json.dumps(out))
`;

for (const [name, script] of [["collection_id", ID], ["collection_index", INDEX]] as const) {
  test(`${name}: the password of a URL whose '@' is the 4,096th, 4,097th or 4,098th candidate of a text is withheld, alone and in windows`, async () => {
    const run = await runPySnippet(BUDGET_CODE, [], { block: await sharedBlock(script) });
    assert.equal(run.code, 0, run.stderr);
    const got = JSON.parse(run.stdout);
    assert.equal(got.cap, 4096);
    for (const [key, printed] of Object.entries(got)) if (key !== "cap") assert.equal(printed, 0, `${key}: the password stood in the answer in ${printed} of 20 texts`);
  });
}

test("both tools: a password after exactly MAX_CANDIDATES, one fewer and one more earlier '@host' candidates is in no byte of the answer or of a file", async () => {
  for (const earlier of [4095, 4096, 4097]) {
    await withCwd(async (cwd) => {
      const pw = rand(14, A62, earlier);
      const line = "@a ".repeat(earlier) + `ftp://admin:${pw}@srv.example.org/x`;
      await put(cwd, "inputs/t/uac.log", [uac3("INF", "start"), uac3("ERR", line, 1)].join("\n") + "\n");
      const run = await asJob(ID, cwd, { root: "inputs/t" });
      body(run);
      assert.equal(leaked(await everything(cwd, run), pw), null, `collection_id, ${earlier} earlier candidates`);
    });
    await withCwd(async (cwd) => {
      const pw = rand(14, A62, earlier + 1);
      const source = "@a ".repeat(earlier) + `ftp://admin:${pw}@srv.example.org/x`;
      await put(cwd, "inputs/t/20260101_CopyLog.csv", [KAPE_COPY_HEADER, kapeCopyRow(source, "D:\\kape\\C\\x.txt")].join("\n") + "\n");
      await put(cwd, "inputs/t/C/x.txt", "x");
      const run = await asJob(INDEX, cwd, { root: "inputs/t" });
      body(run);
      assert.equal(leaked(await everything(cwd, run), pw), null, `collection_index, ${earlier} earlier candidates`);
    });
  }
});

// ---- P1-B: `contains` cannot be made to take exponential time -----------------------------------------------------------------

test("collection_index: overlapping alternations, nested repetitions and the old patterns are refused at once; the accepted forms finish at once", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, `inputs/r/${"a".repeat(120)}`, "x");
    await put(cwd, `inputs/r/${"a".repeat(31)}`, "x");
    const bad = [
      "(a|a)".repeat(40) + "c",                       // 40 groups: 2^40 paths on a name of a
      "(a|a)".repeat(5) + "c",                        // five | inside groups
      "(a|aa)".repeat(12) + "c",
      "((a|a)|(a|a))((a|a)|(a|a))c",
      "(a+)+b", "(a*)*b", "(?:a+)+$", "(a{1,5}){1,5}b", "(a|aa)+$",
      "(a?){30}a{30}", "a*a*a*a*a*a*a*b", ".*.*.*.*.*.*x",
    ];
    for (const pattern of bad) {
      const started = Date.now();
      const out = refused(await tool(INDEX, cwd, { root: "inputs/r", contains: pattern, time_limit_seconds: 5 }));
      assert.match(out.error, /outside the pattern language this tool runs on names \(/, pattern.slice(0, 30));
      assert.ok(Date.now() - started < 5000, `${pattern.slice(0, 30)} was refused at once`);
    }
    for (const pattern of ["(a|a)".repeat(4) + "c", "NTUSER|SYSTEM|SAM|SECURITY|SOFTWARE|AMCACHE|USRCLASS|DEFAULT|a{3}", "(a|b)(c|d)[a-z]+$", "^a{5,60}$"]) {
      const started = Date.now();
      body(await tool(INDEX, cwd, { root: "inputs/r", contains: pattern, time_limit_seconds: 30 }));
      assert.ok(Date.now() - started < 5000, `${pattern.slice(0, 30)} finished at once`);
    }
  });
});

const BOUNDED_CODE = String.raw`
import json, re, sys, time
ns = {"__name__": "triage_index"}
exec(compile(json.load(sys.stdin)["source"], "run.py", "exec"), ns)
bounded, slow = ns["search_bounded"], ns["PatternTooSlow"]
out = {}
cases = {"40 groups of (a|a), name of 120": ("(a|a)" * 40 + "c", 120),
         "26 groups of (a|a), name of 60": ("(a|a)" * 26 + "c", 60),
         "overlapping words, 30 groups": ("(a|aa)" * 30 + "c", 120),
         "two bounded spreads and a star, name of 4000": ("[a/]{0,64}[a/]{0,64}[a/]*b", 4000),
         "four optional, two spreads and a star, name of 4000": ("a?a?a?a?a{0,64}a{0,64}a*b", 4000)}
for label, (pattern, n) in cases.items():
    started = time.monotonic()
    try:
        bounded(re.compile(pattern, re.I), "a" * n, 0.5)
        out[label] = ["finished", round(time.monotonic() - started, 2)]
    except slow:
        out[label] = ["stopped", round(time.monotonic() - started, 2)]
# a search that is quick is not interrupted, and the timer is off afterwards
quick = bounded(re.compile("b", re.I), "aab", 0.5)
time.sleep(0.8)
out["quick"] = bool(quick)
print(json.dumps(out))
`;

test("collection_index: whatever the pattern, one search of one name is stopped after its clock (the matcher is bounded, not only the language)", async () => {
  const run = await runPySnippet(BOUNDED_CODE, [], { source: await readFile(INDEX, "utf8") });
  assert.equal(run.code, 0, run.stderr);
  const got = JSON.parse(run.stdout);
  for (const [label, [state, seconds]] of Object.entries(got).filter(([k]) => k !== "quick") as Array<[string, [string, number]]>) {
    assert.ok(seconds < 4, `${label}: ${seconds} s`);
    if (label.startsWith("40") || label.startsWith("26") || label.startsWith("overlapping")) assert.equal(state, "stopped", label);
  }
  assert.equal(got.quick, true);
});

test("collection_index: a pattern the language accepts but a long path makes slow stops the run with an error that names it, inside the bound", async () => {
  await withCwd(async (cwd) => {
    // a path of 4 directories of 200 'a' (800 characters, what the file system allows): the pattern below takes minutes on 600
    const dirs = Array.from({ length: 4 }, () => "a".repeat(200)).join("/");
    await put(cwd, `inputs/p/${dirs}/a`, "x");
    const started = Date.now();
    const out = refused(await tool(INDEX, cwd, { root: "inputs/p", contains: "[a/]{0,64}[a/]{0,64}[a/]*b", time_limit_seconds: 60 }));
    assert.match(out.error, /contains took more than 2 seconds on one name/);
    assert.ok(Date.now() - started < 30000, `${Date.now() - started} ms`);
    // a pattern that is quick on the same path is answered
    const fine = body(await tool(INDEX, cwd, { root: "inputs/p", contains: "a$" }));
    assert.ok(fine.entry_count >= 1);
  });
});

// ---- P1-C: names that print alike are ordered by nothing the evidence controls ------------------------------------------------

const SORTED_LISTING = String.raw`
import os, runpy, sys

_scandir, _listdir = os.scandir, os.listdir


class _Sorted:
    def __init__(self, entries):
        self.entries = entries

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        return iter(self.entries)

    def close(self):
        pass


def scandir(path="."):
    with _scandir(path) as it:
        return _Sorted(sorted(it, key=lambda e: e.name))


os.scandir = scandir
os.listdir = lambda path=".": sorted(_listdir(path))
script = sys.argv[1]
sys.argv = [script]
runpy.run_path(script, run_name="__main__")
`;

/** The tool on a file system that lists names in order (HFS+, NTFS, ISO 9660 and squashfs do): os.scandir and os.listdir are wrapped. */
function runOnSortedListing(script: string, cwd: string, args: unknown): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", SORTED_LISTING, script], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    child.stdin.end(JSON.stringify(args));
  });
}

/** Kendall's tau between the positions of a list and the values in it. */
function tau(values: number[]): number {
  let agree = 0;
  let pairs = 0;
  for (let i = 0; i < values.length; i++) {
    for (let j = i + 1; j < values.length; j++) {
      pairs += 1;
      agree += Math.sign(values[j] - values[i]);
    }
  }
  return agree / pairs;
}

const SIX = 6;
const TRIALS = 10;
/** Six names of one kind and one length, in raw order; the file under name number k carries k+1 rows or lines, so the raw rank can be read back from the answer. */
const sixNames = (): string[] => Array.from({ length: SIX }, (_, k) => "ghp_" + rand(36, A62, 100 + k)).sort();

test("collection_index: copy logs whose directories print alike come out in an order unrelated to their raw rank under a name-sorted listing", async () => {
  const orders: number[][] = [];
  for (let trial = 0; trial < TRIALS; trial++) {
    await withCwd(async (cwd) => {
      const names = sixNames();
      for (const [k, name] of names.entries()) {
        const rows = Array.from({ length: k + 1 }, (_, r) => kapeCopyRow(`C:\\f${r}.txt`, `D:\\kape\\C\\f${r}.txt`));
        await put(cwd, `inputs/t/${name}/20260101_CopyLog.csv`, [KAPE_COPY_HEADER, ...rows].join("\n") + "\n");
        for (let r = 0; r <= k; r++) await put(cwd, `inputs/t/${name}/C/f${r}.txt`, "x");
      }
      const run = await runOnSortedListing(INDEX, cwd, { root: "inputs/t" });
      const logs: Json[] = body(run).source_paths.observed.logs;
      assert.equal(logs.length, SIX);
      orders.push(logs.map((l) => l.rows - 1));                       // the raw rank of the log at each position
      // the ids follow the order of the rows: W numbers grow along the list
      const ids = logs.map((l) => Number(/W(\d{6})/.exec(l.directory)![1]));
      assert.deepEqual([...ids].sort((a, b) => a - b), ids, "finding ids are handed out in the order of the rows");
    });
  }
  const taus = orders.map(tau);
  const mean = taus.reduce((a, b) => a + b, 0) / taus.length;
  assert.ok(Math.abs(mean) < 0.5, `mean tau between position and raw rank ${mean.toFixed(2)} (a listing-ordered tie gives -1 or 1 in every trial)`);
  assert.ok(new Set(orders.map((o) => o.join(","))).size > 1, "the order is not the same in every run");
});

test("collection_id: results files whose names print alike get finding ids in an order unrelated to their raw rank under a name-sorted listing", async () => {
  const orders: number[][] = [];
  for (let trial = 0; trial < TRIALS; trial++) {
    await withCwd(async (cwd) => {
      const names = sixNames();
      await put(cwd, "inputs/t/w/uploads.json", veloUploadsRow("C:/x") + "\n");
      for (const [k, name] of names.entries()) {
        const rows = Array.from({ length: k + 1 }, (_, r) => veloResultRow(`C:/x${r}`, "denied"));
        await put(cwd, `inputs/t/w/results/${name}.json`, rows.join("\n") + "\n");
      }
      const run = await runOnSortedListing(ID, cwd, { root: "inputs/t", limit: 50 });
      const artefacts: Record<string, number> = body(run).runs[0].record.artefacts;
      const counts = Object.values(artefacts);
      assert.equal(counts.length, SIX);
      orders.push(counts.map((c) => c - 1));
      const ids = Object.keys(artefacts).map((k) => Number(/W(\d{6})/.exec(k)![1]));
      assert.deepEqual([...ids].sort((a, b) => a - b), ids, "finding ids are handed out in the order of the rows");
    });
  }
  const taus = orders.map(tau);
  const mean = taus.reduce((a, b) => a + b, 0) / taus.length;
  assert.ok(Math.abs(mean) < 0.5, `mean tau between position and raw rank ${mean.toFixed(2)}`);
  assert.ok(new Set(orders.map((o) => o.join(","))).size > 1, "the order is not the same in every run");
});

const TIE_CODE = String.raw`
import json, os, sys, tempfile
os.chdir(tempfile.mkdtemp())
ns = {}
exec(json.load(sys.stdin)["block"], ns)
tie, key = ns["tie_key"], ns["sort_key"]
a, b = "ghp_" + "A" * 36, "ghp_" + "B" * 36
print(json.dumps({"stable_in_a_run": tie(a) == tie(a), "differs_by_name": tie(a) != tie(b), "tie": tie(a).hex(),
                  "same_print_first": key(a)[0] == key(b)[0]}))
`;

test("both tools: the tie-break of names that print alike is a keyed hash that is not the same in the next run", async () => {
  for (const script of [ID, INDEX]) {
    const block = await sharedBlock(script);
    const [one, two] = await Promise.all([runPySnippet(TIE_CODE, [], { block }), runPySnippet(TIE_CODE, [], { block })]);
    const a = JSON.parse(one.stdout);
    const b = JSON.parse(two.stdout);
    assert.equal(a.stable_in_a_run, true);
    assert.equal(a.differs_by_name, true);
    assert.equal(a.same_print_first, true);
    assert.notEqual(a.tie, b.tie, "the salt is drawn per run");
  }
});

// ---- P2-1: a stream name is judged before it is split at its last `_` ---------------------------------------------------------

test("collection_index: a token that holds '_' in a name that looks like a renamed stream does not come out in pieces", async () => {
  await withCwd(async (cwd) => {
    const planted: Array<[string, string]> = [];
    for (let i = 0; i < 40; i++) {
      const sig = rand(20, A62, 7000 + i) + "_" + rand(21, B64U, 7100 + i);
      const jwt = "eyJ" + rand(33, B64U, 7200 + i) + "." + "eyJ" + rand(60, B64U, 7300 + i) + "." + sig;
      const proj = "sk-proj-" + rand(30, A62, 7400 + i) + "_" + rand(29, A62, 7500 + i);
      const hf = "hf_" + rand(34, A62, 7600 + i);
      for (const [kind, token] of [["jwt", jwt], ["proj", proj], ["hf", hf]]) {
        await put(cwd, `inputs/t/${kind}${i}/report.docx_${token}.v2`, "x");
        planted.push([kind, token]);
      }
    }
    const run = await asJob(INDEX, cwd, { root: "inputs/t", limit: 5 });
    body(run);
    const text = await everything(cwd, run);
    for (const [kind, token] of planted) {
      const core = kind === "jwt" ? token : token.slice(token.indexOf("_") + 1);
      assert.equal(leaked(text, core, 12), null, `${kind}: a piece of the token is in the output`);
    }
  });
});

// ---- P2-2: a structure is judged with its characters as they are -------------------------------------------------------------

test("collection_id: a results Error or a log.json message that is an object, with a token split by NUL or a zero-width character, is withheld", async () => {
  await withCwd(async (cwd) => {
    const pieces: string[] = [];
    const splits = ["\u200b", "\u0000", "\u202e", "\u00ad"];
    const cuts = [2, 3, 4, 10, 11, 12, 13];
    for (let i = 0; i < 60; i++) {
      const core = rand(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 800 + i);
      const cut = cuts[i % cuts.length];
      pieces.push("AKIA" + core.slice(0, cut), core.slice(cut));
      const token = "AKIA" + core.slice(0, cut) + splits[i % splits.length] + core.slice(cut);
      await put(cwd, `inputs/t/e${i}/uploads.json`, veloUploadsRow("C:/x") + "\n");
      await put(cwd, `inputs/t/e${i}/results/Art.json`, JSON.stringify({ Upload: { Path: "C:/x", StoredName: "s", Error: { detail: token } } }) + "\n");
      await put(cwd, `inputs/t/e${i}/log.json`, JSON.stringify({ level: "ERROR", message: { detail: token } }) + "\n");
    }
    const run = await asJob(ID, cwd, { root: "inputs/t", limit: 5 });
    body(run);
    // a run of 10 characters of either side of the split is a fragment of the key
    const text = await everything(cwd, run);
    for (const piece of pieces) assert.equal(leaked(text, piece, 10), null, "a piece of a split key is in the output");
  });
});

// ---- P3: Velociraptor's own level scale ---------------------------------------------------------------------------------------

test("collection_id: DEFAULT, a real Velociraptor log level, is a key of log_levels and not 'other'", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/t/w/uploads.json", veloUploadsRow("C:/x") + "\n");
    await put(cwd, "inputs/t/w/log.json", [veloLogRow("DEFAULT", "started"), veloLogRow("INFO", "x"), veloLogRow("ERROR", "e")].join("\n") + "\n");
    const levels = body(await tool(ID, cwd, { root: "inputs/t", limit: 5 })).runs[0].record.log_levels;
    assert.equal(levels.DEFAULT, 1);
    assert.equal(levels.other, undefined);
  });
});
