/**
 * triage-collection: the second layer of the review of the two tools, one test per finding. Every test here fails on the tools
 * it replaced (TRIAGE_TOOLS names another copy of the tools to show it): a sort order that leaks the rank of a withheld name, a
 * stray file that claims a copy-log row by a shorter path, a pattern or a long line that runs for minutes, a cache that grows with
 * the log, names of credential stores that were hashed, a copy-log summary that outgrows the first 64 KiB.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readdir, utimes, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import {
  EWF_SIGNATURE, ID, INDEX, KAPE_COPY_HEADER, asJob, body, kapeCopyRow, put, readRows, refused, tableRows, tool, uac3, withCwd,
} from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const rand = (n: number, alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", seed = 1): string => {
  let x = seed;
  let out = "";
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    out += alphabet[x % alphabet.length];
  }
  return out;
};
const byPath = (out: Json): Record<string, Json> => Object.fromEntries(out.entries.filter((e: Json) => e.kind === "file").map((e: Json) => [e.in_collection, e]));
const sameTime = new Date("2026-01-02T03:04:05Z");

/** The two answers with everything that legitimately differs between two runs (random table file names, the tree's own name) normalised. */
function normal(text: string): string {
  return text.replace(/[0-9a-f]{16}/g, "<rand>");
}

// ---- P2-1: the order of rows tells nothing about a withheld name -------------------------------------------------------

async function orderTree(cwd: string, withheld: string, files: Record<string, string>) {
  for (const [name, data] of Object.entries(files)) {
    await put(cwd, `inputs/t/${name}`, data);
    await utimes(join(cwd, `inputs/t/${name}`), sameTime, sameTime);
  }
  await put(cwd, `inputs/t/${withheld}.txt`, "x");
  await utimes(join(cwd, `inputs/t/${withheld}.txt`), sameTime, sameTime);
}

test("collection_index: the position of a row among its siblings does not depend on a withheld name (twin trees, whole answer and limit 1)", async () => {
  const low = "AKIA" + "A".repeat(16);
  const high = "AKIA" + "Z".repeat(16);
  const siblings = { "AKIAM1.txt": "a", "AKIAQ9.txt": "b", "zz.txt": "c", "0.txt": "d" };
  for (const limit of [200, 1, 2]) {
    const answers: string[] = [];
    for (const name of [low, high]) {
      await withCwd(async (cwd) => {
        await orderTree(cwd, name, siblings);
        const run = await tool(INDEX, cwd, { root: "inputs/t", limit });
        body(run);
        answers.push(normal(run.stdout));
      });
    }
    // the inode and the time are the files' own: only the child's modified time and the inode could differ, and the time is pinned
    assert.equal(answers[0], answers[1], `limit ${limit}: the answers differ`);
  }
});

test("collection_id: objects, problems and the order of runs do not depend on a withheld name (twin trees)", async () => {
  const low = "AKIA" + "A".repeat(16);
  const high = "AKIA" + "Z".repeat(16);
  for (const limit of [200, 1]) {
    const answers: string[] = [];
    for (const name of [low, high]) {
      await withCwd(async (cwd) => {
        for (const n of ["AKIAM1", "AKIAQ9", "zz", "aa", name]) await put(cwd, `inputs/t/${n}.E01`, Buffer.concat([EWF_SIGNATURE, Buffer.alloc(16)]));
        for (const n of ["AKIAM1", "AKIAQ9", "zz", name]) await put(cwd, `inputs/t/${n}/uac.log`, [uac3("INF", "start"), uac3("ERR", "x", 1)].join("\n") + "\n");
        await put(cwd, `inputs/t/${name}_SkipLog.csv`, "SourceFile,Reason\nC:\\a,denied\n");
        await put(cwd, "inputs/t/AKIAQ9_SkipLog.csv", "SourceFile,Reason\nC:\\a,denied\n");
        const out = await tool(ID, cwd, { root: "inputs/t", limit });
        body(out);
        answers.push(normal(out.stdout));
      });
    }
    assert.equal(answers[0], answers[1], `limit ${limit}: the answers differ`);
  }
});

// ---- P2-2: a copy-log row is claimed by exactly the files its destination prefix names ------------------------------------

test("collection_index: a stray file with the same tail does not claim a row, and a row named by two files is ambiguous for both", async () => {
  await withCwd(async (cwd) => {
    const log = [KAPE_COPY_HEADER, kapeCopyRow("C:\\$MFT", "D:\\kape\\C\\$MFT"), kapeCopyRow("C:\\Users\\u\\NTUSER.DAT", "D:\\kape\\C\\Users\\u\\NTUSER.DAT"),
      kapeCopyRow("C:\\Users\\u\\a.txt", "D:\\kape\\C\\Users\\u\\a.txt")].join("\n") + "\n";
    await put(cwd, "inputs/a/20260101_CopyLog.csv", log);
    for (const rel of ["C/$MFT", "$MFT", "C/Users/u/NTUSER.DAT", "NTUSER.DAT", "C/Users/u/a.txt"]) await put(cwd, `inputs/a/${rel}`, "x");
    const e = byPath(body(await tool(INDEX, cwd, { root: "inputs/a" })));
    assert.equal(e["C/$MFT"].source_path_mapping, "observed");
    assert.equal(e["C/Users/u/NTUSER.DAT"].source_path_mapping, "observed");
    assert.equal(e["C/Users/u/a.txt"].source_path_mapping, "observed");
    for (const stray of ["$MFT", "NTUSER.DAT"]) {
      assert.equal(e[stray].source_path_mapping, "no_row_matched", `${stray} names the prefix D:\\kape\\C\\, which the files that name a row in full do not`);
      assert.equal(e[stray].source_path_observed, null);
    }
    // two files that name the same row with the same prefix (a name that holds a backslash reads like a path below the log): neither is observed
    await put(cwd, "inputs/b/20260101_CopyLog.csv", [KAPE_COPY_HEADER, kapeCopyRow("C:\\x.txt", "D:\\kape\\C\\x.txt")].join("\n") + "\n");
    await put(cwd, "inputs/b/C/x.txt", "1");
    await put(cwd, "inputs/b/C\\x.txt", "2");
    const two = byPath(body(await tool(INDEX, cwd, { root: "inputs/b" })));
    for (const rel of ["C/x.txt", "C\\x.txt"]) {
      assert.equal(two[rel].source_path_mapping, "ambiguous", `${rel} is not the one owner of the row`);
      assert.match(two[rel].source_path_candidates.why, /named by 2 files/);
    }
    // a tie between two prefixes decides nothing
    await put(cwd, "inputs/c/1_CopyLog.csv", [KAPE_COPY_HEADER, kapeCopyRow("C:\\$MFT", "D:\\kape\\C\\$MFT"), kapeCopyRow("C:\\h.dat", "D:\\kape\\C\\h.dat")].join("\n") + "\n");
    for (const rel of ["C/$MFT", "$MFT", "C/h.dat", "h.dat"]) await put(cwd, `inputs/c/${rel}`, "x");
    const tie = byPath(body(await tool(INDEX, cwd, { root: "inputs/c" })));
    for (const rel of ["C/$MFT", "$MFT", "C/h.dat", "h.dat"]) assert.equal(tie[rel].source_path_mapping, "ambiguous", rel);
    assert.match(tie["$MFT"].source_path_candidates.why, /two destination prefixes/);
  });
});

// ---- P2-9: a pattern outside the language is refused at once; one inside it is fast on the longest name ----------------------

test("collection_index: the reviewer's exponential and polynomial patterns are refused by name, and the accepted ones finish at once on a 255-character name", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, `inputs/r/${"a".repeat(255)}`, "x");
    await put(cwd, `inputs/r/${"a".repeat(31)}`, "x");
    for (const bad of ["(a?){30}a{30}", "a*a*a*a*a*a*a*b", ".*.*.*.*.*.*x", "(.*)(.*)(.*)x", "(a|aa)+$"]) {
      const started = Date.now();
      const out = refused(await tool(INDEX, cwd, { root: "inputs/r", contains: bad, time_limit_seconds: 2 }));
      assert.match(out.error, /outside the pattern language this tool runs on names \(/, bad);
      assert.ok(Date.now() - started < 5000, `${bad} was refused at once`);
    }
    for (const ok of ["a*b", "^a{5,60}$", "a?a?a?aaaa", ".*x", "(a|b)(c|d)[a-z]+$"]) {
      const started = Date.now();
      body(await tool(INDEX, cwd, { root: "inputs/r", contains: ok, time_limit_seconds: 30 }));
      assert.ok(Date.now() - started < 5000, `${ok} finished at once`);
    }
  });
});

// ---- P2-3: the withholding runs in linear time, whatever the line -----------------------------------------------------------

function runWithin(script: string, cwd: string, args: Json, ms: number): Promise<{ code: number | null; stdout: string; ms: number }> {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn("python3", [script], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    let out = "";
    child.stdout.on("data", (c: Buffer) => (out += c.toString()));
    const timer = setTimeout(() => child.kill("SIGKILL"), ms);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: out, ms: Date.now() - started });
    });
    child.stdin.end(JSON.stringify(args));
  });
}

test("collection_id: one line of 1 MiB of a+, of mysql or of //a: is answered in seconds, whole in the table, and the time limit is honoured", async () => {
  await withCwd(async (cwd) => {
    const shapes: Record<string, string> = { "a+": "a+".repeat(1 << 19), "mysql ": "mysql ".repeat(174763), "//a:": "//a:".repeat(1 << 18) };
    for (const [name, payload] of Object.entries(shapes)) {
      await put(cwd, `inputs/${name.replace(/\W/g, "_")}/uac.log`, [uac3("INF", "start"), uac3("ERR", payload, 1)].join("\n") + "\n");
      const run = await runWithin(ID, cwd, { root: `inputs/${name.replace(/\W/g, "_")}`, limit: 1 }, 60000);
      assert.equal(run.code, 0, `${name}: the tool finished`);
      assert.ok(run.ms < 25000, `${name}: ${run.ms} ms (a quadratic scan of 150 KB took 34 s)`);
      const out = JSON.parse(run.stdout);
      assert.ok(out.tables.failed_targets.matched >= 1);
    }
  });
});

const CLOCK_CODE = `
import json, os, sys, tempfile, time
os.chdir(tempfile.mkdtemp())
ns = {}
exec(json.load(sys.stdin)["block"], ns)
scrub = ns["scrub"]
text = ("word " * 30000) + " ghp_" + "Zq7Svb9Kt0" * 4 + "ab " + ("more " * 30000)
ns["SCRUB_DEADLINE"][0] = time.monotonic() - 1
late = scrub(text)
ns["SCRUB_DEADLINE"][0] = None
print(json.dumps({"late_has_secret": "Zq7Svb9Kt0" in late, "late_marker": "over the scan budget withheld" in late, "late_size": len(late), "on_time": "Zq7Svb9Kt0" in scrub(text)}))
`;

test("a text the run has no time left to judge is withheld whole, never printed unjudged; with time it is judged in windows", async () => {
  const { readFile } = await import("node:fs/promises");
  const { runPySnippet } = await import("./tool-library-harness.ts");
  const text = await readFile(ID, "utf8");
  const block = text.slice(text.indexOf("# ---- BEGIN SHARED BLOCK"), text.indexOf("# ---- END SHARED BLOCK"));
  const run = await runPySnippet(CLOCK_CODE, [], { block });
  assert.equal(run.code, 0, run.stderr);
  const got = JSON.parse(run.stdout);
  assert.equal(got.late_has_secret, false);
  assert.equal(got.late_marker, true);
  assert.ok(got.late_size < 1000);
  assert.equal(got.on_time, false, "a token straddling nothing is withheld when there is time");
});

// ---- P2-4: the cache of judged texts is bounded by characters ------------------------------------------------------------

const CACHE_CODE = `
import json, os, sys, tempfile
os.chdir(tempfile.mkdtemp())
ns = {}
exec(json.load(sys.stdin)["block"], ns)
scrub = ns["scrub"]
words = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor "
for i in range(60):
    scrub((words * 4000)[:300000] + " ghp_%036d tail" % i)
cache = ns["_SEEN"]
chars = sum(len(k[0]) if isinstance(k, tuple) else len(k) for k in cache) + sum(len(v) for v in cache.values())
print(json.dumps({"entries": len(cache), "chars": chars}))
`;

test("the cache of judged texts holds a few MiB at most, however many long lines are judged", async () => {
  const { readFile } = await import("node:fs/promises");
  const { runPySnippet } = await import("./tool-library-harness.ts");
  const text = await readFile(ID, "utf8");
  const block = text.slice(text.indexOf("# ---- BEGIN SHARED BLOCK"), text.indexOf("# ---- END SHARED BLOCK"));
  const run = await runPySnippet(CACHE_CODE, [], { block });
  assert.equal(run.code, 0, run.stderr);
  const got = JSON.parse(run.stdout);
  assert.ok(got.chars < 20 << 20, `${got.chars} characters are cached (the 60 lines hold 36 million)`);
});

const EDGE_CODE = `
import json, os, sys, tempfile
os.chdir(tempfile.mkdtemp())
ns = {}
exec(json.load(sys.stdin)["block"], ns)
scrub = ns["scrub"]
tokens = ["ghp_" + "Zq7Svb9Kt0" * 4, "AKIAZQ7KX3MPL2N4R6TY", "user:Zq7Svb9Kt0xx@host.example.test", "password=Zq7Svb9Kt0xx", "-----BEGIN PRIVATE KEY-----\\n" + "MIIEowIBAAKCAQEAq7ZkP3rT9vLmN2xWc5Yh" * 40 + "\\n-----END PRIVATE KEY-----"]
leaks = 0
cases = 0
for token in tokens:
    for edge in (8192, 16384 + 0, 8192 * 3):
        for back in range(-12, 12):
            pad = "filler words go here and there " * 2000
            text = pad[:edge - back] + token + " " + pad[:20000]
            out = scrub(text)
            cases += 1
            leaks += "Zq7Svb9Kt0" in out or "ZQ7KX3MPL2N4" in out or "MIIEowIBAAKCAQEAq7Zk" in out
print(json.dumps({"cases": cases, "leaks": leaks}))
`;

test("a secret that stands on the edge of a window of the text is withheld whole", async () => {
  const { readFile } = await import("node:fs/promises");
  const { runPySnippet } = await import("./tool-library-harness.ts");
  const text = await readFile(ID, "utf8");
  const block = text.slice(text.indexOf("# ---- BEGIN SHARED BLOCK"), text.indexOf("# ---- END SHARED BLOCK"));
  const run = await runPySnippet(EDGE_CODE, [], { block });
  assert.equal(run.code, 0, run.stderr);
  const got = JSON.parse(run.stdout);
  assert.equal(got.cases, 5 * 3 * 24);
  assert.equal(got.leaks, 0);
});

// ---- P2-8: the names of credential stores the review found hashed and printed -----------------------------------------------

const CREDENTIAL_FILES = [
  "terraform.tfstate", "terraform.tfstate.backup", "jenkins/credentials.xml", "var/www/wp-config.php", "k8s/secrets.yaml", "app/tokens.json", "app/vault.json",
  "home/u/.my.cnf", "home/u/.s3cfg", "home/u/.boto", "home/u/vpn.rdp", "home/u/config.ovpn", "home/u/.vnc/passwd", "etc/shadow.bak", "etc/apache2/htpasswd",
  "home/u/.config/gcloud/credentials.db", "home/u/.config/gcloud/access_tokens.db", "home/u/.azure/accessTokens.json", "keys/AuthKey_ABC123.p8", "keys/store.jceks",
  "keys/store.pkcs12", "keys/pub.asc", "Users/a/Documents/bitlocker-recovery-key.txt", "Users/a/BitLocker Recovery Key 4F2A.TXT", "srv/credentials", "Windows/Temp/lsass.dmp",
  "home/u/.kube/cache/token", "home/u/.docker/contexts/meta.json", "home/u/.vault-token", "infra/prod.tfvars",
];

test("collection_index: the names of cloud, database, web and recovery-key credential stores are marked and not hashed", async () => {
  await withCwd(async (cwd) => {
    for (const rel of CREDENTIAL_FILES) await put(cwd, `inputs/c/${rel}`, "x");
    await put(cwd, "inputs/c/home/u/notes.txt", "x");
    const out = body(await tool(INDEX, cwd, { root: "inputs/c" }));
    const e = byPath(out);
    const unmarked = CREDENTIAL_FILES.filter((rel) => !e[rel]?.may_hold_secrets?.kind);
    assert.deepEqual(unmarked, []);
    for (const rel of CREDENTIAL_FILES) assert.equal(e[rel].sha256, null, rel);
    assert.match(e["home/u/notes.txt"].sha256, /^[0-9a-f]{64}$/);
  });
});

// ---- P2-7: the copy logs are a table, not a list that outgrows the first 64 KiB ------------------------------------------------

test("collection_index: 400 copy logs are 25 inline and all 400 in a table file the summary names", async () => {
  await withCwd(async (cwd) => {
    for (let i = 0; i < 400; i++) {
      await put(cwd, `inputs/t/run${String(i).padStart(4, "0")}/2026${String(i).padStart(4, "0")}_CopyLog.csv`, [KAPE_COPY_HEADER, kapeCopyRow(`C:\\a${i}.txt`, `D:\\k\\C\\a${i}.txt`)].join("\n") + "\n");
      await put(cwd, `inputs/t/run${String(i).padStart(4, "0")}/C/a${i}.txt`, "x");
    }
    const run = await asJob(INDEX, cwd, { root: "inputs/t", limit: 5 });
    const out = body(run);
    const observed = out.source_paths.observed;
    assert.equal(observed.logs.length, 25);
    assert.equal(observed.logs_table.matched, 400);
    assert.equal((await tableRows(cwd, observed.logs_table)).length, 400);
    assert.equal(observed.files.observed, 400);
    assert.ok(run.stdout.indexOf('"entries"') < 64 * 1024, "the entries start inside the first 64 KiB");
  });
});

// ---- P3: line numbers, the clock while the copy log is loaded, the honest console status, SIGINT, the bound on inline paths --------

test("collection_index: a copy-log row cites the line it starts on, also after a quoted field that spans lines", async () => {
  await withCwd(async (cwd) => {
    const rows = [KAPE_COPY_HEADER, kapeCopyRow("C:\\a\r\nb.txt", "D:\\k\\C\\odd.txt"), "", kapeCopyRow("C:\\two.txt", "D:\\k\\C\\two.txt")].join("\n") + "\n";
    await put(cwd, "inputs/t/1_CopyLog.csv", rows);
    await put(cwd, "inputs/t/C/odd.txt", "x");
    await put(cwd, "inputs/t/C/two.txt", "x");
    const e = byPath(body(await tool(INDEX, cwd, { root: "inputs/t" })));
    assert.equal(e["C/odd.txt"].source_path_observed.row, 1);
    assert.equal(e["C/odd.txt"].source_path_observed.line, 2);
    assert.equal(e["C/two.txt"].source_path_observed.row, 2, "a blank line is not a row");
    assert.equal(e["C/two.txt"].source_path_observed.line, 5, "the cited line is the line of the file, not the ordinal of the parsed rows");
  });
});

const LOAD_CODE = `
import importlib.util, json, os, sys, tempfile
spec = importlib.util.spec_from_file_location("ix", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
root = tempfile.mkdtemp()
rows = [sys.stdin.readline().rstrip("\\n")]
for i in range(3000):
    rows.append("2026-02-14 09:12:00.123,C:\\\\f%d.txt,D:\\\\k\\\\C\\\\f%d.txt,1,x,False,a,b,c,0.1" % (i, i))
open(os.path.join(root, "1_CopyLog.csv"), "w").write("\\n".join(rows) + "\\n")
calls = [0]
def out_of_time():                                   # the run's time is spent after the log was opened, in the middle of its rows
    calls[0] += 1
    return calls[0] > 2
mod.out_of_time = out_of_time
mapping = mod.Mapping()
mapping.load(root, ["1_CopyLog.csv"])
print(json.dumps({"loaded": mapping.rows, "unreadable": mapping.unreadable}))
`;

test("collection_index: the time limit is read while a copy log is loaded, and the mapping says it stopped", async () => {
  const { runPySnippet } = await import("./tool-library-harness.ts");
  const run = await (async () => {
    const { spawn } = await import("node:child_process");
    return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
      const child = spawn("python3", ["-c", LOAD_CODE, INDEX]);
      let out = "";
      let err = "";
      child.stdout.on("data", (c: Buffer) => (out += c.toString()));
      child.stderr.on("data", (c: Buffer) => (err += c.toString()));
      child.on("close", (code) => resolve({ code, stdout: out, stderr: err }));
      child.stdin.end(KAPE_COPY_HEADER + "\n");
    });
  })();
  void runPySnippet;
  assert.equal(run.code, 0, run.stderr);
  const got = JSON.parse(run.stdout);
  assert.ok(got.loaded < 3000, `${got.loaded} rows were loaded after the time was spent`);
  assert.match(JSON.stringify(got.unreadable), /the time limit stopped the mapping after row \d+/);
});

test("collection_id: a KAPE console log with a line it does not know is partial, not parsed", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/t/20260101_ConsoleLog.txt", "[2026-02-14 09:12:00.1234567 | INF] start\na wrapped continuation of the message above\n[2026-02-14 09:12:01.1234567 | ERR] failed\n");
    const out = body(await tool(ID, cwd, { root: "inputs/t" }));
    const record = out.runs[0].logs[0];
    assert.equal(record.status, "partial");
    assert.equal(record.unmatched_lines, 1);
    assert.equal(out.status, "partial");
  });
});

const SIGNAL_CODE = `
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.install_signal_handlers()
os.kill(os.getpid(), getattr(signal, sys.argv[2]))
`;

test("both tools: SIGINT, SIGTERM and SIGHUP leave a JSON answer and the exit status 128 plus the signal", async () => {
  const { runPySnippet } = await import("./tool-library-harness.ts");
  for (const script of [ID, INDEX]) {
    for (const [name, status] of [["SIGINT", 130], ["SIGTERM", 143], ["SIGHUP", 129]] as const) {
      const run = await runPySnippet(SIGNAL_CODE, [script, name], null);
      assert.equal(run.code, status, `${name}: ${run.stderr}`);
      assert.match(JSON.parse(run.stdout).error, /stopped by signal/);
      assert.doesNotMatch(run.stderr, /Traceback|KeyboardInterrupt/);
    }
  }
});

test("collection_id: an unreadable directory with a very long path is 256 characters inline and whole in the problems table", async (t) => {
  if (process.getuid?.() === 0) return t.skip("root can list a directory of mode 000");
  await withCwd(async (cwd) => {
    const parts = [rand(200, "abcdefghijklmnopqrstuvwxyz", 3), rand(200, "abcdefghijklmnopqrstuvwxyz", 4), rand(200, "abcdefghijklmnopqrstuvwxyz", 5)];
    let path = "inputs/t";
    for (const p of parts) path += `/${p}`;
    await mkdir(join(cwd, path), { recursive: true });
    await chmod(join(cwd, path), 0);
    try {
      const out = body(await tool(ID, cwd, { root: "inputs/t" }));
      const inline = out.walk.first_errors[0].path as string;
      assert.ok(inline.length < 340, `${inline.length} characters inline`);
      assert.match(inline, /602 characters in all/);
      const rows = out.problems;
      assert.ok(rows.some((r: Json) => typeof r.path === "string" && r.path.length >= 602 && !r.path.includes("in all")), "the whole path is in the problems table");
    } finally {
      await chmod(join(cwd, path), 0o755);
    }
  });
});

// ---- G1b: the manifests declare secret output, and a values file is written only in a job the service ran as secret output -----

test("both manifests declare secret_output for the arguments that reach a value, the declaration is one the job service reads, and both tools check SECRET_OUTPUT", async () => {
  const { readFile } = await import("node:fs/promises");
  const { parseSecretDeclaration } = await import("../scripts/output-hygiene.ts");
  const want: Record<string, string[]> = { collection_id: ["write_values"], collection_index: ["write_values", "hash_credential_stores"] };
  for (const [name, args] of Object.entries(want)) {
    const manifest: Json = JSON.parse(await readFile(join(ID, "..", "..", name, "manifest.json"), "utf8"));
    assert.deepEqual(manifest.secret_output, { when_args: args }, name);
    const parsed = parseSecretDeclaration(manifest.secret_output, manifest.params, true);
    assert.ok(parsed.ok, JSON.stringify(parsed));
    for (const a of args) assert.equal(manifest.params[a].type, "boolean");
  }
});

test("a job that is not run as secret output refuses write_values and hash_credential_stores as JSON, and writes nothing", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/t/etc/shadow", "x");
    for (const [script, args] of [[ID, { root: "inputs/t", write_values: true }], [INDEX, { root: "inputs/t", write_values: true }], [INDEX, { root: "inputs/t", write_values: true, hash_credential_stores: true }]] as const) {
      const plain = await tool(script, cwd, args, { JOB_ID: "j000777", OUT: join(cwd, "out") });
      const out = refused(plain);
      assert.match(out.error, /not run as secret output|needs a secret-output job/);
      assert.deepEqual(await readdirSafe(join(cwd, "out")), []);
    }
    body(await asJob(INDEX, cwd, { root: "inputs/t", write_values: true, hash_credential_stores: true }, {}, "out", "j000778"));
    assert.equal((await readRows(join(cwd, "out/collection-index-values.jsonl"))).length, 1);
  });
});

async function readdirSafe(dir: string): Promise<string[]> {
  const { readdir } = await import("node:fs/promises");
  return readdir(dir).catch(() => []);
}

const LATE_CODE = `
import json, os, sys, tempfile
work = tempfile.mkdtemp()
os.chdir(work)
os.makedirs("out")
os.environ.update(JOB_ID="j000001", OUT=os.path.join(work, "out"), SECRET_OUTPUT="1")
ns = {}
exec(json.load(sys.stdin)["block"], ns)
ns["VALUES"][0] = ns["SecretValues"](True, "v.jsonl", "t")
early = ns["scrub"]("early ghp_" + "Zq7Svb9Kt0" * 4)
doc = ns["release"]({"status": "complete", "withheld": {"strings_withheld": 1, "values": {}}, "late": "AKIA" + "ZQ7KX3MPL2N4R6TY", "early": early})
rows = [json.loads(l) for l in open(os.path.join(work, "out", "v.jsonl"))]
print(json.dumps({"doc": doc, "rows": len(rows), "late_in_file": any("AKIAZQ7KX3MPL2N4R6TY" in r["value"] for r in rows)}))
`;

test("a string first judged when the answer is serialised is a finding of the values file too, and the file is closed after it", async () => {
  const { readFile } = await import("node:fs/promises");
  const { runPySnippet } = await import("./tool-library-harness.ts");
  const text = await readFile(ID, "utf8");
  const block = text.slice(text.indexOf("# ---- BEGIN SHARED BLOCK"), text.indexOf("# ---- END SHARED BLOCK"));
  const run = await runPySnippet(LATE_CODE, [], { block });
  assert.equal(run.code, 0, run.stderr);
  const got = JSON.parse(run.stdout);
  assert.equal(got.rows, 2);
  assert.equal(got.late_in_file, true);
  assert.equal(got.doc.withheld.values.written, 2, "the count in the answer is the count in the file");
  assert.doesNotMatch(JSON.stringify(got.doc), /ZQ7KX3MPL2N4R6TY/);
});
