/**
 * What a macos-forensics tool counts as written is what its file holds. A write the filesystem refuses (a tmpfs that is full, `ulimit -f`) is found at
 * the row it fails on, not at a later flush: the count of rows (knowledgec_query rows_written / entry_count, fsevents_parse record_count, plist_read
 * rows_written / file_count) equals the lines in out_file, whatever the size of the space it was given. unified_log's reader writes its own file: the
 * lines it counts are the file's. A resume from a count that is larger than the file leaves a silent gap.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { CREATED, FS, KC, PLIST, PYTHON, UL, fsDir, fsPage, fsRecord, kcDb, logarchive, ulStandin } from "./macos-pack-harness.ts";
import type { Json } from "./macos-pack-harness.ts";

const wholeLines = (text: string): number => text.split("\n").length - 1;       // lines that end in a newline: a row cut off at the end is not a row
const nonBlank = (text: string): number => text.split("\n").filter((l) => l.trim() !== "").length;

type Kind = "knowledgec_query" | "fsevents_parse" | "plist_read" | "unified_log";
const SCRIPT: Record<Kind, string> = { knowledgec_query: KC, fsevents_parse: FS, plist_read: PLIST, unified_log: UL };
const KINDS: Kind[] = ["knowledgec_query", "fsevents_parse", "plist_read", "unified_log"];

/** The arguments of a run that writes `target` (an out_file, or for unified_log the out_dir), and the environment it needs. */
async function setup(kind: Kind, cwd: string, target: string): Promise<{ args: unknown; env: Record<string, string> }> {
  if (kind === "knowledgec_query") return { args: { db: await kcDb(cwd, "k.db", 3000), out_file: target }, env: {} };
  if (kind === "fsevents_parse") {
    const records = Array.from({ length: 6000 }, (_, i) => fsRecord(`Users/alice/Library/Caches/app${i % 40}/file-${i}.tmp`, BigInt(i + 1), CREATED, BigInt(i + 1)));
    await fsDir(cwd, "fse", { "0000000000000001": fsPage("2SLD", records) });
    return { args: { path: "work/fse", out_file: target }, env: {} };
  }
  if (kind === "plist_read") {
    await mkdir(join(cwd, "work", "pl"), { recursive: true });
    for (let i = 0; i < 300; i++) {
      await writeFile(join(cwd, "work", "pl", `p${String(i).padStart(4, "0")}.plist`),
        `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>n</key><integer>${i}</integer><key>s</key><string>${"v".repeat(40)}</string></dict></plist>`);
    }
    return { args: { path: "work/pl", out_file: target }, env: {} };
  }
  const bin = await ulStandin(cwd, `
with open(out, "w") as f:
    for i in range(6000):
        f.write(json.dumps({"timestamp": "2026-01-01T00:00:00", "eventMessage": "message number %d" % i, "processImagePath": "/usr/bin/p"}) + chr(10))
`);
  return { args: { path: await logarchive(cwd), out_dir: target }, env: { PATH: bin } };
}

/** How many rows the answer says it wrote, and how many lines the file holds: equal. */
function check(kind: Kind, answer: Json, file: string, where: string): void {
  if (kind === "unified_log") {
    assert.equal(answer.decoded_coverage.lines, nonBlank(file), `${where}: lines counted ${answer.decoded_coverage.lines}, lines in the file ${nonBlank(file)}`);
    return;
  }
  const said = kind === "fsevents_parse" ? answer.record_count : kind === "plist_read" ? (answer.rows_written ?? answer.file_count) : (answer.rows_written ?? answer.entry_count);
  assert.equal(typeof said, "number", `${where}: no count in ${JSON.stringify(answer).slice(0, 200)}`);
  assert.equal(said, wholeLines(file), `${where}: ${said} counted, ${wholeLines(file)} lines in the file`);
}

const fileOf = (kind: Kind, target: string): string => (kind === "unified_log" ? join(target, "unifiedlogs.jsonl") : target);

for (const kind of KINDS) {
  test(`${kind}: the count of rows written equals the lines in the file on a tmpfs of 4 KiB to 16 MiB (unshare -rm)`, async (t) => {
    if (spawnSync("unshare", ["-rm", "true"]).status !== 0) return t.skip("no user and mount namespaces here");
    for (const kb of [4, 16, 64, 256, 1024, 16384]) {
      await withCwd(async (cwd) => {
        const target = kind === "unified_log" ? "work/outs/o" : "work/outs/o.jsonl";
        const { args, env } = await setup(kind, cwd, target);
        await mkdir(join(cwd, "work", "outs"), { recursive: true });
        await writeFile(join(cwd, "work", "args.json"), JSON.stringify(args));
        const file = fileOf(kind, target);
        const run = spawnSync("/usr/bin/unshare", ["-rm", "/bin/sh", "-c",
          `mount -t tmpfs -o size=${kb}k tmpfs work/outs && "$1" "$2" < work/args.json > work/answer.json 2> work/stderr.txt; cat ${file} > work/copy.jsonl 2>/dev/null; true`,
          "sh", PYTHON, SCRIPT[kind]], { cwd, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1", ...env, ...(env.PATH ? { PATH: `${env.PATH}:/usr/bin:/bin` } : {}) } });
        if (run.status !== 0) return t.skip(`cannot mount here: ${run.stderr.slice(0, 120)}`);
        const answer = JSON.parse(await readFile(join(cwd, "work", "answer.json"), "utf8")) as Json;
        check(kind, answer, await readFile(join(cwd, "work", "copy.jsonl"), "utf8").catch(() => ""), `tmpfs ${kb}k`);
        if (kind !== "unified_log") assert.equal(await readFile(join(cwd, "work", "stderr.txt"), "utf8"), "", `tmpfs ${kb}k: the interpreter complained on stderr`);
      });
    }
  });

  test(`${kind}: the count of rows written equals the lines in the file under ulimit -f of 2 to 2,048 blocks`, async () => {
    for (const blocks of [2, 8, 32, 128, 512, 2048]) {
      await withCwd(async (cwd) => {
        const target = kind === "unified_log" ? "work/o" : "work/o.jsonl";
        const { args, env } = await setup(kind, cwd, target);
        await writeFile(join(cwd, "work", "args.json"), JSON.stringify(args));
        // (the setup's own files are written before the limit; the tool and its reader run under it)
        const run = spawnSync("/bin/sh", ["-c", `ulimit -f ${blocks}; "$1" "$2" < work/args.json 2> work/stderr.txt; true`, "sh", PYTHON, SCRIPT[kind]],
          { cwd, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1", ...env } });
        assert.equal(run.status, 0, run.stderr);
        const answer = JSON.parse(run.stdout) as Json;       // (the answer goes to the pipe: a file would be under the limit too)
        check(kind, answer, await readFile(join(cwd, fileOf(kind, target)), "utf8").catch(() => ""), `ulimit -f ${blocks}`);
      });
    }
  });
}
