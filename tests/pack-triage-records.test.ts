/**
 * triage-collection: the records block (the census, the adapters, the join, the hash and the glob) is one text in the four manifest
 * tools and the collection-intake recipe, and the path conventions and credential-store hints in it are collection_index's own,
 * byte for byte. The recipe reads a collector's output archive in one pass, extracts nothing, names an archive inside it without
 * opening it, and says it could not tell where it could not.
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { ROOT, runPySnippet } from "./tool-library-harness.ts";
import { INDEX, KAPE_COPY_HEADER, TOOLS, TRIAGE, body, kapeCopyRow, put, uac3, veloResultRow, veloUploadsRow, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const BEGIN = "# ---- BEGIN RECORDS BLOCK";
const END = "# ---- END RECORDS BLOCK";
const RECIPE = join(TRIAGE, "recipes", "collection-intake", "run.py");
const TOOL_NAMES = ["collection_manifest_parse", "collection_manifest_verify", "collection_path_map", "collection_coverage"];
const digest = (algorithm: string, data: string | Buffer) => createHash(algorithm).update(data).digest("hex");

async function recordsBlock(path: string): Promise<string> {
  const text = await readFile(path, "utf8");
  const start = text.indexOf(BEGIN);
  const end = text.indexOf(END);
  assert.ok(start >= 0 && end > start, `${path} carries the records block`);
  assert.equal(text.indexOf(BEGIN, start + 1), -1, "once");
  return text.slice(start, text.indexOf("\n", end) + 1);
}

test("the four tools and the recipe carry one records block, byte for byte", async () => {
  const blocks = await Promise.all([...TOOL_NAMES.map((n) => join(TOOLS, n, "run.py")), RECIPE].map(recordsBlock));
  for (const b of blocks.slice(1)) assert.equal(b, blocks[0]);
  assert.ok(blocks[0].length > 30000);
});

test("the path conventions, name hints and hypothesis of collection_index are the block's own, unchanged", async () => {
  const index = await readFile(INDEX, "utf8");
  const block = await recordsBlock(join(TOOLS, "collection_path_map", "run.py"));
  const cut = (text: string, from: string, to: string) => text.slice(text.indexOf(from), text.indexOf(to));
  assert.equal(cut(block, "DRIVE_BARE = re.compile", "def source_path_hypothesis"), cut(index, "DRIVE_BARE = re.compile", "def iso_ns"), "constants and hints");
  assert.equal(cut(block, "def source_path_hypothesis", "def split_stream").trimEnd(), cut(index, "def source_path_hypothesis", "def tail_key").trimEnd());
});

test("no tool of the pack calls os.walk, follows a link or starts a session of its own", async () => {
  for (const n of TOOL_NAMES) {
    const text = await readFile(join(TOOLS, n, "run.py"), "utf8");
    assert.doesNotMatch(text, /os\.walk\(|start_new_session|setsid|shell=True|subprocess/, n);
  }
  assert.doesNotMatch(await readFile(RECIPE, "utf8"), /os\.walk\(|start_new_session|setsid|shell=True|subprocess|extractall|\.extract\(/);
});

async function recipe(args: string[], cwd: string): Promise<{ code: number | null; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [RECIPE, ...args], { cwd });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => out.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8") }));
  });
}

const MAKE_ZIP = `
import sys, zipfile, json
out, spec = sys.argv[1], json.loads(sys.argv[2])
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for name, data in spec:
        z.writestr(name, data)
`;

async function zip(path: string, members: Array<[string, string]>): Promise<void> {
  const run = await runPySnippet(MAKE_ZIP, [path, JSON.stringify(members)], null);
  assert.equal(run.code, 0, run.stderr);
}

const target = (p: string) => JSON.stringify({ paths: [p] });
const SAM = "regf-sam".repeat(10);
const COPY = `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\Users\\a\\notes.txt", "D:\\o\\C\\Users\\a\\notes.txt", 5).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", digest("sha1", "hello").toUpperCase())}\n` +
  `${kapeCopyRow("C:\\x.bin", "D:\\o\\C\\x.bin", 9)}\n${kapeCopyRow("C:\\gone", "D:\\o\\C\\gone", 1)}\n`;

test("recipe: a KAPE zip is read in one pass, each member hashed, each claim checked, nothing extracted, nothing left behind", async () => {
  await withCwd(async (cwd) => {
    await zip(join(cwd, "kape.zip"), [["run/2026_CopyLog.csv", COPY], ["run/C/Users/a/notes.txt", "hello"], ["run/C/x.bin", "wrong-size"], ["run/C/SAM", SAM],
      ["run/inner.zip", "PK-not-opened"]]);
    const detect = await recipe(["detect", "--target", target(join(cwd, "kape.zip"))], cwd);
    assert.equal(detect.code, 0, detect.stdout);
    assert.equal(JSON.parse(detect.stdout).applies, true);
    const run = await recipe(["run", "--target", target(join(cwd, "kape.zip")), "--out", "o"], cwd);
    assert.equal(run.code, 0, run.stdout);
    assert.deepEqual((await readdir(join(cwd, "o"))).sort(), ["coverage.json", "index.tsv", "inventory.tsv", "records.jsonl", "units.json", "verification.jsonl"], "no member was written, no temporary directory is left");
    const cov: Json = JSON.parse(await readFile(join(cwd, "o", "coverage.json"), "utf8"));
    assert.equal(cov.status, "complete");
    assert.equal(cov.members, 5);
    assert.equal(cov.records, 3);
    assert.deepEqual(cov.verification, { matched: 1, mismatch: 1, missing: 1 });
    assert.equal(cov.nested_archives_total, 1);
    assert.equal(cov.nested_archives[0].name, "run/inner.zip");
    assert.match(cov.not_covered, /archives inside the archive/);
    const checks = (await readFile(join(cwd, "o", "verification.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(checks.find((c: Json) => c.member === "run/C/Users/a/notes.txt").status, "matched");
    assert.equal(checks.find((c: Json) => c.member === "run/C/x.bin").size.result, "mismatch");
    const inventory = await readFile(join(cwd, "o", "inventory.tsv"), "utf8");
    assert.ok(inventory.includes(digest("sha256", "hello")));
    assert.ok(!inventory.includes(digest("sha256", SAM)), "the digest of a credential store is not listed");
    assert.match(inventory, /withheld: a Windows account database hive/);
  });
});

test("recipe: a UAC tar.gz is read the same way; a name that appears twice is ambiguous, not matched", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "src/u/uac.log", [uac3("INF", "start"), uac3("ERR", "x")].join("\n") + "\n");
    await put(cwd, "src/u/[root]/etc/passwd", "root\n");
    await put(cwd, "src/u/hash_executables/hash_executables.md5", `${digest("md5", "root\n")}  /etc/passwd\n`);
    execFileSync("tar", ["czf", join(cwd, "uac.tar.gz"), "-C", join(cwd, "src"), "u"]);
    const run = await recipe(["run", "--target", target(join(cwd, "uac.tar.gz")), "--out", "o"], cwd);
    assert.equal(run.code, 0, run.stdout);
    const cov: Json = JSON.parse(await readFile(join(cwd, "o", "coverage.json"), "utf8"));
    assert.equal(cov.format, "tar");
    assert.deepEqual(cov.verification, { matched: 1 });
    await zip(join(cwd, "dup.zip"), [["r/2026_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\a", "D:\\o\\C\\a", 1)}\n`], ["r/C/a", "1"], ["r/C/a", "2"]]);
    const dup = await recipe(["run", "--target", target(join(cwd, "dup.zip")), "--out", "d"], cwd);
    assert.equal(dup.code, 0, dup.stdout);
    assert.deepEqual(JSON.parse(await readFile(join(cwd, "d", "coverage.json"), "utf8")).verification, { ambiguous: 1 });
  });
});

test("recipe: not a collector's archive is 'does not apply', a 7z and an unreadable archive are 'could not tell', and a corrupt archive does not crash", async () => {
  await withCwd(async (cwd) => {
    await zip(join(cwd, "plain.zip"), [["a.txt", "x"], ["b/c.txt", "y"]]);
    const plain = await recipe(["detect", "--target", target(join(cwd, "plain.zip"))], cwd);
    assert.equal(plain.code, 1, plain.stdout);
    await put(cwd, "seven.7z", Buffer.concat([Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]), Buffer.alloc(64)]));
    assert.equal((await recipe(["detect", "--target", target(join(cwd, "seven.7z"))], cwd)).code, 2);
    await put(cwd, "text.bin", "just text, no archive at all in here, not a tar either");
    assert.equal((await recipe(["detect", "--target", target(join(cwd, "text.bin"))], cwd)).code, 1);
    assert.equal((await recipe(["detect", "--target", target(join(cwd, "missing.zip"))], cwd)).code, 2);
    await put(cwd, "bad.zip", Buffer.concat([Buffer.from("PK\x03\x04"), Buffer.alloc(40, 0x41)]));
    const bad = await recipe(["detect", "--target", target(join(cwd, "bad.zip"))], cwd);
    assert.ok(bad.code === 2 || bad.code === 1, bad.stdout);
    assert.doesNotMatch(bad.stdout, /Traceback/);
    const run = await recipe(["run", "--target", target(join(cwd, "bad.zip")), "--out", "b"], cwd);
    assert.doesNotMatch(run.stdout, /Traceback/);
    assert.notEqual((await stat(join(cwd, "b", "coverage.json"))).size, 0);
    const failed: Json = JSON.parse(await readFile(join(cwd, "b", "coverage.json"), "utf8"));
    assert.ok(["failed", "partial"].includes(failed.status), "the receipt says it did not finish");
    const noOut = await recipe(["run", "--target", target(join(cwd, "plain.zip"))], cwd);
    assert.equal(noOut.code, 2);
  });
});

test("recipe: a Velociraptor container in a zip is read like the directory; the tool and the recipe agree on the same claims", async () => {
  await withCwd(async (cwd) => {
    const text = "hello world";
    const members: Array<[string, string]> = [
      ["v/uploads.json", veloUploadsRow("auto/C:/Windows/a.txt", 11, 11) + "\n"],
      ["v/uploads/auto/C%3A/Windows/a.txt", text],
      ["v/results/A.json", veloResultRow("C:/Windows/a.txt").replace("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", digest("sha256", text)) + "\n"],
      ["v/log.json", JSON.stringify({ level: "INFO", message: "x" }) + "\n"],
    ];
    await zip(join(cwd, "v.zip"), members);
    for (const [name, data] of members) await put(cwd, `tree/${name}`, data);
    const run = await recipe(["run", "--target", target(join(cwd, "v.zip")), "--out", "o"], cwd);
    assert.equal(run.code, 0, run.stdout);
    const recipeChecks = (await readFile(join(cwd, "o", "verification.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const verify = body(await (await import("./pack-triage-harness.ts")).tool(join(TOOLS, "collection_manifest_verify", "run.py"), cwd, { root: "tree" }));
    const toolChecks = await (await import("./pack-triage-harness.ts")).tableRows(cwd, verify.tables.checks);
    const strip = (c: Json) => `${c.kind}|${c.status}|${c.path.result}|${c.size.result}|${c.hash.result}`;
    assert.deepEqual(recipeChecks.map(strip).sort(), toolChecks.map(strip).sort(), "the same claims get the same results from the archive and from the tree");
  });
});

test("recipe: the manifest and the pack declare it, and the seal carries its entry's sha256", async () => {
  const recipeJson: Json = JSON.parse(await readFile(join(TRIAGE, "recipes", "collection-intake", "recipe.json"), "utf8"));
  assert.equal(recipeJson.sha256, digest("sha256", await readFile(RECIPE)));
  const pack: Json = JSON.parse(await readFile(join(TRIAGE, "pack.json"), "utf8"));
  assert.ok(pack.recipes.includes("triage-collection/collection-intake"));
  assert.ok(!("secret_output" in recipeJson));
  assert.match(recipeJson.covers, /extracts nothing to disk/);
  assert.ok(ROOT);
});
