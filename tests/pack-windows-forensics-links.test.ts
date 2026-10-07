/**
 * The windows-forensics pack's tools that read or hand on link structures and streams: lnk_parse, jumplist,
 * extract_stream, vss_stores and yara_scan. Each test here fails on the tools as they were before the fix
 * (point WINDOWS_PACK_TOOLS at a copy of them, see the header of pack-windows-forensics.test.ts) and passes on the
 * tools as they are.
 *
 * Where each layout comes from: lnk_parse's fixtures are MS-SHLLINK (the 76-byte header, then StringData: a 16-bit
 * character count and the characters, UTF-16LE when LinkFlags has IsUnicode, in the order name, relative path, working
 * directory, arguments, icon location; then the 4-byte terminal block). jumplist's customDestinations files are link
 * structures one after another, each starting with its own 20-byte header.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ownPathsToOut } from "../extensions/protocol.ts";
import { withCwd } from "./tool-library-harness.ts";
import { AGENT, WIN, body, everyFileUnder, exists, failed, stub, stubModule, tool, type Run } from "./windows-pack-harness.ts";

const root = process.getuid?.() === 0;
const LNK_MAGIC = Buffer.from("4c0000000114020000000000c000000000000046", "hex");

/** The planted value in every form an answer could carry it: whole, its fragments, hex and base64, as ASCII and as UTF-16. */
function pieces(value: string, fragments: string[]): string[] {
  const forms = [value, ...fragments];
  const out: string[] = [];
  for (const f of forms) {
    for (const buf of [Buffer.from(f, "latin1"), Buffer.from(f, "utf16le")]) {
      out.push(f, buf.toString("hex"), buf.toString("base64").replace(/=+$/, ""));
    }
  }
  return [...new Set(out)].filter((x) => x.length >= 6);
}

/** A tool run with a deadline: a tool that waits on a FIFO is killed, and the test says so instead of hanging. */
async function limited(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, seconds = 15): Promise<Run & { killed: boolean; seconds: number }> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const child = spawn("python3", [script], { cwd, env: { ...process.env, ...AGENT, ...env } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let killed = false;
    const timer = setTimeout(() => { killed = true; child.kill("SIGKILL"); }, seconds * 1000);
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), killed, seconds: (Date.now() - started) / 1000 });
    });
    child.stdin.end(JSON.stringify(args));
  });
}

/** The peak resident size of a run, in MiB, and its answer: python3 runs the tool as a child and reports the child's high-water mark. */
async function measured(script: string, cwd: string, args: unknown, env: Record<string, string> = {}): Promise<{ run: Run; peakMiB: number }> {
  const wrapper = `
import json, os, resource, subprocess, sys
p = subprocess.run(["python3", sys.argv[1]], input=sys.stdin.buffer.read(), capture_output=True)
peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
scale = 1 if sys.platform == "darwin" else 1024
sys.stdout.write(json.dumps({"code": p.returncode, "stdout": p.stdout.decode("utf8", "replace"), "stderr": p.stderr.decode("utf8", "replace"), "peak": peak * scale}))
`;
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", wrapper, script], { cwd, env: { ...process.env, ...AGENT, ...env } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.on("error", reject);
    child.on("close", () => {
      const r = JSON.parse(Buffer.concat(out).toString("utf8")) as { code: number; stdout: string; stderr: string; peak: number };
      resolve({ run: { code: r.code, stdout: r.stdout, stderr: r.stderr }, peakMiB: r.peak / (1024 * 1024) });
    });
    child.stdin.end(JSON.stringify(args));
  });
}

// --- lnk_parse ------------------------------------------------------------------

/** A shell link: the 76-byte header, StringData in the order MS-SHLLINK gives (name, relative path, working directory, arguments, icon location), and the terminal block. */
function lnk(strings: { name?: string; relativePath?: string; workingDir?: string; arguments?: string; icon?: string }): Buffer {
  const header = Buffer.alloc(0x4c);
  header.writeUInt32LE(0x4c, 0);
  LNK_MAGIC.subarray(4).copy(header, 4);
  const order: Array<[number, string | undefined]> = [[0x04, strings.name], [0x08, strings.relativePath], [0x10, strings.workingDir], [0x20, strings.arguments], [0x40, strings.icon]];
  let flags = 0x80;
  const parts: Buffer[] = [];
  for (const [bit, text] of order) {
    if (text === undefined) continue;
    flags |= bit;
    const count = Buffer.alloc(2);
    count.writeUInt16LE(text.length, 0);
    parts.push(count, Buffer.from(text, "utf16le"));
  }
  header.writeUInt32LE(flags, 0x14);
  return Buffer.concat([header, ...parts, Buffer.alloc(4)]);
}

type LnkOut = {
  ok?: boolean;
  error?: string;
  name?: string;
  relative_path?: string;
  working_dir?: string;
  arguments?: unknown;
  arguments_present: boolean;
  arguments_chars: number;
  arguments_first_token: string | null;
  arguments_first_token_withheld?: boolean;
  arguments_finding_id?: string;
  utf16_strings: Array<Record<string, unknown>>;
  utf16_string_count: number;
  sensitive_fields_withheld?: Array<{ field: string; chars: number; finding_id: string }>;
  secret_values: { requested: boolean; written: number; values_file: string | null; contains_secret_values: boolean };
  hits?: LnkOut[];
};

const SECRET_ARGS = "-u admin --password Hunter2Secret!";
const SECRET_FORMS = pieces("Hunter2Secret!", ["Hunter2", "Secret!", "--password Hunter2Secret!"]);

async function jobDir(cwd: string): Promise<string> {
  const dir = join(cwd, "out");
  await mkdir(dir, { recursive: true });
  return dir;
}

async function valueRows(file: string): Promise<Array<{ finding_id: string; field: string; value: string; link_offset: number }>> {
  return (await readFile(file, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { finding_id: string; field: string; value: string; link_offset: number });
}

test("lnk_parse never prints a link's arguments: their length, that there are some and a first switch, and the text only in a job's values file", async () => {
  // `arguments` and every string the scan found (`utf16_strings`) were printed whole: `-u admin --password Hunter2Secret!`
  // was in stdout twice.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "a.lnk"), lnk({ name: "Nightly job", relativePath: "..\\tools\\run.exe", arguments: SECRET_ARGS }));
    const run = await tool("lnk_parse", cwd, { path: "work/a.lnk" });
    const out = body<LnkOut>(run);
    for (const piece of SECRET_FORMS) assert.equal(run.stdout.includes(piece), false, `stdout holds ${piece}`);
    assert.equal(out.arguments, undefined);
    assert.equal(out.arguments_present, true);
    assert.equal(out.arguments_chars, SECRET_ARGS.length);
    assert.equal(out.arguments_first_token, "-u");
    assert.equal(out.name, "Nightly job");
    assert.equal(out.relative_path, "..\\tools\\run.exe", "a path with no secret's shape is printed");
    assert.ok(out.utf16_string_count >= 1);
    for (const row of out.utf16_strings) {
      assert.deepEqual(Object.keys(row).sort(), ["chars", "file_offset", "finding_id", "link_offset", "offset"], "a string's place and length, never its text");
    }
    assert.equal(out.secret_values.requested, false);
    assert.equal(out.secret_values.written, 0);

    // Outside a job the values are refused, and nothing is written.
    const refused = failed(await tool("lnk_parse", cwd, { path: "work/a.lnk", write_strings: true }));
    assert.match(refused.error, /refused outside a job/);
    assert.deepEqual((await everyFileUnder(join(cwd, "work"))).filter((f) => f.includes("lnk-strings")), []);

    // In a job the text is in one 0600 file, under the finding id the answer cites; the answer still has none of it.
    const outDir = await jobDir(cwd);
    const jobRun = await tool("lnk_parse", cwd, { path: "work/a.lnk", write_strings: true }, { JOB_ID: "j000001", OUT: outDir });
    const job = body<LnkOut>(jobRun);
    for (const piece of SECRET_FORMS) assert.equal(jobRun.stdout.includes(piece), false, `the job's stdout holds ${piece}`);
    assert.equal(job.secret_values.values_file, "store/jobs/j000001/out/lnk-strings.jsonl");
    assert.equal(job.secret_values.contains_secret_values, true);
    const file = join(outDir, "lnk-strings.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const rows = await valueRows(file);
    const args = rows.filter((r) => r.finding_id === job.arguments_finding_id);
    assert.deepEqual(args.map((r) => r.value), [SECRET_ARGS]);
    assert.ok(rows.length >= 2, "the strings the scan found are in the file too");
    // Nothing else the tool wrote holds it, in any form.
    for (const other of (await everyFileUnder(cwd)).filter((f) => f !== file && !f.endsWith("a.lnk") && !f.includes("/bin/"))) {
      const text = (await readFile(other)).toString("latin1") + (await readFile(other)).toString("utf16le");
      for (const piece of SECRET_FORMS) assert.equal(text.includes(piece), false, `${other} holds ${piece}`);
    }

    // A second run in the same job reads the link all the same and writes the next numbered file: the first is as it was.
    const before = await readFile(file);
    const again = body<LnkOut>(await tool("lnk_parse", cwd, { path: "work/a.lnk", write_strings: true }, { JOB_ID: "j000001", OUT: outDir }));
    assert.equal(again.secret_values.values_file, "store/jobs/j000001/out/lnk-strings-2.jsonl");
    assert.deepEqual(await readFile(file), before);
  });
});

test("lnk_parse shows a first token only when it can only be a switch or a program, and withholds a field that has a secret's shape", async () => {
  await withCwd(async (cwd) => {
    const cases: Array<[string, string | null]> = [
      ["C:\\Windows\\System32\\cmd.exe /c whoami", "C:\\Windows\\System32\\cmd.exe"],
      ["powershell -nop -w hidden", "powershell"],
      ["--password=Hunter2Secret!", "--password"],
      ["Hunter2Secret! --verbose", null],
      ["", null],
    ];
    for (const [i, [text, token]] of cases.entries()) {
      await writeFile(join(cwd, "work", `t${i}.lnk`), lnk({ arguments: text }));
      const out = body<LnkOut>(await tool("lnk_parse", cwd, { path: `work/t${i}.lnk` }));
      assert.equal(out.arguments_first_token, token, text);
      assert.equal(out.arguments_chars, text.length);
      if (text && token === null) assert.equal(out.arguments_first_token_withheld, true, text);
    }
    const planted = "https://svc:Pa55w0rd!@vault.example/x";
    await writeFile(join(cwd, "work", "p.lnk"), lnk({ relativePath: planted, workingDir: "C:\\Users\\x\\password=Winter2026", icon: "C:\\icons\\app.ico" }));
    const run = await tool("lnk_parse", cwd, { path: "work/p.lnk" });
    const out = body<LnkOut>(run);
    for (const piece of pieces("Pa55w0rd!", ["Pa55w0rd", "Winter2026", "svc:Pa55w0rd"])) assert.equal(run.stdout.includes(piece), false, piece);
    assert.equal(out.relative_path, `[withheld: ${planted.length} characters]`);
    assert.equal(out.working_dir, `[withheld: ${"C:\\Users\\x\\password=Winter2026".length} characters]`);
    assert.deepEqual(out.sensitive_fields_withheld?.map((f) => f.field).sort(), ["relative_path", "working_dir"]);
    assert.equal((out as unknown as { icon_location: string }).icon_location, "C:\\icons\\app.ico");
  });
});

test("lnk_parse scan mode withholds the arguments of every link it carves", async () => {
  await withCwd(async (cwd) => {
    const dump = Buffer.concat([Buffer.alloc(40, 1), lnk({ arguments: SECRET_ARGS }), Buffer.alloc(30, 1), lnk({ arguments: "-token=Winter2026Token" })]);
    await writeFile(join(cwd, "work", "dump.bin"), dump);
    const run = await tool("lnk_parse", cwd, { dump: "work/dump.bin", size: dump.length, scan: true });
    const out = body<{ count: number; hits: LnkOut[] }>(run);
    assert.equal(out.count, 2);
    for (const piece of [...SECRET_FORMS, ...pieces("Winter2026Token", ["Winter2026"])]) assert.equal(run.stdout.includes(piece), false, piece);
    assert.deepEqual(out.hits.map((h) => h.arguments_chars), [SECRET_ARGS.length, "-token=Winter2026Token".length]);
  });
});

test("lnk_parse reads a very long run of one byte in bounded memory, with a bounded answer", async () => {
  // 32 MiB of 0x41 after a header took 1,256 MiB and printed 100 MB; the scan decoded the whole read as one string.
  await withCwd(async (cwd) => {
    const size = 16 * 1024 * 1024;
    await writeFile(join(cwd, "work", "big.bin"), Buffer.concat([lnk({}).subarray(0, 0x4c), Buffer.alloc(size, 0x41)]));
    const { run, peakMiB } = await measured(join(WIN, "lnk_parse", "run.py"), cwd, { path: "work/big.bin", size: size + 0x4c });
    const out = body<LnkOut>(run);
    assert.ok(run.stdout.length < 100_000, `the answer is ${run.stdout.length} bytes`);
    assert.equal(out.utf16_string_count, 1);
    assert.equal(out.utf16_strings[0].chars, size / 2);
    assert.ok(peakMiB < 120, `peak ${peakMiB.toFixed(0)} MiB for a ${size / 1024 / 1024} MiB read`);
  });
});

test("lnk_parse reads 128 MiB of zeros after a header in a pass, not a Python loop per character", async () => {
  // 200 MiB of zeros took 24.9 s.
  await withCwd(async (cwd) => {
    const size = 128 * 1024 * 1024;
    await writeFile(join(cwd, "work", "zeros.bin"), Buffer.concat([lnk({}).subarray(0, 0x4c), Buffer.alloc(size)]));
    const started = Date.now();
    const out = body<LnkOut>(await tool("lnk_parse", cwd, { path: "work/zeros.bin", size: size + 0x4c }));
    assert.equal(out.utf16_string_count, 0);
    assert.ok((Date.now() - started) / 1000 < 8, `took ${(Date.now() - started) / 1000} s`);
  });
});

test("lnk_parse answers a file it cannot read, or one that is no link, as JSON that names no bytes of it", async (t) => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "no.lnk"), Buffer.from("password=Summer2024! is what this file holds, and it is no link at all, padding padding"));
    const notLink = await tool("lnk_parse", cwd, { path: "work/no.lnk" });
    const answer = failed(notLink) as unknown as { error: string; bytes_read: number; first_bytes_hex?: string };
    assert.match(answer.error, /not a LNK header/);
    assert.equal(answer.first_bytes_hex, undefined, "the first bytes of a file that is no link can be anything");
    assert.equal(notLink.stdout.includes(Buffer.from("password=Summer2").toString("hex")), false);
    if (root) return t.skip("root reads a mode 000 file");
    await writeFile(join(cwd, "work", "locked.lnk"), lnk({}));
    await chmod(join(cwd, "work", "locked.lnk"), 0o000);
    try {
      const locked = failed(await tool("lnk_parse", cwd, { path: "work/locked.lnk" }));
      assert.match(locked.error, /could not be read/);
    } finally {
      await chmod(join(cwd, "work", "locked.lnk"), 0o644);
    }
  });
});

// --- jumplist -------------------------------------------------------------------

type JumpOut = {
  status: string;
  file_count: number;
  files_failed: number;
  files_not_attempted: number;
  not_attempted: Array<{ file: string; reason: string }>;
  files: Array<{ file: string; links: Array<{ offset?: number; bytes: number; written_to?: string; is_link: boolean | null; not_read?: boolean; stream?: string }>; link_count: number; problems?: string[] }>;
  error?: string;
};

test("jumplist searches a customDestinations file a window at a time and writes each link from its own range", async () => {
  // A 200 MiB file took 420 MiB: it was read whole, and every structure was copied out of it once more.
  await withCwd(async (cwd) => {
    const size = 48 * 1024 * 1024;
    const file = Buffer.alloc(size, 0x20);
    const at = [4, 32 * 1024 * 1024 + 3];
    for (const [i, offset] of at.entries()) {
      LNK_MAGIC.copy(file, offset);
      file.write(`payload-${i}`, offset + 20, "latin1");
    }
    await writeFile(join(cwd, "work", "5f7b5f1e01b83767.customDestinations-ms"), file);
    const { run, peakMiB } = await measured(join(WIN, "jumplist", "run.py"), cwd, { path: "work/5f7b5f1e01b83767.customDestinations-ms", out_dir: "work/s1/links" });
    const out = body<JumpOut>(run);
    const links = out.files[0].links;
    assert.deepEqual(links.map((l) => l.offset), at);
    assert.deepEqual(links.map((l) => l.bytes), [at[1] - at[0], size - at[1]]);
    assert.equal((await stat(join(cwd, links[0].written_to!))).size, at[1] - at[0]);
    const tail = await readFile(join(cwd, links[1].written_to!));
    assert.equal(tail.length, size - at[1]);
    assert.deepEqual(tail.subarray(0, 28), file.subarray(at[1], at[1] + 28));
    assert.ok(peakMiB < 90, `peak ${peakMiB.toFixed(0)} MiB for a ${size / 1024 / 1024} MiB file`);
  });
});

test("jumplist finds a link header that straddles two search windows exactly once", async () => {
  await withCwd(async (cwd) => {
    const window = 1024 * 1024;
    const file = Buffer.alloc(3 * window, 0x20);
    for (const offset of [window - 7, 2 * window - 20, 2 * window]) LNK_MAGIC.copy(file, offset);
    await writeFile(join(cwd, "work", "x.customDestinations-ms"), file);
    const out = body<JumpOut>(await tool("jumplist", cwd, { path: "work/x.customDestinations-ms" }));
    assert.deepEqual(out.files[0].links.map((l) => l.offset), [window - 7, 2 * window - 20, 2 * window]);
  });
});

// olefile as jumplist asks of it, with one stream that claims 200 MiB and must never be opened.
const OLEFILE_BIG = String.raw`
def isOleFile(path):
    return True


class _Stream:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data


class OleFileIO:
    def __init__(self, path):
        pass

    def listdir(self):
        return [["1"], ["huge"]]

    def get_size(self, name):
        return 200 * 1024 * 1024 if name == "huge" else 24

    def openstream(self, name):
        if name == "huge":
            raise AssertionError("a stream of 200 MiB must not be opened")
        return _Stream(bytes.fromhex("4c0000000114020000000000c000000000000046") + b"abcd")

    def close(self):
        pass
`;

test("jumplist names a stream past what it reads whole instead of reading it, and says the list is partial", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "x.automaticDestinations-ms"), "stub");
    const env = await stubModule(cwd, { "olefile.py": OLEFILE_BIG });
    const out = body<JumpOut>(await tool("jumplist", cwd, { path: "work/x.automaticDestinations-ms" }, env));
    const file = out.files[0];
    assert.equal(file.links.find((l) => l.stream === "huge")?.not_read, true);
    assert.equal(file.links.find((l) => l.stream === "1")?.is_link, true);
    assert.match(file.problems?.join(" ") ?? "", /huge is 209715200 bytes/);
    assert.equal(out.status, "partial");
  });
});

test("jumplist does not open a FIFO, a named pipe in a directory of jump lists or one named as the path, and counts it", async () => {
  // A FIFO named *.automaticDestinations-ms made it wait for a writer, until the job's time limit.
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "lists");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "good.customDestinations-ms"), Buffer.concat([Buffer.from([2, 0, 0, 0]), LNK_MAGIC, Buffer.from("x".repeat(30))]));
    const mk = await new Promise<number | null>((resolve) => spawn("mkfifo", [join(dir, "pipe.automaticDestinations-ms")]).on("close", resolve));
    assert.equal(mk, 0);
    const swept = await limited(join(WIN, "jumplist", "run.py"), cwd, { path: "work/lists" });
    assert.equal(swept.killed, false, "the tool waited on the FIFO");
    const out = JSON.parse(swept.stdout) as JumpOut;
    assert.equal(out.files_not_attempted, 1);
    assert.match(out.not_attempted[0].file, /pipe\.automaticDestinations-ms$/);
    assert.match(out.not_attempted[0].reason, /not a regular file/);
    assert.equal(out.files[0].links.length, 1, "the regular file beside it is read");
    assert.equal(out.status, "partial");

    const direct = await limited(join(WIN, "jumplist", "run.py"), cwd, { path: "work/lists/pipe.automaticDestinations-ms" });
    assert.equal(direct.killed, false);
    assert.notEqual(direct.code, 0);
    assert.doesNotMatch(direct.stderr, /Traceback/);
    const refusal = JSON.parse(direct.stdout) as { error: string; not_attempted: number };
    assert.match(refusal.error, /not a regular file or a directory/);
    assert.equal(refusal.not_attempted, 1);
  });
});

test("jumplist writes its links only where the harness lets a job write, and says where when it is asked for anywhere else", async () => {
  // The manifest's example out_dir, work/extracted/jumplinks, is not a place a job can write (the harness maps only
  // work/<id>/, work/extracted/<id>/, work/quarantine/<id>/ and tool-output/<id>/): PermissionError, no link written.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "x.customDestinations-ms"), Buffer.concat([Buffer.from([2, 0, 0, 0]), LNK_MAGIC, Buffer.from("x".repeat(30))]));
    const elsewhere = failed(await tool("jumplist", cwd, { path: "work/x.customDestinations-ms", out_dir: "work/extracted/jumplinks" }));
    assert.match(elsewhere.error, /out_dir must be a directory inside the run directory, in work\/s1\/, work\/extracted\/s1\/ or work\/quarantine\/s1\//);
    assert.equal(await exists(join(cwd, "work", "extracted")), false);
    for (const own of ["work/s1/links", "work/extracted/s1/links", "work/quarantine/s1/links"]) {
      const ok = body<JumpOut>(await tool("jumplist", cwd, { path: "work/x.customDestinations-ms", out_dir: own }));
      assert.match(ok.files[0].links[0].written_to ?? "", new RegExp(`^${own}/`));
    }

    // In a job only $OUT is writable: the harness gives a work/<id>/... path as {OUT}/..., and nothing else is a place.
    const outDir = await jobDir(cwd);
    const job = { JOB_ID: "j000003", OUT: outDir };
    const mapped = body<JumpOut>(await tool("jumplist", cwd, { path: "work/x.customDestinations-ms", out_dir: join(outDir, "links") }, job));
    assert.equal(await exists(join(outDir, "links")), true);
    assert.equal((await readdir(join(outDir, "links"))).length, 1);
    assert.ok(mapped.files[0].links[0].written_to);
    const unmapped = failed(await tool("jumplist", cwd, { path: "work/x.customDestinations-ms", out_dir: "work/s1/links2" }, job));
    assert.match(unmapped.error, /in \$OUT/);
  });
});

test("the manifest examples of the tools that write files name a place the harness lets a job write", async () => {
  for (const name of ["jumplist", "extract_stream"]) {
    const manifest = JSON.parse(await readFile(join(WIN, name, "manifest.json"), "utf8")) as { example: string };
    const example = JSON.parse(manifest.example.replaceAll("<your id>", "s1")) as Record<string, string>;
    const mapped = ownPathsToOut(example, "s1") as Record<string, string>;
    const writes = name === "jumplist" ? mapped.out_dir : mapped.output;
    assert.match(writes, /^\{OUT\}/, `${name}: ${manifest.example} stays where a job cannot write it`);
  }
});

test("jumplist's manifest does not hint every compound file: the OLE signature is not in its use, the file names are", async () => {
  const manifest = JSON.parse(await readFile(join(WIN, "jumplist", "manifest.json"), "utf8")) as { use: { magic?: unknown; names?: string[]; extensions?: string[] } };
  assert.equal(manifest.use.magic, undefined, "d0cf11e0a1b11ae1 is every .doc, .msi and Thumbs.db");
  assert.deepEqual(manifest.use.names, ["*.automaticDestinations-ms", "*.customDestinations-ms"]);
});

// --- extract_stream -------------------------------------------------------------

type StreamOut = { status: string; error?: string; output?: string; stderr_file: string | null; partial_file?: string; partial_bytes?: number };

const ICAT = (script: string): string => `printf '%s\\n' "$@" > "$ICAT_ARGS"\n${script}`;

test("extract_stream never replaces what an earlier run kept: the next partial and stderr take the next free name", async () => {
  // A rerun opened `.stderr` for writing and os.replace'd the new partial over the old: a 1 MiB partial became 4 bytes.
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "disk.raw"), Buffer.alloc(1024));
    const env = { ICAT_ARGS: join(cwd, "icat-args") };
    await stub(bin, "icat", ICAT(`head -c 1048576 /dev/zero | tr '\\0' 'A'\necho "first failure" >&2\nexit 1`));
    const first = failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "9", output: "work/s1/x.bin" }, env, bin)) as unknown as StreamOut;
    assert.equal(first.partial_file, "work/s1/x.bin.partial");
    assert.equal(first.stderr_file, "work/s1/x.bin.stderr");
    await stub(bin, "icat", ICAT(`printf 'tiny'\necho "second failure" >&2\nexit 1`));
    const second = failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "9", output: "work/s1/x.bin" }, env, bin)) as unknown as StreamOut;
    assert.equal(second.partial_file, "work/s1/x.bin.partial.2");
    assert.equal(second.stderr_file, "work/s1/x.bin.stderr.2");
    assert.equal(second.partial_bytes, 4);
    assert.equal((await stat(join(cwd, "work", "s1", "x.bin.partial"))).size, 1048576, "the first run's partial is as it was");
    assert.equal(await readFile(join(cwd, "work", "s1", "x.bin.stderr"), "utf8"), "first failure\n");
    assert.equal(await readFile(join(cwd, "work", "s1", "x.bin.stderr.2"), "utf8"), "second failure\n");
    // A third run takes the next number again.
    const third = failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "9", output: "work/s1/x.bin" }, env, bin)) as unknown as StreamOut;
    assert.equal(third.partial_file, "work/s1/x.bin.partial.3");
    assert.equal(third.stderr_file, "work/s1/x.bin.stderr.3");
  });
});

test("extract_stream writes only in the agent's own places, in a job only under $OUT, and answers a directory it cannot make as JSON", async () => {
  // Outside a job it wrote anywhere inside the run; and the manifest's example, work/extracted/168-128-4.bin, is a place
  // the harness leaves read-only in a job.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "icat", ICAT(`printf 'x'`));
    await writeFile(join(cwd, "work", "disk.raw"), Buffer.alloc(1024));
    const env = { ICAT_ARGS: join(cwd, "icat-args") };
    const refused = failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "5", output: "work/extracted/168-128-4.bin" }, env, bin));
    assert.match(refused.error, /in work\/s1\/, work\/extracted\/s1\/ or work\/quarantine\/s1\//);
    assert.equal(await exists(join(cwd, "work", "extracted")), false);
    assert.match(failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "5", output: "work/other.bin" }, env, bin)).error, /in work\/s1\//);
    assert.match(failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "5", output: "work/s2/x.bin" }, env, bin)).error, /in work\/s1\//);
    for (const own of ["work/s1/a.bin", "work/extracted/s1/a.bin", "work/quarantine/s1/a.bin"]) {
      assert.equal(body<StreamOut>(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "5", output: own }, env, bin)).status, "complete", own);
    }
    // In a job: under $OUT, and nothing mapped is anything else.
    const outDir = await jobDir(cwd);
    const job = { ...env, JOB_ID: "j000004", OUT: outDir };
    assert.equal(body<StreamOut>(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "5", output: join(outDir, "extracted", "a.bin") }, job, bin)).status, "complete");
    assert.match(failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "5", output: "work/s1/b.bin" }, job, bin)).error, /in \$OUT/);
    // A directory that cannot be made is JSON, not a traceback (work/blocker is a file).
    await writeFile(join(cwd, "work", "s1", "blocker"), "a file");
    const blocked = failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "5", output: "work/s1/blocker/sub/x.bin" }, env, bin));
    assert.match(blocked.error, /directory for output could not be created/);
  });
});

// --- vss_stores -----------------------------------------------------------------

type VssOut = { status: string; stdout_file: string; stderr_file: string; earlier_output_files: string[] };

const VSS_REPORT = (note: string): string => `cat <<'REPORT'\nvshadowinfo 20240101\n\nVolume Shadow Snapshot information:\n\tNumber of stores:\t0\nREPORT\necho '${note}' >&2`;

test("vss_stores keeps the files of an earlier run with the same arguments and writes a new pair, naming what was there", async () => {
  // The stdout and stderr files were named by the arguments' digest and opened for writing: a rerun truncated them.
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "disk.raw"), Buffer.alloc(4096));
    await stub(bin, "vshadowinfo", VSS_REPORT("first run"));
    const first = body<VssOut>(await tool("vss_stores", cwd, { image: "work/disk.raw" }, {}, bin));
    assert.deepEqual(first.earlier_output_files, []);
    await stub(bin, "vshadowinfo", VSS_REPORT("second run"));
    const second = body<VssOut>(await tool("vss_stores", cwd, { image: "work/disk.raw" }, {}, bin));
    assert.notEqual(second.stderr_file, first.stderr_file);
    assert.notEqual(second.stdout_file, first.stdout_file);
    assert.equal(second.earlier_output_files.length, 2);
    assert.match(await readFile(join(cwd, first.stderr_file), "utf8"), /first run/);
    assert.match(await readFile(join(cwd, second.stderr_file), "utf8"), /second run/);
    const third = body<VssOut>(await tool("vss_stores", cwd, { image: "work/disk.raw" }, {}, bin));
    assert.equal(third.earlier_output_files.length, 4);
    assert.match(await readFile(join(cwd, first.stdout_file), "utf8"), /Number of stores/);
  });
});

// --- yara_scan ------------------------------------------------------------------

type YaraOut = {
  status: string;
  complete: boolean;
  scan_error_count: number;
  scan_errors: Array<{ file: string; reason: string | null }>;
  not_attempted_count: number;
  not_attempted: Array<{ file: string; reason: string }>;
  stderr_file: string | null;
  match_count: number;
  secret_values: { values_file: string | null };
};

/** yara as 4.x prints it for `-s -L`; `${extra}` runs first and can write to stderr. */
const YARA = (extra = ""): string => `
case "$1" in
  --version) echo 4.5.8; exit 0;;
  --help) printf '%s\\n' '  -s,  --print-strings   print matching strings' '  -L,  --print-string-length   print length of matched strings' '  -N,  --no-follow-symlinks   do not follow symlinks'; exit 0;;
esac
for last; do :; done
${extra}
echo "pw $last/a.txt"
echo '0x0:5:$a: hello'
`;

test("yara_scan does not call a run complete that printed `error scanning`: the files are counted and named, and the run is partial", async () => {
  // yara exits 0 after `error scanning <file>: could not open file`, and the answer said complete: true.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", YARA(`echo "error scanning $last/locked.txt: could not open file" >&2\necho "error scanning $last/other.txt: could not map file" >&2`));
    await mkdir(join(cwd, "work", "d"), { recursive: true });
    await writeFile(join(cwd, "work", "rules.yar"), "rule pw { condition: true }");
    await writeFile(join(cwd, "work", "d", "a.txt"), "hello");
    const out = body<YaraOut>(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/d" }, {}, bin));
    assert.equal(out.complete, false);
    assert.equal(out.status, "partial");
    assert.equal(out.scan_error_count, 2);
    assert.deepEqual(out.scan_errors.map((e) => [e.file, e.reason]), [["work/d/locked.txt", "could not open file"], ["work/d/other.txt", "could not map file"]]);
    assert.equal(out.match_count, 1, "what was read is still listed");
  });
});

test("yara_scan against the installed yara counts the file it could not open", async (t) => {
  if (root) return t.skip("root opens a mode 000 file");
  const present = await new Promise<boolean>((resolve) => spawn("yara", ["--version"]).on("error", () => resolve(false)).on("close", (c) => resolve(c === 0)));
  if (!present) return t.skip("yara is not installed on this host");
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "d"), { recursive: true });
    await writeFile(join(cwd, "work", "rules.yar"), 'rule r { strings: $a = "hello" condition: $a }');
    await writeFile(join(cwd, "work", "d", "a.txt"), "hello");
    await writeFile(join(cwd, "work", "d", "locked.txt"), "hello");
    await chmod(join(cwd, "work", "d", "locked.txt"), 0o000);
    try {
      const out = body<YaraOut>(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/d" }));
      assert.equal(out.complete, false);
      assert.equal(out.scan_error_count, 1);
      assert.match(out.scan_errors[0].file, /locked\.txt$/);
    } finally {
      await chmod(join(cwd, "work", "d", "locked.txt"), 0o644);
    }
  });
});

test("yara_scan names what it did not scan: a FIFO and a link it does not follow in a directory, and refuses a FIFO as the target", async () => {
  // A FIFO in a scanned directory was skipped without a word, and a FIFO as the target waits for a writer.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", YARA());
    const dir = join(cwd, "work", "d");
    await mkdir(dir, { recursive: true });
    await writeFile(join(cwd, "work", "rules.yar"), "rule pw { condition: true }");
    await writeFile(join(dir, "a.txt"), "hello");
    await symlink("a.txt", join(dir, "alias.txt"));
    assert.equal(await new Promise<number | null>((resolve) => spawn("mkfifo", [join(dir, "pipe")]).on("close", resolve)), 0);
    const swept = await limited(join(WIN, "yara_scan", "run.py"), cwd, { rules: "work/rules.yar", target: "work/d" }, { PATH: `${bin}:${process.env.PATH ?? ""}` });
    assert.equal(swept.killed, false);
    const out = JSON.parse(swept.stdout) as YaraOut;
    assert.equal(out.complete, false);
    assert.equal(out.status, "partial");
    assert.deepEqual(out.not_attempted.map((n) => [n.file.split("/").pop(), n.reason.split(":")[0]]).sort(), [["alias.txt", "a symbolic link, not followed (yara -N)"], ["pipe", "a FIFO"]]);
    assert.equal(out.not_attempted_count, 2);

    const direct = await limited(join(WIN, "yara_scan", "run.py"), cwd, { rules: "work/rules.yar", target: "work/d/pipe" }, { PATH: `${bin}:${process.env.PATH ?? ""}` });
    assert.equal(direct.killed, false);
    assert.notEqual(direct.code, 0);
    assert.match((JSON.parse(direct.stdout) as { error: string }).error, /not a regular file or a directory/);
  });
});

test("yara_scan keeps the stderr file of an earlier run and writes this run's under the next number", async () => {
  await withCwd(async (cwd, bin) => {
    await mkdir(join(cwd, "work", "d"), { recursive: true });
    await writeFile(join(cwd, "work", "rules.yar"), "rule pw { condition: true }");
    await stub(bin, "yara", YARA(`echo "warning: first run" >&2`));
    const first = body<YaraOut>(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/d" }, {}, bin));
    await stub(bin, "yara", YARA(`echo "warning: second run" >&2`));
    const second = body<YaraOut>(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/d" }, {}, bin));
    assert.notEqual(second.stderr_file, first.stderr_file);
    assert.match(await readFile(join(cwd, first.stderr_file!), "utf8"), /first run/);
    assert.match(await readFile(join(cwd, second.stderr_file!), "utf8"), /second run/);
  });
});

test("the five tools' manifests say what their answers now carry", async () => {
  const read = async (name: string): Promise<{ description: string; params: Record<string, unknown>; version: number }> => JSON.parse(await readFile(join(WIN, name, "manifest.json"), "utf8"));
  const lnkManifest = await read("lnk_parse");
  assert.ok(lnkManifest.params.write_strings, "write_strings is a parameter");
  assert.match(lnkManifest.description, /arguments_chars/);
  assert.match(lnkManifest.description, /lnk-strings\.jsonl/);
  assert.match((await read("yara_scan")).description, /scan_error_count/);
  assert.match((await read("yara_scan")).description, /not_attempted/);
  assert.match((await read("vss_stores")).description, /earlier_output_files/);
  assert.match((await read("extract_stream")).description, /next free name/);
  assert.match((await read("jumplist")).description, /not_attempted/);
});
