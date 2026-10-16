/**
 * network-forensics: pcap_extract exports protocol objects with tshark and indexes them.
 *
 * tshark is not on every machine these suites run on, so a stand-in program prints what tshark's manual says
 * it prints: `--version` and `--export-objects help` for the build, `--export-objects <protocol>,<dir>` writing
 * object files into the directory, `-T fields -E header=y ...` writing a tab-separated listing whose last
 * column is the hex of the HTTP entity body. That proves the wrapper's own logic (receipts, deadline,
 * association, withholding), not tshark's: whether a real build accepts an exporter name, honours `-Y` on
 * export, or prints `http.file_data` for every body is a thing to check on the build the evidence is read with.
 *
 * What is held here: each exported object is tied to a frame and a stream where its content matches exactly one
 * response body, and is marked ambiguous or unmapped otherwise; a first pass that runs out of time still leaves
 * an index and a partial receipt; an exporter the build does not list is refused by name; a name or a request
 * URI shaped like a credential, and a short object's digest, are withheld from everything the answer names, and
 * the values behind them are written only to a 0600 file in a job; the output directory is private.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import type { Pkt } from "./pack-network-harness.ts";
import { EXTRACT, asJob, body, drop, everythingUnder, exists, filesUnder, frameTcp4, gone, ngBlock, ngInterface, ngPacket, ngSection, pcapClassic, pidFile, refused, startDetached, stub, ticks, tool, TCP, u32, withCwd } from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";

const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");
const BODY_A = Buffer.from("A".repeat(200));
const BODY_B = Buffer.from("B".repeat(300));
const SHORT = Buffer.from("tiny-object");

const FIELDS = ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "http.host", "http.request.full_uri", "http.file_data"];
// What `tshark -G fields` lists on the build the stand-in plays (4.6.9): http.response_for.uri is not there.
const AVAILABLE = [...FIELDS, "frame.cap_len", "http.request.uri", "http.response.code", "tcp.srcport"];

/** The listing: validates every -e field against the build's list like the real program (it refuses the whole command, exit 1,
 * `Some fields aren't valid`), then prints the header of the fields asked for and the stored rows projected onto them. */
const LISTING_PY = `import json, os, sys
d = os.environ["STUB_DIR"]
args = sys.argv[1:]
asked = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
avail = set(open(d + "/fields.txt").read().split())
bad = [f for f in asked if f not in avail]
if bad:
    sys.stderr.write("tshark: Some fields aren't valid:\\n\\t" + "\\n\\t".join(bad) + "\\n")
    sys.exit(1)
raw = d + "/assoc-raw.tsv"
if os.path.exists(raw):
    sys.stdout.write(open(raw).read())
    sys.exit(0)
canon = json.load(open(d + "/canon.json"))
rows = json.load(open(d + "/assoc.json"))
# -Y "... contains \\"x\\"" applies to the request URI column like the real program would, so a test can tell a filter that matched from one that did not
import re
y = args[args.index("-Y") + 1] if "-Y" in args else ""
m = re.search(r'contains "([^"]*)"', y)
if m:
    rows = [r for r in rows if m.group(1) in r[canon.index("http.request.full_uri")]]
alias = {"http.response_for.uri": "http.request.full_uri"}
idx = [canon.index(alias.get(f, f)) if alias.get(f, f) in canon else -1 for f in asked]
sys.stdout.write("\\t".join(asked) + "\\n")
for r in rows:
    sys.stdout.write("\\t".join(r[i] if i >= 0 else "" for i in idx) + "\\n")
`;
const FIELDS_PY = `import os
if os.path.exists(os.environ["STUB_DIR"] + "/fields-exit"):
    import sys
    sys.stderr.write("tshark: stand-in failing on request\\n")
    sys.exit(2)
for f in open(os.environ["STUB_DIR"] + "/fields.txt").read().split():
    print("F\\tLabel\\t%s\\tFT_STRING\\thttp\\t0\\t0x0\\t" % f)
`;

/** The stand-in: reads what to do from $STUB_DIR, and records every call in $STUB_LOG. */
const TSHARK = `#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG"
case " $* " in *" -G fields "*) exec python3 "$STUB_DIR/fields.py";; esac
case " $* " in *" -T fields "*) exec python3 "$STUB_DIR/listing.py" "$@";; esac
spec=""; fields=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ -f "$STUB_DIR/slow-version" ] && sleep 20; printf 'TShark (Wireshark) 4.2.0 (stand-in)\\n'; exit 0;;
    --export-objects) spec="$2"; shift;;
    -T) fields=yes;;
  esac
  shift
done
if [ "$spec" = help ]; then
  { printf 'tshark: The available export object types for the "--export-objects" option are:\\n'; sed 's/^/    /' "$STUB_DIR/exporters.txt"; } >&2
  exit 0
fi
if [ -n "$spec" ]; then
  proto="\${spec%%,*}"; dest="\${spec#*,}"
  [ -f "$STUB_DIR/sleep-$proto" ] && exec sleep "$(cat "$STUB_DIR/sleep-$proto")"
  if [ -f "$STUB_DIR/spawn-$proto" ]; then echo $$ > "$STUB_DIR/engine.pid"; sleep 60 & echo $! > "$STUB_DIR/child.pid"; echo started > "$STUB_DIR/started"; wait; fi
  [ -d "$STUB_DIR/export/$proto" ] && cp -R "$STUB_DIR/export/$proto/." "$dest/"
  [ -f "$STUB_DIR/fifo-$proto" ] && mkfifo "$dest/pipe.bin"
  if [ -f "$STUB_DIR/exit-$proto" ]; then echo "tshark: stand-in failing on request" >&2; exit "$(cat "$STUB_DIR/exit-$proto")"; fi
  exit 0
fi
exit 0
`;

async function stage(cwd: string, bin: string, o: { exporters?: string[]; export?: Record<string, Record<string, Buffer | string>>; assoc?: string[][]; assocRaw?: string; sleeps?: Record<string, number>; exits?: Record<string, number>; spawns?: string[]; fifo?: string[]; slowVersion?: boolean; fields?: string[]; fieldsExit?: boolean }): Promise<{ log: string; dir: string }> {
  const dir = join(cwd, "stub");
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  await stub(bin, "tshark", TSHARK);
  await writeFile(join(dir, "exporters.txt"), (o.exporters ?? ["dicom", "http", "imf", "smb", "tftp"]).join("\n") + "\n");
  for (const [proto, files] of Object.entries(o.export ?? {})) {
    for (const [name, data] of Object.entries(files)) {
      await mkdir(join(dir, "export", proto, name, ".."), { recursive: true });
      await writeFile(join(dir, "export", proto, name), data);
    }
  }
  for (const [proto, s] of Object.entries(o.sleeps ?? {})) await writeFile(join(dir, `sleep-${proto}`), String(s));
  for (const [proto, c] of Object.entries(o.exits ?? {})) await writeFile(join(dir, `exit-${proto}`), String(c));
  for (const proto of o.spawns ?? []) await writeFile(join(dir, `spawn-${proto}`), "1");
  for (const proto of o.fifo ?? []) await writeFile(join(dir, `fifo-${proto}`), "1");
  if (o.slowVersion) await writeFile(join(dir, "slow-version"), "1");
  await writeFile(join(dir, "fields.txt"), (o.fields ?? AVAILABLE).join("\n") + "\n");
  await writeFile(join(dir, "fields.py"), FIELDS_PY);
  if (o.fieldsExit) await writeFile(join(dir, "fields-exit"), "1");
  await writeFile(join(dir, "listing.py"), LISTING_PY);
  await writeFile(join(dir, "canon.json"), JSON.stringify(FIELDS));
  await writeFile(join(dir, "assoc.json"), JSON.stringify(o.assoc ?? []));
  if (o.assocRaw !== undefined) await writeFile(join(dir, "assoc-raw.tsv"), o.assocRaw);
  const log = join(cwd, "tshark-calls.txt");
  await writeFile(log, "");
  return { log, dir };
}

const env = (cwd: string, extra: Record<string, string> = {}) => ({ STUB_DIR: join(cwd, "stub"), STUB_LOG: join(cwd, "tshark-calls.txt"), ...extra });

async function capture(cwd: string): Promise<string> {
  return drop(cwd, "work/c.pcap", pcapClassic([{ sec: 1, frame: frameTcp4({ src: "203.0.113.7", dst: "10.0.0.5", sport: 80, dport: 50000, flags: TCP.ACK }) }]));
}

function row(frame: number, stream: number, uri: string, data: Buffer, time = "1700000000.123456789"): string[] {
  return [String(frame), time, String(stream), "203.0.113.7", "", "10.0.0.5", "", "files.example.test", uri, data.toString("hex")];
}

async function index(cwd: string, dir: string): Promise<Json[]> {
  const lines = (await readFile(join(cwd, dir, "index.tsv"), "utf8")).trimEnd().split("\n");
  const head = lines[0].split("\t");
  return lines.slice(1).map((l) => Object.fromEntries(l.split("\t").map((v, i) => [head[i], v])));
}

test("an exported object is tied to the frame and stream whose body it matches; a body returned twice is ambiguous; one with no match is unmapped", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, {
      export: { http: { "a.html": BODY_A, "b.bin": BODY_B, "c.txt": "C".repeat(150), "d.txt": "D".repeat(160) } },
      assoc: [row(7, 0, "/a.html", BODY_A), row(12, 1, "/b.bin", BODY_B), row(20, 2, "/d.txt", Buffer.from("D".repeat(160))), row(21, 3, "/d-again.txt", Buffer.from("D".repeat(160)))],
    });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin));
    assert.equal(out.objects, 4);
    assert.equal(out.ok, true);
    const rows = await index(cwd, "work/x");
    const by = Object.fromEntries(rows.map((r) => [r.name, r]));
    assert.equal(by["a.html"].association, "matched_by_content");
    assert.equal(by["a.html"].frame, "7");
    assert.equal(by["a.html"].stream, "0");
    assert.equal(by["a.html"].time_utc, "2023-11-14T22:13:20.123456789Z");
    assert.equal(by["a.html"].src, "203.0.113.7");
    assert.equal(by["b.bin"].frame, "12");
    assert.equal(by["c.txt"].association, "unmapped", "no response body matched this object");
    assert.equal(by["c.txt"].frame, "");
    assert.equal(by["d.txt"].association, "ambiguous");
    assert.equal(by["d.txt"].frame, "", "no single frame is claimed");
    assert.match(by["d.txt"].frames, /20/);
    assert.match(by["d.txt"].frames, /21/);
    // Every row has a frame and stream, or says it has none.
    for (const r of rows) assert.ok(r.frame !== "" || ["unmapped", "ambiguous"].includes(r.association), JSON.stringify(r));
    assert.equal(by["a.html"].sha256, sha(BODY_A));
    assert.equal(out.association.matched_by_content, 2);
    assert.equal(out.association.unmapped, 1);
    assert.equal(out.association.ambiguous, 1);
  });
});

test("a protocol with no association method is unmapped, and says why", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { export: { tftp: { "boot.img": BODY_B } } });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["tftp"] }, env(cwd), bin));
    const rows = await index(cwd, "work/x");
    assert.equal(rows[0].association, "unmapped");
    assert.match(rows[0].association_reason, /no content-to-frame association/);
    assert.equal(out.association.unmapped, 1);
  });
});

test("the build, the filter and the exporters it lists are recorded; a name it does not list is refused before anything runs", async () => {
  await withCwd(async (cwd, bin) => {
    const { log } = await stage(cwd, bin, { exporters: ["http", "tftp"], export: { http: { "a.html": BODY_A } }, assoc: [row(3, 0, "/a.html", BODY_A)] });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", display_filter: "ip.addr == 10.0.0.5" }, env(cwd), bin));
    assert.match(out.tshark_version, /4\.2\.0/);
    assert.equal(out.display_filter, undefined, "the filter is not echoed");
    assert.equal(out.display_filter_given, true);
    assert.deepEqual(out.exporters_supported, ["http", "tftp"]);
    // The default list names ftp-data, smb, smb2 and imf; this build lists none of them. They are skipped, and said.
    assert.deepEqual(out.protocols_skipped_unsupported.sort(), ["ftp-data", "imf", "smb", "smb2"]);
    assert.deepEqual(out.runs.map((r: Json) => r.protocol), ["http", "tftp"]);
    assert.match(out.note, /-Y/);
    // An explicit name the build does not list is a refusal, and no export pass ran.
    await writeFile(log, "");
    const err = refused(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/y", protocols: ["http", "smb3"] }, env(cwd), bin));
    assert.match(err.error, /smb3/);
    assert.deepEqual(err.exporters_supported, ["http", "tftp"]);
    assert.doesNotMatch(await readFile(log, "utf8"), /--export-objects http,/);
    assert.equal(await exists(join(cwd, "work/y")), false, "nothing was written for a refused request");
  });
});

test("a build whose exporter list cannot be read is said, and the passes still run and fail loudly on their own", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { exporters: [], export: { http: { "a.html": BODY_A } }, exits: { smb2: 2 } });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin));
    assert.equal(out.exporters_discovered, false);
    assert.equal(out.ok, true);
  });
});

test("a first pass that runs out of time leaves an index and a partial receipt, and the passes after it are not attempted", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { sleeps: { http: 30 }, export: { smb: { "x.dat": BODY_B } } });
    const started = Date.now();
    const result = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http", "smb"], timeout_seconds: 2 }, env(cwd), bin);
    assert.ok(Date.now() - started < 20_000, "the deadline ended the pass");
    assert.equal(result.code, 0, "exit 0 means the engine ran; what did not finish is in status and errors");
    const out = JSON.parse(result.stdout);
    assert.equal(out.ok, false);
    const byProto = Object.fromEntries(out.runs.map((r: Json) => [r.protocol, r]));
    assert.equal(byProto.http.status, "timed_out");
    assert.equal(byProto.smb.status, "not_attempted");
    assert.equal(byProto.smb.reason, "the shared deadline was used up by an earlier pass");
    assert.ok(await exists(join(cwd, "work/x/index.tsv")), "the index exists");
    const receipt = JSON.parse(await readFile(join(cwd, "work/x/receipt.json"), "utf8"));
    assert.equal(receipt.status, "partial");
    assert.equal(receipt.runs.find((r: Json) => r.protocol === "http").status, "timed_out");
  });
});

test("a pass that fails keeps its whole diagnostic, and the objects of the others are still indexed", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { exits: { http: 7 }, export: { smb: { "x.dat": BODY_B } } });
    const result = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http", "smb"] }, env(cwd), bin);
    assert.equal(result.code, 0, "exit 0 means the engine ran; what did not finish is in status and errors");
    const out = JSON.parse(result.stdout);
    assert.equal(out.ok, false);
    assert.equal(out.errors[0].exit_code, 7);
    assert.ok(out.errors[0].stderr);
    assert.equal(out.objects, 1);
    assert.match(await readFile(join(cwd, "work/x/_logs/http.stderr"), "utf8"), /stand-in failing/);
  });
});

const NAME_TOKEN = "Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK"; // an object named like a token
const URI_TOKEN = "SuperSecretToken987";
const USER_PASS = "alice:PassWord1234";

test("a credential-shaped name, a URI's user-info and query values are withheld from everything the answer names; a short object's digest is not written", async () => {
  await withCwd(async (cwd, bin) => {
    const uri = `http://${USER_PASS}@files.example.test/get/${NAME_TOKEN}?token=${URI_TOKEN}&n=2`;
    await stage(cwd, bin, {
      export: { http: { [`${NAME_TOKEN}.bin`]: BODY_A, "tiny.txt": SHORT, "report.pdf": BODY_B } },
      assoc: [row(5, 0, uri, BODY_A), row(6, 1, "/report.pdf", BODY_B), row(7, 2, "/tiny.txt", SHORT)],
    });
    const result = await asJob(EXTRACT, cwd, { path: await capture(cwd), out_dir: "out/x", protocols: ["http"] }, bin, env(cwd));
    const out = body(result);
    const everything = await everythingUnder(cwd, result.stdout, ["out"], ["out/x/withheld-names.jsonl"]);
    for (const secret of [NAME_TOKEN, URI_TOKEN, "PassWord1234", sha(SHORT)]) {
      assert.equal(everything.includes(secret), false, `${secret} reached the answer or a file it names`);
    }
    // The real name of the object moved aside is kept, in one private file of the output directory, with or without write_values.
    const mapped = (await readFile(join(cwd, "out/x/withheld-names.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(mapped.map((m: Json) => [m.path, m.real_path]), [["http/withheld-000001.bin", `http/${NAME_TOKEN}.bin`]]);
    assert.equal(((await stat(join(cwd, "out/x/withheld-names.jsonl"))).mode & 0o777).toString(8), "600");
    // The object is still there, under a name that is no secret, and the row says so.
    const rows = await index(cwd, "out/x");
    const renamed = rows.find((r) => r.name.startsWith("<name withheld"));
    assert.ok(renamed, JSON.stringify(rows));
    assert.match(renamed.path, /^http\/withheld-000001\.bin$/);
    assert.ok(await exists(join(cwd, "out/x", renamed.path)));
    assert.equal(renamed.frame, "5", "the association was made on the content, before the name was withheld");
    assert.match(renamed.request_uri, /^http:\/\/<userinfo withheld \d+ characters>@files\.example\.test\//);
    assert.match(renamed.request_uri, /token=<withheld \d+ characters>/);
    const tiny = rows.find((r) => r.name === "tiny.txt");
    assert.equal(tiny.sha256, "");
    assert.match(tiny.sha256_withheld, /shorter than 128 bytes/);
    assert.equal(rows.find((r) => r.name === "report.pdf").sha256, sha(BODY_B));
    assert.equal(out.names_withheld >= 1, true);
    // The directory and the objects are private.
    assert.equal(((await stat(join(cwd, "out/x"))).mode & 0o777).toString(8), "700");
    assert.equal(((await stat(join(cwd, "out/x/http/report.pdf"))).mode & 0o777).toString(8), "600");
    assert.equal(out.out_dir_contains_secret_values, true);
    assert.match(out.out_dir_note, /secret_output: true/);
  });
});

test("write_values puts the real names and URIs in one 0600 file under $OUT, and is refused outside a job; a second run in the same job is refused, not crashed, and leaves the first file alone", async () => {
  await withCwd(async (cwd, bin) => {
    const uri = `http://${USER_PASS}@files.example.test/get?token=${URI_TOKEN}`;
    await stage(cwd, bin, { export: { http: { [`${NAME_TOKEN}.bin`]: BODY_A } }, assoc: [row(5, 0, uri, BODY_A)] });
    const args = { path: await capture(cwd), out_dir: "work/plain", protocols: ["http"], write_values: true };
    const outside = refused(await tool(EXTRACT, cwd, args, env(cwd), bin));
    assert.match(outside.error, /outside a job/);
    assert.equal(await exists(join(cwd, "work/plain")), false, "nothing was written");
    // In a job.
    const first = body(await asJob(EXTRACT, cwd, { ...args, out_dir: "out/one" }, bin, env(cwd)));
    assert.equal(first.secret_values.written, 1);
    const file = join(cwd, "out", "pcap-extract-values.jsonl");
    assert.equal(((await stat(file)).mode & 0o777).toString(8), "600");
    const rows = (await readFile(file, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(rows.length, 1);
    assert.match(rows[0].value, new RegExp(NAME_TOKEN));
    assert.equal(rows[0].request_uri, uri);
    assert.match(rows[0].finding_id, /^O\d{6}$/);
    const before = await readFile(file, "utf8");
    // Same job output, a second run: refused in JSON, the first values file untouched.
    const second = refused(await asJob(EXTRACT, cwd, { ...args, out_dir: "out/two" }, bin, env(cwd)));
    assert.match(second.error, /already exists/);
    assert.equal(await readFile(file, "utf8"), before);
    // And a run with nothing to withhold leaves an empty 0600 file and says written: 0.
    await stage(cwd, bin, { export: { http: { "plain.txt": BODY_A } }, assoc: [] });
    const empty = body(await asJob(EXTRACT, cwd, { ...args, out_dir: "out3/x" }, bin, env(cwd), "out3"));
    assert.equal(empty.secret_values.written, 0);
    assert.equal((await stat(join(cwd, "out3", "pcap-extract-values.jsonl"))).size, 0);
  });
});

test("in a job out_dir must be under $OUT, and an output place that cannot be written is a JSON error, not a traceback", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } } });
    const outside = refused(await asJob(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/elsewhere", protocols: ["http"] }, bin, env(cwd)));
    assert.match(outside.error, /\$OUT/);
    // A directory that exists and cannot be written (root writes anywhere, so there is nothing to refuse there).
    if (typeof process.getuid === "function" && process.getuid() === 0) return;
    await mkdir(join(cwd, "work/locked"), { recursive: true });
    await chmod(join(cwd, "work/locked"), 0o555);
    try {
      const blocked = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/locked/x", protocols: ["http"] }, env(cwd), bin);
      assert.notEqual(blocked.code, 0);
      assert.doesNotMatch(blocked.stderr, /Traceback/);
      assert.match(JSON.parse(blocked.stdout).error, /could not be (created|written)/);
    } finally {
      await chmod(join(cwd, "work/locked"), 0o755);
    }
  });
});

test("a second run into another directory never replaces the first run's index", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } }, assoc: [row(3, 0, "/a.html", BODY_A)] });
    body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/one", protocols: ["http"] }, env(cwd), bin));
    const first = await readFile(join(cwd, "work/one/index.tsv"), "utf8");
    const again = refused(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/one", protocols: ["http"] }, env(cwd), bin));
    assert.match(again.error, /already holds files/);
    assert.equal(await readFile(join(cwd, "work/one/index.tsv"), "utf8"), first);
    assert.deepEqual((await filesUnder(join(cwd, "work/one"))).filter((f) => f.endsWith(".tmp")), []);
  });
});

test("a row that cannot be read, or a header that is not the fields asked for, means no frame is claimed for any object, and the run says so", async () => {
  await withCwd(async (cwd, bin) => {
    const good = row(7, 0, "/a.html", BODY_A).join("\t");
    const damaged = [...row(8, 1, "/b.bin", BODY_B).slice(0, 9), "ZZ-not-hex"].join("\t");
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } }, assocRaw: [FIELDS.join("\t"), good, damaged].join("\n") + "\n" });
    const result = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin);
    assert.equal(result.code, 0, "exit 0 means the engine ran; what did not finish is in status and errors");
    const out = JSON.parse(result.stdout);
    assert.equal(out.ok, false);
    assert.equal(out.association_pass.status, "incomplete");
    assert.equal(out.association_pass.rows_unreadable, 1);
    assert.equal(out.association_pass.unreadable_lines_file, "association-unreadable-lines.json");
    assert.deepEqual(JSON.parse(await readFile(join(cwd, "work/x/association-unreadable-lines.json"), "utf8")), { listing_lines: [3] }, "the line number counts the header; every line is named");
    const rows = await index(cwd, "work/x");
    assert.equal(rows[0].association, "failed");
    assert.equal(rows[0].frame, "", "a claim from a partial listing could be wrong, so none is made");
    assert.match(rows[0].association_reason, /no frame is claimed/);
    // The header is the contract: another set of columns means the fields cannot be trusted.
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } }, assocRaw: ["frame.number\thttp.file_data", good].join("\n") + "\n" });
    const wrong = JSON.parse((await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/y", protocols: ["http"] }, env(cwd), bin)).stdout);
    assert.equal(wrong.association_pass.status, "failed");
    assert.match(wrong.association_pass.reason, /header/);
  });
});

test("a body larger than one read of the pipe is hashed as it goes by and still matched, and nothing holding a body is written", async () => {
  await withCwd(async (cwd, bin) => {
    const big = randomBytes(3 * 1024 * 1024 + 11);
    await stage(cwd, bin, { export: { http: { "big.bin": big } }, assoc: [row(31, 4, "/big.bin", big)] });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin));
    assert.equal(out.association.matched_by_content, 1);
    const rows = await index(cwd, "work/x");
    assert.equal(rows[0].frame, "31");
    assert.equal(rows[0].sha256, sha(big));
    for (const f of await filesUnder(join(cwd, "work/x"))) {
      assert.ok((await stat(join(cwd, "work/x", f))).size < 4 * 1024 * 1024 + 100 || f.startsWith("http/"), `${f} is larger than an object: a listing was kept`);
    }
    assert.deepEqual((await filesUnder(join(cwd, "work/x"))).filter((f) => /assoc|listing/i.test(f) && !f.startsWith("_logs/")), []);
  });
});

test("a body in many frames is ambiguous with the whole frame list kept in a file; two objects with the same bytes and one frame are ambiguous, not matched", async () => {
  await withCwd(async (cwd, bin) => {
    const many = Array.from({ length: 30 }, (_, i) => row(100 + i, i, `/r${i}`, BODY_A));
    await stage(cwd, bin, {
      export: { http: { "one.bin": BODY_A, "same-a.bin": BODY_B, "same-b.bin": BODY_B } },
      assoc: [...many, row(900, 40, "/b", BODY_B)],
    });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin));
    assert.equal(out.association.ambiguous, 3);
    assert.equal(out.association.matched_by_content, 0);
    const rows = await index(cwd, "work/x");
    const one = rows.find((r) => r.name === "one.bin");
    assert.equal(one.frames.split(",").length, 21, "twenty frames and a count of the rest");
    assert.match(one.frames, /\+10 more$/);
    assert.equal(one.frame, "");
    const sets = (await readFile(join(cwd, "work/x/association-candidates.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    const whole = sets.find((s: Json) => s.frames.length === 30);
    assert.ok(whole, "the whole list of the repeated body is on disk");
    assert.deepEqual(whole.frames.slice(0, 3), [100, 101, 102]);
    assert.match(one.association_reason, /candidate_set S\d{6}/);
    assert.equal(JSON.stringify(sets).includes(sha(BODY_A)), false, "no digest in the candidates file");
  });
});

test("a token-shaped directory name is moved aside too, and a pass's children die with it", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { export: { smb: { [`${NAME_TOKEN}/inner.txt`]: BODY_B } } });
    const result = await asJob(EXTRACT, cwd, { path: await capture(cwd), out_dir: "out/x", protocols: ["smb"] }, bin, env(cwd));
    const out = body(result);
    const everything = await everythingUnder(cwd, result.stdout, ["out"], ["out/x/withheld-names.jsonl"]);
    assert.equal(everything.includes(NAME_TOKEN), false);
    assert.match(await readFile(join(cwd, "out/x/withheld-names.jsonl"), "utf8"), new RegExp(NAME_TOKEN));
    const rows = await index(cwd, "out/x");
    assert.match(rows[0].path, /^smb\/withheld-000001\/inner\.txt$/);
    assert.equal(out.names_withheld, 1);
  });
  await withCwd(async (cwd, bin) => {
    const { dir } = await stage(cwd, bin, { spawns: ["http"] });
    const started = Date.now();
    const result = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"], timeout_seconds: 2 }, env(cwd), bin);
    assert.ok(Date.now() - started < 20_000);
    assert.equal(result.code, 0, "exit 0 means the engine ran; what did not finish is in status and errors");
    const pid = Number((await readFile(join(dir, "child.pid"), "utf8")).trim());
    assert.ok(pid > 1);
    await new Promise((r) => setTimeout(r, 300));
    assert.throws(() => process.kill(pid, 0), /ESRCH/, "the sleeper the pass started is gone");
  });
});

test("a stop signal kills the pass and leaves a receipt that says it was interrupted", async () => {
  await withCwd(async (cwd, bin) => {
    const { dir } = await stage(cwd, bin, { spawns: ["http"] });
    await writeFile(join(cwd, "args.json"), JSON.stringify({ path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }));
    const child = spawn("python3", [EXTRACT], { cwd, env: { ...process.env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}`, ...env(cwd) } });
    const stdout: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdout.push(c));
    child.stdin.end(await readFile(join(cwd, "args.json")));
    for (let i = 0; i < 100 && !(await exists(join(dir, "started"))); i++) await new Promise((r) => setTimeout(r, 50));
    assert.ok(await exists(join(dir, "started")), "the pass started");
    const code = await new Promise<number | null>((resolve) => { child.on("close", resolve); child.kill("SIGTERM"); });
    assert.equal(code, 143);
    const receipt = JSON.parse(await readFile(join(cwd, "work/x/receipt.json"), "utf8"));
    assert.equal(receipt.status, "interrupted");
    assert.match(receipt.why, /signal 15/);
    const pid = Number((await readFile(join(dir, "child.pid"), "utf8")).trim());
    await new Promise((r) => setTimeout(r, 300));
    assert.throws(() => process.kill(pid, 0), /ESRCH/);
  });
});

async function reap(...pids: number[]): Promise<void> {
  for (const pid of pids) {
    try { process.kill(pid, "SIGKILL"); } catch { /* already gone */ }
  }
}

test("the harness ends a tool by killing its process group, and that ends tshark and what tshark started (tshark is in the tool's group, not a session of its own)", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = (await stage(cwd, bin, { spawns: ["http"] })).dir;
    const run = startDetached(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin);
    let engine = 0, child = 0;
    try {
      engine = await pidFile(join(dir, "engine.pid"));
      child = await pidFile(join(dir, "child.pid"));
      run.killGroup();
      await run.closed;
      assert.equal(await gone(engine), true, "tshark was still running after the tool's group was killed");
      assert.equal(await gone(child), true, "what tshark started was still running");
    } finally {
      await reap(engine, child);
    }
  });
});

test("SIGINT and SIGHUP end the pass like SIGTERM: tshark and its children are killed and the receipt says interrupted", async () => {
  for (const sig of ["SIGINT", "SIGHUP"] as const) {
    await withCwd(async (cwd, bin) => {
      const dir = (await stage(cwd, bin, { spawns: ["http"] })).dir;
      const run = startDetached(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin);
      let engine = 0, child = 0;
      try {
        engine = await pidFile(join(dir, "engine.pid"));
        child = await pidFile(join(dir, "child.pid"));
        run.signal(sig);
        const code = await run.closed;
        assert.equal(code, sig === "SIGINT" ? 130 : 129, sig);
        assert.equal(await gone(engine), true, `${sig}: tshark survived`);
        assert.equal(await gone(child), true, `${sig}: its child survived`);
        const receipt = JSON.parse(await readFile(join(cwd, "work/x/receipt.json"), "utf8"));
        assert.equal(receipt.status, "interrupted", sig);
      } finally {
        await reap(engine, child);
      }
    });
  }
});

test("timeout_seconds is held under the manifest's limit, and the deadline counts the preflight", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } } });
    for (const bad of [3301, 7200, 0]) {
      const err = refused(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"], timeout_seconds: bad }, env(cwd), bin));
      assert.match(err.error, /timeout_seconds must be an integer from 1 to 3300/, String(bad));
    }
    assert.equal(await exists(join(cwd, "work/x")), false);
  });
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { slowVersion: true, export: { http: { "a.html": BODY_A } } });
    const started = Date.now();
    const result = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"], timeout_seconds: 3 }, env(cwd), bin);
    assert.ok(Date.now() - started < 12_000, `took ${Date.now() - started} ms: the 20-second version call was not held to the deadline`);
    assert.doesNotMatch(result.stderr, /Traceback/);
  });
});

test("a name that carries a query string is withheld too: Wireshark names an HTTP object after the end of its request target", async () => {
  await withCwd(async (cwd, bin) => {
    const NAME = "login.php%3fuser=bob&pw=hunter2";
    await stage(cwd, bin, { export: { http: { [NAME]: BODY_A, "report.pdf": BODY_B } }, assoc: [row(5, 0, "/login.php?user=bob&pw=hunter2", BODY_A)] });
    const result = await asJob(EXTRACT, cwd, { path: await capture(cwd), out_dir: "out/x", protocols: ["http"] }, bin, env(cwd));
    const out = body(result);
    const everything = await everythingUnder(cwd, result.stdout, ["out"], ["out/x/withheld-names.jsonl"]);
    assert.equal(everything.includes("hunter2"), false, "the password in the name reached the answer or a file it names");
    assert.equal(everything.includes("user=bob"), false);
    const rows = await index(cwd, "out/x");
    assert.match(rows.find((r) => r.frame === "5").name, /^<name withheld/);
    assert.equal(rows.find((r) => r.name === "report.pdf").path, "http/report.pdf", "an ordinary name is left alone");
    assert.match(rows.find((r) => r.frame === "5").request_uri, /pw=<withheld 7 characters>/);
    assert.equal(out.names_withheld, 1);
    assert.match(await readFile(join(cwd, "out/x/withheld-names.jsonl"), "utf8"), /login\.php%3fuser=bob&pw=hunter2/);
  });
});

test("a name moved aside never lands on a name that is there, and the real name of an IOC-shaped object is kept without write_values", async () => {
  await withCwd(async (cwd, bin) => {
    const HASHNAME = `${"ab12".repeat(16)}.exe`;
    await stage(cwd, bin, { export: { http: { "withheld-000001.bin": BODY_A, [`${NAME_TOKEN}.bin`]: BODY_B, [HASHNAME]: BODY_B.subarray(0, 250) } } });
    const result = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin);
    const out = JSON.parse(result.stdout);
    const rows = await index(cwd, "work/x");
    assert.equal(rows.length, 3);
    assert.equal(new Set(rows.map((r) => r.path)).size, 3, "three objects, three different paths");
    const benign = rows.find((r) => r.name === "withheld-000001.bin");
    assert.equal(benign.bytes, String(BODY_A.length), "the object that was already called that is still there, whole");
    assert.equal(await readFile(join(cwd, "work/x", benign.path), "utf8"), BODY_A.toString());
    for (const r of rows) assert.equal((await stat(join(cwd, "work/x", r.path))).size, Number(r.bytes), r.path);
    const mapped = (await readFile(join(cwd, "work/x/withheld-names.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(mapped.map((m: Json) => m.real_path).sort(), [`http/${HASHNAME}`, `http/${NAME_TOKEN}.bin`].sort());
    assert.equal(out.secret_values.requested, false, "this is without write_values");
    assert.equal((await readFile(join(cwd, "work/x/index.tsv"), "utf8")).includes(HASHNAME), false);
  });
});

test("an export type of '.' or '..' is refused, and a failed discovery never walks the directory above out_dir", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { exporters: [], export: { http: { "a.html": BODY_A } } });
    await drop(cwd, "work/other-agent/" + "cd34".repeat(16) + ".bin", Buffer.alloc(300, 7));
    for (const bad of ["..", ".", "a/b", ".hidden", "-x"]) {
      const err = refused(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: [bad] }, env(cwd), bin));
      assert.match(err.error, /protocols must be a non-empty list/, bad);
    }
    const names = await filesUnder(join(cwd, "work/other-agent"));
    assert.deepEqual(names, ["cd34".repeat(16) + ".bin"], "another agent's file was not renamed");
    assert.equal(((await stat(join(cwd, "work/other-agent", names[0]))).mode & 0o777) !== 0o600, true, "nor re-moded");
    assert.equal(await exists(join(cwd, "work/x")), false);
  });
});

test("a named pipe in the export tree is listed and not opened; a cell over the limit is cut with the whole kept in a file", async () => {
  await withCwd(async (cwd, bin) => {
    const LONG = `/get?${Array.from({ length: 700 }, (_, i) => `p${i}=v`).join("&")}`;
    await stage(cwd, bin, { fifo: ["http"], export: { http: { "a.html": BODY_A } }, assoc: [row(8, 0, LONG, BODY_A)] });
    const started = Date.now();
    const result = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin);
    assert.ok(Date.now() - started < 15_000, "it hung on the pipe");
    const out = JSON.parse(result.stdout);
    const rows = await index(cwd, "work/x");
    const pipe = rows.find((r) => r.name === "pipe.bin");
    assert.ok(pipe);
    assert.match(pipe.association_reason, /not a regular file/);
    assert.equal(pipe.sha256, "");
    const a = rows.find((r) => r.name === "a.html");
    assert.match(a.request_uri, /characters not shown; the whole is L000001 in index-long-cells\.jsonl\)$/);
    const whole = JSON.parse((await readFile(join(cwd, "work/x/index-long-cells.jsonl"), "utf8")).trimEnd());
    assert.equal(whole.id, "L000001");
    assert.ok(whole.value.length > 8192 && whole.value.startsWith("/get?p0=<withheld 1 characters>"));
    assert.equal(out.ok, true);
  });
});

test("a run that stops before it wrote a value gives the job's one values file back", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } } });
    // out/locked cannot be written to, so out/locked/x cannot be created, after the values file was.
    await mkdir(join(cwd, "out/locked"), { recursive: true });
    await chmod(join(cwd, "out/locked"), 0o555);
    try {
      if (typeof process.getuid === "function" && process.getuid() === 0) return;
      const args = { path: await capture(cwd), protocols: ["http"], write_values: true };
      const failed = refused(await asJob(EXTRACT, cwd, { ...args, out_dir: "out/locked/x" }, bin, env(cwd)));
      assert.match(failed.error, /could not be created or written/);
      assert.equal(await exists(join(cwd, "out/pcap-extract-values.jsonl")), false, "the values file was given back");
      const again = body(await asJob(EXTRACT, cwd, { ...args, out_dir: "out/ok" }, bin, env(cwd)));
      assert.equal(again.secret_values.requested, true);
    } finally {
      await chmod(join(cwd, "out/locked"), 0o755);
    }
  });
});

// --- D-network-F1: the association pass asks the build for its fields, and names what it lacks ----------------------------

test("the stand-in refuses a field the build does not list, as the real program does (a fixture that accepted anything hid this once)", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } }, assoc: [row(7, 0, "/a.html", BODY_A)] });
    const probe = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/probe", protocols: ["http"] }, env(cwd), bin);
    assert.equal(body(probe).association.matched_by_content, 1);
    const calls = (await readFile(join(cwd, "tshark-calls.txt"), "utf8")).split("\n");
    const listing = calls.find((l) => l.includes("-T fields")) ?? "";
    assert.match(listing, /-e http\.request\.full_uri/, "the field this build lists is asked for");
    assert.doesNotMatch(listing, /http\.response_for\.uri/, "a field this build does not list is not");
  });
});

test("a build that lists only the older URI field is asked for that one; a build that lists neither is not failed, the lack is named", async () => {
  await withCwd(async (cwd, bin) => {
    const old = AVAILABLE.filter((f) => f !== "http.request.full_uri").concat(["http.response_for.uri"]);
    await stage(cwd, bin, { fields: old, export: { http: { "a.html": BODY_A } }, assoc: [row(7, 0, "/a.html", BODY_A)] });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/old", protocols: ["http"] }, env(cwd), bin));
    assert.equal(out.association.matched_by_content, 1);
    assert.ok(out.association_pass.fields_asked_for.includes("http.response_for.uri"));
    assert.equal((await index(cwd, "work/old"))[0].request_uri, "/a.html");
    await stage(cwd, bin, { fields: AVAILABLE.filter((f) => f !== "http.request.full_uri"), export: { http: { "a.html": BODY_A } }, assoc: [row(7, 0, "/a.html", BODY_A)] });
    const none = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/none", protocols: ["http"] }, env(cwd), bin));
    assert.equal(none.ok, true, "a missing optional field is a named reason, not a failure");
    assert.equal(none.association.matched_by_content, 1);
    assert.deepEqual(none.association_pass.fields_missing, ["http.request.full_uri", "http.response_for.uri"]);
    assert.match(none.association_pass.note, /does not list/);
    const rows = await index(cwd, "work/none");
    assert.equal(rows[0].frame, "7");
    assert.equal(rows[0].request_uri, "");
    assert.match(rows[0].association_reason, /does not list: http\.request\.full_uri, http\.response_for\.uri/);
  });
});

test("a build without http.file_data cannot match anything: the association pass is unavailable by name, the objects are still indexed, and the run is partial but exits 0", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { fields: AVAILABLE.filter((f) => f !== "http.file_data"), export: { http: { "a.html": BODY_A } }, assoc: [row(7, 0, "/a.html", BODY_A)] });
    const result = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin);
    assert.equal(result.code, 0);
    const out = JSON.parse(result.stdout);
    assert.equal(out.association_pass.status, "unavailable");
    assert.match(out.association_pass.reason, /http\.file_data/);
    assert.equal(out.status, "partial");
    assert.equal(out.ok, false);
    assert.equal(out.objects, 1);
    const calls = await readFile(join(cwd, "tshark-calls.txt"), "utf8");
    assert.doesNotMatch(calls, /-T fields/, "no listing was attempted with a field the build refuses");
  });
});

test("when the build's field list cannot be read the tool asks for its default fields and says the list was not checked", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { fieldsExit: true, export: { http: { "a.html": BODY_A } }, assoc: [row(7, 0, "/a.html", BODY_A)] });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin));
    assert.equal(out.association_pass.fields_discovered, false);
    assert.match(out.association_pass.fields_note, /exited 2/);
    assert.equal(out.association.matched_by_content, 1);
  });
});

test("a response frame with no Host: the host is the authority of the request URI (tshark 4.6 leaves http.host empty there), through the same host rule as every tool", async () => {
  await withCwd(async (cwd, bin) => {
    const r = row(7, 0, "http://b2eb-115-135-31-192.ngrok-free.app/seetwo/a.html", BODY_A);
    r[7] = "";
    const token = "Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK";
    const r2 = row(8, 1, `http://${token}.cdn.example.test/x.bin`, BODY_B);
    r2[7] = "";
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A, "x.bin": BODY_B } }, assoc: [r, r2] });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin));
    const rows = await index(cwd, "work/x");
    const a = rows.find((x) => x.name === "a.html");
    assert.equal(a.host, "b2eb-115-135-31-192.ngrok-free.app", "a host that is only a name stays readable");
    assert.equal(a.request_uri, "http://b2eb-115-135-31-192.ngrok-free.app/seetwo/a.html");
    const x = rows.find((y) => y.name === "x.bin");
    assert.equal(x.host.includes(token), false, "a token in a sub-domain is withheld in the host column");
    assert.equal(x.request_uri.includes(token), false, "and in the URL's authority");
    assert.match(x.host, /withheld/);
    assert.equal(out.ok, true);
  });
});

test("display_filter is not echoed, is not applied to the listing, and the number of listed responses does not depend on it (no bit oracle on a withheld request URI)", async () => {
  await withCwd(async (cwd, bin) => {
    const SECRET_URI = "/get/session-Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK/a.bin";
    const guesses = [`http.request.full_uri contains "Zk9mQ2xW"`, `http.request.full_uri contains "Zk9mQ2xX"`];
    const counts: number[] = [];
    const answers: string[] = [];
    for (const [i, filter] of guesses.entries()) {
      await stage(cwd, bin, { export: { http: { "a.bin": BODY_A } }, assoc: [row(7, 0, SECRET_URI, BODY_A)] });
      const result = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: `work/f${i}`, protocols: ["http"], display_filter: filter }, env(cwd), bin);
      const out = body(result);
      counts.push(out.association_pass.response_rows);
      answers.push(JSON.stringify([out.association, out.association_pass.response_rows, out.association_pass.bodies_hashed]));
      const everything = await everythingUnder(cwd, result.stdout, [`work/f${i}`], [`work/f${i}/_logs/association.stderr`]);
      assert.equal(everything.includes("Zk9mQ2x"), false, "the filter text is nowhere in the answer, the receipt or the index");
      const calls = (await readFile(join(cwd, "tshark-calls.txt"), "utf8")).split("\n");
      const listing = calls.find((l) => l.includes("-T fields")) ?? "";
      assert.match(listing, /-Y http\.response /, "the listing's own filter is fixed");
      assert.doesNotMatch(listing, /Zk9mQ2x/);
      assert.match(calls.find((l) => l.includes("--export-objects http,")) ?? "", /-Y http\.request\.full_uri contains/, "the caller's filter still reaches the export pass");
    }
    assert.deepEqual(counts, [1, 1], "a matching and a non-matching filter list the same responses");
    assert.equal(answers[0], answers[1]);
  });
});

test("the order of the rows and the numbers of withheld names follow the content, never the real name: shuffling the secret names changes nothing a reader sees", async () => {
  const visible = Object.fromEntries("abcdefghijklmnopqrstuvwxyz".split("").map((c, i) => [`${c}.bin`, Buffer.from(`visible-${c}`.repeat(30 + i))]));
  const secrets = (a: string, b: string): Record<string, Buffer> => ({ [`${a}.bin`]: Buffer.from("S1".repeat(80)), [`${b}.bin`]: Buffer.from("S2".repeat(200)) });
  const shown: string[] = [];
  const mappings: string[] = [];
  for (const [a, b] of [["Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK", "bK3mQ2xW7vB9nL8pR4tY6wD1sFgHjP"], ["cQ9mQ2xW7vB3nL8pR4tY6wD1sFgHjK", "Zz3mQ2xW7vB9nL8pR4tY6wD1sFgHjP"], ["Zz3mQ2xW7vB9nL8pR4tY6wD1sFgHjP", "aQ9mQ2xW7vB3nL8pR4tY6wD1sFgHjK"]]) {
    await withCwd(async (cwd, bin) => {
      await stage(cwd, bin, { export: { http: { ...visible, ...secrets(a, b) } } });
      body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin));
      shown.push(await readFile(join(cwd, "work/x/index.tsv"), "utf8"));
      mappings.push(await readFile(join(cwd, "work/x/withheld-names.jsonl"), "utf8"));
      const rows = await index(cwd, "work/x");
      assert.deepEqual(rows.slice(0, 26).map((r) => r.name), "abcdefghijklmnopqrstuvwxyz".split("").map((c) => `${c}.bin`), "the readable names first, by name");
      assert.deepEqual(rows.slice(26).map((r) => r.path), ["http/withheld-000001.bin", "http/withheld-000002.bin"], "the withheld ones last, numbered in content order");
      assert.deepEqual(rows.slice(26).map((r) => r.bytes), [String(160), String(400)], "smaller content first");
    });
  }
  assert.equal(shown[0], shown[1]);
  assert.equal(shown[0], shown[2], "three different secret names, one index");
  assert.notEqual(mappings[0], mappings[1], "the names themselves are in the private file");
});

test("Decryption Secrets Blocks in a pcapng are counted and said: tshark applies them, so exported content can be decrypted content", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } }, assoc: [row(7, 0, "/a.html", BODY_A)] });
    const dsb = ngBlock(0x0a, Buffer.concat([u32(0x544c534b), u32(13), Buffer.from("CLIENT_RANDOM")]));
    const frame = frameTcp4({ src: "203.0.113.7", dst: "10.0.0.5", sport: 80, dport: 50000, flags: TCP.ACK });
    const file = Buffer.concat([ngSection(), ngInterface({}), dsb, ngPacket({ ticks: ticks(1, 0, 6), frame })]);
    await drop(cwd, "work/d.pcapng", file);
    const out = body(await tool(EXTRACT, cwd, { path: "work/d.pcapng", out_dir: "work/x", protocols: ["http"] }, env(cwd), bin));
    assert.equal(out.decryption_secrets_blocks, 1);
    assert.match(out.decryption_secrets_note, /decrypted content/);
    const plain = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/y", protocols: ["http"] }, env(cwd), bin));
    assert.equal(plain.decryption_secrets_blocks, 0);
  });
});

test("every answer carries status and status_basis: a finished run, a refusal, and a run stopped by a signal (partial JSON on stdout, the receipt says interrupted)", async () => {
  await withCwd(async (cwd, bin) => {
    const { dir } = await stage(cwd, bin, { spawns: ["http"], export: { http: { "a.html": BODY_A } } });
    const refusal = refused(await tool(EXTRACT, cwd, { path: "work/missing.pcap", out_dir: "work/r" }, env(cwd), bin));
    assert.equal(refusal.status, "failed");
    assert.match(refusal.status_basis, /error/);
    const child = spawn("python3", [EXTRACT], { cwd, env: { ...process.env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}`, ...env(cwd) } });
    const stdout: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdout.push(c));
    child.stdin.end(JSON.stringify({ path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }));
    for (let i = 0; i < 100 && !(await exists(join(dir, "started"))); i++) await new Promise((r) => setTimeout(r, 50));
    const code = await new Promise<number | null>((resolve) => { child.on("close", resolve); child.kill("SIGTERM"); });
    assert.equal(code, 143);
    const last = JSON.parse(Buffer.concat(stdout).toString("utf8"));
    assert.equal(last.status, "partial");
    assert.equal(last.receipt_status, "interrupted");
    assert.equal(last.interrupted_by_signal, 15);
    assert.ok(last.status_basis.length > 10);
    assert.equal(JSON.parse(await readFile(join(cwd, "work/x/receipt.json"), "utf8")).status, "interrupted");
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } }, assoc: [row(7, 0, "/a.html", BODY_A)] });
    const done = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/z", protocols: ["http"] }, env(cwd), bin));
    assert.equal(done.status, "complete");
    assert.match(done.status_basis, /every pass ran/);
  });
});

test("the default export types include ftp-data when the build lists it (the skills send the reader to the FTP data channel)", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { exporters: ["ftp-data", "http", "tftp"], export: { "ftp-data": { "dump.bin": BODY_B } } });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x" }, env(cwd), bin));
    assert.deepEqual(out.protocols_requested, ["http", "ftp-data", "tftp"]);
    assert.equal((await index(cwd, "work/x"))[0].path, "ftp-data/dump.bin");
  });
});

test("an unreadable listing row beyond the tenth is still named: every line number is in a file", async () => {
  await withCwd(async (cwd, bin) => {
    const good = row(7, 0, "/a.html", BODY_A).join("\t");
    const bad = (n: number) => [...row(n, 1, "/b.bin", BODY_B).slice(0, 9), "ZZ-not-hex"].join("\t");
    const lines = [FIELDS.join("\t"), good, ...Array.from({ length: 14 }, (_, i) => bad(100 + i))];
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } }, assocRaw: lines.join("\n") + "\n" });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin));
    assert.equal(out.association_pass.rows_unreadable, 14);
    const named = JSON.parse(await readFile(join(cwd, "work/x", out.association_pass.unreadable_lines_file), "utf8")).listing_lines;
    assert.deepEqual(named, Array.from({ length: 14 }, (_, i) => i + 3));
  });
});

// --- the real program, where there is one ---------------------------------------------------------------------------------

/** One HTTP/1.1 exchange over TCP, from the layouts of RFC 9293 (the handshake and the data segments) and RFC 9112 (the messages). */
function httpExchange(o: { client: string; server: string; cport: number; t0: number; host: string; target: string; body: Buffer; gzip?: boolean }): Pkt[] {
  const c = { src: o.client, dst: o.server, sport: o.cport, dport: 80 };
  const s = { src: o.server, dst: o.client, sport: 80, dport: o.cport };
  const request = Buffer.from(`GET ${o.target} HTTP/1.1\r\nHost: ${o.host}\r\nUser-Agent: test\r\n\r\n`);
  const response = Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ${o.body.length}\r\n\r\n`), o.body]);
  const cseq = 1000, sseq = 5000;
  const at = (n: number): number => o.t0 + n;
  return [
    { sec: at(0), frame: frameTcp4({ ...c, flags: TCP.SYN, seq: cseq - 1 }) },
    { sec: at(0), frac: 1000, frame: frameTcp4({ ...s, flags: TCP.SYN | TCP.ACK, seq: sseq - 1, ack: cseq }) },
    { sec: at(0), frac: 2000, frame: frameTcp4({ ...c, flags: TCP.ACK, seq: cseq, ack: sseq }) },
    { sec: at(1), frame: frameTcp4({ ...c, flags: TCP.PSH | TCP.ACK, seq: cseq, ack: sseq, payload: request }) },
    { sec: at(1), frac: 1000, frame: frameTcp4({ ...s, flags: TCP.ACK, seq: sseq, ack: cseq + request.length }) },
    { sec: at(2), frame: frameTcp4({ ...s, flags: TCP.PSH | TCP.ACK, seq: sseq, ack: cseq + request.length, payload: response }) },
    { sec: at(2), frac: 1000, frame: frameTcp4({ ...c, flags: TCP.ACK, seq: cseq + request.length, ack: sseq + response.length }) },
  ];
}

const haveTshark = ((): boolean => {
  const r = spawnSync("tshark", ["--version"], { encoding: "utf8" });
  return r.status === 0 && /TShark/.test(r.stdout);
})();

test("against the real tshark: a three-session HTTP capture is tied to its frames by content, with the host and request URI of each response (skipped where tshark is not installed)", async (t) => {
  if (!haveTshark) {
    t.skip("tshark is not installed on this machine");
    return;
  }
  await withCwd(async (cwd) => {
    const bodies = [Buffer.from("alpha-".repeat(60)), Buffer.from("bravo-".repeat(80)), Buffer.from("charlie-".repeat(70))];
    const packets: Pkt[] = [];
    bodies.forEach((b, i) => packets.push(...httpExchange({ client: "10.0.0.5", server: `203.0.113.${7 + i}`, cport: 50000 + i, t0: 1_700_000_000 + i * 100, host: `f${i}.example.test`, target: `/dir/file${i}.bin`, body: b })));
    await drop(cwd, "work/real.pcap", pcapClassic(packets));
    const result = await tool(EXTRACT, cwd, { path: "work/real.pcap", out_dir: "work/x", protocols: ["http"] });
    const out = body(result);
    assert.equal(out.ok, true, JSON.stringify(out.errors));
    assert.equal(out.status, "complete");
    assert.equal(out.association.matched_by_content, 3, JSON.stringify(out.association_pass));
    assert.equal(out.association_pass.status, "ok");
    const rows = await index(cwd, "work/x");
    for (const r of rows) {
      const i = Number(/file(\d)\.bin/.exec(r.name)?.[1]);
      assert.match(r.frame, /^\d+$/, JSON.stringify(r));
      assert.equal(r.host, `f${i}.example.test`, "the host of a response frame is read from the request URI when http.host is empty");
      assert.equal(r.request_uri, `http://f${i}.example.test/dir/file${i}.bin`);
      assert.equal(r.dst, "10.0.0.5");
    }
  });
});

test("a stop signal still ends the pass's children when ps is slow: the tree is found without waiting on a program (libproc on macOS, /proc on Linux)", async () => {
  await withCwd(async (cwd, bin) => {
    const { dir } = await stage(cwd, bin, { spawns: ["http"] });
    await stub(bin, "ps", "sleep 30\n");
    const child = spawn("python3", [EXTRACT], { cwd, env: { ...process.env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}`, ...env(cwd) } });
    child.stdout.on("data", () => undefined);
    child.stdin.end(JSON.stringify({ path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }));
    for (let i = 0; i < 100 && !(await exists(join(dir, "started"))); i++) await new Promise((r) => setTimeout(r, 50));
    assert.ok(await exists(join(dir, "started")));
    const began = Date.now();
    const code = await new Promise<number | null>((resolve) => { child.on("close", resolve); child.kill("SIGTERM"); });
    assert.equal(code, 143);
    assert.ok(Date.now() - began < 8_000, `took ${Date.now() - began} ms: the tree walk waited on ps`);
    const pid = Number((await readFile(join(dir, "child.pid"), "utf8")).trim());
    await new Promise((r) => setTimeout(r, 300));
    assert.throws(() => process.kill(pid, 0), /ESRCH/, "the sleeper the pass started is gone");
  });
});

test("write_values is refused as JSON, before anything is written, in a job whose process is not a secret job (SECRET_OUTPUT is not 1)", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } } });
    for (const value of ["0", ""]) {
      const err = refused(await asJob(EXTRACT, cwd, { path: await capture(cwd), out_dir: "out/x", protocols: ["http"], write_values: true }, bin, { ...env(cwd), SECRET_OUTPUT: value }));
      assert.match(err.error, /not run as secret output/);
      assert.equal(err.written, false);
      assert.equal(await exists(join(cwd, "out/pcap-extract-values.jsonl")), false);
      assert.equal(await exists(join(cwd, "out/x")), false);
    }
    assert.equal(body(await asJob(EXTRACT, cwd, { path: await capture(cwd), out_dir: "out/y", protocols: ["http"], write_values: true }, bin, env(cwd))).secret_values.requested, true);
  });
});
