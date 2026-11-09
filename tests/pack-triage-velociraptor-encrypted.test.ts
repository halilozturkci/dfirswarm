/**
 * triage-collection: an encrypted Velociraptor collection is named as one. Velociraptor 0.77.2 writes it when a password is set
 * (reporting/container.go, NewContainerFromWriter): an outer zip of `data.zip`, a stored member that is encrypted with the zip password
 * (alexmullins/zip, WinZip AES), and `metadata.json` (plain; present when the collector was given metadata, with the keys Scheme,
 * EncryptedPass and PublicKey that artifacts/definitions/Server/Utils/CreateCollector.yaml sets). Its records are inside the payload.
 * Every triage reader says the records were not read, ends `partial`, gives no failure count and decrypts nothing; the metadata values
 * (an encrypted password, a key) are withheld, and go only to the values file of a secret_output job.
 *
 * The fixtures are built from that layout, not from a tool's output: the outer zip is written with the standard library and its data.zip
 * member then carries the encryption bit of the zip general-purpose flag and compression method 99 (WinZip AES) in its local and central
 * headers, which is what a reader of the central directory sees. A plain 0.77.2 container is read as before (the existing suites).
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { runPySnippet } from "./tool-library-harness.ts";
import { ID, TOOLS, TRIAGE, asJob, body, put, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const RECIPE = join(TRIAGE, "recipes", "collection-intake", "run.py");
const PARSE = join(TOOLS, "collection_manifest_parse", "run.py");
const VERIFY = join(TOOLS, "collection_manifest_verify", "run.py");
const PATH_MAP = join(TOOLS, "collection_path_map", "run.py");
const COVERAGE = join(TOOLS, "collection_coverage", "run.py");

// values that are never printed: an encrypted password and a certificate, and a scheme word that is not one of the real ones
const PASS = "QkFTRTY0LUNBTkFSWS1QQVNTV09SRC0wMDAx";
const KEY = "-----BEGIN CERTIFICATE-----CANARYPUBKEY0001-----END CERTIFICATE-----";
const SCHEME = "SchemeCanary7Q";
const META = JSON.stringify({ Scheme: SCHEME, EncryptedPass: PASS, PublicKey: KEY });
const CANARIES = [PASS, KEY, SCHEME, "CANARYPUBKEY0001"];

// an outer zip as 0.77.2 writes it: data.zip is a stored member marked encrypted (flag bit 0, method 99); metadata.json only when asked for
const OUTER = `
import sys, json, struct, zipfile
out, with_meta, meta = sys.argv[1], sys.argv[2] == "1", sys.argv[3]
with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
    if with_meta:
        z.writestr("metadata.json", meta)
    z.writestr("data.zip", b"PK-the-encrypted-payload-bytes" * 4)
data = bytearray(open(out, "rb").read())
i = data.find(b"PK\\x03\\x04")
while i >= 0:
    n = struct.unpack_from("<H", data, i + 26)[0]
    if bytes(data[i + 30:i + 30 + n]) == b"data.zip":
        struct.pack_into("<H", data, i + 6, struct.unpack_from("<H", data, i + 6)[0] | 1)
        struct.pack_into("<H", data, i + 8, 99)
    i = data.find(b"PK\\x03\\x04", i + 4)
i = data.find(b"PK\\x01\\x02")
while i >= 0:
    n = struct.unpack_from("<H", data, i + 28)[0]
    if bytes(data[i + 46:i + 46 + n]) == b"data.zip":
        struct.pack_into("<H", data, i + 8, struct.unpack_from("<H", data, i + 8)[0] | 1)
        struct.pack_into("<H", data, i + 10, 99)
    i = data.find(b"PK\\x01\\x02", i + 4)
open(out, "wb").write(data)
`;

const PLAIN_ZIP = `
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_STORED) as z:
    for name, data in (("metadata.json", sys.argv[2]), ("data.zip", "PK-a-plain-member")):
        z.writestr(name, data)
`;

async function outer(path: string, withMeta: boolean): Promise<void> {
  const run = await runPySnippet(OUTER, [path, withMeta ? "1" : "0", META], null);
  assert.equal(run.code, 0, run.stderr);
}

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

const target = (p: string) => JSON.stringify({ paths: [p] });

/** A delivered directory: the container's two members, extracted. */
async function delivered(cwd: string, meta = META): Promise<void> {
  await put(cwd, "ev/case1/metadata.json", meta);
  await put(cwd, "ev/case1/data.zip", "PK-the-payload-as-a-file");
}

async function everything(dir: string): Promise<string> {
  const names = await readdir(dir, { recursive: true });
  const parts: string[] = [];
  for (const name of names) {
    const text = await readFile(join(dir, name as string)).then((b) => b.toString("latin1"), () => "");
    parts.push(text);
  }
  return parts.join("\n");
}

test("a delivered directory with data.zip beside a metadata.json that holds the Scheme key is named by every record reader as an encrypted collection, partial, with no failure count", async () => {
  await withCwd(async (cwd) => {
    await delivered(cwd);
    const parse = body(await asJob(PARSE, cwd, { root: "ev" }, {}, "o-parse"));
    assert.equal(parse.status, "partial");
    const source = (parse.sources as Json[]).find((s) => s.kind === "velociraptor_encrypted");
    assert.ok(source, JSON.stringify(parse.sources).slice(0, 400));
    assert.equal(source.status, "unsupported");
    assert.equal(source.adapter, "velociraptor_encrypted/1");
    assert.equal(source.decrypted, false);
    assert.match(String(source.reason), /records are inside the encrypted payload/);
    assert.equal(parse.failures_recorded.count, null, "no failure count is determined");
    assert.equal(parse.runs[0].failures_recorded.count, null);
    assert.match(parse.status_basis, /unsupported/);
    assert.equal(parse.records_total, 0);
    // presence and length of each documented key, never the value
    assert.deepEqual(source.metadata.keys, ["Scheme", "EncryptedPass", "PublicKey"]);
    assert.match(source.metadata.values.EncryptedPass, new RegExp(`^<value withheld, ${PASS.length} characters, W\\d+>$`));

    const verify = body(await asJob(VERIFY, cwd, { root: "ev" }, {}, "o-verify"));
    assert.equal(verify.status, "partial", verify.status_basis);
    assert.match(JSON.stringify(verify), /velociraptor_encrypted/);

    const map = body(await asJob(PATH_MAP, cwd, { root: "ev", paths: ["case1/data.zip"] }, {}, "o-map"));
    assert.equal(map.status, "partial", map.status_basis);
    assert.match(JSON.stringify(map), /velociraptor_encrypted/);

    const cov = body(await asJob(COVERAGE, cwd, { root: "ev", questions: [{ id: "q1", source_paths: ["case1/data.zip"] }] }, {}, "o-cov"));
    assert.equal(cov.status, "partial", cov.status_basis);
    assert.match(JSON.stringify(cov), /velociraptor_encrypted/);
  });
});

test("the metadata values are withheld from every answer and go only to the values file of a secret_output job", async () => {
  await withCwd(async (cwd) => {
    await delivered(cwd);
    for (const [script, args, name] of [
      [PARSE, { root: "ev" }, "parse"], [VERIFY, { root: "ev" }, "verify"], [PATH_MAP, { root: "ev", paths: ["case1/data.zip"] }, "map"],
      [COVERAGE, { root: "ev", questions: [{ id: "q1", source_paths: ["case1/data.zip"] }] }, "cov"], [ID, { root: "ev" }, "id"],
    ] as Array<[string, Json, string]>) {
      const run = await asJob(script, cwd, args, {}, `o-${name}`);
      for (const c of CANARIES) assert.ok(!run.stdout.includes(c) && !run.stderr.includes(c), `${name}: a metadata value is in the answer`);
      assert.ok(!(await everything(join(cwd, `o-${name}`))).includes(PASS), `${name}: a metadata value is in a file of the job`);
    }
    // collection_manifest_parse and collection_id write the values of a withheld string when asked, in a secret_output job
    for (const [script, name, values] of [[PARSE, "parse", "collection-manifest-parse-values.jsonl"], [ID, "id", "collection-id-values.jsonl"]] as Array<[string, string, string]>) {
      const run = await asJob(script, cwd, { root: "ev", write_values: true }, {}, `v-${name}`);
      for (const c of CANARIES) assert.ok(!run.stdout.includes(c), `${name}: a metadata value is in the answer of a secret job`);
      const file = await readFile(join(cwd, `v-${name}`, values), "utf8");
      assert.ok(file.includes(PASS) && file.includes("CANARYPUBKEY0001"), `${name}: the real values are in the values file`);
    }
  });
});

test("collection_id names the directory as an encrypted collection, partial, and says the collector's records were not read", async () => {
  await withCwd(async (cwd) => {
    await delivered(cwd);
    const id = body(await asJob(ID, cwd, { root: "ev" }));
    assert.equal(id.status, "partial", id.status_basis);
    assert.equal(id.failed_target_count, null);
    assert.match(id.failed_target_count_basis, /unsupported/);
    assert.ok((id.delivery.not_observed as string[]).some((x) => /encrypted Velociraptor collection/.test(x) && /not read/.test(x)), JSON.stringify(id.delivery.not_observed));
    assert.equal(id.delivery.not_observed_complete, false);
    assert.ok((id.collector_candidates as Json[]).some((c) => c.collector === "Velociraptor"));
    const run = (id.runs as Json[]).find((r) => r.collector === "Velociraptor");
    assert.equal(run.record.status, "unsupported");
    assert.equal(run.record.decrypted, false);
  });
});

test("a directory that only looks like one is read as before: no Scheme key, or another file beside the pair", async () => {
  await withCwd(async (cwd) => {
    await delivered(cwd, JSON.stringify({ Other: "x" }));
    const parse = body(await asJob(PARSE, cwd, { root: "ev" }, {}, "o1"));
    assert.ok(!(parse.sources as Json[]).some((s) => s.kind === "velociraptor_encrypted"));
    await put(cwd, "ev2/case1/metadata.json", META);
    await put(cwd, "ev2/case1/data.zip", "PK-x");
    await put(cwd, "ev2/case1/notes.txt", "a file beside the pair");
    const second = body(await asJob(PARSE, cwd, { root: "ev2" }, {}, "o2"));
    assert.ok(!(second.sources as Json[]).some((s) => s.kind === "velociraptor_encrypted"));
  });
});

for (const withMeta of [true, false]) {
  test(`the recipe names the encrypted payload of an outer zip ${withMeta ? "with" : "without"} metadata.json, partial, and decrypts nothing`, async () => {
    await withCwd(async (cwd) => {
      await outer(join(cwd, "c.zip"), withMeta);
      const detect = await recipe(["detect", "--target", target("c.zip")], cwd);
      assert.equal(detect.code, 0, detect.stdout);
      assert.equal(JSON.parse(detect.stdout).applies, true);
      const run = await recipe(["run", "--target", target("c.zip"), "--out", "out"], cwd);
      assert.equal(run.code, 0, run.stdout);
      assert.equal(JSON.parse(run.stdout).status, "partial");
      const cov = JSON.parse(await readFile(join(cwd, "out", "coverage.json"), "utf8"));
      assert.equal(cov.status, "partial");
      assert.match(cov.status_basis, /encrypted Velociraptor collection/);
      assert.match(cov.status_basis, /not decrypted and was not read/);
      assert.equal(cov.encrypted_collections_total, 1);
      assert.equal(cov.encrypted_collections[0].payload, "data.zip");
      assert.equal(cov.encrypted_collections[0].decrypted, false);
      assert.equal(cov.nested_archives_total, 0, "the payload is not an archive inside the archive to extract");
      assert.equal(cov.members_unreadable_total, 0, "and not a member that failed to read");
      assert.equal(cov.records, 0);
      const inventory = await readFile(join(cwd, "out", "inventory.tsv"), "utf8");
      assert.match(inventory, /data\.zip\tthe encrypted payload of a Velociraptor collection: not read, not decrypted/);
      const units = JSON.parse(await readFile(join(cwd, "out", "units.json"), "utf8"));
      assert.equal(units.units[0].sources[0].status, "unsupported");
      const all = await everything(join(cwd, "out"));
      for (const c of CANARIES) assert.ok(!all.includes(c) && !run.stdout.includes(c), "a metadata value is in an output of the recipe");
      assert.deepEqual((await readdir(join(cwd, "out"))).sort(), ["coverage.json", "index.tsv", "inventory.tsv", "records.jsonl", "units.json", "verification.jsonl"]);
    });
  });
}

test("a zip with a plain data.zip and a metadata.json that is not the encryption's is not an encrypted collection", async () => {
  await withCwd(async (cwd) => {
    const made = await runPySnippet(PLAIN_ZIP, [join(cwd, "p.zip"), JSON.stringify({ Other: "x" })], null);
    assert.equal(made.code, 0, made.stderr);
    const detect = await recipe(["detect", "--target", target("p.zip")], cwd);
    assert.equal(detect.code, 1, detect.stdout);
    assert.equal(JSON.parse(detect.stdout).applies, false);
  });
});
