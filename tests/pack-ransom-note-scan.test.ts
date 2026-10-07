/**
 * ransom_note_scan, against fixtures the test builds from the documented formats
 * and never from the tool's own output: a bitcoin address is checked here by its
 * own checksum (base58check: the last four bytes are the start of a double sha256;
 * BIP-173: the bech32 polymod), and a note's byte offsets are checked by slicing
 * the file.
 *
 * The tool follows the secret-safe output pattern written down in docs/packs.md
 * ("Secrets and sensitive output"): what it prints and what it writes is checked
 * for every identifier, wallet, onion address, URL and the note's own text, in the
 * answer and in every file the answer names. Only the values file may hold them,
 * and only in a job.
 */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, readdir, stat, symlink, utimes, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPySnippet, withCwd } from "./tool-library-harness.ts";
import { EIO_SITE, NOTES, allRows, body, exists, filesUnder, refused, tool } from "./ransomware-pack-harness.ts";
import type { Page } from "./ransomware-pack-harness.ts";

// --- independent checks of the fixtures ------------------------------------------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** base58check, written from the Bitcoin wiki's description: 25 bytes, the last four the double sha256's first four. */
function base58checkValid(address: string): boolean {
  let n = 0n;
  for (const ch of address) {
    const i = B58.indexOf(ch);
    if (i < 0) return false;
    n = n * 58n + BigInt(i);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  let raw = Buffer.from(hex, "hex");
  const zeros = address.length - address.replace(/^1+/, "").length;
  raw = Buffer.concat([Buffer.alloc(zeros), raw]);
  if (raw.length !== 25) return false;
  const sum = createHash("sha256").update(createHash("sha256").update(raw.subarray(0, 21)).digest()).digest().subarray(0, 4);
  return sum.equals(raw.subarray(21));
}

const BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/** BIP-173 bech32 (the polymod with constant 1) for a v0 witness address. */
function bech32Valid(address: string): boolean {
  const lower = address.toLowerCase();
  const sep = lower.lastIndexOf("1");
  if (sep < 1 || sep + 7 > lower.length) return false;
  const hrp = lower.slice(0, sep);
  const data = [...lower.slice(sep + 1)].map((c) => BECH32.indexOf(c));
  if (data.includes(-1)) return false;
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  const values = [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31), ...data];
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk = (chk ^ gen[i]) >>> 0;
  }
  return chk === 1;
}

// Published example addresses: the genesis block's payout address, the BIP-173
// example for a witness program, and the same address with one character
// changed (the checksum must fail).
const BTC_LEGACY = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
const BTC_BECH32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const BTC_BROKEN = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb";
const ETH = "0x52908400098527886E0F7030069857D2E4169EE7";
// A syntactic Monero address (a 4, a second character in 0-9AB, 93 base58 characters) and a Tox id (76 hex
// digits), both made from digests so that nothing in them repeats; neither has a checksum the test could use.
const digestOf = (label: string, algo = "sha256") => createHash(algo).update(label).digest();
const XMR = "4A" + [...digestOf("xmr-1"), ...digestOf("xmr-2"), ...digestOf("xmr-3")].slice(0, 93).map((b) => B58[b % 58]).join("");
const TOX = (digestOf("tox").toString("hex") + digestOf("tox", "md5").toString("hex").slice(0, 12)).toUpperCase();
const ONION_V3 = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion";
const ONION_V2 = "expyuzz4wqqyqhjn.onion";
const EMAIL = "recovery.desk@example-mail.invalid";
const VICTIM_ID = "Zq7Rk2Vx9LmT4pWn8Hc3";
const ACCESS_KEY = "k8Vd02QmXz5LrTf9AbCdEf6G";
const URL_WITH_KEY = `http://${ONION_V3}/chat?access-key=${ACCESS_KEY}`;

test("the fixture addresses are what their formats say they are", () => {
  assert.equal(base58checkValid(BTC_LEGACY), true);
  assert.equal(base58checkValid(BTC_BROKEN), false);
  assert.equal(bech32Valid(BTC_BECH32), true);
  assert.equal(bech32Valid(BTC_BECH32.slice(0, -1) + "q"), false);
  assert.equal(TOX.length, 76);
  assert.equal(XMR.length, 95);
  assert.equal(ETH.length, 42);
  assert.equal(ONION_V3.length, 56 + ".onion".length);
  assert.equal(ONION_V2.length, 16 + ".onion".length);
});

// --- ransom_note_scan --------------------------------------------------------------

const NOTE_TEXT = [
  "!!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!!",
  "",
  "We can decrypt your files. Install the Tor Browser and open the portal.",
  `Portal: ${URL_WITH_KEY}`,
  `Onion mirror: ${ONION_V2}`,
  `Your personal ID: ${VICTIM_ID}`,
  `Pay to: ${BTC_LEGACY}`,
  `Alternative: ${BTC_BECH32}`,
  `Corrupt copy of the address: ${BTC_BROKEN}`,
  `Ethereum: ${ETH}`,
  `Monero: ${XMR}`,
  `Tox: ${TOX}`,
  `Mail: ${EMAIL}`,
  "",
].join("\n");

const VALUES = [VICTIM_ID, ACCESS_KEY, BTC_LEGACY, BTC_BECH32, BTC_BROKEN, ETH, XMR, TOX, ONION_V3.replace(".onion", ""), ONION_V2.replace(".onion", ""), EMAIL, "recovery.desk"];

type NoteRow = {
  note_id: string;
  file: string;
  bytes: number;
  sha256: string | null;
  modified_utc: string | null;
  mtime_ns: number;
  class: string;
  class_basis: string[];
  encoding: string;
  encoding_basis: string;
  decode_errors: number;
  format_hint: string;
  indicator_counts: Record<string, number>;
  parser: string;
};
type Occurrence = { finding_id: string; note_id: string; kind: string; offset: number; length: number; encoding: string; validation?: string; duplicate_of?: string };
type Rejected = { path: string; status: string; reason: string; bytes?: number; error?: string };
type NoteScan = {
  root: string;
  parser: string;
  complete: string;
  notes: NoteRow[];
  candidate_count: number;
  candidates_by_class: Record<string, number>;
  rejected_count: number;
  rejected: Rejected[];
  indicator_counts: Record<string, Record<string, number>>;
  occurrences: Occurrence[];
  earliest_observed_note_mtime: { note_id: string; modified_utc: string; clock: string; caveat: string } | null;
  distinct_note_contents: { sha256: string | null; copies: number }[];
  coverage: Record<string, number>;
  exclusions: { path: string; reason: string }[];
  pages: Record<string, Page>;
  secret_values: { requested: boolean; written: number; values_file: string | null; contains_secret_values: boolean };
  paths_withheld: number;
  truncated: boolean;
};

/** Everything a tool printed or wrote, apart from the values file. */
async function everythingPrinted(cwd: string, stdout: string, outDir?: string): Promise<string> {
  let all = stdout;
  // The evidence is under work/ev; what a tool writes outside a job is under work/<agent>/tool-output.
  for (const dir of [join(cwd, "work", "s1"), ...(outDir ? [outDir] : [])]) {
    for (const [name, text] of Object.entries(await filesUnder(dir))) {
      if (name === "ransom-note-values.jsonl") continue;
      all += "\n" + text;
    }
  }
  return all;
}

function assertNoValue(printed: string): void {
  for (const v of VALUES) assert.ok(!printed.includes(v), `a value of the note (${v}) is in the output`);
  // Nor a fragment of the longer ones: no run of twelve characters of an identifier or a key.
  for (const v of [VICTIM_ID, ACCESS_KEY, BTC_LEGACY, ETH, TOX, XMR]) {
    for (let i = 0; i + 12 <= v.length; i++) assert.ok(!printed.includes(v.slice(i, i + 12)), `a fragment of a value is in the output (${v.slice(i, i + 12)})`);
  }
  assert.doesNotMatch(printed, /ALL YOUR FILES HAVE BEEN ENCRYPTED|Install the Tor Browser/, "the note's own text is in the output");
  assert.doesNotMatch(printed, /"first_lines"|"preview"/);
}

async function plantNotes(cwd: string): Promise<void> {
  await mkdir(join(cwd, "work", "ev", "Users", "alice", "Desktop"), { recursive: true });
  await mkdir(join(cwd, "work", "ev", "srv", "share"), { recursive: true });
  await writeFile(join(cwd, "work", "ev", "Users", "alice", "Desktop", "HOW_TO_DECRYPT.txt"), NOTE_TEXT);
  await writeFile(join(cwd, "work", "ev", "srv", "share", "HOW_TO_DECRYPT.txt"), NOTE_TEXT);
  // A project readme that happens to match the name gate.
  await writeFile(join(cwd, "work", "ev", "srv", "README.txt"), "# parsley\n\nA small HTTP client. Run `make test`, then read the docs.\n");
}

test("ransom_note_scan prints no identifier, wallet, onion address, URL, address of a contact or note text", async () => {
  // It printed every identifier it matched ("your personal key/token" included),
  // the first lines of every note and global lists of every address, inline.
  await withCwd(async (cwd) => {
    await plantNotes(cwd);
    const out = await tool(NOTES, cwd, { root: "work/ev" });
    const scan = body<NoteScan>(out);
    assertNoValue(await everythingPrinted(cwd, out.stdout));
    assert.equal(scan.candidate_count, 3);
    assert.equal(scan.notes.length, 3);
    for (const key of ["victim_identifiers", "onion_addresses", "wallets", "contact_emails", "urls", "tox_ids", "identifiers"]) {
      assert.ok(!(key in scan), `${key} is still an answer field`);
    }
    // What it says instead: counts per kind, with offsets in the occurrence rows.
    const note = scan.notes.find((n) => n.file.includes("Desktop"));
    assert.ok(note, JSON.stringify(scan.notes));
    assert.deepEqual(note.indicator_counts, {
      onion: 2,
      email: 1,
      url: 1,
      bitcoin: 3,
      ethereum: 1,
      monero: 1,
      tox: 1,
      identifier_candidate: 1,
    });
    assert.match(note.parser, /^ransom_note_scan\//);
    assert.equal(scan.secret_values.requested, false);
    assert.equal(scan.secret_values.contains_secret_values, false);
    assert.equal(scan.secret_values.values_file, null);
  });
});

test("ransom_note_scan says a project readme is a name match and a note with note content resembles one", async () => {
  // Every file whose name matched was counted as a ransom note.
  await withCwd(async (cwd) => {
    await plantNotes(cwd);
    const scan = body<NoteScan>(await tool(NOTES, cwd, { root: "work/ev" }));
    const readme = scan.notes.find((n) => n.file.endsWith("README.txt"));
    assert.ok(readme);
    assert.equal(readme.class, "filename_only");
    assert.deepEqual(readme.indicator_counts, {});
    const real = scan.notes.filter((n) => n.file.endsWith("HOW_TO_DECRYPT.txt"));
    assert.equal(real.length, 2);
    for (const n of real) {
      assert.equal(n.class, "content_resembles_note");
      assert.ok(n.class_basis.includes("onion") && n.class_basis.includes("wallet") && n.class_basis.includes("identifier_candidate"), n.class_basis.join());
    }
    assert.deepEqual(scan.candidates_by_class, { content_resembles_note: 2, filename_only: 1 });
    // Two copies of one note are one content, said by count, and its digest is the whole file's.
    const sha = createHash("sha256").update(NOTE_TEXT).digest("hex");
    assert.deepEqual(scan.distinct_note_contents.find((d) => d.sha256 === sha)?.copies, 2);
    assert.equal(real[0].sha256, sha);
  });
});

test("ransom_note_scan checks a bitcoin address's own checksum and calls the rest a syntactic candidate", async () => {
  await withCwd(async (cwd) => {
    await plantNotes(cwd);
    const scan = body<NoteScan>(await tool(NOTES, cwd, { root: "work/ev", limit: 1000 }));
    const rows = scan.occurrences.filter((o) => o.note_id === scan.notes.find((n) => n.file.includes("Desktop"))?.note_id);
    const bitcoin = rows.filter((o) => o.kind === "bitcoin").map((o) => o.validation).sort();
    assert.deepEqual(bitcoin, ["checksum_failed", "checksum_valid", "checksum_valid"]);
    assert.equal(rows.find((o) => o.kind === "ethereum")?.validation, "syntactic_candidate");
    assert.equal(rows.find((o) => o.kind === "monero")?.validation, "syntactic_candidate");
    assert.equal(scan.indicator_counts.bitcoin.checksum_valid, 4, "two notes, two valid addresses each");
    assert.equal(scan.indicator_counts.bitcoin.checksum_failed, 2);
  });
});

test("ransom_note_scan writes values only on request, only in a job, to a file of mode 0600, with the offset of each in the note", async () => {
  await withCwd(async (cwd) => {
    await plantNotes(cwd);
    const direct = refused(await tool(NOTES, cwd, { root: "work/ev", write_values: true }));
    assert.match(direct.error, /write_values/);
    assert.match(direct.error, /secret_output/);
    assert.deepEqual(await readdir(join(cwd, "work")), ["ev"], "nothing is written outside a job");

    const outDir = join(cwd, "out");
    await mkdir(outDir);
    const job = { JOB_ID: "j000001", OUT: outDir };
    const quiet = await tool(NOTES, cwd, { root: "work/ev" }, job);
    assert.equal(await exists(join(outDir, "ransom-note-values.jsonl")), false);
    assertNoValue(await everythingPrinted(cwd, quiet.stdout, outDir));

    const loud = await tool(NOTES, cwd, { root: "work/ev", write_values: true }, job);
    const scan = body<NoteScan>(loud);
    assertNoValue(await everythingPrinted(cwd, loud.stdout, outDir));
    assert.equal(scan.secret_values.requested, true);
    assert.equal(scan.secret_values.contains_secret_values, true);
    assert.equal(scan.secret_values.values_file, "store/jobs/j000001/out/ransom-note-values.jsonl");
    const file = join(outDir, "ransom-note-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const rows = (await readFile(file, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { finding_id: string; kind: string; file: string; offset: number; encoding: string; value: string });
    assert.equal(scan.secret_values.written, rows.length);
    // Every value the note holds is there, and the offset is where its bytes are.
    const got = new Set(rows.filter((r) => r.kind !== "note_preview").map((r) => r.value));
    for (const want of [VICTIM_ID, BTC_LEGACY, BTC_BECH32, BTC_BROKEN, ETH, XMR, TOX, ONION_V3, ONION_V2, EMAIL, URL_WITH_KEY]) assert.ok(got.has(want), `no row for ${want}`);
    for (const r of rows.filter((x) => x.kind !== "note_preview")) {
      const raw = await readFile(join(cwd, r.file));
      assert.equal(raw.subarray(r.offset, r.offset + Buffer.byteLength(r.value)).toString("utf8"), r.value, `the offset of ${r.kind} is not where the bytes are`);
    }
    // The finding ids of the answer's occurrence rows are the values file's.
    const answerIds = new Set(scan.occurrences.map((o) => o.finding_id));
    for (const r of rows.filter((x) => x.kind !== "note_preview")) assert.ok(answerIds.has(r.finding_id) || scan.pages.occurrences.truncated);
    // A second run does not overwrite the values file of the first: it is refused by name, before anything is scanned.
    const again = refused(await tool(NOTES, cwd, { root: "work/ev", write_values: true }, job));
    assert.match(again.error, /already exists/);
  });
});

test("ransom_note_scan reads a UTF-16 note with or without a byte-order mark, and an offset is a byte offset", async () => {
  // It treated any NUL in the first 200 bytes as UTF-16LE and knew no BOM and no UTF-16BE.
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    const text = `Files locked.\r\nYour personal ID: ${VICTIM_ID}\r\nPay ${BTC_LEGACY}\r\n`;
    const le = Buffer.from(text, "utf16le");
    const be = Buffer.from(le).swap16();
    await writeFile(join(cwd, "work", "ev", "readme_le_bom.txt"), Buffer.concat([Buffer.from([0xff, 0xfe]), le]));
    await writeFile(join(cwd, "work", "ev", "readme_be_bom.txt"), Buffer.concat([Buffer.from([0xfe, 0xff]), be]));
    await writeFile(join(cwd, "work", "ev", "readme_le_plain.txt"), le);
    await writeFile(join(cwd, "work", "ev", "readme_be_plain.txt"), be);
    const outDir = join(cwd, "out");
    await mkdir(outDir);
    const out = await tool(NOTES, cwd, { root: "work/ev", write_values: true }, { JOB_ID: "j000002", OUT: outDir });
    const scan = body<NoteScan>(out);
    const encodings = Object.fromEntries(scan.notes.map((n) => [n.file.split("/").pop(), [n.encoding, n.encoding_basis, n.decode_errors]]));
    assert.deepEqual(encodings, {
      "readme_be_bom.txt": ["UTF-16BE", "byte-order mark", 0],
      "readme_be_plain.txt": ["UTF-16BE", "NUL byte pattern", 0],
      "readme_le_bom.txt": ["UTF-16LE", "byte-order mark", 0],
      "readme_le_plain.txt": ["UTF-16LE", "NUL byte pattern", 0],
    });
    const rows = (await readFile(join(outDir, "ransom-note-values.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { kind: string; file: string; offset: number; encoding: string; value: string });
    const ids = rows.filter((r) => r.kind === "identifier_candidate");
    assert.equal(ids.length, 4);
    for (const r of ids) {
      assert.equal(r.value, VICTIM_ID);
      const raw = await readFile(join(cwd, r.file));
      let slice = Buffer.from(raw.subarray(r.offset, r.offset + 2 * r.value.length));
      if (r.encoding === "UTF-16BE") slice = slice.swap16();
      assert.equal(slice.toString("utf16le"), VICTIM_ID, `${r.file}: the offset ${r.offset} is not the byte offset of the identifier`);
    }
    assertNoValue(await everythingPrinted(cwd, out.stdout, outDir));
  });
});

test("ransom_note_scan rejects a link that is named like a note, and says it did", async () => {
  // It opened whatever the name matched, a symbolic link to a file outside the tree included.
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await mkdir(join(cwd, "outside"), { recursive: true });
    await writeFile(join(cwd, "outside", "target.txt"), `Your personal ID: ${VICTIM_ID}\nsecret of another system\n`);
    await symlink(join(cwd, "outside", "target.txt"), join(cwd, "work", "ev", "HOW_TO_DECRYPT.txt"));
    const out = await tool(NOTES, cwd, { root: "work/ev" });
    assert.ok(!out.stdout.includes("another system"), "the link was followed and its target read");
    const scan = body<NoteScan>(out);
    assert.equal(scan.candidate_count, 0);
    assert.equal(scan.rejected_count, 1);
    assert.match(scan.rejected[0].reason, /symbolic link/);
    assert.ok(!out.stdout.includes(VICTIM_ID));
  });
});

test("ransom_note_scan lists every name match it did not read, with the reason, instead of dropping it", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "empty_readme.txt"), "");
    await writeFile(join(cwd, "work", "ev", "big_decrypt.txt"), Buffer.alloc(5000, 0x41));
    await writeFile(join(cwd, "work", "ev", "readme_ok.txt"), "nothing\n");
    const scan = body<NoteScan>(await tool(NOTES, cwd, { root: "work/ev", max_size: 1000 }));
    assert.equal(scan.candidate_count, 1);
    assert.equal(scan.rejected_count, 2);
    const byName = Object.fromEntries(scan.rejected.map((r) => [r.path.split("/").pop(), r]));
    assert.match(byName["empty_readme.txt"].reason, /empty/);
    assert.match(byName["big_decrypt.txt"].reason, /larger than max_size/);
    assert.equal(byName["big_decrypt.txt"].bytes, 5000);
    assert.equal(scan.complete, "partial");
    // max_size has an upper bound, as well as a lower.
    assert.match(refused(await tool(NOTES, cwd, { root: "work/ev", max_size: 1 << 30 })).error, /max_size/);
  });
});

test("ransom_note_scan names a note whose read failed, and does not count it as read", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await mkdir(join(cwd, "pystub"), { recursive: true });
    await writeFile(join(cwd, "pystub", "sitecustomize.py"), EIO_SITE);
    await writeFile(join(cwd, "work", "ev", "readme_unreadable.txt"), "text");
    await writeFile(join(cwd, "work", "ev", "readme_ok.txt"), "text");
    const scan = body<NoteScan>(await tool(NOTES, cwd, { root: "work/ev" }, { PYTHONPATH: join(cwd, "pystub") }));
    assert.equal(scan.candidate_count, 1);
    assert.equal(scan.rejected_count, 1);
    assert.match(scan.rejected[0].reason, /could not be read/);
    assert.match(scan.rejected[0].error ?? "", /Input\/output error|EIO/);
    assert.equal(scan.complete, "partial");
  });
});

test("ransom_note_scan withholds a path component shaped like an identifier, and the real path is in the values file only", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev", "Users", "bob"), { recursive: true });
    // The note's name carries the victim's identifier, as some families name it.
    const named = `restore-${VICTIM_ID}.txt`;
    await writeFile(join(cwd, "work", "ev", "Users", "bob", named), `Your personal ID: ${VICTIM_ID}\ndecrypt your files\n`);
    // A note whose name carries an identifier of a shape the scan did not extract.
    await writeFile(join(cwd, "work", "ev", "Users", "bob", "readme-9fK2xQ7LmP4w.txt"), "decrypt your files, your files are encrypted\n");
    // And one whose name carries a letters-only identifier, which only the note's own value gives away.
    await writeFile(join(cwd, "work", "ev", "Users", "bob", "readme-ZqRkVxLmTpWnHcab.txt"), "Your personal ID: ZqRkVxLmTpWnHcab\ndecrypt your files\n");
    const outDir = join(cwd, "out");
    await mkdir(outDir);
    const out = await tool(NOTES, cwd, { root: "work/ev", write_values: true }, { JOB_ID: "j000003", OUT: outDir });
    const scan = body<NoteScan>(out);
    const printed = await everythingPrinted(cwd, out.stdout, outDir);
    assert.ok(!printed.includes(VICTIM_ID), "the identifier is in a printed path");
    assert.ok(!printed.includes("9fK2xQ7LmP4w"), "an identifier-shaped name is printed");
    assert.ok(!printed.includes("ZqRkVxLmTpWnHcab"), "a name that carries the note's own identifier is printed");
    assert.equal(scan.notes.length, 3);
    assert.equal(scan.paths_withheld >= 3, true);
    assert.ok(scan.notes.every((n) => n.file.includes("Users/bob/")), "the directory stays: only the shaped component is withheld");
    assert.ok(scan.notes.every((n) => /withheld/.test(n.file)));
    const values = await readFile(join(outDir, "ransom-note-values.jsonl"), "utf8");
    assert.ok(values.includes(named), "the values file keeps the real path");
  });
});

test("ransom_note_scan lists a directory it skipped at the top of a Linux root, and reads one called dev deeper down", async () => {
  // It dropped a directory called proc, sys or dev wherever it stood, without a word.
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev", "dev"), { recursive: true });
    await mkdir(join(cwd, "work", "ev", "home", "dev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "dev", "README_top"), "decrypt your files, your files are encrypted\n");
    await writeFile(join(cwd, "work", "ev", "home", "dev", "README_deep"), "decrypt your files, your files are encrypted\n");
    const scan = body<NoteScan>(await tool(NOTES, cwd, { root: "work/ev" }));
    assert.deepEqual(scan.notes.map((n) => n.file.split("/").pop()), ["README_deep"]);
    assert.equal(scan.exclusions.length, 1);
    assert.match(scan.exclusions[0].path, /ev\/dev$/);
    assert.match(scan.exclusions[0].reason, /exclude_top_level_dirs/);
    const none = body<NoteScan>(await tool(NOTES, cwd, { root: "work/ev", exclude_top_level_dirs: [] }));
    assert.deepEqual(none.notes.map((n) => n.file.split("/").pop()).sort(), ["README_deep", "README_top"]);
    assert.equal(none.exclusions.length, 0);
  });
});

test("ransom_note_scan keeps every note past the page, in the file the answer names", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    for (let i = 0; i < 7; i++) await writeFile(join(cwd, "work", "ev", `readme_${i}.txt`), `decrypt your files, your files are encrypted ${i}\n`);
    const scan = body<NoteScan>(await tool(NOTES, cwd, { root: "work/ev", limit: 3 }));
    assert.equal(scan.notes.length, 3);
    assert.equal(scan.candidate_count, 7);
    assert.equal(scan.pages.notes.truncated, true);
    assert.equal(scan.truncated, true);
    const rows = await allRows<NoteRow>(cwd, scan.pages.notes);
    assert.deepEqual(rows.map((r) => r.file.split("/").pop()), Array.from({ length: 7 }, (_, i) => `readme_${i}.txt`), "name order, every note");
  });
});

test("ransom_note_scan gives the earliest note time as an observation with its clock and its limits", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    const early = join(cwd, "work", "ev", "readme_a.txt");
    const late = join(cwd, "work", "ev", "readme_b.txt");
    await writeFile(early, "decrypt your files\n");
    await writeFile(late, "decrypt your files\n");
    const t0 = Date.UTC(2026, 1, 3, 4, 5, 6) / 1000;
    await utimes(early, t0 + 3600, t0 + 3600);
    await utimes(late, t0 + 7200, t0 + 7200);
    const out = await tool(NOTES, cwd, { root: "work/ev" });
    const scan = body<NoteScan>(out);
    assert.equal(scan.earliest_observed_note_mtime?.modified_utc, "2026-02-03T05:05:06Z");
    assert.match(scan.earliest_observed_note_mtime?.clock ?? "", /filesystem modification time as collected/);
    assert.match(scan.earliest_observed_note_mtime?.caveat ?? "", /not the (time|start)/);
    assert.doesNotMatch(out.stdout, /identifies the group|close to when the run started/);
  });
});

test("ransom_note_scan finishes on a hostile note and refuses a non-object argument without a traceback", async () => {
  // \b[\w.+-]+@ and \s*[:=-]?\s* are quadratic on a long run that nearly matches.
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "readme_dots.txt"), "a.".repeat(100_000));
    await writeFile(join(cwd, "work", "ev", "readme_spaces.txt"), "victim id" + " ".repeat(190_000) + "!");
    const started = Date.now();
    const scan = body<NoteScan>(await tool(NOTES, cwd, { root: "work/ev" }));
    assert.equal(scan.candidate_count, 2);
    assert.ok(Date.now() - started < 20_000, `took ${Date.now() - started} ms`);
    for (const bad of [[], "root", 7, null]) assert.match(refused(await tool(NOTES, cwd, bad)).error, /JSON object/);
  });
});

test("ransom_note_scan does not decode a binary file as text and says so", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    const blob = Buffer.concat([Buffer.from("MZ\x90\x00\x03\x00\x00\x00"), randomBytes(2000), Buffer.from(`Your personal ID: ${VICTIM_ID}`)]);
    await writeFile(join(cwd, "work", "ev", "readme_dropper.exe.txt"), blob);
    await writeFile(join(cwd, "work", "ev", "README.html"), `<html><body>Your files are encrypted. decrypt: ${ONION_V2}</body></html>`);
    const scan = body<NoteScan>(await tool(NOTES, cwd, { root: "work/ev" }));
    const byName = Object.fromEntries(scan.notes.map((n) => [n.file.split("/").pop(), n]));
    assert.equal(byName["readme_dropper.exe.txt"].format_hint, "binary");
    assert.equal(byName["readme_dropper.exe.txt"].class, "binary_not_scanned");
    assert.deepEqual(byName["readme_dropper.exe.txt"].indicator_counts, {});
    assert.equal(byName["README.html"].format_hint, "html");
    assert.equal(byName["README.html"].indicator_counts.onion, 1);
  });
});

test("ransom_note_scan goes on over a note that holds a byte that is not UTF-8, and keeps the bytes' offsets", async () => {
  // A stray byte in a URL: a lone surrogate cannot be written to a UTF-8 file as it is.
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "ev");
    await mkdir(dir, { recursive: true });
    const note = Buffer.concat([Buffer.from("decrypt your files\nportal http://exa"), Buffer.from([0xff]), Buffer.from(`mple.example/chat?k=${ACCESS_KEY}\nPay ${BTC_LEGACY}\n`)]);
    await writeFile(join(dir, "readme_stray.txt"), note);
    const outDir = join(cwd, "out");
    await mkdir(outDir);
    const out = await tool(NOTES, cwd, { root: "work/ev", limit: 1, write_values: true }, { JOB_ID: "j000004", OUT: outDir });
    const scan = body<NoteScan>(out);
    assert.equal(scan.candidate_count, 1);
    assert.equal(scan.notes[0].decode_errors, 1, "one byte that is not UTF-8");
    const rows = (await readFile(join(outDir, "ransom-note-values.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { kind: string; offset: number; value: string });
    const url = rows.find((r) => r.kind === "url");
    assert.ok(url);
    assert.equal(url.offset, note.indexOf("http://exa"));
    const btc = rows.find((r) => r.kind === "bitcoin");
    assert.equal(btc?.value, BTC_LEGACY);
    assert.equal(btc?.offset, note.indexOf(BTC_LEGACY), "an offset past the invalid byte is still a byte offset");
    assert.doesNotMatch(out.stdout, new RegExp(ACCESS_KEY));
  });
});

test("ransom_note_scan's pager and values file take a path with a lone surrogate, as a file name that is not UTF-8 gives", async () => {
  // A name from an old system reaches Python as lone surrogates (APFS refuses to create one, so the
  // components are driven directly): written as UTF-8 they raise, written as JSON escapes they do not.
  await withCwd(async (cwd) => {
    const probe = await runPySnippet(
      `import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("scan", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
os.chdir(sys.argv[2])
os.environ["AGENT_ID"] = "s1"
page = m.LosslessPage("t", ["k"], 1)
for i in range(3):
    page.add({"path": "dir/readme_\udcff\udcfe_%d.txt" % i})
done = page.finish()
rows = [json.loads(l) for l in open(done["all_results"], encoding="utf-8")]
print(json.dumps([done["matched"], len(rows), rows[2]["path"] == "dir/readme_\udcff\udcfe_2.txt"]))`,
      [NOTES, cwd],
      null,
    );
    assert.equal(probe.code, 0, probe.stderr);
    assert.deepEqual(JSON.parse(probe.stdout), [3, 3, true]);
  });
});

// A directory whose name carries "-unlistable" cannot be listed, wherever the suite runs (root lists a mode-000 one).
const LIST_SITE = String.raw`
import errno, os
_real_scandir = os.scandir
def _scandir(path="."):
    if "-unlistable" in os.fsdecode(path):
        raise OSError(errno.EIO, "Input/output error", os.fsdecode(path))
    return _real_scandir(path)
os.scandir = _scandir
`;

test("ransom_note_scan prints an identifier-shaped directory name nowhere: not in exceptions, rejected rows or exclusions either", async () => {
  // The shape check applied to the note's own name, and only in the notes rows: a directory named for the
  // victim was printed in the rows for what it could not list, what it rejected and what it excluded.
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    const id = VICTIM_ID;
    await mkdir(join(ev, `${id}-unlistable`), { recursive: true });
    await mkdir(join(ev, id), { recursive: true });
    await writeFile(join(ev, id, "HOW_TO_DECRYPT.txt"), Buffer.alloc(5000, 0x41));
    await mkdir(join(ev, `${id}-links`), { recursive: true });
    await mkdir(join(cwd, "outside"), { recursive: true });
    await writeFile(join(cwd, "outside", "target.txt"), "x");
    await symlink(join(cwd, "outside", "target.txt"), join(ev, `${id}-links`, "HOW_TO_DECRYPT.txt"));
    await mkdir(join(ev, `${id}-eio`), { recursive: true });
    await writeFile(join(ev, `${id}-eio`, "readme_unreadable.txt"), "text");
    await mkdir(join(ev, `${id}-skip`), { recursive: true });
    await mkdir(join(ev, `${id}-ok`), { recursive: true });
    await writeFile(join(ev, `${id}-ok`, "readme_ok.txt"), "decrypt your files, your files are encrypted\n");
    await mkdir(join(cwd, "pystub"), { recursive: true });
    await writeFile(join(cwd, "pystub", "sitecustomize.py"), EIO_SITE + LIST_SITE);
    const site = { PYTHONPATH: join(cwd, "pystub") };
    const args = { root: "work/ev", max_size: 1000, exclude_top_level_dirs: [`${id}-skip`] };
    // With a page of one row, the rest is in the files the answer names: they are held to the same rule.
    const narrow = await tool(NOTES, cwd, { ...args, limit: 1 }, site);
    assert.equal(body<NoteScan>(narrow).truncated, true);
    assertNoValue(await everythingPrinted(cwd, narrow.stdout));
    const out = await tool(NOTES, cwd, args, site);
    const scan = body<NoteScan & { exceptions: { path: string }[] }>(out);
    // Every kind of row is there, so that the absence below is of printed rows and not of missing ones.
    assert.equal(scan.rejected_count, 3, "oversized, linked and unreadable");
    assert.equal(scan.pages.exceptions.matched, 1, "the directory that could not be listed");
    assert.equal(scan.exclusions.length, 1);
    assert.equal(scan.candidate_count, 1);
    assert.ok(scan.paths_withheld >= 6, `paths_withheld is ${scan.paths_withheld}`);
    assertNoValue(await everythingPrinted(cwd, out.stdout));
    assert.ok(!out.stdout.includes(`${id}-skip`) && !out.stdout.includes("-unlistable"), "an id-shaped directory name is printed");
    const printedPaths = [...scan.rejected, ...scan.exceptions, ...scan.exclusions].map((r) => r.path).concat(scan.notes.map((n) => n.file));
    assert.equal(printedPaths.length, 6);
    for (const p of printedPaths) assert.match(p, /^work\/ev\/<identifier-shaped name withheld>(\/|$)/, p);
  });
});

test("ransom_note_scan prints no digest of a note that is only an identifier, or only one indicator value, or is too short to hide one", async () => {
  // sha256 of a note that is nothing but a 20-character identifier is a digest of the identifier.
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    const long = `http://${ONION_V3}/chat?access-key=${ACCESS_KEY}&pad=${"x".repeat(150)}`;
    const files: Record<string, string> = {
      "README.txt": VICTIM_ID,
      "README_short.txt": `Your personal ID: ${VICTIM_ID}\n`,
      "README_url.txt": `${long}\n`,
      "README_full.txt": NOTE_TEXT,
    };
    for (const [n, t] of Object.entries(files)) await writeFile(join(ev, n), t);
    const out = await tool(NOTES, cwd, { root: "work/ev" });
    const scan = body<NoteScan>(out);
    const printed = await everythingPrinted(cwd, out.stdout);
    for (const t of [VICTIM_ID, `${VICTIM_ID}\n`, files["README_short.txt"], files["README_url.txt"], long]) {
      assert.ok(!printed.includes(createHash("sha256").update(t).digest("hex")), `the digest of ${JSON.stringify(t.slice(0, 24))} is printed`);
    }
    const by = Object.fromEntries(scan.notes.map((n) => [n.file.split("/").pop() ?? "", n]));
    for (const n of ["README.txt", "README_short.txt", "README_url.txt"]) {
      assert.equal(by[n].sha256, null, `${n}: the whole-file digest is withheld`);
      assert.match((by[n] as NoteRow & { sha256_withheld?: string }).sha256_withheld ?? "", /shorter than 128 bytes|single token or indicator value/);
    }
    assert.match(String(by["README_full.txt"].sha256), /^[0-9a-f]{64}$/, "an ordinary note keeps its digest");
    assert.equal(scan.distinct_note_contents.filter((d) => d.sha256 === null).length, 3);
  });
});

test("ransom_note_scan's manifest says what it does not locate: an unlabelled token, and a digest it withholds", async () => {
  const manifest = JSON.parse(await readFile(join(ROOT, "packs", "ransomware-response", "tools", "ransom_note_scan", "manifest.json"), "utf8")) as { description: string };
  assert.match(manifest.description, /unlabelled/);
  assert.match(manifest.description, /shorter than 128 bytes/);
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "README.txt"), `decrypt your files; Token ${createHash("sha256").update("t").digest("hex")}\n`);
    const scan = body<NoteScan>(await tool(NOTES, cwd, { root: "work/ev" }));
    assert.deepEqual(scan.notes[0].indicator_counts, {}, "a long hex token with no label is neither located nor counted");
  });
});

test("a note a permissions refusal keeps from being read is rejected with its reason, where the user is not root", async (t) => {
  if (process.getuid?.() === 0) return t.skip("root reads a mode-000 file; the read failure is covered by the EIO case");
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    await writeFile(join(ev, "readme_locked.txt"), "decrypt your files");
    await chmod(join(ev, "readme_locked.txt"), 0o000);
    try {
      const notes = body<NoteScan>(await tool(NOTES, cwd, { root: "work/ev" }));
      assert.equal(notes.rejected_count, 1);
      assert.match(notes.rejected[0].reason, /could not be read/);
    } finally {
      await chmod(join(ev, "readme_locked.txt"), 0o600);
    }
  });
});
