/**
 * A release's witnesses (scripts/release-witness.ts): an RFC 3161 token
 * over its signature, checked against the authority's CA and, obtained
 * later, dated from then; and its digest line mirrored to a command (the
 * receipt kept whole), a directory another custodian keeps (a file per
 * release, never written over) or a printed line with a QR-ready string.
 * A run's --anchor-mirror is used at every release. Nothing leaves the
 * host: the authority is a local test server.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { draftRelease, runContext } from "../scripts/release.ts";
import { mirrorRelease, timestampRelease } from "../scripts/release-witness.ts";
import { readReleases, runLayout, verifyReleases } from "../scripts/release-record.ts";
import { custodyAnchorPath } from "../scripts/custody.ts";
import { readTimestampResponse, timestampRequest } from "../scripts/custody-checks.ts";
import { reviewsPath } from "../scripts/review.ts";
import { cleanUp, opensslTs, script, stoppedRun, testPki, tsaServer, type StoppedRun } from "./release-fixture.ts";

after(cleanUp);
const quiet = () => undefined;
const ctxOf = (r: StoppedRun) => runContext(r.root, { run: r.id, runsDir: r.runs });
const layout = (r: StoppedRun) => runLayout(r.root, reviewsPath(r.runs, r.id), custodyAnchorPath(r.root));

test("a token obtained after the release dates its proof of existence from the token, and says so; a second one is refused", async () => {
  const r = await stoppedRun();
  await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  const tsa = await tsaServer();
  try {
    const dir = readReleases(r.root)[0].dir;
    const t = await timestampRelease(dir, { url: tsa.url, ca: null, releaseAt: "2026-09-20T00:00:00.000Z" });
    assert.ok(t.ok, JSON.stringify(t));
    if (!t.ok) return;
    assert.equal(t.verified, null);
    assert.match(t.note, /imprint only \(no CA named\); obtained after the release: the proof of existence dates from the token/);
    const rec = JSON.parse(readFileSync(join(dir, "timestamp.json"), "utf8")) as { gen_time: string; note: string; imprint_of: { file: string }; signature: { verified: null; detail: string } };
    assert.equal(rec.gen_time, "2026-09-27T12:00:00Z");
    assert.equal(rec.imprint_of.file, "release.json.sig");
    assert.match(rec.note, /after the release was sealed .*: the release's proof of existence dates from the token's time \(2026-09-27T12:00:00Z\), not from the release's own/);
    assert.match(rec.signature.detail, /imprint only/);
    const again = await timestampRelease(dir, { url: tsa.url, ca: null, releaseAt: "2026-09-20T00:00:00.000Z" });
    assert.ok(!again.ok && /timestamped already/.test(again.why));
    const v = await verifyReleases(layout(r));
    assert.equal(v.ok, true, v.lines.join("\n"));
    assert.match(v.lines[0], /timestamped 2026-09-27T12:00:00Z \(imprint only: give --tsa-ca FILE to check the authority's signature\)/);
  } finally {
    tsa.close();
  }
});

test("a token is checked against the authority's CA: verified by the one that issued it, and fails against another", { skip: !opensslTs() && "no openssl ts on this host" }, async () => {
  const r = await stoppedRun();
  await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  const pki = await testPki();
  const tsa = await tsaServer(pki.reply);
  try {
    const rel = readReleases(r.root)[0];
    const t = await timestampRelease(rel.dir, { url: tsa.url, ca: pki.ca, releaseAt: rel.record?.at ?? "" });
    assert.ok(t.ok && t.verified === true, JSON.stringify(t));
    assert.equal(JSON.parse(readFileSync(join(rel.dir, "timestamp.json"), "utf8")).signature.verified, true);
    let v = await verifyReleases(layout(r), { tsaCa: pki.ca });
    assert.equal(v.ok, true, v.lines.join("\n"));
    assert.match(v.lines[0], /\(token verified against /);
    v = await verifyReleases(layout(r), { tsaCa: pki.otherCa });
    assert.equal(v.ok, false);
    assert.match(v.lines[0], /its timestamp token DOES NOT VERIFY against /);
  } finally {
    tsa.close();
  }
});

test("a timestamp request is a minimal DER, whatever its nonce: one that starts with zero bytes is not refused by the authority", { skip: !opensslTs() && "no openssl ts on this host" }, async () => {
  const pki = await testPki();
  const digest = "ab".repeat(32);
  const nonces = ["0012010203040506", "0000000000000001", "0000000000000000", "00ff010203040506", "7b4b77533d9e7200", "ff00000000000000", "003000e2ebcdaca1"];
  for (const hex of nonces) {
    const read = readTimestampResponse(pki.reply(timestampRequest(digest, Buffer.from(hex, "hex"))), digest);
    assert.ok(read.granted && read.imprint, `nonce ${hex}: status ${read.status}`);
  }
});

test("a release's digest line is mirrored: to a command that receives it on stdin, to a directory a file per release, never written over, and as a printed line with a QR-ready string", async () => {
  const r = await stoppedRun();
  await draftRelease(ctxOf(r), { home: r.home, say: quiet });
  const rel = readReleases(r.root)[0];
  // A command: the line on stdin, the release's files named in its environment; what it prints is the receipt, whole.
  const witness = await script("witness", 'read -r line; printf \'{"received":"%s","json":"%s"}\\n\' "$line" "$(basename "$DFS_RELEASE_JSON")"');
  const m = mirrorRelease(r.root, rel.dir, `cmd:${witness.path}`);
  assert.ok(m.ok, JSON.stringify(m));
  const receipt = JSON.parse(readFileSync(join(rel.dir, "mirror-1.json"), "utf8")) as { kind: string; exit: number; stdout: string; line: string };
  assert.equal(receipt.kind, "command");
  assert.equal(receipt.exit, 0);
  assert.equal(JSON.parse(receipt.stdout).received, receipt.line);
  assert.match(receipt.line, new RegExp(`^dfirswarm-release run=s4v4 v=0 state=draft sha256=${rel.sha256} `));
  assert.equal(JSON.parse(receipt.stdout).json, "release.json");
  // A command that fails: said, with its output kept.
  const failing = mirrorRelease(r.root, rel.dir, "cmd:echo refused >&2; exit 7");
  assert.ok(!failing.ok && /exited 7/.test(failing.why));
  assert.equal(JSON.parse(readFileSync(join(rel.dir, "mirror-2.json"), "utf8")).stderr, "refused\n");
  // A directory: a file per release, and never one written over.
  const store = await mkdtemp(join(tmpdir(), "release-mirror-"));
  const d = mirrorRelease(r.root, rel.dir, `dir:${store}`);
  assert.ok(d.ok, JSON.stringify(d));
  const [file] = readdirSync(store);
  assert.match(file, /^s4v4-v0-[0-9a-f]{12}\.txt$/);
  assert.match(readFileSync(join(store, file), "utf8"), /^dfirswarm-release run=s4v4 v=0 .*\nDFSR1:S4V4:V0:[0-9A-F]{64}\n$/);
  const twice = mirrorRelease(r.root, rel.dir, `dir:${store}`);
  assert.ok(!twice.ok && /nothing there is written over/.test(twice.why));
  assert.ok(!mirrorRelease(r.root, rel.dir, `dir:${join(store, "absent")}`).ok);
  // Printed for the case file: the line and a string of QR alphanumeric characters only.
  const p = mirrorRelease(r.root, rel.dir, "print");
  assert.ok(p.ok);
  const card = readFileSync(join(rel.dir, "case-file.txt"), "utf8");
  const qr = /QR-ready \(alphanumeric\): (\S+)/.exec(card)?.[1] ?? "";
  assert.match(qr, /^DFSR1:S4V4:V0:[0-9A-F]{64}$/);
  assert.equal(qr.split(":")[3].toLowerCase(), rel.sha256);
  assert.ok(!mirrorRelease(r.root, rel.dir, "ftp://nowhere").ok);
  // The sidecars are beside the release, never in it: it still verifies.
  const v = await verifyReleases(layout(r));
  assert.equal(v.ok, true, v.lines.join("\n"));
});

test("a run's --anchor-mirror is used at every release, and a timestamp authority it was set up with dates the draft", async () => {
  const store = await mkdtemp(join(tmpdir(), "release-mirror-"));
  const tsa = await tsaServer();
  try {
    const r = await stoppedRun({ registry: { anchor_mirror: `dir:${store}`, custody_seal: { timestamp_url: tsa.url } } });
    const said: string[] = [];
    const d = await draftRelease(ctxOf(r), { home: r.home, say: (s) => said.push(s) });
    assert.ok(d.written);
    assert.equal(readdirSync(store).length, 1, said.join("\n"));
    assert.ok(existsSync(join(d.written?.dir ?? "", "release.json.sig.tsr")));
    assert.match(said.join("\n"), /Timestamp: {4}token from http:\/\/127\.0\.0\.1:\d+\/tsa, 2026-09-27T12:00:00Z, imprint only/);
    assert.match(said.join("\n"), /Mirror: {7}the digest line is in /);
  } finally {
    tsa.close();
  }
});
