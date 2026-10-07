/**
 * network-forensics: four tools print names, paths, URLs and messages that can echo an identifier-shaped string
 * (a token, an API key, a session id, a JWT, user-info in a URL). They must withhold the same strings, so each
 * carries the same block of code between the markers below; this suite holds the copies equal and holds the
 * block to a table of strings written from the shapes the rule names (never from a tool's output).
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { EXTRACT, LOGS, RECIPE, SURICATA, ZEEK } from "./pack-network-harness.ts";
import { runPySnippet } from "./tool-library-harness.ts";
import type { Json } from "./pack-network-harness.ts";

const BEGIN = "# BEGIN SHARED WITHHOLDING";
const END = "# END SHARED WITHHOLDING";

async function block(path: string): Promise<string> {
  const text = await readFile(path, "utf8");
  const start = text.indexOf(BEGIN);
  const end = text.indexOf(END);
  assert.ok(start >= 0 && end > start, `${path} carries the shared block`);
  assert.equal(text.indexOf(BEGIN, start + 1), -1, "once");
  return text.slice(start, end + END.length);
}

test("the four tools carry the same withholding block, byte for byte", async () => {
  const blocks = await Promise.all([EXTRACT, ZEEK, SURICATA, LOGS].map(block));
  for (const other of blocks.slice(1)) assert.equal(other, blocks[0]);
  assert.ok(blocks[0].length > 2000);
});

async function processBlock(path: string): Promise<string> {
  const text = await readFile(path, "utf8");
  const start = text.indexOf("# BEGIN SHARED PROCESS");
  const end = text.indexOf("# END SHARED PROCESS");
  assert.ok(start >= 0 && end > start, `${path} carries the shared process block`);
  return text.slice(start, end + "# END SHARED PROCESS".length);
}

test("the three engine tools and the recipe carry the same process block, byte for byte, and none starts a program in a session of its own", async () => {
  const blocks = await Promise.all([EXTRACT, ZEEK, SURICATA, RECIPE].map(processBlock));
  for (const other of blocks.slice(1)) assert.equal(other, blocks[0]);
  for (const path of [EXTRACT, ZEEK, SURICATA, RECIPE]) {
    const text = await readFile(path, "utf8");
    assert.doesNotMatch(text.replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, ""), /start_new_session|setsid|preexec_fn=os\.setsid|process_group/, `${path} starts a program outside the tool's process group`);
    assert.doesNotMatch(text, /threading/, `${path} uses a thread (preexec_fn and threads do not mix)`);
  }
});

const CODE = `
import json, re, sys
data = json.load(sys.stdin)
ns = {"re": re}
exec(data["block"], ns)
out = {"shaped": {s: ns["token_shaped"](s) for s in data["names"]},
       "urls": {u: ns["redact_url"](u) for u in data["urls"]},
       "scrub": {t: ns["scrub"](t) for t in data["text"]},
       "cells": {c: ns["cell"](c) for c in data["cells"]}}
print(json.dumps(out))
`;

const TOKEN = "Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK";

test("the block withholds tokens, keys and user-info and leaves names, dates and versions alone", async () => {
  const names = {
    [TOKEN]: true,
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789": true,
    "AKIAIOSFODNN7EXAMPLE": true,
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc": true,
    "d41d8cd98f00b204e9800998ecf8427e": true,
    "3f2504e0-4f89-11d3-9a0c-0305e82c3301": true,
    "dGhpcyBpcyBhIHNlY3JldCB0b2tlbiB2YWx1ZQ==": true,
    "session_id_a1b2c3d4e5f6a7b8c9d0": true,
    "xKjHgFdSaPoIuYtReWqAzSxDcVfBgNhM": true,
    "dXNlcjpwYXNzd29yZA==": true,
    "invoice.pdf": false,
    "/Users/Halil/Library/CloudStorage/Dropbox/PersonalProjects/dfirswarm/ExampleApp/MainWindow": false,
    "/api/v1/users/Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK/profile": true,
    "payload.exe": false,
    "Quarterly_Financial_Report_2024.pdf": false,
    "IncidentResponseReportFinalV2.docx": false,
    "capture-2023-11-14T223045Z.pcap": false,
    "backup_2024-01-05T101500Z_host01_full.tar.gz": false,
    "IMG_20231114_223045.jpg": false,
    "setup_x64_installer_v1.2.3.msi": false,
    "the_quick_brown_fox_jumps_over_the_lazy_dog_2024_01_01.txt": false,
    "SuperSecretToken987": false,
    [`${"T".repeat(4096)}`]: false,
  };
  const urls = [
    `http://alice:PassWord1234@files.example.test/get/${TOKEN}?token=SuperSecretToken987&n=2#frag`,
    "/login?user=bob&pw=hunter2",
    "/plain/path/file.txt",
    "ftp://carol:pw@host/",
    "/k/x3%2B5uZ7Zl9w2kQv%2F8nV4RbT2sLq0PaX1yE6cJ7mNfA8%3D/z",
    "//admin:pw@host/p",
    `/api/v1/users/${TOKEN}/profile?x=1`,
  ];
  const B64 = "x3+5uZ7Zl9w2kQv/8nV4RbT2sLq0PaX1yE6cJ7mNfA8=";
  const AWS = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
  const text = [`error opening ${TOKEN}.bin at http://u:p@h/x`, "nothing secret here", "AKIAIOSFODNN7EXAMPLE was used",
    `key ${B64}`, `secret=${AWS} end`, "//admin:S3cr3tPass@host/x", "proxy=admin:S3cr3tPass@10.0.0.1:3128",
    "Authorization: Basic dXNlcjpwYXNzd29yZA== ok", "Authorization: Bearer abcDEF123456xyz", "mailto:john@example.com and john@example.com",
    "ja3=e7d705a3286e19ea42f587b344ee6865", "x3%2B5uZ7Zl9w2kQv%2F8nV4RbT2sLq0PaX1yE6cJ7mNfA8%3D"];
  const cells = ["a\tb", "line\nbreak", "back\\slash", "lone\udc80surrogate", "high\ud800", "bell\u0007"];
  const run = await runPySnippet(CODE, [], { block: await block(EXTRACT), names: Object.keys(names), urls, text, cells });
  assert.equal(run.code, 0, run.stderr);
  const got: Json = JSON.parse(run.stdout);
  for (const [name, want] of Object.entries(names)) assert.equal(got.shaped[name], want, `${name.slice(0, 40)} should${want ? "" : " not"} be withheld`);
  assert.equal(got.urls[urls[0]], "http://<userinfo withheld 18 characters>@files.example.test/get/<token-shaped text withheld 30 characters>?token=<withheld 19 characters>&n=<withheld 1 characters>#<withheld 4 characters>");
  assert.equal(got.urls[urls[1]], "/login?user=<withheld 3 characters>&pw=<withheld 7 characters>");
  assert.equal(got.urls[urls[2]], "/plain/path/file.txt");
  assert.equal(got.urls[urls[3]], "ftp://<userinfo withheld 8 characters>@host/");
  assert.equal(got.urls[urls[4]], "/k/<token-shaped text withheld 50 characters>/z", "the head of a token with encoded slashes is not printed");
  assert.equal(got.urls[urls[5]], "//<userinfo withheld 8 characters>@host/p");
  assert.equal(got.urls[urls[6]], "/api/v1/users/<token-shaped text withheld 30 characters>/profile?x=<withheld 1 characters>", "its neighbours stay");
  assert.equal(got.scrub[text[0]], "error opening <token-shaped text withheld 30 characters>.bin at http://<userinfo withheld 3 characters>@h/x");
  assert.equal(got.scrub[text[1]], text[1]);
  assert.equal(got.scrub[text[2]], "<token-shaped text withheld 20 characters> was used");
  // A base64 token holds `/`: none of its head is printed (the standard allows four characters at most), and an AWS-style secret with two `/` is caught whole.
  assert.equal(got.scrub[text[3]], "key <token-shaped text withheld 44 characters>");
  assert.equal(got.scrub[text[4]], "secret=<token-shaped text withheld 40 characters> end");
  assert.equal(got.scrub[text[11]], "<token-shaped text withheld 50 characters>");
  // User-info without a scheme, and credentials in a header.
  assert.equal(got.scrub[text[5]], "//<userinfo withheld 16 characters>@host/x");
  assert.equal(got.scrub[text[6]], "proxy=<userinfo withheld 16 characters>@10.0.0.1:3128");
  assert.equal(got.scrub[text[7]], "Authorization: <token-shaped text withheld 26 characters> ok");
  assert.equal(got.scrub[text[8]], "Authorization: <token-shaped text withheld 22 characters>");
  assert.equal(got.scrub[text[9]], text[9], "an address is not user-info");
  assert.equal(got.scrub[text[10]], "ja3=<token-shaped text withheld 32 characters>", "the name of the key stays");
  // A byte that was not UTF-8 reaches Python as a lone surrogate; a cell writes it as \xNN and never raises.
  assert.equal(got.cells[cells[0]], "a\\tb");
  assert.equal(got.cells[cells[1]], "line\\nbreak");
  assert.equal(got.cells[cells[2]], "back\\\\slash");
  assert.equal(got.cells[cells[3]], "lone\\x80surrogate");
  assert.equal(got.cells[cells[4]], "high\\ud800");
  assert.equal(got.cells[cells[5]], "bell\\x07");
});
