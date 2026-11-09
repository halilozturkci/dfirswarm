/**
 * doc_structure, the optional second reading (`second_reading: true`): qpdf for a PDF encryption dictionary and msoffcrypto-tool for an
 * Office encryption record that this reader records as structure and does not interpret. Against stand-ins that print what the real
 * programs printed (qpdf 11.3.0 and msoffcrypto-tool 6.0.0, Debian 12's snapshot), and against the real programs where they are installed.
 *
 * What these cases hold: nothing is started unless the call asks and the first reading left an unsupported variant; the second reading is
 * given beside the first and the first is unchanged by it; no password or key is passed to either program; the line in which qpdf prints a
 * password it recovered never reaches the answer; a program that is missing, ambiguous, cut by the cap or ended by a stop signal is said as
 * such and is never a reading; and the file's own words never reach the answer through the programs' output.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, symlink } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_STRUCTURE, body, gone, pidFile, put, startDetached, stub, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { buildCfb, buildPdf } from "./pack-re-doc-fixtures.ts";
import type { PdfObj } from "./pack-re-doc-fixtures.ts";

const CATALOG: PdfObj = { num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>" };
const PAGES: PdfObj = { num: 2, body: "<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>" };
const PAGE: PdfObj = { num: 3, body: "<< /Type /Page /Parent 2 0 R >>" };
const pdfWith = (encrypt: string): Buffer => buildPdf([CATALOG, PAGES, PAGE, { num: 6, body: encrypt }], "/Root 1 0 R /Encrypt 6 0 R").file;
const STANDARD = pdfWith("<< /Filter /Standard /V 4 /R 4 /Length 128 /P -3904 /O <00> /U <00> /CF << /StdCF << /CFM /AESV2 /Length 16 >> >> /StmF /StdCF /StrF /StdCF >>");
const UNSUPPORTED_FILTER = pdfWith("<< /Filter /Acme#20Security /V 4 /R 4 /Length 128 /P -3904 /O <00> /U <00> >>");
const UNSUPPORTED_REVISION = pdfWith("<< /Filter /Standard /V 7 /R 9 /Length 256 /P -3904 /O <00> /U <00> >>");

/** An OLE compound file that holds an encrypted OOXML package whose EncryptionInfo is the extensible version (3.3), which neither reader interprets. */
const word = (n: number): Buffer => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const dword = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const OFFICE_EXTENSIBLE = buildCfb([
  { name: "EncryptionInfo", data: Buffer.concat([word(3), word(3), dword(0x40), Buffer.alloc(24)]) },
  { name: "EncryptedPackage", data: Buffer.concat([Buffer.alloc(8), Buffer.alloc(32, 7)]) },
]);

const QPDF_TEXT = [
  "R = 6", "P = -3904", "User password = USERPW-CANARY-7731", "extract for accessibility: allowed", "extract for any purpose: allowed", "print low resolution: allowed",
  "print high resolution: allowed", "modify document assembly: not allowed", "modify forms: not allowed", "modify annotations: not allowed", "modify other: not allowed",
  "modify anything: not allowed", "stream encryption method: AESv3", "string encryption method: AESv3", "file encryption method: AESv3",
];

/** A stand-in for qpdf: records its arguments, then prints `body` (one line per item; `$P` is the file name it was given). */
async function fakeQpdf(cwd: string, bin: string, lines: string[], exit = 0): Promise<void> {
  const text = lines.map((l) => `echo '${l.replace(/'/g, "'\\''")}'`).join("\n");
  await stub(bin, "qpdf", `if [ "$1" = "--version" ]; then echo "qpdf version 11.3.0"; exit 0; fi
echo "$@" >> "${cwd}/qpdf.argv"
P="$2"
${text.replace(/\$P/g, "$P")}
exit ${exit}`);
}

async function run(cwd: string, bin: string, name: string, data: Buffer, args: Record<string, unknown> = {}, env: Record<string, string> = {}): Promise<{ a: Json; text: string }> {
  await put(cwd, `work/${name}`, data);
  const r = await tool(DOC_STRUCTURE, cwd, { path: `work/${name}`, ...args }, env, bin);
  return { a: body(r), text: r.stdout };
}

const argvLog = async (cwd: string): Promise<string> => readFile(join(cwd, "qpdf.argv"), "utf8").catch(() => "");

test("without second_reading nothing is started and the answer has no second_reading; with it, a standard handler is not applicable and nothing is started either", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeQpdf(cwd, bin, QPDF_TEXT);
    const plain = await run(cwd, bin, "unsupported.pdf", UNSUPPORTED_FILTER);
    assert.equal(plain.a.second_reading, undefined);
    const std = await run(cwd, bin, "standard.pdf", STANDARD, { second_reading: true });
    assert.equal(std.a.second_reading.requested, true);
    assert.equal(std.a.second_reading.applicable, false);
    assert.deepEqual(std.a.second_reading.variants, []);
    assert.equal(await argvLog(cwd), "", "qpdf was started for a file the first reading supports, or without the call asking");
  });
});

test("a PDF handler the reader does not interpret gets a second reading by qpdf: no password is passed, the first reading is unchanged, the recovered-password line is never kept", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeQpdf(cwd, bin, QPDF_TEXT);
    const first = await run(cwd, bin, "a.pdf", UNSUPPORTED_FILTER);
    const second = await run(cwd, bin, "a.pdf", UNSUPPORTED_FILTER, { second_reading: true });
    assert.deepEqual(second.a.encryption, first.a.encryption, "the first reading is the same with and without the second");
    const sr = second.a.second_reading;
    assert.equal(sr.applicable, true);
    assert.equal(sr.status, "read");
    assert.equal(sr.program, "qpdf");
    assert.equal(sr.replaces_nothing, true);
    assert.deepEqual(sr.variants, [{ where: "the PDF encryption dictionary", codes: ["handler_not_standard"] }]);
    assert.equal(sr.result.r, 6);
    assert.equal(sr.result.p, -3904);
    assert.equal(sr.result.permissions["print low resolution"], true);
    assert.equal(sr.result.permissions["modify anything"], false);
    assert.equal(sr.result.methods.stream, "AESv3");
    assert.match(sr.keys, /empty password on its own/);
    assert.doesNotMatch(second.text, /USERPW-CANARY/, "the password qpdf printed reached the answer");
    const calls = (await argvLog(cwd)).trim().split("\n");
    assert.equal(calls.length, 1, "qpdf is started once for the reading (the --version call is not logged)");
    assert.match(calls[0]!, /^--show-encryption \//, "the arguments are the one mode and the absolute file name: no password, no -password=");
    assert.doesNotMatch(calls[0]!, /password|--decrypt|--requires-password/i);
  });
});

test("a version or revision outside the Standard handler's is an unsupported variant; a qpdf that does not support it says so and that is the reading", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "qpdf", `if [ "$1" = "--version" ]; then echo "qpdf version 11.3.0"; exit 0; fi
echo "qpdf: $2 (encryption dictionary, offset 9): Unsupported /R or /V in encryption dictionary; R = 9 (max 6), V = 7 (max 5)" >&2
exit 2`);
    const r = await run(cwd, bin, "b.pdf", UNSUPPORTED_REVISION, { second_reading: true });
    const sr = r.a.second_reading;
    assert.deepEqual(sr.variants[0].codes, ["version_not_read", "revision_not_read"]);
    assert.equal(sr.status, "unsupported_by_the_program");
    assert.equal(sr.result.program_says, "unsupported_revision_or_version");
    assert.deepEqual(sr.result.unsupported_values, { r: 9, r_max: 6, v: 7, v_max: 5 });
  });
});

test("a qpdf line printed twice, a qpdf that fails, prints nothing readable, floods, is missing or is ended by the call is not a reading", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeQpdf(cwd, bin, [...QPDF_TEXT, "R = 4"]);
    const twice = await run(cwd, bin, "c.pdf", UNSUPPORTED_FILTER, { second_reading: true });
    assert.equal(twice.a.second_reading.status, "ambiguous");
    assert.notEqual(twice.a.status, "complete");
    await fakeQpdf(cwd, bin, ["something qpdf never prints"], 2);
    const odd = await run(cwd, bin, "c.pdf", UNSUPPORTED_FILTER, { second_reading: true });
    assert.equal(odd.a.second_reading.status, "failed");
    assert.notEqual(odd.a.second_reading.status, "read");
    await stub(bin, "qpdf", `if [ "$1" = "--version" ]; then echo "qpdf version 11.3.0"; exit 0; fi
yes 'R = 6'`);
    const flood = await run(cwd, bin, "c.pdf", UNSUPPORTED_FILTER, { second_reading: true });
    assert.equal(flood.a.second_reading.status, "not_finished");
    assert.ok(flood.text.length < 200_000, "the flood reached the answer");
  });
  await withCwd(async (cwd, bin) => {
    // a PATH that holds the interpreter and nothing else: the call is answered and says the program is not installed
    const only = join(cwd, "only");
    await mkdir(only, { recursive: true });
    await symlink(spawnSync("sh", ["-c", "command -v python3"]).stdout.toString().trim(), join(only, "python3"));
    const r = await run(cwd, only, "d.pdf", UNSUPPORTED_FILTER, { second_reading: true }, { PATH: only });
    assert.equal(r.a.second_reading.status, "not_installed");
    assert.match(r.a.second_reading.basis, /qpdf is not installed/);
  });
});

test("a file name with a line break gets no second reading, and hostile parameters are refused as JSON", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeQpdf(cwd, bin, QPDF_TEXT);
    await put(cwd, "work/e\nf.pdf", UNSUPPORTED_FILTER);
    const named = body(await tool(DOC_STRUCTURE, cwd, { path: "work/e\nf.pdf", second_reading: true }, {}, bin));
    assert.equal(named.second_reading.status, "not_attempted");
    assert.equal(await argvLog(cwd), "");
    for (const bad of ["yes", 1, null, [], {}]) {
      await put(cwd, "work/g.pdf", UNSUPPORTED_FILTER);
      const r = await tool(DOC_STRUCTURE, cwd, { path: "work/g.pdf", second_reading: bad }, {}, bin);
      assert.doesNotMatch(r.stderr, /Traceback/);
      assert.equal(JSON.parse(r.stdout).status, "failed");
    }
  });
});

test("an Office encryption record the reader does not interpret gets msoffcrypto-tool asked only whether the file is encrypted: no key, nothing of its output but fixed words", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "msoffcrypto-tool", `echo "$@" >> "${cwd}/mso.argv"
echo "Version: 6.0.0"
echo "OOXMLFile.type: extensibleCANARY5521"
echo "Traceback (most recent call last):"
echo "  File \\"x.py\\", line 1, in main"
echo "msoffcrypto.exceptions.DecryptionError: Unsupported EncryptionInfo version (Extensible Encryption)"
exit 1`);
    const r = await run(cwd, bin, "h.doc", OFFICE_EXTENSIBLE, { second_reading: true });
    const sr = r.a.second_reading;
    assert.equal(sr.applicable, true);
    assert.equal(sr.program, "msoffcrypto-tool");
    assert.equal(sr.variants[0].codes[0], "scheme_not_read");
    assert.equal(sr.status, "unsupported_by_the_program");
    assert.equal(sr.result.error, "unsupported_extensible_encryption");
    assert.equal(sr.result.type, "other", "a type word that is not one of the fixed set is not printed");
    assert.doesNotMatch(r.text, /CANARY5521/);
    const calls = (await readFile(join(cwd, "mso.argv"), "utf8")).trim().split("\n");
    assert.equal(calls.length, 1);
    assert.match(calls[0]!, /^-t -v \//, "only the is-it-encrypted mode: no -p, no -k, no output file");
    assert.doesNotMatch(calls[0]!, /-p |-k |--password|--key/);
  });
});

test("SIGTERM during the second reading ends the program and what it started, and answers once: failed, exit 143", async () => {
  await withCwd(async (cwd, bin) => {
    await mkdir(join(cwd, "pids"), { recursive: true });
    await stub(bin, "qpdf", `if [ "$1" = "--version" ]; then echo "qpdf version 11.3.0"; exit 0; fi
echo $$ > "${cwd}/pids/qpdf.pid"
sleep 60`);
    await put(cwd, "work/i.pdf", UNSUPPORTED_FILTER);
    const r = startDetached(DOC_STRUCTURE, cwd, { path: "work/i.pdf", second_reading: true }, {}, bin);
    try {
      const pid = await pidFile(join(cwd, "pids", "qpdf.pid"));
      r.signal("SIGTERM");
      r.signal("SIGTERM");
      assert.equal(await r.closed, 143);
      const word = JSON.parse(r.stdout()) as Json;
      assert.equal(word.status, "failed");
      assert.ok(await gone(pid, 10_000), "the program of the second reading outlived the tool");
    } finally {
      try { r.signal("SIGKILL"); } catch { /* gone */ }
    }
  });
});

test("qpdf's user and owner lines are both read; a reading is read only when the program exited 0; an ambiguous reading has no result", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeQpdf(cwd, bin, ["Supplied password is user password", "Supplied password is owner password", ...QPDF_TEXT]);
    const both = await run(cwd, bin, "j.pdf", UNSUPPORTED_FILTER, { second_reading: true });
    assert.equal(both.a.second_reading.status, "read");
    assert.equal(both.a.second_reading.result.opened_with, "user_and_owner");
    await fakeQpdf(cwd, bin, QPDF_TEXT, 2);
    const failed = await run(cwd, bin, "j.pdf", UNSUPPORTED_FILTER, { second_reading: true });
    assert.equal(failed.a.second_reading.status, "failed", "fields printed by a program that exited 2 are not a reading");
    assert.match(failed.a.second_reading.basis, /exit 2/);
    await fakeQpdf(cwd, bin, [...QPDF_TEXT, "Supplied password is user password", "Supplied password is user password"]);
    const twice = await run(cwd, bin, "j.pdf", UNSUPPORTED_FILTER, { second_reading: true });
    assert.equal(twice.a.second_reading.status, "ambiguous");
    assert.equal(twice.a.second_reading.result, undefined, "an ambiguous reading's fields are not given");
  });
});

test("a program that ignores TERM, INT and HUP is ended with the tool on SIGTERM, SIGINT and SIGHUP", async () => {
  for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
    await withCwd(async (cwd, bin) => {
      await mkdir(join(cwd, "pids"), { recursive: true });
      await stub(bin, "qpdf", `if [ "$1" = "--version" ]; then echo "qpdf version 11.3.0"; exit 0; fi
trap '' TERM INT HUP
echo $$ > "${cwd}/pids/qpdf.pid"
while true; do sleep 1; done`);
      await put(cwd, "work/k.pdf", UNSUPPORTED_FILTER);
      const r = startDetached(DOC_STRUCTURE, cwd, { path: "work/k.pdf", second_reading: true }, {}, bin);
      try {
        const pid = await pidFile(join(cwd, "pids", "qpdf.pid"));
        r.signal(sig);
        const code = await r.closed;
        assert.equal(code, 128 + { SIGTERM: 15, SIGINT: 2, SIGHUP: 1 }[sig], sig);
        assert.equal((JSON.parse(r.stdout()) as Json).status, "failed");
        assert.ok(await gone(pid, 10_000), `${sig}: the program of the second reading outlived the tool`);
      } finally {
        try { r.signal("SIGKILL"); } catch { /* gone */ }
      }
    });
  }
});

const have = (name: string): boolean => spawnSync("sh", ["-c", `command -v ${name}`]).status === 0;

test("with the real qpdf: an encryption filter qpdf does not support is said by qpdf, and a standard file it opens with the empty password says so", { skip: have("qpdf") ? false : "qpdf is not installed on this machine" }, async () => {
  await withCwd(async (cwd, bin) => {
    const r = await run(cwd, bin, "real.pdf", UNSUPPORTED_FILTER, { second_reading: true }, { PATH: process.env.PATH ?? "" });
    const sr = r.a.second_reading;
    assert.equal(sr.program, "qpdf");
    assert.match(sr.version_output, /^qpdf version 11\.3\./);
    assert.equal(sr.status, "unsupported_by_the_program");
    assert.equal(sr.result.program_says, "unsupported_encryption_filter");
  });
});

test("with the real msoffcrypto-tool: an extensible EncryptionInfo is said unsupported by the program", { skip: have("msoffcrypto-tool") ? false : "msoffcrypto-tool is not installed on this machine" }, async () => {
  await withCwd(async (cwd, bin) => {
    const r = await run(cwd, bin, "real.doc", OFFICE_EXTENSIBLE, { second_reading: true }, { PATH: process.env.PATH ?? "" });
    const sr = r.a.second_reading;
    assert.equal(sr.program, "msoffcrypto-tool");
    assert.equal(sr.status, "unsupported_by_the_program");
    assert.equal(sr.result.error, "unsupported_extensible_encryption");
  });
});

test("a process qpdf leaves behind holding its output pipe is ended when the tool answers: nothing is left running", async () => {
  await withCwd(async (cwd, bin) => {
    await mkdir(join(cwd, "pids"), { recursive: true });
    await stub(bin, "qpdf", `if [ "$1" = "--version" ]; then echo "qpdf version 11.3.0"; exit 0; fi
( while :; do echo late; sleep 0.05; done ) & echo $! > "${cwd}/pids/kid.pid"
${QPDF_TEXT.map((l) => `echo '${l}'`).join("\n")}
exit 0`);
    let kid = 0;
    try {
      const t0 = Date.now();
      const { a } = await run(cwd, bin, "k.pdf", UNSUPPORTED_FILTER, { second_reading: true });
      kid = await pidFile(join(cwd, "pids", "kid.pid"), 3_000).catch(() => 0);
      assert.ok(kid, "qpdf recorded its child's pid");
      assert.ok(Date.now() - t0 < 30_000);
      assert.ok(a.second_reading, "the answer carries the second reading's own record");
      assert.ok(await gone(kid, 5_000), "the child that held the pipe is ended by the tool");
    } finally {
      if (kid) { try { process.kill(kid, "SIGKILL"); } catch { /* gone */ } }
    }
  });
});
