/**
 * pe_directories, the fourth review's P1-2: a string whose address points right after a run of token characters (an export name whose
 * RVA follows a 40-character token) was withheld only in its leading run, and the rest was tested alone, so `head:password@host` printed
 * the password. The fixture is the PE/COFF export directory (tests/pack-re-doc-fixtures.ts buildPeDirs) with one name pointer moved by
 * hand into the middle of another name, never from the tool's output.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { PE_DIRECTORIES, body, put, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { TOKEN_RUN as TOKEN, afterTokenRun } from "./pack-re-doc-fixtures.ts";

test("P1-2 a name that starts right after a token run: the whole text is sanitised with the head masked, so a password after it is withheld, and the random pieces the head is joined to by `/` with it", async () => {
  await withCwd(async (cwd) => {
    const tails = ["svc:Secr3tPassw0rd@db.example", "admin:hunter2pass@10.0.0.5", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "Invoice/report.txt"];
    await put(cwd, "work/m.dll", afterTokenRun(tails));
    const r = await tool(PE_DIRECTORIES, cwd, { path: "work/m.dll" });
    const a = body(r);
    for (const secret of ["Secr3tPassw0rd", "hunter2pass", "K7MDENG", "bPxRfiCYEXAMPLEKEY", TOKEN.slice(4, 20)]) assert.ok(!r.stdout.includes(secret), `${secret} printed`);
    const shown = (a.tables.exports.rows as Json[]).map((x) => x.name as string);
    assert.ok(shown.includes("<userinfo withheld 18 characters>@db.example"), JSON.stringify(shown));
    assert.ok(shown.includes("<userinfo withheld 17 characters>@10.0.0.5"), JSON.stringify(shown));
    assert.ok(shown.includes("<token-shaped text withheld 40 characters>"), JSON.stringify(shown));
    // a plain word after the run: only the run's part is withheld, the rest is the file's text
    assert.ok(shown.includes("<token-shaped text withheld 7 characters>/report.txt"), JSON.stringify(shown));
    assert.equal(a.withheld_by_final_check, undefined);
  });
});
