/**
 * The answer format a question asks for (a "Format:" line) and the note an
 * answer recorded out of it gets: said, never refused (extensions/answer-format.ts).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { formatMiss, questionFormat } from "../extensions/answer-format.ts";
import * as Q from "../extensions/questions.ts";
import { A, F, ok, rec, run } from "./negative-bar-fixture.ts";

const H = "0123456789abcdef0123456789abcdef";

test("a question's Format line is read into a pattern: hashes, a clock, ip:port, an email, and free words joined by separators", () => {
  assert.equal(questionFormat("What happened?"), null, "no format named");
  assert.equal(questionFormat("Format: *a description*"), null, "free words alone say nothing");
  const cases: Array<[string, string, boolean]> = [
    ["What is the name and hash? Format: *Name_md5(file)*", `dropper.exe_${H}`, true],
    ["Format: *Name_md5(file)*", `dropper.exe md5 ${H}`, false],
    ["Format: *DD-MM-YYYY-HH-MM*", "21-02-2024-16-33", true],
    ["Format: *DD-MM-YYYY-HH-MM*", "2024-02-21 16:33 UTC", false],
    ["Format: *ip:port*", "Answer: `192.168.1.33:6969` (from the capture)", true],
    ["Format: *ip:port*", "the address 192.168.1.33 on port 6969", false],
    ["Format: *md5(nonce)*", H.toUpperCase(), true],
    ["Format: *md5(password)_md5(data-in-the-site)*", `${H}_${H}`, true],
    ["Format: *md5(password)_md5(data-in-the-site)*", `${H}_<md5 of the locked page>`, false],
    ["Format: *email_password*", "a@b.com_hunter2", true],
    ["Format: *email_password*", "a@b.com / hunter2", false],
    ["What is the PC name and timezone? Format: *PC-name_Time-Zone-info*", "DESKTOP-37SCR9U_GMT Standard Time", true],
    ["What is the PC name and timezone? Format: *PC-name_Time-Zone-info*", "PC name: DESKTOP-37SCR9U. Timezone: GMT Standard Time", false],
    // The form on a line of its own, the words around it on the next.
    ["Format: *DD-MM-YYYY-HH-MM*", "21-02-2024-16-33\nfrom the Prefetch run times, local time", true],
  ];
  for (const [q, v, fits] of cases) assert.equal(formatMiss(q, v) === null, fits, `${q} / ${v}`);
});

test("an answer out of its question's format is recorded, with a note that names the format; one in it gets none", async () => {
  const goal = ["## Goal", "", "Examine the host.", "", "### Questions", "", "1. When did the file run? Format: *DD-MM-YYYY-HH-MM*", "", "## Definition of done", "", "d", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1`', ""].join("\n");
  const r = await run({ goal });
  await Q.seedRegister(r.S);
  const f = ok(await rec(r.a0, { kind: "finding", ...F, value: "The file ran at 2024-02-21 16:33", source: "the log", evidence: "line 3", refs: ["job:j000002/hits.txt"], answers: ["1"] }));
  const out = ok(await rec(r.a1, { kind: "answer", section: "question:1", value: "It ran on 2024-02-21 at 16:33", reasoning: `E-${f.entry.seq}`, result: "established", ...A }));
  assert.match(out.note ?? "", /question:1 asks for its answer in the format DD-MM-YYYY-HH-MM, and no line of the value is in it/);
  const again = ok(await rec(r.a1, { kind: "answer", section: "question:1", value: "21-02-2024-16-33", reasoning: `E-${f.entry.seq}`, result: "established", supersedes: out.entry.seq, ...A }));
  assert.doesNotMatch(again.note ?? "", /asks for its answer in the format/);
});
