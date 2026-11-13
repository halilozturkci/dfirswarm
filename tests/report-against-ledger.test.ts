/**
 * A report is held against the ledger before the finish: the two must say the same.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { reportAgainstLedger } from "../extensions/finish.ts";

test("a standing answer whose first line the report does not hold is named, and an entry the report cites that the ledger lacks", () => {
  const answers = [
    { section: "question:1", seq: 40, value: "DESKTOP-37SCR9U_GMT Standard Time\nfrom the SYSTEM hive" },
    { section: "question:5", seq: 262, value: "The C2 endpoint is 192.168.1.33:6969 as read from the sample" },
    { section: "question:10", seq: 300, value: "`d774c3a1cbe3d146c20e4142a8361609`" },
  ];
  const report = "## 1\n**DESKTOP-37SCR9U_GMT Standard   Time** (E-40)\n\n## 5\n`192.168.1.33:6969` (E-262, E-97)\n\n## 10\nPending.\n";
  const out = reportAgainstLedger(report, answers, 95 + 210);
  assert.equal(out.length, 2, JSON.stringify(out));
  assert.match(out[0]!, /the report does not hold question:5's standing answer \(E-262\): its value's first line, The C2 endpoint is 192\.168\.1\.33:6969 as read from the sample, is not in it/);
  assert.match(out[1]!, /question:10's standing answer \(E-300\).*d774c3a1cbe3d146c20e4142a8361609/);
  const cites = reportAgainstLedger("See E-97 and E-12 and E-0.", [], 95);
  assert.deepEqual(cites, ["the report cites E-0, E-97, which the ledger does not have (its last entry is E-95)"]);
  assert.deepEqual(reportAgainstLedger("## 10\nd774c3a1cbe3d146c20e4142a8361609\n", [answers[2]!], 300), []);
  assert.deepEqual(reportAgainstLedger("", [{ section: "question:2", seq: 1, value: "" }], 1), [], "an answer with no value yet asks nothing of the report");
});
