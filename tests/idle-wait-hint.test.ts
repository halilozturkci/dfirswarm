/** After three waits nothing woke, a wait's answer leads with the work nobody holds (agent-swarm idleWaitHint). */
import assert from "node:assert/strict";
import { test } from "node:test";
import { IDLE_WAITS, idleWaitHint } from "../extensions/agent-swarm.ts";

const header = (open: string, q: string) => ["Leads: 3 open, 2 active, 0 blocked, 1 closed (leads for the whole register).", `Open, unheld, by priority: ${open}.`, "Yours: none.", `Questions nobody holds a lead for, with no answer yet: ${q}.`].join("\n");

test("an open lead and an unheld question are named first; a seat with nothing to take gets no line", () => {
  assert.equal(IDLE_WAITS, 3);
  const both = idleWaitHint(header("L-4 (the mail store, high); L-9 (browser history)", "question:7, question:9 (open: L-4)"), 3);
  assert.match(both ?? "", /^You have waited 3 times in a row and nothing woke you, while there is work nobody holds: open and held by nobody: L-4 \(the mail store, high\); L-9 \(browser history\) \(lead_claim takes one\); with no lead and no answer: question:7, question:9 \(open: L-4\) \(lead_open with answers: \[the question\] takes one\)\. Take one before you wait again\.$/);
  assert.match(idleWaitHint(header("none", "question:2"), 5) ?? "", /^You have waited 5 times.*with no lead and no answer: question:2 /);
  assert.equal(idleWaitHint(header("none", "none"), 9), null);
  assert.equal(idleWaitHint("The lead register could not be read: x", 3), null);
  assert.ok((idleWaitHint(header("L-1 ".repeat(400), "none"), 3) ?? "").length < 600);
});
