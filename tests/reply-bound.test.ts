/**
 * No answer to a seat is unbounded: the wall in the hub, and the finish
 * header that rides on every answer.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { boundItem, boundItems, boundRpcAnswer, rpcAnswerMax, UNBOUNDED_FNS } from "../scripts/reply-bound.ts";
import { HANDOFF_LEADS_MAX, handoffLeads } from "../extensions/self-compact.ts";

test("an answer past the bound is kept whole and named, not sent; one within it goes as it is", async () => {
  const small = { ok: true, result: { text: "x".repeat(1000) } };
  assert.deepEqual((await boundRpcAnswer("leadsDigest", small, async () => { throw new Error("not called"); })).answer, small);
  const kept: string[] = [];
  const huge = { ok: true, result: { text: "Finish: not ready (43): " + "job:j000011/tree/Windows/x.cat (its 12224 bytes would pass the budget); ".repeat(40_000) } };
  const r = await boundRpcAnswer("waitForSwarmChange", huge, async (text) => { kept.push(text); return { path: "tool-output/harness/answer.txt", bytes: text.length, sha256: "ab".repeat(32) }; });
  assert.equal(r.answer.ok, false);
  assert.match(r.answer.error ?? "", /the hub's answer to waitForSwarmChange was \d+ bytes, over the bound of 262144.*kept whole at tool-output\/harness\/answer\.txt.*fault of the harness/);
  assert.ok(JSON.stringify(r.answer).length < 1000);
  assert.equal(kept.length, 1, "the whole answer is kept");
  assert.equal(kept[0], JSON.stringify(huge));
  assert.equal(r.cut?.fn, "waitForSwarmChange");
  const unkept = await boundRpcAnswer("readInbox", huge, async () => ({ write_error: "disk full" }));
  assert.match(unkept.answer.error ?? "", /could not be kept \(disk full\)/);
});

test("answers that carry a file's bytes keep their own rules; a job's answer has a higher wall; the bound can be set", async () => {
  const big = { ok: true, result: { diff: "y".repeat(600_000) } };
  for (const fn of ["fileDiff", "restoreFileVersion", "listForgedTools"]) {
    assert.ok(UNBOUNDED_FNS.has(fn));
    assert.deepEqual((await boundRpcAnswer(fn, big, async () => { throw new Error("not called"); })).answer, big);
  }
  assert.deepEqual((await boundRpcAnswer("jobStatus", big, async () => { throw new Error("not called"); })).answer, big, "a page of stdout fits");
  const vast = { ok: true, result: { stdout: "z".repeat(3_000_000) } };
  assert.equal((await boundRpcAnswer("jobStatus", vast, async () => ({ path: "p", bytes: 1, sha256: "s" }))).answer.ok, false);
  assert.equal(rpcAnswerMax({}), 262144);
  assert.equal(rpcAnswerMax({ SWARM_RPC_ANSWER_MAX_BYTES: "1048576" }), 1048576);
  assert.equal(rpcAnswerMax({ SWARM_RPC_ANSWER_MAX_BYTES: "12" }), 262144, "a bound too small to answer anything is not taken");
});

test("the finish header's items: the caller's own first, each cut, the rest counted (the run s5d814f's 38 MB item)", () => {
  const monster = `answer #12 (question:5) rests on coverage record E-93, whose store sweep is partial: not searched: ${"job:j000011/tree/a.cat (why); ".repeat(137_703)}`;
  const items = [monster, 'L-3 "nonce" is active (held by s5d814f05) with no disposition', 'L-9 "media" is active (held by s5d814f02) with no disposition', ...Array.from({ length: 40 }, (_, i) => `job j0000${i} has no interpretation yet`)];
  const b = boundItems(items, (i) => i.includes("s5d814f02"));
  assert.ok(b.text.length < 3200, `the header's item text is ${b.text.length} characters`);
  assert.ok(b.text.startsWith('L-9 "media" is active (held by s5d814f02)'), "the caller's own item comes first");
  assert.match(b.text, /and 37 more \(finish status lists every one\)$/);
  assert.deepEqual([b.total, b.own, b.shown], [43, 1, 6]);
  assert.match(boundItem(monster), /… \(\d+ characters; whole in finish status\)$/);
  assert.equal(boundItem("short"), "short");
  assert.equal(boundItems([], () => false).text, "");
});

test("a hand-off carries the seat's own part of the lead register and the finish as a count, within 2,000 characters", () => {
  const digest = [
    "Leads: 0 open, 7 active, 0 blocked, 8 closed (leads for the whole register).",
    "Open, unheld, by priority: none.",
    "Yours: L-9 active.",
    "Blocked on you: none.",
    "Awaiting your interpretation: j000309; j000313.",
    "Questions nobody holds a lead for, with no answer yet: question:11.",
    `Parked (held, no job and no act on it): ${"L-6 (s5d814f07, 118 min); ".repeat(300)}`,
    `Finish: not ready (93, 2 of them yours): ${"job j000001 has no interpretation yet; ".repeat(5000)}; nobody coordinates it yet.`,
  ].join("\n");
  const h = handoffLeads(digest);
  assert.ok(h.length <= HANDOFF_LEADS_MAX, `${h.length} characters`);
  assert.match(h, /^Leads: 0 open/);
  assert.match(h, /Yours: L-9 active\./);
  assert.match(h, /Awaiting your interpretation: j000309; j000313\./);
  assert.match(h, /Finish: not ready \(93, 2 of them yours\); finish status lists what holds it\.$/);
  assert.doesNotMatch(h, /Parked|Open, unheld|no interpretation yet/);
  assert.ok(handoffLeads(`Yours: ${"L-1 active; ".repeat(2000)}`).length <= HANDOFF_LEADS_MAX);
  assert.equal(handoffLeads("Finish: READY by the registers; s1 coordinates it."), "Finish: READY by the registers; finish status lists what holds it.");
});

test("a tool-supply post names the programs and counts the libraries (a bundle's post was 25,000 characters)", async () => {
  const { postFileList, POST_FILES_MAX } = await import("../scripts/material.ts");
  const sha = "a".repeat(64);
  const files = [
    ...Array.from({ length: 80 }, (_, i) => ({ path: `lib/lib${String(i).padStart(2, "0")}.so.1`, bytes: 1000 + i, sha256: sha })),
    { path: "bin/zbarimg", bytes: 50_000, sha256: sha },
    { path: "PACKAGES.txt", bytes: 300, sha256: sha },
  ];
  const text = postFileList("mat-0002", files);
  assert.ok(text.startsWith("bin/zbarimg (50000 bytes, sha256 "), "the program comes first");
  assert.match(text, new RegExp(`and ${files.length - POST_FILES_MAX} more \\(store/imports/mat-0002/manifest\\.json lists every file with its sha256\\)$`));
  assert.ok(text.length < 1000, `${text.length} characters`);
  assert.equal(postFileList("mat-0001", [files[80]!]), `bin/zbarimg (50000 bytes, sha256 ${sha})`);
});
