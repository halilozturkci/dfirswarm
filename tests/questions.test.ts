/**
 * The question register (extensions/questions.ts) at the protocol level: the
 * chain and its revisions, who may do what (the examiner register's roles
 * and the operator), unenrolled and spoofed identities, duplicate
 * submissions, stale amendments, a crash between the chain write and the
 * post, the clarification round trip, withdrawal (leads closed, a lead with a
 * finding to triage), the finish line flipping on an arrival and serialised
 * against a terminal done, the sensitive check on a question's words, the
 * hypothesis and contrary rules, the question:N alias, an open-ended goal's
 * seeding, and a late analyst question becoming work a seat takes.
 */
import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import { actorFor, operatorAct, verifySignedActs } from "../scripts/questions-cli.ts";
import { allowedSignersLine, enrollPerson } from "../scripts/signers.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

const F = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
const A = { result: "established", confidence: "high", confidence_why: "The finding is read from the object.", alternatives_open: "none remains open: the record is direct", would_change: "a second record that disagrees" } as const;

const GOAL = [
  "## Goal",
  "",
  "Examine the archive.",
  "",
  "### Questions",
  "",
  "1. Which account created the archive?",
  "2. Was the archive opened on another machine?",
  "Bonus: what else was in the folder?",
  "",
  "## Objectives",
  "",
  "- O-1: Establish how the archive came to be on this machine.",
  "",
  "## Definition of done",
  "",
  "d",
  "",
  "## Checks",
  "",
  '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,bonus,summary,narrative --existence 2`',
  "",
].join("\n");

async function run(goal: string = GOAL, agents = ["a0", "a1", "a2"]) {
  const base = await mkdtemp(join(tmpdir(), "questions-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "q1", agentIds: agents, capUsd: 5, wallClockMinutes: 30, goal });
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  return { S, base, ctx, a0: ctx("a0"), a1: ctx("a1"), a2: ctx("a2") };
}

type Role = Q.ActorRole;
const person = (role: Role, id: string, o: { enrolled?: boolean; identity?: "claimed" | "signed" } = {}): Q.Actor => ({ kind: "human", role, person: id, name: id.toUpperCase(), enrolled: o.enrolled ?? true, os_user: "tester", host: "lab", via: "cli", identity: o.identity ?? "claimed" });
const operator: Q.Actor = { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };
const agent = (id: string): Q.Actor => ({ kind: "agent", agent: id });

const ok = <T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> => {
  assert.equal(r.ok, true, (r as unknown as { reason?: string }).reason);
  return r as Extract<T, { ok: true }>;
};
const refused = (r: { ok: boolean }, re: RegExp) => {
  assert.equal(r.ok, false, "expected a refusal");
  assert.match((r as unknown as { reason: string }).reason, re);
};

async function posts(S: string): Promise<Array<{ file: string; text: string }>> {
  const dir = join(S, "threads", "main");
  const names = (await readdir(dir).catch(() => [] as string[])).filter((n) => /^\d{6}-.+\.md$/.test(n)).sort();
  return Promise.all(names.map(async (n) => ({ file: n, text: await readFile(join(dir, n), "utf8") })));
}

async function idle(S: string, agent: string, minutes: number) {
  const at = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
  await writeFile(join(S, "inbox", agent, "waiting.json"), JSON.stringify({ since: at(minutes), started_at: at(1) }));
}

test("the goal seeds the register: Q-n is question:n, a goal's own id keeps its section, objectives come from the goal; reading never writes", async () => {
  const { S } = await run();
  // Read before anything is written: derived, and nothing on disk.
  const before = await Q.questionsSnapshot(S);
  assert.equal(before.seeded, false);
  assert.deepEqual([...before.state.questions.keys()], ["Q-1", "Q-2", "Q-3"]);
  assert.equal((await readFile(join(S, Q.QUESTIONS_LOG), "utf8").catch(() => null)), null, "a read writes nothing");
  const seeded = await Q.seedRegister(S);
  assert.deepEqual(seeded, { seeded: true, questions: ["Q-1", "Q-2", "Q-3"], objectives: ["O-1"] });
  assert.equal((await Q.seedRegister(S)).seeded, false, "seeding twice seeds once");
  const snap = await Q.questionsSnapshot(S);
  const [q1, q2, q3] = ["Q-1", "Q-2", "Q-3"].map((id) => snap.state.questions.get(id)!);
  assert.deepEqual([q1.section, q2.section, q3.section], ["1", "2", "bonus"]);
  assert.equal(q1.text, "Which account created the archive?");
  assert.equal(q2.text, "Was the archive opened on another machine?", "a question's text stops where the goal's next question starts");
  assert.equal(q2.expects, "existence", "--existence names what a question expects");
  assert.equal(q3.text, "what else was in the folder?");
  assert.equal(snap.state.objectives.get("O-1")?.text, "Establish how the archive came to be on this machine.");
  assert.ok([q1, q2, q3].every((q) => q.origin.kind === "goal" && q.scope === "in_scope"));
  // The alias: every form of a goal question's id finds it.
  for (const id of ["Q-2", "question:2", "2", "Q2"]) assert.equal(Q.findQuestion(snap, id)?.id, "Q-2", id);
  assert.equal(Q.findQuestion(snap, "question:bonus")?.id, "Q-3");
  assert.equal(P.sectionKey("Q-2"), "2");
});

test("the chain holds every act and every verbatim revision; a rewritten line breaks it and the register takes nothing more", async () => {
  const { S } = await run();
  const opened = ok(await Q.act(S, operator, "open", { text: "Did the archive leave the machine by mail?", why: "The client says it came by mail" }));
  assert.equal(opened.q, "Q-4");
  ok(await Q.act(S, operator, "amend", { q: "Q-4", expected_rev: 1, text: "Did the archive leave the machine by mail or by a stick?", why: "the stick came up" }));
  ok(await Q.act(S, operator, "amend", { q: "Q-4", expected_rev: 2, neutral: "How did the archive leave the machine?" }));
  const snap = await Q.questionsSnapshot(S);
  const q = snap.state.questions.get("Q-4")!;
  assert.equal(q.rev, 2, "a neutral formulation is attributed separately and makes no new revision");
  assert.deepEqual(q.revisions.map((r) => [r.rev, r.text]), [
    [1, "Did the archive leave the machine by mail?"],
    [2, "Did the archive leave the machine by mail or by a stick?"],
  ]);
  assert.equal(q.neutral?.text, "How did the archive leave the machine?");
  const text = await readFile(join(S, Q.QUESTIONS_LOG), "utf8");
  assert.equal(Q.verifyQuestionChain(text).ok, true);
  await writeFile(join(S, Q.QUESTIONS_LOG), text.replace("by mail or by a stick", "by courier"));
  assert.equal(Q.verifyQuestionChain(await readFile(join(S, Q.QUESTIONS_LOG), "utf8")).reason, "the line was rewritten");
  refused(await Q.act(S, operator, "open", { text: "Another question", why: "w" }), /chain is broken/);
  await writeFile(join(S, Q.QUESTIONS_LOG), text);
  // The register's files are the harness's: protected from edit and write, and a shell rewrite of the chain is caught.
  assert.equal(P.isProtectedPath(Q.QUESTIONS_LOG), true);
  const marks = await P.watchedPathHashes(S);
  await appendFile(join(S, Q.QUESTIONS_LOG), "");
  assert.equal((await P.diffWatchedPaths(S, marks, "a0")).some((r) => r.path === Q.QUESTIONS_LOG), false, "unchanged is not a rewrite");
  await writeFile(join(S, Q.QUESTIONS_LOG), text.replace("by mail?", "by post?"));
  const hit = (await P.diffWatchedPaths(S, marks, "a0")).find((r) => r.path === Q.QUESTIONS_LOG);
  assert.ok(hit?.rewritten, "a rewritten question chain is reported");
  await writeFile(join(S, Q.QUESTIONS_LOG), text);
  const md = await readFile(join(S, Q.QUESTIONS_MD), "utf8");
  assert.match(md, /Revision 1 .*by mail\?/);
  assert.match(md, /Neutral formulation .*How did the archive leave/);
});

test("roles: an examiner's question is in scope by authority and may add an objective; an analyst's inside an objective, else proposed; a reviewer's and an observer's are proposed; agents change no person's question", async () => {
  const { S, a1 } = await run();
  const ex = ok(await Q.act(S, person("examiner", "eve"), "open", { text: "Was a wiper run?", why: "the disk is sparse", objective: "new", objective_text: "Establish whether data was destroyed" }));
  assert.equal(ex.scope, "in_scope");
  assert.equal(ex.objective_created, "O-2");
  assert.match(ex.scope_why ?? "", /scope expanded by EVE: new objective O-2/);
  const inObj = ok(await Q.act(S, person("analyst", "ana"), "open", { text: "When was the archive created?", why: "timeline", objective: "O-1" }));
  assert.equal(inObj.scope, "in_scope");
  const outside = ok(await Q.act(S, person("analyst", "ana"), "open", { text: "Who owns the printer?", why: "curious" }));
  assert.equal(outside.scope, "proposed");
  const newObj = ok(await Q.act(S, person("analyst", "ana"), "open", { text: "Were mails deleted?", why: "hunch", objective: "new", objective_text: "Mail handling" }));
  assert.equal(newObj.scope, "proposed", "an analyst cannot expand the case");
  const rev = ok(await Q.act(S, person("reviewer", "rob"), "open", { text: "Was the clock of the image checked?", why: "review", objective: "O-1" }));
  assert.equal(rev.scope, "proposed");
  assert.equal((await Q.questionsSnapshot(S)).state.questions.get(rev.q!)!.review_query, true);
  const obs = ok(await Q.act(S, person("observer", "oli"), "open", { text: "Is there a second archive?", why: "watching", objective: "O-1" }));
  assert.equal(obs.scope, "proposed");
  // Who may change what.
  refused(await Q.act(S, person("analyst", "ana"), "scope", { q: outside.q, scope: "in_scope", why: "please" }), /examiner's or the operator's, not an analyst's/);
  refused(await Q.act(S, person("analyst", "bea"), "amend", { q: inObj.q, expected_rev: 1, text: "When exactly was the archive created?" }), /did not ask .*only its asker/);
  ok(await Q.act(S, person("analyst", "ana"), "amend", { q: inObj.q, expected_rev: 1, text: "When exactly was the archive created?" }));
  refused(await Q.act(S, person("analyst", "ana"), "amend", { q: "Q-1", expected_rev: 1, text: "Which user made it?" }), /did not ask Q-1/);
  refused(await Q.act(S, person("observer", "oli"), "amend", { q: obs.q, expected_rev: 1, text: "Is there a third archive?" }), /observer proposes questions/);
  refused(await Q.act(S, person("analyst", "ana"), "accept", { q: inObj.q, expected_rev: 2, as: "bounded", why: "enough" }), /not an analyst's/);
  ok(await Q.act(S, person("examiner", "eve"), "scope", { q: outside.q, scope: "in_scope", why: "the printer matters after all" }));
  const admitted = ok(await Q.act(S, person("examiner", "eve"), "scope", { q: newObj.q, scope: "in_scope", why: "mail is in the case" }));
  assert.equal(admitted.objective_created, "O-3", "admitting a proposed objective creates it");
  // Agents: no amend, scope, withdraw, priority or accept, on anyone's question.
  for (const ev of ["amend", "scope", "withdraw", "priority", "accept"] as const) {
    refused(await Q.act(S, agent("a1"), ev, { q: "Q-1", expected_rev: 1, text: "x", scope: "excluded", why: "w", priority: "urgent", reason: "r", as: "bounded" }), /an agent does not/);
  }
  // An agent's own question: in scope inside an objective or under a parent in scope, else proposed; never a new objective.
  const follow = ok(await Q.questionOpen(a1, { text: "Which mail client sent it?", why: "follows the mail question", parent: newObj.q, materiality: "material" }));
  assert.equal(follow.scope, "in_scope");
  const loose = ok(await Q.questionOpen(a1, { text: "Is the wallpaper custom?", why: "noticed it", materiality: "background" }));
  assert.equal(loose.scope, "proposed");
  refused(await Q.questionOpen(a1, { text: "Anything else?", why: "w" }), /materiality is required/);
  refused(await Q.act(S, agent("a1"), "open", { text: "New area", why: "w", objective: "new", objective_text: "x", materiality: "material" }), /new objective is the examiner's or the operator's/);
  // A material question is excluded by the operator or the examiner only.
  refused(await Q.act(S, person("analyst", "ana"), "scope", { q: loose.q, scope: "excluded", why: "not needed" }), /not an analyst's/);
  ok(await Q.act(S, operator, "scope", { q: loose.q, scope: "excluded", why: "not the case's" }));
  refused(await Q.act(S, operator, "scope", { q: "Q-1", scope: "excluded", why: "x" }), /question of the goal/);
});

test("identity: an act with no --as is the OS account's, not enrolled, with the operator's authority; --as names an enrolled person as a claim; a signed act verifies, a spoofed one stays claimed", async () => {
  const { S } = await run();
  const home = join(dirname(S), "home");
  // Unenrolled: the OS account on this host, never promoted.
  const bare = actorFor({});
  assert.ok(!("why" in bare));
  if (!("why" in bare)) {
    assert.deepEqual([bare.actor.kind, (bare.actor as { role: string }).role, (bare.actor as { enrolled: boolean }).enrolled, (bare.actor as { identity: string }).identity], ["human", "operator", false, "claimed"]);
  }
  assert.match(String((actorFor({ sign: true }) as { why: string }).why), /--sign signs with an enrolled person's key/);
  assert.match(String((actorFor({ as: "nobody" }, home) as { why: string }).why), /no one is enrolled on this install under nobody/);
  const r0 = await operatorAct(S, "open", { text: "Where did the archive come from?", why: "provenance" }, {}, home);
  assert.equal(r0.ok, true, String(r0.reason));
  const o0 = (await Q.questionsSnapshot(S)).state.questions.get(String(r0.q))!.origin;
  assert.deepEqual([o0.enrolled, o0.identity, o0.role], [false, "claimed", "operator"]);
  // Enrolled: an analyst with a key and a passphrase.
  const pass = Buffer.from("correct horse battery");
  const e = enrollPerson({ name: "Ana Lyst", organisation: "Lab", competence: "Mail forensics", role: "analyst", id: "ana", generateKey: true }, home, Buffer.from(pass));
  assert.ok(!("why" in e), "why" in e ? e.why : "");
  if ("why" in e) return;
  assert.equal(e.register, `ana namespaces="dfirswarm-question" ${e.person.key.kind === "pkcs11" ? "" : e.person.key.public.split(" ").slice(0, 2).join(" ")}`);
  // Claimed: --as without --sign. Anyone at the CLI can type --as ana; it stays a claim.
  const claimed = await operatorAct(S, "open", { text: "When was the archive last opened?", why: "timeline", objective: "O-1" }, { as: "ana" }, home);
  assert.equal(claimed.ok, true, String(claimed.reason));
  const qc = (await Q.questionsSnapshot(S)).state.questions.get(String(claimed.q))!;
  assert.deepEqual([qc.origin.person, qc.origin.role, qc.origin.enrolled, qc.origin.identity, qc.signed.length], ["ana", "analyst", true, "claimed", 0]);
  // A wrong passphrase signs nothing, and nothing is recorded.
  const eventsBefore = (await Q.questionsSnapshot(S)).state.events.length;
  const wrong = await operatorAct(S, "open", { text: "Was the archive sent twice?", why: "w", objective: "O-1" }, { as: "ana", sign: true, secret: Buffer.from("not the passphrase") }, home);
  assert.equal(wrong.ok, false);
  assert.match(String(wrong.reason), /not signed, so nothing was recorded/);
  assert.equal((await Q.questionsSnapshot(S)).state.events.length, eventsBefore);
  // Signed: the act carries its signature on its own event; it verifies under the enrolled key.
  const signed = await operatorAct(S, "open", { text: "Was the archive sent twice?", why: "two copies seen", objective: "O-1" }, { as: "ana", sign: true, secret: Buffer.from(pass) }, home);
  assert.equal(signed.ok, true, String(signed.reason));
  const qs = (await Q.questionsSnapshot(S)).state.questions.get(String(signed.q))!;
  assert.equal(qs.origin.identity, "signed");
  assert.equal(qs.signed.length, 1);
  const checked = await verifySignedActs(S, { home });
  assert.deepEqual(checked.map((c) => [c.q, c.person, c.state]), [[qs.id, "ana", "unchecked"]]);
  // A forged sign event on a claimed act, with that signature copied onto it, does not verify.
  const { events } = await Q.readQuestionEvents(S);
  const sign = events.find((x) => x.signature)!;
  const target = events.find((x) => x.ev === "open" && x.q === qc.id)!;
  await L.withRegisters(S, async (held) => {
    void held;
    const text = await readFile(join(S, Q.QUESTIONS_LOG), "utf8");
    const head = Q.verifyQuestionChain(text).head!;
    const draft = { v: 1 as const, seq: events.length + 1, at: new Date().toISOString(), by: "operator", ev: "sign" as const, q: qc.id, target_seq: target.seq, target_hash: target.hash, signature: sign.signature, prev: head };
    await appendFile(join(S, Q.QUESTIONS_LOG), `${JSON.stringify({ ...draft, hash: Q.questionEventHash(draft, head) })}\n`);
  });
  const again = await verifySignedActs(S, { home });
  assert.equal(again.find((c) => c.q === qc.id)?.state, "bad", "the claimed act is not the statement that was signed");
});

test("duplicate submissions: the same token is one question, acknowledged again; the same words are refused naming the twin", async () => {
  const { S } = await run();
  const first = ok(await Q.act(S, operator, "open", { text: "Which account sent the mail?", why: "attribution", submission: "form-7f3a" }));
  const again = ok(await Q.act(S, operator, "open", { text: "Which account sent the mail?", why: "attribution", submission: "form-7f3a" }));
  assert.equal(again.duplicate, true);
  assert.equal(again.q, first.q);
  refused(await Q.act(S, person("analyst", "ana"), "open", { text: "which  account sent the MAIL?", why: "again", objective: "O-1" }), new RegExp(`${first.q} asks this already, word for word`));
  const snap = await Q.questionsSnapshot(S);
  assert.equal([...snap.state.questions.values()].filter((q) => q.text === "Which account sent the mail?").length, 1);
  // Two submissions at once with one token: one question.
  const [x, y] = await Promise.all([Q.act(S, operator, "open", { text: "Was the mail encrypted?", why: "w", submission: "form-8b1c" }), Q.act(S, operator, "open", { text: "Was the mail encrypted?", why: "w", submission: "form-8b1c" })]);
  assert.equal(ok(x).q, ok(y).q);
});

test("stale amendments: an amendment names the revision it read; one against a replaced revision is refused, and of two at once one wins", async () => {
  const { S } = await run();
  const q = ok(await Q.act(S, operator, "open", { text: "When was the archive made?", why: "timeline" })).q!;
  refused(await Q.act(S, operator, "amend", { q, text: "When exactly?" }), /names the revision it amends/);
  const [r1, r2] = await Promise.all([
    Q.act(S, operator, "amend", { q, expected_rev: 1, text: "When was the archive made, in UTC?" }),
    Q.act(S, person("examiner", "eve"), "amend", { q, expected_rev: 1, text: "When was the archive made, and by which clock?" }),
  ]);
  assert.equal([r1, r2].filter((r) => r.ok).length, 1, "one amendment wins");
  const lost = [r1, r2].find((r) => !r.ok)!;
  refused(lost, /is at revision 2 .*, not 1: read it again/);
  refused(await Q.act(S, operator, "amend", { q, expected_rev: 1, text: "When?" }), /at revision 2/);
  assert.equal((await Q.questionsSnapshot(S)).state.questions.get(q)!.rev, 2);
});

test("a crash between the chain write and the post: the next header delivers it once, and a post made before a crash is found, not made again", async () => {
  const { S, a0, a1 } = await run();
  await idle(S, "a1", 5);
  // The act is committed and acknowledged; the process dies before it publishes.
  const prepared = await Q.prepareAct(S, operator, "open", { text: "Was the archive opened on the laptop?", why: "second machine", objective: "O-1" });
  assert.ok(prepared.ok);
  if (!prepared.ok) return;
  const r = ok(await Q.commitAct(S, prepared.prepared));
  assert.equal((await posts(S)).length, 0, "nothing is published before delivery");
  // Any header delivers what was committed and not published.
  const digest = await L.leadsDigest(a0, { mark: false });
  const after1 = await posts(S);
  assert.equal(after1.length, 1);
  assert.match(after1[0].text, /^from: analyst:tester@lab$/m);
  assert.match(after1[0].text, /^tag: question$/m);
  assert.match(after1[0].text, new RegExp(`QUESTION ${r.q} \\(revision 1\\)`));
  assert.match(after1[0].text, /^to: a1$/m, "addressed to the seat it is offered to, so it wakes one seat");
  assert.match(digest.text.split("\n")[0], new RegExp(`^Analyst questions \\(1\\), each a proposition to test.*${r.q} rev 1`), "ranked first in the header");
  await Q.deliverPending(S);
  await L.leadsDigest(a1, { mark: false });
  assert.equal((await posts(S)).length, 1, "delivered once");
  // A crash after the post and before its record: the post is found by its key.
  const second = ok(await Q.act(S, operator, "open", { text: "Was the archive printed?", why: "paper trail", objective: "O-1" }));
  await P.registerPost(S, { from: "analyst:tester@lab", to: "a1", tag: "question", body: `QUESTION ${Q.postMarker(second.q!, 1)} from the operator; answer it in section question:${second.q!.slice(2)}.`, key: Q.postKey(second.q!, 1) });
  const delivered = await Q.deliverPending(S);
  assert.deepEqual(delivered.map((d) => d.q), [second.q]);
  const all = await posts(S);
  assert.equal(all.length, 2, "the post made before the crash is the post");
  const snap = await Q.questionsSnapshot(S);
  assert.equal(snap.state.questions.get(second.q!)!.delivered.get(1)?.post?.id, 2);
  // An agent cannot use the register's tag.
  await assert.rejects(P.postMessage(a0, { tag: "question", body: "a question" }), /question register's/);
});

test("clarification: an agent asks, the request is the operator's with a durable id, the work state says so, the answer reaches the asker and the chain", async () => {
  const { S, a2 } = await run();
  const q = ok(await Q.act(S, person("analyst", "ana"), "open", { text: "Was the archive handled by the admin?", why: "access", objective: "O-1" })).q!;
  const asked = ok(await Q.questionAsk(a2, q, "admin: the domain admin, or the local one?"));
  assert.equal(asked.clarify, "C-1");
  const req = (await readFile(join(S, L.OPERATOR_REQUESTS), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
  assert.deepEqual([req[0].kind, req[0].id, req[0].q, req[0].by, req[0].to], ["clarification", "C-1", q, "a2", "analyst:ana"]);
  assert.match(String(req[0].answer), new RegExp(`swarm.sh question q1 clarify-reply ${q} C-1`));
  const ctx = await Q.viewContext(S);
  assert.equal(Q.viewQuestion(ctx.questions.state.questions.get(q)!, ctx).work, "clarification_needed");
  assert.match((await L.leadsDigest(a2, { mark: true })).text, /Clarifications not answered yet .*C-1 on Q-4 asked by a2/);
  refused(await Q.act(S, person("analyst", "bea"), "clarify_answer", { q, clarify: "C-1", answer: "the local one" }), /did not ask/);
  refused(await Q.act(S, person("analyst", "ana"), "clarify_answer", { q, clarify: "C-9", answer: "x" }), /C-9 is not a clarification asked on/);
  const r = await operatorAct(S, "clarify_answer", { q, clarify: "C-1", answer: "the local administrator account" }, { as: undefined }, undefined);
  assert.equal(r.ok, true, String(r.reason));
  const post = (await posts(S)).find((p) => p.text.includes("CLARIFICATION C-1"));
  assert.ok(post, "the answer is posted");
  assert.match(post!.text, /^to: a2$/m);
  const wake = await L.leadsWaitCheck(a2)();
  assert.match(wake ?? "", /answered your clarification C-1 on Q-4: the local administrator account/);
  refused(await Q.act(S, operator, "clarify_answer", { q, clarify: "C-1", answer: "again" }), /was answered by/);
  const after = await Q.viewContext(S);
  assert.equal(Q.viewQuestion(after.questions.state.questions.get(q)!, after).work, "admitted");
});

test("withdrawal: its leads close withdrawn, a lead holding a material finding goes to triage instead, a follow-up waits for triage, and nothing is erased", async () => {
  const { S, a1, a2 } = await run();
  const q = ok(await Q.act(S, person("analyst", "ana"), "open", { text: "Did the user print the archive?", why: "paper", objective: "O-1" })).q!;
  const l1 = ok(await L.openLead(a1, { title: "Read the print spool", why: "printing", answers: [q], take: true, proposition: "the archive was printed", negation: "nothing was printed from it", routes: [{ source: "input:disk.E01", method: "read what the question names, looking for what would disconfirm it" }] })).lead;
  // A second route on the same question, said so (A1: otherwise it is opened unheld, naming l1's holder).
  const l2 = ok(await L.openLead(a2, { title: "Read the printer's own log", why: "printing", answers: [q], take: true, overlap: "second_route", overlap_why: "the printer's own log, not the spool" })).lead;
  // l2 found something: a job interpreted as a finding.
  const dir = join(S, "store", "jobs", "j000001");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "job.json"), JSON.stringify({ id: "j000001", state: "committed", status: "ok", requester: { agent: "a2" }, spec: { kind: "command", command: "echo" } }));
  await writeFile(join(dir, "stdout.log"), "a line\n");
  ok(await L.attachJob(S, "a2", "j000001", l2.id));
  const f = await P.recordEntry(a2, { kind: "finding", ...F, value: "The printer log names the archive", source: "printer log", evidence: "the job's output", refs: ["unresolved:the fixture has no store object"], answers: [q] } as P.LedgerInput);
  assert.ok(f.ok, (f as { reason?: string }).reason);
  if (!f.ok) return;
  ok(await L.recordInterpretations(S, "a2", f.entry.seq, ["j000001"]));
  const child = ok(await Q.questionOpen(a1, { text: "Which printer was it?", why: "follows", parent: q, materiality: "background" })).q!;
  refused(await Q.act(S, person("analyst", "bea"), "withdraw", { q, why: "not mine" }), /did not ask/);
  refused(await Q.act(S, person("analyst", "ana"), "withdraw", { q }), /says why/);
  const w = ok(await Q.act(S, person("analyst", "ana"), "withdraw", { q, why: "the client withdrew the claim" }));
  assert.deepEqual(w.closed_leads, [l1.id]);
  assert.deepEqual(w.triaged, [l2.id, child]);
  const ls = await L.leadsSnapshot(S);
  assert.deepEqual([ls.state.leads.get(l1.id)!.closed?.disposition, ls.state.leads.get(l1.id)!.closed?.ref], ["withdrawn", q]);
  assert.equal(ls.state.leads.get(l2.id)!.closed, null, "the lead with a finding is not closed");
  assert.ok(ls.ledger.bySeq.has(f.entry.seq), "the finding stays in the ledger");
  assert.match((await L.leadsWaitCheck(a1)()) ?? "", new RegExp(`${q} was withdrawn .*${l1.id} closed withdrawn`));
  const md = (await L.leadsDigest(a1, { mark: false })).text;
  assert.match(md, new RegExp(`Waiting for the operator's triage.*${l2.id}: ${q} was withdrawn, and ${l2.id} holds E-${f.entry.seq}`));
  refused(await L.openLead(a1, { title: "More on it", why: "w", answers: [q] }), /was withdrawn/);
  refused(await L.closeLead(a1, l2.id, { disposition: "withdrawn", ref: q }), /withdrawn is the harness's/);
  // The operator decides the triage: the lead kept, the follow-up excluded.
  refused(await Q.act(S, person("analyst", "ana"), "scope", { lead: l2.id, scope: "in_scope", why: "keep" }), /not an analyst's/);
  ok(await Q.act(S, operator, "scope", { lead: l2.id, scope: "in_scope", why: "the printer log matters to O-1" }));
  ok(await Q.act(S, operator, "scope", { q: child, scope: "excluded", why: "moot now" }));
  const snap = await Q.questionsSnapshot(S);
  assert.equal(snap.state.triage.filter((t) => !t.resolved).length, 0);
  refused(await Q.act(S, operator, "amend", { q, expected_rev: 1, text: "x" }), /was withdrawn/);
});

test("the finish line: an in-scope arrival makes it not ready, a proposed one does not; an answer stands it down; an amendment makes the answer stale; acceptance limits", async () => {
  const { S, a0, a1 } = await run(["## Goal", "", "g", "", "## Objectives", "", "- O-1: Establish the archive's origin", "", "## Definition of done", "", "d", "", "## Checks", "", "- `true`", ""].join("\n"));
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/mail.pst", sha256: "a".repeat(64), bytes: 1 }] }));
  const gate = async () => finishGate(S, { total: 1, passed: 1, checks: [{ cmd: "true", ok: true }] });
  assert.deepEqual((await gate()).defects, []);
  // A proposed question holds nothing.
  ok(await Q.act(S, person("observer", "oli"), "open", { text: "Is there a second archive?", why: "watching" }));
  assert.deepEqual((await gate()).defects, []);
  assert.deepEqual((await gate()).register?.proposed, ["Q-1"]);
  // An in-scope arrival does.
  const q = ok(await Q.act(S, person("analyst", "ana"), "open", { text: "Where did the archive come from?", why: "origin", objective: "O-1" })).q!;
  const g1 = await gate();
  assert.deepEqual(g1.defects.map((d) => [d.code, (d as { question?: string }).question]), [["open_question", q]]);
  const verdict = P.finishLineVerdict({ total: 1, passed: 1, checks: [{ cmd: "true", ok: true }], gate: g1 }, false);
  assert.equal(verdict.proceed, false);
  if (!verdict.proceed) assert.match(verdict.reason, /lead and question registers hold against done/);
  // Answered, with contrary_none_why (a person's question), and attested: ready.
  const f = await P.recordEntry(a0, { kind: "finding", ...F, value: "The archive came by mail", source: "mail store", evidence: "the header", refs: ["input:mail.pst"], answers: [q] } as P.LedgerInput);
  assert.ok(f.ok);
  if (!f.ok) return;
  refused(await P.recordEntry(a0, { kind: "answer", section: q, value: "By mail", reasoning: `E-${f.entry.seq} shows it`, ...A } as P.LedgerInput), /a person's question is a proposition to test/);
  const ans = await P.recordEntry(a0, { kind: "answer", section: q, value: "By mail", reasoning: `E-${f.entry.seq} shows it`, contrary_none_why: "no other delivery route left a trace", ...A } as P.LedgerInput);
  assert.ok(ans.ok, (ans as { reason?: string }).reason);
  if (!ans.ok) return;
  assert.equal(ans.entry.section, `question:${q.slice(2)}`, "Q-n is question:n");
  const g2 = await gate();
  assert.deepEqual(g2.defects.map((d) => d.code), ["question_answer"], "a critic has not acted on it yet");
  const att = await P.attestEntry(a1, { seq: ans.entry.seq, how: "re-read the finding it rests on", strength: "established", answer_review: { reproduced: "re-read the finding from its ref", read: "nothing else", link: "the finding is the route the question asks about, read from the host's own record", parts: [{ part: "the route", established: true, why: "the finding shows it" }], inference: "the finding is the answer", alternatives: [{ explanation: "the archive was copied in from elsewhere", why: "the finding's record names the route", evidence: ["E-1"] }], other_family: { checked: false, text: "one family only in this fixture" } } } as never);
  assert.ok((att as { ok: boolean }).ok, JSON.stringify(att));
  assert.deepEqual((await gate()).defects, []);
  // Amended after its answer: the answer is stale.
  ok(await Q.act(S, person("analyst", "ana"), "amend", { q, expected_rev: 1, text: "Where did the archive come from, and when?" }));
  assert.deepEqual((await gate()).defects.map((d) => d.code), ["stale_answer"]);
  // Acceptance: refused while a lead is open, bound to its revision, and it limits the run.
  const other = ok(await Q.act(S, operator, "open", { text: "Was the archive altered after arrival?", why: "integrity" })).q!;
  const lead = ok(await L.openLead(a1, { title: "Hash the copies", why: "integrity", answers: [other], take: true, proposition: "it was altered", negation: "it was not", routes: [{ source: "input:disk.E01", method: "read what the question names, looking for what would disconfirm it" }] })).lead;
  refused(await Q.act(S, operator, "accept", { q: other, expected_rev: 1, as: "bounded", why: "enough" }), /a route is still open .*held by a1/);
  const lim = await P.recordEntry(a1, { kind: "limitation", value: "Only one copy could be read", source: "store", evidence: "the second copy is missing", reason: "unavailable", answers: [other] } as P.LedgerInput);
  assert.ok(lim.ok, (lim as { reason?: string }).reason);
  if (!lim.ok) return;
  ok(await L.closeLead(a1, lead.id, { disposition: "infeasible", ref: `E-${lim.entry.seq}` }));
  refused(await Q.act(S, operator, "accept", { q: other, expected_rev: 2, as: "bounded", why: "x" }), /at revision 1/);
  ok(await Q.act(S, operator, "accept", { q: other, expected_rev: 1, as: "bounded", why: "one copy is all there is" }));
  const g4 = await gate();
  assert.ok(g4.limited.some((l) => l.startsWith(`${other} was accepted as a bounded examination`)));
  assert.ok(!g4.defects.some((d) => (d as { question?: string }).question === other), "an accepted question is not held open");
});

test("admission is serialised against a terminal done: a question admitted after the finish line refuses the sentinel; one after the sentinel is a follow-up", async () => {
  const { S, a0 } = await run();
  const revision = (await P.stateRevision(S)).revision;
  ok(await Q.act(S, person("analyst", "ana"), "open", { text: "Was the archive copied again?", why: "late", objective: "O-1" }));
  await assert.rejects(P.markDone(a0, { reason: "finished", outputFile: "work/report.md", revision }), new RegExp(P.FINISH_LINE_UNSETTLED.slice(0, 40)));
  assert.equal(await P.swarmDoneExists(S), false);
  const now = (await P.stateRevision(S)).revision;
  const done = await P.markDone(a0, { reason: "finished", outputFile: "work/report.md", revision: now });
  assert.equal(done.terminate, true);
  const late = ok(await Q.act(S, person("analyst", "ana"), "open", { text: "Was the archive copied a third time?", why: "later", objective: "O-1" }));
  assert.equal(late.after_done, true, "a durable follow-up receipt, not this run's work");
  assert.deepEqual(await Q.deliverPending(S), [], "a finished run delivers nothing");
  const g = await finishGate(S, { total: 1, passed: 1, checks: [{ cmd: "true", ok: true }] });
  assert.ok(!g.defects.some((d) => (d as { question?: string }).question === late.q));
  assert.deepEqual(g.register?.after_done, [late.q]);
});

test("the sensitive check: a question, its reasons and its hints may not carry a value the run marks sensitive, and the refusal never repeats it", async () => {
  const { S, a0 } = await run();
  const secret = "Tr0ub4dor-archive-key-77";
  const e = await P.recordEntry(a0, { kind: "finding", ...F, value: `The archive's password is ${secret}`, source: "a note", evidence: "the note", refs: ["unresolved:the fixture has no store object"], sensitive: true } as P.LedgerInput);
  assert.ok(e.ok);
  for (const input of [
    { text: `Was ${secret} used anywhere else?`, why: "reuse" },
    { text: "Was the key reused?", why: `the key ${secret} is weak` },
    { text: "Was the key reused?", why: "reuse", hints: [{ ref: "work", value: secret }] },
  ]) {
    const r = await Q.act(S, operator, "open", input);
    refused(r, /holds a value the run marks sensitive \(E-1\)/);
    assert.ok(!(r as { reason: string }).reason.includes(secret));
  }
  refused(await Q.questionOpen(a0, { text: `Where else is ${secret}?`, why: "w", materiality: "material", objective: "O-1" }), /sensitive/);
  ok(await Q.act(S, operator, "open", { text: "Was the archive's password (E-1) used anywhere else?", why: "reuse" }));
});

test("hypothesis framing: the first agent lead under a person's question states the proposition and its negation; leading forms are flagged, not refused; premise_not_supported answers; contrary or contrary_none_why is required", async () => {
  const { S, a0, a1 } = await run();
  const q = ok(await Q.act(S, person("examiner", "eve"), "open", { text: "Confirm that the user copied the archive to a stick", why: "the client says so" })).q!;
  const view = (await Q.questionsSnapshot(S)).state.questions.get(q)!;
  assert.deepEqual(view.leading_forms, ["confirm that"]);
  await Q.deliverPending(S);
  assert.match((await posts(S))[0]?.text ?? "", /Leading form \("confirm that"\)/);
  assert.deepEqual(Q.leadingForms("Show that X; prove it; demonstrate that Y; verify that Z"), ["show that", "prove", "demonstrate that", "verify that"]);
  assert.deepEqual(Q.leadingForms("Was the archive copied?"), []);
  // Only the imperative at the start of the question or of a sentence (or a clause after ; or :), never a verb inside one.
  assert.deepEqual(Q.leadingForms("Was the archive mailed, and if not, what shows that."), [], "the pilot's analyst question");
  assert.deepEqual(Q.leadingForms("Which artefact shows that the stick was used? What proves it ran?"), []);
  assert.deepEqual(Q.leadingForms("Did the log verify that the user signed in? It confirms that nothing else ran."), []);
  assert.deepEqual(Q.leadingForms("The client says so. Confirm that the user copied it."), ["confirm that"]);
  assert.deepEqual(Q.leadingForms("Please verify that Bob did it"), ["verify that"]);
  assert.deepEqual(Q.leadingForms("Can you prove the stick was his?"), ["prove"]);
  assert.deepEqual(Q.leadingForms("\"Show that it happened.\""), ["show that"]);
  assert.deepEqual(Q.leadingForms("Where was it sent?\nDemonstrate that it left by mail."), ["demonstrate that"]);
  // The imperative wrapped in a request or a task is an imperative still (the Fable review, P3 11).
  assert.deepEqual(Q.leadingForms("I want you to confirm that the stick was his."), ["confirm that"]);
  assert.deepEqual(Q.leadingForms("The goal is to prove that he copied it."), ["prove"]);
  assert.deepEqual(Q.leadingForms("Your task is to verify that the logon was his."), ["verify that"]);
  assert.deepEqual(Q.leadingForms("We need you to show that it left."), ["show that"]);
  assert.deepEqual(Q.leadingForms("Is the goal to prove anything?"), [], "a question about a goal asks");
  // The goal's own questions need no framing; a person's do, on the first agent lead.
  ok(await L.openLead(a0, { title: "Who made it", why: "q1", answers: ["1"], take: true }));
  refused(await L.openLead(a0, { title: "USB history", why: "the stick", answers: [q], take: true }), /first lead under it: it is a proposition to test/);
  refused(await L.openLead(a0, { title: "USB history", why: "the stick", answers: [q], proposition: "a stick was used" }), /proposition and negation come together/);
  // A directive (the operator's lead) carries a product instead, and does not count as the first test.
  const direct = ok(await L.openLead({ sandboxRoot: S, agentId: "operator" }, { title: "List the USB devices", why: "directive", answers: [q], product: "a table of devices with first and last times", acceptance: "every device in the registry hives is listed" })).lead;
  assert.deepEqual([direct.product, direct.holder], ["a table of devices with first and last times", null]);
  refused(await L.openLead(a1, { title: "USB history", why: "the stick", answers: [q], take: true }), /first lead under it/);
  const first = ok(await L.openLead(a1, { title: "USB history", why: "the stick", answers: [q], take: true, proposition: "the archive was copied to a removable stick", negation: "no removable device received the archive", routes: [{ source: "input:disk.E01", method: "read what the question names, looking for what would disconfirm it" }] })).lead;
  assert.deepEqual([first.proposition, first.negation], ["the archive was copied to a removable stick", "no removable device received the archive"]);
  ok(await L.openLead(a0, { title: "Cloud sync", why: "another route", answers: [q], take: true })); // a second lead needs no framing
  // The answer: contrary or why none; premise_not_supported is an answer.
  const f = await P.recordEntry(a1, { kind: "finding", ...F, value: "No removable device was attached after the archive was made", source: "device history", evidence: "the hive", refs: ["unresolved:the fixture has no store object"], answers: [q] } as P.LedgerInput);
  assert.ok(f.ok);
  if (!f.ok) return;
  const base = { kind: "answer", section: `question:${q.slice(2)}`, value: "No: nothing shows a copy to a stick", reasoning: `E-${f.entry.seq}`, ...A } as const;
  refused(await P.recordEntry(a1, base as P.LedgerInput), /Name the entries that say otherwise \(contrary\), or say why none does \(contrary_none_why\)/);
  refused(await P.recordEntry(a1, { ...base, contrary: [f.entry.seq], contrary_none_why: "x" } as P.LedgerInput), /not both/);
  refused(await P.recordEntry(a1, { ...base, result: "confirmed", contrary_none_why: "x" } as P.LedgerInput), /result is one of established, partial, bounded_negative, not_determinable, out_of_scope, premise_not_supported/);
  const ans = await P.recordEntry(a1, { ...base, result: "premise_not_supported", contrary_none_why: "no device history, cloud log or mail shows a copy" } as P.LedgerInput);
  assert.ok(ans.ok, (ans as { reason?: string }).reason);
  if (!ans.ok) return;
  assert.deepEqual([ans.entry.result, ans.entry.contrary_none_why], ["premise_not_supported", "no device history, cloud log or mail shows a copy"]);
  assert.equal(P.verifyLedgerChain(await readFile(join(S, P.LEDGER_ENTRIES), "utf8")).ok, true, "the new fields are in the chained core");
  refused(await P.recordEntry(a1, { kind: "answer", section: "summary", value: "s", reasoning: `E-${f.entry.seq}`, result: "premise_not_supported", contrary_none_why: "x" } as P.LedgerInput), /a question's answer's/);
  // A goal question's answer is not held to it.
  const g = await P.recordEntry(a0, { kind: "finding", ...F, value: "The account alice made it", source: "metadata", evidence: "owner", refs: ["unresolved:the fixture has no store object"], answers: ["1"] } as P.LedgerInput);
  assert.ok(g.ok);
  if (!g.ok) return;
  assert.ok((await P.recordEntry(a0, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${g.entry.seq}`, ...A } as P.LedgerInput)).ok);
});

test("the question:N alias: Q-n and question:n are one question for leads, entries and answers; a goal's own id is reached through Q-n", async () => {
  const { S, a0 } = await run();
  const l = ok(await L.openLead(a0, { title: "t", why: "w", answers: ["Q-2", "question:1", "Q1"] })).lead;
  assert.deepEqual(l.answers, ["1", "2"]);
  refused(await L.openLead(a0, { title: "t", why: "w", answers: ["Q-99"] }), /Q-99 is not in the question register/);
  const bonus = ok(await L.openLead(a0, { title: "b", why: "w", answers: ["Q-3"] })).lead;
  assert.deepEqual(bonus.answers, ["bonus"], "Q-3 is the goal's bonus question");
  const e = await P.recordEntry(a0, { kind: "finding", ...F, value: "v", source: "s", evidence: "e", refs: ["unresolved:none"], answers: ["Q-2", "Q-3"] } as P.LedgerInput);
  assert.ok(e.ok, (e as { reason?: string }).reason);
  if (!e.ok) return;
  assert.deepEqual(e.entry.answers, ["2", "bonus"]);
  const snap = await L.leadsSnapshot(S);
  assert.ok(L.caseQuestions(snap).includes("bonus"));
  const view = await L.leadsView(a0, { view: "questions" });
  assert.deepEqual((view.register as Array<{ id: string; section: string; origin: string }>).map((r) => [r.id, r.section, r.origin]), [["Q-1", "question:1", "goal"], ["Q-2", "question:2", "goal"], ["Q-3", "question:bonus", "goal"]]);
});

test("an open-ended goal: objectives and no questions; the header asks the first agents to propose them, and one inside an objective is admitted at once", async () => {
  const goal = ["## Goal", "", "Look at what the operator handed over.", "", "## Objectives", "", "- O-1: Describe what each file is", "- Establish anything that looks wrong", "", "## Definition of done", "", "d", "", "## Checks", "", "- `true`", ""].join("\n");
  const { S, a0 } = await run(goal);
  const snap = await Q.questionsSnapshot(S);
  assert.deepEqual([...snap.state.objectives.entries()].map(([id, o]) => [id, o.text]), [["O-1", "Describe what each file is"], ["O-2", "Establish anything that looks wrong"]]);
  assert.equal(snap.state.questions.size, 0);
  const head = (await L.leadsDigest(a0, { mark: false })).text;
  assert.match(head, /No questions yet: the goal names objectives and no questions \(O-1 "Describe what each file is"; O-2 "Establish anything that looks wrong"\)\. Propose the initial questions .* question_open \(objective: "O-1"\)/);
  const q = ok(await Q.questionOpen(a0, { text: "What format is each file in?", why: "O-1 needs it", objective: "O-1", materiality: "material", source_entry: "E-1" }));
  assert.equal(q.scope, "in_scope");
  const origin = (await Q.questionsSnapshot(S)).state.questions.get(q.q!)!.origin;
  assert.deepEqual([origin.kind, origin.agent, origin.source_entry], ["agent", "a0", "E-1"]);
  assert.doesNotMatch((await L.leadsDigest(a0, { mark: false })).text, /No questions yet/);
  assert.match((await L.leadsDigest(a0, { mark: false })).text, /Questions nobody holds a lead for, with no answer yet: question:1/);
  // Its answer is the finish line's too.
  const g = await finishGate(S, { total: 1, passed: 1, checks: [{ cmd: "true", ok: true }] });
  assert.deepEqual(g.defects.map((d) => d.code), ["open_question"]);
});

test("end to end: a late analyst question is offered to its suggested seat for a minute, then to the most suited idle seat, becomes a lead and holds the finish line", async () => {
  const { S, a0, a1, a2 } = await run(GOAL, ["a0", "a1", "a2"]);
  // a1 has worked objective O-1 before (a lead under one of its questions, closed); a2 has not.
  const earlier = ok(await Q.act(S, operator, "open", { text: "Where was the archive stored first?", why: "origin", objective: "O-1" })).q!;
  await Q.deliverPending(S);
  const held = ok(await L.openLead(a1, { title: "Walk the first folder", why: "origin", answers: [earlier], take: true, proposition: "it was first stored in Documents", negation: "it was first stored elsewhere", routes: [{ source: "input:disk.E01", method: "read what the question names, looking for what would disconfirm it" }] })).lead;
  const lim = await P.recordEntry(a1, { kind: "limitation", value: "The folder history is gone", source: "the folder", evidence: "no history", reason: "unavailable", answers: [earlier] } as P.LedgerInput);
  assert.ok(lim.ok);
  if (!lim.ok) return;
  ok(await L.closeLead(a1, held.id, { disposition: "infeasible", ref: `E-${lim.entry.seq}` }));
  ok(await Q.act(S, operator, "withdraw", { q: earlier, why: "the folder is gone; asked elsewhere" }));
  await idle(S, "a1", 3);
  await idle(S, "a2", 10);
  await mkdir(join(S, "work", "notes"), { recursive: true });
  await writeFile(join(S, "work", "notes", "mail.txt"), "x\n");
  const r = await operatorAct(S, "open", { text: "Was the archive attached to a mail?", why: "the client's claim", objective: "O-1", suggested_to: "a0", hints: [{ ref: "work/notes" }], priority: "urgent", reason: "court date" }, { as: undefined }, undefined);
  assert.equal(r.ok, true, String(r.reason));
  const q = String(r.q);
  const d = (r.delivered as Q.Delivery[])[0];
  assert.deepEqual([d.q, d.offer_to, d.first], [q, "a0", true], "the suggested seat is offered it first");
  // a0 is woken with the offer; the others are not offered it within its minute.
  assert.match((await L.leadsWaitCheck(a0)()) ?? "", new RegExp(`${q} is offered to you first, for 60 s`));
  assert.equal(await Q.electQuestionOffer(a1), null, "within the minute nobody else is offered it");
  // After the minute: the most suited idle seat. a2 has waited longer; a1 has worked the objective.
  const later = Date.now() + 61_000;
  assert.equal(await Q.electQuestionOffer(a2, later), null, "a2 has waited longer, but a1 is more suited");
  const offered = await Q.electQuestionOffer(a1, later);
  assert.equal(offered?.q.id, q);
  assert.equal(await Q.electQuestionOffer(a1, later), null, "one pool offer per revision");
  // a1 takes it as work: the first lead under it states the hypothesis.
  const lead = ok(await L.openLead(a1, { title: "Search the mail store for the archive", why: q, answers: [q], take: true, proposition: "the archive was attached to a mail", negation: "no mail carried the archive", routes: [{ source: "input:disk.E01", method: "read what the question names, looking for what would disconfirm it" }] })).lead;
  const ctx = await Q.viewContext(S);
  const v = Q.viewQuestion(ctx.questions.state.questions.get(q)!, ctx);
  assert.deepEqual([v.work, v.leads.map((l) => l.id)], ["working", [lead.id]]);
  // An urgent question under the objective a holder works is a NOTICE that wakes nobody.
  const urgentNotice = (await L.leadsDigest(a1, { mark: false })).notices.find((n) => n.kind === "question_urgent");
  assert.ok(urgentNotice, "the holder under the objective is told it is urgent");
  assert.equal(urgentNotice!.wakes, false);
  // The finish line holds it open until it is answered.
  const g = await finishGate(S, { total: 1, passed: 1, checks: [{ cmd: "true", ok: true }] });
  assert.ok(g.defects.some((x) => (x as { question?: string }).question === q));
  assert.ok(g.defects.some((x) => x.code === "open_lead" && x.lead === lead.id));
});

test("the analyst and observer roles: enrolled with a key, their register line is the question namespace only (a release refuses them: tests/signing.test.ts)", async () => {
  const home = await mkdtemp(join(tmpdir(), "questions-home-"));
  dirs.push(home);
  const r = enrollPerson({ name: "Olive Server", organisation: "Lab", competence: "watches cases", role: "observer", id: "oli", generateKey: true }, home, Buffer.from("a long passphrase"));
  assert.ok(!("why" in r), "why" in r ? r.why : "");
  if ("why" in r) return;
  assert.equal(r.person.role, "observer");
  assert.match(allowedSignersLine(r.person), /^oli namespaces="dfirswarm-question" ssh-ed25519 /);
  assert.match(allowedSignersLine({ ...r.person, role: "examiner" }), /namespaces="dfirswarm-release,dfirswarm-package,dfirswarm-question"/);
  const bad = enrollPerson({ name: "X", organisation: "Lab", competence: "c", role: "boss" as never, id: "x", generateKey: true }, home, Buffer.from("a long passphrase"));
  assert.match("why" in bad ? bad.why : "", /--role is examiner, reviewer, analyst, observer/);
});

function dirname(p: string): string {
  return p.slice(0, p.lastIndexOf("/"));
}
