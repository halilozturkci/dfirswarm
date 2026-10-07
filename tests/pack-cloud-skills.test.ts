/**
 * The cloud pack's skills: what each says it shows and does not, the credential boundary, the leaf budget, and the claims the review
 * removed (an operation read as an effect, a retention figure, a window of attacker access computed from two times). A claim that
 * returns fails by its words; a fixture here is the skill's own text, never a tool's output.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const SKILLS = join(ROOT, "packs", "cloud-forensics", "skills");
const IDS = [
  "aws/cloudtrail",
  "entra/signins",
  "google/workspace",
  "google/workspace-access",
  "identity/grants",
  "identity/tokens",
  "logs/sources",
  "logs/what-exists",
  "m365/unified-audit-log",
];

const read = (id: string): { front: Record<string, string>; text: string; body: string } => {
  const text = readFileSync(join(SKILLS, `${id}.md`), "utf8");
  const m = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text);
  assert.ok(m, `${id} has front matter`);
  const front: Record<string, string> = {};
  for (const line of m[1].split("\n")) {
    const i = line.indexOf(":");
    front[line.slice(0, i)] = line.slice(i + 1).trim();
  }
  return { front, text, body: m[2] };
};

const list = (v: string): string[] => v.replace(/^\[|\]$/g, "").split(",").map((s) => s.trim()).filter(Boolean);

test("the pack carries these nine skills and no others", () => {
  const found: string[] = [];
  const walk = (dir: string, prefix: string): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) walk(join(dir, e.name), `${prefix}${e.name}/`);
      else if (e.name.endsWith(".md") && e.name !== "INDEX.md") found.push(`${prefix}${e.name.replace(/\.md$/, "")}`);
    }
  };
  walk(SKILLS, "");
  assert.deepEqual(found.sort(), [...IDS].sort());
});

test("every skill is a leaf: at most 800 tokens (bytes / 4.245) and 300 lines (the program's bound; these files are under 30), and its first line says when to use it and when not to", () => {
  for (const id of IDS) {
    const { text, body } = read(id);
    const tokens = Math.round(Buffer.byteLength(text) / 4.245);
    assert.ok(tokens <= 800, `${id} is ${tokens} tokens`);
    assert.ok(text.split("\n").length <= 300, `${id} is over 300 lines`);
    assert.match(body.trimStart().split("\n")[0], /^Use when .*\bNot for\b/, `${id}: first line`);
  }
});

test("needs chains are two deep at most, every id resolves in the pack or in the base, and no skill declares a host program it does not run", () => {
  const base = new Set(["evidence/verify"]);
  const needs = (id: string): string[] => list(read(id).front.needs ?? "[]");
  const chain = (id: string): number => (base.has(id) ? 0 : 1 + Math.max(0, ...needs(id).map(chain)));
  for (const id of IDS) {
    for (const n of needs(id)) assert.ok(IDS.includes(n) || base.has(n), `${id} needs ${n}`);
    assert.ok(chain(id) <= 2, `${id} needs chain is ${chain(id)} deep`);
    assert.equal(read(id).front.requires_host, "[]", `${id} runs no host program: the pack's programs are an operator's acquisition tools`);
  }
});

test("each skill names the tools its front matter lists, and says what it does not show", () => {
  for (const id of IDS) {
    const { front, body } = read(id);
    for (const tool of list(front.tools ?? "[]")) assert.ok(body.includes(tool), `${id} lists ${tool} and does not name it`);
    for (const tool of ["cloudtrail_parse", "signin_analyse", "ual_parse"]) {
      if (body.includes(tool)) assert.ok(list(front.tools ?? "[]").includes(tool) || list(front.mentions ?? "[]").includes(tool), `${id} names ${tool} and lists it in neither tools nor mentions`);
    }
    for (const tool of list(front.mentions ?? "[]")) assert.ok(!list(front.tools ?? "[]").includes(tool), `${id} both uses and mentions ${tool}`);
    assert.match(body, /\*\*Does not show:\*\*/, `${id} says what it does not show`);
  }
});

test("a skill whose tool can reach a secret says how it is run and what is never written", () => {
  // Every skill that lists a pack tool, and the two that send an agent to an export of tokens or grants without listing one.
  const reaching = IDS.filter((id) => list(read(id).front.tools ?? "[]").length > 0).concat(["google/workspace-access"]);
  assert.ok(reaching.length >= 8, `${reaching.length} skills reach a tool`);
  for (const id of reaching) {
    const { body } = read(id);
    assert.match(body, /\*\*Sensitive output:\*\*/, id);
    assert.match(body, /secret_output: true/, `${id} says to run the job with secret_output: true`);
    assert.doesNotMatch(body, /print (the|a) (client )?secret|write (the|a) (secret|token) (value|in full)/i, `${id} must not tell an agent to write a secret`);
  }
  const tokens = read("identity/tokens").body;
  assert.match(tokens, /Do not authenticate with, replay, refresh or submit a recovered token/, "tokens: no replay of a recovered token");
  assert.match(tokens, /never its value or a hash of a secret/);
  assert.match(tokens, /decoding does not validate a signature/);
  // A client or grant id is an identifier, cited in full; a client secret and a token are not.
  assert.match(read("google/workspace-access").body, /client and grant ids are identifiers, cited in full/);
  // The tool withholds by name and by shape, and says so: the skill does not claim more.
  assert.match(read("google/workspace").body, /other secrets are not recognised/);
});

test("the claims the review removed do not come back", () => {
  const all = IDS.map((id) => ({ id, ...read(id) }));
  const gone: Array<[RegExp, string]> = [
    [/four-hour window|a window in which the attacker/i, "an attacker access window computed from two administrative times"],
    [/single most common failure|none of those revoke/i, "tokens' unsupported opening"],
    [/equivalent of clearing the event log/i, "StopLogging as clearing the log"],
    [/first hour of an intrusion|shape of enumeration/i, "denials as the start of an intrusion"],
    [/the exfiltration (route|question)/i, "sharing or access as exfiltration"],
    [/every sign-in attempt|only on the business tiers/i, "an unsourced coverage rule"],
    [/enumerate/i, "live-access phrasing in an offline pack"],
    [/one log for every workload|a row per operation/i, "the unified audit log as complete and one row per action"],
    [/\b(30|thirty) minutes\b|\b180 days\b|\b90 days\b|seven days on Free/i, "a retention or delay figure no one supplied"],
    [/two-minute|one-hour intervals/i, "a fixed aggregation window stated as fact"],
    [/the tenant is (Google|Microsoft|AWS)\b/i, "a tenant label as a routing rule"],
    [/\brole_assumed_by\b/, "the old attribution field"],
    [/\bpwsh\b|\baws\b (CLI|configure|sts)/, "a host program this pack does not run"],
    // Reworded overclaims the review put back by hand, 22 of 23 of which the first version of this suite let through.
    [/\b\d+(\.\d+)?[- ]?(days?|hours?|minutes?|seconds?|weeks?|months?|years?)\b/i, "a retention, delay or window figure (no one supplied it)"],
    [/\b(one|two|three|four|five|six|seven|ten|twelve|twenty|thirty|sixty|ninety)[- ](days?|hours?|minutes?|weeks?|months?|years?)\b/i, "a retention, delay or window figure in words"],
    [/bound the period|(period|window|interval) (in which |during which )?(the )?(intruder|attacker) (kept|held|had)\b/i, "an attacker's window of access computed from two times"],
    [/(erase|wipe|clear)s? (the |that )?(trail|log)/i, "StopLogging as erasing the trail"],
    [/denials?[^.]{0,40}\b(marks?|is|are)\b[^.]{0,20}(reconnaissance|the start|the first)/i, "denials as a phase of an intrusion"],
    [/how the data left|data left the tenant/i, "sharing as exfiltration"],
    [/MailItemsAccessed[^.]{0,40}shows? (which|that|the)/i, "MailItemsAccessed read as a statement of what was read"],
    [/SharingSet[^.]{0,60}anonymous/i, "SharingSet as anonymous sharing"],
    [/Add service principal\.?`?[^.]{0,40}records? the consent/i, "a service principal's creation read as a consent"],
    [/records each sign-in|each sign-in attempt/i, "sign-ins as complete"],
    [/only (on|in|for) (the )?(Business|Enterprise|E3|E5|P1|P2|premium)/i, "an edition rule stated as fact"],
    [/(proves?|shows?)\b[^.]{0,40}\b(authentic|complete|correct)\b/i, "a hash or an export read as proof of authenticity or completeness"],
    [/(earliest|oldest) and (latest|newest)[^.]{0,50}(show|prove|period)/i, "the first and last record read as the period an export covers"],
    [/session_origin[^.]{0,40}names? the (person|human|user)/i, "a session link read as a person"],
    [/(50126|50158|50074)[^.]{0,30}\bmeans\b/i, "a result code read as one narrow cause"],
    [/forwarding rule[^.]{0,40}shows?[^.]{0,20}(delivered|was received)/i, "a configured forward read as a delivery"],
    [/every workload'?s? (activity|operation)|one row per (action|operation)/i, "the unified audit log as complete"],
    [/\blist every (grant|consent|permission)\b|record each revocation you make/i, "a task that presumes the tenant can be queried or changed"],
    [/(say|state) (that )?none was read|say that no [A-Za-z ]+ reader was available/i, "a boundary worded as 'do not examine it'"],
    [/names every candidate/i, "an unresolved link that lists every candidate (it lists to a cap, with the count)"],
    [/first sign-in that was not (the )?(account owner|user)/i, "initial access presumed"],
    // The same claims in other words: a verb of proof or meaning joined to a conclusion the evidence cannot carry.
    [/\b(proves?|confirms?|demonstrates?|establishes)\b[^.]{0,40}\b(access|accessed|read|exfiltrat\w*|stolen|theft|compromis\w*|took effect|was used)\b/i, "a conclusion stated as proven"],
    [/\b(means|indicates|signals|marks|denotes)\b[^.]{0,30}\b(anonymous|public|reconnaissance|lateral movement|exfiltrat\w*|persistence|an intrusion|compromise)\b/i, "a name or a pattern read as a stage of an intrusion"],
    [/\b(shows?|proves?|reveals?)\b[^.]{0,25}\bwho (did|read|accessed|took|sent|logged)\b/i, "an artefact read as naming the person"],
    [/\b(guarantees?|definitely|certainly|undoubtedly|beyond doubt)\b/i, "certainty about what an export cannot show"],
    [/\b\d{5,6}\b[^.]{0,30}\b(means|indicates|denotes|is returned when)\b/i, "an error code with one stated meaning"],
    [/\b(attacker|intruder|adversary|threat actor)s?\b[^.]{0,50}\b(window|period|duration)\b/i, "an adversary's window or period"],
    [/\b(wipe[sd]?|erase[sd]?|clear(s|ed)?|delete[sd]?|destroy(s|ed)?) (the |that |all )?(trail|logs?|evidence)\b/i, "a logging call read as destroying evidence"],
    [/\b(an?|one|per) (hour|day|week|month|year)s?\b|\bweek\b|\bhourly\b|\bdaily\b/i, "a retention, delay or window figure in other words"],
    [/\b(free|premium|business|enterprise|E3|E5|P1|P2) (tier|plan|edition|licen[cs]e)s?\b/i, "a licence tier stated as deciding what is kept"],
    [/\b(will|always|never)\b[^.]{0,30}\b(be logged|appear in the (log|export)|leave a (record|trace))\b/i, "what a log always or never holds"],
  ];
  // A figure a skill quotes from the tool (`a 5 second window`, in backticks) is a tool fact, not a retention or delay claim.
  for (const { id, text } of all) {
    const plain = text.replace(/`[^`]*`/g, "``");
    for (const [rx, what] of gone) assert.doesNotMatch(/figure/.test(what) ? plain : text, rx, `${id}: ${what}`);
  }
  const signins = all.find((s) => s.id === "entra/signins")!.text;
  assert.doesNotMatch(signins, /50126[^.]*wrong password|50158[^.]*conditional access failure/i, "result codes are the provider's words, not a narrowed gloss");
  // What the review put right stays right: Interrupted is null even with a code, and the tool's cap and counts are stated.
  assert.match(signins, /portal `Status` of Interrupted[\s\S]{0,160}are null/);
  assert.doesNotMatch(signins, /`Interrupted` and other unlisted statuses are null/);
  const trail = all.find((s) => s.id === "aws/cloudtrail")!.text;
  assert.match(trail, /count distinct `event_id`/, "overlapping exports repeat events");
  assert.match(all.find((s) => s.id === "m365/unified-audit-log")!.text, /count distinct `Id`/, "overlapping searches repeat records");
  assert.match(all.find((s) => s.id === "identity/grants")!.text, /registered authentication method, a role assignment or a created account/, "account-side persistence");
  assert.match(all.find((s) => s.id === "logs/sources")!.text, /Offline:/, "the offline boundary is in every skill");
  for (const { id, body } of all) assert.match(body, /\b(Offline|Boundary)\b|never (query|authenticate)/, `${id} states the offline boundary`);
});

test("the retention and delay figures are not in the README either, and the goal does not presume what it asks", () => {
  const readme = readFileSync(join(ROOT, "packs", "cloud-forensics", "README.md"), "utf8");
  assert.doesNotMatch(readme, /\b(180|90) days\b|seven days on Free|17 October 2023/i);
  const goal = readFileSync(join(ROOT, "packs", "cloud-forensics", "goals", "tenant-compromise.md"), "utf8");
  assert.doesNotMatch(goal, /the first sign-in that was not the user|what the\s+attacker still holds/i);
  assert.doesNotMatch(goal, /what was read, downloaded/, "Q5 asks what the records show was accessed, not what was read");
  assert.match(goal, /not established/);
  assert.match(goal, /the supplied evidence does\s+not establish the configuration/, "the definition of done lets answer 7 say the configuration is not established");
});

test("the goal's check on answer 6 is one awk, so that no pipe can be closed early under pipefail: it passes a long correct report and fails one that never says revoked", () => {
  const goal = readFileSync(join(ROOT, "packs", "cloud-forensics", "goals", "tenant-compromise.md"), "utf8");
  const line = /^- `(awk '\/\^## 6\\\..*work\/report\.md)`$/m.exec(goal);
  assert.ok(line, "the check on answer 6 is an awk over work/report.md");
  const check = line[1];
  assert.doesNotMatch(check, /\|/, "no pipe: awk | grep -q fails a correct report with 141 when grep leaves first");
  assert.match(check, /revo\[kc\]/, "revoked, revoking and revocation all count");
  const filler = `${"a line of filler text that is not about sessions at all\n".repeat(4000)}`;
  const report = (six: string, eight = ""): string => `## 1.\nx\n## 6.\n${six}\n${filler}## 7.\nx\n${eight}`;
  const run = (text: string): number => {
    const dir = spawnSync("mktemp", ["-d"], { encoding: "utf8" }).stdout.trim();
    spawnSync("bash", ["-c", `cat > ${dir}/report.md`], { input: text });
    const res = spawnSync("bash", ["-c", `set -euo pipefail; mkdir -p ${dir}/work; cp ${dir}/report.md ${dir}/work/report.md; cd ${dir}; ${check}`]);
    spawnSync("rm", ["-rf", dir]);
    return res.status ?? -1;
  };
  assert.equal(run(report("Sessions were revoked at 14:00 (E-4).")), 0);
  assert.equal(run(report("Revocation of sessions is not established.")), 0);
  assert.equal(run(report("Only the reset time is evidenced.", "## 8.\nSessions were revoked.\n")), 1, "a word in another section does not count");
});

test("pwsh and aws are said to be an operator's acquisition tools, in requires and not in a skill", () => {
  const host = JSON.parse(readFileSync(join(ROOT, "packs", "cloud-forensics", "requires", "host.json"), "utf8"));
  for (const b of host.binaries) {
    assert.match(b.why, /operator's acquisition/);
    assert.match(b.why, /never (passes|connects)|an agent never/);
  }
  const pack = JSON.parse(readFileSync(join(ROOT, "packs", "cloud-forensics", "pack.json"), "utf8"));
  assert.ok(pack.unreferenced_ok.some((e: { name: string; why: string }) => e.name === "pwsh" && /never connects to a tenant/.test(e.why)));
  assert.equal(pack.skills, 9);
});
