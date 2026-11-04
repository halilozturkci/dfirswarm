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
import { routerChecks } from "./pack-router-checks.ts";
import { ROOT } from "./tool-library-harness.ts";

const SKILLS = join(ROOT, "packs", "cloud-forensics", "skills");
const IDS = [
  "aws/cloudtrail",
  "aws/cloudtrail-integrity",
  "aws/guardduty",
  "aws/s3-access",
  "aws/vpc-flow",
  "azure/activity-resource-logs",
  "entra/directory-audit",
  "entra/signins",
  "gcp/audit-logs",
  "google/workspace",
  "google/workspace-access",
  "identity/grants",
  "identity/tokens",
  "kubernetes/audit",
  "logs/exported-evidence",
  "logs/sources",
  "logs/what-exists",
  "m365/mailbox-persistence",
  "m365/unified-audit-log",
];

// The pack's one router: shown alone when a run's index is over budget, and names every other skill once (routerChecks below).
// IDS holds the nineteen leaves; the router reads no artefact, so the per-leaf checks of this file do not apply to it.
const ROUTER = "cloud/router";

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

test("the pack carries these nineteen skills and its router, and no others", () => {
  const found: string[] = [];
  const walk = (dir: string, prefix: string): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) walk(join(dir, e.name), `${prefix}${e.name}/`);
      else if (e.name.endsWith(".md") && e.name !== "INDEX.md") found.push(`${prefix}${e.name.replace(/\.md$/, "")}`);
    }
  };
  walk(SKILLS, "");
  assert.deepEqual(found.sort(), [...IDS, ROUTER].sort());
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

test("needs chains are two edges deep at most (three skills), every id resolves in the pack or in the base, and no skill declares a host program it does not run", () => {
  const base = new Set(["evidence/verify"]);
  const needs = (id: string): string[] => list(read(id).front.needs ?? "[]");
  const chain = (id: string): number => (base.has(id) ? -1 : needs(id).length ? 1 + Math.max(...needs(id).map(chain)) : 0);
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
    for (const tool of ["cloudtrail_parse", "signin_analyse", "ual_parse", "cloud_normalise", "cloud_timeline_export", "guardduty_findings"]) {
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
  assert.equal(pack.skills, 20);
});

test("aws/cloudtrail-integrity routes the CloudTrail integrity check to the operator: the command and its options are named and cited with a date, the result vocabulary is fixed, a signature-less export and a file hash are not validation, and nothing tells the agent to run the program", () => {
  const leaf = read("aws/cloudtrail-integrity");
  assert.deepEqual(list(leaf.front.tools ?? "[]"), [], "no tool of the pack validates");
  assert.equal(leaf.front.requires_host, "[]", "no host program is required: the agent never runs it");
  assert.deepEqual(list(leaf.front.mentions ?? "[]"), ["aws"], "the program is named as the operator's, in mentions");
  const b = leaf.body;
  assert.match(b, /`aws cloudtrail validate-logs`/);
  for (const opt of ["--trail-arn", "--start-time", "--end-time", "--s3-bucket", "--s3-prefix", "--account-id", "--verbose"]) assert.ok(b.includes(`\`${opt}\``), `${opt} is named`);
  assert.match(b, /read 20\d\d-\d\d-\d\d, docs\.aws\.amazon\.com\/cli\/latest\/reference\/cloudtrail\/validate-logs\.html/, "the source is dated and cited");
  assert.match(b, /UNVERIFIED/, "what the cited page does not document is marked");
  assert.match(b, /`verified`, `failed` or `unavailable`/, "the result vocabulary");
  assert.match(b, /per digest file and per log file/i);
  assert.match(b, /gaps in the chain/);
  assert.match(b, /lost the S3 object metadata \(the digest signature\) cannot show that validation/);
  assert.match(b, /a file hash[^.]*is not that validation/i);
  assert.match(b, /Offline: no tool of this pack validates/);
  assert.match(b, /you never run one or authenticate to an account/);
  assert.doesNotMatch(b, /\b(run|execute|use|invoke)\b[^.]{0,20}`aws /i, "no instruction to run the program");
  // The CloudTrail leaf opens it only if, and the router names it.
  assert.match(read("aws/cloudtrail").body, /only if one is wanted, `aws\/cloudtrail-integrity`/);
  assert.match(readFileSync(join(SKILLS, "cloud", "router.md"), "utf8"), /`aws\/cloudtrail-integrity` /);
  // aws is still an operator's program that is not in the image.
  const host = JSON.parse(readFileSync(join(ROOT, "packs", "cloud-forensics", "requires", "host.json"), "utf8"));
  assert.ok(host.binaries.find((x: { name: string }) => x.name === "aws").not_in_image);
});

test("the split pass: the pack's needs chains stay within the 1,900-token budget without the base pack, and every index entry is within 40 tokens", () => {
  const tokens = (s: string): number => Buffer.byteLength(s) / 4.245;
  const needs = (id: string): string[] => list(read(id).front.needs ?? "[]");
  for (const id of IDS) {
    const members = new Set<string>([id]);
    const walk = (x: string): void => needs(x).forEach((n) => { if (!members.has(n)) { members.add(n); walk(n); } });
    walk(id);
    assert.ok(![...members].some((m) => !IDS.includes(m)), `${id}: no needs edge reaches the base pack, which a pointer in the body replaces`);
    const total = [...members].reduce((n, m) => n + tokens(read(m).text), 0);
    assert.ok(total <= 1900, `${id}: chain is ${Math.round(total)} tokens`);
    const { front } = read(id);
    assert.ok(tokens(`- \`${id}\` ${front.title}: ${front.when}`) <= 40, `${id}: index entry`);
  }
  // The base pack's evidence/verify is a pointer in the body, opened only when a digest must be checked, not a dependency.
  const exists = read("logs/what-exists");
  assert.deepEqual(list(exists.front.needs ?? "[]"), ["logs/exported-evidence"]);
  assert.match(exists.body, /base pack `evidence\/verify`, only if you must check a digest against a manifest/);
  assert.match(exists.body, /A file hash shows the bytes are those recorded when it was taken\. It does not show the provider made them/);
});


// ---- The skills that read what cloud_normalise writes (PKG-CLD-15) ------------------------------------------------------------------------

const NEW_LEAVES = ["logs/exported-evidence", "entra/directory-audit", "gcp/audit-logs", "kubernetes/audit"];
const TOOLS_DIR = join(ROOT, "packs", "cloud-forensics", "tools");

test("the four new leaves name only fields the adapters write: every snake_case name in backticks is a field of cloud_normalise's source, a tool, a recipe, a parameter of its manifest or a skill id", () => {
  const source = readFileSync(join(TOOLS_DIR, "cloud_normalise", "run.py"), "utf8");
  const manifest = JSON.parse(readFileSync(join(TOOLS_DIR, "cloud_normalise", "manifest.json"), "utf8"));
  const allowed = new Set<string>([...Object.keys(manifest.params), "cloud_normalise", "cloud_timeline_export", "guardduty_findings", "cloudtrail_parse", "signin_analyse", "ual_parse", "check_inputs", "cloud_export_inventory", "secret_output", "write_values", "rejected", "pagination_markers", "status"]);
  for (const id of NEW_LEAVES) {
    const { body } = read(id);
    for (const m of body.matchAll(/`([^`]+)`/g)) {
      const name = m[1];
      if (!/^[a-z][a-z0-9_]*$/.test(name) || name.length < 3) continue;
      assert.ok(allowed.has(name) || source.includes(`"${name}"`), `${id} names \`${name}\`, which cloud_normalise does not write`);
    }
  }
});

test("exported-evidence is a prerequisite of what-exists with no needs of its own, at most 250 tokens (400 is the hard limit), and keeps byte integrity, authenticity and completeness apart", () => {
  const leaf = read("logs/exported-evidence");
  assert.deepEqual(list(leaf.front.needs ?? "[]"), []);
  assert.ok(Buffer.byteLength(leaf.text) / 4.245 <= 250, "the chain bound of entra/signins and logs/what-exists leaves no more");
  assert.deepEqual(list(read("logs/what-exists").front.needs ?? "[]"), ["logs/exported-evidence"]);
  assert.match(leaf.body, /byte integrity \([^)]*\), authenticity \([^)]*\) and completeness \([^)]*\)\. None implies another/);
  assert.match(leaf.body, /`check_inputs`/);
  assert.match(leaf.body, /`cloud-export-inventory`/);
});

test("entra/directory-audit keeps the actor from the target and a request from an effect, says the modified values are sensitive, and agrees with entra/signins and identity/tokens", () => {
  const { front, body } = read("entra/directory-audit");
  assert.deepEqual(list(front.tools ?? "[]"), ["cloud_normalise"]);
  assert.match(body, /Actor and target are different fields/);
  assert.match(body, /Request is not effect/);
  assert.match(body, /`ual_parse` is not a substitute/);
  assert.match(body, /values are sensitive/);
  assert.match(body, /Delegated grants, application roles and workload credentials are different objects/);
  assert.match(read("entra/signins").text, /directory audit: cloud_normalise/);
  assert.match(read("identity/tokens").text, /directory-audit export: `cloud_normalise`/);
  assert.doesNotMatch(read("entra/signins").text + read("identity/tokens").text, /no reader here: read it in a recorded job|directory audit: no reader here/);
});

test("gcp/audit-logs separates the four logs, keeps the delegation chain, takes Data Access settings and retention from supplied settings and never from a default", () => {
  const { front, body } = read("gcp/audit-logs");
  assert.deepEqual(list(front.tools ?? "[]"), ["cloud_normalise"]);
  for (const t of ["admin_activity", "data_access", "system_event", "policy_denied"]) assert.ok(body.includes(`\`${t}\``), t);
  assert.match(body, /`delegation_chain` keeps every hop/);
  assert.match(body, /come from supplied settings, never from memory of a default/);
  assert.match(body, /`unknown` when the entry has no status/);
  assert.match(body, /`receive_time_raw`/);
});

test("kubernetes/audit keeps stages as separate rows, says an API request is not execution, points to node evidence only conditionally and names an id that exists", () => {
  const { front, body } = read("kubernetes/audit");
  assert.deepEqual(list(front.tools ?? "[]"), ["cloud_normalise"]);
  assert.match(body, /One row is one stage/);
  assert.match(body, /separate rows, never separate actions/);
  assert.match(body, /A request is not execution/);
  assert.match(body, /Linux pack if it is loaded \(check the run's skill index/);
  assert.match(body, /replaced whole by a marker/);
  assert.doesNotMatch(body, /containers\/runtime-orchestration/, "no pointer into the other pack is a dependency");
});

// ---- The five leaves that read the S3, VPC, Azure, GuardDuty and mailbox evidence (PKG-CLD-16) --------------------------------------------

const S1B_LEAVES = ["aws/s3-access", "aws/vpc-flow", "azure/activity-resource-logs", "aws/guardduty", "m365/mailbox-persistence"];
const toolSource = (tool: string): string => readFileSync(join(TOOLS_DIR, tool, "run.py"), "utf8");
const toolParams = (tool: string): string[] => Object.keys(JSON.parse(readFileSync(join(TOOLS_DIR, tool, "manifest.json"), "utf8")).params);

test("the five leaves name only what the tools they list write: every snake_case, hyphenated or file name in backticks is a field, a parameter, an output file or a tool of the pack", () => {
  const sources: Record<string, string> = {
    "aws/s3-access": toolSource("cloud_normalise") + toolSource("cloudtrail_parse"),
    "aws/vpc-flow": toolSource("cloud_normalise"),
    "azure/activity-resource-logs": toolSource("cloud_normalise"),
    "aws/guardduty": toolSource("guardduty_findings"),
    "m365/mailbox-persistence": toolSource("ual_parse") + toolSource("cloud_normalise"),
  };
  const params = new Set<string>([...["cloud_normalise", "cloudtrail_parse", "guardduty_findings", "ual_parse"].flatMap(toolParams)]);
  const tools = new Set(["cloud_normalise", "cloudtrail_parse", "guardduty_findings", "ual_parse", "network_log_summary", "secret_output", "write_values"]);
  // Values the tools write as words of their own (a provider, a format, a state), spelled in the source as quoted strings.
  const dynamic = /^log_status_(NODATA|SKIPDATA)$/; // adapter_counts keys are built as "log_status_" + the status
  for (const id of S1B_LEAVES) {
    const { body } = read(id);
    for (const m of body.matchAll(/`([^`]+)`/g)) {
      const name = m[1];
      if (/^[a-z]+\/[a-z0-9-]+$/.test(name) || name === "-" || name === "true") continue; // a skill id, a literal
      const isName = /^[a-z][a-z0-9_]*$/.test(name) && name.length >= 3;
      const isField = /^[a-z][a-z0-9]*(-[a-z0-9]+)+$/.test(name) && !name.endsWith(".jsonl");
      const isFile = /^[A-Za-z0-9._-]+\.jsonl$/.test(name);
      if (!isName && !isField && !isFile) continue;
      if (params.has(name) || tools.has(name) || dynamic.test(name)) continue;
      const src = sources[id];
      // A VPC field name is written in the adapter as one word of a list (VPC_VERSIONS), the others as a quoted key.
      assert.ok(src.includes(`"${name}"`) || (isField && new RegExp(`[ "]${name}[ "]`).test(src)), `${id} names \`${name}\`, which its tools do not write`);
    }
  }
});

test("the five leaves open Use when ... Not for, state the offline boundary and what they do not show, and run a sensitive reader as a secret_output job", () => {
  for (const id of S1B_LEAVES) {
    const { front, body } = read(id);
    assert.match(body.trimStart().split("\n")[0], /^Use when .*\bNot for\b.*\bOffline: /, id);
    assert.match(body, /\*\*Does not show:\*\*/, id);
    assert.match(body, /\*\*Sensitive output:\*\*/, id);
    assert.match(body, /secret_output: true/, id);
    assert.deepEqual(list(front.needs ?? "[]"), ["logs/what-exists"], `${id}: the chain stays inside its budget`);
    assert.ok(list(front.tools ?? "[]").length >= 1, `${id} lists the tool it reads with`);
  }
});

test("aws/s3-access keeps attempted, successful, exposed and transferred apart, and the four sources apart", () => {
  const { front, body } = read("aws/s3-access");
  assert.deepEqual(list(front.tools ?? "[]"), ["cloud_normalise", "cloudtrail_parse"]);
  assert.match(body, /\*\*Four sources, four claims\.\*\*/);
  assert.match(body, /A request absent from one is not absent from the others/);
  assert.match(body, /\*\*Attempted, successful, exposed and transferred are four claims\.\*\*/);
  assert.match(body, /Public exposure is a separate claim, from the policy, ACL and public-access settings in force at the request/);
  assert.match(body, /A transfer needs a successful answer with bytes: compare `bytes_sent` with `object_size`/);
  assert.match(body, /The record does not show what the requester did with it/);
  assert.match(body, /A ranged GET answers part of an object, so a 2xx is not the whole object/);
  assert.match(body, /Count distinct `event_id`/);
  assert.match(body, /never from a default/);
  assert.match(body, /`provider` `aws_s3`/);
  // What `notable` flags is held against the tool's own table, so that the sentence cannot drift from it.
  const notable = /^NOTABLE = \{([\s\S]*?)\n\}/m.exec(toolSource("cloudtrail_parse"))![1];
  for (const call of ["PutBucketPolicy", "PutBucketAcl", "PutBucketPublicAccessBlock"]) assert.ok(notable.includes(`"${call}"`), call);
  assert.ok(!notable.includes("PutBucketLogging"), "PutBucketLogging is not flagged, so the leaf must not say logging calls are");
  assert.match(body, /`notable` flags only policy, ACL and public-access-block writes; find logging calls such as PutBucketLogging with `events`/);
});

test("aws/vpc-flow keeps NODATA and SKIPDATA out of the flows, accepted apart from success, and points to the network pack only conditionally and at an id that exists", () => {
  const { front, body } = read("aws/vpc-flow");
  assert.deepEqual(list(front.tools ?? "[]"), ["cloud_normalise"]);
  assert.match(body, /`NODATA` and `SKIPDATA`\.\*\* `row_kind` is `no_flow_record`/);
  assert.match(body, /NODATA is not a flow of zero/);
  assert.match(body, /an interval beside a SKIPDATA record is not shown to be quiet/);
  assert.match(body, /\*\*Accepted is not application success\.\*\*/);
  assert.match(body, /A record is not a connection/);
  assert.match(body, /Bytes count traffic in a window, not the size of what was taken/);
  assert.match(body, /flow_log_version_from_fields/);
  // The pointer is conditional, in the wording the work card fixes, and the id it names is a skill of the network pack.
  assert.match(body, /`flows\/interpret` if the network pack is loaded; check the run's tool inventory/);
  assert.ok(readFileSync(join(ROOT, "packs", "network-forensics", "skills", "flows", "interpret.md"), "utf8").startsWith("---\nid: flows/interpret\n"), "the id exists");
  // A mentions entry is a tool or a program (pack-links); the one tool of the other pack the leaf names is mentioned, never listed, and never depended on.
  assert.deepEqual(list(front.mentions ?? "[]"), ["network_log_summary"]);
  assert.match(body, /`network_log_summary` does not read this schema/);
  assert.ok(!/flow_reader|pcap_summary|nfdump/.test(body), "no other tool of the network pack is named");
  const pack = JSON.parse(readFileSync(join(ROOT, "packs", "cloud-forensics", "pack.json"), "utf8"));
  assert.ok(!(pack.depends as string[]).some((d) => d.startsWith("network-forensics")), "the cloud pack does not depend on the network pack");
});

test("azure/activity-resource-logs keeps the three planes apart, the scope from the resource, a start from its completion, and says its names are unchecked against Azure documentation", () => {
  const { front, body } = read("azure/activity-resource-logs");
  assert.deepEqual(list(front.tools ?? "[]"), ["cloud_normalise"]);
  assert.match(body, /\*\*Three planes, three sources\.\*\*/);
  assert.match(body, /this tool has no adapter for them/);
  assert.match(body, /A control-plane row does not show data-plane access, and a missing data-plane log does not show none/);
  assert.match(body, /`resource` and `authorization_scope` are separate fields printed as written/);
  assert.match(body, /A Started or Accepted row has `outcome` `unknown`, never success/);
  assert.match(body, /its completion is another row with the same `correlation_id`, and rows are never merged/);
  assert.match(body, /A start with no completion in the set is an open question, not a failure/);
  assert.match(body, /not checked against Azure documentation/);
  assert.match(body, /\*\*History of diagnostic settings\.\*\*/);
  assert.match(body, /entra\/directory-audit/);
});

test("aws/guardduty keeps updates apart from incidents, takes suppression and detector state from nowhere it is not recorded, and corroborates against supplied raw evidence", () => {
  const { front, body } = read("aws/guardduty");
  assert.deepEqual(list(front.tools ?? "[]"), ["guardduty_findings"]);
  assert.deepEqual(list(front.mentions ?? "[]"), ["cloudtrail_parse"]);
  assert.match(body, /\*\*Updates are not incidents\.\*\*/);
  assert.match(body, /so records are not occurrences/);
  assert.match(body, /read the versions, not only the latest/);
  assert.match(body, /Which finding ids make one incident is your judgement/);
  assert.match(body, /`suppression` says the file cannot tell which/);
  assert.match(body, /Whether the detector was enabled, and in which Regions, is not in a finding/);
  assert.match(body, /no finding is not no activity/);
  assert.match(body, /Archived and suppressed findings are not exported by default/);
  assert.match(body, /\*\*Corroborate against the supplied raw evidence\.\*\*/);
  assert.match(body, /raw evidence with no finding is not a missed detection/);
  assert.match(body, /are untrusted/);
});

test("m365/mailbox-persistence keeps configuration, authorisation, execution and delivery apart, agrees with the unified audit log leaf, and claims no reader that does not exist", () => {
  const { front, body } = read("m365/mailbox-persistence");
  assert.deepEqual(list(front.tools ?? "[]"), ["ual_parse", "cloud_normalise"]);
  assert.match(body, /Configuration is not effective authorisation, which is not execution, which is not delivery/);
  for (const step of ["Configuration", "Authorisation change", "Execution", "Delivery"]) assert.match(body, new RegExp(`\\*\\*${step}\\.\\*\\*`));
  assert.match(body, /`MailItemsAccessed` records access to items, not a rule firing/);
  assert.match(body, /No reader for message trace is here/);
  assert.match(body, /`m365\/unified-audit-log` says there is no reader here for mailbox configuration or message delivery/);
  // The unified audit log leaf says the same, in its own sentence, which this package leaves as it is.
  assert.match(read("m365/unified-audit-log").text, /Not for sign-in analysis \(`entra\/signins`\), mailbox configuration, or message delivery \(no reader here\)/);
  assert.match(body, /Transport controls\*\* act on mail in flight with no mailbox rule/);
  assert.match(body, /`identity\/grants`/);
  assert.doesNotMatch(body, /message_trace|message trace reader|settings reader/i, "no tool of this pack reads a settings snapshot or a message trace");
});

test("the router names the five new leaves, the README says twenty skills and the pack counts them", () => {
  const router = readFileSync(join(SKILLS, "cloud", "router.md"), "utf8");
  for (const id of S1B_LEAVES) assert.match(router, new RegExp(`\`${id}\` `), `${id} is in the router`);
  const readme = readFileSync(join(ROOT, "packs", "cloud-forensics", "README.md"), "utf8");
  assert.match(readme, /\*\*Twenty skills\*\*/);
  assert.match(readme, /it names the other nineteen/);
  for (const id of S1B_LEAVES) assert.ok(readme.includes(`\`${id}\``), `${id} is in the README`);
  assert.equal(IDS.length, 19);
});

// ---- The router: the one entry a run shows for this pack when its index is over the run's budget. ----

routerChecks({ pack: "cloud-forensics", router: ROUTER, before: IDS, profiles: ["full"] });
