/**
 * evtx_query and evtx_carve: the withholding boundary against random canaries planted in the slots the tools print (an EventData value, an
 * EventData name, the channel, the provider, the computer and the XML itself), the share printed whole asserted against the documented rate, the
 * shapes the boundary does not claim asserted to be printed, a `contains` that cannot be used as an oracle on withheld text, the backstop shown
 * to fire on every write path with the sanitiser removed, the values file held to a job run as secret output, and real event strings shown
 * unchanged.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { test } from "node:test";
import { runPy, withCwd } from "./tool-library-harness.ts";
import { WIN, body, everyFileUnder, failed, stubModule, tool } from "./windows-pack-harness.ts";
import { EVTX_CARVE_STUB, eventXml, evtxChunk, evtxFileHeader } from "./windows-stub-evtx.ts";
import { SHAPES, leaked, plant, prng, type Canary, type Shape } from "./windows-canary.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const N = 300;
const BOUND: Record<string, number> = {
  "token prefix families": 1, JWT: 1, "PEM private key": 1, "named secrets and user-info": 1, "invisible splits": 1,
  "AWS-shaped and base64 keys": 6, "generic random token": 3,
};
const NAMES = ["ghp", "akia", "glpat", "jwt", "aws_secret40", "b64_20", "pem", "pw_assign", "userinfo_at", "zw_split", "random_base62_24", "plain_password", "passphrase", "uuid_secret"];
const shapes = NAMES.map((n) => SHAPES.find((s) => s.name === n)!);
const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const attrOk = (s: Shape): boolean => !/["<>&\u0000]/.test(s.make(() => 0.3).text) && s.name !== "pw_assign";

/** A log (header + chunks) and the same chunks as a blob, with the stand-in library. */
async function put(cwd: string, records: Array<{ number: number; xml: string }>): Promise<Record<string, string>> {
  const stubs = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_CARVE_STUB });
  const chunks: Buffer[] = [];
  for (let i = 0; i < records.length; i += 40) chunks.push(evtxChunk(records.slice(i, i + 40)));
  await writeFile(join(cwd, "work", "Security.evtx"), Buffer.concat([evtxFileHeader(chunks.length, records.length + 1), ...chunks]));
  await writeFile(join(cwd, "work", "Security.evtx.inject.json"), "{}");
  await writeFile(join(cwd, "work", "blob.bin"), Buffer.concat(chunks));
  return stubs;
}

async function reachable(cwd: string, skip: (f: string) => boolean = () => false): Promise<string[]> {
  const out: string[] = [];
  for (const f of await everyFileUnder(cwd)) {
    if (f.endsWith("Security.evtx") || f.endsWith("blob.bin") || f.endsWith(".inject.json") || f.includes("/pystub/") || skip(f)) continue;
    out.push((await readFile(f)).toString("utf8"));
  }
  return out;
}

const rate = (canaries: Canary[], outputs: string[]): number => (100 * leaked(canaries, outputs)) / canaries.length;
function check(shape: Shape, r: number, where: string): void {
  if (shape.residual) assert.ok(r >= 90, `${shape.name}: a residual shape is printed in ${where} (${r}%)`);
  else assert.ok(r <= BOUND[shape.family], `${shape.name}: ${r}% printed whole in ${where}, bound ${BOUND[shape.family]}%`);
}

for (const shape of shapes) {
  test(`evtx_query and evtx_carve: ${shape.name} in an EventData value, an EventData name, a provider, a computer and the XML`, async () => {
    const canaries = plant(shape, N, 31).map((c) => ({ ...c, text: c.text.replace(/\u0000/g, "") }));
    await withCwd(async (cwd) => {
      const records = canaries.map((c, i) => ({
        number: i + 1,
        xml: eventXml({ eid: 4688, rec: i + 1, time: "2026-09-01 10:00:00.000000", data: [["Payload", esc(c.text)], ["CommandLine", esc(c.text)], ...(attrOk(shape) ? [[`F${i}_${c.text}`, "x"] as [string, string]] : [])] })
          .replace("Microsoft-Windows-Security-Auditing", "Prov-" + (attrOk(shape) ? c.text : "x")).replace("<Computer>WS01</Computer>", `<Computer>${attrOk(shape) ? c.text : "WS01"}</Computer>`),
      }));
      const env = await put(cwd, records);
      const query = await tool("evtx_query", cwd, { path: "work/Security.evtx", limit: 5 }, env);
      const q = body<Answer>(query);
      assert.ok(q.boundary);
      check(shape, rate(canaries, [query.stdout, query.stderr, ...(await reachable(cwd, (f) => f.endsWith("blob.bin")))]), "evtx_query output or its result file");
      const carve = await tool("evtx_carve", cwd, { path: "work/blob.bin", limit: 5 }, env);
      body<Answer>(carve);
      check(shape, rate(canaries, [carve.stdout, carve.stderr, ...(await reachable(cwd))]), "evtx_carve output or its result file");
    });
  });
}

test("evtx_query and evtx_carve: contains is looked for in what is shown, so a needle cannot be used to test a withheld value, and the answer says what it could not see", async () => {
  await withCwd(async (cwd) => {
    const secret = "AKIAQWERTYUIOPASDFGH";
    const records = [{ number: 1, xml: eventXml({ eid: 4688, rec: 1, data: [["CommandLine", `aws configure set aws_access_key_id ${secret} --profile p`]] }) }, { number: 2, xml: eventXml({ eid: 4688, rec: 2, data: [["CommandLine", "whoami /all"]] }) }];
    const matched = (a: Answer): number => a.events_matched ?? a.record_count;
    const blind = (a: Answer): number => a.contains_blind_records;
    for (const [name, p] of [["evtx_query", "work/Security.evtx"], ["evtx_carve", "work/blob.bin"]] as const) {
      const env = await put(cwd, records);
      const hit = body<Answer>(await tool(name, cwd, { path: p, contains: secret.slice(0, 12) }, env));
      assert.equal(matched(hit), 0, `${name}: a needle that is part of a withheld value matches nothing`);
      // ... and the answer does not say "complete, none": one record was not matched and has text withheld in it
      assert.equal(blind(hit), 1, `${name}: the record whose text is withheld is counted`);
      assert.equal(hit.status, "partial", name);
      assert.match(JSON.stringify(hit.problems ?? hit.problem_page ?? hit), /contains looks only in the text the answer prints/, name);
      // the count does not depend on the needle: it is no way to test a guess
      const other = body<Answer>(await tool(name, cwd, { path: p, contains: "no-such-needle-at-all" }, env));
      assert.equal(blind(other), 1, `${name}: the same count for another needle`);
      assert.equal(matched(other), 0);
      // the shown text is searchable; the record with withheld text did not match, so it is still counted
      const shown = body<Answer>(await tool(name, cwd, { path: p, contains: "aws_access_key_id" }, env));
      assert.equal(matched(shown), 1, `${name}: the shown text is searchable`);
      assert.equal(blind(shown), 0, `${name}: the record that matched is not blind`);
      assert.equal(shown.status, "complete", name);
      // text nowhere withheld: an absence is an absence
      const none = body<Answer>(await tool(name, cwd, { path: p, contains: "whoami", event_ids: [4688] }, env));
      assert.equal(matched(none), 1);
      const nothingHidden = await put(cwd, [{ number: 1, xml: eventXml({ eid: 4688, rec: 1, data: [["CommandLine", "whoami /all"]] }) }]);
      const absent = body<Answer>(await tool(name, cwd, { path: p, contains: "zzz-not-there" }, nothingHidden));
      assert.equal(matched(absent), 0);
      assert.equal(blind(absent), 0);
      assert.equal(absent.status, "complete", `${name}: nothing is withheld, so none is none`);
    }
  });
});

/** Rows (JSON lines) of every file a run left that is not the log itself. */
async function rowsOf(cwd: string): Promise<Answer[]> {
  const rows: Answer[] = [];
  for (const text of await reachable(cwd)) {
    for (const line of text.split("\n")) {
      if (!line.startsWith("{")) continue;
      try { rows.push(JSON.parse(line) as Answer); } catch { /* an answer printed with indent, not a row */ }
    }
  }
  return rows;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

test("evtx_query and evtx_carve: contains reads the text the answer prints, so a true piece of a secret that only the backstop replaces cannot be told from a wrong needle", async () => {
  await withCwd(async (cwd) => {
    // the layers show a 40-character base64 key in a command line; the backstop replaces it (about 0.3% of random keys): find some with the tool itself
    const rnd = prng(77);
    const candidates = Array.from({ length: 2400 }, () => Array.from({ length: 40 }, () => B64[Math.floor(rnd() * 64)]).join(""));
    const command = (c: string): string => `C:\\tool.exe --key ${c}`;
    const probeEnv = await put(cwd, candidates.map((c, i) => ({ number: i + 1, xml: eventXml({ eid: 4688, rec: i + 1, data: [["CommandLine", command(c)]] }) })));
    const probe = await tool("evtx_query", cwd, { path: "work/Security.evtx", limit: 1 }, probeEnv);
    body<Answer>(probe);
    const backstopped = new Set<number>();
    for (const row of await rowsOf(cwd)) {
      const shown = (row.data as Answer | undefined)?.CommandLine;
      if (typeof shown === "string" && shown.includes("backstop: a random-looking run") && typeof row.record_id === "number") backstopped.add(row.record_id);
    }
    const found = candidates.map((c, i) => ({ c, rec: i + 1 })).filter((x) => backstopped.has(x.rec)).slice(0, 2);
    assert.ok(found.length >= 1, "the planted keys include one that only the backstop replaces");
    const matched = (a: Answer): number => a.events_matched ?? a.record_count;
    for (const { c } of found) {
      for (const [name, p] of [["evtx_query", "work/Security.evtx"], ["evtx_carve", "work/blob.bin"]] as const) {
        const env = await put(cwd, [{ number: 1, xml: eventXml({ eid: 4688, rec: 1, data: [["CommandLine", command(c)]] }) }, { number: 2, xml: eventXml({ eid: 4688, rec: 2, data: [["CommandLine", "whoami /all"]] }) }]);
        const wrong = Array.from({ length: 10 }, () => B64[Math.floor(rnd() * 64)]).join("");
        const needles = [c.slice(0, 10), c.slice(20, 30), c.slice(30), c, wrong, c.slice(0, 9) + (c[9] === "x" ? "y" : "x"), "tool.exe"];
        const answers: Array<[number, string, number, number]> = [];
        for (const contains of needles) {
          const run = await tool(name, cwd, { path: p, contains }, env);
          const a = body<Answer>(run);
          assert.ok(!(await reachable(cwd, (f) => f.endsWith("blob.bin"))).concat([run.stdout, run.stderr]).some((t) => t.includes(c.slice(0, 12))), `${name}: the secret is not printed (needle ${contains.length} characters)`);
          answers.push([matched(a), String(a.status), a.contains_blind_records, (a.problems ?? []).length]);
        }
        assert.deepEqual(new Set(answers.map((a) => JSON.stringify(a))).size, 1, `${name}: a true piece, the whole secret and a wrong needle give different answers: ${JSON.stringify(answers)}`);
        assert.equal(answers[0][0], 0, `${name}: nothing matches in text that is replaced`);
        assert.equal(answers[0][2], 1, `${name}: the record is counted as one the needle may be in`);
      }
    }
  });
});

test("evtx_query and evtx_carve: RelatedActivityID=\"\", EventSourceName= and processorArchitecture= do not make a record partial, and a process id is not taken for a SID", async () => {
  await withCwd(async (cwd) => {
    const token = "gh" + "p_" + Array.from({ length: 36 }, (_, i) => B64[(i * 7 + 3) % 62]).join("");
    const base = eventXml({ eid: 4688, rec: 1, data: [["CommandLine", `run ${token} now`], ["ProcessId", "0x0000000000000124"], ["NewProcessId", "1160"], ["ParentProcessId", "0x1d4"], ["ClientProcessId", "4"],
      ["TargetUserSid", "S-1-5-21-1004336348-1177238915-682003330-1001"], ["SubjectUserSid", "S-1-5-18"], ["LogonId", "0x3E7"], ["EventSourceName", "Service Control Manager"], ["NumberOfGPOsDownloaded", "3"]] });
    const xml = base.replace("<Channel>", `<Correlation ActivityID="{8F1C0B6E-6C3A-4C7B-9A57-2B7B0F1E4A10}" RelatedActivityID=""></Correlation><Channel>`).replace("</EventData>", `</EventData><RenderingInfo processorArchitecture="amd64" EventSourceName=""></RenderingInfo>`);
    for (const [name, p] of [["evtx_query", "work/Security.evtx"], ["evtx_carve", "work/blob.bin"]] as const) {
      const env = await put(cwd, [{ number: 1, xml }]);
      const run = await tool(name, cwd, { path: p, limit: 5 }, env);
      const a = body<Answer>(run);
      assert.equal(a.boundary.strings_replaced_by_the_backstop, 0, `${name}: nothing is replaced by the backstop`);
      assert.equal(a.status, "complete", `${name}: ${a.status_basis}`);
      const row = (await rowsOf(cwd)).find((r) => typeof r.xml === "string" && r.xml.includes("Correlation"));
      assert.ok(row, `${name}: the record is in the result file`);
      assert.ok((row!.xml as string).includes('RelatedActivityID=""') && (row!.xml as string).includes('processorArchitecture="amd64"'), `${name}: the attributes are kept in the XML`);
      assert.ok(!(row!.xml as string).includes(token), `${name}: the token in the same record is still withheld`);
      const data = (row!.data ?? {}) as Answer;
      for (const [k, v] of [["ProcessId", "0x0000000000000124"], ["NewProcessId", "1160"], ["ParentProcessId", "0x1d4"], ["ClientProcessId", "4"], ["TargetUserSid", "S-1-5-21-1004336348-1177238915-682003330-1001"],
        ["SubjectUserSid", "S-1-5-18"], ["LogonId", "0x3E7"], ["NumberOfGPOsDownloaded", "3"]] as const) assert.equal(data[k], v, `${name}: ${k} is shown as it is`);
    }
  });
});

test("evtx_query and evtx_carve: with the sanitiser taken out the backstop still replaces the shapes it claims, on the answer and on the result file", async () => {
  await withCwd(async (cwd) => {
    const families = ["token prefix families", "JWT", "PEM private key", "named secrets and user-info"];
    for (const name of ["evtx_query", "evtx_carve"]) {
      const src = (await readFile(join(WIN, name, "run.py"), "utf8")).replace("    out = _show(str(s), kind, field)\n", "    out = str(s)\n");
      assert.ok(src.includes("    out = str(s)\n"), name);
      await mkdir(join(cwd, "copy", name), { recursive: true });
      await writeFile(join(cwd, "copy", name, "run.py"), src);
      for (const shape of shapes.filter((s) => families.includes(s.family) && s.name !== "userinfo_at" && s.name !== "zw_split")) {
        const canaries = plant(shape, 100, 9).map((c) => ({ ...c, text: c.text.replace(/\u0000/g, "") }));
        const env = await put(cwd, canaries.map((c, i) => ({ number: i + 1, xml: eventXml({ eid: 1, rec: i + 1, data: [["CommandLine", esc(c.text)]] }) })));
        const run = await runPy(join(cwd, "copy", name, "run.py"), cwd, { path: name === "evtx_query" ? "work/Security.evtx" : "work/blob.bin", limit: 1 }, undefined, { ...env, AGENT_ID: "s1" });
        const out = JSON.parse(run.stdout) as Answer;
        const r = rate(canaries, [run.stdout, run.stderr, ...(await reachable(cwd, (f) => f.includes("/copy/")))]);
        assert.ok(r <= 2, `${name}/${shape.name}: ${r}% printed with the sanitiser removed`);
        assert.equal(out.status, "partial", `${name}/${shape.name}`);
        assert.ok(out.boundary.strings_replaced_by_the_backstop > 0, `${name}/${shape.name}`);
      }
    }
  });
});

test("evtx_query and evtx_carve: write_values is held to a job run as secret output, and the originals go to a 0600 file only", async () => {
  await withCwd(async (cwd) => {
    const canaries = plant(SHAPES.find((s) => s.name === "ghp")!, 12, 3);
    const env = await put(cwd, canaries.map((c, i) => ({ number: i + 1, xml: eventXml({ eid: 1, rec: i + 1, data: [["CommandLine", c.text]] }) })));
    for (const [name, p] of [["evtx_query", "work/Security.evtx"], ["evtx_carve", "work/blob.bin"]] as const) {
      assert.match(failed(await tool(name, cwd, { path: p, write_values: true }, env)).error, /write_values is refused/, name);
      const out = join(cwd, "out-" + name);
      await mkdir(out, { recursive: true });
      const job = { ...env, JOB_ID: "j1", OUT: out };
      assert.match(failed(await tool(name, cwd, { path: p, write_values: true }, job)).error, /write_values is refused/, name);
      assert.deepEqual(await readdir(out), [], `${name}: nothing was written`);
      const run = await tool(name, cwd, { path: p, write_values: true }, { ...job, SECRET_OUTPUT: "1" });
      const answer = body<Answer>(run);
      const file = join(out, `${name}-values.jsonl`);
      assert.equal((await stat(file)).mode & 0o777, 0o600);
      const originals = (await readFile(file, "utf8")).trim().split("\n").map((l) => (JSON.parse(l) as Answer).value as string);
      assert.ok(canaries.every((c) => originals.some((o) => o.includes(c.cores[0]))), name);
      assert.equal(leaked(canaries, [run.stdout, run.stderr, ...(await reachable(cwd, (f) => f.endsWith("-values.jsonl")))]), 0, name);
      assert.equal(answer.boundary.values.written, canaries.length);
    }
  });
});

/** Real strings from event logs (the EVTX attack-sample logs): none may be withheld. */
const READABLE = [
  ["Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"], ["ParentImage", "C:\\Windows\\System32\\cmd.exe"],
  ["CommandLine", "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\bob\\Desktop\\collect.ps1 -OutDir \"C:\\Temp\\out\""],
  ["User", "WIN-3QKR5M2L8SD\\Administrator"], ["ProcessGuid", "{A23EAE89-BD56-5903-0000-0010E9D95E00}"], ["UserSid", "S-1-5-21-1004336348-1177238915-682003330-500"],
  ["Hashes", "MD5=2C1AC7C0B9DDC2C8A6FF4F4BB2A57A8C,SHA256=9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08,IMPHASH=C9F2F2B5BA2E9A0F8A2C0C7F5B2C3A11"],
  ["TargetObject", "HKU\\S-1-5-21-1004336348-1177238915-682003330-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive"], ["SourceIp", "10.0.2.15"],
  ["UtcTime", "2017-04-28 22:08:33.016"], ["Description", "Windows PowerShell"], ["Company", "Microsoft Corporation"],
] as Array<[string, string]>;

test("evtx_query and evtx_carve: event data an examiner must be able to read comes through unchanged", async () => {
  await withCwd(async (cwd) => {
    const env = await put(cwd, [{ number: 1, xml: eventXml({ eid: 1, rec: 1, time: "2017-04-28 22:08:33.016000", channel: "Microsoft-Windows-Bits-Client/Operational", data: READABLE.map(([k, v]) => [k, esc(v)] as [string, string]) }).replace("Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Sysmon") }]);
    const q = body<Answer>(await tool("evtx_query", cwd, { path: "work/Security.evtx" }, env));
    assert.deepEqual(q.events[0].data, Object.fromEntries(READABLE));
    assert.equal(q.events[0].provider, "Microsoft-Windows-Sysmon");
    assert.equal(q.events[0].channel, "Microsoft-Windows-Bits-Client/Operational");
    assert.equal(q.boundary.strings_withheld, 0);
    const c = body<Answer>(await tool("evtx_carve", cwd, { path: "work/blob.bin" }, env));
    assert.deepEqual(c.records[0].data, Object.fromEntries(READABLE));
    assert.equal(c.boundary.strings_withheld, 0);
  });
});

test("the windows-forensics tools that carry the SHARED BOUNDARY block carry it identically", async () => {
  const { readdir: ls } = await import("node:fs/promises");
  const begin = "# BEGIN SHARED BOUNDARY";
  const end = "# END SHARED BOUNDARY";
  const found: Record<string, string> = {};
  for (const name of await ls(WIN)) {
    const text = await readFile(join(WIN, name, "run.py"), "utf8").catch(() => "");
    if (text.includes(begin)) found[name] = text.slice(text.indexOf(begin), text.indexOf(end) + end.length);
  }
  assert.ok(Object.keys(found).length >= 1);
  assert.equal(new Set(Object.values(found).map((b) => createHash("sha256").update(b).digest("hex"))).size, 1, `the block differs between ${Object.keys(found).join(", ")}`);
});
