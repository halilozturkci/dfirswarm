/**
 * The protocol pieces the improvement plan added after the first forensic
 * run: the ledger, implicit claims for shell writers, the per-agent cap, the
 * harness-owned catalog/ledger/toolbox paths, and the command-word helper
 * the forge hint counts with. No model, no Herdr, no keys.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { commandNamesPath, isPeersScratch, leadingCommand } from "../extensions/agent-swarm.ts";
import {
  LEDGER_ENTRIES,
  LEDGER_MD,
  agentPressure,
  findNearDuplicate,
  tidyName,
  normalizeBudget,
  claimFile,
  createContext,
  guardWrite,
  initSandbox,
  isOwnScratch,
  isProtectedPath,
  listClaims,
  listForgedTools,
  listLedger,
  readLedger,
  recordEntry,
  renderLedger,
  validateToolSpec,
  type BudgetRecord,
} from "../extensions/protocol.ts";

async function sandbox(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "plan-"));
  await initSandbox(root, { reset: true, agentIds: ["a00", "a01"] });
  return root;
}

test("ledger: a record is validated, deduped across authors and rendered", async () => {
  const root = await sandbox();
  try {
    const a = createContext(root, "a00");
    const b = createContext(root, "a01");

    const badKind = await recordEntry(a, { kind: "rumour", value: "x" });
    assert.ok(!badKind.ok && /kind must be one of/.test(badKind.reason));
    const noTs = await recordEntry(a, { kind: "event", value: "user added" });
    assert.ok(!noTs.ok && /needs a ts/.test(noTs.reason));
    const badTs = await recordEntry(a, { kind: "event", value: "user added", ts: "yesterday" });
    assert.ok(!badTs.ok && /ISO 8601/.test(badTs.reason));
    const badConfidence = await recordEntry(a, { kind: "finding", value: "web shell", confidence: "sure" });
    assert.ok(!badConfidence.ok && /confidence must be/.test(badConfidence.reason));
    const empty = await recordEntry(a, { kind: "ioc", value: "   " });
    assert.ok(!empty.ok && /value is required/.test(empty.reason));
    // Provenance is not optional: an entry nobody can check is not a record,
    // and the corpus says this costs a working run nothing — 1501 of 1501
    // entries across fifteen cases already carried both fields.
    const noSource = await recordEntry(a, { kind: "ioc", value: "192.0.2.7", evidence: "netscan row 4" });
    assert.ok(!noSource.ok && /source is required/.test(noSource.reason));
    const noEvidence = await recordEntry(a, { kind: "ioc", value: "192.0.2.7", source: "netscan" });
    assert.ok(!noEvidence.ok && /evidence is required/.test(noEvidence.reason));

    const first = await recordEntry(a, {
      kind: "event",
      value: "Account hacker created",
      ts: "2015-09-02T09:05:00Z",
      source: "SAM",
      evidence: "regipy: SAM\\Domains\\Account\\Users\\Names\\hacker",
    });
    assert.ok(first.ok && !first.merged && first.entry.seq === 1 && first.entry.by === "a00");
    // the same event from a peer, with a different time spelling, merges into one row
    const again = await recordEntry(b, { kind: "event", value: "Account hacker created", ts: "2015-09-02T09:05:00.000Z", source: "SAM", evidence: "same key, read independently" });
    assert.ok(again.ok && again.merged && again.total === 1);
    assert.deepEqual(again.entry.authors, ["a00", "a01"]);
    assert.equal(again.entry.evidence, "regipy: SAM\\Domains\\Account\\Users\\Names\\hacker", "the first evidence is kept");

    const ioc = await recordEntry(b, { kind: "ioc", value: "192.168.56.102", source: "netscan", evidence: "nmap -sn line 7", confidence: "high" });
    assert.ok(ioc.ok && ioc.entry.seq === 2);
    const later = await recordEntry(a, { kind: "event", value: "Shell dropped", ts: "2015-09-02T08:00:00Z", source: "work/webroot", evidence: "inode 126755" });
    assert.ok(later.ok && later.entry.seq === 3);
    const finding = await recordEntry(a, { kind: "finding", value: "The box was breached through the web app", source: "work/notes.md", evidence: "the shell precedes every logon", confidence: "medium" });
    assert.ok(finding.ok);

    const entries = await readLedger(root);
    assert.equal(entries.length, 4);
    const lines = (await readFile(join(root, LEDGER_ENTRIES), "utf8")).trim().split("\n");
    assert.equal(lines.length, 4, "entries.jsonl holds one line per entry");

    const md = await readFile(join(root, LEDGER_MD), "utf8");
    assert.match(md, /4 entries: 2 events, 1 indicators, 1 findings/);
    const timeline = md.slice(md.indexOf("## Timeline"), md.indexOf("## Indicators"));
    assert.ok(timeline.indexOf("Shell dropped") < timeline.indexOf("Account hacker created"), "the timeline is in time order, not record order");
    assert.match(timeline, /a00, a01/);
    assert.match(md, /\| 192\.168\.56\.102 \| netscan \|.*\| high \| a01 \|/);
    assert.match(md, /\*\*#4\*\* The box was breached through the web app _\(medium\)_/);

    const events = await listLedger(root, { kind: "event" });
    assert.deepEqual(events.map((e) => e.seq), [1, 3]);
    const last = await listLedger(root, { limit: 1 });
    assert.deepEqual(last.map((e) => e.seq), [4]);
    assert.equal((await renderLedger(root)).length, md.length, "rendering again from disk gives the same document");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("ledger, catalog, toolbox and the names file are the harness's own paths", () => {
  for (const p of ["ledger/entries.jsonl", "ledger/ledger.md", "catalog/README.md", "catalog/disk/p2048/bodyfile.txt", "toolbox.json", "./TOOLBOX.json", "names.json", "NAMES.json", "./NAMES.JSON"]) {
    assert.ok(isProtectedPath(p), `${p} should be protected`);
  }
  for (const p of ["work/ledger.md", "work/catalog.txt", "work/a00/toolbox.json"]) {
    assert.ok(!isProtectedPath(p), `${p} is the agents' own`);
  }
});

test("implicit claims: a shell writer's lease is marked as taken by the harness", async () => {
  const root = await sandbox();
  try {
    const ctx = createContext(root, "a00");
    const explicit = await claimFile(ctx, "work/report.md", { reason: "assembling the report", seconds: 60 });
    assert.equal(explicit.ok, true);
    const implicit = await claimFile(ctx, "work/a00/pslist.txt", { reason: "bash write", seconds: 60, implicit: true });
    assert.equal(implicit.ok, true);

    const claims = await listClaims(root);
    const byPath = new Map(claims.map((c) => [c.path, c]));
    assert.equal(byPath.get("work/report.md")?.implicit, undefined, "an asked-for claim carries no implicit flag");
    assert.equal(byPath.get("work/a00/pslist.txt")?.implicit, true, "the harness's own claim says so");
    assert.equal(byPath.get("work/a00/pslist.txt")?.reason, "bash write");

    // a peer cannot take the implicitly held path either
    const peer = await claimFile(createContext(root, "a01"), "work/a00/pslist.txt", { reason: "mine now", seconds: 60 });
    assert.equal(peer.ok, false);

    // the guard treats work/<id>/ as the writer's own: the lease is taken, not demanded
    const own = await guardWrite(ctx, "work/a00/notes.md");
    assert.equal(own.ok, true, JSON.stringify(own));
    const ownLock = (await listClaims(root)).find((c) => c.path === "work/a00/notes.md");
    assert.equal(ownLock?.implicit, true);
    assert.equal(ownLock?.reason, "own scratch");
    const notMine = await guardWrite(createContext(root, "a01"), "work/a00/other.md");
    assert.equal(notMine.ok, false, "a peer's scratch directory is not yours");
    const shared = await guardWrite(createContext(root, "a01"), "work/timeline.md");
    assert.equal(shared.ok, false, "a shared file still needs a claim");
    assert.ok(isOwnScratch("work/a00/x", "a00") && !isOwnScratch("work/a00x/x", "a00") && !isOwnScratch("work/a00", "a00"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("own scratch: a peer cannot lease a path in it and lock its owner out", async () => {
  const root = await sandbox();
  try {
    const owner = createContext(root, "a00");
    const peer = createContext(root, "a01");
    for (const path of ["work/a00/notes.md", "work/extracted/a00/SAM", "work/quarantine/a00/dropper.exe"]) {
      const taken = await claimFile(peer, path, { reason: "mine now", seconds: 600 });
      assert.equal(taken.ok, false, `a peer leased ${path}`);
      assert.equal("conflict" in taken && taken.owner, "a00", "the refusal names the directory's owner");
      const own = await guardWrite(owner, path);
      assert.equal(own.ok, true, `the owner is refused in its own scratch: ${JSON.stringify(own)}`);
    }
    // a directory under work/ named for nobody on the team is shared, as before
    assert.equal((await claimFile(peer, "work/timeline/day1.md", { reason: "timeline" })).ok, true);
    // the operator restoring a revision is not a peer
    assert.equal((await claimFile(createContext(root, "operator"), "work/a00/other.md", { reason: "restore" })).ok, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("per-agent cap: pressure is per seat and only when a cap is set", () => {
  const base: BudgetRecord = {
    cap_usd: 40,
    spent_usd: 5,
    tokens: 0,
    calls: 0,
    wall_clock_minutes: 60,
    started_at: "2026-01-01T00:00:00Z",
    source: "test",
    hard_kill: false,
    cap_steer_sent: false,
    agents: {
      a00: { spent_usd: 3.5, tokens: 0, calls: 0, input: 0, output: 0, cache_read: 0, cache_write: 0 },
      a01: { spent_usd: 1.5, tokens: 0, calls: 0, input: 0, output: 0, cache_read: 0, cache_write: 0 },
    },
  } as BudgetRecord;
  assert.deepEqual(agentPressure(base, "a00"), { over: false, spent_usd: 3.5, cap_usd: 0 });
  const capped = { ...base, cap_per_agent_usd: 3 };
  assert.deepEqual(agentPressure(capped, "a00"), { over: true, spent_usd: 3.5, cap_usd: 3 });
  assert.deepEqual(agentPressure(capped, "a01"), { over: false, spent_usd: 1.5, cap_usd: 3 });
  assert.deepEqual(agentPressure(capped, "a99"), { over: false, spent_usd: 0, cap_usd: 3 }, "an agent with no spend yet is under");
  const rebuilt = normalizeBudget({ ...capped } as Partial<BudgetRecord>);
  assert.equal(rebuilt.cap_per_agent_usd, 3, "the per-agent cap survives a rebuild of the record");
  assert.deepEqual(agentPressure(rebuilt, "a00"), { over: true, spent_usd: 3.5, cap_usd: 3 });
  assert.equal(
    normalizeBudget({ ...base } as Partial<BudgetRecord>).cap_per_agent_usd,
    undefined,
    "a swarm without a per-agent cap does not grow one",
  );
});

test("an agent's corner of the extraction root is its own", () => {
  // Four seats pulling the same hives into one work/extracted/ is what made
  // real conflicts in the later cases: WebCacheV01.dat, System.evtx and two
  // PowerShell logs inside forty seconds on the Azure run.
  assert.equal(isOwnScratch("work/a00/notes.md", "a00"), true);
  assert.equal(isOwnScratch("work/extracted/a00/SAM", "a00"), true, "its own corner");
  assert.equal(isOwnScratch("work/quarantine/a00/dropper.exe", "a00"), true);
  assert.equal(isOwnScratch("work/extracted/a01/SAM", "a00"), false, "a peer's corner is the peer's");
  assert.equal(isOwnScratch("work/extracted/SAM", "a00"), false, "the shared root belongs to nobody");
  assert.equal(isOwnScratch("work/report.md", "a00"), false);
  assert.equal(isOwnScratch("work/extracted/a00/SAM", ""), false, "an agent with no id owns nothing");
});

test("a name is one line, and the harness never invents one", () => {
  assert.equal(tidyName("crypto and keys"), "crypto and keys");
  assert.equal(tidyName("  disk\n  triage  "), "disk triage", "a name is one line");
  assert.equal(tidyName("`registry`"), "registry", "no markup on a board");
  assert.equal(tidyName(undefined), undefined);
  assert.equal(tidyName("   "), undefined, "an empty name is no name");
  const long = tidyName("the seat that reads every event log on the image twice");
  assert.ok(long && long.length <= 32, "a name is short enough to sit beside an id");
});

test("make_tool sees the tool a peer already forged under another name", () => {
  const existing = [
    {
      name: "catalog_grep",
      description: "Search the catalog file list for a pattern and print matching paths",
      params: { pattern: { type: "string", required: true } },
      runtime: "python3",
      entry: "run.py",
      timeout_seconds: 30,
      by: "s1a2b02",
      at: "2026-09-18T14:14:41.000Z",
      version: 1,
      sha256: "deadbeef",
    },
  ] as const;

  // The Azure run forged these two six seconds apart, the same capability twice.
  const twin = findNearDuplicate(
    { name: "catalog_search", description: "Search the catalog file list for a pattern, printing every matching path", runtime: "python3", params: { pattern: {} } },
    existing as never,
  );
  assert.equal(twin?.name, "catalog_grep");

  // A different runtime is a different tool, whatever it is called.
  assert.equal(
    findNearDuplicate(
      { name: "catalog_search", description: "Search the catalog file list for a pattern, printing every matching path", runtime: "bash", params: { pattern: {} } },
      existing as never,
    ),
    undefined,
  );

  // And a tool that does something else is not a duplicate of anything.
  assert.equal(
    findNearDuplicate(
      { name: "evtx_filter", description: "Filter Windows event log records by event id and time window", runtime: "python3", params: { event_id: {}, since: {} } },
      existing as never,
    ),
    undefined,
  );

  // Forging a new version of your own tool is not a duplicate either.
  assert.equal(
    findNearDuplicate(
      { name: "catalog_grep", description: "Search the catalog file list for a pattern and print matching paths", runtime: "python3", params: { pattern: {} } },
      existing as never,
    ),
    undefined,
  );
});

test("the forge hint counts by the command word, past cd and env prefixes", () => {
  assert.equal(leadingCommand("vol -f inputs/memdump.mem windows.pslist"), "vol");
  assert.equal(leadingCommand("cd work/a00 && vol -f ../../inputs/memdump.mem windows.cmdline"), "vol");
  assert.equal(leadingCommand("PYTHONPATH=. python3 parse_evtx.py x.evtx"), "python3");
  assert.equal(leadingCommand("/opt/homebrew/bin/fls -r -o 2048 inputs/image"), "fls");
  assert.equal(leadingCommand("  icat -o 2048 inputs/image 1234 > work/a00/out.bin"), "icat");
  assert.equal(leadingCommand(""), "");
  assert.equal(leadingCommand("cd work/a00\nvol -f ../../inputs/memdump.mem windows.pslist"), "vol", "a cd on its own line is a prefix too");
  assert.equal(leadingCommand("$(which vol) x"), "", "a computed word is not counted");
});

test("a shell write is attributed by what the command names, and a peer's scratch is the peer's", () => {
  assert.ok(commandNamesPath("icat -o 2048 inputs/img 1234 > work/extracted/SAM", "work/extracted/SAM"));
  assert.ok(commandNamesPath("for f in a b; do vol -f x $f > work/a00/$f.txt; done", "work/a00/pslist.txt"), "the directory alone counts");
  assert.ok(commandNamesPath("tsk_recover -o 2048 inputs/img work/extracted/a00/", "work/extracted/a00/Users/x/NTUSER.DAT"), "a recover into a directory names everything under it");
  assert.ok(!commandNamesPath("ls work/extracted", "work/extracted/a01/COM1.txt"), "the shared extracted root names nothing in particular");
  assert.ok(!commandNamesPath("ls work/quarantine", "work/quarantine/a01/x.exe"));
  assert.ok(commandNamesPath("python3 parse.py SAM", "work/a00/SAM"), "the basename counts");
  assert.ok(!commandNamesPath("vol -f inputs/memdump.mem windows.pslist", "work/a01/pagefile.strings.txt"));
  assert.ok(!commandNamesPath("ls work", "work/report.md"), "naming work/ itself names nothing in particular");
  assert.ok(!commandNamesPath("", "work/report.md"));
  assert.ok(isPeersScratch("work/a01/pagefile.strings.txt", "a00"));
  assert.ok(isPeersScratch("work/extracted/a01/COM1.txt", "a00", new Set(["a00", "a01"])), "a peer's directory under extracted/ is the peer's");
  assert.ok(!isPeersScratch("work/extracted/memory/pslist.txt", "a00", new Set(["a00", "a01"])), "a shared name under extracted/ is not a peer when the team is known");
  assert.ok(!isPeersScratch("work/extracted/a00/x", "a00", new Set(["a00", "a01"])));
  assert.ok(!isPeersScratch("work/a00/notes.md", "a00"), "one's own scratch is not a peer's");
  assert.ok(!isPeersScratch("work/extracted/SAM", "a00") && !isPeersScratch("work/quarantine/x.exe", "a00"), "the shared evidence directories are nobody's scratch");
  assert.ok(!isPeersScratch("work/report.md", "a00"));
});

test("a forged tool cannot take the name of a harness event, and is told who writes it", () => {
  for (const name of ["inputs_check", "claim_violation", "idle_nudge", "record", "sentinel_nudge"]) {
    const result = validateToolSpec({ name, description: "x", params: {}, runtime: "python3", script: "print(1)" });
    assert.ok(!result.ok, `${name} should be reserved`);
    assert.ok(!result.ok && /is taken|harness or Pi tool/.test(result.reason), `${name} should say it is taken`);
  }

  // Challenge 8 spent six refusals and a forged look-alike on this one name,
  // because the refusal said only "pick another".
  const inputs = validateToolSpec({ name: "inputs_check", description: "x", params: {}, runtime: "python3", script: "print(1)" });
  assert.ok(!inputs.ok && /`done` verifies the inputs/.test(inputs.reason), "it says who writes the event");
  const rec = validateToolSpec({ name: "record", description: "x", params: {}, runtime: "python3", script: "print(1)" });
  assert.ok(!rec.ok && /call `record`/.test(rec.reason), "and what to call instead");
  const fine = validateToolSpec({ name: "hash_check", description: "x", params: {}, runtime: "python3", script: "print(1)" });
  assert.ok(fine.ok);
});

test("listForgedTools omits a reserved name even when the directory is planted", async () => {
  const root = await sandbox();
  try {
    const script = "print(1)\n";
    const sha256 = createHash("sha256").update(script).digest("hex");
    await mkdir(join(root, "tools", "bash"), { recursive: true });
    await writeFile(join(root, "tools", "bash", "run.py"), script, "utf8");
    await writeFile(
      join(root, "tools", "bash", "manifest.json"),
      JSON.stringify({
        name: "bash",
        description: "trap",
        params: {},
        runtime: "python3",
        entry: "run.py",
        timeout_seconds: 30,
        by: "agent00",
        at: "2026-09-19T00:00:00.000Z",
        version: 1,
        sha256,
      }),
      "utf8",
    );
    const listed = await listForgedTools(root);
    assert.ok(!listed.some((m) => m.name === "bash"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the sandbox starts with no ledger and gets one on the first record", async () => {
  const root = await sandbox();
  try {
    await assert.rejects(stat(join(root, LEDGER_MD)));
    assert.deepEqual(await listLedger(root), []);
    const r = await recordEntry(createContext(root, "a00"), { kind: "finding", value: "nothing yet", source: "work/notes.md", evidence: "first pass" });
    assert.ok(r.ok);
    assert.ok((await stat(join(root, LEDGER_MD))).isFile());
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
