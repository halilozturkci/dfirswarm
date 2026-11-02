/**
 * triage-collection, collection_profile_compare: what a collector's profile could request, set against what the delivery's own records and files
 * show. The definitions are built here from the formats' own descriptions (UAC's profile and artefact YAML, a Velociraptor artifact definition
 * and its ArtifactCollectorContext, KapeFiles' .tkape), packed as the archives the pack pins; a corpus whose sha256 is not on the tool's list is
 * refused or, with allow_unpinned, read and reported as `unknown`. The pinned path is exercised by adding the fixture's own sha256 to the list in a
 * child interpreter, never by changing the tool.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet } from "./tool-library-harness.ts";
import { CANARY_PY } from "./pack-triage-canaries.ts";
import { KAPE_COPY_HEADER, TOOLS, body, kapeCopyRow, put, refused, tableRows, tool, uac3, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

export const COMPARE = join(TOOLS, "collection_profile_compare", "run.py");
const sha = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");

/** Packs a mapping of member name -> text as a tar.gz or a zip into `dir`/`file`. */
const PACK = String.raw`
import gzip, io, json, os, sys, tarfile, zipfile
spec = json.load(sys.stdin)
path = os.path.join(spec["dir"], spec["file"])
if spec["file"].endswith(".zip"):
    with zipfile.ZipFile(path, "w") as z:
        for name, text in spec["members"].items():
            z.writestr(name, text)
else:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, text in spec["members"].items():
            data = text.encode()
            info = tarfile.TarInfo(name); info.size = len(data); info.mtime = 1700000000
            tf.addfile(info, io.BytesIO(data))
    open(path, "wb").write(gzip.compress(buf.getvalue()))
`;

async function pack(dir: string, file: string, members: Record<string, string>): Promise<string> {
  await mkdir(dir, { recursive: true });
  const run = await runPySnippet(PACK, [], { dir, file, members });
  assert.equal(run.code, 0, run.stderr);
  return sha(await readFile(join(dir, file)));
}

/** Runs the tool in a child interpreter after adding `sha256` to the pin list of `kind` (what shipping the corpus does), with the arguments on stdin. */
const PINNED_RUN = String.raw`
import importlib.util, io, json, sys
spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.PINNED[sys.argv[2]].append({"version": sys.argv[3], "sha256": sys.argv[4], "name": "fixture"})
sys.stdin = io.StringIO(sys.argv[5])
mod.main()
`;
async function pinnedRun(cwd: string, kind: string, version: string, digest: string, args: Json) {
  return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn("python3", ["-c", PINNED_RUN, COMPARE, kind, version, digest, JSON.stringify(args)], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    const out: Buffer[] = [], err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
  });
}

function cp(cwd: string, args: Json, env: Record<string, string> = {}) {
  return tool(COMPARE, cwd, args, env);
}

// ---- UAC: profile and artefact YAML as UAC 3.x writes them ------------------------------------------------------------------------
const UAC_PROFILE = `name: ir_triage
description: Incident response triage collection.
artifacts:
  # processes and network
  - live_response/process/*.yaml
  - live_response/network/*.yaml
  - '!live_response/network/ss.yaml'
  - files/logs/var_log.yaml
  - live_response/system/does_not_exist.yaml
  - 'live_response/\${extra}/*.yaml'
`;
const UAC_PS = `version: 2.0
condition: command_exists "ps"
output_directory: /live_response/process
artifacts:
  -
    description: Report a snapshot of the current processes.
    supported_os: [all]
    collector: command
    command: ps -deaf
    output_file: ps_-deaf.txt
`;
const UAC_SS = `version: 2.0
output_directory: /live_response/network
artifacts:
  -
    description: Display socket statistics.
    supported_os: [linux]
    collector: command
    command: ss -tanp
    output_file: ss_-tanp.txt
`;
const UAC_IP = `version: 2.0
output_directory: /live_response/network
artifacts:
  -
    description: Show network addresses.
    supported_os: [linux]
    collector: command
    command: ip addr
    output_file: ip_addr.txt
`;
const UAC_LOGS = `version: 2.0
artifacts:
  -
    description: Collect logs.
    supported_os: [linux]
    collector: find
    path: /var/log
    name_pattern: ["*.log"]
`;
const UAC_CORPUS = {
  "uac-3.4.0/profiles/ir_triage.yaml": UAC_PROFILE,
  "uac-3.4.0/profiles/full.yaml": "name: full\nartifacts:\n  - live_response/process/*.yaml\n",
  "uac-3.4.0/artifacts/live_response/process/ps.yaml": UAC_PS,
  "uac-3.4.0/artifacts/live_response/network/ss.yaml": UAC_SS,
  "uac-3.4.0/artifacts/live_response/network/ip.yaml": UAC_IP,
  "uac-3.4.0/artifacts/files/logs/var_log.yaml": UAC_LOGS,
};

async function uacDelivery(cwd: string): Promise<void> {
  await put(cwd, "d/uac-host/uac.log", [uac3("INF", "Profile: ir_triage", 0), uac3("INF", "Collecting live_response/process/ps.yaml", 1), uac3("ERR", "ip addr failed: ip.yaml could not run", 2)].join("\n") + "\n");
  await put(cwd, "d/uac-host/live_response/process/ps_-deaf.txt", "x");
  await put(cwd, "d/uac-host/[root]/var/log/syslog.log", "x");
}

test("UAC: a profile's include and exclude globs are resolved against the pinned artefacts and set against the delivery's files and log", async () => {
  await withCwd(async (cwd) => {
    const digest = await pack(join(cwd, "defs"), "uac-3.4.0.tar.gz", UAC_CORPUS);
    await uacDelivery(cwd);
    const out = body(await pinnedRun(cwd, "uac", "3.4.0", digest, { root: "d", definitions: "defs" }));
    assert.equal(out.definitions[0].status, "read");
    assert.equal(out.definitions[0].version, "3.4.0");
    assert.equal(out.definitions[0].pinned, true);
    assert.equal(out.definitions[0].sha256, digest);
    assert.equal(out.requested.first[0].profile, "ir_triage");
    assert.match(out.requested.first[0].profile_basis, /line 1 of/);
    const rows = await tableRows(cwd, out.tables.findings);
    const section = (s: string) => rows.filter((r: Json) => r.section === s);
    assert.deepEqual(section("excluded").map((r: Json) => [r.entry, r.removed_artefacts]), [["!live_response/network/ss.yaml", ["live_response/network/ss.yaml"]]]);
    const could = section("could_request").map((r: Json) => r.artefact).sort();
    assert.deepEqual(could, ["files/logs/var_log.yaml", "live_response/network/ip.yaml", "live_response/process/ps.yaml"], "the excluded artefact is not requestable and the include glob took the others");
    assert.deepEqual(section("collected").map((r: Json) => r.artefact).sort(), ["files/logs/var_log.yaml", "live_response/process/ps.yaml"]);
    const missing = section("not_collected");
    assert.deepEqual(missing.map((r: Json) => r.artefact), ["live_response/network/ip.yaml"]);
    assert.ok(missing[0].collector_words[0].includes("ip addr failed"), "the collector's own words are kept");
    assert.deepEqual(section("proposed_additional_evidence").map((r: Json) => r.artefact), ["live_response/network/ip.yaml"]);
    assert.ok(section("proposed_additional_evidence").every((r: Json) => !/ip addr$|command/i.test(Object.keys(r).join(" "))), "a proposal is never a command");
    assert.equal(section("unresolved")[0].kind, "unresolved_dynamic_selection");
    assert.match(section("unknown")[0].why, /no artefact file of the pinned UAC definitions matches/);
    assert.equal(out.status, "partial", "an unresolved selection and an unknown entry make it partial or at least not clean");
  });
});

test("UAC: a profile file in the delivery that differs from the pinned one is reported as differing and is never the definition", async () => {
  await withCwd(async (cwd) => {
    const digest = await pack(join(cwd, "defs"), "uac-3.4.0.tar.gz", UAC_CORPUS);
    await uacDelivery(cwd);
    await put(cwd, "d/profiles/ir_triage.yaml", "name: ir_triage\nartifacts:\n  - live_response/process/*.yaml\n  - live_response/hardware/*.yaml\n");
    const out = body(await pinnedRun(cwd, "uac", "3.4.0", digest, { root: "d", definitions: "defs", delivered_profile: "profiles/ir_triage.yaml" }));
    assert.equal(out.differs.count, 1);
    assert.deepEqual(out.differs.first[0].only_in_delivered.sort(), ["live_response/hardware/*.yaml"]);
    const rows = await tableRows(cwd, out.tables.findings);
    assert.equal(rows.some((r: Json) => r.section === "could_request" && /hardware/.test(r.artefact)), false, "the delivered profile adds nothing to what could be requested");
    assert.ok(rows.some((r: Json) => r.section === "could_request" && r.artefact === "live_response/network/ip.yaml"), "the pinned definition is the one used");
  });
});

test("UAC: definitions that are not on the tool's list are refused, or read as unknown and never as 3.4.0", async () => {
  await withCwd(async (cwd) => {
    await pack(join(cwd, "defs"), "uac-3.4.0.tar.gz", UAC_CORPUS);
    await uacDelivery(cwd);
    const strict = body(await cp(cwd, { root: "d", definitions: "defs" }));
    assert.equal(strict.status, "partial");
    assert.equal(strict.definitions[0].status, "refused");
    assert.match(strict.definitions[0].why, /not on the list/);
    assert.equal(strict.could_request.count, 0);
    assert.match(strict.status_basis, /refused|definitions_not_available/);
    const lax = body(await cp(cwd, { root: "d", definitions: "defs", allow_unpinned: true }));
    assert.equal(lax.definitions[0].version, "unknown");
    assert.equal(lax.definitions[0].pinned, false);
    assert.equal(lax.requested.first[0].definitions_version, "unknown");
    assert.equal(lax.requested.first[0].pinned, false);
    assert.deepEqual(new Set(lax.definition_files_used.map((u: Json) => u.version)), new Set(["unknown"]), "a corpus with no pinned hash is never called 3.4.0, though the archive's name says it");
    assert.equal(lax.definitions.some((d: Json) => d.version === "3.4.0"), false);
    assert.ok(lax.definition_files_used.every((u: Json) => u.version === "unknown" && u.pinned === false));
    const none = body(await cp(cwd, { root: "d" }));
    assert.equal(none.status, "partial");
    assert.match(none.status_basis, /definitions_not_available/);
    // a corpus archive whose bytes were changed after it was pinned is a different hash
    const real = await pack(join(cwd, "defs2"), "uac-3.4.0.tar.gz", UAC_CORPUS);
    const changed = await pack(join(cwd, "defs3"), "uac-3.4.0.tar.gz", { ...UAC_CORPUS, "uac-3.4.0/artifacts/live_response/process/ps.yaml": UAC_PS + "# changed\n" });
    assert.notEqual(real, changed);
    const refusedChanged = body(await pinnedRun(cwd, "uac", "3.4.0", real, { root: "d", definitions: "defs3" }));
    assert.equal(refusedChanged.definitions[0].status, "refused");
  });
});

test("hostile YAML in a delivered profile, a definition or a corpus is refused by name within the bounds", async () => {
  await withCwd(async (cwd) => {
    await uacDelivery(cwd);
    const digest = await pack(join(cwd, "defs"), "uac-3.4.0.tar.gz", UAC_CORPUS);
    const laughs = "a: &a [x, x]\n" + Array.from({ length: 9 }, (_, i) => `${String.fromCharCode(98 + i)}: &${String.fromCharCode(98 + i)} [*${String.fromCharCode(97 + i)}, *${String.fromCharCode(97 + i)}]`).join("\n") + "\n";
    const cases: Array<[string, string, string]> = [
      ["anchor", "name: x\nartifacts: &x\n  - a.yaml\n", "anchor"],
      ["alias", "name: x\nartifacts:\n  - *x\n", "alias"],
      ["billion laughs", laughs, "anchor"],
      ["tag", "name: !!python/object/apply:os.system [ls]\n", "tag"],
      ["merge key", "name: x\n<<: {a: b}\n", "merge_key"],
      ["deep nesting", Array.from({ length: 80 }, (_, i) => `${"  ".repeat(i)}k${i}:`).join("\n") + "\n" + "  ".repeat(80) + "v: 1\n", "too_deep"],
      ["deep flow", "a: " + "[".repeat(200) + "]".repeat(200) + "\n", "too_deep"],
      ["a 10 MB scalar", "name: " + "x".repeat(10 << 20) + "\n", "file_over_bound"],
      ["two documents", "name: x\n---\nname: y\n", "more_than_one_document"],
      ["tab indentation", "name: x\nartifacts:\n\t- a\n", "tab_indentation"],
    ];
    for (const [label, text, code] of cases) {
      await put(cwd, "d/profiles/bad.yaml", text);
      const started = Date.now();
      const out = body(await pinnedRun(cwd, "uac", "3.4.0", digest, { root: "d", definitions: "defs", delivered_profile: "profiles/bad.yaml" }));
      assert.ok(Date.now() - started < 30_000, `${label} is bounded in time`);
      assert.equal(out.yaml.refused[code], 1, `${label}: ${JSON.stringify(out.yaml.refused)}`);
      assert.equal(out.status, "partial", label);
      assert.match(out.status_basis, new RegExp(code));
    }
    // a corpus member that is hostile is refused by name and the rest of the corpus is still read
    const hostile = await pack(join(cwd, "defs4"), "uac-3.4.0.tar.gz", { ...UAC_CORPUS, "uac-3.4.0/artifacts/live_response/process/ps.yaml": "a: &x 1\nb: *x\n" });
    const out = body(await pinnedRun(cwd, "uac", "3.4.0", hostile, { root: "d", definitions: "defs4" }));
    assert.equal(out.yaml.refused.anchor, 1);
    assert.ok(out.yaml.refused_first[0].where.includes("ps.yaml"));
    assert.notEqual(out.status, "complete");
  });
});

// ---- Velociraptor -------------------------------------------------------------------------------------------------------------------
const VELO_PSLIST = `name: Windows.System.Pslist
description: |
   List processes
type: CLIENT
parameters:
  - name: ProcessRegex
    default: .
    type: regex
sources:
  - query: |
      SELECT * FROM pslist()
`;
const VELO_FIND = `name: Custom.Find.Files
type: CLIENT
parameters:
  - name: SearchGlob
    default: ""
  - name: OtherGlob
    default: C:/Windows/*
  - name: MaxSize
    default: "1000"
sources:
  - query: SELECT * FROM glob(globs=SearchGlob)
`;
const VELO_KAPE = `name: Windows.KapeFiles.Targets
parameters:
  - name: Device
    default: C:
sources:
  - query: SELECT 1 FROM scope()
`;
const VELO_CORPUS = {
  "velociraptor-0.77.2/artifacts/definitions/Windows/System/Pslist.yaml": VELO_PSLIST,
  "velociraptor-0.77.2/artifacts/definitions/Custom/Find.yaml": VELO_FIND,
  "velociraptor-0.77.2/artifacts/definitions/Windows/KapeFiles/Targets.yaml": VELO_KAPE,
  "velociraptor-0.77.2/docs/readme.yaml": "name: Not.A.Definition\n",
};
const velo = (value: string) => JSON.stringify({
  session_id: "F.ABC", create_time: 1602103388000000, start_time: 1602103388000000,
  request: { artifacts: ["Windows.System.Pslist"], specs: [
    { artifact: "Custom.Find.Files", parameters: { env: [{ key: "SearchGlob", value }, { key: "ExtraKnob", value: "1" }] } },
    { artifact: "Windows.KapeFiles.Targets", parameters: { env: [] } },
    { artifact: "Custom.Not.In.Pinned", parameters: { env: [] } },
  ] },
});

test("Velociraptor: the request is read as data and each artefact is looked up by name; a run-time selection with no value in the record is unresolved", async () => {
  await withCwd(async (cwd) => {
    const digest = await pack(join(cwd, "defs"), "velociraptor-0.77.2.tar.gz", VELO_CORPUS);
    await put(cwd, "v/c1/collection_context.json", velo("C:/Users/*/NTUSER.DAT"));
    await put(cwd, "v/c1/uploads.json", "");
    const out = body(await pinnedRun(cwd, "velociraptor", "0.77.2", digest, { root: "v", definitions: "defs" }));
    assert.equal(out.requested.first[0].artefacts_total, 4);
    const rows = await tableRows(cwd, out.tables.findings);
    const un = rows.filter((r: Json) => r.section === "unresolved");
    assert.ok(un.every((r: Json) => r.kind === "unresolved_dynamic_selection"));
    assert.ok(un.some((r: Json) => r.artefact === "Windows.KapeFiles.Targets" && /KAPE/.test(r.why)), "an artefact that embeds KAPE target lists stays unresolved");
    assert.ok(un.some((r: Json) => r.artefact === "Windows.System.Pslist" && r.parameter === "ProcessRegex" && r.default === "."), "a regex that selects what is collected has no value in the record");
    assert.ok(un.some((r: Json) => r.artefact === "Custom.Find.Files" && r.parameter === "OtherGlob"));
    assert.equal(un.some((r: Json) => r.artefact === "Custom.Find.Files" && r.parameter === "SearchGlob"), false, "a value in the record is resolved");
    const find = rows.find((r: Json) => r.section === "could_request" && r.artefact === "Custom.Find.Files");
    assert.equal(find.parameters.find((p: Json) => p.name === "SearchGlob").value_in_record, "C:/Users/*/NTUSER.DAT");
    const unknown = rows.filter((r: Json) => r.section === "unknown").flatMap((r: Json) => [r.artefact, r.parameter]);
    assert.ok(unknown.includes("Custom.Not.In.Pinned"), "a name not in the pinned set is unknown");
    assert.ok(unknown.includes("ExtraKnob"), "a parameter the definition does not have is unknown");
    assert.ok(out.definition_files_used.every((u: Json) => u.version === "0.77.2" && u.pinned === true));
  });
});

test("Velociraptor: a definition delivered in the collection that differs from the pinned one is reported and not used; hostile YAML in it is refused", async () => {
  await withCwd(async (cwd) => {
    const digest = await pack(join(cwd, "defs"), "velociraptor-0.77.2.tar.gz", VELO_CORPUS);
    await put(cwd, "v/c1/collection_context.json", velo("x"));
    await put(cwd, "v/c1/Pslist.yaml", VELO_PSLIST.replace("default: .", "default: lsass"));
    await put(cwd, "v/c1/Find.yaml", VELO_FIND);
    await put(cwd, "v/c1/Evil.yaml", "name: Evil\nparameters: &a\n  - *a\n");
    const out = body(await pinnedRun(cwd, "velociraptor", "0.77.2", digest, { root: "v", definitions: "defs" }));
    assert.deepEqual(out.differs.first.map((r: Json) => r.artefact), ["Windows.System.Pslist"], "the identical delivered definition is not a difference");
    assert.equal(out.yaml.refused.anchor, 1);
    const rows = await tableRows(cwd, out.tables.findings);
    const regex = rows.find((r: Json) => r.section === "unresolved" && r.parameter === "ProcessRegex");
    assert.equal(regex.default, ".", "the default is the pinned definition's, not the delivered one's");
  });
});

// ---- KAPE ----------------------------------------------------------------------------------------------------------------------------
const TKAPE = (entries: string[], extra = "") => `Description: test target
Author: someone
Version: 1.0
Id: 6a22b2ba-0000-0000-0000-000000000000
RecreateDirectories: true
Targets:
${entries.join("\n")}${extra}
`;
const ENTRY = (name: string, path: string, mask: string, recursive = false) => `    -
        Name: ${name}
        Category: Test
        Path: ${path}
        FileMask: '${mask}'
        Recursive: ${recursive}`;
const KAPE_CORPUS: Record<string, string> = {
  "KapeFiles-abc/Targets/Leaf.tkape": TKAPE([ENTRY("Event logs", "C:\\Windows\\System32\\winevt\\Logs\\", "*.evtx"), ENTRY("Hosts", "C:\\Windows\\System32\\drivers\\etc\\", "hosts")]),
  "KapeFiles-abc/Targets/Users.tkape": TKAPE([ENTRY("Ntuser", "C:\\Users\\%user%\\", "NTUSER.DAT")]),
  "KapeFiles-abc/Targets/Mid.tkape": TKAPE([ENTRY("Leaf", "Leaf.tkape", "*"), ENTRY("Prefetch", "C:\\Windows\\Prefetch\\", "*.pf")]),
  "KapeFiles-abc/Targets/!Compound.tkape": TKAPE([ENTRY("Mid", "Mid.tkape", "*"), ENTRY("Users", "Users.tkape", "*")]),
  "KapeFiles-abc/Targets/CycleA.tkape": TKAPE([ENTRY("B", "CycleB.tkape", "*")]),
  "KapeFiles-abc/Targets/CycleB.tkape": TKAPE([ENTRY("A", "CycleA.tkape", "*")]),
};

async function kapeDelivery(cwd: string): Promise<void> {
  const rows = [
    kapeCopyRow("C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "C\\Windows\\System32\\winevt\\Logs\\Security.evtx"),
    kapeCopyRow("C:\\Windows\\System32\\winevt\\Logs\\System.evtx", "C\\Windows\\System32\\winevt\\Logs\\System.evtx"),
    kapeCopyRow("C:\\Windows\\Prefetch\\A.EXE-1.pf", "C\\Windows\\Prefetch\\A.EXE-1.pf"),
  ];
  await put(cwd, "k/2026-02-14T09_12_00_CopyLog.csv", [KAPE_COPY_HEADER, ...rows].join("\n") + "\n");
  await put(cwd, "k/2026-02-14T09_12_00_SkipLog.csv", "SourceFile,SourceFileSha1,Reason\nC:\\Windows\\System32\\drivers\\etc\\hosts,,The process cannot access the file\n");
  await put(cwd, "k/2026-02-14T09_12_00_ConsoleLog.txt", "[2026-02-14 09:12:00.123 | INF] Command line: --tsource C: --target !Compound --tdest D:\\out\n");
  await put(cwd, "k/C/Windows/System32/winevt/Logs/Security.evtx", "x");
}

test("KAPE: compound targets resolve two levels deep, a %user% path is unresolved, an unknown target is unknown, and the copy log is compared with what the targets could take", async () => {
  await withCwd(async (cwd) => {
    const digest = await pack(join(cwd, "defs"), "KapeFiles-abc.zip", KAPE_CORPUS);
    await kapeDelivery(cwd);
    const out = body(await pinnedRun(cwd, "kape", "abc", digest, { root: "k", definitions: "defs" }));
    assert.equal(out.requested.first[0].targets_total, 1);
    assert.match(out.requested.first[0].targets_basis, /console log/);
    const rows = await tableRows(cwd, out.tables.findings);
    const sec = (s: string) => rows.filter((r: Json) => r.section === s);
    assert.deepEqual(sec("could_request").map((r: Json) => r.entry_name ?? r.name).sort(), ["Event logs", "Hosts", "Ntuser", "Prefetch"], "!Compound -> Mid -> Leaf: two levels deep");
    assert.deepEqual(sec("unresolved").map((r: Json) => [r.entry_name, r.kind]), [["Ntuser", "unresolved_dynamic_selection"]], "%user% is never expanded");
    const took = Object.fromEntries(sec("collected").map((r: Json) => [r.entry_name, r.copy_log_rows]));
    assert.deepEqual(took, { "Event logs": 2, Prefetch: 1 }, "the copy log took less than the targets could request");
    const missing = sec("not_collected");
    assert.deepEqual(missing.map((r: Json) => r.entry_name), ["Hosts"]);
    assert.equal(missing[0].skip_log_rows, 1);
    assert.match(missing[0].collector_words[0], /cannot access/, "the collector's own words");
    assert.deepEqual(sec("proposed_additional_evidence").map((r: Json) => r.entry_name), ["Hosts"]);
    const named = body(await pinnedRun(cwd, "kape", "abc", digest, { root: "k", definitions: "defs", kape_targets: ["CycleA", "NoSuchTarget", "Leaf"] }));
    const nrows = await tableRows(cwd, named.tables.findings);
    const cycle = nrows.find((r: Json) => r.kind === "cycle");
    assert.ok(cycle, "a cycle is refused by name");
    assert.deepEqual(cycle.chain, ["cyclea", "cycleb", "cyclea"]);
    assert.ok(nrows.some((r: Json) => r.section === "unknown" && r.target === "NoSuchTarget"));
    assert.equal(named.status, "partial");
  });
});

test("KAPE: a hostile .tkape is refused by name and the rest of the corpus is still read", async () => {
  await withCwd(async (cwd) => {
    const digest = await pack(join(cwd, "defs"), "KapeFiles-abc.zip", { ...KAPE_CORPUS, "KapeFiles-abc/Targets/Evil.tkape": "Targets: &a\n  - *a\n", "KapeFiles-abc/Targets/Big.tkape": "Targets:\n" + "x".repeat(3 << 20) });
    await kapeDelivery(cwd);
    const out = body(await pinnedRun(cwd, "kape", "abc", digest, { root: "k", definitions: "defs", kape_targets: ["Leaf", "Evil"] }));
    assert.equal(out.yaml.refused.anchor, 1);
    assert.equal(out.definitions[0].members_refused, 1, "the 3 MB file is over the bound and is counted as refused");
    const rows = await tableRows(cwd, out.tables.findings);
    assert.ok(rows.some((r: Json) => r.section === "could_request" && r.name === "Event logs"));
    assert.ok(rows.some((r: Json) => r.section === "unknown" && r.target === "Evil"));
    assert.equal(out.status, "partial");
  });
});

// ---- the shared contract ---------------------------------------------------------------------------------------------------------------
test("canaries in profile values, parameter values, target paths and file names are withheld from the answer and the table file", async () => {
  await withCwd(async (cwd) => {
    const gen = await runPySnippet(CANARY_PY + String.raw`
import json, random
r = random.Random(38)
picked = [n for n in names(("listed",), safe_only=True)][:6]
print(json.dumps([[n, *make(n, r)] for n in picked]))
`, [], null);
    assert.equal(gen.code, 0, gen.stderr);
    const plants = JSON.parse(gen.stdout) as Array<[string, string, string[]]>;
    const digest = await pack(join(cwd, "defs"), "velociraptor-0.77.2.tar.gz", VELO_CORPUS);
    const specs = plants.map(([, text], i) => ({ artifact: "Custom.Find.Files", parameters: { env: [{ key: "SearchGlob", value: text }, { key: `K${i}`, value: text }] } }));
    await put(cwd, "v/c1/collection_context.json", JSON.stringify({ request: { specs: [...specs, { artifact: plants[0][1] }] } }));
    await put(cwd, "v/c1/uploads.json", "");
    for (const [i, [, text]] of plants.entries()) await put(cwd, `v/c1/${i}-${text}.txt`, "x");
    const call = await pinnedRun(cwd, "velociraptor", "0.77.2", digest, { root: "v", definitions: "defs" });
    const out = body(call);
    const all = call.stdout + JSON.stringify(await tableRows(cwd, out.tables.findings)) + call.stderr;
    for (const [shape, , cores] of plants) for (const core of cores) for (let i = 0; i + 12 <= core.length; i += 6) assert.ok(!all.includes(core.slice(i, i + 12)), `${shape} shows ${core.slice(i, i + 12)}`);
    assert.ok(out.withheld.strings_withheld >= 1);
    const refusal = refused(await cp(cwd, { root: "v", write_values: true }));
    assert.match(refusal.error, /job|secret/i);
  });
});

test("SIGINT, SIGTERM and SIGHUP leave one JSON answer and the exit status 128 plus the signal", async () => {
  const code = `
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.install_signal_handlers()
os.kill(os.getpid(), getattr(signal, sys.argv[2]))
`;
  for (const [name, status] of [["SIGINT", 130], ["SIGTERM", 143], ["SIGHUP", 129]] as const) {
    const run = await runPySnippet(code, [COMPARE, name], null);
    assert.equal(run.code, status, run.stderr);
    assert.match(JSON.parse(run.stdout).error, /stopped by signal/);
    assert.doesNotMatch(run.stderr, /Traceback|KeyboardInterrupt/);
  }
});

test("hostile parameters are JSON refusals, a delivery with no record says so, and nothing is written outside the table files", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "d/readme.txt", "x");
    for (const args of [{}, { root: 3 }, { root: "nope" }, { root: "d/readme.txt" }, { root: "d", limit: 0 }, { root: "d", collectors: ["x"] }, { root: "d", kape_targets: [] }, { root: "d", needs: [1] },
      { root: "d", allow_unpinned: "yes" }, { root: "d", time_limit_seconds: 99999 }, { root: "d", profile: "" }]) {
      const out = refused(await cp(cwd, args));
      assert.equal(out.status, "failed");
    }
    const quiet = body(await cp(cwd, { root: "d" }));
    assert.equal(quiet.status, "partial");
    assert.match(quiet.status_basis, /no UAC, Velociraptor or KAPE record/);
    assert.deepEqual(quiet.ignored_parameters, []);
    await mkdir(join(cwd, "emptydefs"), { recursive: true });
    const noCorpus = body(await cp(cwd, { root: "d", definitions: "emptydefs", profile: "ir_triage" }));
    assert.match(noCorpus.status_basis, /definitions_not_available|no archive of this corpus/);
    const missingDir = body(await cp(cwd, { root: "d", definitions: "nodir", profile: "ir_triage" }));
    assert.equal(missingDir.status, "partial");
    assert.match(JSON.stringify(missingDir.definitions_not_available), /could not be listed/);
  });
});

test("the tool's own clock ends a long record read partial, with JSON", async () => {
  await withCwd(async (cwd) => {
    const rows = Array.from({ length: 200000 }, (_, i) => kapeCopyRow(`C:\\Windows\\Prefetch\\F${i}.pf`, `C\\Windows\\Prefetch\\F${i}.pf`));
    await put(cwd, "k/2026-02-14T09_12_00_CopyLog.csv", [KAPE_COPY_HEADER, ...rows].join("\n") + "\n");
    const started = Date.now();
    const out = body(await cp(cwd, { root: "k", kape_targets: ["Leaf"], time_limit_seconds: 1 }));
    assert.ok(Date.now() - started < 60_000);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /time limit|stopped|definitions_not_available/);
  });
});
