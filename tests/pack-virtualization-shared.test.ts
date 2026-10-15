/**
 * virtualization-backup-forensics: the three tools carry blocks of code that each other (and the network pack's tools) carry
 * too, so that they withhold the same strings, page and report the same way and end a program the same way. A tool is
 * standalone, so each copy is the same text and this suite holds the copies equal. It also holds the manifests to the
 * scripts they describe, and the three tools to the job context: only $OUT is written, nothing outside the output
 * directory is touched, and no tool starts a program in a session of its own.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ALL_TOOLS, AUDIT, CANARY, CHAIN, INVENTORY, IS_ROOT, TOOLS, filesUnder, json, put, qcow2, tool, vmdkDescriptor, vmx, withCwd } from "./pack-virtualization-harness.ts";
import { runPySnippet } from "./tool-library-harness.ts";
import { LOGS, EXTRACT } from "./pack-network-harness.ts";
import type { Json } from "./pack-virtualization-harness.ts";

async function block(path: string, name: string): Promise<string> {
  const text = await readFile(path, "utf8");
  const begin = `# BEGIN SHARED ${name}`, end = `# END SHARED ${name}`;
  const start = text.indexOf(begin), stop = text.indexOf(end);
  assert.ok(start >= 0 && stop > start, `${path} carries the ${name} block`);
  assert.equal(text.indexOf(begin, start + 1), -1, `${path} carries it once`);
  return text.slice(start, stop + end.length);
}

test("the three tools carry the network pack's withholding block, byte for byte, so that every tool of both packs withholds the same strings", async () => {
  const network = await block(LOGS, "WITHHOLDING");
  assert.ok(network.length > 5000);
  for (const [name, path] of Object.entries(ALL_TOOLS)) assert.equal(await block(path, "WITHHOLDING"), network, `${name} carries the network pack's withholding block`);
});

test("the three tools carry one common block (arguments, status, paging, the values file) and one way out (the seal and its check), and the two that walk a directory carry one walker", async () => {
  const common = await block(INVENTORY, "COMMON");
  assert.ok(common.length > 5000);
  for (const [name, path] of Object.entries(ALL_TOOLS)) assert.equal(await block(path, "COMMON"), common, `${name} carries the common block`);
  const boundary = await block(INVENTORY, "BOUNDARY");
  for (const [name, path] of Object.entries(ALL_TOOLS)) assert.equal(await block(path, "BOUNDARY"), boundary, `${name} carries the one way out`);
  const files = await block(INVENTORY, "FILES");
  assert.equal(await block(CHAIN, "FILES"), files);
  assert.doesNotMatch(await readFile(AUDIT, "utf8"), /BEGIN SHARED FILES/, "backup_audit_normalise reads named files and walks nothing");
});

test("snapshot_chain_check, the one tool that runs a program, ends it the way the network pack's engine tools do, and no tool starts a program in a session of its own", async () => {
  assert.equal(await block(CHAIN, "PROCESS"), await block(EXTRACT, "PROCESS"));
  for (const [name, path] of Object.entries(ALL_TOOLS)) {
    const text = await readFile(path, "utf8");
    const code = text.replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, "");
    assert.doesNotMatch(code, /start_new_session|setsid|process_group|os\.fork|os\.system/, `${name} starts a program outside the tool's process group`);
    assert.doesNotMatch(code, /threading|multiprocessing/, `${name} uses a thread or a process pool`);
    assert.doesNotMatch(code, /\b(?:urllib|http\.client|socket|requests|ftplib|smtplib)\b/, `${name} reaches for the network`);
    assert.doesNotMatch(code, /(?<![\w.])(?:eval|exec|compile)\(|__import__|importlib/, `${name} evaluates text`);
  }
  for (const name of ["virtualization_inventory", "backup_audit_normalise"]) {
    assert.doesNotMatch(await readFile(ALL_TOOLS[name as keyof typeof ALL_TOOLS], "utf8"), /subprocess\.|Popen/, `${name} runs no program`);
  }
});

const SHAPES = `
import json, re, sys
data = json.load(sys.stdin)
ns = {"re": re}
exec(data["block"], ns)
print(json.dumps({"shaped": {s: ns["token_shaped"](s) for s in data["names"]}, "scrub": {s: ns["scrub"](s) for s in data["text"]}}))
`;

test("the block withholds the shapes the pack's canaries use, and leaves the names an examiner needs alone", async () => {
  const names: Record<string, boolean> = {
    [CANARY.github]: true, [CANARY.aws]: true, [CANARY.hex]: true,
    "vm-000001-delta.vmdk": false, "base-flat.vmdk": false, "web01": false, "before-upgrade": false, "snapshot-2023-11-14": false, "/vmfs/volumes/datastore1/web/web.vmx": false,
  };
  const text = [`https://${CANARY.userinfo}@h.example.test/x`, "disk Windows Server 2022 (64-bit)", "pre-patch snapshot"];
  const run = await runPySnippet(SHAPES, [], { block: await block(INVENTORY, "WITHHOLDING"), names: Object.keys(names), text });
  assert.equal(run.code, 0, run.stderr);
  const got: Json = JSON.parse(run.stdout);
  for (const [name, want] of Object.entries(names)) assert.equal(got.shaped[name], want, `${name.slice(0, 30)} should${want ? "" : " not"} be withheld`);
  assert.match(got.scrub[text[0]], /<userinfo withheld \d+ characters>@h\.example\.test/);
  assert.equal(got.scrub[text[1]], text[1]);
  assert.equal(got.scrub[text[2]], text[2]);
});

test("every manifest names the parameters its script reads and no others, carries the script's sha256 and a status description, and holds its time budget under its own timeout", async () => {
  for (const [name, path] of Object.entries(ALL_TOOLS)) {
    const manifest: Json = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
    const script = await readFile(path, "utf8");
    assert.equal(manifest.sha256, createHash("sha256").update(script).digest("hex"), `${name} sha256`);
    assert.equal(manifest.name, name);
    assert.ok(manifest.description.length > 1500, `${name} description says what is and is not measured`);
    assert.match(manifest.description, /`status`.*`status_basis`/, `${name} says its answers carry status and status_basis`);
    assert.match(manifest.description, /SENSITIVE/, `${name} says what is sensitive`);
    assert.match(manifest.description, /write_text/, `${name} names its values-file flag`);
    const read = new Set<string>();
    for (const m of script.matchAll(/(?:args\.get|want_str|want_flag|want_int|want_str_list|want_seconds|want_map)\(\s*(?:args,\s*)?"([a-z_]+)"/g)) read.add(m[1]);
    for (const m of script.matchAll(/(?<![A-Za-z_])args\[\s*"([a-z_]+)"\s*\]/g)) read.add(m[1]);
    const named = new Set(Object.keys(manifest.params));
    assert.deepEqual([...read].filter((p) => !named.has(p)).sort(), [], `${name}: parameters the script reads and the manifest does not name`);
    assert.deepEqual([...named].filter((p) => !read.has(p)).sort(), [], `${name}: parameters the manifest names and the script does not read`);
    for (const key of Object.keys(JSON.parse(manifest.example))) assert.ok(named.has(key), `${name} example uses ${key}`);
    const most = Number(/^MAX_SECONDS = ([0-9.]+)/m.exec(script)?.[1]);
    assert.ok(most < manifest.timeout_seconds, `${name}: the most a caller may ask for is under the tool's timeout`);
    assert.match(manifest.params.max_seconds.description, new RegExp(`at most ${most}`));
    assert.ok(manifest.version >= 1);
    assert.ok(manifest.use, `${name} says what it reads`);
    for (const p of Object.values(manifest.params) as Json[]) assert.ok(["string", "number", "integer", "boolean", "array", "object"].includes(p.type) && p.description, `${name} param shape`);
  }
  const chain = JSON.parse(await readFile(join(TOOLS, "snapshot_chain_check", "manifest.json"), "utf8"));
  assert.deepEqual(chain.use.magic.map((m: Json) => m.hex), ["4b444d56", "514649fb", "7668647866696c65", "636f6e6563746978"], "KDMV, QFI+0xfb, vhdxfile, conectix");
  assert.equal(chain.requires, undefined, "qemu-img is optional for snapshot_chain_check and is not declared as a requirement");
});

test("in a job only $OUT is written: the run directory can be read-only, nothing is made outside the output directory, and a rerun in the same job does not touch the first run's pages", async () => {
  if (IS_ROOT) return; // root ignores a read-only directory
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/vm/a.vmdk", vmdkDescriptor({ cid: "aabbccdd", extents: [{ sectors: 8, type: "FLAT", name: "a-flat.vmdk" }] }));
    await put(cwd, "inputs/vm/q.qcow2", qcow2({ snapshots: Array.from({ length: 30 }, (_, i) => ({ id: String(i), name: `s${i}`, date: 1 + i })) }));
    for (let i = 0; i < 8; i++) await put(cwd, `inputs/vm/v${i}.vmx`, vmx([["displayName", `x${i}`]]));
    for (let i = 0; i < 8; i++) await put(cwd, `inputs/vm/d${i}.vmdk`, vmdkDescriptor({ cid: `0000000${i}`, extents: [{ sectors: 8, type: "FLAT", name: `d${i}-flat.vmdk` }] }));
    await put(cwd, "inputs/log/index", Array.from({ length: 30 }, (_, i) => `UPID:pve1:00000B73:0000D2C5:${(0x65000000 + i).toString(16).toUpperCase()}:vzdump::root@pam:`).join("\n") + "\n");
    const out = join(cwd, "..", `outdir-${process.pid}`);
    await mkdir(out, { recursive: true });
    const before = await filesUnder(cwd);
    await chmod(cwd, 0o555);
    try {
      const env = { JOB_ID: "j000001", OUT: out };
      for (const [script, args] of [[CHAIN, { root: "inputs/vm", limit: 2 }], [INVENTORY, { root: "inputs/vm", limit: 2 }], [AUDIT, { path: "inputs/log/index", limit: 2 }]] as const) {
        const run = await tool(script, cwd, args, env);
        assert.equal(run.code === 0 || run.code === 1, true, run.stderr);
        assert.doesNotMatch(run.stderr, /Traceback/);
        const answer: Json = JSON.parse(run.stdout);
        assert.ok(answer.status === "complete" || answer.status === "partial", `${script}: ${run.stdout.slice(0, 200)}`);
        assert.equal(answer.pages ? Object.values(answer.pages as Record<string, Json>).some((p) => p.truncated) : false, true, "the call paged");
      }
    } finally {
      await chmod(cwd, 0o755);
    }
    assert.deepEqual(await filesUnder(cwd), before, "nothing was made in the run directory");
    const made = await filesUnder(out);
    assert.ok(made.length >= 3 && made.every((f) => f.startsWith("tool-output/")), made.join(", "));
    for (const f of made) assert.equal((await stat(join(out, f))).mode & 0o777, 0o600, `${f} is private`);
    const again = await tool(CHAIN, cwd, { root: "inputs/vm", limit: 2 }, { JOB_ID: "j000001", OUT: out });
    assert.equal(json(again).status, "complete");
    assert.equal((await filesUnder(out)).length > made.length, true, "a second run writes new pages under new random names and replaces none");
  });
});

test("no tool leaves a file behind in the paging directory when it stops on an error, and every tool refuses a bad argument with the same error document", async () => {
  await withCwd(async (cwd) => {
    for (const script of Object.values(ALL_TOOLS)) {
      for (const args of [[], "text", 5, null]) {
        const run = await tool(script, cwd, args);
        assert.equal(run.code, 1);
        const out: Json = JSON.parse(run.stdout);
        assert.equal(out.status, "failed");
        assert.equal(out.status_basis, "the tool stopped with an error (see error)");
        assert.match(out.error, /arguments must be a JSON object/);
        assert.equal(out.tool.length > 0, true);
      }
    }
    assert.deepEqual(await filesUnder(join(cwd, "work")), [], "an error made no paging file");
  });
});
