/**
 * virtualization-backup-forensics: a canary harness over every place the three tools read a name or a value from the
 * evidence. Each canary shape (the shapes the withholding rules name: prefixed tokens, a key id after a letter, AWS-style
 * secret keys with one and two `/`, a 16-byte base64 key with `/`, hex runs, a JWT, user-info in a URL, bare, after a
 * Proxmox storage name and inside a path, long random runs, and a lower-case token for the slots a tool folds) is planted
 * in every slot of every format, one file per slot so that no slot hides another, and each tool is run in and out of a
 * job, with a page of one row and with the default page. Then every byte an agent can read (stdout, stderr, every paging
 * file, every file the call made, and every file NAME it made) is searched for any twelve characters of the secret part,
 * in its own case, lower and upper, and for its base64 and its digests. Only the 0600 values file a job asks for with
 * write_text may hold an original.
 *
 * The shapes and the slots are written here from the formats' public descriptions (tests/pack-virtualization-harness.ts),
 * never from a tool's output. VIRT_CANARY_SHAPES=a,b narrows the shapes for a quick run.
 *
 * The backstop: the three tools seal every key and value at the way out and then check what they wrote. Two tests remove
 * the seal and the shape check on purpose (the tool is loaded in-process and its `seal` replaced by a function that lets
 * everything through): one shows that the check still catches a planted token in the answer and in a paging file,
 * replaces it by <withheld: N bytes> and makes the answer partial; the other plants every shape in every slot and finds
 * no canary anywhere. tests/pack-virtualization-review2.test.ts also removes the rules, to show the second check alone.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { ALL, plant, made, needles, registerCanary, unsealed } from "./pack-virtualization-canary-lib.ts";
import type { Files } from "./pack-virtualization-canary-lib.ts";
import { AUDIT, CHAIN, INVENTORY, VIRT, withCwd } from "./pack-virtualization-harness.ts";
import type { Json } from "./pack-virtualization-harness.ts";

registerCanary("snapshot_chain_check");
registerCanary("virtualization_inventory");

test("the backstop: with the seal and the shape check removed on purpose, the check on the way out still finds a planted token in the answer and in every paging file, replaces it by <withheld: N bytes> and makes the answer partial", async () => {
  const token = ALL.github.value;
  for (const [label, script, files, args] of [
    ["snapshot_chain_check", CHAIN, { "vm/a.vmdk": `# Disk DescriptorFile\nCID=aabbccdd\nparentCID=11223344\nparentFileNameHint="${token}.vmdk"\nRW 8 FLAT "${token}"\n`, "vm/b.vmdk": `# Disk DescriptorFile\nCID=aabbccde\nparentCID=ffffffff\nRW 8 FLAT "${token}"\n` }, { root: "inputs" }],
    ["virtualization_inventory", INVENTORY, { "vm/a.vmx": `displayName = "${token}"\nscsi0:0.fileName = "${token}.vmdk"\n`, "vm/b.vmx": `displayName = "${token}"\n` }, { root: "inputs" }],
    ["backup_audit_normalise", AUDIT, { "a/x.csv": `t,a\n2024-01-05T02:00:00Z,${token}\n2024-01-05T03:00:00Z,${token}\n` }, { path: "inputs/a/x.csv", format: "declared_csv", mapping: { time: "t", action: "a" } }],
  ] as const) {
    for (const limit of [1, 200]) {
      await withCwd(async (cwd) => {
        await plant(cwd, files as Files);
        const run = await unsealed(script, cwd, { ...args, limit });
        assert.doesNotMatch(run.stderr, /Traceback/, run.stderr.slice(-500));
        const doc: Json = JSON.parse(run.stdout);
        const written = await made(cwd);
        for (const n of needles(ALL.github)) {
          assert.equal(run.stdout.includes(n), false, `${label}: the answer holds ${n}`);
          for (const [rel, bytes] of written) assert.equal(bytes.includes(n) || rel.includes(n), false, `${label}: ${rel} holds ${n}`);
        }
        assert.ok(doc.boundary.strings_replaced_by_the_check > 0, `${label}: the check replaced nothing`);
        assert.match(run.stdout + written.map(([, b]) => b).join("\n"), /<withheld: \d+ bytes>/);
        assert.equal(doc.status, "partial", `${label} limit ${limit}: ${doc.status_basis}`);
        assert.match(doc.status_basis, /replaced by <withheld: N bytes>/);
        assert.ok(doc.boundary.replaced_at.length > 0);
      });
    }
  }
});


test("the way out is one block, the same text in the three tools", async () => {
  const blockOf = async (path: string): Promise<string> => {
    const text = await readFile(path, "utf8");
    const a = text.indexOf("# BEGIN SHARED BOUNDARY"), b = text.indexOf("# END SHARED BOUNDARY");
    assert.ok(a > 0 && b > a, `${path} carries the boundary block`);
    return text.slice(a, b);
  };
  const first = await blockOf(CHAIN);
  for (const p of [INVENTORY, AUDIT]) assert.equal(await blockOf(p), first);
  for (const p of [CHAIN, INVENTORY, AUDIT]) {
    const code = (await readFile(p, "utf8")).replace(/^\s*#.*$/gm, "");
    assert.equal((code.match(/print\(/g) ?? []).length, 4, `${p}: one print for the answer, one for an error answer and two for the last word after a signal (the answer through answer_text, and a short JSON when that could not be made)`);
    assert.match(code, /print\(answer_text\(\{"error"/);
    assert.match(code, /print\(answer_text\(\{"tool": TOOL, "parser": PARSER, "status": "partial"/);
    assert.doesNotMatch(code, /sys\.stdout\.write|sys\.stderr\.write/);
  }
  assert.ok(VIRT);
});

