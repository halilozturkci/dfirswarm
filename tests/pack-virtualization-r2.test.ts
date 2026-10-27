/**
 * virtualization-backup-forensics: the findings of the independent R2 review, each held by a test that failed on the code it
 * reviewed (origin/main 3e6d4314, pack 1.1.3).
 *
 *   - the audit tool read the clock every 1,024 lines, and one PBS line with a worker id of hundreds of kilobytes cost a tenth
 *     of a second of a Python loop: 1,100 such lines ran 80 s against a manifest timeout of 60;
 *   - snapshot_chain_check ended `complete` over a descriptor, a header or an extent line it had not read (a descriptor over
 *     20,000 lines or 1 MiB, an embedded descriptor over 1 MiB, a QCOW2 backing file name outside the file, an external data
 *     file named past the 64th header extension, a parentCID that is not a number, an extent line in a shape it does not read,
 *     a descriptor with no extent line);
 *   - a .vmx, .vmsd, .conf or storage.cfg line over 64 KiB, and the 500,001st line of a .vmx, was dropped and the answer said
 *     `complete` and "nothing was left out";
 *   - `qemu_img: auto` gave qemu-img a sparse VMDK of capacity 0, whose embedded descriptor qemu-img reads as a descriptor
 *     file and whose extents it then opens, wherever they are;
 *   - a `limit` of 100,000 over 200,000 descriptors made the answer 270 MB, 63 s and without its `status`;
 *   - `write_text` was refused only outside a job; the manifests say it is refused unless the job ran with secret_output;
 *   - the inventory read the clock once per file: a 16 MiB Proxmox .conf ran past max_seconds.
 *
 * Every fixture is made here from the formats' public descriptions (tests/pack-virtualization-harness.ts).
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { AUDIT, CHAIN, INVENTORY, asJob, body, exists, json, put, qcow2, refused, rowsOf, stubQemu, tool, vmdkDescriptor, vmdkSparse, vmx, vmsd, withCwd } from "./pack-virtualization-harness.ts";
import type { Json } from "./pack-virtualization-harness.ts";

const chains = (out: Json): string[] => (out.chains as Json[]).map((c) => c.status);

// ---- P1-1: the clock is read on every line --------------------------------------------------------------------------------

test("a PBS task index of long worker ids stops at max_seconds, not 1,024 lines after it", async () => {
  await withCwd(async (cwd) => {
    const wid = "a-b\\x41".repeat(5000);                                    // 30 KB of escapes per line
    const line = `UPID:n:00000001:00000002:00000003:60000000:backup:${wid}:root@pam: 60000000 OK\n`;
    await put(cwd, "inputs/idx", line.repeat(1500));
    const started = Date.now();
    const out = json(await tool(AUDIT, cwd, { path: "inputs/idx", format: "pve_task_index", max_seconds: 0.3 }));
    const seconds = (Date.now() - started) / 1000;
    assert.equal(out.status, "partial");
    assert.match(out.partial_reasons.join(" "), /max_seconds/);
    assert.ok(out.counts.events < 1000, `${out.counts.events} lines were read in ${seconds}s: the clock must stop the read inside the first lines`);
    assert.ok(seconds < 4, `the call took ${seconds}s for max_seconds 0.3`);
  });
});

test("the worker id of a PBS line is read back from its systemd escapes as before, and no loop checks the clock only every 1,024 lines", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/idx", "UPID:n:00000001:00000002:00000003:60000000:backup:vm-100\\x2d1\\x41b:root@pam: 60000000 OK\n");
    const out = body(await tool(AUDIT, cwd, { path: "inputs/idx", format: "pve_task_index" }));
    assert.equal(out.events[0].object, "vm/100-1Ab", "- is /, \\x2d is -, \\x41 is A");
    assert.equal(out.status, "complete");
  });
  assert.doesNotMatch(await readFile(AUDIT, "utf8"), /clock\.check\(1024\)/, "a line costs up to a tenth of a second: the clock is read on every line");
});

// ---- P1-2: a record that was not read whole is never a complete chain -------------------------------------------------------

/** What a chain row and the run say about one fixture set: neither may say complete. */
async function notComplete(cwd: string, root: string, why: RegExp, extra: Record<string, unknown> = {}) {
  const out = body(await tool(CHAIN, cwd, { root, ...extra }));
  assert.ok(out.chains.length >= 1, "the set has a chain row");
  for (const status of chains(out)) assert.notEqual(status, "complete", `${root}: a chain over a record that was not read whole is not complete`);
  assert.notEqual(out.status, "complete", `${root}: the run is not complete`);
  assert.match(JSON.stringify(out.partial_reasons) + JSON.stringify(out.sources) + JSON.stringify(out.disks) + JSON.stringify(out.markers), why);
  return out;
}

const PARENT_TAIL = ["parentCID=aaaa0001", 'parentFileNameHint="missing-parent.vmdk"', 'RW 2048 FLAT "nonexistent-flat.vmdk" 0'];

test("a descriptor of more than 20,000 lines whose parent and extent come after them is not a complete chain", async () => {
  await withCwd(async (cwd) => {
    const lines = ["# Disk DescriptorFile", "CID=bbbb0002", ...Array.from({ length: 20001 }, () => "#"), ...PARENT_TAIL, ""];
    await put(cwd, "inputs/a/d.vmdk", lines.join("\n"));
    await notComplete(cwd, "inputs/a", /more than 20000 lines/);
    // the same descriptor with its lines at the top is read, and says broken
    const top = ["# Disk DescriptorFile", "CID=bbbb0002", ...PARENT_TAIL, ...Array.from({ length: 100 }, () => "#"), ""];
    await put(cwd, "inputs/b/d.vmdk", top.join("\n"));
    const control = body(await tool(CHAIN, cwd, { root: "inputs/b" }));
    assert.equal(chains(control)[0], "broken");
  });
});

test("an embedded descriptor over 1 MiB, and a text descriptor over 1 MiB, are named in the chain row and the run", async () => {
  await withCwd(async (cwd) => {
    const pad = Array.from({ length: 14000 }, (_, i) => `# padding line ${String(i).padStart(6, "0")} ${"x".repeat(60)}`).join("\n");
    const desc = vmdkDescriptor({ cid: "bbbb0002", parentCid: "aaaa0001", parentHint: "missing-parent.vmdk", extents: [{ sectors: 2048, type: "SPARSE", name: "s.vmdk" }] });
    const [head, rest] = [desc.split("\n").slice(0, 3).join("\n"), desc.split("\n").slice(3).join("\n")];
    const big = `${head}\n${pad}\n${rest}`;
    assert.ok(big.length > 1 << 20, "the descriptor is over the 1 MiB read cap");
    await put(cwd, "inputs/sparse/s.vmdk", vmdkSparse({ descriptor: big }));
    const out = await notComplete(cwd, "inputs/sparse", /longer than 1048576 bytes/);
    assert.equal(out.states.partial, 1);
    await put(cwd, "inputs/text/t.vmdk", big);
    const text = await notComplete(cwd, "inputs/text", /longer than 1048576 bytes/);
    assert.notEqual(chains(text)[0], "complete", "the chain row of a text descriptor over 1 MiB no longer says complete beside a partial run");
  });
});

test("a QCOW2 whose backing file name lies outside the file, or whose external data file is named past the 64th header extension, is not a complete chain", async () => {
  await withCwd(async (cwd) => {
    const outside = qcow2({ backing: "base.qcow2" });
    outside.writeBigUInt64BE(2n ** 40n, 8);                                  // backing_file_offset far outside the file
    await put(cwd, "inputs/c1/top.qcow2", outside);
    await notComplete(cwd, "inputs/c1", /backing file name lies outside the file/);

    const data = Buffer.from("missing-data.bin");
    const ext = (type: number, payload: Buffer): Buffer => {
      const h = Buffer.alloc(8);
      h.writeUInt32BE(type, 0); h.writeUInt32BE(payload.length, 4);
      return Buffer.concat([h, payload, Buffer.alloc((-payload.length) & 7)]);
    };
    const withExt = (pad: number): Buffer => {
      const image = qcow2({ incompat: 4n });                                 // feature bit 2: external data file
      const exts = Buffer.concat([...Array.from({ length: pad }, () => ext(0x6803f857, Buffer.alloc(0))), ext(0x44415441, data), Buffer.alloc(8)]);
      exts.copy(image, 104);
      return image;
    };
    await put(cwd, "inputs/c2/top.qcow2", withExt(70));
    await notComplete(cwd, "inputs/c2", /more than 64 extensions/);
    await put(cwd, "inputs/c3/top.qcow2", withExt(0));
    const control = body(await tool(CHAIN, cwd, { root: "inputs/c3" }));
    assert.equal(chains(control)[0], "data_file_missing", "named early, the data file is read and found missing");
  });
});

test("a parentCID that is not a number, and a descriptor whose extent lines the tool cannot read or that has none, are not complete chains", async () => {
  await withCwd(async (cwd) => {
    const base = (parent: string, extent: string | null): string => ["# Disk DescriptorFile", "version=1", "CID=bbbb0002", `parentCID=${parent}`, 'createType="monolithicFlat"',
      'parentFileNameHint="missing-parent.vmdk"', "", "# Extent description", ...(extent === null ? [] : [extent]), ""].join("\n");
    await put(cwd, "inputs/d/d.vmdk", base("zzzz0001", 'RW 2048 FLAT "gone.vmdk" 0'));
    await notComplete(cwd, "inputs/d", /parentCID is not 1 to 8 hexadecimal digits/);
    let n = 0;
    for (const extent of ['RW 2048 FLAT gone.vmdk 0', 'rw 2048 flat "gone.vmdk" 0', 'RW -5 FLAT "gone.vmdk" 0', 'RW 2048 FLAT "gone.vmdk" 0 trailing']) {
      n += 1;
      await put(cwd, `inputs/e${n}/d.vmdk`, base("ffffffff", extent));
      await notComplete(cwd, `inputs/e${n}`, /begin like an extent line/);
    }
    await put(cwd, "inputs/e0/d.vmdk", base("ffffffff", null));
    await notComplete(cwd, "inputs/e0", /lists no extent line/);
    // the control: the same descriptor with a readable extent that is present is complete
    await put(cwd, "inputs/ok/d.vmdk", base("ffffffff", 'RW 2048 FLAT "gone.vmdk" 0').replace(/parentFileNameHint=.*\n/, ""));
    await put(cwd, "inputs/ok/gone.vmdk", Buffer.alloc(2048 * 512));
    const ok = body(await tool(CHAIN, cwd, { root: "inputs/ok" }));
    assert.equal(chains(ok)[0], "complete");
    assert.equal(ok.status, "complete");
  });
});

// ---- P1-3: a line that was not read is not nothing left out ------------------------------------------------------------------

test("a .vmx, .vmsd, .conf or storage.cfg line over 64 KiB makes the file partial in the inventory and the chain tool names it", async () => {
  await withCwd(async (cwd) => {
    const long = "x".repeat(70000);
    await put(cwd, "inputs/vmware/a.vmx", vmx([["displayName", "vm1"], ["scsi0:0.fileName", long], ["scsi0:1.fileName", "b.vmdk"]]));
    await put(cwd, "inputs/vmware/a.vmsd", vmsd({ snapshots: [{ index: 0, uid: "1", name: long, disks: ["b.vmdk"] }, { index: 1, uid: "2", name: "second", disks: ["b.vmdk"] }] }));
    await put(cwd, "inputs/pve/qemu-server/100.conf", `name: vm\nmemory: 1024\nscsi0: local:100/${long}.qcow2,size=1G\nscsi1: local:100/vm-100-disk-1.qcow2,size=1G\n`);
    await put(cwd, "inputs/pve/storage.cfg", `dir: local\n\tpath /var/lib/vz\n\tcontent ${long}\n\nlvm: data\n\tvgname vg\n`);
    const inv = body(await tool(INVENTORY, cwd, { root: "inputs" }));
    assert.equal(inv.states.parsed ?? 0, 0, "no file of the four was read whole");
    assert.equal(inv.states.partial, 4);
    assert.equal(inv.status, "partial");
    const reasons = (inv.sources as Json[]).map((s) => s.reason).join("\n");
    assert.equal((reasons.match(/line\(s\) of 65536 bytes or more were not read \(the first is line \d+\)/g) ?? []).length, 4);
    const chain = body(await tool(CHAIN, cwd, { root: "inputs/vmware" }));
    assert.equal(chain.states.partial, 2);
    assert.equal(chain.status, "partial");
    assert.match((chain.sources as Json[]).map((s) => s.reason).join("\n"), /1 line\(s\) over 65536 bytes were not read \(the first is line \d+\)/);
  });
});

test("the 500,001st line of a .vmx is named by the chain tool as it is by the inventory", async () => {
  await withCwd(async (cwd) => {
    const lines = ['displayName = "vm1"', ...Array.from({ length: 500000 }, (_, i) => `k${i} = "v"`), 'scsi0:0.fileName = "after.vmdk"'];
    await put(cwd, "inputs/v/a.vmx", lines.join("\n") + "\n");
    const chain = body(await tool(CHAIN, cwd, { root: "inputs/v" }));
    assert.equal(chain.states.partial, 1);
    assert.equal(chain.status, "partial");
    assert.match(JSON.stringify(chain.sources), /more than 500000 lines/);
    const inv = body(await tool(INVENTORY, cwd, { root: "inputs/v" }));
    assert.equal(inv.status, "partial");
  });
});

// ---- P1-4: qemu-img is never given a file that names files outside the set -----------------------------------------------------

test("qemu_img: auto does not give qemu-img a sparse VMDK of capacity 0 whose embedded descriptor names an extent outside the set", async () => {
  await withCwd(async (cwd) => {
    const bin = await stubQemu(cwd);
    const log = join(cwd, "q.log");
    const outside = vmdkDescriptor({ cid: "aaaa0001", createType: "monolithicFlat", extents: [{ sectors: 2048, type: "FLAT", name: "/elsewhere/secret-flat.bin", offset: 0 }] });
    await put(cwd, "inputs/q/zero.vmdk", vmdkSparse({ descriptor: outside, capacity: 0 }));
    // the control: a monolithic sparse disk that names its own file is still given to qemu-img
    const own = vmdkDescriptor({ cid: "aaaa0002", createType: "monolithicSparse", extents: [{ sectors: 2048, type: "SPARSE", name: "own.vmdk" }] });
    await put(cwd, "inputs/q/own.vmdk", vmdkSparse({ descriptor: own }));
    // a sparse VMDK of a nonzero capacity whose embedded descriptor names another file is not given to it either
    const other = vmdkDescriptor({ cid: "aaaa0003", createType: "twoGbMaxExtentSparse", extents: [{ sectors: 2048, type: "SPARSE", name: "../outside/other.vmdk" }] });
    await put(cwd, "inputs/q/other.vmdk", vmdkSparse({ descriptor: other }));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto" }, { QEMU_STUB_LOG: log }, bin));
    const calls = (await readFile(log, "utf8")).trim().split("\n").map((l) => JSON.parse(l) as string[]);
    assert.deepEqual(calls.map((c) => c[c.length - 1]).sort(), ["./inputs/q/own.vmdk"], "only the disk that names itself reaches qemu-img, with its path made unmistakably a path");
    assert.equal(out.qemu_img.checked, 1);
    assert.equal(out.qemu_img.skipped.sparse_vmdk_names_other_files, 2);
    assert.equal(out.disks.find((d: Json) => d.file === "zero.vmdk").qemu_img, undefined);
  });
});

// ---- P1-5, P2-3: the answer is bounded and carries its status ---------------------------------------------------------------------

test("a limit of 100,000 shows the rows inline only up to a size; every row is in the paging file and the answer keeps its status", async () => {
  await withCwd(async (cwd) => {
    const lines: string[] = [];
    for (let i = 0; i < 6000; i++) lines.push(JSON.stringify({ time: "2026-01-01T00:00:00Z", action: `action-${i % 50}`, object: `object-${i}`, actor: "u", result: "ok", message: "m".repeat(200) }));
    await put(cwd, "inputs/ev.jsonl", lines.join("\n") + "\n");
    const args = { path: "inputs/ev.jsonl", format: "declared_jsonl", limit: 100000, mapping: { time: "time", action: "action", object: "object", actor: "actor", result: "result", message: "message" } };
    const run = await asJob(AUDIT, cwd, args);
    const out = body(run);
    assert.equal(out.status, "complete");
    assert.equal(out.counts.events, 6000);
    assert.ok(out.events.length < 6000 && out.events.length > 100, `${out.events.length} rows inline`);
    assert.equal(out.pages.events.truncated, true);
    assert.match(out.pages.events.inline_cut_by_size, /stop at about 1048576 bytes/);
    assert.ok(run.stdout.length < 6 * 1024 * 1024, `${run.stdout.length} bytes of answer`);
    const rows = await rowsOf(cwd, out, "events");
    assert.equal(rows.length, 6000, "nothing is lost: the paging file holds every row");
    assert.deepEqual(rows.slice(0, out.events.length).map((r) => r.seq), out.events.map((r: Json) => r.seq));
  });
});

test("the chain tool cuts its inline lists by size too, and the cut is named", async () => {
  await withCwd(async (cwd) => {
    for (let i = 0; i < 3000; i++) await put(cwd, `inputs/d/d${i}.vmdk`, vmdkDescriptor({ cid: (0xa0000000 + i).toString(16), createType: "monolithicFlat", extents: [{ sectors: 8, type: "FLAT", name: `flat-${"n".repeat(200)}-${i}.vmdk` }] }));
    const out = body(await asJob(CHAIN, cwd, { root: "inputs/d", limit: 100000 }));
    assert.ok(["complete", "partial"].includes(out.status), "the answer carries its status");
    assert.ok(out.extents.length < 3000, `${out.extents.length} extent rows inline`);
    assert.match(out.pages.extents.inline_cut_by_size, /whatever limit says/);
    assert.equal((await rowsOf(cwd, out, "extents")).length, 3000);
  });
});

// ---- P2-1: write_text needs a job that was run as secret output ---------------------------------------------------------------------

test("write_text is refused in a job that was not run with secret_output, in all three tools, and writes nothing", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/vm/a.vmx", vmx([["displayName", "vm1"], ["scsi0:0.fileName", "a.vmdk"]]));
    await put(cwd, "inputs/vm/a.vmdk", vmdkDescriptor({ cid: "aaaa0001", extents: [{ sectors: 8, type: "FLAT", name: "a-flat.vmdk" }] }));
    await put(cwd, "inputs/idx", "UPID:n:00000001:00000002:00000003:60000000:backup:vm-100:root@pam: 60000000 OK\n");
    for (const [script, args, file] of [[INVENTORY, { root: "inputs/vm" }, "inventory-values.jsonl"], [CHAIN, { root: "inputs/vm" }, "chain-values.jsonl"], [AUDIT, { path: "inputs/idx" }, "audit-values.jsonl"]] as const) {
      const plain = refused(await asJob(script, cwd, { ...args, write_text: true }, undefined, { SECRET_OUTPUT: "" }, `plain-${file}`));
      assert.match(plain.error, /write_text is refused in a job that was not run as secret output/);
      assert.match(plain.error, /Nothing was written/);
      assert.equal(await exists(join(cwd, `plain-${file}`, file)), false);
      assert.deepEqual(await readdir(join(cwd, `plain-${file}`)), [], "nothing at all under $OUT");
      const secret = body(await asJob(script, cwd, { ...args, write_text: true }, undefined, { SECRET_OUTPUT: "1" }, `secret-${file}`));
      assert.equal(secret.text.requested, true);
      assert.equal(await exists(join(cwd, `secret-${file}`, file)), true, "a secret job writes the values file");
      // outside a job it is still refused, by its own message
      assert.match(refused(await tool(script, cwd, { ...args, write_text: true })).error, /refused outside a job/);
    }
  });
});

// ---- P2-2: the inventory reads the clock inside a file --------------------------------------------------------------------------

test("a Proxmox .conf of a hundred thousand sections stops at max_seconds inside the file and names the file partial", async () => {
  await withCwd(async (cwd) => {
    const parts = ["name: vm", "memory: 1024", "scsi0: local:100/vm.qcow2,size=1G"];
    for (let i = 0; i < 150000; i++) parts.push(`[s${i}]`, "snaptime: 1700000000", `parent: s${i - 1}`, `vmstate: local:vm-state-${i}`, "scsi0: local:100/vm.qcow2,size=1G");
    await put(cwd, "inputs/pve/qemu-server/100.conf", parts.join("\n") + "\n");
    const started = Date.now();
    const out = body(await tool(INVENTORY, cwd, { root: "inputs/pve", max_seconds: 1, max_file_bytes: 268435456 }));
    const seconds = (Date.now() - started) / 1000;
    assert.equal(out.status, "partial");
    assert.equal(out.states.partial, 1);
    assert.match(JSON.stringify(out.sources), /max_seconds \(1\.0\) was reached while this file was read/);
    assert.ok(seconds < 6, `the call took ${seconds}s for max_seconds 1`);
  });
});
