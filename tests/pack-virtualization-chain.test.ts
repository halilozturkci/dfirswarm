/**
 * virtualization-backup-forensics: snapshot_chain_check reads the descriptors and headers of virtual-disk files and says
 * how they chain. Every fixture is built by the test from the formats' public descriptions (tests/pack-virtualization-harness.ts),
 * never from the tool's output. What is held here: a chain is judged over the files given and a name inside a file is
 * looked up among them and never opened; identities are compared where the format records one and QCOW2's lack of one is
 * said; a marker is a candidate with its observation; every limit (files, depth, snapshots, chain length, time) is reported
 * and nothing is cut without the whole being named; and no planted secret reaches an answer or a file but the 0600 values file.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import {
  CANARY, CHAIN, G, asJob, body, everythingBut, exists, filesUnder, guidBytes, json, put, qcow2, refused, rowsOf, stubQemu, tool, vhdDifferencing, vhdDynamic,
  vhdFixed, vhdx, vmdkDescriptor, vmdkSparse, vmsd, vmx, withCwd, gone, pidFile, startDetached,
} from "./pack-virtualization-harness.ts";
import type { Json } from "./pack-virtualization-harness.ts";

const BASE = "aabbccdd", MID = "11223344", TOP = "55667788";

/** A three-disk VMware chain: a flat base, and two deltas, each recording its parent's CID. */
async function vmwareChain(cwd: string, opts: { topParentCid?: string; omit?: string[] } = {}): Promise<void> {
  const files: Record<string, string | Buffer> = {
    "inputs/vm/base.vmdk": vmdkDescriptor({ cid: BASE, extents: [{ sectors: 2048, type: "FLAT", name: "base-flat.vmdk", offset: 0 }] }),
    "inputs/vm/base-flat.vmdk": Buffer.alloc(2048 * 512),
    "inputs/vm/base-000001.vmdk": vmdkDescriptor({ cid: MID, parentCid: BASE, createType: "vmfsSparse", parentHint: "base.vmdk", extents: [{ sectors: 2048, type: "VMFSSPARSE", name: "base-000001-delta.vmdk" }] }),
    "inputs/vm/base-000001-delta.vmdk": vmdkSparse({ version: 1 }),
    "inputs/vm/base-000002.vmdk": vmdkDescriptor({ cid: TOP, parentCid: opts.topParentCid ?? MID, createType: "vmfsSparse", parentHint: "base-000001.vmdk", extents: [{ sectors: 2048, type: "VMFSSPARSE", name: "base-000002-delta.vmdk" }] }),
    "inputs/vm/base-000002-delta.vmdk": vmdkSparse({ version: 1 }),
  };
  for (const [rel, data] of Object.entries(files)) if (!opts.omit?.includes(rel)) await put(cwd, rel, data);
}

const chainOf = (out: Json, leaf: string): Json => out.chains.find((c: Json) => c.leaf_file.endsWith(leaf));
const markerKinds = async (cwd: string, out: Json): Promise<string[]> => (await rowsOf(cwd, out, "markers")).map((m) => m.kind);

test("a VMware chain whose parents are present and whose CIDs agree is complete, edge by edge, with its extents checked", async () => {
  await withCwd(async (cwd) => {
    await vmwareChain(cwd);
    const out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.chain_summary.complete, 1);
    const top = chainOf(out, "base-000002.vmdk");
    assert.equal(top.status, "complete");
    assert.equal(top.chain_length, 3);
    assert.equal(top.chain_shown.length, 3);
    assert.equal(out.edges.length, 2);
    for (const e of out.edges) {
      assert.equal(e.id_check, "match");
      assert.equal(e.resolution, "relative_exact");
      assert.ok(e.resolved_to);
    }
    const flat = out.extents.find((x: Json) => x.type === "FLAT");
    assert.equal(flat.state, "present");
    assert.equal(flat.expected_size_at_least, 2048 * 512);
    assert.deepEqual(await markerKinds(cwd, out), [], "a whole chain raises no marker");
    // The extent files are not disks of their own and are not leaves.
    assert.equal(out.chains.length, 1);
    assert.match(out.chain_note, /not a disk that boots/);
  });
});

test("a child that records a different parent CID than the parent carries is an identity mismatch, with both values, and the chain is not called complete", async () => {
  await withCwd(async (cwd) => {
    await vmwareChain(cwd, { topParentCid: "deadbeef" });
    const out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    const edge = out.edges.find((e: Json) => e.id_check === "mismatch");
    assert.equal(edge.recorded_by_child, "deadbeef");
    assert.equal(edge.carried_by_parent, MID);
    assert.equal(chainOf(out, "base-000002.vmdk").status, "identity_mismatch");
    assert.equal(out.chain_summary.complete, undefined);
    assert.ok((await markerKinds(cwd, out)).includes("parent_cid_mismatch"));
  });
});

test("a parent that is not among the files is missing, whatever the hint names; nothing outside the set is opened", async () => {
  await withCwd(async (cwd) => {
    await vmwareChain(cwd, { omit: ["inputs/vm/base-000001.vmdk"] });
    // A hint that points at a real file on this machine is still a name looked up among the files given.
    await put(cwd, "inputs/vm/elsewhere-000009.vmdk", vmdkDescriptor({ cid: "01020304", parentCid: "aabbccdd", parentHint: "../../../../../../../etc/hostname", extents: [{ sectors: 8, type: "FLAT", name: "/etc/hostname" }] }));
    await put(cwd, "inputs/vm/abs-000009.vmdk", vmdkDescriptor({ cid: "01020305", parentCid: "aabbccdd", parentHint: "/etc/hosts", extents: [{ sectors: 8, type: "FLAT", name: "/etc/passwd" }] }));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    const top = chainOf(out, "base-000002.vmdk");
    assert.equal(top.status, "broken");
    assert.match(top.detail, /not in the set/);
    const ours = out.edges.find((e: Json) => e.parent_name === "base-000001.vmdk");
    assert.equal(ours.resolved_to, null);
    assert.equal(ours.resolution, "not_in_set");
    for (const hint of ["../../../../../../../etc/hostname", "/etc/hosts"]) {
      const e = out.edges.find((x: Json) => x.parent_name === hint);
      assert.equal(e.resolved_to, null, `${hint} is not a file of the set`);
    }
    const kinds = await markerKinds(cwd, out);
    assert.ok(kinds.includes("parent_missing"));
    assert.ok(kinds.includes("extent_missing"), "an extent named by an absolute path outside the set is missing");
    assert.equal(out.status, "complete", "every file was read; a broken chain is a finding, not a failed read");
  });
});

test("a hint written for another machine (a Windows path) matches by file name alone, and the answer says so; two files of that name are ambiguous", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/vm/parent.vmdk", vmdkDescriptor({ cid: BASE, extents: [{ sectors: 8, type: "FLAT", name: "parent-flat.vmdk" }] }));
    await put(cwd, "inputs/vm/parent-flat.vmdk", Buffer.alloc(8 * 512));
    await put(cwd, "inputs/vm/child.vmdk", vmdkDescriptor({ cid: MID, parentCid: BASE, parentHint: "C:\\\\Virtual Machines\\\\Parent.VMDK", extents: [{ sectors: 8, type: "FLAT", name: "child-flat.vmdk" }] }));
    await put(cwd, "inputs/vm/child-flat.vmdk", Buffer.alloc(8 * 512));
    let out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    const edge = out.edges.find((e: Json) => e.resolved_to);
    assert.equal(edge.resolution, "basename_only");
    assert.equal(edge.id_check, "match");
    await put(cwd, "inputs/vm/sub/parent.vmdk", vmdkDescriptor({ cid: "99999999", extents: [{ sectors: 8, type: "FLAT", name: "x" }] }));
    out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    const ambiguous = out.edges.find((e: Json) => e.resolution === "ambiguous_basename");
    assert.ok(ambiguous, "two files of that name cannot decide the parent");
    assert.equal(ambiguous.resolved_to, null);
    assert.ok((await markerKinds(cwd, out)).includes("parent_ambiguous"));
  });
});

test("two descriptors that name each other as parents are a cycle; the tool ends, names it and does not loop", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/vm/a.vmdk", vmdkDescriptor({ cid: "0000000a", parentCid: "0000000b", parentHint: "b.vmdk", extents: [{ sectors: 8, type: "FLAT", name: "af" }] }));
    await put(cwd, "inputs/vm/b.vmdk", vmdkDescriptor({ cid: "0000000b", parentCid: "0000000a", parentHint: "a.vmdk", extents: [{ sectors: 8, type: "FLAT", name: "bf" }] }));
    await put(cwd, "inputs/vm/self.vmdk", vmdkDescriptor({ cid: "0000000c", parentCid: "0000000c", parentHint: "self.vmdk", extents: [{ sectors: 8, type: "FLAT", name: "sf" }] }));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    assert.ok((await markerKinds(cwd, out)).includes("chain_cycle"));
    const disks = out.disks.filter((d: Json) => d.chain_state === "cycle");
    assert.ok(disks.length >= 3, "every disk on a cycle says so");
    // no leaf exists on a pure cycle (every file on it is named by another), and each cycle still has a chain row
    assert.equal(out.chain_summary.cycle, 2, "the a/b cycle and the disk that names itself");
    assert.equal(out.chain_summary.complete, undefined);
    const rows = out.chains.filter((c: Json) => c.status === "cycle");
    assert.deepEqual(rows.map((c: Json) => c.leaf_file).sort(), ["a.vmdk", "self.vmdk"]);
    assert.equal(rows.find((c: Json) => c.leaf_file === "self.vmdk").chain_length, 1);
    assert.equal(rows.find((c: Json) => c.leaf_file === "a.vmdk").chain_length, 2);
  });
});

test("a chain deeper than max_chain_depth is too deep and says so; the walk is iterative and a long chain costs no recursion", async () => {
  await withCwd(async (cwd) => {
    const n = 3000;
    for (let i = 0; i < n; i++) {
      const cid = (0x10000000 + i).toString(16);
      const parent = (0x10000000 + i - 1).toString(16);
      await put(cwd, `inputs/vm/d${String(i).padStart(5, "0")}.vmdk`, vmdkDescriptor(i === 0
        ? { cid, extents: [{ sectors: 8, type: "FLAT", name: "f" }] }
        : { cid, parentCid: parent, parentHint: `d${String(i - 1).padStart(5, "0")}.vmdk`, extents: [{ sectors: 8, type: "FLAT", name: "f" }] }));
    }
    const full = body(await tool(CHAIN, cwd, { root: "inputs/vm", max_chain_depth: 100000, limit: 5 }));
    assert.equal(chainOf(full, `d${String(n - 1).padStart(5, "0")}.vmdk`).chain_length, n);
    assert.equal(chainOf(full, `d${String(n - 1).padStart(5, "0")}.vmdk`).chain_shown.length, 50, "the page shows the first 50; the length is the whole");
    assert.equal(chainOf(full, `d${String(n - 1).padStart(5, "0")}.vmdk`).chain_shown_cut, true);
    const cut = body(await tool(CHAIN, cwd, { root: "inputs/vm", max_chain_depth: 100 }));
    assert.equal(cut.chain_summary.too_deep, 1);
  });
});

test("the sparse extent header is read for its descriptor and its flags: an unclean-shutdown byte and a text-mode transfer are candidates, not verdicts", async () => {
  await withCwd(async (cwd) => {
    const desc = vmdkDescriptor({ cid: BASE, createType: "monolithicSparse", extents: [{ sectors: 2048, type: "SPARSE", name: "mono.vmdk" }] });
    await put(cwd, "inputs/vm/mono.vmdk", vmdkSparse({ descriptor: desc, unclean: true, newline: [0x0a, 0x20, 0x0d, 0x20] }));
    await put(cwd, "inputs/vm/clean.vmdk", vmdkSparse({ descriptor: vmdkDescriptor({ cid: MID, createType: "monolithicSparse", extents: [{ sectors: 8, type: "SPARSE", name: "clean.vmdk" }] }) }));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    const rows = await rowsOf(cwd, out, "markers");
    const unclean = rows.find((m) => m.kind === "unclean_shutdown_flag");
    assert.ok(unclean);
    assert.match(unclean.observation, /uncleanShutdown byte is 1/);
    assert.match(unclean.reading, /candidate|not a verdict/);
    assert.ok(rows.some((m) => m.kind === "newline_detection_mismatch"));
    assert.equal(rows.filter((m) => m.kind === "unclean_shutdown_flag").length, 1, "the clean extent raises none");
    const mono = out.disks.find((d: Json) => d.file === "mono.vmdk");
    assert.equal(mono.own_id, BASE, "the CID embedded in the sparse extent was read");
    assert.equal(mono.detail.descriptor_source, "embedded in a sparse extent");
    assert.ok(chainOf(out, "mono.vmdk"), "a monolithic sparse disk names its own file as its extent, and is still a disk with a chain of its own");
    assert.equal(chainOf(out, "mono.vmdk").status, "complete");
    // A sparse extent with no descriptor is an extent, not a disk with an identity.
    await put(cwd, "inputs/vm/ext.vmdk", vmdkSparse({}));
    const again = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    assert.equal(again.disks.find((d: Json) => d.file === "ext.vmdk").role, "extent_only");
    assert.equal(again.chains.some((c: Json) => c.leaf_file === "ext.vmdk"), false);
  });
});

test("a flat extent shorter than its descriptor says is short, a missing one is missing, a COWD delta extent is recognised and named by its descriptor, and one no descriptor names is a candidate", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/vm/d.vmdk", vmdkDescriptor({ cid: BASE, extents: [{ sectors: 100, type: "FLAT", name: "d-flat.vmdk", offset: 0 }, { sectors: 100, type: "FLAT", name: "gone-flat.vmdk", offset: 0 }, { sectors: 100, type: "ZERO" }, { sectors: 100, type: "VMFSSPARSE", name: "old.vmdk" }] }));
    await put(cwd, "inputs/vm/d-flat.vmdk", Buffer.alloc(100 * 512 - 1));
    await put(cwd, "inputs/vm/old.vmdk", Buffer.concat([Buffer.from("COWD"), Buffer.alloc(512)]));
    await put(cwd, "inputs/vm/orphan-delta.vmdk", Buffer.concat([Buffer.from("COWD"), Buffer.alloc(512)]));
    await put(cwd, "inputs/vm/orphan-sparse.vmdk", vmdkSparse({}));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    assert.deepEqual(out.extents.map((x: Json) => x.state), ["short", "missing", "not_a_file_extent", "present"]);
    const cowd = out.sources.find((s: Json) => s.file === "old.vmdk");
    assert.equal(cowd.state, "parsed");
    assert.equal(cowd.info.header_read, false);
    assert.match(cowd.info.note, /recognised by its first four bytes; its header is not read/);
    assert.equal(out.status, "complete", "findings about extents are not failed reads");
    const markers = await rowsOf(cwd, out, "markers");
    const orphans = markers.filter((m) => m.kind === "extent_without_descriptor").map((m) => out.sources.find((s: Json) => s.source_id === m.source_ids[0]).file).sort();
    assert.deepEqual(orphans, ["orphan-delta.vmdk", "orphan-sparse.vmdk"], "the extent a descriptor names is not an orphan");
    assert.equal(out.chains.length, 1, "extents are not leaves");
  });
});

test("VHD: the footer is read with its checksum, a differencing disk's parent id is compared with the parent's unique id, and the locators are names to look up", async () => {
  await withCwd(async (cwd) => {
    const BASE_ID = "11111111-aaaa-bbbb-cccc-000000000001", CHILD_ID = "11111111-aaaa-bbbb-cccc-000000000002";
    await put(cwd, "inputs/hv/base.vhd", vhdDynamic({ uid: BASE_ID }));
    await put(cwd, "inputs/hv/child.vhd", vhdDifferencing({ uid: CHILD_ID, parentUid: BASE_ID, parentName: "C:\\VMs\\base.vhd", locators: [{ code: "W2ru", text: ".\\base.vhd" }] }));
    await put(cwd, "inputs/hv/fixed.vhd", vhdFixed("11111111-aaaa-bbbb-cccc-000000000003"));
    let out = body(await tool(CHAIN, cwd, { root: "inputs/hv" }));
    const child = out.disks.find((d: Json) => d.file === "child.vhd");
    assert.equal(child.detail.disk_type, "differencing");
    assert.equal(child.detail.footer_checksum_ok, true);
    assert.equal(child.detail.dynamic_header_checksum_ok, true);
    assert.equal(child.detail.parent_unique_id, BASE_ID.toUpperCase());
    assert.equal(child.detail.created_utc, "2023-11-14T22:13:20Z", "seconds since 2000-01-01 converted");
    assert.equal(out.disks.find((d: Json) => d.file === "fixed.vhd").detail.disk_type, "fixed");
    const edge = out.edges.find((e: Json) => e.child === child.source_id);
    assert.equal(edge.id_check, "match");
    assert.equal(edge.resolution, "basename_only", "the header's name is a Windows path; the locator's relative name was tried only if the first failed");
    assert.equal(chainOf(out, "child.vhd").status, "complete");
    // a different parent file by id
    await put(cwd, "inputs/hv/base.vhd", vhdDynamic({ uid: "22222222-aaaa-bbbb-cccc-000000000009" }));
    out = body(await tool(CHAIN, cwd, { root: "inputs/hv" }));
    assert.equal(chainOf(out, "child.vhd").status, "identity_mismatch");
    assert.ok((await markerKinds(cwd, out)).includes("parent_unique_id_mismatch"));
  });
});

test("VHD: a file format version this tool does not know is unsupported, not read", async () => {
  await withCwd(async (cwd) => {
    const f = vhdDynamic({ uid: "11111111-aaaa-bbbb-cccc-000000000001" });
    f.writeUInt32BE(0x00020000, 12);
    f.writeUInt32BE(0x00020000, f.length - 512 + 12);
    await put(cwd, "inputs/hv/v2.vhd", f);
    const out = body(await tool(CHAIN, cwd, { root: "inputs/hv" }));
    const s = out.sources.find((x: Json) => x.file === "v2.vhd");
    assert.equal(s.state, "unsupported");
    assert.match(s.reason, /VHD file format version 0x00020000 is not one this tool reads/);
    assert.equal(out.status, "partial");
  });
});

test("VHD markers: a footer whose checksum is wrong is reported as such, a saved-state byte and a footer copy that differs are candidates", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/hv/saved.vhd", vhdDynamic({ uid: "11111111-aaaa-bbbb-cccc-000000000001", saved: true, mismatchCopy: true }));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/hv" }));
    const kinds = await markerKinds(cwd, out);
    assert.ok(kinds.includes("vhd_saved_state_flag"));
    assert.ok(kinds.includes("vhd_footer_copy_differs"));
    // A footer with a broken checksum
    const bad = vhdDynamic({ uid: "11111111-aaaa-bbbb-cccc-000000000001" });
    bad[600] ^= 0xff; // inside the dynamic header (bytes 512 to 1535): its checksum no longer holds
    await put(cwd, "inputs/hv/bad.vhd", bad);
    const two = body(await tool(CHAIN, cwd, { root: "inputs/hv" }));
    assert.equal(two.disks.find((d: Json) => d.file === "bad.vhd").detail.dynamic_header_checksum_ok, false);
  });
});

test("VHDX: the current header is the valid one with the higher sequence number, the parent locator is read, and parent_linkage is held against the parent's DataWriteGuid (MS-VHDX), not its VirtualDiskId", async () => {
  await withCwd(async (cwd) => {
    // MS-VHDX: a differencing disk's parent_linkage holds the DataWriteGuid of the parent's header. The parent's
    // VirtualDiskId (its Page 83 data) is a different value and is NOT what a child records.
    const PARENT_DISK = "AAAAAAAA-0000-4000-8000-000000000001", PARENT_WRITE = "DDDDDDDD-0000-4000-8000-0000000000D1", CHILD = "AAAAAAAA-0000-4000-8000-000000000002";
    await put(cwd, "inputs/hv/base.vhdx", vhdx({ diskId: PARENT_DISK, dataWriteGuid: PARENT_WRITE }));
    await put(cwd, "inputs/hv/child.avhdx", vhdx({ diskId: CHILD, parent: { linkage: PARENT_WRITE, relative: ".\\base.vhdx", absolute: "C:\\VMs\\base.vhdx", volume: "\\\\?\\Volume{abc}\\" } }));
    let out = body(await tool(CHAIN, cwd, { root: "inputs/hv" }));
    const child = out.disks.find((d: Json) => d.file === "child.avhdx");
    const parent = out.disks.find((d: Json) => d.file === "base.vhdx");
    assert.equal(child.detail.virtual_disk_id, CHILD);
    assert.equal(parent.detail.virtual_disk_id, PARENT_DISK, "the VirtualDiskId is kept as information");
    assert.equal(parent.own_id, PARENT_WRITE, "the identity a child is held against is the DataWriteGuid");
    assert.equal(parent.detail.data_write_guid, PARENT_WRITE);
    assert.equal(child.detail.has_parent, true);
    assert.equal(child.detail.parent_linkage, PARENT_WRITE);
    assert.deepEqual(child.detail.sequence_numbers, [1, 2]);
    assert.equal(child.detail.current_header_offset, 131072);
    assert.equal(child.detail.headers_checksum_ok, 2);
    assert.equal(child.detail.region_table_checksum_ok, true);
    assert.equal(out.edges[0].id_check, "match");
    assert.match(out.edges[0].compared, /DataWriteGuid/);
    assert.equal(chainOf(out, "child.avhdx").status, "complete");
    assert.deepEqual(await markerKinds(cwd, out), []);
    // A child whose linkage names the parent's VirtualDiskId does not link to it: that is the field libvhdi refuses too
    await put(cwd, "inputs/hv/child.avhdx", vhdx({ diskId: CHILD, parent: { linkage: PARENT_DISK, relative: ".\\base.vhdx" } }));
    out = body(await tool(CHAIN, cwd, { root: "inputs/hv" }));
    assert.equal(out.edges[0].id_check, "mismatch");
    assert.equal(out.edges[0].recorded_by_child, PARENT_DISK);
    assert.equal(out.edges[0].carried_by_parent, PARENT_WRITE);
    assert.equal(chainOf(out, "child.avhdx").status, "identity_mismatch");
    assert.ok((await markerKinds(cwd, out)).includes("parent_linkage_mismatch"));
    // The DataWriteGuid is the current header's: a parent whose newer header carries another one is a different write
    await put(cwd, "inputs/hv/base.vhdx", vhdx({ diskId: PARENT_DISK, headers: [{ dataGuid: PARENT_WRITE }, { dataGuid: "EEEEEEEE-0000-4000-8000-0000000000E2" }] }));
    await put(cwd, "inputs/hv/child.avhdx", vhdx({ diskId: CHILD, parent: { linkage: PARENT_WRITE, relative: ".\\base.vhdx" } }));
    out = body(await tool(CHAIN, cwd, { root: "inputs/hv" }));
    assert.equal(out.edges[0].id_check, "mismatch", "the parent was written after the child was made");
    // linkage2 that matches is said as such, not folded into "match"
    await put(cwd, "inputs/hv/base.vhdx", vhdx({ diskId: PARENT_DISK, dataWriteGuid: PARENT_WRITE }));
    await put(cwd, "inputs/hv/child.avhdx", vhdx({ diskId: CHILD, parent: { linkage: "BBBBBBBB-0000-4000-8000-000000000001", linkage2: PARENT_WRITE, relative: ".\\base.vhdx" } }));
    out = body(await tool(CHAIN, cwd, { root: "inputs/hv" }));
    assert.equal(out.edges[0].id_check, "match_via_parent_linkage2");
  });
});

test("VHDX: a header with a broken checksum is not chosen over a valid one, a log GUID is a candidate, and a header version the tool does not know is unsupported", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/hv/a.vhdx", vhdx({ diskId: "AAAAAAAA-0000-4000-8000-000000000001", headers: [{ seq: 5n }, { seq: 9n, breakCrc: true }] }));
    await put(cwd, "inputs/hv/b.vhdx", vhdx({ diskId: "AAAAAAAA-0000-4000-8000-000000000002", headers: [{}, { logGuid: "CCCCCCCC-0000-4000-8000-000000000001", logLength: 1048576 }] }));
    await put(cwd, "inputs/hv/c.vhdx", vhdx({ diskId: "AAAAAAAA-0000-4000-8000-000000000003", headers: [{ version: 2 }, { version: 2 }] }));
    await put(cwd, "inputs/hv/d.vhdx", vhdx({ diskId: "AAAAAAAA-0000-4000-8000-000000000004", regionBadSignature: true }));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/hv" }));
    const a = out.disks.find((d: Json) => d.file === "a.vhdx");
    assert.equal(a.detail.current_header_offset, 65536, "the higher sequence number had a bad checksum, so the valid header is the current one");
    assert.equal(a.detail.headers_checksum_ok, 1);
    assert.ok((await markerKinds(cwd, out)).includes("vhdx_log_guid_set"));
    assert.equal(out.sources.find((s: Json) => s.file === "c.vhdx").state, "unsupported");
    assert.equal(out.sources.find((s: Json) => s.file === "d.vhdx").state, "failed");
    assert.equal(out.sources.find((s: Json) => s.file === "d.vhdx").reason.includes("region table"), true);
  });
});

test("QCOW2: the backing file is a name and nothing more; the answer says the format records no identity, reads the dirty bit and the feature names, and lists internal snapshots", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/q/base.qcow2", qcow2({ snapshots: [{ id: "1", name: "before-patch", date: 1_700_000_000, dateNsec: 5, vmClock: 12345n }, { id: "2", name: "clean", date: 1_700_000_500 }], incompat: 1n }));
    await put(cwd, "inputs/q/top.qcow2", qcow2({ backing: "base.qcow2", backingFormat: "qcow2" }));
    await put(cwd, "inputs/q/orphan.qcow2", qcow2({ backing: "missing.qcow2", backingFormat: "qcow2" }));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/q" }));
    const edge = out.edges.find((e: Json) => e.parent_name === "base.qcow2");
    assert.equal(edge.id_check, "not_available");
    assert.match(edge.id_note, /records no identity of its backing file/);
    assert.equal(chainOf(out, "top.qcow2").status, "complete");
    assert.equal(chainOf(out, "orphan.qcow2").status, "broken");
    const base = out.disks.find((d: Json) => d.file === "base.qcow2");
    assert.deepEqual(base.detail.incompatible_feature_names, ["dirty"]);
    assert.equal(base.detail.internal_snapshots.read, 2);
    const snaps = await rowsOf(cwd, out, "internal_snapshots");
    assert.deepEqual(snaps.map((s) => [s.id, s.name, s.date_utc]), [["1", "before-patch", "2023-11-14T22:13:20Z"], ["2", "clean", "2023-11-14T22:21:40Z"]]);
    assert.equal(snaps[0].vm_clock_ns, 12345);
    assert.ok((await markerKinds(cwd, out)).includes("qcow2_dirty_bit"));
    assert.equal(out.disks.find((d: Json) => d.file === "top.qcow2").detail.backing_format, "qcow2");
  });
});

test("QCOW2 hostile: a snapshot count of a million with a table that stops, a backing name over 1023 bytes, a cluster size out of range, and versions 1 and 4 are each reported, never read past the file", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/q/many.qcow2", qcow2({ snapshots: [{ id: "1", name: "only", date: 1 }], declared: 1_000_000 }));
    await put(cwd, "inputs/q/longname.qcow2", qcow2({ backing: "x".repeat(2000), backingSizeField: 2000 }));
    await put(cwd, "inputs/q/bits.qcow2", qcow2({ clusterBits: 40 }));
    const v1 = qcow2({}); v1.writeUInt32BE(1, 4);
    const v4 = qcow2({}); v4.writeUInt32BE(4, 4);
    await put(cwd, "inputs/q/v1.qcow2", v1);
    await put(cwd, "inputs/q/v4.qcow2", v4);
    await put(cwd, "inputs/q/short.qcow2", Buffer.concat([Buffer.from("QFI\xfb", "latin1"), Buffer.alloc(20)]));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/q", max_snapshots: 50 }));
    const many = out.disks.find((d: Json) => d.file === "many.qcow2");
    assert.equal(many.detail.internal_snapshots.declared, 1_000_000);
    assert.equal(many.detail.internal_snapshots.read, 1);
    assert.match(many.detail.internal_snapshots.stopped, /empty id string/);
    assert.match(out.disks.find((d: Json) => d.file === "longname.qcow2").detail.problem, /1023/);
    const byFile = Object.fromEntries(out.sources.map((s: Json) => [s.file, s]));
    assert.equal(byFile["bits.qcow2"].state, "failed");
    assert.equal(byFile["v1.qcow2"].state, "unsupported");
    assert.equal(byFile["v4.qcow2"].state, "unsupported");
    assert.equal(byFile["short.qcow2"].state, "failed");
    assert.equal(out.status, "partial");
  });
});

test("QCOW2: a hundred thousand internal snapshots stream through the page; max_snapshots bounds what is read and the declared count stays beside it", async () => {
  await withCwd(async (cwd) => {
    const n = 100_000;
    const snaps = Array.from({ length: n }, (_, i) => ({ id: String(i + 1), name: `s${i}`, date: 1_700_000_000 + i }));
    await put(cwd, "inputs/q/big.qcow2", qcow2({ snapshots: snaps }));
    const started = Date.now();
    const out = body(await asJob(CHAIN, cwd, { root: "inputs/q", limit: 10 }));
    assert.ok(Date.now() - started < 60_000);
    const big = out.disks.find((d: Json) => d.file === "big.qcow2");
    assert.equal(big.detail.internal_snapshots.read, n);
    assert.equal(out.pages.internal_snapshots.matched, n);
    assert.equal(out.pages.internal_snapshots.truncated, true);
    assert.equal(out.internal_snapshots.length, 10, "the page is small");
    const all = await rowsOf(cwd, out, "internal_snapshots");
    assert.equal(all.length, n, "the whole is in the file the page names");
    assert.equal(all[n - 1].name, `s${n - 1}`);
    const capped = body(await asJob(CHAIN, cwd, { root: "inputs/q", limit: 10, max_snapshots: 1000 }));
    assert.equal(capped.disks.find((d: Json) => d.file === "big.qcow2").detail.internal_snapshots.read, 1000);
    assert.match(capped.disks.find((d: Json) => d.file === "big.qcow2").detail.internal_snapshots.stopped, /max_snapshots \(1000\)/);
  });
});

test("the configuration files are held against the descriptors: a running delta with no snapshots listed, a snapshot whose disk is gone, and a delta nothing names; the parents of a named disk are not flagged", async () => {
  await withCwd(async (cwd) => {
    await vmwareChain(cwd);
    await put(cwd, "inputs/vm/vm.vmx", vmx([["displayName", "web"], ["scsi0:0.fileName", "base-000002.vmdk"], ["scsi0:0.present", "TRUE"]]));
    await put(cwd, "inputs/vm/vm.vmsd", vmsd({ snapshots: [] }));
    let out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    let kinds = await markerKinds(cwd, out);
    assert.ok(kinds.includes("running_disk_is_a_delta_without_snapshots"));
    assert.equal(kinds.includes("delta_not_in_snapshot_database"), false, "base-000001 is a parent of the running disk: part of the chain in use");
    // A snapshot database that lists the middle disk, a missing disk, and an unrelated delta
    await put(cwd, "inputs/vm/vm.vmsd", vmsd({ snapshots: [{ index: 0, uid: "1", name: "s1", disks: ["base-000001.vmdk"] }, { index: 1, uid: "2", name: "s2", parent: "1", disks: ["gone-000003.vmdk"] }] }));
    await put(cwd, "inputs/vm/stray-000001.vmdk", vmdkDescriptor({ cid: "77777777", parentCid: "aabbccdd", parentHint: "base.vmdk", extents: [{ sectors: 8, type: "FLAT", name: "stray-flat.vmdk" }] }));
    out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    const markers = await rowsOf(cwd, out, "markers");
    kinds = markers.map((m) => m.kind);
    assert.ok(kinds.includes("snapshot_disk_missing"));
    assert.equal(kinds.includes("running_disk_is_a_delta_without_snapshots"), false, "the database lists snapshots now");
    const stray = markers.filter((m) => m.kind === "delta_not_in_snapshot_database");
    assert.equal(stray.length, 1);
    assert.equal(out.sources.find((s: Json) => s.source_id === stray[0].source_ids[0]).file, "stray-000001.vmdk");
    const db = await rowsOf(cwd, out, "snapshot_database");
    assert.deepEqual(db.map((r) => [r.index, r.display_name, r.parent]), [[0, "s1", null], [1, "s2", "1"]]);
    assert.equal(db[0].create_time_note.includes("not decoded"), true);
    for (const m of markers) assert.ok(m.reading && m.observation && m.corroborate, `${m.kind} carries observation, reading and corroboration`);
  });
});

test("a snapshot database of a hundred thousand entries is read to its cap and the rest is counted, in bounded memory and time", async () => {
  await withCwd(async (cwd) => {
    const lines: string[] = [".encoding = \"UTF-8\"", "snapshot.numSnapshots = \"100000\""];
    for (let i = 0; i < 100_000; i++) lines.push(`snapshot${i}.uid = "${i}"`, `snapshot${i}.displayName = "s${i}"`, `snapshot${i}.disk0.fileName = "d${i}.vmdk"`);
    await put(cwd, "inputs/vm/big.vmsd", lines.join("\n") + "\n");
    const started = Date.now();
    const out = body(await tool(CHAIN, cwd, { root: "inputs/vm", limit: 5 }));
    assert.ok(Date.now() - started < 60_000, "bounded time");
    assert.equal(out.status, "partial");
    assert.match(out.partial_reasons.join(" "), /more than 20000 snapshot indexes/);
    assert.equal(out.pages.snapshot_database.matched, 20000);
  });
});

test("the walk is bounded and says where it stopped: max_files, max_depth, links never followed, a pipe never opened", async () => {
  await withCwd(async (cwd) => {
    for (let i = 0; i < 40; i++) await put(cwd, `inputs/vm/f${String(i).padStart(3, "0")}.txt`, "x");
    await put(cwd, "inputs/vm/a.vmdk", vmdkDescriptor({ cid: BASE, extents: [{ sectors: 8, type: "FLAT", name: "n" }] }));
    let out = body(await tool(CHAIN, cwd, { root: "inputs/vm", max_files: 10 }));
    assert.equal(out.files_in_set, 10);
    assert.equal(out.status, "partial");
    assert.match(out.walk_truncated, /max_files \(10\)/);
    // depth
    await put(cwd, "inputs/deep/a/b/c/d/e/x.vmdk", vmdkDescriptor({ cid: BASE, extents: [{ sectors: 8, type: "FLAT", name: "n" }] }));
    out = body(await tool(CHAIN, cwd, { root: "inputs/deep", max_depth: 2 }));
    assert.equal(out.walk.counts.too_deep, 1);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /directories too deep/);
    // a link inside the root is listed and not followed; a link as the root is refused
    await mkdir(join(cwd, "inputs/lnk"), { recursive: true });
    await put(cwd, "inputs/outside/secret.vmdk", vmdkDescriptor({ cid: "12345678", extents: [{ sectors: 8, type: "FLAT", name: "n" }] }));
    await symlink(join(cwd, "inputs/outside/secret.vmdk"), join(cwd, "inputs/lnk/linked.vmdk"));
    await symlink(join(cwd, "inputs/outside"), join(cwd, "inputs/lnk/dir"));
    out = body(await tool(CHAIN, cwd, { root: "inputs/lnk" }));
    assert.equal(out.walk.counts.links, 2);
    assert.equal(out.files_in_set, 0);
    assert.equal(out.status, "partial", "a set whose only entries were links is not a clean result: it says what it skipped");
    assert.match(refused(await tool(CHAIN, cwd, { root: "inputs/lnk/dir" })).error, /symlink root/);
    // a pipe is named and never opened (opening it would block)
    const fifo = join(cwd, "inputs/pipe/p.vmdk");
    await mkdir(join(cwd, "inputs/pipe"), { recursive: true });
    spawnSync("mkfifo", [fifo]);
    await put(cwd, "inputs/pipe/ok.vmdk", vmdkDescriptor({ cid: BASE, extents: [{ sectors: 8, type: "FLAT", name: "n" }] }));
    const started = Date.now();
    out = body(await tool(CHAIN, cwd, { root: "inputs/pipe" }));
    assert.ok(Date.now() - started < 10_000, "no block on a pipe");
    assert.equal(out.walk.counts.special, 1);
    assert.equal(out.files_in_set, 1);
  });
});

test("bad arguments are an error document, not a traceback", async () => {
  await withCwd(async (cwd) => {
    for (const args of [{}, { root: 5 }, { root: "inputs/none" }, { paths: "x" }, { paths: [""] }, { root: "inputs", limit: 0 }, { root: "inputs", max_seconds: 1e9 }, { root: "inputs", qemu_img: "yes" }, { root: "inputs", max_files: true }, { root: "inputs", write_text: "yes" }, []]) {
      const out = refused(await tool(CHAIN, cwd, args));
      assert.equal(out.status, "failed");
      assert.ok(out.error);
    }
    const bad = await tool(CHAIN, cwd, "not an object");
    assert.equal(json(bad).status, "failed");
  });
});

test("qemu_img: off is the default and nothing runs; auto runs it once per parsed image with the format fixed and never --backing-chain, and its answer sits beside the native reading", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/q/base.qcow2", qcow2({ size: 1073741824n }));
    await put(cwd, "inputs/q/top.qcow2", qcow2({ backing: "base.qcow2", size: 1073741824n }));
    const bin = await stubQemu(cwd);
    const log = join(cwd, "qemu.log");
    const env = { QEMU_STUB_LOG: log };
    let out = body(await tool(CHAIN, cwd, { root: "inputs/q" }, env, bin));
    assert.equal(out.qemu_img.mode, "off");
    assert.equal(await exists(log), false, "qemu-img was not run");
    out = body(await tool(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto" }, env, bin));
    const calls = (await readFile(log, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(calls.length, 2);
    for (const c of calls) {
      assert.deepEqual(c.slice(0, 4), ["info", "--output=json", "-f", "qcow2"]);
      assert.equal(c.includes("--backing-chain"), false);
      assert.match(c[4], /inputs\/q\/(base|top)\.qcow2$/);
    }
    assert.equal(out.qemu_img.checked, 2);
    const top = out.disks.find((d: Json) => d.file === "top.qcow2");
    assert.equal(top.qemu_img.virtual_size, 1073741824);
    assert.equal(top.qemu_img.exit_code, 0);
    assert.equal(chainOf(out, "top.qcow2").status, "complete", "the native reading is unchanged");
    // disagreement is a marker, neither reading preferred
    out = body(await tool(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto" }, { ...env, QEMU_STUB_MODE: "size:2048" }, bin));
    const markers = await rowsOf(cwd, out, "markers");
    assert.equal(markers.filter((m) => m.kind === "qemu_img_disagrees").length, 2);
    assert.match(markers[0].reading, /neither is preferred/);
    // a failing qemu-img is recorded, scrubbed, and the run goes on
    out = body(await tool(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto" }, { ...env, QEMU_STUB_MODE: "fail" }, bin));
    assert.equal(out.disks.find((d: Json) => d.file === "top.qcow2").qemu_img.exit_code, 1);
    assert.match(out.disks.find((d: Json) => d.file === "top.qcow2").qemu_img.error, /Image is corrupt/);
    out = body(await tool(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto" }, { ...env, QEMU_STUB_MODE: "notjson" }, bin));
    assert.match(out.disks.find((d: Json) => d.file === "top.qcow2").qemu_img.error, /not JSON/);
  });
});

test("qemu_img: absent from PATH is said, auto goes on natively, require fails by name; qemu_img_max_images bounds the runs", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/q/base.qcow2", qcow2({}));
    const empty = join(cwd, "emptybin");
    await mkdir(empty, { recursive: true });
    const env = { PATH: `${empty}:/usr/bin:/bin` };
    // python3 must still run: the PATH keeps the system directories, which do not carry qemu-img in the test environment
    const probe = spawnSync("sh", ["-c", "command -v qemu-img"], { env });
    if (probe.status === 0) return; // this host has a real qemu-img on the system path: the absent case cannot be made here
    let out = body(await tool(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto" }, env));
    assert.equal(out.qemu_img.available, false);
    assert.match(out.qemu_img.note, /not on PATH/);
    assert.equal(out.status, "complete", "the native reading is the whole answer");
    assert.match(refused(await tool(CHAIN, cwd, { root: "inputs/q", qemu_img: "require" }, env)).error, /require was asked for and qemu-img is not on PATH/);
    const bin = await stubQemu(cwd);
    const log = join(cwd, "q.log");
    for (let i = 0; i < 5; i++) await put(cwd, `inputs/q/x${i}.qcow2`, qcow2({}));
    out = body(await tool(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto", qemu_img_max_images: 2 }, { QEMU_STUB_LOG: log }, bin));
    assert.equal((await readFile(log, "utf8")).trim().split("\n").length, 2);
  });
});

test("a qemu-img that hangs is killed with the tool's deadline and does not outlive it; ending the tool ends it too", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/q/base.qcow2", qcow2({}));
    const bin = await stubQemu(cwd);
    const pidPath = join(cwd, "qemu.pid");
    const env = { QEMU_STUB_MODE: "hang", QEMU_STUB_PID: pidPath };
    // 1: the tool's own time budget ends the engine
    const run = startDetached(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto", max_seconds: 3 }, env, bin);
    const stubPid = await pidFile(pidPath);
    const code = await run.closed;
    assert.ok(code === 0 || code === 1);
    assert.equal(await gone(stubPid), true, "qemu-img did not outlive the tool's deadline");
    const out = json({ code, stdout: run.stdout(), stderr: "" });
    assert.ok(out.status === "partial" || out.status === "complete");
    // 2: the harness ends a tool by killing its group; the engine is in that group
    await writeFile(pidPath, "");
    const second = startDetached(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto", max_seconds: 40 }, env, bin);
    const pid2 = await pidFile(pidPath);
    second.killGroup();
    await second.closed;
    assert.equal(await gone(pid2), true, "qemu-img was in the tool's process group and ended with it");
    // 3: SIGTERM to the tool alone kills the engine too
    await writeFile(pidPath, "");
    const third = startDetached(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto", max_seconds: 40 }, env, bin);
    const pid3 = await pidFile(pidPath);
    third.signal("SIGTERM");
    await third.closed;
    assert.equal(await gone(pid3), true, "SIGTERM to the tool ended qemu-img");
  });
});

test("names the answer shows are shape-checked: a token, a key, user-info and a long hex run in a file name, a hint, a snapshot name and a database entry never reach an answer, a paging file or the tool-output pages; the originals are in the 0600 values file only when asked, in a job", async () => {
  await withCwd(async (cwd) => {
    const C = CANARY;
    await put(cwd, `inputs/vm/${C.github}/disk.vmdk`, vmdkDescriptor({ cid: MID, parentCid: BASE, parentHint: `${C.hex}.vmdk`, extents: [{ sectors: 8, type: "FLAT", name: `https://${C.userinfo}@files.example.test/${C.aws}-flat.vmdk` }] }));
    await put(cwd, "inputs/vm/q.qcow2", qcow2({ backing: `/srv/${C.aws}/base.qcow2`, snapshots: [{ id: C.hex, name: `snap-${C.github}`, date: 1 }] }));
    await put(cwd, "inputs/vm/v.vmsd", vmsd({ snapshots: [{ index: 0, uid: C.aws, name: `name ${C.userinfo}@host ${C.github}`, parent: C.github, high: C.hex, low: C.github, disks: [`${C.hex}.vmdk`] }] }));
    // fields that are not names too: an extent type, a VHDX parent linkage, an unknown header-extension and a backing format
    await put(cwd, "inputs/vm/ext.vmdk", vmdkDescriptor({ cid: "01020304", extents: [{ sectors: 8, type: C.github, name: "e" }] }));
    await put(cwd, "inputs/vm/c.avhdx", vhdx({ diskId: "AAAAAAAA-0000-4000-8000-000000000002", parent: { linkage: C.hex, linkage2: C.github, relative: ".\\p.vhdx" } }));
    await put(cwd, "inputs/vm/qf.qcow2", qcow2({ backing: "q.qcow2", backingFormat: C.github }));
    const run = await tool(CHAIN, cwd, { root: "inputs/vm", limit: 1 });
    const out = body(run);
    const skip = (await filesUnder(join(cwd, "inputs"))).map((f) => `inputs/${f}`);
    const all = await everythingBut(cwd, run.stdout + run.stderr, skip);
    for (const [name, secret] of Object.entries(CANARY)) {
      const needle = name === "userinfo" ? "S3cr3tPassw0rd" : secret;
      assert.equal(all.toLowerCase().includes(needle.toLowerCase()), false, `${name} reached an answer or a file an agent reads (in any case)`);
    }
    assert.ok(out.withheld.strings_changed > 0);
    // not in a job: write_text is refused and nothing is written
    assert.match(refused(await tool(CHAIN, cwd, { root: "inputs/vm", write_text: true })).error, /outside a job/);
    assert.equal(await exists(join(cwd, "out")), false);
    // in a job: the originals go to the values file, mode 0600, and to nothing else
    const job = await asJob(CHAIN, cwd, { root: "inputs/vm", write_text: true, limit: 1 });
    const jb = body(job);
    assert.equal(jb.text.requested, true);
    assert.equal(jb.text.contains_text_that_may_hold_secrets, true);
    assert.match(jb.text.file, /^store\/jobs\/j\d+\/out\/chain-values\.jsonl$/);
    const valuesPath = join(cwd, "out", "chain-values.jsonl");
    assert.equal((await stat(valuesPath)).mode & 0o777, 0o600);
    const values = await readFile(valuesPath, "utf8");
    assert.ok(values.includes(C.github) && values.includes("S3cr3tPassw0rd"));
    const rest = await everythingBut(cwd, job.stdout + job.stderr, [...skip, "out/chain-values.jsonl"]);
    for (const secret of [C.github, C.aws, C.hex, "S3cr3tPassw0rd"]) assert.equal(rest.includes(secret), false, "only the values file holds the originals");
    // a second run in the same job is refused by name; the file is not overwritten
    jobs2: {
      const again = await tool(CHAIN, cwd, { root: "inputs/vm", write_text: true }, { JOB_ID: "j000001", OUT: join(cwd, "out") });
      assert.match(refused(again).error, /values file already exists/);
      assert.equal(await readFile(valuesPath, "utf8"), values);
      break jobs2;
    }
  });
});

test("an oversize name is shown cut with its whole length, in bounded time and size, and a planted token in a comment is never shown", async () => {
  await withCwd(async (cwd) => {
    const long = "a".repeat(5000);
    const desc = vmdkDescriptor({ cid: MID, parentCid: BASE, parentHint: `${"/ab".repeat(300_000)}.vmdk`, extents: [{ sectors: 8, type: "FLAT", name: `${long}.vmdk` }] })
      .replace("# Extent description", `# a comment with ${CANARY.github} and ${CANARY.aws}\n# Extent description`);
    await put(cwd, "inputs/vm/big.vmdk", desc);
    await put(cwd, `inputs/vm/${"d".repeat(200)}/${"e".repeat(200)}/x.vmx`, `# ${CANARY.github}\n.encoding = "UTF-8"\nscsi0:0.fileName = "${"f".repeat(60_000)}.vmdk"\n`);
    const started = Date.now();
    const run = await tool(CHAIN, cwd, { root: "inputs/vm" });
    const out = body(run);
    assert.ok(Date.now() - started < 15_000, "bounded time");
    assert.ok(run.stdout.length < 250_000, `the answer stays small: ${run.stdout.length} bytes`);
    const edge = out.edges.find((e: Json) => e.parent_name?.includes("whole text:"));
    assert.ok(edge, "a name over the limit is shown cut");
    assert.match(edge.parent_name, /\.\.\.\(whole text: 900005 characters\)$/);
    assert.equal(out.extents[0].file.includes("...(whole text: 5005 characters)"), true);
    assert.equal(run.stdout.includes(CANARY.github) || run.stdout.includes(CANARY.aws), false, "a comment is never shown");
    // the originals of the long names go to the values file when asked, whole
    const job = body(await asJob(CHAIN, cwd, { root: "inputs/vm", write_text: true }));
    const values = (await readFile(join(cwd, "out", "chain-values.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.ok(values.some((v) => typeof v.value === "string" && v.value.length === 900005), "the whole name is kept");
    assert.equal(job.text.written, values.length);
  });
});

test("an empty values file is reported as written: 0 and stays 0600", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/vm/a.vmdk", vmdkDescriptor({ cid: BASE, extents: [{ sectors: 8, type: "FLAT", name: "a-flat.vmdk" }] }));
    const out = body(await asJob(CHAIN, cwd, { root: "inputs/vm", write_text: true }));
    assert.equal(out.text.written, 0);
    assert.equal(out.text.contains_text_that_may_hold_secrets, false);
    assert.equal((await stat(join(cwd, "out", "chain-values.jsonl"))).mode & 0o777, 0o600);
  });
});

test("a second tool-output page and the paging file hold whole rows: every row of a list the page cut is in the file, in order", async () => {
  await withCwd(async (cwd) => {
    for (let i = 0; i < 30; i++) await put(cwd, `inputs/vm/d${String(i).padStart(2, "0")}.vmdk`, vmdkDescriptor({ cid: (0x20000000 + i).toString(16), extents: [{ sectors: 8, type: "FLAT", name: `x${i}` }] }));
    const out = body(await asJob(CHAIN, cwd, { root: "inputs/vm", limit: 7 }));
    assert.equal(out.sources.length, 7);
    assert.equal(out.pages.sources.matched, 30);
    assert.equal(out.pages.sources.truncated, true);
    const rows = await rowsOf(cwd, out, "sources");
    assert.deepEqual(rows.map((r) => r.file), Array.from({ length: 30 }, (_, i) => `d${String(i).padStart(2, "0")}.vmdk`));
    assert.equal(out.truncated, true);
    assert.ok(out.pages.sources.all_results.startsWith("store/jobs/"));
  });
});

test("non-UTF-8 bytes in names and in a descriptor do not raise: they are escapes in the JSON", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/vm/ok.vmdk", Buffer.concat([Buffer.from("# Disk DescriptorFile\nversion=1\nCID=aabbccdd\nparentCID=11111111\ncreateType=\"vmfsSparse\"\nparentFileNameHint=\"caf"), Buffer.from([0xe9, 0xff]), Buffer.from(".vmdk\"\nRW 8 FLAT \"n\"\n")]));
    const bad = Buffer.from([0x62, 0xff, 0xfe, 0x2e, 0x76, 0x6d, 0x64, 0x6b]);
    await writeFile(Buffer.concat([Buffer.from(join(cwd, "inputs/vm") + "/"), bad]), vmdkDescriptor({ cid: "01010101", extents: [{ sectors: 8, type: "FLAT", name: "n" }] })).catch(() => undefined);
    const out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    assert.ok(out.edges.length >= 1);
    assert.doesNotThrow(() => JSON.parse(JSON.stringify(out)));
  });
});

test("the answer names what it did not read: other files are counted by extension, a missing mention of a disk is not a finding, and G is the tool's constants", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/vm/notes.txt", "hello");
    await put(cwd, "inputs/vm/report.docx", "x");
    await put(cwd, "inputs/vm/a.vmdk", vmdkDescriptor({ cid: BASE, extents: [{ sectors: 8, type: "FLAT", name: "n" }] }));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    assert.deepEqual(out.other_files_by_extension, { ".txt": 1, ".docx": 1 });
    assert.match(out.other_files_note, /absence of a disk here is not absence of a disk/);
    assert.equal(G.zero.length, 36);
    assert.equal(guidBytes(G.metadata).length, 16);
  });
});

// A reference that does not share this tool's reading of the formats: files made and described by the real qemu-img,
// when this host has one (a Linux CI job with qemu-utils, a developer machine). Skipped, and said so, when it has not.
const QEMU = spawnSync("qemu-img", ["--version"]);
test("files made by a real qemu-img are read as qemu-img reads them: sizes, backing names, VMDK CIDs, VHD and VHDX identity, internal snapshots", { skip: QEMU.status === 0 ? false : "no qemu-img on this host" }, async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "inputs", "real");
    await mkdir(dir, { recursive: true });
    const make = (...args: string[]): void => { const r = spawnSync("qemu-img", ["create", "-q", ...args], { cwd: dir }); assert.equal(r.status, 0, String(r.stderr)); };
    make("-f", "qcow2", "base.qcow2", "16M");
    make("-f", "qcow2", "-b", "base.qcow2", "-F", "qcow2", "top.qcow2");
    make("-f", "qcow2", "snap.qcow2", "8M");
    assert.equal(spawnSync("qemu-img", ["snapshot", "-c", "before patch", "snap.qcow2"], { cwd: dir }).status, 0);
    make("-f", "vmdk", "mono.vmdk", "16M");
    make("-f", "vmdk", "-b", "mono.vmdk", "-F", "vmdk", "child.vmdk");
    make("-f", "vmdk", "-o", "subformat=twoGbMaxExtentSparse", "two.vmdk", "8M");
    make("-f", "vpc", "dyn.vhd", "16M");
    make("-f", "vhdx", "vx.vhdx", "16M");
    const info = (f: string, ...extra: string[]): Json => JSON.parse(String(spawnSync("qemu-img", ["info", "--output=json", ...extra, f], { cwd: dir }).stdout));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/real" }));
    assert.equal(out.status, "complete", out.status_basis);
    const disk = (f: string): Json => out.disks.find((d: Json) => d.file === f);
    assert.equal(disk("base.qcow2").detail.virtual_size, info("base.qcow2")["virtual-size"]);
    assert.equal(disk("top.qcow2").detail.backing_file, info("top.qcow2")["backing-filename"]);
    assert.equal(chainOf(out, "top.qcow2").chain_length, 2);
    assert.equal(chainOf(out, "top.qcow2").status, "complete");
    assert.equal(disk("snap.qcow2").detail.internal_snapshots.read, 1);
    assert.equal((await rowsOf(cwd, out, "internal_snapshots"))[0].name, "before patch");
    assert.equal(disk("mono.vmdk").detail.capacity_sectors_by_extents * 512, info("mono.vmdk")["virtual-size"]);
    assert.equal(disk("child.vmdk").detail.parent_cid, disk("mono.vmdk").own_id, "a child records its parent's CID");
    assert.ok(disk("mono.vmdk").own_id, "the CID was read (qemu-img writes it without leading zeros)");
    const vmdkEdge = out.edges.find((e: Json) => e.child === disk("child.vmdk").source_id);
    assert.equal(vmdkEdge.id_check, "match", "the child's parentCID was compared with the parent's CID, and they agree");
    assert.equal(chainOf(out, "child.vmdk").status, "complete");
    assert.equal(disk("two.vmdk").detail.create_type, "twoGbMaxExtentSparse", "a closed-vocabulary name is not mistaken for a token");
    assert.equal(disk("dyn.vhd").detail.current_size, info("dyn.vhd")["virtual-size"]);
    assert.equal(disk("dyn.vhd").detail.footer_checksum_ok, true);
    assert.equal(disk("vx.vhdx").detail.virtual_size, info("vx.vhdx")["virtual-size"]);
    assert.equal(disk("vx.vhdx").detail.headers_checksum_ok, 2);
    assert.equal(disk("vx.vhdx").detail.region_table_checksum_ok, true);
    // and the optional second reading agrees with the first, through the real program
    const second = body(await tool(CHAIN, cwd, { root: "inputs/real", qemu_img: "require" }));
    assert.equal(second.qemu_img.available, true);
    assert.equal(second.status, "complete", second.status_basis);
    assert.ok(second.qemu_img.checked >= 7);
    assert.equal(second.qemu_img.failed, 0);
    assert.equal(second.qemu_img.skipped.text_descriptor, 1, "two.vmdk is a text descriptor");
    assert.deepEqual((await rowsOf(cwd, second, "markers")).filter((m) => m.kind === "qemu_img_disagrees"), []);
  });
});

// ---- review fixes: each test below fails on the tool as first proposed ---------------------------------------------------

test("a VMDK CID of fewer than eight hexadecimal digits (qemu-img writes it with %x) is read and compared as a number, not refused", async () => {
  await withCwd(async (cwd) => {
    // VMware's descriptor format: CID is a 32-bit value in hexadecimal; qemu-img prints it without leading zeros
    await put(cwd, "inputs/vm/base.vmdk", vmdkDescriptor({ cid: "363f60d", extents: [{ sectors: 8, type: "FLAT", name: "base-flat.vmdk" }] }));
    await put(cwd, "inputs/vm/base-flat.vmdk", Buffer.alloc(8 * 512));
    await put(cwd, "inputs/vm/child.vmdk", vmdkDescriptor({ cid: "1a2b", parentCid: "0363f60d", parentHint: "base.vmdk", extents: [{ sectors: 8, type: "FLAT", name: "child-flat.vmdk" }] }));
    await put(cwd, "inputs/vm/child-flat.vmdk", Buffer.alloc(8 * 512));
    await put(cwd, "inputs/vm/odd.vmdk", vmdkDescriptor({ cid: "123456789", extents: [{ sectors: 8, type: "FLAT", name: "base-flat.vmdk" }] }));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    const base = out.disks.find((d: Json) => d.file === "base.vmdk");
    assert.equal(base.own_id, "0363f60d");
    assert.equal(base.detail.cid_raw, "363f60d");
    const edge = out.edges.find((e: Json) => e.parent_name === "base.vmdk");
    assert.equal(edge.id_check, "match", "0363f60d and 363f60d are one number");
    assert.equal(chainOf(out, "child.vmdk").status, "complete");
    const markers = await rowsOf(cwd, out, "markers");
    assert.deepEqual(markers.filter((m) => m.kind === "descriptor_problem").map((m) => m.observation), ["CID is not 1 to 8 hexadecimal digits"], "only the nine-digit CID is a problem");
  });
});

test("a QCOW2 image on a raw backing file (the usual Proxmox and libvirt layout) is not a broken chain: the raw base is present and not read, and the answer says so", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/q/base.raw", Buffer.alloc(65536));
    await put(cwd, "inputs/q/top.qcow2", qcow2({ backing: "base.raw", backingFormat: "raw" }));
    await put(cwd, "inputs/q/probe.qcow2", qcow2({ backing: "base.raw" }));
    await put(cwd, "inputs/q/liar.qcow2", qcow2({ backing: "base.raw", backingFormat: "qcow2" }));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/q" }));
    for (const leaf of ["top.qcow2", "probe.qcow2"]) {
      const c = chainOf(out, leaf);
      assert.equal(c.status, "complete", `${leaf}: ${c.detail}`);
      assert.equal(c.chain_length, 2);
      assert.match(c.base_note, /not a disk this tool reads/);
    }
    const edge = out.edges.find((e: Json) => e.child === out.disks.find((d: Json) => d.file === "top.qcow2").source_id);
    assert.equal(edge.parent_state, "raw or unread");
    assert.equal(edge.resolution, "relative_exact");
    assert.equal(chainOf(out, "liar.qcow2").status, "parent_unreadable", "the child says qcow2 and the file is not one");
    assert.equal((await markerKinds(cwd, out)).includes("parent_missing"), false, "the base is in the set");
  });
});

test("a chain is not complete over a parent that could not be read, an extent that is missing or short, or a QCOW2 external data file that is absent: its status names the first problem", async () => {
  await withCwd(async (cwd) => {
    const BASE_ID = "11111111-aaaa-bbbb-cccc-000000000001";
    // a VHD parent whose dynamic header is cut: the footer is there, the header it points at is not
    const cut = vhdDynamic({ uid: BASE_ID });
    await put(cwd, "inputs/a/base.vhd", Buffer.concat([cut.subarray(0, 512), Buffer.alloc(100), cut.subarray(cut.length - 512)]));
    await put(cwd, "inputs/a/child.vhd", vhdDifferencing({ uid: "11111111-aaaa-bbbb-cccc-000000000002", parentUid: BASE_ID, parentName: "base.vhd" }));
    // an unsupported parent: VHD file format version 2
    const v2 = vhdDynamic({ uid: BASE_ID }); v2.writeUInt32BE(0x00020000, 12); v2.writeUInt32BE(0x00020000, v2.length - 512 + 12);
    await put(cwd, "inputs/b/base.vhd", v2);
    await put(cwd, "inputs/b/child.vhd", vhdDifferencing({ uid: "11111111-aaaa-bbbb-cccc-000000000002", parentUid: BASE_ID, parentName: "base.vhd" }));
    // VMDK extents: one missing, one short
    await put(cwd, "inputs/c/gone.vmdk", vmdkDescriptor({ cid: "aabbccdd", extents: [{ sectors: 8, type: "FLAT", name: "gone-flat.vmdk" }] }));
    await put(cwd, "inputs/c/short.vmdk", vmdkDescriptor({ cid: "aabbccde", extents: [{ sectors: 8, type: "FLAT", name: "short-flat.vmdk" }] }));
    await put(cwd, "inputs/c/short-flat.vmdk", Buffer.alloc(100));
    await put(cwd, "inputs/c/child.vmdk", vmdkDescriptor({ cid: "11223344", parentCid: "aabbccdd", parentHint: "gone.vmdk", extents: [{ sectors: 8, type: "FLAT", name: "child-flat.vmdk" }] }));
    await put(cwd, "inputs/c/child-flat.vmdk", Buffer.alloc(8 * 512));
    // QCOW2 with an external data file (header extension 0x44415441, incompatible bit 2) that is not in the set
    const ext = qcow2({ incompat: 4n });
    const name = Buffer.from("data.raw");
    Buffer.concat([Buffer.from([0x44, 0x41, 0x54, 0x41]), Buffer.from([0, 0, 0, name.length]), name, Buffer.alloc((-name.length) & 7), Buffer.alloc(8)]).copy(ext, 104);
    await put(cwd, "inputs/d/img.qcow2", ext);
    await put(cwd, "inputs/d/top.qcow2", qcow2({ backing: "img.qcow2", backingFormat: "qcow2" }));
    for (const [dir, leaf, status] of [["a", "child.vhd", "parent_unreadable"], ["b", "child.vhd", "parent_unreadable"], ["c", "child.vmdk", "extent_missing"], ["c", "short.vmdk", "extent_missing"], ["d", "top.qcow2", "data_file_missing"]]) {
      const out = json(await tool(CHAIN, cwd, { root: `inputs/${dir}` }));
      const c = chainOf(out, leaf);
      assert.equal(c.status, status, `${dir}/${leaf}: ${JSON.stringify(c)}`);
      assert.ok(c.detail, "the status says which disk");
      assert.equal(out.chain_summary.complete, undefined, `${dir}: no chain is complete`);
    }
    const d = json(await tool(CHAIN, cwd, { root: "inputs/d" }));
    assert.ok((await markerKinds(cwd, d)).includes("external_data_file_missing"));
  });
});

test("qemu_img never opens a name a file holds: a VMDK text descriptor and a QCOW2 image with an external data file are not given to it, and a qemu-img that fails or times out makes the answer partial", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/q/desc.vmdk", vmdkDescriptor({ cid: "aabbccdd", extents: [{ sectors: 8, type: "FLAT", name: "/outside/flat.img" }] }));
    const ext = qcow2({ incompat: 4n });
    const name = Buffer.from("/outside/data.raw");
    Buffer.concat([Buffer.from([0x44, 0x41, 0x54, 0x41]), Buffer.from([0, 0, 0, name.length]), name, Buffer.alloc((-name.length) & 7), Buffer.alloc(8)]).copy(ext, 104);
    await put(cwd, "inputs/q/ext.qcow2", ext);
    await put(cwd, "inputs/q/plain.qcow2", qcow2({}));
    const bin = await stubQemu(cwd);
    const log = join(cwd, "q.log");
    let out = json(await tool(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto" }, { QEMU_STUB_LOG: log }, bin));
    const calls = (await readFile(log, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(calls.map((c) => c[c.length - 1].split("/").pop()), ["plain.qcow2"], "only the image that names no other file was given to qemu-img");
    assert.deepEqual(out.qemu_img.skipped, { text_descriptor: 1, external_data_file: 1 });
    assert.equal(out.qemu_img.checked, 1);
    // a split disk: its text descriptor names extents that are sparse files with a descriptor of their own (as qemu-img's
    // twoGbMaxExtentSparse writes them); the disk is the descriptor, so its extents are not given to qemu-img either
    await put(cwd, "inputs/s/two.vmdk", vmdkDescriptor({ cid: "aabbccd1", createType: "twoGbMaxExtentSparse", extents: [{ sectors: 2048, type: "SPARSE", name: "two-s001.vmdk" }] }));
    await put(cwd, "inputs/s/two-s001.vmdk", vmdkSparse({ descriptor: vmdkDescriptor({ cid: "aabbccd1", createType: "twoGbMaxExtentSparse", extents: [{ sectors: 2048, type: "SPARSE", name: "two-s001.vmdk" }] }) }));
    await writeFile(log, "");
    out = json(await tool(CHAIN, cwd, { root: "inputs/s", qemu_img: "auto" }, { QEMU_STUB_LOG: log }, bin));
    assert.equal((await readFile(log, "utf8")).trim(), "", "neither the descriptor nor its extent was given to qemu-img");
    assert.deepEqual(out.qemu_img.skipped, { text_descriptor: 1, extent_of_another_descriptor: 1 });
    assert.equal(out.status, "complete");
    // a failing qemu-img: the second reading is missing, and the answer says so
    out = json(await tool(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto" }, { QEMU_STUB_MODE: "fail" }, bin));
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /qemu-img failed, timed out or printed no JSON on 1 image/);
    assert.equal(out.qemu_img.failed, 1);
    out = json(await tool(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto" }, { QEMU_STUB_MODE: "notjson" }, bin));
    assert.equal(out.status, "partial");
    // a qemu-img that hangs is killed at the deadline and the answer is partial, not complete
    const pid = join(cwd, "qemu.pid");
    out = json(await tool(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto", max_seconds: 3 }, { QEMU_STUB_MODE: "hang", QEMU_STUB_PID: pid }, bin));
    assert.equal(out.status, "partial");
    assert.equal(out.disks.find((d: Json) => d.file === "plain.qcow2").qemu_img.timed_out, true);
  });
});

test("the chain phase is bounded by the clock: fifteen thousand trunk disks and fifteen thousand leaves at the largest settings end inside max_seconds with an answer", async () => {
  await withCwd(async (cwd) => {
    const n = 15_000;
    const dir = join(cwd, "inputs", "vm");
    await mkdir(dir, { recursive: true });
    const name = (k: string, i: number): string => `${k}${String(i).padStart(5, "0")}.vmdk`;
    const writes: Promise<void>[] = [];
    for (let i = 0; i < n; i++) {
      const cid = (0x10000000 + i).toString(16), leaf = (0x40000000 + i).toString(16);
      writes.push(writeFile(join(dir, name("t", i)), i === 0 ? vmdkDescriptor({ cid, extents: [{ sectors: 8, type: "ZERO" }] })
        : vmdkDescriptor({ cid, parentCid: (0x10000000 + i - 1).toString(16), parentHint: name("t", i - 1), extents: [{ sectors: 8, type: "ZERO" }] })));
      writes.push(writeFile(join(dir, name("l", i)), vmdkDescriptor({ cid: leaf, parentCid: cid, parentHint: name("t", i), extents: [{ sectors: 8, type: "ZERO" }] })));
      if (writes.length > 2000) await Promise.all(writes.splice(0));
    }
    await Promise.all(writes);
    const started = Date.now();
    const out = json(await tool(CHAIN, cwd, { root: "inputs/vm", max_files: 200000, max_chain_depth: 1000000, max_seconds: 10, limit: 5 }));
    const took = (Date.now() - started) / 1000;
    // the reading stops at four fifths of max_seconds and the writing at max_seconds; the margin is for starting Python
    // and a loaded machine (the first version took 22 s here on an idle one, and over 70 s on one CPU)
    assert.ok(took < 10 + 5, `the call ended in ${took} s; max_seconds was 10`);
    assert.ok(out.status === "complete" || out.status === "partial", out.status_basis);
    if (out.status === "partial") assert.match(out.status_basis, /max_seconds/, "a stop at the clock is named");
    else assert.equal(out.chain_summary.complete, n, "every leaf has a whole chain");
  });
});

test("a .vmx or .vmsd over 16 MiB is named and not read, and the rest of the answer is still made", async () => {
  await withCwd(async (cwd) => {
    await vmwareChain(cwd);
    const pad = "# padding line ".padEnd(1023, "x") + "\n";
    await put(cwd, "inputs/vm/big.vmsd", 'snapshot.numSnapshots = "0"\n' + pad.repeat(17 * 1024));
    await put(cwd, "inputs/vm/big.vmx", 'scsi0:0.fileName = "base-000002.vmdk"\n' + pad.repeat(17 * 1024));
    const out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    assert.equal(out.status, "partial");
    for (const f of ["big.vmsd", "big.vmx"]) {
      const s = out.sources.find((x: Json) => x.file === f);
      assert.equal(s.state, "failed");
      assert.match(s.reason, /over 16777216 bytes is named and not read/);
    }
    assert.equal(chainOf(out, "base-000002.vmdk").status, "complete", "the disks are still judged");
    assert.equal((await markerKinds(cwd, out)).includes("running_disk_is_a_delta_without_snapshots"), false, "a database that was not read says nothing about its snapshots");
  });
});

test("a QCOW2 snapshot table read short of what the header declares is partial: a max_snapshots cap, and a count of 0xFFFFFFFF over ten real entries", async () => {
  await withCwd(async (cwd) => {
    const snaps = Array.from({ length: 100 }, (_, i) => ({ id: String(i + 1), name: `s${i}`, date: 1_700_000_000 + i }));
    await put(cwd, "inputs/q/a.qcow2", qcow2({ snapshots: snaps }));
    let out = body(await tool(CHAIN, cwd, { root: "inputs/q", max_snapshots: 5 }));
    assert.equal(out.status, "partial");
    const a = out.sources.find((s: Json) => s.file === "a.qcow2");
    assert.equal(a.state, "partial");
    assert.match(a.reason, /declares 100 internal snapshot\(s\) and 5 were read: max_snapshots \(5\) was reached/);
    await put(cwd, "inputs/q/a.qcow2", qcow2({ snapshots: snaps.slice(0, 10), declared: 0xffffffff }));
    out = body(await tool(CHAIN, cwd, { root: "inputs/q" }));
    assert.equal(out.status, "partial");
    assert.match(out.sources.find((s: Json) => s.file === "a.qcow2").reason, /declares 4294967295 internal snapshot\(s\) and 10 were read/);
    await put(cwd, "inputs/q/a.qcow2", qcow2({ snapshots: snaps.slice(0, 10) }));
    assert.equal(body(await tool(CHAIN, cwd, { root: "inputs/q" })).status, "complete", "a table read whole is complete");
  });
});

test("a file name never reaches the answer through its extension, and a .vmsd value never reaches a marker unchecked", async () => {
  await withCwd(async (cwd) => {
    const lower = "ghp_" + "unluvodlhcgedwaxdaodgeikuszucgqhdvzx";
    await put(cwd, `inputs/vm/notes.${CANARY.github}`, "x");
    await put(cwd, `inputs/vm/x.${CANARY.aws}`, "x");
    await put(cwd, "inputs/vm/report.TXT", "x");
    await vmwareChain(cwd);
    await put(cwd, "inputs/vm/vm.vmx", vmx([["scsi0:0.fileName", "base-000002.vmdk"]]));
    await put(cwd, "inputs/vm/vm.vmsd", `.encoding = "UTF-8"\nsnapshot.numSnapshots = "${lower}"\n`);
    // an extent type is compared in upper case and shown as written: a lower-case token is still withheld
    await put(cwd, "inputs/vm/ext.vmdk", vmdkDescriptor({ cid: "01020304", extents: [{ sectors: 8, type: lower, name: "e" }] }));
    const run = await tool(CHAIN, cwd, { root: "inputs/vm", limit: 1 });
    const out = body(run);
    assert.equal(out.other_files_by_extension["(other extensions)"], 2);
    assert.equal(out.other_files_by_extension[".txt"], 1);
    const all = await everythingBut(cwd, run.stdout + run.stderr, (await filesUnder(join(cwd, "inputs"))).map((f) => `inputs/${f}`));
    for (const secret of [CANARY.github, CANARY.aws, lower]) {
      for (let k = 4; k + 12 <= secret.length; k++) assert.equal(all.toLowerCase().includes(secret.slice(k, k + 12).toLowerCase()), false, `a piece of ${secret.slice(0, 6)}... reached an answer`);
    }
    // the marker that quotes the database's count still fires, with the count withheld
    const m = (await rowsOf(cwd, out, "markers")).find((r) => r.kind === "running_disk_is_a_delta_without_snapshots");
    assert.match(m.observation, /<(?:token-shaped text withheld \d+ characters|withheld: \d+ bytes, field numsnapshots)> snapshot\(s\)/);
  });
});

test("a base disk whose parentCID says none is not a child of the name its stray hint gives; duplicate CIDs and parent names that disagree are candidates; a backing format named as qemu names it is not a disagreement", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/vm/base.vmdk", vmdkDescriptor({ cid: "aabbccdd", parentHint: "old-base.vmdk", extents: [{ sectors: 8, type: "ZERO" }] }));
    await put(cwd, "inputs/vm/copy.vmdk", vmdkDescriptor({ cid: "aabbccdd", extents: [{ sectors: 8, type: "ZERO" }] }));
    let out = body(await tool(CHAIN, cwd, { root: "inputs/vm" }));
    assert.equal(out.edges.length, 0, "no parent is recorded, so no edge is made");
    let kinds = await markerKinds(cwd, out);
    assert.equal(kinds.includes("parent_missing"), false);
    assert.match(out.disks.find((d: Json) => d.file === "base.vmdk").detail.parent_hint_not_followed, /not followed/);
    assert.ok(kinds.includes("duplicate_cid"));
    // VHD: the header's parent name and a W2ru locator that name different files
    const BASE_ID = "11111111-aaaa-bbbb-cccc-000000000001";
    await put(cwd, "inputs/hv/base.vhd", vhdDynamic({ uid: BASE_ID }));
    await put(cwd, "inputs/hv/other.vhd", vhdDynamic({ uid: "11111111-aaaa-bbbb-cccc-000000000009" }));
    await put(cwd, "inputs/hv/child.vhd", vhdDifferencing({ uid: "11111111-aaaa-bbbb-cccc-000000000002", parentUid: BASE_ID, parentName: "base.vhd", locators: [{ code: "W2ru", text: ".\\other.vhd" }, { code: "W2ku", text: "C:\\VMs\\base.vhd" }] }));
    out = body(await tool(CHAIN, cwd, { root: "inputs/hv" }));
    kinds = await markerKinds(cwd, out);
    assert.ok(kinds.includes("parent_names_disagree"));
    assert.equal(out.edges[0].parent_names_disagree, true);
    assert.equal(out.edges[0].resolved_to, out.disks.find((d: Json) => d.file === "base.vhd").source_id, "the first name that resolves is used, and said");
    // QCOW2 on a VHD parent, named as qemu names the format (vpc)
    await put(cwd, "inputs/hv/top.qcow2", qcow2({ backing: "base.vhd", backingFormat: "vpc" }));
    out = body(await tool(CHAIN, cwd, { root: "inputs/hv" }));
    const edge = out.edges.find((e: Json) => e.child === out.disks.find((d: Json) => d.file === "top.qcow2").source_id);
    assert.equal(edge.format_note, undefined, "vpc is qemu's name for VHD");
  });
});

test("qemu-img's error text is withheld by shape before it is cut: no piece of a token in a long path reaches the answer", async () => {
  await withCwd(async (cwd) => {
    // qemu-img's message quotes the path: "qemu-img: Could not open '<path>': ..."; the token starts 16 characters before
    // the 400th character of it, where a cut made before the shape check would end
    const deep = `inputs/q/${"x".repeat(247)}/${"y".repeat(100)}`;
    await put(cwd, `${deep}/${CANARY.github}.qcow2`, qcow2({}));
    const bin = await stubQemu(cwd);
    const run = await tool(CHAIN, cwd, { root: "inputs/q", qemu_img: "auto" }, { QEMU_STUB_MODE: "fail" }, bin);
    const out = json(run);
    const err = out.disks[0].qemu_img.error as string;
    assert.ok(err.length > 0);
    for (let k = 4; k + 12 <= CANARY.github.length; k++) assert.equal((run.stdout + run.stderr).includes(CANARY.github.slice(k, k + 12)), false, "a piece of the token was shown");
  });
});

test("a long name is withheld by shape before the examined window is cut: a token the 4096-character cut splits is not shown in part", async () => {
  await withCwd(async (cwd) => {
    // a long random run first (withheld as one, so that what follows moves forward into the page), then a token that
    // starts 36 characters before the 4096th character, where the examined window ends (the old window kept 16 of them)
    const head = "aB3dE5fG7h".repeat(400);
    const hint = `${head} ${"x".repeat(58)} ${CANARY.github}.vmdk`;
    assert.equal(hint.indexOf(CANARY.github), 4060);
    await put(cwd, "inputs/vm/a.vmdk", vmdkDescriptor({ cid: "aabbccdd", parentCid: "11223344", parentHint: hint, extents: [{ sectors: 8, type: "ZERO" }] }));
    const run = await tool(CHAIN, cwd, { root: "inputs/vm" });
    const out = body(run);
    assert.match(out.edges[0].parent_name, /whole text: 4105 characters/);
    for (let k = 4; k + 12 <= CANARY.github.length; k++) assert.equal(run.stdout.includes(CANARY.github.slice(k, k + 12)), false, "a piece of the token at the cut was shown");
  });
});
