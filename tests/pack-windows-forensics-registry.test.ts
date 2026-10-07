/**
 * regkv, shellbags and amcache_apps against hives described once and read twice: by a stand-in for regipy (always, so that
 * what CI cannot install is still proved) and by the real library with real regf bytes (where it is installed).
 *
 * Where each layout comes from:
 *   regf hive     tests/windows-hive.ts writes the base block, hbin, nk/vk/li cells from the format's layout;
 *                 tests/windows-stub-regipy.ts holds the stand-in and the byte patches (a registry type number, a
 *                 key that claims more values than it holds, a subkey list that runs off the end, two keys sharing one list).
 *   shell items   the libfwsi notes: a size and a class byte; a root folder item (0x1F) with a GUID at 4; a volume item
 *                 (0x2F) with an ASCII name at 3; a file entry (0x30 or 0x31 for a folder) with a file size at 4, a FAT
 *                 time at 8, attributes at 12 and the ASCII short name at 14; then, on an even offset, the 0xBEEF0004
 *                 extension block: its size (2), version (2), the signature (4), the FAT creation and access times (4
 *                 each), the 2-byte offset of the long name at 0x10 and then, by version, fields up to the NUL-terminated
 *                 UTF-16LE long name (0x14 in version 3, 0x26 in 7, 0x2A in 8, 0x2E in 9), the localised name when the
 *                 item has one, and the 2-byte offset of the block in the item. The same offsets were read off the items of
 *                 a real Windows 10 UsrClass.dat (all version 9, 0x10 holding 0x2E) when the tool was fixed; none of its
 *                 bytes is in this repository.
 *   Amcache       the numbered values of Root\File as the published research regipy's Amcache plugin follows, and the
 *                 named values of Root\InventoryApplicationFile.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { WIN, body, failed, stubModule, tool } from "./windows-pack-harness.ts";
import {
  REGIPY_ABSENT_FILES,
  VARIANTS,
  breakSubkeyList,
  claimValues,
  shareSubkeyList,
  type Node,
  type Variant,
} from "./windows-stub-regipy.ts";

function dual(name: string, fn: (v: Variant) => Promise<void>): void {
  for (const v of VARIANTS) test(`${name} [${v.label}]`, { skip: v.skip }, () => fn(v));
}

const u16z = (text: string): Buffer => Buffer.concat([Buffer.from(text, "utf16le"), Buffer.from([0, 0])]);

// --- regkv ----------------------------------------------------------------------

type RegkvOut = {
  status: string;
  hive: string;
  key: string;
  values: Record<string, unknown>;
  value_types: Record<string, string>;
  value_lengths: Record<string, number | null>;
  subkeys: Array<{ name: string; subkeys: number; values: number; last_modified?: string; last_modified_filetime?: string; subkey_list?: Array<{ name: string }> }>;
  last_modified?: string;
  last_modified_filetime?: string;
  problems: Array<{ where: string; what: string; error: string }>;
  stopped_branches: Array<{ path: string; reason: string }>;
  stopped_branch_count: number;
  tree_complete: boolean;
  nodes_listed: number;
  nodes?: Array<{ path: string; depth: number }>;
  node_count?: number;
  all_nodes?: string;
  all_subkeys?: string;
  hive_dirty: boolean;
  transaction_logs_beside_hive: string[];
  transaction_logs_replayed: boolean;
  sensitive_values_withheld: Array<{ key: string; name: string; type: string; length: number | null }>;
  hive_type: string | null;
};

dual("regkv returns a value whole with its type and length: a binary value past 128 bytes, a string past 256 characters, a multi-string and a qword", async (v) => {
  // regipy trims a value to 256 characters by default, so a binary value came back cut at 128 bytes and a long
  // string at 256 characters, without a word; types were dropped.
  await withCwd(async (cwd) => {
    const blob = Buffer.from(Array.from({ length: 700 }, (_, i) => i % 251));
    const longText = "C:\\Program Files\\" + "Directory\\".repeat(60) + "tool.exe";
    const env = await v.write(cwd, "work/NTUSER.DAT", {
      name: "ROOT",
      children: [{ name: "Software", children: [{
        name: "Vendor",
        lastWritten: 133_443_104_001_234_567n,
        values: [
          { name: "Blob", type: "binary", value: blob },
          { name: "LongPath", type: "sz", value: longText },
          { name: "List", type: "multi_sz", value: ["alpha", "beta"] },
          { name: "Big", type: "qword", value: 0x1234_5678_9abc_def0n },
          { name: "Count", type: "dword", value: 7 },
        ],
      }] }],
    });
    const out = body<RegkvOut>(await tool("regkv", cwd, { hive: "work/NTUSER.DAT", key: "Software\\Vendor" }, env));
    assert.equal(out.status, "complete");
    assert.equal(out.values.Blob, blob.toString("hex"), "700 bytes, all of them");
    assert.equal(out.value_lengths.Blob, 700);
    assert.equal(out.value_types.Blob, "REG_BINARY");
    assert.equal(out.values.LongPath, longText);
    assert.equal(out.value_lengths.LongPath, longText.length);
    assert.deepEqual(out.values.List, ["alpha", "beta"]);
    assert.equal(out.value_types.List, "REG_MULTI_SZ");
    assert.equal(out.value_types.Big, "REG_QWORD");
    assert.equal(out.value_types.Count, "REG_DWORD");
    assert.equal(out.values.Count, 7);
    assert.equal(out.last_modified, "2023-11-13T00:53:20.1234567Z");
    assert.equal(out.last_modified_filetime, "133443104001234567");
  });
});

dual("regkv says a hive is dirty and names the logs beside it, and does not claim to have replayed them", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SYSTEM", { name: "ROOT", children: [{ name: "Select", values: [{ name: "Current", type: "dword", value: 1 }] }] }, { primarySeq: 12, secondarySeq: 11 });
    await writeFile(join(cwd, "work", "SYSTEM.LOG1"), Buffer.alloc(512));
    await writeFile(join(cwd, "work", "SYSTEM.LOG2"), Buffer.alloc(512));
    const out = body<RegkvOut>(await tool("regkv", cwd, { hive: "work/SYSTEM", key: "Select" }, env));
    assert.equal(out.hive_dirty, true);
    assert.deepEqual(out.transaction_logs_beside_hive, ["work/SYSTEM.LOG1", "work/SYSTEM.LOG2"]);
    assert.equal(out.transaction_logs_replayed, false);
    assert.equal(out.hive, "work/SYSTEM");
  });
});

dual("regkv lists every node of a recursive walk, names the branches it did not enter and why, and keeps the whole listing in a file past the inline page", async (v) => {
  // `walk()` returned [] for any key it could not open, and nothing said a branch had been left out.
  await withCwd(async (cwd) => {
    const wide = Array.from({ length: 30 }, (_, i) => ({ name: `Leaf${String(i).padStart(2, "0")}`, children: [{ name: "Deep", children: [{ name: "Deeper" }] }] }));
    const env = await v.write(cwd, "work/SOFTWARE", { name: "ROOT", children: [{ name: "Tree", children: wide }] });
    const out = body<RegkvOut>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Tree", recurse: true, depth: 1, limit: 10 }, env));
    assert.equal(out.node_count, 60, "30 leaves and the 30 keys below them; the third level is not entered");
    assert.equal(out.nodes!.length, 10);
    assert.ok(out.all_nodes, "the whole listing is in a file the answer names");
    assert.equal(out.stopped_branch_count, 30, "each Deep with a child of its own was not entered");
    assert.match(out.stopped_branches[0].reason, /depth limit \(1\)/);
    assert.equal(out.status, "partial");
    assert.equal(out.tree_complete, true);
    const rows = (await readFile(join(cwd, out.all_nodes as string), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { path: string; depth: number });
    assert.equal(rows.length, 60);
    assert.deepEqual(rows.slice(0, 2).map((r) => r.path), ["Tree\\Leaf00", "Tree\\Leaf01"]);
  });
});

dual("regkv withholds the values that can be secrets, by name and by place, and says what it withheld", async (v) => {
  await withCwd(async (cwd) => {
    const pw = "Summer2024!hunter2";
    const env = await v.write(cwd, "work/SOFTWARE", {
      name: "ROOT",
      children: [{ name: "Winlogon", values: [
        { name: "DefaultUserName", type: "sz", value: "alice" },
        { name: "DefaultPassword", type: "sz", value: pw },
        { name: "AutoAdminLogon", type: "sz", value: "1" },
        { name: "PasswordExpiryWarning", type: "dword", value: 5 },
        { name: "Vpn_Token", type: "binary", value: Buffer.from("tok-" + pw) },
      ] }],
    });
    const run = await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Winlogon" }, env);
    const out = body<RegkvOut>(run);
    for (const piece of [pw, "hunter2", Buffer.from(pw).toString("hex"), Buffer.from(pw, "utf16le").toString("hex"), Buffer.from("tok-" + pw).toString("hex")]) {
      assert.equal(run.stdout.includes(piece), false, piece);
    }
    assert.equal(out.values.DefaultUserName, "alice");
    assert.equal(out.values.AutoAdminLogon, "1");
    assert.equal(out.values.PasswordExpiryWarning, 5, "a DWORD is not text or bytes: not withheld");
    assert.equal(out.values.DefaultPassword, `[withheld: ${pw.length} characters]`);
    assert.deepEqual(out.sensitive_values_withheld.map((w) => [w.name, w.type, w.length]).sort(), [
      ["DefaultPassword", "REG_SZ", pw.length],
      ["Vpn_Token", "REG_BINARY", pw.length + 4],
    ]);
  });
});

dual("regkv withholds the V value of a SAM user and the secrets of a SECURITY hive, whatever their names", async (v) => {
  await withCwd(async (cwd) => {
    const verifier = Buffer.from("planted-verifier-material-0123456789abcdef");
    const env = await v.write(cwd, "work/SAM", {
      name: "ROOT",
      children: [{ name: "SAM", children: [{ name: "Domains", children: [{ name: "Account", children: [{ name: "Users", children: [
        { name: "000003E9", values: [{ name: "F", type: "binary", value: Buffer.alloc(80, 1) }, { name: "V", type: "binary", value: verifier }] },
      ] }] }] }] }],
    });
    const run = await tool("regkv", cwd, { hive: "work/SAM", key: "SAM\\Domains\\Account\\Users\\000003E9" }, env);
    const out = body<RegkvOut>(run);
    assert.equal(run.stdout.includes(verifier.toString("hex")), false);
    assert.equal(out.values.F, Buffer.alloc(80, 1).toString("hex"), "F is account metadata, returned");
    assert.match(String(out.values.V), /^\[withheld: \d+ bytes\]$/);
    assert.deepEqual(out.sensitive_values_withheld.map((w) => w.name), ["V"]);
    // A SECURITY hive's LSA secret and a cached logon, by where they are and what they are called.
    const lsa = Buffer.from("planted-lsa-secret-material-0123456789");
    const securityEnv = await v.write(cwd, "work/SECURITY", {
      name: "ROOT",
      children: [
        { name: "Policy", children: [{ name: "Secrets", children: [{ name: "DPAPI_SYSTEM", children: [{ name: "CurrVal", values: [{ name: "", type: "binary", value: lsa }] }] }] }] },
        { name: "Cache", values: [{ name: "NL$1", type: "binary", value: lsa }, { name: "NL$Control", type: "binary", value: Buffer.alloc(4, 1) }] },
      ],
    });
    const secrets = await tool("regkv", cwd, { hive: "work/SECURITY", key: "Policy\\Secrets\\DPAPI_SYSTEM\\CurrVal" }, securityEnv);
    assert.equal(secrets.stdout.includes(lsa.toString("hex")), false);
    assert.equal(body<RegkvOut>(secrets).sensitive_values_withheld.length, 1);
    const cache = await tool("regkv", cwd, { hive: "work/SECURITY", key: "Cache" }, securityEnv);
    assert.equal(cache.stdout.includes(lsa.toString("hex")), false);
    assert.deepEqual(body<RegkvOut>(cache).sensitive_values_withheld.map((w) => w.name), ["NL$1", "NL$Control"]);
  });
});

dual("regkv reports a file that is not a hive as an error with a non-zero exit, not a traceback", async (v) => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "junk"), Buffer.alloc(8192, 0x41));
    const env = await v.write(cwd, "work/placeholder", { name: "ROOT" });
    const err = failed(await tool("regkv", cwd, { hive: "work/junk", key: "x" }, env));
    assert.match(err.error, /could not read the hive/);
  });
});

dual("regkv withholds a value whose type is not text or bytes when its name or its place says secret: the type decides nothing", async (v) => {
  // The gate let a value through when its type was none of REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_BINARY or REG_NONE, so a
  // `Password*` value of type REG_LINK, REG_RESOURCE_LIST or a number regipy does not know, and any value of such a type in
  // Policy\Secrets, came back whole.
  await withCwd(async (cwd) => {
    const secret = "Hunter2-planted-secret-value";
    const forms = (text: string): string[] => [text, Buffer.from(text).toString("hex"), Buffer.from(text, "utf16le").toString("hex")];
    const env = await v.write(cwd, "work/SOFTWARE", {
      name: "ROOT",
      children: [{ name: "Creds", values: [
        { name: "PasswordOdd", type: 0x1234, value: Buffer.from(secret, "utf16le") },
        { name: "PasswordLink", type: "link", value: Buffer.from(secret, "utf16le") },
        { name: "PasswordResources", type: "resource_list", value: Buffer.from(secret) },
        { name: "PasswordCount", type: "dword", value: 7 },
        { name: "DisplayName", type: "sz", value: "visible" },
      ] }],
    });
    const run = await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Creds" }, env);
    const out = body<RegkvOut>(run);
    for (const form of forms(secret)) assert.equal(run.stdout.includes(form), false, form);
    assert.deepEqual(out.sensitive_values_withheld.map((w) => w.name).sort(), ["PasswordLink", "PasswordOdd", "PasswordResources"]);
    for (const name of ["PasswordOdd", "PasswordLink", "PasswordResources"]) assert.match(String(out.values[name]), /^\[withheld/, name);
    assert.equal(out.values.PasswordCount, 7, "a DWORD under a secret-sounding name is a number, not text");
    assert.equal(out.values.DisplayName, "visible");

    // The place, not the name: Policy\Secrets, PolEKList and PolSecretEncryptionKey of a SECURITY hive, any value, any type.
    const lsa = Buffer.from(Array.from({ length: 38 }, (_, i) => 0xa0 + (i % 16)));
    const lsaEnv = await v.write(cwd, "work/SECURITY", {
      name: "ROOT",
      children: [{ name: "Policy", children: [
        { name: "Secrets", children: [{ name: "DPAPI_SYSTEM", children: [{ name: "CurrVal", values: [
          { name: "", type: 0x1234, value: lsa },
          { name: "Extra", type: "link", value: Buffer.from(secret, "utf16le") },
        ] }] }] },
        { name: "PolEKList", values: [{ name: "", type: "none", value: lsa }] },
        { name: "PolSecretEncryptionKey", values: [{ name: "", type: "none", value: lsa }] },
      ] }],
    });
    for (const key of ["Policy\\Secrets\\DPAPI_SYSTEM\\CurrVal", "policy/secrets/dpapi_system/currval", "\\Policy\\PolEKList", "ROOT\\Policy\\POLEKLIST", "Policy\\PolSecretEncryptionKey"]) {
      const answer = await tool("regkv", cwd, { hive: "work/SECURITY", key }, lsaEnv);
      const got = body<RegkvOut>(answer);
      assert.equal(answer.stdout.includes(lsa.toString("hex")), false, key);
      for (const form of forms(secret)) assert.equal(answer.stdout.includes(form), false, key + " " + form);
      assert.ok(got.sensitive_values_withheld.length >= 1, key);
      for (const w of got.sensitive_values_withheld) assert.match(String(got.values[w.name]), /^\[withheld/, key);
    }
    // The (default) value of PolEKList is the one the typo missed: 38 bytes of type REG_NONE.
    const ek = body<RegkvOut>(await tool("regkv", cwd, { hive: "work/SECURITY", key: "Policy\\PolEKList" }, lsaEnv));
    assert.deepEqual(ek.sensitive_values_withheld.map((w) => [w.name, w.type, w.length]), [["(default)", "REG_NONE", 38]]);
  });
});

dual("regkv keeps every subkey of a key that has more than the inline list holds, in a file the answer names, and says the listing is partial", async (v) => {
  // 2,500 subkeys: 2,000 were listed, the rest dropped, and the answer said complete with no file.
  await withCwd(async (cwd) => {
    const children = Array.from({ length: 2500 }, (_, i) => ({ name: `K${String(i).padStart(4, "0")}` }));
    const env = await v.write(cwd, "work/SOFTWARE", { name: "ROOT", children: [{ name: "Big", children }] });
    const out = body<RegkvOut>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Big" }, env));
    assert.equal(out.subkeys.length, 2000);
    assert.equal(out.nodes_listed, 2500);
    assert.equal(out.tree_complete, false);
    assert.equal(out.status, "partial");
    assert.ok(out.all_subkeys, "the whole list is in a file the answer names");
    const rows = (await readFile(join(cwd, out.all_subkeys as string), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { path: string });
    assert.equal(rows.length, 2500);
    assert.equal(rows[0].path, "Big\\K0000");
    assert.equal(rows[2499].path, "Big\\K2499");
  });
});

dual("regkv refuses a depth past 128 as JSON, and stops a deeper walk at the depth limit, naming the branch", async (v) => {
  // The nested listing was dumped as JSON, which gives up near a thousand levels: a depth of 600 over a long chain was a traceback.
  await withCwd(async (cwd) => {
    let chain: Node = { name: "Leaf" };
    for (let i = 0; i < 700; i++) chain = { name: `L${i}`, children: [chain] };
    const env = await v.write(cwd, "work/SOFTWARE", { name: "ROOT", children: [{ name: "Chain", children: [chain] }] });
    const refusal = failed(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Chain", recurse: true, depth: 600 }, env));
    assert.match(refusal.error, /depth must be a whole number from 0 to 128/);
    const out = body<RegkvOut>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Chain", recurse: true, depth: 128 }, env));
    assert.equal(out.stopped_branch_count, 1);
    assert.match(out.stopped_branches[0].reason, /depth limit \(128\)/);
    assert.equal(out.status, "partial");
  });
});

dual("regkv says when a key declares more values than were read", async (v) => {
  // regipy ends the iteration at a value record it cannot parse, without an error, so a key could hold values the answer lacked.
  await withCwd(async (cwd) => {
    const root: Node = { name: "ROOT", children: [{ name: "Short", values: [{ name: "a", type: "sz", value: "x" }, { name: "b", type: "dword", value: 2 }] }] };
    const env = await v.writePatched(cwd, "work/SOFTWARE", root, {
      real: (buf) => claimValues(buf, "Short", 5),
      stub: (nodes, ids) => { nodes[ids.get(root.children![0])!].declared_values = 5; },
    });
    const out = body<RegkvOut>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Short" }, env));
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p) => /declares 5 values and 2 were read/.test(p.error)), JSON.stringify(out.problems));
    assert.equal(out.values.a, "x", "what was read is kept");
  });
});

dual("regkv does not follow a subkey list a second time: a cycle is a problem it names, and the walk ends", async (v) => {
  await withCwd(async (cwd) => {
    const child: Node = { name: "ChildKey" };
    const top: Node = { name: "TopKey", children: [child] };
    const root: Node = { name: "ROOT", children: [top] };
    const env = await v.writePatched(cwd, "work/SOFTWARE", root, {
      real: (buf) => shareSubkeyList(buf, "ChildKey", "TopKey"),
      stub: (nodes, ids) => { nodes[ids.get(child)!].children_of = ids.get(top)!; },
    });
    const out = body<RegkvOut>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "TopKey", recurse: true, depth: 20 }, env));
    assert.ok(out.problems.some((p) => /already reached: a cycle, or a list two keys share/.test(p.error)), JSON.stringify(out.problems));
    assert.equal(out.status, "partial");
    assert.ok((out.node_count ?? 0) <= 2, "the child is listed once, not once for every level of depth");
  });
});

dual("regkv names the key it did not find, with the names that are there", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SYSTEM", { name: "ROOT", children: [{ name: "ControlSet001", children: [{ name: "Enum" }] }, { name: "Select" }] });
    const err = failed(await tool("regkv", cwd, { hive: "work/SYSTEM", key: "CurrentControlSet\\Enum" }, env));
    assert.equal(err.error, "key not found");
    assert.equal(err.missing, "CurrentControlSet");
    assert.deepEqual(err.subkeys_there, ["ControlSet001", "Select"]);
  });
});

test("regkv without regipy answers in JSON that the library is missing, and does not open a pipe", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "SOFTWARE"), Buffer.alloc(4096, 0x41));
    const absent = await stubModule(cwd, REGIPY_ABSENT_FILES);
    const gone = failed(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "x" }, absent));
    assert.match(gone.error, /regipy is not installed/);
    assert.equal(gone.ok, false);
  });
});

// --- a pipe is not a hive -------------------------------------------------------------

function withFifo(path: string, fn: () => Promise<void>): Promise<void> {
  const made = spawnSync("mkfifo", [path]);
  if (made.status !== 0) return Promise.resolve();
  // A writer feeds the pipe some zeros and closes it when a reader has come, so that a tool that opens the pipe anyway reads to
  // the end and fails, instead of waiting for ever; the writer itself waits at open() until then and is killed after the test.
  const writer = spawn("sh", ["-c", 'head -c 20000 /dev/zero > "$0"', path], { stdio: "ignore" });
  return fn().finally(() => {
    writer.kill("SIGKILL");
  });
}

for (const [name, args] of [
  ["regkv", { hive: "work/pipe", key: "x" }],
  ["shellbags", { hive: "work/pipe" }],
  ["amcache_apps", { hive: "work/pipe" }],
] as const) {
  test(`${name} does not open a named pipe as a hive: it says it is not a regular file and counts it as not attempted`, async () => {
    await withCwd(async (cwd) => {
      await withFifo(join(cwd, "work", "pipe"), async () => {
        const err = failed(await tool(name, cwd, args, await VARIANTS[0].write(cwd, "work/real", { name: "ROOT" })));
        assert.match(err.error, /not a regular file/);
        assert.equal(err.not_attempted, 1);
      });
    });
  });
}

// --- amcache_apps ---------------------------------------------------------------

type AmcacheOut = {
  status: string;
  layouts_found: string[];
  rows_by_layout: Record<string, number>;
  entries: Array<Record<string, unknown>>;
  entry_count: number;
  hive_dirty: boolean;
  transaction_logs_beside_hive: string[];
  transaction_logs_replayed: boolean;
  rows_failed: number;
  problems: string[];
  problems_not_listed: number;
};

const SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

dual("amcache_apps names the numbered values as regipy's Amcache plugin does, and reads the linker time as a Unix-epoch value, not a FILETIME", async (v) => {
  // `c` was labelled file_version (it is the file description; the version is `5`), and the linker
  // timestamp, a 32-bit Unix-epoch value from the PE header, was converted as a FILETIME: 1700000000
  // came out as 1601-01-01T00:02:50Z.
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/Amcache.hve", {
      name: "{11111111-2222-3333-4444-555555555555}",
      children: [{
        name: "Root",
        children: [{
          name: "File",
          children: [{
            name: "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
            children: [{
              name: "1a2b",
              values: [
                { name: "0", type: "sz", value: "Fixture Suite" },
                { name: "1", type: "sz", value: "Fixture Corp" },
                { name: "5", type: "sz", value: "1.2.3.4" },
                { name: "c", type: "sz", value: "The fixture application" },
                { name: "f", type: "dword", value: 1700000000 },
                { name: "11", type: "qword", value: 133_443_104_001_234_567n },
                { name: "15", type: "sz", value: "C:\\Fixtures\\app.exe" },
                { name: "100", type: "sz", value: "0000" + "ab".repeat(16) },
                { name: "101", type: "sz", value: "0000" + SHA1 },
              ],
            }],
          }],
        }],
      }],
    });
    const out = body<AmcacheOut>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }, env));
    assert.deepEqual(out.layouts_found, ["File"]);
    const row = out.entries[0];
    assert.equal(row.layout, "File");
    assert.equal(row.file_version, "1.2.3.4", "value 5 is the file version");
    assert.equal(row.file_description, "The fixture application", "value c is the file description");
    assert.notEqual(row.file_version, row.file_description);
    assert.equal(row.linker_compile_time, 1700000000);
    assert.equal(row.linker_compile_time_utc, "2023-11-14T22:13:20Z", "a Unix-epoch value: 1700000000 is 2023, not 1601");
    assert.equal(row.last_modified_timestamp_filetime, "133443104001234567");
    assert.equal(row.last_modified_timestamp_utc, "2023-11-13T00:53:20.1234567Z");
    assert.equal(row.full_path, "C:\\Fixtures\\app.exe");
    assert.equal(row.sha1_raw, "0000" + SHA1, "the value as stored is kept");
    assert.equal(row.sha1, SHA1, "stripped of its four leading zeros only where it has that shape");
    assert.equal(row.link_date, undefined);
  });
});

dual("amcache_apps reads both layouts when a hive has both, each row naming its own", async (v) => {
  // The older layout was read only when the Windows 10 tree was absent, so a hive that carried both
  // listed one tree and said nothing of the other.
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/Amcache.hve", {
      name: "{11111111-2222-3333-4444-555555555555}",
      children: [{
        name: "Root",
        children: [
          { name: "File", children: [{ name: "{vol}", children: [{ name: "7", values: [{ name: "15", type: "sz", value: "C:\\old\\legacy.exe" }] }] }] },
          {
            name: "InventoryApplicationFile",
            children: [{
              name: "modern.exe|0123456789abcdef",
              values: [
                { name: "LowerCaseLongPath", type: "sz", value: "c:\\new\\modern.exe" },
                { name: "FileId", type: "sz", value: "0000" + SHA1.toUpperCase() },
                { name: "Publisher", type: "sz", value: "Modern Corp" },
                { name: "LinkDate", type: "sz", value: "10/24/2023 10:14:55" },
                { name: "OriginalFileName", type: "sz", value: "modern.exe" },
              ],
            }],
          },
        ],
      }],
    });
    const out = body<AmcacheOut>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }, env));
    assert.deepEqual([...out.layouts_found].sort(), ["File", "InventoryApplicationFile"]);
    assert.deepEqual(out.rows_by_layout, { File: 1, InventoryApplicationFile: 1 });
    assert.equal(out.entry_count, 2);
    const byLayout = Object.fromEntries(out.entries.map((r) => [r.layout as string, r]));
    assert.equal(byLayout.File.full_path, "C:\\old\\legacy.exe");
    assert.equal(byLayout.InventoryApplicationFile.LowerCaseLongPath, "c:\\new\\modern.exe");
    assert.equal(byLayout.InventoryApplicationFile.OriginalFileName, "modern.exe", "every named value is kept, not a chosen few");
    assert.equal(byLayout.InventoryApplicationFile.file_id_sha1, SHA1, "lower-cased, four zeros stripped");
    assert.equal(byLayout.InventoryApplicationFile.FileId, "0000" + SHA1.toUpperCase(), "and the value as stored is kept");
    assert.equal(out.status, "complete");
    assert.equal(out.hive_dirty, false);
  });
});

dual("amcache_apps returns a path past 256 characters whole: regipy's default cut is not taken", async (v) => {
  await withCwd(async (cwd) => {
    const long = "c:\\users\\someone\\" + "nested\\".repeat(60) + "tool.exe";
    const env = await v.write(cwd, "work/Amcache.hve", { name: "{r}", children: [{ name: "Root", children: [
      { name: "InventoryApplicationFile", children: [{ name: "tool.exe|1", values: [{ name: "LowerCaseLongPath", type: "sz", value: long }] }] },
      { name: "File", children: [{ name: "{vol}", children: [{ name: "9", values: [{ name: "15", type: "sz", value: long }] }] }] },
    ] }] });
    const out = body<AmcacheOut>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }, env));
    const by = Object.fromEntries(out.entries.map((r) => [r.layout as string, r]));
    assert.ok(long.length > 256);
    assert.equal(by.InventoryApplicationFile.LowerCaseLongPath, long);
    assert.equal(by.File.full_path, long);
  });
});

dual("amcache_apps says a hive is dirty, names the transaction logs beside it, and does not claim to have replayed them", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(
      cwd,
      "work/Amcache.hve",
      { name: "{r}", children: [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: [{ name: "a.exe|1", values: [{ name: "Name", type: "sz", value: "a.exe" }] }] }] }] },
      { primarySeq: 9, secondarySeq: 8 },
    );
    await writeFile(join(cwd, "work", "Amcache.hve.LOG1"), Buffer.alloc(512));
    const out = body<AmcacheOut>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }, env));
    assert.equal(out.hive_dirty, true);
    assert.deepEqual(out.transaction_logs_beside_hive, ["work/Amcache.hve.LOG1"]);
    assert.equal(out.transaction_logs_replayed, false);
  });
});

dual("amcache_apps fails with the layouts it looked for when the hive holds neither", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/Other.hve", { name: "r", children: [{ name: "Root", children: [{ name: "Elsewhere" }] }] });
    const err = failed(await tool("amcache_apps", cwd, { hive: "work/Other.hve" }, env));
    assert.match(err.error, /neither Amcache layout/);
    assert.deepEqual(err.looked_for, ["\\Root\\InventoryApplicationFile", "\\Root\\File"]);
  });
});

dual("amcache_apps says a subkey list it cannot read is rows lost, and answers in JSON with the rows it could read", async (v) => {
  // The subkey lists were enumerated outside the guard that counts a failed row, so a damaged list was a traceback.
  await withCwd(async (cwd) => {
    const file: Node = { name: "File", children: [{ name: "{vol}", children: [{ name: "7", values: [{ name: "15", type: "sz", value: "C:\\old\\legacy.exe" }] }] }] };
    const root: Node = { name: "{r}", children: [{ name: "Root", children: [
      file,
      { name: "InventoryApplicationFile", children: [{ name: "modern.exe|1", values: [{ name: "LowerCaseLongPath", type: "sz", value: "c:\\new\\modern.exe" }] }] },
    ] }] };
    const env = await v.writePatched(cwd, "work/Amcache.hve", root, {
      real: (buf) => breakSubkeyList(buf, "File"),
      stub: (nodes, ids) => { nodes[ids.get(file)!].broken = ["subkeys"]; },
    });
    const out = body<AmcacheOut>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }, env));
    assert.equal(out.status, "partial");
    assert.deepEqual([...out.layouts_found].sort(), ["File", "InventoryApplicationFile"]);
    assert.ok(out.rows_failed >= 1);
    assert.ok(out.problems.some((p) => p.startsWith("File:")), JSON.stringify(out.problems));
    assert.equal(out.rows_by_layout.InventoryApplicationFile, 1, "the rows that could be read are kept");
  });
});

test("amcache_apps without regipy answers in JSON that the library is missing", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "Amcache.hve"), Buffer.alloc(4096, 0x41));
    const gone = failed(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }, await stubModule(cwd, REGIPY_ABSENT_FILES)));
    assert.match(gone.error, /regipy is not installed/);
  });
});

test("amcache_apps does not describe the newer layout as a Windows 10 one: it names it by its values", async () => {
  const manifest = JSON.parse(await readFile(join(ROOT, "packs", "windows-forensics", "tools", "amcache_apps", "manifest.json"), "utf8")) as { description: string };
  const source = await readFile(join(WIN, "amcache_apps", "run.py"), "utf8");
  assert.doesNotMatch(manifest.description, /Windows 10 and later/);
  assert.doesNotMatch(source.split('"""')[1], /Windows 10 and later/);
  assert.match(manifest.description, /newer InventoryApplicationFile layout \(named values\)/);
});

// --- shellbags ------------------------------------------------------------------

/**
 * Shell items as the libfwsi notes lay them out (see the header of this file): every item starts with its size (2 bytes)
 * and a class byte; the 0xBEEF0004 extension block holds the long name at 0x14 (version 3), 0x26 (7), 0x2A (8) or 0x2E (9),
 * and the 2-byte field at 0x10 says where.
 */
const fat = (y: number, mo: number, d: number, h: number, mi: number, s: number): number => (((y - 1980) << 9) | (mo << 5) | d) | (((h << 11) | (mi << 5) | (s >> 1)) << 16);

function shellItem(parts: Buffer[]): Buffer {
  const content = Buffer.concat(parts);
  const size = Buffer.alloc(2);
  size.writeUInt16LE(content.length + 2);
  return Buffer.concat([size, content]);
}

// My Computer's GUID {20D04FE0-3AEA-1069-A2D8-08002B30309D}: Data1, Data2 and Data3 little-endian, Data4 as written.
const rootFolderItem = (): Buffer => shellItem([Buffer.from([0x1f, 0x50]), Buffer.from("e04fd0203aea6910a2d808002b30309d", "hex")]);
const volumeItem = (name: string): Buffer => shellItem([Buffer.from([0x2f]), Buffer.from(name + "\0", "latin1"), Buffer.alloc(18)]);

const NAME_AT: Record<number, number> = { 3: 0x14, 7: 0x26, 8: 0x2a, 9: 0x2e };

function extensionBlock(version: number, longName: string, o: { localized?: string; nameOffsetField?: number; declaredSize?: number } = {}): Buffer {
  const at = NAME_AT[version];
  const head = Buffer.alloc(at);
  head.writeUInt16LE(version, 2);
  head.writeUInt32LE(0xbeef0004, 4);
  head.writeUInt32LE(fat(2024, 3, 5, 9, 30, 0), 8);
  head.writeUInt32LE(fat(2024, 3, 6, 10, 0, 2), 12);
  head.writeUInt16LE(o.nameOffsetField ?? at, 0x10);
  // The four bytes before the name in versions 8 and 9 hold what is not text; Windows 10 leaves bytes there that read as a
  // printable UTF-16 character (0xB3AC), which is what an extra leading character in the old candidate was.
  if (version >= 8) head.writeUInt32LE(0x012ab3ac, at - 4);
  const trailer = Buffer.alloc(2);
  trailer.writeUInt16LE(0x14);
  const block = Buffer.concat([head, u16z(longName), ...(o.localized ? [u16z(o.localized)] : []), trailer]);
  block.writeUInt16LE(o.declaredSize ?? block.length, 0);
  return block;
}

function folderItem(shortName: string, ext: Buffer): Buffer {
  // After the size and the class (0x31, a folder) and a sort byte: file size (4, at 4), FAT modification time (4, at 8),
  // attributes (2, at 12), then the ASCII short name from 14, padded so the extension block starts on an even offset.
  const fixed = Buffer.alloc(10);
  fixed.writeUInt32LE(fat(2024, 3, 4, 12, 0, 0), 4);
  fixed.writeUInt16LE(0x10, 8);
  const primary = Buffer.from(shortName + "\0", "latin1");
  return shellItem([Buffer.from([0x31, 0x00]), fixed, primary, Buffer.alloc((14 + primary.length) % 2), ext]);
}

const mruList = (...order: number[]): Buffer => {
  const b = Buffer.alloc((order.length + 1) * 4);
  order.forEach((x, i) => b.writeInt32LE(x, i * 4));
  b.writeInt32LE(-1, order.length * 4);
  return b;
};

type BagItem = {
  type: string;
  decoded: string;
  name: string;
  long_name?: string;
  long_name_from?: string;
  localized_name?: string;
  extension_version?: number;
  extension_layout?: string;
  created?: string | null;
  accessed?: string | null;
  guid?: string;
  error?: string;
};
type BagOut = {
  status: string;
  roots_walked: string[];
  entry_count: number;
  entries: Array<{ root: string; path: string; name: string; slot: string; depth: number; mru_position: number | null; item_bytes?: number; no_subkey?: boolean; item: BagItem }>;
  values_without_subkey: Array<{ slot: string; no_subkey: boolean; item: { name: string } }>;
  values_without_subkey_count: number;
  problem_count: number;
  problems: Array<{ key: string; why: string }>;
  tried?: Array<{ key: string; nearest_key_failed?: string }>;
  error?: string;
};

const BAG_PATH = ["Local Settings", "Software", "Microsoft", "Windows", "Shell", "BagMRU"];
function nest(path: string[], leaf: Node): Node {
  return path.reduceRight<Node>((child, name) => ({ name, children: [child] }), leaf);
}

dual("shellbags reads the long name from its layout in versions 3, 7, 8 and 9, at the offset each has, and a localised name that follows it is not mistaken for it", async (v) => {
  // The offsets were 0x12 for version 3 and 0x26 for 7, and nothing for 8 and 9, and the fixture wrote the parser's own layout.
  // On a real Windows 10 hive (version 9) the candidate was wrong in most items: an extra leading character, the localised
  // `@...dll,-N` name, or none.
  await withCwd(async (cwd) => {
    const bag: Node = {
      name: "BagMRU",
      values: [{ name: "0", type: "binary", value: rootFolderItem() }, { name: "MRUListEx", type: "binary", value: mruList(0) }],
      children: [{ name: "0", values: [
        { name: "0", type: "binary", value: volumeItem("C:\\") },
        { name: "1", type: "binary", value: folderItem("QUARTE~1", extensionBlock(7, "Quarterly Reports 2024 ÖZET")) },
        { name: "2", type: "binary", value: folderItem("USERS~1", extensionBlock(9, "Users", { localized: "@shell32.dll,-21813" })) },
        { name: "3", type: "binary", value: folderItem("OLDVER~1", extensionBlock(3, "Old Version Three Folder")) },
        { name: "4", type: "binary", value: folderItem("EIGHT~1", extensionBlock(8, "Version Eight Folder")) },
        { name: "5", type: "binary", value: folderItem("NINE~1", extensionBlock(9, "Documents")) },
        { name: "MRUListEx", type: "binary", value: mruList(2, 1, 0, 3, 4, 5) },
      ], children: [{ name: "0" }, { name: "1" }, { name: "2" }, { name: "3" }, { name: "4" }, { name: "5" }] }],
    };
    const env = await v.write(cwd, "work/UsrClass.dat", { name: "ROOT", children: [nest(BAG_PATH.slice(0, -1), bag)] });
    const out = body<BagOut>(await tool("shellbags", cwd, { hive: "work/UsrClass.dat" }, env));
    const by = Object.fromEntries(out.entries.map((e) => [e.slot + "@" + e.depth, e]));
    const v7 = by["1@2"];
    assert.equal(v7.item.long_name, "Quarterly Reports 2024 ÖZET");
    assert.equal(v7.item.long_name_from, "layout");
    assert.equal(v7.item.extension_layout, "decoded");
    assert.equal(v7.item.extension_version, 7);
    assert.equal(v7.item.created, "2024-03-05T09:30:00 (local)");
    assert.equal(v7.item.accessed, "2024-03-06T10:00:02 (local)");
    assert.equal(v7.mru_position, 1);
    const v3 = by["3@2"];
    assert.equal(v3.item.long_name, "Old Version Three Folder");
    assert.equal(v3.item.long_name_from, "layout");
    assert.equal(v3.item.extension_layout, "decoded");
    const v8 = by["4@2"];
    assert.equal(v8.item.long_name, "Version Eight Folder");
    assert.equal(v8.item.long_name_from, "layout");
    const v9 = by["2@2"];
    assert.equal(v9.item.extension_version, 9);
    assert.equal(v9.item.long_name, "Users", "the long name, not the longer localised name after it and not a character from the bytes before it");
    assert.equal(v9.item.long_name_from, "layout");
    assert.equal(v9.item.extension_layout, "decoded");
    assert.equal(v9.item.localized_name, "@shell32.dll,-21813");
    assert.equal(v9.name, "Users");
    const plain9 = by["5@2"];
    assert.equal(plain9.item.long_name, "Documents");
    assert.equal(plain9.item.localized_name, undefined, "the block's last two bytes are an offset, not a localised name");
    assert.equal(out.status, "complete");
  });
});

dual("shellbags offers a string candidate, labelled, when the block's own name offset disagrees with the layout, or its size cuts the name, and says why", async (v) => {
  await withCwd(async (cwd) => {
    const bag: Node = {
      name: "BagMRU",
      values: [
        { name: "0", type: "binary", value: folderItem("DISAGR~1", extensionBlock(9, "Disagreeing Offset Folder", { nameOffsetField: 0x2c })) },
        { name: "1", type: "binary", value: folderItem("CUTSIZ~1", extensionBlock(7, "Folder Cut By Its Size", { declaredSize: 0x38 })) },
        { name: "2", type: "binary", value: folderItem("FUTURE~1", extensionBlock(9, "Future Folder").subarray(0)) },
        { name: "MRUListEx", type: "binary", value: mruList(0, 1, 2) },
      ],
      children: [{ name: "0" }, { name: "1" }, { name: "2" }],
    };
    const env = await v.write(cwd, "work/UsrClass.dat", { name: "ROOT", children: [nest(BAG_PATH.slice(0, -1), bag)] });
    const out = body<BagOut>(await tool("shellbags", cwd, { hive: "work/UsrClass.dat" }, env));
    const by = Object.fromEntries(out.entries.map((e) => [e.slot, e]));
    assert.equal(by["0"].item.long_name_from, "strings");
    assert.match(by["0"].item.extension_layout ?? "", /^not decoded: the block's own name offset \(0x10\) is 0x2c and this reader expects 0x2e for version 9/);
    assert.equal(by["1"].item.long_name_from, "strings", "a name whose terminator is past the block's declared size is not read from the layout");
    assert.match(by["1"].item.extension_layout ?? "", /^not decoded/);
    assert.equal(by["2"].item.long_name_from, "layout", "the same block, with agreeing fields, is read");
  });
});

dual("shellbags walks every BagMRU root the hive has, names them, and lists a numbered value that has no key under it", async (v) => {
  // It stopped at the first root that opened, so a hive with the Shell and the ShellNoRoam trees both populated
  // answered for one; a value with no child key was never looked at.
  await withCwd(async (cwd) => {
    const classes: Node = {
      name: "BagMRU",
      values: [{ name: "0", type: "binary", value: volumeItem("E:\\") }, { name: "MRUListEx", type: "binary", value: mruList(0) }],
      children: [{ name: "0" }],
    };
    const older: Node = {
      name: "BagMRU",
      values: [
        { name: "0", type: "binary", value: volumeItem("F:\\") },
        { name: "5", type: "binary", value: folderItem("GHOST~1", extensionBlock(7, "A Folder With No Bag")) },
        { name: "NodeSlot", type: "dword", value: 9 },
      ],
      children: [{ name: "0" }],
    };
    const env = await v.write(cwd, "work/NTUSER.DAT", {
      name: "ROOT",
      children: [
        nest(["Local Settings", "Software", "Microsoft", "Windows", "Shell"], classes),
        nest(["Software", "Microsoft", "Windows", "ShellNoRoam"], older),
      ],
    });
    const out = body<BagOut>(await tool("shellbags", cwd, { hive: "work/NTUSER.DAT" }, env));
    assert.deepEqual(out.roots_walked, [
      "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
      "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
    ]);
    const roots = new Set(out.entries.map((e) => e.root));
    assert.equal(roots.size, 2, "entries come from both roots");
    assert.deepEqual(out.entries.filter((e) => e.root.startsWith("Software")).map((e) => e.name).sort(), ["A Folder With No Bag", "F:\\"]);
    assert.equal(out.values_without_subkey_count, 1);
    assert.equal(out.values_without_subkey[0].slot, "5");
    assert.equal(out.values_without_subkey[0].no_subkey, true);
    assert.equal(out.values_without_subkey[0].item.name, "A Folder With No Bag");
  });
});

dual("shellbags reads a shell item longer than 128 bytes whole, and refuses a max_depth that would exhaust the stack", async (v) => {
  // regipy's default read cut a binary value to 128 bytes, so a long item was decoded from its first 128.
  await withCwd(async (cwd) => {
    const long = "a-very-long-folder-name-".repeat(14) + "end";
    const bag: Node = {
      name: "BagMRU",
      values: [{ name: "0", type: "binary", value: folderItem("LONGFO~1", extensionBlock(7, long)) }, { name: "MRUListEx", type: "binary", value: mruList(0) }],
      children: [{ name: "0" }],
    };
    const env = await v.write(cwd, "work/UsrClass.dat", { name: "ROOT", children: [nest(BAG_PATH.slice(0, -1), bag)] });
    const out = body<BagOut>(await tool("shellbags", cwd, { hive: "work/UsrClass.dat" }, env));
    assert.ok((out.entries[0].item_bytes ?? 0) > 128);
    assert.equal(out.entries[0].item.long_name, long);
    assert.equal(out.entries[0].item.long_name_from, "layout");
    assert.match(failed(await tool("shellbags", cwd, { hive: "work/UsrClass.dat", max_depth: 100000 }, env)).error, /max_depth must be a whole number from 1 to 128/);
  });
});

dual("shellbags does not walk a subkey list twice: a cycle is a problem it names, and the walk ends", async (v) => {
  await withCwd(async (cwd) => {
    const child: Node = { name: "0" };
    const bag: Node = {
      name: "BagMRU",
      values: [{ name: "0", type: "binary", value: volumeItem("C:\\") }, { name: "MRUListEx", type: "binary", value: mruList(0) }],
      children: [child],
    };
    const root: Node = { name: "ROOT", children: [nest(BAG_PATH.slice(0, -1), bag)] };
    const env = await v.writePatched(cwd, "work/UsrClass.dat", root, {
      real: (buf) => shareSubkeyList(buf, "0", "BagMRU"),
      stub: (nodes, ids) => { nodes[ids.get(child)!].children_of = ids.get(bag)!; },
    });
    const out = body<BagOut>(await tool("shellbags", cwd, { hive: "work/UsrClass.dat" }, env));
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p) => /already walked: a cycle, or a list two keys share/.test(p.why)), JSON.stringify(out.problems));
    assert.ok(out.entry_count <= 3, "the cycle is not unrolled to the depth limit: " + out.entry_count);
  });
});

dual("shellbags answers in JSON when the key it was asked for is under a subkey list that cannot be read, naming that the neighbours could not be listed", async (v) => {
  // nearest_key re-read the damaged list inside the handler for the first failure, and the second failure was a traceback.
  await withCwd(async (cwd) => {
    const broken: Node = { name: "Broken", children: [{ name: "Inside" }] };
    const root: Node = { name: "ROOT", children: [broken] };
    const env = await v.writePatched(cwd, "work/UsrClass.dat", root, {
      real: (buf) => breakSubkeyList(buf, "Broken"),
      stub: (nodes, ids) => { nodes[ids.get(broken)!].broken = ["subkeys"]; },
    });
    const err = failed(await tool("shellbags", cwd, { hive: "work/UsrClass.dat", key: "Broken\\Missing" }, env)) as unknown as BagOut;
    assert.equal(err.error, "no BagMRU root in this hive");
    assert.ok(err.tried && err.tried.length === 1);
    assert.match(err.tried![0].nearest_key_failed ?? "", /./);
  });
});

test("shellbags without regipy answers in JSON that the library is missing", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work"), { recursive: true });
    await writeFile(join(cwd, "work", "UsrClass.dat"), Buffer.alloc(4096, 0x41));
    const gone = failed(await tool("shellbags", cwd, { hive: "work/UsrClass.dat" }, await stubModule(cwd, REGIPY_ABSENT_FILES)));
    assert.match(gone.error, /regipy is not installed/);
  });
});

// --- hostile input --------------------------------------------------------------------

test("regkv, shellbags and amcache_apps answer a hive that was cut short in JSON, whatever the cut, and never in a traceback", { skip: VARIANTS[1].skip }, async () => {
  // regipy raises mid-walk when the file ends inside a structure; shellbags and amcache_apps let it through as a traceback.
  await withCwd(async (cwd) => {
    const bag: Node = {
      name: "BagMRU",
      values: [{ name: "0", type: "binary", value: folderItem("LONGFO~1", extensionBlock(7, "A Folder")) }, { name: "MRUListEx", type: "binary", value: mruList(0) }],
      children: [{ name: "0", children: [{ name: "0" }] }],
    };
    await VARIANTS[1].write(cwd, "work/full.dat", {
      name: "ROOT",
      children: [
        nest(BAG_PATH.slice(0, -1), bag),
        { name: "Root", children: [{ name: "InventoryApplicationFile", children: [{ name: "a.exe|1", values: [{ name: "LowerCaseLongPath", type: "sz", value: "c:\\a.exe" }] }] }] },
      ],
    });
    const whole = await readFile(join(cwd, "work", "full.dat"));
    let answered = 0;
    for (const cut of [4112, 4208, 4400, 4800, 5100, 5600, 6400]) {
      await writeFile(join(cwd, "work", "cut.dat"), whole.subarray(0, cut));
      for (const [name, args] of [
        ["regkv", { hive: "work/cut.dat", key: "\\", recurse: true, depth: 8 }],
        ["shellbags", { hive: "work/cut.dat" }],
        ["amcache_apps", { hive: "work/cut.dat" }],
      ] as const) {
        const run = await tool(name, cwd, args);
        assert.doesNotMatch(run.stderr, /Traceback/, `${name} cut at ${cut}: ${run.stderr.slice(-300)}`);
        JSON.parse(run.stdout);
        answered++;
      }
    }
    assert.equal(answered, 21);
  });
});
