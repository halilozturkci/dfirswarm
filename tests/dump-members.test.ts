/**
 * The dump-named members of a catalogue and their post (scripts/dump-members.ts).
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { dumpKind, dumpMembers, dumpReaders, dumpsPost, DUMPS_SHOWN, headerKind, kickoffDumps, kickoffDumpsNote, KICKOFF_DUMPS_SHOWN } from "../scripts/dump-members.ts";

const dir = mkdtempSync(join(tmpdir(), "dump-members-"));
after(() => rmSync(dir, { recursive: true, force: true }));

test("a dump is known by its name, and other names are not", () => {
  assert.equal(dumpKind("Users/a/AppData/Local/CrashDumps/app.exe.1234.dmp"), "process or crash dump");
  assert.equal(dumpKind("Windows\\MEMORY.DMP"), "kernel crash dump");
  assert.equal(dumpKind("hiberfil.sys"), "hibernation file");
  assert.equal(dumpKind("C/pagefile.sys"), "page or swap file");
  assert.equal(dumpKind("vm/host.vmem"), "memory image");
  for (const no of ["a/dmp.txt", "a/notpagefile.sys.bak", "a/dump", "a/x.dmpx", "core/readme.md"]) assert.equal(dumpKind(no), null, no);
});

test("the member table is read as a stream: the largest dumps, the count of all, empty ones left out", async () => {
  const rows = ["n\ttype\tpath\tpath_b64\tsize\tpacked\tmtime\ttz\tmode\tuid\tgid\tlink\tlocator\tflags"];
  for (let i = 0; i < 2000; i += 1) rows.push(`${i}\tfile\tdocs/file-${i}.txt\t\t${i}\t\t\t\t\t\t\t\tad1:item=${i}\t`);
  for (let i = 0; i < 30; i += 1) rows.push(`${3000 + i}\tfile\tdumps/p${i}.dmp\t\t${(i + 1) * 1000}\t\t\t\t\t\t\t\tad1:item=${3000 + i}\t`);
  rows.push("4000\tfile\tdumps/empty.dmp\t\t0\t\t\t\t\t\t\t\tad1:item=4000\t");
  rows.push("4001\tfile\thiberfil.sys\t\t5000000000\t\t\t\t\t\t\t\tad1:item=4001\t");
  const tsv = join(dir, "members.tsv");
  writeFileSync(tsv, `${rows.join("\n")}\n`);
  const found = await dumpMembers(tsv);
  assert.ok(found);
  assert.equal(found.total, 31);
  assert.equal(found.top.length, DUMPS_SHOWN);
  assert.deepEqual([found.top[0]!.path, found.top[0]!.kind, found.top[0]!.locator], ["hiberfil.sys", "hibernation file", "ad1:item=4001"]);
  assert.equal(found.top[1]!.path, "dumps/p29.dmp");
  assert.equal(found.whole, true);
  const post = dumpsPost("g0002", "inputs/image.ad1", found, ["minidump_map"]);
  assert.ok(post);
  assert.match(post, /lists 31 members named as a process or memory dump \(4\.7 GiB in all\)/);
  assert.match(post, /These are the 12 largest; catalog_search over g0002 finds the rest by name\./);
  assert.match(post, /- hiberfil\.sys \(4\.7 GiB, hibernation file; ad1:item=4001\)/);
  assert.match(post, /minidump_map reads one/);
  assert.match(post, /a dump under another name is not in this list/);
  assert.ok(post.length < 4000, `${post.length} characters`);
  assert.match(dumpsPost("g0002", "x", found, [])!, /No tool of this run's packs reads a dump by its structure/);
});

test("no dump, no table, or a table without the columns: nothing is said", async () => {
  const tsv = join(dir, "none.tsv");
  writeFileSync(tsv, "n\ttype\tpath\tsize\n0\tfile\ta.txt\t3\n");
  const found = await dumpMembers(tsv);
  assert.equal(found!.total, 0);
  assert.equal(dumpsPost("g1", "x", found!, []), null);
  assert.equal(await dumpMembers(join(dir, "absent.tsv")), null);
  writeFileSync(join(dir, "odd.tsv"), "a\tb\n1\t2\n");
  assert.equal(await dumpMembers(join(dir, "odd.tsv")), null);
});

test("a dump is known by its first bytes: minidump, kernel crash dump, hibernation, LiME, ELF core", () => {
  const b = (s: string | number[]) => (typeof s === "string" ? new Uint8Array(Buffer.from(s, "latin1")) : new Uint8Array(s));
  assert.equal(headerKind(b("MDMP\x93\xa7")), "process or crash dump");
  assert.equal(headerKind(b("PAGEDU64")), "kernel crash dump");
  assert.equal(headerKind(b("PAGEDUMP")), "kernel crash dump");
  for (const h of ["HIBR", "hibr", "WAKE", "RSTR"]) assert.equal(headerKind(b(h)), "hibernation file", h);
  assert.equal(headerKind(b("EMiL\x01\x00\x00\x00")), "memory image");
  const elf = (data: number, type: number[]) => [0x7f, 0x45, 0x4c, 0x46, 2, data, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, ...type];
  assert.equal(headerKind(b(elf(1, [4, 0]))), "process or crash dump");
  assert.equal(headerKind(b(elf(2, [0, 4]))), "process or crash dump");
  assert.equal(headerKind(b(elf(1, [2, 0]))), null, "an ELF executable is not a dump");
  for (const no of ["MDM", "PAGEDU", "MZ\x90\x00", "", "hib"]) assert.equal(headerKind(b(no)), null, JSON.stringify(no));
});

test("the kickoff looks at the top of each input directory: names and headers, never through a link, a FIFO or a folder", async () => {
  const a = join(dir, "set a");
  const c = join(dir, "set-c");
  mkdirSync(join(a, "deeper"), { recursive: true });
  mkdirSync(c, { recursive: true });
  writeFileSync(join(a, "crash.bin"), Buffer.concat([Buffer.from("MDMP"), Buffer.alloc(4096)]));
  writeFileSync(join(a, "app.dmp"), "MDMP and more");
  writeFileSync(join(a, "pagefile.sys"), Buffer.alloc(2048));
  writeFileSync(join(a, "empty.dmp"), "");
  writeFileSync(join(a, "notes.txt"), "text");
  writeFileSync(join(a, "deeper", "inner.dmp"), "MDMP");
  symlinkSync(join(a, "crash.bin"), join(a, "linked.dmp"));
  execFileSync("mkfifo", [join(a, "pipe.dmp")]);
  writeFileSync(join(c, "host.vmem"), Buffer.alloc(100));
  const found = await kickoffDumps([
    { dir: a, under: "inputs/set a" },
    { dir: c, under: "inputs/set-c" },
  ]);
  assert.equal(found.whole, true);
  assert.deepEqual(
    found.dumps.map((d) => [d.path, d.bytes, d.kind, d.by]),
    [
      ["inputs/set a/crash.bin", 4100, "process or crash dump", "header"],
      ["inputs/set a/pagefile.sys", 2048, "page or swap file", "name"],
      ["inputs/set-c/host.vmem", 100, "memory image", "name"],
      ["inputs/set a/app.dmp", 13, "process or crash dump", "name and header"],
    ],
  );
  assert.equal(found.total, 4);
  assert.equal(found.bytes, 4100 + 2048 + 100 + 13);
  assert.deepEqual(await kickoffDumps([{ dir: c, under: "inputs" }]).then((f) => f.dumps.map((d) => d.path)), ["inputs/host.vmem"]);
});

test("the kickoff note lists each dump with its size, says what was done about the memory pack and why, and which tools read one", () => {
  const dumps = Array.from({ length: KICKOFF_DUMPS_SHOWN + 3 }, (_, i) => ({ path: `inputs/p${i}.dmp`, bytes: (i + 1) * 1024 ** 2, kind: "process or crash dump", by: "name" as const }));
  const found = { total: dumps.length, bytes: dumps.reduce((n, d) => n + d.bytes, 0), dumps, whole: true };
  const added = kickoffDumpsNote(found, ["minidump_map", "mem_profile"], "added")!;
  assert.match(added, /^## Dumps among the inputs\n\n/);
  assert.match(added, /found 43 inputs at the top of `inputs\/` that are a process or memory dump/);
  assert.match(added, /- `inputs\/p0\.dmp` \(1\.0 MiB, process or crash dump, by its name\)/);
  assert.match(added, /- … and 3 more/);
  assert.match(added, /The kickoff added memory-forensics/);
  assert.match(added, /minidump_map, mem_profile read one/);
  assert.ok(added.endsWith("\n\n"));
  assert.match(kickoffDumpsNote(found, [], "excluded")!, /memory-forensics was not added: the operator excluded it \(--no-pack memory-forensics\)\. No tool of this run's packs reads a dump/);
  assert.match(kickoffDumpsNote(found, [], "no-packs")!, /started without packs/);
  assert.match(kickoffDumpsNote(found, [], "unavailable")!, /not installed on this host/);
  assert.match(kickoffDumpsNote({ ...found, whole: false }, [], "named")!, /and only its first 10000 entries/);
  assert.equal(kickoffDumpsNote({ total: 0, bytes: 0, dumps: [], whole: true }, [], "added"), null);
});

test("the dump readers are the tools a pack carries, once each", () => {
  const p1 = join(dir, "pack1");
  const p2 = join(dir, "pack2");
  for (const [p, t] of [[p1, "mem_profile"], [p2, "mem_profile"], [p2, "minidump_map"], [p2, "other"]] as const) {
    mkdirSync(join(p, "tools", t), { recursive: true });
    writeFileSync(join(p, "tools", t, "manifest.json"), "{}");
  }
  assert.deepEqual(dumpReaders([p1, p2]), ["mem_profile", "minidump_map"]);
  assert.deepEqual(dumpReaders([join(dir, "absent")]), []);
});

test("detect prints one JSON line for the kickoff", () => {
  const d = join(dir, "cli");
  mkdirSync(d);
  writeFileSync(join(d, "MEMORY.DMP"), "PAGEDU64");
  const out = execFileSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "..", "scripts", "dump-members.ts"), "detect", "--inputs", d, "--under", "inputs/x"], { encoding: "utf8" });
  const j = JSON.parse(out);
  assert.equal(j.total, 1);
  assert.deepEqual(j.dumps[0], { path: "inputs/x/MEMORY.DMP", bytes: 8, kind: "kernel crash dump", by: "name and header" });
  assert.deepEqual(j.reader_names, ["minidump_map", "mem_profile"]);
});
