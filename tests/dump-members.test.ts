/**
 * The dump-named members of a catalogue and their post (scripts/dump-members.ts).
 */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { dumpKind, dumpMembers, dumpsPost, DUMPS_SHOWN } from "../scripts/dump-members.ts";

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
