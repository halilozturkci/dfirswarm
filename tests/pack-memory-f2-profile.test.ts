/**
 * mem_profile, after the second review of the memory-forensics pack: the release and build grammars are closed lists (a secret glued to a
 * version is not printed, and real releases still are), and a LiME walk that stopped before the end of the file is partial, with a clock of its
 * own. Every case here fails on the tool as it was at the head of the first fix round.
 */
import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { PROFILE, json, rng, runTool, shimDir } from "./memory-f1-support.ts";

type Profile = {
  status: string; status_basis: string; kernel_build: string | null; kernel_build_withheld?: string;
  container: { version_user?: string | null; version_user_withheld?: string; problems?: string[]; format: string; walk_complete?: boolean; range_count?: number };
};
const linux = (release: string): Buffer => Buffer.concat([Buffer.alloc(4096), Buffer.from(`Linux version ${release} (builder@host) (gcc) #1 SMP\n`), Buffer.alloc(4096)]);
const crash64 = (version: string): Buffer => {
  const h = Buffer.alloc(0x2000);
  h.write("PAGEDU64", 0, "latin1");
  h.write(version.slice(0, 32), 0x60, "latin1");
  return Buffer.concat([h, Buffer.alloc(4096)]);
};
const pick = (r: () => number, alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[Math.floor(r() * alphabet.length)]).join("");
const lime = (ranges: number, badMagicAt = -1): Buffer => {
  const parts: Buffer[] = [];
  for (let i = 0; i < ranges; i++) {
    const h = Buffer.alloc(32);
    h.write(i === badMagicAt ? "XXXX" : "EMiL", 0, "latin1");
    h.writeUInt32LE(1, 4);
    h.writeBigUInt64LE(BigInt(i), 8);
    h.writeBigUInt64LE(BigInt(i), 16);
    parts.push(h, Buffer.from([i & 0xff]));
  }
  return Buffer.concat(parts);
};

test("mem_profile prints real kernel releases and Windows build strings (P3-4)", async () => {
  await withCwd(async (cwd) => {
    const releases = ["5.15.0-91-generic", "5.15.0-1052-azure", "6.1.0-13-amd64", "4.19.0-25-cloud-amd64", "3.10.0-1160.119.1.el7.x86_64",
      "4.18.0-477.27.1.el8_8.x86_64", "6.5.6-300.fc39.x86_64", "5.10.0-rc1", "6.1.21-v8+", "4.4.0-210-lowlatency", "4.14.336-android12"];
    for (const release of releases) {
      await writeFile(join(cwd, "work", "k.raw"), linux(release));
      assert.equal(json<Profile>(await runTool(PROFILE, cwd, { path: "work/k.raw" })).kernel_build, release);
    }
    const builds = ["9600.17415.amd64fre.winblue_r4.141028-1500".slice(0, 32), "7601.17514.x86fre.win7sp1_rtm.101119-1850".slice(0, 32), "26100.1.amd64fre.ge_release.240331-1435".slice(0, 32),
      "17763.1.amd64fre.rs5_release.180914-1434".slice(0, 32), "22621.1.amd64fre.ni_release.220506-1250".slice(0, 32)];
    for (const build of builds) {
      await writeFile(join(cwd, "work", "w.dmp"), crash64(build));
      assert.equal(json<Profile>(await runTool(PROFILE, cwd, { path: "work/w.dmp" })).container.version_user, build, build);
    }
  });
});

test("mem_profile prints no secret glued to a version: a password after a release prefix, hex, letters or digits after a build (P3-4)", async () => {
  await withCwd(async (cwd) => {
    // 12 letters and 3 digits, a hyphenated passphrase, runs of digits, hex
    const r = rng(404);
    const glued: string[] = [];
    for (let i = 0; i < 10; i++) {
      glued.push("5.15.0-" + pick(r, "abcdefghijklmnopqrstuvwxyz", 12) + pick(r, "0123456789", 3));
      glued.push("5.15.0-" + pick(r, "abcdefghijklmnopqrstuvwxyz", 7) + "-" + pick(r, "abcdefghijklmnopqrstuvwxyz", 6) + "-" + pick(r, "abcdefghijklmnopqrstuvwxyz", 7));
      glued.push("6.1.0-" + pick(r, "0123456789", 5) + "-" + pick(r, "0123456789", 5) + "-" + pick(r, "0123456789", 5) + "-" + pick(r, "0123456789", 5));
    }
    for (const release of glued) {
      await writeFile(join(cwd, "work", "k.raw"), linux(release));
      const run = await runTool(PROFILE, cwd, { path: "work/k.raw" });
      const out = json<Profile>(run);
      assert.equal(out.kernel_build, null, release.length + " characters");
      const tail = release.slice(7);
      for (let i = 0; i + 12 <= tail.length; i++) assert.ok(!run.stdout.includes(tail.slice(i, i + 12)), "a 12-character piece of the glued text is in the answer");
    }
    const builds2: string[] = [];
    for (let i = 0; i < 10; i++) {
      builds2.push("19041.1.amd64fre." + pick(r, "0123456789abcdef", 15));
      builds2.push("19041.1.amd64fre." + pick(r, "abcdefghijklmnopqrstuvwxyz", 15));
      builds2.push("19041.1.amd64fre." + pick(r, "0123456789", 15));
    }
    for (const build of builds2) {
      await writeFile(join(cwd, "work", "w.dmp"), crash64(build));
      const run = await runTool(PROFILE, cwd, { path: "work/w.dmp" });
      assert.equal(json<Profile>(run).container.version_user, null, build.length + " characters");
      assert.ok(!run.stdout.includes(build.slice(17, 29)), "12 characters of the glued text are in the answer");
    }
  });
});

test("a LiME walk that stopped before the end of the file is partial, not complete (P3-5)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "ok.lime"), lime(5));
    const ok = json<Profile>(await runTool(PROFILE, cwd, { path: "work/ok.lime" }));
    assert.equal(ok.container.walk_complete, true);
    assert.equal(ok.status, "complete");
    await writeFile(join(cwd, "work", "bad.lime"), lime(8, 3));
    const bad = json<Profile>(await runTool(PROFILE, cwd, { path: "work/bad.lime" }));
    assert.equal(bad.container.walk_complete, false);
    assert.equal(bad.container.range_count, 3);
    assert.match((bad.container.problems ?? []).join(" "), /no LiME magic at offset/);
    assert.equal(bad.status, "partial");
    assert.match(bad.status_basis, /walk of the LiME headers stopped before the end of the file/);
  });
});

test("the walk of a LiME file's headers has a clock of its own and says it stopped there (P3-5)", async () => {
  await withCwd(async (cwd) => {
    const shim = await shimDir(cwd);
    await writeFile(join(cwd, "work", "many.lime"), lime(1500));
    // the clock moves 30 s at every look: the walk's 60 s are over at its second look, which is after 1,024 ranges
    const out = json<Profile>(await runTool(PROFILE, cwd, { path: "work/many.lime" }, { PYTHONPATH: shim, FAKE_CLOCK_STEP: "30" }));
    assert.equal(out.container.range_count, 1024);
    assert.equal(out.container.walk_complete, false);
    assert.match((out.container.problems ?? []).join(" "), /time limit \(60 s\) after 1024 ranges/);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /stopped before the end of the file/);
  });
});
