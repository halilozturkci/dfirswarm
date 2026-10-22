/**
 * mem_profile, after the review of the memory-forensics pack: the two strings it reads from the capture as text are printed only when they
 * have the grammar of a version, signals end it with one JSON answer, every answer has a status, and LiME ranges that overlap are named.
 * Every case here fails on the tool as it was on main.
 */
import assert from "node:assert/strict";
import { truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { PROFILE, SHAPES, json, rng, runTool } from "./memory-f1-support.ts";

type Profile = {
  status: string; status_basis: string; error?: string; signal?: number; kernel_build: string | null; kernel_build_offset: number | null; kernel_build_withheld?: string;
  container: { version_user?: string | null; version_user_withheld?: string; problems?: string[]; format: string }; scan_stopped_at?: number; boundary?: Record<string, unknown>;
};

const linux = (release: string): Buffer => Buffer.concat([Buffer.alloc(4096), Buffer.from(`Linux version ${release} (builder@host) (gcc) #1 SMP\n`), Buffer.alloc(4096)]);
const crash64 = (version: string): Buffer => {
  const h = Buffer.alloc(0x2000);
  h.write("PAGEDU64", 0, "latin1");
  h.write(version.slice(0, 32), 0x60, "latin1");
  return Buffer.concat([h, Buffer.alloc(4096)]);
};

test("mem_profile prints the kernel release and the Windows build string when they have the grammar of a version, and nothing else (P2-7)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "k.raw"), linux("5.15.0-91-generic"));
    const k = json<Profile>(await runTool(PROFILE, cwd, { path: "work/k.raw" }));
    assert.equal(k.kernel_build, "5.15.0-91-generic");
    assert.ok(!JSON.stringify(k).includes("builder@host"), "the banner around the release is not printed");
    assert.equal(typeof k.kernel_build_offset, "number");
    await writeFile(join(cwd, "work", "w.dmp"), crash64("19041.1.amd64fre.vb_release.191206-1406"));
    const w = json<Profile>(await runTool(PROFILE, cwd, { path: "work/w.dmp" }));
    assert.equal(w.container.version_user, "19041.1.amd64fre.vb_release.1912", "the 32-byte field, cut where the field ends");
  });
});

test("mem_profile prints no secret placed where a version should be: 13 shapes, 12 plants each, in both slots (P2-7)", async () => {
  await withCwd(async (cwd) => {
    const r = rng(21);
    const leaked: Record<string, number> = {};
    let planted = 0;
    for (const [shape, make] of Object.entries(SHAPES)) {
      for (let i = 0; i < 12; i++) {
        const secret = make(r);
        planted++;
        await writeFile(join(cwd, "work", "k.raw"), linux(secret));
        const k = await runTool(PROFILE, cwd, { path: "work/k.raw" });
        // the 32-byte field cuts a long secret: a secret that is cut is judged by its first 32 characters
        await writeFile(join(cwd, "work", "w.dmp"), crash64(secret));
        const w = await runTool(PROFILE, cwd, { path: "work/w.dmp" });
        const piece = secret.slice(0, 32);
        for (const out of [k, w]) {
          const stdout = out.stdout;
          if (stdout.includes(secret) || stdout.includes(piece)) leaked[shape] = (leaked[shape] ?? 0) + 1;
          assert.doesNotMatch(out.stderr, /Traceback/);
        }
      }
    }
    assert.equal(planted, Object.keys(SHAPES).length * 12);
    assert.deepEqual(leaked, {}, "whole secrets (or their 32-character cut) printed, by shape");
    // the answer says a release or a build string was withheld, and how long it was
    await writeFile(join(cwd, "work", "k.raw"), linux(SHAPES.ghp(rng(4))));
    const withheld = json<Profile>(await runTool(PROFILE, cwd, { path: "work/k.raw" }));
    assert.equal(withheld.kernel_build, null);
    assert.match(withheld.kernel_build_withheld as string, /^<withheld \d+ characters: not a release string>$/);
    assert.equal(typeof withheld.kernel_build_offset, "number");
  });
});

test("mem_profile carries status and status_basis, and fails with them on an empty file (P2-11)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "k.raw"), linux("6.1.0-rc3+"));
    const ok = json<Profile>(await runTool(PROFILE, cwd, { path: "work/k.raw" }));
    assert.equal(ok.status, "complete");
    assert.match(ok.status_basis, /not a validation of the capture/);
    await writeFile(join(cwd, "work", "empty.raw"), "");
    const bad = json<Profile>(await runTool(PROFILE, cwd, { path: "work/empty.raw" }));
    assert.equal(bad.status, "failed");
    assert.ok(bad.status_basis.length > 20);
  });
});

test("mem_profile ends with one JSON answer on SIGTERM and SIGINT, exit 128 plus the signal, no traceback (P2-5)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "big.raw"), "");
    await truncate(join(cwd, "work", "big.raw"), 6 * 1024 ** 3); // sparse: reading it takes seconds
    const term = await runTool(PROFILE, cwd, { path: "work/big.raw", scan_mb: 4096 }, {}, undefined, "SIGTERM", 700);
    assert.equal(term.code, 143, term.stderr + term.stdout.slice(0, 200));
    assert.doesNotMatch(term.stderr, /Traceback/);
    const out = json<Profile>(term);
    assert.equal(out.status, "interrupted");
    assert.equal(out.signal, 15);
    const intr = await runTool(PROFILE, cwd, { path: "work/big.raw", scan_mb: 4096 }, {}, undefined, "SIGINT", 700);
    assert.equal(intr.code, 130);
    assert.doesNotMatch(intr.stderr, /Traceback|KeyboardInterrupt/);
  });
});

test("mem_profile names LiME ranges that are out of order or overlap (P3-14)", async () => {
  await withCwd(async (cwd) => {
    const range = (start: bigint, end: bigint): Buffer => {
      const h = Buffer.alloc(32);
      h.write("EMiL", 0, "latin1");
      h.writeUInt32LE(1, 4);
      h.writeBigUInt64LE(start, 8);
      h.writeBigUInt64LE(end, 16);
      return Buffer.concat([h, Buffer.alloc(Number(end - start + 1n))]);
    };
    await writeFile(join(cwd, "work", "l.lime"), Buffer.concat([range(0x1000n, 0x1fffn), range(0x1800n, 0x27ffn), range(0x0n, 0xfffn)]));
    const out = json<Profile>(await runTool(PROFILE, cwd, { path: "work/l.lime" }));
    const problems = out.container.problems ?? [];
    assert.ok(problems.some((p) => /overlapping/.test(p)), problems.join("\n"));
    assert.ok(problems.some((p) => /out of order/.test(p)), problems.join("\n"));
  });
});
