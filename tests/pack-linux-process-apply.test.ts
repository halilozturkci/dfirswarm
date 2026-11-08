/**
 * PKG-P6 (the linux-forensics pack in the process sweep). The shared PROCESS block ends what a program leaves behind (settle()); the linux tools that run a program call
 * process_apply or put a line under problems, so that a program that exits 0 and leaves a writer behind, or a host where the absence of one cannot be proven, never
 * answers `complete` over what the program wrote. Stand-ins only, with real abandoned children (network-process-harness.ts and process-apply-cases.ts describe them):
 *   linux_triage       target-query (dissect.target) writes the family file and leaves a process that writes to it by name or holds it
 *   linux-target       the same, through the recipe: the wrapper's verdict reaches the recipe's coverage.json
 *   journal_export     journalctl prints on a pipe the tool copies, and its stderr is a file it wrote; the leftover holds the pipe (plain, stdout) or none (setsid, double)
 *   package_verify     debsums prints on a pipe; the answer counts what it printed (pipe only: not held to the non-Linux rule)
 *   audit_events       ausearch (the second reader) prints on a pipe (pipe only: not held to the non-Linux rule)
 * Every tool is also probed with leftovers that hold what it reads and never end (a sleeper on every descriptor, a slow writer, a holder of the standard input): it must answer in time, partial, and end them. The cases that fail on the batch head (before the tools called process_apply) are the ones
 * that expect `partial` and program_group: the answer was `complete`.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { alive, pids, reap, CUT_FLOODERS, FEW, HOLDERS, VARIANTS, exec, sh, stubDir } from "./network-process-harness.ts";
import { register, SAYS_UNPROVEN } from "./process-apply-cases.ts";
import type { Case } from "./process-apply-cases.ts";
import { NO_ADOPTION } from "./host-gates.ts";

const PACK = process.env.LINUX_PACK ?? join(ROOT, "packs", "linux-forensics");
const TRIAGE = join(PACK, "tools", "linux_triage", "run.py");
const JOURNAL = join(PACK, "tools", "journal_export", "run.py");
const VERIFY = join(PACK, "tools", "package_verify", "run.py");
const AUDIT = join(PACK, "tools", "audit_events", "run.py");
const RECIPE = join(PACK, "recipes", "linux-target", "run.py");

async function stub(bin: string, name: string, script: string): Promise<void> {
  await mkdir(bin, { recursive: true });
  await writeFile(join(bin, name), script, { mode: 0o755 });
  await chmod(join(bin, name), 0o755);
}
/** A tool may give its programs a clean environment: the stand-ins carry the leftover's settings themselves. */
const pre = (dir: string, left: string | undefined): string => `export STUB_DIR="${dir}" STUB_LEFT="${left ?? ""}" STUB_LSLEEP=3\n`;

// ---- linux_triage and the linux-target recipe -----------------------------------------------------------------------------------------------------------

/** target-query: one line on its standard output (the family file the tool keeps); the first call leaves a process that holds or writes that file. */
const triageStub = (dir: string, left: string | undefined): string => sh(`${pre(dir, left)}case "$*" in *" -j "*) echo '{"fn":"x"}';; *) echo value;; esac
[ -e "$STUB_DIR/left.pids" ] || leave "$(readlink /proc/$$/fd/1 2>/dev/null || lsof -a -p $$ -d 1 -Fn 2>/dev/null | sed -n 's/^n//p')"
exit 0
`);

const triage: Case = {
  name: "linux_triage",
  variants: VARIANTS,
  holdsFiles: true,
  holders: HOLDERS,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "target-query", triageStub(dir, left));
    await writeFile(join(cwd, "inputs", "server.E01"), "image bytes\n");
    const run = await exec(TRIAGE, [], { source: "inputs/server.E01", out_dir: "work/s1/triage", groups: ["identity"] }, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout), run };
  },
};
register(triage);

const recipe: Case = {
  name: "linux-target recipe",
  variants: VARIANTS,
  holdsFiles: true,
  holders: HOLDERS,
  skipOk: true,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "target-query", triageStub(dir, left));
    const image = join(cwd, "inputs", "server.E01");
    await writeFile(image, "image bytes\n");
    await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [image], name: "server" }));
    const run = await exec(RECIPE, ["run", "--target", join(cwd, "target.json"), "--out", join(cwd, "recipe-out")], undefined, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.ok(run.code === 0 || run.code === 2, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout.trim().split("\n").pop() ?? "{}"), run };
  },
};
// the recipe selects every family: a leftover of the first function only (the stand-in leaves once), the other functions are clean
register(recipe);

// ---- journal_export -----------------------------------------------------------------------------------------------------------------------------------

const ENTRY = JSON.stringify({
  __CURSOR: "s=739ad463348b4ceca5a9699c3d7d5e1f;i=3a01;b=9d6a4f4b7a7e4b2d9b2f0a1e3f4c5d6e;m=4c4b40;t=64a8f0c0e1240;x=1a2b3c4d5e6f1", __REALTIME_TIMESTAMP: "1771061400123456",
  __MONOTONIC_TIMESTAMP: "5000000", _BOOT_ID: "9d6a4f4b7a7e4b2d9b2f0a1e3f4c5d6e", _MACHINE_ID: "3f2e1d0c9b8a79685746352413020100", _HOSTNAME: "web01", _TRANSPORT: "journal", PRIORITY: "6", MESSAGE: "hello",
});
const journalStub = (dir: string, left: string | undefined): string => sh(`${pre(dir, left)}case "$*" in
  *--verify*) echo "PASS: system.journal";;
  *) echo '${ENTRY}';;
esac
leave "$(readlink /proc/$$/fd/2 2>/dev/null || lsof -a -p $$ -d 2 -Fn 2>/dev/null | sed -n 's/^n//p')"
exit 0
`);

function journal(mode: "export" | "verify"): Case {
  return {
    name: `journal_export ${mode}`,
    variants: mode === "export" ? VARIANTS : FEW,
    holdsFiles: true,
  holders: HOLDERS,
    invoke: async (cwd, bin, left, host) => {
      const dir = await stubDir(cwd);
      await stub(bin, "journalctl", journalStub(dir, left));
      await mkdir(join(cwd, "work", "journal"), { recursive: true });
      await writeFile(join(cwd, "work", "journal", "system.journal"), Buffer.concat([Buffer.from("LPKSHHRH"), Buffer.alloc(248)]));
      const out = join(cwd, "out");
      await mkdir(out, { recursive: true });
      const run = await exec(JOURNAL, [], { path: "work/journal", ...(mode === "verify" ? { mode: "verify" } : {}) }, cwd, bin,
        { STUB_DIR: dir, JOB_ID: "j-1", OUT: out, SECRET_OUTPUT: "1", ...(left ? { STUB_LEFT: left } : {}) }, host);
      assert.equal(run.code, 0, run.stderr + run.stdout);
      return { answer: JSON.parse(run.stdout), run };
    },
  };
}
register(journal("export"));
register(journal("verify"));

// ---- package_verify (debsums prints on a pipe) --------------------------------------------------------------------------------------------------------

const verify: Case = {
  name: "package_verify",
  variants: FEW.concat(["plain"]),
  holdsFiles: false,
  holders: HOLDERS,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    const root = join(cwd, "work", "r");
    await mkdir(join(root, "var/lib/dpkg/info"), { recursive: true });
    await writeFile(join(root, "var/lib/dpkg/status"), "Package: a\nStatus: install ok installed\n");
    await writeFile(join(root, "var/lib/dpkg/info/a.md5sums"), "d41d8cd98f00b204e9800998ecf8427e  usr/bin/a\n");
    await writeFile(join(cwd, "late.txt"), "");
    await stub(bin, "debsums", sh(`${pre(dir, left)}case "$1" in --version) echo "debsums version 9.9.9"; exit 0;; esac
printf '%s\\n' '/usr/bin/a                                        OK'
leave "${join(cwd, "late.txt")}"
exit 0
`));
    const run = await exec(VERIFY, [], { root: "work/r", family: "debian" }, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout), run };
  },
};
register(verify);

// ---- audit_events (ausearch prints on a pipe) ----------------------------------------------------------------------------------------------------------------

const AUDIT_LOG = [
  "type=SYSCALL msg=audit(1700000000.001:1): arch=c000003e syscall=2 success=yes exit=3",
  "type=EXECVE msg=audit(1700000000.001:1): argc=1 a0=\"x\"",
  "type=PROCTITLE msg=audit(1700000000.001:1): proctitle=78",
  "type=USER_LOGIN msg=audit(1700000001.001:2): pid=1 uid=0 auid=1000 ses=1 msg='op=login acct=\"a\" res=success'",
].join("\n") + "\n";

const audit: Case = {
  name: "audit_events",
  variants: FEW.concat(["plain"]),
  holdsFiles: false,
  holders: HOLDERS,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await writeFile(join(cwd, "work", "audit.log"), AUDIT_LOG);
    await writeFile(join(cwd, "late.txt"), "");
    // the probe file and the version are always answered; the sample call leaves the process
    await stub(bin, "ausearch", sh(`${pre(dir, left)}case "$1" in --version) echo "ausearch version 9.9.9"; exit 0;; esac
cat "$2"
case "$2" in *sample.log) leave "${join(cwd, "late.txt")}";; esac
exit 0
`));
    const out = join(cwd, "out");
    await mkdir(out, { recursive: true });
    const run = await exec(AUDIT, [], { paths: ["work/audit.log"], compare_ausearch: true }, cwd, bin,
      { STUB_DIR: dir, JOB_ID: "j-1", OUT: out, SECRET_OUTPUT: "1", ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout), run };
  },
};
register(audit);
void SAYS_UNPROVEN;

// ---- the recipe's detect step reads target-query on a pipe (preflight): a holder neither hangs it nor survives ---------------------------------------------------------------

for (const holder of HOLDERS) {
  test(`linux-target detect: a ${holder} that holds the pipes after target-query printed its answer does not hold the step, and is ended`, { timeout: 120000 }, async () => {
    await withCwd(async (cwd, bin) => {
      const dir = await stubDir(cwd);
      await stub(bin, "target-query", sh(`${pre(dir, holder)}echo linux\nleave "$STUB_DIR/late.txt"\nexit 0\n`));
      const image = join(cwd, "inputs", "server.E01");
      await writeFile(image, "image bytes\n");
      await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [image], name: "server" }));
      try {
        const began = Date.now();
        const run = await exec(RECIPE, ["detect", "--target", join(cwd, "target.json")], undefined, cwd, bin, { STUB_DIR: dir, STUB_LEFT: holder }, "linux");
        assert.ok(Date.now() - began < 25000, `took ${Date.now() - began} ms`);
        // a writer on the pipe adds its bytes to the name target-query printed: the name is then not one the recipe recognises, and it says "unknown" (exit 2), which closes no route
        const said = JSON.parse(run.stdout.trim().split("\n").pop() ?? "{}");
        assert.equal(run.code, ["slow", "fast", "yes"].includes(holder) ? 2 : 0, run.stderr + run.stdout);
        assert.equal(said.applies, ["slow", "fast", "yes"].includes(holder) ? "unknown" : true);
        if (!NO_ADOPTION) for (const pid of await pids(cwd)) assert.equal(alive(pid), false, `holder ${pid} is gone`);
      } finally {
        await reap(cwd);
      }
    });
  });
}

// ---- a stop that arrives after the wrapper ended, while a holder keeps its pipes (the read window): the holder is ended and the recipe prints its line --------------------------

test("linux-target: a stop signal in the wrapper-read window ends the holder the wrapper left and still prints one JSON line", { timeout: 120000 }, async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await stubDir(cwd);
    // a copy of the recipe beside a stand-in wrapper that leaves a holder of its pipes and exits at once
    const recipeCopy = join(cwd, "recipes", "linux-target");
    await mkdir(recipeCopy, { recursive: true });
    await mkdir(join(cwd, "tools", "linux_triage"), { recursive: true });
    await writeFile(join(recipeCopy, "run.py"), await readFile(RECIPE, "utf8"));
    await writeFile(join(cwd, "tools", "linux_triage", "run.py"),
      `import subprocess, sys\nsys.stdin.read()\nk = subprocess.Popen(["sleep", "600"])\nopen(${JSON.stringify(join(dir, "left.pids"))}, "a").write("%d\\n" % k.pid)\nprint("{}")\n`);
    const image = join(cwd, "inputs", "server.E01");
    await writeFile(image, "image bytes\n");
    await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [image], name: "server" }));
    const child = spawn("python3", [join(recipeCopy, "run.py"), "run", "--target", join(cwd, "target.json"), "--out", join(cwd, "recipe-out")], { cwd, detached: true, env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    const closed = new Promise<number | null>((r) => child.on("close", (code) => r(code)));
    try {
      for (let i = 0; i < 100 && (await pids(cwd)).length === 0; i++) await new Promise((r) => setTimeout(r, 50));
      assert.ok((await pids(cwd)).length >= 1, "the wrapper left a holder");
      await new Promise((r) => setTimeout(r, 300));            // the wrapper has exited; the recipe is in the pipe grace
      child.kill("SIGTERM");
      assert.equal(await closed, 143);
      const line = JSON.parse(Buffer.concat(out).toString("utf8").trim().split("\n").pop() ?? "{}");
      // The stand-in wrapper wrote no summary: coverage.json says failed, and so does the line (it said "partial ... coverage.json says partial").
      const coverage = JSON.parse(await readFile(join(cwd, "recipe-out", "coverage.json"), "utf8"));
      assert.equal(coverage.status, "failed");
      assert.equal(line.status, coverage.status);
      assert.match(line.status_basis, /coverage\.json says failed/);
      if (!NO_ADOPTION) for (const pid of await pids(cwd)) assert.equal(alive(pid), false, `holder ${pid} is gone`);
    } finally {
      await reap(cwd);
      try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* gone */ }
    }
  });
});

// ---- the version probes (package_verify, audit_events) read the program on a pipe: a holder or a flood left by --version neither hangs the probe nor survives -----------------

for (const holder of HOLDERS) {
  for (const which of ["package_verify", "audit_events"] as const) {
    test(`${which} version probe: a ${holder} left by --version is ended, the tool answers in time and says partial`, { skip: NO_ADOPTION, timeout: 120000 }, async () => {
      await withCwd(async (cwd, bin) => {
        const dir = await stubDir(cwd);
        const out = join(cwd, "out");
        await mkdir(out, { recursive: true });
        await writeFile(join(cwd, "late.txt"), "");
        try {
          let run;
          const began = Date.now();
          if (which === "audit_events") {
            await writeFile(join(cwd, "work", "audit.log"), AUDIT_LOG);
            await stub(bin, "ausearch", sh(`${pre(dir, holder)}case "$1" in --version) leave "${join(cwd, "late.txt")}"; echo "ausearch version 9.9.9"; exit 0;; esac\ncat "$2"\nexit 0\n`));
            run = await exec(AUDIT, [], { paths: ["work/audit.log"], compare_ausearch: true }, cwd, bin, { STUB_DIR: dir, JOB_ID: "j-1", OUT: out, SECRET_OUTPUT: "1", STUB_LEFT: holder }, "linux");
          } else {
            const root = join(cwd, "work", "r");
            await mkdir(join(root, "var/lib/dpkg/info"), { recursive: true });
            await writeFile(join(root, "var/lib/dpkg/status"), "Package: a\nStatus: install ok installed\n");
            await writeFile(join(root, "var/lib/dpkg/info/a.md5sums"), "d41d8cd98f00b204e9800998ecf8427e  usr/bin/a\n");
            await stub(bin, "debsums", sh(`${pre(dir, holder)}case "$1" in --version) leave "${join(cwd, "late.txt")}"; echo "debsums version 9.9.9"; exit 0;; esac\nprintf '%s\\n' '/usr/bin/a                                        OK'\nexit 0\n`));
            run = await exec(VERIFY, [], { root: "work/r", family: "debian" }, cwd, bin, { STUB_DIR: dir, JOB_ID: "j-1", OUT: out, SECRET_OUTPUT: "1", STUB_LEFT: holder }, "linux");
          }
          assert.ok(Date.now() - began < 12000, `took ${Date.now() - began} ms`);
          assert.equal(run.code, 0, run.stderr + run.stdout);
          const answer = JSON.parse(run.stdout);
          assert.equal(answer.status, "partial", JSON.stringify(answer.status_basis));
          assert.ok(answer.program_group.left_behind >= 1, JSON.stringify(answer.program_group));
          for (const pid of await pids(cwd)) assert.equal(alive(pid), false, `holder ${pid} is gone`);
        } finally {
          await reap(cwd);
        }
      });
    });
  }
}

// ---- a pipe cut at the byte cap of the shared block (PKG-P8c) -----------------------------------------------------------------------------------------
// communicate_bounded reads at most 1 MiB more from the pipes of a program that has ended, then ends the holder and lets the pipes go (PIPE_CUT). A tool that reads a pipe through the block and
// does not call process_apply must not answer `complete` over bytes a flooder may have mixed into it. The flooder here is a writer in a session of its own, started after the program printed
// its answer. On Linux the tool also adopts and ends it (left_behind >= 1); where it cannot (darwin, prctl refused) nothing finds the flooder (left_behind 0) and only the cut is left to say so:
// that is the case that was `complete` on the batch head. The sentence is looked for in the status_basis / problems / errors, not in program_group.notes (where the head said it too).

const CUT_SAYS = /a process that held (a program's|target-query's|the wrapper's) pipe after (the program|it) ended went on writing: the (tool|recipe) read no more than 1048576 bytes of it/;
const cutText = (a: Record<string, unknown>): string => JSON.stringify([a.status_basis, a.problems, a.errors]);

async function stagePipeTool(cwd: string, bin: string, which: "package_verify" | "audit_events", holder: string | undefined): Promise<{ script: string; args: Record<string, unknown>; env: Record<string, string> }> {
  const dir = await stubDir(cwd);
  const out = join(cwd, "out");
  await mkdir(out, { recursive: true });
  const env = { STUB_DIR: dir, JOB_ID: "j-1", OUT: out, SECRET_OUTPUT: "1", ...(holder ? { STUB_LEFT: holder } : {}) };
  // the program prints its version, and only then leaves the flooder
  if (which === "audit_events") {
    await writeFile(join(cwd, "work", "audit.log"), AUDIT_LOG);
    await stub(bin, "ausearch", sh(`${pre(dir, holder)}case "$1" in --version) echo "ausearch version 9.9.9"; leave x; exit 0;; esac\ncat "$2"\nexit 0\n`));
    return { script: AUDIT, args: { paths: ["work/audit.log"], compare_ausearch: true }, env };
  }
  const root = join(cwd, "work", "r");
  await mkdir(join(root, "var/lib/dpkg/info"), { recursive: true });
  await writeFile(join(root, "var/lib/dpkg/status"), "Package: a\nStatus: install ok installed\n");
  await writeFile(join(root, "var/lib/dpkg/info/a.md5sums"), "d41d8cd98f00b204e9800998ecf8427e  usr/bin/a\n");
  await stub(bin, "debsums", sh(`${pre(dir, holder)}case "$1" in --version) echo "debsums version 9.9.9"; leave x; exit 0;; esac\nprintf '%s\\n' '/usr/bin/a                                        OK'\nexit 0\n`));
  return { script: VERIFY, args: { root: "work/r", family: "debian" }, env };
}

for (const which of ["package_verify", "audit_events"] as const) {
  for (const holder of CUT_FLOODERS) {
    for (const host of ["linux", "refused", "darwin"] as const) {
      test(`${which}: a pipe cut at the byte cap (${holder}, ${host}) is partial and says a process went on writing`, { timeout: 120000 }, async () => {
        await withCwd(async (cwd, bin) => {
          try {
            const staged = await stagePipeTool(cwd, bin, which, holder);
            const run = await exec(staged.script, [], staged.args, cwd, bin, staged.env, host);
            assert.equal(run.code, 0, run.stderr + run.stdout);
            const answer = JSON.parse(run.stdout);
            assert.equal(answer.status, "partial", JSON.stringify(answer.status_basis));
            if ("ok" in answer) assert.equal(answer.ok, false);
            assert.match(cutText(answer), CUT_SAYS);
            assert.match(cutText(answer), /may contain bytes the program did not write/);
            assert.match(JSON.stringify(answer.program_group.notes), /went on writing/);
            // (the host "linux" is this machine: a machine that cannot adopt orphans, macOS, finds nothing here, and the cut alone makes it partial, as on the other hosts)
            // (on a real macOS the tool also looks at the processes it saw below the program, and may find and end the flooder: then it counts it; the cut makes the answer partial either way)
            if (NO_ADOPTION) assert.ok(answer.program_group.left_behind >= 0, "the flooder is counted if it was found");
            else if (host !== "linux") assert.equal(answer.program_group.left_behind, 0, "nothing was found: the cut alone makes it partial");
            else assert.ok(answer.program_group.left_behind >= 1);
            if (host === "linux" && !NO_ADOPTION) for (const pid of await pids(cwd)) assert.equal(alive(pid), false, `flooder ${pid} is gone`);
          } finally {
            await reap(cwd);
          }
        });
      });
    }
  }
  test(`${which}: a clean run stays complete on every host (no cut, nothing found)`, { timeout: 120000 }, async () => {
    for (const host of ["linux", "refused", "darwin"] as const) {
      await withCwd(async (cwd, bin) => {
        const staged = await stagePipeTool(cwd, bin, which, undefined);
        const answer = JSON.parse((await exec(staged.script, [], staged.args, cwd, bin, staged.env, host)).stdout);
        assert.equal(answer.status, "complete", `${host}: ${answer.status_basis}`);
      });
    }
  });
}

// the recipe's detect step: target-query printed its answer on stdout, and a flood on stderr was cut. The name is one word, so `applies` stands; the answer is partial, not complete.
for (const host of ["linux", "refused", "darwin"] as const) {
  test(`linux-target detect: a pipe cut at the byte cap (setsiderr, ${host}) keeps applies and says partial, with the sentence`, { timeout: 120000 }, async () => {
    await withCwd(async (cwd, bin) => {
      const dir = await stubDir(cwd);
      await stub(bin, "target-query", sh(`${pre(dir, "setsiderr")}echo linux\nleave x\nexit 0\n`));
      const image = join(cwd, "inputs", "server.E01");
      await writeFile(image, "image bytes\n");
      await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [image], name: "server" }));
      try {
        const run = await exec(RECIPE, ["detect", "--target", join(cwd, "target.json")], undefined, cwd, bin, { STUB_DIR: dir, STUB_LEFT: "setsiderr" }, host);
        const said = JSON.parse(run.stdout.trim().split("\n").pop() ?? "{}");
        assert.equal(run.code, 0, run.stderr + run.stdout);
        assert.equal(said.applies, true);
        assert.equal(said.status, "partial", said.status_basis);
        assert.match(said.status_basis, /target-query's pipe after it ended went on writing: the recipe read no more than 1048576 bytes/);
      } finally {
        await reap(cwd);
      }
    });
  });
}
test("linux-target detect: without a cut the answer is complete on every host", { timeout: 120000 }, async () => {
  for (const host of ["linux", "refused", "darwin"] as const) {
    await withCwd(async (cwd, bin) => {
      const dir = await stubDir(cwd);
      await stub(bin, "target-query", sh(`${pre(dir, undefined)}echo linux\nexit 0\n`));
      const image = join(cwd, "inputs", "server.E01");
      await writeFile(image, "image bytes\n");
      await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [image], name: "server" }));
      const said = JSON.parse((await exec(RECIPE, ["detect", "--target", join(cwd, "target.json")], undefined, cwd, bin, { STUB_DIR: dir }, host)).stdout.trim().split("\n").pop() ?? "{}");
      assert.deepEqual([said.applies, said.status], [true, "complete"], host);
    });
  }
});

// the recipe's run step: a wrapper (a stand-in linux_triage) that wrote a clean, finished summary of its own, printed on its pipe and left a flooder holding the pipe. Its own verdict is clean,
// so the cut is the only thing the receipt and the printed line have to go on.
for (const host of ["linux", "refused", "darwin"] as const) {
  test(`linux-target run: a wrapper pipe cut at the byte cap (${host}) is in the recipe's own verdict: partial, with the sentence, in the receipt and in the printed line`, { skip: NO_ADOPTION, timeout: 120000 }, async () => {
    await withCwd(async (cwd, bin) => {
      const dir = await stubDir(cwd);
      const recipeCopy = join(cwd, "recipes", "linux-target");
      await mkdir(recipeCopy, { recursive: true });
      await mkdir(join(cwd, "tools", "linux_triage"), { recursive: true });
      await writeFile(join(recipeCopy, "run.py"), await readFile(RECIPE, "utf8"));
      const summary = { state: "finished", execution_complete: true, started: 0, groups: [{ group: "identity", functions: [{ name: "hostname", status: "parsed", exit_code: 0 }] }],
        program_group: { subreaper: true, left_behind: 0, unproven: [], notes: [] } };
      await writeFile(join(cwd, "tools", "linux_triage", "run.py"),
        `import json, os, subprocess, sys, time\nsys.stdin.read()\nos.makedirs("artefacts", exist_ok=True)\ns = json.loads(${JSON.stringify(JSON.stringify(summary))})\ns["started"] = time.time()\n` +
        `json.dump(s, open("artefacts/summary.json", "w"))\nprint(json.dumps(s))\nsys.stdout.flush()\n` +
        `subprocess.Popen(["setsid", "sh", "-c", 'echo $$ >> ${join(dir, "left.pids")}; exec yes y'], stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n` +
        `while len(open(${JSON.stringify(join(dir, "left.pids"))}).read().split()) < 1: time.sleep(0.02)\n`);
      const image = join(cwd, "inputs", "server.E01");
      await writeFile(image, "image bytes\n");
      await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [image], name: "server" }));
      await writeFile(join(dir, "left.pids"), "");
      try {
        const run = await exec(join(recipeCopy, "run.py"), ["run", "--target", join(cwd, "target.json"), "--out", join(cwd, "recipe-out")], undefined, cwd, bin, {}, host);
        const line = JSON.parse(run.stdout.trim().split("\n").pop() ?? "{}");
        const coverage = JSON.parse(await readFile(join(cwd, "recipe-out", "coverage.json"), "utf8"));
        for (const said of [coverage, line]) {
          assert.equal(said.status, "partial", JSON.stringify(said.status_basis));
          assert.match(JSON.stringify([said.status_basis, said.errors]), /a process that held the wrapper's pipe after it ended went on writing: the recipe read no more than 1048576 bytes of it/);
        }
        assert.match(JSON.stringify(coverage.errors), /summary\.json and runner\.stderr in the output directory may contain bytes the wrapper did not write/);
      } finally {
        await reap(cwd);
      }
    });
  });
}
test("linux-target run: the same wrapper without a flooder is complete", { skip: NO_ADOPTION, timeout: 120000 }, async () => {
  await withCwd(async (cwd, bin) => {
    const recipeCopy = join(cwd, "recipes", "linux-target");
    await mkdir(recipeCopy, { recursive: true });
    await mkdir(join(cwd, "tools", "linux_triage"), { recursive: true });
    await writeFile(join(recipeCopy, "run.py"), await readFile(RECIPE, "utf8"));
    const summary = { state: "finished", execution_complete: true, started: 0, groups: [{ group: "identity", functions: [{ name: "hostname", status: "parsed", exit_code: 0 }] }],
      program_group: { subreaper: true, left_behind: 0, unproven: [], notes: [] } };
    await writeFile(join(cwd, "tools", "linux_triage", "run.py"),
      `import json, os, sys, time\nsys.stdin.read()\nos.makedirs("artefacts", exist_ok=True)\ns = json.loads(${JSON.stringify(JSON.stringify(summary))})\ns["started"] = time.time()\njson.dump(s, open("artefacts/summary.json", "w"))\nprint(json.dumps(s))\n`);
    const image = join(cwd, "inputs", "server.E01");
    await writeFile(image, "image bytes\n");
    await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [image], name: "server" }));
    const run = await exec(join(recipeCopy, "run.py"), ["run", "--target", join(cwd, "target.json"), "--out", join(cwd, "recipe-out")], undefined, cwd, bin, {}, "linux");
    const line = JSON.parse(run.stdout.trim().split("\n").pop() ?? "{}");
    assert.equal(line.status, "complete", JSON.stringify(line.status_basis));
  });
});
