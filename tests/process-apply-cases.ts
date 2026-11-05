/**
 * The cases the process-sweep suites of the mobile, linux and memory packs share (PKG-P6): a tool is run against a stand-in program that exits and leaves an abandoned
 * child behind (see network-process-harness.ts for the leftover itself), and the answer is checked for what the sweep promises. The same four checks for every tool:
 *   left      a leftover (plain, stdout, setsid, double fork, rewrite, periodic) is ended, the answer is `partial`, carries program_group (left_behind >= 1, subreaper) and says
 *             so; every leftover is gone and nothing under the working directory changes between the answer and 1.6 seconds later
 *   clean     a clean run is `complete` with left_behind 0 and nothing unproven
 *   unproven  where the absence of a leftover cannot be proven (the host is not Linux: sys.platform patched; the kernel refuses PR_SET_CHILD_SUBREAPER: ctypes.CDLL replaced
 *             by a library whose prctl fails) a tool that reports files a program wrote is `partial` and says why; a tool that reports only what a program printed on a pipe
 *             is not held to that (it keeps its status, program_group says why)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { alive, pids, reap, sleep, snapshot } from "./network-process-harness.ts";
import type { Host, Run } from "./network-process-harness.ts";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Json = any;

export type Case = {
  name: string;
  /** Stage the stand-ins and run the tool; the printed answer (the first JSON document on stdout, or the one the case reads back) and the run. */
  invoke: (cwd: string, bin: string, left: string | undefined, host: Host) => Promise<{ answer: Json; run: Run }>;
  variants: string[];
  /** False for a tool that reports only what a program printed on a pipe. */
  holdsFiles: boolean;
  /** A tool whose own `ok` / `complete` flag is not the status (the recipes print ok for the exit code). */
  skipOk?: boolean;
  /** The leftovers that hold a pipe the tool reads and never end by themselves (HOLDERS in network-process-harness.ts): each must be answered, truthfully, within maxSeconds. */
  holders?: string[];
  /** The most a run with a holder may take (default 15 seconds: the pipe grace, one settle, the work around them). */
  maxSeconds?: number;
  /** Where the verdict is read from: the answer itself (default) or a nested object. */
  group?: (answer: Json) => Json;
  /** What a partial answer says, searched in the whole answer. */
  says?: RegExp;
};
export const SAYS_LEFT = /left \d+ process\(es\) running after it ended/;
export const SAYS_UNPROVEN = /cannot be shown to be final/;
const group = (c: Case, a: Json): Json => (c.group ? c.group(a) : a.program_group);
const text = (a: Json): string => JSON.stringify(a);

export async function expectLeft(c: Case, variant: string): Promise<void> {
  await withCwd(async (cwd, bin) => {
    try {
      const began = Date.now();
      const { answer } = await c.invoke(cwd, bin, variant, "linux");
      const took = (Date.now() - began) / 1000;
      assert.ok(took < (c.maxSeconds ?? 15), `${c.name} ${variant}: answered after ${took} seconds`);
      assert.equal(answer.status, "partial", `${c.name} ${variant}: ${answer.status_basis}`);
      if (!c.skipOk && "ok" in answer) assert.equal(answer.ok, false, `${c.name} ${variant}`);
      const g = group(c, answer);
      assert.ok(g, `${c.name} ${variant}: the answer carries program_group`);
      assert.ok(g.left_behind >= 1, `${c.name} ${variant}: ${JSON.stringify(g)}`);
      assert.equal(g.subreaper, true);
      assert.match(text(answer), c.says ?? SAYS_LEFT, `${c.name} ${variant}: the leftover is named`);
      const left = await pids(cwd);
      assert.ok(left.length >= 1, `${c.name} ${variant}: the stand-in left a process`);
      for (const pid of left) assert.equal(alive(pid), false, `${c.name} ${variant}: leftover ${pid} is gone`);
      const now = await snapshot(cwd);
      await sleep(1600);
      assert.deepEqual(await snapshot(cwd), now, `${c.name} ${variant}: nothing changed after the answer`);
      for (const pid of left) assert.equal(alive(pid), false);
    } finally {
      await reap(cwd);
    }
  });
}

export async function expectClean(c: Case): Promise<void> {
  await withCwd(async (cwd, bin) => {
    const { answer } = await c.invoke(cwd, bin, undefined, "linux");
    assert.equal(answer.status, "complete", `${c.name}: ${answer.status_basis}`);
    const g = group(c, answer);
    assert.ok(g, "program_group is in a clean answer too");
    assert.equal(g.left_behind, 0);
    assert.deepEqual(g.unproven, []);
    assert.equal(g.subreaper, true);
  });
}

export async function expectUnproven(c: Case, host: Host): Promise<void> {
  await withCwd(async (cwd, bin) => {
    const { answer } = await c.invoke(cwd, bin, undefined, host);
    const g = group(c, answer);
    assert.ok(g, `${c.name} ${host}: program_group`);
    assert.equal(g.subreaper, false);
    assert.ok(g.unproven.length >= 1, `${c.name} ${host}: ${JSON.stringify(g)}`);
    if (c.holdsFiles) {
      assert.equal(answer.status, "partial", `${c.name} ${host}: ${answer.status_basis}`);
      assert.match(text(answer), SAYS_UNPROVEN, `${c.name} ${host}: says why`);
      if (!c.skipOk && "ok" in answer) assert.equal(answer.ok, false);
    } else {
      assert.equal(answer.status, "complete", `${c.name} ${host}: a tool that reports only what a program printed is not held: ${answer.status_basis}`);
    }
  });
}

export function register(c: Case): void {
  for (const variant of c.variants) test(`${c.name}: a ${variant} leftover is ended, the answer is partial and the files do not change after it`, { timeout: 120000 }, () => expectLeft(c, variant));
  for (const holder of c.holders ?? []) {
    test(`${c.name}: a ${holder} that holds the pipes after the program ended does not hold the tool: it answers in time, partial, and the holder is ended`, { timeout: 120000 }, () => expectLeft(c, holder));
  }
  test(`${c.name}: a clean run is complete, nothing left, nothing unproven`, () => expectClean(c));
  for (const host of ["darwin", "refused"] as const) {
    test(`${c.name}: where the absence of a leftover cannot be proven (${host}) a clean run ${c.holdsFiles ? "is partial and says why" : "keeps its status and says why in program_group"}`, () => expectUnproven(c, host));
  }
}
