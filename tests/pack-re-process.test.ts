/**
 * Programs the pack's tool and recipe start. The harness ends a tool that runs too long, or is aborted, by killing
 * the tool's process group (process.kill(-pid, SIGKILL), extensions/protocol-core.ts, runForgedTool). A program
 * started in a session of its own is not in that group: it outlives the tool and goes on writing. So every program
 * the pack starts (the two engines fuzzy_hash drives, the two tools the static-binary recipe runs) is started in the
 * caller's group, asked to die with its parent on Linux, ended with what it started at the tool's own deadline, and
 * ended by SIGTERM, SIGINT and SIGHUP, after which the tool says it was stopped.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir, truncate } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_PROBE, FUZZY, PE_INFO, RE, RECIPE, TOOLS, buildPe, childrenOf, gone, pidFile, put, startDetached, stub, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";

const TLSH_DIGEST = "T1" + "A1B2C3D4E5".repeat(7);

/** Engines that start a child of their own and then wait: the pids they write say who must die. */
async function engines(cwd: string, bin: string): Promise<string> {
  const dir = join(cwd, "pids");
  await put(cwd, "pids/.keep", "");
  await stub(bin, "ssdeep", `if [ "$1" = "-V" ]; then echo 2.14.1; exit 0; fi
echo 'ssdeep,1.1--blocksize:hash:hash,filename'
echo '3:abc:def,"x"'`);
  await stub(bin, "tlsh", `if [ "$1" = "-version" ]; then echo "tlsh 4.12.0"; exit 0; fi
if [ "$1" = "-f" ]; then
  echo $$ > "$PIDS/engine.pid"
  sleep 60 &
  echo $! > "$PIDS/child.pid"
  wait
fi
printf '${TLSH_DIGEST}\\t%s\\n' "$2"`);
  return dir;
}

test("the harness ends fuzzy_hash by killing its process group, and that ends the engine and what the engine started", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await engines(cwd, bin);
    await put(cwd, "work/sample.bin", "x".repeat(2000));
    const run = startDetached(FUZZY, cwd, { path: "work/sample.bin" }, { PIDS: dir }, bin);
    let engine = 0, child = 0;
    try {
      engine = await pidFile(join(dir, "engine.pid"));
      child = await pidFile(join(dir, "child.pid"));
      run.killGroup();
      await run.closed;
      assert.equal(await gone(engine), true, "the engine survived the group kill: it was started outside the tool's group");
      assert.equal(await gone(child), true, "what the engine started survived the group kill");
    } finally {
      for (const pid of [engine, child]) if (pid) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
    }
  });
});

test("SIGTERM, SIGINT and SIGHUP end the engine and what it started, and the tool says it was stopped", async () => {
  for (const how of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
    await withCwd(async (cwd, bin) => {
      const dir = await engines(cwd, bin);
      await put(cwd, "work/sample.bin", "x".repeat(2000));
      const run = startDetached(FUZZY, cwd, { path: "work/sample.bin" }, { PIDS: dir }, bin);
      let engine = 0, child = 0;
      try {
        engine = await pidFile(join(dir, "engine.pid"));
        child = await pidFile(join(dir, "child.pid"));
        run.signal(how);
        const code = await run.closed;
        assert.ok(code !== 0 && code !== null, `${how}: the tool exited ${code}`);
        assert.equal(await gone(engine), true, `${how}: the engine survived`);
        assert.equal(await gone(child), true, `${how}: what the engine started survived`);
        const word = JSON.parse(run.stdout()) as Json;
        assert.equal(word.status, "failed");
        assert.match(word.error, /stopped by signal/);
      } finally {
        for (const pid of [engine, child]) if (pid) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
      }
    });
  }
});

test("at the tool's own deadline the engine and what it started are ended, and the answer is the engine's timeout", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await engines(cwd, bin);
    await put(cwd, "work/sample.bin", "x".repeat(2000));
    const out = await tool(FUZZY, cwd, { path: "work/sample.bin", engine_timeout_seconds: 1 }, { PIDS: dir }, bin);
    assert.equal(out.code, 0, out.stderr + out.stdout);
    const answer = JSON.parse(out.stdout) as Json;
    assert.equal(answer.files[0].tlsh_status, "timeout");
    const engine = await pidFile(join(dir, "engine.pid"));
    const child = await pidFile(join(dir, "child.pid"));
    try {
      assert.equal(await gone(engine), true);
      assert.equal(await gone(child), true, "what the engine started outlived the deadline");
    } finally {
      for (const pid of [engine, child]) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
    }
  });
});

/** A PE of one GiB, almost all of it a hole: entropy_map takes long enough over it to be stopped in the middle. */
async function bigSample(cwd: string): Promise<string> {
  const path = await put(cwd, "inputs/big.exe", buildPe({}).file);
  await truncate(path, 1 << 30);
  return path;
}

async function startRecipe(cwd: string, sample: string) {
  const out = join(cwd, "catalog");
  const run = startDetached(RECIPE, cwd, {}, {}, undefined, ["run", "--target", JSON.stringify({ paths: [sample] }), "--out", out]);
  // entropy_map creates its profile file as it starts: from then on it is the running child.
  const until = Date.now() + 15000;
  let kids: number[] = [];
  for (;;) {
    const files = await readdir(out).catch(() => [] as string[]);
    kids = childrenOf(run.pid);
    if (files.some((f) => f.startsWith("entropy-windows")) && kids.length) break;
    if (Date.now() > until) throw new Error(`the recipe did not reach its entropy pass: ${files.join(",")}`);
    await new Promise((r) => setTimeout(r, 50));
  }
  return { run, out, kids };
}

test("the harness ends the static-binary recipe by killing its process group, and that ends the tool it is running", async () => {
  await withCwd(async (cwd) => {
    const { run, out, kids } = await startRecipe(cwd, await bigSample(cwd));
    try {
      run.killGroup();
      await run.closed;
      for (const pid of kids) assert.equal(await gone(pid), true, `the recipe's child ${pid} survived the group kill: it was started outside the recipe's group`);
      // Nothing is written after the group is gone.
      const name = (await readdir(out)).find((f) => f.startsWith("entropy-windows"))!;
      const before = (await readFile(join(out, name))).length;
      await new Promise((r) => setTimeout(r, 800));
      assert.equal((await readFile(join(out, name))).length, before, "the profile grew after the group was killed");
      // The recipe left a coverage.json from its first moment that says it did not finish.
      const coverage = JSON.parse(await readFile(join(out, "coverage.json"), "utf8")) as Json;
      assert.notEqual(coverage.status, "complete");
    } finally {
      for (const pid of kids) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
    }
  });
});

test("SIGINT and SIGHUP end the recipe's tool and leave a coverage.json that says the recipe was stopped", async () => {
  for (const how of ["SIGINT", "SIGHUP"] as const) {
    await withCwd(async (cwd) => {
      const { run, out, kids } = await startRecipe(cwd, await bigSample(cwd));
      try {
        run.signal(how);
        const code = await run.closed;
        assert.ok(code !== 0 && code !== null);
        for (const pid of kids) assert.equal(await gone(pid), true, `${how}: the recipe's child survived`);
        const coverage = JSON.parse(await readFile(join(out, "coverage.json"), "utf8")) as Json;
        assert.equal(coverage.status, "partial", "pe_info had finished, so there is a usable result");
        assert.ok(coverage.errors.some((e: string) => /stopped by signal/.test(e)), JSON.stringify(coverage.errors));
        assert.equal(coverage.entropy_map.status, "failed");
        const index = await readFile(join(out, "index.tsv"), "utf8");
        assert.match(index, /^binary\.json\t/m);
      } finally {
        for (const pid of kids) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
      }
    });
  }
});

async function block(path: string, name: string): Promise<string> {
  const text = await readFile(path, "utf8");
  const start = text.indexOf(`# BEGIN SHARED ${name}`);
  const end = text.indexOf(`# END SHARED ${name}`);
  assert.ok(start >= 0 && end > start, `${path} carries the shared ${name.toLowerCase()} block`);
  return text.slice(start, end + `# END SHARED ${name}`.length);
}
const processBlock = (path: string): Promise<string> => block(path, "PROCESS");
const sha = (text: string): string => createHash("sha256").update(text).digest("hex");

// The text of each block as the network pack carries it (its PR 1a, head f5ad0030): a copy here is a copy of that text, and a
// change to either side shows as a change of this hash, to be made in both places.
const NETWORK_PROCESS_SHA = "072a9f28f521a9bc039e717811ef0a2b4e9118169fca908bfd4467969cefddac";
const NETWORK_WITHHOLDING_SHA = "e90959c1c374a2ce465fdd85e1c8a5e9c9f5fe1d6088192a3291baa9da0c23c2";

test("the tool and the recipe that start programs carry one process block, the network pack's text, and nothing in the pack starts a program in a session or a group of its own", async () => {
  const files = [join(TOOLS, "fuzzy_hash", "run.py"), RECIPE];
  const blocks = await Promise.all(files.map(processBlock));
  assert.equal(blocks[1], blocks[0]);
  assert.equal(sha(blocks[0]!), NETWORK_PROCESS_SHA);
  const all: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (e.isDirectory()) await walk(join(dir, e.name));
      else if (e.name.endsWith(".py")) all.push(join(dir, e.name));
    }
  };
  await walk(join(RE, "tools"));
  await walk(join(RE, "recipes"));
  for (const path of all) {
    const text = (await readFile(path, "utf8")).replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, "");
    assert.doesNotMatch(text, /start_new_session|setsid|setpgrp|setpgid|preexec_fn=os\.setsid|process_group|os\.killpg|os\.spawn|os\.popen|os\.system|os\.exec|pty\.|multiprocessing/, `${path} starts or ends a program by process group, or by a means the tool's group does not reach`);
    assert.doesNotMatch(text, /import threading/, `${path} uses a thread (preexec_fn and threads do not mix)`);
    if (!files.includes(path)) assert.doesNotMatch(text, /subprocess/, `${path} starts a program`);
  }
});

test("the withholding blocks of doc_probe and pe_info are the network pack's text", async () => {
  for (const path of [DOC_PROBE, PE_INFO]) assert.equal(sha(await block(path, "WITHHOLDING")), NETWORK_WITHHOLDING_SHA, path);
});

test("the timeouts the pack sets itself are below the manifest's and the recipe's own limits", async () => {
  const fuzzy = await readFile(join(TOOLS, "fuzzy_hash", "run.py"), "utf8");
  const total = Number(/^TOTAL_BUDGET = (\d+)/m.exec(fuzzy)![1]);
  const manifest = JSON.parse(await readFile(join(TOOLS, "fuzzy_hash", "manifest.json"), "utf8")) as Json;
  assert.ok(total < manifest.timeout_seconds, `fuzzy_hash budgets ${total} s of ${manifest.timeout_seconds}`);
  for (const [tool, name] of [["doc_probe", "DEFAULT_SECONDS"], ["pe_info", "DEFAULT_SECONDS"], ["entropy_map", "DEFAULT_SECONDS"]] as const) {
    const text = await readFile(join(TOOLS, tool, "run.py"), "utf8");
    const own = Number(new RegExp(`^MAX_SECONDS = (\\d+)`, "m").exec(text)![1]);
    const dflt = Number(new RegExp(`^${name} = (\\d+)`, "m").exec(text)![1]);
    const m = JSON.parse(await readFile(join(TOOLS, tool, "manifest.json"), "utf8")) as Json;
    assert.ok(own < m.timeout_seconds && dflt <= own, `${tool}: default ${dflt}, most ${own}, manifest ${m.timeout_seconds}`);
    assert.ok(m.params.max_seconds, `${tool} lists max_seconds in its manifest`);
  }
  const recipe = await readFile(RECIPE, "utf8");
  const budget = Number(/^BUDGET_SECONDS = (\d+)/m.exec(recipe)![1]);
  const rj = JSON.parse(await readFile(join(RE, "recipes", "static-binary", "recipe.json"), "utf8")) as Json;
  assert.ok(budget < rj.limits.seconds, `the recipe budgets ${budget} s of ${rj.limits.seconds}`);
});
