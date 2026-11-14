/**
 * A target that is not a regular file must not block a recipe. For every recipe of every pack, `detect` and `run` are given a FIFO (nothing writes to it),
 * a directory and a link to the FIFO as the target: each ends within 10 seconds with a JSON document on stdout and no traceback, and `detect` says
 * `applies: "unknown"` with exit 2 for the FIFO (a file it cannot read is a file it cannot tell about). Linux only (mkfifo).
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const LIMIT_MS = 10_000;
type Recipe = { id: string; dir: string; runtime: string; entry: string };

async function recipes(): Promise<Recipe[]> {
  const out: Recipe[] = [];
  for (const pack of (await readdir(join(ROOT, "packs"))).sort()) {
    for (const name of (await readdir(join(ROOT, "packs", pack, "recipes")).catch(() => [] as string[])).sort()) {
      const dir = join(ROOT, "packs", pack, "recipes", name);
      const j = JSON.parse(await readFile(join(dir, "recipe.json"), "utf8")) as { runtime: string; entry: string };
      out.push({ id: `${pack}/${name}`, dir, runtime: j.runtime === "bash" ? "bash" : "python3", entry: j.entry });
    }
  }
  return out;
}

function run(r: Recipe, cwd: string, verb: string, target: string): Promise<{ code: number | null; stdout: string; stderr: string; killed: boolean }> {
  return new Promise((resolve) => {
    const argv = [join(r.dir, r.entry), verb, "--target", JSON.stringify({ paths: [target], name: "f", ref: "input:f" }), ...(verb === "run" ? ["--out", join(cwd, `out-${verb}`)] : [])];
    const child = spawn(r.runtime, argv, { cwd, env: { ...process.env, AGENT_ID: "s1" }, stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let killed = false;
    const timer = setTimeout(() => {
      killed = true;
      child.kill("SIGKILL");
    }, LIMIT_MS);
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", () => undefined);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), killed });
    });
  });
}

test("every recipe, given a FIFO, a directory and a link to a FIFO as the target, ends in JSON in time, for detect and for run", { timeout: 900_000, skip: process.platform !== "linux" ? "mkfifo" : false }, async () => {
  const all = await recipes();
  assert.ok(all.length >= 16, `${all.length} recipes`);
  const failures: string[] = [];
  for (const r of all) {
    const cwd = await mkdtemp(join(tmpdir(), "recipe-fifo-"));
    try {
      const fifo = join(cwd, "f");
      execFileSync("mkfifo", [fifo]);
      await mkdir(join(cwd, "d"));
      await symlink(fifo, join(cwd, "linkf"));
      for (const [label, target] of [["a FIFO", fifo], ["a directory", join(cwd, "d")], ["a link to a FIFO", join(cwd, "linkf")]] as const) {
        for (const verb of ["detect", "run"]) {
          const x = await run(r, cwd, verb, target);
          const where = `${r.id} ${verb} given ${label}`;
          if (x.killed) {
            failures.push(`${where}: no answer in ${LIMIT_MS / 1000} s`);
            continue;
          }
          if (/Traceback/.test(x.stderr)) failures.push(`${where}: a traceback`);
          let doc: { applies?: unknown } | null = null;
          try {
            doc = JSON.parse(x.stdout.trim().split("\n").pop() ?? "") as { applies?: unknown };
          } catch {
            failures.push(`${where}: no JSON on stdout (exit ${x.code})`);
            continue;
          }
          // A recipe that cannot run on this host at all says so whatever the target ("does not apply here: ..."): that is not an answer about the FIFO.
          const aboutTheHost = x.code === 1 && doc.applies === false && /^does not apply here: /.test(String((doc as { why?: unknown }).why ?? ""));
          if (verb === "detect" && label === "a FIFO" && !aboutTheHost && !(x.code === 2 && doc.applies === "unknown")) failures.push(`${where}: exit ${x.code} applies ${JSON.stringify(doc.applies)}, not exit 2 and "unknown"`);
        }
      }
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  }
  assert.deepEqual(failures, []);
});
