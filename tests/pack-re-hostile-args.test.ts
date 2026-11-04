/**
 * Caller input that is JSON but is not an object, or nests past what the parser can follow, is a refusal in JSON from every tool and both recipes:
 * never a traceback, never an empty stdout. The static-binary recipe read `--target` with json.loads and called .get on the result, so
 * `[`*100000 was a RecursionError and `[]`, `1`, `null` and `"abc"` were an AttributeError, each with a traceback and exit 1 and no JSON on stdout.
 * The six tools that read their arguments with json.load(sys.stdin) answered a RecursionError through the catch-all ("unexpected failure"); they
 * now name the real cause, as go_buildinfo and marshal_inspect did.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import { RE, TOOLS, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";

const TOOL_NAMES = ["doc_probe", "doc_structure", "entropy_map", "fuzzy_hash", "go_buildinfo", "marshal_inspect", "pe_directories", "elf_directories", "macho_directories", "pe_info", "unpack_safe", "authenticode_verify"];
const RECIPES = ["static-binary", "capa-floss"];
const HOSTILE = ["[".repeat(100_000), "{" + '"path":['.repeat(50_000), "[]", "1", "null", '"abc"', "true"];

test("every tool answers JSON that nests too deeply, or is not an object, with a failed document that names the arguments, no traceback", async () => {
  await withCwd(async (cwd) => {
    for (const name of TOOL_NAMES) {
      for (const input of HOSTILE) {
        const r = spawnSync("python3", [join(TOOLS, name, "run.py")], { input, cwd, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" }, timeout: 60_000 });
        const label = `${name} <- ${input.slice(0, 12)}`;
        assert.doesNotMatch(r.stderr, /Traceback/, label);
        const a = JSON.parse(r.stdout) as Json;
        assert.equal(a.status, "failed", label);
        assert.notEqual(r.status, 0, label);
        assert.doesNotMatch(String(a.error), /unexpected failure/, `${label}: the cause is named, not the catch-all`);
        assert.ok(typeof a.status_basis === "string" && a.status_basis.length > 0, label);
      }
    }
  });
});

test("both recipes answer a --target that nests too deeply, or is not a JSON object with a list of paths, with a failed document and exit 2, in detect and in run", async () => {
  await withCwd(async (cwd) => {
    // (an argument longer than the kernel allows for one never reaches the recipe, so the 50,000-fold object of the tools is left out)
    const targets = [...HOSTILE.filter((t) => t.length < 120_000), '{"paths":"x"}', '{"paths":[5]}', '{"paths":[]}', '{"paths":{}}'];
    for (const recipe of RECIPES) {
      for (const mode of ["detect", "run"]) {
        for (const target of targets) {
          const argv = [join(RE, "recipes", recipe, "run.py"), mode, "--target", target, ...(mode === "run" ? ["--out", "o"] : [])];
          const r = spawnSync("python3", argv, { cwd, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" }, timeout: 60_000 });
          const label = `${recipe} ${mode} <- ${target.slice(0, 14)}`;
          assert.doesNotMatch(r.stderr, /Traceback/, label);
          const a = JSON.parse(r.stdout) as Json;
          assert.equal(a.ok, false, label);
          assert.equal(a.status, "failed", label);
          assert.equal(r.status, 2, label);
          assert.ok(typeof a.status_basis === "string" && a.status_basis.length > 0, label);
        }
      }
    }
  });
});
