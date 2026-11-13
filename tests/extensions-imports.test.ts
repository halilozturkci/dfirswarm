/**
 * An extension is loaded in a seat's VM, where scripts/ is the hub's and may not be mounted: an extension reaches a
 * script only with a dynamic import on a path the hub takes. A static import of one (extensions/finish.ts took one for
 * a pure helper) made every seat's extension fail to load in a rig that mounts extensions/ alone.
 */
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

test("no extension imports a script statically", () => {
  const dir = join(import.meta.dirname, "..", "extensions");
  const found: string[] = [];
  for (const f of readdirSync(dir).filter((x) => x.endsWith(".ts"))) {
    readFileSync(join(dir, f), "utf8").split("\n").forEach((line, i) => {
      if (/^\s*(import|export)\b[^;]*\bfrom\s+["']\.\.\/scripts\//.test(line) && !/^\s*import\s+type\b/.test(line)) found.push(`extensions/${f}:${i + 1}`);
    });
  }
  assert.deepEqual(found, []);
});
