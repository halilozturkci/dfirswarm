/**
 * The Linux pack: the six tool manifests of the Linux pack: what each says it reads, and that it carries its
 * script's sha256.
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, tool } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

test("every manifest says what its tool reads, the sha256 of its script, and a version above the one before", async () => {
  const expected: Record<string, { names?: string[]; magic?: string[]; extensions?: string[] }> = {
    auth_log: { names: ["auth.log*", "secure*"] },
    utmp_parse: { names: ["utmp", "wtmp", "btmp", "lastlog", "wtmp.*", "btmp.*", "lastlog.*"] },
    shell_history: { names: [".bash_history", ".zsh_history", ".sh_history", ".ash_history", ".history", ".python_history", ".mysql_history", ".psql_history", ".rediscli_history", ".node_repl_history", "fish_history"] },
    cron_dump: { names: ["crontab", "*.timer"] },
    journal_export: { extensions: [".journal", ".journal~"], magic: ["4c504b5348485248"] },
    linux_triage: { extensions: [".e01", ".ex01", ".dd", ".img", ".raw", ".vhd", ".vhdx", ".vmdk", ".qcow2"] },
  };
  for (const [name, want] of Object.entries(expected)) {
    const manifest = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
    assert.ok(manifest.use, `${name} says what it reads`);
    for (const key of ["names", "extensions"] as const) if (want[key]) assert.deepEqual([...manifest.use[key]].sort(), [...want[key]!].sort(), `${name} use.${key}`);
    if (want.magic) assert.deepEqual(manifest.use.magic.map((m: Json) => m.hex), want.magic);
    const script = await readFile(join(TOOLS, name, "run.py"));
    assert.equal(manifest.sha256, createHash("sha256").update(script).digest("hex"), `${name} sha256`);
    assert.ok(manifest.version >= 4 || name === "linux_triage" || name === "cron_dump", `${name} version raised`);
  }
});

test("shell_history's manifest names exactly the file names its script reads", async () => {
  // `use.names` is the hint the hub matches an input against: it must not promise a name the script skips, or skip one it reads.
  const script = await readFile(join(TOOLS, "shell_history", "run.py"), "utf8");
  const block = script.slice(script.indexOf("NAMES = {"), script.indexOf("# Known files that are not command histories"));
  const read = [...block.matchAll(/"([^"]+)": \("/g)].map((m) => m[1]).sort();
  const manifest = JSON.parse(await readFile(join(TOOLS, "shell_history", "manifest.json"), "utf8"));
  assert.ok(read.length >= 10);
  assert.deepEqual([...manifest.use.names].sort(), read);
  const skipped = [...script.slice(script.indexOf("NOT_PARSED = {")).matchAll(/"(\.[a-z]+)": "/g)].map((m) => m[1]);
  for (const name of skipped) assert.ok(!manifest.use.names.includes(name), `${name} is named, not read`);
});

test("every argument a tool's script reads is declared in its manifest, and every manifest says that its answers carry status and status_basis", async () => {
  // The hub rejects an argument the manifest does not declare, so a parameter that only the script knows can never be used.
  const read = /(?:args\.get|want_str|want_flag|want_limit|want_str_list|want_seconds)\(\s*(?:args,\s*)?"([a-z_]+)"|"([a-z_]+)" in args/g;
  for (const name of ["auth_log", "utmp_parse", "shell_history", "cron_dump", "journal_export", "linux_triage"]) {
    const manifest = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
    const script = await readFile(join(TOOLS, name, "run.py"), "utf8");
    const keys = new Set([...script.matchAll(read)].map((m) => m[1] ?? m[2]));
    // journal_export reads its filters through a loop over their names.
    if (name === "journal_export") for (const key of ["unit", "since", "until", "priority"]) keys.add(key);
    for (const key of keys) assert.ok(key in manifest.params, `${name} reads ${key} and does not declare it`);
    assert.match(manifest.description, /`status`.*`status_basis`/, `${name} says its answers carry status and status_basis`);
    assert.doesNotMatch(manifest.description, /export_status/, `${name} names the old status field`);
  }
});

test("each tool that takes a time budget accepts no more than its manifest's own timeout leaves room for", async () => {
  for (const [name, most] of [["auth_log", 105], ["utmp_parse", 45], ["shell_history", 105], ["cron_dump", 50], ["journal_export", 270]] as const) {
    const manifest = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
    assert.ok(most < manifest.timeout_seconds, `${name}: the most a caller may ask for is under the tool's timeout`);
    assert.equal(manifest.params.max_seconds.type, "number");
    assert.match(manifest.params.max_seconds.description, new RegExp(`at most ${most}`), name);
    assert.match(String((await readFile(join(TOOLS, name, "run.py"), "utf8")).match(/^MAX_SECONDS = [0-9.]+/m)), new RegExp(`MAX_SECONDS = ${most}`));
  }
});
