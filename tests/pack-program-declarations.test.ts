/**
 * Pack tools and recipes declare the programs they run. The program names are every `binaries[].name` of every pack's requires/host.json. A tool's source
 * (run.py or run.sh) that names one of them the way a call does (a quoted argv item or `which()` argument in Python; a command at the start of a line or after
 * a pipe in a shell script) must name it in the manifest's `requires`; a recipe in `requires` (cannot run without it) or `requires_optional` (uses it when it is
 * there) of its recipe.json. The seal checks the shape of those keys; the program must be one the tests/pack's host.json lists.
 *
 * A name that is only a word in the source (a file type, a dictionary key, a collector's name) is allow-listed below, each with its reason; an entry whose
 * program is no longer named is stale and fails. A new call that is neither declared nor allow-listed fails, naming the tool and the program.
 */
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

type Unit = { id: string; kind: "tool" | "recipe"; source: string; entry: string; declared: string[] };

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** The programs this source names as a call does. */
export function calls(source: string, entry: string, programs: string[]): string[] {
  if (!programs.length) return [];
  const alt = [...programs].sort((a, b) => b.length - a.length).map(esc).join("|");
  const rx = entry.endsWith(".sh") ? new RegExp(`(?:^|\\|)\\s*(${alt})\\s`, "gm") : new RegExp(`["'](${alt})["']\\s*[,\\])]`, "g");
  return [...new Set([...source.matchAll(rx)].map((m) => m[1]))].sort();
}

/** What is wrong with these units: a program named as a call, declared nowhere and allowed nowhere. */
export function undeclared(units: Unit[], programs: string[], allowed: Record<string, Record<string, string>>): string[] {
  const problems: string[] = [];
  for (const u of units) {
    for (const p of calls(u.source, u.entry, programs)) {
      if (u.declared.includes(p)) continue;
      if (allowed[u.id]?.[p]) continue;
      problems.push(`${u.id} names the program ${p} and does not declare it (requires${u.kind === "recipe" ? " or requires_optional" : ""}), and it is not allow-listed as a word`);
    }
  }
  return problems;
}

async function hostPrograms(): Promise<string[]> {
  const names = new Set<string>();
  for (const pack of await readdir(join(ROOT, "packs"))) {
    const host = await readFile(join(ROOT, "packs", pack, "requires", "host.json"), "utf8").then((t) => JSON.parse(t) as { binaries?: Array<{ name: string }> }, () => null);
    for (const b of host?.binaries ?? []) names.add(b.name);
  }
  return [...names].sort();
}

async function units(): Promise<Unit[]> {
  const out: Unit[] = [];
  const names = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => (typeof x === "string" ? x : String((x as { name?: string })?.name ?? ""))) : []);
  for (const pack of (await readdir(join(ROOT, "packs"))).sort()) {
    for (const [dir, file, kind] of [["tools", "manifest.json", "tool"], ["recipes", "recipe.json", "recipe"]] as const) {
      for (const name of (await readdir(join(ROOT, "packs", pack, dir)).catch(() => [] as string[])).sort()) {
        const base = join(ROOT, "packs", pack, dir, name);
        const m = await readFile(join(base, file), "utf8").then((t) => JSON.parse(t) as Record<string, unknown>, () => null);
        if (!m || typeof m.entry !== "string") continue;
        const source = await readFile(join(base, m.entry), "utf8").catch(() => "");
        out.push({ id: `${pack}/${dir}/${name}`, kind, source, entry: m.entry, declared: [...names(m.requires), ...names(m.requires_optional)] });
      }
    }
  }
  return out;
}

const WORD = {
  strings: "a counter or a dictionary key named strings (a count of strings withheld, a list of decoded strings), not the program",
  log: "a field or a key named log (a collector's log, a result's log), not the program",
  "7z": "an archive type or suffix in a table of names, not the program",
  CyLR: "the name of a collector in a table of collectors, not a program the tool runs",
  uac: "the name of a collector in a table of collectors, not a program the tool runs",
  velociraptor: "the name of a collector in a table of collectors, not a program the tool runs",
  java: "a file type or a language name in a table of names, not the program",
  pwsh: "a word in a list of program names to recognise in a command line, not a program the tool runs",
};
const w = (...programs: Array<keyof typeof WORD>): Record<string, string> => Object.fromEntries(programs.map((p) => [p, WORD[p]]));
const COLLECTORS = w("7z", "CyLR", "log", "uac", "velociraptor");

/** Words that are not calls. A tool or recipe that is not here and names a program in its source declares it. */
const ALLOWED: Record<string, Record<string, string>> = {
  "computer-forensics-base/tools/file_type": w("7z"),
  "ransomware-response/tools/encryption_extent": w("7z"),
  "encrypted-containers/tools/archive_probe": w("strings"),
  "encrypted-containers/tools/crypto_id": w("strings"),
  "encrypted-containers/tools/crypto_metadata": w("strings"),
  "encrypted-containers/tools/crypto_selftest": w("strings"),
  "encrypted-containers/tools/archive_metadata": w("strings"),
  "encrypted-containers/tools/materialise_decrypted": w("strings"),
  "encrypted-containers/tools/password_recover": w("7z", "strings"),
  "encrypted-containers/tools/recovery_key_scan": w("strings"),
  "encrypted-containers/tools/tcrypt_header": w("strings"),
  "linux-forensics/tools/linux_triage": w("strings"),
  "macos-forensics/tools/fsevents_parse": w("strings"),
  "macos-forensics/tools/knowledgec_query": w("log", "strings"),
  "macos-forensics/tools/unified_log": { ...w("strings"), log: "the macOS system log command, looked for with which() only when sys.platform is darwin and for the live store; it is not in any image, and the reader this tool needs is unifiedlog_iterator (its requires)" },
  "mobile-forensics/recipes/android-aleapp": w("log"),
  "mobile-forensics/recipes/ios-ileapp": w("log"),
  "ransomware-response/tools/encrypted_survey": w("7z", "java", "log"),
  "reverse-engineering/recipes/capa-floss": w("strings"),
  "triage-collection/recipes/collection-intake": COLLECTORS,
  "triage-collection/tools/collection_coverage": COLLECTORS,
  "triage-collection/tools/collection_id": w("7z", "log", "uac", "velociraptor"),
  "triage-collection/tools/collection_index": w("7z", "log"),
  "triage-collection/tools/collection_manifest_parse": COLLECTORS,
  "triage-collection/tools/collection_manifest_verify": COLLECTORS,
  "triage-collection/tools/collection_path_map": COLLECTORS,
  "triage-collection/tools/collection_timestamps": COLLECTORS,
  "windows-forensics/tools/amcache_apps": w("strings"),
  "windows-forensics/tools/esedb_query": w("strings"),
  "windows-forensics/tools/evtx_carve": w("strings"),
  "windows-forensics/tools/evtx_query": w("strings"),
  "windows-forensics/tools/lnk_jumplist": w("strings"),
  "windows-forensics/tools/lnk_parse": w("java", "pwsh", "strings"),
  "windows-forensics/tools/regkv": w("strings"),
  "windows-forensics/tools/registry_recover": w("log"),
  "virtualization-backup-forensics/tools/snapshot_chain_check": { "qemu-img": "run only when it is installed, to read a disk format header; the pack pins that the tool declares no requires (tests/pack-virtualization-shared.test.ts), as nothing in it needs the program to answer" },
  "memory-forensics/tools/vol_readiness": { vol: "the tool starts `vol` itself and, when it is not on PATH, answers that as its own result (a blocked view, or a JSON refusal naming it) instead of the harness refusing the call first; requires/host.json declares vol as an optional program of the pack", yara: "not a program the tool starts: the name is the Python module (yara, yara_x) whose import it tests in the interpreter of the vol script" },
  "memory-forensics/tools/mem_registry": { vol: "the tool starts `vol` itself and, when it is not on PATH, answers that as its own result (a blocked view, or a JSON refusal naming it) instead of the harness refusing the call first; requires/host.json declares vol as an optional program of the pack" },
  "memory-forensics/tools/vol_views": { vol: "the tool starts `vol` itself and, when it is not on PATH, answers that as its own result (a blocked view, or a JSON refusal naming it) instead of the harness refusing the call first; requires/host.json declares vol as an optional program of the pack" },
  "memory-forensics/tools/isf_intake": { vol: "the tool starts `vol` itself and, when it is not on PATH, answers that as its own result (a blocked view, or a JSON refusal naming it) instead of the harness refusing the call first; requires/host.json declares vol as an optional program of the pack" },
  "windows-forensics/tools/sigma_hunt": { hayabusa: "one of two engines, either of which is enough (the description says so, and tests/pack-windows-forensics.test.ts pins that it declares neither: declaring both would claim both are needed)", zircolite: "one of two engines, either of which is enough (see hayabusa)" },
  "windows-forensics/tools/shellbags": w("strings"),
  "windows-forensics/tools/yara_scan": w("strings"),
};

test("every program a pack tool or recipe names as a call is declared in its manifest or recipe.json, or allow-listed as a word", async () => {
  const programs = await hostPrograms();
  const all = await units();
  assert.ok(programs.length >= 90 && all.length >= 100, `${programs.length} programs, ${all.length} tools and recipes`);
  assert.deepEqual(undeclared(all, programs, ALLOWED), []);
});

test("an allow-list entry is a word the source still names, in a tool that does not declare it", async () => {
  const programs = await hostPrograms();
  const all = new Map((await units()).map((u) => [u.id, u]));
  const stale: string[] = [];
  for (const [id, words] of Object.entries(ALLOWED)) {
    const u = all.get(id);
    if (!u) {
      stale.push(`${id}: no such tool or recipe`);
      continue;
    }
    const named = calls(u.source, u.entry, programs);
    for (const p of Object.keys(words)) {
      if (!named.includes(p)) stale.push(`${id}: ${p} is not named any more, remove the entry`);
      if (u.declared.includes(p)) stale.push(`${id}: ${p} is declared, remove the entry`);
    }
  }
  assert.deepEqual(stale, []);
});

test("the recipes' declarations name programs that a pack's host.json lists", async () => {
  const programs = new Set(await hostPrograms());
  for (const u of (await units()).filter((x) => x.kind === "recipe")) for (const p of u.declared) assert.ok(programs.has(p), `${u.id} declares ${p}, which no host.json lists`);
});

test("the check finds a planted undeclared call in Python and in a shell script, takes a declared one, and reads a word as a word", () => {
  const programs = ["tshark", "7z", "fls"];
  const py = 'import shutil\nbinary = shutil.which("tshark")\nargv = ["fls", "-r", path]\nTYPES = ("zip", "7z", "gz")\n';
  assert.deepEqual(calls(py, "run.py", programs), ["7z", "fls", "tshark"], "a quoted word followed by a comma is read as a call; the allow-list tells the word from the call");
  const unit = (declared: string[]): Unit => ({ id: "p/tools/t", kind: "tool", source: py, entry: "run.py", declared });
  assert.equal(undeclared([unit([])], programs, {}).length, 3);
  assert.equal(undeclared([unit(["tshark", "fls"])], programs, {}).length, 1);
  assert.equal(undeclared([unit(["tshark", "fls"])], programs, { "p/tools/t": { "7z": "a suffix" } }).length, 0);
  const sh = "#!/bin/bash\nfls -r \"$img\" | grep x\necho tshark is not run\n";
  assert.deepEqual(calls(sh, "run.sh", programs), ["fls"]);
});
