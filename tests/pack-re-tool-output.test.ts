/**
 * Every reverse-engineering writer makes its output directory through the own_dir walk (pe_directories and doc_structure carry the same
 * text): a symbolic link anywhere on the way (`tool-output`, the agent's directory `work/<agent>`, `work/`, and in a job `$OUT/tool-output`)
 * is refused, and nothing is written through it. O_NOFOLLOW guards only the last name of a file; before this, a link at any other level sent
 * the tables, the logs, the private names file and the profile into the directory it pointed at.
 *
 * Each case plants the link, runs the writer in a job and outside one, and looks at the link's target: it must be empty. The writer says why
 * (a refusal for a tool whose only output is the file, a named problem for one whose answer stands without it, a failed receipt for a recipe).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readdir, rm, symlink } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { DOC_PROBE, ENTROPY, FUZZY, PE_INFO, RECIPE, RE, asJob, buildPe, buildZip, put, stub, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { PYTHON3 } from "./host-gates.ts";

const CAPA_FLOSS = join(RE, "recipes", "capa-floss", "run.py");

type Level = "tool-output" | "agent" | "work";
const LEVELS: Level[] = ["tool-output", "agent", "work"];

/** Plants a symbolic link at the named level of the outside-a-job path work/s1/tool-output, pointing at an empty directory; returns that directory. */
async function plant(cwd: string, level: Level): Promise<string> {
  const target = join(cwd, "elsewhere");
  await mkdir(target, { recursive: true });
  if (level === "work") {
    await rm(join(cwd, "work"), { recursive: true, force: true });
    await symlink(target, join(cwd, "work"));
  } else {
    await mkdir(join(cwd, "work"), { recursive: true });
    if (level === "agent") {
      await symlink(target, join(cwd, "work", "s1"));
    } else {
      await mkdir(join(cwd, "work", "s1"), { recursive: true });
      await symlink(target, join(cwd, "work", "s1", "tool-output"));
    }
  }
  return target;
}

/** In a job the writer's directory is $OUT/tool-output (the tables, logs and names file) or $OUT itself (entropy_map's profile). */
async function plantInJob(cwd: string, at: "tool-output" | "out"): Promise<string> {
  const target = join(cwd, "elsewhere");
  await mkdir(target, { recursive: true });
  if (at === "out") {
    await symlink(target, join(cwd, "out"));
  } else {
    await mkdir(join(cwd, "out"), { recursive: true });
    await symlink(target, join(cwd, "out", "tool-output"));
  }
  return target;
}

async function empty(dir: string, where: string): Promise<void> {
  assert.deepEqual(await readdir(dir), [], `${where}: something was written through the link`);
}

const THREE_MEMBERS = (): Buffer => buildZip([
  { name: "[Content_Types].xml", data: Buffer.from("<Types/>") },
  { name: "word/document.xml", data: Buffer.from("<w:document/>") },
  { name: "word/styles.xml", data: Buffer.from("<w:styles/>") },
]);

const PE_THREE_SECTIONS = (): Buffer => buildPe({ sections: [
  { name: ".text", data: Buffer.alloc(512, 0x90), flags: 0x60000020 },
  { name: ".data", data: Buffer.alloc(512, 1), flags: 0xc0000040 },
  { name: ".rsrc", data: Buffer.alloc(512, 2), flags: 0x40000040 },
] }).file;

const TOOLS: { name: string; script: string; input: () => Buffer; args: Json; stubs?: boolean; expect: (a: Json, where: string) => void }[] = [
  {
    name: "doc_probe", script: DOC_PROBE, input: THREE_MEMBERS, args: { limit: 1 },
    expect: (a, where) => {
      assert.match(JSON.stringify(a), /symbolic link/, `${where}: the answer says why the table file was not written`);
      assert.equal(a.status, "partial", where);
    },
  },
  {
    name: "pe_info", script: PE_INFO, input: PE_THREE_SECTIONS, args: { limit: 1 },
    expect: (a, where) => {
      assert.match(JSON.stringify(a), /symbolic link/, `${where}: the answer says why the table file was not written`);
      assert.equal(a.status, "partial", where);
    },
  },
  {
    name: "entropy_map", script: ENTROPY, input: () => Buffer.alloc(8192, 3), args: { window: 64 },
    expect: (a, where) => {
      assert.equal(a.status, "failed", where);
      assert.match(a.error, /symbolic link/, where);
    },
  },
  {
    name: "fuzzy_hash", script: FUZZY, input: () => Buffer.alloc(4000, 7), args: {}, stubs: true,
    expect: (a, where) => {
      assert.match(JSON.stringify(a.problems), /symbolic link/, `${where}: ${JSON.stringify(a.problems)}`);
      assert.equal(a.status, "partial", where);
    },
  },
];

for (const t of TOOLS) {
  for (const level of LEVELS) {
    test(`${t.name}: a symbolic link at ${level === "tool-output" ? "tool-output" : level === "agent" ? "the agent's directory" : "work/"} is refused, outside a job, and nothing is written through it`, async () => {
      await withCwd(async (cwd, bin) => {
        if (t.stubs) {
          await stub(bin, "ssdeep", `if [ "$1" = "-V" ]; then echo 2.14.1; exit 0; fi\necho 'ssdeep,1.1--blocksize:hash:hash,filename'\necho '96:aBcDeF0123456789+/aBcDeF0123456789+/:XyZ0123456789+/,"x"'`);
          await stub(bin, "tlsh", `if [ "$1" = "-version" ]; then echo 4.12.0; exit 0; fi\nprintf 'T1${"A1B2C3D4E5".repeat(7)}\\t%s\\n' "$2"`);
        }
        await put(cwd, "inputs/sample.bin", t.input());
        const target = await plant(cwd, level);
        const ran = await tool(t.script, cwd, { path: "inputs/sample.bin", ...t.args }, {}, t.stubs ? bin : undefined);
        assert.doesNotMatch(ran.stderr, /Traceback/, ran.stderr);
        t.expect(JSON.parse(ran.stdout) as Json, `${t.name} ${level}`);
        await empty(target, `${t.name} ${level}`);
      });
    });
  }
  test(`${t.name}: in a job, a symbolic link at ${t.name === "entropy_map" ? "$OUT" : "$OUT/tool-output"} is refused and nothing is written through it`, async () => {
    await withCwd(async (cwd, bin) => {
      if (t.stubs) {
        await stub(bin, "ssdeep", `if [ "$1" = "-V" ]; then echo 2.14.1; exit 0; fi\necho 'ssdeep,1.1--blocksize:hash:hash,filename'\necho '96:aBcDeF0123456789+/aBcDeF0123456789+/:XyZ0123456789+/,"x"'`);
        await stub(bin, "tlsh", `if [ "$1" = "-version" ]; then echo 4.12.0; exit 0; fi\nprintf 'T1${"A1B2C3D4E5".repeat(7)}\\t%s\\n' "$2"`);
      }
      await put(cwd, "inputs/sample.bin", t.input());
      const target = await plantInJob(cwd, t.name === "entropy_map" ? "out" : "tool-output");
      const ran = await asJob(t.script, cwd, { path: "inputs/sample.bin", ...t.args }, t.stubs ? bin : undefined);
      assert.doesNotMatch(ran.stderr, /Traceback/, ran.stderr);
      t.expect(JSON.parse(ran.stdout) as Json, `${t.name} job`);
      await empty(target, `${t.name} job`);
    });
  });
}

// --- the recipes ------------------------------------------------------------------------------------------------------------------------

for (const [name, script, write] of [["capa-floss", CAPA_FLOSS, "catalog"], ["static-binary", RECIPE, "catalog"]] as const) {
  for (const level of ["the directory itself", "a directory above it"] as const) {
    test(`${name}: --out through a symbolic link (${level}) is refused as JSON, nothing is written at the target, and the target stays empty`, async () => {
      await withCwd(async (cwd) => {
        await put(cwd, "inputs/s.exe", buildPe({}).file);
        const target = join(cwd, "elsewhere");
        await mkdir(target, { recursive: true });
        let out: string;
        if (level === "the directory itself") {
          await symlink(target, join(cwd, write));
          out = write;
        } else {
          await symlink(target, join(cwd, "link"));
          out = join("link", "inner");
        }
        const r = spawnSync(PYTHON3, [script, "run", "--target", JSON.stringify({ paths: ["inputs/s.exe"] }), "--out", out], { cwd, encoding: "utf8", env: { ...process.env, PATH: "/usr/bin:/bin" } });
        assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
        const a = JSON.parse(r.stdout) as Json;
        assert.equal(a.ok, false);
        assert.equal(a.status, "failed");
        assert.match(a.error, /symbolic link/);
        assert.notEqual(r.status, 0);
        await empty(target, `${name} ${level}`);
      });
    });
  }
  test(`${name}: a symbolic link as --out for a format the recipe does not run on (unsupported) is refused too`, async () => {
    await withCwd(async (cwd) => {
      await put(cwd, "inputs/mach", Buffer.concat([Buffer.from("cffaedfe", "hex"), Buffer.alloc(100)]));
      const target = join(cwd, "elsewhere");
      await mkdir(target, { recursive: true });
      await symlink(target, join(cwd, "catalog"));
      const r = spawnSync(PYTHON3, [script, "run", "--target", JSON.stringify({ paths: ["inputs/mach"] }), "--out", "catalog"], { cwd, encoding: "utf8", env: { ...process.env, PATH: "/usr/bin:/bin" } });
      assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
      const a = JSON.parse(r.stdout) as Json;
      assert.match(JSON.stringify(a), /symbolic link/);
      assert.notEqual(r.status, 0);
      await empty(target, `${name} unsupported`);
    });
  });
}

test("a directory path with no link on the way is still made, in a job and outside: the walk refuses links, not directories", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/sample.bin", Buffer.alloc(8192, 3));
    const outside = await tool(ENTROPY, cwd, { path: "inputs/sample.bin" });
    assert.equal(JSON.parse(outside.stdout).status, "complete");
    const job = await asJob(ENTROPY, cwd, { path: "inputs/sample.bin" });
    assert.equal(JSON.parse(job.stdout).status, "complete");
    const r = spawnSync("python3", [CAPA_FLOSS, "run", "--target", JSON.stringify({ paths: ["inputs/sample.bin"] }), "--out", "catalog"], { cwd, encoding: "utf8" });
    assert.equal(JSON.parse(r.stdout).status, "unsupported", "a recipe makes its directory and answers for a format it does not run on");
    assert.deepEqual((await readdir(join(cwd, "catalog"))).sort(), ["coverage.json"]);
  });
});
