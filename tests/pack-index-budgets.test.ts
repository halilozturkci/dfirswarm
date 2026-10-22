/**
 * The skill index of every pack fits the prompt, and every pack can be shortened to one line.
 *
 * `renderSkillsSection` (extensions/skills.ts) shows a pack by its router alone when the pack's index passes 1,000
 * tokens or the run's passes 2,500, and a pack that names no router cannot be shortened. Each pack's own tests
 * (tests/pack-router-checks.ts) hold its router to the rules; this suite holds the whole tree to them, so a new pack
 * under packs/ cannot ship without a router, and a leaf added to a pack cannot leave its router behind:
 *
 * - INDEX.md names a router, the harness reads it, the file is there, says `router: true` and is the pack's only one;
 * - the router is at most 400 tokens and names every other skill of the pack exactly once, no other;
 * - the entry lines of INDEX.md are the pack's skills, and cost at most 1,000 tokens as the harness counts them;
 * - every profile of images/profiles.json, and the base pack beside any one, two or three other packs, is shown within
 *   2,500 tokens (measured by scripts/pack-index-budgets.ts, which prints the table).
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { BYTES_PER_TOKEN, readPackIndex, SKILL_BUDGET, splitSkill } from "../extensions/skills.ts";
import { loadCorpus, measureCombinations, measureProfiles, ROOT } from "../scripts/pack-index-budgets.ts";

const ROUTER_MAX_TOKENS = 400;
const tokensOf = (text: string): number => Buffer.byteLength(text) / BYTES_PER_TOKEN;

/** Every skill of a pack: id (from the front matter) and file, INDEX.md apart. */
async function skillsOf(skillsDir: string): Promise<Map<string, { meta: Record<string, string | string[]>; path: string; text: string }>> {
  const out = new Map<string, { meta: Record<string, string | string[]>; path: string; text: string }>();
  const walk = async (dir: string): Promise<void> => {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (e.isDirectory()) await walk(join(dir, e.name));
      else if (e.name.endsWith(".md") && !(dir === skillsDir && e.name === "INDEX.md")) {
        const path = join(dir, e.name);
        const text = await readFile(path, "utf8");
        const { meta } = splitSkill(text);
        out.set(String(meta.id ?? path), { meta, path, text });
      }
    }
  };
  await walk(skillsDir);
  return out;
}

/** What is wrong with one pack's router and index, in words; empty when nothing is. */
async function packProblems(packDir: string): Promise<string[]> {
  const problems: string[] = [];
  const skillsDir = join(packDir, "skills");
  const skills = await skillsOf(skillsDir);
  const index = await readPackIndex(packDir);
  if (index.error) problems.push(`the index cannot be read: ${index.error}`);

  // The index lists the pack's skills, no more and no fewer, and costs what the harness says it may.
  const listed = index.entries.map((e) => e.id);
  const ids = [...skills.keys()];
  const unlisted = ids.filter((id) => !listed.includes(id));
  const unknown = listed.filter((id) => !skills.has(id));
  if (unlisted.length) problems.push(`INDEX.md does not list ${unlisted.join(", ")}`);
  if (unknown.length) problems.push(`INDEX.md lists ${unknown.join(", ")}, which no file carries`);
  if (new Set(listed).size !== listed.length) problems.push("INDEX.md lists a skill twice");
  if (index.tokens > SKILL_BUDGET.pack) problems.push(`the index is ${index.tokens} tokens, over ${SKILL_BUDGET.pack}`);

  const marked = [...skills.values()].filter((s) => s.meta.router === "true").map((s) => String(s.meta.id));
  const router = index.router;
  const text = await readFile(join(skillsDir, "INDEX.md"), "utf8").catch(() => "");
  if (!router) {
    problems.push(text.includes("Router:") ? "INDEX.md names a router that is not one of its entries" : "INDEX.md has no `Router:` line");
    return problems;
  }
  const file = skills.get(router);
  if (!file) {
    problems.push(`the router ${router} is not a skill of the pack: no file carries that id`);
    return problems;
  }
  if (file.path !== join(skillsDir, `${router}.md`)) problems.push(`the router ${router} does not resolve to skills/${router}.md`);
  if (file.meta.router !== "true") problems.push(`${router} does not say router: true`);
  if (marked.length !== 1 || marked[0] !== router) problems.push(`the pack's routers are ${JSON.stringify(marked)}, the index names ${router}`);
  const size = tokensOf(file.text);
  if (size > ROUTER_MAX_TOKENS) problems.push(`the router is ${Math.round(size)} tokens, over ${ROUTER_MAX_TOKENS}`);
  const entry = index.entries.find((e) => e.id === router)!;
  if (entry.tokens > SKILL_BUDGET.entry) problems.push(`the router's index line is ${entry.tokens} tokens, over ${SKILL_BUDGET.entry}`);

  // Every other skill is named, once.
  const body = splitSkill(file.text).body;
  const named = [...body.matchAll(/`([a-z0-9][a-z0-9_-]*(?:\/[a-z0-9_-]+)+)`/g)].map((m) => m[1]!);
  const twice = [...new Set(named.filter((id, i) => named.indexOf(id) !== i))];
  const leaves = ids.filter((id) => id !== router);
  const missing = leaves.filter((id) => !named.includes(id));
  const stray = [...new Set(named.filter((id) => !leaves.includes(id)))];
  if (twice.length) problems.push(`the router names ${twice.join(", ")} more than once`);
  if (missing.length) problems.push(`the router does not name ${missing.join(", ")}`);
  if (stray.length) problems.push(`the router names ${stray.join(", ")}, which are not skills of the pack`);
  return problems;
}

test("every pack under packs/ names a router that resolves, within 400 tokens, naming each leaf once, in an index within 1,000 tokens", async () => {
  const corpus = await loadCorpus();
  const failures: string[] = [];
  for (const name of corpus.names) {
    for (const problem of await packProblems(join(ROOT, "packs", name))) failures.push(`${name}: ${problem}`);
  }
  assert.deepEqual(failures, []);
});

test("every profile, and the base pack beside any one, two or three other packs, is shown within the run's 2,500 tokens", async () => {
  const corpus = await loadCorpus();
  const over: string[] = [];
  const check = (m: { label: string; shown: number; noRouter: string[] }): void => {
    if (m.shown > SKILL_BUDGET.run) over.push(`${m.label}: ${m.shown} tokens shown${m.noRouter.length ? ` (no router: ${m.noRouter.join(", ")})` : ""}`);
  };
  const profiles = measureProfiles(corpus);
  assert.ok(profiles.length >= 11, `${profiles.length} profiles measured`);
  profiles.forEach(check);
  for (const k of [1, 2, 3] as const) {
    const all = measureCombinations(corpus, k);
    const others = corpus.names.length - 1;
    assert.equal(all.length, k === 1 ? others : k === 2 ? (others * (others - 1)) / 2 : (others * (others - 1) * (others - 2)) / 6, `every base + ${k} combination is measured`);
    all.forEach(check);
  }
  assert.deepEqual(over, []);
});

test("the base pack's index is at most 1,000 tokens, so it is never shortened to its router", async () => {
  const corpus = await loadCorpus();
  const base = corpus.indexes.get("computer-forensics-base")!;
  assert.ok(base.tokens <= SKILL_BUDGET.pack, `the base index is ${base.tokens} tokens`);
});

// The checks above are only worth anything if they can fail: each rule is broken on a small pack of its own.
async function fixturePack(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "pack-index-budgets-"));
  await writeFile(join(dir, "pack.json"), JSON.stringify({ id: "fixture", version: "1.0.0", skills: 0 }));
  for (const [rel, text] of Object.entries(files)) {
    await mkdir(join(dir, "skills", rel, ".."), { recursive: true });
    await writeFile(join(dir, "skills", rel), text);
  }
  return dir;
}
const skillFile = (id: string, extra = "", body = "Use when you test. Not for real work.\n"): string => `---\nid: ${id}\ntitle: ${id}\nwhen: Testing ${id}.\nneeds: []\ntools: []\nrequires_host: []\n${extra}---\n\n${body}`;
const indexFile = (router: string | null, ids: string[], pad = ""): string =>
  `# Skills in this pack\n\n${router ? `Router: \`${router}\`\n\n` : ""}${ids.map((id) => `- \`${id}\` ${id}: when it applies.${pad}`).join("\n")}\n`;
const goodRouter = (leaves: string[]): string => skillFile("t/router", "router: true\n", `Use when you route. Not for rules.\n\n${leaves.map((l) => `\`${l}\` somewhere`).join("\n")}\n`);

async function withFixture(files: Record<string, string>, run: (dir: string) => Promise<void>): Promise<void> {
  const dir = await fixturePack(files);
  try {
    await run(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("the check passes a pack with a router that names each leaf once", async () => {
  await withFixture({ "INDEX.md": indexFile("t/router", ["t/a", "t/b", "t/router"]), "t/a.md": skillFile("t/a"), "t/b.md": skillFile("t/b"), "t/router.md": goodRouter(["t/a", "t/b"]) }, async (dir) => {
    assert.deepEqual(await packProblems(dir), []);
  });
});

test("the check fails a pack with no router line, a router file that is missing, or one not marked router: true", async () => {
  const leaves = { "t/a.md": skillFile("t/a") };
  await withFixture({ ...leaves, "INDEX.md": indexFile(null, ["t/a"]) }, async (dir) => {
    assert.deepEqual(await packProblems(dir), ["INDEX.md has no `Router:` line"]);
  });
  await withFixture({ ...leaves, "INDEX.md": indexFile("t/router", ["t/a"]) }, async (dir) => {
    assert.deepEqual(await packProblems(dir), ["INDEX.md names a router that is not one of its entries"]);
  });
  await withFixture({ ...leaves, "INDEX.md": indexFile("t/router", ["t/a", "t/router"]) }, async (dir) => {
    assert.deepEqual(await packProblems(dir), ["INDEX.md lists t/router, which no file carries", "the router t/router is not a skill of the pack: no file carries that id"]);
  });
  await withFixture({ ...leaves, "INDEX.md": indexFile("t/router", ["t/a", "t/router"]), "t/router.md": skillFile("t/router", "", "Use when you route.\n\n`t/a` there\n") }, async (dir) => {
    const problems = await packProblems(dir);
    assert.ok(problems.includes("t/router does not say router: true"), problems.join("; "));
  });
});

test("the check fails a router that names a leaf twice, not at all, or one that is not the pack's, and one over 400 tokens", async () => {
  const base = { "INDEX.md": indexFile("t/router", ["t/a", "t/b", "t/router"]), "t/a.md": skillFile("t/a"), "t/b.md": skillFile("t/b") };
  await withFixture({ ...base, "t/router.md": goodRouter(["t/a", "t/a", "t/b"]) }, async (dir) => {
    assert.deepEqual(await packProblems(dir), ["the router names t/a more than once"]);
  });
  await withFixture({ ...base, "t/router.md": goodRouter(["t/a"]) }, async (dir) => {
    assert.deepEqual(await packProblems(dir), ["the router does not name t/b"]);
  });
  await withFixture({ ...base, "t/router.md": goodRouter(["t/a", "t/b", "other/leaf"]) }, async (dir) => {
    assert.deepEqual(await packProblems(dir), ["the router names other/leaf, which are not skills of the pack"]);
  });
  await withFixture({ ...base, "t/router.md": skillFile("t/router", "router: true\n", `Use when you route. Not for rules.\n\n\`t/a\` x\n\`t/b\` y\n${"padding words here ".repeat(120)}\n`) }, async (dir) => {
    const problems = await packProblems(dir);
    assert.equal(problems.length, 1);
    assert.match(problems[0]!, /^the router is \d+ tokens, over 400$/);
  });
});

test("the check fails an index that passes 1,000 tokens, lists a skill twice or leaves one out", async () => {
  const many = Array.from({ length: 40 }, (_, i) => `t/leaf-${i}`);
  const files: Record<string, string> = { "INDEX.md": indexFile("t/router", [...many, "t/router"], " More words to make the line cost something.".repeat(2)), "t/router.md": goodRouter(many) };
  for (const id of many) files[`${id}.md`] = skillFile(id);
  await withFixture(files, async (dir) => {
    const problems = await packProblems(dir);
    assert.equal(problems.length, 1);
    assert.match(problems[0]!, /^the index is \d+ tokens, over 1000$/);
  });
  await withFixture({ "INDEX.md": indexFile("t/router", ["t/a", "t/a", "t/router"]), "t/a.md": skillFile("t/a"), "t/b.md": skillFile("t/b"), "t/router.md": goodRouter(["t/a", "t/b"]) }, async (dir) => {
    assert.deepEqual(await packProblems(dir), ["INDEX.md does not list t/b", "INDEX.md lists a skill twice"]);
  });
});
