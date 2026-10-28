/**
 * scripts/test-select.ts: which suites a change needs. A narrow change runs the
 * suites that read what it touched; anything the map does not narrow runs
 * everything. A layout of a few files stands in for the repository, so each
 * rule is checked on a case that means one thing; two cases at the end read the
 * repository itself.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { ALWAYS_NODE, PACK_WIDE_SHELL, helperClosure, repoLayout, select, type Layout } from "../scripts/test-select.ts";

function layout(files: Record<string, string>): Layout {
  return {
    nodeRun: Object.keys(files).filter((p) => p.endsWith(".test.ts")).sort(),
    shell: Object.keys(files).filter((p) => p.endsWith(".test.sh")).map((p) => p.slice("tests/".length, -".test.sh".length)).sort(),
    read: (p) => files[p] ?? "",
  };
}

const FAKE = layout({
  "tests/changelog.test.ts": "",
  "tests/ci-shards.test.ts": "",
  "tests/test-select.test.ts": "",
  "tests/pack-memory-a.test.ts": 'import { FS } from "./memory-support.ts";\n',
  "tests/memory-support.ts": 'export const FS = join(ROOT, "packs", "memory-forensics", "tools", "mem_fs", "run.py");\n',
  "tests/pack-mobile-a.test.ts": 'const T = "packs/mobile-forensics/tools/x/run.py";\n',
  "tests/pack-shared-process.test.ts": "every carrier of the block\n",
  "tests/kickoff.test.ts": 'run("scripts/swarm.sh"); read("docs/packs.md");\n',
  "tests/orphan.ts": "export const x = 1;\n",
  "tests/packs.test.sh": "",
  "tests/pack-tools.test.sh": 'packs/memory-forensics/tools/mem_fs\n',
  "tests/pack-links.test.sh": "",
  "tests/skill-budgets.test.sh": "",
  "tests/recipe.test.sh": "",
  "tests/stop.test.sh": "",
});

const always = ALWAYS_NODE;

test("a change to one pack's skill runs the suites that name the pack, through a helper too, and the pack-wide shell suites", () => {
  const s = select(["packs/memory-forensics/skills/x.md"], FAKE);
  assert.equal(s.all, false);
  assert.deepEqual(s.node, [...always, "tests/pack-memory-a.test.ts"].sort());
  assert.ok(!s.node.includes("tests/pack-mobile-a.test.ts"), "another pack's suite ran");
  assert.ok(!s.node.includes("tests/pack-shared-process.test.ts"), "a skill is not a tool: the shared-block suites need not run");
  assert.deepEqual(s.shell, ["pack-links", "pack-tools", "packs", "skill-budgets"], "the pack-wide shell suites that exist, and the one naming the pack");
});

test("a change to one pack's tools also runs every pack-shared suite", () => {
  const s = select(["packs/memory-forensics/tools/mem_fs/run.py"], FAKE);
  assert.equal(s.all, false);
  assert.ok(s.node.includes("tests/pack-shared-process.test.ts"));
  assert.ok(s.node.includes("tests/pack-memory-a.test.ts"));
});

test("the tools of two packs at once run everything: that is how a shared block changes", () => {
  const s = select(["packs/memory-forensics/tools/mem_fs/run.py", "packs/mobile-forensics/tools/x/run.py"], FAKE);
  assert.equal(s.all, true);
  assert.deepEqual(s.node, FAKE.nodeRun);
  assert.deepEqual(s.shell, FAKE.shell);
});

test("a pack's requirements also run the recipe suite", () => {
  assert.ok(select(["packs/mobile-forensics/requires/host.json"], FAKE).shell.includes("recipe"));
});

test("the harness, the workflow, the images, package.json, a fixture or an unknown path run everything", () => {
  for (const f of ["scripts/swarm.sh", "extensions/agent-swarm.ts", ".github/workflows/ci.yml", "images/install.py", "package.json", "package-lock.json", "tests/fixtures/kickoff/x/SWARM.md", "prompts/worker-system.md", "library/general/x.md", "brand/logo.svg", "tests/node-tests.deep"]) {
    const s = select([f], FAKE);
    assert.equal(s.all, true, `${f} did not run everything`);
    assert.match(s.reasons.at(-1) ?? "", /everything/);
  }
});

test("a suite that changed runs itself", () => {
  assert.ok(select(["tests/kickoff.test.ts"], FAKE).node.includes("tests/kickoff.test.ts"));
  assert.deepEqual(select(["tests/stop.test.sh"], FAKE).shell, ["stop"]);
});

test("a test helper runs the suites that import it; one nothing imports runs everything", () => {
  const s = select(["tests/memory-support.ts"], FAKE);
  assert.equal(s.all, false);
  assert.deepEqual(s.node, [...always, "tests/pack-memory-a.test.ts"].sort());
  assert.equal(select(["tests/orphan.ts"], FAKE).all, true);
});

test("a document runs the suites that name it and the link check; a changelog fragment the changelog suite", () => {
  const s = select(["docs/packs.md"], FAKE);
  assert.equal(s.all, false);
  assert.ok(s.node.includes("tests/kickoff.test.ts"), "the suite that reads docs/packs.md did not run");
  assert.deepEqual(s.shell, ["pack-links"]);
  const c = select(["changelog.d/claude-x.md"], FAKE);
  assert.equal(c.all, false);
  assert.ok(c.node.includes("tests/changelog.test.ts"));
});

test("one path that runs everything wins over narrow ones beside it", () => {
  assert.equal(select(["packs/memory-forensics/skills/x.md", "scripts/test-bash.sh"], FAKE).all, true);
});

test("the helper closure follows imports through helpers, under tests/ only", () => {
  const l = layout({ "tests/a.test.ts": 'import "./b.ts";\nimport x from "../scripts/y.ts";\n', "tests/b.ts": 'export * from "./c.ts";\n', "tests/c.ts": "" });
  assert.deepEqual(helperClosure("tests/a.test.ts", l.read), ["tests/b.ts", "tests/c.ts"]);
});

test("on this repository: a change to the memory pack's mem_fs is narrow and holds its suites; the kickoff script is everything", () => {
  const repo = repoLayout();
  const s = select(["packs/memory-forensics/tools/mem_fs/run.py"], repo);
  assert.equal(s.all, false, s.reasons.join("\n"));
  assert.ok(s.node.includes("tests/pack-memory-engine-descendants.test.ts"), "mem_fs's own suite was not selected");
  assert.ok(s.node.length < repo.nodeRun.length / 2, `${s.node.length} of ${repo.nodeRun.length} suites: not narrow`);
  for (const w of PACK_WIDE_SHELL) if (repo.shell.includes(w)) assert.ok(s.shell.includes(w), `${w} did not run`);
  assert.equal(select(["scripts/swarm.sh"], repo).all, true);
});
