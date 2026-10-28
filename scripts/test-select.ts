/**
 * Which suites a change needs: the node suites and the shell suites that read
 * what it touched, or all of them. A pull request runs these; main and the
 * nightly run run everything (.github/workflows/ci.yml), so a suite this
 * leaves out is still run before long.
 *
 * The rule is to run everything unless the change is plainly narrow:
 *
 *   packs/<id>/...        the suites that name the pack (in their own text or
 *                         in a test helper they import), the pack-wide shell
 *                         suites, and, when the pack's tools changed, every
 *                         tests/pack-shared-* suite (the blocks the tools carry
 *                         in common are checked there). Tools of two packs or
 *                         more changed at once: everything, since that is how a
 *                         shared block changes.
 *   tests/<x>.test.ts|sh  that suite.
 *   tests/<helper>        the node suites that import it, directly or not; none
 *                         found: everything.
 *   docs, *.md, changelog.d
 *                         the suites that name the file, the link check and the
 *                         changelog suite.
 *   anything else         everything: the harness (scripts/, extensions/),
 *                         images/, prompts/, the libraries, the workflow,
 *                         package*.json, a fixture, a path this map does not
 *                         know.
 *
 * Three suites always run, being about the test layout itself.
 *
 *   node --experimental-strip-types scripts/test-select.ts [--base REF] [--files a,b,...]
 *        [--node-out FILE] [--shell-out FILE] [--json]
 *
 * --base REF reads the change as `git diff REF...HEAD` plus what is not
 * committed yet; --files names it. The lists go one path (node) or stem
 * (shell) per line to the --*-out files, or as JSON with --json; a summary goes
 * to stdout otherwise.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { nodeSuites } from "./test-node.ts";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

/** Suites that run on every change: the layout of the tests and of this map. */
export const ALWAYS_NODE = ["tests/changelog.test.ts", "tests/ci-shards.test.ts", "tests/test-select.test.ts"];
/** The shell suites that read every pack. */
export const PACK_WIDE_SHELL = ["packs", "pack-tools", "pack-recipes", "pack-parsers", "pack-links", "skill-budgets"];

export type Selection = { all: boolean; reasons: string[]; node: string[]; shell: string[] };

export type Layout = {
  /** The node suites npm test runs (scripts/test-node.ts). */
  nodeRun: string[];
  /** Every shell suite's stem (tests/<stem>.test.sh). */
  shell: string[];
  /** A file's text, by repository path ("" when it is not there). */
  read: (path: string) => string;
};

// `from "./x"`, `import("./x")`, and the bare `import "./x"` of a module run for its effects.
const IMPORT = /(?:from\s+|import\s*\(\s*|import\s+)["'](\.{1,2}\/[^"']+)["']/g;

/** The local modules a test file imports, transitively, under tests/ (its helpers). */
export function helperClosure(file: string, read: Layout["read"]): string[] {
  const seen = new Set<string>();
  const stack = [file];
  while (stack.length) {
    const f = stack.pop() as string;
    for (const m of read(f).matchAll(IMPORT)) {
      const p = normalize(join(dirname(f), m[1])).split(sep).join("/");
      if (p.startsWith("tests/") && !seen.has(p) && p !== file) {
        seen.add(p);
        stack.push(p);
      }
    }
  }
  return [...seen].sort();
}

const NARROW_DOC = /^(docs\/.*|[^/]+\.md|changelog\.d\/.*)$/;

/** What the change needs. `changed` holds repository paths with forward slashes. */
export function select(changed: string[], layout: Layout): Selection {
  const reasons: string[] = [];
  const everything = (why: string): Selection => ({ all: true, reasons: [...reasons, why], node: [...layout.nodeRun], shell: [...layout.shell] });
  const node = new Set<string>(ALWAYS_NODE.filter((p) => layout.nodeRun.includes(p)));
  const shell = new Set<string>();
  const closure = new Map<string, string>();
  const textOf = (suite: string): string => {
    let t = closure.get(suite);
    if (t === undefined) {
      t = [suite, ...helperClosure(suite, layout.read)].map((p) => layout.read(p)).join("\n");
      closure.set(suite, t);
    }
    return t;
  };
  const naming = (needle: string): void => {
    for (const s of layout.nodeRun) if (textOf(s).includes(needle)) node.add(s);
    for (const s of layout.shell) if (layout.read(`tests/${s}.test.sh`).includes(needle)) shell.add(s);
  };
  const files = [...new Set(changed.map((p) => p.trim()).filter(Boolean))].sort();
  if (!files.length) return { all: false, reasons: ["nothing changed"], node: [...node].sort(), shell: [] };
  const toolPacks = new Set<string>();
  for (const f of files) {
    const pack = f.match(/^packs\/([^/]+)\/(.*)$/);
    if (pack) {
      const [, id, rest] = pack;
      naming(id);
      for (const s of PACK_WIDE_SHELL) if (layout.shell.includes(s)) shell.add(s);
      if (rest.startsWith("tools/") || rest.startsWith("recipes/")) toolPacks.add(id);
      if (rest.startsWith("requires/") && layout.shell.includes("recipe")) shell.add("recipe");
      reasons.push(`${f}: the suites that name ${id}, and the pack-wide shell suites`);
      continue;
    }
    const nodeSuite = f.match(/^tests\/.+\.test\.ts$/);
    if (nodeSuite && !f.split("/").includes("fixtures")) {
      if (layout.nodeRun.includes(f)) node.add(f);
      reasons.push(`${f}: itself`);
      continue;
    }
    const shellSuite = f.match(/^tests\/([^/]+)\.test\.sh$/);
    if (shellSuite) {
      shell.add(shellSuite[1]);
      reasons.push(`${f}: itself`);
      continue;
    }
    if (/^tests\/[^/]+\.(ts|mjs|js|py)$/.test(f)) {
      const users = layout.nodeRun.filter((s) => helperClosure(s, layout.read).includes(f));
      if (!users.length) return everything(`${f}: a test helper no node suite imports; everything`);
      for (const u of users) node.add(u);
      reasons.push(`${f}: the ${users.length} node suite(s) that import it`);
      continue;
    }
    if (NARROW_DOC.test(f)) {
      naming(f);
      if (layout.shell.includes("pack-links")) shell.add("pack-links");
      reasons.push(`${f}: the suites that name it, and the link check`);
      continue;
    }
    return everything(`${f}: outside what this map narrows; everything`);
  }
  if (toolPacks.size >= 2) return everything(`the tools of ${toolPacks.size} packs changed (${[...toolPacks].sort().join(", ")}): a shared block; everything`);
  if (toolPacks.size === 1) {
    for (const s of layout.nodeRun) if (/^tests\/pack-shared-[^/]+\.test\.ts$/.test(s)) node.add(s);
    reasons.push(`tools of ${[...toolPacks][0]} changed: every tests/pack-shared-* suite`);
  }
  return { all: false, reasons, node: [...node].sort(), shell: [...shell].sort() };
}

/** The repository's own layout, read from disk. */
export function repoLayout(root: string = ROOT): Layout {
  const shell = readdirSync(join(root, "tests")).filter((f) => f.endsWith(".test.sh")).map((f) => f.slice(0, -".test.sh".length)).sort();
  const cache = new Map<string, string>();
  return {
    nodeRun: nodeSuites(root).run,
    shell,
    read: (p) => {
      let t = cache.get(p);
      if (t === undefined) {
        const abs = join(root, p);
        t = existsSync(abs) ? readFileSync(abs, "utf8") : "";
        cache.set(p, t);
      }
      return t;
    },
  };
}

/** What changed against `base`: the commits since the merge base, and what is not committed. */
export function changedSince(base: string, root: string = ROOT): string[] {
  const git = (...args: string[]) => execFileSync("git", args, { cwd: root, encoding: "utf8" }).split("\n").map((l) => l.trim()).filter(Boolean);
  return [...new Set([...git("diff", "--name-only", `${base}...HEAD`), ...git("diff", "--name-only", "HEAD"), ...git("ls-files", "--others", "--exclude-standard")])].sort();
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opt = (name: string): string | null => {
    const i = args.indexOf(name);
    return i >= 0 && i + 1 < args.length ? args[i + 1] : null;
  };
  try {
    const listed = opt("--files");
    const base = opt("--base");
    if (!listed && !base) throw new Error("give --base REF or --files a,b,...");
    const changed = listed ? listed.split(",") : changedSince(base as string);
    const s = select(changed, repoLayout());
    const nodeOut = opt("--node-out");
    const shellOut = opt("--shell-out");
    if (nodeOut) writeFileSync(nodeOut, s.node.map((p) => p + "\n").join(""));
    if (shellOut) writeFileSync(shellOut, s.shell.map((p) => p + "\n").join(""));
    if (args.includes("--json")) {
      process.stdout.write(JSON.stringify({ changed, ...s }, null, 1) + "\n");
    } else {
      console.log(`test-select: ${changed.length} changed file(s); ${s.all ? "everything" : `${s.node.length} node suite(s), ${s.shell.length} shell suite(s)`}`);
      for (const r of s.reasons) console.log(`  ${r}`);
    }
  } catch (err) {
    console.error(`test-select: ${(err as Error).message}`);
    process.exit(2);
  }
}
