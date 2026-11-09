/**
 * Every relative link in the tracked Markdown resolves. A link to a file or a directory that is not tracked is a dead link on GitHub and in any
 * checkout; this test reads the tracked Markdown (fixtures excepted), takes the inline links and the reference definitions whose target has no
 * scheme and is not a bare anchor, drops `#anchor` and `?query`, resolves the rest against the file's directory, and fails on any target that is
 * not a tracked file or directory, naming it as file:line -> target. Fenced blocks and code spans are not read (they show links, they are not
 * links). The scanner is a pure function, so the cases below plant dead links in memory and see them found.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { test } from "node:test";
import { ALWAYS_NODE, select, type Layout } from "../scripts/test-select.ts";

const ROOT = join(import.meta.dirname, "..");

type Link = { line: number; target: string };

/** The relative targets a Markdown text links to, with their line numbers; code (fenced blocks and spans) is skipped. */
export function relativeLinks(text: string): Link[] {
  const found: Link[] = [];
  let fence: { ch: string; len: number } | null = null;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i]!;
    const open = /^ {0,3}(`{3,}|~{3,})/.exec(raw);
    if (fence) {
      const close = /^ {0,3}(`{3,}|~{3,})\s*$/.exec(raw);
      if (close && close[1]![0] === fence.ch && close[1]!.length >= fence.len) fence = null;
      continue;
    }
    if (open) {
      fence = { ch: open[1]![0]!, len: open[1]!.length };
      continue;
    }
    // A code span hides what is in it: the backtick runs of equal length pair up.
    const line = raw.replace(/(`+)(?:(?!\1)[\s\S])*?\1(?!`)/g, (m) => " ".repeat(m.length));
    const targets: string[] = [];
    for (const m of line.matchAll(/!?\[(?:[^\]\\]|\\.)*\]\(\s*(<[^>]*>|[^)\s]*)(?:\s+(?:"[^"]*"|'[^']*'))?\s*\)/g)) targets.push(m[1]!);
    const ref = /^ {0,3}\[(?:[^\]\\]|\\.)+\]:\s*(<[^>]*>|\S+)/.exec(line);
    if (ref) targets.push(ref[1]!);
    for (let t of targets) {
      if (t.startsWith("<") && t.endsWith(">")) t = t.slice(1, -1);
      if (!t || t.startsWith("#") || t.startsWith("//") || /^[a-z][a-z0-9+.-]*:/i.test(t)) continue;
      found.push({ line: i + 1, target: t });
    }
  }
  return found;
}

/** The links of the given files that do not resolve to a tracked file or directory: "file:line -> target". */
export function deadLinks(files: Map<string, string>, tracked: Set<string>, directories: Set<string>): string[] {
  const dead: string[] = [];
  for (const [file, text] of files) {
    for (const { line, target } of relativeLinks(text)) {
      let path = target.replace(/[#?].*$/, "");
      if (!path) continue;
      try {
        path = decodeURIComponent(path);
      } catch {
        // an undecodable escape is taken as written
      }
      const resolved = path.startsWith("/") ? posix.normalize(path.slice(1)) : posix.normalize(posix.join(dirname(file), path));
      const bare = resolved.replace(/\/+$/, "");
      if (resolved.startsWith("../") || resolved === "..") dead.push(`${file}:${line} -> ${target}`);
      else if (!(bare === "" || bare === "." || tracked.has(bare) || directories.has(bare))) dead.push(`${file}:${line} -> ${target}`);
    }
  }
  return dead;
}

function trackedTree(): { files: string[]; directories: Set<string> } {
  const files = execFileSync("git", ["ls-files", "-z"], { cwd: ROOT, encoding: "utf8", maxBuffer: 1 << 28 }).split("\0").filter(Boolean);
  const directories = new Set<string>();
  for (const f of files) for (let d = dirname(f); d && d !== "."; d = dirname(d)) directories.add(d);
  return { files, directories };
}

test("the scanner reads inline links and reference definitions, and skips code, schemes, anchors and fixtures' kind of text", () => {
  const text = [
    "A [live](docs/a.md) and a [dead](docs/gone.md#part) and ![img](img/x.png \"title\") and [anchor](#top) and [web](https://example.org/x.md) and [mail](mailto:a@b.c).",
    "Code `[hidden](docs/hidden.md)` and ``[also](docs/also.md)`` are not links.",
    "```",
    "[fenced](docs/fenced.md)",
    "```",
    "~~~sh",
    "[tilde](docs/tilde.md)",
    "~~~",
    "[ref]: docs/ref.md \"Title\"",
    "[ref2]: <docs/spaced name.md>",
    "[query](docs/q.md?plain=1) [abs](/docs/root.md) [wrapped](<docs/w.md>)",
  ].join("\n");
  const got = relativeLinks(text).map((l) => `${l.line}:${l.target}`);
  assert.deepEqual(got, ["1:docs/a.md", "1:docs/gone.md#part", "1:img/x.png", "9:docs/ref.md", "10:docs/spaced name.md", "11:docs/q.md?plain=1", "11:/docs/root.md", "11:docs/w.md"]);
});

test("a dead link planted in a document is found, with its file and line; a live one, an anchor, a directory and a root-relative link are not", () => {
  const tracked = new Set(["docs/a.md", "docs/b/c.md", "README.md", "img/x.png"]);
  const directories = new Set(["docs", "docs/b", "img"]);
  const files = new Map([
    ["docs/index.md", ["[a](a.md)", "[dead](missing.md)", "[dir](b/) [dir2](b)", "[up](../README.md#top)", "[root](/img/x.png)", "[out](../../etc/passwd)", "[gone](b/nope.md?x=1)"].join("\n")],
  ]);
  assert.deepEqual(deadLinks(files, tracked, directories), ["docs/index.md:2 -> missing.md", "docs/index.md:6 -> ../../etc/passwd", "docs/index.md:7 -> b/nope.md?x=1"]);
});

test("a Markdown change selects this suite, with the link check", () => {
  const layout: Layout = { nodeRun: [...ALWAYS_NODE, "tests/markdown-links.test.ts"], shell: ["pack-links"], read: () => "" };
  for (const f of ["docs/usage.md", "README.md", "changelog.d/claude-x.md"]) {
    const s = select([f], layout);
    assert.equal(s.all, false, f);
    assert.ok(s.node.includes("tests/markdown-links.test.ts"), `${f} did not select the Markdown link suite`);
    assert.ok(s.shell.includes("pack-links"), `${f} did not select the pack link check`);
  }
});

test("every relative link in the tracked Markdown (fixtures excepted) resolves to a tracked file or directory", (t) => {
  const { files, directories } = trackedTree();
  const tracked = new Set(files);
  const docs = new Map<string, string>();
  for (const f of files) {
    if (!f.endsWith(".md") || f.startsWith("tests/fixtures/") || f.split("/").includes("fixtures")) continue;
    try {
      docs.set(f, readFileSync(join(ROOT, f), "utf8"));
    } catch {
      // tracked but not on disk (a deletion not yet committed): nothing to read
    }
  }
  const scanned = [...docs.values()].reduce((n, text) => n + relativeLinks(text).length, 0);
  t.diagnostic(`${docs.size} Markdown files, ${scanned} relative links scanned`);
  assert.ok(docs.size > 100 && scanned > 100, "the scan found almost nothing: it is broken");
  const dead = deadLinks(docs, tracked, directories);
  assert.deepEqual(dead, [], `${dead.length} dead relative link(s):\n${dead.join("\n")}`);
});
