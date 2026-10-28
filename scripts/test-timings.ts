/**
 * What the test runs measured, said where a person reads it.
 *
 *   node --experimental-strip-types scripts/test-timings.ts summary FILE.json... [--top N]
 *       the node suite files that took longest, as a markdown table (a CI
 *       job writes it to its summary page), from one or more timings files
 *       of scripts/test-node.ts --timings (one per shard).
 *   node --experimental-strip-types scripts/test-timings.ts weights LOG... [--write]
 *       tests/shell-suites.weights from the "=== ok <suite> (Ns)" lines of
 *       test-bash.sh logs: each suite's mean over the logs, suites the logs
 *       do not hold kept as they were. Printed, or written with --write.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

type FileTime = { file: string; ms: number; tests: number; failed: number; slowest?: { name: string; ms: number }[] };

/** The slowest files of the timings documents, merged, as a markdown table. */
export function summary(docs: string[], top = 20, root: string = ROOT): string {
  const files: FileTime[] = docs.flatMap((d) => (JSON.parse(d) as { files?: FileTime[] }).files ?? []);
  const rel = (f: string) => (f.startsWith(root) ? f.slice(root.length + 1) : f).split("\\").join("/");
  const total = files.reduce((s, f) => s + f.ms, 0);
  const rows = [...files].sort((a, b) => b.ms - a.ms).slice(0, top);
  const lines = [
    `**${files.length} node suite files, ${(total / 60000).toFixed(1)} min of test time** (the sum over files; the wall time is shorter by the concurrency)`,
    "",
    "| seconds | share | tests | file | slowest test |",
    "| ---: | ---: | ---: | --- | --- |",
    ...rows.map((f) => `| ${(f.ms / 1000).toFixed(1)} | ${total ? ((100 * f.ms) / total).toFixed(1) : "0"}% | ${f.tests} | \`${rel(f.file)}\`${f.failed ? " (failed)" : ""} | ${(f.slowest?.[0]?.name ?? "").slice(0, 80).replace(/\|/g, "\\|")} |`),
  ];
  return lines.join("\n") + "\n";
}

/** The weights file again: the header kept, each suite the logs time set to its mean (rounded up), the rest as they were, longest first. */
export function weights(current: string, logs: string[]): string {
  const header = current.split("\n").filter((l) => l.startsWith("#"));
  const old = new Map<string, number>();
  for (const l of current.split("\n")) {
    const m = l.replace(/#.*$/, "").trim().match(/^(\S+)\s+(\d+)$/);
    if (m) old.set(m[1], Number(m[2]));
  }
  const seen = new Map<string, number[]>();
  for (const log of logs) {
    for (const m of log.matchAll(/^(?:\S+\s)?=== ok\s+(\S+) \((\d+)s\)\s*$/gm)) {
      const list = seen.get(m[1]) ?? [];
      list.push(Number(m[2]));
      seen.set(m[1], list);
    }
  }
  const merged = new Map(old);
  for (const [suite, secs] of seen) merged.set(suite, Math.max(1, Math.ceil(secs.reduce((s, x) => s + x, 0) / secs.length)));
  const body = [...merged.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([s, n]) => `${s} ${n}`);
  return [...header, ...body].join("\n") + "\n";
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [cmd, ...rest] = process.argv.slice(2);
  const topAt = rest.indexOf("--top");
  const top = topAt >= 0 ? Number(rest[topAt + 1]) : 20;
  const paths = rest.filter((a, i) => !a.startsWith("--") && !(topAt >= 0 && i === topAt + 1));
  if (cmd === "summary" && paths.length) {
    process.stdout.write(summary(paths.map((p) => readFileSync(p, "utf8")), top));
  } else if (cmd === "weights" && paths.length) {
    const file = join(ROOT, "tests", "shell-suites.weights");
    const next = weights(readFileSync(file, "utf8"), paths.map((p) => readFileSync(p, "utf8")));
    if (rest.includes("--write")) writeFileSync(file, next);
    else process.stdout.write(next);
  } else {
    console.error("usage: test-timings.ts summary FILE.json... [--top N] | weights LOG... [--write]");
    process.exit(2);
  }
}
