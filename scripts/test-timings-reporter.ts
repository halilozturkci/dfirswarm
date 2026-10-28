/**
 * A `node --test` reporter that writes one JSON document: how long each suite
 * file took and which files had a failing test. scripts/test-node.ts hands
 * it to node beside the usual reporter (`--timings FILE`, `--retry-alone`),
 * so the output a person reads is unchanged.
 *
 * A file's time is the sum of its top-level tests and suites (nesting 0):
 * node runs one file's top-level tests one after another, so the sum is the
 * file's own time, apart from its imports, without its subtests counted twice.
 * Paths are as node reports them; the caller makes them relative.
 */

type Event = { type: string; data?: { name?: string; nesting?: number; file?: string; details?: { duration_ms?: number } } };

type FileTime = { ms: number; tests: number; failed: number; slowest: { name: string; ms: number }[] };

export default async function* timings(source: AsyncIterable<Event>): AsyncGenerator<string> {
  const files = new Map<string, FileTime>();
  for await (const event of source) {
    if (event.type !== "test:pass" && event.type !== "test:fail") continue;
    const d = event.data ?? {};
    if (!d.file) continue;
    let f = files.get(d.file);
    if (!f) files.set(d.file, (f = { ms: 0, tests: 0, failed: 0, slowest: [] }));
    if (event.type === "test:fail") f.failed++;
    if ((d.nesting ?? 0) !== 0) continue;
    const ms = d.details?.duration_ms ?? 0;
    f.ms += ms;
    f.tests++;
    f.slowest.push({ name: String(d.name ?? ""), ms: Math.round(ms) });
    f.slowest.sort((a, b) => b.ms - a.ms);
    f.slowest.length = Math.min(f.slowest.length, 3);
  }
  const out = [...files.entries()]
    .map(([file, t]) => ({ file, ms: Math.round(t.ms), tests: t.tests, failed: t.failed, slowest: t.slowest }))
    .sort((a, b) => b.ms - a.ms);
  yield JSON.stringify({ files: out, failed: out.filter((f) => f.failed > 0).map((f) => f.file) }, null, 1) + "\n";
}
