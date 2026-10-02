// Semantic parity of the archive-only optimization against the unchanged
// original replacement function, including overlap and inserted-digest cases.
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const [original, optimized, privateDir, resultPath] = process.argv.slice(2);
const getBlock = file => {
  const text = readFileSync(file, 'utf8');
  const start = text.indexOf('  const digestList = [...sensitiveDigests];');
  return text.slice(start, text.indexOf('  let files = 0;', start));
};
async function load(file, label) {
  const code = `export function probe(text: string, digests: string[], ids: Record<string,string>) {
    const sensitiveDigests = new Set(digests);
    type Replaced = Record<string, unknown>;
    const hideDigest = (sha: string, why: string) => ids[sha] ?? ('hidden-' + sha.slice(0, 12));
    ${getBlock(file)}
    const changes: Replaced[] = [];
    return { value: replaceDigests(text, changes), changes };
  }`;
  const p = `${privateDir}/${label}-probe.ts`;
  writeFileSync(p, code, { mode: 0o600 });
  return (await import(pathToFileURL(p).href)).probe;
}
const baseline = await load(original, 'original');
const candidate = await load(optimized, 'optimized');
const a = 'a'.repeat(64), b = 'b'.repeat(64), c = 'a'.repeat(63) + 'b';
const fixtures = [
  { name: 'no digest', text: 'plain JSON text', digests: [a, b], ids: {} },
  { name: 'repeated exact digests', text: `${a}:${b}:${a}`, digests: [b, a], ids: {} },
  { name: 'embedded in longer hex run', text: `1${a}2`, digests: [a], ids: {} },
  { name: 'overlapping same digest', text: 'a'.repeat(65), digests: [a], ids: {} },
  { name: 'overlapping different digests ordered', text: a + 'b', digests: [c, a], ids: {} },
  { name: 'inserted following digest', text: a, digests: [a, b], ids: { [a]: 'hidden-' + b, [b]: 'replacement' } },
  { name: 'inserted already processed digest', text: a, digests: [b, a], ids: { [a]: 'hidden-' + b, [b]: 'replacement' } },
  { name: 'uppercase remains case sensitive', text: a.toUpperCase(), digests: [a], ids: {} },
  { name: 'Unicode and adjacent matches', text: `ö\u2028${a}${b}\u2029`, digests: [a, b], ids: {} },
];
const results = fixtures.map(f => ({ name: f.name,
  equal_value_and_metadata: JSON.stringify(baseline(f.text, f.digests, f.ids)) === JSON.stringify(candidate(f.text, f.digests, f.ids)) }));
const result = { at: new Date().toISOString(), node: process.version, cases: results,
  all_passed: results.every(r => r.equal_value_and_metadata),
  scope: 'finite meaningful parity probes; not an exhaustive proof or production change' };
writeFileSync(resultPath, JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result));
if (!result.all_passed) process.exitCode = 1;
