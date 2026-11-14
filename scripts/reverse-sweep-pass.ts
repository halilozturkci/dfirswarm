/**
 * One pass of an addition's reverse sweep, as a process of its own
 * (extensions/store-sweep.ts execReverseSweepPass): the hub, or whoever
 * asks, gives the addition and the pass's budget on stdin as one JSON
 * object ({sandbox, addition: {seq, hash, import}, budget: {maxBytes,
 * maxMs}}); this lists the store, reads what the addition's last pass left,
 * searches the import's objects for the strings of the coverage records
 * standing at the addition (reverseSweepPassFor), keeps what each object
 * holds of each string and the long lists under ledger/sweeps/, and
 * answers on stdout with one JSON object ({line, continues, stats}): the
 * line as it is written (bounded), or null when nothing is left, for the
 * asker to chain onto ledger/sweeps.jsonl. It writes no line itself. The
 * search is here so that the asker's loop is never in it.
 *
 * When the asker goes away the pass stops at the next look (what it kept
 * so far is kept, and the next pass reads none of those objects again).
 */
import { reverseSweepPassFor, sweepLineAsWritten } from "../extensions/store-sweep.ts";

const chunks: Buffer[] = [];
for await (const c of process.stdin) chunks.push(c as Buffer);
const request = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { sandbox: string; addition: { seq: number; hash: string; import: string }; budget?: { maxBytes?: number; maxMs?: number } };

// An asker that died is not answered: the pass ends, and what it found so far was kept as it went.
const parent = process.ppid;
const watch = setInterval(() => {
  if (process.ppid !== parent) process.exit(3);
}, 1000);
watch.unref();

const result = await reverseSweepPassFor(request.sandbox, request.addition, request.budget ?? {});
// The line as it is written: what it found in a file of its own when it is long (boundHits), so that the answer stays small.
if (result.line) result.line = await sweepLineAsWritten(request.sandbox, result.line);
await new Promise<void>((done) => process.stdout.write(JSON.stringify(result), () => done()));
process.exit(0);
