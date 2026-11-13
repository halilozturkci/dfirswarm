/**
 * One pass of the store sweep, as a process of its own
 * (extensions/store-sweep.ts execSweepPass): the hub, or whoever asks,
 * gives the coverage records and the pass's budget on stdin as one JSON
 * object ({sandbox, budget: {maxBytes, maxMs}, records: [{seq, hash, refs,
 * result_refs, looked_for}]}); this lists the store, reads each object
 * once for every string no kept result answers (sweepPassFor), keeps its
 * results and the long lists under ledger/sweeps/, and answers on stdout
 * with one JSON object ({lines, stats}): the lines bounded, for the asker
 * to chain onto ledger/sweeps.jsonl. It writes no line itself. The search
 * is here so that the asker's loop is never in it: the run D's hub held
 * twelve sweeps of 212,000 objects in its loop when it died.
 *
 * When the asker goes away the pass stops at the next look (its results so
 * far are kept, and the next pass reads none of those objects again).
 */
import { sweepPassFor, type SweepCoverage } from "../extensions/store-sweep.ts";

const chunks: Buffer[] = [];
for await (const c of process.stdin) chunks.push(c as Buffer);
const request = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { sandbox: string; budget?: { maxBytes?: number; maxMs?: number }; records: SweepCoverage[] };

// An asker that died is not answered: the pass ends, and what it found so far was written as it went.
const parent = process.ppid;
const watch = setInterval(() => {
  if (process.ppid !== parent) process.exit(3);
}, 1000);
watch.unref();

const result = await sweepPassFor(request.sandbox, request.records, request.budget ?? {});
await new Promise<void>((done) => process.stdout.write(JSON.stringify(result), () => done()));
process.exit(0);
