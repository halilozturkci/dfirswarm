/**
 * The store sweeps read again under this harness's rules (rereadSweeps), as
 * a process of its own (extensions/store-sweep.ts execRereadSweeps): the hub
 * gives the run's directory on stdin as one JSON object ({sandbox}); this
 * reads the ledger and the sweeps, sorts each record's hits anew or searches
 * its objects again within the sweep's budget, writes the lines under the
 * sweeps' lock (a lock on disk, which the hub's own writes take too), and
 * answers on stdout with the pass ({rules, records, cleared, added}) for the
 * asker to say. A hub that starts on a store of 212,000 objects is not in
 * that search.
 *
 * When the asker goes away the pass stops at the next look: what was
 * written stands, and the next pass reads again only what was not.
 */
import { rereadSweeps } from "../extensions/store-sweep.ts";

const chunks: Buffer[] = [];
for await (const c of process.stdin) chunks.push(c as Buffer);
const request = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { sandbox: string };

const parent = process.ppid;
const watch = setInterval(() => {
  if (process.ppid !== parent) process.exit(3);
}, 1000);
watch.unref();

// The trace's line and the board's post are the asker's (announceReread): it is the hub, whose identity they carry.
const result = await rereadSweeps(request.sandbox, { announce: false });
await new Promise<void>((done) => process.stdout.write(JSON.stringify(result), () => done()));
process.exit(0);
