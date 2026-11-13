/**
 * Every hash-chained register a run writes under its sandbox, in one place:
 * where the run keeps it, where custody seals its length and head, where a
 * package carries it, how a release binds it, and the chain code that
 * recomputes its lines. The custody seal (scripts/custody.ts), the release
 * (scripts/release.ts, scripts/release-record.ts), the package
 * (scripts/swarm.sh cmd_package, scripts/package-tools.ts) and the checks
 * (custody-verify, swarm.sh verify) cover each; tests/chained-registers.test.ts
 * holds them to it, and fails on a .jsonl the harness names that is in
 * neither list below.
 */

/** How a register's lines chain: each line's hash recomputed by this code (package-tools.ts and custody read them so). */
export type ChainCode =
  /** prev is the sha256 of the raw line before ("" first): the trace. */
  | "trace"
  /** prev is the sha256 of the raw line before (null first): the model gateway's log. */
  | "gateway"
  /** seq from 0, prev the sha256 of the raw line before (null first): the store's journal. */
  | "journal"
  /** protocol.ts ledgerHash: the ledger's entries. */
  | "ledger"
  /** protocol.ts attestationHash and disputeHash: the acts on entries. */
  | "attestation"
  | "dispute"
  /** store-sweep.ts sweepHash: the store sweeps. */
  | "sweep"
  /** leads.ts leadEventHash: the lead register and every register chained with its code (questions, requests, the network, the finish). */
  | "lead";

export type ChainedRegister = {
  /** Where the run keeps it, under its sandbox. */
  rel: string;
  /** What it is, in words. */
  what: string;
  /** Where the custody verdict seals it: its key under `seal` (a dotted path for the network's two). */
  seal: string;
  /** Where a package carries it. */
  package: string;
  /** How a release binds it: in the release's own chains, or through the custody verdict it binds (verifyReleases holds each to that verdict's seal). */
  release: "chains" | "verdict";
  /** The key of the release layouts (runLayout, packageLayout) that names it. */
  layout: string;
  code: ChainCode;
};

export const CHAINED_REGISTERS: readonly ChainedRegister[] = [
  { rel: "traces/events.jsonl", what: "the trace", seal: "trace", package: "trace/events.jsonl", release: "chains", layout: "trace", code: "trace" },
  { rel: "ledger/entries.jsonl", what: "the ledger", seal: "ledger", package: "ledger.jsonl", release: "chains", layout: "ledger", code: "ledger" },
  { rel: "ledger/attestations.jsonl", what: "the ledger's attestations", seal: "attestations", package: "ledger-attestations.jsonl", release: "chains", layout: "attestations", code: "attestation" },
  { rel: "ledger/disputes.jsonl", what: "the agents' disputes", seal: "disputes", package: "ledger-disputes.jsonl", release: "chains", layout: "disputes", code: "dispute" },
  { rel: "ledger/sweeps.jsonl", what: "the store sweeps", seal: "sweeps", package: "ledger-sweeps.jsonl", release: "chains", layout: "sweeps", code: "sweep" },
  { rel: "leads/leads.jsonl", what: "the lead register", seal: "leads", package: "leads.jsonl", release: "verdict", layout: "leads", code: "lead" },
  { rel: "leads/finish.jsonl", what: "the finish register", seal: "finish", package: "finish.jsonl", release: "verdict", layout: "finish", code: "lead" },
  { rel: "questions/questions.jsonl", what: "the question register", seal: "questions", package: "questions.jsonl", release: "verdict", layout: "questions", code: "lead" },
  { rel: "requests/requests.jsonl", what: "the operator requests", seal: "requests", package: "requests.jsonl", release: "verdict", layout: "requests", code: "lead" },
  { rel: "network/grants.jsonl", what: "the network grants", seal: "network.grants", package: "network/grants.jsonl", release: "verdict", layout: "grants", code: "lead" },
  { rel: "network/fetches.jsonl", what: "the network fetches", seal: "network.fetches", package: "network/fetches.jsonl", release: "verdict", layout: "fetches", code: "lead" },
  { rel: "store/journal.jsonl", what: "the store's journal", seal: "journal", package: "store/journal.jsonl", release: "chains", layout: "journal", code: "journal" },
  { rel: "traces/model-gateway.jsonl", what: "the model gateway's log", seal: "model_gateway", package: "trace/model-gateway.jsonl", release: "verdict", layout: "gateway", code: "gateway" },
];

/**
 * Every other .jsonl name the harness writes or reads, with why it is not a
 * hash-chained register of the run that custody seals. A name the harness
 * uses that is in neither list fails tests/chained-registers.test.ts: a new
 * chain is added above, and covered, or here, with why.
 */
export const OTHER_JSONL: Readonly<Record<string, string>> = {
  "operator-audit.jsonl": "the operator's audit, in the runs directory beside the registry, outside the run: custody matches it to the trace",
  "review.jsonl": "the examiner's review, in the runs directory outside the run (reviews/<run>.jsonl); a package carries it as review.jsonl and a release binds it in its chains",
  "review-import.jsonl": "the examiner's import of a technical review, written outside the run",
  "operator-requests.jsonl": "the view of the operator requests, one line per request as it stood: rendered from requests/requests.jsonl, not a chain",
  "operator-hosts.jsonl": "the hosts the operator allowed, a list the job service reads: not a chain (the grants and the trace record each act)",
  ".trace-spill.jsonl": "lines a pane could not hand the collector, gathered into the trace, which custody seals",
  "trace-spill.jsonl": "a seat's spilled trace lines under tool-output/<seat>/, gathered into the trace",
  "system-spill.jsonl": "the harness's spilled trace lines, gathered into the trace",
  "hub-spill.jsonl": "the hub's spilled trace lines, gathered into the trace",
  ".gathered.jsonl": "the suffix of a harness spill's lines kept whole once `swarm.sh stop` chained them into the trace (trace-collector.mjs --gather), each line on the chain marked gathered with its sha256",
  "system-spill.gathered.jsonl": "traces/system-spill.jsonl's lines kept whole beside the trace once the stop chained them into it, and carried by the package: not a chain of its own",
  "hub-spill.gathered.jsonl": "traces/hub-spill.jsonl's lines kept whole beside the trace once the stop chained them into it, and carried by the package: not a chain of its own",
  "telemetry.jsonl": "a running job's samples, kept beside it by the job service: not a record custody seals",
  "same_as.jsonl": "the files of a job that are the same bytes as an earlier job's, listed beside the job; the store journal's job_same_as line carries their count and bytes: not a chain",
  "replies.jsonl": "the hub's answers kept for request-id resends: not a record",
  "fetched.jsonl": "the operator's symbol store's log of what swarm.sh symbols fetch put there, on the host outside every run ($DFIRSWARM_HOME/symbols): not a run's register",
  "trace.jsonl": "the name a download of traces/events.jsonl takes (the dossier, the console), not a register of its own",
  "ledger.jsonl": "the package's name for ledger/entries.jsonl",
  "ledger-attestations.jsonl": "the package's name for ledger/attestations.jsonl",
  "ledger-disputes.jsonl": "the package's name for ledger/disputes.jsonl",
  "ledger-sweeps.jsonl": "the package's name for ledger/sweeps.jsonl",
  "notify-events.jsonl": "the notifications the run sent, a plain log under traces/ (each also on the trace, which custody seals): not a chain",
  "id.jsonl": "$id.jsonl in swarm.sh: the examiner's review, reviews/<run>.jsonl, outside the run",
  "spill-host.jsonl": "the package's name for work/.trace-spill.jsonl",
  "spill-hub.jsonl": "the package's name for traces/hub-spill.jsonl",
  "spill-system.jsonl": "the package's name for traces/system-spill.jsonl",
  "spill-system.gathered.jsonl": "the package's name for traces/system-spill.gathered.jsonl",
  "spill-hub.gathered.jsonl": "the package's name for traces/hub-spill.gathered.jsonl",
  ".jsonl": "a suffix the code joins to a name, not a file",
};

/** A register's sealed value from a verdict's seal, by its seal path. */
export function sealedOf(seal: Record<string, unknown> | null | undefined, path: string): unknown {
  return path.split(".").reduce<unknown>((o, k) => (o && typeof o === "object" ? (o as Record<string, unknown>)[k] : undefined), seal ?? undefined);
}

/** Every basename the list above covers. */
export function coveredNames(): Set<string> {
  const out = new Set<string>(Object.keys(OTHER_JSONL));
  for (const r of CHAINED_REGISTERS) {
    out.add(r.rel.split("/").at(-1)!);
    out.add(r.package.split("/").at(-1)!);
  }
  return out;
}
