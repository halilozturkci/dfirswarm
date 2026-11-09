# Ledger

6 entries: 0 events, 0 indicators, 1 findings, 1 searches that found nothing, 2 coverage records, 2 answers. Written by the harness from `record`, `attest` and `dispute`; cite it as `ledger/ledger.md`.

## Timeline

| # | Time (UTC) | Event | Source | Evidence | By |
| --- | --- | --- | --- | --- | --- |

## Indicators

| # | Indicator | Source | Evidence | Confidence | By |
| --- | --- | --- | --- | --- | --- |

## Findings

- **#1** the record question 2 asks for [answers 2; observed] _(high)_ — source: the disk — evidence: a registry key — refs: `job:j000001/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000001: command `search` in unknown (unknown), ok — by a0

## Answers

- **#2** question:2 (established): Established: the record question 2 asks for [attested by a2] _(high: The cited entries are direct.)_ — rests on: E-1 — still open: none open — would change it: a second source that disagrees — reasoning: E-1 — by a1
- **#5** question:1 (not_determinable) (negative, reviewed by a2): Who logged on cannot be determined from the log _(medium: The cited entries are direct.)_ — rests on: E-4 — still open: none open — would change it: a second source that disagrees — reasoning: E-4 — by a1

## Searched, not found

| # | Looked for | Searched | Query, tool, scope | By |
| --- | --- | --- | --- | --- |
| 3 | an account name for the logon [answers 1] | the log | a search · refs: job:j000002/hits.txt | a0 |

## Coverage records

- **#4** for question:1: proposition: The event question 1 asks about happened [answers 1] [attested by a2] — objects: `input:logs/a.log` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-3, job:j000002/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — no literal form to look for: the fixture's event has no literal form a byte search could find — reviewed by a2: challenged the detection assumptions: the event writes to the objects searched, and they keep it for their whole range; reproduced a decisive check: ran the decisive search again over the same objects: nothing; not tried another route: no second source for the event in the case — by a0
- **#6** for question:2: proposition: The event question 2 asks about happened [answers 2] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — no literal form to look for: the fixture event has no literal form a byte search could find — **unreviewed** — by a0
