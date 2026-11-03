# Ledger

6 entries: 0 events, 0 indicators, 2 findings, 0 searches that found nothing, 2 coverage records, 2 answers. Written by the harness from `record`, `attest` and `dispute`; cite it as `ledger/ledger.md`.

## Timeline

| # | Time (UTC) | Event | Source | Evidence | By |
| --- | --- | --- | --- | --- | --- |

## Indicators

| # | Indicator | Source | Evidence | Confidence | By |
| --- | --- | --- | --- | --- | --- |

## Findings

- **#1** the employee's account logged on at 09:14 UTC [answers 1; observed] _(high)_ — source: the disk — evidence: a registry key — refs: `job:j000001/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000001: command `search` in unknown (unknown), ok — by a0
- **#3** a remote tool was installed as a service at 10:02 UTC [answers 2; observed] _(high)_ — source: the disk — evidence: a registry key — refs: `job:j000001/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000001: command `search` in unknown (unknown), ok — by a0

## Answers

- **#2** question:1 (established): Established: the employee's account logged on at 09:14 UTC [attested by a2] _(high: The cited entries are direct.)_ — rests on: E-1 — still open: none open — would change it: a second source that disagrees — premises: assuming P-1 (revision 1) — reasoning: E-1 — by a1
- **#4** question:2 (established): Established: a remote tool was installed as a service at 10:02 UTC [attested by a2] _(high: The cited entries are direct.)_ — rests on: E-3 — still open: none open — would change it: a second source that disagrees — premises: P-1 assumed (revision 1) — reasoning: E-3 — by a1

## Searched, not found

| # | Looked for | Searched | Query, tool, scope | By |
| --- | --- | --- | --- | --- |

## Coverage records

- **#5** for question:1: proposition: The event question 1 asks about happened [answers 1] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — no literal form to look for: the fixture event has no literal form a byte search could find — **unreviewed** — by a0
- **#6** for question:2: proposition: The event question 2 asks about happened [answers 2] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — no literal form to look for: the fixture event has no literal form a byte search could find — **unreviewed** — by a0
