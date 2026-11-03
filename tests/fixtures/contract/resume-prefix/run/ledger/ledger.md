# Ledger

10 entries: 0 events, 0 indicators, 3 findings, 0 searches that found nothing, 1 limitations, 3 coverage records, 3 answers; 1 corrected by a later entry, which stands. Written by the harness from `record`, `attest` and `dispute`; cite it as `ledger/ledger.md`.

## Timeline

| # | Time (UTC) | Event | Source | Evidence | By |
| --- | --- | --- | --- | --- | --- |

## Indicators

| # | Indicator | Source | Evidence | Confidence | By |
| --- | --- | --- | --- | --- | --- |

## Findings

- **#1** the record question 1 asks for [answers 1; observed] _(high)_ — source: the disk — evidence: a registry key — refs: `job:j000001/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000001: command `search` in unknown (unknown), ok — by a0
- **#3** a logon at 09:14 for question 2 [answers 2; observed] _(high)_ — source: the log — evidence: line 12 — refs: `job:j000002/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000002: command `search` in unknown (unknown), ok — by a0
- **#6** the logon at 09:14 was the second account [answers 2; observed] _(high)_ — source: the disk — evidence: an account record — refs: `job:j000001/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000001: command `search` in unknown (unknown), ok — by a0

## Answers

- **#2** question:1 (established): Established: the record question 1 asks for [attested by a2] _(high: The cited entries are direct.)_ — rests on: E-1 — still open: none open — would change it: a second source that disagrees — reasoning: E-1 — by a1
- **#5** question:2 (partial): A logon at 09:14; the account is not established **(superseded by #7)** [attested by a3] _(medium: The cited entries are direct.)_ — rests on: E-3 — limitations: E-4 — still open: none open — would change it: a second source that disagrees — reasoning: E-3 shows the logon and its time; the account is open (E-4) — by a1
- **#7** question:2 (established): The second account, at 09:14 (corrects #5) [attested by a2] _(high: The cited entries are direct.)_ — rests on: E-3, E-6 — still open: none open — would change it: a second source that disagrees — reasoning: E-3 and E-6 — by a1

## Searched, not found

| # | Looked for | Searched | Query, tool, scope | By |
| --- | --- | --- | --- | --- |

## Limitations

| # | Not established | Reason | Scope | What was tried | By |
| --- | --- | --- | --- | --- | --- |
| 4 | The log keeps no account name for question 2 [answers 2] | unavailable | the log | its field list | a0 |

## Coverage records

- **#8** for question:1: proposition: The event question 1 asks about happened [answers 1] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — no literal form to look for: the fixture event has no literal form a byte search could find — **unreviewed** — by a0
- **#9** for question:2: proposition: The event question 2 asks about happened [answers 2] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — planned routes not examined: input:logs/a.log (read the log): no job under the question's leads declared it, and no coverage record names it — no literal form to look for: the fixture event has no literal form a byte search could find — **unreviewed** — by a0
- **#10** for question:2: proposition: The event question 2 asks about happened [answers 2] — objects: `input:logs/a.log` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: job:j000002/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — planned routes not examined: input:disk.E01 (read the disk's account records): no job under the question's leads declared it, and no coverage record names it — no literal form to look for: the fixture event has no literal form a byte search could find — **unreviewed** — by a0
