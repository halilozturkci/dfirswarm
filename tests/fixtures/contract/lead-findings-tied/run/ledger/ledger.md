# Ledger

10 entries: 0 events, 0 indicators, 6 findings, 0 searches that found nothing, 2 coverage records, 2 answers. Written by the harness from `record`, `attest` and `dispute`; cite it as `ledger/ledger.md`.

## Timeline

| # | Time (UTC) | Event | Source | Evidence | By |
| --- | --- | --- | --- | --- | --- |

## Indicators

| # | Indicator | Source | Evidence | Confidence | By |
| --- | --- | --- | --- | --- | --- |

## Findings

- **#1** the first method [answers 1; observed] [attested by a3] _(high)_ — source: the disk — evidence: a record — refs: `job:j000001/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000001: command `search` in unknown (unknown), ok — by a0
- **#2** the second method [answers 2, 1; observed] [attested by a3] _(high)_ — source: the disk — evidence: a record — refs: `job:j000001/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000001: command `search` in unknown (unknown), ok — by a2
- **#3** the first method was run twice [answers 2; supports #1; observed] [attested by a3] _(high)_ — source: the disk — evidence: a record — refs: `job:j000001/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000001: command `search` in unknown (unknown), ok — by a2
- **#4** the account used [answers 2; observed] [attested by a3] _(high)_ — source: the disk — evidence: a record — refs: `job:j000001/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000001: command `search` in unknown (unknown), ok — by a2
- **#5** the third method [answers 2, 1; observed] _(high)_ — source: the disk — evidence: a record — refs: `job:j000001/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000001: command `search` in unknown (unknown), ok — by a2
- **#6** a fourth method, seen once [answers 1; observed] _(high)_ — source: the disk — evidence: a record — refs: `job:j000001/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000001: command `search` in unknown (unknown), ok — by a0

## Answers

- **#7** question:2 (established): The account, and three methods [attested by a3] _(high: The cited entries are direct.)_ — rests on: E-2, E-3, E-5, E-4 — still open: none open — would change it: a second source that disagrees — reasoning: E-2, E-3, E-5 and E-4 — by a1
- **#8** question:1 (established): The first method [attested by a2] _(high: The cited entries are direct.)_ — rests on: E-1 — still open: none open — would change it: a second source that disagrees — reasoning: E-1 — by a1

## Searched, not found

| # | Looked for | Searched | Query, tool, scope | By |
| --- | --- | --- | --- | --- |

## Coverage records

- **#9** for question:2: proposition: The event question 2 asks about happened [answers 2] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — no literal form to look for: the fixture event has no literal form a byte search could find — **unreviewed** — by a0
- **#10** for question:1: proposition: The event question 1 asks about happened [answers 1] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — no literal form to look for: the fixture event has no literal form a byte search could find — **unreviewed** — by a0
