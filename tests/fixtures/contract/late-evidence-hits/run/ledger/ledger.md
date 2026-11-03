# Ledger

13 entries: 0 events, 0 indicators, 1 findings, 2 searches that found nothing, 5 coverage records, 4 answers; 3 corrected by a later entry, which stands. Written by the harness from `record`, `attest` and `dispute`; cite it as `ledger/ledger.md`.

## Timeline

| # | Time (UTC) | Event | Source | Evidence | By |
| --- | --- | --- | --- | --- | --- |

## Indicators

| # | Indicator | Source | Evidence | Confidence | By |
| --- | --- | --- | --- | --- | --- |

## Findings

- **#4** a remote tool installed at 09:14 [answers 2; observed] _(high)_ — source: the log — evidence: line 12 — refs: `job:j000002/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000002: command `search` in unknown (unknown), ok — by a0

## Answers

- **#3** question:1 (bounded_negative) **(negative, unreviewed)**: No evidence of the event of question 1 was found on the disk **(superseded by #10)** _(medium: The cited entries are direct.)_ — rests on: E-2 — still open: none open — would change it: a second source that disagrees — reasoning: E-2 — by a1
- **#6** question:2 (established): A remote tool, installed at 09:14 **(superseded by #11)** [attested by a3] _(high: The cited entries are direct.)_ — rests on: E-4, E-5 — still open: none open — would change it: a second source that disagrees — reasoning: E-4, searched as E-5 — by a1
- **#10** question:1 (bounded_negative) (negative, reviewed by a2): No evidence of the event of question 1 was found on the disk or in the proxy export (corrects #3) _(medium: The cited entries are direct.)_ — rests on: E-9 — still open: none open — would change it: a second source that disagrees — reasoning: E-9 — by a1
- **#11** question:2 (established): A remote tool, installed at 09:14, as the log shows (corrects #6) [attested by a3] _(high: The cited entries are direct.)_ — rests on: E-4, E-5 — still open: none open — would change it: a second source that disagrees — reasoning: E-4, searched as E-5 — by a1

## Searched, not found

| # | Looked for | Searched | Query, tool, scope | By |
| --- | --- | --- | --- | --- |
| 1 | the event of question 1 [answers 1] | inputs/disk.E01 | a search · refs: job:j000001/hits.txt | a0 |
| 8 | the event of question 1 in the proxy export: alice is a proxy user there, not the event [answers 1; irrelevant #3] | the proxy export | read whole · refs: import:ev-0001/proxy.csv | a0 |

## External material

| # | What | Class | From | Provenance | By |
| --- | --- | --- | --- | --- | --- |
| 7 | Evidence added after the kickoff (inventory revision 1): 1 file(s) as import:ev-0001: the proxy export the network team kept | acquired_evidence | /tmp/dfirswarm-contract-late/proxy.csv | store/imports/ev-0001/material.json and manifest.json; store journal line 0 · refs: import:ev-0001/proxy.csv · sha256 716c23c1fedefb54c1fa420e0e8431faec2d5a56b4a28414be489d1ebc69e754 | system |

## Coverage records

- **#2** for question:1: proposition: The event question 1 asks about happened **(superseded by #9)** [answers 1] [attested by a2] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-1, job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — looked for: "alice"; store sweep clean: 2 object(s), 16 bytes searched for "alice" — reviewed by a2: challenged the detection assumptions: the event writes to the objects searched, and they keep it for their whole range; reproduced a decisive check: ran the decisive search again over the same objects: nothing; not tried another route: no second source for the event in the case — by a0
- **#5** for question:2: proposition: The event question 2 asks about happened [answers 2] — objects: `input:logs/a.log` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-4, job:j000002/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — looked for: "bob-laptop"; store sweep clean: 2 object(s), 16 bytes searched for "bob-laptop" — **unreviewed** — by a0
- **#9** for question:1: proposition: The event question 1 asks about happened (corrects #2) [answers 1] [attested by a2] — objects: `input:disk.E01`, `import:ev-0001/proxy.csv` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-1, E-8, job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 05e89c1548cc79f91f7a4645b11c4ff8007c143dff0204f669d6e4d625fbee76 — **coverage partial** (not covered: import:ev-0001/proxy.csv (no job behind the record declared it, or a directory holding it, or an object with its digest)) — looked for: "alice"; store sweep clean: 3 object(s), 54 bytes searched for "alice"; found in objects the record names (does the answer account for them?): "alice" in import:ev-0001/proxy.csv, 1 time, first at byte 21 — reviewed by a2: challenged the detection assumptions: the event writes to the objects searched, and they keep it for their whole range; reproduced a decisive check: ran the decisive search again over the same objects: nothing; not tried another route: no second source for the event in the case — by a0
- **#12** for question:2: proposition: The event question 2 asks about happened [answers 2] — objects: `input:logs/a.log` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: job:j000002/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 05e89c1548cc79f91f7a4645b11c4ff8007c143dff0204f669d6e4d625fbee76 — **coverage complete** — no literal form to look for: the fixture event has no literal form a byte search could find — **unreviewed** — by a0
- **#13** for question:2: proposition: The event question 2 asks about happened [answers 2] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 05e89c1548cc79f91f7a4645b11c4ff8007c143dff0204f669d6e4d625fbee76 — **coverage complete** — planned routes not examined: input:logs/a.log (read the log): no job under the question's leads declared it, and no coverage record names it — no literal form to look for: the fixture event has no literal form a byte search could find — **unreviewed** — by a0
