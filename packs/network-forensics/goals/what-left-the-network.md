# What this capture shows

A capture, and the question of who talked to whom, what left, and whether
anything called home.

Read the skill index with `skill()` first. `capture/what-you-have` decides what
any answer can be worth, and it comes before every other question.

## Questions

1. The capture itself: format, link type, snap length, time range, and what the
   capture point and snap length mean for what can be established from it.
2. The shape: top talkers, top destinations, protocols and ports, with byte
   counts each way.
3. Anything periodic: the destination, the interval and how tightly the series
   clusters (`mad_over_median`, not a configured jitter), the span observed, and
   what makes it more than a software update. Say that it stopped only as a
   bounded negative: it needs a declared observation window and a sensor known
   to be recording over it.
4. What can still be established about encrypted sessions: names resolved,
   server names requested, certificates, and the sizes and timing.
5. Outbound volume: which internal host sent most, to where, in what windows.
6. Correlation with the host evidence, including whether a clock offset between
   the capture and the host could be measured from several independent matched
   events (with its uncertainty), or that none could and times were correlated
   over a stated interval.
7. What you could not establish, and what evidence would settle it.

## How to divide the work

**Report author and critic.** Two of you take these roles early with
`name(doing=…)`, and they are different agents. The report author writes the
answers from the ledger, not from memory: compact first, read `ledger`, then
one `record(kind=answer)` per question (`section=question:<n>`) and one each
for `summary` and `narrative`, citing `E-<seq>` for every claim and stating the
confidence and its reason, the contrary evidence, the limitations, what else
could explain it and what would change the answer. When the ledger cannot
answer, reopen the investigation and say so on the board. The critic re-derives
each finding an answer rests on from its sealed refs and records `attest` (what
was re-derived, what only read) or `dispute` (why), then does the same for
every answer. The critic writes no answer; the author attests nothing of their
own. The sign-off is these acts, not a post. Nothing else is assigned.

## Definition of done

`work/report.md` exists and answers questions 1 to 7 under the headings `## 1.`
through `## 7.`. The snap length is stated, and the clock offset is either measured with its
uncertainty or stated as not measurable. The
ledger holds one `answer` entry per question (`question:1` to `question:7`) and
one each for `summary` and `narrative`, with every defect the answers check
names fixed or named by a limitation, and the critic, who wrote none of them,
has recorded `attest` or `dispute` on each answer, saying what they verified.
`inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'snap length|snaplen' work/report.md`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,7,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
