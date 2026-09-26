# A Mac that was compromised

This machine is believed to have been compromised. Establish what happened on
it, in order, with a citation for every step.

Read the skill index with `skill()` before you start. `triage/system-profile` is
the first ten minutes, and most of what you will read is a binary property list
rather than text.

## Questions

1. The system profile: product version and build, hostname, setup date, the
   timezone you converted every timestamp from, and which volumes of the APFS
   container you examined.
2. Initial access: how the operator first reached this machine, with the
   artefact that shows it and the time in UTC.
3. Persistence: every launch daemon, launch agent, login item, cron entry,
   profile or extension that does not belong, with the file's own modification
   time — or the evidence that nothing was added.
4. Permissions granted: what TCC records as approved for screen recording,
   accessibility, full disk access or the microphone, and when each was granted.
5. Activity: what a person was doing and when, from the unified log and
   knowledgeC, and what places them at the keyboard rather than a job running.
6. File system changes: what was created, renamed or removed, from FSEvents,
   with the anchor you used to place the event ids in time.
7. Snapshots: using a snapshot-capable parser, whether the container holds any,
   and what a previous state shows that the live one does not — or state that
   the available parser cannot answer the question.
8. The timeline in UTC, and what you could not establish.

## Definition of done

`work/report.md` exists and answers questions 1 to 8 under the headings `## 1.`
through `## 8.`. Every claim cites a path with a hash, a plist key, a log
predicate, a knowledgeC stream, or the command that produced it. A critic has
read the report against the board and posted a sign-off as a `result`
post that starts a line with `SIGN-OFF:` and names what they verified. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'UTC' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 8`
- `awk 'FNR==1{r=0} /^tag: result$/{r=1} r&&/^\**SIGN-OFF/{m=1;exit} END{exit !m}' threads/main/*.md`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
