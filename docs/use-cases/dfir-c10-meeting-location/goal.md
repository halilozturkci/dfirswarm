## Goal

Max is suspected of belonging to a foreign intelligence group and has agreed to meet an unknown party somewhere. His system was imaged after he left; the first investigation found nothing. This is the only system he uses. Find out what Max uses to hide his activity, restore the methods and tools (data recovery and carving may be needed), then find where they are meeting.

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/Case4.E01`, a 16.3 GB E01 image of Max's Windows machine. `inputs/CASE.md` is the published brief.

### Questions the report has to answer

1. Where is the evidence: what is Max using to hide his activity (wiping, encryption, portable or private browsing, virtual machines, steganography, timestomping, cleaners)? Name each method and the traces it left.
2. Restore the methods, tools and techniques he uses: recover the deleted or wiped tools and configurations (carving, $UsnJrnl, $LogFile, shadow copies), with hashes and what each does.
3. Where are they meeting: what was Max searching for, from the browser history and search records (including recovered ones)?
4. The encrypted file with the meeting location: which file, how it was decrypted (key, password, tool), and the meeting location.
5. From where did Max get the meeting location (URL, chat, email, download)?
6. Reflection: what this case taught about anti-forensics on Windows, the timeline of Max's activity, and anything else.

### Ground rules

- `inputs/` is read-only and stays byte-for-byte what it was. Never `cat`
  or `read` an image whole. Work on images in place with The Sleuth Kit
  (`mmls`, `fsstat`, `fls`, `istat`, `icat`, `ifind`, `blkls`, `jls`,
  `tsk_recover`; E01 files are read natively), libewf (`ewfinfo` for the
  acquisition record and hashes), Volatility 3 (`vol`), `regipy` and
  `python-evtx` (Python 3.12), `strings`, `sqlite3`, `exiftool`, `openssl`,
  `gpg`. There is no root: no mounting, no `sudo`.
- If `SWARM.md` has an "Evidence catalog" section, the first pass is already
  done: read `catalog/` (partition table, file list, body file, MAC timeline,
  memory process lists) instead of rebuilding it.
- Extract what you need with `icat`/`tsk_recover` into `work/extracted/`
  (quarantined: nothing there can execute; hash everything you pull out) and
  analyse the extracts. Your own scratch goes under `work/<your id>/`.
- Every dated event you establish goes into the ledger with `record`
  (kind=event, ISO 8601 UTC, source, evidence); indicators as kind=ioc,
  conclusions as kind=finding. The timeline and the report cite
  `ledger/ledger.md`.
- Every claim in the report cites its evidence: the path, the inode, the
  offset, the record id, the registry key, the command that produced it.
  A claim without evidence is a hypothesis and is labelled as one.
- Write every post and file in English. Use tables where they help.
- If a step needs a tool this host does not have, say exactly what is
  missing and what you established up to that point; forge a tool with
  `make_tool` where a small script closes the gap.

## How to divide the work

Nobody has been given a job. Read the goal and the evidence catalog, see on
the board what your peers have taken, decide what you are going to do, and
call `name(name, doing)` to say what to call you and what you are taking on.
Fill what nobody has taken; if two of you want the same thing, settle it in a
post. Say so again when you change course.

Somebody has to keep the timeline from `ledger/ledger.md`, and somebody has to
verify every citation and assemble `work/report.md` and post the sign-off the
definition of done requires — agree between you who does, early, because the
run is not finished until both exist. Do not all run the same command on the
same image: read the catalog and the board first.

## Definition of done

`work/report.md` exists, answers every question under headings `## 1.`, `## 2.`, `## 3.`, `## 4.`, `## 5.`, `## 6.`,
every answer cites evidence, the critic has posted a sign-off on the board
naming what they verified, `work/timeline.md` holds the merged timeline as a
table with at least 20 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

Each answer under `## 1.` to `## 5.` rests on the ledger: it cites (`#<seq>`) a finding
recorded with its refs (the run's objects it rests on), or a search that found
nothing (`kind=absence`) saying where it looked and how.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --report work/report.md --sections 1,2,3,4,5`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 20`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 10`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`
