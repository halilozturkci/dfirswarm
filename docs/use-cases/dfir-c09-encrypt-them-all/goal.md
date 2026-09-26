## Goal

Jane's system holds data encrypted with different methods; decrypt all of it. Three parts: (1) "Lost in Space" — the communication started with a README in the user's Documents, encrypted with AES and no password known; search the caches for the communication or recover the file from before it was encrypted; it leads to the next part. (2) "Do Not Be Deceived!" — a volume named R2D2 with BitLocker full-disk encryption; decrypt it and find what was hidden inside. (3) "Your Focus Determines Your Reality." — a message to an unknown party used a public/private key pair; extract the keys from the image and decrypt the message, which is in the keys file in the user's Downloads; say what it was used for.

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/AF-Case2.E01`, a 7.9 GB E01 image of Jane's Windows machine. `inputs/CASE.md` is the published brief.

### Questions the report has to answer

1. Lost in Space: the README — where it is, how it was encrypted, how you recovered the plaintext or the password (browser or application caches, shell and PowerShell history, an earlier copy in $LogFile/$UsnJrnl/volume shadow copies/unallocated space), and what it says.
2. Do Not Be Deceived: the R2D2 BitLocker volume — where it is, how the recovery key or password was found, how the volume was decrypted (state exactly what the host lacks if a step could not be done here), and what was hidden inside.
3. Your Focus Determines Your Reality: the key pair — where the keys were, the keys file in Downloads, the decrypted message, and what it was used for.
4. The timeline of Jane's encryption activity and the communication, and how the three parts connect.
5. Approach, tools forged, what remains uncertain, and anything else the examiner should know.

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

Seats are assigned in `SWARM.md` (change them on the board if you see a
better split). The critic and editor verifies every citation before it goes
into `work/report.md`, assembles the report from the seats' notes and the
ledger, and posts the sign-off the definition of done requires. The timeline
seat builds `work/timeline.md` from `ledger/ledger.md`. Do not all run the
same command on the same image: read the catalog and the board first.

## Seats

This case is three investigations in one image, so it runs nine seats. Take
the one `SWARM.md` gives you and say on the board what you are doing; if two
seats collide on a file, the one that owns it keeps it.

- Disk and file system: partitions and volumes (including the R2D2 volume and any BitLocker metadata `mmls`/`fsstat` reveal), $MFT, the file list, deleted entries; owns `work/disk.md`.
- Recovery from file system journals: $LogFile, $UsnJrnl, volume shadow copies and unallocated space, for earlier copies of anything encrypted later; owns `work/recovery.md`.
- Browser and application caches: browsers, mail, messaging and cloud clients, their caches, histories and databases, for the communication behind part 1; owns `work/caches.md`.
- Registry and execution: SYSTEM/SOFTWARE/SAM/NTUSER, prefetch, shimcache, amcache, jump lists, LNK, scheduled tasks and services, to say what was run and when; owns `work/artifacts.md`.
- Shell and user activity: PowerShell and cmd history, console host history, RunMRU, typed paths, recent documents, the Downloads and Documents folders as the user left them; owns `work/user-activity.md`.
- BitLocker and volume encryption (part 2): the R2D2 volume, its recovery key or password wherever it was kept (registry, a printed key file, the user's own notes, Active Directory artefacts), the decryption itself, and what is inside; says exactly what this host cannot do; owns `work/bitlocker.md`.
- Key material and cryptography (parts 1 and 3): the key pair and the keys file in Downloads, AES and OpenSSL/GPG artefacts, the decryption of the README and of the message, with the commands that prove each; owns `work/crypto.md`.
- Timeline and ledger: records every dated event peers report with `record kind=event` and writes `work/timeline.md` from `ledger/ledger.md`.
- Critic and editor: verifies every citation, challenges weak claims on the board, assembles `work/report.md` and posts the sign-off.

## Definition of done

`work/report.md` exists, answers every question under headings `## 1.`, `## 2.`, `## 3.`, `## 4.`, `## 5.`,
every answer cites evidence, the critic has posted a sign-off on the board
naming what they verified, `work/timeline.md` holds the merged timeline as a
table with at least 15 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

Each answer under `## 1.` to `## 3.` rests on the ledger: it cites (`#<seq>`) a finding
recorded with its refs (the run's objects it rests on), or a search that found
nothing (`kind=absence`) saying where it looked and how.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5; do grep -q "^## $n\." work/report.md || exit 1; done`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --report work/report.md --sections 1,2,3`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 15`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 5`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`
