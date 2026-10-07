---
id: filesystem/timestamps
title: NTFS time sets that disagree
when: Two time sets of one record disagree, or you are about to quote an NTFS time.
needs: [filesystem/mft]
tools: [mft_records, usn_journal]
requires_host: []
---

Use when you compare or quote NTFS times. Not for reading the record (`filesystem/mft`), the zone (`registry/clock`) or the change journal itself (`filesystem/journals`).

- $STANDARD_INFORMATION (type 16) is what the shell shows and the public API sets. $FILE_NAME (type 48) is usually written when the name is created, renamed or moved, and not on ordinary writes. Software can change either: neither set is a clock you can trust or exclude.
- `mft_records` flags are indicators: `si_created_before_fn_created`, `si_modified_before_si_created` (common after a copy), `si_times_identical`, and `si_times_whole_seconds`, which is printed but not in the `timestomp_only` filter because current software writes any fraction and some ordinary paths write none. Compare against the $FILE_NAME set `file_name_times_source` names, and report both sets with their raw FILETIME.
- Ordinary causes of a difference: a copy or restore that keeps the modified time, archive extraction, installers, backup and synchronisation tools, a rename or a move. Write the strongest benign explanation beside the observation.
- What corroborates: `usn_journal` records of the entry (`BASIC_INFO_CHANGE` or a rename near the time a value was stored), and independent times for the same file elsewhere (an application's record, Prefetch, another copy). `$LogFile` is not read by this pack (`filesystem/journals`).
- Times are UTC FILETIMEs at 100 ns; convert to a local zone only with the rules of that date (`registry/clock`). Last-access updates can be disabled or delayed by configuration, so an access time is not evidence of an access.
- A record with `structural_errors`, or an unresolved attribute list, is not compared as if it were whole.

Sensitive output: only time fields are read here; `mft_records` `with_resident` returns file content, so leave it off or run it as a job with `secret_output: true` (`filesystem/mft`).

Shows: both sets as stored, and which flags fired. Does not show: manipulation, which set is true, or when a value was changed. Record: raw FILETIMEs of both sets, the flags, the benign explanation considered, and the corroboration you looked for and what it returned.
