### Fixed: ransomware-response cuts the rows shown inline by size as well as by count

In `ransom_note_scan` and `encrypted_survey`, a `limit` of 1,000,000 over a tree of
100,000 or more note-named (or candidate) files put every row in the answer,
which was then serialised and read back: tens of megabytes of stdout and a
resident set that grew with the table (445 MiB and 65 MB of stdout, 349 MiB and
51 MB, on 100,000 files). The rows a table shows inline now stop at about 512 KiB
as well as at `limit`; the cut is named in `pages.<table>.inline_cut_by_size` and
the whole table stays in the paging file `pages.<table>.all_results` (43 MiB and
0.64 MB, 29 MiB and 0.66 MB, on the same trees). The two `LosslessPage` classes
of the pack are the same text and a test holds them equal. Each tool's manifest
says so in `limit`; PARSER stays `/3` (the census and values formats do not change).
