### Fixed: macos-forensics fsevents_parse refuses an unknown flag and reads compressed input on its clock

- `flags` with a name the tool does not know is refused as JSON before anything is
  read (it used to give a complete answer with no record). `flags_unknown` and
  `flags_known` are in the refusal; a hostile list is cut there (the first 20 names,
  each cut at 80 characters, and the count), and a `flags` that is not a list of
  strings is refused too.
- The bytes after the last gzip member, and the rest of a file after a member that
  failed to decode, are counted from the file's size and are not read. The clock
  is looked at once per 1 MiB of input inside a member, so one member whose
  deflate stream inflates to nothing is under `max_seconds` too.

### Fixed: macos-forensics plist_read times its walk over directories, and a name of unknown type is not lost

- The walk looks at its clock for directories as well as names: a tree of empty
  directories ends `partial` with `walk_stopped_by_time_limit` at `max_seconds`
  (names are still counted for up to 5 seconds more, as before).
- A name whose type the listing does not give and an lstat cannot find out is
  counted under `entries_unreadable` whatever it is called (it was counted as a
  name that matches nothing, though it may be a directory with plists in it), and
  the answer is not `complete`.

### Fixed: macos-forensics stop signals: a stop after the sweep is a stop of the run, and the start-up window and the held print are stated

- A stop signal that landed in the few bytecodes after a sweep (plist_read,
  fsevents_parse, knowledgec_query, unified_log) went to the last-resort handler and
  the answer said the tool was stopped "before it had read anything" although the
  sweep had finished. The hold now starts inside the sweep's own `try`, so such a
  signal gives the normal answer with `interrupted` set. The last-resort text says
  whether the sweep had begun, and no longer says nothing was read when something was.
- The README and the four manifests say that a stop in the first tens of
  milliseconds, before the file has run, ends a tool with no answer (measured on
  plist_read in a container with one CPU: 19 of 80 SIGTERMs at 0-250 ms, all within the
  first 42 ms), and that the final print is made with the stop signals held, so a reader
  of stdout that stops reading a full pipe can be answered only by SIGKILL. The header
  comment of the STOP block says the same (the code of the block is unchanged).
- Listed, not fixed: knowledgec_query's `schema.fingerprint` is a sha256 over the
  sorted column names, the `/var/folders` alias `tmp-id-<12 hex>` is an unsalted digest,
  and unified_log's `walk_tree` names the first offender in raw sort order. All three
  are size, time or order oracles.

### Fixed: macos-forensics knowledgec_query keeps its private copies in a directory of its own and names a sidecar it cannot use

- Outside a job the private copies are made in `work/<id>/.knowledgec-stage`, a
  directory the tool makes (mode 0700, with a marker file), and the dead-copy sweep
  runs only there. An agent's directory in `work/<id>` is never swept: one with a
  stale `.lock`, or an empty one with a dead process number in its name, was removed
  before. A copy with files and no lock file whose run is over is not removed and is
  named in `source_used.copies_without_lock_not_removed` (path and size). Copies an
  earlier version left in `work/<id>` are no longer swept.
- A `-wal`, `-shm` or `-journal` name is found with lstat. One that is a link, a FIFO,
  a socket, a directory or a device is not opened and not followed (a linked `-wal`
  had its target copied into the private copy), is named in
  `source_used.sidecars_not_used` and in `problems`, and the answer is not
  `complete`. The sidecars that are copied are opened without waiting and without
  following a link, and the WAL is counted from the private copy.

### Fixed: macos-forensics unified_log reads lines with a bound, ends the reader's whole tree and names a staged copy left by a killed run

- The reader's output is read with a line bound of 8 MiB and the clock is looked at
  for every bounded read. A longer line is counted with its length
  (`decoded_coverage.lines_over_cap`, `longest_line_bytes`, `first_lines_over_cap`),
  is not parsed, stays in the output file as the reader wrote it, and makes the
  status `partial`; one line of 300 MB cost 1.2 GB of memory before.
- The reader is started with `PR_SET_PDEATHSIG` on Linux. On a stop signal or its own
  time-out the tool also ends the processes that appeared in its process group after
  the reader started and whose parent is gone (a descendant that forked twice was out
  of reach of the walk down the process tree), when the tool leads its group as the
  harness starts it. A process that was in the group before is never touched, the start
  time is read again before each signal, and `reader_processes_left` says what was done.
- An `out_dir` that holds `.logarchive-input` from a run that was killed is still
  refused, and the refusal now says it is a staged copy of the evidence, with its file
  count and bytes. Nothing is swept.

### Fixed: macos-forensics fix round 1: clocks over raw input, refused writes, staging looks, last resort

- fsevents_parse keeps `max_seconds` over an uncompressed record file: the read, the skip over
  bytes that are not a page and the drain are looked at once per 1 MiB (a 16 GiB tail with
  `max_seconds` 5 took 150 s). The rest of a file after an unsupported page is counted
  from its size and not read. A record that cannot be written to `out_file` is a failed
  write ("could not write"), no longer "read failed", and is not counted.
- knowledgec_query no longer says a valid database "is not a SQLite database" when SQLite could not
  write the index of the private copy (disk full, file too large): the refusal says the staging
  area could not be written, with the SQLite error name. A row that cannot be written stops the
  run with that said. The looks at the directory of private copies take at most 10,000
  entries and 5 s (`sweep_cut`), the WAL frame count is under the clock, and copies an
  earlier version left in `work/<id>` are named (`copies_in_work_dir_not_swept`), not swept.
- unified_log: staging, the comparison of members, the copy of each file and the census are
  under the clock; files are opened without waiting and without following a link. A line
  of exactly 8 MiB is read (the cap does not count the newline), a line nested a million
  levels deep is a line that did not parse, and the reader's pre-exec step ends at once if
  the tool is already gone.
- All four tools: after an unexpected error the pager's temporary file is removed and a
  partial `out_file` (or the reader's output) is named; plist_read stops with a clear
  message when a row cannot be written. fsevents_parse's `run.py` is executable again.
- Left (P3): the hash of the staged database after a rollback journal is bounded by the
  time the copy took, not by a clock of its own.

### Fixed: macos-forensics fix round 2: the count of rows written is the lines in the file

- knowledgec_query and fsevents_parse flush every row they write to `out_file` (plist_read
  already did), so a write the filesystem refuses is found at its row and the count
  (`rows_written`, `entry_count`, `record_count`) equals the lines in the file; before, the
  failure surfaced at a later buffer flush and the count was larger than the file by up to
  hundreds of rows. After the first failed write fsevents_parse writes nothing more, and
  both tools close the file quietly. Tests in `tests/pack-macos-written-counts.test.ts`
  sweep a tmpfs of 4 KiB to 16 MiB and `ulimit -f` of 2 to 2,048 blocks for all four
  tools (unified_log counts the lines of the reader's own file).
- knowledgec_query: a storage error is also named when the `stream` pattern is run; a cut look
  at the directory of private copies or at `work/<id>` makes the answer partial and is named
  in `problems`; a dead copy with more than 10,000 files is named, not removed.

- Fix round 3, the result-file pager (the default when no `out_file` is given), the same cause
  as round 2 in the block the three paging tools share: its rows were buffered, so a refused
  write was found rows after the count had passed it, and `fail()` left the half-written dot
  temporary in `tool-output`. Now the pager of knowledgec_query, fsevents_parse and plist_read
  flushes every row and counts it only then (`in_file`), so fsevents_parse's `record_count`
  equals the lines of the result file it names; and `fail()` removes the temporaries of every
  pager. A refused write to the result file in knowledgec_query and plist_read says the result
  file was not made, names the partial copy it removed (`removed_result_file`) and the rows it
  held (`rows_in_removed_file`), and no longer says the counted rows are in it. The tests in
  `tests/pack-macos-written-counts.test.ts` run the pager path under a tmpfs of 4 KiB to 1 MiB
  and `ulimit -f` of 2 to 2,048 blocks for the three tools: count equals lines, no dot
  temporary left (they fail on the earlier code).
