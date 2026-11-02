### Fixed: macos-forensics fsevents_parse refuses an unknown flag and reads compressed input on its clock

- `flags` with a name the tool does not know is refused as JSON before anything is
  read (it used to give a complete answer with no record). `flags_unknown` and
  `flags_known` are in the refusal.
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
