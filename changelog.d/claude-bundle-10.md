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
