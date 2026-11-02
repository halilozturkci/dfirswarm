### Fixed: macos-forensics fsevents_parse refuses an unknown flag and reads compressed input on its clock

- `flags` with a name the tool does not know is refused as JSON before anything is
  read (it used to give a complete answer with no record). `flags_unknown` and
  `flags_known` are in the refusal.
- The bytes after the last gzip member, and the rest of a file after a member that
  failed to decode, are counted from the file's size and are not read. The clock
  is looked at once per 1 MiB of input inside a member, so one member whose
  deflate stream inflates to nothing is under `max_seconds` too.
