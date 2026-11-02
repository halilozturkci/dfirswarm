### Added: linux-forensics `audit_events` reads the audit log with the standard library

- Read an explicit, ordered set of acquired `audit.log` files (rotations named by the caller, gzip allowed) and
  group the records into events by their `audit(<seconds>.<fraction>:<serial>)` stamp, across rotation boundaries.
  A group carries its locators, record types, the grammar's numeric fields, the lengths of command lines, `cwd`
  and PATH names, and the parts that are missing (a PATH short of `items=`, EXECVE arguments short of `argc`, an
  execve with no EXECVE). Command lines, `exe`, `cwd`, PATH names and typed names are never printed; the whole of
  every line goes to a 0600 file on `write_text` in a secret-output job.
- Report the rotation inventory, gaps between files and in rotation numbers, serial restarts, `lost=` counters and
  DAEMON records, and runs of time that go backwards. Uids and gids are named only from identity files of the evidence.
