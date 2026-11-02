### Added: linux-forensics `audit_events` reads the audit log with the standard library

- Read an explicit, ordered set of acquired `audit.log` files (rotations named by the caller, gzip allowed) and
  group the records into events by their `audit(<seconds>.<fraction>:<serial>)` stamp, across rotation boundaries.
  A group carries its locators, record types, the grammar's numeric fields, the lengths of command lines, `cwd`
  and PATH names, and the parts that are missing (a PATH short of `items=`, EXECVE arguments short of `argc`, an
  execve with no EXECVE). Command lines, `exe`, `cwd`, PATH names and typed names are never printed; the whole of
  every line goes to a 0600 file on `write_text` in a secret-output job.
- Report the rotation inventory, gaps between files and in rotation numbers, serial restarts, `lost=` counters and
  DAEMON records, and runs of time that go backwards. Uids and gids are named only from identity files of the evidence.

### Added: linux-forensics `audit_events` can compare itself with `ausearch` on a sample

- `compare_ausearch` runs the installed `ausearch` (`-if <sample> -r`, never `-i`) on the first 2000 lines of the first
  file and says `agree`, `disagree` or `not_run`, with the installed version and the differences counted and never shown.
  A one-record probe must come back through `-if <file> -r` first. The program runs in the tool's own process group:
  a deadline, an output past 32 MiB or a stop signal ends it and what it started. It is declared secret output.

### Added: linux-forensics `linux_persistence` lists where a root starts programs from

- List cron tables, system and user systemd units (the homes of the passwd and every directory under `home/`, so a deleted
  account's home is read), drop-ins in file-name order with the assignments that reset a list, enablement links, masks and aliases
  (listed, never followed), `.path` and `.socket` units, `rc.local`, `init.d` and XDG autostart, each with file, line and byte
  offset and every place tried named. Configuration and execution are separate fields (execution only from journal rows the
  caller declares), the effective state is always unresolved with the reasons, and a copy without links says enablement cannot
  be read. Command lines and environments, and key names systemd does not define, are lengths; the text goes to a 0600 file on
  `write_text` in a secret-output job. `persistence/mechanisms` names the tool.
