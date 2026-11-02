### Fixed: library finish-line checks no longer fail an honest run or pass a broken one

- Leave the panes' `work/.tmp` out of the execute-bit check, in the library
  README and in the six goals that carry it, as `work/.toolchain` already was.
- Make the sample-static-triage inventory check fail when `jq` or
  `inputs.json` is missing, where it used to count one row and pass. Let the
  unallocated-carving offset check accept `675840 (0xA5000)`, `**675840**`,
  `0X` offsets and offsets under 100, and keep rejecting text.
- Read every table for a timeline or carvings header (CloudTrail, Microsoft 365,
  identity-provider, SIEM/EDR and Windows event-log goals), not the first one
  that looks like a header. Skip the manifest re-hash for a dump directory
  holding a file over 256 MiB or more than 1 GiB in all, so the check stays
  inside its 30 s limit; the goals say the report must record that hash.
- Correct the accuracy notes: Lambda event names carry a version suffix,
  Workspace `password_edit` is in the user-accounts audit, Security 1100 is
  also logged on a normal shutdown, the sector after an NTFS file system is its
  backup boot sector, a plain copy of `ntds.dit` raises no ESENT event, and
  `oledump.py` is not part of oletools.
- Run the changed checks against honest and broken fixtures
  (`tests/library-checks.test.ts`).

### Fixed: a default compact line raised to the warning line now lands above it

- When the default compact threshold is raised to an explicit warning (or
  notice) line, it becomes one token above that line instead of equal to it,
  so the warning stage still fires before compaction. A warning line at the
  most the window holds is refused, since nothing above it fits.
