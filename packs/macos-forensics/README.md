# macOS Forensics Pack

What a macOS examination needs: where each artefact lives, what it proves, what
parses it, and the traps that make an answer wrong on this platform in
particular.

Depends on the Computer Forensics Base Pack.

## What it carries

**Eight skills**, in six families.

| Family | Skills |
| --- | --- |
| Triage | `triage/system-profile` |
| Artefacts | `artifacts/plists`, `artifacts/fsevents`, `artifacts/knowledgec` |
| Logs | `logs/unified` |
| Persistence | `persistence/mechanisms` |
| Accounts | `accounts/users` |
| File system | `filesystem/apfs` |

**Four tools.** Each says what it read and what it did not, and none turns a failure
into an empty result.

- `plist_read` reads binary and XML property lists with Apple dates converted to UTC.
  It prints no binary value, digest or preview, and withholds a value under a key
  named for a secret (an account plist holds a password verifier): the answer is a
  locator, and values go only to a private file, in a job. One file at a time, with
  counts of what was parsed, failed, skipped over a bound or not reached.
- `fsevents_parse` reads `/.fseventsd` records, 1SLD and 2SLD pages only. It names an
  unsupported page, a gzip member that did not decode, bytes it could not place and an
  incomplete record, with counts per file, member, page and record, and states that
  event ids order records and do not date them.
- `knowledgec_query` reads `knowledgeC.db`: the typed values, the raw and converted
  times, and the rows of `ZSTRUCTUREDMETADATA` and `ZSOURCE` joined from the file's own
  schema. It applies a write-ahead log in a private copy and counts the frames, lists
  every stream, and says when a filter could not be applied. The streams are records of
  application and device state, not of a person.
- `unified_log` runs Apple's `log` on a Mac or Mandiant's pinned `unifiedlog_iterator`
  elsewhere, keeps the reader's whole output, and counts all of it. Its `status` is
  about the run, not about whether the archive was fully decoded.

**One goal template**: `mac-compromise.md`.

**Not in this pack.** A wrapper, recipe or skill for `mac_apt.py` (declared in
`requires/host.json`, installed in the amd64 worker image only); TCC, Keychain,
Gatekeeper and XProtect, Spotlight, Biome and recent-item skills; APFS snapshot content
access. A macOS examination that needs them needs other tools, and the skills say where
they stop.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/macos-forensics
    scripts/swarm.sh start --pack computer-forensics-base,macos-forensics ...

The pack's own tools use the Python standard library only (`plistlib`, `sqlite3`,
`zlib`); the parsers that cover more of this platform are the host programs in
`requires/host.json`, each of them optional and each with the limits its entry states.
