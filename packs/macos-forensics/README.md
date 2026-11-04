# macOS Forensics Pack

What a macOS examination needs: where each artefact lives, what it proves, what
parses it, and the traps that make an answer wrong on this platform in
particular.

Depends on the Computer Forensics Base Pack.

## What it carries

**Nineteen skills**, in seven families: a decision-rule leaf for each question,
second-level leaves a leaf points to ("only if") for the reference material, and the router
`macos/router` (at most 500 tokens; the prompt shows this one line for the pack when the run's index is over its budget, and it names every leaf).

| Family | Skills |
| --- | --- |
| Triage | `triage/system-profile`; `triage/clocks-hardware` (zone, epochs, hardware generation) |
| Artefacts | `artifacts/plists`, `artifacts/plists-archives-dates`; `artifacts/fsevents`, `artifacts/fsevents-dating`; `artifacts/knowledgec`, `artifacts/knowledgec-fields-time` |
| Logs | `logs/unified`; `logs/unified-readers` (readers, staging, retention levels) |
| Persistence | `persistence/mechanisms`; `persistence/login-items-quieter` |
| Accounts | `accounts/users`; `accounts/attribution-remote` |
| File system | `filesystem/apfs`; `filesystem/apfs-recovery`; `filesystem/apfs-encryption` |
| Security | `security/keychains` (identification, and opening with the case's password) |

**Ten tools.** Each says what it read and what it did not, and none turns a failure
into an empty result. Every answer carries `status` (`complete`, `partial` or `failed`)
and `status_basis`; each tool has a clock of its own below its time limit and, once its
sweep has started, ends on SIGTERM, SIGINT or SIGHUP with one JSON answer
(`interrupted`, exit 128 plus the signal), what it staged removed and the reader it
started ended. A stop signal in the first tens of milliseconds, before the tool's file
has run (the start of the interpreter, the compiling of the file, the imports above its
stop handlers), ends it with no answer at all; that window is stated, not closed. The
final print is made with the stop signals held, so that the document is whole: if
whatever reads a tool's stdout stops reading a full pipe, only SIGKILL ends the tool
(the harness ends a tool with a SIGKILL of its group).

- `plist_read` reads binary and XML property lists with Apple dates converted to UTC.
  It prints no binary value, digest or preview, and withholds a value under a key
  named for a secret (an account plist holds a password verifier): the answer is a
  locator, and values go only to a private file, in a job run as secret output. A file
  that does not parse is a row with the kind of error, never the file's text. One file
  at a time, with counts of what was parsed, failed, skipped over a bound or not reached.
- `fsevents_parse` reads `/.fseventsd` records, 1SLD and 2SLD pages only. It names an
  unsupported page, a gzip member that did not decode, bytes it could not place and an
  incomplete record, with counts per file, member, page and record, and states that
  event ids order records and do not date them. Its paths pass the shared boundary, and
  its `contains` is a restricted regular expression matched on the path as printed.
- `knowledgec_query` reads `knowledgeC.db`: the typed values, the raw and converted
  times, and the rows of `ZSTRUCTUREDMETADATA` and `ZSOURCE` joined from the file's own
  schema. It applies a write-ahead log in a private copy and counts the frames, lists
  every stream, and says when a filter could not be applied or the clock stopped it
  (`resume`). Every string passes the shared boundary. The streams are records of
  application and device state, not of a person.
- `unified_log` runs Apple's `log` on a Mac or Mandiant's pinned `unifiedlog_iterator`
  elsewhere, keeps the reader's whole output, and counts all of it. Its `status` is
  about the run, not about whether the archive was fully decoded; the preview passes
  the shared boundary and the reader's own output file does not.
- `macos_tcc` reads one `TCC.db` (the system one or a user's) through a private copy of it and its sidecars, with the
  write-ahead log applied there and a read-only authorizer. It keeps the columns of the schema it finds raw, decodes only
  the `auth_value` and `client_type` numbers that are written down (with the raw number beside), gives `last_modified` and
  `last_reminder` as the row's last write and never as a grant time, keeps a managed row (`policy_id`) apart, and shows the
  code-signing requirement by length only. A sidecar that is a link or a FIFO is named and not followed.
- `macos_login_items` resolves a `backgrounditems.btm` or `BackgroundItems-v*.btm` keyed archive into items, with the
  path of references behind each property, the archive's state fields raw, data (bookmark, alias) by presence and length
  only, and a row with a reason for every reference it cannot resolve (dangling, cyclic, over the depth or node bound).
  A registered item is not a running one.
- `safari_history` reads Safari's `History.db` through a private copy (the WAL applied there): one entry per visit, the
  raw Apple-absolute time beside its UTC reading, URL query values withheld by shape, and the whole URL written only with
  `write_values` in a job run as secret output.
- `segb_read` decodes the framing of Biome's SEGB1 and SEGB2 files (frames, offsets, state, the two container times) and
  shows a payload only as protobuf tags. The layouts are from public notes and are not checked here against Apple's own or
  against a sample file; the answer says so.
- `apfs_inventory` runs `fsapfsinfo` on a container image, keeps its whole output on disk and reads it as container and
  volume sections. It says in every answer that no snapshot is enumerated, no object is extracted and no password is
  passed (the reader takes one only on its command line).
- `keychain_open` opens a login or System keychain (a file that begins with `kych`) when the case supplies its
  password or the SystemKey file as a job input file, and writes every item, metadata and value, to one 0600 file
  in a job run as secret output (the tool declares `secret_output: required`). The password goes to the reader as a
  function argument from the file, never on a command line or in the environment. The answer tells the outcomes
  apart (opened, partial, wrong secret, unsupported format, damaged, reader unavailable, clock, signal), counts
  records per class, decrypted and not, and gives the file's size and sha256; it prints no name, value or hash of
  one. The Local Items store (`keychain-2.db`) is answered `unsupported_format`. No password is guessed or cracked.

- `macos_triage` runs the pinned `mac_apt.py` (1.33.2, amd64 worker image only) in the input mode the caller names (AFF4,
  AXIOMZIP, DD, DMG, E01, MOUNTED, SPARSE, UAC, VMDK or VR; a mismatch with the object is refused before the program starts),
  keeps its logs and output whole under a run directory of its own, and gives each plugin `parsed`, `empty`, `unsupported` or
  `failed` from mac_apt's own log, never from its exit code (mac_apt exits 0 after errors it has logged). A FileVault password
  is only a sealed file handed to mac_apt as `-pf`, and the tool declares `secret_output: required`. The `macos-artefacts`
  recipe (`purpose: broad_extraction`) does the same over an image or a mounted folder it recognises, writes `coverage.json`
  first and an index, and cannot be complete for the FAST or ALL sets. What was read and what was not: the argument shape and
  the texts of the start, plugin start, plugin end, plugin exception and finish log lines come from the 1.33.2 source; mac_apt
  was never run here, so the prefix of a log line, the wording behind `empty` and `unsupported` and the per-plugin file names
  are unverified, and the tests use stand-in programs. On arm64, where mac_apt is not installed, the tool answers `failed`
  with the packaging reason and the recipe's detect exits 1.

The boundary is the windows-forensics pack's block, copied byte for byte (a test holds
the copies equal): an allow-list per field type, a deny-list for free text and a second
check written apart. It works by shape, so a secret of another shape (a plain password, a
passphrase, a UUID-shaped key, a BitLocker recovery key, anything under 16 characters in a name) is printed, and
a file whose secrets matter is read in a job run with `secret_output: true`.

**One goal template**: `mac-compromise.md`.

**Not in this pack.** A skill of its own for `mac_apt.py` (`macos_triage` and the `macos-artefacts` recipe run it; it is
declared in `requires/host.json`, installed in the amd64 worker image only); Gatekeeper and
XProtect, Spotlight, Biome and recent-item skills, and TCC and background-item skills
(`macos_tcc` and `macos_login_items` have a naming edit in the persistence leaf, not a
leaf of their own); APFS snapshot content access. A macOS examination that needs them
needs other tools, and the skills say where they stop.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/macos-forensics
    scripts/swarm.sh start --pack computer-forensics-base,macos-forensics ...

The pack's own tools use the Python standard library only (`plistlib`, `sqlite3`,
`zlib`); the parsers that cover more of this platform are the host programs in
`requires/host.json`, each of them optional and each with the limits its entry states.
