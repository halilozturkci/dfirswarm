# Mobile Forensics Pack

iOS and Android: what kind of extraction you were handed, what it can and
cannot show, and where each answer lives.

Depends on the Computer Forensics Base Pack and on the macOS Forensics Pack:
iOS is macOS's sibling, and `plist_read` and `unified_log` from that pack are
needed for much of what an iPhone stores.

## What it carries

**Eighteen skills**: seventeen short decision leaves (800 tokens at most) that point
to a second-level leaf only when the case needs it: `extractions/what-you-have`
(start here), `extractions/backups` (local and cloud backups, derivatives, encrypted
backups) with `extractions/backup-detail` as the second-level leaf for reading a
backup answer, and `extractions/protection-state`; `apps/databases`, `apps/fragments`,
`apps/messaging` and `apps/identity-containers`; `ios/artifacts`,
`ios/containers-and-time`, `ios/biome-segb`, `ios/unified-logs` and
`ios/knowledgec-activity`; `android/artifacts`; `location/sources`;
`media/provenance`; `validation/parser-coverage`; and the pack's router,
`mobile/router` (at most 400 tokens), which names the seventeen by the question each
answers, holds no rule, and is the one line a run shows for the pack when its skills
index is over budget.

**Seven tools.** Each says in its manifest what it measures and what it does
not, and each returns its whole result: an inline page and, when there is more,
a file the answer names. Only `backup_decrypt` decrypts anything or reads a password, and only in a job run as secret output.
`sqlite_freespace` and `protobuf_peek` read no `-wal` or `-journal`; `manifest_db`
opens a `Manifest.db`'s `-wal` and `-journal` in a working copy, with the file.

- `manifest_db` lists an iOS backup's map: for each file id its domain, relative
  path, kind, the metadata of its keyed archive, and the state of the blob the id
  names (present, missing, a directory, a link it does not follow, or refused: an
  id is joined to a path only when it is 40 hexadecimal digits). It reads the
  backup's plain files (`Manifest.plist`, `Info.plist`, `Status.plist`) for the
  encryption flag, the device, the backup's version and date and whether it
  finished (`completion`: finished, not_finished or unknown, from Status.plist's
  `SnapshotState`; a backup that did not finish makes the status partial). The
  encryption state is three-valued: a flag that is missing is
  `unknown`, not unencrypted. An encrypted backup is not reported as empty: its
  `Manifest.db` is listed when it opens as SQLite (with `payload_encrypted` set),
  and when it does not the answer says the listing is not available and what the
  file was. Key material (the key bag, the manifest key) is a presence and a
  length, never a value. `contains` and `domain` filter the path and domain as the
  answer prints them, so a withheld component cannot be guessed through a filter.
  A name that holds 42 or more digits with at most three characters that are not
  letters or digits between two digits (any separator, none, full-width digits, a key
  split across path components) is a placeholder, as is a path over 8,192
  characters, which is not judged. Times are converted from the epoch you name (`unix` by
  default, or `apple`), with the raw seconds beside them: the tool does not guess,
  and `epoch.consistency` counts the times that fall after the backup's own date or
  before 2007 under the epoch applied (the wrong epoch is a 31-year shift). The
  Files table is read in row order, so a damaged index page does not cost the
  listing, and a `Manifest.db` cut inside its last page is said and partial. Every
  SQLite statement is ended at `max_seconds` and by a stop signal (the count of the
  rows gets a tenth of the time, and an answer without it says so); a name column
  is read to its first 8,193 characters, and a row whose metadata is not in the
  answer for any reason makes the status partial.
- `backup_materialise` lays an unencrypted (or already decrypted) iOS backup out as
  a derivative under `$OUT/derivative/files/<domain>/<relativePath>`, for a selection
  (domains, paths, or `all: true`; never the whole map by default), each file tied to
  its Manifest row: the file id, the domain and path as printed and as base64 of
  their bytes, the row number, the Size the Manifest records, the SHA-256 of the blob,
  and the state of the blob (copied, missing, a directory, a link it does not follow,
  a FIFO, refused). The whole account is a result file, one line per row. A hostile
  `relativePath` (`..`, an absolute path, a NUL, a component over 255 bytes) is
  rejected and listed; two rows on one name (duplicate, case-folded, a file and a
  directory) each get their own name and say so; a second run never replaces a file.
  It does not decrypt and is not an acquisition: the derivative is not the phone.
  `copy_content` (false by default, a plan) writes content and is a secret-output
  mode: a job run as secret output only; a name shaped like a recovery password is
  the placeholder everywhere and its real name is only in the 0600 values file.
- `backup_decrypt` decrypts an encrypted iOS backup (iOS 13 or later) with the library
  `iphone_backup_decrypt` 0.11.2, pinned with hashes in `requires/`, from `password_ref`: a
  0600 file the job was given. The library runs in a child process; this tool only looks at
  the file, and the child reads it, so the password is on no command line, in no
  environment variable, on no output channel, in no path or file (an exception of the
  library is reported by its class name). The manifest declares `secret_output: required`.
  The decrypted `Manifest.db` and one decrypted file per file row go under
  `$OUT/backup_decrypt-<id>/decrypted/<xx>/<file id>` (mode 0600, never replaced), with a
  result file of one line per Manifest row. `verified` means the decrypted `Manifest.db`
  opens and every file row has the length the Manifest records as its Size; it does not
  say the content is what the phone held. `wrong_secret` (only the library's IncorrectPassphraseError), `secret_unavailable`,
  `unsupported_format`, `backend_unavailable`, `failed` (any other library error while
  opening) and `partial` are told apart; before each file the tool runs the library's own
  row query on a copy of the map, and a row it does not return alone is
  `ambiguous_selection` and not decrypted. The library was exercised here
  only through a stand-in for its three documented calls; it has not been run on a real
  backup. Its licence label (MIT) is the owner's: PyPI carries none; its LICENSE.txt at v0.11.2 is MIT with a BSD-3-Clause section for google_iphone_dataprotection.py (as a verifier read it; the author did not).
- `heic_inspect` makes a JPEG or PNG preview of a HEIC or HEIF original under
  `$OUT/heic_inspect` and ties it back to the original: the size and SHA-256 of
  both, the dimensions, the image count, which item is primary, and the backend's
  settings and errors. One backend per run, recorded and never a silent fallback:
  `heif-convert` (in the tool's process group) or `pillow-heif` (in a child process).
  A pixel or size limit is checked on the original's own boxes and a conversion past
  it is refused before any backend starts. A bounded standard-library walk of the
  ISO-BMFF boxes (`ftyp` brands, then under `meta` the handler, primary item, items,
  locations, properties and references) reports hostile sizes and counts with their
  offsets. Metadata comes from the original with `exiftool`, never from the preview:
  the answer holds presence and counts, and the values go only to the 0600 file of a
  `write_values` job run as secret output.
- `ab_layout` maps an unencrypted Android `.ab` backup (header versions 1 to 5)
  onto the layout ALEAPP reads and calls the result what it is: a derivative of an
  adb backup, in a banner file and in the answer, never an acquisition. The tar is
  streamed once under a decompression budget, and the end of the zlib stream, the
  tar's two end blocks and anything after them are checked. `apps/<package>/<domain>/...`
  members go to `data/data/<package>/...` by a mapping table in the manifest (its basis
  is the author's recollection of AOSP's FullBackup tokens, not checked against the
  source); `_manifest`, the SQLite companions and per-member provenance are kept.
  Unknown domains, links, devices, directories and `shared/` are listed and not
  extracted; hostile names are rejected and listed. `copy_content` (false by default,
  a plan) is a secret-output mode, and an encrypted payload is refused after its header.
- `sqlite_freespace` reads the free space of a SQLite database's main file
  (freelist pages, the unallocated gap of a page, the freeblock chain) and returns
  where each text fragment is: page, kind of region, byte offset (read back from
  the file and compared), length and encoding. It does not return a row, a column,
  a table or a time, and it does not return the text: the text is written only on
  `write_values: true`, in a job run with `secret_output: true`, to a file that job
  seals. It reads UTF-8 and UTF-16 text (the byte order the header declares) and
  says so. A `-wal` or a `-journal` beside the file is listed and not read, so what
  only the WAL holds is absent, and the status is partial while one holds bytes.
  `contains` only marks the rows of the values file (it needs `write_values`):
  the file holds a row for every fragment, each with `match` 1, 0 or 2 (not decided
  in time), so its size and digest do not depend on the expression; the answer
  lists every fragment and does not say which matched. It is accepted only as an
  expression of bounded cost (no `*`, `+` or `{m,}`, no nested repeat, no
  lookaround, no back reference, at most 256 steps), which keeps the time it takes
  small per character (at most about 0.06 s of CPU per 32,768 characters, for an
  expression that repeats one class of characters 250 times), but not small for a
  large free space: 1.4 s against 0.16 s for 1.3 MB of digits against letters, and
  the job's duration can say that much of the hidden text is of a class the
  expression matches, up to about 7 s of CPU (10.5 s on a loaded machine). The answer does not say it: the expression
  has a work budget in sizes the answer shows (a character of a fragment times the
  expression's cost, and 1,000 steps for every fragment it is called on), a fragment past it is marked `match` 2 and the status is
  partial, the same for any text of those sizes, and the clock of `max_seconds`
  does not run while the expression does, for 12 seconds at most in all (a run with
  `contains` ends within `max_seconds` plus that). `complete` means every page was
  accounted for: b-tree and free pages are read, the others must be overflow pages a
  cell of a b-tree names; a page no structure owns (what a header with its freelist
  fields zeroed leaves) is read as free space and makes the status `partial`, with the reason in `status_basis` and `problems`. A job that asks for `write_values` is run
  as secret output.
- `protobuf_peek` reads the wire structure of a protobuf message without its
  schema: field numbers, wire types, absolute offsets and field paths, numbers
  raw with their zigzag reading. It does not say what a field means. A group or a
  structural error makes the window `not_accepted` (one status, no count, in the
  same words for every such window; what the parser found is in the sealed values
  file), and a bounded window is read, not a whole file. Only a top-level varint is printed, and only for
  a window that is a message (it parses whole, is not printable text and meets a
  stated rule, which is stricter for a window aimed with `offset` or `length`, so
  that a window aimed at a string or a token is not read back as numbers): the text of a
  string, the bytes of a bytes field, a number under a length-delimited field and a
  fixed-width value go to the job's sealed values file on request. The shown-window
  rates it states hold at any `max_fields`: an aimed window that the field budget
  stopped is not shown. The size of its values file follows how JSON writes the text
  of a string field (a quote, a backslash or a control character adds bytes; nothing
  for a token of letters and digits), and the time of a parse follows the fields it
  read, even for a window it does not show.

**What a requesting agent can see.** The answer, and the job's file list with each
file's size and digest. The sealed values file lies under `store/` of the sandbox,
which an agent's VM mounts read-only: an agent that opens it reads every row, the
values and `match` included. The measures of these tools protect what is shown
without anyone opening the file (the answer, its status and counts, the size and
digest); they do not stop an agent that deliberately opens the sealed file, and the
tools do not decide whether it may: that is the sandbox's mounts.

**Five recipes**, each saying what it prepares (`purpose` in its `recipe.json`).
Two inventories: `ios-filesystem` turns a full-file-system tar into a structural
mobile catalogue without extracting it (it parses no artefact content, keeps every
member name as the archive spelled it and every occurrence of a duplicated name),
and `android-backup` reads an adb-backup header and inventories every member of an
unencrypted payload of a version it reads (1 to 5), within a decompression budget.
Both follow the tar header by header beside the tar library and say `complete`
only when the two end-of-archive blocks came and the library listed as many members as
there are headers: a tar cut at a member boundary, or ended quietly by a header the
library refuses, is `partial`, with where; a zero block with a header after it is
read past, as GNU tar does, and said (partial), and data after the end blocks is not
read and said. `ios-filesystem` decodes a compressed tar within an output budget
too (`--max-decompressed-bytes`). Neither writes over an earlier run's
output.
Two broad extractions, run by the kickoff: `ios-ileapp` hands a whole iOS full
file-system acquisition (a tar or a zip) to iLEAPP, or an unencrypted iOS backup
directory to iLEAPP's own backup reader (`-t itunes`; the backup is not laid out first,
an encrypted backup or one whose `IsEncrypted` cannot be read is `failed` before iLEAPP
starts, no password option is ever passed, a `backup_materialise` derivative is refused,
and `coverage.json` names the route in `input`), and keeps every report it
writes, a TSV per artefact with records, its timeline and the HTML, under
`ileapp/`; `android-aleapp` does the same for an Android full file-system
acquisition with ALEAPP. Each reads the program's own log for one outcome per
module (`modules.tsv`: completed, no_record, unsupported, errored, errors_logged or
unknown) and says `complete` only when the program exited 0, wrote a report, its
log was recognised and says how many modules it parses and that many started, it
ends with its processing-completed line, no module errored, logged an error or is
unknown, no line outside a module speaks of an error and stderr holds nothing the
log shape does not explain: a module that errored while the others wrote their
reports leaves the run `partial`. A module with no report is `no_record`, which
does not show the artefact is absent from the phone, and an `unsupported` module
is one whose own gate does not take the operating-system version. Their `exclusions` say
what they do not hold, and a run stopped before its end says partial: the program runs in a process group of its own with a time limit (`--max-seconds`), and a stop signal ends it and its children. And one
run on request, not by the kickoff: `android-backup-apps`, which lays an unencrypted adb backup
(header versions 1 to 5) out the way the `ab_layout` tool does (`apps/<package>/<domain>/...` onto
`data/data/<package>/...`; the copy of that logic is in the recipe, a recipe does not import a tool) and runs
ALEAPP over the layout with `-t fs`, with the same `modules.tsv` receipt as `android-aleapp`. Its result is a
derivative of an adb backup, never a file-system acquisition, and says so in `derivative/DERIVATIVE.json`
and in `coverage.json`; the mapping table behind it is the author's recollection of AOSP's FullBackup
tokens and has not been checked against the source. An encrypted backup is refused (failed), a stream
that is not whole (a missing end block, bytes after the end) makes the run partial, and `ab-members.tsv`
lists every member and its state. Every recipe says exactly what it did not cover in
`coverage.json`. What the harness does with a broad extraction (its receipts, the
lead that offers one, the hold on a negative that claims absence while it runs) is
ADR 0013's "A source's broad extraction before a negative on it".

**One goal template**: `phone-examination.md`.

## What this pack does not provide

**Decryption is one backend and one tool.** Only an iOS backup, with `backup_decrypt`,
and only from a password file the operator supplies; the pack breaks or guesses no
password. An encrypted Android `.ab` payload, and a backup from before iOS 13, are
identified and their readable parts listed, not opened. Say in the report what could
not be read and why, and ask the operator for what the case lawfully supplies.

**No claim about a phone's deleted data from a label.** A logical extraction or a
backup has no unallocated space of the device, but the files in it can still hold
deleted records in their own free pages, which `sqlite_freespace` reads for the
main file only. A WAL or a journal beside a database is evidence of its own and is
copied with it; `sqlite_freespace` and `protobuf_peek` read neither.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/macos-forensics
    scripts/pack.sh install packs/mobile-forensics
    scripts/swarm.sh start --pack computer-forensics-base,macos-forensics,mobile-forensics ...
