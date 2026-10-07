# Mobile Forensics Pack

iOS and Android: what kind of extraction you were handed, what it can and
cannot show, and where each answer lives.

Depends on the Computer Forensics Base Pack and on the macOS Forensics Pack:
iOS is macOS's sibling, and `plist_read` and `unified_log` from that pack are
needed for much of what an iPhone stores.

## What it carries

**Ten skills**, each a short decision leaf (three kilobytes at most) that points to
a second-level leaf only when the case needs it: `extractions/what-you-have` (start
here) and `extractions/backup-detail`; `apps/databases` and `apps/fragments`;
`ios/artifacts`, `ios/containers-and-time`, `ios/biome-segb` and `ios/unified-logs`;
`android/artifacts`; `location/sources`.

**Three tools.** Each says in its manifest what it measures and what it does
not, and each returns its whole result: an inline page and, when there is more,
a file the answer names. None of them decrypts anything or reads a password.
`sqlite_freespace` and `protobuf_peek` read no `-wal` or `-journal`; `manifest_db`
opens a `Manifest.db`'s in a working copy.

- `manifest_db` lists an iOS backup's map: for each file id its domain, relative
  path, kind, the metadata of its keyed archive, and the state of the blob the id
  names (present, missing, a directory, a link it does not follow, or refused: an
  id is joined to a path only when it is 40 hexadecimal digits). It reads the
  backup's plain files (`Manifest.plist`, `Info.plist`, `Status.plist`) for the
  encryption flag, the device, the backup's version and date and whether it
  finished. The encryption state is three-valued: a flag that is missing is
  `unknown`, not unencrypted. An encrypted backup is not reported as empty: its
  `Manifest.db` is listed when it opens as SQLite (with `payload_encrypted` set),
  and when it does not the answer says the listing is not available and what the
  file was. Key material (the key bag, the manifest key) is a presence and a
  length, never a value. Times are converted from the epoch you name (`unix` by
  default, or `apple`), with the raw seconds beside them: the tool does not guess.
- `sqlite_freespace` reads the free space of a SQLite database's main file
  (freelist pages, the unallocated gap of a page, the freeblock chain) and returns
  where each text fragment is: page, kind of region, byte offset (read back from
  the file and compared), length and encoding. It does not return a row, a column,
  a table or a time, and it does not return the text: the text is written only on
  `write_values: true`, in a job run with `secret_output: true`, to a file that job
  seals. It reads UTF-8 and UTF-16 text (the byte order the header declares) and
  says so. A `-wal` or a `-journal` beside the file is listed and not read, so what
  only the WAL holds is absent, and the status is partial while one holds bytes.
- `protobuf_peek` reads the wire structure of a protobuf message without its
  schema: field numbers, wire types, absolute offsets and field paths, numbers
  raw with their zigzag reading. It does not say what a field means. A group makes
  a message `unsupported`, a structural error names its offset, and a bounded
  window is read, not a whole file. Only a top-level varint is printed: the text of
  a string, the bytes of a bytes field, a number under a length-delimited field and
  a fixed-width value go to the job's sealed values file on request.

**Five recipes**, each saying what it prepares (`purpose` in its `recipe.json`).
Two inventories: `ios-filesystem` turns a full-file-system tar into a structural
mobile catalogue without extracting it (it parses no artefact content, keeps every
member name as the archive spelled it and every occurrence of a duplicated name),
and `android-backup` reads an adb-backup header and inventories every member of an
unencrypted payload of a version it reads (1 to 5), within a decompression budget.
Two broad extractions, run by the kickoff: `ios-ileapp` hands a whole iOS full
file-system acquisition (a tar or a zip) to iLEAPP and keeps every report it
writes, a TSV per artefact with records, its timeline and the HTML, under
`ileapp/`; `android-aleapp` does the same for an Android full file-system
acquisition with ALEAPP. Each reads the program's own log for one outcome per
module (`modules.tsv`: completed, no_record, errored or unknown) and says
`complete` only when the program exited 0, wrote a report, its log was recognised
and no module errored or is unknown: a module that errored while the others wrote
their reports leaves the run `partial`. A module with no report is `no_record`,
which does not show the artefact is absent from the phone. Their `exclusions` say
what they do not hold, and a run stopped before its end says partial. And one
declared and never run: `android-backup-apps`, the broad extraction an adb backup
would need, which the image cannot do (ALEAPP reads a file-system layout, an adb
backup keeps each app under `apps/<package>/`), so the harness records the
preparation of every adb backup declined with that reason instead of a parse that
would find next to nothing. Every recipe says exactly what it did not cover in
`coverage.json`. What the harness does with a broad extraction (its receipts, the
lead that offers one, the hold on a negative that claims absence while it runs) is
ADR 0013's "A source's broad extraction before a negative on it".

**One goal template**: `phone-examination.md`.

## What this pack does not provide

**No decryption.** An encrypted iOS backup or an encrypted Android `.ab` payload
is identified and its readable parts are listed; opening it needs a decryption
backend that this pack does not carry, and the pack reads no password. The pack
does not choose one. Say in the report what could not be read and why, and ask the
operator for what the case lawfully supplies.

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
