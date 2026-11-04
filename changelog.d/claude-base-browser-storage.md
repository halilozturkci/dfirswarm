### Added: computer-forensics-base inventories a browser's LevelDB and IndexedDB with `browser_storage`, over the pinned ccl_chromium_reader

`browser_storage` reads a Chromium or Electron LevelDB directory (an IndexedDB, Local Storage or Session Storage) with `ccl_chromium_reader` 0.3.18, which it
runs as a program of its own in the `ccl_indexeddb_dump` venv, and answers with the databases, object stores, key types, the puts, deletes, distinct keys and
current keys of each store, a locator (file, offset, sequence number, state) for every record it shows, and a bounded preview of each store's first current
records after the shared withholding. In a job run as secret output, `write_values` writes every selected record whole (the decoded value and the record's
bytes) to a mode 0600 file under `$OUT` with a header line and an end line, and the answer then carries no value. The new leaf `data/browser-storage` names the
tool, the INDEX and the router list it (a dozen `title` and `when` lines elsewhere are shorter to hold the index at 999 of 1,000 tokens), and
`ccl_indexeddb_dump` is no longer in `unreferenced_ok`.

A venv that is missing, is not the pinned reader or cannot import it is `failed` with `unavailable: true`, never an empty inventory. A file the reader cannot
read to its end is named with its stage and the class of its error, the records it gave before are kept, the other files are still read, and the status is
`partial`; so are an entry under a data file's name that is a symbolic link, a FIFO or a directory (refused, never opened), a MANIFEST that cannot be read, the
2,000,000-record cap, the reader's clock (`max_seconds`, at most 100 seconds) and a values file that stopped at its 1 GiB quota or has no end line. More than
256 MiB of data files is refused before anything is read. Neither the reader nor the tool verifies the CRC32C of log records or table blocks, and the answer says
so; values kept in blob files are counted as not decoded, and Local Storage and Session Storage records are shown as text and not interpreted.

The reader reads past some damage without an error: a log record cut inside its data, a spanning record that never ends and a length that runs past its write batch
were each read to the end as a whole file (measured). The tool runs the reader's iteration of log files and table blocks with the formats' rules applied, so the first
inconsistency stops that file (`partial`, with the problem from a fixed list and its offset), a batch is counted whole or not at all, and a table block compressed
in a way other than none or snappy is named and not read.

Two further defects of the reader were measured and are handled, not hidden. The reader decodes a negative 32-bit integer one too high (it reads -1 as 0), so the tool
decodes that V8 tag as V8 defines it; and the reader's `backing_store_schema_version` is never filled (it looks bytes keys up as strings), so the tool reads the
schema version from the metadata record itself.

Withholding is by shape and a secret of another shape is printed. Measured on 1,000 random plants of each shape in preview slots (the Wilson upper bound at
95%): AWS key ids, JWTs, PEM keys, `Password=` and `password: "..."` pairs, `ghp_` tokens and 40-digit hex strings none printed (at most 0.4% each); a random
base64 text of 16 bytes 15.3% (at most 17.7%), of 20 bytes 17.4% (19.9%), of 32 bytes 1.2% (2.1%); user-info whose password holds an `@` 3.3% (4.6%); a key id
split by NUL characters 8.1% (10.0%), by zero-width spaces 6.7% (8.4%), and a token in UTF-16 text read as one-byte 4.0% (5.4%). NUL and zero-width characters
are removed from a printed text. A file whose secrets matter is read in a `secret_output` job.

`ccl_simplesnappy` 0.4, the one dependency that is not on PyPI, is now hashed: the URL of its commit's archive carries `#sha256=0d7558f8...6ca7` (4,321 bytes,
measured on 2026-11-04 from the archive the owner approved downloading), and pip refuses an archive that differs (a wrong hash on a file:// URL of the same archive was refused in a throwaway venv).
It stays outside `requires/locks/ccl_indexeddb_dump.txt`, whose format takes `name==version` lines only; `tests/recipe.test.sh` accepts the fragment on a commit
archive URL. GitHub does not promise that an archive of a commit stays byte-identical. Nothing was installed in an image: the first image build is the first
install of the venv from these pins. The tool was tried against ccl_chromium_reader 0.3.18 with Brotli 1.2.1, zstd 1.5.7.2 and ccl_simplesnappy 0.4 on Python
3.12 (the images' Python 3.11 was not available), on amd64 only.

Pack `computer-forensics-base` 1.15.0.
