### Added: encrypted-containers reads the encryption metadata of a volume through its reader

A new tool, `crypto_metadata`, takes a volume image and a byte offset, names the
scheme from the signature at that offset (LUKS1, LUKS2, BitLocker, BitLocker To Go,
Core Storage, an APFS container) and runs the reader for it: `cryptsetup luksDump`
(with `--dump-json-metadata` for LUKS2) on a copy of the header it makes and removes,
`bdeinfo`, `fvdeinfo` or `fsapfsinfo`. The answer keeps each program's argv, version
and exit code and gives one record per LUKS key slot, segment, digest and token,
per BitLocker key protector (its type), or per count the Core Storage and APFS
readers print; the first `limit` inline and all of them in the file it names. It
prints no key, salt, digest, UUID, label or identifier, only whether each is present.
A reader that is not installed answers `unavailable` and is named, never an empty
list; a reader that fails, times out, prints what the tool cannot read or disagrees
with the header answers `partial`. `volumes/luks-filevault`, `volumes/filevault-apfs`
and `volumes/bitlocker` name it. What the installed Core Storage and APFS readers
print is not established here, so only their counts and encryption lines are shown.

### Added: encrypted-containers proves its readers on synthetic samples

A new tool, `crypto_selftest`, builds the smallest LUKS1, LUKS2, BitLocker-metadata,
Core Storage, APFS, ZIP-with-AES and VHD samples from the formats' descriptions,
runs `cryptsetup`, `bdeinfo`, `fvdeinfo`, `fsapfsinfo` and `7z` on them and says per
pair whether the reader parsed the sample, did not, is unavailable or timed out.
It also imports `pybde`, `pyvhdi`, `pyluksde`, `pytsk3`, `dfvfs` and `pyAesCrypt` in
a child interpreter with a version and an open test, and lists the `*2john` helpers
on PATH by name. A verdict is about the sample only, never about a real volume. A
rerun in the same job replaces no sample. `identify/by-format` names it.

### Added: encrypted-containers archive_probe reads a doc_structure result by reference

`archive_probe` takes an optional `structure`: the path, inside the run, of a
doc_structure result file. For a PDF or an OLE file it validates the file (inside the
run with no link on the way, a regular file of at most 16 MiB, doc_structure's shape,
the same size and name as the file probed, a sha256 where the result records one) and
reports its encryption reading as `structure_reading` beside the byte search, with its
source named. A result that fails a check is rejected with the reason and none of its
content is shown. The byte search stays a heuristic, the status stays partial, and no
marker is not "not encrypted". doc_structure/1 does not record the file's hash, so
the match is by size and name. `archives/protected` says so.

### Added: encrypted-containers reads the protection of 7-Zip and RAR archives, and lists a ZIP, without extracting

A new tool, `archive_metadata`, keeps two findings apart: whether an archive's headers
are encrypted (the names need the password) and whether its members are. For 7-Zip it
reads the start header (both CRCs), the next header's place against the file's size and,
when the header is packed, the coder list for 7-Zip's AES coder; for RAR 4 and RAR 5 it
reads every block header (the password flags, the archive encryption header, each file's
encrypted flag and declared sizes, each CRC) to the end-of-archive block; 7z then lists
the members with an impossible password and no prompt. A set of volumes with a missing
next volume is named, and a member declared enormously larger than its packed size is
counted, never unpacked. A ZIP is listed through 7z only: its structure stays
`archive_probe`'s, so the ZIP reader is not copied. The first `limit` members are inline
and all of them are in the file the answer names. `archives/formats` names it.

### Added: encrypted-containers writes decrypted evidence under the job's output from a sealed key reference

A new tool, `materialise_decrypted`, runs only in a `secret_output` job (it refuses as JSON
before reading anything otherwise) and takes an operation (`bitlocker_image` through pybde,
`luks_image` through pyluksde, `aescrypt_decrypt` through pyAesCrypt), the evidence, and a path
to a 0600 file in the job that holds the key. The key is read inside the tool and handed to the
module in memory: the tool starts no program, and the key is on no command line, in no
environment, answer, path, JSON key or file, and a module's exception text is never shown.
Output is a 0600 `.partial` file first: a key that does not work removes it, a whole result is
placed under its final name without replacing anything, and a container that is cut short, a
volume that ends early, the output budget or the time limit keep it as an unverified
`.partial`. A provenance file beside each output holds the reader's version, the evidence's size
and sha256, the offset, the kind of key used and the output's sha256. Selected files out of a
volume are not provided. It was tested against stand-in modules and, where installed, the real
pyAesCrypt; pybde and pyluksde were not run on a real volume.
