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
