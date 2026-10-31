### Fixed: the pack seal gives the same pack.json on every file system

`scripts/pack.sh seal` walked directories in the file system's own order and
wrote the checksum map in that order, so a pack sealed on another file system
(macOS, ext4, NTFS) was rewritten whole with no file changed. It now walks
directories in sorted order and writes the checksum map sorted by path
(`skills/INDEX.md` in its sorted place). Every pack under `packs/` was resealed
once into that order: the `pack.json` diffs are a pure reorder of
`checksums.sha256`, and no pack version moves.
