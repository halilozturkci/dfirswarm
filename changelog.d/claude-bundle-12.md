### Changed: ransomware-response states how yara is pinned

The `yara` entry of the pack's `requires/host.json` no longer says that its
version is not pinned. On Linux the image installs it from the Debian snapshot
at the date in `images/debian-snapshot`, so the version is the one Debian 12
(bookworm) held on that date (4.2.3-4 at the time of writing); the apt line is
not edited, the snapshot pins it. Homebrew on macOS stays unpinned, and the
entry says so. `optional` and `redistributable` are unchanged.
`tests/recipe.test.sh` now refuses an apt entry that says its version is
unpinned and checks the yara entry. No image is rebuilt.
