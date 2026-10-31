### Changed: ransomware-response states how yara is pinned

The `yara` entry of the pack's `requires/host.json` no longer says that its
version is not pinned. On Linux the image installs it from the Debian snapshot
at the date in `images/debian-snapshot`, so the version is the one Debian 12
(bookworm) held on that date (4.2.3-4 at the time of writing); the apt line is
not edited, the snapshot pins it. Homebrew on macOS stays unpinned, and the
entry says so. `optional` and `redistributable` are unchanged.
`tests/recipe.test.sh` now refuses an apt entry that says its version is
unpinned and checks the yara entry. No image is rebuilt.

### Fixed: ransomware-response leaves no hidden temporary file from a stop between create and register

`ransom_note_scan` and `encrypted_survey` held no protection for the moment
between creating a page's (or the census's) temporary file and registering it
for the stop handler: a SIGTERM, SIGINT or SIGHUP there ended the tool with its
JSON answer but left `.ransom_note_scan-*`, page or census temporary files in
`$OUT`. Both `LosslessPage` copies and `encrypted_survey`'s `Census` now hold
the three stop signals for those steps and restore the old mask right after
(in a `finally`), so a held signal is delivered once the file is registered and
the handler removes it. Where `signal.pthread_sigmask` is missing the call is a
no-op. The shared STOP block is unchanged. New cases in
`tests/pack-ransomware-stop.test.ts` signal from inside `tempfile.mkstemp`, for
each page and for the census, with each of the three signals.
