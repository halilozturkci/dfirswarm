### Changed: encrypted-containers john is named as the pack's password-recovery route, and its entry says what the image's build lacks

`requires/host.json` and `unreferenced_ok` no longer call john a capability
nobody has decided on. They say it is the pack's password-recovery route,
used only in `secret_output` jobs, and that the Debian `john` the image
installs (1.9.0-2, the core build) carries none of the `*2john` helpers, so
the helper inventory is not met on Linux until a jumbo build is pinned for the
image.

### Added: encrypted-containers gets its password-recovery route, and its governance leaf

A new tool, `password_recover`, runs inside a `secret_output` job only: it
extracts a hash with the matching `*2john` helper (or takes one from another
sealed job by reference), then runs john against a case-supplied candidate
list, bounded by a time budget. Every file that could carry the hash or the
password is written only under `$OUT`, mode 0600; the answer carries counts
and versions, never a value, a hash, a salt or a length. A new leaf,
`recovery/authorised`, states the governance an attempt needs (question,
authority, basis, scope, approved method, stopping condition) and is the
pack's one place that names `password_recover` and john; john, which was
listed in `unreferenced_ok` with no skill using it, is now referenced by this
leaf and leaves that list.

### Added: encrypted-containers reads a VeraCrypt/TrueCrypt header over cryptsetup's tcrypt mode

A new tool, `tcrypt_header`, reads a password from a sealed file and gives it
to `cryptsetup tcryptDump` on that program's own stdin (never on argv, in the
environment, or in a file it writes); when a header decrypts, the answer
carries only its non-secret fields (cipher chain and mode, PBKDF, key size,
sizes and offsets), never the volume key or a salt, and a header that does
not decrypt is reported without claiming the volume is not VeraCrypt or
TrueCrypt. `crypto_id` and `identify/by-format` now name it as the next
reader for a VeraCrypt or TrueCrypt lead, once the case supplies a candidate
password. PIM is refused for this version, named: whether it may go on
cryptsetup's own command line needs a decision this change does not have a
reviewer for.

### Fixed: encrypted-containers: a symlinked tool-output path, an unbounded flat-directory walk, no limit ceiling, and a 7z read held open by its own child

`archive_probe` and `recovery_key_scan` now refuse a symbolic link anywhere
on the way to their paging directory (`$OUT/tool-output` or
`work/<agent>/tool-output`, and `recovery_key_scan`'s values file under
`$OUT`), nothing written through it, instead of following it silently.
`recovery_key_scan`'s directory walk no longer keeps a whole flat
directory's entries sorted in memory (a 600,000-file directory held about
208 MB); it reads 10,000 entries at a time, bounding memory, and a stop
names the unreached part, including a directory that may hold more
entries beyond the chunk in hand, within the stop's own grace period.
`limit` is refused above 1,000 in both tools' manifests, as
`archive_extract`'s already was. `archive_probe`'s 7-Zip listing no
longer waits for end of file on 7z's own stdout pipe when a program 7z
forked keeps that pipe open after 7z itself has ended: the read ends
within a short grace of 7z's own exit, and what still holds the pipe is
reaped.
