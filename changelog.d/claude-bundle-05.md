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

### Fixed: encrypted-containers: the STOP block now runs first, before a SIGTERM in the first tens of milliseconds can land with no handler installed

In `archive_probe`, `crypto_id` and `recovery_key_scan`, and for the same
reason in the two tools this bundle adds (`password_recover`,
`tcrypt_header`), the SHARED STOP block (its pinned text unchanged) now
runs right after the standard-library imports, before the PLACE, PAGE,
WITHHOLDING, NAMES and PROCESS blocks and their own module-level work
(regex compiles and the rest). A stop signal in that window used to get
the interpreter's default action, no JSON answer; moving the block first
narrows it. A structural test holds the block's position in every
carrier, and fails on the previous head, where STOP still sits after
those blocks.

### Fixed: encrypted-containers: password_recover and tcrypt_header no longer answer `complete` for an attempt that did not happen

`password_recover` answers `failed`, with `recovered: 0`, when the hash file
holds no hash line, when the candidate list holds no line, or when john loads
no hash (`--show` reports nothing loaded, or john says "No password hashes
loaded"); before, a john that exited 0 on a file of blank lines gave
`complete` with "john tried every candidate line". Its budget sentence now
carries the call's real `max_seconds`, not the default; `versions.helper` says
"not reported by this build" when the helper reports no version (no john build
is pinned for the image yet, so it no longer claims one); `format` is required
with `hash_file`, as the manifest says. `tcrypt_header` answers about the
password only for cryptsetup's exit 0 (decrypted) and exit 2 (bad passphrase,
`decrypted: false`); any other exit, or exit 0 with none of the header fields,
answers `failed` naming the exit code, and a `password_file` readable by group
or other is refused, so the manifest's "0600" is enforced.

### Fixed: encrypted-containers: tcrypt_header no longer hangs on a FIFO named as password_file

`tcrypt_header` read `password_file` with a plain `open()` before its own clock
was set, so a FIFO with no writer held it until the harness killed it. It now
starts its clock before touching any caller-supplied path, refuses (as JSON,
`failed`) a password file that is not a regular file before opening it, and
opens it non-blocking, following no link, with the descriptor checked again.
`password_recover` counts its hash file and candidate list through the same
non-blocking, regular-file-checked open. A FIFO named as source, keyfile,
hash_file, candidates or path is answered as JSON, within seconds, by all five
tools of the pack (a test holds each).
