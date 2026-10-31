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
