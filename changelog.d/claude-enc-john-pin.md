### Changed: encrypted-containers john is named as the pack's password-recovery route, and its entry says what the image's build lacks

`requires/host.json` and `unreferenced_ok` no longer call john a capability
nobody has decided on. They say it is the pack's password-recovery route,
used only in `secret_output` jobs, and that the Debian `john` the image
installs (1.9.0-2, the core build) carries none of the `*2john` helpers, so
the helper inventory is not met on Linux until a jumbo build is pinned for the
image.
