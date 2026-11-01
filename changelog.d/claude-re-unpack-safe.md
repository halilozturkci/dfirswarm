### Added: reverse-engineering `unpack_safe` unpacks a UPX file into a derivative

`unpack_safe` runs `upx -t`, then `upx -d`, and writes the unpacked file into a
directory of its own under the tool-output directory (in a job, under `$OUT`),
never over the original, then links it under a new name that replaces no
existing file, with mode 0600. It records both SHA-256 values, `upx --version`
as printed, each step's argv and exit code, and keeps UPX's own output in a log
file: nothing from the sample is printed inline. UPX only: a file UPX does not
recognise is `unsupported` (a marker of another packer in the first MiB is
named as a hint), a damaged file or a failing UPX is `failed` with no
derivative. The output budget (`max_output_bytes`, default 256 MiB) is checked
against the size UPX lists before anything is written and against the growing
file while UPX writes it; past it, or past `max_seconds`, UPX and what it
started are ended, the half-written file is removed and the answer is
`partial` with `limits_hit`. `complete` means upx -t accepted the file, upx -d
exited 0 and the derivative is a non-empty regular file within the budget.
The tests use a stand-in for upx; the case with the real program is skipped,
naming it, where upx is not installed.
