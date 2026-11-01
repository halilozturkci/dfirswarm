### Added: a CI job runs the reverse-engineering real-program cases

`tests/pack-re-real-programs.test.ts` skips every case whose program is not on
the machine, so until now no CI job ran them. The new `re-real-programs` job
installs the programs the reverse-engineering pack pins (capa, radare2 and UPX
from the sha256-checked downloads in `requires/host.json`, FLOSS from its hash
lock, ssdeep, TLSH, YARA and binutils from Ubuntu) and runs that suite with
the capa-floss suite. It reports and does not gate: the test step has
`continue-on-error`, and drop that line if the owner wants it to gate.

The capa-floss recipe is unchanged. Its flags (`-j` and `--version` for capa
9.4.0 and for FLOSS 3.2.0, the sample as the positional argument) were
compared with those releases' argument parsers in their source; the recipe was
not run against the real programs in this change.
