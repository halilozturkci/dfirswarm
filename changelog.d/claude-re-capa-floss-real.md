### Added: a CI job runs the reverse-engineering real-program cases

`tests/pack-re-real-programs.test.ts` skips every case whose program is not on
the machine, so until now no CI job ran them. The new `re-real-programs` job
installs the programs the reverse-engineering pack pins (capa, radare2 and UPX
from the sha256-checked downloads in `requires/host.json`, FLOSS from its hash
lock, ssdeep, TLSH, YARA and binutils from Ubuntu) and runs that suite with
the capa-floss suite. It reports and does not gate: `continue-on-error` is on the
job, so a failing install or case does not fail CI green (drop that line if the owner wants it to gate). It sets
up Python 3.11, the one the FLOSS lock is resolved for, and runs when the select job asks for the Python 3.11 job
(a pack, the tool library, an image file or a pack-tool suite changed, and nightly). The workflow was not run on
GitHub in this change: only its YAML and its embedded installer script were checked here.

The capa-floss recipe is unchanged. Its flags (`-j` and `--version` for capa
9.4.0 and for FLOSS 3.2.0, the sample as the positional argument) were
compared with those releases' argument parsers in their source; the recipe was
not run against the real programs in this change.
