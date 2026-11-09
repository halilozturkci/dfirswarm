### Changed: computer-forensics-base and linux-forensics pin Plaso, Dissect, Pillow and the ccl venv, with hash locks

`log2timeline`, `psort` and `pinfo` install plaso 20260720 and `target-query`
(base) and `target-fs` (linux) install the dissect metapackage 3.22
(dissect.target 3.25.1), each from a lock in `requires/locks/` that holds the
sha256 of every file PyPI publishes for the package and its whole dependency
set that CPython 3.11 on Linux (x86_64 or aarch64) can use, plus the sdist;
the one exception is the x86_64 manylinux_2_4 wheel of zstd 1.5.7.2, which the
plaso and ccl locks do not hash, so amd64 builds zstd from the sdist (the
compiler is present).
Pillow is `==12.3.0` in `python.txt`, installed from the pack's
`requires/python.lock`. `ccl_indexeddb_dump`'s own venv installs Brotli 1.2.1
and zstd 1.5.7.2 from a hash lock; `ccl_simplesnappy` is not on PyPI and stays
at its commit (an archive URL, outside the lock; its bytes are not hashed).
The plaso and dissect versions are the newest releases PyPI had on 2026-10-05,
the date OD-10 names: no recorded image.json of that date was available. They
share the image's venv, so the locks agree with the tool library's and the
reverse-engineering locks on every shared package (yara-python is held at the
memory pack's 4.5.1). The locks were resolved from PyPI's metadata; nothing was
installed or downloaded to make them, so the first image build is their first
install. The brew routes of `luksdeinfo`, `fvdeinfo` and `fsapfsinfo`, which
installed the Python bindings and not the command-line tools, now point to the
libyal projects' sources; Homebrew formula names were not checked and CI does
not exercise any brew route. `tests/recipe.test.sh` gains a case that fails on
an unpinned or unlocked pip line.
