### Changed: mobile-forensics installs the LEAPP environments and pillow-heif from hash locks

iLEAPP's venv no longer installs its tag's `requirements.txt` as it stands:
`requires/locks/ileapp.txt` holds that file's requirements for CPython 3.11 on
Linux (read from the tag's raw view on GitHub) and their dependencies,
`==` with the sha256 of every file PyPI publishes for each that x86_64 or
aarch64 can use, plus the sdist. ALEAPP's venv installs
`requires/locks/aleapp.txt` the same way; bencoding, packaging, PyCryptodome,
pytz, simplekml, wheel and xmltodict, which its list left open, are pinned
there, and Brotli 1.2.1, lz4 4.3.3 and zstd 1.5.7.2 moved from `pip_after` into
the lock; the x86_64 manylinux_2_4 wheel of that zstd is not hashed in it, so
amd64 builds zstd from the sdist (the compiler is present). `pillow-heif` 1.8.0
is locked with its Pillow in `requires/python.lock`.
The four git packages ALEAPP installs (`mister_skinnylegs`, the two readers and
`ccl_simplesnappy`) stay outside the lock, each at a commit, because pip's hash
mode cannot hash a git URL and their archives were not downloaded to take a
sha256; `mister_skinnylegs` is now at the commit its tag v0.0.18 names. The locks
were resolved from PyPI's metadata; nothing was installed or downloaded to make
them, so the first image build is their first install. PGPy 0.6.0 (an sdist
with no dependency metadata on PyPI) is locked with the dependencies its 0.5.4
wheel lists; a dependency still missing fails that build at pip's hash check,
not silently. ALEAPP's apt packages are PKG-IMG-01's and are not changed here.
