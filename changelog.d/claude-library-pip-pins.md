### Changed: the tool library's Python packages are pinned and hash-locked

`images/library-python.txt` now pins cryptography 50.0.2, dissect.util 3.24,
python-evtx 0.8.1 and regipy 6.3.0 with `==` (each keeps the floor its comment
names; dissect.util stays at 3.5 or later, the Apache-2.0 releases), and the
base image installs `images/library-python.lock` with `pip --require-hashes`:
the sha256 of every file PyPI publishes for those four packages and their six
dependencies that CPython 3.11 on Linux (x86_64 or aarch64) can use, plus the
sdist. The lock was resolved from PyPI's metadata; nothing was installed or
downloaded to make it, so the first image build is its first install. The pins
are the versions the other pinned packs already hold (the Windows pack's
python.txt and the reverse-engineering lock), so one venv has one version of
each. FLOSS and oletools, named by the same work, were already pinned and
locked by the reverse-engineering declarations.
