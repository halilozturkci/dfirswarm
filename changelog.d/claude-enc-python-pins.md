### Changed: encrypted-containers pins its six Python packages and locks their dependencies

`requires/python.txt` now names libbde-python 20260916, libvhdi-python 20260901,
libluksde-python 20260902, pytsk3 20260715, dfvfs 20260924 and pyAesCrypt 6.1.1
with `==`, and the image installs `requires/python.lock`: the sha256 of every
file PyPI publishes for them and for dfvfs's whole dependency graph (the
libyal bindings, libewf-python and libfvde-python among them) that CPython 3.11
on Linux x86_64 or aarch64 can use, wheels and sdist. The libyal bindings and
pytsk3 versions are the ones the computer-forensics-base plaso lock holds, since
both install into one venv. The licences in `python.txt` are the ones PyPI's
metadata declares. The lock was resolved from PyPI's metadata; nothing was
installed or downloaded to make it, so the first image build is its first
install. The old comment, which said the two libyal packages dfvfs pulls have
no wheel, is replaced: PyPI carries cp311 manylinux wheels of both for both
architectures.
