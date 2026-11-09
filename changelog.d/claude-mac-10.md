### Changed: macos-forensics installs mac_apt's Python dependencies from a hash lock

- mac_apt 1.33.2's venv is now installed from `requires/locks/mac_apt.txt` with pip's `--require-hashes`, in place of the tag's plain requirements file. The lock names every package of that file and its dependencies, `==` with the sha256 of each file PyPI lists for CPython 3.11 on Linux x86_64 (amd64 is the pin's one architecture), plus the sdist.
- The lock was written from PyPI's JSON metadata and has not been installed: the first install is the image build. The names the tag leaves unpinned are at the newest version PyPI listed on 2026-11-04, and mac_apt 1.33.2 was not run against them.
- The bundled pyaff4 zip is installed after the lock with `--no-deps` and is not hash-locked; whether AFF4 input can be read is not established.
- The `why` of mac_apt.py no longer says its dependencies come without a hash lock, and the `why` of fsapfsinfo says the apt package is pinned by the image's snapshot date.
