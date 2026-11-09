### Added: images install a pip set from a hash lock when a pack names one

`images/install.py` installs a pack's pip set with `--require-hashes` from a
lock file: `requires/python.lock` beside `python.txt`, `install.pip_lock` on a
`python3 -m pip install` program, and `pip_lock` / `pip_after_lock` on a pinned
source. A lock line without `==` or without a hash, an option line, a lock
changed after the build recorded its sha256 and a hash pip does not accept all
fail the seal or the build, naming the program. `/etc/dfirswarm/image.json`
lists the sets installed from a lock under `locked`, only after pip succeeded.
`docs/packs.md` says how a pack declares a lock (a venv shared by several
programs needs one lock for all of them). No pack carries a lock yet.
