### Changed: Python 3.15 is named unsupported for the pack tools, with the measurements behind it

- `CONTRIBUTING.md` says Python 3.15 is not supported. The deep-nesting run of `beacon_score` (`network-forensics`) that took 300 s on a hosted macOS runner's 3.15 was not reproduced in `python:3.15` (3.15.2, Linux amd64): 1.4 s wall for the nested series, 0.8 s for `window_end`, four runs together 1.5 s, 2.8 s with an unlimited stack, and a SIGSEGV of the interpreter (exit 139) with a 1 MiB stack. No cause was found in `beacon_score`, so the tool is unchanged.
