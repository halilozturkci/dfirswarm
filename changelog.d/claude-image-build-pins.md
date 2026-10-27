### Fixed: the mobile, network and full images build again

Three image builds failed on every branch from 27 October, for two reasons outside this repository.

- **ALEAPP's browser readers are pinned to commits.** ALEAPP's `mister_skinnylegs` names `ccl_mozilla_reader` and `ccl_chromium_reader` by an unpinned git URL, and `ccl_mozilla_reader`'s head of 27 October has a `pyproject.toml` that does not parse, so `pip install -r requirements.txt` stopped the `mobile` and `full` builds. pip will not let another URL replace the one a requirement names, so the mobile pack now installs ALEAPP's other requirements as its tag pins them, then `mister_skinnylegs` and its dependencies with `--no-deps`, each git one at a commit: the readers at their last commit before that head. Brotli is installed at 1.2.1 over the readers' old bound of 1.2.0 (GHSA-9v8h-qqgm-4m35, an out-of-bounds write in the decoder, which reads the examined profile's cache), which is what the readers' heads now ask for themselves.
- **A pinned source can install in two steps.** `install.source` takes `pip_after`, a second `pip install` into the same venv after `pip`, for a dependency one resolve cannot pin. `pack.sh seal` checks it is a list of strings.
- **Zeek 8.0.11.** The Zeek project's Debian 12 repository keeps its latest release only, and 8.0.10 was removed when 8.0.11 came out, so the `network` and `full` builds got a 404. The network pack pins 8.0.11 (the same `zeek-8.0-core` package, the same dependencies, the same path), and its note says the pin goes 404 again at the next release.

Packs mobile-forensics and network-forensics. Tests: `tests/recipe.test.sh`.
