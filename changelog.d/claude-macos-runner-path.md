### Fixed: the macOS CI jobs run on the owner's Mac

Two defects stopped every macOS job on the self-hosted runner from #227's setup.

- **The hook path had a space.** `scripts/macos-runner-setup.sh` installed under `/Library/Application Support/dfirswarm-runner`, and the runner calls the job-started hook by its path without quoting it, so every job stopped at `/bin/bash: /Library/Application: No such file or directory` before its checkout (no step of the job ran). The script now installs under `/Library/dfirswarm-runner`, refuses an install directory that holds a space, and `install` on a Mac set up by the first version stops that version's supervisor, moves its stored token to the new directory and removes the old one.
- **setup-python needs sudo on macOS.** actions/setup-python installs a macOS Python with `sudo`, which the job user does not have, so the job failed at "sudo: a password is required". On a self-hosted runner the macOS job now puts Homebrew's `python@3.14` first on `PATH` and checks it is 3.14; the hosted runner keeps setup-python. `install` requires `python@3.14`.
- **Nine test files at once on a ten-core Mac.** `node --test` runs cores less one files at a time: two on the hosted runner, nine on the Mac mini, where timing-bound suites (mobile, virtualization canaries, the derived catalog) ran past their limits and the UI server's trace collector did not come up in time. On a self-hosted runner the node tests run with `--test-concurrency=3`.

`docs/macos-runners.md` says so, and names the fork-approval setting as GitHub's settings page words it today ("Require approval for all external contributors").
