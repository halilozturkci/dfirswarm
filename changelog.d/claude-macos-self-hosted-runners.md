### Changed: the macOS CI jobs can run on the owner's own Macs

The hosted macOS runners queued for one to two hours and sometimes cancelled a job that no runner took. The four macOS parts of the CI workflow now run on a self-hosted Mac when the repository variable `MACOS_RUNNER` names its labels, for a push to main or a pull request the owner opened from a branch of this repository; a fork's pull request, a Dependabot one and every run without the variable stay on `macos-latest`. The macOS job now installs Python 3.14 with actions/setup-python rather than taking the host's.

- `scripts/macos-runner-setup.sh` installs one runner per Mac: jobs run as a hidden standard user, each job on a fresh ephemeral runner copied from a root-owned one, and a root-owned job-started hook fails any job whose event is not the owner's own, so a fork that edits `runs-on` in its pull request is still refused.
- `docs/macos-runners.md` covers the setup, the three guards, going back to hosted runners, and per-job Tart VMs as the next step.
