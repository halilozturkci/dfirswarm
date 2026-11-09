### Changed: CI green reads the macOS parts from the run, and the Linux jobs are pinned

`CI green` no longer waits for the macOS job through `needs`. After the other
jobs finish it lists the run attempt's jobs and `scripts/ci-green.ts` decides:
a macOS part that failed or was cancelled fails it, a part still running is
waited for up to its own limit (90 minutes for a node part, 55 for a shell
part), and a part that has not started after 15 minutes, or was skipped, does
not block and a notice names it. This lets the four macOS parts run on the
owner's Mac (`MACOS_RUNNER`) without a queued part holding every pull request.
`docs/macos-runners.md` and `CONTRIBUTING.md` say so. The repository variable
itself is set by the owner, after this change is on `main`.

The Linux jobs of `ci.yml`, `images.yml` and `image-boot.yml` run on
`ubuntu-24.04`, not `ubuntu-latest`, which GitHub moves to Ubuntu 26 from
2026-10-19; the label moves on purpose, in a change that tests it.
