### Added: images

Dependabot also watches the images' inputs, weekly and as pull requests a person reviews: the docker ecosystem for `images/base.Dockerfile` and `tests/linux/Dockerfile`, pip for `images/library-python.txt`, and npm for `spikes/microvm-smoke`. A Node major is held back in both Dockerfiles, and the microsandbox hold is kept in the smoke spike. The pinned downloads in the packs' `requires/host.json` are not an ecosystem Dependabot reads; `pins.yml` asks every one of them.

### Changed: pinned-download check

`scripts/check-pins.ts` has a deadline for the whole run (`--deadline`, 20 minutes by default, under the workflow's 30), on top of the per-request timeout: a pin the deadline reached is reported as an error that says so. `pins.yml` now has a last job that, for a scheduled run, opens one `ci-failure` tracking issue (or comments on the open one) when the check fails, and closes it when a later run is green, through the same reporter as `ci.yml` and `image-boot.yml`.
