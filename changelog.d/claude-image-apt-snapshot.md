### Changed: images install apt packages from a Debian snapshot, and the base images are pinned to digests

Every apt install in the base image, and in every profile built on it, resolves
from snapshot.debian.org at one date (`images/debian-snapshot`, repeated in
`images/base.Dockerfile`), so two builds of one source install the same
packages. Both `FROM` lines carry `@sha256:` index digests with the tag beside
them. `/etc/dfirswarm/image.json` records `apt_snapshot` and the image has the
label `dev.dfirswarm.apt-snapshot`. `images/install.py` takes the backports
mirror from the snapshot (the security archive is skipped by name).
`scripts/apt-snapshot-bump.sh` moves the date (and, with `--digests`, the
digests) and nothing else; a monthly workflow (`apt-snapshot.yml`) opens the
pull request and starts the CI and image builds on its branch. The apt lines of
the packs are unchanged: the snapshot pins them. The images are rebuilt by the
owner.
