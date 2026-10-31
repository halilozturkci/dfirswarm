### Security: the base image's Pi runs with undici 8.12.2 or later

Pi 1.4.0 still pins undici 8.10.2 (GHSA-xjj6-f33q-929c, GHSA-4qv8-2p9j-2685,
GHSA-f72v-6w45-q472). `images/base.Dockerfile` now installs Pi as a project in
`/opt/pi` with the repository's own `undici` override (`^8.12.2`), links `pi`
onto `PATH`, and `images/install.py --base` fails the build when any undici
under Pi is older than 8.12.2; `tests/image-programs.sh` checks the same inside
the image. `PI_VERSION` in the Dockerfile is held equal to `package.json`'s Pi
devDependency by a test, `scripts/cloud-setup.sh` installs that version when
`PI_VERSION` is unset, and a test derives each `BASE_PROGRAMS` entry from the
Dockerfile's apt list. The seat VMs get the fix with the owner's image rebuild.
