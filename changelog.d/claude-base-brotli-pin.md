### Security: computer-forensics-base

The isolated `ccl_indexeddb_dump` venv now installs `Brotli==1.2.1`, the
release that fixes GHSA-9v8h-qqgm-4m35 (an out-of-bounds write in the decoder,
which reads content taken from the examined profile); the reader's own bound of
1.2.0 no longer holds it back. The in-image check (`tests/image-programs.sh`)
fails a venv whose Brotli is older. Images must be rebuilt to pick it up.
