### Changed: a pull request runs the suites its change needs; main and every night run everything

A pull request waited for every suite whatever it changed: the node suites ran four times (the Linux parts, Node 22.19, Node 24, the macOS parts), each about half an hour of test time, for a change to one pack's skill. Now:

- **A `select` job** reads the pull request against its base with `scripts/test-select.ts` and hands every job its lists. Narrow only where the change plainly is (a pack, a suite, a test helper and the suites that import it, a document); the harness, the workflow, images, package files, the tools of two packs at once and any path the map does not know run everything. The job's summary says which suites and why.
- **Everything** on a push to main, on a new nightly run (02:17 UTC), on a run by hand, and on a pull request labelled `full-ci`: what a narrow run leaves out runs within a day, on main as it is.
- **The microVM job** runs when everything does, or when a pack's requirements change (the images are built from them).
- **Each node part writes its slowest suite files** to its summary (`scripts/test-timings.ts`), from the timings `scripts/test-node.ts --timings` records.
- `scripts/test-bash.sh --within FILE` keeps, of a shard, the suites a file names. `tests/ci-shards.test.ts` holds that a list narrows a job only through the select job's guarded lists, never on a run it marks as everything, and that every test job waits for it.
