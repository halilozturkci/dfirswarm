### Added: a change map, a deep tier, per-file timings, retry alone and a local gate for the tests

Tooling for the CI policy and for testing on the owner's own machines; `npm test` with no option runs exactly what it ran before.

- `scripts/test-select.ts` (`npm run test:changed`): the suites a change needs. It narrows only where a change plainly is (a pack, a suite, a test helper and the suites importing it, a document) and runs everything for the harness, the workflow, images, package files, the tools of two packs at once and any path it does not know.
- `scripts/test-node.ts`: `--tier=fast|deep` (`tests/node-tests.deep`, the long hardening suites), `--files-from=FILE`, `--timings=FILE`, and `--retry-alone`, which runs each failed file again alone and exits 3, not 0, when every failure passed only alone.
- `scripts/test-timings-reporter.ts`: each suite file's time and failures as JSON (node's own output does not list passing files). `scripts/test-timings.ts`: the slowest files as a table, and `tests/shell-suites.weights` rebuilt from test-bash.sh logs.
- `scripts/test-gate.sh` (`npm run test:gate`): the typecheck, the node suites the change needs at this machine's concurrency with retry alone, the shell suites in groups side by side; every group waited for, and stopped if the gate is interrupted.
