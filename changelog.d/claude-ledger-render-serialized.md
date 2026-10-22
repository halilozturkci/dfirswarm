### Fixed: ledger.md is rendered one render at a time

A render of `ledger/ledger.md` that began before a store sweep line was written could finish after the sweep's own render and write the document back saying "store sweep pending", which stayed until the next render. Renders of one ledger now run in turn, in the order asked for, and each reads the run's records when its turn comes, so the last document written always shows the latest state. Nothing in the document is shortened or left out. A lock beside the registers orders renders of different processes too.

`tests/ledger-render-serialized.test.ts` holds a first render at its read of the sweeps file, writes the sweep line, asks for a second render and then lets the first go; it fails without the change.
