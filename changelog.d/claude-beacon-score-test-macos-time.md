### Fixed: the beacon_score test file no longer ends unnamed at the suite limit on the hosted macOS runner

On the hosted macOS runner the file `tests/pack-network-beacon-score.test.ts` failed three times on main with "test timed out after 300000ms", for the whole file and with no test named: its last tests were never reported. The test of a series nested 100,000 deep ran the tool with `spawnSync`, which blocks the runner's event loop, so no test timeout could fire and a slow or stuck run ended the file at the suite limit and took the tests after it with it. It is a test change only; the tool is unchanged.

- The deep-nesting test now runs each tool in a process group of its own, under a 45-second limit per run and a test timeout of its own; a run that has not answered is killed with its group and the failure names the interpreter, the series and the time. The time of every run is printed in the test's diagnostics.
- The signal loop of the clock test kills its tool's group in a `finally`, and the other `spawnSync` that feeds the tool has a limit of its own.
- The watchdog of the `/dev/zero` test is cleared when the tool has answered. It was left running and held the whole file open for its full 20 seconds after the last test: the file took 31 s on a laptop and now takes 12.5 s.
- Every assertion is kept. Checked by mutation: without the read clock, without the regular-file check, without the tool's handling of a stack overflow, and with a tool that stops answering, the matching test fails.
