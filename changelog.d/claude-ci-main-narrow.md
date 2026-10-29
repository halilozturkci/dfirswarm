### Changed: a push to main runs what it brought; everything runs every night

A push to main ran every suite. Three merges in a row on 2026-10-28 then held about 60 jobs against the account's 20 concurrent (5 macOS), and the pull request behind them, whose own jobs took 1 to 7 minutes, waited 10 to 23 minutes for a runner. A push to main now runs what it brought (`scripts/test-select.ts` against the push's `before`, the merged pull requests together); the nightly run, a run by hand and the `full-ci` label still run everything, and a push with no range to read (a force-push) does too.

`tests/node-tests.deep` is filled from measurement: the suites that took 60 s or more on the hosted Linux runner in a full CI run (40 % of the node suites' time there), less `ui-server`, plus the suites importing the two helpers whose tests took longest. Three of them are the ones cut off at 300 s on the owner's Mac mini.
