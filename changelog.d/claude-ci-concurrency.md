### Changed: a new push to a pull request cancels the CI runs the older push left behind

`ci.yml` and `images.yml` now have a `concurrency` group per pull request, with `cancel-in-progress` on for `pull_request` events only. Before, every push to a PR branch queued three more macOS jobs behind the old ones, and the account's five concurrent macOS jobs were spent on commits nobody looked at any more. Pushes to `main`, tags, schedules and manual runs get a group of their own (the run id), so none of them is ever cancelled or replaced while pending. No harness, pack or skill file changes.

### Fixed: the macOS node-tests part is no longer cancelled by its limit when the runner is slow

On 2026-10-22 two macOS `typecheck · node tests` jobs ran to the 55-minute limit and ended cancelled: the same 4550 tests that take 13 to 46 minutes (median about 37) on a hosted runner ran at about half speed, and one of them had finished every test, none failed, a minute before the limit. Nothing hung. That part now has 90 minutes; the two shell-suite parts keep 55. Every test still has its own 5-minute limit.
