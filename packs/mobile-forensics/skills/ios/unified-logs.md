---
id: ios/unified-logs
title: iOS unified logs on Linux with explicit coverage
when: Use when an iOS question depends on retained diagnostic or operational logs. Not for app databases.
needs: [ios/artifacts]
tools: [unified_log]
requires_host: [unifiedlog_iterator]
---

Use when an iOS question depends on retained diagnostic or operational logs. Not for app databases (`apps/databases`).

**Inventory** the `tracev3` files in every acquired log store (not Persist alone), the timesync data, `uuidtext` and other support files; keep their layout. Missing support data can block rendering or UTC conversion of some entries without making the rest worthless.

**Run** `unified_log` in a job on the directory that holds `diagnostics` and `uuidtext` (a `private/var/db` copy is staged as one archive for `unifiedlog_iterator`): `{"path":"inputs/ios-root/private/var/db","out_dir":"work/<agent>/ulog"}`. `out_dir` is required and under `work/` (in a job, `$OUT`). On Linux `predicate`, `start` and `end` are refused (they belong to Apple's own logging tool): filter the retained JSONL afterwards, keep the original and the exact expression. Check the job image holds `unifiedlog_iterator` (an optional program of the macOS pack).

**Record** reader version, command, exit status, warnings and the source inventory. `status: complete` or `unparsed_lines: 0` does not show that every record rendered; the wrapper does not give a trustworthy unresolved-format count: report it unknown unless you derived it by a stated method. If the reader stopped, name the partial output and the excluded scope; do not claim absence over the archive.

**Per entry** keep the output locator, boot identity, process, subsystem and category, raw clock and the UTC conversion used. Order events within a boot; clock jumps and boots are separate.

**Does not show**: a complete audit of what a user did. Privacy-redacted values, unresolved strings, disabled persistence, rotation and unacquired stores each limit it. Minimum and maximum times do not show continuous coverage between them.

**Readers**: use Mandiant's, not the archived Python reader, whose own upstream names a tested range that ends at older releases: that is no evidence for current builds, and no proof it fails on them.

**Sensitive output**: log messages can hold URLs, account names and message fragments: run as a job with `secret_output: true` when the question reaches them; cite locators, not text.
