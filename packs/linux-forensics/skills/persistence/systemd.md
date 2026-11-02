---
id: persistence/systemd
title: systemd units, links and what is in effect
when: Deciding which systemd units were configured, enabled and eligible, and which ran.
needs: []
tools: [linux_persistence, journal_export]
requires_host: [target-fs, target-query]
---

Use when you must say which systemd units could start at boot or on a trigger. Not for the sweep's frame (`persistence/mechanisms`) or for cron and timers as schedules (`persistence/cron-timers`).

Keep five states apart: configured (a unit file or drop-in says so), enabled (a link in a `.wants/` or `.requires/` directory, made when someone enabled the unit), eligible (its conditions, dependencies and masks allow it), triggered (a target, timer, path or socket starts it) and observed running (a journal row for the unit). A file shows the first, a link the second; the rest comes from other evidence.

`linux_persistence` lists units from the system and user load paths and from each home (the passwd's and every directory under `home/` and `root`, so a deleted account's home is read: `account_in_passwd` is false), the drop-ins of each unit in file-name order with `list_resets` where an empty assignment clears a list, the links, masks (a link to `/dev/null`) and aliases (listed, never followed), the `.path` and `.socket` triggers, and every place it tried in `locations`. Its effective state is never resolved, and it says why: the search-path order, generators, transient and runtime units and `systemctl` itself are not on a disk. A user unit runs without a login only where lingering is set (a file under `var/lib/systemd/linger`), so read that before you call a user unit persistent.

A copy made with `target-fs` does not keep links. Where no link is found though unit files are, the answer says enablement, masks and aliases cannot be read from that copy: go back to the image before you write that a unit was or was not enabled. If you also ran Dissect's `services` function with `target-query`, treat its list as a second reader and explain each difference from `linux_persistence`.

For what ran, pass the records file of a `journal_export` call as `execution_rows` (rows with a `unit` or `user_unit`): each unit then has a row count and first and last time, and a unit those rows do not name is not claimed idle. The journal has its own retention and rotation limits (`logs/journal`).

Shows: what the unit files, drop-ins and links say, and the journal rows you supplied. Does not show: the effective state, that a unit was enabled when links are missing, or who made it. Record: `locations`, each unit's file, line and offset, what the copy lost, the journal files used.

Sensitive output: an Exec line is its word count and length, an Environment its length and count. The text is in the file `write_text: true` writes in a job run with `secret_output: true`. Cite file and line, never the value or a hash of it.
