---
id: artifacts/jumplists
title: Reading Jump Lists
when: You read automaticDestinations-ms or customDestinations-ms files for recent or pinned items.
needs: [artifacts/shell]
tools: [jumplist, lnk_parse]
requires_host: [olecfexport]
---

Use when you read Jump List files. Not for the Recent folder's own links (`artifacts/links`) or for execution (`execution/overview`).

- `jumplist` reads an automaticDestinations-ms file (with `olefile`) and its DestList by its version's layout: versions 1, 3 and 4. Any other version is refused with a problem and no entries; report that as a limitation, not as an empty list.
- An entry gives `entry_number`, the NetBIOS host name, the last access (raw FILETIME and ISO UTC), `pin_status` and the path. The counters between those fields come back raw as `undecoded_*`: no access count is claimed, so do not read one from the hex. Automatic destinations hold pins too.
- Every embedded link is written to `out_dir`, which must be under your own `work/<your id>/jumplinks`; any other place is refused and the answer names the places that work (in a job the harness maps that path to $OUT). The volume serial and the target's times are the link's, not the DestList's: run `lnk_parse` over the written links before citing either.
- A customDestinations-ms file has no container: its links are carved by the 20-byte header and marked `carved`, so they are candidates. Its categories, pins and tasks are not parsed.
- A stream too large to read is named, not read (`not_read`, a problem, status partial). A FIFO or device is never opened: `not_attempted` and `files_not_attempted` count them. Read `status` (complete, partial, failed) and `problems` first.
- `olecfexport` takes the compound file apart as a second reader of the container; it does not check what a DestList field means.

Shows: that an application or the shell listed that item (recent use, a pin, a destination or a task), with the entry's own last access. Does not show: an opening event, the target's timestamp, a person. Record: application id (the file name), source file, DestList version, entry and stream, the link written for it.

Sensitive output: the links inside carry arguments and working directories; run `jumplist` as a job (`secret_output: true`). `lnk_parse` withholds the arguments from its answer.
