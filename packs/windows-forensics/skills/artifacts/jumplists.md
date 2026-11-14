---
id: artifacts/jumplists
title: Jump Lists
when: Recent and pinned items.
needs: [artifacts/shell]
tools: [jumplist, lnk_parse, lnk_jumplist]
requires_host: [olecfexport, lnkinfo, JLECmd, dotnet]
card: jumplist {"path": "<AutomaticDestinations-ms>"}: a DestList version other than 1, 3 or 4 is refused, a limitation and not an empty list; undecoded_* is no access count. A volume serial or target time is the link's: write_links: true, then lnk_parse. Does not show: an opening event, the target's times, a person.
---

Use when you read Jump List files. Not for the Recent folder's own links (`artifacts/links`) or for execution (`execution/overview`).

- `jumplist` reads an automaticDestinations-ms file (with `olefile`) and its DestList by its version's layout: versions 1, 3 and 4. Any other version is refused with a problem: a limitation, not an empty list.
- An entry gives `entry_number`, the NetBIOS host name, the last access (raw FILETIME and ISO UTC), `pin_status` and the path. The counters come back raw as `undecoded_*`: read no access count from the hex.
- With `write_links: true` every embedded link is written to `out_dir`, which must be under your own `work/<your id>/jumplinks`; the links keep their arguments, so this is secret output; `out_dir` without `write_links`, or in another place, is refused. The volume serial and the target's times are the link's, not the DestList's: run `lnk_parse` over the written links before citing either.
- A customDestinations-ms file has no container: its links are carved by the 20-byte header and marked `carved`, so they are candidates. Its categories, pins and tasks are not parsed.
- A stream too large to read is named, not read (`not_read`, status partial). A FIFO or device is never opened (`not_attempted`, `files_not_attempted`). Read `status` and `problems` first.
- `olecfexport` is a second reader of the container, not of what a DestList field means.
- `lnk_jumplist` reads a file or a directory in one call: rows for the file, the container, each stream with its `extents`, each DestList entry with its stream (a stream with no entry is `orphan`; past 50,000 entries the rest is a problem), and each link with its extents and an `integrity` that includes a `lnkinfo` read. Cite offsets from its rows.
- `JLECmd` (through `dotnet`) is `lnk_jumplist`'s optional second reader of a DestList: entry rows have `integrity.jlecmd`, `agree`, `disagree` (field, both values) or `not_run` (why). It compares count, path, access time, pin state and app id. A disagreement makes the status partial; check the bytes first. Its column mapping comes from the build's help strings, not a real run.

Shows: that an application or the shell listed that item (recent use, a pin, a destination or a task), with the entry's own last access. Does not show: an opening event, the target's timestamp, a person. Record: application id (the file name), source file, DestList version, entry and stream, the link written for it.

Sensitive output: the links inside carry arguments and working directories; run `jumplist` as a job (`secret_output: true`). `lnk_parse` and `lnk_jumplist` keep the arguments out of their answers by shape, so a secret in a field that does not look like one is printed (`artifacts/links`). Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.
