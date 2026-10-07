---
id: artifacts/links
title: Reading a shell link (.lnk)
when: You read a .lnk file, or carve link structures from a dump, for a target, volume or share.
needs: [artifacts/shell]
tools: [lnk_parse]
requires_host: [lnkinfo]
---

Use when you read a shell link or carve link structures from a dump. Not for the set of recent items (`artifacts/shell`) or the links inside a Jump List (`artifacts/jumplists`).

- `lnk_parse` follows MS-SHLLINK: flags, the three target FILETIMEs (raw decimal beside ISO 8601 UTC, seven fractional digits), LinkInfo (VolumeID: `drive_type_name`, `serial_number` as eight hex digits, label; local base path and common path suffix; CommonNetworkRelativeLink: `net_name`, device name, provider), `linkinfo_target` with `linkinfo_target_kind` (local or network), and the extra blocks it knows.
- The shell item list is not decoded. `idlist_ascii`, `idlist_paths`, the tracker block's `machine` and the UTF-16 scan are printable runs, listed under `heuristic_fields`. ANSI strings are shown as Latin-1 because the file records no code page.
- `structure_complete` false with `problems` means the read ended inside the structure: read more bytes (`size`) before citing a field of it. With `scan` and `dump`, links are carved by the 20-byte header and a hit is a candidate.
- A removable `drive_type_name` with serial and label says the volume was recorded that way; tie it to a device only through `registry/devices`. A network target says that share path named it when the link was written, not that content came from there.
- Target times and size are as they were when the link was last written.
- `lnkinfo` reads a link by another implementation: for a field a report depends on, keep both outputs and any disagreement.

Arguments and the string scan are withheld from the answer. You get `arguments_present`, `arguments_chars` and `arguments_first_token` (only a switch name, a program or a script; otherwise null with `arguments_first_token_withheld`), and `utf16_strings` as offsets and lengths with a `finding_id` (`utf16_string_count`). A path-like field shaped like a secret is replaced by a length marker, listed in `sensitive_fields_withheld`. The text goes only to `lnk-strings.jsonl` under $OUT with `write_strings: true`, in a job.

Shows: a reference to the target was recorded, with its size and times as of the last write of the link. Does not show: that the target was opened (a user or application can create a link, and one can arrive in an archive or message), where content came from, who used it. Record: the link's path and its own times, `structure_complete`, the cited fields with their raw values, the second reader.

Sensitive output: run `lnk_parse` as a job (`secret_output: true`) with `write_strings` only when the command line itself matters.
