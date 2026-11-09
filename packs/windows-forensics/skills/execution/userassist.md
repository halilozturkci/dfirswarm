---
id: execution/userassist
title: UserAssist, BAM, DAM
when: Program activity by profile.
needs: []
tools: [userassist_bam_shimcache, regkv]
requires_host: []
---

Use when you meet UserAssist, BAM or DAM values. Not for the claims execution sources can support (`execution/overview`) or for who was at the keyboard (`accounts/sessions`).

Both stores attach activity to an account context: a profile's hive for UserAssist, a SID for BAM and DAM. That is a profile or SID, not a person.

- **What the pack gives.** `userassist_bam_shimcache` reads UserAssist and BAM and DAM into records: `raw_hex` beside the decoded fields, `layout` with `layout_basis`, and `unsupported` (bytes kept) for a length or type it does not know. Its offsets are from published notes, unverified against real hives, and nothing cross-checks it (`cross_check` is `not_run`; a second reader: `registry/readers`). A subkey's last-written time belongs to the key, not to one entry.
- **UserAssist.** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`. Value names are ROT13 program paths or identifiers (`name_raw`, `name_decoded`). The tool knows data of 72 and 16 bytes and labels each record; record the GUID, the raw value, the decoded name and the count, time and focus fields. Apply no universal adjustment to a count. An NTUSER.DAT does not name its owner: `sid` is null unless you pass `owner_sid`, your word. It is shell-associated activity in that profile: a program started by a service, a task or another process need not appear, and a missing entry may also be disabled tracking, cleanup or an incomplete collection.
- **BAM and DAM**, where the build keeps them: `SYSTEM\ControlSet00n\Services\bam\State\UserSettings\<SID>`, the older `...\bam\UserSettings\<SID>` and `dam`, all read (SID = key name, time = first 8 bytes of a 24-byte value). Record the exact path (`key`) and the build. Retention and the application types covered vary and are not established. Read the control set the question concerns (`registry/overview`).
- **Value names** are NT device paths, `\Device\HarddiskVolumeN\...`: keep them as they are with the SID. MountedDevices alone may not resolve a historical volume number to a drive letter; use volume and mount evidence (`registry/system-profile`, `registry/devices`) and leave it unresolved rather than invent a letter.
- **Agreement.** When these stores and Prefetch agree and their clocks and meanings are compatible, an application-activity hypothesis is stronger; it does not identify the human, show one shared launch time or exclude automation.
- A negative says whether the hive was dirty, the logs applied and the user's hive collected at all: a user whose hive was not collected is not a user with no entry.
- Sensitive output: `regkv` withholds secret-looking values by name or place (`registry/readers`); program paths and counts are not secrets. Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.

Shows: shell or service activity recorded against a profile or SID. Does not show: who was at the keyboard, that the program finished or had an effect, every program that ran, or an exact launch time shared by the sources. Record: hive digest and state, control set, GUID or SID, raw value, the decoder and its version.
