---
id: execution/userassist
title: UserAssist, BAM and DAM activity records
when: You need program activity tied to a profile or SID from NTUSER.DAT or the SYSTEM hive.
needs: []
tools: [regkv]
requires_host: []
---

Use when you meet UserAssist, BAM or DAM values. Not for the claims execution sources can support (`execution/overview`) or for who was at the keyboard (`accounts/sessions`).

Both stores attach activity to an account context: a profile's hive for UserAssist, a SID for BAM and DAM. That is a profile or SID, not a person.

- **What the pack gives.** `regkv` returns a key's values and subkeys; a binary value comes back as hex with its registry type and length and nothing is decoded. The pack has no UserAssist, BAM or DAM reader: a count or time you quote comes from a decoder you name, with the raw value kept beside it (an independent reader that supports this value and Windows version: `registry/readers`). A subkey's last-written time belongs to the key, not to one entry.
- **UserAssist.** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`. Value names are the program path or identifier, ROT13-encoded: decode the name as text offline. The data is binary and its layout differs by length and Windows version: decode with a parser validated for the build and record the GUID, the raw value, the decoded name and the count, time and focus fields it supports. Apply no universal adjustment to a count. It is shell-associated activity in that profile: a program started by a service, a task or another process need not appear, and a missing entry may also be disabled tracking, cleanup or an incomplete collection.
- **BAM and DAM**, where the build keeps them: `SYSTEM\ControlSet00n\Services\bam\State\UserSettings\<SID>` and the `dam` path. These are the paths this leaf was written for: record the exact path you find and the build. Retention and the application types covered vary and are not established. Read the control set the question concerns (`registry/overview`).
- **Value names** are NT device paths, `\Device\HarddiskVolumeN\...`: keep them as they are with the SID. MountedDevices alone may not resolve a historical volume number to a drive letter; use volume and mount evidence (`registry/system-profile`, `registry/devices`) and leave it unresolved rather than invent a letter.
- **Agreement.** When these stores and Prefetch agree and their clocks and meanings are compatible, an application-activity hypothesis is stronger; it does not identify the human, show one shared launch time or exclude automation.
- A negative says whether the hive was dirty, the logs applied and the user's hive collected at all: a user whose hive was not collected is not a user with no entry.
- Sensitive output: `regkv` withholds secret-looking values by name or place (`registry/readers`); program paths and counts are not secrets.

Shows: shell or service activity recorded against a profile or SID. Does not show: who was at the keyboard, that the program finished or had an effect, every program that ran, or an exact launch time shared by the sources. Record: hive digest and state, control set, GUID or SID, raw value, the decoder and its version.
