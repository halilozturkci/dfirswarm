---
id: artifacts/shell
title: Links, Jump Lists and ShellBags: which to read
when: Trace a path, volume or share through what the shell kept, without claiming an action.
needs: []
tools: [lnk_parse, jumplist, shellbags]
requires_host: [lnkinfo, olecfexport]
---

Use when a path, volume or share must be traced through what the shell kept. Not for execution (`execution/overview`) or a device's own records (`registry/devices`).

These are references the shell kept, not records that something was done. They outlive the file they name, and none names a person. For each, say what it holds, which clock its times are on, and what else would have to be true for the claim you want.

- Links: `Users/<u>/AppData/Roaming/Microsoft/Windows/Recent/*.lnk` and any link an application wrote elsewhere. A link's own file times are separate from the times stored inside it. Open `artifacts/links` (`lnk_parse`) only if you read a link.
- Jump Lists: the `AutomaticDestinations` and `CustomDestinations` folders beside Recent; the file name is an application id, which this pack does not map. Open `artifacts/jumplists` (`jumplist`) only if you read one.
- ShellBags: the BagMRU trees of `UsrClass.dat` (`Local Settings\Software\Microsoft\Windows\Shell`) and `NTUSER.DAT` (`Software\Microsoft\Windows\Shell`, `ShellNoRoam` in older hives). Open `artifacts/shellbags` (`shellbags`) only if you read BagMRU or the recent-document keys.

Collect the set per profile, with each hive's logs beside it (hive state: `registry/overview`). A profile that was not collected is a gap, not an empty profile.

Second readers, where the image carries them: `lnkinfo` parses a link by another implementation, and `olecfexport` takes a Jump List's compound file apart (it confirms stream extraction, not DestList meaning). For a target, serial, share or long name a report line depends on, keep both outputs and any disagreement; with no second reader, say the field has one. Compare volume serials like with like (`registry/system-profile`); convert DOS times by the zone rules of their date (`registry/clock`).

A negative is bounded by the profiles collected, the hive state and the acquisition date: these records are written by components that can be disabled, limited or cleaned.

Shows: that the shell, or an application, kept a reference to the target, with the metadata it had when the record was written. Does not show: a person, that a file was opened, read, copied or run, where content came from, when it was first or last used, or that the item still exists. Record: profile, source file and its own times, hive state, which clock each time is on, the second reader.

Sensitive output: `lnk_parse` and `jumplist` run as jobs (`secret_output: true`); the two leaves say what each withholds.
