---
id: persistence/tasks-com-wmi
title: Tasks, COM, WMI and replaced system binaries
when: Persistence may sit in a task, COM, WMI or a substituted system program.
needs: [persistence/mechanisms]
tools: [regkv, evtx_query, ioc_scan, mft_records]
requires_host: []
---

Use when the sweep reaches tasks, COM, WMI or a suspect system binary. Not for services and run keys (`persistence/mechanisms`).

- Scheduled tasks, three records to compare: the task files under `Windows/System32/Tasks/` (XML: triggers, actions, principals, enabled state); `TaskCache` `Tree` and `Tasks` under `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule` (the registry side); events 4698 and 4699 (`logs/events`) where creation and deletion were audited. `Author` and date fields are metadata the creator supplied. The binary values (`Actions`, `Triggers`, `DynamicInfo`) arrive from `regkv` as hex and are not decoded in this pack: name the decoder if you read one. A task in one place and not the other is a finding with both sides; name no cause (deletion, cleanup, partial collection and tampering all produce it).
- COM: a per-user registration (`Software\Classes\CLSID\...\InprocServer32`) is stored in that user's `UsrClass.dat`, not `NTUSER.DAT`; record the server path and whether the CLSID is also registered machine-wide.
- WMI: event subscriptions live in the WMI repository (`Windows/System32/wbem/Repository`), which this pack does not decode: record it as not examined. `ioc_scan` over its files gives locators for consumer class names, not a decoded subscription. Add `WMI-Activity/Operational` events where the image has them (`evtx_query`; 5861 is a permanent subscription binding).
- Replaced or redirected system binaries (the login-screen accessibility programs among them): compare the recovered file with a trusted reference for the exact build (from the case or vendor media; this pack carries none) and record hash, signature and version metadata, size, owner and permissions where the image keeps them, and its file system history (`mft_records`, `filesystem/mft`, `filesystem/journals`), since servicing rewrites system files too. File replacement and registry redirection are different hypotheses: check both.

Sensitive output: task arguments and event data can hold a typed secret; run `evtx_query` in a job with `secret_output: true`. `regkv` withholds by name and place only.
Shows: a task, registration or binary as configured and its file-system history. Does not show: that it ran; a matching hash identifies bytes, not the mechanism, the actor or use. Record: task file and TaskCache keys, CLSID and server path, the reference used for the binary, what was not examined.
