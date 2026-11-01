---
id: encryptor/windows-evidence
title: NTFS records and Windows events
when: The chain rests on MFT or USN records, or on service, task or log-clear events.
needs: []
tools: [backup_destruction_correlate]
requires_host: []
mentions: [mft_records, usn_journal, prefetch_mam, amcache_apps, regkv, evtx_query]
---

Use only if the chain rests on NTFS records or Windows events. Not for the chain as a whole (`encryptor/traces`).

**Filesystem evidence.** Preserve the suspected binary or script, its original
path and source-object identity, its configuration, staging files and deployment
lists. On NTFS look at the relevant MFT records and any change-journal records.
An MFT timestamp is not a general deletion time. A retained USN record can support
a deletion event; rollover, record reuse and an incomplete collection limit what
survives. If the windows-forensics pack is loaded (check the run's tool
inventory), `mft_records` and `usn_journal` read them, `prefetch_mam` and
`amcache_apps` read the execution artefacts below, and its skills
(`execution/overview`, `logs/remote-access`, `logs/powershell`) carry the
per-artefact limits: read those rather than a summary of them here. Where it is
not loaded, say that these artefacts were not examined.

**Windows event evidence.** A System 7045 record shows a service installed, not
that it ran. Security 4698 and TaskScheduler 106 show a task created or
registered; look separately for records of its action running. Security 4688
depends on the audit policy, and a command line in it on a further setting. Record
the provider, channel, event id, record id and source host. Security 1102 records
the clearing of the Security log: do not expect it in every incident, do not read
its absence as evidence against cleanup, and look at other clearing records,
interrupted collection, retention and central copies. Clearing can also be
authorised administration. `evtx_query` and `regkv`, where that pack is loaded,
read these; otherwise say they were not read. To see what a log says was done to the
backups, `backup_destruction_correlate` reads an `evtx_query` answer by reference: it
recognises a destructive command in a record and prints the record's reference, not its text.

**Does not show.** That an MFT timestamp is a deletion time; that a service installation is execution; that the absence of a 1102 record is evidence against cleanup; that a record exists in every incident.

Record: provider, channel, event id, record id and source host per event; which windows-forensics tools were not loaded, so which artefacts were not examined.
Sensitive output: command lines and task actions can hold secrets; cite record ids, never the text.
