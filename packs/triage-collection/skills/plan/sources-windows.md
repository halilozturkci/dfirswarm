---
id: plan/sources-windows
title: Windows sources to request, by question
when: You request more evidence from a Windows source.
needs: []
tools: [collection_index]
requires_host: []
---

Use when the delivery is Windows and a request needs concrete sources. Not for the request itself (`plan/what-to-collect`).

Compare each source with `collection_index`'s census of what you hold. Choose by the unanswered question and by how fast the source is lost, not from a fixed ranking. Identify the actual Windows root, volumes and profiles first; do not assume `C:` and one user. Paths are where each usually sits.

- File system: `$MFT`, `$UsnJrnl:$J` (`$Extend/$J`), `$LogFile`, `$Boot` and the volume's identifying metadata.
- Registry: `Windows/System32/config/` SYSTEM and SOFTWARE (SAM and SECURITY only where the question justifies them); each relevant user's `NTUSER.DAT` and `AppData/Local/Microsoft/Windows/UsrClass.dat`; the hives' `.LOG1`/`.LOG2` transaction logs beside them.
- Event logs: the relevant channels under `Windows/System32/winevt/Logs/`, and the logging configuration that decides what they hold.
- Execution and activity: `Windows/Prefetch/`, `Windows/AppCompat/Programs/Amcache.hve`, `Windows/System32/sru/SRUDB.dat` with the ESE recovery companions it needs, `AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt` and the PowerShell logs, each user's Recent items and both Jump List stores, scheduled tasks under `Windows/System32/Tasks/` and their supporting configuration.
- Browsers: each database with the journal or WAL files that belong to it.
- Earlier states: snapshot-derived versions of any of the above.

Ask for raw source artefacts beside parsed exports whenever the export will have to be verified: a report-only delivery supports limited observations, not every claim a source file could test.

Shows: which sources could bear on a question. Does not show: that they exist, were retained or would contain a trace.
Record: each source, the question, and the companion files named with it.
Sensitive output: the account hives hold password verifiers; ask for them only where the question and the authority justify it, read them in jobs with `secret_output: true`, and never write a hash of a secret.
