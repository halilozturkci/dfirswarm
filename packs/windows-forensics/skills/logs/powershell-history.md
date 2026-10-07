---
id: logs/powershell-history
title: PowerShell history, encoded commands
when: You meet ConsoleHost_history.txt, an -EncodedCommand argument or an engine 2 request.
needs: [logs/powershell]
tools: [mft_records, evtx_query]
requires_host: []
---

Use when you read the PSReadLine history file, decode a command line or see an older-engine request. Not for the event-log records themselves (`logs/powershell`).

- **`ConsoleHost_history.txt`** is a plain-text file per user, written by PSReadLine, not an event log: clearing the logs does not touch it. It is configurable and host-specific (other hosts keep their own `<host>_history.txt`; it can be redirected, disabled or made to leave out lines), so a missing line is not a command that was not typed. It has no per-command times and several sessions write to one file: an order with possible interleaving, not a clock. Its file times (`mft_records`, both time sets, `filesystem/mft`) say when the file was created and last changed on this volume; they do not bracket a session or date a line. Check every profile that exists, service and administrator accounts included, and put its lines on a timeline only beside a source that carries time.
- **`-EncodedCommand`** is data: on the observed host the encoding is base64 of UTF-16LE. Decode it offline as text into a file you read; keep the encoded form as the artefact and the decoded text as a derivative whose transformation you record.
- **An older engine.** `-Version 2` in a command line, or an EngineVersion of 2.0 in 400 (`evtx_query`), shows a request or a start, not that the engine was installed or that logging was absent; availability and logging differ by build and installed features. Ask what the launching context was: legacy applications can request an older engine.
- Changes to Defender or other controls arise through policy, management software and interfaces other than PowerShell; read their own records (`antiforensics/controls`).

Shows: what the host chose to save, and what the command line asked for. Does not show: who typed it, that the code completed or had an effect, that a missing command was never run, or that the file is whole. Record: path, encoding, extent, the profile, file times, and the decoding step.
Sensitive output: command lines and decoded text can hold credentials; run `evtx_query` and any decoding as jobs with `secret_output: true`, and do not carry the encoded form of a command that holds one into a note.
